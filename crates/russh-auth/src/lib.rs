//! Authentication engine for RuSSH (RFC 4252).
//!
//! Implements all three standard SSH authentication methods:
//!
//! | Method | Description |
//! |--------|-------------|
//! | `publickey` | Ed25519 signature verification against RFC 4252 signing payload |
//! | `password` | Constant-time comparison via `subtle::ConstantTimeEq` |
//! | `keyboard-interactive` | InfoRequest/InfoResponse challenge-response flow |
//!
//! ## Key types
//!
//! - [`AuthMessage`] — parsed `SSH_MSG_USERAUTH_REQUEST` variants.
//! - [`AuthPolicy`] — pluggable policy trait deciding accept/partial/reject.
//! - [`MemoryAuthorizedKeys`] — in-memory authorized-keys store with
//!   constant-time key lookup.
//! - [`FileIdentityProvider`] — reads `~/.ssh/id_ed25519.pub` from disk.
//! - [`CertificateValidator`] — certificate chain validation stub.
//!
//! ## Signature verification
//!
//! [`verify_publickey_auth_signature`] constructs the full RFC 4252 signing
//! payload (`string session_id || byte 50 || string user || … || string pubkey_blob`)
//! and verifies the Ed25519 signature using `russh-crypto`'s `Ed25519Verifier`.
//!
//! All secret comparisons (passwords, HMAC tags) use `subtle::ConstantTimeEq`.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{SystemTime, UNIX_EPOCH};

use russh_core::{PacketCodec, PacketFrame, RusshError, RusshErrorCategory};
use russh_crypto::{
    EcdsaP256Verifier, EcdsaP384Verifier, EcdsaP521Verifier, Ed25519Verifier, RsaVerifier,
    Verifier, constant_time_eq, decode_ssh_string, encode_ssh_string,
};

/// Client authentication request variants.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthRequest {
    PublicKey {
        user: String,
        public_key: Vec<u8>,
        signature: Vec<u8>,
    },
    Password {
        user: String,
        password: String,
    },
    KeyboardInteractive {
        user: String,
        responses: Vec<String>,
    },
}

impl AuthRequest {
    #[must_use]
    pub fn user(&self) -> &str {
        match self {
            Self::PublicKey { user, .. }
            | Self::Password { user, .. }
            | Self::KeyboardInteractive { user, .. } => user,
        }
    }

    #[must_use]
    pub fn method(&self) -> AuthMethod {
        match self {
            Self::PublicKey { .. } => AuthMethod::PublicKey,
            Self::Password { .. } => AuthMethod::Password,
            Self::KeyboardInteractive { .. } => AuthMethod::KeyboardInteractive,
        }
    }
}

/// Authentication engine result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthResult {
    Accepted,
    Rejected { reason: String },
    PartiallyAccepted { next_methods: Vec<AuthMethod> },
}

/// Methods exposed by negotiation and policy APIs.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AuthMethod {
    PublicKey,
    Password,
    KeyboardInteractive,
}

impl AuthMethod {
    #[must_use]
    pub fn as_ssh_name(self) -> &'static str {
        match self {
            Self::PublicKey => "publickey",
            Self::Password => "password",
            Self::KeyboardInteractive => "keyboard-interactive",
        }
    }

    /// Parse an SSH method name into an `AuthMethod`.
    /// Returns `None` for unrecognised names.
    #[must_use]
    pub fn from_ssh_name(name: &str) -> Option<Self> {
        match name {
            "publickey" => Some(Self::PublicKey),
            "password" => Some(Self::Password),
            "keyboard-interactive" => Some(Self::KeyboardInteractive),
            _ => None,
        }
    }
}

/// Typed authentication events for observability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthEvent {
    MethodOffered(AuthMethod),
    Accepted {
        user: String,
        method: AuthMethod,
    },
    Rejected {
        user: String,
        method: AuthMethod,
        reason: String,
    },
    PartiallyAccepted {
        user: String,
        completed_methods: Vec<AuthMethod>,
        next_methods: Vec<AuthMethod>,
    },
}

/// Server policy for accepted auth mechanisms.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerAuthPolicy {
    allowed_methods: BTreeSet<AuthMethod>,
    required_methods: BTreeSet<AuthMethod>,
    pub max_attempts: u8,
    /// If set, incoming certificate-based auth is validated using this validator.
    /// Certificate auth is always verified cryptographically (CA signature); this
    /// adds policy checks (trusted CA keys, required principal).
    pub certificate_validator: Option<CertificateValidator>,
    /// If set, only public keys present in this store are accepted.
    /// When `None`, any cryptographically valid key is accepted (insecure default).
    pub authorized_keys: Option<MemoryAuthorizedKeys>,
}

impl ServerAuthPolicy {
    #[must_use]
    pub fn secure_defaults() -> Self {
        let allowed_methods = [
            AuthMethod::PublicKey,
            AuthMethod::Password,
            AuthMethod::KeyboardInteractive,
        ]
        .into_iter()
        .collect();

        Self {
            allowed_methods,
            required_methods: BTreeSet::new(),
            max_attempts: 6,
            certificate_validator: None,
            authorized_keys: None,
        }
    }

    /// Configure a certificate validator for cert-based publickey auth.
    pub fn set_certificate_validator(&mut self, v: CertificateValidator) {
        self.certificate_validator = Some(v);
    }

    /// Configure the authorized keys store for public-key auth.
    pub fn set_authorized_keys(&mut self, keys: MemoryAuthorizedKeys) {
        self.authorized_keys = Some(keys);
    }

    #[must_use]
    pub fn allows(&self, method: AuthMethod) -> bool {
        self.allowed_methods.contains(&method)
    }

    #[must_use]
    pub fn allowed_methods(&self) -> Vec<AuthMethod> {
        self.allowed_methods.iter().copied().collect()
    }

    #[must_use]
    pub fn required_methods(&self) -> Vec<AuthMethod> {
        self.required_methods.iter().copied().collect()
    }

    pub fn set_allowed_methods(
        &mut self,
        methods: impl IntoIterator<Item = AuthMethod>,
    ) -> Result<(), RusshError> {
        let allowed_methods: BTreeSet<AuthMethod> = methods.into_iter().collect();
        if allowed_methods.is_empty() {
            return Err(RusshError::new(
                RusshErrorCategory::Auth,
                "at least one authentication method must be allowed",
            ));
        }

        if !self.required_methods.is_subset(&allowed_methods) {
            return Err(RusshError::new(
                RusshErrorCategory::Auth,
                "required authentication methods must be part of allowed methods",
            ));
        }

        self.allowed_methods = allowed_methods;
        Ok(())
    }

    pub fn set_required_methods(
        &mut self,
        methods: impl IntoIterator<Item = AuthMethod>,
    ) -> Result<(), RusshError> {
        let required_methods: BTreeSet<AuthMethod> = methods.into_iter().collect();
        if !required_methods.is_subset(&self.allowed_methods) {
            return Err(RusshError::new(
                RusshErrorCategory::Auth,
                "required authentication methods must be part of allowed methods",
            ));
        }

        self.required_methods = required_methods;
        Ok(())
    }
}

/// Host key material lookup for server identity validation.
pub trait HostKeyStore {
    fn host_public_key(&self, host: &str) -> Option<Vec<u8>>;
}

/// Known hosts verification interface for client checks.
pub trait KnownHostsStore {
    fn is_known_host(&self, host: &str, key: &[u8]) -> bool;
}

/// Identity resolution interface for available user keys.
pub trait IdentityProvider {
    fn identities_for_user(&self, user: &str) -> Vec<Vec<u8>>;
}

/// Agent protocol abstraction for agent forwarding flows.
pub trait AgentClient {
    fn sign(&self, key_blob: &[u8], message: &[u8]) -> Result<Vec<u8>, RusshError>;
}

/// SSH USERAUTH request payload variants.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UserAuthRequest {
    None {
        user: String,
        service: String,
    },
    PublicKey {
        user: String,
        service: String,
        algorithm: String,
        public_key: Vec<u8>,
        signature: Option<Vec<u8>>,
    },
    Password {
        user: String,
        service: String,
        password: String,
    },
    KeyboardInteractive {
        user: String,
        service: String,
        language_tag: String,
        submethods: String,
    },
}

/// SSH USERAUTH message model.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UserAuthMessage {
    Request(UserAuthRequest),
    Failure {
        methods: Vec<String>,
        partial_success: bool,
    },
    Success,
    Banner {
        message: String,
        language_tag: String,
    },
    PublicKeyOk {
        algorithm: String,
        public_key: Vec<u8>,
    },
    KeyboardInteractiveInfoRequest {
        name: String,
        instruction: String,
        language_tag: String,
        prompts: Vec<(String, bool)>,
    },
    KeyboardInteractiveInfoResponse {
        responses: Vec<String>,
    },
}

impl UserAuthMessage {
    const MSG_REQUEST: u8 = 50;
    const MSG_FAILURE: u8 = 51;
    const MSG_SUCCESS: u8 = 52;
    const MSG_BANNER: u8 = 53;
    const MSG_INFO_REQUEST_OR_PK_OK: u8 = 60;
    const MSG_INFO_RESPONSE: u8 = 61;

    pub fn to_frame(&self) -> Result<PacketFrame, RusshError> {
        let mut payload = Vec::new();

        match self {
            Self::Request(request) => {
                payload.push(Self::MSG_REQUEST);
                match request {
                    UserAuthRequest::None { user, service } => {
                        write_string(&mut payload, user)?;
                        write_string(&mut payload, service)?;
                        write_string(&mut payload, "none")?;
                    }
                    UserAuthRequest::PublicKey {
                        user,
                        service,
                        algorithm,
                        public_key,
                        signature,
                    } => {
                        write_string(&mut payload, user)?;
                        write_string(&mut payload, service)?;
                        write_string(&mut payload, AuthMethod::PublicKey.as_ssh_name())?;
                        write_bool(&mut payload, signature.is_some());
                        write_string(&mut payload, algorithm)?;
                        write_binary_string(&mut payload, public_key)?;
                        if let Some(signature) = signature {
                            write_binary_string(&mut payload, signature)?;
                        }
                    }
                    UserAuthRequest::Password {
                        user,
                        service,
                        password,
                    } => {
                        write_string(&mut payload, user)?;
                        write_string(&mut payload, service)?;
                        write_string(&mut payload, AuthMethod::Password.as_ssh_name())?;
                        write_bool(&mut payload, false);
                        write_string(&mut payload, password)?;
                    }
                    UserAuthRequest::KeyboardInteractive {
                        user,
                        service,
                        language_tag,
                        submethods,
                    } => {
                        write_string(&mut payload, user)?;
                        write_string(&mut payload, service)?;
                        write_string(&mut payload, AuthMethod::KeyboardInteractive.as_ssh_name())?;
                        write_string(&mut payload, language_tag)?;
                        write_string(&mut payload, submethods)?;
                    }
                }
            }
            Self::Failure {
                methods,
                partial_success,
            } => {
                payload.push(Self::MSG_FAILURE);
                write_name_list(&mut payload, methods)?;
                write_bool(&mut payload, *partial_success);
            }
            Self::Success => payload.push(Self::MSG_SUCCESS),
            Self::Banner {
                message,
                language_tag,
            } => {
                payload.push(Self::MSG_BANNER);
                write_string(&mut payload, message)?;
                write_string(&mut payload, language_tag)?;
            }
            Self::PublicKeyOk {
                algorithm,
                public_key,
            } => {
                payload.push(Self::MSG_INFO_REQUEST_OR_PK_OK);
                write_string(&mut payload, algorithm)?;
                write_binary_string(&mut payload, public_key)?;
            }
            Self::KeyboardInteractiveInfoRequest {
                name,
                instruction,
                language_tag,
                prompts,
            } => {
                payload.push(Self::MSG_INFO_REQUEST_OR_PK_OK);
                write_string(&mut payload, name)?;
                write_string(&mut payload, instruction)?;
                write_string(&mut payload, language_tag)?;
                write_u32(
                    &mut payload,
                    u32::try_from(prompts.len()).map_err(|_| {
                        RusshError::new(
                            RusshErrorCategory::Auth,
                            "keyboard-interactive prompt count exceeds u32",
                        )
                    })?,
                );
                for (prompt, echo) in prompts {
                    write_string(&mut payload, prompt)?;
                    write_bool(&mut payload, *echo);
                }
            }
            Self::KeyboardInteractiveInfoResponse { responses } => {
                payload.push(Self::MSG_INFO_RESPONSE);
                write_u32(
                    &mut payload,
                    u32::try_from(responses.len()).map_err(|_| {
                        RusshError::new(
                            RusshErrorCategory::Auth,
                            "keyboard-interactive response count exceeds u32",
                        )
                    })?,
                );
                for response in responses {
                    write_string(&mut payload, response)?;
                }
            }
        }

        Ok(PacketFrame::new(payload))
    }

    pub fn from_frame(frame: &PacketFrame) -> Result<Self, RusshError> {
        let payload = &frame.payload;
        let (message_type, body) = payload.split_first().ok_or_else(|| {
            RusshError::new(RusshErrorCategory::Auth, "empty USERAUTH frame payload")
        })?;
        let mut offset = 0usize;

        let message = match *message_type {
            Self::MSG_REQUEST => {
                let user = read_string(body, &mut offset)?;
                let service = read_string(body, &mut offset)?;
                let method = read_string(body, &mut offset)?;

                match method.as_str() {
                    "none" => Self::Request(UserAuthRequest::None { user, service }),
                    "publickey" => {
                        let has_signature = read_bool(body, &mut offset)?;
                        let algorithm = read_string(body, &mut offset)?;
                        let public_key = read_binary_string(body, &mut offset)?;
                        let signature = if has_signature {
                            Some(read_binary_string(body, &mut offset)?)
                        } else {
                            None
                        };
                        Self::Request(UserAuthRequest::PublicKey {
                            user,
                            service,
                            algorithm,
                            public_key,
                            signature,
                        })
                    }
                    "password" => {
                        let password_change = read_bool(body, &mut offset)?;
                        if password_change {
                            return Err(RusshError::new(
                                RusshErrorCategory::Auth,
                                "password change requests are not supported",
                            ));
                        }
                        let password = read_string(body, &mut offset)?;
                        Self::Request(UserAuthRequest::Password {
                            user,
                            service,
                            password,
                        })
                    }
                    "keyboard-interactive" => {
                        let language_tag = read_string(body, &mut offset)?;
                        let submethods = read_string(body, &mut offset)?;
                        Self::Request(UserAuthRequest::KeyboardInteractive {
                            user,
                            service,
                            language_tag,
                            submethods,
                        })
                    }
                    _ => {
                        return Err(RusshError::new(
                            RusshErrorCategory::Auth,
                            format!("unsupported USERAUTH method '{method}'"),
                        ));
                    }
                }
            }
            Self::MSG_FAILURE => {
                let methods = read_name_list(body, &mut offset)?;
                let partial_success = read_bool(body, &mut offset)?;
                Self::Failure {
                    methods,
                    partial_success,
                }
            }
            Self::MSG_SUCCESS => Self::Success,
            Self::MSG_BANNER => {
                let message = read_string(body, &mut offset)?;
                let language_tag = read_string(body, &mut offset)?;
                Self::Banner {
                    message,
                    language_tag,
                }
            }
            Self::MSG_INFO_REQUEST_OR_PK_OK => {
                let start = offset;
                let algorithm_or_name = read_string(body, &mut offset)?;
                let second = read_binary_string(body, &mut offset)?;
                if offset == body.len() {
                    Self::PublicKeyOk {
                        algorithm: algorithm_or_name,
                        public_key: second,
                    }
                } else {
                    offset = start;
                    let name = read_string(body, &mut offset)?;
                    let instruction = read_string(body, &mut offset)?;
                    let language_tag = read_string(body, &mut offset)?;
                    let count = usize::try_from(read_u32(body, &mut offset)?).map_err(|_| {
                        RusshError::new(
                            RusshErrorCategory::Auth,
                            "keyboard-interactive prompt count does not fit usize",
                        )
                    })?;
                    let mut prompts = Vec::with_capacity(count);
                    for _ in 0..count {
                        prompts.push((
                            read_string(body, &mut offset)?,
                            read_bool(body, &mut offset)?,
                        ));
                    }
                    Self::KeyboardInteractiveInfoRequest {
                        name,
                        instruction,
                        language_tag,
                        prompts,
                    }
                }
            }
            Self::MSG_INFO_RESPONSE => {
                let count = usize::try_from(read_u32(body, &mut offset)?).map_err(|_| {
                    RusshError::new(
                        RusshErrorCategory::Auth,
                        "keyboard-interactive response count does not fit usize",
                    )
                })?;
                let mut responses = Vec::with_capacity(count);
                for _ in 0..count {
                    responses.push(read_string(body, &mut offset)?);
                }
                Self::KeyboardInteractiveInfoResponse { responses }
            }
            _ => {
                return Err(RusshError::new(
                    RusshErrorCategory::Auth,
                    format!("unsupported USERAUTH message type {message_type}"),
                ));
            }
        };

        if offset != body.len() {
            return Err(RusshError::new(
                RusshErrorCategory::Auth,
                "USERAUTH message has trailing bytes",
            ));
        }

        Ok(message)
    }

    pub fn encode(&self, codec: &PacketCodec) -> Result<Vec<u8>, RusshError> {
        codec.encode(&self.to_frame()?)
    }

    pub fn decode(codec: &PacketCodec, bytes: &[u8]) -> Result<Self, RusshError> {
        Self::from_frame(&codec.decode(bytes)?)
    }
}

/// Parsed authorized key entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedKeyEntry {
    pub options: Option<String>,
    pub algorithm: String,
    pub key: Vec<u8>,
    pub comment: Option<String>,
}

/// Parsed known_hosts entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KnownHostEntry {
    pub marker: Option<String>,
    pub host_patterns: Vec<String>,
    pub algorithm: String,
    pub key: Vec<u8>,
    pub comment: Option<String>,
}

/// In-memory authorized keys store keyed by user.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MemoryAuthorizedKeys {
    entries: BTreeMap<String, Vec<AuthorizedKeyEntry>>,
}

impl MemoryAuthorizedKeys {
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    pub fn insert_entry(&mut self, user: impl Into<String>, entry: AuthorizedKeyEntry) {
        self.entries.entry(user.into()).or_default().push(entry);
    }

    pub fn load_authorized_keys(
        &mut self,
        user: impl Into<String>,
        input: &str,
    ) -> Result<usize, RusshError> {
        let user = user.into();
        let parsed = parse_authorized_keys(input)?;
        let count = parsed.len();
        self.entries.insert(user, parsed);
        Ok(count)
    }

    /// Returns `true` if `key` is an authorized key blob for `user`.
    ///
    /// A wildcard entry stored under `"*"` matches any user.
    ///
    /// # Constant-time note
    ///
    /// Key blob comparison uses [`russh_crypto::constant_time_eq`] (`subtle::ConstantTimeEq`)
    /// to prevent timing side-channels.
    #[must_use]
    pub fn is_authorized(&self, user: &str, key: &[u8]) -> bool {
        let check = |entries: &Vec<AuthorizedKeyEntry>| {
            entries
                .iter()
                .any(|entry| constant_time_eq(&entry.key, key))
        };
        if self.entries.get(user).is_some_and(check) {
            return true;
        }
        // Also check wildcard entries (e.g. loaded with user="*" for any user).
        if user != "*" && self.entries.get("*").is_some_and(check) {
            return true;
        }
        false
    }
}

impl IdentityProvider for MemoryAuthorizedKeys {
    fn identities_for_user(&self, user: &str) -> Vec<Vec<u8>> {
        self.entries
            .get(user)
            .map(|entries| entries.iter().map(|entry| entry.key.clone()).collect())
            .unwrap_or_default()
    }
}

/// In-memory host key store keyed by host.
#[derive(Clone, Debug, Default)]
pub struct MemoryHostKeyStore {
    keys: BTreeMap<String, Vec<u8>>,
}

impl MemoryHostKeyStore {
    #[must_use]
    pub fn new() -> Self {
        Self {
            keys: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, host: impl Into<String>, key: Vec<u8>) {
        self.keys.insert(host.into(), key);
    }
}

impl HostKeyStore for MemoryHostKeyStore {
    fn host_public_key(&self, host: &str) -> Option<Vec<u8>> {
        self.keys.get(host).cloned()
    }
}

/// In-memory identity map for fixed user key lists.
#[derive(Clone, Debug, Default)]
pub struct MemoryIdentityProvider {
    keys: BTreeMap<String, Vec<Vec<u8>>>,
}

impl MemoryIdentityProvider {
    #[must_use]
    pub fn new() -> Self {
        Self {
            keys: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, user: impl Into<String>, key: Vec<u8>) {
        self.keys.entry(user.into()).or_default().push(key);
    }
}

impl IdentityProvider for MemoryIdentityProvider {
    fn identities_for_user(&self, user: &str) -> Vec<Vec<u8>> {
        self.keys.get(user).cloned().unwrap_or_default()
    }
}

/// File-backed identity provider that loads SSH public keys from `.pub` files.
///
/// For each key path provided, it looks for a corresponding `.pub` file and
/// parses it as an SSH authorized-keys public key blob.
pub struct FileIdentityProvider {
    key_paths: Vec<std::path::PathBuf>,
}

impl FileIdentityProvider {
    pub fn new(paths: Vec<std::path::PathBuf>) -> Self {
        Self { key_paths: paths }
    }

    /// Create with default OpenSSH identity file paths for the current user.
    pub fn with_default_paths() -> Self {
        let home = std::env::var("HOME").unwrap_or_default();
        let paths = ["id_ed25519", "id_ecdsa", "id_rsa"]
            .iter()
            .map(|f| std::path::PathBuf::from(format!("{home}/.ssh/{f}")))
            .filter(|p| p.exists())
            .collect();
        Self::new(paths)
    }
}

impl IdentityProvider for FileIdentityProvider {
    fn identities_for_user(&self, _user: &str) -> Vec<Vec<u8>> {
        self.key_paths
            .iter()
            .filter_map(|path| {
                let pub_path = path.with_extension("pub");
                if let Ok(content) = std::fs::read_to_string(&pub_path) {
                    parse_pub_file_blob(&content)
                } else {
                    None
                }
            })
            .collect()
    }
}

fn parse_pub_file_blob(content: &str) -> Option<Vec<u8>> {
    let line = content.lines().next()?.trim();
    if line.starts_with('#') || line.is_empty() {
        return None;
    }
    let mut parts = line.splitn(3, ' ');
    let _alg = parts.next()?;
    let b64 = parts.next()?;
    decode_base64(b64).ok()
}

/// In-memory known_hosts store with wildcard host pattern support.
#[derive(Clone, Debug, Default)]
pub struct MemoryKnownHostsStore {
    entries: Vec<KnownHostEntry>,
}

impl MemoryKnownHostsStore {
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn load_known_hosts(&mut self, input: &str) -> Result<usize, RusshError> {
        let parsed = parse_known_hosts(input)?;
        let count = parsed.len();
        self.entries.extend(parsed);
        Ok(count)
    }
}

impl KnownHostsStore for MemoryKnownHostsStore {
    /// Returns `true` if `host` is a known host with the provided `key` blob.
    ///
    /// # Constant-time note
    ///
    /// Key blob comparison uses [`russh_crypto::constant_time_eq`] (`subtle::ConstantTimeEq`)
    /// to prevent timing side-channels.
    fn is_known_host(&self, host: &str, key: &[u8]) -> bool {
        let mut positive_match = false;

        for entry in self
            .entries
            .iter()
            .filter(|entry| constant_time_eq(&entry.key, key))
        {
            let (entry_positive, entry_negative) =
                evaluate_host_patterns(&entry.host_patterns, host);
            if entry_negative {
                return false;
            }
            if entry_positive {
                positive_match = true;
            }
        }

        positive_match
    }
}

pub fn parse_authorized_keys(input: &str) -> Result<Vec<AuthorizedKeyEntry>, RusshError> {
    let mut entries = Vec::new();

    for (index, original_line) in input.lines().enumerate() {
        let line_number = index + 1;
        let line = original_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.len() < 2 {
            return Err(RusshError::new(
                RusshErrorCategory::Auth,
                format!("authorized_keys line {line_number}: expected key fields"),
            ));
        }

        let (options, index_offset) = if looks_like_key_algorithm(tokens[0]) {
            (None, 0usize)
        } else {
            (Some(tokens[0].to_string()), 1usize)
        };
        if tokens.len() < index_offset + 2 {
            return Err(RusshError::new(
                RusshErrorCategory::Auth,
                format!("authorized_keys line {line_number}: missing key data"),
            ));
        }

        let algorithm = tokens[index_offset].to_string();
        let key = decode_base64(tokens[index_offset + 1]).map_err(|error| {
            RusshError::new(
                RusshErrorCategory::Auth,
                format!("authorized_keys line {line_number}: {error}"),
            )
        })?;
        let comment = if tokens.len() > index_offset + 2 {
            Some(tokens[index_offset + 2..].join(" "))
        } else {
            None
        };

        entries.push(AuthorizedKeyEntry {
            options,
            algorithm,
            key,
            comment,
        });
    }

    Ok(entries)
}

pub fn parse_known_hosts(input: &str) -> Result<Vec<KnownHostEntry>, RusshError> {
    let mut entries = Vec::new();

    for (index, original_line) in input.lines().enumerate() {
        let line_number = index + 1;
        let line = original_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.len() < 3 {
            return Err(RusshError::new(
                RusshErrorCategory::Auth,
                format!("known_hosts line {line_number}: expected host, algorithm, key"),
            ));
        }

        let (marker, index_offset) = if tokens[0].starts_with('@') {
            (Some(tokens[0].to_string()), 1usize)
        } else {
            (None, 0usize)
        };
        if tokens.len() < index_offset + 3 {
            return Err(RusshError::new(
                RusshErrorCategory::Auth,
                format!("known_hosts line {line_number}: missing key fields"),
            ));
        }

        let host_patterns = tokens[index_offset]
            .split(',')
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
        let algorithm = tokens[index_offset + 1].to_string();
        let key = decode_base64(tokens[index_offset + 2]).map_err(|error| {
            RusshError::new(
                RusshErrorCategory::Auth,
                format!("known_hosts line {line_number}: {error}"),
            )
        })?;
        let comment = if tokens.len() > index_offset + 3 {
            Some(tokens[index_offset + 3..].join(" "))
        } else {
            None
        };

        entries.push(KnownHostEntry {
            marker,
            host_patterns,
            algorithm,
            key,
            comment,
        });
    }

    Ok(entries)
}

/// OpenSSH certificate (`ssh-ed25519-cert-v01@openssh.com`) wire-format model.
///
/// Wire layout (all fields encoded as SSH data types per RFC 4251 §5):
/// ```text
/// string  key_type      "ssh-ed25519-cert-v01@openssh.com"
/// string  nonce
/// string  public_key    (32-byte Ed25519 public key)
/// uint64  serial
/// uint32  cert_type     (1 = user, 2 = host)
/// string  key_id
/// string  valid_principals  (buffer: sequence of SSH strings)
/// uint64  valid_after
/// uint64  valid_before
/// string  critical_options  (buffer: name+data pairs)
/// string  extensions        (buffer: name+data pairs)
/// string  reserved
/// string  ca_public_key     (CA public key blob, e.g. ssh-ed25519 format)
/// string  signature         (CA signature blob)
/// ```
/// `signed_data` = all bytes from the start of the blob through and including
/// the `ca_public_key` field (i.e., everything before `signature`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenSshCertificate {
    /// The certificate key type (e.g. "ssh-ed25519-cert-v01@openssh.com").
    pub cert_key_type: String,
    pub nonce: Vec<u8>,
    /// Embedded public key — format depends on cert_key_type.
    /// Ed25519: raw 32 bytes. RSA: SSH wire-format (string e, string n).
    /// ECDSA: string curve_name, string ec_point.
    pub public_key: Vec<u8>,
    pub serial: u64,
    /// 1 = user certificate, 2 = host certificate.
    pub cert_type: u32,
    pub key_id: String,
    pub principals: Vec<String>,
    pub valid_after_unix: u64,
    pub valid_before_unix: u64,
    pub critical_options: Vec<(String, Vec<u8>)>,
    pub extensions: Vec<(String, Vec<u8>)>,
    /// CA public key blob (SSH wire format).
    pub ca_public_key: Vec<u8>,
    /// CA signature blob (SSH wire format).
    pub signature: Vec<u8>,
    /// The bytes that were signed: cert blob[0..offset_after_ca_public_key].
    pub signed_data: Vec<u8>,
}

impl OpenSshCertificate {
    pub const CERT_TYPE_USER: u32 = 1;
    pub const CERT_TYPE_HOST: u32 = 2;

    /// Parse a certificate from its SSH wire encoding.
    ///
    /// Supports Ed25519, RSA, and ECDSA (P-256, P-384, P-521) cert types.
    pub fn parse(blob: &[u8]) -> Result<Self, RusshError> {
        let mut off = 0;

        // key_type
        let key_type = decode_ssh_string(blob, &mut off)?;
        let cert_key_type = String::from_utf8(key_type.clone()).map_err(|_| {
            RusshError::new(
                RusshErrorCategory::Auth,
                "certificate key type is not valid UTF-8",
            )
        })?;

        // Validate supported cert types
        let supported = [
            "ssh-ed25519-cert-v01@openssh.com",
            "ssh-rsa-cert-v01@openssh.com",
            "ecdsa-sha2-nistp256-cert-v01@openssh.com",
            "ecdsa-sha2-nistp384-cert-v01@openssh.com",
            "ecdsa-sha2-nistp521-cert-v01@openssh.com",
            "rsa-sha2-256-cert-v01@openssh.com",
            "rsa-sha2-512-cert-v01@openssh.com",
        ];
        if !supported.contains(&cert_key_type.as_str()) {
            return Err(RusshError::new(
                RusshErrorCategory::Auth,
                format!("unsupported certificate key type: {cert_key_type}"),
            ));
        }

        // nonce
        let nonce = decode_ssh_string(blob, &mut off)?;

        // Embedded public key — format varies by key type.
        // We capture the raw bytes from the current offset to after reading the
        // key fields so we can re-parse them during verification.
        let public_key = if cert_key_type.starts_with("ssh-ed25519") {
            let pk = decode_ssh_string(blob, &mut off)?;
            if pk.len() != 32 {
                return Err(RusshError::new(
                    RusshErrorCategory::Auth,
                    "certificate Ed25519 public key must be 32 bytes",
                ));
            }
            pk
        } else if cert_key_type.starts_with("ssh-rsa") || cert_key_type.starts_with("rsa-sha2") {
            // RSA: string e, string n
            let e = decode_ssh_string(blob, &mut off)?;
            let n = decode_ssh_string(blob, &mut off)?;
            // Store as SSH wire blob for later reconstruction
            let mut pk = Vec::new();
            pk.extend_from_slice(&encode_ssh_string(&e));
            pk.extend_from_slice(&encode_ssh_string(&n));
            pk
        } else {
            // ECDSA: string curve_name, string ec_point
            let curve = decode_ssh_string(blob, &mut off)?;
            let point = decode_ssh_string(blob, &mut off)?;
            let mut pk = Vec::new();
            pk.extend_from_slice(&encode_ssh_string(&curve));
            pk.extend_from_slice(&encode_ssh_string(&point));
            pk
        };

        // serial (uint64)
        let serial = Self::read_u64(blob, &mut off)?;

        // cert_type (uint32)
        let cert_type = Self::read_u32(blob, &mut off)?;

        // key_id
        let key_id = String::from_utf8(decode_ssh_string(blob, &mut off)?).map_err(|_| {
            RusshError::new(
                RusshErrorCategory::Auth,
                "certificate key_id is not valid UTF-8",
            )
        })?;

        // valid_principals — a buffer of SSH strings
        let principals_buf = decode_ssh_string(blob, &mut off)?;
        let principals = Self::parse_string_list(&principals_buf)?;

        // valid_after / valid_before (uint64)
        let valid_after_unix = Self::read_u64(blob, &mut off)?;
        let valid_before_unix = Self::read_u64(blob, &mut off)?;

        // critical_options — buffer of name+data pairs
        let crit_buf = decode_ssh_string(blob, &mut off)?;
        let critical_options = Self::parse_string_pairs(&crit_buf)?;

        // extensions — buffer of name+data pairs
        let ext_buf = decode_ssh_string(blob, &mut off)?;
        let extensions = Self::parse_string_pairs(&ext_buf)?;

        // reserved (ignore)
        let _ = decode_ssh_string(blob, &mut off)?;

        // CA public key blob
        let ca_public_key = decode_ssh_string(blob, &mut off)?;

        // Signed data = everything from start through the CA key (inclusive).
        let signed_data = blob[..off].to_vec();

        // signature blob
        let signature = decode_ssh_string(blob, &mut off)?;

        Ok(Self {
            cert_key_type,
            nonce,
            public_key,
            serial,
            cert_type,
            key_id,
            principals,
            valid_after_unix,
            valid_before_unix,
            critical_options,
            extensions,
            ca_public_key,
            signature,
            signed_data,
        })
    }

    /// Verify the CA signature over `self.signed_data`.
    ///
    /// Supports Ed25519, RSA, and ECDSA CA keys.
    pub fn verify_ca_signature(&self) -> Result<(), RusshError> {
        // Parse CA key type from the CA public key blob
        let mut ca_off = 0;
        let ca_algo = decode_ssh_string(&self.ca_public_key, &mut ca_off)?;
        let ca_algo_str = std::str::from_utf8(&ca_algo).map_err(|_| {
            RusshError::new(
                RusshErrorCategory::Auth,
                "CA key algorithm is not valid UTF-8",
            )
        })?;

        // Parse signature blob: string(algo) || string(sig_bytes)
        let mut sig_off = 0;
        let _sig_algo = decode_ssh_string(&self.signature, &mut sig_off)?;
        let sig_bytes = decode_ssh_string(&self.signature, &mut sig_off)?;

        match ca_algo_str {
            "ssh-ed25519" => {
                let ca_key_bytes = parse_ed25519_public_key_blob(&self.ca_public_key)?;
                let verifier = Ed25519Verifier::from_bytes(&ca_key_bytes)?;
                verifier.verify(&self.signed_data, &sig_bytes)
            }
            "ssh-rsa" | "rsa-sha2-256" | "rsa-sha2-512" => {
                let verifier = RsaVerifier::from_ssh_blob(&self.ca_public_key)?;
                let verifier = if ca_algo_str == "rsa-sha2-512" {
                    verifier.with_sha512()
                } else {
                    verifier
                };
                verifier.verify(&self.signed_data, &sig_bytes)
            }
            "ecdsa-sha2-nistp256" => {
                let _curve = decode_ssh_string(&self.ca_public_key, &mut ca_off)?;
                let ec_point = decode_ssh_string(&self.ca_public_key, &mut ca_off)?;
                let verifier = EcdsaP256Verifier::from_sec1_bytes(&ec_point)?;
                verifier.verify(&self.signed_data, &sig_bytes)
            }
            "ecdsa-sha2-nistp384" => {
                let _curve = decode_ssh_string(&self.ca_public_key, &mut ca_off)?;
                let ec_point = decode_ssh_string(&self.ca_public_key, &mut ca_off)?;
                let verifier = EcdsaP384Verifier::from_sec1_bytes(&ec_point)?;
                verifier.verify(&self.signed_data, &sig_bytes)
            }
            "ecdsa-sha2-nistp521" => {
                let _curve = decode_ssh_string(&self.ca_public_key, &mut ca_off)?;
                let ec_point = decode_ssh_string(&self.ca_public_key, &mut ca_off)?;
                let verifier = EcdsaP521Verifier::from_sec1_bytes(&ec_point)?;
                verifier.verify(&self.signed_data, &sig_bytes)
            }
            _ => Err(RusshError::new(
                RusshErrorCategory::Auth,
                format!("unsupported CA key algorithm: {ca_algo_str}"),
            )),
        }
    }

    fn read_u64(data: &[u8], offset: &mut usize) -> Result<u64, RusshError> {
        if *offset + 8 > data.len() {
            return Err(RusshError::new(
                RusshErrorCategory::Protocol,
                "buffer too short for uint64",
            ));
        }
        let val = u64::from_be_bytes(data[*offset..*offset + 8].try_into().unwrap());
        *offset += 8;
        Ok(val)
    }

    fn read_u32(data: &[u8], offset: &mut usize) -> Result<u32, RusshError> {
        if *offset + 4 > data.len() {
            return Err(RusshError::new(
                RusshErrorCategory::Protocol,
                "buffer too short for uint32",
            ));
        }
        let val = u32::from_be_bytes(data[*offset..*offset + 4].try_into().unwrap());
        *offset += 4;
        Ok(val)
    }

    /// Parse a buffer containing a sequence of SSH strings into a `Vec<String>`.
    fn parse_string_list(buf: &[u8]) -> Result<Vec<String>, RusshError> {
        let mut list = Vec::new();
        let mut off = 0;
        while off < buf.len() {
            let s = decode_ssh_string(buf, &mut off)?;
            list.push(String::from_utf8(s).map_err(|_| {
                RusshError::new(RusshErrorCategory::Auth, "principal is not valid UTF-8")
            })?);
        }
        Ok(list)
    }

    /// Parse a buffer containing name+data string pairs.
    fn parse_string_pairs(buf: &[u8]) -> Result<Vec<(String, Vec<u8>)>, RusshError> {
        let mut pairs = Vec::new();
        let mut off = 0;
        while off < buf.len() {
            let name_bytes = decode_ssh_string(buf, &mut off)?;
            let name = String::from_utf8(name_bytes).map_err(|_| {
                RusshError::new(
                    RusshErrorCategory::Auth,
                    "cert option name is not valid UTF-8",
                )
            })?;
            let data = decode_ssh_string(buf, &mut off)?;
            pairs.push((name, data));
        }
        Ok(pairs)
    }
}

/// Certificate validator for principal, validity-window, and CA-signature checks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificateValidator {
    pub required_principal: Option<String>,
    /// Trusted CA public key blobs (`string "ssh-ed25519" || string 32_bytes`).
    /// If empty, any CA is accepted (signature is still verified).
    pub trusted_ca_keys: Vec<Vec<u8>>,
}

impl CertificateValidator {
    #[must_use]
    pub fn permissive() -> Self {
        Self {
            required_principal: None,
            trusted_ca_keys: Vec::new(),
        }
    }

    #[must_use]
    pub fn require_principal(principal: impl Into<String>) -> Self {
        Self {
            required_principal: Some(principal.into()),
            trusted_ca_keys: Vec::new(),
        }
    }

    /// Add a trusted CA public key blob to this validator.
    #[must_use]
    pub fn trust_ca_key(mut self, ca_blob: Vec<u8>) -> Self {
        self.trusted_ca_keys.push(ca_blob);
        self
    }

    /// Validate policy only (validity window + principal).
    ///
    /// Does **not** verify the CA signature. Use [`validate_cert`](Self::validate_cert)
    /// for full validation including the cryptographic signature check.
    pub fn validate(&self, cert: &OpenSshCertificate, now: SystemTime) -> Result<(), RusshError> {
        let now_unix = now
            .duration_since(UNIX_EPOCH)
            .map_err(|_| {
                RusshError::new(RusshErrorCategory::Auth, "system time before UNIX_EPOCH")
            })?
            .as_secs();

        if now_unix < cert.valid_after_unix || now_unix > cert.valid_before_unix {
            return Err(RusshError::new(
                RusshErrorCategory::Auth,
                "certificate validity window check failed",
            ));
        }

        if let Some(required) = &self.required_principal {
            let has_principal = cert
                .principals
                .iter()
                .any(|candidate| candidate == required);
            if !has_principal {
                return Err(RusshError::new(
                    RusshErrorCategory::Auth,
                    "required certificate principal missing",
                ));
            }
        }

        Ok(())
    }

    /// Full certificate validation: CA signature + trusted-CA-key check + policy.
    pub fn validate_cert(
        &self,
        cert: &OpenSshCertificate,
        now: SystemTime,
    ) -> Result<(), RusshError> {
        // 1. Verify cryptographic CA signature.
        cert.verify_ca_signature()?;

        // 2. Check that the signing CA key is in our trusted set (if any).
        if !self.trusted_ca_keys.is_empty() {
            let trusted = self
                .trusted_ca_keys
                .iter()
                .any(|ca| ca.as_slice() == cert.ca_public_key.as_slice());
            if !trusted {
                return Err(RusshError::new(
                    RusshErrorCategory::Auth,
                    "certificate was not signed by a trusted CA",
                ));
            }
        }

        // 3. Policy checks (time window + principal).
        self.validate(cert, now)
    }
}

/// Minimal policy engine for first-pass method admission.
#[derive(Clone, Debug)]
pub struct AuthEngine {
    policy: ServerAuthPolicy,
}

impl AuthEngine {
    #[must_use]
    pub fn new(policy: ServerAuthPolicy) -> Self {
        Self { policy }
    }

    /// Access the certificate validator configured in the policy (if any).
    #[must_use]
    pub fn certificate_validator(&self) -> Option<&CertificateValidator> {
        self.policy.certificate_validator.as_ref()
    }

    #[must_use]
    pub fn evaluate(&self, request: &AuthRequest) -> AuthResult {
        self.evaluate_with_event(request).0
    }

    #[must_use]
    pub fn evaluate_with_event(&self, request: &AuthRequest) -> (AuthResult, AuthEvent) {
        let user = request.user();
        let method = request.method();

        if self.policy.allows(method) {
            (
                AuthResult::Accepted,
                AuthEvent::Accepted {
                    user: user.to_string(),
                    method,
                },
            )
        } else {
            let reason = format!("method {:?} disabled by policy", method);
            (
                AuthResult::Rejected {
                    reason: reason.clone(),
                },
                AuthEvent::Rejected {
                    user: user.to_string(),
                    method,
                    reason,
                },
            )
        }
    }
}

/// Stateful authentication session that tracks attempts and optional multi-method completion.
#[derive(Clone, Debug)]
pub struct AuthSession {
    engine: AuthEngine,
    policy: ServerAuthPolicy,
    completed_methods: BTreeSet<AuthMethod>,
    attempts: u8,
    authenticated: bool,
}

impl AuthSession {
    #[must_use]
    pub fn new(policy: ServerAuthPolicy) -> Self {
        Self {
            engine: AuthEngine::new(policy.clone()),
            policy,
            completed_methods: BTreeSet::new(),
            attempts: 0,
            authenticated: false,
        }
    }

    #[must_use]
    pub fn attempts(&self) -> u8 {
        self.attempts
    }

    #[must_use]
    pub fn is_authenticated(&self) -> bool {
        self.authenticated
    }

    #[must_use]
    pub fn completed_methods(&self) -> Vec<AuthMethod> {
        self.completed_methods.iter().copied().collect()
    }

    #[must_use]
    pub fn allowed_methods(&self) -> Vec<AuthMethod> {
        self.policy.allowed_methods()
    }

    /// Access the certificate validator from the policy, if configured.
    #[must_use]
    pub fn certificate_validator(&self) -> Option<&CertificateValidator> {
        self.policy.certificate_validator.as_ref()
    }

    /// Returns `true` if the given public-key blob is authorized for `user`.
    ///
    /// When no authorized-keys store is configured, all cryptographically valid keys
    /// are accepted (permissive mode). With a store configured, only listed keys pass.
    #[must_use]
    pub fn check_authorized_key(&self, user: &str, key_blob: &[u8]) -> bool {
        match &self.policy.authorized_keys {
            Some(store) => store.is_authorized(user, key_blob),
            None => true,
        }
    }

    #[must_use]
    pub fn evaluate(&mut self, request: &AuthRequest) -> AuthResult {
        self.evaluate_with_event(request).0
    }

    #[must_use]
    pub fn evaluate_with_event(&mut self, request: &AuthRequest) -> (AuthResult, AuthEvent) {
        let user = request.user().to_string();
        let method = request.method();

        if self.authenticated {
            let reason = "authentication already completed".to_string();
            return (
                AuthResult::Rejected {
                    reason: reason.clone(),
                },
                AuthEvent::Rejected {
                    user,
                    method,
                    reason,
                },
            );
        }

        if self.attempts >= self.policy.max_attempts {
            let reason = "maximum authentication attempts exceeded".to_string();
            return (
                AuthResult::Rejected {
                    reason: reason.clone(),
                },
                AuthEvent::Rejected {
                    user,
                    method,
                    reason,
                },
            );
        }

        self.attempts = self.attempts.saturating_add(1);
        let (result, event) = self.engine.evaluate_with_event(request);
        match result {
            AuthResult::Accepted => {
                self.completed_methods.insert(method);
                let next_methods = self.remaining_required_methods();
                if next_methods.is_empty() {
                    self.authenticated = true;
                    (AuthResult::Accepted, event)
                } else {
                    (
                        AuthResult::PartiallyAccepted {
                            next_methods: next_methods.clone(),
                        },
                        AuthEvent::PartiallyAccepted {
                            user,
                            completed_methods: self.completed_methods(),
                            next_methods,
                        },
                    )
                }
            }
            AuthResult::Rejected { .. } | AuthResult::PartiallyAccepted { .. } => (result, event),
        }
    }

    fn remaining_required_methods(&self) -> Vec<AuthMethod> {
        if self.policy.required_methods.is_empty() {
            return Vec::new();
        }

        self.policy
            .required_methods
            .difference(&self.completed_methods)
            .copied()
            .collect()
    }
}

/// Parse an SSH Ed25519 public key blob (wire format: string "ssh-ed25519" || string <32 bytes>)
/// and return the 32-byte raw key bytes.
pub fn parse_ed25519_public_key_blob(blob: &[u8]) -> Result<[u8; 32], RusshError> {
    let mut offset = 0;
    let algo = decode_ssh_string(blob, &mut offset)?;
    if algo != b"ssh-ed25519" {
        return Err(RusshError::new(
            RusshErrorCategory::Crypto,
            "expected ssh-ed25519 algorithm in public key blob",
        ));
    }
    let key_bytes = decode_ssh_string(blob, &mut offset)?;
    key_bytes.try_into().map_err(|_| {
        RusshError::new(
            RusshErrorCategory::Crypto,
            "Ed25519 public key must be exactly 32 bytes",
        )
    })
}

/// Parse an SSH Ed25519 signature blob (wire format: string "ssh-ed25519" || string <64 bytes>)
/// and return the 64-byte signature bytes.
pub fn parse_ed25519_signature_blob(blob: &[u8]) -> Result<[u8; 64], RusshError> {
    let mut offset = 0;
    let algo = decode_ssh_string(blob, &mut offset)?;
    if algo != b"ssh-ed25519" {
        return Err(RusshError::new(
            RusshErrorCategory::Crypto,
            "expected ssh-ed25519 algorithm in signature blob",
        ));
    }
    let sig_bytes = decode_ssh_string(blob, &mut offset)?;
    sig_bytes.try_into().map_err(|_| {
        RusshError::new(
            RusshErrorCategory::Crypto,
            "Ed25519 signature must be exactly 64 bytes",
        )
    })
}

/// Build an SSH Ed25519 public key blob: string "ssh-ed25519" || string <32 bytes>
pub fn build_ed25519_public_key_blob(key_bytes: &[u8; 32]) -> Vec<u8> {
    let mut blob = Vec::new();
    blob.extend_from_slice(&encode_ssh_string(b"ssh-ed25519"));
    blob.extend_from_slice(&encode_ssh_string(key_bytes.as_slice()));
    blob
}

/// Build an SSH Ed25519 signature blob: string "ssh-ed25519" || string <64 bytes>
pub fn build_ed25519_signature_blob(sig_bytes: &[u8; 64]) -> Vec<u8> {
    build_signature_blob("ssh-ed25519", sig_bytes.as_slice())
}

/// Build a generic SSH signature blob: string algorithm || string raw_signature
pub fn build_signature_blob(algorithm: &str, sig_bytes: &[u8]) -> Vec<u8> {
    let mut blob = Vec::new();
    blob.extend_from_slice(&encode_ssh_string(algorithm.as_bytes()));
    blob.extend_from_slice(&encode_ssh_string(sig_bytes));
    blob
}

/// Verify a publickey auth signature for SSH_MSG_USERAUTH_REQUEST.
///
/// The signing payload is:
///   string  session_id
///   byte    50 (SSH_MSG_USERAUTH_REQUEST)
///   string  user
///   string  service
///   string  "publickey"
///   boolean true
///   string  algorithm_name
///   string  public_key_blob
pub fn verify_publickey_auth_signature(
    session_id: &[u8],
    user: &str,
    service: &str,
    algorithm: &str,
    public_key_blob: &[u8],
    signature_blob: &[u8],
) -> Result<(), RusshError> {
    let payload =
        build_userauth_signing_payload(session_id, user, service, algorithm, public_key_blob);

    // Parse key type from public key blob
    let mut key_offset = 0;
    let key_type = decode_ssh_string(public_key_blob, &mut key_offset)?;
    let key_type_str = std::str::from_utf8(&key_type).unwrap_or("");

    // Parse signature blob
    let mut sig_offset = 0;
    let _sig_algo = decode_ssh_string(signature_blob, &mut sig_offset)?;
    let sig_bytes = decode_ssh_string(signature_blob, &mut sig_offset)?;

    match key_type_str {
        "ssh-ed25519" => {
            let pubkey_bytes = decode_ssh_string(public_key_blob, &mut key_offset)?;
            let pubkey_arr: [u8; 32] = pubkey_bytes.try_into().map_err(|_| {
                RusshError::new(
                    RusshErrorCategory::Crypto,
                    "Ed25519 public key must be 32 bytes",
                )
            })?;
            let verifier = Ed25519Verifier::from_bytes(&pubkey_arr)?;
            verifier.verify(&payload, &sig_bytes)
        }
        "ecdsa-sha2-nistp256" => {
            let _curve_name = decode_ssh_string(public_key_blob, &mut key_offset)?;
            let ec_point = decode_ssh_string(public_key_blob, &mut key_offset)?;
            let verifier = EcdsaP256Verifier::from_sec1_bytes(&ec_point)?;
            verifier.verify(&payload, &sig_bytes)
        }
        "ecdsa-sha2-nistp384" => {
            let _curve_name = decode_ssh_string(public_key_blob, &mut key_offset)?;
            let ec_point = decode_ssh_string(public_key_blob, &mut key_offset)?;
            let verifier = EcdsaP384Verifier::from_sec1_bytes(&ec_point)?;
            verifier.verify(&payload, &sig_bytes)
        }
        "ecdsa-sha2-nistp521" => {
            let _curve_name = decode_ssh_string(public_key_blob, &mut key_offset)?;
            let ec_point = decode_ssh_string(public_key_blob, &mut key_offset)?;
            let verifier = EcdsaP521Verifier::from_sec1_bytes(&ec_point)?;
            verifier.verify(&payload, &sig_bytes)
        }
        "ssh-rsa" | "rsa-sha2-256" | "rsa-sha2-512" => {
            let verifier = RsaVerifier::from_ssh_blob(public_key_blob)?;
            let verifier = if key_type_str == "rsa-sha2-512" {
                verifier.with_sha512()
            } else {
                verifier
            };
            verifier.verify(&payload, &sig_bytes)
        }
        _ => Err(RusshError::new(
            RusshErrorCategory::Crypto,
            format!("unsupported public key algorithm: {key_type_str}"),
        )),
    }
}

/// Verify the user signature in a certificate-based publickey auth request.
///
/// The signing payload is built with `algorithm` and `cert_blob` as the public key blob.
/// The signature is verified using the embedded public key, dispatching by cert key type.
pub fn verify_cert_auth_signature(
    session_id: &[u8],
    user: &str,
    service: &str,
    algorithm: &str,
    cert_blob: &[u8],
    cert: &OpenSshCertificate,
    signature_blob: &[u8],
) -> Result<(), RusshError> {
    let payload = build_userauth_signing_payload(session_id, user, service, algorithm, cert_blob);

    // Parse signature blob: string(algo) || string(raw_sig)
    let mut sig_off = 0;
    let _sig_algo = decode_ssh_string(signature_blob, &mut sig_off)?;
    let sig_bytes = decode_ssh_string(signature_blob, &mut sig_off)?;

    if cert.cert_key_type.starts_with("ssh-ed25519") {
        let pubkey_arr: [u8; 32] = cert.public_key.as_slice().try_into().map_err(|_| {
            RusshError::new(
                RusshErrorCategory::Auth,
                "Ed25519 cert embedded key must be 32 bytes",
            )
        })?;
        let verifier = Ed25519Verifier::from_bytes(&pubkey_arr)?;
        verifier.verify(&payload, &sig_bytes)
    } else if cert.cert_key_type.starts_with("ssh-rsa")
        || cert.cert_key_type.starts_with("rsa-sha2")
    {
        // Reconstruct SSH wire blob: string("ssh-rsa") || string(e) || string(n)
        let mut rsa_blob = Vec::new();
        rsa_blob.extend_from_slice(&encode_ssh_string(b"ssh-rsa"));
        rsa_blob.extend_from_slice(&cert.public_key);
        let verifier = RsaVerifier::from_ssh_blob(&rsa_blob)?;
        let verifier = if cert.cert_key_type.contains("rsa-sha2-512") {
            verifier.with_sha512()
        } else {
            verifier
        };
        verifier.verify(&payload, &sig_bytes)
    } else if cert.cert_key_type.starts_with("ecdsa-sha2-nistp256") {
        let mut pk_off = 0;
        let _curve = decode_ssh_string(&cert.public_key, &mut pk_off)?;
        let ec_point = decode_ssh_string(&cert.public_key, &mut pk_off)?;
        let verifier = EcdsaP256Verifier::from_sec1_bytes(&ec_point)?;
        verifier.verify(&payload, &sig_bytes)
    } else if cert.cert_key_type.starts_with("ecdsa-sha2-nistp384") {
        let mut pk_off = 0;
        let _curve = decode_ssh_string(&cert.public_key, &mut pk_off)?;
        let ec_point = decode_ssh_string(&cert.public_key, &mut pk_off)?;
        let verifier = EcdsaP384Verifier::from_sec1_bytes(&ec_point)?;
        verifier.verify(&payload, &sig_bytes)
    } else if cert.cert_key_type.starts_with("ecdsa-sha2-nistp521") {
        let mut pk_off = 0;
        let _curve = decode_ssh_string(&cert.public_key, &mut pk_off)?;
        let ec_point = decode_ssh_string(&cert.public_key, &mut pk_off)?;
        let verifier = EcdsaP521Verifier::from_sec1_bytes(&ec_point)?;
        verifier.verify(&payload, &sig_bytes)
    } else {
        Err(RusshError::new(
            RusshErrorCategory::Auth,
            format!(
                "unsupported cert key type for auth: {}",
                cert.cert_key_type
            ),
        ))
    }
}

pub fn build_userauth_signing_payload(
    session_id: &[u8],
    user: &str,
    service: &str,
    algorithm: &str,
    public_key_blob: &[u8],
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&encode_ssh_string(session_id));
    payload.push(50u8); // SSH_MSG_USERAUTH_REQUEST
    payload.extend_from_slice(&encode_ssh_string(user.as_bytes()));
    payload.extend_from_slice(&encode_ssh_string(service.as_bytes()));
    payload.extend_from_slice(&encode_ssh_string(b"publickey"));
    payload.push(1u8); // boolean true
    payload.extend_from_slice(&encode_ssh_string(algorithm.as_bytes()));
    payload.extend_from_slice(&encode_ssh_string(public_key_blob));
    payload
}

fn looks_like_key_algorithm(token: &str) -> bool {
    token.starts_with("ssh-")
        || token.starts_with("ecdsa-")
        || token.starts_with("sk-")
        || token.starts_with("rsa-sha2-")
}

fn evaluate_host_patterns(patterns: &[String], host: &str) -> (bool, bool) {
    let mut positive_match = false;
    let mut negative_match = false;
    for pattern in patterns {
        if pattern.starts_with('|') {
            continue;
        }

        let (negated, value) = if let Some(value) = pattern.strip_prefix('!') {
            (true, value)
        } else {
            (false, pattern.as_str())
        };

        if glob_matches(value, host) {
            if negated {
                negative_match = true;
                continue;
            }
            positive_match = true;
        }
    }

    (positive_match, negative_match)
}

fn glob_matches(pattern: &str, candidate: &str) -> bool {
    let pattern = pattern.as_bytes();
    let candidate = candidate.as_bytes();

    let mut dp = vec![vec![false; candidate.len() + 1]; pattern.len() + 1];
    dp[0][0] = true;

    for i in 1..=pattern.len() {
        if pattern[i - 1] == b'*' {
            dp[i][0] = dp[i - 1][0];
        }
    }

    for i in 1..=pattern.len() {
        for j in 1..=candidate.len() {
            dp[i][j] = match pattern[i - 1] {
                b'*' => dp[i - 1][j] || dp[i][j - 1],
                b'?' => dp[i - 1][j - 1],
                value => value == candidate[j - 1] && dp[i - 1][j - 1],
            };
        }
    }

    dp[pattern.len()][candidate.len()]
}

fn decode_base64(input: &str) -> Result<Vec<u8>, &'static str> {
    let mut values = Vec::new();
    for byte in input.bytes() {
        if byte.is_ascii_whitespace() {
            continue;
        }
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => 26 + (byte - b'a'),
            b'0'..=b'9' => 52 + (byte - b'0'),
            b'+' => 62,
            b'/' => 63,
            b'=' => 64,
            _ => return Err("invalid base64 character"),
        };
        values.push(value);
    }

    if values.is_empty() {
        return Err("base64 payload is empty");
    }
    if values.len() % 4 != 0 {
        return Err("base64 length must be divisible by 4");
    }

    let mut out = Vec::with_capacity(values.len() / 4 * 3);
    let mut saw_padding = false;

    for chunk in values.chunks_exact(4) {
        let a = chunk[0];
        let b = chunk[1];
        let c = chunk[2];
        let d = chunk[3];

        if a == 64 || b == 64 {
            return Err("invalid base64 padding placement");
        }
        if saw_padding && (c != 64 || d != 64) {
            return Err("base64 has data after padding");
        }

        let c_bits = if c == 64 { 0 } else { c };
        let d_bits = if d == 64 { 0 } else { d };
        let block = ((u32::from(a)) << 18)
            | ((u32::from(b)) << 12)
            | ((u32::from(c_bits)) << 6)
            | u32::from(d_bits);

        out.push(((block >> 16) & 0xFF) as u8);
        if c != 64 {
            out.push(((block >> 8) & 0xFF) as u8);
        } else if d != 64 {
            return Err("invalid base64 padding placement");
        }
        if d != 64 {
            out.push((block & 0xFF) as u8);
        }

        if c == 64 || d == 64 {
            saw_padding = true;
        }
    }

    Ok(out)
}

fn write_u32(target: &mut Vec<u8>, value: u32) {
    target.extend_from_slice(&value.to_be_bytes());
}

fn write_bool(target: &mut Vec<u8>, value: bool) {
    target.push(u8::from(value));
}

fn write_string(target: &mut Vec<u8>, value: &str) -> Result<(), RusshError> {
    write_binary_string(target, value.as_bytes())
}

fn write_binary_string(target: &mut Vec<u8>, value: &[u8]) -> Result<(), RusshError> {
    let len = u32::try_from(value.len()).map_err(|_| {
        RusshError::new(
            RusshErrorCategory::Auth,
            "binary string length does not fit in u32",
        )
    })?;
    write_u32(target, len);
    target.extend_from_slice(value);
    Ok(())
}

fn write_name_list(target: &mut Vec<u8>, names: &[String]) -> Result<(), RusshError> {
    write_string(target, &names.join(","))
}

fn read_u32(data: &[u8], offset: &mut usize) -> Result<u32, RusshError> {
    let end = offset.checked_add(4).ok_or_else(|| {
        RusshError::new(RusshErrorCategory::Auth, "u32 read overflow in USERAUTH")
    })?;
    if end > data.len() {
        return Err(RusshError::new(
            RusshErrorCategory::Auth,
            "unexpected EOF while reading USERAUTH u32",
        ));
    }
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&data[*offset..end]);
    *offset = end;
    Ok(u32::from_be_bytes(bytes))
}

fn read_bool(data: &[u8], offset: &mut usize) -> Result<bool, RusshError> {
    let end = offset.checked_add(1).ok_or_else(|| {
        RusshError::new(RusshErrorCategory::Auth, "bool read overflow in USERAUTH")
    })?;
    if end > data.len() {
        return Err(RusshError::new(
            RusshErrorCategory::Auth,
            "unexpected EOF while reading USERAUTH bool",
        ));
    }
    let value = data[*offset];
    *offset = end;
    Ok(value != 0)
}

fn read_binary_string(data: &[u8], offset: &mut usize) -> Result<Vec<u8>, RusshError> {
    let len = usize::try_from(read_u32(data, offset)?).map_err(|_| {
        RusshError::new(
            RusshErrorCategory::Auth,
            "binary string length does not fit in usize",
        )
    })?;
    let end = offset.checked_add(len).ok_or_else(|| {
        RusshError::new(
            RusshErrorCategory::Auth,
            "binary string read overflow in USERAUTH",
        )
    })?;
    if end > data.len() {
        return Err(RusshError::new(
            RusshErrorCategory::Auth,
            "unexpected EOF while reading USERAUTH binary string",
        ));
    }
    let value = data[*offset..end].to_vec();
    *offset = end;
    Ok(value)
}

fn read_string(data: &[u8], offset: &mut usize) -> Result<String, RusshError> {
    let bytes = read_binary_string(data, offset)?;
    String::from_utf8(bytes).map_err(|_| {
        RusshError::new(
            RusshErrorCategory::Auth,
            "USERAUTH string field is not valid UTF-8",
        )
    })
}

fn read_name_list(data: &[u8], offset: &mut usize) -> Result<Vec<String>, RusshError> {
    let joined = read_string(data, offset)?;
    if joined.is_empty() {
        return Ok(Vec::new());
    }
    Ok(joined.split(',').map(ToOwned::to_owned).collect())
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use russh_core::PacketCodec;

    use super::{
        AuthEngine, AuthMethod, AuthRequest, AuthResult, AuthSession, CertificateValidator,
        KnownHostsStore, MemoryAuthorizedKeys, MemoryKnownHostsStore, OpenSshCertificate,
        ServerAuthPolicy, UserAuthMessage, UserAuthRequest, parse_authorized_keys,
    };

    #[test]
    fn policy_accepts_password_by_default() {
        let engine = AuthEngine::new(ServerAuthPolicy::secure_defaults());
        let request = AuthRequest::Password {
            user: "alice".to_string(),
            password: "secret".to_string(),
        };

        assert_eq!(engine.evaluate(&request), AuthResult::Accepted);
    }

    #[test]
    fn certificate_validator_checks_principal_and_time() {
        let cert = OpenSshCertificate {
            cert_key_type: "ssh-ed25519-cert-v01@openssh.com".to_string(),
            nonce: vec![],
            public_key: vec![0u8; 32],
            serial: 1,
            cert_type: OpenSshCertificate::CERT_TYPE_USER,
            key_id: "id-1".to_string(),
            principals: vec!["alice".to_string()],
            valid_after_unix: 100,
            valid_before_unix: 200,
            critical_options: vec![],
            extensions: vec![],
            ca_public_key: vec![],
            signature: vec![],
            signed_data: vec![],
        };

        let validator = CertificateValidator::require_principal("alice");
        let now = UNIX_EPOCH + Duration::from_secs(150);

        validator
            .validate(&cert, now)
            .expect("certificate should be valid");
    }

    #[test]
    fn policy_rejects_required_methods_not_in_allowed_set() {
        let mut policy = ServerAuthPolicy::secure_defaults();
        policy
            .set_allowed_methods([AuthMethod::PublicKey])
            .expect("allowed methods update should succeed");

        let error = policy
            .set_required_methods([AuthMethod::Password])
            .expect_err("required methods outside allowed set must fail");

        assert_eq!(error.category(), russh_core::RusshErrorCategory::Auth);
    }

    #[test]
    fn auth_session_supports_multi_method_partial_acceptance() {
        let mut policy = ServerAuthPolicy::secure_defaults();
        policy
            .set_required_methods([AuthMethod::PublicKey, AuthMethod::KeyboardInteractive])
            .expect("required methods should be accepted");

        let mut session = AuthSession::new(policy);
        let first = session.evaluate(&AuthRequest::PublicKey {
            user: "alice".to_string(),
            public_key: vec![1, 2, 3],
            signature: vec![4, 5, 6],
        });
        assert_eq!(
            first,
            AuthResult::PartiallyAccepted {
                next_methods: vec![AuthMethod::KeyboardInteractive]
            }
        );

        let second = session.evaluate(&AuthRequest::KeyboardInteractive {
            user: "alice".to_string(),
            responses: vec!["123456".to_string()],
        });
        assert_eq!(second, AuthResult::Accepted);
        assert!(session.is_authenticated());
    }

    #[test]
    fn auth_session_enforces_max_attempts() {
        let mut policy = ServerAuthPolicy::secure_defaults();
        policy.max_attempts = 1;
        policy
            .set_allowed_methods([AuthMethod::PublicKey])
            .expect("policy should allow only public key");

        let mut session = AuthSession::new(policy);
        let first = session.evaluate(&AuthRequest::Password {
            user: "alice".to_string(),
            password: "bad".to_string(),
        });
        assert!(matches!(first, AuthResult::Rejected { .. }));

        let second = session.evaluate(&AuthRequest::Password {
            user: "alice".to_string(),
            password: "bad-again".to_string(),
        });
        assert_eq!(
            second,
            AuthResult::Rejected {
                reason: "maximum authentication attempts exceeded".to_string()
            }
        );
    }

    #[test]
    fn userauth_password_round_trip() {
        let codec = PacketCodec::with_defaults();
        let message = UserAuthMessage::Request(UserAuthRequest::Password {
            user: "alice".to_string(),
            service: "ssh-connection".to_string(),
            password: "secret".to_string(),
        });

        let encoded = message.encode(&codec).expect("encode should succeed");
        let decoded = UserAuthMessage::decode(&codec, &encoded).expect("decode should succeed");
        assert_eq!(decoded, message);
    }

    #[test]
    fn userauth_keyboard_interactive_info_request_round_trip() {
        let codec = PacketCodec::with_defaults();
        let message = UserAuthMessage::KeyboardInteractiveInfoRequest {
            name: "duo".to_string(),
            instruction: "enter code".to_string(),
            language_tag: "en-US".to_string(),
            prompts: vec![("code:".to_string(), false)],
        };

        let encoded = message.encode(&codec).expect("encode should succeed");
        let decoded = UserAuthMessage::decode(&codec, &encoded).expect("decode should succeed");
        assert_eq!(decoded, message);
    }

    #[test]
    fn parse_authorized_keys_supports_options() {
        let text = "command=\"echo_hi\" ssh-ed25519 YWJjZA== alice@laptop\n";
        let entries = parse_authorized_keys(text).expect("authorized_keys parse should succeed");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].algorithm, "ssh-ed25519");
        assert_eq!(entries[0].key, b"abcd");
        assert_eq!(entries[0].comment.as_deref(), Some("alice@laptop"));
    }

    #[test]
    fn memory_authorized_keys_and_known_hosts_match() {
        let mut keys = MemoryAuthorizedKeys::new();
        keys.load_authorized_keys("alice", "ssh-ed25519 YWJjZA== alice@host\n")
            .expect("authorized_keys load should succeed");
        assert!(keys.is_authorized("alice", b"abcd"));

        let mut known_hosts = MemoryKnownHostsStore::new();
        known_hosts
            .load_known_hosts(
                "*.example.com ssh-ed25519 YWJjZA==\n!bad.example.com ssh-ed25519 YWJjZA==\n",
            )
            .expect("known_hosts load should succeed");
        assert!(known_hosts.is_known_host("ssh.example.com", b"abcd"));
        assert!(!known_hosts.is_known_host("bad.example.com", b"abcd"));
    }

    #[test]
    fn build_and_parse_ed25519_public_key_blob_roundtrip() {
        use super::{build_ed25519_public_key_blob, parse_ed25519_public_key_blob};
        let raw = [0xABu8; 32];
        let blob = build_ed25519_public_key_blob(&raw);
        let parsed = parse_ed25519_public_key_blob(&blob).expect("should parse valid blob");
        assert_eq!(parsed, raw);
    }

    #[test]
    fn build_and_parse_ed25519_signature_blob_roundtrip() {
        use super::{build_ed25519_signature_blob, parse_ed25519_signature_blob};
        let raw = [0xCDu8; 64];
        let blob = build_ed25519_signature_blob(&raw);
        let parsed = parse_ed25519_signature_blob(&blob).expect("should parse valid blob");
        assert_eq!(parsed, raw);
    }

    #[test]
    fn parse_ed25519_public_key_blob_rejects_wrong_algorithm() {
        use super::parse_ed25519_public_key_blob;
        use russh_crypto::encode_ssh_string;
        let mut bad_blob = Vec::new();
        bad_blob.extend_from_slice(&encode_ssh_string(b"ecdsa-sha2-nistp256"));
        bad_blob.extend_from_slice(&encode_ssh_string(&[0u8; 32]));
        assert!(parse_ed25519_public_key_blob(&bad_blob).is_err());
    }

    #[test]
    fn parse_ed25519_public_key_blob_rejects_wrong_key_length() {
        use super::parse_ed25519_public_key_blob;
        use russh_crypto::encode_ssh_string;
        let mut bad_blob = Vec::new();
        bad_blob.extend_from_slice(&encode_ssh_string(b"ssh-ed25519"));
        bad_blob.extend_from_slice(&encode_ssh_string(&[0u8; 16])); // wrong length
        assert!(parse_ed25519_public_key_blob(&bad_blob).is_err());
    }

    #[test]
    fn verify_publickey_auth_signature_accepts_valid_signature() {
        use russh_crypto::{Ed25519Signer, Signer};

        use super::{
            build_ed25519_signature_blob, build_userauth_signing_payload,
            verify_publickey_auth_signature,
        };

        let signer = Ed25519Signer::from_seed(&[42u8; 32]);
        // public_key_blob() already returns SSH wire format: string "ssh-ed25519" || string <32 bytes>
        let public_key_blob = signer.public_key_blob();

        let session_id = [0xABu8; 32];
        let user = "alice";
        let service = "ssh-connection";
        let algorithm = "ssh-ed25519";

        let payload =
            build_userauth_signing_payload(&session_id, user, service, algorithm, &public_key_blob);
        let sig_raw = signer.sign(&payload).unwrap();
        let sig_bytes: [u8; 64] = sig_raw.try_into().unwrap();
        let signature_blob = build_ed25519_signature_blob(&sig_bytes);

        verify_publickey_auth_signature(
            &session_id,
            user,
            service,
            algorithm,
            &public_key_blob,
            &signature_blob,
        )
        .expect("valid signature should verify");
    }

    #[test]
    fn verify_publickey_auth_signature_rejects_tampered_signature() {
        use russh_crypto::{Ed25519Signer, Signer};

        use super::{
            build_ed25519_signature_blob, build_userauth_signing_payload,
            verify_publickey_auth_signature,
        };

        let signer = Ed25519Signer::from_seed(&[7u8; 32]);
        let public_key_blob = signer.public_key_blob();

        let session_id = [0x11u8; 32];
        let payload = build_userauth_signing_payload(
            &session_id,
            "bob",
            "ssh-connection",
            "ssh-ed25519",
            &public_key_blob,
        );
        let sig_raw = signer.sign(&payload).unwrap();
        let mut sig_bytes: [u8; 64] = sig_raw.try_into().unwrap();
        sig_bytes[0] ^= 0xFF; // tamper
        let signature_blob = build_ed25519_signature_blob(&sig_bytes);

        assert!(
            verify_publickey_auth_signature(
                &session_id,
                "bob",
                "ssh-connection",
                "ssh-ed25519",
                &public_key_blob,
                &signature_blob,
            )
            .is_err()
        );
    }

    #[test]
    fn verify_publickey_auth_signature_rejects_wrong_key() {
        use russh_crypto::{Ed25519Signer, Signer};

        use super::{
            build_ed25519_signature_blob, build_userauth_signing_payload,
            verify_publickey_auth_signature,
        };

        let signer1 = Ed25519Signer::from_seed(&[1u8; 32]);
        let signer2 = Ed25519Signer::from_seed(&[2u8; 32]);
        // present signer1's public key blob
        let public_key_blob = signer1.public_key_blob();

        let session_id = [0x22u8; 32];
        let payload = build_userauth_signing_payload(
            &session_id,
            "carol",
            "ssh-connection",
            "ssh-ed25519",
            &public_key_blob,
        );
        // signed with signer2 but presenting key1
        let sig_raw = signer2.sign(&payload).unwrap();
        let sig_bytes: [u8; 64] = sig_raw.try_into().unwrap();
        let signature_blob = build_ed25519_signature_blob(&sig_bytes);

        assert!(
            verify_publickey_auth_signature(
                &session_id,
                "carol",
                "ssh-connection",
                "ssh-ed25519",
                &public_key_blob,
                &signature_blob,
            )
            .is_err()
        );
    }

    #[test]
    fn parse_pub_file_blob_parses_openssh_pub_format() {
        use super::parse_pub_file_blob;
        // A simple base64 payload (b"abcd" = YWJjZA==)
        let content = "ssh-ed25519 YWJjZA== alice@host\n";
        let blob = parse_pub_file_blob(content).expect("should parse valid .pub line");
        assert_eq!(blob, b"abcd");
    }

    #[test]
    fn parse_pub_file_blob_skips_comments() {
        use super::parse_pub_file_blob;
        let _content = "# this is a comment\nssh-ed25519 YWJjZA==\n";
        // first line is a comment, so parse returns None for first line
        assert!(parse_pub_file_blob("# comment\n").is_none());
    }

    #[test]
    fn file_identity_provider_with_default_paths_does_not_panic() {
        use super::FileIdentityProvider;
        use crate::IdentityProvider;
        let provider = FileIdentityProvider::with_default_paths();
        // should not panic even if ~/.ssh/ doesn't exist
        let _ = provider.identities_for_user("alice");
    }

    /// Build a minimal but valid `ssh-ed25519-cert-v01@openssh.com` blob signed
    /// by `ca_signer`, with the given parameters.
    #[cfg(test)]
    fn build_test_cert(
        user_pub_key: &[u8; 32],
        ca_signer: &russh_crypto::Ed25519Signer,
        key_id: &str,
        principals: &[&str],
        valid_after: u64,
        valid_before: u64,
    ) -> Vec<u8> {
        use russh_crypto::{Signer, encode_ssh_string};

        let mut blob = Vec::new();

        // key_type
        blob.extend_from_slice(&encode_ssh_string(b"ssh-ed25519-cert-v01@openssh.com"));

        // nonce (32 zero bytes)
        blob.extend_from_slice(&encode_ssh_string(&[0u8; 32]));

        // ed25519 public key (32 bytes)
        blob.extend_from_slice(&encode_ssh_string(user_pub_key.as_ref()));

        // serial (uint64)
        blob.extend_from_slice(&1u64.to_be_bytes());

        // cert_type user=1 (uint32)
        blob.extend_from_slice(&1u32.to_be_bytes());

        // key_id
        blob.extend_from_slice(&encode_ssh_string(key_id.as_bytes()));

        // valid_principals buffer: each principal as an SSH string
        let mut principals_buf = Vec::new();
        for p in principals {
            principals_buf.extend_from_slice(&encode_ssh_string(p.as_bytes()));
        }
        blob.extend_from_slice(&encode_ssh_string(&principals_buf));

        // valid_after / valid_before (uint64)
        blob.extend_from_slice(&valid_after.to_be_bytes());
        blob.extend_from_slice(&valid_before.to_be_bytes());

        // critical_options (empty buffer)
        blob.extend_from_slice(&encode_ssh_string(&[]));

        // extensions (empty buffer)
        blob.extend_from_slice(&encode_ssh_string(&[]));

        // reserved (empty string)
        blob.extend_from_slice(&encode_ssh_string(&[]));

        // signature_key = CA public key blob
        blob.extend_from_slice(&encode_ssh_string(&ca_signer.public_key_blob()));

        // signed_data ends here
        let signed_data = blob.clone();

        // Compute CA signature over signed_data
        let sig_raw = ca_signer.sign(&signed_data).expect("sign should succeed");
        let sig_64: [u8; 64] = sig_raw.try_into().unwrap();
        let sig_blob = super::build_ed25519_signature_blob(&sig_64);
        blob.extend_from_slice(&encode_ssh_string(&sig_blob));

        blob
    }

    #[test]
    fn openssh_cert_parse_and_verify_ca_signature() {
        use russh_crypto::{Ed25519Signer, Signer};
        use std::time::Duration;
        use std::time::UNIX_EPOCH;

        let ca = Ed25519Signer::from_seed(&[0xCAu8; 32]);
        let user_key = Ed25519Signer::from_seed(&[0xBBu8; 32]);
        let user_pub: [u8; 32] =
            super::parse_ed25519_public_key_blob(&user_key.public_key_blob()).unwrap();

        let blob = build_test_cert(&user_pub, &ca, "test-cert", &["alice"], 100, u64::MAX);

        let cert = OpenSshCertificate::parse(&blob).expect("cert should parse");
        assert_eq!(cert.key_id, "test-cert");
        assert_eq!(cert.principals, ["alice"]);
        assert_eq!(cert.cert_type, OpenSshCertificate::CERT_TYPE_USER);
        cert.verify_ca_signature()
            .expect("CA signature should verify");

        // Validator: trust the CA key, require principal "alice"
        let validator =
            CertificateValidator::require_principal("alice").trust_ca_key(ca.public_key_blob());
        let now = UNIX_EPOCH + Duration::from_secs(200);
        validator
            .validate_cert(&cert, now)
            .expect("full validation should pass");
    }

    #[test]
    fn openssh_cert_validator_rejects_unknown_ca() {
        use russh_crypto::{Ed25519Signer, Signer};
        use std::time::Duration;
        use std::time::UNIX_EPOCH;

        let ca = Ed25519Signer::from_seed(&[0xCAu8; 32]);
        let other_ca = Ed25519Signer::from_seed(&[0xCCu8; 32]); // different CA
        let user_key = Ed25519Signer::from_seed(&[0xBBu8; 32]);
        let user_pub: [u8; 32] =
            super::parse_ed25519_public_key_blob(&user_key.public_key_blob()).unwrap();

        let blob = build_test_cert(&user_pub, &ca, "id", &["bob"], 0, u64::MAX);
        let cert = OpenSshCertificate::parse(&blob).expect("parse");

        // Validator only trusts the other CA
        let validator = CertificateValidator::permissive().trust_ca_key(other_ca.public_key_blob());
        let now = UNIX_EPOCH + Duration::from_secs(1);
        let err = validator
            .validate_cert(&cert, now)
            .expect_err("unknown CA should fail");
        assert!(
            err.message().contains("trusted CA"),
            "err={}",
            err.message()
        );
    }

    #[test]
    fn openssh_cert_parse_rejects_tampered_data() {
        use russh_crypto::{Ed25519Signer, Signer};

        let ca = Ed25519Signer::from_seed(&[0xCAu8; 32]);
        let user_key = Ed25519Signer::from_seed(&[0xBBu8; 32]);
        let user_pub: [u8; 32] =
            super::parse_ed25519_public_key_blob(&user_key.public_key_blob()).unwrap();

        let mut blob = build_test_cert(&user_pub, &ca, "id", &["alice"], 0, u64::MAX);

        // Flip a byte in the middle of the blob (inside the signed region)
        let mid = blob.len() / 2;
        blob[mid] ^= 0xFF;

        let cert = OpenSshCertificate::parse(&blob).expect("should still parse");
        cert.verify_ca_signature()
            .expect_err("tampered cert should fail signature verification");
    }

    #[test]
    fn auth_method_from_ssh_name_known() {
        assert_eq!(
            AuthMethod::from_ssh_name("publickey"),
            Some(AuthMethod::PublicKey)
        );
        assert_eq!(
            AuthMethod::from_ssh_name("password"),
            Some(AuthMethod::Password)
        );
        assert_eq!(
            AuthMethod::from_ssh_name("keyboard-interactive"),
            Some(AuthMethod::KeyboardInteractive)
        );
    }

    #[test]
    fn auth_method_from_ssh_name_unknown() {
        assert_eq!(AuthMethod::from_ssh_name("gssapi-with-mic"), None);
        assert_eq!(AuthMethod::from_ssh_name(""), None);
    }

    #[test]
    fn auth_method_round_trips() {
        for method in [
            AuthMethod::PublicKey,
            AuthMethod::Password,
            AuthMethod::KeyboardInteractive,
        ] {
            assert_eq!(
                AuthMethod::from_ssh_name(method.as_ssh_name()),
                Some(method)
            );
        }
    }
}
