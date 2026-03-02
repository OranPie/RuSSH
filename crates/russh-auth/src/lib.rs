//! Authentication types and policy for RuSSH.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{SystemTime, UNIX_EPOCH};

use russh_core::{PacketCodec, PacketFrame, RusshError, RusshErrorCategory};
use russh_crypto::constant_time_eq;

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
        }
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
#[derive(Clone, Debug, Default)]
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

    #[must_use]
    pub fn is_authorized(&self, user: &str, key: &[u8]) -> bool {
        self.entries.get(user).is_some_and(|entries| {
            entries
                .iter()
                .any(|entry| constant_time_eq(&entry.key, key))
        })
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

/// Minimal OpenSSH certificate model for policy validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenSshCertificate {
    pub key_id: String,
    pub principals: Vec<String>,
    pub valid_after_unix: u64,
    pub valid_before_unix: u64,
}

/// Certificate validator for principal + validity checks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificateValidator {
    pub required_principal: Option<String>,
}

impl CertificateValidator {
    #[must_use]
    pub fn permissive() -> Self {
        Self {
            required_principal: None,
        }
    }

    #[must_use]
    pub fn require_principal(principal: impl Into<String>) -> Self {
        Self {
            required_principal: Some(principal.into()),
        }
    }

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
            key_id: "id-1".to_string(),
            principals: vec!["alice".to_string()],
            valid_after_unix: 100,
            valid_before_unix: 200,
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
}
