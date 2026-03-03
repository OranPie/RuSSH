//! SSH transport-layer state machine for RuSSH.
//!
//! This crate implements the full RFC 4253 connection setup sequence:
//!
//! 1. **Version exchange** — `SSH-2.0-RuSSH_0.1` banner sent/received.
//! 2. **Algorithm negotiation** — `SSH_MSG_KEXINIT` (20) with secure-default
//!    algorithm lists; strict-KEX extension supported.
//! 3. **Key exchange** — Curve25519-SHA256 ECDH (`SSH_MSG_KEX_ECDH_INIT` 30 /
//!    `SSH_MSG_KEX_ECDH_REPLY` 31); exchange hash; `SSH_MSG_NEWKEYS` (21).
//! 4. **Host key verification** — Ed25519 signature over exchange hash;
//!    `KnownHostsStore` checked before accepting.
//! 5. **Service / auth dispatch** — `SSH_MSG_SERVICE_REQUEST` (5) accepted,
//!    `SSH_MSG_USERAUTH_REQUEST` (50) dispatched to auth layer.
//! 6. **Re-key** — triggered by byte count or time thresholds.
//!
//! ## Session keys
//!
//! After KEX, six key derivation labels (A–F) produce IVs and encryption keys
//! for each direction per RFC 4253 §7.2. Keys are stored in [`SessionKeys`]
//! and zeroized on drop via `ZeroizeOnDrop`.
//!
//! ## Structures
//!
//! - [`ClientSession`] — client-side state machine.
//! - [`ServerSession`] — server-side state machine.
//! - [`ServerConfig`] — server configuration including optional host key seed.
//! - [`KexContext`] — ephemeral state held during key exchange.
//! - [`SessionKeys`] — derived encryption keys, zeroized on drop.

use std::future::ready;
use std::time::Duration;

use russh_auth::{
    AuthMethod, AuthRequest, AuthResult, AuthSession, OpenSshCertificate, ServerAuthPolicy,
    UserAuthMessage, UserAuthRequest, verify_cert_auth_signature, verify_publickey_auth_signature,
};
use russh_core::{AlgorithmSet, PacketCodec, PacketFrame, RusshError, RusshErrorCategory};
use russh_crypto::{
    CryptoPolicy, Curve25519Sha256, Ed25519Signer, Ed25519Verifier, HashAlgorithm,
    KeyExchangeAlgorithm, OsRng, Sha256, Signer, Verifier, decode_ssh_string, derive_key_sha256,
    encode_mpint, encode_ssh_string,
};

const SSH_USERAUTH_SERVICE: &str = "ssh-userauth";
const SSH_CONNECTION_SERVICE: &str = "ssh-connection";
const CERT_ALGORITHM_ED25519: &str = "ssh-ed25519-cert-v01@openssh.com";

/// Shared transport knobs with secure defaults.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportConfig {
    pub rekey_after_bytes: u64,
    pub rekey_after_duration: Duration,
    pub idle_timeout: Duration,
    pub keepalive_interval: Duration,
    pub policy: CryptoPolicy,
}

impl TransportConfig {
    #[must_use]
    pub fn builder() -> TransportConfigBuilder {
        TransportConfigBuilder::default()
    }
}

#[derive(Clone, Debug)]
pub struct TransportConfigBuilder {
    rekey_after_bytes: u64,
    rekey_after_duration: Duration,
    idle_timeout: Duration,
    keepalive_interval: Duration,
    policy: CryptoPolicy,
}

impl Default for TransportConfigBuilder {
    fn default() -> Self {
        Self {
            rekey_after_bytes: 1 << 30,
            rekey_after_duration: Duration::from_secs(60 * 60),
            idle_timeout: Duration::from_secs(300),
            keepalive_interval: Duration::from_secs(30),
            policy: CryptoPolicy::secure_defaults(),
        }
    }
}

impl TransportConfigBuilder {
    #[must_use]
    pub fn rekey_after_bytes(mut self, bytes: u64) -> Self {
        self.rekey_after_bytes = bytes;
        self
    }

    #[must_use]
    pub fn rekey_after_duration(mut self, duration: Duration) -> Self {
        self.rekey_after_duration = duration;
        self
    }

    #[must_use]
    pub fn idle_timeout(mut self, timeout: Duration) -> Self {
        self.idle_timeout = timeout;
        self
    }

    #[must_use]
    pub fn keepalive_interval(mut self, interval: Duration) -> Self {
        self.keepalive_interval = interval;
        self
    }

    #[must_use]
    pub fn policy(mut self, policy: CryptoPolicy) -> Self {
        self.policy = policy;
        self
    }

    #[must_use]
    pub fn build(self) -> TransportConfig {
        TransportConfig {
            rekey_after_bytes: self.rekey_after_bytes,
            rekey_after_duration: self.rekey_after_duration,
            idle_timeout: self.idle_timeout,
            keepalive_interval: self.keepalive_interval,
            policy: self.policy,
        }
    }
}

/// Client-side session configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientConfig {
    pub transport: TransportConfig,
    pub user: String,
    pub strict_host_key_checking: bool,
}

impl ClientConfig {
    #[must_use]
    pub fn secure_defaults(user: impl Into<String>) -> Self {
        Self {
            transport: TransportConfig::builder().build(),
            user: user.into(),
            strict_host_key_checking: true,
        }
    }
}

/// Server-side session configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerConfig {
    pub transport: TransportConfig,
    pub max_sessions_per_connection: u16,
    pub permit_password_auth: bool,
    pub host_key_seed: Option<[u8; 32]>,
    /// Override the default auth policy (e.g. to configure a certificate validator).
    /// When `None`, `ServerAuthPolicy::secure_defaults()` is used.
    pub auth_policy: Option<ServerAuthPolicy>,
}

impl ServerConfig {
    #[must_use]
    pub fn secure_defaults() -> Self {
        Self {
            transport: TransportConfig::builder().build(),
            max_sessions_per_connection: 64,
            permit_password_auth: true,
            host_key_seed: None,
            auth_policy: None,
        }
    }
}

/// Holds ongoing key exchange state.
#[derive(Clone, Debug)]
struct KexContext {
    local_version: String,
    remote_version: String,
    local_kexinit_payload: Vec<u8>,
    remote_kexinit_payload: Vec<u8>,
    ephemeral_private_key: Vec<u8>,
    ephemeral_public_key: Vec<u8>,
}

/// Derived SSH session keys (RFC 4253 §7.2).
///
/// All key and IV fields are zeroized from memory when this value is dropped.
#[derive(Clone, Debug, zeroize::ZeroizeOnDrop)]
pub struct SessionKeys {
    pub session_id: Vec<u8>,
    pub iv_c2s: Vec<u8>,
    pub iv_s2c: Vec<u8>,
    pub key_c2s: Vec<u8>,
    pub key_s2c: Vec<u8>,
    pub mac_key_c2s: Vec<u8>,
    pub mac_key_s2c: Vec<u8>,
}

/// Peer information used during handshake/negotiation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerDescription {
    pub banner: String,
    pub algorithms: AlgorithmSet,
}

impl PeerDescription {
    #[must_use]
    pub fn openssh_like(banner: impl Into<String>) -> Self {
        Self {
            banner: banner.into(),
            algorithms: AlgorithmSet::secure_defaults(),
        }
    }
}

/// Final algorithm choices selected during key exchange.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NegotiatedAlgorithms {
    pub kex: String,
    pub host_key: String,
    pub cipher_client_to_server: String,
    pub cipher_server_to_client: String,
    pub mac_client_to_server: String,
    pub mac_server_to_client: String,
    pub compression_client_to_server: String,
    pub compression_server_to_client: String,
    pub strict_kex: bool,
    pub ext_info_c: bool,
    pub ext_info_s: bool,
}

/// KEXINIT proposal payload (simplified RFC 4253 representation).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KexInitProposal {
    pub cookie: [u8; 16],
    pub kex_algorithms: Vec<String>,
    pub host_key_algorithms: Vec<String>,
    pub ciphers_client_to_server: Vec<String>,
    pub ciphers_server_to_client: Vec<String>,
    pub macs_client_to_server: Vec<String>,
    pub macs_server_to_client: Vec<String>,
    pub compression_client_to_server: Vec<String>,
    pub compression_server_to_client: Vec<String>,
    pub languages_client_to_server: Vec<String>,
    pub languages_server_to_client: Vec<String>,
    pub first_kex_packet_follows: bool,
    pub ext_info_c: bool,
    pub ext_info_s: bool,
    pub strict_kex_c: bool,
    pub strict_kex_s: bool,
}

impl KexInitProposal {
    #[must_use]
    pub fn from_algorithms(cookie: [u8; 16], algorithms: AlgorithmSet) -> Self {
        Self {
            cookie,
            kex_algorithms: algorithms.kex,
            host_key_algorithms: algorithms.host_key,
            ciphers_client_to_server: algorithms.ciphers.clone(),
            ciphers_server_to_client: algorithms.ciphers,
            macs_client_to_server: algorithms.macs.clone(),
            macs_server_to_client: algorithms.macs,
            compression_client_to_server: vec!["none".to_string()],
            compression_server_to_client: vec!["none".to_string()],
            languages_client_to_server: Vec::new(),
            languages_server_to_client: Vec::new(),
            first_kex_packet_follows: false,
            ext_info_c: false,
            ext_info_s: false,
            strict_kex_c: false,
            strict_kex_s: false,
        }
    }

    #[must_use]
    pub fn with_client_extensions(mut self) -> Self {
        self.ext_info_c = true;
        self.strict_kex_c = true;
        self
    }

    #[must_use]
    pub fn with_server_extensions(mut self) -> Self {
        self.ext_info_s = true;
        self.strict_kex_s = true;
        self
    }

    fn effective_kex_algorithms(&self) -> Vec<String> {
        let mut kex = self.kex_algorithms.clone();
        maybe_push_extension(&mut kex, self.ext_info_c, "ext-info-c");
        maybe_push_extension(&mut kex, self.ext_info_s, "ext-info-s");
        maybe_push_extension(&mut kex, self.strict_kex_c, "kex-strict-c-v00@openssh.com");
        maybe_push_extension(&mut kex, self.strict_kex_s, "kex-strict-s-v00@openssh.com");
        kex
    }
}

/// Minimal transport message model for stateful protocol handling.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransportMessage {
    KexInit {
        proposal: Box<KexInitProposal>,
    },
    NewKeys,
    ExtInfo {
        extensions: Vec<(String, String)>,
    },
    ServiceRequest {
        service: String,
    },
    ServiceAccept {
        service: String,
    },
    Ignore {
        data: Vec<u8>,
    },
    Disconnect {
        code: DisconnectReasonCode,
        reason: String,
    },
    /// SSH_MSG_UNIMPLEMENTED (message type 3)
    Unimplemented {
        sequence_number: u32,
    },
    /// SSH_MSG_KEX_ECDH_INIT (message type 30)
    KexEcdhInit {
        client_pubkey: Vec<u8>,
    },
    /// SSH_MSG_KEX_ECDH_REPLY (message type 31)
    KexEcdhReply {
        server_host_key_blob: Vec<u8>,
        server_pubkey: Vec<u8>,
        signature: Vec<u8>,
    },
    Unknown {
        message_type: u8,
        payload: Vec<u8>,
    },
}

/// Disconnect reason code values aligned with SSH transport semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DisconnectReasonCode {
    HostNotAllowedToConnect,
    ProtocolError,
    KeyExchangeFailed,
    ByApplication,
}

impl DisconnectReasonCode {
    #[must_use]
    fn to_wire(self) -> u32 {
        match self {
            Self::HostNotAllowedToConnect => 1,
            Self::ProtocolError => 2,
            Self::KeyExchangeFailed => 3,
            Self::ByApplication => 11,
        }
    }

    #[must_use]
    fn from_wire(value: u32) -> Option<Self> {
        match value {
            1 => Some(Self::HostNotAllowedToConnect),
            2 => Some(Self::ProtocolError),
            3 => Some(Self::KeyExchangeFailed),
            11 => Some(Self::ByApplication),
            _ => None,
        }
    }
}

impl TransportMessage {
    const MSG_DISCONNECT: u8 = 1;
    const MSG_IGNORE: u8 = 2;
    const MSG_SERVICE_REQUEST: u8 = 5;
    const MSG_SERVICE_ACCEPT: u8 = 6;
    const MSG_EXT_INFO: u8 = 7;
    const MSG_KEXINIT: u8 = 20;
    const MSG_NEWKEYS: u8 = 21;
    const MSG_UNIMPLEMENTED: u8 = 3;
    const MSG_KEX_ECDH_INIT: u8 = 30;
    const MSG_KEX_ECDH_REPLY: u8 = 31;

    pub fn to_frame(&self) -> Result<PacketFrame, RusshError> {
        let mut payload = Vec::new();

        match self {
            Self::KexInit { proposal } => {
                payload.push(Self::MSG_KEXINIT);
                payload.extend_from_slice(&proposal.cookie);
                write_name_list(&mut payload, &proposal.effective_kex_algorithms())?;
                write_name_list(&mut payload, &proposal.host_key_algorithms)?;
                write_name_list(&mut payload, &proposal.ciphers_client_to_server)?;
                write_name_list(&mut payload, &proposal.ciphers_server_to_client)?;
                write_name_list(&mut payload, &proposal.macs_client_to_server)?;
                write_name_list(&mut payload, &proposal.macs_server_to_client)?;
                write_name_list(&mut payload, &proposal.compression_client_to_server)?;
                write_name_list(&mut payload, &proposal.compression_server_to_client)?;
                write_name_list(&mut payload, &proposal.languages_client_to_server)?;
                write_name_list(&mut payload, &proposal.languages_server_to_client)?;
                write_bool(&mut payload, proposal.first_kex_packet_follows);
                write_u32(&mut payload, 0);
            }
            Self::NewKeys => payload.push(Self::MSG_NEWKEYS),
            Self::ExtInfo { extensions } => {
                payload.push(Self::MSG_EXT_INFO);
                write_u32(
                    &mut payload,
                    u32::try_from(extensions.len()).map_err(|_| {
                        RusshError::new(
                            RusshErrorCategory::Protocol,
                            "EXT_INFO entry count does not fit in u32",
                        )
                    })?,
                );
                for (name, value) in extensions {
                    write_ssh_string(&mut payload, name)?;
                    write_ssh_string(&mut payload, value)?;
                }
            }
            Self::ServiceRequest { service } => {
                payload.push(Self::MSG_SERVICE_REQUEST);
                write_ssh_string(&mut payload, service)?;
            }
            Self::ServiceAccept { service } => {
                payload.push(Self::MSG_SERVICE_ACCEPT);
                write_ssh_string(&mut payload, service)?;
            }
            Self::Ignore { data } => {
                payload.push(Self::MSG_IGNORE);
                payload.extend_from_slice(data);
            }
            Self::Disconnect { code, reason } => {
                payload.push(Self::MSG_DISCONNECT);
                write_u32(&mut payload, code.to_wire());
                write_ssh_string(&mut payload, reason)?;
            }
            Self::Unimplemented { sequence_number } => {
                payload.push(Self::MSG_UNIMPLEMENTED);
                write_u32(&mut payload, *sequence_number);
            }
            Self::KexEcdhInit { client_pubkey } => {
                payload.push(Self::MSG_KEX_ECDH_INIT);
                write_ssh_bytes(&mut payload, client_pubkey);
            }
            Self::KexEcdhReply {
                server_host_key_blob,
                server_pubkey,
                signature,
            } => {
                payload.push(Self::MSG_KEX_ECDH_REPLY);
                write_ssh_bytes(&mut payload, server_host_key_blob);
                write_ssh_bytes(&mut payload, server_pubkey);
                write_ssh_bytes(&mut payload, signature);
            }
            Self::Unknown {
                message_type,
                payload: body,
            } => {
                payload.push(*message_type);
                payload.extend_from_slice(body);
            }
        }

        Ok(PacketFrame::new(payload))
    }

    pub fn from_frame(frame: &PacketFrame) -> Result<Self, RusshError> {
        let message_type = *frame.payload.first().ok_or_else(|| {
            RusshError::new(
                RusshErrorCategory::Protocol,
                "transport message payload is empty",
            )
        })?;
        let body = &frame.payload[1..];

        match message_type {
            Self::MSG_KEXINIT => {
                if body.len() < 16 {
                    return Err(RusshError::new(
                        RusshErrorCategory::Protocol,
                        "KEXINIT payload too short",
                    ));
                }
                let mut offset = 0usize;
                let mut cookie = [0u8; 16];
                cookie.copy_from_slice(&body[offset..offset + 16]);
                offset += 16;

                let kex_wire = read_name_list(body, &mut offset)?;
                let (kex_algorithms, ext_info_c, ext_info_s, strict_kex_c, strict_kex_s) =
                    parse_kex_with_extensions(kex_wire);
                let host_key_algorithms = read_name_list(body, &mut offset)?;
                let ciphers_client_to_server = read_name_list(body, &mut offset)?;
                let ciphers_server_to_client = read_name_list(body, &mut offset)?;
                let macs_client_to_server = read_name_list(body, &mut offset)?;
                let macs_server_to_client = read_name_list(body, &mut offset)?;
                let compression_client_to_server = read_name_list(body, &mut offset)?;
                let compression_server_to_client = read_name_list(body, &mut offset)?;
                let languages_client_to_server = read_name_list(body, &mut offset)?;
                let languages_server_to_client = read_name_list(body, &mut offset)?;
                let first_kex_packet_follows = read_bool(body, &mut offset)?;
                let _reserved = read_u32(body, &mut offset)?;

                if offset != body.len() {
                    return Err(RusshError::new(
                        RusshErrorCategory::Protocol,
                        "KEXINIT has trailing bytes",
                    ));
                }

                let proposal = KexInitProposal {
                    cookie,
                    kex_algorithms,
                    host_key_algorithms,
                    ciphers_client_to_server,
                    ciphers_server_to_client,
                    macs_client_to_server,
                    macs_server_to_client,
                    compression_client_to_server,
                    compression_server_to_client,
                    languages_client_to_server,
                    languages_server_to_client,
                    first_kex_packet_follows,
                    ext_info_c,
                    ext_info_s,
                    strict_kex_c,
                    strict_kex_s,
                };
                validate_kexinit_proposal(&proposal)?;

                Ok(Self::KexInit {
                    proposal: Box::new(proposal),
                })
            }
            Self::MSG_NEWKEYS => {
                if !body.is_empty() {
                    return Err(RusshError::new(
                        RusshErrorCategory::Protocol,
                        "NEWKEYS payload must be empty",
                    ));
                }
                Ok(Self::NewKeys)
            }
            Self::MSG_EXT_INFO => {
                let mut offset = 0usize;
                let extension_count =
                    usize::try_from(read_u32(body, &mut offset)?).map_err(|_| {
                        RusshError::new(
                            RusshErrorCategory::Protocol,
                            "EXT_INFO entry count does not fit usize",
                        )
                    })?;
                let mut extensions = Vec::with_capacity(extension_count);
                for _ in 0..extension_count {
                    let name = read_ssh_string(body, &mut offset)?;
                    let value = read_ssh_string(body, &mut offset)?;
                    extensions.push((name, value));
                }
                if offset != body.len() {
                    return Err(RusshError::new(
                        RusshErrorCategory::Protocol,
                        "EXT_INFO has trailing bytes",
                    ));
                }
                Ok(Self::ExtInfo { extensions })
            }
            Self::MSG_SERVICE_REQUEST => {
                let mut offset = 0usize;
                let service = read_ssh_string(body, &mut offset)?;
                if offset != body.len() {
                    return Err(RusshError::new(
                        RusshErrorCategory::Protocol,
                        "SERVICE_REQUEST has trailing bytes",
                    ));
                }
                Ok(Self::ServiceRequest { service })
            }
            Self::MSG_SERVICE_ACCEPT => {
                let mut offset = 0usize;
                let service = read_ssh_string(body, &mut offset)?;
                if offset != body.len() {
                    return Err(RusshError::new(
                        RusshErrorCategory::Protocol,
                        "SERVICE_ACCEPT has trailing bytes",
                    ));
                }
                Ok(Self::ServiceAccept { service })
            }
            Self::MSG_DISCONNECT => {
                let mut offset = 0usize;
                let code_wire = read_u32(body, &mut offset)?;
                let code = DisconnectReasonCode::from_wire(code_wire).ok_or_else(|| {
                    RusshError::new(
                        RusshErrorCategory::Protocol,
                        "DISCONNECT reason code is not recognized",
                    )
                })?;
                let reason = read_ssh_string(body, &mut offset)?;
                if offset != body.len() {
                    return Err(RusshError::new(
                        RusshErrorCategory::Protocol,
                        "DISCONNECT has trailing bytes",
                    ));
                }
                Ok(Self::Disconnect { code, reason })
            }
            Self::MSG_IGNORE => Ok(Self::Ignore {
                data: body.to_vec(),
            }),
            Self::MSG_UNIMPLEMENTED => {
                let mut offset = 0;
                let sequence_number = read_u32(body, &mut offset)?;
                Ok(Self::Unimplemented { sequence_number })
            }
            Self::MSG_KEX_ECDH_INIT => {
                let mut offset = 0;
                let client_pubkey = read_ssh_bytes(body, &mut offset)?;
                Ok(Self::KexEcdhInit { client_pubkey })
            }
            Self::MSG_KEX_ECDH_REPLY => {
                let mut offset = 0;
                let server_host_key_blob = read_ssh_bytes(body, &mut offset)?;
                let server_pubkey = read_ssh_bytes(body, &mut offset)?;
                let signature = read_ssh_bytes(body, &mut offset)?;
                Ok(Self::KexEcdhReply {
                    server_host_key_blob,
                    server_pubkey,
                    signature,
                })
            }
            unknown => Ok(Self::Unknown {
                message_type: unknown,
                payload: body.to_vec(),
            }),
        }
    }

    pub fn encode(&self, codec: &PacketCodec) -> Result<Vec<u8>, RusshError> {
        let frame = self.to_frame()?;
        codec.encode(&frame)
    }

    pub fn decode(codec: &PacketCodec, bytes: &[u8]) -> Result<Self, RusshError> {
        let frame = codec.decode(bytes)?;
        Self::from_frame(&frame)
    }
}

/// Typed transport events for observability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransportEvent {
    VersionExchange {
        local: String,
        remote: String,
    },
    AlgorithmNegotiated {
        kex: String,
        cipher_client_to_server: String,
        cipher_server_to_client: String,
    },
    KeyExchangeInitSent,
    KeyExchangeInitReceived,
    KeyExchangeComplete {
        host_key: String,
        mac_client_to_server: String,
        mac_server_to_client: String,
        strict_kex: bool,
    },
    ExtInfoReceived {
        extension_count: usize,
    },
    ServiceRequested {
        service: String,
    },
    ServiceAccepted {
        service: String,
    },
    RekeyStarted,
    RekeyFinished,
    KeepaliveSent,
    Disconnected {
        code: DisconnectReasonCode,
        reason: String,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionState {
    Initialized,
    BannerExchanged,
    AlgorithmsNegotiated,
    KeyExchangeInitSent,
    Established,
    WaitingServiceAccept,
    Rekeying,
    Closed,
}

/// Bootstrap client session handle with explicit handshake/rekey state.
#[derive(Clone, Debug)]
pub struct ClientSession {
    pub config: ClientConfig,
    state: SessionState,
    events: Vec<TransportEvent>,
    negotiated: Option<NegotiatedAlgorithms>,
    bytes_since_rekey: u64,
    elapsed_since_rekey: Duration,
    elapsed_since_activity: Duration,
    elapsed_since_keepalive: Duration,
    pending_service: Option<String>,
    active_service: Option<String>,
    authenticated_user: Option<String>,
    local_kexinit_sent: bool,
    remote_kexinit_received: bool,
    awaiting_ext_info: bool,
    incoming_sequence: u32,
    outgoing_sequence: u32,
    kex_context: Option<KexContext>,
    session_keys: Option<SessionKeys>,
    local_version: String,
    remote_version: String,
}

impl ClientSession {
    #[must_use]
    pub fn new(config: ClientConfig) -> Self {
        Self {
            config,
            state: SessionState::Initialized,
            events: Vec::new(),
            negotiated: None,
            bytes_since_rekey: 0,
            elapsed_since_rekey: Duration::ZERO,
            elapsed_since_activity: Duration::ZERO,
            elapsed_since_keepalive: Duration::ZERO,
            pending_service: None,
            active_service: None,
            authenticated_user: None,
            local_kexinit_sent: false,
            remote_kexinit_received: false,
            awaiting_ext_info: false,
            incoming_sequence: 0,
            outgoing_sequence: 0,
            kex_context: None,
            session_keys: None,
            local_version: String::new(),
            remote_version: String::new(),
        }
    }

    pub async fn handshake(&mut self, remote_version: &str) -> Result<(), RusshError> {
        self.handshake_with_peer(PeerDescription::openssh_like(remote_version))
            .await
    }

    /// Override the local SSH version string used in the exchange hash.
    ///
    /// Call this **before** `handshake` / `send_kexinit` when the networking
    /// layer uses a banner different from the default.  The string must not
    /// include the trailing `\r\n`.
    pub fn set_local_version(&mut self, version: impl Into<String>) {
        self.local_version = version.into();
    }

    pub async fn handshake_with_peer(&mut self, peer: PeerDescription) -> Result<(), RusshError> {
        ready(()).await;
        self.ensure_state(SessionState::Initialized, "handshake")?;

        if !is_supported_banner(&peer.banner) {
            return Err(RusshError::new(
                RusshErrorCategory::Interop,
                "unsupported banner (requires SSH-2.0 or SSH-1.99)",
            ));
        }

        self.state = SessionState::BannerExchanged;
        if self.local_version.is_empty() {
            self.local_version = "SSH-2.0-RuSSH_0.1".to_string();
        }
        self.remote_version = peer.banner.clone();
        self.events.push(TransportEvent::VersionExchange {
            local: "SSH-2.0-RuSSH_0.1".to_string(),
            remote: peer.banner,
        });

        let negotiated =
            negotiate_algorithms(self.config.transport.policy.algorithms(), &peer.algorithms)?;
        self.events.push(TransportEvent::AlgorithmNegotiated {
            kex: negotiated.kex.clone(),
            cipher_client_to_server: negotiated.cipher_client_to_server.clone(),
            cipher_server_to_client: negotiated.cipher_server_to_client.clone(),
        });

        self.negotiated = Some(negotiated);
        self.state = SessionState::AlgorithmsNegotiated;
        self.reset_rekey_counters();

        Ok(())
    }

    pub fn send_kexinit(&mut self) -> Result<PacketFrame, RusshError> {
        match self.state {
            SessionState::AlgorithmsNegotiated => self.state = SessionState::KeyExchangeInitSent,
            SessionState::Established | SessionState::WaitingServiceAccept => {
                self.state = SessionState::Rekeying
            }
            SessionState::Rekeying => {}
            _ => {
                return Err(RusshError::new(
                    RusshErrorCategory::Protocol,
                    format!("cannot send KEXINIT while in state {:?}", self.state),
                ));
            }
        }

        self.events.push(TransportEvent::KeyExchangeInitSent);
        self.local_kexinit_sent = true;
        self.remote_kexinit_received = false;
        self.bump_outgoing_sequence();
        let proposal = KexInitProposal::from_algorithms(
            [0x11; 16],
            self.config.transport.policy.algorithms().clone(),
        )
        .with_client_extensions();
        let frame = TransportMessage::KexInit {
            proposal: Box::new(proposal),
        }
        .to_frame()?;

        if self.kex_context.is_none() {
            let keypair = Curve25519Sha256::generate_keypair(&mut OsRng);
            self.kex_context = Some(KexContext {
                local_version: self.local_version.clone(),
                remote_version: self.remote_version.clone(),
                local_kexinit_payload: frame.payload.clone(),
                remote_kexinit_payload: Vec::new(),
                ephemeral_private_key: keypair.secret_bytes().to_vec(),
                ephemeral_public_key: keypair.public_key.clone(),
            });
        }

        Ok(frame)
    }

    pub fn send_service_request(
        &mut self,
        service: impl Into<String>,
    ) -> Result<PacketFrame, RusshError> {
        self.ensure_state(SessionState::Established, "service request")?;

        let service = service.into();
        if service.trim().is_empty() {
            return Err(RusshError::new(
                RusshErrorCategory::Protocol,
                "service request cannot be empty",
            ));
        }
        if service == SSH_USERAUTH_SERVICE {
            self.authenticated_user = None;
        }

        self.pending_service = Some(service.clone());
        self.state = SessionState::WaitingServiceAccept;
        self.events.push(TransportEvent::ServiceRequested {
            service: service.clone(),
        });
        self.bump_outgoing_sequence();

        TransportMessage::ServiceRequest { service }.to_frame()
    }

    pub fn send_userauth_request(
        &mut self,
        request: UserAuthRequest,
    ) -> Result<PacketFrame, RusshError> {
        self.ensure_state(SessionState::Established, "userauth request")?;
        self.ensure_userauth_service_active()?;

        let request_user = match &request {
            UserAuthRequest::None { user, .. }
            | UserAuthRequest::PublicKey { user, .. }
            | UserAuthRequest::Password { user, .. }
            | UserAuthRequest::KeyboardInteractive { user, .. } => user,
        };
        if request_user != &self.config.user {
            return Err(RusshError::new(
                RusshErrorCategory::Auth,
                "userauth request user does not match client configuration user",
            ));
        }

        self.bump_outgoing_sequence();
        UserAuthMessage::Request(request).to_frame()
    }

    pub fn receive_userauth_message(&mut self, message: UserAuthMessage) -> Result<(), RusshError> {
        self.ensure_state(SessionState::Established, "userauth response handling")?;
        self.ensure_userauth_service_active()?;
        self.bump_incoming_sequence();

        match message {
            UserAuthMessage::Success => {
                self.authenticated_user = Some(self.config.user.clone());
                Ok(())
            }
            UserAuthMessage::Failure { .. } => {
                self.authenticated_user = None;
                Ok(())
            }
            UserAuthMessage::Banner { .. }
            | UserAuthMessage::PublicKeyOk { .. }
            | UserAuthMessage::KeyboardInteractiveInfoRequest { .. } => Ok(()),
            UserAuthMessage::Request(_)
            | UserAuthMessage::KeyboardInteractiveInfoResponse { .. } => Err(RusshError::new(
                RusshErrorCategory::Interop,
                "client session received invalid USERAUTH message direction",
            )),
        }
    }

    pub fn receive_encoded_userauth_message(
        &mut self,
        codec: &PacketCodec,
        bytes: &[u8],
    ) -> Result<(), RusshError> {
        let message = UserAuthMessage::decode(codec, bytes).inspect_err(|_| {
            self.protocol_violation("failed to decode USERAUTH packet");
        })?;
        self.receive_userauth_message(message)
    }

    pub fn receive_encoded_userauth_message_with_sequence(
        &mut self,
        codec: &PacketCodec,
        bytes: &[u8],
        incoming_sequence: u32,
    ) -> Result<(), RusshError> {
        let expected = self.incoming_sequence.wrapping_add(1);
        if incoming_sequence != expected {
            return Err(self.protocol_violation(format!(
                "incoming packet sequence mismatch: expected {expected}, got {incoming_sequence}"
            )));
        }
        self.receive_encoded_userauth_message(codec, bytes)
    }

    pub fn receive_message(&mut self, message: TransportMessage) -> Result<(), RusshError> {
        self.bump_incoming_sequence();
        self.enforce_strict_kex_packet_order(&message)?;

        match message {
            TransportMessage::KexInit { proposal } => {
                if matches!(
                    self.state,
                    SessionState::AlgorithmsNegotiated
                        | SessionState::KeyExchangeInitSent
                        | SessionState::Established
                        | SessionState::WaitingServiceAccept
                        | SessionState::Rekeying
                ) {
                    if matches!(
                        self.state,
                        SessionState::Established | SessionState::WaitingServiceAccept
                    ) {
                        self.state = SessionState::Rekeying;
                    }
                    let local = KexInitProposal::from_algorithms(
                        [0xAA; 16],
                        self.config.transport.policy.algorithms().clone(),
                    )
                    .with_client_extensions();
                    let negotiated =
                        negotiate_algorithms_from_proposals(&local, proposal.as_ref())?;
                    self.negotiated = Some(negotiated);
                    self.remote_kexinit_received = true;
                    self.events.push(TransportEvent::KeyExchangeInitReceived);
                    Ok(())
                } else {
                    Err(RusshError::new(
                        RusshErrorCategory::Protocol,
                        format!("unexpected KEXINIT while in state {:?}", self.state),
                    ))
                }
            }
            TransportMessage::NewKeys => {
                if matches!(
                    self.state,
                    SessionState::AlgorithmsNegotiated
                        | SessionState::KeyExchangeInitSent
                        | SessionState::Rekeying
                ) {
                    self.ensure_newkeys_sequence()?;
                    self.complete_key_exchange()
                } else {
                    Err(RusshError::new(
                        RusshErrorCategory::Protocol,
                        format!("unexpected NEWKEYS while in state {:?}", self.state),
                    ))
                }
            }
            TransportMessage::ExtInfo { extensions } => {
                if !matches!(
                    self.state,
                    SessionState::Established | SessionState::WaitingServiceAccept
                ) {
                    return Err(RusshError::new(
                        RusshErrorCategory::Protocol,
                        format!("unexpected EXT_INFO while in state {:?}", self.state),
                    ));
                }
                let strict_kex = self.negotiated.as_ref().is_some_and(|n| n.strict_kex);
                if strict_kex && !self.awaiting_ext_info {
                    return Err(RusshError::new(
                        RusshErrorCategory::Protocol,
                        "strict-kex received unexpected EXT_INFO",
                    ));
                }
                self.awaiting_ext_info = false;
                self.events.push(TransportEvent::ExtInfoReceived {
                    extension_count: extensions.len(),
                });
                Ok(())
            }
            TransportMessage::ServiceAccept { service } => {
                self.ensure_state(SessionState::WaitingServiceAccept, "service accept")?;
                let expected = self.pending_service.take().ok_or_else(|| {
                    RusshError::new(
                        RusshErrorCategory::Protocol,
                        "missing pending service for SERVICE_ACCEPT",
                    )
                })?;
                if service != expected {
                    return Err(RusshError::new(
                        RusshErrorCategory::Protocol,
                        "SERVICE_ACCEPT does not match requested service",
                    ));
                }

                self.active_service = Some(service.clone());
                self.state = SessionState::Established;
                self.events
                    .push(TransportEvent::ServiceAccepted { service });
                Ok(())
            }
            TransportMessage::Ignore { .. } => Ok(()),
            TransportMessage::Disconnect { code, reason } => {
                self.close_with_code(code, reason);
                Ok(())
            }
            TransportMessage::Unimplemented { .. } => Ok(()),
            TransportMessage::KexEcdhInit { .. } => Err(RusshError::new(
                RusshErrorCategory::Interop,
                "client session cannot accept inbound KEX_ECDH_INIT",
            )),
            TransportMessage::KexEcdhReply { .. } => Err(RusshError::new(
                RusshErrorCategory::Interop,
                "use receive_kex_ecdh_reply_and_send_newkeys for KEX_ECDH_REPLY",
            )),
            TransportMessage::ServiceRequest { .. } => Err(RusshError::new(
                RusshErrorCategory::Interop,
                "client session cannot accept inbound SERVICE_REQUEST",
            )),
            TransportMessage::Unknown { message_type, .. } => Err(RusshError::new(
                RusshErrorCategory::Interop,
                format!("unsupported transport message type {message_type}"),
            )),
        }
    }

    pub fn receive_encoded_message(
        &mut self,
        codec: &PacketCodec,
        bytes: &[u8],
    ) -> Result<(), RusshError> {
        let message = TransportMessage::decode(codec, bytes).inspect_err(|_| {
            self.protocol_violation("failed to decode transport packet");
        })?;
        self.receive_message(message)
    }

    pub fn receive_encoded_message_with_sequence(
        &mut self,
        codec: &PacketCodec,
        bytes: &[u8],
        incoming_sequence: u32,
    ) -> Result<(), RusshError> {
        let expected = self.incoming_sequence.wrapping_add(1);
        if incoming_sequence != expected {
            return Err(self.protocol_violation(format!(
                "incoming packet sequence mismatch: expected {expected}, got {incoming_sequence}"
            )));
        }
        self.receive_encoded_message(codec, bytes)
    }

    pub fn account_payload(&mut self, bytes: usize) -> Result<bool, RusshError> {
        self.ensure_live_state("payload accounting")?;
        self.mark_activity();

        let delta = u64::try_from(bytes).map_err(|_| {
            RusshError::new(
                RusshErrorCategory::Protocol,
                "payload size does not fit in u64",
            )
        })?;
        self.bytes_since_rekey = self.bytes_since_rekey.saturating_add(delta);

        if self.rekey_due() {
            self.perform_rekey();
            return Ok(true);
        }

        Ok(false)
    }

    pub fn advance_time(&mut self, elapsed: Duration) -> Result<bool, RusshError> {
        self.ensure_live_state("time advancement")?;

        self.elapsed_since_rekey = self.elapsed_since_rekey.saturating_add(elapsed);
        self.elapsed_since_activity = self.elapsed_since_activity.saturating_add(elapsed);
        self.elapsed_since_keepalive = self.elapsed_since_keepalive.saturating_add(elapsed);
        if self.rekey_due() {
            self.perform_rekey();
            return Ok(true);
        }

        let idle_timeout = self.config.transport.idle_timeout;
        if !idle_timeout.is_zero() && self.elapsed_since_activity >= idle_timeout {
            self.close_with_code(
                DisconnectReasonCode::ByApplication,
                format!("idle timeout exceeded after {}s", idle_timeout.as_secs()),
            );
            return Ok(false);
        }

        let keepalive_interval = self.config.transport.keepalive_interval;
        if !keepalive_interval.is_zero() && self.elapsed_since_keepalive >= keepalive_interval {
            self.events.push(TransportEvent::KeepaliveSent);
            self.elapsed_since_keepalive = Duration::ZERO;
        }

        Ok(false)
    }

    pub fn close(&mut self, reason: impl Into<String>) {
        self.close_with_code(DisconnectReasonCode::ByApplication, reason);
    }

    pub fn close_with_code(&mut self, code: DisconnectReasonCode, reason: impl Into<String>) {
        let reason = reason.into();
        self.events
            .push(TransportEvent::Disconnected { code, reason });
        self.state = SessionState::Closed;
    }

    /// Build a KEX_ECDH_INIT frame using the ephemeral keypair from kex_context.
    pub fn send_kex_ecdh_init(&mut self) -> Result<PacketFrame, RusshError> {
        let ctx = self.kex_context.as_ref().ok_or_else(|| {
            RusshError::new(
                RusshErrorCategory::Protocol,
                "no kex context: call send_kexinit first",
            )
        })?;
        let pubkey = ctx.ephemeral_public_key.clone();
        self.bump_outgoing_sequence();
        TransportMessage::KexEcdhInit {
            client_pubkey: pubkey,
        }
        .to_frame()
    }

    /// Process a KEX_ECDH_REPLY from the server, derive session keys, and return a NEWKEYS frame.
    pub fn receive_kex_ecdh_reply_and_send_newkeys(
        &mut self,
        reply: &TransportMessage,
    ) -> Result<(PacketFrame, SessionKeys), RusshError> {
        let (server_host_key_blob, server_pubkey, signature) = match reply {
            TransportMessage::KexEcdhReply {
                server_host_key_blob,
                server_pubkey,
                signature,
            } => (
                server_host_key_blob.clone(),
                server_pubkey.clone(),
                signature.clone(),
            ),
            _ => {
                return Err(RusshError::new(
                    RusshErrorCategory::Protocol,
                    "expected KexEcdhReply",
                ));
            }
        };

        let ctx = self
            .kex_context
            .as_ref()
            .ok_or_else(|| RusshError::new(RusshErrorCategory::Protocol, "no kex context"))?
            .clone();

        let kex_result =
            Curve25519Sha256::compute_shared_secret(&ctx.ephemeral_private_key, &server_pubkey)?;
        let shared_secret_mpint = encode_mpint(&kex_result.shared_secret);

        let exchange_hash = compute_exchange_hash_curve25519(
            &ctx.local_version,
            &ctx.remote_version,
            &ctx.local_kexinit_payload,
            &ctx.remote_kexinit_payload,
            &server_host_key_blob,
            &ctx.ephemeral_public_key,
            &server_pubkey,
            &shared_secret_mpint,
            true,
        );

        if self.config.strict_host_key_checking {
            verify_host_key_signature(&server_host_key_blob, &exchange_hash, &signature)?;
        }

        let keys = derive_session_keys(&shared_secret_mpint, &exchange_hash, None);
        let newkeys_frame = TransportMessage::NewKeys.to_frame()?;

        self.session_keys = Some(keys.clone());
        self.kex_context = None;

        let (host_key_alg, mac_c2s, mac_s2c, strict_kex, ext_info_c, ext_info_s) = self
            .negotiated
            .as_ref()
            .map(|n| {
                (
                    n.host_key.clone(),
                    n.mac_client_to_server.clone(),
                    n.mac_server_to_client.clone(),
                    n.strict_kex,
                    n.ext_info_c,
                    n.ext_info_s,
                )
            })
            .unwrap_or_else(|| {
                (
                    "ssh-ed25519".to_string(),
                    "hmac-sha2-256-etm@openssh.com".to_string(),
                    "hmac-sha2-256-etm@openssh.com".to_string(),
                    false,
                    false,
                    false,
                )
            });

        self.events.push(TransportEvent::KeyExchangeComplete {
            host_key: host_key_alg,
            mac_client_to_server: mac_c2s,
            mac_server_to_client: mac_s2c,
            strict_kex,
        });
        // Expect EXT_INFO if server advertised ext-info-s, or if client advertised ext-info-c
        // (RFC 8308 servers may send EXT_INFO whenever the client signals ext-info-c).
        self.awaiting_ext_info = ext_info_s || ext_info_c;
        self.state = SessionState::Established;
        self.local_kexinit_sent = false;
        self.remote_kexinit_received = false;
        self.reset_rekey_counters();

        self.bump_outgoing_sequence();
        Ok((newkeys_frame, keys))
    }

    /// Return derived session keys if key exchange has completed.
    pub fn session_keys(&self) -> Option<&SessionKeys> {
        self.session_keys.as_ref()
    }

    #[must_use]
    pub fn state(&self) -> SessionState {
        self.state
    }

    #[must_use]
    pub fn negotiated(&self) -> Option<&NegotiatedAlgorithms> {
        self.negotiated.as_ref()
    }

    #[must_use]
    pub fn pending_service(&self) -> Option<&str> {
        self.pending_service.as_deref()
    }

    #[must_use]
    pub fn active_service(&self) -> Option<&str> {
        self.active_service.as_deref()
    }

    #[must_use]
    pub fn authenticated_user(&self) -> Option<&str> {
        self.authenticated_user.as_deref()
    }

    #[must_use]
    pub fn is_authenticated(&self) -> bool {
        self.authenticated_user.is_some()
    }

    /// Store the raw KEXINIT payload received from the server so the exchange
    /// hash can include it during `receive_kex_ecdh_reply_and_send_newkeys`.
    /// Must be called after `send_kexinit` and before `send_kex_ecdh_init`.
    pub fn store_server_kexinit_payload(&mut self, payload: Vec<u8>) -> Result<(), RusshError> {
        let ctx = self.kex_context.as_mut().ok_or_else(|| {
            RusshError::new(
                RusshErrorCategory::Protocol,
                "no active kex context to store remote kexinit payload",
            )
        })?;
        ctx.remote_kexinit_payload = payload;
        Ok(())
    }

    #[must_use]
    pub fn events(&self) -> &[TransportEvent] {
        &self.events
    }

    #[must_use]
    pub fn incoming_sequence(&self) -> u32 {
        self.incoming_sequence
    }

    #[must_use]
    pub fn outgoing_sequence(&self) -> u32 {
        self.outgoing_sequence
    }

    fn complete_key_exchange(&mut self) -> Result<(), RusshError> {
        let negotiated = self.negotiated.as_ref().ok_or_else(|| {
            RusshError::new(
                RusshErrorCategory::Protocol,
                "cannot complete key exchange without negotiated algorithms",
            )
        })?;

        self.events.push(TransportEvent::KeyExchangeComplete {
            host_key: negotiated.host_key.clone(),
            mac_client_to_server: negotiated.mac_client_to_server.clone(),
            mac_server_to_client: negotiated.mac_server_to_client.clone(),
            strict_kex: negotiated.strict_kex,
        });
        self.awaiting_ext_info = negotiated.ext_info_s;

        self.state = if self.pending_service.is_some() {
            SessionState::WaitingServiceAccept
        } else {
            SessionState::Established
        };
        self.reset_rekey_counters();
        self.local_kexinit_sent = false;
        self.remote_kexinit_received = false;

        Ok(())
    }

    fn ensure_newkeys_sequence(&self) -> Result<(), RusshError> {
        let strict_kex = self.negotiated.as_ref().is_some_and(|n| n.strict_kex);
        if strict_kex && !(self.local_kexinit_sent && self.remote_kexinit_received) {
            return Err(RusshError::new(
                RusshErrorCategory::Protocol,
                "strict-kex requires both local and remote KEXINIT before NEWKEYS",
            ));
        }
        Ok(())
    }

    fn enforce_strict_kex_packet_order(
        &mut self,
        message: &TransportMessage,
    ) -> Result<(), RusshError> {
        if self.strict_kex_window_active()
            && !matches!(
                message,
                TransportMessage::KexInit { .. }
                    | TransportMessage::NewKeys
                    | TransportMessage::Disconnect { .. }
            )
        {
            return Err(
                self.protocol_violation("strict-kex disallows non-KEX packets before NEWKEYS")
            );
        }
        Ok(())
    }

    #[must_use]
    fn strict_kex_window_active(&self) -> bool {
        self.negotiated.as_ref().is_some_and(|n| n.strict_kex)
            && (self.local_kexinit_sent || self.remote_kexinit_received)
    }

    fn bump_incoming_sequence(&mut self) {
        self.incoming_sequence = self.incoming_sequence.wrapping_add(1);
        self.mark_activity();
    }

    fn bump_outgoing_sequence(&mut self) {
        self.outgoing_sequence = self.outgoing_sequence.wrapping_add(1);
        self.mark_activity();
    }

    fn mark_activity(&mut self) {
        self.elapsed_since_activity = Duration::ZERO;
        self.elapsed_since_keepalive = Duration::ZERO;
    }

    fn protocol_violation(&mut self, reason: impl Into<String>) -> RusshError {
        let reason = reason.into();
        self.close_with_code(DisconnectReasonCode::ProtocolError, reason.clone());
        RusshError::new(RusshErrorCategory::Protocol, reason)
    }

    fn ensure_state(&self, expected: SessionState, action: &str) -> Result<(), RusshError> {
        if self.state == expected {
            Ok(())
        } else {
            Err(RusshError::new(
                RusshErrorCategory::Protocol,
                format!("cannot {action} while in state {:?}", self.state),
            ))
        }
    }

    fn ensure_live_state(&self, action: &str) -> Result<(), RusshError> {
        if matches!(
            self.state,
            SessionState::Established | SessionState::WaitingServiceAccept
        ) {
            Ok(())
        } else {
            Err(RusshError::new(
                RusshErrorCategory::Protocol,
                format!("cannot {action} while in state {:?}", self.state),
            ))
        }
    }

    fn ensure_userauth_service_active(&self) -> Result<(), RusshError> {
        if self.active_service.as_deref() == Some(SSH_USERAUTH_SERVICE) {
            Ok(())
        } else {
            Err(RusshError::new(
                RusshErrorCategory::Protocol,
                "USERAUTH messages require active ssh-userauth service",
            ))
        }
    }

    #[must_use]
    fn rekey_due(&self) -> bool {
        self.bytes_since_rekey >= self.config.transport.rekey_after_bytes
            || self.elapsed_since_rekey >= self.config.transport.rekey_after_duration
    }

    fn perform_rekey(&mut self) {
        self.state = SessionState::Rekeying;
        self.events.push(TransportEvent::RekeyStarted);
        self.reset_rekey_counters();
        self.events.push(TransportEvent::RekeyFinished);
        self.state = if self.pending_service.is_some() {
            SessionState::WaitingServiceAccept
        } else {
            SessionState::Established
        };
    }

    fn reset_rekey_counters(&mut self) {
        self.bytes_since_rekey = 0;
        self.elapsed_since_rekey = Duration::ZERO;
    }
}

/// Bootstrap server session handle.
#[derive(Clone, Debug)]
pub struct ServerSession {
    pub config: ServerConfig,
    state: SessionState,
    negotiated: Option<NegotiatedAlgorithms>,
    awaiting_client_newkeys: bool,
    active_service: Option<String>,
    auth_session: Option<AuthSession>,
    authenticating_user: Option<String>,
    authenticated_user: Option<String>,
    keyboard_interactive_pending: bool,
    incoming_sequence: u32,
    outgoing_sequence: u32,
    kex_context: Option<KexContext>,
    session_keys: Option<SessionKeys>,
    local_version: String,
    remote_version: String,
    /// Raw client KEXINIT payload (original wire bytes, used for exchange hash).
    raw_client_kexinit: Option<Vec<u8>>,
}

impl ServerSession {
    #[must_use]
    pub fn new(config: ServerConfig) -> Self {
        Self {
            config,
            state: SessionState::Initialized,
            negotiated: None,
            awaiting_client_newkeys: false,
            active_service: None,
            auth_session: None,
            authenticating_user: None,
            authenticated_user: None,
            keyboard_interactive_pending: false,
            incoming_sequence: 0,
            outgoing_sequence: 0,
            kex_context: None,
            session_keys: None,
            local_version: String::new(),
            remote_version: String::new(),
            raw_client_kexinit: None,
        }
    }

    /// Store the raw (wire-format) bytes of the client's KEXINIT payload.
    /// Must be called before `receive_message(KexInit)` so the exchange hash uses
    /// the original bytes rather than a re-encoded version.
    pub fn store_client_kexinit_payload(&mut self, payload: Vec<u8>) {
        self.raw_client_kexinit = Some(payload);
    }

    pub fn activate_userauth(&mut self, policy: ServerAuthPolicy) {
        self.auth_session = Some(AuthSession::new(policy));
    }

    pub fn accept_banner(&mut self, client_banner: &str) -> Result<(), RusshError> {
        if self.state != SessionState::Initialized {
            return Err(RusshError::new(
                RusshErrorCategory::Protocol,
                "client banner already processed",
            ));
        }
        if !is_supported_banner(client_banner) {
            return Err(RusshError::new(
                RusshErrorCategory::Interop,
                "unsupported banner (requires SSH-2.0 or SSH-1.99)",
            ));
        }

        self.state = SessionState::BannerExchanged;
        if self.local_version.is_empty() {
            self.local_version = "SSH-2.0-RuSSH_0.1".to_string();
        }
        self.remote_version = client_banner.to_string();
        Ok(())
    }

    /// Override the local SSH version string used in the exchange hash.
    ///
    /// Call this **before** `accept_banner` when the networking layer uses a
    /// banner different from the default.  The string must not include `\r\n`.
    pub fn set_local_version(&mut self, version: impl Into<String>) {
        self.local_version = version.into();
    }

    pub fn negotiate_with_client(
        &mut self,
        client_algorithms: &AlgorithmSet,
    ) -> Result<&NegotiatedAlgorithms, RusshError> {
        if self.state != SessionState::BannerExchanged {
            return Err(RusshError::new(
                RusshErrorCategory::Protocol,
                "must accept banner before algorithm negotiation",
            ));
        }

        let negotiated =
            negotiate_algorithms(self.config.transport.policy.algorithms(), client_algorithms)?;
        self.state = SessionState::AlgorithmsNegotiated;
        self.negotiated = Some(negotiated);

        self.negotiated.as_ref().ok_or_else(|| {
            RusshError::new(
                RusshErrorCategory::Protocol,
                "negotiated algorithms unexpectedly unavailable",
            )
        })
    }

    pub fn receive_message(
        &mut self,
        message: TransportMessage,
    ) -> Result<Option<TransportMessage>, RusshError> {
        self.bump_incoming_sequence();
        if self.strict_kex_window_active()
            && !matches!(
                message,
                TransportMessage::NewKeys | TransportMessage::Disconnect { .. }
            )
        {
            self.state = SessionState::Closed;
            return Err(RusshError::new(
                RusshErrorCategory::Protocol,
                "strict-kex disallows non-NEWKEYS packets before client NEWKEYS",
            ));
        }

        match message {
            TransportMessage::KexInit { proposal } => {
                if self.state != SessionState::AlgorithmsNegotiated {
                    return Err(RusshError::new(
                        RusshErrorCategory::Protocol,
                        "KEXINIT received before algorithm negotiation",
                    ));
                }
                let local = KexInitProposal::from_algorithms(
                    [0xBB; 16],
                    self.config.transport.policy.algorithms().clone(),
                )
                .with_server_extensions();
                let negotiated = negotiate_algorithms_from_proposals(&local, proposal.as_ref())?;
                self.negotiated = Some(negotiated);

                if self.config.host_key_seed.is_some() {
                    // Real ECDH path: store context and return server's KexInit.
                    // Use the raw client KEXINIT payload (original wire bytes) for the exchange
                    // hash, falling back to re-encoding only if raw bytes weren't pre-stored.
                    let remote_kexinit_payload =
                        self.raw_client_kexinit.take().unwrap_or_else(|| {
                            TransportMessage::KexInit { proposal }
                                .to_frame()
                                .map(|f| f.payload)
                                .unwrap_or_default()
                        });
                    let server_kexinit_frame = TransportMessage::KexInit {
                        proposal: Box::new(local),
                    }
                    .to_frame()?;
                    let keypair = Curve25519Sha256::generate_keypair(&mut OsRng);
                    self.kex_context = Some(KexContext {
                        local_version: self.local_version.clone(),
                        remote_version: self.remote_version.clone(),
                        local_kexinit_payload: server_kexinit_frame.payload.clone(),
                        remote_kexinit_payload,
                        ephemeral_private_key: keypair.secret_bytes().to_vec(),
                        ephemeral_public_key: keypair.public_key.clone(),
                    });
                    self.state = SessionState::KeyExchangeInitSent;
                    self.bump_outgoing_sequence();
                    let reply = TransportMessage::from_frame(&server_kexinit_frame)?;
                    Ok(Some(reply))
                } else {
                    // Simple test path: respond with NEWKEYS immediately
                    self.state = SessionState::Established;
                    self.awaiting_client_newkeys = true;
                    self.bump_outgoing_sequence();
                    Ok(Some(TransportMessage::NewKeys))
                }
            }
            TransportMessage::NewKeys => {
                if !self.awaiting_client_newkeys {
                    return Err(RusshError::new(
                        RusshErrorCategory::Protocol,
                        "unexpected NEWKEYS for server session",
                    ));
                }
                self.awaiting_client_newkeys = false;
                Ok(None)
            }
            TransportMessage::ExtInfo { .. } => Ok(None),
            TransportMessage::ServiceRequest { service } => {
                if self.state != SessionState::Established {
                    return Err(RusshError::new(
                        RusshErrorCategory::Protocol,
                        "SERVICE_REQUEST received before NEWKEYS",
                    ));
                }
                if self.awaiting_client_newkeys {
                    let strict_kex = self.negotiated.as_ref().is_some_and(|n| n.strict_kex);
                    if strict_kex {
                        return Err(RusshError::new(
                            RusshErrorCategory::Protocol,
                            "strict-kex requires NEWKEYS before SERVICE_REQUEST",
                        ));
                    }
                }
                if service == SSH_USERAUTH_SERVICE {
                    self.authenticating_user = None;
                    self.authenticated_user = None;
                }
                self.active_service = Some(service.clone());
                self.bump_outgoing_sequence();
                Ok(Some(TransportMessage::ServiceAccept { service }))
            }
            TransportMessage::Ignore { .. } => Ok(None),
            TransportMessage::Disconnect { .. } => {
                self.state = SessionState::Closed;
                Ok(None)
            }
            TransportMessage::KexEcdhInit { client_pubkey } => {
                let seed = match self.config.host_key_seed {
                    Some(s) => s,
                    None => {
                        return Err(RusshError::new(
                            RusshErrorCategory::Config,
                            "no host key configured for ECDH",
                        ));
                    }
                };
                let ctx = self
                    .kex_context
                    .as_ref()
                    .ok_or_else(|| {
                        RusshError::new(
                            RusshErrorCategory::Protocol,
                            "received KEX_ECDH_INIT without kex context",
                        )
                    })?
                    .clone();
                let kex_result = Curve25519Sha256::compute_shared_secret(
                    &ctx.ephemeral_private_key,
                    &client_pubkey,
                )?;
                let shared_secret_mpint = encode_mpint(&kex_result.shared_secret);
                let host_signer = Ed25519Signer::from_seed(&seed);
                let host_key_blob = host_signer.public_key_blob();
                let exchange_hash = compute_exchange_hash_curve25519(
                    &ctx.local_version,
                    &ctx.remote_version,
                    &ctx.local_kexinit_payload,
                    &ctx.remote_kexinit_payload,
                    &host_key_blob,
                    &client_pubkey,
                    &ctx.ephemeral_public_key,
                    &shared_secret_mpint,
                    false,
                );
                let sig_bytes = host_signer.sign(&exchange_hash)?;
                let mut signature = Vec::new();
                signature.extend_from_slice(&encode_ssh_string(b"ssh-ed25519"));
                signature.extend_from_slice(&encode_ssh_string(&sig_bytes));
                let keys = derive_session_keys(&shared_secret_mpint, &exchange_hash, None);
                self.session_keys = Some(keys);
                self.kex_context = None;
                self.state = SessionState::Established;
                self.awaiting_client_newkeys = true;
                self.bump_outgoing_sequence();
                Ok(Some(TransportMessage::KexEcdhReply {
                    server_host_key_blob: host_key_blob,
                    server_pubkey: ctx.ephemeral_public_key,
                    signature,
                }))
            }
            _ => Ok(Some(TransportMessage::Unimplemented {
                sequence_number: self.incoming_sequence,
            })),
        }
    }

    pub fn receive_userauth_message(
        &mut self,
        message: UserAuthMessage,
    ) -> Result<Option<UserAuthMessage>, RusshError> {
        self.ensure_userauth_ready()?;
        self.bump_incoming_sequence();

        match message {
            UserAuthMessage::Request(request) => self.handle_userauth_request(request),
            UserAuthMessage::KeyboardInteractiveInfoResponse { responses } => {
                if !self.keyboard_interactive_pending {
                    return Err(RusshError::new(
                        RusshErrorCategory::Auth,
                        "received keyboard-interactive response without pending request",
                    ));
                }
                self.keyboard_interactive_pending = false;

                let password = responses.into_iter().next().unwrap_or_default();
                let user = self.authenticating_user.clone().ok_or_else(|| {
                    RusshError::new(
                        RusshErrorCategory::Auth,
                        "no authenticating user for keyboard-interactive response",
                    )
                })?;

                let auth_session = self.auth_session.as_mut().ok_or_else(|| {
                    RusshError::new(
                        RusshErrorCategory::Auth,
                        "server USERAUTH policy is not configured",
                    )
                })?;

                let auth_request = AuthRequest::Password {
                    user: user.clone(),
                    password,
                };
                let (result, _event) = auth_session.evaluate_with_event(&auth_request);
                match result {
                    AuthResult::Accepted => {
                        self.authenticated_user = Some(user);
                        self.bump_outgoing_sequence();
                        Ok(Some(UserAuthMessage::Success))
                    }
                    AuthResult::Rejected { .. } | AuthResult::PartiallyAccepted { .. } => {
                        let methods = auth_session
                            .allowed_methods()
                            .into_iter()
                            .map(AuthMethod::as_ssh_name)
                            .map(ToOwned::to_owned)
                            .collect();
                        self.bump_outgoing_sequence();
                        Ok(Some(UserAuthMessage::Failure {
                            methods,
                            partial_success: false,
                        }))
                    }
                }
            }
            _ => Err(RusshError::new(
                RusshErrorCategory::Interop,
                "server session received invalid USERAUTH message direction",
            )),
        }
    }

    pub fn receive_encoded_userauth_message_with_sequence(
        &mut self,
        codec: &PacketCodec,
        bytes: &[u8],
        incoming_sequence: u32,
    ) -> Result<Option<UserAuthMessage>, RusshError> {
        let expected = self.incoming_sequence.wrapping_add(1);
        if incoming_sequence != expected {
            self.state = SessionState::Closed;
            return Err(RusshError::new(
                RusshErrorCategory::Protocol,
                format!(
                    "incoming packet sequence mismatch: expected {expected}, got {incoming_sequence}"
                ),
            ));
        }
        let message = UserAuthMessage::decode(codec, bytes).inspect_err(|_| {
            self.state = SessionState::Closed;
        })?;
        self.receive_userauth_message(message)
    }

    pub fn receive_encoded_message_with_sequence(
        &mut self,
        codec: &PacketCodec,
        bytes: &[u8],
        incoming_sequence: u32,
    ) -> Result<Option<TransportMessage>, RusshError> {
        let expected = self.incoming_sequence.wrapping_add(1);
        if incoming_sequence != expected {
            self.state = SessionState::Closed;
            return Err(RusshError::new(
                RusshErrorCategory::Protocol,
                format!(
                    "incoming packet sequence mismatch: expected {expected}, got {incoming_sequence}"
                ),
            ));
        }
        let message = TransportMessage::decode(codec, bytes).inspect_err(|_| {
            self.state = SessionState::Closed;
        })?;
        self.receive_message(message)
    }

    pub fn mark_closed(&mut self) {
        self.state = SessionState::Closed;
    }

    #[must_use]
    pub fn state(&self) -> SessionState {
        self.state
    }

    #[must_use]
    pub fn negotiated(&self) -> Option<&NegotiatedAlgorithms> {
        self.negotiated.as_ref()
    }

    #[must_use]
    pub fn active_service(&self) -> Option<&str> {
        self.active_service.as_deref()
    }

    #[must_use]
    pub fn authenticated_user(&self) -> Option<&str> {
        self.authenticated_user.as_deref()
    }

    #[must_use]
    pub fn incoming_sequence(&self) -> u32 {
        self.incoming_sequence
    }

    #[must_use]
    pub fn outgoing_sequence(&self) -> u32 {
        self.outgoing_sequence
    }

    #[must_use]
    fn strict_kex_window_active(&self) -> bool {
        self.awaiting_client_newkeys && self.negotiated.as_ref().is_some_and(|n| n.strict_kex)
    }

    fn bump_incoming_sequence(&mut self) {
        self.incoming_sequence = self.incoming_sequence.wrapping_add(1);
    }

    fn bump_outgoing_sequence(&mut self) {
        self.outgoing_sequence = self.outgoing_sequence.wrapping_add(1);
    }

    fn ensure_userauth_ready(&self) -> Result<(), RusshError> {
        if self.state != SessionState::Established {
            return Err(RusshError::new(
                RusshErrorCategory::Protocol,
                "server session is not established for USERAUTH",
            ));
        }
        if self.active_service.as_deref() != Some(SSH_USERAUTH_SERVICE) {
            return Err(RusshError::new(
                RusshErrorCategory::Protocol,
                "USERAUTH messages require active ssh-userauth service",
            ));
        }
        if self.auth_session.is_none() {
            return Err(RusshError::new(
                RusshErrorCategory::Auth,
                "server USERAUTH policy is not configured",
            ));
        }
        Ok(())
    }

    fn handle_userauth_request(
        &mut self,
        request: UserAuthRequest,
    ) -> Result<Option<UserAuthMessage>, RusshError> {
        let (user, auth_request) = match request {
            UserAuthRequest::None {
                user: _,
                service: _,
            } => {
                // RFC 4252 §5.2: respond with the allowed methods list.
                let methods = self.allowed_userauth_methods();
                self.bump_outgoing_sequence();
                return Ok(Some(UserAuthMessage::Failure {
                    methods,
                    partial_success: false,
                }));
            }
            UserAuthRequest::PublicKey {
                user,
                service,
                algorithm,
                public_key,
                signature,
            } => {
                if service != SSH_CONNECTION_SERVICE {
                    return Err(RusshError::new(
                        RusshErrorCategory::Auth,
                        "USERAUTH request service must be ssh-connection",
                    ));
                }

                // Certificate-based public key auth.
                if algorithm == CERT_ALGORITHM_ED25519 {
                    return self.handle_cert_userauth(user, algorithm, public_key, signature);
                }

                if let Some(signature) = signature {
                    // Verify the signature before policy evaluation when session keys exist.
                    if let Some(session_keys) = &self.session_keys {
                        let session_id = session_keys.session_id.clone();
                        let verify_result = verify_publickey_auth_signature(
                            &session_id,
                            &user,
                            SSH_CONNECTION_SERVICE,
                            &algorithm,
                            &public_key,
                            &signature,
                        );
                        if verify_result.is_err() {
                            let methods = self.allowed_userauth_methods();
                            self.bump_outgoing_sequence();
                            return Ok(Some(UserAuthMessage::Failure {
                                methods,
                                partial_success: false,
                            }));
                        }
                    }
                    (
                        user.clone(),
                        AuthRequest::PublicKey {
                            user,
                            public_key,
                            signature,
                        },
                    )
                } else {
                    self.bump_outgoing_sequence();
                    return Ok(Some(UserAuthMessage::PublicKeyOk {
                        algorithm,
                        public_key,
                    }));
                }
            }
            UserAuthRequest::Password {
                user,
                service,
                password,
            } => {
                if service != SSH_CONNECTION_SERVICE {
                    return Err(RusshError::new(
                        RusshErrorCategory::Auth,
                        "USERAUTH request service must be ssh-connection",
                    ));
                }
                (user.clone(), AuthRequest::Password { user, password })
            }
            UserAuthRequest::KeyboardInteractive {
                user,
                service,
                language_tag: _,
                submethods: _,
            } => {
                if service != SSH_CONNECTION_SERVICE {
                    return Err(RusshError::new(
                        RusshErrorCategory::Auth,
                        "USERAUTH request service must be ssh-connection",
                    ));
                }
                self.authenticating_user = Some(user.clone());
                self.keyboard_interactive_pending = true;
                self.bump_outgoing_sequence();
                return Ok(Some(UserAuthMessage::KeyboardInteractiveInfoRequest {
                    name: "Authentication".to_string(),
                    instruction: "Enter your credentials".to_string(),
                    language_tag: String::new(),
                    prompts: vec![("Password: ".to_string(), false)],
                }));
            }
        };

        if let Some(authenticating_user) = self.authenticating_user.as_deref() {
            if authenticating_user != user {
                let methods = self.allowed_userauth_methods();
                self.bump_outgoing_sequence();
                return Ok(Some(UserAuthMessage::Failure {
                    methods,
                    partial_success: false,
                }));
            }
        } else {
            self.authenticating_user = Some(user.clone());
        }

        let auth_session = self.auth_session.as_mut().ok_or_else(|| {
            RusshError::new(
                RusshErrorCategory::Auth,
                "server USERAUTH policy is not configured",
            )
        })?;

        let (result, _event) = auth_session.evaluate_with_event(&auth_request);
        match result {
            AuthResult::Accepted => {
                self.authenticated_user = Some(user);
                self.bump_outgoing_sequence();
                Ok(Some(UserAuthMessage::Success))
            }
            AuthResult::PartiallyAccepted { next_methods } => {
                self.bump_outgoing_sequence();
                Ok(Some(UserAuthMessage::Failure {
                    methods: next_methods
                        .into_iter()
                        .map(AuthMethod::as_ssh_name)
                        .map(ToOwned::to_owned)
                        .collect(),
                    partial_success: true,
                }))
            }
            AuthResult::Rejected { .. } => {
                let methods = auth_session
                    .allowed_methods()
                    .into_iter()
                    .map(AuthMethod::as_ssh_name)
                    .map(ToOwned::to_owned)
                    .collect();
                self.bump_outgoing_sequence();
                Ok(Some(UserAuthMessage::Failure {
                    methods,
                    partial_success: false,
                }))
            }
        }
    }

    fn allowed_userauth_methods(&self) -> Vec<String> {
        self.auth_session
            .as_ref()
            .map(|session| {
                session
                    .allowed_methods()
                    .into_iter()
                    .map(AuthMethod::as_ssh_name)
                    .map(ToOwned::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Handle a certificate-based `publickey` userauth request.
    ///
    /// Steps:
    /// 1. Parse the cert blob; verify the CA's Ed25519 signature over it.
    /// 2. If a `CertificateValidator` is configured, apply policy (trusted CAs, time, principal).
    /// 3. If the client provided a user signature, verify it using the cert's embedded public key.
    /// 4. On success, build an `AuthRequest::PublicKey` referencing the embedded key and delegate
    ///    to the normal auth session (which checks whether `publickey` is an allowed method).
    fn handle_cert_userauth(
        &mut self,
        user: String,
        algorithm: String,
        cert_blob: Vec<u8>,
        signature: Option<Vec<u8>>,
    ) -> Result<Option<UserAuthMessage>, RusshError> {
        let failure = |this: &mut Self| -> Result<Option<UserAuthMessage>, RusshError> {
            let methods = this.allowed_userauth_methods();
            this.bump_outgoing_sequence();
            Ok(Some(UserAuthMessage::Failure {
                methods,
                partial_success: false,
            }))
        };

        // Parse the certificate.
        let cert = match OpenSshCertificate::parse(&cert_blob) {
            Ok(c) => c,
            Err(_) => return failure(self),
        };

        // Validate CA signature + optional policy.
        let validation_result = if let Some(auth_session) = &self.auth_session {
            if let Some(validator) = auth_session.certificate_validator() {
                use std::time::SystemTime;
                validator.validate_cert(&cert, SystemTime::now())
            } else {
                cert.verify_ca_signature()
            }
        } else {
            cert.verify_ca_signature()
        };
        if validation_result.is_err() {
            return failure(self);
        }

        // If the client did not include a signature this is a "query" (is cert acceptable?).
        let Some(signature) = signature else {
            self.bump_outgoing_sequence();
            return Ok(Some(UserAuthMessage::PublicKeyOk {
                algorithm,
                public_key: cert_blob,
            }));
        };

        // Verify the user's signature over the auth payload using the cert's embedded key.
        if let Some(session_keys) = &self.session_keys {
            let session_id = session_keys.session_id.clone();
            let embedded: &[u8; 32] = cert.public_key.as_slice().try_into().map_err(|_| {
                RusshError::new(
                    RusshErrorCategory::Auth,
                    "cert embedded key is not 32 bytes",
                )
            })?;
            if verify_cert_auth_signature(
                &session_id,
                &user,
                SSH_CONNECTION_SERVICE,
                &algorithm,
                &cert_blob,
                embedded,
                &signature,
            )
            .is_err()
            {
                return failure(self);
            }
        }

        // Delegate to auth session (checks method is allowed).
        let auth_request = AuthRequest::PublicKey {
            user: user.clone(),
            public_key: cert_blob,
            signature,
        };

        let auth_session = self.auth_session.as_mut().ok_or_else(|| {
            RusshError::new(
                RusshErrorCategory::Auth,
                "server USERAUTH policy is not configured",
            )
        })?;
        let (result, _event) = auth_session.evaluate_with_event(&auth_request);
        match result {
            AuthResult::Accepted => {
                self.authenticated_user = Some(user);
                self.bump_outgoing_sequence();
                Ok(Some(UserAuthMessage::Success))
            }
            AuthResult::PartiallyAccepted { next_methods } => {
                self.bump_outgoing_sequence();
                Ok(Some(UserAuthMessage::Failure {
                    methods: next_methods
                        .into_iter()
                        .map(AuthMethod::as_ssh_name)
                        .map(ToOwned::to_owned)
                        .collect(),
                    partial_success: true,
                }))
            }
            AuthResult::Rejected { .. } => failure(self),
        }
    }

    /// Return derived session keys if key exchange has completed.
    pub fn session_keys(&self) -> Option<&SessionKeys> {
        self.session_keys.as_ref()
    }
}

fn is_supported_banner(banner: &str) -> bool {
    banner.starts_with("SSH-2.0-") || banner.starts_with("SSH-1.99-")
}

fn negotiate_algorithms(
    local: &AlgorithmSet,
    remote: &AlgorithmSet,
) -> Result<NegotiatedAlgorithms, RusshError> {
    Ok(NegotiatedAlgorithms {
        kex: pick_algorithm(&local.kex, &remote.kex, "kex")?,
        host_key: pick_algorithm(&local.host_key, &remote.host_key, "host key")?,
        cipher_client_to_server: pick_algorithm(&local.ciphers, &remote.ciphers, "cipher c2s")?,
        cipher_server_to_client: pick_algorithm(&local.ciphers, &remote.ciphers, "cipher s2c")?,
        mac_client_to_server: pick_algorithm(&local.macs, &remote.macs, "mac c2s")?,
        mac_server_to_client: pick_algorithm(&local.macs, &remote.macs, "mac s2c")?,
        compression_client_to_server: "none".to_string(),
        compression_server_to_client: "none".to_string(),
        strict_kex: false,
        ext_info_c: false,
        ext_info_s: false,
    })
}

fn negotiate_algorithms_from_proposals(
    local: &KexInitProposal,
    remote: &KexInitProposal,
) -> Result<NegotiatedAlgorithms, RusshError> {
    Ok(NegotiatedAlgorithms {
        kex: pick_algorithm(&local.kex_algorithms, &remote.kex_algorithms, "kex")?,
        host_key: pick_algorithm(
            &local.host_key_algorithms,
            &remote.host_key_algorithms,
            "host key",
        )?,
        cipher_client_to_server: pick_algorithm(
            &local.ciphers_client_to_server,
            &remote.ciphers_client_to_server,
            "cipher c2s",
        )?,
        cipher_server_to_client: pick_algorithm(
            &local.ciphers_server_to_client,
            &remote.ciphers_server_to_client,
            "cipher s2c",
        )?,
        mac_client_to_server: pick_algorithm(
            &local.macs_client_to_server,
            &remote.macs_client_to_server,
            "mac c2s",
        )?,
        mac_server_to_client: pick_algorithm(
            &local.macs_server_to_client,
            &remote.macs_server_to_client,
            "mac s2c",
        )?,
        compression_client_to_server: pick_algorithm(
            &local.compression_client_to_server,
            &remote.compression_client_to_server,
            "compression c2s",
        )?,
        compression_server_to_client: pick_algorithm(
            &local.compression_server_to_client,
            &remote.compression_server_to_client,
            "compression s2c",
        )?,
        strict_kex: (local.strict_kex_c && remote.strict_kex_s)
            || (local.strict_kex_s && remote.strict_kex_c),
        ext_info_c: local.ext_info_c || remote.ext_info_c,
        ext_info_s: local.ext_info_s || remote.ext_info_s,
    })
}

fn pick_algorithm(local: &[String], remote: &[String], label: &str) -> Result<String, RusshError> {
    for candidate in local {
        if remote.iter().any(|peer| peer == candidate) {
            return Ok(candidate.clone());
        }
    }

    Err(RusshError::new(
        RusshErrorCategory::Crypto,
        format!("no shared {label} algorithm"),
    ))
}

fn validate_kexinit_proposal(proposal: &KexInitProposal) -> Result<(), RusshError> {
    let has_required_lists = !proposal.kex_algorithms.is_empty()
        && !proposal.host_key_algorithms.is_empty()
        && !proposal.ciphers_client_to_server.is_empty()
        && !proposal.ciphers_server_to_client.is_empty()
        && !proposal.macs_client_to_server.is_empty()
        && !proposal.macs_server_to_client.is_empty()
        && !proposal.compression_client_to_server.is_empty()
        && !proposal.compression_server_to_client.is_empty();
    if has_required_lists {
        Ok(())
    } else {
        Err(RusshError::new(
            RusshErrorCategory::Protocol,
            "KEXINIT must include required algorithm/compression lists",
        ))
    }
}

fn write_name_list(target: &mut Vec<u8>, values: &[String]) -> Result<(), RusshError> {
    let joined = values.join(",");
    write_ssh_string(target, &joined)
}

fn read_name_list(bytes: &[u8], offset: &mut usize) -> Result<Vec<String>, RusshError> {
    let raw = read_ssh_string(bytes, offset)?;
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    Ok(raw
        .split(',')
        .filter(|entry| !entry.is_empty())
        .map(ToOwned::to_owned)
        .collect())
}

fn maybe_push_extension(values: &mut Vec<String>, enabled: bool, extension: &str) {
    if enabled && !values.iter().any(|value| value == extension) {
        values.push(extension.to_string());
    }
}

fn parse_kex_with_extensions(values: Vec<String>) -> (Vec<String>, bool, bool, bool, bool) {
    let mut kex_algorithms = Vec::new();
    let mut ext_info_c = false;
    let mut ext_info_s = false;
    let mut strict_kex_c = false;
    let mut strict_kex_s = false;

    for value in values {
        match value.as_str() {
            "ext-info-c" => ext_info_c = true,
            "ext-info-s" => ext_info_s = true,
            "kex-strict-c-v00@openssh.com" => strict_kex_c = true,
            "kex-strict-s-v00@openssh.com" => strict_kex_s = true,
            _ => kex_algorithms.push(value),
        }
    }

    (
        kex_algorithms,
        ext_info_c,
        ext_info_s,
        strict_kex_c,
        strict_kex_s,
    )
}

fn write_bool(target: &mut Vec<u8>, value: bool) {
    target.push(u8::from(value));
}

fn read_bool(bytes: &[u8], offset: &mut usize) -> Result<bool, RusshError> {
    if bytes.len() <= *offset {
        return Err(RusshError::new(
            RusshErrorCategory::Protocol,
            "boolean field truncated",
        ));
    }
    let value = bytes[*offset] != 0;
    *offset += 1;
    Ok(value)
}

fn write_u32(target: &mut Vec<u8>, value: u32) {
    target.extend_from_slice(&value.to_be_bytes());
}

fn read_u32(bytes: &[u8], offset: &mut usize) -> Result<u32, RusshError> {
    if bytes.len().saturating_sub(*offset) < 4 {
        return Err(RusshError::new(
            RusshErrorCategory::Protocol,
            "u32 field truncated",
        ));
    }
    let start = *offset;
    let value_bytes: [u8; 4] = bytes[start..start + 4]
        .try_into()
        .map_err(|_| RusshError::new(RusshErrorCategory::Protocol, "failed to parse u32 field"))?;
    *offset += 4;
    Ok(u32::from_be_bytes(value_bytes))
}

fn write_ssh_string(target: &mut Vec<u8>, value: &str) -> Result<(), RusshError> {
    let bytes = value.as_bytes();
    let len = u32::try_from(bytes.len()).map_err(|_| {
        RusshError::new(
            RusshErrorCategory::Protocol,
            "string length does not fit in u32",
        )
    })?;
    target.extend_from_slice(&len.to_be_bytes());
    target.extend_from_slice(bytes);
    Ok(())
}

fn read_ssh_string(bytes: &[u8], offset: &mut usize) -> Result<String, RusshError> {
    if bytes.len().saturating_sub(*offset) < 4 {
        return Err(RusshError::new(
            RusshErrorCategory::Protocol,
            "string length prefix truncated",
        ));
    }

    let start = *offset;
    let len_bytes: [u8; 4] = bytes[start..start + 4].try_into().map_err(|_| {
        RusshError::new(
            RusshErrorCategory::Protocol,
            "failed to parse string length prefix",
        )
    })?;
    *offset += 4;

    let len = usize::try_from(u32::from_be_bytes(len_bytes)).map_err(|_| {
        RusshError::new(
            RusshErrorCategory::Protocol,
            "string length does not fit usize",
        )
    })?;
    let end = offset
        .checked_add(len)
        .ok_or_else(|| RusshError::new(RusshErrorCategory::Protocol, "string length overflow"))?;

    if end > bytes.len() {
        return Err(RusshError::new(
            RusshErrorCategory::Protocol,
            "string data truncated",
        ));
    }

    let value = std::str::from_utf8(&bytes[*offset..end]).map_err(|_| {
        RusshError::new(
            RusshErrorCategory::Protocol,
            "string data is not valid UTF-8",
        )
    })?;
    *offset = end;

    Ok(value.to_string())
}

fn write_ssh_bytes(target: &mut Vec<u8>, data: &[u8]) {
    let len = data.len() as u32;
    target.extend_from_slice(&len.to_be_bytes());
    target.extend_from_slice(data);
}

fn read_ssh_bytes(bytes: &[u8], offset: &mut usize) -> Result<Vec<u8>, RusshError> {
    if bytes.len().saturating_sub(*offset) < 4 {
        return Err(RusshError::new(
            RusshErrorCategory::Protocol,
            "binary string length prefix truncated",
        ));
    }
    let start = *offset;
    let len_bytes: [u8; 4] = bytes[start..start + 4].try_into().map_err(|_| {
        RusshError::new(
            RusshErrorCategory::Protocol,
            "failed to parse binary string length",
        )
    })?;
    *offset += 4;
    let len = u32::from_be_bytes(len_bytes) as usize;
    if *offset + len > bytes.len() {
        return Err(RusshError::new(
            RusshErrorCategory::Protocol,
            "binary string data truncated",
        ));
    }
    let result = bytes[*offset..*offset + len].to_vec();
    *offset += len;
    Ok(result)
}

/// Compute the RFC 4253 exchange hash for curve25519-sha256.
/// When `is_client` is true, `local_version` is V_C and `remote_version` is V_S.
/// When `is_client` is false (server), `local_version` is V_S and `remote_version` is V_C.
#[allow(clippy::too_many_arguments)]
fn compute_exchange_hash_curve25519(
    local_version: &str,
    remote_version: &str,
    local_kexinit_payload: &[u8],
    remote_kexinit_payload: &[u8],
    server_host_key_blob: &[u8],
    client_ephemeral_pubkey: &[u8],
    server_ephemeral_pubkey: &[u8],
    shared_secret_mpint: &[u8],
    is_client: bool,
) -> Vec<u8> {
    let (v_c, v_s, i_c, i_s) = if is_client {
        (
            local_version,
            remote_version,
            local_kexinit_payload,
            remote_kexinit_payload,
        )
    } else {
        (
            remote_version,
            local_version,
            remote_kexinit_payload,
            local_kexinit_payload,
        )
    };
    let mut data = Vec::new();
    data.extend_from_slice(&encode_ssh_string(v_c.as_bytes()));
    data.extend_from_slice(&encode_ssh_string(v_s.as_bytes()));
    data.extend_from_slice(&encode_ssh_string(i_c));
    data.extend_from_slice(&encode_ssh_string(i_s));
    data.extend_from_slice(&encode_ssh_string(server_host_key_blob));
    data.extend_from_slice(&encode_ssh_string(client_ephemeral_pubkey));
    data.extend_from_slice(&encode_ssh_string(server_ephemeral_pubkey));
    data.extend_from_slice(shared_secret_mpint);
    Sha256::digest(&data)
}

/// Derive the seven SSH session keys from a completed key exchange.
fn derive_session_keys(
    shared_secret_mpint: &[u8],
    exchange_hash: &[u8],
    session_id: Option<&[u8]>,
) -> SessionKeys {
    let sid = session_id.unwrap_or(exchange_hash);
    SessionKeys {
        session_id: sid.to_vec(),
        iv_c2s: derive_key_sha256(shared_secret_mpint, exchange_hash, b'A', sid, 12),
        iv_s2c: derive_key_sha256(shared_secret_mpint, exchange_hash, b'B', sid, 12),
        key_c2s: derive_key_sha256(shared_secret_mpint, exchange_hash, b'C', sid, 32),
        key_s2c: derive_key_sha256(shared_secret_mpint, exchange_hash, b'D', sid, 32),
        mac_key_c2s: derive_key_sha256(shared_secret_mpint, exchange_hash, b'E', sid, 32),
        mac_key_s2c: derive_key_sha256(shared_secret_mpint, exchange_hash, b'F', sid, 32),
    }
}

/// Verify an SSH host key signature blob against an exchange hash.
fn verify_host_key_signature(
    host_key_blob: &[u8],
    exchange_hash: &[u8],
    signature_blob: &[u8],
) -> Result<(), RusshError> {
    let mut offset = 0;
    let algo = decode_ssh_string(host_key_blob, &mut offset)?;
    if algo != b"ssh-ed25519" {
        return Err(RusshError::new(
            RusshErrorCategory::Crypto,
            "unsupported host key algorithm",
        ));
    }
    let pubkey_bytes = decode_ssh_string(host_key_blob, &mut offset)?;
    let pubkey_arr: [u8; 32] = pubkey_bytes.try_into().map_err(|_| {
        RusshError::new(
            RusshErrorCategory::Crypto,
            "Ed25519 public key must be 32 bytes",
        )
    })?;

    let mut sig_offset = 0;
    let sig_algo = decode_ssh_string(signature_blob, &mut sig_offset)?;
    if sig_algo != b"ssh-ed25519" {
        return Err(RusshError::new(
            RusshErrorCategory::Crypto,
            "unsupported signature algorithm",
        ));
    }
    let sig_bytes = decode_ssh_string(signature_blob, &mut sig_offset)?;

    let verifier = Ed25519Verifier::from_bytes(&pubkey_arr)?;
    verifier.verify(exchange_hash, &sig_bytes)
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Poll, Waker};
    use std::time::Duration;

    use russh_auth::{AuthMethod, ServerAuthPolicy, UserAuthMessage, UserAuthRequest};
    use russh_core::{AlgorithmSet, PacketCodec, RusshErrorCategory};

    use super::{
        ClientConfig, ClientSession, DisconnectReasonCode, KexInitProposal, PeerDescription,
        ServerConfig, ServerSession, SessionState, TransportConfig, TransportEvent,
        TransportMessage,
    };

    fn block_on<T>(future: impl Future<Output = T>) -> T {
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        let mut future = Box::pin(future);

        loop {
            match Pin::as_mut(&mut future).poll(&mut context) {
                Poll::Ready(value) => return value,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    fn test_kexinit(cookie: [u8; 16]) -> TransportMessage {
        TransportMessage::KexInit {
            proposal: Box::new(KexInitProposal::from_algorithms(
                cookie,
                AlgorithmSet::secure_defaults(),
            )),
        }
    }

    fn test_kexinit_with_server_extensions(cookie: [u8; 16]) -> TransportMessage {
        TransportMessage::KexInit {
            proposal: Box::new(
                KexInitProposal::from_algorithms(cookie, AlgorithmSet::secure_defaults())
                    .with_server_extensions(),
            ),
        }
    }

    fn test_kexinit_with_client_extensions(cookie: [u8; 16]) -> TransportMessage {
        TransportMessage::KexInit {
            proposal: Box::new(
                KexInitProposal::from_algorithms(cookie, AlgorithmSet::secure_defaults())
                    .with_client_extensions(),
            ),
        }
    }

    #[test]
    fn secure_defaults_enable_host_checking() {
        let config = ClientConfig::secure_defaults("alice");
        assert!(config.strict_host_key_checking);
    }

    #[test]
    fn handshake_moves_to_algorithms_negotiated_state() {
        let mut session = ClientSession::new(ClientConfig::secure_defaults("alice"));
        block_on(session.handshake("SSH-2.0-OpenSSH_9.8")).expect("handshake should succeed");

        assert_eq!(session.state(), SessionState::AlgorithmsNegotiated);
        assert!(session.negotiated().is_some());
    }

    #[test]
    fn key_exchange_messages_establish_session() {
        let mut session = ClientSession::new(ClientConfig::secure_defaults("alice"));
        block_on(session.handshake("SSH-2.0-OpenSSH_9.8")).expect("handshake should succeed");

        let frame = session.send_kexinit().expect("KEXINIT should be encoded");
        let message = TransportMessage::from_frame(&frame).expect("frame should parse");
        assert!(matches!(message, TransportMessage::KexInit { .. }));

        session
            .receive_message(test_kexinit([0x22; 16]))
            .expect("peer KEXINIT should be accepted");
        session
            .receive_message(TransportMessage::NewKeys)
            .expect("NEWKEYS should complete key exchange");

        assert_eq!(session.state(), SessionState::Established);
        assert!(
            session
                .events()
                .iter()
                .any(|event| matches!(event, TransportEvent::KeyExchangeComplete { .. }))
        );
    }

    #[test]
    fn strict_kex_rejects_newkeys_without_local_kexinit() {
        let mut session = ClientSession::new(ClientConfig::secure_defaults("alice"));
        block_on(session.handshake("SSH-2.0-OpenSSH_9.8")).expect("handshake should succeed");

        session
            .receive_message(test_kexinit_with_server_extensions([0x66; 16]))
            .expect("peer KEXINIT should be accepted");
        let error = session
            .receive_message(TransportMessage::NewKeys)
            .expect_err("strict-kex should reject NEWKEYS before local KEXINIT");

        assert_eq!(error.category(), RusshErrorCategory::Protocol);
    }

    #[test]
    fn strict_kex_rejects_ignore_during_kex_window_and_closes_session() {
        let mut session = ClientSession::new(ClientConfig::secure_defaults("alice"));
        block_on(session.handshake("SSH-2.0-OpenSSH_9.8")).expect("handshake should succeed");

        session
            .send_kexinit()
            .expect("local KEXINIT should be sent before strict enforcement");
        session
            .receive_message(test_kexinit_with_server_extensions([0x67; 16]))
            .expect("peer KEXINIT should be accepted");
        let error = session
            .receive_message(TransportMessage::Ignore {
                data: vec![1, 2, 3],
            })
            .expect_err("strict-kex should reject non-kex packets");

        assert_eq!(error.category(), RusshErrorCategory::Protocol);
        assert_eq!(session.state(), SessionState::Closed);
        assert!(session.events().iter().any(|event| matches!(
            event,
            TransportEvent::Disconnected {
                code: DisconnectReasonCode::ProtocolError,
                ..
            }
        )));
    }

    #[test]
    fn kexinit_message_round_trip_preserves_algorithm_lists() {
        let proposal =
            KexInitProposal::from_algorithms([0x44; 16], AlgorithmSet::secure_defaults())
                .with_client_extensions()
                .with_server_extensions();
        let message = TransportMessage::KexInit {
            proposal: Box::new(proposal),
        };
        let frame = message.to_frame().expect("message should encode to frame");
        let decoded = TransportMessage::from_frame(&frame).expect("frame should parse");

        match decoded {
            TransportMessage::KexInit { proposal } => {
                assert_eq!(proposal.cookie, [0x44; 16]);
                assert!(
                    proposal
                        .kex_algorithms
                        .iter()
                        .any(|alg| alg == "curve25519-sha256")
                );
                assert!(proposal.ext_info_c);
                assert!(proposal.ext_info_s);
                assert!(proposal.strict_kex_c);
                assert!(proposal.strict_kex_s);
                assert!(
                    proposal
                        .compression_client_to_server
                        .iter()
                        .any(|alg| alg == "none")
                );
            }
            _ => panic!("expected KEXINIT message"),
        }
    }

    #[test]
    fn proposal_negotiation_tracks_directional_algorithms_and_flags() {
        let mut local =
            KexInitProposal::from_algorithms([0x10; 16], AlgorithmSet::secure_defaults())
                .with_client_extensions();
        local.ciphers_client_to_server = vec![
            "aes256-gcm@openssh.com".to_string(),
            "chacha20-poly1305@openssh.com".to_string(),
        ];
        local.ciphers_server_to_client = vec!["chacha20-poly1305@openssh.com".to_string()];
        local.macs_client_to_server = vec!["hmac-sha2-256-etm@openssh.com".to_string()];
        local.macs_server_to_client = vec![
            "hmac-sha2-512-etm@openssh.com".to_string(),
            "hmac-sha2-256-etm@openssh.com".to_string(),
        ];

        let mut remote =
            KexInitProposal::from_algorithms([0x20; 16], AlgorithmSet::secure_defaults())
                .with_server_extensions();
        remote.ciphers_client_to_server = vec![
            "chacha20-poly1305@openssh.com".to_string(),
            "aes128-gcm@openssh.com".to_string(),
        ];
        remote.ciphers_server_to_client = vec![
            "aes128-gcm@openssh.com".to_string(),
            "chacha20-poly1305@openssh.com".to_string(),
        ];
        remote.macs_client_to_server = vec!["hmac-sha2-256-etm@openssh.com".to_string()];
        remote.macs_server_to_client = vec![
            "hmac-sha2-256-etm@openssh.com".to_string(),
            "hmac-sha2-512-etm@openssh.com".to_string(),
        ];

        let negotiated = super::negotiate_algorithms_from_proposals(&local, &remote)
            .expect("proposal negotiation should succeed");

        assert_eq!(
            negotiated.cipher_client_to_server,
            "chacha20-poly1305@openssh.com"
        );
        assert_eq!(
            negotiated.cipher_server_to_client,
            "chacha20-poly1305@openssh.com"
        );
        assert_eq!(
            negotiated.mac_client_to_server,
            "hmac-sha2-256-etm@openssh.com"
        );
        assert_eq!(
            negotiated.mac_server_to_client,
            "hmac-sha2-512-etm@openssh.com"
        );
        assert!(negotiated.strict_kex);
        assert!(negotiated.ext_info_c);
        assert!(negotiated.ext_info_s);
    }

    #[test]
    fn ext_info_message_round_trip() {
        let message = TransportMessage::ExtInfo {
            extensions: vec![
                (
                    "server-sig-algs".to_string(),
                    "ssh-ed25519,rsa-sha2-512".to_string(),
                ),
                ("ping@openssh.com".to_string(), "1".to_string()),
            ],
        };
        let frame = message.to_frame().expect("EXT_INFO should encode");
        let decoded = TransportMessage::from_frame(&frame).expect("EXT_INFO should decode");

        assert_eq!(decoded, message);
    }

    #[test]
    fn disconnect_message_round_trip_with_reason_code() {
        let message = TransportMessage::Disconnect {
            code: DisconnectReasonCode::ProtocolError,
            reason: "strict-kex violation".to_string(),
        };
        let frame = message.to_frame().expect("disconnect should encode");
        let decoded = TransportMessage::from_frame(&frame).expect("disconnect should decode");
        assert_eq!(decoded, message);
    }

    #[test]
    fn client_records_ext_info_event() {
        let mut session = ClientSession::new(ClientConfig::secure_defaults("alice"));
        block_on(session.handshake("SSH-2.0-OpenSSH_9.8")).expect("handshake should succeed");
        session
            .send_kexinit()
            .expect("local KEXINIT should be sent for strict sequence");
        session
            .receive_message(test_kexinit_with_server_extensions([0x77; 16]))
            .expect("peer KEXINIT should be accepted");
        session
            .receive_message(TransportMessage::NewKeys)
            .expect("NEWKEYS should be accepted");
        session
            .receive_message(TransportMessage::ExtInfo {
                extensions: vec![("server-sig-algs".to_string(), "ssh-ed25519".to_string())],
            })
            .expect("EXT_INFO should be accepted");

        assert!(session.events().iter().any(
            |event| matches!(event, TransportEvent::ExtInfoReceived { extension_count } if *extension_count == 1)
        ));
    }

    #[test]
    fn client_encoded_sequence_mismatch_closes_with_protocol_error_code() {
        let codec = PacketCodec::with_defaults();
        let mut session = ClientSession::new(ClientConfig::secure_defaults("alice"));
        block_on(session.handshake("SSH-2.0-OpenSSH_9.8")).expect("handshake should succeed");

        let newkeys = TransportMessage::NewKeys
            .encode(&codec)
            .expect("NEWKEYS should encode");
        let error = session
            .receive_encoded_message_with_sequence(&codec, &newkeys, 2)
            .expect_err("sequence mismatch must fail");

        assert_eq!(error.category(), RusshErrorCategory::Protocol);
        assert_eq!(session.state(), SessionState::Closed);
        assert!(session.events().iter().any(|event| matches!(
            event,
            TransportEvent::Disconnected {
                code: DisconnectReasonCode::ProtocolError,
                ..
            }
        )));
    }

    #[test]
    fn client_decode_failure_maps_to_protocol_disconnect() {
        let codec = PacketCodec::with_defaults();
        let mut session = ClientSession::new(ClientConfig::secure_defaults("alice"));
        block_on(session.handshake("SSH-2.0-OpenSSH_9.8")).expect("handshake should succeed");

        let malformed = [0u8, 0, 0, 1, 0];
        let error = session
            .receive_encoded_message(&codec, &malformed)
            .expect_err("decode failure must fail");

        assert_eq!(error.category(), RusshErrorCategory::Protocol);
        assert_eq!(session.state(), SessionState::Closed);
        assert!(session.events().iter().any(|event| matches!(
            event,
            TransportEvent::Disconnected {
                code: DisconnectReasonCode::ProtocolError,
                reason
            } if reason.contains("failed to decode")
        )));
    }

    #[test]
    fn client_sequence_numbers_advance_with_send_and_receive() {
        let mut session = ClientSession::new(ClientConfig::secure_defaults("alice"));
        block_on(session.handshake("SSH-2.0-OpenSSH_9.8")).expect("handshake should succeed");

        assert_eq!(session.outgoing_sequence(), 0);
        assert_eq!(session.incoming_sequence(), 0);

        session.send_kexinit().expect("KEXINIT should send");
        assert_eq!(session.outgoing_sequence(), 1);

        session
            .receive_message(test_kexinit([0x11; 16]))
            .expect("peer KEXINIT should be accepted");
        session
            .receive_message(TransportMessage::NewKeys)
            .expect("NEWKEYS should be accepted");
        assert_eq!(session.incoming_sequence(), 2);

        session
            .send_service_request("ssh-userauth")
            .expect("service request should send");
        assert_eq!(session.outgoing_sequence(), 2);
    }

    #[test]
    fn service_request_round_trip_succeeds() {
        let codec = PacketCodec::with_defaults();
        let mut session = ClientSession::new(ClientConfig::secure_defaults("alice"));
        block_on(session.handshake("SSH-2.0-OpenSSH_9.8")).expect("handshake should succeed");
        session
            .receive_message(TransportMessage::NewKeys)
            .expect("NEWKEYS should establish session");

        let request = session
            .send_service_request("ssh-userauth")
            .expect("request should encode");
        let encoded = codec
            .encode(&request)
            .expect("packet encoding should succeed");
        let decoded = TransportMessage::decode(&codec, &encoded).expect("decode should succeed");

        assert_eq!(
            decoded,
            TransportMessage::ServiceRequest {
                service: "ssh-userauth".to_string()
            }
        );

        session
            .receive_message(TransportMessage::ServiceAccept {
                service: "ssh-userauth".to_string(),
            })
            .expect("service accept should succeed");

        assert_eq!(session.active_service(), Some("ssh-userauth"));
        assert_eq!(session.state(), SessionState::Established);
    }

    #[test]
    fn service_accept_with_wrong_service_fails() {
        let mut session = ClientSession::new(ClientConfig::secure_defaults("alice"));
        block_on(session.handshake("SSH-2.0-OpenSSH_9.8")).expect("handshake should succeed");
        session
            .receive_message(TransportMessage::NewKeys)
            .expect("NEWKEYS should establish session");
        session
            .send_service_request("ssh-userauth")
            .expect("request should encode");

        let error = session
            .receive_message(TransportMessage::ServiceAccept {
                service: "ssh-connection".to_string(),
            })
            .expect_err("mismatched service should fail");

        assert_eq!(error.category(), RusshErrorCategory::Protocol);
    }

    #[test]
    fn client_userauth_flow_marks_authenticated_user() {
        let mut session = ClientSession::new(ClientConfig::secure_defaults("alice"));
        block_on(session.handshake("SSH-2.0-OpenSSH_9.8")).expect("handshake should succeed");
        session
            .receive_message(TransportMessage::NewKeys)
            .expect("NEWKEYS should establish session");
        session
            .send_service_request("ssh-userauth")
            .expect("service request should be sent");
        session
            .receive_message(TransportMessage::ServiceAccept {
                service: "ssh-userauth".to_string(),
            })
            .expect("service should be accepted");

        let _auth_request = session
            .send_userauth_request(UserAuthRequest::Password {
                user: "alice".to_string(),
                service: "ssh-connection".to_string(),
                password: "top-secret".to_string(),
            })
            .expect("USERAUTH request should encode");
        session
            .receive_userauth_message(UserAuthMessage::Success)
            .expect("USERAUTH success should be handled");

        assert!(session.is_authenticated());
        assert_eq!(session.authenticated_user(), Some("alice"));
    }

    #[test]
    fn client_userauth_requires_active_userauth_service() {
        let mut session = ClientSession::new(ClientConfig::secure_defaults("alice"));
        block_on(session.handshake("SSH-2.0-OpenSSH_9.8")).expect("handshake should succeed");
        session
            .receive_message(TransportMessage::NewKeys)
            .expect("NEWKEYS should establish session");

        let error = session
            .send_userauth_request(UserAuthRequest::Password {
                user: "alice".to_string(),
                service: "ssh-connection".to_string(),
                password: "top-secret".to_string(),
            })
            .expect_err("USERAUTH should require active ssh-userauth service");
        assert_eq!(error.category(), RusshErrorCategory::Protocol);
    }

    #[test]
    fn server_userauth_success_response_is_emitted() {
        let mut server = ServerSession::new(ServerConfig::secure_defaults());
        server.activate_userauth(ServerAuthPolicy::secure_defaults());
        server
            .accept_banner("SSH-2.0-OpenSSH_9.8")
            .expect("banner should be accepted");
        server
            .negotiate_with_client(&AlgorithmSet::secure_defaults())
            .expect("negotiation should succeed");
        let _newkeys = server
            .receive_message(test_kexinit([0x92; 16]))
            .expect("server should accept KEXINIT")
            .expect("NEWKEYS response expected");
        server
            .receive_message(TransportMessage::NewKeys)
            .expect("server should accept client NEWKEYS");
        let _service_accept = server
            .receive_message(TransportMessage::ServiceRequest {
                service: "ssh-userauth".to_string(),
            })
            .expect("service request should succeed")
            .expect("service accept should be emitted");

        let response = server
            .receive_userauth_message(UserAuthMessage::Request(UserAuthRequest::Password {
                user: "alice".to_string(),
                service: "ssh-connection".to_string(),
                password: "pw".to_string(),
            }))
            .expect("USERAUTH request should be evaluated")
            .expect("server should emit USERAUTH response");

        assert_eq!(response, UserAuthMessage::Success);
        assert_eq!(server.authenticated_user(), Some("alice"));
    }

    #[test]
    fn server_userauth_partial_response_includes_remaining_methods() {
        let mut policy = ServerAuthPolicy::secure_defaults();
        policy
            .set_required_methods([AuthMethod::PublicKey, AuthMethod::KeyboardInteractive])
            .expect("required methods should be configured");

        let mut server = ServerSession::new(ServerConfig::secure_defaults());
        server.activate_userauth(policy);
        server
            .accept_banner("SSH-2.0-OpenSSH_9.8")
            .expect("banner should be accepted");
        server
            .negotiate_with_client(&AlgorithmSet::secure_defaults())
            .expect("negotiation should succeed");
        let _newkeys = server
            .receive_message(test_kexinit([0x93; 16]))
            .expect("server should accept KEXINIT")
            .expect("NEWKEYS response expected");
        server
            .receive_message(TransportMessage::NewKeys)
            .expect("server should accept client NEWKEYS");
        let _service_accept = server
            .receive_message(TransportMessage::ServiceRequest {
                service: "ssh-userauth".to_string(),
            })
            .expect("service request should succeed")
            .expect("service accept should be emitted");

        let response = server
            .receive_userauth_message(UserAuthMessage::Request(UserAuthRequest::PublicKey {
                user: "alice".to_string(),
                service: "ssh-connection".to_string(),
                algorithm: "ssh-ed25519".to_string(),
                public_key: vec![1, 2, 3, 4],
                signature: Some(vec![5, 6, 7]),
            }))
            .expect("USERAUTH request should be evaluated")
            .expect("server should emit USERAUTH response");

        assert_eq!(
            response,
            UserAuthMessage::Failure {
                methods: vec!["keyboard-interactive".to_string()],
                partial_success: true
            }
        );
        assert_eq!(server.authenticated_user(), None);
    }

    #[test]
    fn message_decode_rejects_malformed_service_request() {
        let codec = PacketCodec::with_defaults();
        let malformed = vec![
            0, 0, 0, 16, // packet length
            10, // padding length
            5,  // message type: SERVICE_REQUEST
            0, 0, 0, 10, // declared string length
            b's', b's', b'h', // truncated service
            1, 2, 3, 4, 5, 6, 7, // padding bytes
        ];

        let error = TransportMessage::decode(&codec, &malformed)
            .expect_err("malformed service request must fail");

        assert_eq!(error.category(), RusshErrorCategory::Protocol);
    }

    #[test]
    fn message_decode_rejects_kexinit_without_required_lists() {
        let codec = PacketCodec::with_defaults();
        let invalid_kexinit = TransportMessage::KexInit {
            proposal: Box::new(KexInitProposal {
                cookie: [0x55; 16],
                kex_algorithms: Vec::new(),
                host_key_algorithms: vec!["ssh-ed25519".to_string()],
                ciphers_client_to_server: vec!["chacha20-poly1305@openssh.com".to_string()],
                ciphers_server_to_client: vec!["chacha20-poly1305@openssh.com".to_string()],
                macs_client_to_server: vec!["hmac-sha2-256-etm@openssh.com".to_string()],
                macs_server_to_client: vec!["hmac-sha2-256-etm@openssh.com".to_string()],
                compression_client_to_server: vec!["none".to_string()],
                compression_server_to_client: vec!["none".to_string()],
                languages_client_to_server: Vec::new(),
                languages_server_to_client: Vec::new(),
                first_kex_packet_follows: false,
                ext_info_c: false,
                ext_info_s: false,
                strict_kex_c: false,
                strict_kex_s: false,
            }),
        };

        let encoded = invalid_kexinit
            .encode(&codec)
            .expect("encoding happens before validation");
        let error = TransportMessage::decode(&codec, &encoded)
            .expect_err("decode must reject missing required KEXINIT lists");

        assert_eq!(error.category(), RusshErrorCategory::Protocol);
    }

    #[test]
    fn client_handshake_rejects_unsupported_banner() {
        let mut session = ClientSession::new(ClientConfig::secure_defaults("alice"));
        let error = block_on(session.handshake("SSH-1.5-legacy"))
            .expect_err("handshake should reject unsupported banners");
        assert_eq!(error.category(), RusshErrorCategory::Interop);
    }

    #[test]
    fn client_handshake_fails_without_shared_cipher() {
        let mut session = ClientSession::new(ClientConfig::secure_defaults("alice"));
        let mut remote = AlgorithmSet::secure_defaults();
        remote.ciphers = vec!["arcfour".to_string()];

        let error = block_on(session.handshake_with_peer(PeerDescription {
            banner: "SSH-2.0-OpenSSH_9.8".to_string(),
            algorithms: remote,
        }))
        .expect_err("handshake should fail without shared cipher");

        assert_eq!(error.category(), RusshErrorCategory::Crypto);
    }

    #[test]
    fn client_rekeys_on_byte_threshold() {
        let transport = TransportConfig::builder().rekey_after_bytes(32).build();
        let mut config = ClientConfig::secure_defaults("alice");
        config.transport = transport;

        let mut session = ClientSession::new(config);
        block_on(session.handshake("SSH-2.0-OpenSSH_9.8")).expect("handshake should succeed");
        session
            .receive_message(TransportMessage::NewKeys)
            .expect("NEWKEYS should establish session");

        let rekeyed = session
            .account_payload(64)
            .expect("accounting should succeed in established state");

        assert!(rekeyed);
        assert!(
            session
                .events()
                .iter()
                .any(|event| matches!(event, TransportEvent::RekeyStarted))
        );
    }

    #[test]
    fn client_rekeys_on_elapsed_time() {
        let transport = TransportConfig::builder()
            .rekey_after_duration(Duration::from_secs(10))
            .build();
        let mut config = ClientConfig::secure_defaults("alice");
        config.transport = transport;

        let mut session = ClientSession::new(config);
        block_on(session.handshake("SSH-2.0-OpenSSH_9.8")).expect("handshake should succeed");
        session
            .receive_message(TransportMessage::NewKeys)
            .expect("NEWKEYS should establish session");

        let rekeyed = session
            .advance_time(Duration::from_secs(11))
            .expect("time advancement should succeed");

        assert!(rekeyed);
    }

    #[test]
    fn client_keepalive_resets_after_emit_and_activity() {
        let transport = TransportConfig::builder()
            .keepalive_interval(Duration::from_secs(10))
            .build();
        let mut config = ClientConfig::secure_defaults("alice");
        config.transport = transport;

        let mut session = ClientSession::new(config);
        block_on(session.handshake("SSH-2.0-OpenSSH_9.8")).expect("handshake should succeed");
        session
            .receive_message(TransportMessage::NewKeys)
            .expect("NEWKEYS should establish session");

        session
            .advance_time(Duration::from_secs(9))
            .expect("time advancement should succeed");
        assert!(
            !session
                .events()
                .iter()
                .any(|event| matches!(event, TransportEvent::KeepaliveSent))
        );

        session
            .advance_time(Duration::from_secs(1))
            .expect("time advancement should succeed");
        assert_eq!(
            session
                .events()
                .iter()
                .filter(|event| matches!(event, TransportEvent::KeepaliveSent))
                .count(),
            1
        );

        session
            .advance_time(Duration::from_secs(1))
            .expect("time advancement should succeed");
        assert_eq!(
            session
                .events()
                .iter()
                .filter(|event| matches!(event, TransportEvent::KeepaliveSent))
                .count(),
            1
        );

        session
            .receive_message(TransportMessage::Ignore {
                data: vec![1, 2, 3],
            })
            .expect("IGNORE should be accepted");
        session
            .advance_time(Duration::from_secs(10))
            .expect("time advancement should succeed");
        assert_eq!(
            session
                .events()
                .iter()
                .filter(|event| matches!(event, TransportEvent::KeepaliveSent))
                .count(),
            2
        );
    }

    #[test]
    fn client_idle_timeout_closes_session() {
        let transport = TransportConfig::builder()
            .idle_timeout(Duration::from_secs(5))
            .keepalive_interval(Duration::from_secs(30))
            .build();
        let mut config = ClientConfig::secure_defaults("alice");
        config.transport = transport;

        let mut session = ClientSession::new(config);
        block_on(session.handshake("SSH-2.0-OpenSSH_9.8")).expect("handshake should succeed");
        session
            .receive_message(TransportMessage::NewKeys)
            .expect("NEWKEYS should establish session");

        session
            .advance_time(Duration::from_secs(5))
            .expect("time advancement should succeed");

        assert_eq!(session.state(), SessionState::Closed);
        assert!(session.events().iter().any(|event| matches!(
            event,
            TransportEvent::Disconnected {
                code: DisconnectReasonCode::ByApplication,
                reason
            } if reason.contains("idle timeout")
        )));
    }

    #[test]
    fn server_requires_banner_before_negotiation() {
        let mut server = ServerSession::new(ServerConfig::secure_defaults());
        let error = server
            .negotiate_with_client(&AlgorithmSet::secure_defaults())
            .expect_err("negotiation must fail before banner");
        assert_eq!(error.category(), RusshErrorCategory::Protocol);
    }

    #[test]
    fn server_negotiation_and_kex_complete_flow() {
        let mut server = ServerSession::new(ServerConfig::secure_defaults());
        server
            .accept_banner("SSH-2.0-OpenSSH_9.8")
            .expect("banner should be accepted");
        let negotiated = server
            .negotiate_with_client(&AlgorithmSet::secure_defaults())
            .expect("negotiation should succeed");

        assert_eq!(negotiated.kex, "curve25519-sha256");
        assert_eq!(server.state(), SessionState::AlgorithmsNegotiated);

        let reply = server
            .receive_message(test_kexinit([0x33; 16]))
            .expect("server should accept KEXINIT")
            .expect("server should produce NEWKEYS");
        assert_eq!(reply, TransportMessage::NewKeys);
        assert_eq!(server.state(), SessionState::Established);
    }

    #[test]
    fn server_strict_kex_requires_client_newkeys_before_service() {
        let mut server = ServerSession::new(ServerConfig::secure_defaults());
        server
            .accept_banner("SSH-2.0-OpenSSH_9.8")
            .expect("banner should be accepted");
        server
            .negotiate_with_client(&AlgorithmSet::secure_defaults())
            .expect("negotiation should succeed");

        let _newkeys = server
            .receive_message(test_kexinit_with_client_extensions([0x88; 16]))
            .expect("server should accept strict client KEXINIT")
            .expect("server should produce NEWKEYS");

        let error = server
            .receive_message(TransportMessage::ServiceRequest {
                service: "ssh-userauth".to_string(),
            })
            .expect_err("strict-kex should require NEWKEYS before service");
        assert_eq!(error.category(), RusshErrorCategory::Protocol);
        assert_eq!(server.state(), SessionState::Closed);
    }

    #[test]
    fn server_strict_kex_allows_service_after_client_newkeys() {
        let mut server = ServerSession::new(ServerConfig::secure_defaults());
        server
            .accept_banner("SSH-2.0-OpenSSH_9.8")
            .expect("banner should be accepted");
        server
            .negotiate_with_client(&AlgorithmSet::secure_defaults())
            .expect("negotiation should succeed");

        let _newkeys = server
            .receive_message(test_kexinit_with_client_extensions([0x89; 16]))
            .expect("server should accept strict client KEXINIT")
            .expect("server should produce NEWKEYS");

        server
            .receive_message(TransportMessage::NewKeys)
            .expect("server should accept client NEWKEYS");
        let response = server
            .receive_message(TransportMessage::ServiceRequest {
                service: "ssh-userauth".to_string(),
            })
            .expect("service request should succeed after NEWKEYS")
            .expect("service accept response expected");
        assert_eq!(
            response,
            TransportMessage::ServiceAccept {
                service: "ssh-userauth".to_string()
            }
        );
    }

    #[test]
    fn server_sequence_numbers_advance_with_traffic() {
        let mut server = ServerSession::new(ServerConfig::secure_defaults());
        server
            .accept_banner("SSH-2.0-OpenSSH_9.8")
            .expect("banner should be accepted");
        server
            .negotiate_with_client(&AlgorithmSet::secure_defaults())
            .expect("negotiation should succeed");

        let reply = server
            .receive_message(test_kexinit([0x90; 16]))
            .expect("KEXINIT should succeed")
            .expect("NEWKEYS expected");
        assert_eq!(reply, TransportMessage::NewKeys);
        assert_eq!(server.incoming_sequence(), 1);
        assert_eq!(server.outgoing_sequence(), 1);

        server
            .receive_message(TransportMessage::NewKeys)
            .expect("client NEWKEYS should be accepted");
        assert_eq!(server.incoming_sequence(), 2);
        assert_eq!(server.outgoing_sequence(), 1);

        let service_reply = server
            .receive_message(TransportMessage::ServiceRequest {
                service: "ssh-userauth".to_string(),
            })
            .expect("service request should succeed")
            .expect("service accept expected");
        assert_eq!(
            service_reply,
            TransportMessage::ServiceAccept {
                service: "ssh-userauth".to_string()
            }
        );
        assert_eq!(server.incoming_sequence(), 3);
        assert_eq!(server.outgoing_sequence(), 2);
    }

    #[test]
    fn server_encoded_sequence_mismatch_closes_session() {
        let codec = PacketCodec::with_defaults();
        let mut server = ServerSession::new(ServerConfig::secure_defaults());
        server
            .accept_banner("SSH-2.0-OpenSSH_9.8")
            .expect("banner should be accepted");
        server
            .negotiate_with_client(&AlgorithmSet::secure_defaults())
            .expect("negotiation should succeed");

        let encoded = test_kexinit([0x91; 16])
            .encode(&codec)
            .expect("KEXINIT should encode");
        let error = server
            .receive_encoded_message_with_sequence(&codec, &encoded, 7)
            .expect_err("sequence mismatch must fail");

        assert_eq!(error.category(), RusshErrorCategory::Protocol);
        assert_eq!(server.state(), SessionState::Closed);
    }

    #[test]
    fn server_keyboard_interactive_flow_completes_authentication() {
        let mut server = ServerSession::new(ServerConfig::secure_defaults());
        server.activate_userauth(ServerAuthPolicy::secure_defaults());
        server
            .accept_banner("SSH-2.0-OpenSSH_9.8")
            .expect("banner should be accepted");
        server
            .negotiate_with_client(&AlgorithmSet::secure_defaults())
            .expect("negotiation should succeed");
        let _newkeys = server
            .receive_message(test_kexinit([0x94; 16]))
            .expect("server should accept KEXINIT")
            .expect("NEWKEYS response expected");
        server
            .receive_message(TransportMessage::NewKeys)
            .expect("server should accept client NEWKEYS");
        let _service_accept = server
            .receive_message(TransportMessage::ServiceRequest {
                service: "ssh-userauth".to_string(),
            })
            .expect("service request should succeed")
            .expect("service accept should be emitted");

        // Step 1: client sends keyboard-interactive request
        let info_request = server
            .receive_userauth_message(UserAuthMessage::Request(
                UserAuthRequest::KeyboardInteractive {
                    user: "alice".to_string(),
                    service: "ssh-connection".to_string(),
                    language_tag: String::new(),
                    submethods: String::new(),
                },
            ))
            .expect("keyboard-interactive request should succeed")
            .expect("server should emit InfoRequest");

        assert!(
            matches!(
                info_request,
                UserAuthMessage::KeyboardInteractiveInfoRequest { .. }
            ),
            "expected KeyboardInteractiveInfoRequest, got {info_request:?}"
        );

        // Step 2: client sends responses
        let result = server
            .receive_userauth_message(UserAuthMessage::KeyboardInteractiveInfoResponse {
                responses: vec!["mysecret".to_string()],
            })
            .expect("InfoResponse should succeed")
            .expect("server should emit Success or Failure");

        assert_eq!(result, UserAuthMessage::Success);
        assert_eq!(server.authenticated_user(), Some("alice"));
    }

    #[test]
    fn server_keyboard_interactive_response_without_pending_request_errors() {
        let mut server = ServerSession::new(ServerConfig::secure_defaults());
        server.activate_userauth(ServerAuthPolicy::secure_defaults());
        server
            .accept_banner("SSH-2.0-OpenSSH_9.8")
            .expect("banner should be accepted");
        server
            .negotiate_with_client(&AlgorithmSet::secure_defaults())
            .expect("negotiation should succeed");
        let _newkeys = server
            .receive_message(test_kexinit([0x95; 16]))
            .expect("server should accept KEXINIT")
            .expect("NEWKEYS response expected");
        server
            .receive_message(TransportMessage::NewKeys)
            .expect("server should accept client NEWKEYS");
        let _service_accept = server
            .receive_message(TransportMessage::ServiceRequest {
                service: "ssh-userauth".to_string(),
            })
            .expect("service request should succeed")
            .expect("service accept should be emitted");

        // Send InfoResponse without a preceding keyboard-interactive request
        let error = server
            .receive_userauth_message(UserAuthMessage::KeyboardInteractiveInfoResponse {
                responses: vec!["password".to_string()],
            })
            .expect_err("should error without pending keyboard-interactive request");

        assert_eq!(error.category(), RusshErrorCategory::Auth);
    }
}
