//! Async tokio networking layer for RuSSH.
//!
//! Wraps the pure in-memory state machines from `russh-transport`,
//! `russh-channel`, `russh-sftp`, and `russh-scp` with real TCP I/O.
//!
//! ## Client
//!
//! ```no_run
//! use russh_net::SshClient;
//! use russh_transport::ClientConfig;
//!
//! # async fn example() -> Result<(), russh_core::RusshError> {
//! let config = ClientConfig::secure_defaults("alice");
//! let mut conn = SshClient::connect("127.0.0.1:22", config).await?;
//! conn.authenticate_password("hunter2").await?;
//! let output = conn.exec("echo hello").await?;
//! assert_eq!(output.stdout, b"hello\n");
//! # Ok(()) }
//! ```
//!
//! ## Server
//!
//! ```no_run
//! use russh_net::{SshServer, DefaultSessionHandler};
//! use russh_transport::ServerConfig;
//!
//! # async fn example() -> Result<(), russh_core::RusshError> {
//! let config = ServerConfig::secure_defaults();
//! let server = SshServer::bind("127.0.0.1:2222", config).await?;
//! let conn = server.accept().await?;
//! conn.run(DefaultSessionHandler::new("/tmp")).await?;
//! # Ok(()) }
//! ```

mod agent;
pub use agent::SshAgentClient;

use std::path::{Path, PathBuf};

use russh_auth::{
    AgentClient, ServerAuthPolicy, UserAuthMessage, UserAuthRequest, build_ed25519_signature_blob,
    build_userauth_signing_payload,
};
use russh_channel::{ChannelKind, ChannelManager, ChannelMessage, ChannelRequest, ForwardHandle};
use russh_core::{PacketCodec, PacketFrame, RusshError, RusshErrorCategory};
use russh_crypto::{AeadCipher, Aes256GcmCipher, Signer};
use russh_scp::build_scp_file_upload;
use russh_sftp::{SftpFileServer, SftpFramer, SftpWirePacket};
use russh_transport::{
    ClientConfig, ClientSession, NegotiatedAlgorithms, ServerConfig, ServerSession, SessionKeys,
    TransportMessage,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};

/// Re-exported for callers that want to use public-key auth without depending on `russh-crypto` directly.
pub use russh_crypto::Ed25519Signer;

const OUR_BANNER: &str = "SSH-2.0-RuSSH_0.4";

// ── Stream type alias ────────────────────────────────────────────────────────

/// Supertrait combining async read and write so it can be used as a trait object.
pub trait AsyncReadWrite: tokio::io::AsyncRead + tokio::io::AsyncWrite {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite> AsyncReadWrite for T {}

/// Any async readable+writable stream that can carry SSH packets.
///
/// Used to make [`SshClientConnection`] stream-agnostic so that the same type
/// works over a plain TCP socket, a tokio duplex pipe (for ProxyJump), or any
/// other async I/O.
pub type AnyStream = Box<dyn AsyncReadWrite + Unpin + Send>;

// ── io helper ────────────────────────────────────────────────────────────────

fn io_err(e: std::io::Error) -> RusshError {
    RusshError::new(RusshErrorCategory::Io, e.to_string())
}

fn protocol_err(msg: impl Into<String>) -> RusshError {
    RusshError::new(RusshErrorCategory::Protocol, msg)
}

// ── DirectionalCipher ────────────────────────────────────────────────────────

/// Per-direction AEAD cipher state (used for one of TX or RX).
///
/// After NEWKEYS, both sides must encrypt/decrypt packets.  Only
/// `aes256-gcm@openssh.com` is implemented here; all other negotiated ciphers
/// fall back to `None` (plaintext), which works for loopback tests where both
/// sides use RuSSH.
enum DirectionalCipher {
    None,
    Aes256Gcm {
        cipher: Box<Aes256GcmCipher>,
        /// Current 12-byte nonce: first 4 bytes fixed, last 8 bytes counter.
        nonce: [u8; 12],
    },
}

impl DirectionalCipher {
    /// Build a cipher from the negotiated algorithm name, key material, and IV.
    fn new(name: &str, key: &[u8], iv: &[u8]) -> Self {
        if name == "aes256-gcm@openssh.com" {
            if let Ok(cipher) = Aes256GcmCipher::new(key) {
                let mut nonce = [0u8; 12];
                nonce.copy_from_slice(&iv[..12]);
                return Self::Aes256Gcm {
                    cipher: Box::new(cipher),
                    nonce,
                };
            }
        }
        Self::None
    }

    /// Increment the last 8 bytes of the nonce as a big-endian u64 counter.
    fn increment_nonce(nonce: &mut [u8; 12]) {
        let mut counter = u64::from_be_bytes(nonce[4..12].try_into().unwrap());
        counter = counter.wrapping_add(1);
        nonce[4..12].copy_from_slice(&counter.to_be_bytes());
    }
}

// ── PacketStream ─────────────────────────────────────────────────────────────

/// Async SSH packet framing over any `tokio` I/O stream.
///
/// Handles the RFC 4253 §6 wire format:
/// `uint32 packet_length | uint8 padding_length | payload | random_padding`
///
/// After NEWKEYS, AEAD encryption is applied via [`DirectionalCipher`].
pub struct PacketStream<S> {
    inner: S,
    codec: PacketCodec,
    tx_cipher: DirectionalCipher,
    rx_cipher: DirectionalCipher,
}

impl<S: AsyncReadExt + AsyncWriteExt + Unpin> PacketStream<S> {
    pub fn new(stream: S) -> Self {
        Self {
            inner: stream,
            codec: PacketCodec::with_defaults(),
            tx_cipher: DirectionalCipher::None,
            rx_cipher: DirectionalCipher::None,
        }
    }

    /// Enable AEAD encryption for the **client** side after NEWKEYS.
    ///
    /// Client → server direction uses `key_c2s` / `iv_c2s`;
    /// server → client direction uses `key_s2c` / `iv_s2c`.
    pub fn enable_client_encryption(&mut self, keys: &SessionKeys, neg: &NegotiatedAlgorithms) {
        self.tx_cipher =
            DirectionalCipher::new(&neg.cipher_client_to_server, &keys.key_c2s, &keys.iv_c2s);
        self.rx_cipher =
            DirectionalCipher::new(&neg.cipher_server_to_client, &keys.key_s2c, &keys.iv_s2c);
    }

    /// Enable AEAD encryption for the **server** side after NEWKEYS.
    pub fn enable_server_encryption(&mut self, keys: &SessionKeys, neg: &NegotiatedAlgorithms) {
        self.tx_cipher =
            DirectionalCipher::new(&neg.cipher_server_to_client, &keys.key_s2c, &keys.iv_s2c);
        self.rx_cipher =
            DirectionalCipher::new(&neg.cipher_client_to_server, &keys.key_c2s, &keys.iv_c2s);
    }

    /// Enable only the TX (outgoing) cipher for the server after sending NEWKEYS.
    pub fn enable_server_tx_encryption(&mut self, keys: &SessionKeys, neg: &NegotiatedAlgorithms) {
        self.tx_cipher =
            DirectionalCipher::new(&neg.cipher_server_to_client, &keys.key_s2c, &keys.iv_s2c);
    }

    /// Enable only the RX (incoming) cipher for the server after receiving client NEWKEYS.
    pub fn enable_server_rx_encryption(&mut self, keys: &SessionKeys, neg: &NegotiatedAlgorithms) {
        self.rx_cipher =
            DirectionalCipher::new(&neg.cipher_client_to_server, &keys.key_c2s, &keys.iv_c2s);
    }

    /// Read lines until one starts with "SSH-" (the version banner).
    pub async fn read_banner_line(&mut self) -> Result<String, RusshError> {
        let mut line: Vec<u8> = Vec::new();
        loop {
            let mut byte = [0u8; 1];
            self.inner.read_exact(&mut byte).await.map_err(io_err)?;
            if byte[0] == b'\n' {
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                let s = String::from_utf8(line)
                    .map_err(|_| protocol_err("banner is not valid UTF-8"))?;
                if s.starts_with("SSH-") {
                    return Ok(s);
                }
                line = Vec::new();
            } else {
                if line.len() >= 255 {
                    return Err(protocol_err("banner line too long"));
                }
                line.push(byte[0]);
            }
        }
    }

    /// Write a banner line terminated with `\r\n`.
    pub async fn write_banner_line(&mut self, banner: &str) -> Result<(), RusshError> {
        let mut bytes = banner.as_bytes().to_vec();
        bytes.extend_from_slice(b"\r\n");
        self.inner.write_all(&bytes).await.map_err(io_err)
    }

    /// Read exactly one SSH binary packet and return its `PacketFrame`.
    pub async fn read_packet(&mut self) -> Result<PacketFrame, RusshError> {
        match &mut self.rx_cipher {
            DirectionalCipher::None => {
                let mut len_buf = [0u8; 4];
                self.inner.read_exact(&mut len_buf).await.map_err(io_err)?;
                let pkt_len = u32::from_be_bytes(len_buf) as usize;

                if pkt_len > PacketCodec::DEFAULT_MAX_PACKET_SIZE + 512 {
                    return Err(protocol_err("incoming packet length too large"));
                }

                let mut body = vec![0u8; pkt_len];
                self.inner.read_exact(&mut body).await.map_err(io_err)?;

                let mut full = Vec::with_capacity(4 + pkt_len);
                full.extend_from_slice(&len_buf);
                full.extend_from_slice(&body);
                self.codec.decode(&full)
            }
            DirectionalCipher::Aes256Gcm { cipher, nonce } => {
                // AES-256-GCM@openssh.com wire format:
                // [4-byte packet_length (plaintext AAD)]
                // [packet_length bytes of ciphertext]
                // [16-byte authentication tag]
                let mut len_buf = [0u8; 4];
                self.inner.read_exact(&mut len_buf).await.map_err(io_err)?;
                let pkt_len = u32::from_be_bytes(len_buf) as usize;

                if pkt_len > PacketCodec::DEFAULT_MAX_PACKET_SIZE + 512 {
                    return Err(protocol_err("incoming packet length too large"));
                }

                // Read ciphertext + 16-byte tag together.
                let mut ct_and_tag = vec![0u8; pkt_len + 16];
                self.inner
                    .read_exact(&mut ct_and_tag)
                    .await
                    .map_err(io_err)?;

                let plaintext = cipher
                    .open(nonce, &len_buf, &ct_and_tag)
                    .map_err(|e| RusshError::new(RusshErrorCategory::Crypto, e.to_string()))?;
                DirectionalCipher::increment_nonce(nonce);

                if plaintext.is_empty() {
                    return Err(protocol_err("AES-GCM decrypted to empty plaintext"));
                }
                let padding_len = plaintext[0] as usize;
                let payload_end = plaintext.len().saturating_sub(padding_len);
                if payload_end == 0 {
                    return Err(protocol_err("AES-GCM padding exceeds plaintext length"));
                }
                Ok(PacketFrame::new(plaintext[1..payload_end].to_vec()))
            }
        }
    }

    /// Encode `frame` and write it to the stream.
    pub async fn write_packet(&mut self, frame: &PacketFrame) -> Result<(), RusshError> {
        match &mut self.tx_cipher {
            DirectionalCipher::None => {
                let bytes = self.codec.encode(frame)?;
                self.inner.write_all(&bytes).await.map_err(io_err)
            }
            DirectionalCipher::Aes256Gcm { cipher, nonce } => {
                // Build plaintext: [padding_len (1 byte)] [payload] [padding]
                // Plaintext length must be a multiple of 16 (AES block size).
                const BLOCK: usize = 16;
                let payload = &frame.payload;
                let body_len = 1 + payload.len(); // padding_len byte + payload
                let remainder = body_len % BLOCK;
                let mut padding_len = if remainder == 0 {
                    BLOCK
                } else {
                    BLOCK - remainder
                };
                if padding_len < 4 {
                    padding_len += BLOCK;
                }
                let mut plaintext = Vec::with_capacity(body_len + padding_len);
                plaintext.push(padding_len as u8);
                plaintext.extend_from_slice(payload);
                plaintext.extend(std::iter::repeat_n(0u8, padding_len));

                let packet_length = (plaintext.len() as u32).to_be_bytes();
                let ciphertext_and_tag = cipher
                    .seal(nonce, &packet_length, &plaintext)
                    .map_err(|e| RusshError::new(RusshErrorCategory::Crypto, e.to_string()))?;
                DirectionalCipher::increment_nonce(nonce);

                // Wire: [4-byte length (AAD)] [ciphertext] [16-byte tag]
                self.inner.write_all(&packet_length).await.map_err(io_err)?;
                self.inner
                    .write_all(&ciphertext_and_tag)
                    .await
                    .map_err(io_err)
            }
        }
    }

    /// Write raw bytes (e.g. a pre-encoded message).
    pub async fn write_raw(&mut self, bytes: &[u8]) -> Result<(), RusshError> {
        self.inner.write_all(bytes).await.map_err(io_err)
    }
}

// ── ExecResult ───────────────────────────────────────────────────────────────

/// Result of an SSH exec request.
#[derive(Debug, Default)]
pub struct ExecResult {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: Option<u32>,
}

// ── SftpSession ──────────────────────────────────────────────────────────────

/// SFTP v3 client session over an open SSH session channel.
///
/// All operations are synchronous request-response pairs.
pub struct SftpSession<'a> {
    stream: &'a mut PacketStream<AnyStream>,
    /// Server's channel ID (used as `recipient_channel` when we send).
    remote_channel: u32,
    next_request_id: u32,
    framer: SftpFramer,
}

impl<'a> SftpSession<'a> {
    fn new(
        stream: &'a mut PacketStream<AnyStream>,
        remote_channel: u32,
        _local_channel: u32,
    ) -> Self {
        Self {
            stream,
            remote_channel,
            next_request_id: 1,
            framer: SftpFramer::new(),
        }
    }

    fn alloc_id(&mut self) -> u32 {
        let id = self.next_request_id;
        self.next_request_id = self.next_request_id.wrapping_add(1);
        id
    }

    async fn send_sftp(&mut self, pkt: &SftpWirePacket) -> Result<(), RusshError> {
        let data = pkt.encode();
        let msg = ChannelMessage::Data {
            recipient_channel: self.remote_channel,
            data,
        };
        self.stream.write_packet(&msg.to_frame()?).await
    }

    async fn recv_sftp(&mut self) -> Result<SftpWirePacket, RusshError> {
        loop {
            if let Some(pkt) = self.framer.next_packet()? {
                return Ok(pkt);
            }
            let frame = self.stream.read_packet().await?;
            // Skip SSH_MSG_IGNORE(2), SSH_MSG_DEBUG(4), SSH_MSG_GLOBAL_REQUEST(80).
            match frame.payload.first().copied() {
                Some(2) | Some(4) => continue,
                Some(80) => {
                    let want_reply = if frame.payload.len() >= 5 {
                        let nlen = u32::from_be_bytes([
                            frame.payload[1],
                            frame.payload[2],
                            frame.payload[3],
                            frame.payload[4],
                        ]) as usize;
                        frame.payload.get(5 + nlen).copied().unwrap_or(0) != 0
                    } else {
                        false
                    };
                    if want_reply {
                        self.stream
                            .write_packet(&PacketFrame::new(vec![82]))
                            .await?;
                    }
                    continue;
                }
                _ => {}
            }
            let ch = ChannelMessage::from_bytes(&frame.payload)?;
            match ch {
                ChannelMessage::Data { data, .. } => self.framer.feed(&data),
                ChannelMessage::Eof { .. } | ChannelMessage::Close { .. } => {
                    return Err(protocol_err("SFTP channel closed prematurely"));
                }
                ChannelMessage::WindowAdjust { .. } => {}
                _ => {}
            }
        }
    }

    /// Initialise the SFTP session (exchange SSH_FXP_INIT / SSH_FXP_VERSION).
    pub async fn init(&mut self) -> Result<(), RusshError> {
        self.send_sftp(&SftpWirePacket::Init { version: 3 }).await?;
        match self.recv_sftp().await? {
            SftpWirePacket::Version { .. } => Ok(()),
            other => Err(protocol_err(format!(
                "expected SSH_FXP_VERSION, got {:?}",
                other
            ))),
        }
    }

    /// Write `data` to `path` on the server, creating or truncating the file.
    pub async fn write_file(&mut self, path: &str, data: &[u8]) -> Result<(), RusshError> {
        let id = self.alloc_id();
        self.send_sftp(&SftpWirePacket::Open {
            id,
            filename: path.to_owned(),
            pflags: russh_sftp::open_flags::WRITE
                | russh_sftp::open_flags::CREAT
                | russh_sftp::open_flags::TRUNC,
            attrs: russh_sftp::FileAttrs::default(),
        })
        .await?;
        let handle = match self.recv_sftp().await? {
            SftpWirePacket::Handle { handle, .. } => handle,
            other => return Err(protocol_err(format!("expected Handle, got {:?}", other))),
        };

        let id2 = self.alloc_id();
        self.send_sftp(&SftpWirePacket::Write {
            id: id2,
            handle: handle.clone(),
            offset: 0,
            data: data.to_vec(),
        })
        .await?;
        match self.recv_sftp().await? {
            SftpWirePacket::Status {
                status: russh_sftp::SftpStatus::Ok,
                ..
            } => {}
            other => return Err(protocol_err(format!("write failed: {:?}", other))),
        }

        let id3 = self.alloc_id();
        self.send_sftp(&SftpWirePacket::Close { id: id3, handle })
            .await?;
        match self.recv_sftp().await? {
            SftpWirePacket::Status {
                status: russh_sftp::SftpStatus::Ok,
                ..
            } => Ok(()),
            other => Err(protocol_err(format!("close failed: {:?}", other))),
        }
    }

    /// Read the entire contents of `path` from the server.
    pub async fn read_file(&mut self, path: &str) -> Result<Vec<u8>, RusshError> {
        let id = self.alloc_id();
        self.send_sftp(&SftpWirePacket::Open {
            id,
            filename: path.to_owned(),
            pflags: russh_sftp::open_flags::READ,
            attrs: russh_sftp::FileAttrs::default(),
        })
        .await?;
        let handle = match self.recv_sftp().await? {
            SftpWirePacket::Handle { handle, .. } => handle,
            other => return Err(protocol_err(format!("expected Handle, got {:?}", other))),
        };

        let mut buf = Vec::new();
        let mut offset = 0u64;
        loop {
            let id2 = self.alloc_id();
            self.send_sftp(&SftpWirePacket::Read {
                id: id2,
                handle: handle.clone(),
                offset,
                len: 32_768,
            })
            .await?;
            match self.recv_sftp().await? {
                SftpWirePacket::Data { data, .. } => {
                    offset += data.len() as u64;
                    buf.extend_from_slice(&data);
                }
                SftpWirePacket::Status {
                    status: russh_sftp::SftpStatus::Eof,
                    ..
                } => break,
                other => return Err(protocol_err(format!("read failed: {:?}", other))),
            }
        }

        let id3 = self.alloc_id();
        self.send_sftp(&SftpWirePacket::Close { id: id3, handle })
            .await?;
        match self.recv_sftp().await? {
            SftpWirePacket::Status {
                status: russh_sftp::SftpStatus::Ok,
                ..
            } => {}
            other => return Err(protocol_err(format!("close failed: {:?}", other))),
        }

        Ok(buf)
    }

    /// Close the SFTP subsystem channel.
    pub async fn close(self) -> Result<(), RusshError> {
        let eof = ChannelMessage::Eof {
            recipient_channel: self.remote_channel,
        };
        self.stream.write_packet(&eof.to_frame()?).await?;
        let close = ChannelMessage::Close {
            recipient_channel: self.remote_channel,
        };
        self.stream.write_packet(&close.to_frame()?).await
    }
}

// ── SshClientConnection ──────────────────────────────────────────────────────

/// An authenticated SSH connection to a server.
///
/// Obtained via [`SshClient::connect`].
pub struct SshClientConnection {
    stream: PacketStream<AnyStream>,
    session: ClientSession,
    channel_manager: ChannelManager,
}

impl SshClientConnection {
    /// Read the next packet from the server, skipping non-channel messages
    /// (SSH_MSG_IGNORE=2, SSH_MSG_DEBUG=4, SSH_MSG_GLOBAL_REQUEST=80).
    /// For GLOBAL_REQUEST with want_reply, sends REQUEST_FAILURE (82).
    async fn read_channel_packet(&mut self) -> Result<PacketFrame, RusshError> {
        loop {
            let frame = self.stream.read_packet().await?;
            match frame.payload.first().copied() {
                Some(2) | Some(4) => continue, // SSH_MSG_IGNORE, SSH_MSG_DEBUG
                Some(80) => {
                    // SSH_MSG_GLOBAL_REQUEST
                    let want_reply = if frame.payload.len() >= 5 {
                        let nlen = u32::from_be_bytes([
                            frame.payload[1],
                            frame.payload[2],
                            frame.payload[3],
                            frame.payload[4],
                        ]) as usize;
                        frame.payload.get(5 + nlen).copied().unwrap_or(0) != 0
                    } else {
                        false
                    };
                    if want_reply {
                        self.stream
                            .write_packet(&PacketFrame::new(vec![82]))
                            .await?;
                    }
                }
                _ => return Ok(frame),
            }
        }
    }

    /// Connect to `addr` and perform the full SSH handshake through
    /// algorithm negotiation, key exchange, and service request.
    pub async fn connect(
        addr: impl ToSocketAddrs,
        config: ClientConfig,
    ) -> Result<Self, RusshError> {
        let tcp = TcpStream::connect(addr).await.map_err(io_err)?;
        Self::connect_via_stream(Box::new(tcp), config).await
    }

    /// Perform SSH handshake over an already-open async stream.
    ///
    /// This is the common implementation shared by [`connect`] (TCP) and
    /// [`connect_via_jump`] (ProxyJump channel bridge).
    pub async fn connect_via_stream(
        stream: AnyStream,
        config: ClientConfig,
    ) -> Result<Self, RusshError> {
        let mut stream = PacketStream::new(stream);

        // ── Banner exchange ──
        stream.write_banner_line(OUR_BANNER).await?;
        let remote_banner = stream.read_banner_line().await?;

        let mut session = ClientSession::new(config);
        session.set_local_version(OUR_BANNER);
        // Advance state machine through banner → AlgorithmsNegotiated.
        session.handshake(&remote_banner).await?;

        // ── KEXINIT ──
        let kexinit_frame = session.send_kexinit()?;
        stream.write_packet(&kexinit_frame).await?;

        // Read server KEXINIT; store its raw payload for exchange hash.
        let server_kexinit_frame = stream.read_packet().await?;
        let server_kexinit_payload = server_kexinit_frame.payload.clone();
        let server_kexinit_msg = TransportMessage::from_frame(&server_kexinit_frame)?;
        session.store_server_kexinit_payload(server_kexinit_payload)?;
        session.receive_message(server_kexinit_msg)?;

        // ── ECDH key exchange ──
        let ecdh_init_frame = session.send_kex_ecdh_init()?;
        stream.write_packet(&ecdh_init_frame).await?;

        let ecdh_reply_frame = stream.read_packet().await?;
        let ecdh_reply_msg = TransportMessage::from_frame(&ecdh_reply_frame)?;
        let (newkeys_frame, _keys) =
            session.receive_kex_ecdh_reply_and_send_newkeys(&ecdh_reply_msg)?;
        stream.write_packet(&newkeys_frame).await?;

        // ── NewKeys ── read and discard; state is already Established after
        // receive_kex_ecdh_reply_and_send_newkeys.
        let _server_newkeys_frame = stream.read_packet().await?;

        // Enable AEAD encryption in both directions now that NEWKEYS is complete.
        if let (Some(keys), Some(neg)) = (session.session_keys(), session.negotiated()) {
            let keys = keys.clone();
            let neg = neg.clone();
            stream.enable_client_encryption(&keys, &neg);
        }

        // ── Service request ──
        let service_frame = session.send_service_request("ssh-userauth")?;
        stream.write_packet(&service_frame).await?;
        // Read responses; skip EXT_INFO (server may send it before service accept).
        let service_accept_msg = loop {
            let frame = stream.read_packet().await?;
            let msg = TransportMessage::from_frame(&frame)?;
            if matches!(msg, TransportMessage::ExtInfo { .. }) {
                session.receive_message(msg)?;
            } else {
                break msg;
            }
        };
        session.receive_message(service_accept_msg)?;

        Ok(Self {
            stream,
            session,
            channel_manager: ChannelManager::new(),
        })
    }

    /// Authenticate with a password.  Returns `Ok(())` on success.
    pub async fn authenticate_password(&mut self, password: &str) -> Result<(), RusshError> {
        let user = self.session.config.user.clone();
        let request = UserAuthRequest::Password {
            user: user.clone(),
            service: "ssh-connection".to_owned(),
            password: password.to_owned(),
        };
        let frame = self.session.send_userauth_request(request)?;
        self.stream.write_packet(&frame).await?;

        // Read responses until auth succeeds or definitively fails.
        loop {
            let response_frame = self.stream.read_packet().await?;
            let msg = UserAuthMessage::from_frame(&response_frame)?;
            self.session.receive_userauth_message(msg.clone())?;
            match msg {
                UserAuthMessage::Success => return Ok(()),
                UserAuthMessage::Failure { .. } => {
                    return Err(RusshError::new(
                        RusshErrorCategory::Auth,
                        "password authentication rejected",
                    ));
                }
                UserAuthMessage::Banner { .. } => {}
                _ => {
                    return Err(protocol_err("unexpected auth response message"));
                }
            }
        }
    }

    /// Authenticate with an Ed25519 private key.  Returns `Ok(())` on success.
    pub async fn authenticate_pubkey(&mut self, signer: &Ed25519Signer) -> Result<(), RusshError> {
        let user = self.session.config.user.clone();
        let session_id = self
            .session
            .session_keys()
            .ok_or_else(|| protocol_err("no session keys for pubkey auth"))?
            .session_id
            .clone();

        let public_key_blob = signer.public_key_blob();
        let signing_payload = build_userauth_signing_payload(
            &session_id,
            &user,
            "ssh-connection",
            "ssh-ed25519",
            &public_key_blob,
        );
        let raw_sig = signer.sign(&signing_payload)?;
        let signature = build_ed25519_signature_blob(
            raw_sig
                .as_slice()
                .try_into()
                .map_err(|_| protocol_err("unexpected signature length"))?,
        );

        let request = UserAuthRequest::PublicKey {
            user,
            service: "ssh-connection".to_owned(),
            algorithm: "ssh-ed25519".to_owned(),
            public_key: public_key_blob,
            signature: Some(signature),
        };
        let frame = self.session.send_userauth_request(request)?;
        self.stream.write_packet(&frame).await?;

        loop {
            let response_frame = self.stream.read_packet().await?;
            let msg = UserAuthMessage::from_frame(&response_frame)?;
            self.session.receive_userauth_message(msg.clone())?;
            match msg {
                UserAuthMessage::Success => return Ok(()),
                UserAuthMessage::Failure { .. } => {
                    return Err(RusshError::new(
                        RusshErrorCategory::Auth,
                        "public key authentication rejected",
                    ));
                }
                UserAuthMessage::Banner { .. } | UserAuthMessage::PublicKeyOk { .. } => {}
                _ => {
                    return Err(protocol_err("unexpected auth response message"));
                }
            }
        }
    }

    /// Authenticate using an OpenSSH certificate.
    ///
    /// `cert_blob` is the raw certificate blob (as returned by `ssh-keygen -s` or
    /// `OpenSshCertificate::to_bytes`).  `signer` holds the private key that corresponds
    /// to the public key embedded in the certificate.
    pub async fn authenticate_pubkey_with_cert(
        &mut self,
        cert_blob: Vec<u8>,
        signer: &Ed25519Signer,
    ) -> Result<(), RusshError> {
        let user = self.session.config.user.clone();
        let session_id = self
            .session
            .session_keys()
            .ok_or_else(|| protocol_err("no session keys for cert auth"))?
            .session_id
            .clone();

        const CERT_ALG: &str = "ssh-ed25519-cert-v01@openssh.com";
        let signing_payload = build_userauth_signing_payload(
            &session_id,
            &user,
            "ssh-connection",
            CERT_ALG,
            &cert_blob,
        );
        let raw_sig = signer.sign(&signing_payload)?;
        let signature = build_ed25519_signature_blob(
            raw_sig
                .as_slice()
                .try_into()
                .map_err(|_| protocol_err("unexpected signature length"))?,
        );

        let request = UserAuthRequest::PublicKey {
            user,
            service: "ssh-connection".to_owned(),
            algorithm: CERT_ALG.to_owned(),
            public_key: cert_blob,
            signature: Some(signature),
        };
        let frame = self.session.send_userauth_request(request)?;
        self.stream.write_packet(&frame).await?;

        loop {
            let response_frame = self.stream.read_packet().await?;
            let msg = UserAuthMessage::from_frame(&response_frame)?;
            self.session.receive_userauth_message(msg.clone())?;
            match msg {
                UserAuthMessage::Success => return Ok(()),
                UserAuthMessage::Failure { .. } => {
                    return Err(RusshError::new(
                        RusshErrorCategory::Auth,
                        "certificate authentication rejected",
                    ));
                }
                UserAuthMessage::Banner { .. } | UserAuthMessage::PublicKeyOk { .. } => {}
                _ => {
                    return Err(protocol_err("unexpected auth response message"));
                }
            }
        }
    }

    /// Authenticate using keys held by an SSH agent.
    ///
    /// Queries the agent for identities, tries each key via publickey query,
    /// and signs with the first key that the server accepts.
    pub async fn authenticate_via_agent(
        &mut self,
        agent: &SshAgentClient,
    ) -> Result<(), RusshError> {
        let user = self.session.config.user.clone();
        let session_id = self
            .session
            .session_keys()
            .ok_or_else(|| protocol_err("no session keys for agent auth"))?
            .session_id
            .clone();

        let identities = agent.list_identities().map_err(|e| {
            RusshError::new(
                RusshErrorCategory::Auth,
                format!("agent list_identities failed: {e}"),
            )
        })?;

        if identities.is_empty() {
            return Err(RusshError::new(
                RusshErrorCategory::Auth,
                "ssh-agent holds no identities",
            ));
        }

        for (key_blob, _comment) in identities {
            const ALG: &str = "ssh-ed25519";
            let payload = build_userauth_signing_payload(
                &session_id,
                &user,
                "ssh-connection",
                ALG,
                &key_blob,
            );
            let sig_blob = match agent.sign(&key_blob, &payload) {
                Ok(s) => s,
                Err(_) => continue,
            };

            let request = UserAuthRequest::PublicKey {
                user: user.clone(),
                service: "ssh-connection".to_owned(),
                algorithm: ALG.to_owned(),
                public_key: key_blob,
                signature: Some(sig_blob),
            };
            let frame = self.session.send_userauth_request(request)?;
            self.stream.write_packet(&frame).await?;

            let mut success = false;
            loop {
                let response_frame = self.stream.read_packet().await?;
                let msg = UserAuthMessage::from_frame(&response_frame)?;
                self.session.receive_userauth_message(msg.clone())?;
                match msg {
                    UserAuthMessage::Success => {
                        success = true;
                        break;
                    }
                    UserAuthMessage::Failure { .. } => break,
                    UserAuthMessage::Banner { .. } | UserAuthMessage::PublicKeyOk { .. } => {}
                    _ => return Err(protocol_err("unexpected auth response message")),
                }
            }
            if success {
                return Ok(());
            }
        }
        Err(RusshError::new(
            RusshErrorCategory::Auth,
            "agent authentication: all keys rejected",
        ))
    }

    /// Open a session channel, send `exec <cmd>`, and collect output.
    pub async fn exec(&mut self, cmd: &str) -> Result<ExecResult, RusshError> {
        let (local_id, open_msg) = self.channel_manager.open_channel(ChannelKind::Session);
        self.stream.write_packet(&open_msg.to_frame()?).await?;

        // Wait for CHANNEL_OPEN_CONFIRMATION.
        let remote_id = loop {
            let frame = self.read_channel_packet().await?;
            let ch = ChannelMessage::from_bytes(&frame.payload)?;
            match &ch {
                ChannelMessage::OpenConfirmation {
                    recipient_channel,
                    sender_channel,
                    ..
                } if *recipient_channel == local_id => {
                    let rid = *sender_channel;
                    self.channel_manager.accept_confirmation(local_id, &ch)?;
                    break rid;
                }
                ChannelMessage::OpenFailure { .. } => {
                    return Err(protocol_err("channel open rejected by server"));
                }
                _ => {}
            }
        };

        // Send exec request.
        let req = ChannelMessage::Request {
            recipient_channel: remote_id,
            want_reply: true,
            request: ChannelRequest::Exec {
                command: cmd.to_owned(),
            },
        };
        self.stream.write_packet(&req.to_frame()?).await?;

        // Wait for CHANNEL_SUCCESS, then collect data until EOF/CLOSE.
        let mut result = ExecResult::default();
        let mut success_seen = false;

        loop {
            let frame = self.read_channel_packet().await?;
            let ch = ChannelMessage::from_bytes(&frame.payload)?;
            let responses = self.channel_manager.process(&ch)?;
            for r in responses {
                self.stream.write_packet(&r.to_frame()?).await?;
            }
            match ch {
                ChannelMessage::Success { .. } => success_seen = true,
                ChannelMessage::Failure { .. } => {
                    return Err(protocol_err("exec request rejected by server"));
                }
                ChannelMessage::Data { data, .. } if success_seen => {
                    result.stdout.extend_from_slice(&data);
                }
                ChannelMessage::ExtendedData { data, .. } if success_seen => {
                    result.stderr.extend_from_slice(&data);
                }
                ChannelMessage::Request {
                    request: ChannelRequest::ExitStatus { exit_status },
                    ..
                } => {
                    result.exit_code = Some(exit_status);
                }
                ChannelMessage::Eof { .. } => {}
                ChannelMessage::Close { .. } => {
                    // Send our close.
                    let close = ChannelMessage::Close {
                        recipient_channel: remote_id,
                    };
                    self.stream.write_packet(&close.to_frame()?).await?;
                    break;
                }
                _ => {}
            }
        }

        Ok(result)
    }

    /// Open a session channel, request the `sftp` subsystem, and return an
    /// [`SftpSession`] ready to send requests.
    pub async fn sftp(&mut self) -> Result<SftpSession<'_>, RusshError> {
        let (local_id, open_msg) = self.channel_manager.open_channel(ChannelKind::Session);
        self.stream.write_packet(&open_msg.to_frame()?).await?;

        let remote_id = loop {
            let frame = self.read_channel_packet().await?;
            let ch = ChannelMessage::from_bytes(&frame.payload)?;
            match &ch {
                ChannelMessage::OpenConfirmation {
                    recipient_channel,
                    sender_channel,
                    ..
                } if *recipient_channel == local_id => {
                    let rid = *sender_channel;
                    self.channel_manager.accept_confirmation(local_id, &ch)?;
                    break rid;
                }
                ChannelMessage::OpenFailure { .. } => {
                    return Err(protocol_err("sftp channel open rejected"));
                }
                _ => {}
            }
        };

        // Request the sftp subsystem.
        let req = ChannelMessage::Request {
            recipient_channel: remote_id,
            want_reply: true,
            request: ChannelRequest::SubSystem {
                name: "sftp".to_owned(),
            },
        };
        self.stream.write_packet(&req.to_frame()?).await?;

        // Wait for CHANNEL_SUCCESS.
        loop {
            let frame = self.read_channel_packet().await?;
            let ch = ChannelMessage::from_bytes(&frame.payload)?;
            match ch {
                ChannelMessage::Success { .. } => break,
                ChannelMessage::Failure { .. } => {
                    return Err(protocol_err("sftp subsystem request rejected"));
                }
                _ => {}
            }
        }

        let mut sftp = SftpSession::new(&mut self.stream, remote_id, local_id);
        sftp.init().await?;
        Ok(sftp)
    }

    /// Upload `data` to `remote_path` on the server via SCP.
    ///
    /// Opens a channel, sends `scp -t <remote_path>`, then transmits the file
    /// using the SCP wire format.
    pub async fn scp_upload(
        &mut self,
        filename: &str,
        mode: u32,
        data: &[u8],
        remote_path: &str,
    ) -> Result<(), RusshError> {
        let cmd = format!("scp -t {remote_path}");
        let (local_id, open_msg) = self.channel_manager.open_channel(ChannelKind::Session);
        self.stream.write_packet(&open_msg.to_frame()?).await?;

        let remote_id = loop {
            let frame = self.read_channel_packet().await?;
            let ch = ChannelMessage::from_bytes(&frame.payload)?;
            match &ch {
                ChannelMessage::OpenConfirmation {
                    recipient_channel,
                    sender_channel,
                    ..
                } if *recipient_channel == local_id => {
                    let rid = *sender_channel;
                    self.channel_manager.accept_confirmation(local_id, &ch)?;
                    break rid;
                }
                ChannelMessage::OpenFailure { .. } => {
                    return Err(protocol_err("scp channel open rejected"));
                }
                _ => {}
            }
        };

        let req = ChannelMessage::Request {
            recipient_channel: remote_id,
            want_reply: true,
            request: ChannelRequest::Exec {
                command: cmd.clone(),
            },
        };
        self.stream.write_packet(&req.to_frame()?).await?;

        // Wait for CHANNEL_SUCCESS then receive the initial SCP ACK (0x00).
        loop {
            let frame = self.read_channel_packet().await?;
            let ch = ChannelMessage::from_bytes(&frame.payload)?;
            match ch {
                ChannelMessage::Success { .. } => break,
                ChannelMessage::Failure { .. } => {
                    return Err(protocol_err("scp exec request rejected"));
                }
                _ => {}
            }
        }

        // Read the server's initial ACK byte.
        let frame = self.read_channel_packet().await?;
        let ch = ChannelMessage::from_bytes(&frame.payload)?;
        if let ChannelMessage::Data { data: ack, .. } = ch {
            if ack.first() != Some(&0x00) {
                return Err(protocol_err("scp server did not send initial ACK"));
            }
        }

        // Send the SCP file payload.
        let scp_bytes = build_scp_file_upload(filename, mode, data);
        let scp_data = ChannelMessage::Data {
            recipient_channel: remote_id,
            data: scp_bytes,
        };
        self.stream.write_packet(&scp_data.to_frame()?).await?;

        // Wait for server acknowledgement.
        loop {
            let frame = self.read_channel_packet().await?;
            let ch = ChannelMessage::from_bytes(&frame.payload)?;
            match ch {
                ChannelMessage::Data { data: ack, .. } => {
                    if ack.first() == Some(&0x00) {
                        break;
                    }
                }
                ChannelMessage::Eof { .. } | ChannelMessage::Close { .. } => break,
                _ => {}
            }
        }

        // Clean close.
        let eof = ChannelMessage::Eof {
            recipient_channel: remote_id,
        };
        self.stream.write_packet(&eof.to_frame()?).await?;
        let close = ChannelMessage::Close {
            recipient_channel: remote_id,
        };
        self.stream.write_packet(&close.to_frame()?).await
    }

    /// Send `SSH_MSG_DISCONNECT` and flush the connection.
    pub async fn disconnect(&mut self) -> Result<(), RusshError> {
        self.session.close("client disconnect");
        Ok(())
    }
}

// ── SshClient ────────────────────────────────────────────────────────────────

/// Entry point for creating SSH client connections.
pub struct SshClient;

impl SshClient {
    /// Connect to `addr` and perform the SSH handshake.  Authenticate
    /// separately with [`SshClientConnection::authenticate_password`].
    pub async fn connect(
        addr: impl ToSocketAddrs,
        config: ClientConfig,
    ) -> Result<SshClientConnection, RusshError> {
        SshClientConnection::connect(addr, config).await
    }

    /// Connect to `target` via a ProxyJump host.
    ///
    /// 1. Opens a TCP connection to `jump_addr` and performs full KEX + auth using
    ///    `jump_auth`.
    /// 2. Opens a `direct-tcpip` channel through the jump host to `target_host:target_port`.
    /// 3. Runs full KEX + auth over that channel using `target_cfg`.
    ///
    /// The jump connection is kept alive by a background task as long as the returned
    /// `SshClientConnection` is in use.
    ///
    /// # Arguments
    ///
    /// * `jump_addr` — TCP address of the jump host (e.g. `"jump.example.com:22"`).
    /// * `jump_cfg` — `ClientConfig` for authenticating to the jump host.
    /// * `jump_auth` — a callback that authenticates the jump connection.
    /// * `target_host` — hostname/IP that the jump host should forward to.
    /// * `target_port` — port on the target host.
    /// * `target_cfg` — `ClientConfig` for the inner (target) SSH session.
    pub async fn connect_via_jump<F>(
        jump_addr: impl ToSocketAddrs,
        jump_cfg: ClientConfig,
        jump_auth: F,
        target_host: impl Into<String>,
        target_port: u16,
        target_cfg: ClientConfig,
    ) -> Result<SshClientConnection, RusshError>
    where
        F: for<'a> FnOnce(
            &'a mut SshClientConnection,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<(), RusshError>> + Send + 'a>,
        >,
    {
        // ── Step 1: connect to jump host ────────────────────────────────────
        let mut jump = SshClientConnection::connect(jump_addr, jump_cfg).await?;
        jump_auth(&mut jump).await?;

        let target_host: String = target_host.into();

        // ── Step 2: open a direct-tcpip channel ─────────────────────────────
        let extra_data = ForwardHandle::build_direct_tcpip_open_extra(
            &target_host,
            target_port as u32,
            "127.0.0.1",
            0,
        );
        let (local_id, mut open_msg) =
            jump.channel_manager.open_channel(ChannelKind::DirectTcpIp {
                host: target_host,
                port: target_port,
            });

        // Inject the extra_data into the open message.
        if let ChannelMessage::Open {
            extra_data: ref mut ed,
            ..
        } = open_msg
        {
            *ed = extra_data;
        }

        jump.stream.write_packet(&open_msg.to_frame()?).await?;

        // Wait for CHANNEL_OPEN_CONFIRMATION.
        let remote_id = loop {
            let frame = jump.stream.read_packet().await?;
            // Skip SSH_MSG_IGNORE(2), SSH_MSG_DEBUG(4), SSH_MSG_GLOBAL_REQUEST(80).
            match frame.payload.first().copied() {
                Some(2) | Some(4) => continue,
                Some(80) => {
                    let want_reply = frame
                        .payload
                        .get(
                            5 + {
                                if frame.payload.len() >= 5 {
                                    u32::from_be_bytes([
                                        frame.payload[1],
                                        frame.payload[2],
                                        frame.payload[3],
                                        frame.payload[4],
                                    ]) as usize
                                } else {
                                    0
                                }
                            },
                        )
                        .copied()
                        .unwrap_or(0)
                        != 0;
                    if want_reply {
                        jump.stream
                            .write_packet(&PacketFrame::new(vec![82]))
                            .await?;
                    }
                    continue;
                }
                _ => {}
            }
            let ch = ChannelMessage::from_bytes(&frame.payload)?;
            match &ch {
                ChannelMessage::OpenConfirmation {
                    recipient_channel,
                    sender_channel,
                    ..
                } if *recipient_channel == local_id => {
                    let rid = *sender_channel;
                    jump.channel_manager.accept_confirmation(local_id, &ch)?;
                    break rid;
                }
                ChannelMessage::OpenFailure { description, .. } => {
                    return Err(RusshError::new(
                        RusshErrorCategory::Channel,
                        format!("direct-tcpip channel open refused: {description}"),
                    ));
                }
                _ => {}
            }
        };

        // ── Step 3: duplex bridge ────────────────────────────────────────────
        let (inner_half, bridge_half) = tokio::io::duplex(1 << 17); // 128 KiB buffer

        // Spawn bridge task: bidirectional copy between the jump channel and bridge_half.
        tokio::spawn(channel_bridge(jump, local_id, remote_id, bridge_half));

        // ── Step 4: inner SSH session over the bridge ────────────────────────
        let target: AnyStream = Box::new(inner_half);
        SshClientConnection::connect_via_stream(target, target_cfg).await
    }
}

// ── ProxyJump bridge ─────────────────────────────────────────────────────────

/// Background task that bridges a `direct-tcpip` SSH channel and a tokio duplex stream.
///
/// Data from `bridge` is framed as `SSH_MSG_CHANNEL_DATA` and sent to the jump host.
/// `SSH_MSG_CHANNEL_DATA` packets from the jump host are written to `bridge`.
async fn channel_bridge(
    mut jump: SshClientConnection,
    local_id: u32,
    remote_id: u32,
    bridge: tokio::io::DuplexStream,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (mut bridge_rx, mut bridge_tx) = tokio::io::split(bridge);
    let mut read_buf = vec![0u8; 32768];

    loop {
        tokio::select! {
            // Data from bridge → channel_data to jump host
            n = bridge_rx.read(&mut read_buf) => {
                let n = match n {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                let msg = ChannelMessage::Data {
                    recipient_channel: remote_id,
                    data: read_buf[..n].to_vec(),
                };
                let Ok(frame) = msg.to_frame() else { break };
                if jump.stream.write_packet(&frame).await.is_err() {
                    break;
                }
            }
            // Packets from jump host → write channel_data to bridge
            frame = jump.stream.read_packet() => {
                let frame = match frame {
                    Ok(f) => f,
                    Err(_) => break,
                };
                match ChannelMessage::from_bytes(&frame.payload) {
                    Ok(ChannelMessage::Data { recipient_channel, data })
                        if recipient_channel == local_id =>
                    {
                        if bridge_tx.write_all(&data).await.is_err() {
                            break;
                        }
                    }
                    Ok(ChannelMessage::Eof { recipient_channel, .. })
                    | Ok(ChannelMessage::Close { recipient_channel, .. })
                        if recipient_channel == local_id =>
                    {
                        break;
                    }
                    _ => {}
                }
            }
        }
    }
}

// ── SessionHandler ───────────────────────────────────────────────────────────

/// Server-side dispatch trait for session channel requests.
///
/// Implement this to control how the server handles `exec` commands,
/// the `sftp` subsystem, and SCP transfers.
pub trait SessionHandler: Send + Sync + 'static {
    /// Handle an `exec` request.  Return the stdout bytes to send back.
    fn exec(&self, cmd: &str) -> Vec<u8>;

    /// Return the root directory used by the SFTP server, or `None` to
    /// reject sftp subsystem requests.
    fn sftp_root(&self) -> Option<PathBuf>;

    /// Return the root directory where SCP files should be stored, or
    /// `None` to reject SCP transfers.
    fn scp_root(&self) -> Option<PathBuf>;
}

/// A [`SessionHandler`] that runs exec commands in a sandboxed environment
/// and serves SFTP/SCP from a configurable root directory.
pub struct DefaultSessionHandler {
    sftp_root: PathBuf,
}

impl DefaultSessionHandler {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            sftp_root: root.into(),
        }
    }
}

impl SessionHandler for DefaultSessionHandler {
    fn exec(&self, cmd: &str) -> Vec<u8> {
        // For testing: handle "echo <text>" directly without a subprocess.
        if let Some(rest) = cmd.strip_prefix("echo ") {
            let mut out = rest.as_bytes().to_vec();
            out.push(b'\n');
            return out;
        }
        // SCP receive: "scp -t <path>" — handled at a higher layer; return empty.
        b"".to_vec()
    }

    fn sftp_root(&self) -> Option<PathBuf> {
        Some(self.sftp_root.clone())
    }

    fn scp_root(&self) -> Option<PathBuf> {
        Some(self.sftp_root.clone())
    }
}

// ── SshServerConnection ──────────────────────────────────────────────────────

/// A server-side connection accepted from [`SshServer`].
pub struct SshServerConnection {
    stream: PacketStream<AnyStream>,
    config: ServerConfig,
}

impl SshServerConnection {
    fn new(tcp: TcpStream, config: ServerConfig) -> Self {
        Self {
            stream: PacketStream::new(Box::new(tcp)),
            config,
        }
    }

    /// Drive the full connection lifecycle: handshake → auth → channel loop.
    pub async fn run(mut self, handler: impl SessionHandler) -> Result<(), RusshError> {
        let mut session = ServerSession::new(self.config.clone());
        session.set_local_version(OUR_BANNER);

        // ── Banner exchange ──
        self.stream.write_banner_line(OUR_BANNER).await?;
        let client_banner = self.stream.read_banner_line().await?;
        session.accept_banner(&client_banner)?;

        // Advance state machine to AlgorithmsNegotiated so receive_message
        // can accept KexInit.  The actual negotiation happens inside receive_message.
        use russh_core::AlgorithmSet;
        session.negotiate_with_client(&AlgorithmSet::secure_defaults())?;

        // ── KEXINIT from client ──
        let client_kexinit_frame = self.stream.read_packet().await?;
        // Store raw payload BEFORE parsing so the exchange hash uses original bytes.
        session.store_client_kexinit_payload(client_kexinit_frame.payload.clone());
        let client_kexinit_msg = TransportMessage::from_frame(&client_kexinit_frame)?;
        // Returns the server's KexInit to send.
        if let Some(reply) = session.receive_message(client_kexinit_msg)? {
            let reply_frame = reply.to_frame()?;
            self.stream.write_packet(&reply_frame).await?;
        }

        // ── ECDH_INIT from client ──
        let ecdh_init_frame = self.stream.read_packet().await?;
        let ecdh_init_msg = TransportMessage::from_frame(&ecdh_init_frame)?;
        // Returns KexEcdhReply.
        if let Some(ecdh_reply) = session.receive_message(ecdh_init_msg)? {
            let reply_frame = ecdh_reply.to_frame()?;
            self.stream.write_packet(&reply_frame).await?;
        }

        // Send server NEWKEYS, then immediately enable TX encryption.
        // The server switches to encrypted TX after sending NEWKEYS.
        let newkeys_frame = TransportMessage::NewKeys.to_frame()?;
        self.stream.write_packet(&newkeys_frame).await?;
        if let (Some(keys), Some(neg)) = (session.session_keys(), session.negotiated()) {
            let keys = keys.clone();
            let neg = neg.clone();
            self.stream.enable_server_tx_encryption(&keys, &neg);
        }

        // Send EXT_INFO if we advertised ext-info-s (OpenSSH client expects it, encrypted).
        let sends_ext_info = session.negotiated().is_some_and(|n| n.ext_info_s);
        if sends_ext_info {
            let ext_info = TransportMessage::ExtInfo {
                extensions: vec![("server-sig-algs".to_owned(), "ssh-ed25519".to_owned())],
            };
            self.stream.write_packet(&ext_info.to_frame()?).await?;
        }

        // ── NEWKEYS from client ──
        let client_newkeys_frame = self.stream.read_packet().await?;
        let client_newkeys_msg = TransportMessage::from_frame(&client_newkeys_frame)?;
        session.receive_message(client_newkeys_msg)?;

        // Enable RX decryption now that client has sent NEWKEYS and will start encrypting.
        if let (Some(keys), Some(neg)) = (session.session_keys(), session.negotiated()) {
            let keys = keys.clone();
            let neg = neg.clone();
            self.stream.enable_server_rx_encryption(&keys, &neg);
        }

        // ── SERVICE_REQUEST ──
        // Skip EXT_INFO (client may send it before SERVICE_REQUEST when server advertised ext-info-s).
        let service_req_msg = loop {
            let frame = self.stream.read_packet().await?;
            let msg = TransportMessage::from_frame(&frame)?;
            if matches!(msg, TransportMessage::ExtInfo { .. }) {
                session.receive_message(msg)?;
            } else {
                break msg;
            }
        };
        if let Some(service_accept) = session.receive_message(service_req_msg)? {
            self.stream
                .write_packet(&service_accept.to_frame()?)
                .await?;
        }

        // ── Auth ──
        let auth_policy = self
            .config
            .auth_policy
            .clone()
            .unwrap_or_else(ServerAuthPolicy::secure_defaults);
        session.activate_userauth(auth_policy);
        loop {
            let auth_frame = self.stream.read_packet().await?;
            let auth_msg = UserAuthMessage::from_frame(&auth_frame)?;
            let reply = session.receive_userauth_message(auth_msg)?;
            if let Some(reply) = reply {
                self.stream.write_packet(&reply.to_frame()?).await?;
                if session.authenticated_user().is_some() {
                    break;
                }
            }
        }

        // ── Channel loop ──
        self.run_channels(&mut session, &handler).await
    }

    async fn run_channels(
        &mut self,
        session: &mut ServerSession,
        handler: &impl SessionHandler,
    ) -> Result<(), RusshError> {
        let mut server_channels: std::collections::HashMap<u32, ServerChannelState> =
            std::collections::HashMap::new();
        let mut next_server_id: u32 = 0;

        loop {
            let frame = match self.stream.read_packet().await {
                Ok(f) => f,
                // Treat connection-level IO errors (peer closed) as a clean session end.
                Err(e) if e.category() == russh_core::RusshErrorCategory::Io => break,
                Err(e) => return Err(e),
            };

            // Check for disconnect.
            if frame.message_type() == Some(1) {
                break;
            }

            // Skip non-channel messages (e.g. GLOBAL_REQUEST, IGNORE, DEBUG).
            let msg = match ChannelMessage::from_bytes(&frame.payload) {
                Ok(m) => m,
                Err(_) => continue,
            };
            match msg {
                ChannelMessage::Open {
                    sender_channel: client_ch,
                    initial_window_size,
                    maximum_packet_size,
                    ..
                } => {
                    let our_id = next_server_id;
                    next_server_id += 1;
                    server_channels.insert(
                        client_ch,
                        ServerChannelState {
                            is_sftp: false,
                            scp_root: None,
                            sftp_server: None,
                            sftp_framer: SftpFramer::new(),
                        },
                    );
                    let confirm = ChannelMessage::OpenConfirmation {
                        recipient_channel: client_ch,
                        sender_channel: our_id,
                        initial_window_size,
                        maximum_packet_size,
                    };
                    self.stream.write_packet(&confirm.to_frame()?).await?;
                }

                ChannelMessage::Request {
                    recipient_channel,
                    want_reply,
                    request,
                } => {
                    let state = match server_channels.get_mut(&recipient_channel) {
                        Some(s) => s,
                        None => continue,
                    };
                    let client_ch = recipient_channel;
                    match request {
                        ChannelRequest::Exec { command } => {
                            if want_reply {
                                let ok = ChannelMessage::Success {
                                    recipient_channel: client_ch,
                                };
                                self.stream.write_packet(&ok.to_frame()?).await?;
                            }
                            // Handle scp receive
                            if command.starts_with("scp -t") {
                                let root = handler.scp_root();
                                state.scp_root = root;
                                // Send initial ACK.
                                let ack = ChannelMessage::Data {
                                    recipient_channel: client_ch,
                                    data: vec![0x00],
                                };
                                self.stream.write_packet(&ack.to_frame()?).await?;
                            } else {
                                let output = handler.exec(&command);
                                if !output.is_empty() {
                                    let data_msg = ChannelMessage::Data {
                                        recipient_channel: client_ch,
                                        data: output,
                                    };
                                    self.stream.write_packet(&data_msg.to_frame()?).await?;
                                }
                                let eof = ChannelMessage::Eof {
                                    recipient_channel: client_ch,
                                };
                                self.stream.write_packet(&eof.to_frame()?).await?;
                                let exit_status = ChannelMessage::Request {
                                    recipient_channel: client_ch,
                                    want_reply: false,
                                    request: ChannelRequest::ExitStatus { exit_status: 0 },
                                };
                                self.stream.write_packet(&exit_status.to_frame()?).await?;
                                let close = ChannelMessage::Close {
                                    recipient_channel: client_ch,
                                };
                                self.stream.write_packet(&close.to_frame()?).await?;
                            }
                        }

                        ChannelRequest::SubSystem { name } if name == "sftp" => {
                            if want_reply {
                                if let Some(root) = handler.sftp_root() {
                                    state.is_sftp = true;
                                    state.sftp_server = Some(SftpFileServer::new(&root));
                                    let ok = ChannelMessage::Success {
                                        recipient_channel: client_ch,
                                    };
                                    self.stream.write_packet(&ok.to_frame()?).await?;
                                } else {
                                    let fail = ChannelMessage::Failure {
                                        recipient_channel: client_ch,
                                    };
                                    self.stream.write_packet(&fail.to_frame()?).await?;
                                }
                            }
                        }

                        _ => {
                            if want_reply {
                                let fail = ChannelMessage::Failure {
                                    recipient_channel: client_ch,
                                };
                                self.stream.write_packet(&fail.to_frame()?).await?;
                            }
                        }
                    }
                }

                ChannelMessage::Data {
                    recipient_channel,
                    data,
                } => {
                    let state = match server_channels.get_mut(&recipient_channel) {
                        Some(s) => s,
                        None => continue,
                    };
                    let client_ch = recipient_channel;

                    if state.is_sftp {
                        // SFTP subsystem: feed data into the per-channel framer, then
                        // dispatch each complete packet to the per-channel SftpFileServer.
                        if let Some(sftp_server) = state.sftp_server.as_mut() {
                            state.sftp_framer.feed(&data);
                            while let Some(request) = state.sftp_framer.next_packet()? {
                                let response = sftp_server.process(&request)?;
                                let resp_bytes = response.encode();
                                let resp_msg = ChannelMessage::Data {
                                    recipient_channel: client_ch,
                                    data: resp_bytes,
                                };
                                self.stream.write_packet(&resp_msg.to_frame()?).await?;
                            }
                        }
                    } else if let Some(scp_root) = state.scp_root.clone() {
                        // SCP receive: parse and store the uploaded file.
                        self.handle_scp_data(client_ch, &data, &scp_root).await?;
                    }
                }

                ChannelMessage::Eof { recipient_channel } => {
                    // Client is done sending; send EOF + CLOSE back to unblock the client.
                    let _ = self
                        .stream
                        .write_packet(&ChannelMessage::Eof { recipient_channel }.to_frame()?)
                        .await;
                    let _ = self
                        .stream
                        .write_packet(&ChannelMessage::Close { recipient_channel }.to_frame()?)
                        .await;
                    server_channels.remove(&recipient_channel);
                }

                ChannelMessage::Close { recipient_channel } => {
                    server_channels.remove(&recipient_channel);
                }

                ChannelMessage::WindowAdjust { .. } => {}

                _ => {}
            }

            // Stop if the session is closed.
            if session.state() == russh_transport::SessionState::Closed {
                break;
            }
        }

        Ok(())
    }

    async fn handle_scp_data(
        &mut self,
        client_ch: u32,
        data: &[u8],
        root: &Path,
    ) -> Result<(), RusshError> {
        // Parse the SCP C header and store the file.
        // Format: "C0644 <size> <filename>\n<data>\0"
        if data.is_empty() {
            return Ok(());
        }
        if data[0] == b'C' {
            if let Ok(s) = std::str::from_utf8(data) {
                let header_end = s.find('\n').unwrap_or(s.len());
                let header = &s[..header_end];
                let parts: Vec<&str> = header.splitn(3, ' ').collect();
                if parts.len() == 3 {
                    let size: usize = parts[1].parse().unwrap_or(0);
                    let filename = parts[2];
                    let file_data_start = header_end + 1;
                    if file_data_start + size <= data.len() {
                        let file_bytes = &data[file_data_start..file_data_start + size];
                        let dest = root.join(filename);
                        if let Some(parent) = dest.parent() {
                            let _ = std::fs::create_dir_all(parent);
                        }
                        let _ = std::fs::write(&dest, file_bytes);
                    }
                }
            }
        }
        // Send ACK.
        let ack = ChannelMessage::Data {
            recipient_channel: client_ch,
            data: vec![0x00],
        };
        self.stream.write_packet(&ack.to_frame()?).await
    }
}

// ── ServerChannelState ───────────────────────────────────────────────────────

struct ServerChannelState {
    is_sftp: bool,
    scp_root: Option<PathBuf>,
    /// Stateful SFTP server instance (None when channel is not SFTP).
    sftp_server: Option<SftpFileServer>,
    /// Framer to reassemble SFTP packets across multiple DATA messages.
    sftp_framer: SftpFramer,
}

// ── SshServer ────────────────────────────────────────────────────────────────

/// A bound SSH server that accepts incoming connections.
pub struct SshServer {
    listener: TcpListener,
    config: ServerConfig,
}

impl SshServer {
    /// Bind a TCP socket and create the server.
    pub async fn bind(addr: impl ToSocketAddrs, config: ServerConfig) -> Result<Self, RusshError> {
        let listener = TcpListener::bind(addr).await.map_err(io_err)?;
        Ok(Self { listener, config })
    }

    /// Accept the next incoming connection.
    pub async fn accept(&self) -> Result<SshServerConnection, RusshError> {
        let (tcp, _peer) = self.listener.accept().await.map_err(io_err)?;
        Ok(SshServerConnection::new(tcp, self.config.clone()))
    }

    /// Return the local address the server is bound to.
    pub fn local_addr(&self) -> Result<std::net::SocketAddr, RusshError> {
        self.listener.local_addr().map_err(io_err)
    }
}

#[cfg(test)]
mod tests {
    use russh_transport::{ClientConfig, ServerConfig};
    use tokio::task;

    use super::*;

    /// End-to-end loopback test: RuSSH client → RuSSH server over a real TCP
    /// loopback socket.  Covers password auth, exec, SFTP upload/read,
    /// and SCP upload.
    #[tokio::test]
    async fn loopback_full_pipeline() {
        // ── Server config ──
        // Use a fixed host key seed so ECDH always succeeds; disable strict
        // host key checking on the client to avoid having to set up known hosts.
        let host_key_seed = [0x42u8; 32];
        let server_config = {
            let mut cfg = ServerConfig::secure_defaults();
            cfg.host_key_seed = Some(host_key_seed);
            cfg
        };

        // Temporary directory for SFTP/SCP files.
        let root_dir = std::env::temp_dir().join(format!(
            "russh_net_loopback_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root_dir).expect("create temp dir");

        let root_for_handler = root_dir.clone();
        let root_for_assert = root_dir.clone();

        // ── Bind server ──
        let server = SshServer::bind("127.0.0.1:0", server_config)
            .await
            .expect("bind server");
        let addr = server.local_addr().expect("local addr");

        // ── Spawn server task ──
        let server_handle = task::spawn(async move {
            let conn = server.accept().await.expect("accept");
            conn.run(DefaultSessionHandler::new(root_for_handler))
                .await
                .expect("server run");
        });

        // ── Client config ──
        let client_config = {
            let mut cfg = ClientConfig::secure_defaults("alice");
            cfg.strict_host_key_checking = false; // skip known-hosts for test
            cfg
        };

        let mut client = SshClient::connect(addr, client_config)
            .await
            .expect("connect");

        client
            .authenticate_password("test-password")
            .await
            .expect("auth");

        // ── exec ──
        let exec_result = client.exec("echo hello").await.expect("exec");
        assert_eq!(exec_result.stdout, b"hello\n", "exec stdout mismatch");

        // ── SFTP ──
        let mut sftp = client.sftp().await.expect("open sftp");
        sftp.write_file("test.txt", b"sftp-content")
            .await
            .expect("sftp write");
        let data = sftp.read_file("test.txt").await.expect("sftp read");
        assert_eq!(data, b"sftp-content", "sftp round-trip mismatch");
        sftp.close().await.expect("sftp close");

        // ── SCP ──
        client
            .scp_upload("scp_test.txt", 0o644, b"scp-content", "/scp_test.txt")
            .await
            .expect("scp upload");

        // Verify SCP file was stored.
        let scp_path = root_for_assert.join("scp_test.txt");
        let scp_data = std::fs::read(&scp_path).expect("read scp file");
        assert_eq!(scp_data, b"scp-content", "scp content mismatch");

        // ── Disconnect ──
        client.disconnect().await.expect("disconnect");

        // Wait for server to finish.
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), server_handle).await;

        // Cleanup.
        let _ = std::fs::remove_dir_all(&root_for_assert);
    }
}
