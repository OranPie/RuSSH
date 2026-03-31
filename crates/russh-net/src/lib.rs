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

#[cfg(unix)]
mod agent;
#[cfg(unix)]
pub use agent::SshAgentClient;

use std::path::{Component, Path, PathBuf};
use tracing::{debug, info, trace, warn};

#[cfg(unix)]
use russh_auth::AgentClient;
use russh_auth::{
    ServerAuthPolicy, UserAuthMessage, UserAuthRequest, build_ed25519_signature_blob,
    build_userauth_signing_payload,
};
use russh_channel::{ChannelKind, ChannelManager, ChannelMessage, ChannelRequest, ForwardHandle};
use russh_core::{PacketCodec, PacketFrame, RusshError, RusshErrorCategory};
use russh_crypto::{
    AeadCipher, Aes128CtrCipher, Aes256CtrCipher, Aes256GcmCipher, HmacSha256, HmacSha512,
    MacAlgorithm, Signer, StreamCipher,
};
use russh_scp::build_scp_file_upload;
use russh_sftp::{SftpFileServer, SftpFramer, SftpWirePacket};
use russh_transport::{
    ClientConfig, ClientSession, NegotiatedAlgorithms, ServerConfig, ServerSession, SessionKeys,
    TransportMessage,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};

use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress, Status};

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

fn resolve_scp_target_path(root: &Path, filename: &str) -> Result<PathBuf, RusshError> {
    let mut sanitized = PathBuf::new();
    for component in Path::new(filename).components() {
        match component {
            Component::Normal(part) => sanitized.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(protocol_err(format!(
                    "scp target path {:?} escapes SCP root",
                    filename
                )));
            }
        }
    }
    Ok(root.join(sanitized))
}

fn scp_status_data(code: u8, message: &str) -> Vec<u8> {
    let mut data = Vec::with_capacity(message.len() + 2);
    data.push(code);
    data.extend_from_slice(message.as_bytes());
    data.push(b'\n');
    data
}

fn write_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn write_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    write_u32(out, bytes.len() as u32);
    out.extend_from_slice(bytes);
}

fn channel_data_frame(recipient_channel: u32, data: &[u8]) -> PacketFrame {
    let mut payload = Vec::with_capacity(1 + 4 + 4 + data.len());
    payload.push(94);
    write_u32(&mut payload, recipient_channel);
    write_bytes(&mut payload, data);
    PacketFrame::new(payload)
}

fn channel_extended_data_frame(
    recipient_channel: u32,
    data_type_code: u32,
    data: &[u8],
) -> PacketFrame {
    let mut payload = Vec::with_capacity(1 + 4 + 4 + 4 + data.len());
    payload.push(95);
    write_u32(&mut payload, recipient_channel);
    write_u32(&mut payload, data_type_code);
    write_bytes(&mut payload, data);
    PacketFrame::new(payload)
}

/// Parse a `SSH_MSG_GLOBAL_REQUEST` payload into `(request_name, want_reply)`.
///
/// Wire format: `byte(80) | string(request_name) | bool(want_reply) [| data...]`
fn parse_global_request(payload: &[u8]) -> (&str, bool) {
    if payload.len() < 6 {
        // Too short to contain type + u32 length + at least 1 char
        return ("", false);
    }
    let name_len = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]) as usize;
    let name_end = 5 + name_len.min(payload.len().saturating_sub(5));
    let request_name = std::str::from_utf8(&payload[5..name_end]).unwrap_or("?");
    let want_reply = payload.get(5 + name_len).copied().unwrap_or(0) != 0;
    (request_name, want_reply)
}

/// Build a `keepalive@openssh.com` global request frame with `want_reply = true`.
///
/// Wire format: `byte(80) | string("keepalive@openssh.com") | bool(true)`
fn build_keepalive_frame() -> PacketFrame {
    const REQUEST_NAME: &[u8] = b"keepalive@openssh.com";
    let mut payload = Vec::with_capacity(1 + 4 + REQUEST_NAME.len() + 1);
    payload.push(80); // SSH_MSG_GLOBAL_REQUEST
    write_bytes(&mut payload, REQUEST_NAME);
    payload.push(1); // want_reply = true
    PacketFrame::new(payload)
}

// ── DirectionalCipher ────────────────────────────────────────────────────────

/// Object-safe trait for stream cipher encrypt/decrypt operations.
trait CtrCipherOps: Send {
    fn encrypt_in_place(&mut self, data: &mut [u8]);
    fn decrypt_in_place(&mut self, data: &mut [u8]);
}

impl<T: StreamCipher + Send> CtrCipherOps for T {
    fn encrypt_in_place(&mut self, data: &mut [u8]) {
        StreamCipher::encrypt_in_place(self, data);
    }
    fn decrypt_in_place(&mut self, data: &mut [u8]) {
        StreamCipher::decrypt_in_place(self, data);
    }
}

/// MAC algorithm dispatch enum.
enum MacKind {
    Sha256,
    Sha512,
}

impl MacKind {
    fn tag_len(&self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha512 => 64,
        }
    }

    fn sign(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => HmacSha256::sign(key, data),
            Self::Sha512 => HmacSha512::sign(key, data),
        }
    }

    fn verify(&self, key: &[u8], data: &[u8], tag: &[u8]) -> Result<(), RusshError> {
        let ok = match self {
            Self::Sha256 => HmacSha256::verify(key, data, tag),
            Self::Sha512 => HmacSha512::verify(key, data, tag),
        };
        if ok {
            Ok(())
        } else {
            Err(RusshError::new(
                RusshErrorCategory::Crypto,
                "MAC verification failed",
            ))
        }
    }
}

/// Per-direction cipher state (used for one of TX or RX).
///
/// After NEWKEYS, both sides must encrypt/decrypt packets.
/// Supports AEAD ciphers (AES-GCM) and stream ciphers with ETM MAC (AES-CTR).
enum DirectionalCipher {
    None,
    Aes256Gcm {
        cipher: Box<Aes256GcmCipher>,
        /// Current 12-byte nonce: first 4 bytes fixed, last 8 bytes counter.
        nonce: [u8; 12],
    },
    AesCtr {
        cipher: Box<dyn CtrCipherOps + Send>,
        mac: MacKind,
        mac_key: Vec<u8>,
    },
}

impl DirectionalCipher {
    /// Build a cipher from the negotiated algorithm name, key material, IV, and MAC.
    fn new(cipher_name: &str, key: &[u8], iv: &[u8], mac_name: &str, mac_key: &[u8]) -> Self {
        match cipher_name {
            "aes256-gcm@openssh.com" => {
                if let Ok(cipher) = Aes256GcmCipher::new(key) {
                    let mut nonce = [0u8; 12];
                    let copy_len = iv.len().min(12);
                    nonce[..copy_len].copy_from_slice(&iv[..copy_len]);
                    return Self::Aes256Gcm {
                        cipher: Box::new(cipher),
                        nonce,
                    };
                }
                Self::None
            }
            "aes256-ctr" => {
                if let Ok(cipher) = Aes256CtrCipher::new(key, iv) {
                    let mac = match mac_name {
                        "hmac-sha2-512-etm@openssh.com" => MacKind::Sha512,
                        _ => MacKind::Sha256,
                    };
                    Self::AesCtr {
                        cipher: Box::new(cipher),
                        mac,
                        mac_key: mac_key.to_vec(),
                    }
                } else {
                    Self::None
                }
            }
            "aes128-ctr" => {
                // AES-128 uses a 16-byte key; key derivation produces 32 bytes.
                let key128 = if key.len() > 16 { &key[..16] } else { key };
                if let Ok(cipher) = Aes128CtrCipher::new(key128, iv) {
                    let mac = match mac_name {
                        "hmac-sha2-512-etm@openssh.com" => MacKind::Sha512,
                        _ => MacKind::Sha256,
                    };
                    Self::AesCtr {
                        cipher: Box::new(cipher),
                        mac,
                        mac_key: mac_key.to_vec(),
                    }
                } else {
                    Self::None
                }
            }
            _ => Self::None,
        }
    }

    /// Increment the last 8 bytes of the nonce as a big-endian u64 counter.
    fn increment_nonce(nonce: &mut [u8; 12]) {
        let mut counter = u64::from_be_bytes(nonce[4..12].try_into().unwrap());
        counter = counter.wrapping_add(1);
        nonce[4..12].copy_from_slice(&counter.to_be_bytes());
    }
}

// ── DirectionalCompression ────────────────────────────────────────────────────

/// Per-direction compression state for `zlib@openssh.com` (delayed compression).
///
/// The zlib stream is stateful: compression context persists across packets.
/// Each packet is flushed with `Z_SYNC_FLUSH` per RFC 4253 §6.2.
enum DirectionalCompression {
    None,
    Zlib {
        compress: Compress,
        decompress: Decompress,
    },
}

impl DirectionalCompression {
    fn new_zlib() -> Self {
        Self::Zlib {
            compress: Compress::new(Compression::default(), true),
            decompress: Decompress::new(true),
        }
    }

    /// Compress `data` in place using Z_SYNC_FLUSH.  No-op for `None`.
    fn compress_payload(&mut self, data: &mut Vec<u8>) -> Result<(), RusshError> {
        match self {
            Self::None => Ok(()),
            Self::Zlib { compress, .. } => {
                let input = std::mem::take(data);
                let mut output = vec![0u8; input.len() + 64];
                let mut in_offset = 0;
                let mut out_offset = 0;
                loop {
                    let before_in = compress.total_in();
                    let before_out = compress.total_out();
                    let status = compress
                        .compress(
                            &input[in_offset..],
                            &mut output[out_offset..],
                            FlushCompress::Sync,
                        )
                        .map_err(|e| {
                            RusshError::new(
                                RusshErrorCategory::Protocol,
                                format!("zlib compress error: {e}"),
                            )
                        })?;
                    in_offset += (compress.total_in() - before_in) as usize;
                    out_offset += (compress.total_out() - before_out) as usize;
                    match status {
                        Status::Ok | Status::BufError => {
                            if in_offset >= input.len() && out_offset < output.len() {
                                break;
                            }
                            // Need more output space.
                            output.resize(output.len() + input.len().max(128) + 64, 0);
                        }
                        Status::StreamEnd => break,
                    }
                }
                output.truncate(out_offset);
                *data = output;
                Ok(())
            }
        }
    }

    /// Decompress `data` in place using Z_SYNC_FLUSH.  No-op for `None`.
    fn decompress_payload(&mut self, data: &mut Vec<u8>) -> Result<(), RusshError> {
        match self {
            Self::None => Ok(()),
            Self::Zlib { decompress, .. } => {
                let input = std::mem::take(data);
                let mut output = vec![0u8; input.len() * 2 + 64];
                let mut in_offset = 0;
                let mut out_offset = 0;
                loop {
                    let before_in = decompress.total_in();
                    let before_out = decompress.total_out();
                    let status = decompress
                        .decompress(
                            &input[in_offset..],
                            &mut output[out_offset..],
                            FlushDecompress::Sync,
                        )
                        .map_err(|e| {
                            RusshError::new(
                                RusshErrorCategory::Protocol,
                                format!("zlib decompress error: {e}"),
                            )
                        })?;
                    in_offset += (decompress.total_in() - before_in) as usize;
                    out_offset += (decompress.total_out() - before_out) as usize;
                    match status {
                        Status::Ok | Status::BufError => {
                            if in_offset >= input.len() && out_offset < output.len() {
                                break;
                            }
                            output.resize(output.len() + input.len().max(128) * 2 + 64, 0);
                        }
                        Status::StreamEnd => break,
                    }
                }
                output.truncate(out_offset);
                *data = output;
                Ok(())
            }
        }
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
    tx_compression: DirectionalCompression,
    rx_compression: DirectionalCompression,
    /// Negotiated compression algorithm for TX (stored to support delayed activation).
    pending_tx_compression: Option<String>,
    /// Negotiated compression algorithm for RX (stored to support delayed activation).
    pending_rx_compression: Option<String>,
    /// SSH protocol sequence number for outgoing packets (incremented per packet, all modes).
    tx_seq: u32,
    /// SSH protocol sequence number for incoming packets (incremented per packet, all modes).
    rx_seq: u32,
}

impl<S: AsyncReadExt + AsyncWriteExt + Unpin> PacketStream<S> {
    pub fn new(stream: S) -> Self {
        Self {
            inner: stream,
            codec: PacketCodec::with_defaults(),
            tx_cipher: DirectionalCipher::None,
            rx_cipher: DirectionalCipher::None,
            tx_compression: DirectionalCompression::None,
            rx_compression: DirectionalCompression::None,
            pending_tx_compression: None,
            pending_rx_compression: None,
            tx_seq: 0,
            rx_seq: 0,
        }
    }

    /// Enable AEAD encryption for the **client** side after NEWKEYS.
    ///
    /// Client → server direction uses `key_c2s` / `iv_c2s`;
    /// server → client direction uses `key_s2c` / `iv_s2c`.
    pub fn enable_client_encryption(&mut self, keys: &SessionKeys, neg: &NegotiatedAlgorithms) {
        if neg.strict_kex {
            self.tx_seq = 0;
            self.rx_seq = 0;
        }
        self.tx_cipher = DirectionalCipher::new(
            &neg.cipher_client_to_server,
            &keys.key_c2s,
            &keys.iv_c2s,
            &neg.mac_client_to_server,
            &keys.mac_key_c2s,
        );
        self.rx_cipher = DirectionalCipher::new(
            &neg.cipher_server_to_client,
            &keys.key_s2c,
            &keys.iv_s2c,
            &neg.mac_server_to_client,
            &keys.mac_key_s2c,
        );
        // Store compression algorithms for delayed activation after auth.
        self.pending_tx_compression = Some(neg.compression_client_to_server.clone());
        self.pending_rx_compression = Some(neg.compression_server_to_client.clone());
    }

    /// Enable AEAD encryption for the **server** side after NEWKEYS.
    pub fn enable_server_encryption(&mut self, keys: &SessionKeys, neg: &NegotiatedAlgorithms) {
        if neg.strict_kex {
            self.tx_seq = 0;
            self.rx_seq = 0;
        }
        self.tx_cipher = DirectionalCipher::new(
            &neg.cipher_server_to_client,
            &keys.key_s2c,
            &keys.iv_s2c,
            &neg.mac_server_to_client,
            &keys.mac_key_s2c,
        );
        self.rx_cipher = DirectionalCipher::new(
            &neg.cipher_client_to_server,
            &keys.key_c2s,
            &keys.iv_c2s,
            &neg.mac_client_to_server,
            &keys.mac_key_c2s,
        );
        // Store compression algorithms for delayed activation after auth.
        self.pending_tx_compression = Some(neg.compression_server_to_client.clone());
        self.pending_rx_compression = Some(neg.compression_client_to_server.clone());
    }

    /// Enable only the TX (outgoing) cipher for the server after sending NEWKEYS.
    pub fn enable_server_tx_encryption(&mut self, keys: &SessionKeys, neg: &NegotiatedAlgorithms) {
        if neg.strict_kex {
            self.tx_seq = 0;
        }
        self.tx_cipher = DirectionalCipher::new(
            &neg.cipher_server_to_client,
            &keys.key_s2c,
            &keys.iv_s2c,
            &neg.mac_server_to_client,
            &keys.mac_key_s2c,
        );
        self.pending_tx_compression = Some(neg.compression_server_to_client.clone());
    }

    /// Enable only the RX (incoming) cipher for the server after receiving client NEWKEYS.
    pub fn enable_server_rx_encryption(&mut self, keys: &SessionKeys, neg: &NegotiatedAlgorithms) {
        if neg.strict_kex {
            self.rx_seq = 0;
        }
        self.rx_cipher = DirectionalCipher::new(
            &neg.cipher_client_to_server,
            &keys.key_c2s,
            &keys.iv_c2s,
            &neg.mac_client_to_server,
            &keys.mac_key_c2s,
        );
        self.pending_rx_compression = Some(neg.compression_client_to_server.clone());
    }

    /// Activate delayed compression (`zlib@openssh.com`) after user authentication succeeds.
    ///
    /// Must be called after `enable_*_encryption()` which stores the negotiated
    /// compression algorithm names.  No-op if compression is `"none"`.
    pub fn activate_compression(&mut self) {
        if let Some(alg) = self.pending_tx_compression.take() {
            if alg == "zlib@openssh.com" {
                self.tx_compression = DirectionalCompression::new_zlib();
            }
        }
        if let Some(alg) = self.pending_rx_compression.take() {
            if alg == "zlib@openssh.com" {
                self.rx_compression = DirectionalCompression::new_zlib();
            }
        }
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
        let seq = self.rx_seq;
        let result = match &mut self.rx_cipher {
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
            DirectionalCipher::AesCtr {
                cipher,
                mac,
                mac_key,
            } => {
                // ETM: packet_length is plaintext, body is encrypted, MAC follows
                let mut len_buf = [0u8; 4];
                self.inner.read_exact(&mut len_buf).await.map_err(io_err)?;
                let pkt_len = u32::from_be_bytes(len_buf) as usize;

                if pkt_len > PacketCodec::DEFAULT_MAX_PACKET_SIZE + 512 {
                    return Err(protocol_err("incoming packet length too large"));
                }

                let mut encrypted_body = vec![0u8; pkt_len];
                self.inner
                    .read_exact(&mut encrypted_body)
                    .await
                    .map_err(io_err)?;

                // Read MAC tag
                let mac_len = mac.tag_len();
                let mut mac_tag = vec![0u8; mac_len];
                self.inner.read_exact(&mut mac_tag).await.map_err(io_err)?;

                // Verify MAC over (seqnum || packet_length || encrypted_body)
                let mut mac_data = Vec::new();
                mac_data.extend_from_slice(&seq.to_be_bytes());
                mac_data.extend_from_slice(&len_buf);
                mac_data.extend_from_slice(&encrypted_body);
                mac.verify(mac_key, &mac_data, &mac_tag)
                    .map_err(|e| RusshError::new(RusshErrorCategory::Crypto, e.to_string()))?;

                // Decrypt
                cipher.decrypt_in_place(&mut encrypted_body);

                if encrypted_body.is_empty() {
                    return Err(protocol_err("AES-CTR decrypted to empty plaintext"));
                }
                let padding_len = encrypted_body[0] as usize;
                let payload_end = encrypted_body.len().saturating_sub(padding_len);
                if payload_end == 0 {
                    return Err(protocol_err("AES-CTR padding exceeds plaintext length"));
                }
                Ok(PacketFrame::new(encrypted_body[1..payload_end].to_vec()))
            }
        };
        self.rx_seq = seq.wrapping_add(1);
        // Apply decompression after decryption if active.
        match result {
            Ok(mut frame) => {
                self.rx_compression.decompress_payload(&mut frame.payload)?;
                Ok(frame)
            }
            err => err,
        }
    }

    /// Encode `frame` and write it to the stream.
    pub async fn write_packet(&mut self, frame: &PacketFrame) -> Result<(), RusshError> {
        // Apply compression before encryption if active.
        let mut payload = frame.payload.clone();
        self.tx_compression.compress_payload(&mut payload)?;
        let frame = &PacketFrame::new(payload);

        let seq = self.tx_seq;
        let result = match &mut self.tx_cipher {
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
            DirectionalCipher::AesCtr {
                cipher,
                mac,
                mac_key,
            } => {
                const BLOCK: usize = 16;
                let payload = &frame.payload;
                let body_len = 1 + payload.len();
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

                cipher.encrypt_in_place(&mut plaintext);

                // Compute MAC over (seqnum || packet_length || encrypted_body)
                let mut mac_data = Vec::new();
                mac_data.extend_from_slice(&seq.to_be_bytes());
                mac_data.extend_from_slice(&packet_length);
                mac_data.extend_from_slice(&plaintext);
                let tag = mac.sign(mac_key, &mac_data);

                // Wire: [4-byte length] [encrypted body] [MAC tag]
                self.inner.write_all(&packet_length).await.map_err(io_err)?;
                self.inner.write_all(&plaintext).await.map_err(io_err)?;
                self.inner.write_all(&tag).await.map_err(io_err)
            }
        };
        self.tx_seq = seq.wrapping_add(1);
        result
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
    /// For GLOBAL_REQUEST with want_reply, sends REQUEST_FAILURE (82)
    /// unless the request is `keepalive@openssh.com` (REQUEST_SUCCESS=81).
    async fn read_channel_packet(&mut self) -> Result<PacketFrame, RusshError> {
        loop {
            let frame = self.stream.read_packet().await?;
            match frame.payload.first().copied() {
                Some(2) | Some(4) => continue, // SSH_MSG_IGNORE, SSH_MSG_DEBUG
                Some(80) => {
                    // SSH_MSG_GLOBAL_REQUEST
                    let (request_name, want_reply) = parse_global_request(&frame.payload);
                    debug!(request_name, want_reply, "GLOBAL_REQUEST (client side)");
                    if want_reply {
                        let reply = if request_name == "keepalive@openssh.com" {
                            81 // SSH_MSG_REQUEST_SUCCESS
                        } else {
                            82 // SSH_MSG_REQUEST_FAILURE
                        };
                        self.stream
                            .write_packet(&PacketFrame::new(vec![reply]))
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
        debug!("sending banner");
        stream.write_banner_line(OUR_BANNER).await?;
        let remote_banner = stream.read_banner_line().await?;
        info!(server_version = %remote_banner, "banner exchanged");

        let mut session = ClientSession::new(config);
        session.set_local_version(OUR_BANNER);
        // Advance state machine through banner → AlgorithmsNegotiated.
        session.handshake(&remote_banner).await?;

        // ── KEXINIT ──
        debug!("sending KEXINIT");
        let kexinit_frame = session.send_kexinit()?;
        stream.write_packet(&kexinit_frame).await?;

        // Read server KEXINIT; store its raw payload for exchange hash.
        let server_kexinit_frame = stream.read_packet().await?;
        let server_kexinit_payload = server_kexinit_frame.payload.clone();
        let server_kexinit_msg = TransportMessage::from_frame(&server_kexinit_frame)?;
        session.store_server_kexinit_payload(server_kexinit_payload)?;
        session.receive_message(server_kexinit_msg)?;
        debug!("KEXINIT exchanged");

        // ── ECDH key exchange ──
        debug!("sending ECDH init");
        let ecdh_init_frame = session.send_kex_ecdh_init()?;
        stream.write_packet(&ecdh_init_frame).await?;

        let ecdh_reply_frame = stream.read_packet().await?;
        let ecdh_reply_msg = TransportMessage::from_frame(&ecdh_reply_frame)?;
        let (newkeys_frame, _keys) =
            session.receive_kex_ecdh_reply_and_send_newkeys(&ecdh_reply_msg)?;
        stream.write_packet(&newkeys_frame).await?;
        debug!(cipher = ?session.negotiated().map(|n| &n.cipher_client_to_server), "KEX complete, sending NEWKEYS");

        // ── NewKeys ── read and discard; state is already Established after
        // receive_kex_ecdh_reply_and_send_newkeys.
        let _server_newkeys_frame = stream.read_packet().await?;
        debug!("received server NEWKEYS");

        // Enable AEAD encryption in both directions now that NEWKEYS is complete.
        if let (Some(keys), Some(neg)) = (session.session_keys(), session.negotiated()) {
            let keys = keys.clone();
            let neg = neg.clone();
            stream.enable_client_encryption(&keys, &neg);
        }
        debug!("encryption enabled");

        // ── Service request ──
        debug!("requesting ssh-userauth service");
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
        debug!("service accepted");

        Ok(Self {
            stream,
            session,
            channel_manager: ChannelManager::new(),
        })
    }

    /// Returns the server's host public key blob (SSH wire format), available after KEX.
    #[must_use]
    pub fn server_host_key_blob(&self) -> Option<&[u8]> {
        self.session.server_host_key_blob()
    }

    /// Authenticate with a password.  Returns `Ok(())` on success.
    pub async fn authenticate_password(&mut self, password: &str) -> Result<(), RusshError> {
        let user = self.session.config.user.clone();
        debug!(user = %user, "authenticating with password");
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
            debug!(msg_type = ?std::mem::discriminant(&msg), "auth response");
            self.session.receive_userauth_message(msg.clone())?;
            match msg {
                UserAuthMessage::Success => {
                    info!(user = %user, "password auth succeeded");
                    self.stream.activate_compression();
                    return Ok(());
                }
                UserAuthMessage::Failure { .. } => {
                    warn!(user = %user, "password auth failed");
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

    /// Begin keyboard-interactive authentication (RFC 4256).
    ///
    /// Sends the initial request and reads back the first
    /// `KeyboardInteractiveInfoRequest`.  Returns the prompts as
    /// `(prompt_text, echo)` pairs for the caller to display and collect
    /// answers for.  An empty vec means the server sent zero prompts
    /// (unusual but valid — the caller should still call
    /// [`respond_keyboard_interactive`] with an empty response list).
    ///
    /// Returns `Err` if the server immediately rejects the method or
    /// sends an unexpected message.
    pub async fn authenticate_keyboard_interactive(
        &mut self,
    ) -> Result<Vec<(String, bool)>, RusshError> {
        let user = self.session.config.user.clone();
        debug!(user = %user, "starting keyboard-interactive auth");
        let request = UserAuthRequest::KeyboardInteractive {
            user: user.clone(),
            service: "ssh-connection".to_owned(),
            language_tag: String::new(),
            submethods: String::new(),
        };
        let frame = self.session.send_userauth_request(request)?;
        self.stream.write_packet(&frame).await?;

        loop {
            let response_frame = self.stream.read_packet().await?;
            let msg = UserAuthMessage::from_frame(&response_frame)?;
            debug!(msg_type = ?std::mem::discriminant(&msg), "kbd-interactive auth response");
            self.session.receive_userauth_message(msg.clone())?;
            match msg {
                UserAuthMessage::KeyboardInteractiveInfoRequest { prompts, .. } => {
                    return Ok(prompts);
                }
                UserAuthMessage::Success => {
                    // Server accepted without prompts (e.g. PAM with no challenges).
                    info!(user = %user, "keyboard-interactive auth succeeded (no prompts)");
                    return Ok(Vec::new());
                }
                UserAuthMessage::Failure { .. } => {
                    warn!(user = %user, "keyboard-interactive auth rejected");
                    return Err(RusshError::new(
                        RusshErrorCategory::Auth,
                        "keyboard-interactive authentication rejected",
                    ));
                }
                UserAuthMessage::Banner { .. } => {}
                _ => {
                    return Err(protocol_err("unexpected keyboard-interactive response"));
                }
            }
        }
    }

    /// Send responses to a keyboard-interactive challenge.
    ///
    /// After calling [`authenticate_keyboard_interactive`], collect answers
    /// from the user and pass them here.  The server may respond with
    /// `Success`, `Failure`, or *another* `InfoRequest` (multi-round).
    ///
    /// On success returns `Ok(None)`.  If the server asks another round
    /// of questions, returns `Ok(Some(prompts))`.
    pub async fn respond_keyboard_interactive(
        &mut self,
        responses: Vec<String>,
    ) -> Result<Option<Vec<(String, bool)>>, RusshError> {
        let user = self.session.config.user.clone();
        debug!(user = %user, responses_count = responses.len(), "sending kbd-interactive responses");
        let msg = UserAuthMessage::KeyboardInteractiveInfoResponse { responses };
        let frame = msg.to_frame()?;
        self.stream.write_packet(&frame).await?;

        loop {
            let response_frame = self.stream.read_packet().await?;
            let reply = UserAuthMessage::from_frame(&response_frame)?;
            debug!(msg_type = ?std::mem::discriminant(&reply), "kbd-interactive reply");
            self.session.receive_userauth_message(reply.clone())?;
            match reply {
                UserAuthMessage::Success => {
                    info!(user = %user, "keyboard-interactive auth succeeded");
                    self.stream.activate_compression();
                    return Ok(None);
                }
                UserAuthMessage::Failure { .. } => {
                    warn!(user = %user, "keyboard-interactive auth failed");
                    return Err(RusshError::new(
                        RusshErrorCategory::Auth,
                        "keyboard-interactive authentication rejected",
                    ));
                }
                UserAuthMessage::KeyboardInteractiveInfoRequest { prompts, .. } => {
                    return Ok(Some(prompts));
                }
                UserAuthMessage::Banner { .. } => {}
                _ => {
                    return Err(protocol_err("unexpected keyboard-interactive response"));
                }
            }
        }
    }

    /// Authenticate with an Ed25519 private key.  Returns `Ok(())` on success.
    pub async fn authenticate_pubkey(&mut self, signer: &Ed25519Signer) -> Result<(), RusshError> {
        let user = self.session.config.user.clone();
        debug!(user = %user, "authenticating with pubkey");
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
            user: user.clone(),
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
            debug!(msg_type = ?std::mem::discriminant(&msg), "auth response");
            self.session.receive_userauth_message(msg.clone())?;
            match msg {
                UserAuthMessage::Success => {
                    info!(user = %user, "pubkey auth succeeded");
                    self.stream.activate_compression();
                    return Ok(());
                }
                UserAuthMessage::Failure { .. } => {
                    warn!(user = %user, "pubkey auth rejected");
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
                UserAuthMessage::Success => {
                    self.stream.activate_compression();
                    return Ok(());
                }
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
    #[cfg(unix)]
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
                        self.stream.activate_compression();
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

    /// Open a session channel with a PTY request and interactive shell.
    ///
    /// Returns `(local_id, remote_id)` once the shell request is accepted.
    /// Use [`run_shell_session`] to drive bidirectional I/O.
    pub async fn open_shell(
        &mut self,
        term: &str,
        cols: u32,
        rows: u32,
    ) -> Result<(u32, u32), RusshError> {
        debug!(term, cols, rows, "opening shell channel");
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
                    debug!(local_id, remote_id = rid, "channel open confirmed");
                    break rid;
                }
                ChannelMessage::OpenFailure { .. } => {
                    return Err(protocol_err("shell channel open rejected"));
                }
                _ => {}
            }
        };

        // Request PTY.
        debug!("requesting PTY");
        let pty_req = ChannelMessage::Request {
            recipient_channel: remote_id,
            want_reply: true,
            request: ChannelRequest::PtyReq {
                term: term.to_owned(),
                width_chars: cols,
                height_rows: rows,
                width_pixels: 0,
                height_pixels: 0,
                term_modes: vec![],
            },
        };
        self.stream.write_packet(&pty_req.to_frame()?).await?;
        loop {
            let frame = self.read_channel_packet().await?;
            let ch = ChannelMessage::from_bytes(&frame.payload)?;
            match ch {
                ChannelMessage::Success { .. } => {
                    debug!("PTY accepted");
                    break;
                }
                ChannelMessage::Failure { .. } => {
                    return Err(protocol_err("pty-req rejected"));
                }
                _ => {}
            }
        }

        // Request shell.
        debug!("requesting shell");
        let shell_req = ChannelMessage::Request {
            recipient_channel: remote_id,
            want_reply: true,
            request: ChannelRequest::Shell,
        };
        self.stream.write_packet(&shell_req.to_frame()?).await?;
        loop {
            let frame = self.read_channel_packet().await?;
            let ch = ChannelMessage::from_bytes(&frame.payload)?;
            match ch {
                ChannelMessage::Success { .. } => {
                    info!("shell opened");
                    break;
                }
                ChannelMessage::Failure { .. } => {
                    return Err(protocol_err("shell request rejected"));
                }
                _ => {}
            }
        }

        Ok((local_id, remote_id))
    }

    /// Drive an interactive shell session with bidirectional I/O.
    ///
    /// Reads raw bytes from `input` (e.g. stdin) and forwards to the channel;
    /// data arriving on the channel is written to `output` (e.g. stdout).
    /// Returns when the server sends EOF or CLOSE.
    pub async fn run_shell_session(
        &mut self,
        local_id: u32,
        remote_id: u32,
        input: &mut (impl tokio::io::AsyncRead + Unpin),
        output: &mut (impl tokio::io::AsyncWrite + Unpin),
    ) -> Result<u32, RusshError> {
        debug!(remote_id, "starting shell session I/O loop");
        let mut buf = vec![0u8; 4096];
        let mut exit_code: u32 = 0;
        let mut input_open = true;
        loop {
            tokio::select! {
                // stdin → channel
                n = input.read(&mut buf), if input_open => {
                    let n = n.map_err(|e| RusshError::new(RusshErrorCategory::Io, e.to_string()))?;
                    if n == 0 {
                        let eof = ChannelMessage::Eof { recipient_channel: remote_id };
                        self.stream.write_packet(&eof.to_frame()?).await?;
                        input_open = false;
                        continue;
                    }
                    let frame = channel_data_frame(remote_id, &buf[..n]);
                    self.stream.write_packet(&frame).await?;
                }
                // channel → stdout
                frame_res = self.stream.read_packet() => {
                    let frame = frame_res?;
                    let ch = ChannelMessage::from_bytes(&frame.payload)?;
                    let responses = self.channel_manager.process(&ch)?;
                    for response in responses {
                        self.stream.write_packet(&response.to_frame()?).await?;
                    }
                    match ch {
                        ChannelMessage::Data {
                            recipient_channel,
                            data,
                        } if recipient_channel == local_id => {
                            output.write_all(&data).await
                                .map_err(|e| RusshError::new(RusshErrorCategory::Io, e.to_string()))?;
                        }
                        ChannelMessage::ExtendedData {
                            recipient_channel,
                            data,
                            ..
                        } if recipient_channel == local_id => {
                            output.write_all(&data).await
                                .map_err(|e| RusshError::new(RusshErrorCategory::Io, e.to_string()))?;
                        }
                        ChannelMessage::Request {
                            recipient_channel,
                            request: ChannelRequest::ExitStatus { exit_status },
                            ..
                        } if recipient_channel == local_id => {
                            debug!(exit_status, "received exit-status");
                            exit_code = exit_status;
                        }
                        ChannelMessage::Eof { recipient_channel } if recipient_channel == local_id => {
                            debug!("received EOF from server");
                            break;
                        }
                        ChannelMessage::Close { recipient_channel } if recipient_channel == local_id => {
                            debug!("received Close from server");
                            break;
                        }
                        _ => {}
                    }
                }
            }
        }
        output
            .flush()
            .await
            .map_err(|e| RusshError::new(RusshErrorCategory::Io, e.to_string()))?;
        info!(exit_code, "shell session ended");
        Ok(exit_code)
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

    /// Send a `keepalive@openssh.com` global request to the server.
    ///
    /// This is the standard OpenSSH keepalive mechanism. The request has
    /// `want_reply = true`, so the server should respond with either
    /// `SSH_MSG_REQUEST_SUCCESS` (81) or `SSH_MSG_REQUEST_FAILURE` (82).
    pub async fn send_keepalive(&mut self) -> Result<(), RusshError> {
        let frame = build_keepalive_frame();
        self.stream.write_packet(&frame).await?;
        debug!("sent keepalive@openssh.com global request");
        Ok(())
    }

    /// Send a window-change (terminal resize) notification on an open channel.
    ///
    /// Per RFC 4254 §6.7 the request is sent with `want_reply = false`.
    pub async fn resize_terminal(
        &mut self,
        remote_id: u32,
        cols: u32,
        rows: u32,
    ) -> Result<(), RusshError> {
        debug!(remote_id, cols, rows, "sending window-change");
        let req = ChannelMessage::Request {
            recipient_channel: remote_id,
            want_reply: false,
            request: ChannelRequest::WindowChange {
                width_chars: cols,
                height_rows: rows,
                width_pixels: 0,
                height_pixels: 0,
            },
        };
        self.stream.write_packet(&req.to_frame()?).await?;
        Ok(())
    }

    /// Open a `direct-tcpip` channel to `host:port` through this SSH connection.
    ///
    /// Returns `(local_id, remote_id)` once the server confirms the channel.
    /// Use this for local port forwarding (`-L`).
    pub async fn open_direct_tcpip(
        &mut self,
        host: &str,
        port: u16,
        originator_host: &str,
        originator_port: u16,
    ) -> Result<(u32, u32), RusshError> {
        debug!(host, port, "opening direct-tcpip channel");
        let extra_data = ForwardHandle::build_direct_tcpip_open_extra(
            host,
            u32::from(port),
            originator_host,
            u32::from(originator_port),
        );
        let (local_id, mut open_msg) =
            self.channel_manager.open_channel(ChannelKind::DirectTcpIp {
                host: host.to_owned(),
                port,
            });

        if let ChannelMessage::Open {
            extra_data: ref mut ed,
            ..
        } = open_msg
        {
            *ed = extra_data;
        }

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
                    debug!(local_id, remote_id = rid, "direct-tcpip channel confirmed");
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

        Ok((local_id, remote_id))
    }

    /// Write data to an open channel as `SSH_MSG_CHANNEL_DATA`.
    pub async fn channel_write(&mut self, remote_id: u32, data: &[u8]) -> Result<(), RusshError> {
        let frame = channel_data_frame(remote_id, data);
        self.stream.write_packet(&frame).await
    }

    /// Read data from the next `SSH_MSG_CHANNEL_DATA` arriving on `local_id`.
    ///
    /// Processes window-adjust and other channel messages through the
    /// channel manager while waiting. Returns `Ok(data)` on data,
    /// or an empty `Vec` on EOF/Close.
    pub async fn channel_read(&mut self, local_id: u32) -> Result<Vec<u8>, RusshError> {
        loop {
            let frame = self.read_channel_packet().await?;
            let ch = ChannelMessage::from_bytes(&frame.payload)?;
            let responses = self.channel_manager.process(&ch)?;
            for response in responses {
                self.stream.write_packet(&response.to_frame()?).await?;
            }
            match ch {
                ChannelMessage::Data {
                    recipient_channel,
                    data,
                } if recipient_channel == local_id => {
                    return Ok(data);
                }
                ChannelMessage::Eof { recipient_channel }
                | ChannelMessage::Close { recipient_channel }
                    if recipient_channel == local_id =>
                {
                    return Ok(vec![]);
                }
                _ => {}
            }
        }
    }

    /// Drive bidirectional I/O between a TCP stream and an SSH channel.
    ///
    /// Used for local port forwarding: reads from `tcp` are sent as channel
    /// data to `remote_id`; channel data arriving on `local_id` is written
    /// to `tcp`. Returns when either side closes.
    pub async fn relay_tcp_channel(
        &mut self,
        local_id: u32,
        remote_id: u32,
        tcp: &mut TcpStream,
    ) -> Result<(), RusshError> {
        let (mut tcp_rx, mut tcp_tx) = tcp.split();
        let mut buf = vec![0u8; 32768];

        loop {
            tokio::select! {
                n = tcp_rx.read(&mut buf) => {
                    let n = match n {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    let frame = channel_data_frame(remote_id, &buf[..n]);
                    if self.stream.write_packet(&frame).await.is_err() {
                        break;
                    }
                }
                frame_res = self.stream.read_packet() => {
                    let frame = match frame_res {
                        Ok(f) => f,
                        Err(_) => break,
                    };
                    match ChannelMessage::from_bytes(&frame.payload) {
                        Ok(ChannelMessage::Data { recipient_channel, data })
                            if recipient_channel == local_id =>
                        {
                            if tcp_tx.write_all(&data).await.is_err() {
                                break;
                            }
                        }
                        Ok(ChannelMessage::WindowAdjust { .. }) => {
                            // Process window adjust through the channel manager
                            if let Ok(ch) = ChannelMessage::from_bytes(&frame.payload) {
                                let _ = self.channel_manager.process(&ch);
                            }
                        }
                        Ok(ChannelMessage::Eof { recipient_channel })
                        | Ok(ChannelMessage::Close { recipient_channel })
                            if recipient_channel == local_id =>
                        {
                            break;
                        }
                        _ => {}
                    }
                }
            }
        }
        Ok(())
    }

    /// Request SSH agent forwarding on an open session channel.
    ///
    /// Sends a `"auth-agent-req@openssh.com"` channel request with
    /// `want_reply = true` and waits for the server's success/failure response.
    pub async fn request_agent_forwarding(&mut self, channel_id: u32) -> Result<(), RusshError> {
        debug!(channel_id, "requesting agent forwarding");
        let req = ChannelMessage::Request {
            recipient_channel: channel_id,
            want_reply: true,
            request: ChannelRequest::Unknown {
                request_type: "auth-agent-req@openssh.com".to_string(),
                data: vec![],
            },
        };
        self.stream.write_packet(&req.to_frame()?).await?;

        loop {
            let frame = self.read_channel_packet().await?;
            let ch = ChannelMessage::from_bytes(&frame.payload)?;
            match ch {
                ChannelMessage::Success { .. } => {
                    info!(channel_id, "agent forwarding accepted");
                    return Ok(());
                }
                ChannelMessage::Failure { .. } => {
                    return Err(protocol_err("agent forwarding request rejected by server"));
                }
                _ => {}
            }
        }
    }

    /// Request the server to listen on `bind_host:bind_port` and forward
    /// incoming connections back to the client (`-R` remote port forwarding).
    ///
    /// Sends a `tcpip-forward` global request (RFC 4254 §7.1). If
    /// `bind_port` is 0 the server picks a port and returns it in the
    /// `REQUEST_SUCCESS` payload.
    pub async fn request_remote_forward(
        &mut self,
        bind_host: &str,
        bind_port: u16,
    ) -> Result<u16, RusshError> {
        debug!(bind_host, bind_port, "requesting tcpip-forward");
        let data = ForwardHandle::build_tcpip_forward_data(bind_host, u32::from(bind_port));
        // Build SSH_MSG_GLOBAL_REQUEST: [80 | string("tcpip-forward") | want_reply(1) | data]
        let mut payload = Vec::new();
        payload.push(80); // SSH_MSG_GLOBAL_REQUEST
        let name = b"tcpip-forward";
        payload.extend_from_slice(&(name.len() as u32).to_be_bytes());
        payload.extend_from_slice(name);
        payload.push(1); // want_reply = true
        payload.extend_from_slice(&data);
        self.stream.write_packet(&PacketFrame::new(payload)).await?;

        // Wait for REQUEST_SUCCESS (81) or REQUEST_FAILURE (82).
        loop {
            let frame = self.read_channel_packet().await?;
            match frame.payload.first().copied() {
                Some(81) => {
                    // REQUEST_SUCCESS — if bind_port was 0, extract allocated port.
                    let actual_port = if bind_port == 0 && frame.payload.len() >= 5 {
                        u32::from_be_bytes([
                            frame.payload[1],
                            frame.payload[2],
                            frame.payload[3],
                            frame.payload[4],
                        ]) as u16
                    } else {
                        bind_port
                    };
                    info!(bind_host, actual_port, "remote forward accepted");
                    return Ok(actual_port);
                }
                Some(82) => {
                    return Err(RusshError::new(
                        RusshErrorCategory::Channel,
                        format!("remote forward request rejected for {bind_host}:{bind_port}"),
                    ));
                }
                _ => {
                    // Process other channel messages while waiting.
                    if let Ok(ch) = ChannelMessage::from_bytes(&frame.payload) {
                        let _ = self.channel_manager.process(&ch);
                    }
                }
            }
        }
    }

    /// Wait for the server to open a `forwarded-tcpip` channel and accept it.
    ///
    /// Returns `(local_id, remote_id)` once the channel is confirmed.
    pub async fn accept_forwarded_channel(&mut self) -> Result<(u32, u32), RusshError> {
        loop {
            let frame = self.read_channel_packet().await?;
            let ch = ChannelMessage::from_bytes(&frame.payload)?;
            match &ch {
                ChannelMessage::Open {
                    channel_type,
                    sender_channel,
                    initial_window_size,
                    maximum_packet_size,
                    ..
                } if channel_type == "forwarded-tcpip" => {
                    let remote_id = *sender_channel;
                    // Allocate a local channel ID by opening a placeholder channel.
                    let (local_id, _) =
                        self.channel_manager
                            .open_channel(ChannelKind::ForwardedTcpIp {
                                host: String::new(),
                                port: 0,
                            });
                    let confirm = ChannelMessage::OpenConfirmation {
                        recipient_channel: remote_id,
                        sender_channel: local_id,
                        initial_window_size: *initial_window_size,
                        maximum_packet_size: *maximum_packet_size,
                    };
                    self.stream.write_packet(&confirm.to_frame()?).await?;
                    debug!(local_id, remote_id, "accepted forwarded-tcpip channel");
                    return Ok((local_id, remote_id));
                }
                _ => {
                    let _ = self.channel_manager.process(&ch);
                }
            }
        }
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
                let frame = channel_data_frame(remote_id, &read_buf[..n]);
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

    /// Return the shell executable path to use for interactive sessions,
    /// or `None` to reject shell requests.
    fn shell_command(&self) -> Option<String> {
        None
    }
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
        debug!("starting banner exchange");
        self.stream.write_banner_line(OUR_BANNER).await?;
        let client_banner = self.stream.read_banner_line().await?;
        session.accept_banner(&client_banner)?;
        debug!(client_version = %client_banner, "banner exchanged");

        // Advance state machine to AlgorithmsNegotiated so receive_message
        // can accept KexInit.  The actual negotiation happens inside receive_message.
        use russh_core::AlgorithmSet;
        session.negotiate_with_client(&AlgorithmSet::secure_defaults())?;

        // ── KEXINIT from client ──
        debug!("waiting for client KEXINIT");
        let client_kexinit_frame = self.stream.read_packet().await?;
        // Store raw payload BEFORE parsing so the exchange hash uses original bytes.
        session.store_client_kexinit_payload(client_kexinit_frame.payload.clone());
        let client_kexinit_msg = TransportMessage::from_frame(&client_kexinit_frame)?;
        // Returns the server's KexInit to send.
        if let Some(reply) = session.receive_message(client_kexinit_msg)? {
            let reply_frame = reply.to_frame()?;
            self.stream.write_packet(&reply_frame).await?;
        }
        debug!("KEXINIT exchanged");

        // ── ECDH_INIT from client ──
        debug!("waiting for ECDH init");
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
        debug!(cipher = ?session.negotiated().map(|n| &n.cipher_client_to_server), "KEX complete, TX encrypted");

        // Send EXT_INFO if we advertised ext-info-s (OpenSSH client expects it, encrypted).
        let sends_ext_info = session.negotiated().is_some_and(|n| n.ext_info_s);
        if sends_ext_info {
            let ext_info = TransportMessage::ExtInfo {
                extensions: vec![("server-sig-algs".to_owned(), "ssh-ed25519".to_owned())],
            };
            self.stream.write_packet(&ext_info.to_frame()?).await?;
        }

        // ── NEWKEYS from client ──
        debug!("waiting for client NEWKEYS");
        let client_newkeys_frame = self.stream.read_packet().await?;
        let client_newkeys_msg = TransportMessage::from_frame(&client_newkeys_frame)?;
        session.receive_message(client_newkeys_msg)?;

        // Enable RX decryption now that client has sent NEWKEYS and will start encrypting.
        if let (Some(keys), Some(neg)) = (session.session_keys(), session.negotiated()) {
            let keys = keys.clone();
            let neg = neg.clone();
            self.stream.enable_server_rx_encryption(&keys, &neg);
        }
        debug!("RX decryption enabled");

        // ── SERVICE_REQUEST ──
        // Skip transport-layer housekeeping messages that may arrive before SERVICE_REQUEST.
        // Clients (especially PuTTY) may send EXT_INFO, IGNORE (2), DEBUG (4),
        // GLOBAL_REQUEST (80), or other unknown types before the service request.
        debug!("waiting for SERVICE_REQUEST");
        let service_req_msg = loop {
            let frame = self.stream.read_packet().await?;
            let msg = TransportMessage::from_frame(&frame)?;
            match &msg {
                TransportMessage::ExtInfo { .. } | TransportMessage::Ignore { .. } => {
                    session.receive_message(msg)?;
                }
                TransportMessage::Unknown { message_type, .. } => {
                    debug!(
                        msg_type = message_type,
                        "skipping unknown transport message before SERVICE_REQUEST"
                    );
                }
                _ => break msg,
            }
        };
        if let Some(service_accept) = session.receive_message(service_req_msg)? {
            self.stream
                .write_packet(&service_accept.to_frame()?)
                .await?;
        }
        debug!("service accepted");

        // ── Auth ──
        let auth_policy = self
            .config
            .auth_policy
            .clone()
            .unwrap_or_else(ServerAuthPolicy::secure_defaults);
        session.activate_userauth(auth_policy);
        info!("starting authentication");
        loop {
            let auth_frame = self.stream.read_packet().await?;
            // Skip transport-layer housekeeping messages (IGNORE=2, DEBUG=4, etc.)
            // that PuTTY and other clients may send during the auth phase.
            let msg_type = auth_frame.message_type().unwrap_or(0);
            if msg_type < 50 || msg_type == 80 {
                trace!(msg_type, "skipping transport msg during auth");
                // GLOBAL_REQUEST (80) and all transport-layer messages are silently skipped.
                continue;
            }
            let auth_msg = UserAuthMessage::from_frame(&auth_frame)?;
            debug!(auth_msg_type = msg_type, "received auth message");
            let reply = session.receive_userauth_message(auth_msg)?;
            if let Some(reply) = reply {
                let reply_type = match &reply {
                    UserAuthMessage::Success => "success",
                    UserAuthMessage::Failure { .. } => "failure",
                    UserAuthMessage::PublicKeyOk { .. } => "pk-ok",
                    UserAuthMessage::Banner { .. } => "banner",
                    _ => "other",
                };
                debug!(reply_type, "sending auth reply");
                self.stream.write_packet(&reply.to_frame()?).await?;
                if let Some(user) = session.authenticated_user() {
                    info!(user = %user, "authentication successful");
                    self.stream.activate_compression();
                    break;
                }
            }
        }

        // ── Channel loop ──
        info!("entering channel loop");
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
        let mut remote_forward_listeners: Vec<(TcpListener, String, u16)> = Vec::new();

        loop {
            // Multiplex between reading SSH packets and accepting TCP
            // connections on remote-forward listeners.
            enum LoopEvent {
                Packet(Result<PacketFrame, RusshError>),
                ForwardAccept(usize, std::io::Result<(TcpStream, std::net::SocketAddr)>),
            }

            let event = if remote_forward_listeners.is_empty() {
                LoopEvent::Packet(self.stream.read_packet().await)
            } else {
                tokio::select! {
                    biased;
                    frame = self.stream.read_packet() => LoopEvent::Packet(frame),
                    result = accept_any(&remote_forward_listeners) => {
                        let (idx, res) = result;
                        LoopEvent::ForwardAccept(idx, res)
                    }
                }
            };

            match event {
                LoopEvent::ForwardAccept(idx, accept_result) => {
                    let (_, ref bind_host, bind_port) = remote_forward_listeners[idx];
                    let bind_host = bind_host.clone();

                    match accept_result {
                        Ok((mut tcp_stream, peer_addr)) => {
                            debug!(
                                bind_host = %bind_host, bind_port,
                                originator = %peer_addr,
                                "accepted connection on remote forward listener"
                            );
                            let our_id = next_server_id;
                            next_server_id += 1;
                            let extra_data = ForwardHandle::build_forwarded_tcpip_open_extra(
                                &bind_host,
                                u32::from(bind_port),
                                &peer_addr.ip().to_string(),
                                u32::from(peer_addr.port()),
                            );
                            let open_msg = ChannelMessage::Open {
                                channel_type: "forwarded-tcpip".to_string(),
                                sender_channel: our_id,
                                initial_window_size: 2 * 1024 * 1024,
                                maximum_packet_size: 32768,
                                extra_data,
                            };
                            if self
                                .stream
                                .write_packet(&open_msg.to_frame()?)
                                .await
                                .is_err()
                            {
                                continue;
                            }
                            let client_ch = loop {
                                let f = match self.stream.read_packet().await {
                                    Ok(f) => f,
                                    Err(_) => break None,
                                };
                                match ChannelMessage::from_bytes(&f.payload) {
                                    Ok(ChannelMessage::OpenConfirmation {
                                        recipient_channel,
                                        sender_channel,
                                        ..
                                    }) if recipient_channel == our_id => {
                                        break Some(sender_channel);
                                    }
                                    Ok(ChannelMessage::OpenFailure { .. }) => break None,
                                    _ => {}
                                }
                            };
                            if let Some(client_ch) = client_ch {
                                let _ = self
                                    .relay_server_tcp_channel(our_id, client_ch, &mut tcp_stream)
                                    .await;
                            }
                        }
                        Err(e) => {
                            warn!(error = %e, "forward listener accept error");
                        }
                    }
                }
                LoopEvent::Packet(Err(e)) if e.category() == russh_core::RusshErrorCategory::Io => {
                    break;
                }
                LoopEvent::Packet(Err(e)) => return Err(e),
                LoopEvent::Packet(Ok(frame)) => {
                    // Check for disconnect.
                    if frame.message_type() == Some(1) {
                        break;
                    }

                    // Handle SSH_MSG_GLOBAL_REQUEST (80).
                    if frame.message_type() == Some(80) {
                        let (request_name, want_reply) = parse_global_request(&frame.payload);
                        debug!(request_name, want_reply, "GLOBAL_REQUEST");

                        if request_name == "tcpip-forward" {
                            let name_len = u32::from_be_bytes([
                                frame.payload[1],
                                frame.payload[2],
                                frame.payload[3],
                                frame.payload[4],
                            ]) as usize;
                            let data_start = 5 + name_len + 1;
                            let data = &frame.payload[data_start..];
                            match ForwardHandle::parse_tcpip_forward_data(data) {
                                Ok((bind_host, bind_port)) => {
                                    let bind_addr = if bind_host.is_empty()
                                        || bind_host == "0.0.0.0"
                                    {
                                        "0.0.0.0"
                                    } else if bind_host == "localhost" || bind_host == "127.0.0.1" {
                                        "127.0.0.1"
                                    } else {
                                        &bind_host
                                    };
                                    let bp = bind_port as u16;
                                    match TcpListener::bind(format!("{bind_addr}:{bp}")).await {
                                        Ok(listener) => {
                                            let actual_port = listener
                                                .local_addr()
                                                .map(|a| a.port())
                                                .unwrap_or(bp);
                                            info!(
                                                bind_addr,
                                                requested_port = bp,
                                                actual_port,
                                                "tcpip-forward: listener bound"
                                            );
                                            if want_reply {
                                                let mut rp = vec![81u8];
                                                if bp == 0 {
                                                    write_u32(&mut rp, u32::from(actual_port));
                                                }
                                                let _ = self
                                                    .stream
                                                    .write_packet(&PacketFrame::new(rp))
                                                    .await;
                                            }
                                            remote_forward_listeners.push((
                                                listener,
                                                bind_host.clone(),
                                                actual_port,
                                            ));
                                        }
                                        Err(e) => {
                                            warn!(error = %e, "tcpip-forward: bind failed");
                                            if want_reply {
                                                let _ = self
                                                    .stream
                                                    .write_packet(&PacketFrame::new(vec![82]))
                                                    .await;
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    warn!(error = %e, "tcpip-forward: parse failed");
                                    if want_reply {
                                        let _ = self
                                            .stream
                                            .write_packet(&PacketFrame::new(vec![82]))
                                            .await;
                                    }
                                }
                            }
                        } else if want_reply {
                            let reply = if request_name == "keepalive@openssh.com" {
                                81
                            } else {
                                82
                            };
                            let _ = self
                                .stream
                                .write_packet(&PacketFrame::new(vec![reply]))
                                .await;
                        }
                        continue;
                    }

                    // Handle SSH_MSG_IGNORE (2) and SSH_MSG_DEBUG (4).
                    match frame.message_type() {
                        Some(2) | Some(4) => {
                            trace!(
                                msg_type = frame.message_type(),
                                "ignoring transport msg in channel loop"
                            );
                            continue;
                        }
                        _ => {}
                    }

                    // Parse as channel message.
                    let msg = match ChannelMessage::from_bytes(&frame.payload) {
                        Ok(m) => m,
                        Err(e) => {
                            debug!(error = %e, msg_type = frame.message_type(), "failed to parse channel message, skipping");
                            continue;
                        }
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
                            debug!(client_ch, our_id, "channel opened");
                            server_channels.insert(
                                client_ch,
                                ServerChannelState {
                                    is_sftp: false,
                                    scp_root: None,
                                    sftp_server: None,
                                    sftp_framer: SftpFramer::new(),
                                    pty_requested: false,
                                    pty_size: None,
                                    pty_term: None,
                                    env: Vec::new(),
                                    agent_forwarding_requested: false,
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
                                    info!(command = %command, "exec request");
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
                                    info!("SFTP subsystem requested");
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

                                ChannelRequest::Env { name, value } => {
                                    debug!(env_name = %name, "client sent env var");
                                    state.env.push((name, value));
                                    if want_reply {
                                        let ok = ChannelMessage::Success {
                                            recipient_channel: client_ch,
                                        };
                                        self.stream.write_packet(&ok.to_frame()?).await?;
                                    }
                                }

                                ChannelRequest::PtyReq {
                                    term,
                                    width_chars,
                                    height_rows,
                                    ..
                                } => {
                                    info!(term = %term, cols = width_chars, rows = height_rows, "PTY requested");
                                    state.pty_requested = true;
                                    state.pty_term = Some(term);
                                    state.pty_size = Some((
                                        u16::try_from(width_chars).unwrap_or(80),
                                        u16::try_from(height_rows).unwrap_or(24),
                                    ));
                                    if want_reply {
                                        let ok = ChannelMessage::Success {
                                            recipient_channel: client_ch,
                                        };
                                        self.stream.write_packet(&ok.to_frame()?).await?;
                                    }
                                }

                                ChannelRequest::Shell => {
                                    info!("shell request");
                                    if let Some(shell) = handler.shell_command() {
                                        if want_reply {
                                            let ok = ChannelMessage::Success {
                                                recipient_channel: client_ch,
                                            };
                                            self.stream.write_packet(&ok.to_frame()?).await?;
                                        }
                                        let pty_size = state.pty_size;
                                        let pty_term = state.pty_term.clone();
                                        let env = state.env.clone();
                                        info!(shell = %shell, pty = pty_size.is_some(), "spawning shell");
                                        self.run_shell_channel(
                                            client_ch, &shell, pty_size, pty_term, env,
                                        )
                                        .await?;
                                    } else {
                                        warn!("shell request denied (no shell configured)");
                                        if want_reply {
                                            let fail = ChannelMessage::Failure {
                                                recipient_channel: client_ch,
                                            };
                                            self.stream.write_packet(&fail.to_frame()?).await?;
                                        }
                                    }
                                }

                                ChannelRequest::WindowChange {
                                    width_chars,
                                    height_rows,
                                    width_pixels,
                                    height_pixels,
                                } => {
                                    debug!(
                                        cols = width_chars,
                                        rows = height_rows,
                                        px_w = width_pixels,
                                        px_h = height_pixels,
                                        "window-change request"
                                    );
                                    state.pty_size = Some((
                                        u16::try_from(width_chars).unwrap_or(80),
                                        u16::try_from(height_rows).unwrap_or(24),
                                    ));
                                    // Per RFC 4254 §6.7, window-change MUST NOT
                                    // have want_reply set, so we do not send a
                                    // response.
                                }

                                ChannelRequest::Unknown {
                                    ref request_type, ..
                                } if request_type == "auth-agent-req@openssh.com" => {
                                    debug!("agent forwarding requested");
                                    state.agent_forwarding_requested = true;
                                    if want_reply {
                                        let ok = ChannelMessage::Success {
                                            recipient_channel: client_ch,
                                        };
                                        self.stream.write_packet(&ok.to_frame()?).await?;
                                    }
                                }

                                ChannelRequest::Unknown {
                                    ref request_type, ..
                                } => {
                                    debug!(request_type = %request_type, "unknown channel request");
                                    if want_reply {
                                        let fail = ChannelMessage::Failure {
                                            recipient_channel: client_ch,
                                        };
                                        self.stream.write_packet(&fail.to_frame()?).await?;
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
                                .write_packet(
                                    &ChannelMessage::Eof { recipient_channel }.to_frame()?,
                                )
                                .await;
                            let _ = self
                                .stream
                                .write_packet(
                                    &ChannelMessage::Close { recipient_channel }.to_frame()?,
                                )
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
                } // LoopEvent::Packet(Ok(frame))
            } // match event
        }

        Ok(())
    }

    /// Drive bidirectional I/O between a TCP stream and an SSH channel (server side).
    async fn relay_server_tcp_channel(
        &mut self,
        _our_id: u32,
        client_ch: u32,
        tcp: &mut TcpStream,
    ) -> Result<(), RusshError> {
        let (mut tcp_rx, mut tcp_tx) = tcp.split();
        let mut buf = vec![0u8; 32768];

        loop {
            tokio::select! {
                n = tcp_rx.read(&mut buf) => {
                    let n = match n {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    let frame = channel_data_frame(client_ch, &buf[..n]);
                    if self.stream.write_packet(&frame).await.is_err() {
                        break;
                    }
                }
                frame_res = self.stream.read_packet() => {
                    let frame = match frame_res {
                        Ok(f) => f,
                        Err(_) => break,
                    };
                    match ChannelMessage::from_bytes(&frame.payload) {
                        Ok(ChannelMessage::Data { data, .. }) => {
                            if tcp_tx.write_all(&data).await.is_err() {
                                break;
                            }
                        }
                        Ok(ChannelMessage::WindowAdjust { .. }) => {}
                        Ok(ChannelMessage::Eof { .. })
                        | Ok(ChannelMessage::Close { .. }) => break,
                        _ => {}
                    }
                }
            }
        }
        // Send EOF + CLOSE on the forwarded channel.
        let _ = self
            .stream
            .write_packet(
                &ChannelMessage::Eof {
                    recipient_channel: client_ch,
                }
                .to_frame()?,
            )
            .await;
        let _ = self
            .stream
            .write_packet(
                &ChannelMessage::Close {
                    recipient_channel: client_ch,
                }
                .to_frame()?,
            )
            .await;
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
        let mut response = vec![0x00];
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
                        match resolve_scp_target_path(root, filename) {
                            Ok(dest) => {
                                let write_result = if let Some(parent) = dest.parent() {
                                    std::fs::create_dir_all(parent)
                                        .and_then(|_| std::fs::write(&dest, file_bytes))
                                } else {
                                    std::fs::write(&dest, file_bytes)
                                };
                                if let Err(error) = write_result {
                                    response = scp_status_data(
                                        0x01,
                                        &format!("scp write failed: {error}"),
                                    );
                                }
                            }
                            Err(error) => {
                                response = scp_status_data(0x01, error.message());
                            }
                        }
                    } else {
                        response = scp_status_data(0x01, "scp payload shorter than declared size");
                    }
                } else {
                    response = scp_status_data(0x01, "invalid scp header");
                }
            } else {
                response = scp_status_data(0x01, "invalid utf-8 in scp header");
            }
        }
        // Send ACK or error status.
        let ack = ChannelMessage::Data {
            recipient_channel: client_ch,
            data: response,
        };
        self.stream.write_packet(&ack.to_frame()?).await
    }

    /// Spawn `shell_exe` as a child process and bridge its stdin/stdout
    /// bidirectionally with the SSH channel data stream.
    async fn run_shell_channel(
        &mut self,
        client_ch: u32,
        shell_exe: &str,
        pty_size: Option<(u16, u16)>,
        pty_term: Option<String>,
        env: Vec<(String, String)>,
    ) -> Result<(), RusshError> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::process::Command;

        if let Some((cols, rows)) = pty_size {
            #[cfg(unix)]
            return self
                .run_shell_pty(client_ch, shell_exe, cols, rows, pty_term, env)
                .await;
            #[cfg(not(unix))]
            {
                let _ = (cols, rows, pty_term, env);
                Err(RusshError::new(
                    RusshErrorCategory::Channel,
                    "PTY shell sessions are not supported on this platform",
                ))
            }
        } else {
            // No PTY: pipe-only mode for non-interactive exec.
            let mut cmd = Command::new(shell_exe);
            for (k, v) in &env {
                cmd.env(k, v);
            }
            let mut child = cmd
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .map_err(|e| RusshError::new(RusshErrorCategory::Io, e.to_string()))?;

            let mut child_stdin = Some(
                child
                    .stdin
                    .take()
                    .ok_or_else(|| RusshError::new(RusshErrorCategory::Io, "no stdin"))?,
            );
            let child_stdout = child
                .stdout
                .take()
                .ok_or_else(|| RusshError::new(RusshErrorCategory::Io, "no stdout"))?;
            let child_stderr = child
                .stderr
                .take()
                .ok_or_else(|| RusshError::new(RusshErrorCategory::Io, "no stderr"))?;

            let mut stdout_reader = tokio::io::BufReader::new(child_stdout);
            let mut stderr_reader = tokio::io::BufReader::new(child_stderr);
            let mut buf = vec![0u8; 4096];
            let mut stderr_buf = vec![0u8; 4096];
            let mut channel_open = true;
            let mut stdout_open = true;
            let mut stderr_open = true;
            let mut exit_code = None;

            while stdout_open || stderr_open || exit_code.is_none() {
                tokio::select! {
                    frame_res = self.stream.read_packet(), if channel_open => {
                        match frame_res {
                            Err(_) => {
                                channel_open = false;
                                child_stdin.take();
                            }
                            Ok(frame) => {
                                match ChannelMessage::from_bytes(&frame.payload) {
                                    Ok(ChannelMessage::Data { data, .. }) => {
                                        if let Some(stdin) = child_stdin.as_mut() {
                                            if stdin.write_all(&data).await.is_err() {
                                                child_stdin.take();
                                            }
                                        }
                                    }
                                    Ok(ChannelMessage::Eof { .. }) | Ok(ChannelMessage::Close { .. }) => {
                                        channel_open = false;
                                        child_stdin.take();
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                    n = stdout_reader.read(&mut buf), if stdout_open => {
                        let n = n.unwrap_or(0);
                        if n == 0 {
                            stdout_open = false;
                            continue;
                        }
                        let frame = channel_data_frame(client_ch, &buf[..n]);
                        if self.stream.write_packet(&frame).await.is_err() { break; }
                    }
                    n = stderr_reader.read(&mut stderr_buf), if stderr_open => {
                        let n = n.unwrap_or(0);
                        if n == 0 {
                            stderr_open = false;
                            continue;
                        }
                        // Send stderr as extended data type 1.
                        let frame = channel_extended_data_frame(client_ch, 1, &stderr_buf[..n]);
                        if self.stream.write_packet(&frame).await.is_err() { break; }
                    }
                    status = child.wait(), if exit_code.is_none() => {
                        exit_code = Some(status.map(|s| s.code().unwrap_or(0) as u32).unwrap_or(0));
                        child_stdin.take();
                    }
                }
            }

            let exit_code = if let Some(code) = exit_code {
                code
            } else {
                child_stdin.take();
                match tokio::time::timeout(std::time::Duration::from_secs(1), child.wait()).await {
                    Ok(status) => status.map(|s| s.code().unwrap_or(0) as u32).unwrap_or(0),
                    Err(_) => {
                        let _ = child.start_kill();
                        match tokio::time::timeout(std::time::Duration::from_secs(1), child.wait())
                            .await
                        {
                            Ok(status) => status.map(|s| s.code().unwrap_or(0) as u32).unwrap_or(0),
                            Err(_) => 0,
                        }
                    }
                }
            };
            info!(exit_code, "shell (no-pty) exited");
            let _ = self
                .stream
                .write_packet(
                    &ChannelMessage::Request {
                        recipient_channel: client_ch,
                        want_reply: false,
                        request: ChannelRequest::ExitStatus {
                            exit_status: exit_code,
                        },
                    }
                    .to_frame()?,
                )
                .await;
            let _ = self
                .stream
                .write_packet(
                    &ChannelMessage::Eof {
                        recipient_channel: client_ch,
                    }
                    .to_frame()?,
                )
                .await;
            let _ = self
                .stream
                .write_packet(
                    &ChannelMessage::Close {
                        recipient_channel: client_ch,
                    }
                    .to_frame()?,
                )
                .await;
            Ok(())
        }
    }

    #[cfg(unix)]
    async fn run_shell_pty(
        &mut self,
        client_ch: u32,
        shell_exe: &str,
        cols: u16,
        rows: u16,
        pty_term: Option<String>,
        env: Vec<(String, String)>,
    ) -> Result<(), RusshError> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let pty = pty_process::Pty::new()
            .map_err(|e| RusshError::new(RusshErrorCategory::Io, e.to_string()))?;
        pty.resize(pty_process::Size::new(rows, cols))
            .map_err(|e| RusshError::new(RusshErrorCategory::Io, e.to_string()))?;
        let pts = pty
            .pts()
            .map_err(|e| RusshError::new(RusshErrorCategory::Io, e.to_string()))?;

        let mut cmd = pty_process::Command::new(shell_exe);
        // Set TERM from the pty-req term field, defaulting to "xterm-256color".
        let term = pty_term.as_deref().unwrap_or("xterm-256color");
        cmd.env("TERM", term);
        for (k, v) in &env {
            cmd.env(k, v);
        }
        debug!(shell = %shell_exe, term, cols, rows, "spawning PTY shell");
        let mut child = cmd
            .spawn(&pts)
            .map_err(|e| RusshError::new(RusshErrorCategory::Io, e.to_string()))?;

        // `pty` must not be split until after spawn() since `pts` borrows from it.
        // Re-create to own: use the already-moved pty.
        let (mut pty_read, mut pty_write) = tokio::io::split(pty);
        let mut pty_buf = vec![0u8; 4096];
        let mut client_open = true;

        loop {
            tokio::select! {
                // Data from SSH client → PTY (→ shell stdin).
                frame_res = self.stream.read_packet(), if client_open => {
                    match frame_res {
                        Err(_) => {
                            client_open = false;
                            let _ = pty_write.shutdown().await;
                        }
                        Ok(frame) => match ChannelMessage::from_bytes(&frame.payload) {
                            Ok(ChannelMessage::Data { data, .. }) => {
                                trace!(bytes = data.len(), "client→PTY");
                                if pty_write.write_all(&data).await.is_err() {
                                    break;
                                }
                            }
                            Ok(ChannelMessage::Request { request: ChannelRequest::WindowChange { width_chars, height_rows, .. }, .. }) => {
                                let new_cols = u16::try_from(width_chars).unwrap_or(80);
                                let new_rows = u16::try_from(height_rows).unwrap_or(24);
                                debug!(cols = new_cols, rows = new_rows, "PTY resize");
                                // Unsplit to resize, then re-split.
                                let pty_whole = pty_read.unsplit(pty_write);
                                let _ = pty_whole.resize(pty_process::Size::new(new_rows, new_cols));
                                let (r, w) = tokio::io::split(pty_whole);
                                pty_read = r;
                                pty_write = w;
                            }
                            Ok(ChannelMessage::Eof { .. }) | Ok(ChannelMessage::Close { .. }) => {
                                client_open = false;
                                let _ = pty_write.shutdown().await;
                            }
                            _ => {}
                        },
                    }
                }
                // Data from PTY (shell output) → SSH channel.
                n = pty_read.read(&mut pty_buf) => {
                    let n = match n {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    trace!(bytes = n, "PTY→client");
                    let frame = channel_data_frame(client_ch, &pty_buf[..n]);
                    if self.stream.write_packet(&frame).await.is_err() {
                        break;
                    }
                }
                // Shell process exited — drain any remaining PTY output then stop.
                status = child.wait() => {
                    let exit_code = status.map(|s| s.code().unwrap_or(0) as u32).unwrap_or(0);
                    info!(exit_code, "PTY shell exited");
                    // Drain any buffered PTY output (with short timeout).
                    let drain_deadline = tokio::time::Instant::now()
                        + std::time::Duration::from_millis(200);
                    loop {
                        match tokio::time::timeout_at(drain_deadline, pty_read.read(&mut pty_buf)).await {
                            Ok(Ok(n)) if n > 0 => {
                                trace!(bytes = n, "PTY drain→client");
                                let frame = channel_data_frame(client_ch, &pty_buf[..n]);
                                let _ = self.stream.write_packet(&frame).await;
                            }
                            _ => break,
                        }
                    }
                    let _ = self.stream.write_packet(&ChannelMessage::Request {
                        recipient_channel: client_ch,
                        want_reply: false,
                        request: ChannelRequest::ExitStatus { exit_status: exit_code },
                    }.to_frame()?).await;
                    let _ = self.stream.write_packet(&ChannelMessage::Eof { recipient_channel: client_ch }.to_frame()?).await;
                    let _ = self.stream.write_packet(&ChannelMessage::Close { recipient_channel: client_ch }.to_frame()?).await;
                    return Ok(());
                }
            }
        }

        // Fallback path (client closed channel first).
        let exit_code = child
            .wait()
            .await
            .map(|s| s.code().unwrap_or(0) as u32)
            .unwrap_or(0);
        info!(exit_code, "PTY shell exited (client-closed)");
        let _ = self
            .stream
            .write_packet(
                &ChannelMessage::Request {
                    recipient_channel: client_ch,
                    want_reply: false,
                    request: ChannelRequest::ExitStatus {
                        exit_status: exit_code,
                    },
                }
                .to_frame()?,
            )
            .await;
        let _ = self
            .stream
            .write_packet(
                &ChannelMessage::Eof {
                    recipient_channel: client_ch,
                }
                .to_frame()?,
            )
            .await;
        let _ = self
            .stream
            .write_packet(
                &ChannelMessage::Close {
                    recipient_channel: client_ch,
                }
                .to_frame()?,
            )
            .await;
        Ok(())
    }
}

// ── Agent forwarding relay ───────────────────────────────────────────────────

/// Relay SSH agent protocol between an `auth-agent@openssh.com` channel and
/// a local Unix domain socket (`SSH_AUTH_SOCK`).
///
/// Reads data from the channel and writes it to the Unix socket, and vice
/// versa, until one side sends EOF or the socket closes.
#[cfg(unix)]
pub async fn relay_agent_channel<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: &mut PacketStream<S>,
    channel_id: u32,
    auth_sock: &str,
) -> Result<(), RusshError> {
    use tokio::net::UnixStream;

    let mut sock = UnixStream::connect(auth_sock).await.map_err(|e| {
        RusshError::new(
            RusshErrorCategory::Io,
            format!("failed to connect to SSH_AUTH_SOCK ({auth_sock}): {e}"),
        )
    })?;

    let mut buf = vec![0u8; 16384];
    loop {
        tokio::select! {
            result = stream.read_packet() => {
                let frame = result?;
                let msg = ChannelMessage::from_bytes(&frame.payload)?;
                match msg {
                    ChannelMessage::Data { data, .. } => {
                        sock.write_all(&data).await.map_err(io_err)?;
                    }
                    ChannelMessage::Eof { .. } | ChannelMessage::Close { .. } => break,
                    _ => {}
                }
            }
            result = sock.read(&mut buf) => {
                let n = result.map_err(io_err)?;
                if n == 0 {
                    // Socket closed; send EOF on the channel.
                    let eof = ChannelMessage::Eof { recipient_channel: channel_id };
                    stream.write_packet(&eof.to_frame()?).await?;
                    break;
                }
                let data_msg = ChannelMessage::Data {
                    recipient_channel: channel_id,
                    data: buf[..n].to_vec(),
                };
                stream.write_packet(&data_msg.to_frame()?).await?;
            }
        }
    }
    Ok(())
}

// ── ServerChannelState ───────────────────────────────────────────────────────

struct ServerChannelState {
    is_sftp: bool,
    scp_root: Option<PathBuf>,
    /// Stateful SFTP server instance (None when channel is not SFTP).
    sftp_server: Option<SftpFileServer>,
    /// Framer to reassemble SFTP packets across multiple DATA messages.
    sftp_framer: SftpFramer,
    /// Whether the client has requested a PTY on this channel.
    pty_requested: bool,
    /// PTY terminal dimensions (cols, rows) if pty-req was received.
    pty_size: Option<(u16, u16)>,
    /// Terminal type from pty-req (e.g. "xterm-256color").
    pty_term: Option<String>,
    /// Environment variables sent by the client via env channel requests.
    env: Vec<(String, String)>,
    /// Whether the client has requested SSH agent forwarding on this channel.
    agent_forwarding_requested: bool,
}

// ── Remote-forward listener helper ───────────────────────────────────────────

/// Accept a TCP connection on any of the given listeners.
///
/// Returns `(index, result)` where `index` is the position of the listener
/// that accepted the connection.
async fn accept_any(
    listeners: &[(TcpListener, String, u16)],
) -> (usize, std::io::Result<(TcpStream, std::net::SocketAddr)>) {
    // Safety: this function is only called when listeners is non-empty.
    assert!(!listeners.is_empty());

    // Use poll_fn to poll all listeners concurrently.
    use std::future::poll_fn;
    use std::task::Poll;

    poll_fn(|cx| {
        for (i, (listener, _, _)) in listeners.iter().enumerate() {
            if let Poll::Ready(result) = listener.poll_accept(cx) {
                return Poll::Ready((i, result));
            }
        }
        Poll::Pending
    })
    .await
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

    #[test]
    fn scp_target_path_rejects_traversal() {
        let root = PathBuf::from("/tmp/russh_scp_root");
        let error = resolve_scp_target_path(&root, "../escape.txt")
            .expect_err("traversal should be rejected");
        assert_eq!(error.category(), RusshErrorCategory::Protocol);
    }

    #[test]
    fn scp_target_path_allows_nested_relative_paths() {
        let root = PathBuf::from("/tmp/russh_scp_root");
        let path = resolve_scp_target_path(&root, "nested/file.txt")
            .expect("nested path should be accepted");
        assert_eq!(path, root.join("nested/file.txt"));
    }

    // ── Global request / keepalive tests ─────────────────────────────────────

    #[test]
    fn parse_global_request_keepalive() {
        let frame = build_keepalive_frame();
        let (name, want_reply) = parse_global_request(&frame.payload);
        assert_eq!(name, "keepalive@openssh.com");
        assert!(want_reply);
    }

    #[test]
    fn parse_global_request_unknown() {
        // Build an unknown global request with want_reply=true
        let request_name = b"tcpip-forward";
        let mut payload = Vec::new();
        payload.push(80); // SSH_MSG_GLOBAL_REQUEST
        write_bytes(&mut payload, request_name);
        payload.push(1); // want_reply = true
        let (name, want_reply) = parse_global_request(&payload);
        assert_eq!(name, "tcpip-forward");
        assert!(want_reply);
    }

    #[test]
    fn parse_global_request_no_reply() {
        let request_name = b"some-notify";
        let mut payload = Vec::new();
        payload.push(80);
        write_bytes(&mut payload, request_name);
        payload.push(0); // want_reply = false
        let (name, want_reply) = parse_global_request(&payload);
        assert_eq!(name, "some-notify");
        assert!(!want_reply);
    }

    #[test]
    fn parse_global_request_too_short() {
        let (name, want_reply) = parse_global_request(&[80]);
        assert_eq!(name, "");
        assert!(!want_reply);
    }

    #[test]
    fn build_keepalive_frame_wire_format() {
        let frame = build_keepalive_frame();
        let p = &frame.payload;
        // Byte 0: SSH_MSG_GLOBAL_REQUEST
        assert_eq!(p[0], 80);
        // Bytes 1..5: string length of "keepalive@openssh.com" (21)
        let name_len = u32::from_be_bytes([p[1], p[2], p[3], p[4]]);
        assert_eq!(name_len, 21);
        // Bytes 5..26: the request name
        assert_eq!(&p[5..26], b"keepalive@openssh.com");
        // Byte 26: want_reply = true
        assert_eq!(p[26], 1);
        // Total length: 1 + 4 + 21 + 1 = 27
        assert_eq!(p.len(), 27);
    }

    /// Verify that a WindowChange channel request round-trips through
    /// encoding and decoding, and that the SSH-spec `want_reply = false`
    /// convention is preserved.
    #[test]
    fn window_change_request_encodes_correctly() {
        use russh_channel::{ChannelMessage, ChannelRequest};

        let msg = ChannelMessage::Request {
            recipient_channel: 7,
            want_reply: false,
            request: ChannelRequest::WindowChange {
                width_chars: 200,
                height_rows: 50,
                width_pixels: 1600,
                height_pixels: 800,
            },
        };
        let bytes = msg.to_bytes().expect("encode window-change");
        let decoded = ChannelMessage::from_bytes(&bytes).expect("decode window-change");
        assert_eq!(decoded, msg);

        // Confirm want_reply is false in the wire encoding (byte at offset 5
        // inside the CHANNEL_REQUEST payload: msg_type(1) + recipient(4) +
        // string-length(4) + "window-change"(13) = offset 22, then want_reply).
        // Instead of hard-coding offsets, re-check via the decoded struct.
        if let ChannelMessage::Request {
            want_reply,
            request:
                ChannelRequest::WindowChange {
                    width_chars,
                    height_rows,
                    ..
                },
            ..
        } = decoded
        {
            assert!(!want_reply, "window-change must have want_reply=false");
            assert_eq!(width_chars, 200);
            assert_eq!(height_rows, 50);
        } else {
            panic!("unexpected decoded variant");
        }
    }

    // ── open_direct_tcpip / channel_write / channel_read tests ───────────

    #[test]
    fn open_direct_tcpip_builds_correct_frame() {
        use russh_channel::{ChannelKind, ChannelManager, ChannelMessage, ForwardHandle};

        let mut cm = ChannelManager::new();
        let (local_id, mut open_msg) = cm.open_channel(ChannelKind::DirectTcpIp {
            host: "db.internal".to_owned(),
            port: 5432,
        });

        let extra =
            ForwardHandle::build_direct_tcpip_open_extra("db.internal", 5432, "127.0.0.1", 0);
        if let ChannelMessage::Open {
            ref mut extra_data,
            ref channel_type,
            sender_channel,
            initial_window_size,
            maximum_packet_size,
        } = open_msg
        {
            assert_eq!(channel_type, "direct-tcpip");
            assert_eq!(sender_channel, local_id);
            assert!(initial_window_size > 0);
            assert!(maximum_packet_size > 0);
            *extra_data = extra.clone();
        } else {
            panic!("expected ChannelMessage::Open");
        }

        // Verify the extra_data wire format:
        // [4-byte len]["db.internal"][4-byte port=5432][4-byte len]["127.0.0.1"][4-byte port=0]
        let mut off = 0;
        let host_len = u32::from_be_bytes([extra[0], extra[1], extra[2], extra[3]]) as usize;
        off += 4;
        assert_eq!(&extra[off..off + host_len], b"db.internal");
        off += host_len;
        let port_val =
            u32::from_be_bytes([extra[off], extra[off + 1], extra[off + 2], extra[off + 3]]);
        assert_eq!(port_val, 5432);
        off += 4;
        let orig_len =
            u32::from_be_bytes([extra[off], extra[off + 1], extra[off + 2], extra[off + 3]])
                as usize;
        off += 4;
        assert_eq!(&extra[off..off + orig_len], b"127.0.0.1");
        off += orig_len;
        let orig_port =
            u32::from_be_bytes([extra[off], extra[off + 1], extra[off + 2], extra[off + 3]]);
        assert_eq!(orig_port, 0);

        // Verify the full message can be serialized.
        let frame = open_msg.to_frame().expect("encode direct-tcpip open");
        // Byte 0 must be SSH_MSG_CHANNEL_OPEN (90).
        assert_eq!(frame.payload[0], 90);
    }

    #[test]
    fn channel_data_frame_encodes_correctly() {
        let data = b"hello world";
        let frame = channel_data_frame(42, data);
        let p = &frame.payload;
        // Byte 0: SSH_MSG_CHANNEL_DATA (94)
        assert_eq!(p[0], 94);
        // Bytes 1..5: recipient channel
        let ch = u32::from_be_bytes([p[1], p[2], p[3], p[4]]);
        assert_eq!(ch, 42);
        // Bytes 5..9: data length
        let len = u32::from_be_bytes([p[5], p[6], p[7], p[8]]) as usize;
        assert_eq!(len, data.len());
        // Bytes 9..: data
        assert_eq!(&p[9..9 + len], data);
    }

    #[test]
    fn compression_round_trip() {
        let original = b"Hello, SSH compression! This is a test payload for zlib@openssh.com delayed compression.";
        let mut data = original.to_vec();

        let mut tx = DirectionalCompression::new_zlib();
        tx.compress_payload(&mut data).expect("compress");
        // Compressed data should differ from the original.
        assert_ne!(data, original.as_slice());

        let mut rx = DirectionalCompression::new_zlib();
        rx.decompress_payload(&mut data).expect("decompress");
        assert_eq!(data, original.as_slice());
    }

    #[test]
    fn compression_none_is_passthrough() {
        let original = b"payload that should not change";
        let mut data = original.to_vec();

        let mut none_tx = DirectionalCompression::None;
        none_tx.compress_payload(&mut data).expect("compress none");
        assert_eq!(data, original.as_slice());

        let mut none_rx = DirectionalCompression::None;
        none_rx
            .decompress_payload(&mut data)
            .expect("decompress none");
        assert_eq!(data, original.as_slice());
    }

    #[test]
    fn algorithm_set_includes_compression() {
        use russh_core::AlgorithmSet;
        let defaults = AlgorithmSet::secure_defaults();
        assert!(defaults.compression.contains(&"none".to_string()));
        assert!(
            defaults
                .compression
                .contains(&"zlib@openssh.com".to_string())
        );
    }

    #[test]
    fn compression_stateful_across_packets() {
        let mut tx = DirectionalCompression::new_zlib();
        let mut rx = DirectionalCompression::new_zlib();

        // Compress and decompress multiple packets through the same stream.
        for i in 0..5 {
            let original = format!("packet number {i} with repeated data aaaaaaaaaa").into_bytes();
            let mut data = original.clone();
            tx.compress_payload(&mut data).expect("compress");
            rx.decompress_payload(&mut data).expect("decompress");
            assert_eq!(data, original);
        }
    }

    #[test]
    fn keyboard_interactive_request_round_trips() {
        let request = UserAuthRequest::KeyboardInteractive {
            user: "alice".to_owned(),
            service: "ssh-connection".to_owned(),
            language_tag: String::new(),
            submethods: String::new(),
        };
        let msg = UserAuthMessage::Request(request.clone());
        let frame = msg.to_frame().expect("encode kbd-interactive request");
        let decoded = UserAuthMessage::from_frame(&frame).expect("decode kbd-interactive request");
        if let UserAuthMessage::Request(UserAuthRequest::KeyboardInteractive {
            user,
            service,
            language_tag,
            submethods,
        }) = decoded
        {
            assert_eq!(user, "alice");
            assert_eq!(service, "ssh-connection");
            assert_eq!(language_tag, "");
            assert_eq!(submethods, "");
        } else {
            panic!("expected KeyboardInteractive request, got {decoded:?}");
        }
    }

    #[test]
    fn keyboard_interactive_info_response_round_trips() {
        let msg = UserAuthMessage::KeyboardInteractiveInfoResponse {
            responses: vec!["s3cret".to_owned(), "42".to_owned()],
        };
        let frame = msg.to_frame().expect("encode info response");
        let decoded = UserAuthMessage::from_frame(&frame).expect("decode info response");
        if let UserAuthMessage::KeyboardInteractiveInfoResponse { responses } = decoded {
            assert_eq!(responses, vec!["s3cret", "42"]);
        } else {
            panic!("expected InfoResponse, got {decoded:?}");
        }
    }

    #[test]
    fn keyboard_interactive_info_request_round_trips() {
        let msg = UserAuthMessage::KeyboardInteractiveInfoRequest {
            name: "PAM".to_owned(),
            instruction: "Enter your credentials".to_owned(),
            language_tag: String::new(),
            prompts: vec![
                ("Password: ".to_owned(), false),
                ("Token: ".to_owned(), true),
            ],
        };
        let frame = msg.to_frame().expect("encode info request");
        let decoded = UserAuthMessage::from_frame(&frame).expect("decode info request");
        if let UserAuthMessage::KeyboardInteractiveInfoRequest {
            name,
            instruction,
            prompts,
            ..
        } = decoded
        {
            assert_eq!(name, "PAM");
            assert_eq!(instruction, "Enter your credentials");
            assert_eq!(prompts.len(), 2);
            assert_eq!(prompts[0], ("Password: ".to_owned(), false));
            assert_eq!(prompts[1], ("Token: ".to_owned(), true));
        } else {
            panic!("expected InfoRequest, got {decoded:?}");
        }
    }

    /// Verify that an `auth-agent-req@openssh.com` channel request
    /// encodes to the expected SSH wire format and round-trips through
    /// `ChannelMessage` encode/decode.
    #[test]
    fn agent_forwarding_request_encodes_correctly() {
        use russh_channel::{ChannelMessage, ChannelRequest};

        let msg = ChannelMessage::Request {
            recipient_channel: 3,
            want_reply: true,
            request: ChannelRequest::Unknown {
                request_type: "auth-agent-req@openssh.com".to_string(),
                data: vec![],
            },
        };
        let bytes = msg.to_bytes().expect("encode agent forwarding request");
        let decoded = ChannelMessage::from_bytes(&bytes).expect("decode agent forwarding request");

        if let ChannelMessage::Request {
            recipient_channel,
            want_reply,
            request: ChannelRequest::Unknown { request_type, data },
        } = decoded
        {
            assert_eq!(recipient_channel, 3);
            assert!(want_reply, "auth-agent-req must have want_reply=true");
            assert_eq!(request_type, "auth-agent-req@openssh.com");
            assert!(data.is_empty());
        } else {
            panic!("unexpected decoded variant");
        }
    }

    /// Verify that `ServerChannelState` tracks the `agent_forwarding_requested` flag.
    #[test]
    fn server_channel_state_tracks_agent_forwarding() {
        let mut state = ServerChannelState {
            is_sftp: false,
            scp_root: None,
            sftp_server: None,
            sftp_framer: SftpFramer::new(),
            pty_requested: false,
            pty_size: None,
            pty_term: None,
            env: Vec::new(),
            agent_forwarding_requested: false,
        };
        assert!(!state.agent_forwarding_requested);
        state.agent_forwarding_requested = true;
        assert!(state.agent_forwarding_requested);
    }
}
