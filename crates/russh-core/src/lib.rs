//! Core protocol primitives for RuSSH.
//!
//! This crate defines the foundational types shared across all RuSSH crates:
//!
//! - **[`RusshError`]** — unified error type carrying a [`RusshErrorCategory`]
//!   discriminant and a human-readable message.
//! - **[`AlgorithmSet`]** — negotiated algorithm identifiers for key exchange,
//!   host keys, ciphers, and MACs.
//! - **[`PacketCodec`]** — SSH binary packet framing (RFC 4253 §6).
//!   Handles length, random padding, sequence numbers, and provides
//!   [`PacketCodec::encode_aead`] / [`PacketCodec::decode_aead`] closure-based
//!   hooks for AEAD-encrypted framing without creating a circular dependency
//!   on `russh-crypto`.
//! - **[`PacketParser`]** — stateful streaming parser that reassembles
//!   complete packets from a byte stream.
//!
//! # Packet framing
//!
//! ```text
//! uint32  packet_length
//! byte    padding_length
//! byte[n] payload
//! byte[p] random_padding  (p = padding_length)
//! byte[m] mac             (optional, appended by AEAD layer)
//! ```
//!
//! # Example
//!
//! ```rust
//! use russh_core::{PacketCodec, PacketFrame};
//!
//! let codec = PacketCodec::with_defaults();
//! let frame = PacketFrame::new(vec![1, 2, 3]);
//! let encoded = codec.encode(&frame).unwrap();
//! let decoded = codec.decode(&encoded).unwrap();
//! assert_eq!(decoded.payload, vec![1, 2, 3]);
//! ```

use std::error::Error;
use std::fmt::{Display, Formatter};

/// Stable error categories used across all RuSSH crates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RusshErrorCategory {
    Config,
    Crypto,
    Protocol,
    Auth,
    Channel,
    Io,
    Interop,
}

/// Shared RuSSH error type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RusshError {
    category: RusshErrorCategory,
    message: String,
}

impl RusshError {
    #[must_use]
    pub fn new(category: RusshErrorCategory, message: impl Into<String>) -> Self {
        Self {
            category,
            message: message.into(),
        }
    }

    #[must_use]
    pub fn category(&self) -> RusshErrorCategory {
        self.category
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl Display for RusshError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.category, self.message)
    }
}

impl Error for RusshError {}

/// Common list container for algorithm negotiation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AlgorithmSet {
    pub kex: Vec<String>,
    pub host_key: Vec<String>,
    pub ciphers: Vec<String>,
    pub macs: Vec<String>,
    pub compression: Vec<String>,
}

impl AlgorithmSet {
    #[must_use]
    pub fn secure_defaults() -> Self {
        Self {
            kex: vec![
                "curve25519-sha256".to_string(),
                "ecdh-sha2-nistp256".to_string(),
                "diffie-hellman-group14-sha256".to_string(),
            ],
            host_key: vec![
                "ssh-ed25519".to_string(),
                "ecdsa-sha2-nistp256".to_string(),
                "rsa-sha2-256".to_string(),
                "rsa-sha2-512".to_string(),
            ],
            ciphers: vec![
                "aes256-gcm@openssh.com".to_string(),
                "aes256-ctr".to_string(),
                "aes128-ctr".to_string(),
            ],
            macs: vec![
                "hmac-sha2-256-etm@openssh.com".to_string(),
                "hmac-sha2-512-etm@openssh.com".to_string(),
            ],
            compression: vec!["none".to_string(), "zlib@openssh.com".to_string()],
        }
    }
}

/// SSH packet frame representation (payload only).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PacketFrame {
    pub payload: Vec<u8>,
}

impl PacketFrame {
    #[must_use]
    pub fn new(payload: Vec<u8>) -> Self {
        Self { payload }
    }

    /// Return the SSH message type byte if the payload is non-empty.
    #[must_use]
    pub fn message_type(&self) -> Option<u8> {
        self.payload.first().copied()
    }
}

/// Packet codec implementing SSH binary packet structure.
///
/// Packet format:
/// - `packet_length` (`u32` big endian)
/// - `padding_length` (`u8`)
/// - `payload` (`packet_length - padding_length - 1` bytes)
/// - `random_padding` (`padding_length` bytes)
#[derive(Clone, Copy, Debug)]
pub struct PacketCodec {
    max_packet_size: usize,
    block_size: usize,
}

impl PacketCodec {
    pub const DEFAULT_MAX_PACKET_SIZE: usize = 256 * 1024;
    pub const DEFAULT_BLOCK_SIZE: usize = 8;
    pub const MIN_PADDING_LENGTH: usize = 4;

    #[must_use]
    pub fn new(max_packet_size: usize) -> Self {
        Self {
            max_packet_size,
            block_size: Self::DEFAULT_BLOCK_SIZE,
        }
    }

    #[must_use]
    pub fn with_block_size(max_packet_size: usize, block_size: usize) -> Self {
        Self {
            max_packet_size,
            block_size: block_size.max(Self::DEFAULT_BLOCK_SIZE),
        }
    }

    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(Self::DEFAULT_MAX_PACKET_SIZE)
    }

    #[must_use]
    pub fn max_packet_size(&self) -> usize {
        self.max_packet_size
    }

    #[must_use]
    pub fn block_size(&self) -> usize {
        self.block_size
    }

    pub fn encode(&self, frame: &PacketFrame) -> Result<Vec<u8>, RusshError> {
        let payload_len = frame.payload.len();
        if payload_len > self.max_packet_size {
            return Err(RusshError::new(
                RusshErrorCategory::Protocol,
                "payload exceeds max packet size",
            ));
        }

        let padding_len = self.padding_length_for_payload(payload_len)?;
        let packet_len = 1 + payload_len + padding_len;
        let packet_len_u32 = u32::try_from(packet_len).map_err(|_| {
            RusshError::new(
                RusshErrorCategory::Protocol,
                "packet length does not fit in u32",
            )
        })?;

        let mut out = Vec::with_capacity(packet_len + 4);
        out.extend_from_slice(&packet_len_u32.to_be_bytes());
        out.push(u8::try_from(padding_len).map_err(|_| {
            RusshError::new(
                RusshErrorCategory::Protocol,
                "padding length does not fit in u8",
            )
        })?);
        out.extend_from_slice(&frame.payload);

        let pad_start = out.len();
        out.resize(out.len() + padding_len, 0u8);
        getrandom::getrandom(&mut out[pad_start..]).map_err(|_| {
            RusshError::new(
                RusshErrorCategory::Crypto,
                "OS RNG failed for packet padding",
            )
        })?;

        Ok(out)
    }

    pub fn decode(&self, bytes: &[u8]) -> Result<PacketFrame, RusshError> {
        let (frame, consumed) = self.decode_prefix(bytes)?.ok_or_else(|| {
            RusshError::new(
                RusshErrorCategory::Protocol,
                "frame too short for full packet",
            )
        })?;

        if consumed != bytes.len() {
            return Err(RusshError::new(
                RusshErrorCategory::Protocol,
                "frame length mismatch",
            ));
        }

        Ok(frame)
    }

    /// Decode exactly one frame from the start of `bytes`.
    /// Returns `Ok(None)` when more data is required.
    pub fn decode_prefix(&self, bytes: &[u8]) -> Result<Option<(PacketFrame, usize)>, RusshError> {
        if bytes.len() < 5 {
            return Ok(None);
        }

        let len_bytes: [u8; 4] = bytes[0..4].try_into().map_err(|_| {
            RusshError::new(
                RusshErrorCategory::Protocol,
                "failed to parse packet length",
            )
        })?;
        let packet_len = usize::try_from(u32::from_be_bytes(len_bytes)).map_err(|_| {
            RusshError::new(
                RusshErrorCategory::Protocol,
                "packet length does not fit usize",
            )
        })?;

        let total_len = packet_len.checked_add(4).ok_or_else(|| {
            RusshError::new(RusshErrorCategory::Protocol, "packet length overflow")
        })?;
        if bytes.len() < total_len {
            return Ok(None);
        }

        if total_len % self.block_size != 0 {
            return Err(RusshError::new(
                RusshErrorCategory::Protocol,
                "packet is not aligned to transport block size",
            ));
        }

        let min_packet_len = 1 + Self::MIN_PADDING_LENGTH;
        if packet_len < min_packet_len {
            return Err(RusshError::new(
                RusshErrorCategory::Protocol,
                "packet length is below SSH minimum",
            ));
        }

        let padding_len = usize::from(bytes[4]);
        if padding_len < Self::MIN_PADDING_LENGTH {
            return Err(RusshError::new(
                RusshErrorCategory::Protocol,
                "padding length below SSH minimum",
            ));
        }

        if padding_len + 1 > packet_len {
            return Err(RusshError::new(
                RusshErrorCategory::Protocol,
                "padding length exceeds packet length",
            ));
        }

        let payload_len = packet_len - padding_len - 1;
        if payload_len > self.max_packet_size {
            return Err(RusshError::new(
                RusshErrorCategory::Protocol,
                "decoded payload exceeds max packet size",
            ));
        }

        let payload_start = 5;
        let payload_end = payload_start + payload_len;
        let payload = bytes[payload_start..payload_end].to_vec();

        Ok(Some((PacketFrame::new(payload), total_len)))
    }

    fn padding_length_for_payload(&self, payload_len: usize) -> Result<usize, RusshError> {
        let base_len = 1usize
            .checked_add(payload_len)
            .ok_or_else(|| RusshError::new(RusshErrorCategory::Protocol, "packet size overflow"))?;
        let with_header = base_len
            .checked_add(4)
            .ok_or_else(|| RusshError::new(RusshErrorCategory::Protocol, "packet size overflow"))?;

        let remainder = with_header % self.block_size;
        let mut padding = if remainder == 0 {
            0
        } else {
            self.block_size - remainder
        };
        if padding < Self::MIN_PADDING_LENGTH {
            padding = padding.checked_add(self.block_size).ok_or_else(|| {
                RusshError::new(RusshErrorCategory::Protocol, "padding computation overflow")
            })?;
        }
        if padding > usize::from(u8::MAX) {
            return Err(RusshError::new(
                RusshErrorCategory::Protocol,
                "padding length exceeds u8 range",
            ));
        }

        Ok(padding)
    }

    /// Encode a frame with AEAD encryption.
    /// `encrypt_fn(nonce, aad, plaintext) -> ciphertext || auth_tag`
    pub fn encode_aead<F>(
        &self,
        frame: &PacketFrame,
        sequence_number: u32,
        fixed_iv: &[u8],
        encrypt_fn: F,
    ) -> Result<Vec<u8>, RusshError>
    where
        F: FnOnce(&[u8], &[u8], &[u8]) -> Result<Vec<u8>, RusshError>,
    {
        let payload_len = frame.payload.len();
        if payload_len > self.max_packet_size {
            return Err(RusshError::new(
                RusshErrorCategory::Protocol,
                "payload exceeds max packet size",
            ));
        }

        let padding_len = self.padding_length_for_payload(payload_len)?;
        let packet_len = 1 + payload_len + padding_len;
        let packet_len_u32 = u32::try_from(packet_len).map_err(|_| {
            RusshError::new(
                RusshErrorCategory::Protocol,
                "packet length does not fit in u32",
            )
        })?;

        // Build AAD: packet_length (4 bytes, big-endian)
        let aad = packet_len_u32.to_be_bytes();

        // Build plaintext: padding_len_byte || payload || random_padding
        let mut plaintext = Vec::with_capacity(1 + payload_len + padding_len);
        plaintext.push(u8::try_from(padding_len).map_err(|_| {
            RusshError::new(
                RusshErrorCategory::Protocol,
                "padding length does not fit in u8",
            )
        })?);
        plaintext.extend_from_slice(&frame.payload);
        let pad_start = plaintext.len();
        plaintext.resize(plaintext.len() + padding_len, 0u8);
        getrandom::getrandom(&mut plaintext[pad_start..]).map_err(|_| {
            RusshError::new(RusshErrorCategory::Crypto, "OS RNG failed for AEAD padding")
        })?;

        let nonce = compute_aead_nonce(fixed_iv, sequence_number);
        let ciphertext_with_tag = encrypt_fn(&nonce, &aad, &plaintext)?;

        let mut out = Vec::with_capacity(4 + ciphertext_with_tag.len());
        out.extend_from_slice(&aad);
        out.extend_from_slice(&ciphertext_with_tag);
        Ok(out)
    }

    /// Decode a frame with AEAD decryption.
    /// `decrypt_fn(nonce, aad, ciphertext_with_tag) -> plaintext`
    pub fn decode_aead<F>(
        &self,
        bytes: &[u8],
        sequence_number: u32,
        fixed_iv: &[u8],
        tag_len: usize,
        decrypt_fn: F,
    ) -> Result<PacketFrame, RusshError>
    where
        F: FnOnce(&[u8], &[u8], &[u8]) -> Result<Vec<u8>, RusshError>,
    {
        if bytes.len() < 4 {
            return Err(RusshError::new(
                RusshErrorCategory::Protocol,
                "too short for packet length",
            ));
        }

        let len_bytes: [u8; 4] = bytes[0..4].try_into().map_err(|_| {
            RusshError::new(
                RusshErrorCategory::Protocol,
                "failed to parse packet length",
            )
        })?;
        let packet_len = usize::try_from(u32::from_be_bytes(len_bytes)).map_err(|_| {
            RusshError::new(
                RusshErrorCategory::Protocol,
                "packet length does not fit usize",
            )
        })?;

        let required = 4usize
            .checked_add(packet_len)
            .and_then(|n| n.checked_add(tag_len))
            .ok_or_else(|| {
                RusshError::new(RusshErrorCategory::Protocol, "packet length overflow")
            })?;
        if bytes.len() < required {
            return Err(RusshError::new(
                RusshErrorCategory::Protocol,
                "buffer too short for AEAD packet",
            ));
        }

        let aad = &bytes[0..4];
        let ciphertext_with_tag = &bytes[4..4 + packet_len + tag_len];

        let nonce = compute_aead_nonce(fixed_iv, sequence_number);
        let plaintext = decrypt_fn(&nonce, aad, ciphertext_with_tag)?;

        if plaintext.is_empty() {
            return Err(RusshError::new(
                RusshErrorCategory::Protocol,
                "decrypted plaintext is empty",
            ));
        }

        let padding_len = usize::from(plaintext[0]);
        if padding_len < Self::MIN_PADDING_LENGTH {
            return Err(RusshError::new(
                RusshErrorCategory::Protocol,
                "padding length below SSH minimum",
            ));
        }

        let inner_len = plaintext.len();
        if padding_len + 1 > inner_len {
            return Err(RusshError::new(
                RusshErrorCategory::Protocol,
                "padding length exceeds plaintext",
            ));
        }

        let payload_len = inner_len - 1 - padding_len;
        if payload_len > self.max_packet_size {
            return Err(RusshError::new(
                RusshErrorCategory::Protocol,
                "decoded payload exceeds max packet size",
            ));
        }

        let payload = plaintext[1..1 + payload_len].to_vec();
        Ok(PacketFrame::new(payload))
    }
}

fn compute_aead_nonce(fixed_iv: &[u8], sequence_number: u32) -> Vec<u8> {
    let mut nonce = fixed_iv.to_vec();
    let nonce_len = nonce.len();
    let seq_bytes = (sequence_number as u64).to_be_bytes();
    let offset = nonce_len.saturating_sub(8);
    for (i, b) in seq_bytes.iter().enumerate() {
        if offset + i < nonce_len {
            nonce[offset + i] ^= b;
        }
    }
    nonce
}

/// Streaming packet parser for incremental socket reads.
#[derive(Clone, Debug)]
pub struct PacketParser {
    codec: PacketCodec,
    buffer: Vec<u8>,
    sequence_number: u32,
}

impl PacketParser {
    #[must_use]
    pub fn new(codec: PacketCodec) -> Self {
        Self {
            codec,
            buffer: Vec::new(),
            sequence_number: 0,
        }
    }

    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(PacketCodec::with_defaults())
    }

    pub fn feed(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    #[must_use]
    pub fn sequence_number(&self) -> u32 {
        self.sequence_number
    }

    /// Decode a single frame from buffered data when available.
    pub fn next_frame(&mut self) -> Result<Option<PacketFrame>, RusshError> {
        match self.codec.decode_prefix(&self.buffer)? {
            Some((frame, consumed)) => {
                self.buffer.drain(0..consumed);
                self.sequence_number = self.sequence_number.wrapping_add(1);
                Ok(Some(frame))
            }
            None => Ok(None),
        }
    }

    #[must_use]
    pub fn buffered_len(&self) -> usize {
        self.buffer.len()
    }

    pub fn clear(&mut self) {
        self.buffer.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::{PacketCodec, PacketFrame, PacketParser, RusshErrorCategory};

    #[test]
    fn packet_round_trip() {
        let codec = PacketCodec::with_defaults();
        let original = PacketFrame::new(vec![21, 2, 3, 4]);

        let encoded = codec.encode(&original).expect("encode should succeed");
        let decoded = codec.decode(&encoded).expect("decode should succeed");

        assert_eq!(decoded, original);
    }

    #[test]
    fn encoded_packet_is_aligned() {
        let codec = PacketCodec::with_defaults();
        let encoded = codec
            .encode(&PacketFrame::new(vec![1, 2, 3]))
            .expect("encode should succeed");

        assert_eq!(encoded.len() % codec.block_size(), 0);
        assert!(usize::from(encoded[4]) >= PacketCodec::MIN_PADDING_LENGTH);
    }

    #[test]
    fn decode_rejects_invalid_padding_length() {
        let codec = PacketCodec::with_defaults();
        // packet_length=8, padding_length=2 (invalid; minimum is 4)
        let bytes = [0, 0, 0, 8, 2, 21, 1, 2, 3, 4, 5, 6];

        let error = codec
            .decode(&bytes)
            .expect_err("decode should fail on invalid padding length");

        assert_eq!(error.category(), RusshErrorCategory::Protocol);
    }

    #[test]
    fn decode_prefix_returns_none_for_partial_data() {
        let codec = PacketCodec::with_defaults();
        let encoded = codec
            .encode(&PacketFrame::new(vec![21, 1, 2]))
            .expect("encode should succeed");
        let partial = &encoded[..encoded.len() - 1];

        let result = codec
            .decode_prefix(partial)
            .expect("prefix decode should not fail");
        assert!(result.is_none());
    }

    #[test]
    fn parser_streams_multiple_packets() {
        let codec = PacketCodec::with_defaults();
        let mut parser = PacketParser::with_defaults();

        let first = codec
            .encode(&PacketFrame::new(vec![50, 1, 2]))
            .expect("encode should succeed");
        let second = codec
            .encode(&PacketFrame::new(vec![94, 9]))
            .expect("encode should succeed");

        let mut stream = Vec::new();
        stream.extend_from_slice(&first);
        stream.extend_from_slice(&second);

        parser.feed(&stream[..6]);
        assert!(parser.next_frame().expect("parse should succeed").is_none());

        parser.feed(&stream[6..]);
        let frame1 = parser
            .next_frame()
            .expect("parse should succeed")
            .expect("first frame should be ready");
        let frame2 = parser
            .next_frame()
            .expect("parse should succeed")
            .expect("second frame should be ready");

        assert_eq!(frame1.message_type(), Some(50));
        assert_eq!(frame2.message_type(), Some(94));
        assert!(parser.next_frame().expect("parse should succeed").is_none());
    }

    #[test]
    fn parser_rejects_oversized_payload() {
        let codec = PacketCodec::new(2);
        let frame = PacketFrame::new(vec![21, 1, 2]);
        let encoded = PacketCodec::with_defaults()
            .encode(&frame)
            .expect("encode should succeed in source codec");

        let mut parser = PacketParser::new(codec);
        parser.feed(&encoded);

        let error = parser
            .next_frame()
            .expect_err("oversized payload must fail");

        assert_eq!(error.category(), RusshErrorCategory::Protocol);
    }

    #[test]
    fn parser_sequence_number_increments() {
        let codec = PacketCodec::with_defaults();
        let mut parser = PacketParser::with_defaults();
        assert_eq!(parser.sequence_number(), 0);

        let pkt1 = codec.encode(&PacketFrame::new(vec![1])).unwrap();
        let pkt2 = codec.encode(&PacketFrame::new(vec![2])).unwrap();
        parser.feed(&pkt1);
        parser.feed(&pkt2);

        parser.next_frame().unwrap().unwrap();
        assert_eq!(parser.sequence_number(), 1);

        parser.next_frame().unwrap().unwrap();
        assert_eq!(parser.sequence_number(), 2);

        // no frame => sequence_number unchanged
        parser.next_frame().unwrap();
        assert_eq!(parser.sequence_number(), 2);
    }

    #[test]
    fn aead_encode_decode_round_trip() {
        // Use a simple XOR-based fake cipher to test the framing logic.
        let codec = PacketCodec::with_defaults();
        let fixed_iv = vec![0xAAu8; 12];
        let key = vec![0x5Cu8; 32];
        let tag = vec![0xBBu8; 16];

        let original = PacketFrame::new(vec![42, 1, 2, 3]);

        let key_enc = key.clone();
        let tag_clone = tag.clone();
        let encrypted = codec
            .encode_aead(&original, 0, &fixed_iv, |_nonce, _aad, plaintext| {
                // fake encrypt: XOR each byte with key byte
                let mut ct: Vec<u8> = plaintext
                    .iter()
                    .enumerate()
                    .map(|(i, b)| b ^ key_enc[i % key_enc.len()])
                    .collect();
                ct.extend_from_slice(&tag_clone);
                Ok(ct)
            })
            .expect("encode_aead should succeed");

        // wire format: 4-byte length || ciphertext || tag
        let tag_len = 16;
        let decoded = codec
            .decode_aead(
                &encrypted,
                0,
                &fixed_iv,
                tag_len,
                |_nonce, _aad, ct_with_tag| {
                    let ct = &ct_with_tag[..ct_with_tag.len() - tag_len];
                    let plaintext: Vec<u8> = ct
                        .iter()
                        .enumerate()
                        .map(|(i, b)| b ^ key[i % key.len()])
                        .collect();
                    Ok(plaintext)
                },
            )
            .expect("decode_aead should succeed");

        assert_eq!(decoded, original);
    }

    #[test]
    fn aead_nonce_differs_by_sequence_number() {
        use super::compute_aead_nonce;
        let iv = vec![0u8; 12];
        let n0 = compute_aead_nonce(&iv, 0);
        let n1 = compute_aead_nonce(&iv, 1);
        let n2 = compute_aead_nonce(&iv, 2);
        assert_ne!(n0, n1);
        assert_ne!(n1, n2);
    }
}
