//! Core protocol primitives for RuSSH.

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
}

impl AlgorithmSet {
    #[must_use]
    pub fn secure_defaults() -> Self {
        Self {
            kex: vec![
                "curve25519-sha256".to_string(),
                "ecdh-sha2-nistp256".to_string(),
                "sntrup761x25519-sha512@openssh.com".to_string(),
            ],
            host_key: vec![
                "ssh-ed25519".to_string(),
                "ecdsa-sha2-nistp256".to_string(),
                "rsa-sha2-256".to_string(),
                "rsa-sha2-512".to_string(),
            ],
            ciphers: vec![
                "chacha20-poly1305@openssh.com".to_string(),
                "aes128-gcm@openssh.com".to_string(),
                "aes256-gcm@openssh.com".to_string(),
            ],
            macs: vec!["hmac-sha2-256-etm@openssh.com".to_string()],
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

        // Placeholder deterministic padding; encrypted transport will replace this with RNG.
        for i in 0..padding_len {
            out.push((i as u8).wrapping_add(0xA5));
        }

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
}

/// Streaming packet parser for incremental socket reads.
#[derive(Clone, Debug)]
pub struct PacketParser {
    codec: PacketCodec,
    buffer: Vec<u8>,
}

impl PacketParser {
    #[must_use]
    pub fn new(codec: PacketCodec) -> Self {
        Self {
            codec,
            buffer: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(PacketCodec::with_defaults())
    }

    pub fn feed(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    /// Decode a single frame from buffered data when available.
    pub fn next_frame(&mut self) -> Result<Option<PacketFrame>, RusshError> {
        match self.codec.decode_prefix(&self.buffer)? {
            Some((frame, consumed)) => {
                self.buffer.drain(0..consumed);
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
}
