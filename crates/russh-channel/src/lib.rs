//! SSH channel multiplexing and forwarding for RuSSH (RFC 4254).
//!
//! SSH channels carry interactive sessions, TCP port forwards, and other
//! data streams multiplexed over a single connection. This crate provides:
//!
//! ## Wire codec
//!
//! [`ChannelMessage`] encodes/decodes all 11 RFC 4254 channel messages
//! (types 90–100): OPEN, OPEN_CONFIRMATION, OPEN_FAILURE, WINDOW_ADJUST,
//! DATA, EXTENDED_DATA, EOF, CLOSE, REQUEST, SUCCESS, FAILURE.
//!
//! [`ChannelRequest`] represents typed channel requests: `pty-req`, `shell`,
//! `exec`, `env`, `signal`, `exit-status`, `exit-signal`, `subsystem`,
//! `window-change`.
//!
//! ## Flow control
//!
//! [`ChannelState`] tracks local and remote window sizes.
//! [`ChannelState::consume_remote_window`] enforces the remote window budget.
//! [`ChannelState::credit_local_window`] generates `WINDOW_ADJUST` messages
//! automatically when the local window falls below the refill threshold.
//!
//! ## Multiplexing
//!
//! [`ChannelManager`] manages a table of open channels (locally initiated),
//! routing incoming messages to the correct [`ChannelState`] by channel ID.
//!
//! ## Port forwarding
//!
//! [`ForwardHandle`] carries forwarding parameters; `build_direct_tcpip_open_extra`
//! constructs the extra data field for `direct-tcpip` OPEN messages.
//!
//! [`JumpChain`] models ProxyJump host chains.
//! [`MultiplexPool`] provides connection reuse across sessions.

pub mod socks;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, RwLock};

use russh_core::{RusshError, RusshErrorCategory};
use russh_transport::ClientSession;

static NEXT_CHANNEL_ID: AtomicU32 = AtomicU32::new(0);

/// Unique channel identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ChannelId(u32);

impl ChannelId {
    #[must_use]
    pub fn next() -> Self {
        Self(NEXT_CHANNEL_ID.fetch_add(1, Ordering::Relaxed))
    }

    #[must_use]
    pub fn value(self) -> u32 {
        self.0
    }
}

/// SSH channel kinds used by high-level APIs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChannelKind {
    Session,
    DirectTcpIp { host: String, port: u16 },
    ForwardedTcpIp { host: String, port: u16 },
    StreamLocal { path: String },
}

/// Basic channel handle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Channel {
    pub id: ChannelId,
    pub kind: ChannelKind,
    pub open: bool,
}

impl Channel {
    #[must_use]
    pub fn open(kind: ChannelKind) -> Self {
        Self {
            id: ChannelId::next(),
            kind,
            open: true,
        }
    }

    pub fn close(&mut self) {
        self.open = false;
    }
}

/// TCP forwarding registration token.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForwardHandle {
    pub bind_host: String,
    pub bind_port: u16,
    pub active: bool,
}

impl ForwardHandle {
    #[must_use]
    pub fn new(bind_host: impl Into<String>, bind_port: u16) -> Self {
        Self {
            bind_host: bind_host.into(),
            bind_port,
            active: true,
        }
    }

    pub fn deactivate(&mut self) {
        self.active = false;
    }
}

/// Jump host chain model (ProxyJump style).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JumpChain {
    hops: Vec<String>,
}

impl JumpChain {
    pub fn new(hops: Vec<String>) -> Result<Self, RusshError> {
        if hops.is_empty() {
            return Err(RusshError::new(
                RusshErrorCategory::Config,
                "jump chain requires at least one hop",
            ));
        }

        Ok(Self { hops })
    }

    #[must_use]
    pub fn hops(&self) -> &[String] {
        &self.hops
    }
}

/// Lightweight multiplexing pool that reuses established client sessions by key.
#[derive(Debug, Default)]
pub struct ConnectionPool {
    entries: Arc<RwLock<HashMap<String, Arc<ClientSession>>>>,
}

impl ConnectionPool {
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn insert(&self, key: impl Into<String>, session: ClientSession) -> Result<(), RusshError> {
        let mut guard = self.entries.write().map_err(|_| {
            RusshError::new(
                RusshErrorCategory::Channel,
                "connection pool lock poisoned during insert",
            )
        })?;
        guard.insert(key.into(), Arc::new(session));
        Ok(())
    }

    pub fn get(&self, key: &str) -> Result<Option<Arc<ClientSession>>, RusshError> {
        let guard = self.entries.read().map_err(|_| {
            RusshError::new(
                RusshErrorCategory::Channel,
                "connection pool lock poisoned during get",
            )
        })?;
        Ok(guard.get(key).cloned())
    }

    pub fn len(&self) -> Result<usize, RusshError> {
        let guard = self.entries.read().map_err(|_| {
            RusshError::new(
                RusshErrorCategory::Channel,
                "connection pool lock poisoned during len",
            )
        })?;
        Ok(guard.len())
    }

    pub fn is_empty(&self) -> Result<bool, RusshError> {
        self.len().map(|count| count == 0)
    }
}

/// Typed channel-level events.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChannelEvent {
    Opened { id: ChannelId, kind: ChannelKind },
    Closed { id: ChannelId },
    ForwardingEnabled { bind_host: String, bind_port: u16 },
    ForwardingDisabled { bind_host: String, bind_port: u16 },
}

// ─────────────────────────────────────────────────────────────
// Wire-format helpers (internal)
// ─────────────────────────────────────────────────────────────

fn write_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn write_bool(out: &mut Vec<u8>, v: bool) {
    out.push(u8::from(v));
}

fn write_string(out: &mut Vec<u8>, s: &[u8]) {
    write_u32(out, s.len() as u32);
    out.extend_from_slice(s);
}

fn read_u32(data: &[u8], offset: &mut usize) -> Result<u32, RusshError> {
    if data.len() < offset.saturating_add(4) {
        return Err(RusshError::new(
            RusshErrorCategory::Protocol,
            "unexpected end of data reading u32",
        ));
    }
    let bytes: [u8; 4] = data[*offset..*offset + 4]
        .try_into()
        .map_err(|_| RusshError::new(RusshErrorCategory::Protocol, "slice-to-array failed"))?;
    *offset += 4;
    Ok(u32::from_be_bytes(bytes))
}

fn read_bool(data: &[u8], offset: &mut usize) -> Result<bool, RusshError> {
    if *offset >= data.len() {
        return Err(RusshError::new(
            RusshErrorCategory::Protocol,
            "unexpected end of data reading bool",
        ));
    }
    let val = data[*offset] != 0;
    *offset += 1;
    Ok(val)
}

fn read_bytes(data: &[u8], offset: &mut usize) -> Result<Vec<u8>, RusshError> {
    let len = read_u32(data, offset)? as usize;
    if data.len() < offset.saturating_add(len) {
        return Err(RusshError::new(
            RusshErrorCategory::Protocol,
            "unexpected end of data reading string bytes",
        ));
    }
    let s = data[*offset..*offset + len].to_vec();
    *offset += len;
    Ok(s)
}

fn read_utf8(data: &[u8], offset: &mut usize) -> Result<String, RusshError> {
    let bytes = read_bytes(data, offset)?;
    String::from_utf8(bytes).map_err(|_| {
        RusshError::new(
            RusshErrorCategory::Protocol,
            "invalid UTF-8 in string field",
        )
    })
}

// ─────────────────────────────────────────────────────────────
// ChannelOpenFailureReason
// ─────────────────────────────────────────────────────────────

/// RFC 4254 §5.1 channel open failure reason codes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChannelOpenFailureReason {
    AdministrativelyProhibited,
    ConnectFailed,
    UnknownChannelType,
    ResourceShortage,
}

impl ChannelOpenFailureReason {
    fn to_code(&self) -> u32 {
        match self {
            Self::AdministrativelyProhibited => 1,
            Self::ConnectFailed => 2,
            Self::UnknownChannelType => 3,
            Self::ResourceShortage => 4,
        }
    }

    fn from_code(code: u32) -> Result<Self, RusshError> {
        match code {
            1 => Ok(Self::AdministrativelyProhibited),
            2 => Ok(Self::ConnectFailed),
            3 => Ok(Self::UnknownChannelType),
            4 => Ok(Self::ResourceShortage),
            _ => Err(RusshError::new(
                RusshErrorCategory::Protocol,
                format!("unknown channel open failure reason code: {code}"),
            )),
        }
    }
}

// ─────────────────────────────────────────────────────────────
// ChannelRequest
// ─────────────────────────────────────────────────────────────

/// RFC 4254 §6 session channel request types.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChannelRequest {
    PtyReq {
        term: String,
        width_chars: u32,
        height_rows: u32,
        width_pixels: u32,
        height_pixels: u32,
        term_modes: Vec<u8>,
    },
    Shell,
    Exec {
        command: String,
    },
    Env {
        name: String,
        value: String,
    },
    Signal {
        signal_name: String,
    },
    ExitStatus {
        exit_status: u32,
    },
    ExitSignal {
        signal_name: String,
        core_dumped: bool,
        error_message: String,
    },
    SubSystem {
        name: String,
    },
    WindowChange {
        width_chars: u32,
        height_rows: u32,
        width_pixels: u32,
        height_pixels: u32,
    },
    Unknown {
        request_type: String,
        data: Vec<u8>,
    },
}

impl ChannelRequest {
    fn request_type_str(&self) -> &str {
        match self {
            Self::PtyReq { .. } => "pty-req",
            Self::Shell => "shell",
            Self::Exec { .. } => "exec",
            Self::Env { .. } => "env",
            Self::Signal { .. } => "signal",
            Self::ExitStatus { .. } => "exit-status",
            Self::ExitSignal { .. } => "exit-signal",
            Self::SubSystem { .. } => "subsystem",
            Self::WindowChange { .. } => "window-change",
            Self::Unknown { request_type, .. } => request_type,
        }
    }

    fn encode_body(&self, out: &mut Vec<u8>) {
        match self {
            Self::PtyReq {
                term,
                width_chars,
                height_rows,
                width_pixels,
                height_pixels,
                term_modes,
            } => {
                write_string(out, term.as_bytes());
                write_u32(out, *width_chars);
                write_u32(out, *height_rows);
                write_u32(out, *width_pixels);
                write_u32(out, *height_pixels);
                write_string(out, term_modes);
            }
            Self::Shell => {}
            Self::Exec { command } => write_string(out, command.as_bytes()),
            Self::Env { name, value } => {
                write_string(out, name.as_bytes());
                write_string(out, value.as_bytes());
            }
            Self::Signal { signal_name } => write_string(out, signal_name.as_bytes()),
            Self::ExitStatus { exit_status } => write_u32(out, *exit_status),
            Self::ExitSignal {
                signal_name,
                core_dumped,
                error_message,
            } => {
                write_string(out, signal_name.as_bytes());
                write_bool(out, *core_dumped);
                write_string(out, error_message.as_bytes());
                write_string(out, b""); // language tag (empty)
            }
            Self::SubSystem { name } => write_string(out, name.as_bytes()),
            Self::WindowChange {
                width_chars,
                height_rows,
                width_pixels,
                height_pixels,
            } => {
                write_u32(out, *width_chars);
                write_u32(out, *height_rows);
                write_u32(out, *width_pixels);
                write_u32(out, *height_pixels);
            }
            Self::Unknown { data, .. } => out.extend_from_slice(data),
        }
    }

    fn decode(request_type: &str, data: &[u8], offset: &mut usize) -> Result<Self, RusshError> {
        match request_type {
            "pty-req" => Ok(Self::PtyReq {
                term: read_utf8(data, offset)?,
                width_chars: read_u32(data, offset)?,
                height_rows: read_u32(data, offset)?,
                width_pixels: read_u32(data, offset)?,
                height_pixels: read_u32(data, offset)?,
                term_modes: read_bytes(data, offset)?,
            }),
            "shell" => Ok(Self::Shell),
            "exec" => Ok(Self::Exec {
                command: read_utf8(data, offset)?,
            }),
            "env" => Ok(Self::Env {
                name: read_utf8(data, offset)?,
                value: read_utf8(data, offset)?,
            }),
            "signal" => Ok(Self::Signal {
                signal_name: read_utf8(data, offset)?,
            }),
            "exit-status" => Ok(Self::ExitStatus {
                exit_status: read_u32(data, offset)?,
            }),
            "exit-signal" => {
                let req = Self::ExitSignal {
                    signal_name: read_utf8(data, offset)?,
                    core_dumped: read_bool(data, offset)?,
                    error_message: read_utf8(data, offset)?,
                };
                let _ = read_bytes(data, offset)?; // language tag, discard
                Ok(req)
            }
            "subsystem" => Ok(Self::SubSystem {
                name: read_utf8(data, offset)?,
            }),
            "window-change" => Ok(Self::WindowChange {
                width_chars: read_u32(data, offset)?,
                height_rows: read_u32(data, offset)?,
                width_pixels: read_u32(data, offset)?,
                height_pixels: read_u32(data, offset)?,
            }),
            _ => {
                let remaining = data[*offset..].to_vec();
                *offset = data.len();
                Ok(Self::Unknown {
                    request_type: request_type.to_string(),
                    data: remaining,
                })
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────
// ChannelMessage
// ─────────────────────────────────────────────────────────────

/// RFC 4254 SSH channel protocol messages (§5–§7).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChannelMessage {
    Open {
        channel_type: String,
        sender_channel: u32,
        initial_window_size: u32,
        maximum_packet_size: u32,
        /// Channel-type-specific extra bytes (e.g. `direct-tcpip` addresses).
        extra_data: Vec<u8>,
    },
    OpenConfirmation {
        recipient_channel: u32,
        sender_channel: u32,
        initial_window_size: u32,
        maximum_packet_size: u32,
    },
    OpenFailure {
        recipient_channel: u32,
        reason: ChannelOpenFailureReason,
        description: String,
    },
    WindowAdjust {
        recipient_channel: u32,
        bytes_to_add: u32,
    },
    Data {
        recipient_channel: u32,
        data: Vec<u8>,
    },
    ExtendedData {
        recipient_channel: u32,
        data_type_code: u32,
        data: Vec<u8>,
    },
    Eof {
        recipient_channel: u32,
    },
    Close {
        recipient_channel: u32,
    },
    Request {
        recipient_channel: u32,
        want_reply: bool,
        request: ChannelRequest,
    },
    Success {
        recipient_channel: u32,
    },
    Failure {
        recipient_channel: u32,
    },
}

impl ChannelMessage {
    /// Encode to SSH wire-format bytes (payload only, no packet framing).
    pub fn to_bytes(&self) -> Result<Vec<u8>, RusshError> {
        let mut out = Vec::new();
        match self {
            Self::Open {
                channel_type,
                sender_channel,
                initial_window_size,
                maximum_packet_size,
                extra_data,
            } => {
                out.push(90u8);
                write_string(&mut out, channel_type.as_bytes());
                write_u32(&mut out, *sender_channel);
                write_u32(&mut out, *initial_window_size);
                write_u32(&mut out, *maximum_packet_size);
                out.extend_from_slice(extra_data);
            }
            Self::OpenConfirmation {
                recipient_channel,
                sender_channel,
                initial_window_size,
                maximum_packet_size,
            } => {
                out.push(91u8);
                write_u32(&mut out, *recipient_channel);
                write_u32(&mut out, *sender_channel);
                write_u32(&mut out, *initial_window_size);
                write_u32(&mut out, *maximum_packet_size);
            }
            Self::OpenFailure {
                recipient_channel,
                reason,
                description,
            } => {
                out.push(92u8);
                write_u32(&mut out, *recipient_channel);
                write_u32(&mut out, reason.to_code());
                write_string(&mut out, description.as_bytes());
                write_string(&mut out, b""); // language tag
            }
            Self::WindowAdjust {
                recipient_channel,
                bytes_to_add,
            } => {
                out.push(93u8);
                write_u32(&mut out, *recipient_channel);
                write_u32(&mut out, *bytes_to_add);
            }
            Self::Data {
                recipient_channel,
                data,
            } => {
                out.push(94u8);
                write_u32(&mut out, *recipient_channel);
                write_string(&mut out, data);
            }
            Self::ExtendedData {
                recipient_channel,
                data_type_code,
                data,
            } => {
                out.push(95u8);
                write_u32(&mut out, *recipient_channel);
                write_u32(&mut out, *data_type_code);
                write_string(&mut out, data);
            }
            Self::Eof { recipient_channel } => {
                out.push(96u8);
                write_u32(&mut out, *recipient_channel);
            }
            Self::Close { recipient_channel } => {
                out.push(97u8);
                write_u32(&mut out, *recipient_channel);
            }
            Self::Request {
                recipient_channel,
                want_reply,
                request,
            } => {
                out.push(98u8);
                write_u32(&mut out, *recipient_channel);
                write_string(&mut out, request.request_type_str().as_bytes());
                write_bool(&mut out, *want_reply);
                request.encode_body(&mut out);
            }
            Self::Success { recipient_channel } => {
                out.push(99u8);
                write_u32(&mut out, *recipient_channel);
            }
            Self::Failure { recipient_channel } => {
                out.push(100u8);
                write_u32(&mut out, *recipient_channel);
            }
        }
        Ok(out)
    }

    /// Decode from SSH wire-format payload bytes.
    pub fn from_bytes(payload: &[u8]) -> Result<Self, RusshError> {
        if payload.is_empty() {
            return Err(RusshError::new(
                RusshErrorCategory::Protocol,
                "empty channel message payload",
            ));
        }
        let msg_type = payload[0];
        let mut off = 1usize;

        match msg_type {
            90 => {
                let channel_type = read_utf8(payload, &mut off)?;
                let sender_channel = read_u32(payload, &mut off)?;
                let initial_window_size = read_u32(payload, &mut off)?;
                let maximum_packet_size = read_u32(payload, &mut off)?;
                let extra_data = payload[off..].to_vec();
                Ok(Self::Open {
                    channel_type,
                    sender_channel,
                    initial_window_size,
                    maximum_packet_size,
                    extra_data,
                })
            }
            91 => Ok(Self::OpenConfirmation {
                recipient_channel: read_u32(payload, &mut off)?,
                sender_channel: read_u32(payload, &mut off)?,
                initial_window_size: read_u32(payload, &mut off)?,
                maximum_packet_size: read_u32(payload, &mut off)?,
            }),
            92 => {
                let recipient_channel = read_u32(payload, &mut off)?;
                let reason = ChannelOpenFailureReason::from_code(read_u32(payload, &mut off)?)?;
                let description = read_utf8(payload, &mut off)?;
                let _ = read_bytes(payload, &mut off)?; // language tag, discard
                Ok(Self::OpenFailure {
                    recipient_channel,
                    reason,
                    description,
                })
            }
            93 => Ok(Self::WindowAdjust {
                recipient_channel: read_u32(payload, &mut off)?,
                bytes_to_add: read_u32(payload, &mut off)?,
            }),
            94 => Ok(Self::Data {
                recipient_channel: read_u32(payload, &mut off)?,
                data: read_bytes(payload, &mut off)?,
            }),
            95 => Ok(Self::ExtendedData {
                recipient_channel: read_u32(payload, &mut off)?,
                data_type_code: read_u32(payload, &mut off)?,
                data: read_bytes(payload, &mut off)?,
            }),
            96 => Ok(Self::Eof {
                recipient_channel: read_u32(payload, &mut off)?,
            }),
            97 => Ok(Self::Close {
                recipient_channel: read_u32(payload, &mut off)?,
            }),
            98 => {
                let recipient_channel = read_u32(payload, &mut off)?;
                let request_type = read_utf8(payload, &mut off)?;
                let want_reply = read_bool(payload, &mut off)?;
                let request = ChannelRequest::decode(&request_type, payload, &mut off)?;
                Ok(Self::Request {
                    recipient_channel,
                    want_reply,
                    request,
                })
            }
            99 => Ok(Self::Success {
                recipient_channel: read_u32(payload, &mut off)?,
            }),
            100 => Ok(Self::Failure {
                recipient_channel: read_u32(payload, &mut off)?,
            }),
            _ => Err(RusshError::new(
                RusshErrorCategory::Protocol,
                format!("unknown channel message type: {msg_type}"),
            )),
        }
    }

    /// Wrap payload bytes in a `PacketFrame`.
    pub fn to_frame(&self) -> Result<russh_core::PacketFrame, RusshError> {
        Ok(russh_core::PacketFrame::new(self.to_bytes()?))
    }
}

// ─────────────────────────────────────────────────────────────
// ChannelState
// ─────────────────────────────────────────────────────────────

/// RFC 4254 per-channel state with flow-control tracking.
#[derive(Clone, Debug)]
pub struct ChannelState {
    pub id: ChannelId,
    /// Peer's channel number (filled after CHANNEL_OPEN_CONFIRMATION).
    pub remote_id: u32,
    pub kind: ChannelKind,
    /// Bytes we can still receive before we must send WINDOW_ADJUST.
    pub local_window_size: u32,
    /// Bytes we can still send before the peer blocks us.
    pub remote_window_size: u32,
    pub max_packet_size: u32,
    pub eof_sent: bool,
    pub eof_received: bool,
    pub close_sent: bool,
    pub close_received: bool,
}

impl ChannelState {
    pub const DEFAULT_WINDOW_SIZE: u32 = 2 * 1024 * 1024; // 2 MiB
    pub const DEFAULT_MAX_PACKET: u32 = 32_768; // 32 KiB

    #[must_use]
    pub fn new(id: ChannelId, remote_id: u32, kind: ChannelKind) -> Self {
        Self {
            id,
            remote_id,
            kind,
            local_window_size: Self::DEFAULT_WINDOW_SIZE,
            remote_window_size: Self::DEFAULT_WINDOW_SIZE,
            max_packet_size: Self::DEFAULT_MAX_PACKET,
            eof_sent: false,
            eof_received: false,
            close_sent: false,
            close_received: false,
        }
    }

    /// Consume `bytes` from the outbound (remote) window before sending data.
    /// Returns `Err` when the window is exhausted.
    pub fn consume_remote_window(&mut self, bytes: u32) -> Result<(), RusshError> {
        self.remote_window_size = self.remote_window_size.checked_sub(bytes).ok_or_else(|| {
            RusshError::new(RusshErrorCategory::Channel, "remote window size exhausted")
        })?;
        Ok(())
    }

    /// Credit the outbound window upon receiving a WINDOW_ADJUST from the peer.
    pub fn credit_local_window(&mut self, bytes: u32) {
        self.remote_window_size = self.remote_window_size.saturating_add(bytes);
    }

    /// Build a WINDOW_ADJUST message that adds `bytes_to_add` to our receive window.
    #[must_use]
    pub fn build_window_adjust(&mut self, bytes_to_add: u32) -> ChannelMessage {
        self.local_window_size = self.local_window_size.saturating_add(bytes_to_add);
        ChannelMessage::WindowAdjust {
            recipient_channel: self.remote_id,
            bytes_to_add,
        }
    }

    /// Returns `true` when both sides have completed the EOF + CLOSE handshake.
    #[must_use]
    pub fn is_fully_closed(&self) -> bool {
        self.eof_sent && self.eof_received && self.close_sent && self.close_received
    }
}

// ─────────────────────────────────────────────────────────────
// ChannelManager
// ─────────────────────────────────────────────────────────────

fn channel_kind_type_string(kind: &ChannelKind) -> &'static str {
    match kind {
        ChannelKind::Session => "session",
        ChannelKind::DirectTcpIp { .. } => "direct-tcpip",
        ChannelKind::ForwardedTcpIp { .. } => "forwarded-tcpip",
        ChannelKind::StreamLocal { .. } => "direct-streamlocal@openssh.com",
    }
}

/// Manages multiple open channels for a single SSH connection.
#[derive(Debug, Default)]
pub struct ChannelManager {
    channels: HashMap<u32, ChannelState>,
    next_local_id: u32,
}

impl ChannelManager {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Allocate a new outbound channel. Returns the local ID and the CHANNEL_OPEN to send.
    pub fn open_channel(&mut self, kind: ChannelKind) -> (u32, ChannelMessage) {
        let local_id = self.next_local_id;
        self.next_local_id = self.next_local_id.wrapping_add(1);

        // ChannelId's inner field is private but accessible within the same module.
        let channel_id = ChannelId(local_id);
        let kind_type = channel_kind_type_string(&kind);
        let state = ChannelState::new(channel_id, 0, kind);
        let msg = ChannelMessage::Open {
            channel_type: kind_type.to_string(),
            sender_channel: local_id,
            initial_window_size: ChannelState::DEFAULT_WINDOW_SIZE,
            maximum_packet_size: ChannelState::DEFAULT_MAX_PACKET,
            extra_data: vec![],
        };
        self.channels.insert(local_id, state);
        (local_id, msg)
    }

    /// Record the remote channel ID and window parameters from CHANNEL_OPEN_CONFIRMATION.
    pub fn accept_confirmation(
        &mut self,
        local_id: u32,
        msg: &ChannelMessage,
    ) -> Result<(), RusshError> {
        let ChannelMessage::OpenConfirmation {
            sender_channel,
            initial_window_size,
            maximum_packet_size,
            ..
        } = msg
        else {
            return Err(RusshError::new(
                RusshErrorCategory::Channel,
                "expected CHANNEL_OPEN_CONFIRMATION",
            ));
        };
        let state = self
            .channels
            .get_mut(&local_id)
            .ok_or_else(|| RusshError::new(RusshErrorCategory::Channel, "channel not found"))?;
        state.remote_id = *sender_channel;
        state.remote_window_size = *initial_window_size;
        state.max_packet_size = *maximum_packet_size;
        Ok(())
    }

    /// Dispatch an incoming message and return any response messages to send.
    pub fn process(&mut self, msg: &ChannelMessage) -> Result<Vec<ChannelMessage>, RusshError> {
        let mut responses = Vec::new();
        match msg {
            // Incoming OPEN: this layer doesn't accept server-initiated channels.
            ChannelMessage::Open { sender_channel, .. } => {
                responses.push(ChannelMessage::OpenFailure {
                    recipient_channel: *sender_channel,
                    reason: ChannelOpenFailureReason::AdministrativelyProhibited,
                    description: "server-side channel accept not supported at this layer"
                        .to_string(),
                });
            }

            ChannelMessage::WindowAdjust {
                recipient_channel,
                bytes_to_add,
            } => {
                let state = self.channels.get_mut(recipient_channel).ok_or_else(|| {
                    RusshError::new(
                        RusshErrorCategory::Channel,
                        "channel not found for WINDOW_ADJUST",
                    )
                })?;
                state.remote_window_size = state.remote_window_size.saturating_add(*bytes_to_add);
            }

            ChannelMessage::Data {
                recipient_channel,
                data,
            } => {
                let data_len = u32::try_from(data.len()).map_err(|_| {
                    RusshError::new(RusshErrorCategory::Protocol, "data length exceeds u32")
                })?;
                let state = self.channels.get_mut(recipient_channel).ok_or_else(|| {
                    RusshError::new(RusshErrorCategory::Channel, "channel not found for DATA")
                })?;
                state.local_window_size = state.local_window_size.saturating_sub(data_len);
                if state.local_window_size < ChannelState::DEFAULT_WINDOW_SIZE / 2 {
                    let to_add =
                        ChannelState::DEFAULT_WINDOW_SIZE.saturating_sub(state.local_window_size);
                    let adjust = state.build_window_adjust(to_add);
                    responses.push(adjust);
                }
            }

            ChannelMessage::ExtendedData {
                recipient_channel,
                data,
                ..
            } => {
                let data_len = u32::try_from(data.len()).map_err(|_| {
                    RusshError::new(RusshErrorCategory::Protocol, "data length exceeds u32")
                })?;
                let state = self.channels.get_mut(recipient_channel).ok_or_else(|| {
                    RusshError::new(
                        RusshErrorCategory::Channel,
                        "channel not found for EXTENDED_DATA",
                    )
                })?;
                state.local_window_size = state.local_window_size.saturating_sub(data_len);
            }

            ChannelMessage::Eof { recipient_channel } => {
                let state = self.channels.get_mut(recipient_channel).ok_or_else(|| {
                    RusshError::new(RusshErrorCategory::Channel, "channel not found for EOF")
                })?;
                state.eof_received = true;
            }

            ChannelMessage::Close { recipient_channel } => {
                let state = self.channels.get_mut(recipient_channel).ok_or_else(|| {
                    RusshError::new(RusshErrorCategory::Channel, "channel not found for CLOSE")
                })?;
                state.close_received = true;
                if !state.close_sent {
                    state.close_sent = true;
                    responses.push(ChannelMessage::Close {
                        recipient_channel: state.remote_id,
                    });
                }
            }

            ChannelMessage::Request {
                recipient_channel,
                want_reply,
                request,
            } => {
                let state = self.channels.get_mut(recipient_channel).ok_or_else(|| {
                    RusshError::new(RusshErrorCategory::Channel, "channel not found for REQUEST")
                })?;
                if *want_reply {
                    let remote_id = state.remote_id;
                    let reply = match request {
                        ChannelRequest::Unknown { .. } => ChannelMessage::Failure {
                            recipient_channel: remote_id,
                        },
                        _ => ChannelMessage::Success {
                            recipient_channel: remote_id,
                        },
                    };
                    responses.push(reply);
                }
            }

            // Passthrough: handled at a higher layer or by accept_confirmation().
            ChannelMessage::Success { .. }
            | ChannelMessage::Failure { .. }
            | ChannelMessage::OpenConfirmation { .. }
            | ChannelMessage::OpenFailure { .. } => {}
        }
        Ok(responses)
    }

    /// Get an immutable reference to a channel by its local ID.
    #[must_use]
    pub fn channel(&self, local_id: u32) -> Option<&ChannelState> {
        self.channels.get(&local_id)
    }

    /// Get a mutable reference to a channel by its local ID.
    pub fn channel_mut(&mut self, local_id: u32) -> Option<&mut ChannelState> {
        self.channels.get_mut(&local_id)
    }

    /// All channels that have not completed a full close handshake.
    #[must_use]
    pub fn open_channels(&self) -> Vec<&ChannelState> {
        self.channels
            .values()
            .filter(|s| !s.is_fully_closed())
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────
// ForwardHandle – direct-tcpip helper
// ─────────────────────────────────────────────────────────────

impl ForwardHandle {
    /// Build the extra-data section for a `direct-tcpip` CHANNEL_OPEN (RFC 4254 §7.2).
    #[must_use]
    pub fn build_direct_tcpip_open_extra(
        host: &str,
        port: u32,
        originator_host: &str,
        originator_port: u32,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        write_string(&mut out, host.as_bytes());
        write_u32(&mut out, port);
        write_string(&mut out, originator_host.as_bytes());
        write_u32(&mut out, originator_port);
        out
    }

    /// Build the extra-data section for a `forwarded-tcpip` CHANNEL_OPEN (RFC 4254 §7.2).
    ///
    /// Wire: `string(connected_address) + uint32(connected_port)
    ///        + string(originator_address) + uint32(originator_port)`
    #[must_use]
    pub fn build_forwarded_tcpip_open_extra(
        connected_address: &str,
        connected_port: u32,
        originator_address: &str,
        originator_port: u32,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        write_string(&mut out, connected_address.as_bytes());
        write_u32(&mut out, connected_port);
        write_string(&mut out, originator_address.as_bytes());
        write_u32(&mut out, originator_port);
        out
    }

    /// Parse the extra-data from a `forwarded-tcpip` CHANNEL_OPEN.
    ///
    /// Returns `(connected_address, connected_port, originator_address, originator_port)`.
    pub fn parse_forwarded_tcpip_extra(
        data: &[u8],
    ) -> Result<(String, u32, String, u32), RusshError> {
        let mut off = 0;
        let connected_address = {
            let bytes = read_bytes(data, &mut off)?;
            String::from_utf8(bytes).map_err(|_| {
                RusshError::new(
                    RusshErrorCategory::Protocol,
                    "invalid UTF-8 in connected_address",
                )
            })?
        };
        let connected_port = read_u32(data, &mut off)?;
        let originator_address = {
            let bytes = read_bytes(data, &mut off)?;
            String::from_utf8(bytes).map_err(|_| {
                RusshError::new(
                    RusshErrorCategory::Protocol,
                    "invalid UTF-8 in originator_address",
                )
            })?
        };
        let originator_port = read_u32(data, &mut off)?;
        Ok((
            connected_address,
            connected_port,
            originator_address,
            originator_port,
        ))
    }

    /// Build the data payload for a `tcpip-forward` global request (RFC 4254 §7.1).
    ///
    /// Wire: `string(bind_address) + uint32(bind_port)`
    #[must_use]
    pub fn build_tcpip_forward_data(bind_address: &str, bind_port: u32) -> Vec<u8> {
        let mut out = Vec::new();
        write_string(&mut out, bind_address.as_bytes());
        write_u32(&mut out, bind_port);
        out
    }

    /// Parse the data payload from a `tcpip-forward` global request.
    ///
    /// Returns `(bind_address, bind_port)`.
    pub fn parse_tcpip_forward_data(data: &[u8]) -> Result<(String, u32), RusshError> {
        let mut off = 0;
        let bind_address = {
            let bytes = read_bytes(data, &mut off)?;
            String::from_utf8(bytes).map_err(|_| {
                RusshError::new(
                    RusshErrorCategory::Protocol,
                    "invalid UTF-8 in bind_address",
                )
            })?
        };
        let bind_port = read_u32(data, &mut off)?;
        Ok((bind_address, bind_port))
    }

    /// Build the data payload for a `cancel-tcpip-forward` global request (RFC 4254 §7.1).
    ///
    /// Wire format is identical to `tcpip-forward`: `string(bind_address) + uint32(bind_port)`.
    #[must_use]
    pub fn build_cancel_tcpip_forward_data(bind_address: &str, bind_port: u32) -> Vec<u8> {
        Self::build_tcpip_forward_data(bind_address, bind_port)
    }

    /// Parse the data payload from a `cancel-tcpip-forward` global request.
    ///
    /// Wire format is identical to `tcpip-forward`: `string(bind_address) + uint32(bind_port)`.
    pub fn parse_cancel_tcpip_forward_data(data: &[u8]) -> Result<(String, u32), RusshError> {
        Self::parse_tcpip_forward_data(data)
    }

    // ── streamlocal (Unix domain socket) helpers ───────────────

    /// Parse the extra data from a `direct-streamlocal@openssh.com` channel open.
    ///
    /// Wire format: `string(socket_path) || string(reserved) || uint32(reserved)`.
    /// Returns the socket path.
    pub fn parse_direct_streamlocal_extra(data: &[u8]) -> Result<String, RusshError> {
        if data.len() < 4 {
            return Err(RusshError::new(
                RusshErrorCategory::Protocol,
                "streamlocal extra data too short",
            ));
        }
        let path_len =
            u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        if data.len() < 4 + path_len {
            return Err(RusshError::new(
                RusshErrorCategory::Protocol,
                "streamlocal socket path truncated",
            ));
        }
        String::from_utf8(data[4..4 + path_len].to_vec()).map_err(|_| {
            RusshError::new(
                RusshErrorCategory::Protocol,
                "streamlocal socket path is not valid UTF-8",
            )
        })
    }

    /// Build the extra data for a `direct-streamlocal@openssh.com` channel open.
    ///
    /// Wire format: `string(socket_path) || string("") || uint32(0)`.
    #[must_use]
    pub fn build_direct_streamlocal_extra(socket_path: &str) -> Vec<u8> {
        let path_bytes = socket_path.as_bytes();
        let mut buf = Vec::with_capacity(4 + path_bytes.len() + 4 + 4);
        buf.extend_from_slice(&(path_bytes.len() as u32).to_be_bytes());
        buf.extend_from_slice(path_bytes);
        // reserved string (empty)
        buf.extend_from_slice(&0u32.to_be_bytes());
        // reserved uint32
        buf.extend_from_slice(&0u32.to_be_bytes());
        buf
    }

    /// Parse the data payload from a `streamlocal-forward@openssh.com` global request.
    ///
    /// Wire format: `string(socket_path)`.
    pub fn parse_streamlocal_forward_data(data: &[u8]) -> Result<String, RusshError> {
        if data.len() < 4 {
            return Err(RusshError::new(
                RusshErrorCategory::Protocol,
                "streamlocal-forward data too short",
            ));
        }
        let path_len =
            u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        if data.len() < 4 + path_len {
            return Err(RusshError::new(
                RusshErrorCategory::Protocol,
                "streamlocal-forward socket path truncated",
            ));
        }
        String::from_utf8(data[4..4 + path_len].to_vec()).map_err(|_| {
            RusshError::new(
                RusshErrorCategory::Protocol,
                "streamlocal socket path is not valid UTF-8",
            )
        })
    }
}

#[cfg(test)]
mod channel_tests {
    use super::*;

    // ── ChannelMessage round-trip tests ──────────────────────

    #[test]
    fn channel_open_round_trip() {
        let msg = ChannelMessage::Open {
            channel_type: "session".to_string(),
            sender_channel: 0,
            initial_window_size: ChannelState::DEFAULT_WINDOW_SIZE,
            maximum_packet_size: ChannelState::DEFAULT_MAX_PACKET,
            extra_data: vec![],
        };
        let bytes = msg.to_bytes().expect("encode");
        assert_eq!(bytes[0], 90);
        assert_eq!(ChannelMessage::from_bytes(&bytes).expect("decode"), msg);
    }

    #[test]
    fn channel_open_with_extra_data_round_trip() {
        let msg = ChannelMessage::Open {
            channel_type: "direct-tcpip".to_string(),
            sender_channel: 3,
            initial_window_size: 1024,
            maximum_packet_size: 512,
            extra_data: vec![1, 2, 3, 4],
        };
        let bytes = msg.to_bytes().expect("encode");
        assert_eq!(ChannelMessage::from_bytes(&bytes).expect("decode"), msg);
    }

    #[test]
    fn channel_open_confirmation_round_trip() {
        let msg = ChannelMessage::OpenConfirmation {
            recipient_channel: 0,
            sender_channel: 7,
            initial_window_size: 1_048_576,
            maximum_packet_size: 16_384,
        };
        let bytes = msg.to_bytes().expect("encode");
        assert_eq!(bytes[0], 91);
        assert_eq!(ChannelMessage::from_bytes(&bytes).expect("decode"), msg);
    }

    #[test]
    fn channel_open_failure_round_trip() {
        for reason in [
            ChannelOpenFailureReason::AdministrativelyProhibited,
            ChannelOpenFailureReason::ConnectFailed,
            ChannelOpenFailureReason::UnknownChannelType,
            ChannelOpenFailureReason::ResourceShortage,
        ] {
            let msg = ChannelMessage::OpenFailure {
                recipient_channel: 5,
                reason: reason.clone(),
                description: format!("reason {}", reason.to_code()),
            };
            let bytes = msg.to_bytes().expect("encode");
            assert_eq!(bytes[0], 92);
            assert_eq!(ChannelMessage::from_bytes(&bytes).expect("decode"), msg);
        }
    }

    #[test]
    fn channel_window_adjust_round_trip() {
        let msg = ChannelMessage::WindowAdjust {
            recipient_channel: 2,
            bytes_to_add: 65_536,
        };
        let bytes = msg.to_bytes().expect("encode");
        assert_eq!(bytes[0], 93);
        assert_eq!(ChannelMessage::from_bytes(&bytes).expect("decode"), msg);
    }

    #[test]
    fn channel_data_round_trip() {
        let msg = ChannelMessage::Data {
            recipient_channel: 42,
            data: b"hello, SSH world".to_vec(),
        };
        let bytes = msg.to_bytes().expect("encode");
        assert_eq!(bytes[0], 94);
        assert_eq!(ChannelMessage::from_bytes(&bytes).expect("decode"), msg);
    }

    #[test]
    fn channel_extended_data_round_trip() {
        let msg = ChannelMessage::ExtendedData {
            recipient_channel: 1,
            data_type_code: 1, // SSH_EXTENDED_DATA_STDERR
            data: b"error output".to_vec(),
        };
        let bytes = msg.to_bytes().expect("encode");
        assert_eq!(bytes[0], 95);
        assert_eq!(ChannelMessage::from_bytes(&bytes).expect("decode"), msg);
    }

    #[test]
    fn channel_eof_close_round_trip() {
        let eof = ChannelMessage::Eof {
            recipient_channel: 3,
        };
        let close = ChannelMessage::Close {
            recipient_channel: 4,
        };
        for (msg, expected_type) in [(eof, 96u8), (close, 97u8)] {
            let bytes = msg.to_bytes().expect("encode");
            assert_eq!(bytes[0], expected_type);
            assert_eq!(ChannelMessage::from_bytes(&bytes).expect("decode"), msg);
        }
    }

    #[test]
    fn channel_success_failure_round_trip() {
        for (msg, expected_type) in [
            (
                ChannelMessage::Success {
                    recipient_channel: 1,
                },
                99u8,
            ),
            (
                ChannelMessage::Failure {
                    recipient_channel: 2,
                },
                100u8,
            ),
        ] {
            let bytes = msg.to_bytes().expect("encode");
            assert_eq!(bytes[0], expected_type);
            assert_eq!(ChannelMessage::from_bytes(&bytes).expect("decode"), msg);
        }
    }

    #[test]
    fn channel_request_shell_round_trip() {
        let msg = ChannelMessage::Request {
            recipient_channel: 0,
            want_reply: true,
            request: ChannelRequest::Shell,
        };
        let bytes = msg.to_bytes().expect("encode");
        assert_eq!(bytes[0], 98);
        assert_eq!(ChannelMessage::from_bytes(&bytes).expect("decode"), msg);
    }

    #[test]
    fn channel_request_exec_round_trip() {
        let msg = ChannelMessage::Request {
            recipient_channel: 1,
            want_reply: true,
            request: ChannelRequest::Exec {
                command: "echo hello".to_string(),
            },
        };
        let bytes = msg.to_bytes().expect("encode");
        assert_eq!(ChannelMessage::from_bytes(&bytes).expect("decode"), msg);
    }

    #[test]
    fn channel_request_pty_round_trip() {
        let msg = ChannelMessage::Request {
            recipient_channel: 2,
            want_reply: true,
            request: ChannelRequest::PtyReq {
                term: "xterm-256color".to_string(),
                width_chars: 80,
                height_rows: 24,
                width_pixels: 0,
                height_pixels: 0,
                term_modes: vec![0], // end of modes
            },
        };
        let bytes = msg.to_bytes().expect("encode");
        assert_eq!(ChannelMessage::from_bytes(&bytes).expect("decode"), msg);
    }

    #[test]
    fn channel_request_env_round_trip() {
        let msg = ChannelMessage::Request {
            recipient_channel: 0,
            want_reply: false,
            request: ChannelRequest::Env {
                name: "LANG".to_string(),
                value: "en_US.UTF-8".to_string(),
            },
        };
        let bytes = msg.to_bytes().expect("encode");
        assert_eq!(ChannelMessage::from_bytes(&bytes).expect("decode"), msg);
    }

    #[test]
    fn channel_request_exit_status_round_trip() {
        let msg = ChannelMessage::Request {
            recipient_channel: 0,
            want_reply: false,
            request: ChannelRequest::ExitStatus { exit_status: 127 },
        };
        let bytes = msg.to_bytes().expect("encode");
        assert_eq!(ChannelMessage::from_bytes(&bytes).expect("decode"), msg);
    }

    #[test]
    fn channel_request_exit_signal_round_trip() {
        let msg = ChannelMessage::Request {
            recipient_channel: 3,
            want_reply: false,
            request: ChannelRequest::ExitSignal {
                signal_name: "TERM".to_string(),
                core_dumped: false,
                error_message: "terminated".to_string(),
            },
        };
        let bytes = msg.to_bytes().expect("encode");
        assert_eq!(ChannelMessage::from_bytes(&bytes).expect("decode"), msg);
    }

    #[test]
    fn channel_request_window_change_round_trip() {
        let msg = ChannelMessage::Request {
            recipient_channel: 4,
            want_reply: false,
            request: ChannelRequest::WindowChange {
                width_chars: 132,
                height_rows: 50,
                width_pixels: 0,
                height_pixels: 0,
            },
        };
        let bytes = msg.to_bytes().expect("encode");
        assert_eq!(ChannelMessage::from_bytes(&bytes).expect("decode"), msg);
    }

    #[test]
    fn channel_request_subsystem_round_trip() {
        let msg = ChannelMessage::Request {
            recipient_channel: 0,
            want_reply: true,
            request: ChannelRequest::SubSystem {
                name: "sftp".to_string(),
            },
        };
        let bytes = msg.to_bytes().expect("encode");
        assert_eq!(ChannelMessage::from_bytes(&bytes).expect("decode"), msg);
    }

    #[test]
    fn channel_request_signal_round_trip() {
        let msg = ChannelMessage::Request {
            recipient_channel: 0,
            want_reply: false,
            request: ChannelRequest::Signal {
                signal_name: "HUP".to_string(),
            },
        };
        let bytes = msg.to_bytes().expect("encode");
        assert_eq!(ChannelMessage::from_bytes(&bytes).expect("decode"), msg);
    }

    #[test]
    fn channel_request_unknown_round_trip() {
        let msg = ChannelMessage::Request {
            recipient_channel: 0,
            want_reply: false,
            request: ChannelRequest::Unknown {
                request_type: "x-custom@example.com".to_string(),
                data: vec![1, 2, 3],
            },
        };
        let bytes = msg.to_bytes().expect("encode");
        assert_eq!(ChannelMessage::from_bytes(&bytes).expect("decode"), msg);
    }

    #[test]
    fn to_frame_carries_correct_message_type_byte() {
        let msg = ChannelMessage::WindowAdjust {
            recipient_channel: 0,
            bytes_to_add: 65_536,
        };
        let frame = msg.to_frame().expect("to_frame");
        assert_eq!(frame.message_type(), Some(93));
    }

    #[test]
    fn from_bytes_rejects_empty_payload() {
        assert!(ChannelMessage::from_bytes(&[]).is_err());
    }

    #[test]
    fn from_bytes_rejects_unknown_message_type() {
        assert!(ChannelMessage::from_bytes(&[0x00]).is_err());
    }

    // ── ChannelState flow-control tests ──────────────────────

    #[test]
    fn channel_state_consume_remote_window_ok() {
        let mut s = ChannelState::new(ChannelId::next(), 0, ChannelKind::Session);
        s.consume_remote_window(1024).expect("should succeed");
        assert_eq!(
            s.remote_window_size,
            ChannelState::DEFAULT_WINDOW_SIZE - 1024
        );
    }

    #[test]
    fn channel_state_consume_remote_window_exhausted() {
        let mut s = ChannelState::new(ChannelId::next(), 0, ChannelKind::Session);
        let result = s.consume_remote_window(ChannelState::DEFAULT_WINDOW_SIZE + 1);
        assert!(result.is_err());
    }

    #[test]
    fn channel_state_credit_local_window() {
        let mut s = ChannelState::new(ChannelId::next(), 0, ChannelKind::Session);
        s.consume_remote_window(4096).expect("consume");
        s.credit_local_window(4096);
        assert_eq!(s.remote_window_size, ChannelState::DEFAULT_WINDOW_SIZE);
    }

    #[test]
    fn channel_state_build_window_adjust() {
        let mut s = ChannelState::new(ChannelId::next(), 99, ChannelKind::Session);
        let original = s.local_window_size;
        let msg = s.build_window_adjust(65_536);
        assert_eq!(
            msg,
            ChannelMessage::WindowAdjust {
                recipient_channel: 99,
                bytes_to_add: 65_536
            }
        );
        assert_eq!(s.local_window_size, original + 65_536);
    }

    #[test]
    fn channel_state_is_fully_closed() {
        let mut s = ChannelState::new(ChannelId::next(), 0, ChannelKind::Session);
        assert!(!s.is_fully_closed());
        s.eof_sent = true;
        s.eof_received = true;
        s.close_sent = true;
        assert!(!s.is_fully_closed());
        s.close_received = true;
        assert!(s.is_fully_closed());
    }

    // ── ChannelManager tests ──────────────────────────────────

    #[test]
    fn manager_open_channel_creates_state() {
        let mut mgr = ChannelManager::new();
        let (local_id, msg) = mgr.open_channel(ChannelKind::Session);
        assert!(
            matches!(msg, ChannelMessage::Open { channel_type, .. } if channel_type == "session")
        );
        assert!(mgr.channel(local_id).is_some());
        assert_eq!(mgr.open_channels().len(), 1);
    }

    #[test]
    fn manager_accept_confirmation_updates_remote_id() {
        let mut mgr = ChannelManager::new();
        let (local_id, _) = mgr.open_channel(ChannelKind::Session);
        let confirm = ChannelMessage::OpenConfirmation {
            recipient_channel: local_id,
            sender_channel: 42,
            initial_window_size: 1_024 * 1_024,
            maximum_packet_size: 16_384,
        };
        mgr.accept_confirmation(local_id, &confirm).expect("accept");
        let s = mgr.channel(local_id).expect("state");
        assert_eq!(s.remote_id, 42);
        assert_eq!(s.remote_window_size, 1_024 * 1_024);
        assert_eq!(s.max_packet_size, 16_384);
    }

    #[test]
    fn manager_process_window_adjust_credits_remote_window() {
        let mut mgr = ChannelManager::new();
        let (local_id, _) = mgr.open_channel(ChannelKind::Session);
        let msg = ChannelMessage::WindowAdjust {
            recipient_channel: local_id,
            bytes_to_add: 8_192,
        };
        let responses = mgr.process(&msg).expect("process");
        assert!(responses.is_empty());
        assert_eq!(
            mgr.channel(local_id).unwrap().remote_window_size,
            ChannelState::DEFAULT_WINDOW_SIZE + 8_192
        );
    }

    #[test]
    fn manager_process_data_triggers_window_adjust_when_low() {
        let mut mgr = ChannelManager::new();
        let (local_id, _) = mgr.open_channel(ChannelKind::Session);
        // Drain local window to just below half
        let big_data = vec![0u8; (ChannelState::DEFAULT_WINDOW_SIZE / 2 + 1) as usize];
        let msg = ChannelMessage::Data {
            recipient_channel: local_id,
            data: big_data,
        };
        let responses = mgr.process(&msg).expect("process");
        assert_eq!(responses.len(), 1);
        assert!(matches!(responses[0], ChannelMessage::WindowAdjust { .. }));
    }

    #[test]
    fn manager_process_close_sends_close_back() {
        let mut mgr = ChannelManager::new();
        let (local_id, _) = mgr.open_channel(ChannelKind::Session);
        // Set remote_id so the CLOSE response is addressed correctly.
        let confirm = ChannelMessage::OpenConfirmation {
            recipient_channel: local_id,
            sender_channel: 100,
            initial_window_size: ChannelState::DEFAULT_WINDOW_SIZE,
            maximum_packet_size: ChannelState::DEFAULT_MAX_PACKET,
        };
        mgr.accept_confirmation(local_id, &confirm).expect("accept");

        let close = ChannelMessage::Close {
            recipient_channel: local_id,
        };
        let responses = mgr.process(&close).expect("process");
        assert_eq!(
            responses,
            vec![ChannelMessage::Close {
                recipient_channel: 100
            }]
        );
        let s = mgr.channel(local_id).unwrap();
        assert!(s.close_received && s.close_sent);
    }

    #[test]
    fn manager_process_close_does_not_double_send() {
        let mut mgr = ChannelManager::new();
        let (local_id, _) = mgr.open_channel(ChannelKind::Session);
        mgr.channel_mut(local_id).unwrap().close_sent = true;

        let close = ChannelMessage::Close {
            recipient_channel: local_id,
        };
        let responses = mgr.process(&close).expect("process");
        assert!(responses.is_empty(), "must not send a second CLOSE");
    }

    #[test]
    fn manager_process_eof_marks_received() {
        let mut mgr = ChannelManager::new();
        let (local_id, _) = mgr.open_channel(ChannelKind::Session);
        let eof = ChannelMessage::Eof {
            recipient_channel: local_id,
        };
        mgr.process(&eof).expect("process");
        assert!(mgr.channel(local_id).unwrap().eof_received);
    }

    #[test]
    fn manager_process_request_with_reply_sends_success() {
        let mut mgr = ChannelManager::new();
        let (local_id, _) = mgr.open_channel(ChannelKind::Session);
        mgr.channel_mut(local_id).unwrap().remote_id = 55;

        let req = ChannelMessage::Request {
            recipient_channel: local_id,
            want_reply: true,
            request: ChannelRequest::Shell,
        };
        let responses = mgr.process(&req).expect("process");
        assert_eq!(
            responses,
            vec![ChannelMessage::Success {
                recipient_channel: 55
            }]
        );
    }

    #[test]
    fn manager_process_unknown_request_with_reply_sends_failure() {
        let mut mgr = ChannelManager::new();
        let (local_id, _) = mgr.open_channel(ChannelKind::Session);
        mgr.channel_mut(local_id).unwrap().remote_id = 77;

        let req = ChannelMessage::Request {
            recipient_channel: local_id,
            want_reply: true,
            request: ChannelRequest::Unknown {
                request_type: "x-unknown@test".to_string(),
                data: vec![],
            },
        };
        let responses = mgr.process(&req).expect("process");
        assert_eq!(
            responses,
            vec![ChannelMessage::Failure {
                recipient_channel: 77
            }]
        );
    }

    #[test]
    fn manager_rejects_incoming_open() {
        let mut mgr = ChannelManager::new();
        let open = ChannelMessage::Open {
            channel_type: "session".to_string(),
            sender_channel: 99,
            initial_window_size: ChannelState::DEFAULT_WINDOW_SIZE,
            maximum_packet_size: ChannelState::DEFAULT_MAX_PACKET,
            extra_data: vec![],
        };
        let responses = mgr.process(&open).expect("process");
        assert_eq!(responses.len(), 1);
        assert!(matches!(
            &responses[0],
            ChannelMessage::OpenFailure {
                recipient_channel: 99,
                ..
            }
        ));
    }

    #[test]
    fn forward_handle_build_direct_tcpip_extra() {
        let extra =
            ForwardHandle::build_direct_tcpip_open_extra("example.com", 8080, "127.0.0.1", 12345);
        let mut off = 0;
        let host = read_utf8(&extra, &mut off).expect("host");
        let port = read_u32(&extra, &mut off).expect("port");
        let orig_host = read_utf8(&extra, &mut off).expect("orig_host");
        let orig_port = read_u32(&extra, &mut off).expect("orig_port");
        assert_eq!(host, "example.com");
        assert_eq!(port, 8080);
        assert_eq!(orig_host, "127.0.0.1");
        assert_eq!(orig_port, 12345);
        assert_eq!(off, extra.len(), "no trailing bytes");
    }

    #[test]
    fn cancel_tcpip_forward_data_round_trip() {
        let data = ForwardHandle::build_cancel_tcpip_forward_data("192.168.1.1", 2222);
        let (addr, port) = ForwardHandle::parse_cancel_tcpip_forward_data(&data).expect("parse");
        assert_eq!(addr, "192.168.1.1");
        assert_eq!(port, 2222);
    }

    #[test]
    fn cancel_tcpip_forward_data_empty_address() {
        let data = ForwardHandle::build_cancel_tcpip_forward_data("", 0);
        let (addr, port) = ForwardHandle::parse_cancel_tcpip_forward_data(&data).expect("parse");
        assert_eq!(addr, "");
        assert_eq!(port, 0);
    }

    #[test]
    fn cancel_tcpip_forward_parse_truncated_payload() {
        // Only 3 bytes — too short for a valid string length
        assert!(ForwardHandle::parse_cancel_tcpip_forward_data(&[0, 0, 0]).is_err());
    }

    #[test]
    fn direct_streamlocal_extra_round_trip() {
        let extra = ForwardHandle::build_direct_streamlocal_extra("/var/run/app.sock");
        let path = ForwardHandle::parse_direct_streamlocal_extra(&extra).expect("parse");
        assert_eq!(path, "/var/run/app.sock");
    }

    #[test]
    fn direct_streamlocal_extra_truncated() {
        assert!(ForwardHandle::parse_direct_streamlocal_extra(&[0, 0, 0]).is_err());
        // Length says 10 but only 4 bytes of data
        assert!(ForwardHandle::parse_direct_streamlocal_extra(&[0, 0, 0, 10, 1, 2, 3, 4]).is_err());
    }

    #[test]
    fn streamlocal_forward_data_round_trip() {
        let path = "/tmp/test.sock";
        let mut data = Vec::new();
        data.extend_from_slice(&(path.len() as u32).to_be_bytes());
        data.extend_from_slice(path.as_bytes());
        let parsed = ForwardHandle::parse_streamlocal_forward_data(&data).expect("parse");
        assert_eq!(parsed, path);
    }

    #[test]
    fn streamlocal_forward_data_truncated() {
        assert!(ForwardHandle::parse_streamlocal_forward_data(&[0, 0]).is_err());
    }
}

#[cfg(test)]
mod tests {
    use russh_transport::ClientConfig;

    use super::{Channel, ChannelKind, ConnectionPool, JumpChain};

    #[test]
    fn channel_opens_with_unique_ids() {
        let first = Channel::open(ChannelKind::Session);
        let second = Channel::open(ChannelKind::Session);
        assert!(first.open);
        assert!(second.open);
        assert_ne!(first.id.value(), second.id.value());
    }

    #[test]
    fn jump_chain_requires_hops() {
        assert!(JumpChain::new(vec![]).is_err());
        assert!(JumpChain::new(vec!["jump.example".to_string()]).is_ok());
    }

    #[test]
    fn connection_pool_reuses_by_key() {
        let pool = ConnectionPool::new();
        let session = russh_transport::ClientSession::new(ClientConfig::secure_defaults("alice"));
        pool.insert("main", session).expect("insert should succeed");
        let found = pool.get("main").expect("get should succeed");
        assert!(found.is_some());
    }
}
