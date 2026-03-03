//! SSH Agent Protocol client over a Unix-domain socket.
//!
//! Implements the subset of the IETF SSH Agent Protocol needed for public-key
//! authentication:
//!
//! | Code | Message |
//! |------|---------|
//! | 11 | `SSH_AGENTC_REQUEST_IDENTITIES` |
//! | 12 | `SSH_AGENT_IDENTITIES_ANSWER` |
//! | 13 | `SSH_AGENTC_SIGN_REQUEST` |
//! | 14 | `SSH_AGENT_SIGN_RESPONSE` |
//!
//! All messages are framed as: `uint32 length || byte type || payload`.

use russh_auth::AgentClient;
use russh_core::{RusshError, RusshErrorCategory};
use russh_crypto::encode_ssh_string;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

/// Message type codes (SSH Agent Protocol).
const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
const SSH_AGENT_SIGN_RESPONSE: u8 = 14;

/// Blocking SSH agent client that communicates over `SSH_AUTH_SOCK`.
///
/// Each method opens a fresh connection to the socket so callers do not need
/// to worry about protocol state across calls.
#[derive(Clone, Debug)]
pub struct SshAgentClient {
    socket_path: String,
}

impl SshAgentClient {
    /// Create a client using the path stored in `SSH_AUTH_SOCK`.
    ///
    /// Returns `None` when the environment variable is not set.
    #[must_use]
    pub fn from_env() -> Option<Self> {
        let path = std::env::var("SSH_AUTH_SOCK").ok()?;
        Some(Self { socket_path: path })
    }

    /// Create a client for a specific socket path.
    #[must_use]
    pub fn new(socket_path: impl Into<String>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }

    /// List all identities currently held by the agent.
    ///
    /// Returns a list of `(key_blob, comment)` pairs.
    pub fn list_identities(&self) -> Result<Vec<(Vec<u8>, String)>, RusshError> {
        let mut sock = self.connect()?;

        // Send SSH_AGENTC_REQUEST_IDENTITIES (type=11, no payload).
        self.send_message(&mut sock, SSH_AGENTC_REQUEST_IDENTITIES, &[])?;

        let (msg_type, payload) = self.recv_message(&mut sock)?;
        if msg_type != SSH_AGENT_IDENTITIES_ANSWER {
            return Err(agent_err("unexpected response to IDENTITIES request"));
        }

        // Parse: uint32 nkeys; then nkeys × (string key_blob + string comment)
        let mut off = 0usize;
        let nkeys = read_u32_at(&payload, &mut off)? as usize;
        let mut identities = Vec::with_capacity(nkeys);
        for _ in 0..nkeys {
            let key_blob = read_string_at(&payload, &mut off)?;
            let comment_bytes = read_string_at(&payload, &mut off)?;
            let comment = String::from_utf8(comment_bytes).unwrap_or_default();
            identities.push((key_blob, comment));
        }
        Ok(identities)
    }

    // ── Private helpers ──────────────────────────────────────────────────────

    fn connect(&self) -> Result<UnixStream, RusshError> {
        UnixStream::connect(&self.socket_path).map_err(|e| {
            RusshError::new(
                RusshErrorCategory::Io,
                format!("cannot connect to ssh-agent socket: {e}"),
            )
        })
    }

    fn send_message(
        &self,
        sock: &mut UnixStream,
        msg_type: u8,
        payload: &[u8],
    ) -> Result<(), RusshError> {
        let len = (payload.len() + 1) as u32;
        let mut buf = Vec::with_capacity(5 + payload.len());
        buf.extend_from_slice(&len.to_be_bytes());
        buf.push(msg_type);
        buf.extend_from_slice(payload);
        sock.write_all(&buf)
            .map_err(|e| RusshError::new(RusshErrorCategory::Io, format!("agent write error: {e}")))
    }

    fn recv_message(&self, sock: &mut UnixStream) -> Result<(u8, Vec<u8>), RusshError> {
        let mut len_buf = [0u8; 4];
        sock.read_exact(&mut len_buf).map_err(|e| {
            RusshError::new(RusshErrorCategory::Io, format!("agent read error: {e}"))
        })?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len == 0 {
            return Err(agent_err("agent returned zero-length message"));
        }
        let mut body = vec![0u8; len];
        sock.read_exact(&mut body).map_err(|e| {
            RusshError::new(RusshErrorCategory::Io, format!("agent read error: {e}"))
        })?;
        Ok((body[0], body[1..].to_vec()))
    }
}

impl AgentClient for SshAgentClient {
    /// Request the agent to sign `message` using the key identified by `key_blob`.
    ///
    /// Returns the raw signature blob (SSH wire format: `string "ssh-ed25519" || string 64_bytes`).
    fn sign(&self, key_blob: &[u8], message: &[u8]) -> Result<Vec<u8>, RusshError> {
        let mut sock = self.connect()?;

        // Payload: string key_blob + string message + uint32 flags(0)
        let mut req = Vec::new();
        req.extend_from_slice(&encode_ssh_string(key_blob));
        req.extend_from_slice(&encode_ssh_string(message));
        req.extend_from_slice(&0u32.to_be_bytes()); // flags

        self.send_message(&mut sock, SSH_AGENTC_SIGN_REQUEST, &req)?;

        let (msg_type, payload) = self.recv_message(&mut sock)?;
        if msg_type != SSH_AGENT_SIGN_RESPONSE {
            return Err(agent_err("unexpected response to SIGN request"));
        }

        // Payload: string signature_blob
        let mut off = 0usize;
        let sig_blob = read_string_at(&payload, &mut off)?;
        Ok(sig_blob)
    }
}

// ── Wire helpers ─────────────────────────────────────────────────────────────

fn read_u32_at(data: &[u8], off: &mut usize) -> Result<u32, RusshError> {
    if *off + 4 > data.len() {
        return Err(agent_err("truncated agent message (u32)"));
    }
    let v = u32::from_be_bytes(data[*off..*off + 4].try_into().unwrap());
    *off += 4;
    Ok(v)
}

fn read_string_at(data: &[u8], off: &mut usize) -> Result<Vec<u8>, RusshError> {
    let len = read_u32_at(data, off)? as usize;
    if *off + len > data.len() {
        return Err(agent_err("truncated agent message (string)"));
    }
    let s = data[*off..*off + len].to_vec();
    *off += len;
    Ok(s)
}

fn agent_err(msg: impl Into<String>) -> RusshError {
    RusshError::new(RusshErrorCategory::Auth, msg)
}
