//! SOCKS4/SOCKS5 proxy protocol parsing for dynamic port forwarding (`-D`).
//!
//! This module provides pure protocol parsing for SOCKS handshakes — no async
//! I/O or networking. The caller is responsible for reading bytes from a TCP
//! stream, feeding them to the parsing functions, and writing the generated
//! reply bytes back.
//!
//! ## SOCKS5 (RFC 1928)
//!
//! 1. Client sends a greeting: version (0x05), number of auth methods, method list.
//! 2. Server replies with chosen method (we always pick 0x00 = no authentication).
//! 3. Client sends a CONNECT request: version, cmd, reserved, address type, address, port.
//! 4. Server replies with success/failure and bound address.
//!
//! ## SOCKS4 / SOCKS4a
//!
//! 1. Client sends: version (0x04), cmd, dest port, dest ip, userid (null-terminated).
//!    For SOCKS4a, if the IP starts with `0.0.0.x` (x ≠ 0), a domain name follows
//!    after the userid null terminator.
//! 2. Server replies: 0x00, status (0x5a = granted), port, ip.

use std::net::{Ipv4Addr, Ipv6Addr};

use russh_core::{RusshError, RusshErrorCategory};

/// The target address extracted from a SOCKS CONNECT request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SocksTarget {
    /// IPv4 address and port.
    Ipv4(Ipv4Addr, u16),
    /// IPv6 address and port.
    Ipv6(Ipv6Addr, u16),
    /// Domain name and port.
    Domain(String, u16),
}

impl SocksTarget {
    /// Host string suitable for SSH `direct-tcpip`.
    #[must_use]
    pub fn host(&self) -> String {
        match self {
            Self::Ipv4(ip, _) => ip.to_string(),
            Self::Ipv6(ip, _) => ip.to_string(),
            Self::Domain(name, _) => name.clone(),
        }
    }

    /// Destination port.
    #[must_use]
    pub fn port(&self) -> u16 {
        match self {
            Self::Ipv4(_, p) | Self::Ipv6(_, p) | Self::Domain(_, p) => *p,
        }
    }
}

// ─── SOCKS5 ──────────────────────────────────────────────────────────────

const SOCKS5_VERSION: u8 = 0x05;
const SOCKS5_NO_AUTH: u8 = 0x00;
const SOCKS5_CMD_CONNECT: u8 = 0x01;
const SOCKS5_ATYP_IPV4: u8 = 0x01;
const SOCKS5_ATYP_DOMAIN: u8 = 0x03;
const SOCKS5_ATYP_IPV6: u8 = 0x04;
const SOCKS5_REP_SUCCEEDED: u8 = 0x00;
const SOCKS5_REP_GENERAL_FAILURE: u8 = 0x01;
const SOCKS5_REP_CMD_NOT_SUPPORTED: u8 = 0x07;

/// Parsed SOCKS5 client greeting.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Socks5Greeting {
    /// Authentication methods offered by the client.
    pub methods: Vec<u8>,
}

/// Parse a SOCKS5 client greeting from raw bytes.
///
/// Expected wire format: `[0x05, nmethods, method_0, method_1, ...]`
pub fn parse_socks5_greeting(data: &[u8]) -> Result<Socks5Greeting, RusshError> {
    if data.len() < 2 {
        return Err(socks_err("SOCKS5 greeting too short"));
    }
    if data[0] != SOCKS5_VERSION {
        return Err(socks_err("expected SOCKS5 version byte"));
    }
    let nmethods = data[1] as usize;
    if data.len() < 2 + nmethods {
        return Err(socks_err("SOCKS5 greeting truncated"));
    }
    let methods = data[2..2 + nmethods].to_vec();
    Ok(Socks5Greeting { methods })
}

/// Build the SOCKS5 server greeting reply selecting "no authentication".
#[must_use]
pub fn build_socks5_greeting_reply() -> Vec<u8> {
    vec![SOCKS5_VERSION, SOCKS5_NO_AUTH]
}

/// Parse a SOCKS5 CONNECT request.
///
/// Wire format: `[0x05, cmd, 0x00, atyp, addr..., port(2)]`
pub fn parse_socks5_request(data: &[u8]) -> Result<SocksTarget, RusshError> {
    if data.len() < 4 {
        return Err(socks_err("SOCKS5 request too short"));
    }
    if data[0] != SOCKS5_VERSION {
        return Err(socks_err("expected SOCKS5 version in request"));
    }
    if data[1] != SOCKS5_CMD_CONNECT {
        return Err(socks_err("only CONNECT command is supported"));
    }
    // data[2] is reserved
    let atyp = data[3];
    match atyp {
        SOCKS5_ATYP_IPV4 => {
            if data.len() < 10 {
                return Err(socks_err("SOCKS5 IPv4 request too short"));
            }
            let ip = Ipv4Addr::new(data[4], data[5], data[6], data[7]);
            let port = u16::from_be_bytes([data[8], data[9]]);
            Ok(SocksTarget::Ipv4(ip, port))
        }
        SOCKS5_ATYP_DOMAIN => {
            if data.len() < 5 {
                return Err(socks_err("SOCKS5 domain request too short"));
            }
            let dlen = data[4] as usize;
            if data.len() < 5 + dlen + 2 {
                return Err(socks_err("SOCKS5 domain request truncated"));
            }
            let domain = String::from_utf8(data[5..5 + dlen].to_vec())
                .map_err(|_| socks_err("invalid UTF-8 in SOCKS5 domain"))?;
            let port = u16::from_be_bytes([data[5 + dlen], data[5 + dlen + 1]]);
            Ok(SocksTarget::Domain(domain, port))
        }
        SOCKS5_ATYP_IPV6 => {
            if data.len() < 22 {
                return Err(socks_err("SOCKS5 IPv6 request too short"));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[4..20]);
            let ip = Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([data[20], data[21]]);
            Ok(SocksTarget::Ipv6(ip, port))
        }
        _ => Err(socks_err("unsupported SOCKS5 address type")),
    }
}

/// Build a SOCKS5 success reply.
///
/// Uses `0.0.0.0:0` as bound address since the client doesn't need it.
#[must_use]
pub fn build_socks5_reply_success() -> Vec<u8> {
    vec![
        SOCKS5_VERSION,
        SOCKS5_REP_SUCCEEDED,
        0x00, // reserved
        SOCKS5_ATYP_IPV4,
        0,
        0,
        0,
        0, // bind addr
        0,
        0, // bind port
    ]
}

/// Build a SOCKS5 failure reply.
#[must_use]
pub fn build_socks5_reply_failure() -> Vec<u8> {
    vec![
        SOCKS5_VERSION,
        SOCKS5_REP_GENERAL_FAILURE,
        0x00,
        SOCKS5_ATYP_IPV4,
        0,
        0,
        0,
        0,
        0,
        0,
    ]
}

/// Build a SOCKS5 "command not supported" reply.
#[must_use]
pub fn build_socks5_reply_cmd_not_supported() -> Vec<u8> {
    vec![
        SOCKS5_VERSION,
        SOCKS5_REP_CMD_NOT_SUPPORTED,
        0x00,
        SOCKS5_ATYP_IPV4,
        0,
        0,
        0,
        0,
        0,
        0,
    ]
}

// ─── SOCKS4 / SOCKS4a ──────────────────────────────────────────────────

const SOCKS4_VERSION: u8 = 0x04;
const SOCKS4_CMD_CONNECT: u8 = 0x01;
const SOCKS4_REPLY_GRANTED: u8 = 0x5a;
const SOCKS4_REPLY_REJECTED: u8 = 0x5b;

/// Parse a SOCKS4/SOCKS4a CONNECT request.
///
/// Wire format: `[0x04, cmd, port(2), ip(4), userid..., 0x00, (domain..., 0x00)?]`
///
/// For SOCKS4a: if the IP is `0.0.0.x` where x ≠ 0, a null-terminated domain
/// name follows the userid null terminator.
pub fn parse_socks4_request(data: &[u8]) -> Result<SocksTarget, RusshError> {
    if data.len() < 9 {
        return Err(socks_err("SOCKS4 request too short"));
    }
    if data[0] != SOCKS4_VERSION {
        return Err(socks_err("expected SOCKS4 version byte"));
    }
    if data[1] != SOCKS4_CMD_CONNECT {
        return Err(socks_err("only CONNECT command is supported for SOCKS4"));
    }
    let port = u16::from_be_bytes([data[2], data[3]]);
    let ip = Ipv4Addr::new(data[4], data[5], data[6], data[7]);

    // Find end of userid (null-terminated string starting at offset 8).
    let userid_end = data[8..]
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| socks_err("SOCKS4 userid not null-terminated"))?
        + 8;

    // SOCKS4a: IP is 0.0.0.x with x != 0 → domain follows after userid null.
    let is_socks4a = data[4] == 0 && data[5] == 0 && data[6] == 0 && data[7] != 0;
    if is_socks4a {
        let domain_start = userid_end + 1;
        if domain_start >= data.len() {
            return Err(socks_err("SOCKS4a domain missing"));
        }
        let domain_end = data[domain_start..]
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| socks_err("SOCKS4a domain not null-terminated"))?
            + domain_start;
        let domain = String::from_utf8(data[domain_start..domain_end].to_vec())
            .map_err(|_| socks_err("invalid UTF-8 in SOCKS4a domain"))?;
        Ok(SocksTarget::Domain(domain, port))
    } else {
        Ok(SocksTarget::Ipv4(ip, port))
    }
}

/// Build a SOCKS4 "request granted" reply.
#[must_use]
pub fn build_socks4_reply_granted() -> Vec<u8> {
    vec![0x00, SOCKS4_REPLY_GRANTED, 0, 0, 0, 0, 0, 0]
}

/// Build a SOCKS4 "request rejected" reply.
#[must_use]
pub fn build_socks4_reply_rejected() -> Vec<u8> {
    vec![0x00, SOCKS4_REPLY_REJECTED, 0, 0, 0, 0, 0, 0]
}

// ─── Version detection ──────────────────────────────────────────────────

/// Detected SOCKS protocol version from the first byte of a client message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SocksVersion {
    V4,
    V5,
}

/// Detect whether the client is speaking SOCKS4 or SOCKS5 from the first byte.
pub fn detect_version(first_byte: u8) -> Result<SocksVersion, RusshError> {
    match first_byte {
        SOCKS4_VERSION => Ok(SocksVersion::V4),
        SOCKS5_VERSION => Ok(SocksVersion::V5),
        other => Err(socks_err(&format!(
            "unsupported SOCKS version: 0x{other:02x}"
        ))),
    }
}

// ─── helpers ────────────────────────────────────────────────────────────

fn socks_err(msg: &str) -> RusshError {
    RusshError::new(RusshErrorCategory::Protocol, msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── SOCKS5 greeting ──────────────────────────────────────────────

    #[test]
    fn socks5_greeting_no_auth() {
        let data = [0x05, 0x01, 0x00];
        let g = parse_socks5_greeting(&data).unwrap();
        assert_eq!(g.methods, vec![0x00]);
    }

    #[test]
    fn socks5_greeting_multiple_methods() {
        let data = [0x05, 0x03, 0x00, 0x01, 0x02];
        let g = parse_socks5_greeting(&data).unwrap();
        assert_eq!(g.methods, vec![0x00, 0x01, 0x02]);
    }

    #[test]
    fn socks5_greeting_wrong_version() {
        let data = [0x04, 0x01, 0x00];
        assert!(parse_socks5_greeting(&data).is_err());
    }

    #[test]
    fn socks5_greeting_truncated() {
        let data = [0x05, 0x03, 0x00]; // claims 3 methods but only 1
        assert!(parse_socks5_greeting(&data).is_err());
    }

    #[test]
    fn socks5_greeting_reply_format() {
        let reply = build_socks5_greeting_reply();
        assert_eq!(reply, vec![0x05, 0x00]);
    }

    // ── SOCKS5 CONNECT request ───────────────────────────────────────

    #[test]
    fn socks5_connect_ipv4() {
        let data = [
            0x05, 0x01, 0x00, // ver, cmd=CONNECT, reserved
            0x01, // atyp=IPv4
            192, 168, 1, 1, // address
            0x00, 0x50, // port 80
        ];
        let target = parse_socks5_request(&data).unwrap();
        assert_eq!(target, SocksTarget::Ipv4(Ipv4Addr::new(192, 168, 1, 1), 80));
        assert_eq!(target.host(), "192.168.1.1");
        assert_eq!(target.port(), 80);
    }

    #[test]
    fn socks5_connect_ipv6() {
        let mut data = vec![0x05, 0x01, 0x00, 0x04]; // ver, cmd, rsv, atyp=IPv6
        // ::1
        let mut ipv6_bytes = [0u8; 16];
        ipv6_bytes[15] = 1;
        data.extend_from_slice(&ipv6_bytes);
        data.extend_from_slice(&[0x01, 0xBB]); // port 443
        let target = parse_socks5_request(&data).unwrap();
        assert_eq!(
            target,
            SocksTarget::Ipv6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1), 443)
        );
        assert_eq!(target.host(), "::1");
        assert_eq!(target.port(), 443);
    }

    #[test]
    fn socks5_connect_domain() {
        let domain = b"example.com";
        let mut data = vec![0x05, 0x01, 0x00, 0x03]; // ver, cmd, rsv, atyp=domain
        data.push(domain.len() as u8);
        data.extend_from_slice(domain);
        data.extend_from_slice(&[0x1F, 0x90]); // port 8080
        let target = parse_socks5_request(&data).unwrap();
        assert_eq!(target, SocksTarget::Domain("example.com".to_string(), 8080));
        assert_eq!(target.host(), "example.com");
        assert_eq!(target.port(), 8080);
    }

    #[test]
    fn socks5_non_connect_rejected() {
        // cmd=0x02 (BIND) — not supported
        let data = [0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0, 80];
        assert!(parse_socks5_request(&data).is_err());
    }

    #[test]
    fn socks5_unsupported_atyp() {
        let data = [0x05, 0x01, 0x00, 0xFF, 0, 0, 0, 0, 0, 80];
        assert!(parse_socks5_request(&data).is_err());
    }

    // ── SOCKS5 replies ───────────────────────────────────────────────

    #[test]
    fn socks5_success_reply_format() {
        let reply = build_socks5_reply_success();
        assert_eq!(reply.len(), 10);
        assert_eq!(reply[0], 0x05);
        assert_eq!(reply[1], 0x00); // succeeded
        assert_eq!(reply[3], 0x01); // IPv4 addr type
    }

    #[test]
    fn socks5_failure_reply_format() {
        let reply = build_socks5_reply_failure();
        assert_eq!(reply.len(), 10);
        assert_eq!(reply[0], 0x05);
        assert_eq!(reply[1], 0x01); // general failure
    }

    #[test]
    fn socks5_cmd_not_supported_reply() {
        let reply = build_socks5_reply_cmd_not_supported();
        assert_eq!(reply[1], 0x07); // command not supported
    }

    // ── SOCKS4 CONNECT ───────────────────────────────────────────────

    #[test]
    fn socks4_connect_ipv4() {
        let data = [
            0x04, 0x01, // ver, cmd
            0x00, 0x50, // port 80
            93, 184, 216, 34,   // ip (93.184.216.34)
            0x00, // empty userid + null
        ];
        let target = parse_socks4_request(&data).unwrap();
        assert_eq!(
            target,
            SocksTarget::Ipv4(Ipv4Addr::new(93, 184, 216, 34), 80)
        );
    }

    #[test]
    fn socks4_connect_with_userid() {
        let mut data = vec![
            0x04, 0x01, // ver, cmd
            0x01, 0xBB, // port 443
            10, 0, 0, 1, // ip
        ];
        data.extend_from_slice(b"alice"); // userid
        data.push(0x00); // null terminator
        let target = parse_socks4_request(&data).unwrap();
        assert_eq!(target, SocksTarget::Ipv4(Ipv4Addr::new(10, 0, 0, 1), 443));
    }

    #[test]
    fn socks4a_domain() {
        let mut data = vec![
            0x04, 0x01, // ver, cmd
            0x00, 0x50, // port 80
            0, 0, 0, 1, // SOCKS4a marker (0.0.0.1)
        ];
        data.push(0x00); // empty userid + null
        data.extend_from_slice(b"example.com");
        data.push(0x00); // domain null terminator
        let target = parse_socks4_request(&data).unwrap();
        assert_eq!(target, SocksTarget::Domain("example.com".to_string(), 80));
    }

    #[test]
    fn socks4a_with_userid_and_domain() {
        let mut data = vec![
            0x04, 0x01, // ver, cmd
            0x1F, 0x90, // port 8080
            0, 0, 0, 42, // SOCKS4a marker
        ];
        data.extend_from_slice(b"bob");
        data.push(0x00);
        data.extend_from_slice(b"internal.host");
        data.push(0x00);
        let target = parse_socks4_request(&data).unwrap();
        assert_eq!(
            target,
            SocksTarget::Domain("internal.host".to_string(), 8080)
        );
    }

    #[test]
    fn socks4_non_connect_rejected() {
        let data = [0x04, 0x02, 0x00, 0x50, 10, 0, 0, 1, 0x00];
        assert!(parse_socks4_request(&data).is_err());
    }

    #[test]
    fn socks4_too_short() {
        let data = [0x04, 0x01, 0x00];
        assert!(parse_socks4_request(&data).is_err());
    }

    // ── SOCKS4 replies ───────────────────────────────────────────────

    #[test]
    fn socks4_granted_reply() {
        let reply = build_socks4_reply_granted();
        assert_eq!(reply.len(), 8);
        assert_eq!(reply[0], 0x00);
        assert_eq!(reply[1], 0x5a);
    }

    #[test]
    fn socks4_rejected_reply() {
        let reply = build_socks4_reply_rejected();
        assert_eq!(reply[1], 0x5b);
    }

    // ── Version detection ────────────────────────────────────────────

    #[test]
    fn detect_socks4() {
        assert_eq!(detect_version(0x04).unwrap(), SocksVersion::V4);
    }

    #[test]
    fn detect_socks5() {
        assert_eq!(detect_version(0x05).unwrap(), SocksVersion::V5);
    }

    #[test]
    fn detect_unknown_version() {
        assert!(detect_version(0x03).is_err());
    }
}
