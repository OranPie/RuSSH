//! Shared helpers for russh-cli binaries.

/// Parse an unencrypted OpenSSH Ed25519 private key file (RFC 4716 / openssh-key-v1 format)
/// and return the 32-byte seed.
///
/// Also accepts RuSSH's compact seed file format (header `RUSSH-SEED-V1\n` + 32 raw bytes).
///
/// The OpenSSH file must be a `-----BEGIN OPENSSH PRIVATE KEY-----` PEM block containing
/// an unencrypted `ssh-ed25519` key.
pub fn load_ed25519_seed(path: &std::path::Path) -> Result<[u8; 32], String> {
    let raw = std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;

    // Detect compact seed format: b"RUSSH-SEED-V1\n" (14 bytes) + 32 bytes seed.
    const SEED_MAGIC: &[u8] = b"RUSSH-SEED-V1\n";
    if raw.starts_with(SEED_MAGIC) {
        let seed_bytes = &raw[SEED_MAGIC.len()..];
        if seed_bytes.len() < 32 {
            return Err("seed file truncated".into());
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&seed_bytes[..32]);
        return Ok(seed);
    }

    // OpenSSH PEM format.
    let text = std::str::from_utf8(&raw).map_err(|_| "key file is not valid UTF-8".to_string())?;
    let b64: String = text.lines().filter(|l| !l.starts_with("-----")).collect();
    let decoded = base64_decode(&b64).map_err(|e| format!("base64 decode failed: {e}"))?;
    parse_openssh_ed25519_seed(&decoded).map_err(|e| format!("key parse failed: {e}"))
}

fn parse_openssh_ed25519_seed(raw: &[u8]) -> Result<[u8; 32], &'static str> {
    let magic = b"openssh-key-v1\0";
    if !raw.starts_with(magic) {
        return Err("missing openssh-key-v1 magic");
    }
    let mut off = magic.len();

    // ciphername, kdfname, kdfoptions — must all be "none" / ""
    let cipher = read_ssh_string(raw, &mut off).ok_or("truncated: ciphername")?;
    if cipher != b"none" {
        return Err("encrypted private keys are not supported");
    }
    let kdf = read_ssh_string(raw, &mut off).ok_or("truncated: kdfname")?;
    if kdf != b"none" {
        return Err("encrypted private keys are not supported");
    }
    let _kdfopts = read_ssh_string(raw, &mut off).ok_or("truncated: kdfoptions")?;

    // number of keys (uint32)
    let _nkeys = read_u32(raw, &mut off).ok_or("truncated: nkeys")?;

    // pubkey blob (skip)
    let _pubkey = read_ssh_string(raw, &mut off).ok_or("truncated: pubkey blob")?;

    // private section blob
    let priv_blob = read_ssh_string(raw, &mut off).ok_or("truncated: private blob")?;
    let mut poff = 0usize;

    // check1, check2
    let _check1 = read_u32(priv_blob, &mut poff).ok_or("truncated: check1")?;
    let _check2 = read_u32(priv_blob, &mut poff).ok_or("truncated: check2")?;

    // key type string
    let keytype = read_ssh_string(priv_blob, &mut poff).ok_or("truncated: keytype")?;
    if keytype != b"ssh-ed25519" {
        return Err("not an ed25519 key");
    }

    // public key (32 bytes, wrapped as SSH string)
    let _pubkey_inner = read_ssh_string(priv_blob, &mut poff).ok_or("truncated: inner pubkey")?;

    // private key: 64 bytes (seed || public), wrapped as SSH string
    let privkey = read_ssh_string(priv_blob, &mut poff).ok_or("truncated: inner privkey")?;
    if privkey.len() < 32 {
        return Err("private key blob too short");
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&privkey[..32]);
    Ok(seed)
}

fn read_u32(buf: &[u8], off: &mut usize) -> Option<u32> {
    if buf.len() < *off + 4 {
        return None;
    }
    let v = u32::from_be_bytes([buf[*off], buf[*off + 1], buf[*off + 2], buf[*off + 3]]);
    *off += 4;
    Some(v)
}

fn read_ssh_string<'a>(buf: &'a [u8], off: &mut usize) -> Option<&'a [u8]> {
    let len = read_u32(buf, off)? as usize;
    if buf.len() < *off + len {
        return None;
    }
    let s = &buf[*off..*off + len];
    *off += len;
    Some(s)
}

fn base64_decode(s: &str) -> Result<Vec<u8>, &'static str> {
    const DECODE: [u8; 256] = {
        let mut t = [0xFFu8; 256];
        let src = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut i = 0usize;
        while i < 64 {
            t[src[i] as usize] = i as u8;
            i += 1;
        }
        t
    };
    let bytes = s.as_bytes();
    let len = bytes.iter().filter(|&&b| b != b'=').count();
    let mut out = Vec::with_capacity((len * 6).div_ceil(8));
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for &b in bytes {
        if b == b'=' {
            break;
        }
        let v = DECODE[b as usize];
        if v == 0xFF {
            continue;
        }
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Ok(out)
}

/// Save a 32-byte Ed25519 seed to a file in the compact `RUSSH-SEED-V1` format.
///
/// The file can be read back with [`load_ed25519_seed`].
pub fn save_seed_file(path: &std::path::Path, seed: &[u8; 32]) -> Result<(), String> {
    let mut data = b"RUSSH-SEED-V1\n".to_vec();
    data.extend_from_slice(seed);
    std::fs::write(path, &data).map_err(|e| format!("write {}: {e}", path.display()))
}

/// The default known_hosts path: `~/.russh/known_hosts`.
pub fn default_known_hosts_path() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    std::path::PathBuf::from(home)
        .join(".russh")
        .join("known_hosts")
}

/// Verify or TOFU-trust the server host key.
///
/// - Parses `~/.russh/known_hosts` (created if missing).
/// - If a matching entry is found, verifies the key matches.
/// - If no entry exists, writes one (TOFU) and prints a notice.
///
/// Returns `Ok(())` on success, `Err(String)` if the key has changed.
pub fn verify_or_trust_host_key(host: &str, port: u16, key_blob: &[u8]) -> Result<(), String> {
    use russh_auth::parse_known_hosts;

    let kh_path = default_known_hosts_path();
    if let Some(parent) = kh_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let host_key = format_known_hosts_key(key_blob)?;
    let host_pattern = if port == 22 {
        host.to_string()
    } else {
        format!("[{host}]:{port}")
    };

    let existing = std::fs::read_to_string(&kh_path).unwrap_or_default();
    let entries = parse_known_hosts(&existing).map_err(|e| format!("parse known_hosts: {e}"))?;

    // Look for a matching host entry.
    for entry in &entries {
        let matches = entry
            .host_patterns
            .iter()
            .any(|p| p == &host_pattern || p == host);
        if matches {
            // Verify key matches.
            let stored = format_known_hosts_key(&entry.key)?;
            if stored != host_key {
                return Err(format!(
                    "WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!\n\
                     Host key for '{host_pattern}' has changed.\n\
                     Stored: {stored}\n\
                     Got:    {host_key}"
                ));
            }
            return Ok(());
        }
    }

    // TOFU: no existing entry — trust and record.
    eprintln!(
        "The authenticity of host '{host_pattern}' can't be established.\n\
         Ed25519 key fingerprint: {host_key}\n\
         This key has been added to known_hosts."
    );
    let line = format!("{host_pattern} ssh-ed25519 {host_key}\n");
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&kh_path)
        .map_err(|e| format!("open known_hosts: {e}"))?;
    file.write_all(line.as_bytes())
        .map_err(|e| format!("write known_hosts: {e}"))?;
    Ok(())
}

/// Format a raw key blob as the base64-encoded string used in known_hosts.
fn format_known_hosts_key(key_blob: &[u8]) -> Result<String, String> {
    Ok(base64_encode(key_blob))
}

fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2).div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((n >> 18) & 0x3f) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[((n >> 6) & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(n & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}
