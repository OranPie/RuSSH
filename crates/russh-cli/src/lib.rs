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
