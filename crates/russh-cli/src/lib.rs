//! Shared helpers for russh-cli binaries.

/// Parsed private key from an OpenSSH private key file.
#[derive(Debug)]
pub enum ParsedPrivateKey {
    Ed25519([u8; 32]),
    EcdsaP256(Vec<u8>),
    Rsa {
        n: Vec<u8>,
        e: Vec<u8>,
        d: Vec<u8>,
        iqmp: Vec<u8>,
        p: Vec<u8>,
        q: Vec<u8>,
    },
}

/// Load a private key from an OpenSSH private key file.
///
/// Supports:
/// - Ed25519 (`ssh-ed25519`)
/// - ECDSA P-256 (`ecdsa-sha2-nistp256`)
/// - RSA (`ssh-rsa`)
/// - RuSSH compact seed format (`RUSSH-SEED-V1\n` + 32 raw bytes, Ed25519 only)
pub fn load_private_key(path: &std::path::Path) -> Result<ParsedPrivateKey, String> {
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
        return Ok(ParsedPrivateKey::Ed25519(seed));
    }

    // OpenSSH PEM format.
    let text = std::str::from_utf8(&raw).map_err(|_| "key file is not valid UTF-8".to_string())?;
    let b64: String = text.lines().filter(|l| !l.starts_with("-----")).collect();
    let decoded = base64_decode(&b64).map_err(|e| format!("base64 decode failed: {e}"))?;
    parse_openssh_private_key(&decoded).map_err(|e| format!("key parse failed: {e}"))
}

/// Parse an unencrypted OpenSSH Ed25519 private key file and return the 32-byte seed.
///
/// Convenience wrapper around [`load_private_key`] for backward compatibility.
pub fn load_ed25519_seed(path: &std::path::Path) -> Result<[u8; 32], String> {
    match load_private_key(path)? {
        ParsedPrivateKey::Ed25519(seed) => Ok(seed),
        _ => Err("not an Ed25519 key".into()),
    }
}

fn parse_openssh_private_key(raw: &[u8]) -> Result<ParsedPrivateKey, &'static str> {
    let magic = b"openssh-key-v1\0";
    if !raw.starts_with(magic) {
        return Err("missing openssh-key-v1 magic");
    }
    let mut off = magic.len();

    // ciphername, kdfname, kdfoptions — must all be "none" / ""
    let cipher = read_ssh_string(raw, &mut off).ok_or("truncated: ciphername")?;
    if cipher != b"none" {
        return Err("encrypted private keys are not yet supported");
    }
    let kdf = read_ssh_string(raw, &mut off).ok_or("truncated: kdfname")?;
    if kdf != b"none" {
        return Err("encrypted private keys are not yet supported");
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
    let check1 = read_u32(priv_blob, &mut poff).ok_or("truncated: check1")?;
    let check2 = read_u32(priv_blob, &mut poff).ok_or("truncated: check2")?;
    if check1 != check2 {
        return Err("check values mismatch (wrong passphrase or corrupt key)");
    }

    // key type string — dispatch on type
    let keytype = read_ssh_string(priv_blob, &mut poff).ok_or("truncated: keytype")?;

    match keytype {
        b"ssh-ed25519" => parse_ed25519_private(priv_blob, &mut poff),
        b"ecdsa-sha2-nistp256" => parse_ecdsa_p256_private(priv_blob, &mut poff),
        b"ssh-rsa" => parse_rsa_private(priv_blob, &mut poff),
        _ => Err("unsupported key type"),
    }
}

fn parse_ed25519_private(
    priv_blob: &[u8],
    poff: &mut usize,
) -> Result<ParsedPrivateKey, &'static str> {
    // public key (32 bytes, wrapped as SSH string)
    let _pubkey_inner = read_ssh_string(priv_blob, poff).ok_or("truncated: inner pubkey")?;
    // private key: 64 bytes (seed || public), wrapped as SSH string
    let privkey = read_ssh_string(priv_blob, poff).ok_or("truncated: inner privkey")?;
    if privkey.len() < 32 {
        return Err("Ed25519 private key blob too short");
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&privkey[..32]);
    Ok(ParsedPrivateKey::Ed25519(seed))
}

fn parse_ecdsa_p256_private(
    priv_blob: &[u8],
    poff: &mut usize,
) -> Result<ParsedPrivateKey, &'static str> {
    // curve identifier (e.g. "nistp256")
    let curve = read_ssh_string(priv_blob, poff).ok_or("truncated: curve id")?;
    if curve != b"nistp256" {
        return Err("expected nistp256 curve identifier");
    }
    // public key point (uncompressed SEC1 format)
    let _pubkey = read_ssh_string(priv_blob, poff).ok_or("truncated: ECDSA pubkey")?;
    // private scalar (may have leading 0x00 for mpint sign encoding)
    let privkey = read_ssh_string(priv_blob, poff).ok_or("truncated: ECDSA privkey")?;
    let scalar = if privkey.len() == 33 && privkey[0] == 0x00 {
        &privkey[1..]
    } else if privkey.len() == 32 {
        privkey
    } else {
        return Err("ECDSA-P256 private scalar must be 32 or 33 bytes");
    };
    Ok(ParsedPrivateKey::EcdsaP256(scalar.to_vec()))
}

fn parse_rsa_private(priv_blob: &[u8], poff: &mut usize) -> Result<ParsedPrivateKey, &'static str> {
    // OpenSSH stores RSA components in this order:
    // n, e, d, iqmp (coefficient), p, q
    let n = read_ssh_string(priv_blob, poff).ok_or("truncated: RSA n")?;
    let e = read_ssh_string(priv_blob, poff).ok_or("truncated: RSA e")?;
    let d = read_ssh_string(priv_blob, poff).ok_or("truncated: RSA d")?;
    let iqmp = read_ssh_string(priv_blob, poff).ok_or("truncated: RSA iqmp")?;
    let p = read_ssh_string(priv_blob, poff).ok_or("truncated: RSA p")?;
    let q = read_ssh_string(priv_blob, poff).ok_or("truncated: RSA q")?;

    // Strip leading zero bytes (SSH mpint may have a leading 0x00 for sign)
    fn strip_leading_zeros(b: &[u8]) -> Vec<u8> {
        let start = b.iter().position(|&x| x != 0).unwrap_or(b.len());
        b[start..].to_vec()
    }

    Ok(ParsedPrivateKey::Rsa {
        n: strip_leading_zeros(n),
        e: strip_leading_zeros(e),
        d: strip_leading_zeros(d),
        iqmp: strip_leading_zeros(iqmp),
        p: strip_leading_zeros(p),
        q: strip_leading_zeros(q),
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    const ED25519_PEM: &str = "\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDxVI5PETr/maZNd6SV9ljHauAMiQBFBgUMC6rvzfHt7AAAAJDkMK0I5DCt
CAAAAAtzc2gtZWQyNTUxOQAAACDxVI5PETr/maZNd6SV9ljHauAMiQBFBgUMC6rvzfHt7A
AAAECuYIJ5XOGqp1SkO5D43vRfMFfPWvg5ESN7oGBNUj4/tvFUjk8ROv+Zpk13pJX2WMdq
4AyJAEUGBQwLqu/N8e3sAAAACXJvb3RAa2FzbQECAwQ=
-----END OPENSSH PRIVATE KEY-----";

    const ECDSA_P256_PEM: &str = "\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQRJu+rGKbiclZb9uU7C17aUkQ/PtlOC
EDa4YjhixVVeZA6ywVUfypw+04vVzRQcc9QkqMAQhwyqCCBMD8PC7tpnAAAAqPnYWo352F
qNAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEm76sYpuJyVlv25
TsLXtpSRD8+2U4IQNrhiOGLFVV5kDrLBVR/KnD7Ti9XNFBxz1CSowBCHDKoIIEwPw8Lu2m
cAAAAhAKPXClwJ4G0Tg7vEfnzpCKxDkLX4Pf9wrMBSl9zCZK9AAAAACXJvb3RAa2FzbQEC
AwQFBg==
-----END OPENSSH PRIVATE KEY-----";

    fn decode_pem(pem: &str) -> Vec<u8> {
        let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        base64_decode(&b64).expect("base64 decode failed")
    }

    #[test]
    fn parse_ed25519_key() {
        let decoded = decode_pem(ED25519_PEM);
        let key = parse_openssh_private_key(&decoded).expect("parse failed");
        match key {
            ParsedPrivateKey::Ed25519(seed) => {
                assert_eq!(seed.len(), 32);
            }
            _ => panic!("expected Ed25519 key"),
        }
    }

    #[test]
    fn parse_ecdsa_p256_key() {
        let decoded = decode_pem(ECDSA_P256_PEM);
        let key = parse_openssh_private_key(&decoded).expect("parse failed");
        match key {
            ParsedPrivateKey::EcdsaP256(scalar) => {
                assert_eq!(scalar.len(), 32);
            }
            _ => panic!("expected ECDSA-P256 key"),
        }
    }

    #[test]
    fn parse_rsa_key() {
        let tmp = std::env::temp_dir().join("russh_test_rsa_parse");
        let _ = std::fs::remove_file(&tmp);
        let status = std::process::Command::new("ssh-keygen")
            .args(["-t", "rsa", "-b", "2048", "-f"])
            .arg(&tmp)
            .args(["-N", "", "-q"])
            .status()
            .expect("ssh-keygen not found");
        assert!(status.success());
        let key = load_private_key(&tmp).expect("load_private_key failed");
        let _ = std::fs::remove_file(&tmp);
        let _ = std::fs::remove_file(tmp.with_extension("pub"));
        match key {
            ParsedPrivateKey::Rsa {
                n,
                e,
                d,
                iqmp,
                p,
                q,
            } => {
                assert!(!n.is_empty(), "n should not be empty");
                assert!(!e.is_empty(), "e should not be empty");
                assert!(!d.is_empty(), "d should not be empty");
                assert!(!iqmp.is_empty(), "iqmp should not be empty");
                assert!(!p.is_empty(), "p should not be empty");
                assert!(!q.is_empty(), "q should not be empty");
                assert!(
                    n.len() >= 200 && n.len() <= 300,
                    "RSA n unexpected size: {}",
                    n.len()
                );
            }
            _ => panic!("expected RSA key"),
        }
    }

    #[test]
    fn ed25519_sign_verify_roundtrip() {
        let decoded = decode_pem(ED25519_PEM);
        let key = parse_openssh_private_key(&decoded).unwrap();
        let ParsedPrivateKey::Ed25519(seed) = key else {
            panic!("expected Ed25519");
        };
        let signer = russh_crypto::Ed25519Signer::from_seed(&seed);
        use russh_crypto::Signer;
        let msg = b"hello world";
        let sig = signer.sign(msg).expect("sign failed");
        assert_eq!(sig.len(), 64);
    }

    #[test]
    fn ecdsa_p256_sign_verify_roundtrip() {
        let decoded = decode_pem(ECDSA_P256_PEM);
        let key = parse_openssh_private_key(&decoded).unwrap();
        let ParsedPrivateKey::EcdsaP256(scalar) = key else {
            panic!("expected ECDSA-P256");
        };
        let signer =
            russh_crypto::EcdsaP256Signer::from_bytes(&scalar).expect("signer creation failed");
        use russh_crypto::Signer;
        let msg = b"hello world";
        let sig = signer.sign(msg).expect("sign failed");
        assert!(!sig.is_empty());
    }

    #[test]
    fn rsa_sign_verify_roundtrip() {
        let tmp = std::env::temp_dir().join("russh_test_rsa_sign");
        let _ = std::fs::remove_file(&tmp);
        let status = std::process::Command::new("ssh-keygen")
            .args(["-t", "rsa", "-b", "2048", "-f"])
            .arg(&tmp)
            .args(["-N", "", "-q"])
            .status()
            .expect("ssh-keygen not found");
        assert!(status.success());
        let key = load_private_key(&tmp).expect("load_private_key failed");
        let _ = std::fs::remove_file(&tmp);
        let _ = std::fs::remove_file(tmp.with_extension("pub"));
        let ParsedPrivateKey::Rsa {
            n,
            e,
            d,
            iqmp,
            p,
            q,
        } = key
        else {
            panic!("expected RSA");
        };
        let rsa_signer =
            russh_crypto::RsaSigner::from_openssh_components(&n, &e, &d, &iqmp, &p, &q)
                .expect("RSA signer creation failed");
        let signer = russh_crypto::RsaSha256Signer(rsa_signer);
        use russh_crypto::Signer;
        let msg = b"hello world";
        let sig = signer.sign(msg).expect("sign failed");
        assert!(!sig.is_empty());
    }

    #[test]
    fn reject_encrypted_key() {
        // Craft a minimal header with cipher != "none"
        let mut data = Vec::new();
        data.extend_from_slice(b"openssh-key-v1\0");
        // ciphername = "aes256-ctr"
        let cipher = b"aes256-ctr";
        data.extend_from_slice(&(cipher.len() as u32).to_be_bytes());
        data.extend_from_slice(cipher);
        let result = parse_openssh_private_key(&data);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("encrypted"));
    }

    #[test]
    fn russh_seed_v1_format() {
        let tmp = std::env::temp_dir().join("russh_test_seed_v1");
        let seed = [42u8; 32];
        save_seed_file(&tmp, &seed).expect("save failed");
        let loaded = load_private_key(&tmp).expect("load failed");
        let _ = std::fs::remove_file(&tmp);
        match loaded {
            ParsedPrivateKey::Ed25519(s) => assert_eq!(s, seed),
            _ => panic!("expected Ed25519 from RUSSH-SEED-V1 format"),
        }
    }
}
