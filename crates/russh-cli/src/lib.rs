//! Shared helpers for russh-cli binaries.

/// Parsed private key from an OpenSSH private key file.
#[derive(Debug)]
pub enum ParsedPrivateKey {
    Ed25519([u8; 32]),
    EcdsaP256(Vec<u8>),
    EcdsaP384(Vec<u8>),
    EcdsaP521(Vec<u8>),
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
///
/// For encrypted keys, pass `passphrase`. If `None` and the key is encrypted,
/// returns an error.
pub fn load_private_key(path: &std::path::Path) -> Result<ParsedPrivateKey, String> {
    load_private_key_with_passphrase(path, None)
}

/// Load a private key, decrypting with the given passphrase if encrypted.
pub fn load_private_key_with_passphrase(
    path: &std::path::Path,
    passphrase: Option<&[u8]>,
) -> Result<ParsedPrivateKey, String> {
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
    parse_openssh_private_key_with_passphrase(&decoded, passphrase)
        .map_err(|e| format!("key parse failed: {e}"))
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

#[cfg(test)]
fn parse_openssh_private_key(raw: &[u8]) -> Result<ParsedPrivateKey, String> {
    parse_openssh_private_key_with_passphrase(raw, None)
}

fn parse_openssh_private_key_with_passphrase(
    raw: &[u8],
    passphrase: Option<&[u8]>,
) -> Result<ParsedPrivateKey, String> {
    let magic = b"openssh-key-v1\0";
    if !raw.starts_with(magic) {
        return Err("missing openssh-key-v1 magic".into());
    }
    let mut off = magic.len();

    let cipher = read_ssh_string(raw, &mut off).ok_or("truncated: ciphername")?;
    let kdf = read_ssh_string(raw, &mut off).ok_or("truncated: kdfname")?;
    let kdfopts = read_ssh_string(raw, &mut off).ok_or("truncated: kdfoptions")?;

    // number of keys (uint32)
    let _nkeys = read_u32(raw, &mut off).ok_or("truncated: nkeys")?;

    // pubkey blob (skip)
    let _pubkey = read_ssh_string(raw, &mut off).ok_or("truncated: pubkey blob")?;

    // private section blob
    let priv_blob_encrypted = read_ssh_string(raw, &mut off).ok_or("truncated: private blob")?;

    let priv_blob: Vec<u8> = if cipher == b"none" && kdf == b"none" {
        priv_blob_encrypted.to_vec()
    } else if kdf == b"bcrypt" {
        let passphrase = passphrase.ok_or("key is encrypted; passphrase required")?;
        decrypt_private_section(cipher, kdfopts, passphrase, priv_blob_encrypted)?
    } else {
        return Err(format!("unsupported KDF: {}", String::from_utf8_lossy(kdf)));
    };

    let mut poff = 0usize;

    // check1, check2
    let check1 = read_u32(&priv_blob, &mut poff).ok_or("truncated: check1")?;
    let check2 = read_u32(&priv_blob, &mut poff).ok_or("truncated: check2")?;
    if check1 != check2 {
        return Err("check values mismatch (wrong passphrase or corrupt key)".into());
    }

    // key type string — dispatch on type
    let keytype = read_ssh_string(&priv_blob, &mut poff).ok_or("truncated: keytype")?;

    match keytype {
        b"ssh-ed25519" => parse_ed25519_private(&priv_blob, &mut poff).map_err(|e| e.into()),
        b"ecdsa-sha2-nistp256" => {
            parse_ecdsa_private(&priv_blob, &mut poff, b"nistp256", 32, |s| {
                ParsedPrivateKey::EcdsaP256(s)
            })
            .map_err(|e| e.into())
        }
        b"ecdsa-sha2-nistp384" => {
            parse_ecdsa_private(&priv_blob, &mut poff, b"nistp384", 48, |s| {
                ParsedPrivateKey::EcdsaP384(s)
            })
            .map_err(|e| e.into())
        }
        b"ecdsa-sha2-nistp521" => {
            parse_ecdsa_private(&priv_blob, &mut poff, b"nistp521", 66, |s| {
                ParsedPrivateKey::EcdsaP521(s)
            })
            .map_err(|e| e.into())
        }
        b"ssh-rsa" => parse_rsa_private(&priv_blob, &mut poff).map_err(|e| e.into()),
        _ => Err("unsupported key type".into()),
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

fn parse_ecdsa_private(
    priv_blob: &[u8],
    poff: &mut usize,
    expected_curve: &[u8],
    scalar_len: usize,
    wrap: fn(Vec<u8>) -> ParsedPrivateKey,
) -> Result<ParsedPrivateKey, &'static str> {
    let curve = read_ssh_string(priv_blob, poff).ok_or("truncated: curve id")?;
    if curve != expected_curve {
        return Err("unexpected curve identifier");
    }
    // public key point (uncompressed SEC1 format)
    let _pubkey = read_ssh_string(priv_blob, poff).ok_or("truncated: ECDSA pubkey")?;
    // private scalar (may have leading 0x00 for mpint sign encoding)
    let privkey = read_ssh_string(priv_blob, poff).ok_or("truncated: ECDSA privkey")?;
    let scalar = if privkey.len() == scalar_len + 1 && privkey[0] == 0x00 {
        &privkey[1..]
    } else if privkey.len() == scalar_len {
        privkey
    } else {
        return Err("ECDSA private scalar has unexpected length");
    };
    Ok(wrap(scalar.to_vec()))
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

/// Decrypt the private section of an OpenSSH encrypted key.
///
/// Supports aes256-ctr and aes256-cbc ciphers with bcrypt KDF.
fn decrypt_private_section(
    cipher_name: &[u8],
    kdfopts: &[u8],
    passphrase: &[u8],
    encrypted: &[u8],
) -> Result<Vec<u8>, String> {
    use aes::cipher::KeyIvInit;
    use zeroize::Zeroize;

    // Parse KDF options: string(salt) || uint32(rounds)
    let mut koff = 0usize;
    let salt = read_ssh_string(kdfopts, &mut koff).ok_or("truncated: KDF salt")?;
    let rounds = read_u32(kdfopts, &mut koff).ok_or("truncated: KDF rounds")?;

    // Determine key_len and iv_len from cipher
    let (key_len, iv_len) = match cipher_name {
        b"aes256-ctr" | b"aes256-cbc" => (32, 16),
        b"aes128-ctr" | b"aes128-cbc" => (16, 16),
        _ => {
            return Err(format!(
                "unsupported cipher for encrypted key: {}",
                String::from_utf8_lossy(cipher_name)
            ));
        }
    };

    // Derive key material via bcrypt-pbkdf
    let mut derived = vec![0u8; key_len + iv_len];
    bcrypt_pbkdf::bcrypt_pbkdf(passphrase, salt, rounds, &mut derived)
        .map_err(|e| format!("bcrypt-pbkdf failed: {e}"))?;
    let key = &derived[..key_len];
    let iv = &derived[key_len..];

    // Decrypt
    let mut plaintext = encrypted.to_vec();
    match cipher_name {
        b"aes256-ctr" => {
            type Aes256Ctr = ctr::Ctr64BE<aes::Aes256>;
            let mut cipher = Aes256Ctr::new(key.into(), iv.into());
            aes::cipher::StreamCipher::apply_keystream(&mut cipher, &mut plaintext);
        }
        b"aes128-ctr" => {
            type Aes128Ctr = ctr::Ctr64BE<aes::Aes128>;
            let mut cipher = Aes128Ctr::new(key.into(), iv.into());
            aes::cipher::StreamCipher::apply_keystream(&mut cipher, &mut plaintext);
        }
        b"aes256-cbc" | b"aes128-cbc" => {
            return Err(format!(
                "CBC cipher for encrypted keys is not yet supported ({})",
                String::from_utf8_lossy(cipher_name)
            ));
        }
        _ => return Err("unsupported cipher".into()),
    }

    // Zeroize derived key material
    derived.zeroize();

    Ok(plaintext)
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
    fn reject_encrypted_key_without_passphrase() {
        // Generate an encrypted ed25519 key with ssh-keygen
        let tmp = std::env::temp_dir().join("russh_test_encrypted_reject");
        let _ = std::fs::remove_file(&tmp);
        let _ = std::fs::remove_file(tmp.with_extension("pub"));
        let status = std::process::Command::new("ssh-keygen")
            .args(["-t", "ed25519", "-f"])
            .arg(&tmp)
            .args(["-N", "testpassword", "-q"])
            .status()
            .expect("ssh-keygen not found");
        assert!(status.success());
        // Loading without passphrase should fail
        let result = load_private_key(&tmp);
        let _ = std::fs::remove_file(&tmp);
        let _ = std::fs::remove_file(tmp.with_extension("pub"));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("passphrase"),
            "expected 'passphrase' in error, got: {err}"
        );
    }

    #[test]
    fn decrypt_encrypted_ed25519_key() {
        let tmp = std::env::temp_dir().join("russh_test_encrypted_ed25519");
        let _ = std::fs::remove_file(&tmp);
        let _ = std::fs::remove_file(tmp.with_extension("pub"));
        let passphrase = "test-passphrase-123";
        let status = std::process::Command::new("ssh-keygen")
            .args(["-t", "ed25519", "-f"])
            .arg(&tmp)
            .args(["-N", passphrase, "-q"])
            .status()
            .expect("ssh-keygen not found");
        assert!(status.success());
        // Correct passphrase should succeed
        let key = load_private_key_with_passphrase(&tmp, Some(passphrase.as_bytes()))
            .expect("failed to decrypt with correct passphrase");
        let _ = std::fs::remove_file(&tmp);
        let _ = std::fs::remove_file(tmp.with_extension("pub"));
        match key {
            ParsedPrivateKey::Ed25519(seed) => {
                assert_ne!(seed, [0u8; 32], "seed should not be all zeros");
            }
            _ => panic!("expected Ed25519 key"),
        }
    }

    #[test]
    fn decrypt_encrypted_rsa_key() {
        let tmp = std::env::temp_dir().join("russh_test_encrypted_rsa");
        let _ = std::fs::remove_file(&tmp);
        let _ = std::fs::remove_file(tmp.with_extension("pub"));
        let passphrase = "rsa-test-pass";
        let status = std::process::Command::new("ssh-keygen")
            .args(["-t", "rsa", "-b", "2048", "-f"])
            .arg(&tmp)
            .args(["-N", passphrase, "-q"])
            .status()
            .expect("ssh-keygen not found");
        assert!(status.success());
        let key = load_private_key_with_passphrase(&tmp, Some(passphrase.as_bytes()))
            .expect("failed to decrypt RSA key");
        let _ = std::fs::remove_file(&tmp);
        let _ = std::fs::remove_file(tmp.with_extension("pub"));
        match key {
            ParsedPrivateKey::Rsa { n, e, d, .. } => {
                assert!(!n.is_empty());
                assert!(!e.is_empty());
                assert!(!d.is_empty());
            }
            _ => panic!("expected RSA key"),
        }
    }

    #[test]
    fn decrypt_encrypted_ecdsa_key() {
        let tmp = std::env::temp_dir().join("russh_test_encrypted_ecdsa");
        let _ = std::fs::remove_file(&tmp);
        let _ = std::fs::remove_file(tmp.with_extension("pub"));
        let passphrase = "ecdsa-test-pass";
        let status = std::process::Command::new("ssh-keygen")
            .args(["-t", "ecdsa", "-b", "256", "-f"])
            .arg(&tmp)
            .args(["-N", passphrase, "-q"])
            .status()
            .expect("ssh-keygen not found");
        assert!(status.success());
        let key = load_private_key_with_passphrase(&tmp, Some(passphrase.as_bytes()))
            .expect("failed to decrypt ECDSA key");
        let _ = std::fs::remove_file(&tmp);
        let _ = std::fs::remove_file(tmp.with_extension("pub"));
        match key {
            ParsedPrivateKey::EcdsaP256(scalar) => {
                assert_eq!(scalar.len(), 32, "P-256 scalar should be 32 bytes");
            }
            _ => panic!("expected ECDSA P-256 key"),
        }
    }

    #[test]
    fn wrong_passphrase_fails() {
        let tmp = std::env::temp_dir().join("russh_test_wrong_pass");
        let _ = std::fs::remove_file(&tmp);
        let _ = std::fs::remove_file(tmp.with_extension("pub"));
        let status = std::process::Command::new("ssh-keygen")
            .args(["-t", "ed25519", "-f"])
            .arg(&tmp)
            .args(["-N", "correct-password", "-q"])
            .status()
            .expect("ssh-keygen not found");
        assert!(status.success());
        let result = load_private_key_with_passphrase(&tmp, Some(b"wrong-password"));
        let _ = std::fs::remove_file(&tmp);
        let _ = std::fs::remove_file(tmp.with_extension("pub"));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("check values mismatch") || err.contains("wrong passphrase"),
            "expected check mismatch error, got: {err}"
        );
    }

    #[test]
    fn encrypted_key_sign_verify_roundtrip() {
        let tmp = std::env::temp_dir().join("russh_test_enc_signverify");
        let _ = std::fs::remove_file(&tmp);
        let _ = std::fs::remove_file(tmp.with_extension("pub"));
        let passphrase = "sign-verify-pass";
        let status = std::process::Command::new("ssh-keygen")
            .args(["-t", "ed25519", "-f"])
            .arg(&tmp)
            .args(["-N", passphrase, "-q"])
            .status()
            .expect("ssh-keygen not found");
        assert!(status.success());
        let key = load_private_key_with_passphrase(&tmp, Some(passphrase.as_bytes()))
            .expect("decrypt failed");
        let _ = std::fs::remove_file(&tmp);
        let _ = std::fs::remove_file(tmp.with_extension("pub"));
        match key {
            ParsedPrivateKey::Ed25519(seed) => {
                let signer = russh_crypto::Ed25519Signer::from_seed(&seed);
                use russh_crypto::Signer;
                let msg = b"encrypted key test";
                let sig = signer.sign(msg).expect("sign failed");
                assert!(!sig.is_empty());
                let pub_blob = signer.public_key_blob();
                assert!(!pub_blob.is_empty());
            }
            _ => panic!("expected Ed25519"),
        }
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

    #[test]
    fn truncated_pem_missing_end_line() {
        let pem = "\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDxVI5PETr/maZNd6SV9ljHauAMiQBFBgUMC6rvzfHt7AAAAJDkMK0I5DCt
";
        let tmp = std::env::temp_dir().join("russh_test_truncated_pem");
        std::fs::write(&tmp, pem).unwrap();
        let result = load_private_key(&tmp);
        let _ = std::fs::remove_file(&tmp);
        assert!(result.is_err(), "truncated PEM should return an error");
    }

    #[test]
    fn invalid_base64_in_pem() {
        let pem = "\
-----BEGIN OPENSSH PRIVATE KEY-----
!!!not-valid-base64@@@$$$
-----END OPENSSH PRIVATE KEY-----";
        let tmp = std::env::temp_dir().join("russh_test_invalid_b64");
        std::fs::write(&tmp, pem).unwrap();
        let result = load_private_key(&tmp);
        let _ = std::fs::remove_file(&tmp);
        assert!(result.is_err(), "invalid base64 should return an error");
    }

    #[test]
    fn empty_pem_body() {
        let pem = "\
-----BEGIN OPENSSH PRIVATE KEY-----
-----END OPENSSH PRIVATE KEY-----";
        let tmp = std::env::temp_dir().join("russh_test_empty_pem");
        std::fs::write(&tmp, pem).unwrap();
        let result = load_private_key(&tmp);
        let _ = std::fs::remove_file(&tmp);
        assert!(result.is_err(), "empty PEM body should return an error");
    }

    #[test]
    fn wrong_pem_type_rsa_private_key() {
        // An RSA PRIVATE KEY PEM (PKCS#1) is not the OPENSSH PRIVATE KEY format
        let pem = "\
-----BEGIN RSA PRIVATE KEY-----
MIIBogIBAAJBALRiMLAHudeSA/x3hB2f+2NRkJfIqPpF
-----END RSA PRIVATE KEY-----";
        let tmp = std::env::temp_dir().join("russh_test_wrong_pem_type");
        std::fs::write(&tmp, pem).unwrap();
        let result = load_private_key(&tmp);
        let _ = std::fs::remove_file(&tmp);
        assert!(result.is_err(), "wrong PEM type should return an error");
        let err = result.unwrap_err();
        assert!(
            err.contains("magic") || err.contains("parse"),
            "expected magic/parse error, got: {err}"
        );
    }

    #[test]
    fn seed_v1_wrong_length_too_short() {
        let tmp = std::env::temp_dir().join("russh_test_seed_short");
        let mut data = b"RUSSH-SEED-V1\n".to_vec();
        data.extend_from_slice(&[0u8; 16]); // only 16 bytes, need 32
        std::fs::write(&tmp, &data).unwrap();
        let result = load_private_key(&tmp);
        let _ = std::fs::remove_file(&tmp);
        assert!(result.is_err(), "short seed should return an error");
        let err = result.unwrap_err();
        assert!(
            err.contains("truncated"),
            "expected 'truncated' in error, got: {err}"
        );
    }

    #[test]
    fn seed_v1_valid_roundtrip() {
        let seed = [0xAB_u8; 32];
        let tmp = std::env::temp_dir().join("russh_test_seed_roundtrip");
        save_seed_file(&tmp, &seed).expect("save failed");
        // Read back and verify the key matches
        let loaded = load_private_key(&tmp).expect("load failed");
        let _ = std::fs::remove_file(&tmp);
        let ParsedPrivateKey::Ed25519(loaded_seed) = loaded else {
            panic!("expected Ed25519 from seed file");
        };
        assert_eq!(loaded_seed, seed, "round-tripped seed must match");
        // Verify we can sign with the loaded seed
        let signer = russh_crypto::Ed25519Signer::from_seed(&loaded_seed);
        use russh_crypto::Signer;
        let sig = signer.sign(b"test").expect("sign failed");
        assert_eq!(sig.len(), 64);
    }

    #[test]
    fn encrypted_key_wrong_passphrase() {
        let tmp = std::env::temp_dir().join("russh_test_wrong_pass2");
        let _ = std::fs::remove_file(&tmp);
        let _ = std::fs::remove_file(tmp.with_extension("pub"));
        let status = std::process::Command::new("ssh-keygen")
            .args(["-t", "ed25519", "-f"])
            .arg(&tmp)
            .args(["-N", "real-passphrase", "-q"])
            .status()
            .expect("ssh-keygen not found");
        assert!(status.success());
        let result = load_private_key_with_passphrase(&tmp, Some(b"wrong-passphrase"));
        let _ = std::fs::remove_file(&tmp);
        let _ = std::fs::remove_file(tmp.with_extension("pub"));
        assert!(result.is_err(), "wrong passphrase should fail");
        let err = result.unwrap_err();
        assert!(
            err.contains("check values mismatch") || err.contains("wrong passphrase"),
            "expected decrypt error, got: {err}"
        );
    }

    #[test]
    fn key_type_detection() {
        // Ed25519
        let ed_decoded = decode_pem(ED25519_PEM);
        let ed_key = parse_openssh_private_key(&ed_decoded).unwrap();
        assert!(
            matches!(ed_key, ParsedPrivateKey::Ed25519(_)),
            "should detect Ed25519"
        );

        // ECDSA P-256
        let ec_decoded = decode_pem(ECDSA_P256_PEM);
        let ec_key = parse_openssh_private_key(&ec_decoded).unwrap();
        assert!(
            matches!(ec_key, ParsedPrivateKey::EcdsaP256(_)),
            "should detect ECDSA P-256"
        );

        // RSA (generated key)
        let tmp = std::env::temp_dir().join("russh_test_keytype_rsa");
        let _ = std::fs::remove_file(&tmp);
        let status = std::process::Command::new("ssh-keygen")
            .args(["-t", "rsa", "-b", "2048", "-f"])
            .arg(&tmp)
            .args(["-N", "", "-q"])
            .status()
            .expect("ssh-keygen not found");
        assert!(status.success());
        let rsa_key = load_private_key(&tmp).expect("load RSA failed");
        let _ = std::fs::remove_file(&tmp);
        let _ = std::fs::remove_file(tmp.with_extension("pub"));
        assert!(
            matches!(rsa_key, ParsedPrivateKey::Rsa { .. }),
            "should detect RSA"
        );
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let decoded = decode_pem(ED25519_PEM);
        let key = parse_openssh_private_key(&decoded).unwrap();
        let ParsedPrivateKey::Ed25519(seed) = key else {
            panic!("expected Ed25519");
        };
        let signer = russh_crypto::Ed25519Signer::from_seed(&seed);
        let verifier = signer.verifier();
        use russh_crypto::{Signer, Verifier};
        let msg = b"sign-verify roundtrip message";
        let sig = signer.sign(msg).expect("sign failed");
        verifier
            .verify(msg, &sig)
            .expect("verify should succeed with matching key");
    }

    #[test]
    fn verify_with_wrong_public_key() {
        // Sign with ED25519_PEM key
        let decoded_a = decode_pem(ED25519_PEM);
        let key_a = parse_openssh_private_key(&decoded_a).unwrap();
        let ParsedPrivateKey::Ed25519(seed_a) = key_a else {
            panic!("expected Ed25519");
        };
        let signer_a = russh_crypto::Ed25519Signer::from_seed(&seed_a);
        use russh_crypto::{Signer, Verifier};
        let msg = b"test message for wrong key";
        let sig = signer_a.sign(msg).expect("sign failed");

        // Create a different Ed25519 key (key B) and get its verifier
        let seed_b = [0x99u8; 32];
        let signer_b = russh_crypto::Ed25519Signer::from_seed(&seed_b);
        let verifier_b = signer_b.verifier();

        // Verification with wrong key should fail
        let result = verifier_b.verify(msg, &sig);
        assert!(result.is_err(), "verify with wrong public key should fail");
    }
}
