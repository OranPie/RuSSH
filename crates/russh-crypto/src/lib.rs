//! Cryptographic primitives for RuSSH.
//!
//! This crate provides all low-level cryptographic building blocks used
//! across the SSH library:
//!
//! | Category | Implementations |
//! |----------|----------------|
//! | AEAD ciphers | AES-256-GCM, AES-128-GCM, ChaCha20-Poly1305 |
//! | Hash | SHA-256, SHA-512 |
//! | MAC | HMAC-SHA-256, HMAC-SHA-512 |
//! | Key exchange | Curve25519-SHA256 (RFC 8731), ECDH-NIST-P256-SHA256 |
//! | Signatures | Ed25519 sign/verify |
//! | RNG | `OsRng` backed by the OS CSPRNG |
//! | Key derivation | RFC 4253 §7.2 SHA-256 label-based KDF |
//!
//! # Wire helpers
//!
//! SSH binary protocol helpers are provided for encoding/decoding SSH
//! "string" (length-prefixed) and "mpint" (multi-precision integer) types
//! as defined in RFC 4251.
//!
//! # Constant-time guarantees
//!
//! All secret comparisons use [`subtle::ConstantTimeEq`] to prevent
//! timing side-channels. HMAC verification delegates to the `hmac` crate's
//! built-in constant-time verification.
//!
//! # Zeroization
//!
//! Secret key material is wrapped in [`zeroize::Zeroizing`] or
//! `#[derive(ZeroizeOnDrop)]` so that key bytes are overwritten in memory
//! when they leave scope.
//!
//! # Example
//!
//! ```rust
//! use russh_crypto::{HashAlgorithm, Sha256};
//!
//! let digest = Sha256::digest(b"hello");
//! assert_eq!(digest.len(), 32);
//! ```

use russh_core::{AlgorithmSet, RusshError, RusshErrorCategory};
use zeroize::Zeroizing;

// ============================================================
// Policy types (unchanged from stub)
// ============================================================

/// Active cryptographic policy, including explicit legacy compatibility mode.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CryptoPolicy {
    algorithms: AlgorithmSet,
    allow_legacy: bool,
}

impl CryptoPolicy {
    #[must_use]
    pub fn secure_defaults() -> Self {
        Self {
            algorithms: AlgorithmSet::secure_defaults(),
            allow_legacy: false,
        }
    }

    #[must_use]
    pub fn legacy_compat() -> Self {
        let mut policy = Self::secure_defaults();
        policy.allow_legacy = true;
        policy
            .algorithms
            .kex
            .push("diffie-hellman-group14-sha1".to_string());
        policy.algorithms.ciphers.push("aes128-ctr".to_string());
        policy
            .algorithms
            .macs
            .push("hmac-sha1-etm@openssh.com".to_string());
        policy
    }

    #[must_use]
    pub fn algorithms(&self) -> &AlgorithmSet {
        &self.algorithms
    }

    #[must_use]
    pub fn allow_legacy(&self) -> bool {
        self.allow_legacy
    }
}

/// Key algorithms currently recognized by policy-level APIs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyAlgorithm {
    Ed25519,
    EcdsaP256,
    RsaSha2_256,
    RsaSha2_512,
}

// ============================================================
// RNG
// ============================================================

/// Random source abstraction for pluggable RNG backends.
pub trait RandomSource {
    fn fill_bytes(&mut self, target: &mut [u8]);
}

/// OS-backed cryptographically secure random source.
pub struct OsRng;

impl RandomSource for OsRng {
    fn fill_bytes(&mut self, target: &mut [u8]) {
        getrandom::getrandom(target).expect("getrandom::getrandom failed");
    }
}

/// Deterministic, non-cryptographic random source for tests and bootstrap.
#[cfg(any(test, feature = "test-utils"))]
#[derive(Clone, Debug)]
pub struct LcgRandom {
    state: u64,
}

#[cfg(any(test, feature = "test-utils"))]
impl LcgRandom {
    #[must_use]
    pub fn seeded(seed: u64) -> Self {
        Self { state: seed }
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl RandomSource for LcgRandom {
    fn fill_bytes(&mut self, target: &mut [u8]) {
        for byte in target {
            self.state = self.state.wrapping_mul(6364136223846793005).wrapping_add(1);
            *byte = (self.state >> 24) as u8;
        }
    }
}

// ============================================================
// Adapter: wrap &mut dyn RandomSource as rand_core RNG
// (needed for p256 / ed25519-dalek key generation)
// ============================================================

struct DynRngAdapter<'a> {
    inner: &'a mut dyn RandomSource,
}

impl rand_core::RngCore for DynRngAdapter<'_> {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.inner.fill_bytes(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.inner.fill_bytes(dest);
        Ok(())
    }
}

// Safety note: this marker asserts the inner source is crypto-quality.
// In production, only OsRng is passed here; using LcgRandom would be
// cryptographically insecure but is not a memory-safety issue.
impl rand_core::CryptoRng for DynRngAdapter<'_> {}

// ============================================================
// Constant-time utilities
// ============================================================

/// Constant-time byte-slice equality check.
///
/// # Constant-time note
///
/// Uses `subtle::ConstantTimeEq` to prevent timing side-channels when
/// comparing secret values such as MAC tags or key blobs.
#[must_use]
pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    use subtle::ConstantTimeEq as _;
    left.ct_eq(right).into()
}

/// Securely wipe secret bytes from memory.
pub fn wipe_secret(bytes: &mut [u8]) {
    use zeroize::Zeroize as _;
    bytes.zeroize();
}

// ============================================================
// Internal error helper
// ============================================================

fn crypto_error(msg: &'static str) -> RusshError {
    RusshError::new(RusshErrorCategory::Crypto, msg)
}

// ============================================================
// Hash algorithms
// ============================================================

pub trait HashAlgorithm {
    fn digest(data: &[u8]) -> Vec<u8>;
    fn digest_multi(parts: &[&[u8]]) -> Vec<u8>;
}

pub struct Sha256;
pub struct Sha512;

impl HashAlgorithm for Sha256 {
    fn digest(data: &[u8]) -> Vec<u8> {
        use sha2::Digest as _;
        sha2::Sha256::digest(data).to_vec()
    }

    fn digest_multi(parts: &[&[u8]]) -> Vec<u8> {
        use sha2::Digest as _;
        let mut h = sha2::Sha256::new();
        for part in parts {
            h.update(part);
        }
        h.finalize().to_vec()
    }
}

impl HashAlgorithm for Sha512 {
    fn digest(data: &[u8]) -> Vec<u8> {
        use sha2::Digest as _;
        sha2::Sha512::digest(data).to_vec()
    }

    fn digest_multi(parts: &[&[u8]]) -> Vec<u8> {
        use sha2::Digest as _;
        let mut h = sha2::Sha512::new();
        for part in parts {
            h.update(part);
        }
        h.finalize().to_vec()
    }
}

// ============================================================
// MAC algorithms
// ============================================================

pub trait MacAlgorithm {
    fn sign(key: &[u8], data: &[u8]) -> Vec<u8>;
    /// Constant-time tag verification.
    fn verify(key: &[u8], data: &[u8], tag: &[u8]) -> bool;
}

pub struct HmacSha256;
pub struct HmacSha512;

impl MacAlgorithm for HmacSha256 {
    fn sign(key: &[u8], data: &[u8]) -> Vec<u8> {
        use hmac::Mac;
        let mut mac: hmac::Hmac<sha2::Sha256> =
            <hmac::Hmac<sha2::Sha256> as hmac::Mac>::new_from_slice(key)
                .expect("HMAC accepts any key length");
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    }

    /// Constant-time tag verification.
    ///
    /// # Constant-time note
    ///
    /// Uses `subtle::ConstantTimeEq` to compare the computed and provided
    /// tags, preventing timing side-channels.
    fn verify(key: &[u8], data: &[u8], tag: &[u8]) -> bool {
        use hmac::Mac;
        use subtle::ConstantTimeEq as _;
        let mut mac: hmac::Hmac<sha2::Sha256> =
            <hmac::Hmac<sha2::Sha256> as hmac::Mac>::new_from_slice(key)
                .expect("HMAC accepts any key length");
        mac.update(data);
        let computed = mac.finalize().into_bytes();
        computed.as_slice().ct_eq(tag).into()
    }
}

impl MacAlgorithm for HmacSha512 {
    fn sign(key: &[u8], data: &[u8]) -> Vec<u8> {
        use hmac::Mac;
        let mut mac: hmac::Hmac<sha2::Sha512> =
            <hmac::Hmac<sha2::Sha512> as hmac::Mac>::new_from_slice(key)
                .expect("HMAC accepts any key length");
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    }

    /// Constant-time tag verification.
    ///
    /// # Constant-time note
    ///
    /// Uses `subtle::ConstantTimeEq` to compare the computed and provided
    /// tags, preventing timing side-channels.
    fn verify(key: &[u8], data: &[u8], tag: &[u8]) -> bool {
        use hmac::Mac;
        use subtle::ConstantTimeEq as _;
        let mut mac: hmac::Hmac<sha2::Sha512> =
            <hmac::Hmac<sha2::Sha512> as hmac::Mac>::new_from_slice(key)
                .expect("HMAC accepts any key length");
        mac.update(data);
        let computed = mac.finalize().into_bytes();
        computed.as_slice().ct_eq(tag).into()
    }
}

// ============================================================
// AEAD ciphers
// ============================================================

use aes_gcm::{
    Aes128Gcm, Aes256Gcm, KeyInit,
    aead::generic_array::GenericArray,
    aead::{Aead, Payload},
};
use chacha20poly1305::ChaCha20Poly1305;

pub trait AeadCipher: Sized {
    fn key_len() -> usize;
    fn nonce_len() -> usize;
    fn new(key: &[u8]) -> Result<Self, RusshError>;
    /// Encrypt `plaintext`, appending the authentication tag. Returns ciphertext || tag.
    fn seal(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, RusshError>;
    /// Decrypt `ciphertext_with_tag`, verifying the authentication tag.
    fn open(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext_with_tag: &[u8],
    ) -> Result<Vec<u8>, RusshError>;
}

pub struct Aes256GcmCipher {
    inner: Aes256Gcm,
}

pub struct Aes128GcmCipher {
    inner: Aes128Gcm,
}

pub struct ChaCha20Poly1305Cipher {
    inner: ChaCha20Poly1305,
}

impl AeadCipher for Aes256GcmCipher {
    fn key_len() -> usize {
        32
    }
    fn nonce_len() -> usize {
        12
    }

    fn new(key: &[u8]) -> Result<Self, RusshError> {
        Aes256Gcm::new_from_slice(key)
            .map(|inner| Self { inner })
            .map_err(|_| crypto_error("AES-256-GCM key must be 32 bytes"))
    }

    fn seal(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, RusshError> {
        if nonce.len() != 12 {
            return Err(crypto_error("AES-256-GCM nonce must be 12 bytes"));
        }
        let nonce = GenericArray::from_slice(nonce);
        self.inner
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| crypto_error("AES-256-GCM encryption failed"))
    }

    fn open(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext_with_tag: &[u8],
    ) -> Result<Vec<u8>, RusshError> {
        if nonce.len() != 12 {
            return Err(crypto_error("AES-256-GCM nonce must be 12 bytes"));
        }
        let nonce = GenericArray::from_slice(nonce);
        self.inner
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext_with_tag,
                    aad,
                },
            )
            .map_err(|_| crypto_error("AES-256-GCM decryption/authentication failed"))
    }
}

impl AeadCipher for Aes128GcmCipher {
    fn key_len() -> usize {
        16
    }
    fn nonce_len() -> usize {
        12
    }

    fn new(key: &[u8]) -> Result<Self, RusshError> {
        Aes128Gcm::new_from_slice(key)
            .map(|inner| Self { inner })
            .map_err(|_| crypto_error("AES-128-GCM key must be 16 bytes"))
    }

    fn seal(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, RusshError> {
        if nonce.len() != 12 {
            return Err(crypto_error("AES-128-GCM nonce must be 12 bytes"));
        }
        let nonce = GenericArray::from_slice(nonce);
        self.inner
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| crypto_error("AES-128-GCM encryption failed"))
    }

    fn open(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext_with_tag: &[u8],
    ) -> Result<Vec<u8>, RusshError> {
        if nonce.len() != 12 {
            return Err(crypto_error("AES-128-GCM nonce must be 12 bytes"));
        }
        let nonce = GenericArray::from_slice(nonce);
        self.inner
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext_with_tag,
                    aad,
                },
            )
            .map_err(|_| crypto_error("AES-128-GCM decryption/authentication failed"))
    }
}

impl AeadCipher for ChaCha20Poly1305Cipher {
    fn key_len() -> usize {
        32
    }
    fn nonce_len() -> usize {
        12
    }

    fn new(key: &[u8]) -> Result<Self, RusshError> {
        use chacha20poly1305::KeyInit as _;
        ChaCha20Poly1305::new_from_slice(key)
            .map(|inner| Self { inner })
            .map_err(|_| crypto_error("ChaCha20Poly1305 key must be 32 bytes"))
    }

    fn seal(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, RusshError> {
        use chacha20poly1305::aead::Aead as _;
        if nonce.len() != 12 {
            return Err(crypto_error("ChaCha20Poly1305 nonce must be 12 bytes"));
        }
        let nonce = chacha20poly1305::aead::generic_array::GenericArray::from_slice(nonce);
        self.inner
            .encrypt(
                nonce,
                chacha20poly1305::aead::Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| crypto_error("ChaCha20Poly1305 encryption failed"))
    }

    fn open(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext_with_tag: &[u8],
    ) -> Result<Vec<u8>, RusshError> {
        use chacha20poly1305::aead::Aead as _;
        if nonce.len() != 12 {
            return Err(crypto_error("ChaCha20Poly1305 nonce must be 12 bytes"));
        }
        let nonce = chacha20poly1305::aead::generic_array::GenericArray::from_slice(nonce);
        self.inner
            .decrypt(
                nonce,
                chacha20poly1305::aead::Payload {
                    msg: ciphertext_with_tag,
                    aad,
                },
            )
            .map_err(|_| crypto_error("ChaCha20Poly1305 decryption/authentication failed"))
    }
}

// ============================================================
// AES-CTR stream ciphers (non-AEAD, used with ETM MACs)
// ============================================================

/// A non-AEAD stream cipher for encrypt-then-MAC mode.
pub trait StreamCipher: Sized {
    fn key_len() -> usize;
    fn iv_len() -> usize;
    fn mac_key_len() -> usize;
    fn mac_len() -> usize;
    fn new(key: &[u8], iv: &[u8]) -> Result<Self, RusshError>;
    fn encrypt_in_place(&mut self, data: &mut [u8]);
    fn decrypt_in_place(&mut self, data: &mut [u8]);
}

type Aes256Ctr = ctr::Ctr64BE<aes::Aes256>;
type Aes128Ctr = ctr::Ctr64BE<aes::Aes128>;

pub struct Aes256CtrCipher {
    cipher: Aes256Ctr,
}

pub struct Aes128CtrCipher {
    cipher: Aes128Ctr,
}

impl StreamCipher for Aes256CtrCipher {
    fn key_len() -> usize {
        32
    }
    fn iv_len() -> usize {
        16
    }
    fn mac_key_len() -> usize {
        32
    }
    fn mac_len() -> usize {
        32
    }

    fn new(key: &[u8], iv: &[u8]) -> Result<Self, RusshError> {
        use ctr::cipher::KeyIvInit as _;
        let cipher = Aes256Ctr::new_from_slices(key, iv)
            .map_err(|_| crypto_error("AES-256-CTR key/IV length mismatch"))?;
        Ok(Self { cipher })
    }

    fn encrypt_in_place(&mut self, data: &mut [u8]) {
        use ctr::cipher::StreamCipher as _;
        self.cipher.apply_keystream(data);
    }

    fn decrypt_in_place(&mut self, data: &mut [u8]) {
        use ctr::cipher::StreamCipher as _;
        self.cipher.apply_keystream(data);
    }
}

impl StreamCipher for Aes128CtrCipher {
    fn key_len() -> usize {
        16
    }
    fn iv_len() -> usize {
        16
    }
    fn mac_key_len() -> usize {
        32
    }
    fn mac_len() -> usize {
        32
    }

    fn new(key: &[u8], iv: &[u8]) -> Result<Self, RusshError> {
        use ctr::cipher::KeyIvInit as _;
        let cipher = Aes128Ctr::new_from_slices(key, iv)
            .map_err(|_| crypto_error("AES-128-CTR key/IV length mismatch"))?;
        Ok(Self { cipher })
    }

    fn encrypt_in_place(&mut self, data: &mut [u8]) {
        use ctr::cipher::StreamCipher as _;
        self.cipher.apply_keystream(data);
    }

    fn decrypt_in_place(&mut self, data: &mut [u8]) {
        use ctr::cipher::StreamCipher as _;
        self.cipher.apply_keystream(data);
    }
}

// ============================================================
// Key exchange
// ============================================================

/// Ephemeral key pair produced by a key-exchange algorithm.
pub struct KexKeyPair {
    pub public_key: Vec<u8>,
    /// Raw secret bytes; zeroized on drop via `Zeroizing`.
    secret: Zeroizing<Vec<u8>>,
}

impl KexKeyPair {
    /// Return the raw secret bytes for use in `compute_shared_secret`.
    pub fn secret_bytes(&self) -> &[u8] {
        &self.secret
    }
}

/// Output of a completed key exchange; zeroized on drop.
pub struct KexResult {
    pub shared_secret: Zeroizing<Vec<u8>>,
}

pub trait KeyExchangeAlgorithm {
    fn generate_keypair(rng: &mut dyn RandomSource) -> KexKeyPair;
    fn compute_shared_secret(
        local_secret: &[u8],
        remote_public: &[u8],
    ) -> Result<KexResult, RusshError>;
}

/// X25519 key exchange (curve25519-sha256).
pub struct Curve25519Sha256;

impl KeyExchangeAlgorithm for Curve25519Sha256 {
    fn generate_keypair(rng: &mut dyn RandomSource) -> KexKeyPair {
        let mut secret_bytes = [0u8; 32];
        rng.fill_bytes(&mut secret_bytes);
        let secret = x25519_dalek::StaticSecret::from(secret_bytes);
        let public = x25519_dalek::PublicKey::from(&secret);
        KexKeyPair {
            public_key: public.as_bytes().to_vec(),
            secret: Zeroizing::new(secret.as_bytes().to_vec()),
        }
    }

    fn compute_shared_secret(
        local_secret: &[u8],
        remote_public: &[u8],
    ) -> Result<KexResult, RusshError> {
        let secret_arr: [u8; 32] = local_secret
            .try_into()
            .map_err(|_| crypto_error("Curve25519 secret must be 32 bytes"))?;
        let public_arr: [u8; 32] = remote_public
            .try_into()
            .map_err(|_| crypto_error("Curve25519 public key must be 32 bytes"))?;
        let secret = x25519_dalek::StaticSecret::from(secret_arr);
        let remote = x25519_dalek::PublicKey::from(public_arr);
        let shared = secret.diffie_hellman(&remote);
        Ok(KexResult {
            shared_secret: Zeroizing::new(shared.as_bytes().to_vec()),
        })
    }
}

/// ECDH on NIST P-256 (ecdh-sha2-nistp256).
pub struct EcdhNistp256;

impl KeyExchangeAlgorithm for EcdhNistp256 {
    fn generate_keypair(rng: &mut dyn RandomSource) -> KexKeyPair {
        use p256::elliptic_curve::sec1::ToEncodedPoint as _;
        let mut adapter = DynRngAdapter { inner: rng };
        let secret = p256::SecretKey::random(&mut adapter);
        let public = secret.public_key();
        // Uncompressed SEC1 point: 0x04 || x || y (65 bytes for P-256)
        let encoded = public.to_encoded_point(false);
        KexKeyPair {
            public_key: encoded.as_bytes().to_vec(),
            secret: Zeroizing::new(secret.to_bytes().to_vec()),
        }
    }

    fn compute_shared_secret(
        local_secret: &[u8],
        remote_public: &[u8],
    ) -> Result<KexResult, RusshError> {
        let secret = p256::SecretKey::from_slice(local_secret)
            .map_err(|_| crypto_error("invalid P-256 secret key"))?;
        let public = p256::PublicKey::from_sec1_bytes(remote_public)
            .map_err(|_| crypto_error("invalid P-256 public key (SEC1)"))?;
        let shared = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), public.as_affine());
        Ok(KexResult {
            shared_secret: Zeroizing::new(shared.raw_secret_bytes().to_vec()),
        })
    }
}

/// Diffie-Hellman group 14 with SHA-256 (diffie-hellman-group14-sha256).
///
/// Uses the 2048-bit MODP group from RFC 3526 §3.
pub struct DhGroup14Sha256;

/// RFC 3526 §3: 2048-bit MODP Group (group 14) prime, big-endian.
const DH_GROUP14_PRIME: &[u8] = &[
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
    0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
    0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
    0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45, 0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
    0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
    0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D, 0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05,
    0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
    0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB,
    0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D, 0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04,
    0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x18, 0x21, 0x7C, 0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
    0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03, 0x9B, 0x27, 0x83, 0xA2, 0xEC, 0x07, 0xA2, 0x8F,
    0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9, 0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18,
    0x39, 0x95, 0x49, 0x7C, 0xEA, 0x95, 0x6A, 0xE5, 0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
    0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAC, 0xAA, 0x68, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
];

impl KeyExchangeAlgorithm for DhGroup14Sha256 {
    fn generate_keypair(rng: &mut dyn RandomSource) -> KexKeyPair {
        let p = rsa::BigUint::from_bytes_be(DH_GROUP14_PRIME);
        let g = rsa::BigUint::from(2u32);

        // Generate random exponent x in [2, p-2]
        let mut x_bytes = [0u8; 256];
        rng.fill_bytes(&mut x_bytes);
        let x = rsa::BigUint::from_bytes_be(&x_bytes) % (&p - 2u32) + 2u32;

        // Public value: e = g^x mod p
        let e = g.modpow(&x, &p);

        KexKeyPair {
            public_key: e.to_bytes_be(),
            secret: Zeroizing::new(x.to_bytes_be()),
        }
    }

    fn compute_shared_secret(
        local_secret: &[u8],
        remote_public: &[u8],
    ) -> Result<KexResult, RusshError> {
        let p = rsa::BigUint::from_bytes_be(DH_GROUP14_PRIME);
        let x = rsa::BigUint::from_bytes_be(local_secret);
        let f = rsa::BigUint::from_bytes_be(remote_public);

        // Validate: 1 < f < p-1
        if f <= rsa::BigUint::from(1u32) || f >= (&p - 1u32) {
            return Err(crypto_error("DH public value out of safe range"));
        }

        // Shared secret: K = f^x mod p
        let k = f.modpow(&x, &p);
        Ok(KexResult {
            shared_secret: Zeroizing::new(k.to_bytes_be()),
        })
    }
}

// ============================================================
// Signing / verification
// ============================================================

pub trait Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, RusshError>;
    /// SSH wire-format public key blob.
    fn public_key_blob(&self) -> Vec<u8>;
    fn algorithm_name(&self) -> &'static str;
}

pub trait Verifier {
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), RusshError>;
    fn algorithm_name(&self) -> &'static str;
}

pub struct Ed25519Signer {
    key: ed25519_dalek::SigningKey,
}

impl Ed25519Signer {
    /// Generate a new Ed25519 signing key from the provided RNG.
    pub fn generate(rng: &mut dyn RandomSource) -> Self {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        Self {
            key: ed25519_dalek::SigningKey::from_bytes(&seed),
        }
    }

    /// Construct from a 32-byte seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            key: ed25519_dalek::SigningKey::from_bytes(seed),
        }
    }

    pub fn verifier(&self) -> Ed25519Verifier {
        Ed25519Verifier {
            key: self.key.verifying_key(),
        }
    }
}

impl Signer for Ed25519Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, RusshError> {
        use ed25519_dalek::Signer as _;
        let sig: ed25519_dalek::Signature = self.key.sign(message);
        Ok(sig.to_bytes().to_vec())
    }

    fn public_key_blob(&self) -> Vec<u8> {
        // SSH wire format: [u32 len "ssh-ed25519"][u32 len raw_32_bytes]
        let mut blob = Vec::new();
        blob.extend_from_slice(&encode_ssh_string(b"ssh-ed25519"));
        blob.extend_from_slice(&encode_ssh_string(self.key.verifying_key().as_bytes()));
        blob
    }

    fn algorithm_name(&self) -> &'static str {
        "ssh-ed25519"
    }
}

pub struct Ed25519Verifier {
    key: ed25519_dalek::VerifyingKey,
}

impl Ed25519Verifier {
    /// Construct from a 32-byte compressed public key.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, RusshError> {
        ed25519_dalek::VerifyingKey::from_bytes(bytes)
            .map(|key| Self { key })
            .map_err(|_| crypto_error("invalid Ed25519 verifying key"))
    }
}

impl Verifier for Ed25519Verifier {
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), RusshError> {
        use ed25519_dalek::Verifier as _;
        let sig_bytes: [u8; 64] = signature
            .try_into()
            .map_err(|_| crypto_error("Ed25519 signature must be 64 bytes"))?;
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        self.key
            .verify(message, &sig)
            .map_err(|_| crypto_error("Ed25519 signature verification failed"))
    }

    fn algorithm_name(&self) -> &'static str {
        "ssh-ed25519"
    }
}

// ============================================================
// ECDSA-P256 signing / verification
// ============================================================

pub struct EcdsaP256Signer {
    key: p256::ecdsa::SigningKey,
}

impl EcdsaP256Signer {
    /// Generate a new ECDSA-P256 signing key from the provided RNG.
    pub fn generate(rng: &mut dyn RandomSource) -> Self {
        let mut adapter = DynRngAdapter { inner: rng };
        let key = p256::ecdsa::SigningKey::random(&mut adapter);
        Self { key }
    }

    /// Construct from raw 32-byte secret scalar.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RusshError> {
        p256::ecdsa::SigningKey::from_bytes(bytes.into())
            .map(|key| Self { key })
            .map_err(|_| crypto_error("invalid ECDSA-P256 secret key"))
    }

    pub fn verifier(&self) -> EcdsaP256Verifier {
        EcdsaP256Verifier {
            key: *self.key.verifying_key(),
        }
    }
}

impl Signer for EcdsaP256Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, RusshError> {
        use p256::ecdsa::signature::Signer as _;
        let sig: p256::ecdsa::Signature = self.key.sign(message);
        // SSH wire format for ECDSA: the signature is DER-encoded (r, s)
        // but SSH uses a custom format: string "ecdsa-sha2-nistp256" + string (mpint r + mpint s)
        // We return the raw (r || s) fixed-size representation (64 bytes) which callers
        // wrap into SSH wire format.
        Ok(sig.to_bytes().to_vec())
    }

    fn public_key_blob(&self) -> Vec<u8> {
        // SSH wire format: string "ecdsa-sha2-nistp256" + string "nistp256" + string <SEC1 uncompressed point>
        let mut blob = Vec::new();
        blob.extend_from_slice(&encode_ssh_string(b"ecdsa-sha2-nistp256"));
        blob.extend_from_slice(&encode_ssh_string(b"nistp256"));
        let point = self.key.verifying_key().to_encoded_point(false);
        blob.extend_from_slice(&encode_ssh_string(point.as_bytes()));
        blob
    }

    fn algorithm_name(&self) -> &'static str {
        "ecdsa-sha2-nistp256"
    }
}

pub struct EcdsaP256Verifier {
    key: p256::ecdsa::VerifyingKey,
}

impl EcdsaP256Verifier {
    /// Construct from an uncompressed SEC1 public key point (65 bytes: 0x04 || x || y).
    pub fn from_sec1_bytes(bytes: &[u8]) -> Result<Self, RusshError> {
        p256::ecdsa::VerifyingKey::from_sec1_bytes(bytes)
            .map(|key| Self { key })
            .map_err(|_| crypto_error("invalid ECDSA-P256 public key"))
    }
}

impl Verifier for EcdsaP256Verifier {
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), RusshError> {
        use p256::ecdsa::signature::Verifier as _;
        // SSH ECDSA signatures are (r || s), each 32 bytes for P-256
        if signature.len() != 64 {
            return Err(crypto_error("ECDSA-P256 signature must be 64 bytes"));
        }
        let sig = p256::ecdsa::Signature::from_bytes(signature.into())
            .map_err(|_| crypto_error("invalid ECDSA-P256 signature encoding"))?;
        self.key
            .verify(message, &sig)
            .map_err(|_| crypto_error("ECDSA-P256 signature verification failed"))
    }

    fn algorithm_name(&self) -> &'static str {
        "ecdsa-sha2-nistp256"
    }
}

// ============================================================
// RSA signing / verification (rsa-sha2-256, rsa-sha2-512)
// ============================================================

pub struct RsaSigner {
    key: rsa::RsaPrivateKey,
}

impl RsaSigner {
    /// Generate a new 3072-bit RSA key from the provided RNG.
    pub fn generate(rng: &mut dyn RandomSource) -> Result<Self, RusshError> {
        let mut adapter = DynRngAdapter { inner: rng };
        let key = rsa::RsaPrivateKey::new(&mut adapter, 3072)
            .map_err(|_| crypto_error("RSA key generation failed"))?;
        Ok(Self { key })
    }

    /// Construct from DER-encoded PKCS#1 private key bytes.
    pub fn from_pkcs1_der(der: &[u8]) -> Result<Self, RusshError> {
        use rsa::pkcs1::DecodeRsaPrivateKey as _;
        let key = rsa::RsaPrivateKey::from_pkcs1_der(der)
            .map_err(|_| crypto_error("invalid RSA PKCS#1 DER private key"))?;
        use rsa::traits::PublicKeyParts as _;
        let bits = key.n().bits();
        if bits < 2048 {
            return Err(crypto_error("RSA key must be at least 2048 bits"));
        }
        Ok(Self { key })
    }

    /// Return the public key for verification.
    pub fn verifier_sha256(&self) -> RsaVerifier {
        RsaVerifier {
            key: self.key.to_public_key(),
            sha512: false,
        }
    }

    pub fn verifier_sha512(&self) -> RsaVerifier {
        RsaVerifier {
            key: self.key.to_public_key(),
            sha512: true,
        }
    }

    /// SSH wire-format public key blob for this RSA key.
    pub fn public_key_blob(&self) -> Vec<u8> {
        rsa_public_key_blob(&self.key.to_public_key())
    }

    fn sign_sha256(&self, message: &[u8]) -> Result<Vec<u8>, RusshError> {
        use sha2::Digest as _;
        let hash = sha2::Sha256::digest(message);
        self.key
            .sign(rsa::Pkcs1v15Sign::new::<sha2::Sha256>(), &hash)
            .map_err(|_| crypto_error("RSA-SHA256 signing failed"))
    }

    fn sign_sha512(&self, message: &[u8]) -> Result<Vec<u8>, RusshError> {
        use sha2::Digest as _;
        let hash = sha2::Sha512::digest(message);
        self.key
            .sign(rsa::Pkcs1v15Sign::new::<sha2::Sha512>(), &hash)
            .map_err(|_| crypto_error("RSA-SHA512 signing failed"))
    }
}

/// Sign with rsa-sha2-256.
pub struct RsaSha256Signer(pub RsaSigner);

impl Signer for RsaSha256Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, RusshError> {
        self.0.sign_sha256(message)
    }

    fn public_key_blob(&self) -> Vec<u8> {
        self.0.public_key_blob()
    }

    fn algorithm_name(&self) -> &'static str {
        "rsa-sha2-256"
    }
}

/// Sign with rsa-sha2-512.
pub struct RsaSha512Signer(pub RsaSigner);

impl Signer for RsaSha512Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, RusshError> {
        self.0.sign_sha512(message)
    }

    fn public_key_blob(&self) -> Vec<u8> {
        self.0.public_key_blob()
    }

    fn algorithm_name(&self) -> &'static str {
        "rsa-sha2-512"
    }
}

pub struct RsaVerifier {
    key: rsa::RsaPublicKey,
    sha512: bool,
}

impl RsaVerifier {
    /// Construct from SSH wire-format public key blob (string "ssh-rsa" + mpint e + mpint n).
    pub fn from_ssh_blob(blob: &[u8]) -> Result<Self, RusshError> {
        let mut offset = 0;
        let algo = decode_ssh_string(blob, &mut offset)?;
        if algo != b"ssh-rsa" {
            return Err(crypto_error("expected ssh-rsa key type in blob"));
        }
        let e_bytes = decode_ssh_string(blob, &mut offset)?;
        let n_bytes = decode_ssh_string(blob, &mut offset)?;
        let e = rsa::BigUint::from_bytes_be(&e_bytes);
        let n = rsa::BigUint::from_bytes_be(&n_bytes);
        let key = rsa::RsaPublicKey::new(n, e)
            .map_err(|_| crypto_error("invalid RSA public key components"))?;
        use rsa::traits::PublicKeyParts as _;
        if key.n().bits() < 2048 {
            return Err(crypto_error("RSA key must be at least 2048 bits"));
        }
        Ok(Self { key, sha512: false })
    }

    /// Set hash algorithm to SHA-512 (for rsa-sha2-512).
    #[must_use]
    pub fn with_sha512(mut self) -> Self {
        self.sha512 = true;
        self
    }
}

impl Verifier for RsaVerifier {
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), RusshError> {
        if self.sha512 {
            use sha2::Digest as _;
            let hash = sha2::Sha512::digest(message);
            self.key
                .verify(rsa::Pkcs1v15Sign::new::<sha2::Sha512>(), &hash, signature)
                .map_err(|_| crypto_error("RSA-SHA512 signature verification failed"))
        } else {
            use sha2::Digest as _;
            let hash = sha2::Sha256::digest(message);
            self.key
                .verify(rsa::Pkcs1v15Sign::new::<sha2::Sha256>(), &hash, signature)
                .map_err(|_| crypto_error("RSA-SHA256 signature verification failed"))
        }
    }

    fn algorithm_name(&self) -> &'static str {
        if self.sha512 {
            "rsa-sha2-512"
        } else {
            "rsa-sha2-256"
        }
    }
}

/// Build SSH wire-format public key blob for an RSA public key.
fn rsa_public_key_blob(key: &rsa::RsaPublicKey) -> Vec<u8> {
    use rsa::traits::PublicKeyParts as _;
    let mut blob = Vec::new();
    blob.extend_from_slice(&encode_ssh_string(b"ssh-rsa"));
    blob.extend_from_slice(&encode_mpint(&key.e().to_bytes_be()));
    blob.extend_from_slice(&encode_mpint(&key.n().to_bytes_be()));
    blob
}

// ============================================================
// SSH encoding helpers
// ============================================================

/// Encode a big-endian byte slice as an SSH mpint (RFC 4251 §5).
/// Strips leading zeros; prepends 0x00 if the high bit is set (positive integer).
pub fn encode_mpint(bytes: &[u8]) -> Vec<u8> {
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    let trimmed = &bytes[start..];

    if trimmed.is_empty() {
        return vec![0, 0, 0, 0];
    }

    let needs_pad = trimmed[0] & 0x80 != 0;
    let payload_len = trimmed.len() + usize::from(needs_pad);
    let mut result = Vec::with_capacity(4 + payload_len);
    result.extend_from_slice(&(payload_len as u32).to_be_bytes());
    if needs_pad {
        result.push(0x00);
    }
    result.extend_from_slice(trimmed);
    result
}

/// Encode bytes as an SSH string (RFC 4251 §5): u32-BE length prefix followed by data.
pub fn encode_ssh_string(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + data.len());
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
    out
}

/// Decode an SSH string from `data` starting at `*offset`, advancing `*offset` past it.
pub fn decode_ssh_string(data: &[u8], offset: &mut usize) -> Result<Vec<u8>, RusshError> {
    if *offset + 4 > data.len() {
        return Err(RusshError::new(
            RusshErrorCategory::Protocol,
            "buffer too short for SSH string length field",
        ));
    }
    let len = u32::from_be_bytes(
        data[*offset..*offset + 4]
            .try_into()
            .expect("slice is 4 bytes"),
    ) as usize;
    *offset += 4;
    if *offset + len > data.len() {
        return Err(RusshError::new(
            RusshErrorCategory::Protocol,
            "buffer too short for SSH string data",
        ));
    }
    let s = data[*offset..*offset + len].to_vec();
    *offset += len;
    Ok(s)
}

// ============================================================
// Key derivation (RFC 4253 §7.2, simplified)
// ============================================================

/// Derive `needed_bytes` of key material using the SSH key derivation construction.
///
/// `K1 = SHA256(shared_secret_mpint || exchange_hash || label || session_id)`
/// `K_{n+1} = SHA256(shared_secret_mpint || exchange_hash || K_n)`
pub fn derive_key_sha256(
    shared_secret_mpint: &[u8],
    exchange_hash: &[u8],
    label: u8,
    session_id: &[u8],
    needed_bytes: usize,
) -> Vec<u8> {
    if needed_bytes == 0 {
        return Vec::new();
    }

    let k1 = Sha256::digest_multi(&[shared_secret_mpint, exchange_hash, &[label], session_id]);

    if k1.len() >= needed_bytes {
        return k1[..needed_bytes].to_vec();
    }

    let mut result = k1.clone();
    let mut kn = k1;
    while result.len() < needed_bytes {
        kn = Sha256::digest_multi(&[shared_secret_mpint, exchange_hash, &kn]);
        result.extend_from_slice(&kn);
    }
    result.truncate(needed_bytes);
    result
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Unchanged policy / rng / utility tests ----

    #[test]
    fn secure_policy_disables_legacy() {
        let policy = CryptoPolicy::secure_defaults();
        assert!(!policy.allow_legacy());
    }

    #[test]
    fn legacy_policy_enables_legacy() {
        let policy = CryptoPolicy::legacy_compat();
        assert!(policy.allow_legacy());
    }

    #[test]
    fn deterministic_rng_fills_bytes() {
        let mut rng = LcgRandom::seeded(42);
        let mut output = [0u8; 4];
        rng.fill_bytes(&mut output);
        assert_ne!(output, [0u8; 4]);
    }

    #[test]
    fn ct_compare_works() {
        assert!(constant_time_eq(&[1, 2], &[1, 2]));
        assert!(!constant_time_eq(&[1, 2], &[2, 1]));
    }

    #[test]
    fn wipe_overwrites_data() {
        let mut secret = [1u8, 2, 3];
        wipe_secret(&mut secret);
        assert_eq!(secret, [0u8, 0, 0]);
    }

    // ---- Hash ----

    #[test]
    fn sha256_known_vector() {
        // SHA-256("abc") = ba7816bf...
        let digest = Sha256::digest(b"abc");
        assert_eq!(digest.len(), 32);
        assert_eq!(digest[0], 0xba);
        assert_eq!(digest[1], 0x78);
    }

    #[test]
    fn sha256_multi_equals_concat() {
        let combined = Sha256::digest(b"helloworld");
        let multi = Sha256::digest_multi(&[b"hello", b"world"]);
        assert_eq!(combined, multi);
    }

    #[test]
    fn sha512_output_length() {
        assert_eq!(Sha512::digest(b"test").len(), 64);
    }

    // ---- MAC ----

    #[test]
    fn hmac_sha256_sign_verify_roundtrip() {
        let key = b"secret-key";
        let data = b"message";
        let tag = HmacSha256::sign(key, data);
        assert!(HmacSha256::verify(key, data, &tag));
        // Wrong key => false
        assert!(!HmacSha256::verify(b"wrong-key", data, &tag));
    }

    #[test]
    fn hmac_sha512_sign_verify_roundtrip() {
        let key = b"k";
        let data = b"d";
        let tag = HmacSha512::sign(key, data);
        assert!(HmacSha512::verify(key, data, &tag));
        assert_eq!(tag.len(), 64);
    }

    // ---- AEAD ----

    #[test]
    fn aes256_gcm_roundtrip() {
        let key = [0u8; 32];
        let nonce = [1u8; 12];
        let aad = b"associated";
        let plaintext = b"hello world";
        let cipher = Aes256GcmCipher::new(&key).unwrap();
        let ct = cipher.seal(&nonce, aad, plaintext).unwrap();
        let recovered = cipher.open(&nonce, aad, &ct).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn aes256_gcm_tag_check() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let cipher = Aes256GcmCipher::new(&key).unwrap();
        let mut ct = cipher.seal(&nonce, b"", b"data").unwrap();
        // Flip a tag byte
        let last = ct.len() - 1;
        ct[last] ^= 0xff;
        assert!(cipher.open(&nonce, b"", &ct).is_err());
    }

    #[test]
    fn aes128_gcm_roundtrip() {
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let cipher = Aes128GcmCipher::new(&key).unwrap();
        let ct = cipher.seal(&nonce, b"aad", b"plaintext").unwrap();
        let pt = cipher.open(&nonce, b"aad", &ct).unwrap();
        assert_eq!(pt, b"plaintext");
    }

    #[test]
    fn chacha20poly1305_roundtrip() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let cipher = ChaCha20Poly1305Cipher::new(&key).unwrap();
        let ct = cipher.seal(&nonce, b"", b"secret").unwrap();
        let pt = cipher.open(&nonce, b"", &ct).unwrap();
        assert_eq!(pt, b"secret");
    }

    // ---- AES-CTR stream ciphers ----

    #[test]
    fn aes256_ctr_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 32];
        let iv = [0x01u8; 16];
        let plaintext = b"hello aes-256-ctr world!";
        let mut data = plaintext.to_vec();
        let mut enc = Aes256CtrCipher::new(&key, &iv).unwrap();
        enc.encrypt_in_place(&mut data);
        assert_ne!(&data, plaintext);
        let mut dec = Aes256CtrCipher::new(&key, &iv).unwrap();
        dec.decrypt_in_place(&mut data);
        assert_eq!(&data, plaintext);
    }

    #[test]
    fn aes128_ctr_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 16];
        let iv = [0x01u8; 16];
        let plaintext = b"hello aes-128-ctr!";
        let mut data = plaintext.to_vec();
        let mut enc = Aes128CtrCipher::new(&key, &iv).unwrap();
        enc.encrypt_in_place(&mut data);
        assert_ne!(&data, plaintext);
        let mut dec = Aes128CtrCipher::new(&key, &iv).unwrap();
        dec.decrypt_in_place(&mut data);
        assert_eq!(&data, plaintext);
    }

    // ---- Key exchange: Curve25519 ----

    #[test]
    fn curve25519_kex_produces_shared_secret() {
        let mut rng = LcgRandom::seeded(1);
        let alice = Curve25519Sha256::generate_keypair(&mut rng);
        let mut rng2 = LcgRandom::seeded(2);
        let bob = Curve25519Sha256::generate_keypair(&mut rng2);

        let alice_shared =
            Curve25519Sha256::compute_shared_secret(alice.secret_bytes(), &bob.public_key).unwrap();
        let bob_shared =
            Curve25519Sha256::compute_shared_secret(bob.secret_bytes(), &alice.public_key).unwrap();

        assert_eq!(alice_shared.shared_secret, bob_shared.shared_secret);
        assert_eq!(alice_shared.shared_secret.len(), 32);
    }

    // ---- Key exchange: P-256 ----

    #[test]
    fn p256_kex_produces_shared_secret() {
        let mut rng = LcgRandom::seeded(3);
        let alice = EcdhNistp256::generate_keypair(&mut rng);
        let mut rng2 = LcgRandom::seeded(4);
        let bob = EcdhNistp256::generate_keypair(&mut rng2);

        assert_eq!(alice.public_key.len(), 65);
        assert_eq!(alice.public_key[0], 0x04); // uncompressed SEC1

        let alice_shared =
            EcdhNistp256::compute_shared_secret(alice.secret_bytes(), &bob.public_key).unwrap();
        let bob_shared =
            EcdhNistp256::compute_shared_secret(bob.secret_bytes(), &alice.public_key).unwrap();

        assert_eq!(alice_shared.shared_secret, bob_shared.shared_secret);
        assert_eq!(alice_shared.shared_secret.len(), 32);
    }

    // ---- Key exchange: DH group14 ----

    #[test]
    fn dh_group14_kex_produces_shared_secret() {
        let mut rng = LcgRandom::seeded(10);
        let alice = DhGroup14Sha256::generate_keypair(&mut rng);
        let mut rng2 = LcgRandom::seeded(11);
        let bob = DhGroup14Sha256::generate_keypair(&mut rng2);

        let alice_shared =
            DhGroup14Sha256::compute_shared_secret(alice.secret_bytes(), &bob.public_key).unwrap();
        let bob_shared =
            DhGroup14Sha256::compute_shared_secret(bob.secret_bytes(), &alice.public_key).unwrap();

        assert_eq!(alice_shared.shared_secret, bob_shared.shared_secret);
        assert!(!alice_shared.shared_secret.is_empty());
    }

    #[test]
    fn dh_group14_rejects_out_of_range_public() {
        let mut rng = LcgRandom::seeded(12);
        let alice = DhGroup14Sha256::generate_keypair(&mut rng);
        // Public value of 1 is invalid
        assert!(DhGroup14Sha256::compute_shared_secret(alice.secret_bytes(), &[1]).is_err());
        // Public value of 0 is invalid
        assert!(DhGroup14Sha256::compute_shared_secret(alice.secret_bytes(), &[0]).is_err());
    }

    // ---- Ed25519 signing ----

    #[test]
    fn ed25519_sign_verify_roundtrip() {
        let mut rng = LcgRandom::seeded(99);
        let signer = Ed25519Signer::generate(&mut rng);
        let verifier = signer.verifier();
        let msg = b"test message";
        let sig = signer.sign(msg).unwrap();
        assert_eq!(sig.len(), 64);
        assert!(verifier.verify(msg, &sig).is_ok());
    }

    #[test]
    fn ed25519_wrong_signature_rejected() {
        let mut rng = LcgRandom::seeded(7);
        let signer = Ed25519Signer::generate(&mut rng);
        let verifier = signer.verifier();
        let mut sig = signer.sign(b"hello").unwrap();
        sig[0] ^= 0xff;
        assert!(verifier.verify(b"hello", &sig).is_err());
    }

    #[test]
    fn ed25519_public_key_blob_format() {
        let seed = [0u8; 32];
        let signer = Ed25519Signer::from_seed(&seed);
        let blob = signer.public_key_blob();
        // Layout: 4 + 11 + 4 + 32 = 51 bytes
        assert_eq!(blob.len(), 51);
        assert_eq!(&blob[4..15], b"ssh-ed25519");
        assert_eq!(u32::from_be_bytes(blob[15..19].try_into().unwrap()), 32u32);
    }

    // ---- RSA signing ----

    #[test]
    fn rsa_sha256_sign_verify_roundtrip() {
        let mut rng = OsRng;
        let signer = RsaSigner::generate(&mut rng).unwrap();
        let sha256_signer = RsaSha256Signer(signer);
        let verifier = sha256_signer.0.verifier_sha256();
        let msg = b"rsa test message";
        let sig = sha256_signer.sign(msg).unwrap();
        assert!(verifier.verify(msg, &sig).is_ok());
    }

    #[test]
    fn rsa_sha512_sign_verify_roundtrip() {
        let mut rng = OsRng;
        let signer = RsaSigner::generate(&mut rng).unwrap();
        let sha512_signer = RsaSha512Signer(signer);
        let verifier = sha512_signer.0.verifier_sha512();
        let msg = b"rsa-512 test";
        let sig = sha512_signer.sign(msg).unwrap();
        assert!(verifier.verify(msg, &sig).is_ok());
    }

    #[test]
    fn rsa_wrong_signature_rejected() {
        let mut rng = OsRng;
        let signer = RsaSigner::generate(&mut rng).unwrap();
        let sha256_signer = RsaSha256Signer(signer);
        let verifier = sha256_signer.0.verifier_sha256();
        let mut sig = sha256_signer.sign(b"data").unwrap();
        sig[0] ^= 0xff;
        assert!(verifier.verify(b"data", &sig).is_err());
    }

    #[test]
    fn rsa_public_key_blob_roundtrip() {
        let mut rng = OsRng;
        let signer = RsaSigner::generate(&mut rng).unwrap();
        let blob = signer.public_key_blob();
        let mut offset = 0;
        let algo = decode_ssh_string(&blob, &mut offset).unwrap();
        assert_eq!(algo, b"ssh-rsa");
        // Verify we can reconstruct a verifier from the blob
        let verifier = RsaVerifier::from_ssh_blob(&blob).unwrap();
        let sha256_signer = RsaSha256Signer(signer);
        let msg = b"blob roundtrip";
        let sig = sha256_signer.sign(msg).unwrap();
        assert!(verifier.verify(msg, &sig).is_ok());
    }

    // ---- ECDSA-P256 signing ----

    #[test]
    fn ecdsa_p256_sign_verify_roundtrip() {
        let mut rng = LcgRandom::seeded(200);
        let signer = EcdsaP256Signer::generate(&mut rng);
        let verifier = signer.verifier();
        let msg = b"ecdsa test message";
        let sig = signer.sign(msg).unwrap();
        assert_eq!(sig.len(), 64);
        assert!(verifier.verify(msg, &sig).is_ok());
    }

    #[test]
    fn ecdsa_p256_wrong_signature_rejected() {
        let mut rng = LcgRandom::seeded(201);
        let signer = EcdsaP256Signer::generate(&mut rng);
        let verifier = signer.verifier();
        let mut sig = signer.sign(b"hello ecdsa").unwrap();
        sig[0] ^= 0xff;
        assert!(verifier.verify(b"hello ecdsa", &sig).is_err());
    }

    #[test]
    fn ecdsa_p256_public_key_blob_format() {
        let mut rng = LcgRandom::seeded(202);
        let signer = EcdsaP256Signer::generate(&mut rng);
        let blob = signer.public_key_blob();
        let mut offset = 0;
        let algo = decode_ssh_string(&blob, &mut offset).unwrap();
        assert_eq!(algo, b"ecdsa-sha2-nistp256");
        let curve = decode_ssh_string(&blob, &mut offset).unwrap();
        assert_eq!(curve, b"nistp256");
        let point = decode_ssh_string(&blob, &mut offset).unwrap();
        assert_eq!(point.len(), 65);
        assert_eq!(point[0], 0x04); // uncompressed SEC1 point
        assert_eq!(offset, blob.len());
    }

    // ---- SSH encoding helpers ----

    #[test]
    fn encode_mpint_zero() {
        assert_eq!(encode_mpint(&[0, 0, 0]), vec![0, 0, 0, 0]);
        assert_eq!(encode_mpint(&[]), vec![0, 0, 0, 0]);
    }

    #[test]
    fn encode_mpint_no_high_bit() {
        // 0x01: no padding needed
        let out = encode_mpint(&[0x01]);
        assert_eq!(out, vec![0, 0, 0, 1, 0x01]);
    }

    #[test]
    fn encode_mpint_high_bit_set() {
        // 0x80: needs 0x00 padding to stay positive
        let out = encode_mpint(&[0x80]);
        assert_eq!(out, vec![0, 0, 0, 2, 0x00, 0x80]);
    }

    #[test]
    fn encode_mpint_strips_leading_zeros() {
        let out = encode_mpint(&[0, 0, 0x05]);
        assert_eq!(out, vec![0, 0, 0, 1, 0x05]);
    }

    #[test]
    fn ssh_string_roundtrip() {
        let data = b"curve25519-sha256";
        let encoded = encode_ssh_string(data);
        let mut offset = 0;
        let decoded = decode_ssh_string(&encoded, &mut offset).unwrap();
        assert_eq!(decoded, data);
        assert_eq!(offset, encoded.len());
    }

    #[test]
    fn decode_ssh_string_error_on_short_buffer() {
        let bad = [0u8, 0, 0, 10, 1, 2]; // claims 10 bytes but only 2 provided
        let mut offset = 0;
        assert!(decode_ssh_string(&bad, &mut offset).is_err());
    }

    // ---- Key derivation ----

    #[test]
    fn derive_key_sha256_length() {
        let k = derive_key_sha256(b"secret", b"hash", b'A', b"session", 32);
        assert_eq!(k.len(), 32);
    }

    #[test]
    fn derive_key_sha256_extended() {
        let k = derive_key_sha256(b"K", b"H", b'C', b"S", 64);
        assert_eq!(k.len(), 64);
    }

    #[test]
    fn derive_key_sha256_deterministic() {
        let a = derive_key_sha256(b"K", b"H", b'A', b"S", 20);
        let b = derive_key_sha256(b"K", b"H", b'A', b"S", 20);
        assert_eq!(a, b);
    }

    #[test]
    fn derive_key_sha256_different_labels() {
        let a = derive_key_sha256(b"K", b"H", b'A', b"S", 16);
        let b = derive_key_sha256(b"K", b"H", b'B', b"S", 16);
        assert_ne!(a, b);
    }
}
