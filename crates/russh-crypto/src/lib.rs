//! Cryptographic policy and algorithm selection primitives.

use russh_core::AlgorithmSet;

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

/// Random source abstraction for pluggable RNG backends.
pub trait RandomSource {
    fn fill_bytes(&mut self, target: &mut [u8]);
}

/// Deterministic, std-only random source used for tests and bootstrap.
#[derive(Clone, Debug)]
pub struct LcgRandom {
    state: u64,
}

impl LcgRandom {
    #[must_use]
    pub fn seeded(seed: u64) -> Self {
        Self { state: seed }
    }
}

impl RandomSource for LcgRandom {
    fn fill_bytes(&mut self, target: &mut [u8]) {
        for byte in target {
            self.state = self.state.wrapping_mul(6364136223846793005).wrapping_add(1);
            *byte = (self.state >> 24) as u8;
        }
    }
}

/// Constant-time byte-slice equality check.
#[must_use]
pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }

    let mut diff = 0u8;
    for (&a, &b) in left.iter().zip(right.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

/// Best-effort secret wiping helper.
pub fn wipe_secret(bytes: &mut [u8]) {
    bytes.fill(0);
}

#[cfg(test)]
mod tests {
    use super::{CryptoPolicy, LcgRandom, RandomSource, constant_time_eq, wipe_secret};

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
}
