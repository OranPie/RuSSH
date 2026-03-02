# RuSSH Threat Model (Initial)

## Assets
- Long-term keys, agent identities, session keys, forwarded traffic, credentials.

## Adversaries
- Active network attacker (MITM, packet tampering, replay attempts).
- Malicious remote peer (protocol abuse, resource exhaustion).
- Local attacker with partial host access (log scraping, socket hijacking).

## Goals
- Confidentiality and integrity of transport/channel data.
- Strict peer authentication and key verification.
- Fail-closed behavior on parse/auth/crypto errors.
- Minimized attack surface with secure defaults.

## Non-goals (current phase)
- Formal verification of protocol state machines.
- FIPS certification in v1.

## Security controls roadmap
1. Constant-time checks on sensitive comparisons.
2. Memory hygiene for secrets (zeroization strategy).
3. Fuzzing coverage over parser/decoder surfaces.
4. Interop tests with OpenSSH for downgrade and negotiation behavior.
5. Unsafe code audit before `1.0.0`.
