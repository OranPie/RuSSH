# RuSSH Threat Model

## Assets

- **Long-term private keys** — host keys and user identity keys stored on disk; encrypted at rest with bcrypt-pbkdf / OpenSSH private key format.
- **SSH agent socket identities** — in-memory key material held by `ssh-agent`; exposed via `SSH_AUTH_SOCK` and optionally forwarded to remote hosts through agent forwarding.
- **Session keys** — ephemeral symmetric keys derived per-connection; wrapped in `ZeroizeOnDrop` types and never written to disk.
- **Channel data** — shell I/O, SFTP file contents, and forwarded TCP/Unix streams; confidentiality and integrity protected by the negotiated AEAD/MAC scheme.
- **Authentication credentials** — passwords and keyboard-interactive responses in transit; never logged or retained after the auth phase completes.
- **Known-hosts trust anchors** — TOFU fingerprints stored in `~/.russh/known_hosts`; form the root of host authentication for all subsequent connections.
- **SOCKS/forwarded traffic plaintext** — data decrypted from the SSH layer before being forwarded to the target; exposed only in memory while in flight.

## Adversaries

### Network attacker
An adversary with the ability to observe, inject, and modify packets on the wire.

- **MITM**: mitigated by host key pinning (known-hosts TOFU) — a first-connection fingerprint is stored and verified on all subsequent connections.
- **Packet injection / tampering**: mitigated by AEAD (ChaCha20-Poly1305, AES-GCM) with per-packet sequence numbers; any modification causes authentication tag failure and immediate connection termination.
- **Replay attacks**: mitigated by strict KEX (`kex-strict-*-v00@openssh.com`) which resets sequence numbers at session start and enforces packet ordering, closing the Terrapin window (CVE-2023-48795).

### Malicious SSH server
A server under adversary control that the client connects to.

- **Algorithm downgrade**: mitigated by `secure_defaults()` rejecting legacy ciphers, MACs, and KEX algorithms at negotiation time; connection is refused if no acceptable overlap exists.
- **Rogue host key**: mitigated by known-hosts TOFU; the client aborts on key mismatch after first trust.

### Malicious SSH client
A client under adversary control connecting to a RuSSH server.

- **Auth brute force**: mitigated by `LoginGraceTime` (default 120 s) — the auth phase is terminated after the grace period, preventing indefinite resource hold.
- **Resource exhaustion via channels/forwards**: channel and forward counts are bounded; a client that opens excessive channels or port-forward listeners is disconnected.
- **SFTP path traversal**: all SFTP paths are canonicalized and constrained to the configured chroot root; symlink traversal outside the chroot is blocked.

### Local attacker
An adversary with unprivileged access to the same host as the russh process.

- **`SSH_AUTH_SOCK` hijacking**: socket permissions are set to `0600`; agent connections from other UIDs are rejected.
- **ptrace / `/proc/mem` inspection**: mitigated by `PR_SET_DUMPABLE` and OS-level ptrace restrictions; secrets are zeroed as soon as they are no longer needed.
- **Log scraping for credentials**: passwords and key material are never emitted to logs; `Zeroizing<_>` wrappers ensure secrets are cleared on drop.

## Goals
- Confidentiality and integrity of transport/channel data.
- Strict peer authentication and key verification.
- Fail-closed behavior on parse/auth/crypto errors.
- Minimized attack surface with secure defaults.

## Non-goals (current phase)
- Formal verification of protocol state machines.
- FIPS certification in v1.0.

## Mitigations in place

| Threat | Mitigation |
|---|---|
| CVE-2023-48795 (Terrapin) | Strict KEX (`kex-strict-*-v00@openssh.com`) with sequence number reset and enforced packet ordering at session start |
| Timing side-channels | `subtle::ConstantTimeEq` for all secret comparisons — passwords, HMAC tags, and key material |
| Secret memory exposure | `ZeroizeOnDrop` on `SessionKeys`; `Zeroizing<Vec<u8>>` on all ephemeral secrets and passphrase buffers |
| Memory-safety bugs | `#[deny(unsafe_code)]` at workspace level; zero `unsafe` blocks across all 13 crates |
| Silent failure on error | Parse/auth/crypto errors always return `Err`; no silent fallbacks or default-allow paths |
| SFTP path traversal | All paths canonicalized and constrained to chroot root; symlink targets outside chroot are rejected |
| Encrypted identity files | bcrypt-pbkdf with configurable rounds for passphrase-protected keys (OpenSSH private key format) |
| Auth-phase resource hold | `LoginGraceTime` (default 120 s) terminates unauthenticated connections after the grace period |

## Known gaps / future work

- **GSSAPI/Kerberos**: scaffolded but not fully wired; Kerberos token validation not yet implemented. Treat GSSAPI auth as unavailable until this gap is closed.
- **X11 forwarding**: not yet implemented. When added, the X11 channel is a significant injection surface and will require its own threat analysis.
- **ControlMaster mux-socket**: not yet implemented. The Unix socket path is subject to TOCTOU races; implementation will need atomic socket creation and strict permission checks.
- **Constant-time audit**: no external reviewer has performed a systematic constant-time audit of the codebase. Self-assessed via `subtle` usage; formal audit deferred to pre-1.0.
- **FIPS certification**: non-goal for v1.0.
- **Formal protocol state machine verification**: non-goal.

## Security controls roadmap
1. Constant-time checks on sensitive comparisons. ✅ (subtle::ConstantTimeEq throughout)
2. Memory hygiene for secrets (zeroization strategy). ✅ (ZeroizeOnDrop / Zeroizing<_>)
3. Fuzzing coverage over parser/decoder surfaces. 🔄 (fuzz/ scaffolded; corpus campaigns planned for v0.8)
4. Interop tests with OpenSSH for downgrade and negotiation behavior. ✅ (v0.3+ interop suite)
5. Unsafe code audit before `1.0.0`. ✅ (zero unsafe blocks enforced by deny directive)
