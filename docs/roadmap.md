# RuSSH Roadmap

## v0.1 ✅ (current)
Complete SSH protocol stack — cryptographic primitives, encrypted transport,
Curve25519-SHA256 KEX, Ed25519 host keys, publickey/password/keyboard-interactive
auth, RFC 4254 channel multiplexing with flow control, SFTP v3 wire codec +
filesystem server, SCP wire helpers, OpenSSH config resolution with Host pattern
matching, tracing/metrics observability backends, ZeroizeOnDrop + constant-time
security hardening, and libfuzzer fuzz targets.

158 tests, 0 unsafe blocks.

## v0.2 — Async networked transport
- Async TCP I/O layer (tokio feature flag)
- Client `connect()` → negotiation → auth → channel pipeline
- Server `bind()` → accept loop → per-connection session
- Proper framing over `AsyncRead` / `AsyncWrite`

## v0.3 — OpenSSH interoperability
- Spawn real `sshd` / `ssh` binaries in integration tests
- Validate full handshake, auth, and channel I/O against OpenSSH 9.x
- SFTP subsystem interop with `sftp` client

## v0.4 — Advanced features
- OpenSSH certificate format (ssh-ed25519-cert-v01@openssh.com) validation
- Agent forwarding protocol bridge (`SSH_AUTH_SOCK`)
- ProxyJump / `nc`-mode tunneling (`-W` / `-J`)
- Connection multiplexing (`ControlMaster` / `ControlPath`)

## v0.5 — Hardening and performance
- Corpus-based fuzz campaigns; coverage-guided CI
- Performance benchmark harness (handshake/s, MB/s throughput)
- Constant-time audit by external reviewer
- API stabilization pass; deprecation of internal-only symbols

## v1.0 — Stable release
- External security review gate
- Stable public API (semver guarantees)
- crates.io publication
