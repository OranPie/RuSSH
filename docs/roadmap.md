# RuSSH Roadmap

## v0.1 ✅ (current)
Complete SSH protocol stack — cryptographic primitives, encrypted transport,
Curve25519-SHA256 KEX, Ed25519 host keys, publickey/password/keyboard-interactive
auth, RFC 4254 channel multiplexing with flow control, SFTP v3 wire codec +
filesystem server, SCP wire helpers, OpenSSH config resolution with Host pattern
matching, tracing/metrics observability backends, ZeroizeOnDrop + constant-time
security hardening, and libfuzzer fuzz targets.

158 tests, 0 unsafe blocks.

## v0.3 ✅ (current)
OpenSSH interoperability — all four cross-implementation tests pass:
- RuSSH client → OpenSSH server: `exec` + SFTP v3 upload/read
- OpenSSH client → RuSSH server: `exec` + SFTP v3 upload/read

Bug fixes applied during v0.3:
- **Exchange hash**: server now preserves raw client KEXINIT bytes before parsing
  (`store_client_kexinit_payload`) so the exchange hash uses the original wire
  encoding, not a re-encoded version.
- **Cipher negotiation**: removed unimplemented ciphers (`chacha20-poly1305`,
  `aes128-gcm`) from `AlgorithmSet::secure_defaults()` to avoid OpenSSH selecting
  an unsupported cipher.
- **`none` auth probe**: OpenSSH always sends a `UserAuthRequest` with method
  `"none"` first to discover allowed methods; added `UserAuthRequest::None` variant
  and handler returning `USERAUTH_FAILURE` with the allowed-methods list.
- **SFTP chroot paths**: `SftpFileServer::resolve_path` now strips the leading
  `/` component rather than rejecting absolute paths, matching SFTP v3 convention.
- **Channel EOF/Close**: server sends `CHANNEL_EOF + CHANNEL_CLOSE` back when it
  receives `CHANNEL_EOF`, unblocking the remote client; IO-level read errors
  (connection close) are treated as a clean session end.

## v0.2 ✅
Async networked transport (`russh-net` crate, tokio):
- `SshClient::connect()` → full KEX → password auth → channel pipeline
- `SshServer::bind()` → accept loop → per-connection session
- `exec`, SFTP v3 (upload + read-back), SCP upload over real TCP
- Self-contained loopback integration test (RuSSH client ↔ RuSSH server)

All tests pass (zero unsafe blocks).

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
