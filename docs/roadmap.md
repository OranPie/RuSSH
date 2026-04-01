# RuSSH Roadmap

## v0.1 ✅
Complete SSH protocol stack — cryptographic primitives, encrypted transport,
Curve25519-SHA256 KEX, Ed25519 host keys, publickey/password/keyboard-interactive
auth, RFC 4254 channel multiplexing with flow control, SFTP v3 wire codec +
filesystem server, SCP wire helpers, OpenSSH config resolution with Host pattern
matching, tracing/metrics observability backends, ZeroizeOnDrop + constant-time
security hardening, and libfuzzer fuzz targets.

158 tests, 0 unsafe blocks.

## v0.2 ✅
Async networked transport (`russh-net` crate, tokio):
- `SshClient::connect()` → full KEX → password auth → channel pipeline
- `SshServer::bind()` → accept loop → per-connection session
- `exec`, SFTP v3 (upload + read-back), SCP upload over real TCP
- Self-contained loopback integration test (RuSSH client ↔ RuSSH server)

## v0.3 ✅
OpenSSH interoperability — all four cross-implementation tests pass:
- RuSSH client → OpenSSH server: `exec` + SFTP v3 upload/read
- OpenSSH client → RuSSH server: `exec` + SFTP v3 upload/read

Bug fixes: exchange-hash wire encoding, cipher negotiation, `none` auth probe,
SFTP chroot absolute paths, channel EOF/Close sequencing.

## v0.4 ✅
Advanced SSH features:
- **OpenSSH certificate support** — `ssh-ed25519-cert-v01@openssh.com` wire parsing,
  CA signature verification, server-side cert auth (`CertificateValidator`), client-side
  `authenticate_pubkey_with_cert()`. Two integration tests: RuSSH cert client → sshd,
  OpenSSH cert client → RuSSH server.
- **SSH Agent Protocol** — `SshAgentClient` over `SSH_AUTH_SOCK` Unix socket; implements
  `list_identities()` and `sign()` (SSH-AGENT protocol). `authenticate_via_agent()` on
  `SshClientConnection`. Integration test against real OpenSSH `ssh-agent`.
- **ProxyJump** — `SshClient::connect_via_jump()` opens a `direct-tcpip` channel to a
  target through a jump host; inner SSH session runs over a `tokio::io::duplex` bridge.
  `SshClientConnection` refactored to use boxed `AnyStream` for stream-type agnosticism.
  Integration test through two real `sshd` instances.
- **ControlMaster config directives** — `ProxyJump`, `ControlMaster`, and `ControlPath`
  added to `russh-config`; token expansion (`%h`/`%u`/`%%`) and tilde expansion applied
  to `ControlPath`. Mux-socket protocol defers to v0.6+.

## v0.5 ✅
Broad protocol coverage, CLI maturity, and OpenSSH compatibility:
- **Crypto**: ECDSA-P256, RSA (sha2-256/sha2-512) host keys; AES-256-CTR, AES-128-CTR
  ciphers with ETM MACs; DH group14-sha256 KEX.
- **Transport**: `zlib@openssh.com` delayed compression; strict KEX counter reset
  (CVE-2023-48795 mitigation).
- **Auth**: keyboard-interactive (server + client), password auth in CLI, auth method
  ordering via `-o PreferredAuthentications`, multiple identity files (`-i` repeatable).
- **SFTP**: symlink/readlink; OpenSSH extensions (posix-rename, statvfs, hardlink, fsync).
- **SCP**: timestamp preservation (T-directive, `filetime` crate).
- **Forwarding**: local port forwarding (`-L`), agent forwarding (`-A`).
- **CLI**: SSH config file integration (`-F`), expanded `-o` options (Port, User,
  IdentityFile, ServerAliveInterval, Compression, KexAlgorithms, Ciphers, MACs,
  HostKeyAlgorithms, PasswordAuthentication, PreferredAuthentications), terminal resize
  (window-change), keepalive (`keepalive@openssh.com`).

258 tests, 0 unsafe blocks.

## v0.6 ✅
Algorithm expansion, server hardening, and advanced forwarding:
- **Crypto**: ECDSA P-384/P-521 host key algorithms; DH group16-sha512 (4096-bit) and group18-sha512 (8192-bit) KEX; encrypted private key support (bcrypt-pbkdf / OpenSSH format)
- **Certificates**: Multi-algorithm cert support (Ed25519, RSA, ECDSA) in OpenSshCertificate
- **Server hardening**: AllowUsers/DenyUsers policy enforcement; LoginGraceTime (auth phase timeout); cancel-tcpip-forward with listener teardown
- **Forwarding**: SOCKS4/5 dynamic proxy (-D), remote port forwarding (-R), unix socket forwarding (direct-streamlocal), GSSAPI auth scaffolding
- **CLI**: -N (no shell) and -f (background) flags

399 tests, 0 unsafe blocks.

## v0.7 ✅ (current)
Protocol completeness and observability wiring:
- **Transport**: SSH_MSG_DEBUG handling (passed to EventSink, no longer dropped)
- **Config**: Include directive with glob expansion, tilde, circular-include depth limiting
- **SFTP**: fsetstat / setstat attribute handlers
- **Network**: SO_KEEPALIVE on all client and server sockets; tcpip-forward lifecycle tracking with cancel cleanup
- **Observability**: EventSink and MetricsHook wired through SshClientConnection / SshServerConnection
- **SOCKS**: SOCKS4/5 proxy fully wired to direct-tcpip channels (domain name forwarding, SOCKS4a)
- **Tests**: +87 edge case and security tests covering AEAD tampering, seq# wraparound, cert expiry boundaries, window overflow, circular includes, large offsets

495 tests, 0 unsafe blocks.

## v0.8 — Interop completeness
- X11 forwarding (x11-req channel request, X11 forwarding channel)
- ControlMaster mux-socket protocol (multiplexed sessions over Unix socket)
- ProxyCommand support (pipe through arbitrary command)
- hostbased authentication (RFC 4252 §9)
- Full GSSAPI/Kerberos wiring (beyond scaffolding)
- Corpus-based fuzz campaigns with coverage-guided CI
- Performance benchmark harness (handshake/s, MB/s throughput)

## v1.0 — Stable release
- External security review gate
- Stable public API (semver guarantees)
- crates.io publication
