# Changelog

All notable changes to RuSSH are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Planned for v0.8
- X11 forwarding (`-X`/`-Y` flags, `x11-req` channel request, X11 channel type)
- ControlMaster mux-socket (full `ControlMaster auto` / `ControlPath` / `ControlPersist` lifecycle)
- ProxyCommand support (`ProxyCommand` config directive, stdio-forwarding subprocess transport)
- Host-based authentication (`hostbased` auth method, `/etc/ssh/ssh_known_hosts` integration)
- Full GSSAPI/Kerberos authentication (complete the scaffolding introduced in v0.6)
- Fuzz campaigns targeting packet framing, config parsing, and auth-message surfaces
- Performance benchmarks (throughput, latency, and rekey overhead baselines)

---

## [0.7.0] — 2026-04-01

### Added
- SSH_MSG_DEBUG packet handling in transport layer (passed to `EventSink`)
- `Include` directive in SSH config parser (glob expansion, tilde expansion, depth-limited recursion, circular-include safe)
- SFTP `SSH_FXP_FSETSTAT` (opcode 10) and `SSH_FXP_SETSTAT` (opcode 9) attribute handlers
- TCP-level `SO_KEEPALIVE` on all client and server sockets (via `socket2`)
- `tcpip-forward` lifecycle tracking: active listener registry with cancel-on-close cleanup
- Observability wiring: `EventSink` and `MetricsHook` threaded through `SshClientConnection` / `SshServerConnection`
- SOCKS4/5 proxy fully wired to `direct-tcpip` SSH channels (SOCKS4a domain name support included)
- 87 new edge-case and security tests: AEAD tampering, MAC bit-flips, sequence-number wraparound, certificate expiry boundaries, window overflow, circular includes, large file offsets, PEM error paths
- Total: 495 tests, 0 failures

---

## [0.6.0] — 2026-03-31

### Added
- Encrypted private key support: bcrypt-pbkdf KDF, OpenSSH `-----BEGIN OPENSSH PRIVATE KEY-----` format; passphrase prompting in CLI
- ECDSA P-384 (`ecdsa-sha2-nistp384`) and P-521 (`ecdsa-sha2-nistp521`) host key algorithms and user key signing/verification
- DH group16-sha512 (4096-bit MODP) and group18-sha512 (8192-bit MODP) key exchange (RFC 3526)
- Multi-algorithm `OpenSshCertificate`: Ed25519, RSA, and ECDSA certificate public key serialization
- `AllowUsers` / `DenyUsers` config directives with `ServerAuthPolicy` enforcement (`DenyUsers` wins on conflict)
- `LoginGraceTime`: configurable auth-phase timeout (default 120 s via `tokio::time::timeout`)
- `cancel-tcpip-forward` global request handler with listener teardown
- GSSAPI auth scaffolding (method infrastructure, not yet fully wired)
- Unix socket forwarding (`direct-streamlocal@openssh.com` channel type)
- SOCKS4/5 dynamic proxy (`-D [bind:]port` CLI flag); `socks.rs` parser module
- Remote port forwarding (`-R [bind:]port:host:hostport` CLI flag)
- `-N` flag: no-shell mode (keeps connection alive for port forwarding; Ctrl+C to exit)
- `-f` flag: background mode (detaches process after authentication)
- Total: 399 tests, 0 failures

---

## [0.5.0] — 2026-03-30

### Added
- ECDSA-P256, RSA (`rsa-sha2-256` / `rsa-sha2-512`) host key algorithms
- AES-256-CTR and AES-128-CTR ciphers with ETM MACs (`hmac-sha2-256-etm`, `hmac-sha2-512-etm`)
- DH group14-sha256 key exchange
- `zlib@openssh.com` delayed compression (activates post-authentication)
- Strict KEX hardening: CVE-2023-48795 mitigation via sequence-number reset and packet-order enforcement
- Keyboard-interactive authentication (server and client sides)
- Password authentication in CLI (`read_password()`, echo-disabled stdin)
- Auth method ordering via `-o PreferredAuthentications`
- Multiple `-i` identity files (tried in order)
- SFTP symlink and readlink operations
- SFTP OpenSSH extensions: `posix-rename`, `statvfs`, `hardlink`, `fsync`
- SCP timestamp preservation (T-directive, `filetime` crate)
- Local port forwarding (`-L [bind:]port:host:hostport`)
- Agent forwarding (`-A`)
- SSH config file integration (`-F`)
- Expanded `-o` options: `Port`, `User`, `IdentityFile`, `ServerAliveInterval`, `Compression`, `KexAlgorithms`, `Ciphers`, `MACs`, `HostKeyAlgorithms`, `PasswordAuthentication`, `PreferredAuthentications`
- Terminal resize (`window-change` channel requests)
- Keepalive (`keepalive@openssh.com` global request)
- Total: 258 tests, 0 failures

---

## [0.4.0] — 2026-03-29

### Added
- OpenSSH certificate support (`ssh-ed25519-cert-v01@openssh.com`): wire parsing, CA verification, server-side `CertificateValidator`, client-side `authenticate_pubkey_with_cert()`
- SSH Agent Protocol: `SshAgentClient` over `SSH_AUTH_SOCK` (`list_identities`, `sign`); `authenticate_via_agent()`
- ProxyJump: multi-hop connections via `direct-tcpip` channel to jump host; `AnyStream` abstraction for polymorphic transports
- ControlMaster config directives: `ProxyJump`, `ControlMaster`, `ControlPath` with token and tilde expansion

---

## [0.3.0] — 2026-03-28

### Added
- Full OpenSSH interoperability: all 4 cross-implementation integration tests pass (RuSSH↔OpenSSH both directions for exec and SFTP)

### Fixed
- Exchange hash now uses raw wire encoding of client KEXINIT (fixes field-order mismatch with OpenSSH)
- Only advertise implemented ciphers in `AlgorithmSet` (removed unimplemented `aes128-gcm`)
- `none` auth method probe handled correctly (returns `USERAUTH_FAILURE` with available method list)
- SFTP chroot: absolute paths now work correctly (strip leading `/` instead of returning `PermissionDenied`)
- Channel EOF/Close sequencing: server sends EOF then CLOSE to unblock remote side on channel EOF

---

## [0.2.0] — 2026-03-27

### Added
- `russh-net` crate: async TCP client and server backed by Tokio
- `SshClient::connect()`, `SshServer::bind()` / `accept()`, `SshServerConnection::run()`
- `exec`, SFTP v3 (upload and read-back), and SCP upload over real TCP connections
- `SessionHandler` trait and `DefaultSessionHandler` implementation
- Self-contained loopback integration test

### Fixed
- `ServerSession` now clears rekey state after a completed exchange (strict-KEX sequence-number reset correctness)
- `ClientSession` stores raw server KEXINIT bytes for use in exchange hash computation

---

## [0.1.0] — 2026-03-26

### Added
- Initial release: complete SSH protocol stack across 10 crates
- **russh-crypto**: AES-256-GCM, ChaCha20-Poly1305, SHA-2, HMAC, Curve25519 / ECDH-P256 KEX, Ed25519 signatures, session key derivation
- **russh-core**: RFC 4253 packet codec, `RusshError` / `RusshErrorCategory` types, algorithm negotiation primitives
- **russh-transport**: SSH version exchange, KEX state machine, strict KEX, session key derivation, rekey thresholds
- **russh-auth**: `publickey` / `password` / `keyboard-interactive` methods, `MemoryAuthorizedKeys`, `FileIdentityProvider`
- **russh-channel**: RFC 4254 channel messages, flow control, `ChannelManager`, `ForwardHandle`
- **russh-sftp**: SFTP v3 wire codec and `SftpFileServer` (14 operations, chroot enforcement)
- **russh-scp**: wire protocol helpers
- **russh-config**: OpenSSH config parser, `Host` glob matching, token expansion
- **russh-observability**: `EventSink` / `MetricsHook` traits, `tracing` and `metrics` feature backends, `MemorySink`
- **russh-integration**: smoke-test harness, OpenSSH interop helpers
- Fuzz target scaffolding: `fuzz_packet_codec`, `fuzz_auth_parse`, `fuzz_config_parse`
- Security baselines: `#[deny(unsafe_code)]` workspace-wide, `ZeroizeOnDrop` on session keys, `subtle::ConstantTimeEq` for all security-sensitive comparisons
- 158 tests, 0 unsafe blocks
