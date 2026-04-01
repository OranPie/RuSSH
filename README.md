# RuSSH

RuSSH is a layered Rust workspace for building secure, OpenSSH-compatible SSH clients and servers.

[![CI](https://github.com/RuSSH/RuSSH/actions/workflows/ci.yml/badge.svg)](https://github.com/RuSSH/RuSSH/actions/workflows/ci.yml)
[![Rust 1.89+](https://img.shields.io/badge/rust-1.89%2B-orange.svg)](https://www.rust-lang.org)

## Features

- **Real cryptography** — AES-256-GCM, AES-256-CTR, AES-128-CTR, ChaCha20-Poly1305, HMAC-SHA-256/512 (ETM), SHA-256/512
- **Key exchange** — Curve25519-SHA256 (RFC 8731), ECDH-NIST-P256-SHA256, DH group14-sha256, DH group16-sha512 (4096-bit), DH group18-sha512 (8192-bit)
- **Host keys** — Ed25519, ECDSA-P256/P-384/P-521, RSA (sha2-256 / sha2-512); OpenSSH certificates (Ed25519, ECDSA, RSA)
- **Encrypted private keys** — bcrypt-pbkdf key derivation, OpenSSH `-----BEGIN OPENSSH PRIVATE KEY-----` format; passphrase-protected keys
- **Full auth engine** — publickey, password (constant-time), keyboard-interactive; GSSAPI scaffolding; `AllowUsers`/`DenyUsers` policy enforcement; `LoginGraceTime` timeout (120 s default)
- **SSH Agent** — `SSH_AUTH_SOCK` agent protocol (`list_identities`, `sign`), agent forwarding (`-A`)
- **Channel multiplexing** — RFC 4254 flow-controlled channels with window management
- **Port forwarding** — local (`-L`), remote (`-R`), dynamic SOCKS4/5 proxy (`-D`); `cancel-tcpip-forward` with listener teardown; active listener registry; Unix socket forwarding (`direct-streamlocal@openssh.com`)
- **ProxyJump** — multi-hop connections through jump hosts (`-J` / `ProxyJump` config)
- **Compression** — `zlib@openssh.com` delayed compression
- **Strict KEX** — CVE-2023-48795 mitigation (sequence number reset, packet order enforcement)
- **SFTP v3** — complete wire codec + filesystem server; `fsetstat`/`setstat` handlers; symlink/readlink; extensions: posix-rename, statvfs, hardlink, fsync
- **SCP** — file/directory wire protocol with timestamp preservation (T-directive)
- **OpenSSH config** — Host pattern matching, first-match-wins resolution, `%h`/`%u` tokens, `~` expansion, `ProxyJump`/`ControlMaster`/`ControlPath`; `Include` directive with glob and tilde expansion (depth-limited to prevent circular includes)
- **Transport extras** — `SSH_MSG_DEBUG` packet handling; TCP `SO_KEEPALIVE` on client and server sockets
- **CLI client** — `russh` binary with `-L`, `-R`, `-D`, `-N`, `-f`, `-J`, `-A`, `-F`, `-i`, `-o` flags; keepalive; terminal resize
- **Web client** — xterm.js terminal over WebSocket with secure WASM tunnel mode
- **Observability** — `EventSink` and `MetricsHook` wired through `russh-net`; `tracing` and `metrics` feature-gated backends; `MemorySink` for tests
- **Security hardening** — `#[deny(unsafe_code)]`, `ZeroizeOnDrop` on session keys, `subtle::ConstantTimeEq` for secrets
- **Fuzz infrastructure** — libfuzzer targets for packet codec, auth parser, and config parser

### Algorithm compatibility matrix

| Category | Algorithms |
|----------|-----------|
| **KEX** | `curve25519-sha256`, `ecdh-sha2-nistp256`, `diffie-hellman-group14-sha256`, `diffie-hellman-group16-sha512`, `diffie-hellman-group18-sha512` |
| **Host key** | `ssh-ed25519`, `ecdsa-sha2-nistp256`, `ecdsa-sha2-nistp384`, `ecdsa-sha2-nistp521`, `rsa-sha2-256`, `rsa-sha2-512` |
| **Ciphers** | `aes256-gcm@openssh.com`, `chacha20-poly1305@openssh.com`, `aes256-ctr`, `aes128-ctr` |
| **MACs** | `hmac-sha2-256-etm@openssh.com`, `hmac-sha2-512-etm@openssh.com` |
| **Compression** | `none`, `zlib@openssh.com` |
| **Certificates** | `ssh-ed25519-cert-v01@openssh.com`, `ecdsa-sha2-nistp256-cert-v01@openssh.com`, `rsa-sha2-256-cert-v01@openssh.com` |

### CLI flags (`russh`)

| Flag | Description |
|------|-------------|
| `-i PATH` | Identity file (repeatable for multiple keys) |
| `-F PATH` | SSH config file (default: `~/.ssh/config`) |
| `-L [bind:]port:host:hostport` | Local port forwarding |
| `-R [bind:]port:host:hostport` | Remote port forwarding |
| `-D [bind:]port` | Dynamic SOCKS4/5 proxy |
| `-J host` | ProxyJump through a jump host |
| `-N` | No remote commands (port-forward only) |
| `-f` | Background mode (detach after authentication) |
| `-A` | Enable agent forwarding |
| `-o KEY=VALUE` | OpenSSH-style option override (see below) |

**Supported `-o` options:** `Port`, `User`, `IdentityFile`, `ServerAliveInterval`,
`Compression`, `KexAlgorithms`, `Ciphers`, `MACs`, `HostKeyAlgorithms`,
`PasswordAuthentication`, `PreferredAuthentications`

## Workspace crates

| Crate | Description |
|-------|-------------|
| `russh-crypto` | AES-GCM, ChaCha20-Poly1305, SHA-2, HMAC, Curve25519 KEX, Ed25519, key derivation |
| `russh-core` | Packet framing (RFC 4253 §6), error types, algorithm negotiation primitives |
| `russh-transport` | SSH handshake state machine: version exchange → KEX → NewKeys → auth dispatch |
| `russh-auth` | publickey / password / keyboard-interactive; Ed25519 signature verification |
| `russh-channel` | RFC 4254 channel messages, flow control, `ChannelManager`, port-forward handles |
| `russh-sftp` | SFTP v3 wire codec, `SftpFileServer`, `SftpFramer`, high-level `SftpClient` |
| `russh-scp` | SCP wire protocol (`ScpFileHeader`, `ScpDirHeader`, build/parse helpers) |
| `russh-config` | OpenSSH config parser, `resolve_for_host`, Host glob matching, token expansion |
| `russh-observability` | `EventSink` / `MetricsHook` traits; `tracing` and `metrics` optional backends |
| `russh-net` | Async TCP client/server (`SshClient`, `SshServer`, SFTP, SCP, exec); observability wiring; `SO_KEEPALIVE` |
| `russh-web` | WebSocket bridge + static terminal UI (`/ws` legacy, `/ws-tunnel` secure opaque TCP tunnel) |
| `russh-web-wasm` | Browser SSH client core (WASM) used by secure tunnel mode |
| `russh-integration` | End-to-end smoke scenarios, OpenSSH interop helpers |

## Quick start

```toml
[dependencies]
russh-crypto  = { path = "crates/russh-crypto" }
russh-transport = { path = "crates/russh-transport" }
```

## Build & test

```sh
cargo build --workspace
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings

# With optional observability backends
cargo test -p russh-observability --features tracing,metrics

# Fuzz (requires cargo-fuzz + nightly)
cargo +nightly fuzz run fuzz_packet_codec
```

## Web Client (Secure Tunnel Mode)

Run local web UI + bridge:

```sh
./scripts/run_web_local.sh
```

Then open `http://127.0.0.1:8088` and use:

- `Mode`: `Secure Tunnel (Preferred)`
- `WebSocket URL`: `ws://127.0.0.1:8090/ws-tunnel`

Security model:

- `/ws` (legacy): server terminates SSH and can observe plaintext session data.
- `/ws-tunnel` (preferred): server forwards opaque TCP bytes only; SSH transport/auth run in-browser via WASM.

For full web setup, compatibility notes, and troubleshooting, see [`docs/web.md`](docs/web.md).

## Security posture

- `#[deny(unsafe_code)]` enforced at workspace level — zero unsafe blocks.
- Secret key material wrapped in `Zeroizing<_>` or `#[derive(ZeroizeOnDrop)]`.
- All secret comparisons use `subtle::ConstantTimeEq` to prevent timing attacks.
- Weak legacy algorithms require explicit `AlgorithmSet::allow_legacy()` opt-in.
- Threat model tracked in [`docs/threat-model.md`](docs/threat-model.md).

## Status

v0.7 delivers comprehensive protocol coverage, CLI maturity, and OpenSSH compatibility —
including expanded KEX (DH group16/group18), full ECDSA family (P-256/P-384/P-521),
encrypted private key support (bcrypt-pbkdf), OpenSSH certificates for all key types,
remote and dynamic port forwarding (SOCKS4/5), Unix socket forwarding, `AllowUsers`/`DenyUsers`
policy enforcement, `LoginGraceTime`, SFTP `fsetstat`/`setstat`, `Include` config directive
with glob expansion, `SSH_MSG_DEBUG` handling, TCP `SO_KEEPALIVE`, and observability fully
wired through `russh-net`. The test suite covers **495 tests, 0 failures, 0 unsafe blocks**.
See [`docs/implementation-status.md`](docs/implementation-status.md)
for a full feature matrix and [`docs/roadmap.md`](docs/roadmap.md) for upcoming work.
