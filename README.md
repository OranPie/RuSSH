# RuSSH

RuSSH is a layered Rust workspace for building secure, OpenSSH-compatible SSH clients and servers.

[![CI](https://github.com/RuSSH/RuSSH/actions/workflows/ci.yml/badge.svg)](https://github.com/RuSSH/RuSSH/actions/workflows/ci.yml)
[![Rust 1.89+](https://img.shields.io/badge/rust-1.89%2B-orange.svg)](https://www.rust-lang.org)

## Features

- **Real cryptography** — AES-256-GCM, AES-128-GCM, ChaCha20-Poly1305, HMAC-SHA-256/512, SHA-256/512
- **Curve25519-SHA256 KEX** — RFC 8731 compliant; ECDH-NIST-P256-SHA256 also supported
- **Ed25519 host keys** — signature generation and verification; exchange hash per RFC 4253 §8
- **Full auth engine** — publickey (Ed25519), password (constant-time), keyboard-interactive
- **Channel multiplexing** — RFC 4254 flow-controlled channels with window management
- **SFTP v3** — complete wire codec + filesystem-backed server (draft-ietf-secsh-filexfer-02)
- **SCP** — file/directory wire protocol helpers (C/D/E headers, ACK, build/parse helpers)
- **OpenSSH config** — Host pattern matching, first-match-wins resolution, `%h`/`%u` tokens, `~` expansion
- **Observability** — `tracing` and `metrics` feature-gated backends; `MemorySink` for tests
- **Security hardening** — `#[deny(unsafe_code)]`, `ZeroizeOnDrop` on session keys, `subtle::ConstantTimeEq` for secrets
- **Fuzz infrastructure** — libfuzzer targets for packet codec, auth parser, and config parser

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
| `russh-net` | **v0.2** Async TCP client/server (`SshClient`, `SshServer`, SFTP, SCP, exec) |
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

## Security posture

- `#[deny(unsafe_code)]` enforced at workspace level — zero unsafe blocks.
- Secret key material wrapped in `Zeroizing<_>` or `#[derive(ZeroizeOnDrop)]`.
- All secret comparisons use `subtle::ConstantTimeEq` to prevent timing attacks.
- Weak legacy algorithms require explicit `AlgorithmSet::allow_legacy()` opt-in.
- Threat model tracked in [`docs/threat-model.md`](docs/threat-model.md).

## Status

v0.1 implements the complete SSH protocol stack from cryptographic primitives
through encrypted transport, authentication, channels, file transfer, and
configuration resolution. See [`docs/implementation-status.md`](docs/implementation-status.md)
for a full feature matrix and [`docs/roadmap.md`](docs/roadmap.md) for upcoming work.
