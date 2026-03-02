# RuSSH Copilot Instructions

## Build, test, and lint

```bash
# Format check
cargo fmt --all -- --check

# Lint (warnings are errors)
cargo clippy --workspace --all-targets -- -D warnings

# Run all tests
cargo test --workspace --all-targets

# Run tests for a single crate
cargo test -p russh-core

# Run a single test
cargo test -p russh-core packet_round_trip
```

Toolchain is pinned to **1.89.0** via `rust-toolchain.toml`. Use `rustup` if the channel is missing.

## Architecture

RuSSH is a 10-crate Rust workspace implementing SSH protocol layers. Crates form a strict dependency DAG:

```
russh-integration (top-level harness)
├── russh-sftp / russh-scp  →  russh-channel  →  russh-transport
│                                               ├── russh-auth
│                                               └── russh-crypto
└── russh-config
         all above  →  russh-core  (no deps)
└── russh-observability  →  russh-core
```

- **russh-core**: `RusshError`/`RusshErrorCategory`, `PacketCodec`, `AlgorithmSet` — shared primitives, no upstream deps.
- **russh-crypto**: `CryptoPolicy` with `secure_defaults()` / `legacy_compat()` variants; `KeyAlgorithm`; pluggable `RandomSource` trait.
- **russh-transport**: `TransportConfigBuilder`, `ClientSession`, `NegotiatedAlgorithms`, `KexInitProposal`.
- **russh-auth**: `AuthRequest`, `AuthResult`, `ServerAuthPolicy`; pluggable traits: `HostKeyStore`, `KnownHostsStore`, `IdentityProvider`, `AgentClient`.
- **russh-channel**: `Channel`, `ChannelId`, `ForwardHandle`, `JumpChain`, `ConnectionPool`.
- **russh-observability**: `EventSink` and `MetricsHook` traits for telemetry.
- **russh-integration**: smoke-test harness (`run_bootstrap_scenario`), not a library API.

## Key conventions

### Error handling
All crates use the unified `RusshError` / `RusshErrorCategory` from `russh-core`. Do not introduce crate-local error types; map to these instead.

### Security posture
- `unsafe_code = "deny"` is set at workspace level — no unsafe code.
- Weak/legacy algorithms must use the `legacy_compat()` config path, never the default.
- Fail-closed: parse/auth/crypto errors must return `Err`, never silently continue.

### Extensibility pattern
Pluggable backends (key stores, agent clients, telemetry sinks) are defined as traits in their respective crates. Implementations belong outside the core crates (or in `russh-integration` for test doubles).

### Configuration
`CryptoPolicy`, `TransportConfig`, `ClientConfig`, and `ServerConfig` all expose a `secure_defaults()` constructor. Use the builder (`TransportConfigBuilder`) for layered overrides. `russh-config` parses OpenSSH-style files and preserves unknown directives as warnings rather than errors.

### Tests
Tests live in `#[cfg(test)]` modules inside `lib.rs` — no separate `tests/` directories per crate. Use the crate's own public constructors as test fixtures; there is no shared test utility crate.

### Fuzz targets
`fuzz/` is scaffolded but empty. New fuzz targets should focus on parser/decoder surfaces (packet framing, config parsing).
