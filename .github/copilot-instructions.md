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

The development toolchain is pinned to **1.89.0** via `rust-toolchain.toml` (use `rustup` if the channel is missing). The workspace MSRV (`rust-version` in `Cargo.toml`) is **1.85**.

## Architecture

RuSSH is a 13-crate Rust workspace implementing SSH protocol layers. Crates form a strict dependency DAG:

```
russh-cli  russh-web  russh-integration
     \          |          /
      \         |         /
       +--> russh-net <--+
                |
   +---------+--+---------+
   |         |            |
russh-sftp  russh-scp  russh-channel  russh-config
   |         |            |
   +---------+------> russh-core  (no deps)
                       ^  ^
russh-transport -------+  |
  ├── russh-auth           |
  └── russh-crypto         |
russh-observability -------+
```

**Protocol / wire layer:**
- **russh-core**: `RusshError`/`RusshErrorCategory`, `PacketCodec`, `AlgorithmSet` — shared primitives, no upstream deps.
- **russh-crypto**: `CryptoPolicy` with `secure_defaults()` / `legacy_compat()` variants; `KeyAlgorithm`; pluggable `RandomSource` trait.
- **russh-transport**: `TransportConfigBuilder`, `ClientSession`, `NegotiatedAlgorithms`, `KexInitProposal`.
- **russh-auth**: `AuthRequest`, `AuthResult`, `ServerAuthPolicy`; pluggable traits: `HostKeyStore`, `KnownHostsStore`, `IdentityProvider`, `AgentClient`.
- **russh-channel**: `Channel`, `ChannelId`, `ForwardHandle`, `JumpChain`, `ConnectionPool`.
- **russh-observability**: `EventSink` and `MetricsHook` traits for telemetry.

**Network binding layer:**
- **russh-net**: Central hub that binds in-memory state machines to real TCP I/O. Key types: `SshClientConnection` (`.connect()`, `.authenticate_password/pubkey()`, `.exec()`, `.open_shell()`, `.sftp()`, `.scp_upload()`), `SshServerConnection`, `SshServer`, `SessionHandler` trait, `DefaultSessionHandler`. `PacketStream<S>` abstracts over TCP/WebSocket/jump-host transports.

**Application layer:**
- **russh-cli**: `russh` client and `russhd` server binaries. Implements TOFU host-key verification (`verify_or_trust_host_key()`). Key format: "RUSSH-SEED-V1" for Ed25519 identity files.
- **russh-web**: Axum HTTP server serving an embedded xterm.js terminal over WebSocket → SSH relay. Two-phase: JSON connect request then binary I/O relay. Entry point: `app(Arc<StderrLogger>) -> Router`.
- **russh-integration**: smoke-test harness (`run_bootstrap_scenario`), not a library API.

## Key conventions

### Error handling
All crates use the unified `RusshError` / `RusshErrorCategory` from `russh-core`. Do not introduce crate-local error types; map to these instead.

### Security posture
- `unsafe_code = "deny"` is set at workspace level — no unsafe code.
- Weak/legacy algorithms must use the `legacy_compat()` config path, never the default.
- Fail-closed: parse/auth/crypto errors must return `Err`, never silently continue.
- Secrets (keys, passwords) must be wrapped in `Zeroizing<_>` or types that implement `ZeroizeOnDrop`.
- Use `subtle::ConstantTimeEq` for all security-sensitive comparisons to prevent timing attacks.

### Extensibility pattern
Pluggable backends (key stores, agent clients, telemetry sinks) are defined as traits in their respective crates. Implementations belong outside the core crates (or in `russh-integration` for test doubles).

### Configuration
`CryptoPolicy`, `TransportConfig`, `ClientConfig`, and `ServerConfig` all expose a `secure_defaults()` constructor. Use the builder (`TransportConfigBuilder`) for layered overrides. `russh-config` parses OpenSSH-style files and preserves unknown directives as warnings rather than errors.

### Auth test doubles
`russh-auth` ships in-memory implementations for use in tests and `russh-integration`: `MemoryHostKeyStore`, `MemoryKnownHostsStore`, `MemoryIdentityProvider`, `MemoryAuthorizedKeys`. Use these as fixtures rather than building your own trait implementations from scratch.

### Feature flags
- `russh-observability`: enable `tracing` for `TracingEventSink` / `NoopSink`, or `metrics` for `MetricsEventSink` / `MetricsCounterHook`. Both are off by default.
- `russh-crypto`: the `test-utils` feature exposes deterministic RNG helpers for use in tests.

### Reference docs
`docs/` contains `threat-model.md`, `implementation-status.md`, and `roadmap.md`. Check `implementation-status.md` before adding new protocol features — it tracks what is and isn't wired up yet.

### Tests
Tests live in `#[cfg(test)]` modules inside `lib.rs` — no separate `tests/` directories per crate. Use the crate's own public constructors as test fixtures; there is no shared test utility crate.

### Fuzz targets
`fuzz/` is scaffolded but empty. New fuzz targets should focus on parser/decoder surfaces (packet framing, config parsing).
