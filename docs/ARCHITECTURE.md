# RuSSH Architecture

## Overview

RuSSH is a 14-crate Rust workspace implementing the SSH protocol (RFC 4251–4254, 8731) as
layered, composable components. The workspace enforces `#[deny(unsafe_code)]` globally and
targets OpenSSH/PuTTY compatibility.

Protocol concerns are separated into discrete crates with a strict dependency DAG: lower layers
expose only stable, well-typed interfaces; higher layers compose them without reaching down past
their immediate dependencies. Every layer uses the unified `RusshError`/`RusshErrorCategory`
error type from `russh-core` — there are no crate-local error types.

---

## Crate Dependency Graph

```
russh-cli  russh-web  russh-web-wasm  russh-integration
     \          |           |              /
      \         |           |             /
       +------> russh-net <-+            /
                    |                   /
        +-----------+----------+       /
        |           |          |      /
  russh-sftp   russh-scp  russh-channel  russh-config
        |           |          |
        +-----------+------> russh-auth
                                |
                         russh-transport
                         /           \
                   russh-crypto   russh-observability
                         \           /
                          russh-core  (no upstream deps)
```

### Layer 0 — No dependencies

| Crate | Role |
|-------|------|
| **russh-core** | Shared primitives: `RusshError`/`RusshErrorCategory`, `PacketCodec` (RFC 4253 §6 binary-packet framing with AEAD hooks), `AlgorithmSet` for negotiation, `PacketFrame`. |

### Layer 1 — Depends only on russh-core

| Crate | Role |
|-------|------|
| **russh-crypto** | All cryptographic primitives: AEAD ciphers (AES-256-GCM, ChaCha20-Poly1305, AES-CTR), HMAC-ETM MACs, KEX (Curve25519, ECDH-P256/384/521, DH group14/16/18), session-key derivation (RFC 4253 §7.2), signers/verifiers (Ed25519, RSA-SHA2, ECDSA P-256/384/521), `CryptoPolicy` with `secure_defaults()` and `legacy_compat()` constructors. |
| **russh-observability** | `EventSink` and `MetricsHook` traits for telemetry. Feature-gated backends: `tracing` → `TracingEventSink`, `metrics` → `MetricsEventSink`/`MetricsCounterHook`. `MemorySink` for in-test assertions. Both features are off by default. |

### Layer 2 — Depends on russh-core + russh-crypto

| Crate | Role |
|-------|------|
| **russh-transport** | SSH transport-layer state machine (`ClientSession`/`ServerSession`): version-string exchange, KEXINIT proposal send/receive (`KexInitProposal`), KEX execution, NEWKEYS, strict-KEX mode (CVE-2023-48795 countermeasure), SSH_MSG_DEBUG, service-request dispatch, rekeying, `NegotiatedAlgorithms`, `SessionKeys`, `TransportConfigBuilder`. |
| **russh-auth** | Authentication engine: publickey, password, keyboard-interactive, GSSAPI; `ServerAuthPolicy` (AllowUsers/DenyUsers/LoginGraceTime); `CertificateValidator`; `OpenSshCertificate` parsing; pluggable traits (`HostKeyStore`, `KnownHostsStore`, `IdentityProvider`, `AgentClient`); in-memory test doubles (`MemoryHostKeyStore`, `MemoryKnownHostsStore`, `MemoryIdentityProvider`, `MemoryAuthorizedKeys`). |
| **russh-channel** | RFC 4254 channel protocol: `Channel`, `ChannelId`, `ChannelManager`, flow-control (local/remote window tracking), all channel-message types (`ChannelMessage`, `ChannelRequest`, `ChannelKind`), `ForwardHandle` (direct-tcpip, tcpip-forward, streamlocal), `JumpChain`, `ConnectionPool`, SOCKS4/5 parser (`socks.rs`). |

### Layer 3 — Domain crates

| Crate | Role |
|-------|------|
| **russh-sftp** | SFTP v3 server: `SftpFileServer` with chroot enforcement, all 18 standard operations, 4 OpenSSH extensions (posix-rename, statvfs, hardlink, fsync), fsetstat/setstat, `SftpFramer`, `FileAttrs`. |
| **russh-scp** | SCP wire protocol: `ScpFileHeader`/`ScpDirHeader`, T-directive timestamp preservation, build/parse helpers. |
| **russh-config** | OpenSSH config parser: Host-block matching (glob/negation/wildcards), first-match-wins resolution, Include directive (glob + depth limiting), token expansion (`%h`/`%u`/`%%`/`~`), all common directives; unknown directives produce warnings rather than errors. |

### Layer 4 — Network binding

| Crate | Role |
|-------|------|
| **russh-net** | Central hub binding in-memory state machines to real TCP I/O. Key types: `SshClientConnection` (`.connect()`, `.authenticate_password/pubkey()`, `.exec()`, `.open_shell()`, `.sftp()`, `.scp_upload()`), `SshServerConnection`, `SshServer`, `SessionHandler` trait, `DefaultSessionHandler`. `PacketStream<S>` abstracts over TCP/WebSocket/jump-host transports; SO_KEEPALIVE; tcpip-forward lifecycle tracking; observability wiring. |

### Layer 5 — Application layer

| Crate | Role |
|-------|------|
| **russh-cli** | `russh` client binary and `russhd` server binary. TOFU host-key verification (`verify_or_trust_host_key()`). Full flag set: `-i`, `-F`, `-L`, `-R`, `-D`, `-N`, `-f`, `-A`, `-J`, `-o`. Key format: `RUSSH-SEED-V1` for Ed25519 identity files; encrypted-key passphrase prompting. |
| **russh-web** | Axum HTTP server with embedded xterm.js terminal over WebSocket → SSH relay. Two endpoints: `/ws` (legacy) and `/ws-tunnel` (secure opaque TCP). Two-phase protocol: JSON connect request followed by binary I/O relay. Entry point: `app(Arc<StderrLogger>) -> Router`. |
| **russh-web-wasm** | WASM build of the SSH client, consumed by the xterm.js frontend. Compiled with `wasm-bindgen`; speaks the same WebSocket protocol as `russh-web`; exposes JS callbacks for status, info, error, and binary data. |
| **russh-integration** | Smoke-test harness (`run_bootstrap_scenario`), OpenSSH interop helpers. Not a library API; never depended on by other crates. |

---

## Key Data Flow: Client Connection

The following describes how a connection travels through the crate layers from TCP dial to
interactive channel use.

```
russh-net          russh-transport        russh-crypto          russh-auth        russh-channel
    |                     |                     |                    |                  |
(1) TcpStream::connect
    → PacketStream<TcpStream>
    |
(2) ClientSession::begin_handshake
    → version string exchange (RFC 4253 §4)
    |
(3)               KEXINIT send/receive
                  KexInitProposal negotiation
    |
(4)                              Curve25519KeyPair (or ECDH/DH)
                                 compute_exchange_hash
                                 derive_session_keys
    |
(5) NEWKEYS → PacketCodec AEAD hooks activated
    |
(6)                                            AuthRequest
                                               IdentityProvider::sign
                                               UserAuth exchange
    |
(7)                                                              Channel::open
                                                                 ChannelId assigned
    |
(8)                                                              exec / shell /
                                                                 SFTP / SCP /
                                                                 port-forward
    |
(9) EventSink::on_* called at every step (russh-observability)
```

**Step-by-step:**

1. **TCP connect** (`russh-net`) — `SshClientConnection::connect()` dials the remote host and
   wraps the `TcpStream` in `PacketStream<TcpStream>` (or `PacketStream<WebSocket>` for the web
   path). SO_KEEPALIVE is set immediately.

2. **Banner exchange** (`russh-transport`) — `ClientSession::begin_handshake` exchanges
   SSH identification strings (RFC 4253 §4). The remote banner is stored for later hash input.

3. **KEXINIT** (`russh-transport`) — Both sides send `SSH_MSG_KEXINIT` (`KexInitProposal`).
   `NegotiatedAlgorithms` is resolved by intersecting the two lists in preference order.

4. **KEX** (`russh-crypto` + `russh-transport`) — The negotiated method executes (e.g.
   `Curve25519KeyPair::generate_ephemeral` → DH exchange → `compute_exchange_hash`).
   `derive_session_keys` (RFC 4253 §7.2) produces six key streams.

5. **NEWKEYS** — Derived `SessionKeys` are loaded into `PacketCodec`'s AEAD hooks; all
   subsequent packets are encrypted and authenticated.

6. **Service request → USERAUTH** (`russh-auth`) — An `AuthRequest` is built; the
   `IdentityProvider` supplies (or signs with) the private key; the
   `KnownHostsStore`/`HostKeyStore` verifies the server host key. TOFU is handled in
   `russh-cli` via `verify_or_trust_host_key()`.

7. **Channel open** (`russh-channel`) — `ChannelManager` assigns a `ChannelId` and tracks
   window sizes. `SSH_MSG_CHANNEL_OPEN_CONFIRMATION` completes the handshake.

8. **Channel data** — Depending on use case: `exec` runs a remote command; `open_shell`
   creates a PTY session; `sftp()` hands off to `russh-sftp`; `scp_upload()` uses
   `russh-scp`; port-forwarding uses `ForwardHandle` and SOCKS parsing in `russh-channel`.

9. **Observability** — `EventSink::on_connect`, `::on_auth`, `::on_channel_open`, `::on_error`
   and `MetricsHook` counters are emitted at every significant transition.

---

## Key Design Decisions

### 1. No unsafe code
`unsafe_code = "deny"` is set at workspace level in `[workspace.lints.rust]`. Every crate
inherits this lint. Memory safety is achieved entirely through safe Rust and the ownership model.

### 2. Unified error type
`RusshError` (with variant-tagging via `RusshErrorCategory`) lives in `russh-core` and is the
only error type used across all crates. Conversions from third-party errors (`io::Error`, cipher
errors, etc.) are implemented with `From` impls in the appropriate crate. Crate-local error
enums are prohibited.

### 3. Pluggable backends
Traits for key stores, agent clients, and telemetry are defined in the protocol crates
(`russh-auth`, `russh-observability`). Concrete implementations belong outside the core crates
(production implementations in `russh-cli`/`russh-net`; test doubles in `russh-auth` itself
and in `russh-integration`). This keeps the protocol crates free of I/O dependencies.

### 4. Fail-closed
Parse errors, authentication failures, and cryptographic errors all return `Err(RusshError)`.
There is no "degrade gracefully" path; partial or ambiguous state is never silently accepted.
Strict-KEX mode (CVE-2023-48795) is enforced in `russh-transport` when the peer supports it.

### 5. Secure defaults
`CryptoPolicy::secure_defaults()` excludes legacy CBC-mode ciphers and SHA-1 MACs. Legacy
algorithm support is available only through `CryptoPolicy::legacy_compat()`, which must be
explicitly constructed — it is never returned by a default constructor.

### 6. Secret hygiene
Session keys and ephemeral DH/ECDH values are held in types implementing `ZeroizeOnDrop` or
wrapped in `Zeroizing<Vec<u8>>`. All security-sensitive comparisons (MAC tags, host-key
fingerprints, password hashes) use `subtle::ConstantTimeEq` to prevent timing side-channels.

### 7. Stream abstraction
`PacketStream<S>` is generic over `tokio::io::AsyncRead + AsyncWrite`. This single abstraction
enables `russh-net` to handle plain TCP, WebSocket (for `russh-web`), and jump-host tunnels
(via `JumpChain`) without any code duplication in the state machines above it.

---

## Extension Points

All pluggable interfaces are Rust traits. Protocol crates define the trait; callers supply an
`Arc<dyn Trait>` (or similar) at construction time.

| Trait | Defined in | Purpose |
|-------|-----------|---------|
| `HostKeyStore` | `russh-auth` | Server-side host key material — load and sign with the server's long-term identity key. |
| `KnownHostsStore` | `russh-auth` | Client-side trust anchors — verify or record a server's host key (TOFU). |
| `IdentityProvider` | `russh-auth` | Client-side private key access — list available keys, sign auth payloads. |
| `AgentClient` | `russh-auth` | SSH agent protocol client — delegates signing to an external agent over a Unix socket. |
| `EventSink` | `russh-observability` | Observability events: `on_connect`, `on_auth`, `on_channel_open`, `on_channel_close`, `on_error`. Feature-gated `tracing` and `metrics` backends ship with the crate; `MemorySink` for tests. |
| `MetricsHook` | `russh-observability` | Counter-based metrics for connection, auth, and channel lifecycle events. |
| `SessionHandler` | `russh-net` | Server-side request routing — `handle_exec`, `handle_sftp`, `handle_scp`, `handle_pty_request`. `DefaultSessionHandler` is provided for simple servers; override for custom routing. |

**Test doubles** (in `russh-auth`):
- `MemoryHostKeyStore` — in-memory key map, no filesystem.
- `MemoryKnownHostsStore` — in-memory trust store, accepts all or requires explicit pre-load.
- `MemoryIdentityProvider` — holds a list of `(public_key, signer)` pairs.
- `MemoryAuthorizedKeys` — simple set of accepted public keys for server-side auth.

---

## Testing Strategy

- **Test location** — All unit tests live in `#[cfg(test)] mod tests` blocks inside each
  crate's `src/lib.rs`. There are no separate `tests/` directories per crate.
- **Async tests** — Tests requiring Tokio use `#[tokio::test]`.
- **Test doubles** — `russh-auth` ships in-memory implementations of all four pluggable auth
  traits so tests never touch the filesystem or require a running SSH agent.
- **Integration tests** — `russh-integration` provides `run_bootstrap_scenario` (full
  client↔server round-trip in process) and OpenSSH interop helpers.
- **Scale** — 495 tests across the workspace (run with
  `cargo test --workspace --all-targets`).
- **Fuzz targets** — `fuzz/` is scaffolded for `cargo-fuzz`. Priority surfaces: packet-codec
  framing (PacketCodec), auth-message parsing, and OpenSSH config parsing.
- **Crypto determinism** — `russh-crypto` exposes a `test-utils` feature with a seeded
  deterministic RNG, allowing KEX and signing tests to be reproducible without live entropy.

---

## Security Controls Summary

| Control | Mechanism | Crate |
|---------|-----------|-------|
| No memory-unsafe code | `#[deny(unsafe_code)]` workspace lint | all crates |
| Fail-closed error handling | `RusshError` return on every failure path | `russh-core` + all crates |
| Secure algorithm defaults | `CryptoPolicy::secure_defaults()` (no CBC, no SHA-1 MAC) | `russh-crypto` |
| Legacy algorithm isolation | `CryptoPolicy::legacy_compat()` explicit opt-in only | `russh-crypto` |
| Session key zeroization | `ZeroizeOnDrop` on `SessionKeys` and ephemeral key material | `russh-crypto`, `russh-transport` |
| Password/secret zeroization | `Zeroizing<Vec<u8>>` wrappers on all secret byte buffers | `russh-auth`, `russh-cli` |
| Timing-safe comparisons | `subtle::ConstantTimeEq` for MAC tags, fingerprints, passwords | `russh-crypto`, `russh-auth` |
| Strict KEX (CVE-2023-48795) | Sequence-number reset enforcement in KEXINIT state machine | `russh-transport` |
| Host key verification | `KnownHostsStore` trait; TOFU in `russh-cli` | `russh-auth`, `russh-cli` |
| Certificate validation | `CertificateValidator` + `OpenSshCertificate` parsing | `russh-auth` |
| Chroot enforcement (SFTP) | `SftpFileServer` path canonicalisation before every operation | `russh-sftp` |
| Auth policy enforcement | `ServerAuthPolicy` (AllowUsers, DenyUsers, LoginGraceTime) | `russh-auth` |
| Observability (audit trail) | `EventSink` events at every connection, auth, and channel transition | `russh-observability`, `russh-net` |
