# RuSSH Implementation Status — v0.1

## Delivered in v0.1

### Cryptographic primitives (`russh-crypto`)
- OS-backed CSPRNG (`OsRng`)
- AEAD ciphers: AES-256-GCM, AES-128-GCM, ChaCha20-Poly1305
- Hash: SHA-256, SHA-512
- MAC: HMAC-SHA-256, HMAC-SHA-512 (constant-time verify via `subtle`)
- Key exchange: Curve25519-SHA256 (RFC 8731), ECDH-NIST-P256-SHA256
- Signatures: Ed25519 sign + verify
- RFC 4253 §7.2 key derivation (labels A–F, SHA-256, extension blocks)
- SSH wire helpers: `encode_mpint`, `encode_ssh_string`, `decode_ssh_string`

### Packet framing (`russh-core`)
- RFC 4253 §6 packet codec (length, padding, sequence numbers)
- OS-entropy random padding via `getrandom`
- Closure-based AEAD hooks (`encode_aead` / `decode_aead`) to avoid circular deps
- AEAD nonce derivation: `fixed_iv XOR seqnum` (right-justified, big-endian)

### Transport state machine (`russh-transport`)
- Version exchange (`SSH-2.0-RuSSH_0.1`)
- Algorithm negotiation (`SSH_MSG_KEXINIT` / strict-KEX extension)
- Curve25519-SHA256 ECDH KEX with exchange hash (RFC 4253 §8)
- Ed25519 host key signing and verification
- Session key derivation into `SessionKeys` (ZeroizeOnDrop)
- Service request / `SSH_MSG_USERAUTH_REQUEST` dispatch
- Re-key thresholds (byte count + time)

### Authentication engine (`russh-auth`)
- `publickey`: RFC 4252 signing payload + Ed25519 signature verification
- `password`: constant-time comparison (`subtle::ConstantTimeEq`)
- `keyboard-interactive`: InfoRequest / InfoResponse challenge-response
- `MemoryAuthorizedKeys`: in-memory store with CT key lookup
- `FileIdentityProvider`: reads `.pub` files from disk
- `CertificateValidator` stub (pluggable chain validation)

### Channel protocol (`russh-channel`)
- All 11 RFC 4254 channel messages (types 90–100) with binary codec
- Typed channel requests: pty-req, shell, exec, env, signal, exit-status,
  exit-signal, subsystem, window-change
- `ChannelState`: local/remote window tracking, `WINDOW_ADJUST` generation
- `ChannelManager`: multi-channel demultiplexer
- `ForwardHandle`: `direct-tcpip` open payload builder
- `JumpChain`, `MultiplexPool`

### SFTP v3 (`russh-sftp`)
- Full SFTP v3 wire codec (`SftpWirePacket` encode/decode)
- `SftpFileServer`: all 14 operations against a chrooted filesystem
- `SftpFramer`: streaming framer (yields complete packets from byte stream)
- `FileAttrs` with size/uid/gid/permissions/timestamps
- `SftpStatus` code mapping (SSH_FX_*)

### SCP protocol (`russh-scp`)
- `ScpFileHeader` / `ScpDirHeader` encode/decode (C/D header format)
- `SCP_END_DIR` / `SCP_ACK` / `SCP_ERR` constants
- `build_scp_file_upload` / `parse_scp_file_receive` helpers

### Config resolution (`russh-config`)
- OpenSSH-style `Host` block parser
- `resolve_for_host`: first-match-wins across all matching blocks
- Glob pattern matching (`*` / `?` / `!negation`) — `matches_host_patterns`
- `%h` (hostname) / `%u` (username) / `%%` token expansion
- `~` tilde expansion in path values
- `Include` directive recognized

### Observability (`russh-observability`)
- `EventSink` + `MetricsHook` traits
- `NoopSink`, `NoopMetrics` (defaults)
- `MemorySink` for testing
- `TracingEventSink` (feature `tracing`) — debug/info/warn tracing events
- `MetricsEventSink` + `MetricsCounterHook` (feature `metrics`) — counter increments

### Security hardening
- `#[deny(unsafe_code)]` workspace-wide
- `SessionKeys` in `russh-transport`: `#[derive(ZeroizeOnDrop)]`
- `KexKeyPair.secret`, `KexResult.shared_secret`: `Zeroizing<Vec<u8>>`
- All secret comparisons use `subtle::ConstantTimeEq`
- HMAC verification uses `hmac` crate's built-in CT verify

### Fuzz infrastructure
- `fuzz/fuzz_targets/fuzz_packet_codec.rs` — PacketCodec::decode
- `fuzz/fuzz_targets/fuzz_auth_parse.rs` — UserAuthMessage::decode
- `fuzz/fuzz_targets/fuzz_config_parse.rs` — parse_config

### Integration
- `openssh_available` / `openssh_version` / `run_openssh_version_check`
- Graceful skip when OpenSSH is not installed

### CI
- Format, clippy, test matrix: Ubuntu / macOS / Windows × stable Rust 1.89

## Test coverage

158 tests across all 10 crates, all passing.

## Pending for v0.2+

- Networked TCP transport (async I/O integration, tokio/async-std)
- OpenSSH interop fixtures (spawn real sshd/ssh binaries)
- Agent forwarding protocol bridge
- ProxyJump / `nc`-mode tunneling
- Certificate (OpenSSH cert format) validation
- Performance benchmark harness
- Corpus-based fuzz campaigns with coverage metrics
