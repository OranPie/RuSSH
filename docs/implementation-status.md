# RuSSH Implementation Status — v0.7

## Delivered in v0.7

### SSH_MSG_DEBUG handling (`russh-transport`)
- `SSH_MSG_DEBUG` (type 4) packets decoded and passed to `EventSink::on_debug_message()`
- `always_display` flag and language tag preserved; debug messages no longer silently dropped

### Config Include directive (`russh-config`)
- `Include` directive with glob pattern expansion, `~` tilde expansion, and recursive depth limiting (default 16, prevents circular includes)
- A→B→A circular includes and self-includes are detected and halted at the depth limit
- Missing or empty glob matches produce warnings, not errors

### SFTP fsetstat / setstat (`russh-sftp`)
- `SSH_FXP_FSETSTAT` (opcode 10): set attributes on an open file handle
- `SSH_FXP_SETSTAT` (opcode 9): set attributes by path; permission bits, timestamps applied via `std::fs`

### TCP keepalive (`russh-net`)
- `SO_KEEPALIVE` set on both client and server TCP sockets via `socket2` crate
- Applied at socket level before `TcpStream` is handed to the transport layer

### tcpip-forward lifecycle tracking (`russh-net`)
- Active forward listener registry: maps bind address to `JoinHandle` + cancel token
- `cancel-tcpip-forward` tears down the registered listener atomically
- Prevents dangling listeners on session close

### Observability wiring (`russh-net`, `russh-observability`)
- `EventSink` and `MetricsHook` traits now threaded through `SshClientConnection` and `SshServerConnection`
- Per-connection event emission: connect, auth, channel open/close, forward, error
- `TracingEventSink` (feature `tracing`) and `MetricsEventSink` (feature `metrics`) available as drop-in implementations

### SOCKS proxy wiring (`russh-channel`, `russh-net`)
- SOCKS4/5 handshake fully wired: SOCKS request parsed → `direct-tcpip` channel opened to target → bidirectional relay
- SOCKS5 domain names resolved server-side through the SSH connection
- SOCKS4a domain support

## Delivered in v0.6

### Encrypted private key support (`russh-cli`, `russh-crypto`)
- `-----BEGIN OPENSSH PRIVATE KEY-----` format with bcrypt-pbkdf KDF passphrase decryption
- RUSSH-SEED-V1 format for Ed25519 identity files (raw 32-byte seed)
- CLI passphrase prompt for encrypted keys via `read_passphrase()`

### Wider algorithm support (`russh-crypto`, `russh-transport`)
- **Host key algorithms**: ECDSA P-384 (`ecdsa-sha2-nistp384`) and P-521 (`ecdsa-sha2-nistp521`) signers and verifiers
- **Key exchange**: `diffie-hellman-group16-sha512` (4096-bit MODP, RFC 3526 §4) and `diffie-hellman-group18-sha512` (8192-bit MODP, RFC 3526 §6); SHA-512 used for both exchange hash and key derivation
- **Certificates**: `OpenSshCertificate` generalized to support Ed25519, RSA, and ECDSA cert key types; serializes/deserializes cert public key block per key algorithm

### Server hardening (`russh-auth`, `russh-config`, `russh-net`)
- **AllowUsers / DenyUsers**: Parsed from SSH config; enforced in `ServerAuthPolicy` before auth succeeds (DenyUsers takes precedence over AllowUsers)
- **LoginGraceTime**: 120s default; `tokio::time::timeout` wraps the entire authentication phase; configurable via `LoginGraceTime` directive
- **`cancel-tcpip-forward`**: Global request handler tears down the active TCP listener registered for that bind address, returns success/failure response

### Advanced forwarding (`russh-net`, `russh-channel`, `russh-cli`)
- **GSSAPI scaffolding**: `AuthMethod::GssapiWithMic` variant; method name `gssapi-with-mic`; infrastructure for future Kerberos wiring
- **Unix socket forwarding**: `direct-streamlocal@openssh.com` channel type; `ForwardHandle::streamlocal()` constructor; `parse_direct_streamlocal_extra()` for socket path extraction
- **SOCKS4/5 proxy**: `-D [bind:]port` flag spawns local TCP listener; `socks.rs` module parses SOCKS4 (IP + userid) and SOCKS5 (IP/domain/IPv6) CONNECT requests; relays over `direct-tcpip` channel
- **Remote port forwarding**: `-R [bind:]port:host:hostport` global request; `tcpip-forward` request/response; server-side channel opens forwarded connections back to client

### CLI flags (`russh-cli`)
- `-N` — No remote commands; keeps connection alive for port forwarding (uses `tokio::signal::ctrl_c()` to block)
- `-f` — Background mode; detaches process after authentication completes
- `-D [bind:]port` — Dynamic SOCKS4/5 proxy
- `-R [bind:]port:host:hostport` — Remote port forwarding

## Delivered in v0.5

### Expanded cryptographic algorithm support (`russh-crypto`)

- **Host key algorithms**: ECDSA-P256 (`ecdsa-sha2-nistp256`) signer/verifier with DER-encoded
  (r, s) signatures; RSA (`rsa-sha2-256`, `rsa-sha2-512`) signing with 3072-bit key generation
  (2048-bit minimum validation) and PKCS#1 DER public key format.
- **Ciphers**: AES-256-CTR and AES-128-CTR (non-AEAD, paired with ETM MACs).
- **MACs**: `hmac-sha2-256-etm@openssh.com` and `hmac-sha2-512-etm@openssh.com` encrypt-then-MAC.
- **Key exchange**: `diffie-hellman-group14-sha256` (2048-bit MODP group from RFC 3526).
- **`AlgorithmSet::secure_defaults()`** now advertises:
  - KEX: `curve25519-sha256`, `ecdh-sha2-nistp256`, `diffie-hellman-group14-sha256`
  - Host key: `ssh-ed25519`, `ecdsa-sha2-nistp256`, `rsa-sha2-256`, `rsa-sha2-512`
  - Ciphers: `aes256-gcm@openssh.com`, `aes256-ctr`, `aes128-ctr`
  - MACs: `hmac-sha2-256-etm@openssh.com`, `hmac-sha2-512-etm@openssh.com`
  - Compression: `none`, `zlib@openssh.com`

### Compression (`russh-transport`)

- `zlib@openssh.com` delayed compression negotiated in `KexInitProposal` and
  `NegotiatedAlgorithms`. Compression activates after user authentication completes,
  matching OpenSSH behaviour.

### Strict KEX hardening (`russh-transport`)

- Full CVE-2023-48795 mitigation via `kex-strict-c-v00@openssh.com` /
  `kex-strict-s-v00@openssh.com` extensions. Sequence number reset after NEWKEYS,
  packet order enforcement during key exchange window
  (`enforce_strict_kex_packet_order`, `strict_kex_window_active`).

### Keyboard-interactive auth — server + client (`russh-auth`, `russh-cli`)

- Server-side: `AuthRequest::KeyboardInteractive`, `UserAuthMessage::KeyboardInteractiveInfoRequest`
  with prompt list, `UserAuthMessage::KeyboardInteractiveInfoResponse` decode. Full
  encode/decode support for challenge-response flows.
- Client-side: CLI prompts interactively and sends `InfoResponse` replies.

### Password auth — client CLI (`russh-cli`)

- `read_password()` reads from stdin with echo disabled; password sent via
  `authenticate_password()`. Enabled by default, configurable with
  `-o PasswordAuthentication=yes|no`.

### Auth method ordering (`russh-cli`)

- `-o PreferredAuthentications=publickey,keyboard-interactive,password` controls
  auth attempt order. Default order: `publickey → keyboard-interactive → password`.

### Multiple identity files (`russh-cli`)

- `-i` flag is repeatable; each identity file is tried in order during publickey
  auth. Also resolved from SSH config `IdentityFile` directives.

### SFTP extensions (`russh-sftp`)

- **Symlink / readlink**: `FXP_SYMLINK` and `FXP_READLINK` operations with proper
  path resolution under the chroot.
- **OpenSSH extensions** advertised during SFTP init:
  - `posix-rename@openssh.com` v1 — atomic rename via `handle_posix_rename()`
  - `statvfs@openssh.com` v2 — filesystem statistics via `handle_statvfs()`
  - `hardlink@openssh.com` v1 — hard link creation via `handle_hardlink()`
  - `fsync@openssh.com` v1 — flush file data to disk via `handle_fsync()`

### SCP timestamp preservation (`russh-scp`)

- `ScpTimestamp` struct encodes/decodes T-directives (`T<mtime> 0 <atime> 0\n`).
- `apply_timestamps()` sets file mtime/atime using the `filetime` crate.

### Local port forwarding (`russh-cli`, `russh-net`)

- `-L [bind_addr:]port:host:hostport` opens a local TCP listener, relays
  connections over a `direct-tcpip` SSH channel to the remote endpoint.
  `relay_tcp_channel()` handles bidirectional data transfer.

### Agent forwarding (`russh-cli`, `russh-net`)

- `-A` flag requests `auth-agent-req@openssh.com` on the session channel.
  `request_agent_forwarding()` sends the channel request; server tracks state
  in `ServerChannelState`.

### SSH config file integration (`russh-cli`)

- `-F path` specifies a custom SSH config file (default: `~/.ssh/config`).
  Config values are resolved via `russh-config`'s `resolve_for_host()` and
  applied to connection parameters.

### Expanded `-o` options (`russh-cli`)

Supported OpenSSH-style options via `-o KEY=VALUE`:
- `Port`, `User`, `IdentityFile`, `ServerAliveInterval`, `Compression`
- `KexAlgorithms`, `Ciphers`, `MACs`, `HostKeyAlgorithms`
- `PasswordAuthentication`, `PreferredAuthentications`

### Terminal resize (`russh-net`)

- `send_window_change()` sends RFC 4254 `window-change` channel requests with
  terminal dimensions (cols, rows, pixel width, pixel height).

### Keepalive (`russh-net`, `russh-cli`)

- `keepalive@openssh.com` global request sent at the interval specified by
  `-o ServerAliveInterval=N`. `parse_global_request()` decodes incoming keepalive
  and unknown global requests.

## Delivered in v0.4

### OpenSSH certificate support (`russh-auth`, `russh-net`)

- `ssh-ed25519-cert-v01@openssh.com` wire parsing and CA signature verification.
- Server-side: `CertificateValidator` for cert-based publickey auth.
- Client-side: `authenticate_pubkey_with_cert()` on `SshClientConnection`.
- Integration tests: RuSSH cert client → `sshd`, OpenSSH cert client → RuSSH server.

### SSH Agent Protocol (`russh-auth`, `russh-net`)

- `SshAgentClient` over `SSH_AUTH_SOCK` Unix socket; `list_identities()` and
  `sign()` per SSH-AGENT protocol.
- `authenticate_via_agent()` on `SshClientConnection`.
- Integration test against real OpenSSH `ssh-agent`.

### ProxyJump (`russh-net`)

- `SshClient::connect_via_jump()` opens a `direct-tcpip` channel to a target
  through a jump host; inner SSH session runs over a `tokio::io::duplex` bridge.
- `SshClientConnection` refactored to use boxed `AnyStream` for stream-type
  agnosticism.
- Integration test through two real `sshd` instances.

### ControlMaster config directives (`russh-config`)

- `ProxyJump`, `ControlMaster`, and `ControlPath` added to the config parser;
  token expansion (`%h`/`%u`/`%%`) and tilde expansion applied to `ControlPath`.
  Mux-socket protocol deferred to a future release.

## Delivered in v0.3

### OpenSSH interoperability

All four cross-implementation integration tests now pass:
- `russh_client_exec_against_openssh_sshd` — RuSSH client exec to real `sshd`
- `russh_client_sftp_against_openssh_sshd` — RuSSH client SFTP to real `sshd`
- `openssh_ssh_exec_against_russh_server` — `ssh` exec to RuSSH server
- `openssh_sftp_against_russh_server` — `sftp` SFTP to RuSSH server

### Bug fixes applied during v0.3

- **`russh-transport`**: `ServerSession` stores raw client KEXINIT bytes before
  parsing (`store_client_kexinit_payload`) so the exchange hash uses the original
  wire encoding, preventing mismatch when OpenSSH field order differs.
- **`russh-core`**: Removed unimplemented ciphers (`chacha20-poly1305@openssh.com`,
  `aes128-gcm@openssh.com`) from `AlgorithmSet::secure_defaults()`. Only
  `aes256-gcm@openssh.com` is advertised, avoiding negotiation of an unsupported
  cipher.
- **`russh-auth`**: Added `UserAuthRequest::None { user, service }` variant to
  handle OpenSSH's RFC 4252 §5.2 `"none"` method probe. Server responds with
  `USERAUTH_FAILURE` listing allowed methods.
- **`russh-sftp`**: `SftpFileServer::resolve_path` now treats `RootDir` as a
  no-op (strips leading `/`) rather than returning `PermissionDenied`, so
  absolute SFTP paths like `/upload.txt` work correctly under the chroot.
- **`russh-net`**: On `CHANNEL_EOF` from the client, the server now sends
  `CHANNEL_EOF + CHANNEL_CLOSE` back to unblock the remote; IO-level read errors
  (peer closed connection) are treated as a clean session end.

## Delivered in v0.2

### Async networked transport (`russh-net`)
- `PacketStream<S>`: async framing over `tokio::net::TcpStream` using `PacketCodec`
- `SshClient::connect()`: TCP connect → banner exchange → KEXINIT → ECDH → NEWKEYS → service request
- `SshClientConnection::authenticate_password()`: password auth request/response loop
- `SshClientConnection::exec()`: channel open → exec request → data collection → exit-status
- `SshClientConnection::sftp()`: SFTP subsystem channel open → `SftpSession` (init/write_file/read_file/close)
- `SshClientConnection::scp_upload()`: exec `scp -t` → SCP wire protocol upload
- `SshClientConnection::disconnect()`: `SSH_MSG_DISCONNECT`
- `SshServer::bind()`: `tokio::net::TcpListener` wrapper
- `SshServer::accept()`: returns `SshServerConnection`
- `SshServerConnection::run()`: full server handshake, password auth, exec/SFTP/SCP channel dispatch
- `SessionHandler` trait: pluggable exec handler, sftp root, scp root
- `DefaultSessionHandler`: built-in `echo <text>` and filesystem-backed SFTP/SCP
- Loopback integration test covering exec + SFTP + SCP in a single tokio test

### Bug fixes applied during v0.2

- **`russh-transport`**: `receive_kex_ecdh_reply_and_send_newkeys` now clears
  `local_kexinit_sent`, `remote_kexinit_received`, and rekey counters so that
  strict-KEX packet-order enforcement is correctly reset after a completed exchange.
- **`russh-transport`**: Added `ClientSession::store_server_kexinit_payload()` so
  that the server's raw KEXINIT bytes are captured in `kex_context` before the
  exchange hash is computed.

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

## Test coverage (current)

495 tests across all workspace crates, all passing, 0 unsafe blocks.

## Pending for future releases

- ControlMaster mux-socket protocol (mux-client wire format, `ControlMaster auto/ask`)
- X11 forwarding (`x11-req` channel request, `x11` channel type, `DISPLAY` injection)
- Hostbased authentication (`hostbased` auth method, `/etc/ssh/ssh_known_hosts` lookup)
- ProxyCommand support (spawn subprocess, relay over stdio)
- Formal GSSAPI / Kerberos wiring (replace scaffolding with real `libgssapi` or `sspi` backend)
- Certificate chain validation beyond single CA (intermediate CA support)
- Performance benchmark harness (handshake/s, MB/s throughput)
- Corpus-based fuzz campaigns with coverage metrics
- Constant-time audit by external reviewer
- API stabilization pass; deprecation of internal-only symbols
