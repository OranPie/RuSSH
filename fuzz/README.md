# Fuzz Targets (Planned)

Planned fuzz entry points:
- `russh-core`: packet decoder and binary parsing.
- `russh-config`: directive parser and malformed line handling.
- `russh-sftp`: SFTP packet decoding and id/length boundary handling.
- `russh-transport`: handshake state transitions.

Recommended setup:
1. `cargo install cargo-fuzz`
2. Create dedicated fuzz crates under `fuzz/` per target crate.
3. Wire corpus seeds from OpenSSH-compatible packet/config samples.
