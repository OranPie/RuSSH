# RuSSH Implementation Status

## Delivered in this bootstrap

- Workspace with 10 crates and shared package policy.
- Stable core API types (`RusshError`, config/auth/channel/session primitives).
- Secure crypto policy defaults with explicit legacy opt-in.
- SSH-like packet framing codec.
- OpenSSH-style config parser preserving unknown directives and warnings.
- Typed observability interfaces with event sink + metrics hook extension points.
- Integration harness smoke scenario wiring parser + handshake + auth + channel.
- CI workflow for formatting, clippy, and tests across Linux/macOS/Windows.

## Pending for production-grade SSH

- Real cryptographic implementation and key exchange engines.
- Full SSH transport packet/state machine with encrypted framing.
- End-to-end networked client/server implementations and OpenSSH interop fixtures.
- Production SFTP/SCP protocol engines (streaming, metadata, permissions, resume).
- Agent forwarding protocol bridge, ProxyJump tunneling, and robust multiplexing.
- Fuzz targets, performance harness, and long-run soak tests.
