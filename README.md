# RuSSH

RuSSH is a layered Rust workspace for building secure, OpenSSH-compatible SSH clients and servers.

## Workspace crates

- `russh-core`: protocol types, packet framing, and shared errors.
- `russh-crypto`: algorithm and policy primitives with secure defaults.
- `russh-transport`: client/server transport/session configuration and lifecycle.
- `russh-auth`: authentication types, policies, and certificate checks.
- `russh-channel`: channel primitives, forwarding handles, jump chains, multiplexing pool.
- `russh-sftp`: SFTP packet model + client/server shell.
- `russh-scp`: SCP compatibility client primitives.
- `russh-config`: OpenSSH-like config parser and normalization helpers.
- `russh-observability`: typed telemetry events and metrics hooks.
- `russh-integration`: integration scenarios and compatibility harness.

## Security posture

- Secure defaults; weak legacy algorithms require explicit opt-in.
- Unsafe code denied at workspace lint level.
- Threat model tracked in `docs/threat-model.md`.

## Status

This repository contains the v1 architecture skeleton with compileable APIs, tests, and CI scaffolding. It is ready for iterative protocol and cryptographic hardening work.
