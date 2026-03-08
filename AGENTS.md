# Repository Guidelines

## Project Structure & Module Organization
RuSSH is a Rust workspace with protocol layers split into crates under `crates/`.
- Core protocol crates: `russh-core`, `russh-crypto`, `russh-transport`, `russh-auth`, `russh-channel`
- Higher-level functionality: `russh-sftp`, `russh-scp`, `russh-config`, `russh-net`, `russh-observability`
- Apps and integration: `russh-cli`, `russh-web`, `russh-integration`
- Documentation: `docs/` (`threat-model.md`, `implementation-status.md`, `roadmap.md`)
- Fuzz scaffolding: `fuzz/` (excluded from workspace members)

## Build, Test, and Development Commands
Use Rust `1.89.0` (see `rust-toolchain.toml`).
- `cargo build --workspace` — build all crates.
- `cargo fmt --all -- --check` — formatting check (CI enforced).
- `cargo clippy --workspace --all-targets -- -D warnings` — lint with warnings as errors.
- `cargo test --workspace --all-targets --lib` — unit/library tests.
- `cargo test --workspace --test '*'` — integration/interop test targets.
- `cargo test -p russh-core` — run a single crate’s tests.

## Coding Style & Naming Conventions
- Follow `rustfmt` defaults; use 4-space indentation and standard Rust ordering/import style.
- Keep modules and functions `snake_case`, types/traits `CamelCase`, constants `SCREAMING_SNAKE_CASE`.
- Workspace forbids unsafe code (`unsafe_code = "deny"`); do not introduce `unsafe` blocks.
- Prefer shared `RusshError`/`RusshErrorCategory` patterns used across crates instead of ad hoc error types.

## Testing Guidelines
- Place tests in `#[cfg(test)] mod tests` blocks inside each crate’s `src/lib.rs`.
- Use descriptive `snake_case` test names (for async tests, use `#[tokio::test]`).
- Run crate-local tests first, then workspace-wide checks before opening a PR.
- For protocol or compatibility changes, include/adjust integration coverage in `russh-integration`.

## Commit & Pull Request Guidelines
Recent history favors concise, imperative messages, often with prefixes (`fix:`, `ci:`, `feat:`).
- Commit format: `type: short summary` (example: `fix: avoid deadlock in shell flow control`).
- Keep commits focused by crate or concern.
- PRs should include: problem statement, scope, impacted crates, and exact validation commands run.
- Link related issues; include logs or screenshots when changing CLI/web behavior.

## Security & Configuration Notes
- Preserve secure defaults; legacy algorithms must remain explicit opt-ins.
- Treat key material as sensitive (zeroization and constant-time comparisons are expected patterns).
