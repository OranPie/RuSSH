# russh-web-wasm

Browser-side SSH client core for the RuSSH static web UI.

## Responsibilities

- WebSocket bridge setup (`/ws` and `/ws-tunnel`)
- Full SSH client path in tunnel mode:
  - banner exchange
  - KEX / NEWKEYS
  - password or Ed25519 public-key auth
  - PTY + shell channel
- Terminal byte relay to/from the page

## Build (default)

```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.92
cargo build --release --target wasm32-unknown-unknown --manifest-path crates/russh-web-wasm/Cargo.toml
wasm-bindgen \
  --target web \
  --out-dir crates/russh-web/src/pkg \
  crates/russh-web-wasm/target/wasm32-unknown-unknown/release/russh_web_wasm.wasm
```

## Compatibility build (older browsers)

Some runtimes fail on `externref`. Build with:

```bash
RUSTFLAGS='-C target-feature=-reference-types' \
  cargo build --release --target wasm32-unknown-unknown \
  --manifest-path crates/russh-web-wasm/Cargo.toml
wasm-bindgen \
  --target web \
  --out-dir crates/russh-web/src/pkg \
  crates/russh-web-wasm/target/wasm32-unknown-unknown/release/russh_web_wasm.wasm
```

The static UI at `crates/russh-web/src/index.html` imports `./pkg/russh_web_wasm.js`.
