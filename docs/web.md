# Web Client Guide

## Overview

RuSSH web has two modes:

- `Legacy` (`/ws`): server terminates SSH.
- `Secure Tunnel` (`/ws-tunnel`, preferred): server only forwards opaque TCP bytes; SSH transport/auth execute in browser WASM.

In secure tunnel mode, the bridge does not parse SSH payloads.

## Endpoints

- UI static files: serve `crates/russh-web/src/`
- Legacy bridge: `ws://<host>:<port>/ws`
- Secure tunnel bridge: `ws://<host>:<port>/ws-tunnel`

## Local Run

```bash
./scripts/run_web_local.sh
```

Then open:

- `http://127.0.0.1:8088`
- Select `Mode = Secure Tunnel (Preferred)`
- Set `WebSocket URL = ws://127.0.0.1:8090/ws-tunnel`

## Build + Verify

```bash
./scripts/test_web.sh
```

This script checks:

1. `cargo check -p russh-web`
2. wasm crate check for `wasm32-unknown-unknown`
3. wasm build + `wasm-bindgen` generation into `crates/russh-web/src/pkg`
4. basic source sanity checks

## Browser Compatibility

If you see `invalid value type 'externref'`, rebuild compatibility assets:

```bash
RUSTFLAGS='-C target-feature=-reference-types' \
  cargo build --release --target wasm32-unknown-unknown \
  --manifest-path crates/russh-web-wasm/Cargo.toml
~/.cargo/bin/wasm-bindgen \
  --target web \
  --out-dir crates/russh-web/src/pkg \
  crates/russh-web-wasm/target/wasm32-unknown-unknown/release/russh_web_wasm.wasm
```

Then hard refresh the page (`Ctrl+Shift+R`).

## Troubleshooting

- Stuck after `SSH-2.0...` banner:
  - You are likely in JS fallback. Tunnel mode requires WASM SSH engine.
- `WebSocket error`:
  - Confirm bridge process is listening (`ss -ltnp | rg ':8090'`).
  - Confirm URL/path (`/ws-tunnel` vs `/ws`).
- WASM failed to load:
  - Check `crates/russh-web/src/pkg` exists and page can fetch `russh_web_wasm.js` and `.wasm`.

## Security Notes

- Use `Secure Tunnel` for privacy against bridge-side session inspection.
- Legacy mode is for compatibility and debugging only.
