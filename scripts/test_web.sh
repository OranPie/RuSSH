#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

echo "[1/4] cargo check -p russh-web"
cargo check -p russh-web

echo "[2/4] cargo check wasm client"
cargo check --manifest-path crates/russh-web-wasm/Cargo.toml --target wasm32-unknown-unknown

echo "[3/4] build wasm and regenerate pkg"
cargo build --release --target wasm32-unknown-unknown --manifest-path crates/russh-web-wasm/Cargo.toml
"${HOME}/.cargo/bin/wasm-bindgen" \
  --target web \
  --out-dir crates/russh-web/src/pkg \
  crates/russh-web-wasm/target/wasm32-unknown-unknown/release/russh_web_wasm.wasm

echo "[4/4] sanity checks"
rg -n "ws-tunnel|connect_tcp" crates/russh-web/src/lib.rs crates/russh-web/src/index.html crates/russh-web-wasm/src/lib.rs >/dev/null
rg -n "function connect\(|mode" crates/russh-web/src/index.html >/dev/null

echo "web checks passed"
