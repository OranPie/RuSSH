#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo "starting static UI on :8088"
(
  cd "$ROOT_DIR/crates/russh-web/src"
  python3 -m http.server 8088
) &
STATIC_PID=$!

echo "starting russh-web bridge on :8090"
(
  cd "$ROOT_DIR"
  cargo run -p russh-web --bin russh-web -- -b 127.0.0.1 -p 8090
) &
BRIDGE_PID=$!

cleanup() {
  kill "$STATIC_PID" "$BRIDGE_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

echo "UI:     http://127.0.0.1:8088"
echo "Bridge: ws://127.0.0.1:8090/ws-tunnel (preferred)"
echo "Bridge: ws://127.0.0.1:8090/ws (legacy)"
wait
