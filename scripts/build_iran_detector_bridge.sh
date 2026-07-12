#!/usr/bin/env bash
# Build the iran_detector PyO3 bridge and install it into core/ so that the
# runtime `core.iran_detector` shim is Rust-backed (Gate 4). The compiled
# extension is platform + CPython-ABI specific, so it is built per environment
# rather than committed. Idempotent.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
crate="$here/rust/iran_detector_py"

echo "[bridge] building release extension…"
( cd "$crate" && cargo build --release )

so="$crate/target/release/libiran_detector_rs.so"
if [[ ! -f "$so" ]]; then
  echo "[bridge] ERROR: expected artifact not found: $so" >&2
  exit 1
fi

dest="$here/core/_iran_detector_rs.so"
cp -f "$so" "$dest"
echo "[bridge] installed -> $dest"

echo "[bridge] verifying Rust-backed import…"
( cd "$here" && python3 -c "import core.iran_detector as m; assert m._RUST_BACKED, 'shim did not load the Rust extension'; print('[bridge] OK: core.iran_detector is Rust-backed')" )
