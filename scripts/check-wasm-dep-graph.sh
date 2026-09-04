#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Fail if the wasm32 dependency graph of mkit's browser/edge-facing crates
# pulls in a C-toolchain crate (blst, zstd-sys) or commonware's native
# storage/runtime stack (commonware-runtime, commonware-storage) — none of
# these build for `wasm32-unknown-unknown`, and mkit-wasm / apps/repo-worker
# are default-features=false specifically to keep them out (see
# crates/mkit-core/Cargo.toml and crates/mkit-attest/Cargo.toml's wasm
# comments). This is a fast `cargo tree` check, not a build: it does not
# replace `cargo build --target wasm32-unknown-unknown`, only catches a
# manifest change that widened the dependency graph before a slow wasm
# build (or a CI run without the target installed) would.
#
# See docs/INVARIANTS.md, "mkit-wasm and apps/repo-worker wasm32
# dependency graphs contain no C-toolchain crates".

set -euo pipefail

cd "$(dirname "$0")/.."

fail=0

# `tokio` is checked for mkit-wasm (which has no legitimate reason to pull
# it — it's a pure wasm-bindgen crypto/hashing shim) but NOT for
# apps/repo-worker: repo-worker legitimately depends on `connectrpc` and
# `worker` (Cloudflare workers-rs), both of which pull in `tokio` for its
# wasm-compatible sync/time primitives, unrelated to commonware or to
# mkit's own crates. Checking for it there would flag a dependency this
# repo already accepts, not a regression.
check_tree() {
  local label="$1"
  local manifest_dir="$2"
  shift 2
  local forbidden=("$@")

  if ! command -v cargo >/dev/null 2>&1; then
    echo "warning: cargo not found; skipping wasm dep-graph check for ${label}"
    return
  fi
  if ! rustup target list --installed 2>/dev/null | grep -q '^wasm32-unknown-unknown$'; then
    echo "warning: wasm32-unknown-unknown target not installed; skipping wasm dep-graph check for ${label} (run: rustup target add wasm32-unknown-unknown)"
    return
  fi

  local tree
  if ! tree=$(cd "$manifest_dir" && cargo tree --target wasm32-unknown-unknown -e normal --prefix none 2>&1); then
    echo "error: 'cargo tree --target wasm32-unknown-unknown' failed for ${label}:"
    echo "$tree"
    fail=1
    return
  fi

  local crate
  for crate in "${forbidden[@]}"; do
    if echo "$tree" | grep -qE "^${crate} v"; then
      echo "error: ${label}'s wasm32 dependency graph pulls in '${crate}', which does not build for wasm32-unknown-unknown:"
      echo "$tree" | grep -E "^${crate} v"
      fail=1
    fi
  done
}

check_tree "mkit-wasm" "rust/crates/mkit-wasm" blst zstd-sys commonware-runtime commonware-storage tokio
check_tree "apps/repo-worker" "apps/repo-worker" blst zstd-sys commonware-runtime commonware-storage

if [ "$fail" -ne 0 ]; then
  echo
  echo "See docs/INVARIANTS.md (\"mkit-wasm and apps/repo-worker wasm32 dependency graphs contain no C-toolchain crates\")."
  exit 1
fi

echo "ok: mkit-wasm and apps/repo-worker wasm32 dependency graphs contain no C-toolchain crates"
