#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Run mkit-core's decode-only `pack-ruzstd` path on a real
# wasm32-unknown-unknown target (32-bit usize) under node, over the
# committed C-encoded SPEC-PACKFILE v2 fixtures. The native test suites
# run on 64-bit, where integer-width bugs in hand-written frame parsing
# cannot show up; this lane is where they do.
#
# Harness: rust/crates/mkit-core-wasm-check (wasm-bindgen-test, run by
# `wasm-pack test --node`, the same wasm-pack the web build uses).
# See docs/INVARIANTS.md, "Both zstd backends accept exactly one frame per
# entry".

set -euo pipefail

cd "$(dirname "$0")/.."

for tool in wasm-pack node; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "error: $tool not found; the pack-ruzstd wasm32 check needs wasm-pack and node" >&2
    exit 1
  fi
done
if ! rustup target list --installed 2>/dev/null | grep -q '^wasm32-unknown-unknown$'; then
  echo "error: wasm32-unknown-unknown target not installed. Run: rustup target add wasm32-unknown-unknown" >&2
  exit 1
fi

( cd rust/crates/mkit-core-wasm-check && wasm-pack test --node )
echo "ok: pack-ruzstd decodes every v2 fixture, and pack framing is overflow-free, on wasm32-unknown-unknown"
