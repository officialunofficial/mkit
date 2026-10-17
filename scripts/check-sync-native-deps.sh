#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# The `connect-native` dependency gate for `mkit-sync`.
#
# `connect-native` is a small native HTTP channel (hyper over rustls on a
# current-thread runtime, gzip as the only content coding). For the builds an
# embedding native addon uses, the normal dependency graph must contain:
#
#   - no zstd at all: not `zstd`, `zstd-safe` or `zstd-sys` (so no C zstd
#     library), with pack decode through the pure-Rust `ruzstd`;
#   - no second C crypto library (`aws-lc-*`, `openssl*`, `native-tls`), no platform trust store (`rustls-native-certs`),
#     no brotli, no HTTP/2 (`h2`),
#     no Connect runtime (`connectrpc`) and no `reqwest`;
#   - no tokio multi-thread scheduler (`rt-multi-thread`);
#
# and it must contain the pieces that make it work: `flate2` (gzip), `hyper`,
# `rustls`, `ring` and (in the pack-ruzstd row) `ruzstd`.
#
# Rows checked:
#   --no-default-features --features pack-ruzstd,connect-native  (the addon build)
#   --no-default-features --features connect-native
# Both are printed with their crate counts so a reviewer sees the footprint,
# and both are compiled (`cargo check --lib`).

set -euo pipefail

cd "$(dirname "$0")/.."

fail=0
err() {
  echo "check-sync-native-deps: $*" >&2
  fail=1
}

banned=(ruzstd zstd zstd-safe zstd-sys aws-lc-rs aws-lc-sys openssl openssl-sys native-tls
  rustls-native-certs brotli async-compression brotli-decompressor libz-sys hyper-tls h2 connectrpc reqwest)

check_row() {
  local features=$1 want_ruzstd=$2
  local tree feats count
  tree=$(cd rust && cargo tree --locked -p mkit-sync --no-default-features \
    --features "$features" -e normal --target all --prefix none)
  # Bans also cover build edges, so a build-time zstd cannot hide.
  built=$(cd rust && cargo tree --locked -p mkit-sync --no-default-features \
    --features "$features" -e normal,build --target all --prefix none)
  feats=$(cd rust && cargo tree --locked -p mkit-sync --no-default-features \
    --features "$features" -e normal,features --target all --prefix none)
  count=$(printf '%s\n' "$tree" | awk '{print $1}' | sort -u | wc -l | tr -d ' ')
  echo "check-sync-native-deps: [$features] $count unique crates"
  for pkg in "${banned[@]}"; do
    if grep -q "^$pkg " <<<"$built"; then
      err "[$features] the graph contains $pkg"
    fi
  done
  # Canary: the feature listing must show tokio's `rt`, else the negative
  # check below would pass on a changed output format.
  grep -q 'tokio feature "rt"' <<<"$feats" || err "[$features] cannot read tokio's features"
  if grep -q 'tokio feature "rt-multi-thread"' <<<"$feats"; then
    err "[$features] tokio's multi-thread scheduler is enabled"
  fi
  for pkg in flate2 hyper rustls ring; do
    grep -q "^$pkg " <<<"$tree" || err "[$features] the graph lacks $pkg"
  done
  if [ "$want_ruzstd" = yes ]; then
    grep -q '^mkit-ruzstd ' <<<"$tree" || err "[$features] the graph lacks mkit-ruzstd"
  fi
  # The graph is not the build: compile the row so a cfg or feature break
  # specific to it cannot merge unnoticed.
  (cd rust && cargo check --locked -p mkit-sync --no-default-features \
    --features "$features" --lib) || err "[$features] does not compile"
}

check_row pack-ruzstd,connect-native yes
check_row connect-native no

if [ "$fail" -ne 0 ]; then
  exit 1
fi
echo "check-sync-native-deps: OK"
