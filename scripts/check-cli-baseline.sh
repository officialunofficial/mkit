#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# The server-free CLI check (PRD MKIT-29 Q1; docs/INVARIANTS.md, "The
# default `mkit` CLI is server-free"). For the DEFAULT features of
# `mkit-cli`, on every target, the normal dependency graph must contain:
#
#   - no `axum`, `mkit-server-native`, `rusqlite` or `libsqlite3-sys`;
#   - no hyper `server` feature, no hyper-util `server*` feature, and no
#     connectrpc `server` or `axum` feature;
#   - `mkit-server` (the engine of `mkit serve`) with only its `ssh` and
#     `fs` features, never `connect`, `sql`, `memory` or `test-faults`;
#
# and `mkit serve` (rust/crates/mkit-cli/src/commands/serve/) must not name
# tokio: it runs its session under `futures::executor::block_on` and builds
# no async runtime.
#
# tokio itself is NOT banned: the default CLI graph has it through the
# Connect client (`mkit-transport-connect`) and reqwest's blocking client,
# and `mkit-server` uses `tokio::sync` alone. Nor is tower-http, reqwest's
# redirect layer. This is a fast `cargo tree` model of the graph; the
# release build's compiler artifacts are checked separately by
# scripts/check-release-artifact-features.sh.

set -euo pipefail

cd "$(dirname "$0")/.."

fail=0
err() {
  echo "check-cli-baseline: $*" >&2
  fail=1
}

tree=$(cd rust && cargo tree --locked -p mkit-cli -e normal --target all --prefix none)
features=$(cd rust && cargo tree --locked -p mkit-cli -e normal,features --target all --prefix none)

for pkg in axum mkit-server-native rusqlite libsqlite3-sys; do
  if printf '%s\n' "$tree" | grep -q "^$pkg "; then
    err "the default mkit-cli graph contains $pkg"
  fi
done

banned_features=(
  'hyper feature "server"'
  'hyper-util feature "server'
  'connectrpc feature "server"'
  'connectrpc feature "axum"'
)
for f in "${banned_features[@]}"; do
  if printf '%s\n' "$features" | grep -qF "$f"; then
    err "the default mkit-cli graph enables $(printf '%s\n' "$features" | grep -F "$f" | sort -u | tr '\n' ' ')"
  fi
done

extra=$(printf '%s\n' "$features" \
  | sed -n 's/^mkit-server feature "\([^"]*\)".*/\1/p' \
  | sort -u | grep -vxE 'ssh|fs' || true)
if [ -n "$extra" ]; then
  err "mkit-cli enables mkit-server features beyond ssh, fs: $(printf '%s' "$extra" | tr '\n' ' ')"
fi

if grep -rn 'tokio' rust/crates/mkit-cli/src/commands/serve; then
  err "\`mkit serve\` (rust/crates/mkit-cli/src/commands/serve/) names tokio; it must build no async runtime"
fi

if [ "$fail" -ne 0 ]; then
  echo "check-cli-baseline: FAILED (see docs/INVARIANTS.md, \"The default \`mkit\` CLI is server-free\")" >&2
  exit 1
fi
echo "check-cli-baseline: OK (no axum/SQLite/mkit-server-native, no server features; mkit-server: ssh, fs)"
