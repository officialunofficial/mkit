#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Fail if `ed25519-dalek` or `sha2` are pinned to more than one
# Cargo-semver-compatible version across the repo's Cargo workspaces.
#
# WHY: several crates independently re-verify signatures/digests the same
# byte-for-byte way another crate already does (mkit-wasm's Ed25519 exports
# vs. mkit-core::sign, apps/*-worker's write-envelope strict-verify vs.
# mkit-core), and the golden-vector / cross-impl-parity tests assert that
# stays true. Two Cargo-incompatible versions of the same crypto crate in
# the dependency graph can silently diverge in wire-visible behavior (see
# ed25519-dalek 2->3 dropping the `std` feature and re-deriving errors from
# `core::error::Error`, or a future change to signature/verification
# semantics) with nothing forcing every workspace to move together.
#
# This is a version-string check, not a build: it does not catch a
# same-compatible-version behavior change, only a drifted pin across
# workspaces. "Cargo-semver-compatible" follows Cargo's own caret-default
# rule: for 0.y.z, y is the breaking component (0.10 and 0.11 are
# incompatible); for x.y.z with x >= 1, x is the breaking component.

set -euo pipefail

cd "$(dirname "$0")/.."

fail=0

# Cargo workspaces/standalone packages that may declare these crates.
# Built as an array (not a plain string) so a path is never re-split
# on whitespace; `mapfile`/`readarray` need Bash 4+, unavailable on
# macOS's stock /bin/bash (3.2), so this uses a Bash-3.2-safe
# NUL-delimited read loop instead.
MANIFESTS=()
while IFS= read -r -d '' manifest; do
  MANIFESTS+=("$manifest")
done < <(find rust contrib/signers apps -name Cargo.toml -not -path '*/target/*' -print0)

# Extracts the version string after either `crate = "X.Y"` or
# `crate = { version = "X.Y", ... }`, then normalizes it to Cargo's
# semver-compatibility channel (see file header). Plain POSIX ERE (`sed -E`)
# on purpose — no GNU-only `-P`/`\K`, so this also runs correctly with
# BSD sed/grep on a contributor's Mac, not just CI's GNU toolchain.
channel_of() {
  awk -F. '{ if ($1 == "0") print "0." $2; else print $1 }'
}

check_crate() {
  local crate="$1"
  local channels
  channels=$(
    sed -nE "s/^${crate}[[:space:]]*=[[:space:]]*(\\{[^}]*version[[:space:]]*=[[:space:]]*)?\"([0-9]+(\\.[0-9]+)?).*/\\2/p" "${MANIFESTS[@]}" 2>/dev/null \
      | channel_of \
      | sort -u
  )
  local count
  count=$(echo "$channels" | grep -c . || true)
  if [ "$count" -gt 1 ]; then
    echo "error: ${crate} is pinned to more than one Cargo-compatible version across the repo: $(echo "$channels" | tr '\n' ' ')"
    grep -n -E "^${crate}[[:space:]]*=" "${MANIFESTS[@]}"
    fail=1
  fi
}

check_crate "ed25519-dalek"
check_crate "sha2"

if [ "$fail" -ne 0 ]; then
  echo
  echo "See docs/INVARIANTS.md ('Single crypto-stack version across workspaces')."
  exit 1
fi

echo "ok: ed25519-dalek and sha2 are each pinned to a single Cargo-compatible version"
