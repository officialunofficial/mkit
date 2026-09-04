#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Minimal smoke check shared by release-verify.yml's per-distribution-
# channel jobs (crates.io, cargo binstall, install.sh, Homebrew):
# version contract, then a basic init/keygen/add/commit flow. Distinct
# from scripts/release-smoke.sh, which additionally verifies a GitHub
# Release ARCHIVE's cosign signature, SHA256SUMS entry, and bundled man
# page/completions — those don't apply to a channel that installs just
# the binary (cargo install, npm has no mkit binary at all, etc.).
#
# Usage: scripts/basic-flow-smoke.sh <path-to-mkit-binary> <expected-version>

set -euo pipefail

bin="${1:-}"
version="${2:-}"
if [ -z "$bin" ] || [ -z "$version" ]; then
  echo "usage: $0 <path-to-mkit-binary> <expected-version>" >&2
  exit 2
fi
if [ ! -x "$bin" ]; then
  echo "basic-flow-smoke: not an executable: $bin" >&2
  exit 1
fi

out="$("$bin" version)"
expected="mkit ${version}"
if [ "$out" != "$expected" ]; then
  echo "basic-flow-smoke: version contract violated: got [$out], expected [$expected]" >&2
  exit 1
fi
echo "basic-flow-smoke: version contract OK: ${out}"

repo_dir="$(mktemp -d)"
trap 'rm -rf "$repo_dir"' EXIT
(
  cd "$repo_dir"
  "$bin" init
  "$bin" keygen
  echo "hello" > README.md
  "$bin" add README.md
  "$bin" commit -m "smoke test commit"
)
echo "basic-flow-smoke: basic init/keygen/add/commit flow OK"
