#!/bin/bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# RUSTC_WRAPPER for the Cloud Build Rust steps (cloudbuild/ci.yaml).
# Every step that compiles Rust points RUSTC_WRAPPER here.
set -euo pipefail
# sccache replaces Cargo's jobserver, including for uncached binaries.
# Preserve the serial compiler bound for the linked server lib-test.
if [[ " $* " == *" --crate-name mkit_server "* &&
      " $* " == *" crates/mkit-server/src/lib.rs "* &&
      " $* " == *" --test "* &&
      " $* " == *" --emit=dep-info,link "* ]]; then
  exec "$@"
fi
# Cargo's JSON renderer drops raw stdout, including sccache's signal
# diagnostics. Copy it to stderr on failure and preserve the exit code.
output=$(mktemp)
trap 'rm -f "$output"' EXIT
status=0
sccache "$@" >"$output" || status=$?
cat "$output"
if [ "$status" -ne 0 ]; then
  cat "$output" >&2
fi
exit "$status"
