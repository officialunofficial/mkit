#!/usr/bin/env bash
#
# C compiler shim: compiles C for a Darwin target on Linux with `zig cc`.
# cc-rs passes Apple-style `-arch`, `--target=arm64-apple-macosx` and
# `-mmacosx-version-min`, which zig cc rejects, so the shim drops them and uses the zig `-target` instead.
#
# Usage (set by cloudbuild/darwin.yaml):
#   ZIG_DARWIN_TARGET=aarch64-macos CC_aarch64_apple_darwin=scripts/zig-cc-darwin.sh
set -euo pipefail

: "${ZIG_DARWIN_TARGET:?set ZIG_DARWIN_TARGET, e.g. aarch64-macos}"

args=()
skip=0
for a in "$@"; do
  if [ "$skip" -eq 1 ]; then skip=0; continue; fi
  case "$a" in
    -arch) skip=1 ;;
    -mmacosx-version-min=*|--target=*) ;;
    *) args+=("$a") ;;
  esac
done

exec python3 -m ziglang cc -target "$ZIG_DARWIN_TARGET" "${args[@]}"
