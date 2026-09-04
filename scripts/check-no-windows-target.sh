#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Fail if a Windows CI/release leg, a Windows-only keystore backend, or a
# Windows-only installer artifact has crept back into the repo.
#
# WHY: commonware-runtime 2026.9.0's non-Linux storage-sync path calls
# `libc::sync()` (rust/crates/mkit-core's `history-mmr`/`sparse-checkout`
# dev-deps and mkit-transport-enc pull commonware-runtime in unconditionally),
# which does not exist on `x86_64-pc-windows-msvc` — the workspace and its
# test suite no longer build there. Rather than maintain an untested
# Windows-only build/release leg, Windows was dropped as a supported target
# (MKIT-6; see docs/INVARIANTS.md). This check turns a reintroduced Windows
# leg — a CI job, a keystore feature, an installer artifact — into a
# config-time error instead of a red build discovered later.
#
# Scope: workflow/action YAML, the justfile, every crate manifest, the POSIX
# installer, and the web app's installer-asset assertion script/manifest.
# CHANGELOG.md and other prose that documents the removal itself are
# excluded — they are expected to mention Windows by name. Deliberately NOT
# a glob over every apps/web/scripts/*.mjs: an unrelated script (e.g.
# gen-headers.mjs) can legitimately name "install.ps1" in prose (to say what
# it does NOT cover) without that being a reintroduced Windows artifact —
# scope this to the one script whose job is asserting installer assets
# exist.

set -euo pipefail

cd "$(dirname "$0")/.."

# Pattern -> what it would mean if it reappeared. Kept as a fixed list (not
# a bare "windows" grep) so this doesn't fire on unrelated hits — legitimate
# `.windows(n)` slice-iterator calls, OS-abstraction `cfg(windows)` arms that
# mirror already-supported-platform code (see docs/CONTRIBUTING "Confirmed
# DO-NOT-TOUCH" notes), or `\\?\`/`NUL` git-interop path handling.
PATTERNS=(
  'windows-latest'
  'pc-windows-msvc'
  'backend-windows-credential'
  'windows-credential'
  "install\\.ps1"
  "cfg\\(windows\\)'\\.dependencies"
)

# Files/dirs that legitimately document the removal (or its history) and are
# expected to name Windows.
EXCLUDE_PATHS=(
  ':!CHANGELOG.md'
  ':!docs/INVARIANTS.md'
  ':!scripts/check-no-windows-target.sh'
)

SEARCH_PATHS=(
  '.github/workflows'
  '.github/actions'
  'justfile'
  'rust/crates/*/Cargo.toml'
  'contrib/**/Cargo.toml'
  'install.sh'
  'apps/web/package.json'
  'apps/web/scripts/assert-installer.mjs'
  'apps/web/.gitignore'
)

fail=0
for pattern in "${PATTERNS[@]}"; do
  if hits=$(git -c core.quotepath=false grep -InE "$pattern" -- "${SEARCH_PATHS[@]}" "${EXCLUDE_PATHS[@]}" 2>/dev/null); then
    echo "::error::found a reintroduced Windows target reference matching /${pattern}/:" >&2
    echo "$hits" >&2
    fail=1
  fi
done

if [ "$fail" -ne 0 ]; then
  echo "check-no-windows-target FAILED — see docs/INVARIANTS.md's \"Windows is not a build, test, or release target\" entry." >&2
  exit 1
fi

echo "check-no-windows-target passed: no Windows CI leg, keystore backend, or installer artifact found."
