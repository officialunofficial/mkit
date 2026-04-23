#!/usr/bin/env bash
# Fails if any forbidden zmit-era or consumer-specific string survived the
# cleanup. The public mkit utility is generic content-addressed VCS — no
# chain-aware strings should appear in its public surface.
#
# This script excludes itself from the scan (its FORBIDDEN array
# necessarily contains the strings it is looking for).
set -euo pipefail

FORBIDDEN=(
  'zmit'
  'ZMIT'
  'ZMITFCDC'
  'vcs.makechain.net'
  '\.zmit'
  'ZMIT_'
  'makechain-vcs'
  'makechain'
  'Makechain'
  'MAKECHAIN'
  'MakechainNotary'
  'gateway_url'
  '--attest'
  '--submit'
  'project create'
)

# Paths scanned. Docs and the changelog are intentionally excluded —
# they carry historical references to the upstream "zmit" project name
# as part of the project's provenance. The public build surface (src/,
# build files, CI workflows, contrib, man, completions) MUST be clean.
SCAN_PATHS=(
  src/
  build.zig
  build.zig.zon
  contrib/
  completions/
  man/
  .github/
  README.md
  SECURITY.md
  rust/
)

EXCLUDES=(
  --exclude-dir=.git
  --exclude-dir=.zig-cache
  --exclude-dir=zig-out
  --exclude-dir=target
  --exclude=verify-rename.sh
)

fail=0
for pat in "${FORBIDDEN[@]}"; do
  # grep returns 1 on no-match, 0 on match, 2 on error; we want to flag only
  # match-found. Use `|| true` to avoid set -e tripping on no-match.
  hits=$(grep -rEn "${EXCLUDES[@]}" -- "$pat" "${SCAN_PATHS[@]}" 2>/dev/null || true)
  if [ -n "$hits" ]; then
    echo "verify-rename: forbidden string '$pat' found:"
    echo "$hits"
    fail=1
  fi
done

if [ "$fail" -eq 0 ]; then
  echo "verify-rename: OK"
fi
exit "$fail"
