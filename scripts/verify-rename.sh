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
# as part of the project's provenance. The public build surface
# (rust/, CI workflows, contrib, man, completions) MUST be clean.
SCAN_PATHS=(
  rust/
  contrib/
  completions/
  man/
  .github/
  README.md
  SECURITY.md
)

EXCLUDES=(
  --exclude-dir=.git
  --exclude-dir=target
  --exclude=verify-rename.sh
)

# Lines whose ONLY match against a FORBIDDEN pattern is one of these
# allowed substrings are neutralized. Use sparingly — every entry here
# is a deliberate exception to the rename gate. Each must be a fixed
# string, not a regex.
ALLOWLIST=(
  '@makechain/mkit-wasm'  # npm package name; token is scoped to @makechain
)

fail=0
for pat in "${FORBIDDEN[@]}"; do
  # grep returns 1 on no-match, 0 on match, 2 on error; we want to flag only
  # match-found. Use `|| true` to avoid set -e tripping on no-match.
  hits=$(grep -rEn "${EXCLUDES[@]}" -- "$pat" "${SCAN_PATHS[@]}" 2>/dev/null || true)
  # Strip allowlisted substrings from each hit line before re-checking
  # for the forbidden pattern. A line that only contained the forbidden
  # string AS PART OF an allowlisted substring vanishes.
  if [ -n "$hits" ] && [ "${#ALLOWLIST[@]}" -gt 0 ]; then
    filtered="$hits"
    for allow in "${ALLOWLIST[@]}"; do
      filtered=$(printf '%s\n' "$filtered" | sed "s|${allow}||g")
    done
    # Re-check: keep only lines that still contain the forbidden pat.
    hits=$(printf '%s\n' "$filtered" | grep -E -- "$pat" || true)
  fi
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
