#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Fail if any docs/specs/SPEC-*.md file is missing a `status:` frontmatter
# field, or the value isn't a recognized token from SPEC-CONVENTIONS.md §2.1's
# `<maturity>-<bindingness>` vocabulary (maturity: draft|stable; bindingness:
# normative|advisory; either axis alone is also accepted per §2.1's "bare
# draft/stable... is permitted" carve-out, plus the bindingness-only forms a
# few pre-convention specs already use).
#
# WHY: a SPEC-*.md file with no status line (or a typo'd one) silently
# defeats the maturity signal readers rely on to know whether a doc is safe
# to build against — see issue #717.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
spec_dir="${repo_root}/docs/specs"

# Recognized tokens: bare maturity, bare bindingness, or the hyphenated
# combined form. Keep in sync with SPEC-CONVENTIONS.md §2.1.
status_re='^(draft|stable|normative|advisory|draft-normative|draft-advisory|stable-normative|stable-advisory)$'

fail=0

for f in "${spec_dir}"/SPEC-*.md; do
  [ -e "$f" ] || continue
  name="$(basename "$f")"

  # Frontmatter is the block between the first two `---` lines.
  frontmatter="$(awk '/^---$/{n++; next} n==1' "$f")"

  status_line="$(printf '%s\n' "$frontmatter" | grep -m1 '^status:' || true)"
  if [ -z "$status_line" ]; then
    echo "::error file=${f}::${name} has no 'status:' field in its frontmatter"
    fail=1
    continue
  fi

  value="$(printf '%s' "$status_line" | sed -E 's/^status:[[:space:]]*//')"
  if ! printf '%s' "$value" | grep -Eq "$status_re"; then
    echo "::error file=${f}::${name} has an unrecognized status value '${value}' (see docs/specs/SPEC-CONVENTIONS.md §2.1)"
    fail=1
  fi
done

if [ "$fail" -ne 0 ]; then
  echo "check-spec-status: one or more docs/specs/SPEC-*.md files failed the status check" >&2
  exit 1
fi

echo "check-spec-status: all docs/specs/SPEC-*.md files have a recognized status"
