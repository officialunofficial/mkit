#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Fail if .github/dependabot.yml does not have an update entry whose
# package-ecosystem matches the actual lockfile format for every directory
# that has one, or if a composite GitHub Action is not covered by a
# github-actions entry.
#
# WHY: a `package-ecosystem` that names the wrong lockfile format still opens
# PRs, but Dependabot writes only the manifest (package.json, Cargo.toml) and
# never touches a lockfile of a different format. Every such PR then fails
# CI's `--frozen-lockfile` / `--locked` install step and gets closed unmerged
# (see apps/web PRs #921-#923, #931, #934 for the npm-vs-bun instance of this).
# This check turns that after-the-fact PR failure into a config-time error.
#
# The directory -> ecosystem mapping is a fixed table, not filesystem
# sniffing: some directories carry more than one lockfile (e.g. a stray
# `bun.lock` alongside the `package-lock.json` that CI actually installs
# from), so "which lockfile is present" is not always unambiguous. The table
# instead encodes "which installer CI actually runs" for each directory,
# cross-checked against `.github/workflows/*.yml` below.

set -euo pipefail

cd "$(dirname "$0")/.."

DEPENDABOT_YML=".github/dependabot.yml"
fail=0

# directory:ecosystem, one per line. "ecosystem" is Dependabot's
# package-ecosystem value (cargo / bun / npm).
read -r -d '' MANIFEST_TABLE <<'EOF' || true
/rust:cargo
/contrib/signers:cargo
/apps/keys-worker:cargo
/apps/repo-worker:cargo
/apps/vcs-worker:cargo
/apps/mkit-worker-common:cargo
/apps/web:bun
/apps/og:bun
/apps/spammer-worker:bun
/apps/mcp:npm
EOF

# A directory has an entry in dependabot.yml for the given ecosystem when a
# `package-ecosystem: "<eco>"` line is followed (before the next
# `- package-ecosystem`) by a `directory: "<dir>"` line.
has_entry() {
  local dir="$1" eco="$2"
  awk -v dir="$dir" -v eco="$eco" '
    /^  - package-ecosystem:/ {
      cur_eco = $0
      gsub(/^  - package-ecosystem: *"|"$/, "", cur_eco)
      cur_dir = ""
    }
    /^    directory:/ {
      cur_dir = $0
      gsub(/^    directory: *"|"$/, "", cur_dir)
      if (cur_eco == eco && cur_dir == dir) { found = 1 }
    }
    END { exit(found ? 0 : 1) }
  ' "$DEPENDABOT_YML"
}

echo "Checking lockfile-bearing directories against ${DEPENDABOT_YML}..."
while IFS=: read -r dir eco; do
  [ -z "$dir" ] && continue
  if ! has_entry "$dir" "$eco"; then
    echo "::error::${DEPENDABOT_YML} has no package-ecosystem \"${eco}\" entry for directory \"${dir}\"" >&2
    fail=1
  fi
done <<< "$MANIFEST_TABLE"

echo "Checking composite GitHub Actions against ${DEPENDABOT_YML}..."
while IFS= read -r action_yml; do
  action_dir="/$(dirname "$action_yml")"
  if ! has_entry "$action_dir" "github-actions"; then
    echo "::error::${DEPENDABOT_YML} has no package-ecosystem \"github-actions\" entry for directory \"${action_dir}\" (composite action)" >&2
    fail=1
  fi
done < <(find .github/actions -mindepth 2 -maxdepth 2 -name 'action.yml')

if [ "$fail" -ne 0 ]; then
  echo "Dependabot coverage check FAILED." >&2
  exit 1
fi

echo "Dependabot coverage check passed: every lockfile directory and composite action has a matching ecosystem entry."
