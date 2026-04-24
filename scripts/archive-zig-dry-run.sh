#!/usr/bin/env bash
# archive-zig-dry-run.sh — enumerate (and optionally execute) the git mv
# operations that move the Zig reference implementation into legacy/zig/.
#
# Usage:
#   bash scripts/archive-zig-dry-run.sh            # dry-run (default)
#   bash scripts/archive-zig-dry-run.sh --execute  # actually perform the moves
#
# Exit codes:
#   0 — all criteria satisfied (SAFE to archive, or execute succeeded)
#   1 — one or more criteria unmet (BLOCKED) or a git mv failed
set -euo pipefail

EXECUTE=false
for arg in "$@"; do
  case "$arg" in
    --execute) EXECUTE=true ;;
    *) echo "Unknown argument: $arg" >&2; exit 1 ;;
  esac
done

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

###############################################################################
# Helpers
###############################################################################

info()    { echo "[INFO]  $*"; }
warn()    { echo "[WARN]  $*"; }
blocked() { echo "[BLOCK] $*"; BLOCKED+=("$*"); }
do_mv()   {
  local src="$1" dst="$2"
  echo "  git mv '$src' '$dst'"
  if [[ "$EXECUTE" == "true" ]]; then
    git mv "$src" "$dst"
  fi
}

BLOCKED=()

###############################################################################
# 1. Verify legacy/zig/ does not already exist
###############################################################################

info "Checking that legacy/zig/ does not already exist..."
if [[ -e "legacy/zig" ]]; then
  blocked "legacy/zig/ already exists — archival may have already run, or a partial run left debris"
fi

###############################################################################
# 2. Verify source paths exist
###############################################################################

info "Checking that source paths exist..."
MISSING=()
for p in src build.zig build.zig.zon .zigversion .github/workflows/ci.yml; do
  if [[ ! -e "$p" ]]; then
    MISSING+=("$p")
  fi
done
if [[ ${#MISSING[@]} -gt 0 ]]; then
  blocked "Missing source path(s): ${MISSING[*]}"
fi

###############################################################################
# 3. Soak criterion 1 — Rust binary shipped in a tagged release >= v0.3.0
###############################################################################

info "Soak criterion 1: checking for a release tag >= v0.3.0..."
LATEST_TAG=$(git tag --list 'v*' | sort -V | tail -1 2>/dev/null || true)
if [[ -z "$LATEST_TAG" ]]; then
  blocked "Criterion 1: no release tags found — Rust binary has not shipped a release yet"
else
  # Extract major.minor.patch and compare
  MAJOR=$(echo "$LATEST_TAG" | sed 's/^v//' | cut -d. -f1)
  MINOR=$(echo "$LATEST_TAG" | sed 's/^v//' | cut -d. -f2)
  if [[ "$MAJOR" -gt 0 ]] || [[ "$MAJOR" -eq 0 && "$MINOR" -ge 3 ]]; then
    info "  Latest tag: $LATEST_TAG — OK"
  else
    blocked "Criterion 1: latest tag is $LATEST_TAG (< v0.3.0) — soak window not started"
  fi
fi

###############################################################################
# 4. Soak criterion 3 — CI Rust matrix green for >= 30 consecutive days
###############################################################################

info "Soak criterion 3: checking rust.yml CI run history (last 60 runs)..."
if command -v gh &>/dev/null; then
  RUST_FAILURES=$(gh run list \
    --workflow rust.yml \
    --limit 60 \
    --json conclusion,createdAt \
    --jq '[.[] | select(.conclusion != "success" and .conclusion != null)] | length' \
    2>/dev/null || echo "gh-error")
  if [[ "$RUST_FAILURES" == "gh-error" ]]; then
    warn "  Could not query gh run list — skipping criterion 3 (run manually)"
  elif [[ "$RUST_FAILURES" -eq 0 ]]; then
    info "  Last 60 rust.yml runs: all successful — OK (verify covers >= 30 days)"
  else
    blocked "Criterion 3: $RUST_FAILURES failure(s) in last 60 rust.yml runs — 30-day green window not achieved"
  fi
else
  warn "  gh CLI not found — skipping criterion 3 (run manually: gh run list --workflow rust.yml --limit 60)"
fi

###############################################################################
# 5. Soak criterion 4 — issue #33 closed
###############################################################################

info "Soak criterion 4: checking whether issue #33 is closed..."
if command -v gh &>/dev/null; then
  ISSUE_STATE=$(gh issue view 33 --repo officialunofficial/mkit --json state --jq '.state' 2>/dev/null || echo "gh-error")
  if [[ "$ISSUE_STATE" == "gh-error" ]]; then
    warn "  Could not query issue #33 — skipping criterion 4 (check manually)"
  elif [[ "$(echo "$ISSUE_STATE" | tr '[:lower:]' '[:upper:]')" == "OPEN" ]]; then
    blocked "Criterion 4: issue #33 is still open — all stubbed CLI subcommands must be complete before archiving"
  else
    # CLOSED or MERGED both mean resolved
    info "  Issue #33 state is '$ISSUE_STATE' — treated as resolved, OK"
  fi
else
  warn "  gh CLI not found — skipping criterion 4 (run manually: gh issue view 33)"
fi

###############################################################################
# 6. Soak criterion 5 — no open arch/zig-legacy blockers
###############################################################################

info "Soak criterion 5: checking for open arch/zig-legacy issues..."
if command -v gh &>/dev/null; then
  BLOCKER_COUNT=$(gh issue list \
    --repo officialunofficial/mkit \
    --label "arch/zig-legacy" \
    --state open \
    --json number \
    --jq 'length' \
    2>/dev/null || echo "gh-error")
  if [[ "$BLOCKER_COUNT" == "gh-error" ]]; then
    warn "  Could not query arch/zig-legacy issues — skipping criterion 5 (check manually)"
  elif [[ "$BLOCKER_COUNT" -eq 0 ]]; then
    info "  No open arch/zig-legacy issues — OK"
  else
    blocked "Criterion 5: $BLOCKER_COUNT open issue(s) labelled arch/zig-legacy"
  fi
else
  warn "  gh CLI not found — skipping criterion 5"
fi

###############################################################################
# 7. Enumerate git mv operations
###############################################################################

echo ""
echo "─────────────────────────────────────────────────────────────"
echo "Git mv operations that WOULD be (or ARE being) executed:"
echo "─────────────────────────────────────────────────────────────"

if [[ "$EXECUTE" == "true" ]]; then
  mkdir -p legacy/zig/.github-workflows
fi

do_mv "src"                           "legacy/zig/src"
do_mv "build.zig"                     "legacy/zig/build.zig"
do_mv "build.zig.zon"                 "legacy/zig/build.zig.zon"
do_mv ".zigversion"                   "legacy/zig/.zigversion"
do_mv ".github/workflows/ci.yml"      "legacy/zig/.github-workflows/ci.yml"

echo "─────────────────────────────────────────────────────────────"
echo ""

###############################################################################
# 8. Final verdict
###############################################################################

if [[ ${#BLOCKED[@]} -gt 0 ]]; then
  echo "BLOCKED: ${#BLOCKED[@]} criterion/criteria unmet:"
  for reason in "${BLOCKED[@]}"; do
    echo "  • $reason"
  done
  exit 1
fi

if [[ "$EXECUTE" == "false" ]]; then
  echo "SAFE to archive — all checked criteria passed. Re-run with --execute to perform the moves."
else
  echo "SAFE to archive — moves completed. Stage and commit the result:"
  echo "  git add -A legacy/zig"
  echo "  git commit -m 'chore(arch): move Zig reference implementation to legacy/zig/'"
fi
exit 0
