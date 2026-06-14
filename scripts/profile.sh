#!/usr/bin/env bash
# profile.sh — record a samply CPU profile of the mkit CLI (or a bench
# binary) using the dedicated `profiling` cargo profile, then open it in
# the Firefox Profiler. The companion to scripts/bench-vs-git.sh: that
# script answers "how fast", this one answers "where does the time go".
#
# Usage:
#   scripts/profile.sh [-- <mkit args>]         # profile the mkit CLI
#   scripts/profile.sh --bench <name> [-- ...]  # profile a criterion bench
#
# Examples:
#   scripts/profile.sh -- commit -m "msg"
#   scripts/profile.sh --bench pack_create
#
# Requires: samply (cargo install samply), and on Linux a readable
# kernel.perf_event_paranoid (samply prints the sysctl to run if not).
# macOS needs no extra setup.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT/rust"

command -v samply >/dev/null || {
  echo "samply not found — install with: cargo install samply" >&2
  exit 1
}

BENCH=""
if [ "${1:-}" = "--bench" ]; then
  BENCH="${2:?--bench requires a bench name (e.g. pack_create)}"
  shift 2
fi
# Drop a leading `--` separating script flags from program args.
[ "${1:-}" = "--" ] && shift

if [ -n "$BENCH" ]; then
  echo ">> building bench '$BENCH' (profile=profiling)" >&2
  # --no-run builds the bench binary without executing it; we grab the
  # produced artifact path from cargo's JSON output and hand it to samply.
  BIN="$(cargo build --profile profiling -p mkit-benches --bench "$BENCH" \
           --message-format=json 2>/dev/null \
         | python3 -c 'import sys,json;[print(o["executable"]) for l in sys.stdin if (o:=json.loads(l)).get("executable") and o.get("target",{}).get("name")=="'"$BENCH"'"]' \
         | tail -1)"
  [ -n "$BIN" ] && [ -x "$BIN" ] || { echo "could not locate built bench binary for '$BENCH'" >&2; exit 1; }
  echo ">> samply record $BIN --bench" >&2
  exec samply record "$BIN" --bench "$@"
else
  echo ">> building mkit (profile=profiling)" >&2
  cargo build --profile profiling -p mkit-cli >&2
  BIN="$REPO_ROOT/rust/target/profiling/mkit"
  [ -x "$BIN" ] || { echo "mkit binary not found at $BIN" >&2; exit 1; }
  echo ">> samply record $BIN $*" >&2
  exec samply record "$BIN" "$@"
fi
