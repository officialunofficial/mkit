#!/usr/bin/env bash
# profile.sh — record a samply CPU profile of the mkit CLI (or a bench
# binary) using the dedicated `profiling` cargo profile, then open it in
# the Firefox Profiler. The companion to scripts/bench-vs-git.sh: that
# script answers "how fast", this one answers "where does the time go".
#
# Usage:
#   scripts/profile.sh [--features <list>] [-- <mkit args>]         # CLI
#   scripts/profile.sh --bench <name> [--features <list>] [-- ...]  # bench
#
# Examples:
#   scripts/profile.sh -- commit -m "msg"
#   scripts/profile.sh --bench pack_create
#   scripts/profile.sh --bench pack_shard_transfer --features pack-shards
#
# Requires: samply (cargo install samply). On Linux, recording needs a
# readable kernel.perf_event_paranoid — samply prints the exact sysctl if
# not. Prefer lowering that knob over running this script under sudo (see
# docs/PROFILING.md).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT/rust"

command -v samply >/dev/null || {
  echo "samply not found — install with: cargo install samply" >&2
  exit 1
}

BENCH=""
FEATURES=""
# Parse script-level flags up to a `--` separator; everything after `--`
# is forwarded to the profiled program (mkit args, or bench args).
while [ $# -gt 0 ]; do
  case "$1" in
    --bench) BENCH="${2:?--bench requires a bench name (e.g. pack_create)}"; shift 2 ;;
    -f | --features) FEATURES="${2:?--features requires a cargo feature list}"; shift 2 ;;
    --) shift; break ;;
    *) break ;;
  esac
done

# Forward cargo features to the BUILD (not the program) when requested.
FEAT_ARGS=()
[ -n "$FEATURES" ] && FEAT_ARGS=(--features "$FEATURES")

# Resolve a built artifact's path from cargo's JSON output by target name,
# honouring CARGO_TARGET_DIR / a config `target-dir` (never hard-code the
# `target/` layout). The target name is passed via argv — not interpolated
# into the program text — so it can't break out into arbitrary Python.
artifact_path() {
  python3 -c '
import sys, json
want = sys.argv[1]
found = ""
for line in sys.stdin:
    try:
        obj = json.loads(line)
    except ValueError:
        continue
    if obj.get("executable") and obj.get("target", {}).get("name") == want:
        found = obj["executable"]
print(found)
' "$1" | tail -1
}

if [ -n "$BENCH" ]; then
  echo ">> building bench '$BENCH' (profile=profiling)" >&2
  # First build (human output incl. errors), then a cached no-op rebuild
  # with --message-format=json purely to learn the artifact path.
  cargo build --profile profiling -p mkit-benches --bench "$BENCH" "${FEAT_ARGS[@]}" >&2
  BIN="$(cargo build --profile profiling -p mkit-benches --bench "$BENCH" "${FEAT_ARGS[@]}" \
           --message-format=json 2>/dev/null | artifact_path "$BENCH")"
  [ -n "$BIN" ] && [ -x "$BIN" ] || {
    echo "could not locate built bench binary for '$BENCH'" >&2
    echo "  (feature-gated benches need --features, e.g. pack_shard_transfer --features pack-shards)" >&2
    exit 1
  }
  echo ">> samply record $BIN --bench $*" >&2
  exec samply record "$BIN" --bench "$@"
else
  echo ">> building mkit (profile=profiling)" >&2
  cargo build --profile profiling -p mkit-cli "${FEAT_ARGS[@]}" >&2
  BIN="$(cargo build --profile profiling -p mkit-cli "${FEAT_ARGS[@]}" \
           --message-format=json 2>/dev/null | artifact_path "mkit")"
  [ -n "$BIN" ] && [ -x "$BIN" ] || { echo "mkit binary not found (build failed?)" >&2; exit 1; }
  echo ">> samply record $BIN $*" >&2
  exec samply record "$BIN" "$@"
fi
