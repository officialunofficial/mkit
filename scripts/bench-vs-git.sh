#!/usr/bin/env bash
# bench-vs-git.sh — the hyperfine suite behind apps/web/src/lib/perf-data.ts
# (mkit.sh/performance). Reproduces every timing row plus the
# repository-size table, exporting hyperfine JSON per benchmark.
#
# Usage:
#   scripts/bench-vs-git.sh [path-to-mkit-binary] [output-dir]
#
# Defaults: binary = rust/target/release/mkit, output = ./bench-results.
# Requires: hyperfine, git, python3, ~3 GiB free under $TMPDIR.
#
# Methodology (keep in sync with perf-data.ts):
# - Random (incompressible) bytes — a stand-in for compressed media.
# - Both tools through their CLI end to end, stock configuration.
# - hyperfine --warmup with per-command --prepare resetting a temp repo
#   to a clean state between runs; sizes via du -k.
#
# Provenance (#607 — keep in sync with perf-data.ts's `methodology.commit`):
# `mkit --version` is a byte-exact Homebrew/Scoop contract (`mkit
# <X.Y.Z>\n`, see rust/crates/mkit-cli/tests/version_snapshot.rs) and does
# NOT carry a commit hash, so this script derives the measured binary's
# provenance itself: `mkit --version` plus `git -C "$REPO_ROOT" rev-parse
# HEAD`, with a dirty flag if rust/ has uncommitted changes at bench time.
# This assumes the binary was built from this same checkout (the normal
# `cargo build --release -p mkit-cli` workflow the error below points at);
# it fails loudly rather than emit unattributed numbers if $REPO_ROOT
# isn't a git checkout. Provenance is written to `$OUT/provenance.txt` and
# echoed in the summary.
#
# Set MKIT_BENCH_PROVENANCE_ONLY=1 to capture and print provenance, then
# exit before touching fixtures or running hyperfine — a fast smoke test
# for this code path that skips the ~3 GiB benchmark run.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MKIT="${1:-$REPO_ROOT/rust/target/release/mkit}"
OUT="${2:-$REPO_ROOT/bench-results}"
MKIT="$(cd "$(dirname "$MKIT")" && pwd)/$(basename "$MKIT")"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"

[ -x "$MKIT" ] || { echo "mkit binary not found at $MKIT (cargo build --release -p mkit-cli)" >&2; exit 1; }

capture_provenance() { # writes $OUT/provenance.txt, fails loudly if the commit can't be determined
  local version commit dirty
  version="$("$MKIT" --version 2>&1)" || { echo "'$MKIT --version' failed" >&2; exit 1; }
  commit="$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null)" || {
    echo "cannot determine the measured mkit commit: $REPO_ROOT is not a git checkout." >&2
    echo "refusing to emit unattributed benchmark numbers (see #607) — run this script" >&2
    echo "from a git clone of mkit, or record provenance manually in \$OUT/provenance.txt." >&2
    exit 1
  }
  dirty="clean"
  [ -n "$(git -C "$REPO_ROOT" status --porcelain -- rust 2>/dev/null)" ] && dirty="dirty"
  {
    echo "mkit binary: $MKIT"
    echo "mkit version: $version"
    echo "mkit commit: $commit ($dirty)"
    echo "measured: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  } | tee "$OUT/provenance.txt"
}

echo "== provenance =="
capture_provenance
if [ "${MKIT_BENCH_PROVENANCE_ONLY:-}" = "1" ]; then
  echo "MKIT_BENCH_PROVENANCE_ONLY=1 set — skipping fixtures and hyperfine runs"
  exit 0
fi

command -v hyperfine >/dev/null || { echo "hyperfine not found" >&2; exit 1; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/mkit-bench.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

echo "== fixtures (incompressible payloads) =="
mkdir -p fixtures/small100
for i in $(seq 1 100); do head -c 10240 /dev/urandom > "fixtures/small100/f$i.bin"; done
head -c $((100 * 1024 * 1024)) /dev/urandom > fixtures/video100m.bin
head -c $((1024 * 1024 * 1024)) /dev/urandom > fixtures/blob1g.bin
head -c $((1024 * 1024)) /dev/urandom > fixtures/append1m.bin

mkit_fresh() { # $1 = files to copy in (glob under fixtures)
  echo "rm -rf work && mkdir work && cd work && $MKIT init >/dev/null 2>&1 && $MKIT keygen >/dev/null 2>&1 && cp -R $1 ."
}
git_fresh() {
  echo "rm -rf work && mkdir work && cd work && git init -q && git config user.email b@b && git config user.name b && cp -R $1 ."
}

run() { # $1 name, then hyperfine args
  local name="$1"; shift
  echo "== $name =="
  hyperfine --export-json "$OUT/$name.json" "$@"
}

# 1. init
run init --warmup 2 \
  --prepare 'rm -rf work && mkdir work' "cd work && $MKIT init" \
  --prepare 'rm -rf work && mkdir work' 'cd work && git init -q'

# 2. add + commit 100 small files
run small-files --warmup 1 \
  --prepare "$(mkit_fresh "$WORK/fixtures/small100/")" \
  "cd work && $MKIT add . >/dev/null && $MKIT commit -m bench >/dev/null 2>&1" \
  --prepare "$(git_fresh "$WORK/fixtures/small100/")" \
  'cd work && git add . && git commit -q -m bench'

# 3. add + commit one 100 MiB file
run big-100m --warmup 1 \
  --prepare "$(mkit_fresh "$WORK/fixtures/video100m.bin")" \
  "cd work && $MKIT add video100m.bin >/dev/null && $MKIT commit -m bench >/dev/null 2>&1" \
  --prepare "$(git_fresh "$WORK/fixtures/video100m.bin")" \
  'cd work && git add video100m.bin && git commit -q -m bench'

# 4. add + commit one 1 GiB file (3 runs — slow on the git side)
run big-1g --runs 3 \
  --prepare "$(mkit_fresh "$WORK/fixtures/blob1g.bin")" \
  "cd work && $MKIT add blob1g.bin >/dev/null && $MKIT commit -m bench >/dev/null 2>&1" \
  --prepare "$(git_fresh "$WORK/fixtures/blob1g.bin")" \
  'cd work && git add blob1g.bin && git commit -q -m bench'

# 5. commit a 1 MiB append to the pre-committed 100 MiB file
prep_append_mkit="$(mkit_fresh "$WORK/fixtures/video100m.bin") && $MKIT add video100m.bin >/dev/null && $MKIT commit -m v1 >/dev/null 2>&1 && cat $WORK/fixtures/append1m.bin >> video100m.bin"
prep_append_git="$(git_fresh "$WORK/fixtures/video100m.bin") && git add video100m.bin && git commit -q -m v1 && cat $WORK/fixtures/append1m.bin >> video100m.bin"
run append-1m --warmup 1 \
  --prepare "$prep_append_mkit" \
  "cd work && $MKIT add video100m.bin >/dev/null && $MKIT commit -m v2 >/dev/null 2>&1" \
  --prepare "$prep_append_git" \
  'cd work && git add video100m.bin && git commit -q -m v2'

# 6. re-add an unchanged 100 MiB file after touch (pure re-hash for both)
prep_rehash_mkit="$(mkit_fresh "$WORK/fixtures/video100m.bin") && $MKIT add video100m.bin >/dev/null && $MKIT commit -m v1 >/dev/null 2>&1 && touch video100m.bin"
prep_rehash_git="$(git_fresh "$WORK/fixtures/video100m.bin") && git add video100m.bin && git commit -q -m v1 && touch video100m.bin"
run rehash-unchanged --warmup 1 \
  --prepare "$prep_rehash_mkit" "cd work && $MKIT add video100m.bin >/dev/null" \
  --prepare "$prep_rehash_git" 'cd work && git add video100m.bin'

# 7. status with an unchanged 100 MiB file, warm stat cache (mkit-only
#    row vs git status — exercises the index v2 stat cache)
prep_status_mkit="$(mkit_fresh "$WORK/fixtures/video100m.bin") && $MKIT add video100m.bin >/dev/null && $MKIT commit -m v1 >/dev/null 2>&1 && sleep 1.1 && $MKIT status >/dev/null 2>&1"
prep_status_git="$(git_fresh "$WORK/fixtures/video100m.bin") && git add video100m.bin && git commit -q -m v1 && git status >/dev/null"
run status-unchanged --warmup 1 \
  --prepare "$prep_status_mkit" "cd work && $MKIT status >/dev/null 2>&1" \
  --prepare "$prep_status_git" 'cd work && git status >/dev/null'

# ---- repository sizes (du -k), mirrored from perf-data.ts ------------
echo "== sizes ==" | tee "$OUT/sizes.txt"
size_of() { du -sk "$1" | cut -f1; }

rm -rf work && mkdir work && cd work
"$MKIT" init >/dev/null 2>&1 && "$MKIT" keygen >/dev/null 2>&1
cp -R "$WORK/fixtures/small100/" . && "$MKIT" add . >/dev/null && "$MKIT" commit -m bench >/dev/null 2>&1
echo "size-small mkit KiB: $(size_of .mkit)" | tee -a "$OUT/sizes.txt"
cd "$WORK" && rm -rf work && mkdir work && cd work
git init -q && git config user.email b@b && git config user.name b
cp -R "$WORK/fixtures/small100/" . && git add . && git commit -q -m bench
echo "size-small git KiB: $(size_of .git)" | tee -a "$OUT/sizes.txt"

cd "$WORK" && rm -rf work && mkdir work && cd work
"$MKIT" init >/dev/null 2>&1 && "$MKIT" keygen >/dev/null 2>&1
cp "$WORK/fixtures/video100m.bin" . && "$MKIT" add video100m.bin >/dev/null && "$MKIT" commit -m v1 >/dev/null 2>&1
V1=$(size_of .mkit)
echo "size-big-v1 mkit KiB: $V1" | tee -a "$OUT/sizes.txt"
cat "$WORK/fixtures/append1m.bin" >> video100m.bin
"$MKIT" add video100m.bin >/dev/null && "$MKIT" commit -m v2 >/dev/null 2>&1
echo "size-big-v2 mkit growth KiB: $(( $(size_of .mkit) - V1 ))" | tee -a "$OUT/sizes.txt"

cd "$WORK" && rm -rf work && mkdir work && cd work
git init -q && git config user.email b@b && git config user.name b
cp "$WORK/fixtures/video100m.bin" . && git add video100m.bin && git commit -q -m v1
V1=$(size_of .git)
echo "size-big-v1 git KiB: $V1" | tee -a "$OUT/sizes.txt"
cat "$WORK/fixtures/append1m.bin" >> video100m.bin
git add video100m.bin && git commit -q -m v2
echo "size-big-v2 git growth KiB: $(( $(size_of .git) - V1 ))" | tee -a "$OUT/sizes.txt"

# Packed GROWTH (the perf-data `gitPackedKiB` field): the bytes git's
# .git retains AFTER `git gc`, measured the same growth way as the loose
# row above (v2 packed total − v1 packed total). A separate clean run so
# the intermediate `git gc` does not contaminate the loose-growth number.
cd "$WORK" && rm -rf work && mkdir work && cd work
git init -q && git config user.email b@b && git config user.name b
cp "$WORK/fixtures/video100m.bin" . && git add video100m.bin && git commit -q -m v1
git gc -q
V1P=$(size_of .git)
echo "size-big-v1 git packed KiB total: $V1P" | tee -a "$OUT/sizes.txt"
cat "$WORK/fixtures/append1m.bin" >> video100m.bin
git add video100m.bin && git commit -q -m v2
git gc -q
echo "size-big-v2 git packed KiB total: $(size_of .git)" | tee -a "$OUT/sizes.txt"
echo "size-big-v2 git packed growth KiB: $(( $(size_of .git) - V1P ))" | tee -a "$OUT/sizes.txt"

echo
echo "== provenance =="
cat "$OUT/provenance.txt"
echo
echo "== summary (mean seconds) =="
python3 - "$OUT" <<'PY'
import json, sys, glob, os
out = sys.argv[1]
for path in sorted(glob.glob(os.path.join(out, "*.json"))):
    name = os.path.basename(path).removesuffix(".json")
    with open(path) as f:
        data = json.load(f)
    row = []
    for r in data["results"]:
        tool = "mkit" if "mkit" in r["command"] else "git"
        row.append(f'{tool} {r["mean"]:.4f}s ±{r["stddev"] if r["stddev"] is not None else 0:.4f}')
    print(f'{name:18} {"  vs  ".join(row)}')
PY
echo "JSON + sizes + provenance in $OUT"
