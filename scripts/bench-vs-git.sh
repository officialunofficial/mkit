#!/usr/bin/env bash
# bench-vs-git.sh — the hyperfine suite behind web/src/lib/perf-data.ts
# (mkit.makechain.net/performance). Reproduces every timing row plus the
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
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MKIT="${1:-$REPO_ROOT/rust/target/release/mkit}"
OUT="${2:-$REPO_ROOT/bench-results}"
MKIT="$(cd "$(dirname "$MKIT")" && pwd)/$(basename "$MKIT")"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"

command -v hyperfine >/dev/null || { echo "hyperfine not found" >&2; exit 1; }
[ -x "$MKIT" ] || { echo "mkit binary not found at $MKIT (cargo build --release -p mkit-cli)" >&2; exit 1; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/mkit-bench.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

echo "== fixtures (incompressible payloads) =="
mkdir -p fixtures/small100
for i in $(seq 1 100); do head -c 10240 /dev/urandom > "fixtures/small100/f$i.bin"; done
head -c $((100 * 1024 * 1024)) /dev/urandom > fixtures/video100m.bin
head -c $((1024 * 1024 * 1024)) /dev/urandom > fixtures/blob1g.bin
head -c $((1024 * 1024)) /dev/urandom > fixtures/append1m.bin

MKIT_PREP="rm -rf work && mkdir work && cd work && $MKIT init -q >/dev/null 2>&1 || cd work && true"
# (init prints a notice; discard. keygen needed once per fresh repo.)

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
git gc -q
echo "size-big-v2 git packed KiB total: $(size_of .git)" | tee -a "$OUT/sizes.txt"

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
echo "JSON + sizes in $OUT"
