#!/usr/bin/env bash
# scripts/bench-baseline.sh — save/restore the criterion "committed"
# baseline used by the nightly bench-regression job
# (.github/workflows/bench-nightly.yml), tracked under
# rust/benches/criterion-baselines/.
#
# `rust/target/` (including `target/criterion/`) is gitignored build
# output, so "commit a criterion baseline" means copying just the
# baseline's small stats files out to a tracked directory that mirrors
# criterion's own `<bench-dir>/<name>/` layout — never the `report/`
# HTML+SVG bundle criterion also writes alongside it (megabytes of
# regenerable charts, not a baseline).
#
# Usage:
#   # 1. Run the benches, saving (not just comparing) the "committed"
#   #    baseline:
#   cd rust && cargo bench -p mkit-benches \
#     --bench hashing --bench sign_verify \
#     --bench object_commit --bench pack_create \
#     -- --save-baseline committed
#   # 2. Copy the small stats files out to the tracked directory:
#   scripts/bench-baseline.sh save
#   git add rust/benches/criterion-baselines
#
# Restoring (what the nightly job does before comparing):
#   scripts/bench-baseline.sh restore
#   cd rust && cargo bench -p mkit-benches \
#     --bench hashing --bench sign_verify \
#     --bench object_commit --bench pack_create \
#     -- --baseline committed
#   cargo run -p mkit-benches --bin check-regressions
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CRITERION_DIR="$REPO_ROOT/rust/target/criterion"
BASELINE_DIR="$REPO_ROOT/rust/benches/criterion-baselines"
BASELINE_NAME="committed"
STATS_FILES=(estimates.json sample.json tukey.json benchmark.json)

save() {
  if [ ! -d "$CRITERION_DIR" ]; then
    echo "error: no $CRITERION_DIR — run the benches with '-- --save-baseline $BASELINE_NAME' first" >&2
    exit 1
  fi

  # Clear the previous snapshot, keeping the directory's README (docs,
  # not data — it lives at the top level only, so subdirectories are
  # removed wholesale).
  mkdir -p "$BASELINE_DIR"
  find "$BASELINE_DIR" -mindepth 1 ! -name 'README.md' -delete

  local found=0
  while IFS= read -r -d '' dir; do
    found=1
    local bench_dir rel dest
    bench_dir="$(dirname "$dir")"
    rel="${bench_dir#"$CRITERION_DIR"/}"
    dest="$BASELINE_DIR/$rel/$BASELINE_NAME"
    mkdir -p "$dest"
    for f in "${STATS_FILES[@]}"; do
      [ -f "$dir/$f" ] && cp "$dir/$f" "$dest/$f"
    done
  done < <(find "$CRITERION_DIR" -type d -name "$BASELINE_NAME" -print0)

  if [ "$found" -eq 0 ]; then
    echo "error: no '$BASELINE_NAME' baseline directories found under $CRITERION_DIR" \
      "— did you run with '-- --save-baseline $BASELINE_NAME'?" >&2
    exit 1
  fi
  echo "saved baseline snapshot to $BASELINE_DIR"
}

restore() {
  if [ ! -d "$BASELINE_DIR" ]; then
    echo "error: no committed baseline at $BASELINE_DIR yet — run '$0 save' once first" >&2
    exit 1
  fi

  mkdir -p "$CRITERION_DIR"
  while IFS= read -r -d '' src; do
    local rel dest
    rel="${src#"$BASELINE_DIR"/}"
    dest="$CRITERION_DIR/$rel"
    mkdir -p "$(dirname "$dest")"
    cp "$src" "$dest"
  done < <(find "$BASELINE_DIR" -type f ! -name 'README.md' -print0)
  echo "restored committed baseline into $CRITERION_DIR"
}

case "${1:-}" in
  save) save ;;
  restore) restore ;;
  *)
    echo "usage: $0 {save|restore}" >&2
    exit 64
    ;;
esac
