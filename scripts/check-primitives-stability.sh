#!/usr/bin/env bash
# Typecheck stability minima, then inventory the resolved public API per backend.
set -euo pipefail
cd "$(dirname "$0")/.."
export CARGO_BUILD_JOBS=3 CARGO_INCREMENTAL=0
if [[ "${MKIT_PRIMITIVES_CI:-0}" != 1 ]]; then
  export CARGO_BUILD_BUILD_DIR="${MKIT_BUILD_ROOT:-$HOME/.cache/mkit/build}/{workspace-path-hash}"
fi
wrappers=$(mktemp -d)
trap 'rm -rf "$wrappers"' EXIT
cd rust
cargo check --locked -p mkit-primitives --lib --all-features
# sccache cannot nest the scoped compiler wrapper. Dependencies never receive
# stability cfgs. Wrapper paths differ so Cargo fingerprints each minimum.
stability_rustc_wrapper="${RUSTC_WRAPPER:-}"
unset RUSTC_WRAPPER
for level in BETA GAMMA DELTA EPSILON RESERVED; do
  cp ../scripts/primitives-stability-rustc.py "$wrappers/$level"
  MKIT_PRIMITIVES_MIN_STABILITY="$level" \
    RUSTC_WORKSPACE_WRAPPER="$wrappers/$level" \
    cargo check --locked -p mkit-primitives --lib --all-features
done
if [[ -n "$stability_rustc_wrapper" ]]; then
  export RUSTC_WRAPPER="$stability_rustc_wrapper"
fi

# Only rustdoc's JSON interface needs nightly. Keep all dependency compilation
# on that same pinned compiler, without passing cfgs to those dependencies.
nightly=nightly-2026-09-01
if ! rustup run "$nightly" rustdoc --version >/dev/null 2>&1; then
  rustup toolchain install "$nightly" --profile minimal --no-self-update
fi
python3 ../scripts/test-primitives-stability.py --rustdoc-tests "$nightly"
cp ../scripts/primitives-stability-rustc.py "$wrappers/ALPHA"
export MKIT_PRIMITIVES_REAL_RUSTDOC
MKIT_PRIMITIVES_REAL_RUSTDOC=$(rustup which --toolchain "$nightly" rustdoc)
target_dir=$(cargo metadata --locked --no-deps --format-version 1 | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')
for backend in raw pure native both; do
  features=(--no-default-features)
  case "$backend" in
    pure) features+=(--features pack-ruzstd) ;;
    native) features+=(--features pack-zstd) ;;
    both) features+=(--all-features) ;;
  esac
  mkdir "$wrappers/$backend"
  for level in ALPHA BETA GAMMA DELTA EPSILON RESERVED; do
    MKIT_PRIMITIVES_MIN_STABILITY="$level" \
      RUSTDOC="$wrappers/$level" \
      cargo +"$nightly" rustdoc --locked -p mkit-primitives --lib "${features[@]}" \
      -- -Z unstable-options --output-format json --document-hidden-items
    cp "$target_dir/doc/mkit_primitives.json" "$wrappers/$backend/$level.json"
  done
  echo "primitives stability inventory: $backend"
  python3 ../scripts/check-primitives-stability-inventory.py "$wrappers/$backend"
done
