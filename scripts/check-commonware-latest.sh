#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Probe compatible Commonware releases in a disposable checkout. This updates
# rust/Cargo.lock deliberately; never commit the probe's lockfile changes.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root/rust"
export CARGO_BUILD_JOBS=3 CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0
cargo_cmd=(cargo)
if [ "${MKIT_CARGO_CACHED:-0}" = 1 ]; then
  cargo_cmd=(just --justfile "$root/justfile" --working-directory "$root" cargo-cached)
fi

# Include transitive family members too (macros, math, formatting, etc.).
# Updating them together avoids keeping a compatible member behind merely
# because the current lockfile already satisfies its requirement.
packages=()
while IFS= read -r package; do
  packages+=(-p "$package")
done < <(python3 - <<'PY'
import tomllib
from pathlib import Path
lock = tomllib.loads(Path('Cargo.lock').read_text())
for name in sorted({p['name'] for p in lock['package'] if p['name'].startswith('commonware-')}):
    print(name)
PY
)
if [ "${#packages[@]}" = 0 ]; then
  echo 'error: no Commonware packages found' >&2
  exit 1
fi
# Do not let the resolver quietly fall back to an older, MSRV-compatible
# release. Build failures against a newer release must be visible.
"${cargo_cmd[@]}" update --ignore-rust-version "${packages[@]}"
python3 - <<'PY'
import tomllib
from pathlib import Path
lock = tomllib.loads(Path('Cargo.lock').read_text())
for package in lock['package']:
    if package['name'].startswith('commonware-'):
        print(f"{package['name']} {package['version']}")
PY

crates=(-p mkit-core -p mkit-attest -p mkit-transport-enc)
if [ -f crates/mkit-primitives/Cargo.toml ]; then
  crates+=(-p mkit-primitives)
fi
# All features exercise optional Commonware-backed formats, including BLS and
# erasure-coded shards. Normal nextest runs execute the same golden tests.
"${cargo_cmd[@]}" build --locked "${crates[@]}" --all-features
"${cargo_cmd[@]}" nextest run --locked "${crates[@]}" --all-features -j 3
