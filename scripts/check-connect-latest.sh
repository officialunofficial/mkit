#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Probe compatible Connect stack patches in a disposable checkout. Never commit
# the probe's rust/Cargo.lock changes or pin an older release to hide a failure.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root/rust"
export CARGO_BUILD_JOBS=3 CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0
cargo_cmd=(cargo)
if [ "${MKIT_CARGO_CACHED:-0}" = 1 ]; then
  cargo_cmd=(just --justfile "$root/justfile" --working-directory "$root" cargo-cached)
fi

# Stay within the manifests' caret ranges; expose incompatible newer patches.
"${cargo_cmd[@]}" update --ignore-rust-version -p connectrpc -p connectrpc-build -p buffa -p buffa-build
python3 - <<'VERSIONS'
import tomllib
from pathlib import Path
lock = tomllib.loads(Path('Cargo.lock').read_text())
for package in lock['package']:
    if package['name'] in {'connectrpc', 'connectrpc-build', 'buffa', 'buffa-build'}:
        print(f"{package['name']} {package['version']}")
VERSIONS

crates=(-p mkit-rpc -p mkit-transport-connect -p mkit-client -p mkit-repo-client)
features='mkit-rpc/transport,mkit-rpc/transport-messages,mkit-rpc/hooks'
"${cargo_cmd[@]}" build --locked "${crates[@]}" --features "$features"
"${cargo_cmd[@]}" nextest run --locked "${crates[@]}" --features "$features" -j 3
# Mirror both mkit-client wasm builds in cloudbuild/server.yaml.
"${cargo_cmd[@]}" build --locked -p mkit-client --target wasm32-unknown-unknown
"${cargo_cmd[@]}" build --locked -p mkit-client --no-default-features --target wasm32-unknown-unknown
