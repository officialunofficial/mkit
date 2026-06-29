#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Fail if the vendored codegen committed under */generated/ has drifted from
# what the current protos + buffa-build / connectrpc-build would produce.
#
# WHY: mkit commits its buffa/connectrpc codegen so that consumers, docs.rs,
# and the Cloudflare Workers Builds image never need protoc (their images lack
# a protoc new enough for Edition 2023). The cost of that choice is drift: a
# runtime/codegen version bump — or a .proto edit — that isn't followed by a
# regen leaves stale generated code that only fails at compile time, cryptically,
# against the new runtime. This check regenerates and fails on any diff, turning
# that silent drift into one clear, early error.
#
# Bumping buffa / connectrpc is therefore a deliberate "regen + commit" change,
# not a version-only Dependabot bump (see .github/dependabot.yml).
#
# Requires protoc >= 27 and the wasm32-unknown-unknown target (same as the regen
# scripts it invokes).

set -euo pipefail

cd "$(dirname "$0")/.."

gen_paths=(
    rust/crates/mkit-rpc/generated
    rust/crates/mkit-repo-client/generated
    apps/repo-worker/generated
)

bash scripts/regen-rpc-proto.sh
bash scripts/regen-repo-proto.sh

# `git status --porcelain` (not `git diff`) so the check catches ADDED and
# DELETED generated files too, not just modifications: the regen scripts
# `rm -f */*.rs` then re-`cp`, so a brand-new codegen module lands untracked —
# which `git diff` would silently miss. Fail on any add/delete/modify.
drift="$(git status --porcelain -- "${gen_paths[@]}")"
if [ -n "${drift}" ]; then
    echo "::error::Vendored generated code is STALE. Run scripts/regen-rpc-proto.sh and scripts/regen-repo-proto.sh, then commit the result." >&2
    echo >&2
    echo "Drift detected in vendored codegen:" >&2
    echo "${drift}" >&2
    exit 1
fi

echo "Vendored generated code is up to date with the protos and the *-build crates."
