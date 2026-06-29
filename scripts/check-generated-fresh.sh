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

bash scripts/regen-rpc-proto.sh
bash scripts/regen-repo-proto.sh

# Detect drift in ANY committed codegen tree: every vendored generated dir is
# named `generated/`, so match on that rather than a hardcoded list that has to
# be kept in sync with the regen scripts — a new generated tree added to a regen
# script is then covered automatically. `git status --porcelain` (not `git diff`)
# so ADDED and DELETED files count too: the regen scripts `rm -f */*.rs` then
# re-`cp`, so a new module lands untracked, which `git diff` would silently miss.
# Scoping to `/generated/` keeps cargo build's Cargo.lock / target churn out.
drift="$(git status --porcelain | grep -E '/generated/' || true)"
if [ -n "${drift}" ]; then
    echo "::error::Vendored generated code is STALE. Run scripts/regen-rpc-proto.sh and scripts/regen-repo-proto.sh, then commit the result." >&2
    echo >&2
    echo "Drift detected in vendored codegen:" >&2
    echo "${drift}" >&2
    exit 1
fi

echo "Vendored generated code is up to date with the protos and the *-build crates."
