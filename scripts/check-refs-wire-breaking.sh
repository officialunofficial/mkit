#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# WIRE-level `buf breaking` gate for mkit/common/v1/refs.proto and its two
# consumers (rust/crates/mkit-rpc/proto/mkit/rpc/v1/ssh/ssh.proto,
# apps/repo-worker/proto/mkit/repo/v1/repo.proto).
#
# WHY WIRE, NOT the FILE-level default: `RefExpectation`/`RefEntry` used to
# be hand-duplicated, verbatim, in both ssh.proto and repo.proto. A
# FILE-level breaking check (the future general CI gate — see #678) treats
# "message/enum moved to a different file" as a delete-and-add pair and
# always flags it, even when the move changes zero serialized bytes. WIRE
# is the actual contract SPEC-RPC promises (byte-for-byte v1 compatibility,
# not "same file layout"), so it's the right level to gate *this* file.
#
# USAGE:
#   scripts/check-refs-wire-breaking.sh [git-ref]   # default: origin/main, falling back to main
#
# Builds two buf Images — one from `git-ref`'s tree (reconstructed into an
# isolated directory so a commit that predates mkit/common/v1/refs.proto
# entirely, like every commit before this script was added, still builds),
# one from the current working tree — and runs `buf breaking` between them
# with ONLY the WIRE rule category enabled.
#
# KNOWN, REVIEWED EXPECTED OUTPUT the first time this runs against a
# pre-extraction ref (i.e. against the commit that introduced
# mkit/common/v1/refs.proto, comparing back to before it existed): buf's
# `FIELD_WIRE_COMPATIBLE_TYPE` rule flags both `repeated RefEntry refs = 1`
# fields (ssh.proto's `ListRefsResponse.refs`, repo.proto's
# `ListRefsResponse.refs`) because their declared message TYPE NAME changed
# (`…ssh.ListRefsResponse.RefEntry` / `mkit.repo.v1.RefEntry` ->
# `mkit.common.v1.RefEntry`). This is a buf limitation, not a real wire
# break: for message-typed fields, buf's WIRE category compares referenced
# type IDENTITY, not the target schema's actual byte layout, so it cannot
# tell "renamed inside a totally different, incompatible message" apart
# from "moved verbatim to a shared file with the same field numbers/types"
# — which is exactly this extraction (mkit/common/v1/refs.proto's header
# comment + the mkit-rpc/repo-worker round-trip tests are the actual
# evidence of byte-identity). Once `main` includes the extraction, this
# script comparing any LATER ref back to `main` will not see this
# false-positive again — it only appears once, across the introducing
# commit boundary.
#
# Requires buf >= 1.28 (WIRE breaking category) and a clean git checkout
# (uses `git worktree`/`git show`, not the working tree, for the `against`
# side).

set -euo pipefail

cd "$(dirname "$0")/.."

AGAINST_REF="${1:-}"
if [ -z "${AGAINST_REF}" ]; then
    if git rev-parse --verify --quiet origin/main >/dev/null; then
        AGAINST_REF="origin/main"
    else
        AGAINST_REF="main"
    fi
fi

WORKDIR="$(mktemp -d)"
trap 'rm -rf "${WORKDIR}"' EXIT

OLD_DIR="${WORKDIR}/old"
mkdir -p "${OLD_DIR}"

# Reconstruct the `against` ref's proto tree in isolation (not the working
# tree — a pre-extraction ref has no mkit/common/v1/refs.proto, no root
# buf.yaml, and no proto/ directory at all). Only the files this check
# cares about are needed; every one of them is self-contained enough to
# build standalone once staged at its original relative root.
#
# Paths are the post-#677 package-matching layout (mkit/rpc/v1/...); #677
# moved mkit-rpc's protos off the old flat rust/crates/mkit-rpc/proto/*.proto
# layout before this script was written to compare against a moving
# origin/main, so there is no need to special-case the pre-#677 flat paths
# here.
mkdir -p "${OLD_DIR}/rust/crates/mkit-rpc/proto/mkit/rpc/v1/signer"
mkdir -p "${OLD_DIR}/rust/crates/mkit-rpc/proto/mkit/rpc/v1/ssh"
git show "${AGAINST_REF}:rust/crates/mkit-rpc/proto/mkit/rpc/v1/common.proto" \
    > "${OLD_DIR}/rust/crates/mkit-rpc/proto/mkit/rpc/v1/common.proto"
git show "${AGAINST_REF}:rust/crates/mkit-rpc/proto/mkit/rpc/v1/signer/signer.proto" \
    > "${OLD_DIR}/rust/crates/mkit-rpc/proto/mkit/rpc/v1/signer/signer.proto"
git show "${AGAINST_REF}:rust/crates/mkit-rpc/proto/mkit/rpc/v1/ssh/ssh.proto" \
    > "${OLD_DIR}/rust/crates/mkit-rpc/proto/mkit/rpc/v1/ssh/ssh.proto"

mkdir -p "${OLD_DIR}/apps/repo-worker/proto/mkit/repo/v1"
git show "${AGAINST_REF}:apps/repo-worker/proto/mkit/repo/v1/repo.proto" \
    > "${OLD_DIR}/apps/repo-worker/proto/mkit/repo/v1/repo.proto"

# If the ref already has the shared file (i.e. this is a normal, post-#679
# comparison), pull it in too so the "old" side isn't spuriously missing an
# import.
if git cat-file -e "${AGAINST_REF}:proto/mkit/common/v1/refs.proto" 2>/dev/null; then
    mkdir -p "${OLD_DIR}/proto/mkit/common/v1"
    git show "${AGAINST_REF}:proto/mkit/common/v1/refs.proto" \
        > "${OLD_DIR}/proto/mkit/common/v1/refs.proto"
fi

cat > "${OLD_DIR}/buf.yaml" <<'EOF'
version: v2
modules:
  - path: rust/crates/mkit-rpc/proto
  - path: apps/repo-worker/proto
  - path: proto
EOF
# `proto/` may not exist on a pre-extraction ref; buf errors on a
# nonexistent module path, so drop it when absent.
if [ ! -d "${OLD_DIR}/proto" ]; then
    cat > "${OLD_DIR}/buf.yaml" <<'EOF'
version: v2
modules:
  - path: rust/crates/mkit-rpc/proto
  - path: apps/repo-worker/proto
EOF
fi

cat > "${WORKDIR}/wire-only.yaml" <<'EOF'
version: v2
breaking:
  use:
    - WIRE
EOF

echo ">> building '${AGAINST_REF}' image"
buf build "${OLD_DIR}" -o "${WORKDIR}/old.binpb"

echo ">> building working-tree image"
buf build -o "${WORKDIR}/new.binpb"

echo ">> buf breaking (WIRE only): working tree against '${AGAINST_REF}'"
buf breaking "${WORKDIR}/new.binpb" \
    --against "${WORKDIR}/old.binpb" \
    --config "${WORKDIR}/wire-only.yaml"
