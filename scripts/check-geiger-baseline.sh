#!/usr/bin/env bash
#
# Asserts the per-first-party-crate unsafe-expression count from
# cargo-geiger stays at or below a known baseline. New unsafe in any
# `mkit-*` crate must be conscious — the offending PR also updates
# this baseline, which gives the review thread a single place to
# discuss whether the new `unsafe` is justified.
#
# The baseline counts unsafe EXPRESSIONS, not unsafe BLOCKS. A single
# `unsafe { … }` block typically contributes several expressions (one
# per field access, call, etc. inside). The numbers can drift slightly
# when a justified `unsafe` block is refactored — bump the ceiling in
# `ceiling_for()` and explain why in the same PR.
#
# Why first-party crates have non-zero counts today:
#   mkit-cli   — `getpwuid_r` opt-in in config::home_dir_for_euid
#                (lib.rs:9-17 documents the exception)
#   mkit-core  — two `#[allow(unsafe_code)]` callsites, both documented in
#                lib.rs's own header comment: `sign::load_key`'s
#                `libc::geteuid()` POSIX uid check, and
#                `batch::RealSyncer::file_barrier`'s
#                `libc::fcntl(.., F_BARRIERFSYNC)` on macOS/iOS (added by
#                #587). The ceiling counts unsafe EXPRESSIONS (see above),
#                not blocks, hence 3 rather than 2.
#
# All other first-party crates MUST stay at 0.
#
# mkit-transport-memory is deliberately NOT in ceiling_for()/
# EXPECTED_CRATES below: it's a dev-only dependency of mkit-cli (used by
# its integration tests, not the production binary), so it's never
# reachable from geiger's scan of mkit-cli's normal dependency graph.
#
# Bash 3.2-compatible (so the script runs on macOS dev machines
# without installing bash 5).

set -euo pipefail

ceiling_for() {
    case "$1" in
        mkit-cli)               echo 23 ;;
        mkit-core)              echo 3  ;;
        mkit-keystore)          echo 0  ;;
        mkit-attest)            echo 0  ;;
        mkit-rpc)               echo 0  ;;
        mkit-transport-file)    echo 0  ;;
        mkit-transport-http)    echo 0  ;;
        mkit-transport-s3)      echo 0  ;;
        mkit-transport-ssh)     echo 0  ;;
        mkit-transport-enc)     echo 0  ;;
        mkit-transport-connect) echo 0  ;;
        mkit-git-bridge)        echo 0  ;;
        *)                      echo "UNKNOWN" ;;
    esac
}

# All first-party crates we expect to see in geiger's output. Used
# to flag the case where a crate disappears entirely (deletion,
# unreachable from mkit-cli). mkit-transport-memory is intentionally
# excluded — see the dev-only-dependency note above.
EXPECTED_CRATES=(
    mkit-cli mkit-core mkit-keystore mkit-attest mkit-rpc
    mkit-transport-file mkit-transport-http
    mkit-transport-s3 mkit-transport-ssh
    mkit-transport-enc mkit-transport-connect mkit-git-bridge
)

# Run from the crate that pulls every other first-party crate. mkit-cli
# depends on every other publishable mkit-* crate except mkit-wasm
# (Cloudflare Workers builds; lints separately). Two of those deps —
# mkit-transport-enc (enc-transport feature) and mkit-git-bridge
# (git-bridge feature) — are optional, so they only appear in geiger's
# output when their feature is enabled; the geiger run below passes
# --features enc-transport,git-bridge so the ceiling is enforced rather
# than silently skipped.
cd "$(dirname "$0")/../rust/crates/mkit-cli"

OUTPUT=$(cargo geiger --quiet --features enc-transport,git-bridge 2>/dev/null || true)

FAIL=0
SEEN=""

# cargo-geiger row format (after the tree-drawing prefix is stripped):
#   used/total/functions   used/total/expressions   used/total/impls   ...
#   used/total/methods     STATUS   NAME VERSION
#
# We compare column 2 ("used unsafe expressions") against the ceiling.
while IFS= read -r line; do
    case "$line" in
        *" mkit-"*" "[0-9]*.[0-9]*.[0-9]*)
            # Extract the crate name with sed: pick the first
            # "mkit-...." token followed by a version-shaped number.
            name=$(printf '%s\n' "$line" | sed -nE 's/.* (mkit-[a-z0-9-]+) [0-9]+\.[0-9]+\.[0-9]+.*/\1/p')
            if [ -z "$name" ]; then
                continue
            fi
            case " $SEEN " in *" $name "*) continue ;; esac
            SEEN="$SEEN $name"

            # Column 2 is the second whitespace-delimited token.
            counts=$(printf '%s\n' "$line" | awk '{print $2}')
            used="${counts%/*}"

            ceiling=$(ceiling_for "$name")
            if [ "$ceiling" = "UNKNOWN" ]; then
                printf '::warning::Unknown first-party crate %s (count=%s). Add it to scripts/check-geiger-baseline.sh.\n' "$name" "$used"
                continue
            fi

            if [ "$used" -gt "$ceiling" ]; then
                printf '::error::%s has %s unsafe expressions, ceiling is %s\n' "$name" "$used" "$ceiling"
                printf '   review the new unsafe site; if justified, bump the ceiling in scripts/check-geiger-baseline.sh in the same PR.\n'
                FAIL=1
            elif [ "$used" -lt "$ceiling" ]; then
                printf '::notice::%s dropped from %s to %s unsafe expressions — consider lowering the ceiling.\n' "$name" "$ceiling" "$used"
            fi
            ;;
    esac
done <<<"$OUTPUT"

# Catch the case where a first-party crate disappears from geiger's
# output entirely.
for name in "${EXPECTED_CRATES[@]}"; do
    case " $SEEN " in
        *" $name "*) ;;
        *) printf '::warning::Expected %s in geiger output but did not see it. Either the crate was removed or geiger could not reach it.\n' "$name" ;;
    esac
done

exit "$FAIL"
