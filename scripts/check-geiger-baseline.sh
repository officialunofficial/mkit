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
        # `mkit serve`'s engine (features ssh + fs), since WP-M0-13.
        mkit-server)            echo 0  ;;
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
    mkit-server
)

# Run from the crate that pulls every other first-party crate. mkit-cli
# depends on every other publishable mkit-* crate except mkit-wasm
# (Cloudflare Workers builds; lints separately) and the mkit-server-*
# adapter crates (the separate `mkit-server` binary). Two of those deps —
# mkit-transport-enc (enc-transport feature) and mkit-git-bridge
# (git-bridge feature) — are optional, so they only appear in geiger's
# output when their feature is enabled; the geiger run below passes
# --features enc-transport,git-bridge so the ceiling is enforced rather
# than silently skipped.
#
# The check fails closed. `cargo geiger` exits non-zero on a normal run
# ("error: Found N warnings": build-script outputs and data files it
# cannot scan), so its exit status alone says nothing. Instead the run
# must print the report table with mkit-cli as its root, and every
# EXPECTED_CRATES entry must appear in it; otherwise the script prints
# geiger's stderr and fails. (It used to discard stderr and ignore the
# exit status, and a missing crate was only a warning, so a geiger that
# could not build printed nothing and the check passed.)
#
# cargo-geiger must be installed (`cargo install cargo-geiger --locked
# --version 0.13.0`; baked into the CI image). MKIT_SKIP_GEIGER=1 skips
# the check with a visible warning, for a machine without it; CI never
# sets it.
#
# geiger builds the crate graph itself, with its own flags, so it gets its
# own target directory (`<target>/geiger`): sharing target/debug with a
# nextest run in flight rebuilds, and can delete, that run's test binaries.

rust_dir="$(cd "$(dirname "$0")/../rust" && pwd)"

if [ "${MKIT_SKIP_GEIGER:-}" = "1" ]; then
    printf '::warning::MKIT_SKIP_GEIGER=1: the unsafe-code ceiling was NOT checked.\n'
    exit 0
fi
if ! cargo geiger --version >/dev/null 2>&1; then
    printf '::error::cargo-geiger is not installed, so the unsafe-code ceiling cannot be checked.\n' >&2
    printf '   install it: cargo install cargo-geiger --locked --version 0.13.0\n' >&2
    printf '   (or set MKIT_SKIP_GEIGER=1 to skip the check explicitly).\n' >&2
    exit 1
fi

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$rust_dir/target}/geiger"
stderr_file="$(mktemp "${TMPDIR:-/tmp}/geiger-stderr.XXXXXX")"
trap 'rm -f "$stderr_file"' EXIT

cd "$rust_dir/crates/mkit-cli"
geiger_status=0
OUTPUT=$(cargo geiger --quiet --features enc-transport,git-bridge 2>"$stderr_file") ||
    geiger_status=$?

geiger_failed() {
    printf '::error::cargo geiger produced no usable report (%s; exit %s). Its stderr, without the per-file scan noise:\n' \
        "$1" "$geiger_status" >&2
    grep -v -e '^WARNING: Dependency file was never scanned' -e '^Failed to match' "$stderr_file" |
        tail -n 30 >&2 || true
    exit 1
}

# The report's header row and its root, mkit-cli's own row.
case "$OUTPUT" in
    *Functions*Expressions*) ;;
    *) geiger_failed "no report table" ;;
esac
# (A here-string, not a pipe: `grep -q` exits at the first match, and
# under pipefail the writer's SIGPIPE would fail the pipeline.)
if ! grep -qE '^[0-9]+/[0-9]+ +[0-9]+/[0-9]+ .* mkit-cli [0-9]+\.[0-9]+\.[0-9]+' <<<"$OUTPUT"; then
    geiger_failed "no mkit-cli root row"
fi
# The only error a complete run may report is geiger's warning count
# ("error: Found N warnings"). Any other `error:` line (a crate that failed
# to compile, a scan that aborted) fails the check even when a table was
# printed, and so does a non-zero exit without the count line. (No
# `grep -q` at the end of a pipe: under pipefail its early exit can
# SIGPIPE the writer and turn a match into "no match".)
other_errors=$(grep -E '^error:' "$stderr_file" | grep -vE '^error: Found [0-9]+ warnings$' || true)
if [ -n "$other_errors" ]; then
    geiger_failed "an error other than the warning count"
fi
if [ "$geiger_status" -ne 0 ] && ! grep -qE '^error: Found [0-9]+ warnings$' "$stderr_file"; then
    geiger_failed "non-zero exit"
fi

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
            case "$used" in
                '' | *[!0-9]*)
                    printf '::error::could not read the unsafe-expression count of %s from: %s\n' "$name" "$line"
                    FAIL=1
                    continue
                    ;;
            esac

            ceiling=$(ceiling_for "$name")
            if [ "$ceiling" = "UNKNOWN" ]; then
                printf '::error::Unknown first-party crate %s (count=%s). Add it to ceiling_for and EXPECTED_CRATES in scripts/check-geiger-baseline.sh.\n' "$name" "$used"
                FAIL=1
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
        *)
            printf '::error::Expected %s in geiger output but did not see it. Either the crate was removed from mkit-cli'"'"'s graph (drop it from EXPECTED_CRATES and ceiling_for) or geiger could not reach it.\n' "$name"
            FAIL=1
            ;;
    esac
done

if [ "$FAIL" -eq 0 ]; then
    printf 'geiger baseline OK:%s\n' "$SEEN"
fi
exit "$FAIL"
