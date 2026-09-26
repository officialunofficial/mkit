#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Run the black-box wire suite (mkit-server-conformance, WP-M0-07) against
# apps/vcs-worker under a local `wrangler dev`: the M0 "nothing changes on
# the wire" exit check for the vcs-worker port (WP-M0-17).
#
#   scripts/vcs-worker-conformance.sh [--test-faults] [-- <extra runner args>]
#
#   (default)      a release-feature build; the whole suite once.
#   --test-faults  a `test-faults` build, in two phases, each on a fresh
#                  server: (1) the whole suite, with the clock-skew directive
#                  and the stats hook (`replay.expired_retry_rejected`); (2)
#                  with a declared per-signer quota (`TEST_QUOTA_*` vars, read
#                  only by a test-faults build): `growth.replay_and_quota_pruned`
#                  first, on the still-disposable server (it waits out the
#                  quota window: about 3 minutes), then the `quota.` cases.
#                  It then checks that the adapter never held more than 1 MiB
#                  of an `UploadPack` or `DownloadPack` body at once. The
#                  bound covers the streaming RPCs only: a unary response is
#                  one frame, so a `ListRefs` of N refs is about 45*N bytes
#                  held whole (1.2 MB at 30,000; the default 10,000-ref case
#                  stays under) until WP-1.27 pages it.
#   -- ARGS        passed to every `mkit-server-conformance wire` run (e.g.
#                  `-- --filter refs.`, `-- --list-refs 1000`).
#
# Every server starts from an empty `--persist-to` state directory, so the
# runs declare `--fresh-target` (whole-server listings stay bounded). Needs
# `worker-build` (cargo install worker-build --locked), Node.js with `npx`,
# curl, and the Rust toolchain of rust/rust-toolchain.toml.
#
# Environment:
#   VCS_CONFORMANCE_PORT   local port (default 8791)
#   VCS_CONFORMANCE_KEEP   keep the state and log directory (default: removed
#                          on success)
#   VCS_CONFORMANCE_WRANGLER_ARGS  extra `wrangler dev` arguments, split on
#                          spaces (e.g. `--compatibility-date 2024-09-23`)
#
# During the MKIT-29 epic no CI runs on feat/mkit-server: this script is run
# locally, at each WP that changes server behavior and at every milestone
# boundary. `.github/workflows/workers.yml`'s `vcs-worker-conformance` job
# runs it on `main` only, first on the final PR to `main`.

set -euo pipefail

cd "$(dirname "$0")/.."
root="$(pwd)"

# The exact wrangler every run uses: the one apps/workspace-worker locks.
WRANGLER_VERSION="4.134.0"
PORT="${VCS_CONFORMANCE_PORT:-8791}"
ORIGIN="http://127.0.0.1:${PORT}"
REPOSITORY="default"
MAX_PACK_BYTES=67108864
# Phase 2's quota: a window the growth case waits out (at most 60 s) that
# still fits its 265 probe writes, and the quota cases' exhausting writes,
# at `wrangler dev` speed.
TEST_QUOTA_OPS=300
TEST_QUOTA_BYTES=2097152
TEST_QUOTA_WINDOW_MS=60000
# The adapter's body-buffer bound under test (bytes).
MAX_BUFFERED_BYTES=1048576

test_faults=0
runner_args=()
while [ $# -gt 0 ]; do
    case "$1" in
        --test-faults) test_faults=1 ;;
        --) shift; runner_args=("$@"); break ;;
        *) echo "usage: $0 [--test-faults] [-- <runner args>]" >&2; exit 2 ;;
    esac
    shift
done

work="$(mktemp -d "${TMPDIR:-/tmp}/vcs-worker-conformance.XXXXXX")"
server_pid=""
log=""

stop_server() {
    if [ -n "${server_pid}" ]; then
        # `npx` forks wrangler, which forks workerd: stop the whole group.
        kill -- "-${server_pid}" 2>/dev/null || kill "${server_pid}" 2>/dev/null || true
        wait "${server_pid}" 2>/dev/null || true
        server_pid=""
    fi
}

cleanup() {
    local status=$?
    stop_server
    if [ "${status}" -ne 0 ] || [ -n "${VCS_CONFORMANCE_KEEP:-}" ]; then
        echo "state and wrangler logs kept in ${work}" >&2
    else
        rm -rf "${work}"
    fi
    exit "${status}"
}
trap cleanup EXIT

# start_server <name> <wrangler dev args...>: a fresh server whose state and
# log live under ${work}/<name>.
start_server() {
    local name="$1"
    shift
    mkdir -p "${work}/${name}"
    log="${work}/${name}/wrangler.log"
    echo ">> [${name}] starting wrangler ${WRANGLER_VERSION} dev on ${ORIGIN}"
    # `set -m`: the server gets its own process group, so stop_server
    # stops wrangler and workerd with it.
    set -m
    (
        cd apps/vcs-worker
        # shellcheck disable=SC2086 # extra args split on spaces by design
        exec env WRANGLER_SEND_METRICS=false npx --yes "wrangler@${WRANGLER_VERSION}" dev \
            --config wrangler.dev.jsonc --ip 127.0.0.1 --port "${PORT}" \
            --persist-to "${work}/${name}/state" --show-interactive-dev-session=false \
            "$@" ${VCS_CONFORMANCE_WRANGLER_ARGS:-}
    ) >"${log}" 2>&1 &
    server_pid=$!
    set +m

    echo ">> [${name}] waiting for grpc.health.v1.Health/Check to report SERVING (up to 120 s)"
    local deadline=$((SECONDS + 120))
    until curl -fsS -X POST "${ORIGIN}/grpc.health.v1.Health/Check" \
        -H 'content-type: application/json' -H 'connect-protocol-version: 1' \
        --data '{}' 2>/dev/null | grep -q SERVING; do
        if ! kill -0 "${server_pid}" 2>/dev/null || [ "${SECONDS}" -ge "${deadline}" ]; then
            echo "wrangler dev did not become healthy; its log:" >&2
            tail -n 80 "${log}" >&2
            exit 1
        fi
        sleep 1
    done
}

# run_suite <features> <runner args...>
run_suite() {
    local features="$1"
    shift
    echo ">> running the wire suite (features: ${features}) $*"
    local status=0
    "${runner}" wire --base-url "${ORIGIN}" --auth auth-v2 --audience "${ORIGIN}" \
        --repository "${REPOSITORY}" --random-signer --atomic-advance --fresh-target \
        --max-pack-bytes "${MAX_PACK_BYTES}" --features "${features}" \
        "$@" ${runner_args[@]+"${runner_args[@]}"} || status=$?
    if [ "${status}" -ne 0 ]; then
        echo "wire suite failed (exit ${status}); wrangler log tail:" >&2
        tail -n 80 "${log}" >&2
        exit "${status}"
    fi
}

# The pipeline serves grpc.health.v1 and rejects an auth v2 signature over
# gzip-encoded bytes (fails closed, SPEC-WRITE-GRANTS §9.2 is open).
features="health,strict-gzip-auth"
build_args=(--dev)
vars=(--var "AUTH_AUDIENCE:${ORIGIN}" --var "AUTH_REPOSITORY:${REPOSITORY}")
if [ "${test_faults}" -eq 1 ]; then
    features="${features},test-faults,timers"
    build_args+=(--features test-faults)
fi

echo ">> building the conformance runner"
cargo build --manifest-path rust/Cargo.toml -p mkit-server-conformance \
    --bin mkit-server-conformance
runner="${root}/rust/target/debug/mkit-server-conformance"

echo ">> building apps/vcs-worker (worker-build ${build_args[*]})"
(cd apps/vcs-worker && worker-build "${build_args[@]}")

start_server suite "${vars[@]}"
run_suite "${features}"
stop_server

if [ "${test_faults}" -eq 1 ]; then
    quota_args=(--quota-ops "${TEST_QUOTA_OPS}" --quota-bytes "${TEST_QUOTA_BYTES}"
        --quota-window-ms "${TEST_QUOTA_WINDOW_MS}")
    start_server quota "${vars[@]}" \
        --var "TEST_QUOTA_OPS:${TEST_QUOTA_OPS}" \
        --var "TEST_QUOTA_BYTES:${TEST_QUOTA_BYTES}" \
        --var "TEST_QUOTA_WINDOW_MS:${TEST_QUOTA_WINDOW_MS}"
    run_suite "${features}" "${quota_args[@]}" --filter growth.
    run_suite "${features}" "${quota_args[@]}" --filter quota.
    stop_server

    # A test-faults build logs `mkit-adapter peak-buffered-bytes <n> ...
    # path <path>` per request: the most body bytes the adapter held at
    # once. Bound the streaming RPCs (see the header on unary replies).
    peak="$(cat "${work}"/*/wrangler.log \
        | grep -E 'mkit-adapter peak-buffered-bytes .* path /mkit\.transport\.v1\.TransportService/(UploadPack|DownloadPack)' \
        | sed -n 's/.*mkit-adapter peak-buffered-bytes \([0-9][0-9]*\).*/\1/p' \
        | sort -n | tail -n 1)"
    if [ -z "${peak}" ]; then
        echo "no streaming-RPC buffer measurements in the wrangler logs" >&2
        exit 1
    fi
    echo ">> adapter peak buffered UploadPack/DownloadPack body bytes: ${peak} (bound ${MAX_BUFFERED_BYTES})"
    if [ "${peak}" -gt "${MAX_BUFFERED_BYTES}" ]; then
        echo "the adapter buffered more than ${MAX_BUFFERED_BYTES} bytes" >&2
        exit 1
    fi
fi
echo ">> vcs-worker conformance passed"
