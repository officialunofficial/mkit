#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Run the black-box wire suite (mkit-server-conformance, WP-M0-07) against
# apps/vcs-worker under a local `wrangler dev`: the M0 "nothing changes on
# the wire" exit check for the vcs-worker port (WP-M0-17).
#
#   scripts/vcs-worker-conformance.sh [--test-faults] [--hooks] [--sharding single|d34] [--multi] [--indexed] [-- <extra runner args>]
#
#   (default)      a release-optimized build; the whole suite once.
#   --test-faults  an `__test-faults` build, with each case/phase on a fresh
#                  server: (1) the whole suite, with the clock-skew directive
#                  and the stats hook (`replay.expired_retry_rejected`); (2)
#                  with a declared per-signer quota (`TEST_QUOTA_*` vars, read
#                  only by a test-faults build) and a 20 s ticket lifetime
#                  (`TEST_TICKET_TTL_MS`): the `growth.` cases first, on the
#                  still-disposable server (they wait out the quota window and
#                  the ticket lifetime: about 6 minutes), then the `quota.`
#                  cases. Each growth case has its own empty state directory,
#                  so earlier records cannot expire during its calibration.
#                  It then checks that the adapter never held more than 1 MiB
#                  of an `UploadPack` or `DownloadPack` body at once. The
#                  bound covers the streaming RPCs only: a unary response is
#                  one frame: each bounded `ListRefs` page is held whole,
#                  about 45 bytes per ref for this fixture, subject to the
#                  configured page-size limit and the 2 MiB reply cap.
#   --sharding d34  the default (WP-1.28c; `--sharding single` pins the old
#                   routing). D34 quota cases spend one branch (quota is per
#                   (signer, branch) under Single addressing); the growth
#                   cases read the stats hook scoped to one ref's shard
#                   (`?ref=`, WP-1.27), and the suite declares `epoch-leases`.
#                   With --test-faults it plants a RefShard relay and verifies
#                   RepoIndexShard delivery and queue drainage, and the lag
#                   cases hold the relay (`x-mkit-test-relay-delay-ms`); with
#                   --multi too, the grant phase adds the lease, lag-window and
#                   D36 hint cases, and a Multi + D34 quota phase forces a
#                   rollup under clock skew and checks the namespace cap
#                   across branches.
#   --hooks        add M3 admission/CORS/outcome checks with the Rust MPP fixture.
#   --multi        add the Multi phase (WP-1.30): a fresh server started with
#                  ADDRESSING=multi and the namespace allowlist the run's
#                  fixed seed and run id derive, then the Multi wire cases
#                  (repo., repository., policy., tickets.advance_other_repository,
#                  tickets.advance_ticket_bindings, info.). The membership
#                  cases seed their fixture over the wire; only
#                  repo.membership_read_your_writes still skips (its membership
#                  index must stay undelivered against a live relay). With
#                  --test-faults, a grant phase (WP-1.30b) configures
#                  GRANT_SCHEMES, WEBAUTHN_RPS and UNSAFE_LOOPBACK_GRANTS and
#                  runs the grants., ref_scopes., epochs., leases., lag. and
#                  repo. cases at M2.
#   --indexed      add the indexed phase (WP-4.8; needs --test-faults and
#                  d34): a fresh Multi server with INDEXED_MODE and a Paid
#                  plan, where a push of three 16 MiB windows answers
#                  PendingVerification until scheduled alarm slices verify it,
#                  one slice failing mid-pack on purpose, and the same signed
#                  advance then commits (`indexed.async_verification_commits`).
#                  The wrangler log must show the injected slice failure.
#   --indexed-only run only the injected indexed phase, with test faults.
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
# Run it locally whenever server behavior changes.
# `.github/workflows/workers.yml`'s `vcs-worker-conformance` job runs it on
# `main` only.

set -euo pipefail

cd "$(dirname "$0")/.."
root="$(pwd)"

# The exact wrangler every run uses: the one apps/workspace-worker locks.
WRANGLER_VERSION="4.134.0"
PORT="${VCS_CONFORMANCE_PORT:-8791}"
ORIGIN="http://127.0.0.1:${PORT}"
REPOSITORY="default"
MAX_PACK_BYTES=1073741824
# Phase 2's quota: a window the growth case waits out (at most 60 s) that
# still fits its 265 probe writes, and the quota cases' exhausting writes,
# at `wrangler dev` speed.
TEST_QUOTA_OPS=300
TEST_QUOTA_BYTES=2097152
TEST_QUOTA_WINDOW_MS=60000
# The ticket lifetime in that phase: the ticket growth case waits it out.
TEST_TICKET_TTL_MS=20000
# The adapter's body-buffer bound under test (bytes).
MAX_BUFFERED_BYTES=1048576

hooks=0
test_faults=0
sharding=d34
multi=0
hooks=0
indexed=0
indexed_only=0
runner_args=()
# Under D34 a ListRefs page scans 16 buckets and each lag poll re-lists, so the
# 10,000-ref case would take many minutes in miniflare; 1,000 exercises paging
# (R-134).
d34_list_args=(--list-refs 1000)
while [ $# -gt 0 ]; do
    case "$1" in
        --hooks) hooks=1 ;;
        --test-faults) test_faults=1 ;;
        --multi) multi=1 ;;
        --hooks) hooks=1 ;;
        --indexed) indexed=1 ;;
        --indexed-only) indexed=1; indexed_only=1; test_faults=1 ;;
        --sharding)
            if [ $# -lt 2 ] || { [ "$2" != single ] && [ "$2" != d34 ]; }; then
                echo "--sharding requires single or d34" >&2; exit 2
            fi
            sharding="$2"; shift
            d34_list_args=()
            if [ "${sharding}" = d34 ]; then d34_list_args=(--list-refs 1000); fi ;;
        --) shift; runner_args=("$@"); break ;;
        *) echo "usage: $0 [--test-faults] [--hooks] [--sharding single|d34] [--multi] [--indexed] [-- <runner args>]" >&2; exit 2 ;;
    esac
    shift
done

if [ "${indexed}" -eq 1 ] && { [ "${test_faults}" -ne 1 ] || [ "${sharding}" != d34 ]; }; then
    echo "--indexed needs --test-faults and --sharding d34" >&2; exit 2
fi

work="$(mktemp -d "${TMPDIR:-/tmp}/vcs-worker-conformance.XXXXXX")"
server_pid=""
log=""

stop_server() {
    if [ -n "${server_pid}" ]; then
        # `npx` forks wrangler, which forks workerd: stop the whole group.
        kill -- "-${server_pid}" 2>/dev/null || kill "${server_pid}" 2>/dev/null || true
        wait "${server_pid}" 2>/dev/null || true
        server_pid=""
        # workerd can outlive its parent for a moment: wait for the port, or the
        # next phase's health probe answers from the dying server.
        local deadline=$((SECONDS + 30))
        while (echo >"/dev/tcp/127.0.0.1/${PORT}") 2>/dev/null && [ "${SECONDS}" -lt "${deadline}" ]; do
            sleep 0.2
        done
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

    # Wait only for TCP readiness: an HTTP probe would warm the guard before
    # concurrent requests could exercise cold-start initialization.
    if ! node - "${PORT}" <<'NODE'
const net = require('node:net');
const deadline = Date.now() + 120000;
function connect() {
    const socket = net.connect({host: '127.0.0.1', port: Number(process.argv[2])});
    socket.once('connect', () => { socket.destroy(); process.exit(0); });
    socket.once('error', () => {
        socket.destroy();
        if (Date.now() >= deadline) process.exit(1);
        setTimeout(connect, 100);
    });
}
connect();
NODE
    then
        echo "wrangler dev did not open its port; its log:" >&2
        tail -n 80 "${log}" >&2
        exit 1
    fi
    cold_start "${name}"

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

# Each request owns its curl process and response files. All thirty wait for
# the release file, then call the freshly started server before any health wait.
cold_start() {
    local name="$1" cold="${work}/$1/cold-start" i pid failed=0
    local pids=()
    mkdir -p "${cold}"
    echo ">> [${name}] concurrent cold-start: 30 Health/Check requests"
    for i in $(seq 1 30); do
        (
            while [ ! -f "${cold}/release" ]; do sleep 0.01; done
            curl -sS --max-time 60 -X POST "${ORIGIN}/grpc.health.v1.Health/Check" \
                -H 'content-type: application/json' -H 'connect-protocol-version: 1' \
                --data '{}' -o "${cold}/${i}.body" -w '%{http_code}' \
                >"${cold}/${i}.status" 2>"${cold}/${i}.error"
        ) &
        pids+=("$!")
    done
    touch "${cold}/release"
    for pid in "${pids[@]}"; do wait "${pid}" || failed=1; done
    for i in $(seq 1 30); do
        if [ "$(cat "${cold}/${i}.status")" != 200 ] ||
            ! grep -Eq '"status"[[:space:]]*:[[:space:]]*"SERVING"' "${cold}/${i}.body"; then
            echo "cold-start request ${i} failed:" >&2
            cat "${cold}/${i}.status" "${cold}/${i}.body" "${cold}/${i}.error" >&2
            failed=1
        fi
    done
    if [ "${failed}" -ne 0 ]; then
        tail -n 80 "${log}" >&2
        exit 1
    fi
    echo ">> [${name}] concurrent cold-start passed: 30/30 HTTP 200 / SERVING"
}

# capture <command...>: run it with its TAP on stdout kept in ${work}/last.tap
# as well; the command's exit status lands in ${status}.
capture() {
    set +e
    "$@" | tee "${work}/last.tap"
    status=${PIPESTATUS[0]}
    set -e
}

# require_pass <case...>: each named case passed in the last captured run (a
# skip or an absent case is a failure): the exit status alone cannot tell.
require_pass() {
    local name
    for name in "$@"; do
        if ! grep -E "^ok [0-9]+ - ${name}( #|\$)" "${work}/last.tap" | grep -v '# SKIP' | grep -q .; then
            echo "${name} did not run and pass" >&2
            exit 1
        fi
    done
}

# run_suite <features> <runner args...>
run_suite() {
    local features="$1"
    shift
    echo ">> running the wire suite (features: ${features}) $*"
    # List fixture concurrency: miniflare's proxy drops UpdateRef ("Network
    # connection lost"; the dev server continues) when several slow writes are
    # in flight, so local runs pace to 1. CI keeps 8, the concurrent-UpdateRef
    # load (and a throughput signal); the harness resends dropped writes.
    # Override with VCS_LIST_PARALLEL.
    local list_parallel="${VCS_LIST_PARALLEL:-}"
    if [ -z "${list_parallel}" ]; then
        if [ -n "${CI:-}" ]; then list_parallel=8; else list_parallel=1; fi
    fi
    capture "${runner}" wire --base-url "${ORIGIN}" --auth auth-v2 --audience "${ORIGIN}" \
        --repository "${REPOSITORY}" --random-signer --atomic-advance --fresh-target --milestone M1 \
        --max-pack-bytes "${MAX_PACK_BYTES}" --features "${features}" --sharding "${sharding}" \
        --list-parallel "${list_parallel}" \
        "$@" ${d34_list_args[@]+"${d34_list_args[@]}"} ${runner_args[@]+"${runner_args[@]}"}
    if [ "${status}" -ne 0 ]; then
        echo "wire suite failed (exit ${status}); wrangler log tail:" >&2
        tail -n 80 "${log}" >&2
        exit "${status}"
    fi
}

# The test-faults routes export one DO in a single synchronous snapshot,
# import it into a separate fresh DO, then export that DO again. The header's
# export timestamp changes; the portable records and end marker must match.
snapshot_round_trip() {
    local source="${work}/snapshot/source.kvlog"
    local restored="${work}/snapshot/restored.kvlog"
    local result="${work}/snapshot/restore.json"
    echo ">> [snapshot] test-faults Durable Object snapshot round trip"
    curl -fsS "${ORIGIN}/__mkit_test/snapshot" -o "${source}"
    curl -fsS -X POST "${ORIGIN}/__mkit_test/restore" \
        -H 'content-type: application/octet-stream' --data-binary "@${source}" \
        -o "${result}"
    curl -fsS "${ORIGIN}/__mkit_test/restored-snapshot" -o "${restored}"
    node - "${source}" "${restored}" "${result}" <<'NODE'
const fs = require('node:fs');
const assert = require('node:assert/strict');
const [sourcePath, restoredPath, resultPath] = process.argv.slice(2);
const source = fs.readFileSync(sourcePath);
const restored = fs.readFileSync(restoredPath);
const headerLength = 8 + 1 + 4 + 8;
for (const bytes of [source, restored]) {
    assert.ok(bytes.length > headerLength + 2, 'snapshot has no records');
    assert.equal(bytes.subarray(0, 8).toString(), 'mkitexp\0');
    assert.equal(bytes[8], 1);
}
assert.deepEqual(restored.subarray(headerLength), source.subarray(headerLength));
assert.ok(JSON.parse(fs.readFileSync(resultPath, 'utf8')).records > 0);
NODE
}

# Exercise actual RefShard registration and its alarm through test-only hooks.
# Ordinary Single-mode pack reads bypass membership, so inspect the planted
# membership row in the RepoIndexShard and the source's relay queue directly.
check_relay_delivery() {
    local fixture relay_url deadline
    fixture="$(node -e "process.stdout.write(require('node:crypto').randomBytes(32).toString('hex'))")"
    relay_url="${ORIGIN}/__mkit_test/relay/${fixture}"
    echo ">> planting a RefShard membership relay and waiting for RepoIndexShard delivery (up to 20 s)"
    if ! curl -fsS --max-time 10 -X POST "${relay_url}" >"${work}/suite/relay-plant.json"; then
        echo "relay fixture planting failed; wrangler log tail:" >&2
        tail -n 80 "${log}" >&2
        exit 1
    fi
    deadline=$((SECONDS + 20))
    until curl -fsS --max-time 2 "${relay_url}" >"${work}/suite/relay-state.json" \
        2>"${work}/suite/relay-error" && node - "${work}/suite/relay-state.json" <<'NODE'
const fs = require('node:fs');
try {
    const state = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
    process.exit(state.member === true && state.queued === false ? 0 : 1);
} catch {
    process.exit(1);
}
NODE
    do
        if ! kill -0 "${server_pid}" 2>/dev/null || [ "${SECONDS}" -ge "${deadline}" ]; then
            echo "relay did not deliver and drain its queue within 20 s:" >&2
            cat "${work}/suite/relay-state.json" "${work}/suite/relay-error" >&2
            tail -n 80 "${log}" >&2
            exit 1
        fi
        sleep 0.1
    done
    echo ">> Worker relay passed: target member=true, source queued=false"
}

# The pipeline serves grpc.health.v1 and rejects an auth v2 signature over
# gzip-encoded bytes (fails closed, SPEC-WRITE-GRANTS §9.2 is open).
features="health,strict-gzip-auth,tickets,multipart"
# D34 runs epoch leases (the bump case needs the test-faults directive).
if [ "${sharding}" = d34 ]; then features="${features},epoch-leases"; fi
build_args=(--release)
vars=(--var "AUTH_AUDIENCE:${ORIGIN}" --var "AUTH_REPOSITORY:${REPOSITORY}" --var "SHARDING:${sharding}")
if [ "${test_faults}" -eq 1 ]; then
    features="${features},test-faults,timers"
    build_args+=(--features __test-faults)
fi

if [ "${hooks}" -eq 1 ]; then
    build_args=(--release --features __test-faults,signed-http-hooks)
fi

echo ">> building the conformance runner"
cargo build --manifest-path rust/Cargo.toml -p mkit-server-conformance \
    --bin mkit-server-conformance
runner="${root}/rust/target/debug/mkit-server-conformance"

echo ">> building apps/vcs-worker (worker-build ${build_args[*]})"
(cd apps/vcs-worker && CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=true \
    CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS=true worker-build "${build_args[@]}")

if [ "${indexed_only}" -eq 0 ]; then
start_server suite "${vars[@]}"
run_suite "${features}"
if [ "${test_faults}" -eq 1 ] && [ -z "${runner_args[*]:-}" ]; then
    require_pass tickets.expiry_timer_frees_cap_slot
    if [ "${sharding}" = d34 ]; then
        require_pass lag.list_refs_window leases.bump_completes_and_writes_continue
    fi
fi
if [ "${test_faults}" -eq 1 ] && [ "${sharding}" = d34 ]; then
    check_relay_delivery
fi
stop_server

if [ "${test_faults}" -eq 1 ] && [ "${sharding}" = single ]; then
    # The full suite's 10,000-ref fixture exceeds the 16 MiB snapshot cap.
    # Keep its coverage, and round-trip a separate bounded, populated object.
    start_server snapshot "${vars[@]}"
    run_suite "${features}" --filter refs.many_refs_one_repository
    require_pass refs.many_refs_one_repository
    snapshot_round_trip
    stop_server
fi

if [ "${test_faults}" -eq 1 ]; then
    quota_args=(--quota-ops "${TEST_QUOTA_OPS}" --quota-bytes "${TEST_QUOTA_BYTES}"
        --quota-window-ms "${TEST_QUOTA_WINDOW_MS}")
    quota_vars=("${vars[@]}"
        --var "TEST_QUOTA_OPS:${TEST_QUOTA_OPS}"
        --var "TEST_QUOTA_BYTES:${TEST_QUOTA_BYTES}"
        --var "TEST_QUOTA_WINDOW_MS:${TEST_QUOTA_WINDOW_MS}"
        --var "TEST_TICKET_TTL_MS:${TEST_TICKET_TTL_MS}")
    # Each growth measurement needs an empty partition. The replay case
    # leaves rows that may expire during ticket calibration under Single
    # sharding, so a shared server can understate per-write growth.
    for growth_case in growth.replay_and_quota_pruned growth.tickets_and_outbox_pruned; do
        start_server "${growth_case}" "${quota_vars[@]}"
        run_suite "${features}" "${quota_args[@]}" --filter "${growth_case}"
        if [ -z "${runner_args[*]:-}" ]; then
            require_pass "${growth_case}"
        fi
        stop_server
    done
    start_server quota "${quota_vars[@]}"
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

if [ "${multi}" -eq 1 ]; then
    # The Multi phase (WP-1.30): a fixed seed and run id, so the namespace
    # allowlist the deployment starts with is the one this run's signers
    # derive. `--repository` is unused by a Multi deployment (requests route
    # by X-Repository); the runner still derives signer keys with it, so the
    # allowlist and wire runs must pass the same value.
    multi_seed="5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e"
    multi_run_id="worker-multi"
    multi_features="health,strict-gzip-auth,tickets,multi-repo,namespace-policy"
    allowlist="$("${runner}" allowlist --auth auth-v2 --audience "${ORIGIN}" \
        --repository "${REPOSITORY}" --signer-seed-hex "${multi_seed}" \
        --run-id "${multi_run_id}")"
    # `--var` values are one line each; the var's parser takes commas too.
    allowlist="$(printf '%s' "${allowlist}" | tr '\n' ',')"

    start_server multi "${vars[@]}" \
        --var "ADDRESSING:multi" --var "NAMESPACE_ALLOWLIST:${allowlist}"
    for filter in repo. repository. policy. tickets.advance_other_repository \
        tickets.advance_ticket_bindings info.; do
        echo ">> running the Multi wire suite (features: ${multi_features}) --filter ${filter}"
        status=0
        "${runner}" wire --base-url "${ORIGIN}" --auth auth-v2 --audience "${ORIGIN}" \
            --repository "${REPOSITORY}" --signer-seed-hex "${multi_seed}" \
            --run-id "${multi_run_id}" --atomic-advance --fresh-target --milestone M1 \
            --max-pack-bytes "${MAX_PACK_BYTES}" --features "${multi_features}" \
            --sharding "${sharding}" --filter "${filter}" \
            ${runner_args[@]+"${runner_args[@]}"} || status=$?
        if [ "${status}" -ne 0 ]; then
            echo "Multi wire suite failed (exit ${status}); wrangler log tail:" >&2
            tail -n 80 "${log}" >&2
            exit "${status}"
        fi
    done
    stop_server

    # Namespace listing is an M2 signed-read RPC. Run it explicitly so the
    # ordinary M1 Multi suite cannot silently skip this additive case.
    start_server multi-list-repos "${vars[@]}" \
        --var "ADDRESSING:multi" --var "NAMESPACE_ALLOWLIST:${allowlist}"
    capture "${runner}" wire --base-url "${ORIGIN}" --auth auth-v2 --audience "${ORIGIN}" \
        --repository "${REPOSITORY}" --signer-seed-hex "${multi_seed}" \
        --run-id "${multi_run_id}" --atomic-advance --fresh-target --milestone M2 \
        --features "${multi_features},signed-reads" --sign-reads \
        --sharding "${sharding}" --filter repo.list_repos
    if [ "${status}" -ne 0 ]; then
        tail -n 80 "${log}" >&2
        exit "${status}"
    fi
    require_pass repo.list_repos
    stop_server

    if [ "${test_faults}" -eq 1 ]; then
        # The Multi grant phase (WP-1.30b): every owner scheme, the
        # conformance relying party, and the loopback opt-in the local
        # origin needs (honoured only by a test-faults build). The allowlist
        # adds the grant cases' fixed test-seed owner namespaces, which are
        # public seeds: never in a shipped config.
        grant_allowlist="$("${runner}" allowlist --auth auth-v2 --audience "${ORIGIN}" \
            --repository "${REPOSITORY}" --signer-seed-hex "${multi_seed}" \
            --run-id "${multi_run_id}" --grant-owners)"
        grant_allowlist="$(printf '%s' "${grant_allowlist}" | tr '\n' ',')"
        grant_features="${multi_features},grants,test-faults,timers"
        # Epoch leases exist under D34 only; the lease, lag-window and D36
        # hint cases also need test-faults (this phase is such a build).
        if [ "${sharding}" = d34 ]; then grant_features="${grant_features},epoch-leases"; fi
        start_server multi-grants "${vars[@]}" \
            --var "ADDRESSING:multi" --var "NAMESPACE_ALLOWLIST:${grant_allowlist}" \
            --var "GRANT_SCHEMES:ed25519,secp256k1-eip191,webauthn-p256" \
            --var "WEBAUTHN_RPS:example.test=https://example.test" \
            --var "UNSAFE_LOOPBACK_GRANTS:true"
        for filter in info.shape_and_policy grants. ref_scopes. epochs. leases. lag. repo. \
            tickets.advance_ticket_bindings; do
            echo ">> running the Multi grant wire suite (features: ${grant_features}) --filter ${filter}"
            capture "${runner}" wire --base-url "${ORIGIN}" --auth auth-v2 --audience "${ORIGIN}" \
                --repository "${REPOSITORY}" --signer-seed-hex "${multi_seed}" \
                --run-id "${multi_run_id}" --atomic-advance --fresh-target --milestone M2 \
                --max-pack-bytes "${MAX_PACK_BYTES}" --features "${grant_features}" \
                --sharding "${sharding}" --filter "${filter}" \
                ${d34_list_args[@]+"${d34_list_args[@]}"} \
                ${runner_args[@]+"${runner_args[@]}"}
            if [ "${status}" -ne 0 ]; then
                echo "Multi grant wire suite failed (exit ${status}); wrangler log tail:" >&2
                tail -n 80 "${log}" >&2
                exit "${status}"
            fi
            if [ -z "${runner_args[*]:-}" ]; then
                case "${filter}" in
                    leases.) if [ "${sharding}" = d34 ]; then
                        require_pass leases.idle_shard_renews_at_new_epoch \
                            leases.lease_expires_before_revocation_completes
                    fi ;;
                    repo.) require_pass repo.isolation_replay
                        if [ "${sharding}" = d34 ]; then require_pass repo.d36_hint_reads_during_lag; fi ;;
                    lag.) if [ "${sharding}" = d34 ]; then require_pass lag.membership_window; fi ;;
                esac
            fi
        done
        stop_server
    fi

    if [ "${test_faults}" -eq 1 ] && [ "${sharding}" = d34 ]; then
        # The Multi + D34 quota phase: the namespace cap across branches after
        # a forced rollup. The quota window (1 h) is far longer than the 60 s
        # rollup period the case skews past; ops are few enough to exhaust.
        multi_quota_ops=6
        multi_quota_window_ms=3600000
        start_server multi-quota "${vars[@]}" \
            --var "ADDRESSING:multi" --var "NAMESPACE_ALLOWLIST:${allowlist}" \
            --var "TEST_QUOTA_OPS:${multi_quota_ops}" \
            --var "TEST_QUOTA_BYTES:${TEST_QUOTA_BYTES}" \
            --var "TEST_QUOTA_WINDOW_MS:${multi_quota_window_ms}"
        echo ">> running the Multi + D34 quota wire case"
        status=0
        "${runner}" wire --base-url "${ORIGIN}" --auth auth-v2 --audience "${ORIGIN}" \
            --repository "${REPOSITORY}" --signer-seed-hex "${multi_seed}" \
            --run-id "${multi_run_id}" --atomic-advance --fresh-target --milestone M1 \
            --max-pack-bytes "${MAX_PACK_BYTES}" \
            --features "${multi_features},test-faults,timers" --sharding d34 \
            --quota-ops "${multi_quota_ops}" --quota-bytes "${TEST_QUOTA_BYTES}" \
            --quota-window-ms "${multi_quota_window_ms}" \
            --filter quota.namespace_cap_after_rollup \
            ${runner_args[@]+"${runner_args[@]}"} || status=$?
        if [ "${status}" -ne 0 ]; then
            echo "Multi + D34 quota case failed (exit ${status}); wrangler log tail:" >&2
            tail -n 80 "${log}" >&2
            exit "${status}"
        fi
        stop_server
    fi
fi
fi
if [ "${indexed}" -eq 1 ]; then
    # The indexed phase (WP-4.8): the Multi allowlist of the run's fixed seed,
    # INDEXED_MODE enabled in this test-faults profile and a Paid plan, so
    # the RefShard registers the kind-7 verifier. The Worker fails the fourth
    # pack read once (`MidPackCrash`), the second slice of a three-window pack.
    indexed_seed="5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e"
    indexed_run_id="worker-indexed"
    indexed_features="health,strict-gzip-auth,tickets,multi-repo,namespace-policy,indexed-async,test-faults,timers"
    indexed_allowlist="$("${runner}" allowlist --auth auth-v2 --audience "${ORIGIN}" \
        --repository "${REPOSITORY}" --signer-seed-hex "${indexed_seed}" \
        --run-id "${indexed_run_id}")"
    indexed_allowlist="$(printf '%s' "${indexed_allowlist}" | tr '\n' ',')"
    start_server indexed "${vars[@]}" \
        --var "ADDRESSING:multi" --var "NAMESPACE_ALLOWLIST:${indexed_allowlist}" \
        --var "INDEXED_MODE:true" --var "WORKERS_PLAN:paid"
    echo ">> running the indexed wire case (features: ${indexed_features})"
    status=0
    capture "${runner}" wire --base-url "${ORIGIN}" --auth auth-v2 --audience "${ORIGIN}" \
        --repository "${REPOSITORY}" --signer-seed-hex "${indexed_seed}" \
        --run-id "${indexed_run_id}" --atomic-advance --fresh-target --milestone M4 \
        --max-pack-bytes "${MAX_PACK_BYTES}" --features "${indexed_features}" \
        --sharding d34 --filter indexed.async \
        ${runner_args[@]+"${runner_args[@]}"} || status=$?
    if [ "${status}" -ne 0 ]; then
        echo "indexed wire case failed (exit ${status}); wrangler log tail:" >&2
        tail -n 80 "${log}" >&2
        exit "${status}"
    fi
    require_pass indexed.async_verification_commits
    cp "${work}/last.tap" "${work}/indexed/producer.tap"
    if ! grep -q "verification slice failed" "${work}/indexed/wrangler.log"; then
        echo "the injected mid-pack slice failure never showed in the wrangler log" >&2
        tail -n 80 "${log}" >&2
        exit 1
    fi
    echo ">> indexed phase passed: pending until verified, the failed slice resumed, then committed"
    stop_server
fi
if [ "${hooks}" -eq 1 ]; then bash scripts/vcs-worker-hooks.sh; fi
echo ">> vcs-worker conformance passed"

# The hooks phase includes real workerd timer and HTTP cancellation probes.
if [ "${hooks}" -eq 1 ]; then
    stop_server
    node scripts/vcs-worker-hooks-probe.mjs
fi
