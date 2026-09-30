#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Local M3 lane. One isolated wrangler multi-worker session forwards unsigned
# hook bytes to the Rust MPP fixture. Never deploy this configuration.
set -euo pipefail
cd "$(dirname "$0")/.."
root="$(pwd)"
port="${VCS_CONFORMANCE_PORT:-8791}"
stub_port="${VCS_HOOKS_STUB_PORT:-$((port + 1))}"
origin="http://127.0.0.1:${port}"
upstream="http://127.0.0.1:${stub_port}"
work="$(mktemp -d "${TMPDIR:?set a private TMPDIR}/vcs-m3.XXXXXX")"
main_pid=""
stub_pid=""
cleanup() {
    local status=$?
    if [ -n "${main_pid}" ]; then
        kill -- "-${main_pid}" 2>/dev/null || kill "${main_pid}" 2>/dev/null || true
        wait "${main_pid}" 2>/dev/null || true
    fi
    if [ -n "${stub_pid}" ]; then
        kill "${stub_pid}" 2>/dev/null || true
        wait "${stub_pid}" 2>/dev/null || true
    fi
    if [ "${status}" -ne 0 ] || [ -n "${VCS_CONFORMANCE_KEEP:-}" ]; then
        echo "M3 logs kept in ${work}" >&2
    else
        rm -rf "${work}"
    fi
    exit "${status}"
}
trap cleanup EXIT
export WRANGLER_REGISTRY_PATH="${work}/registry"
export WRANGLER_SEND_METRICS=false
cargo build --locked --manifest-path rust/Cargo.toml -p mkit-server-conformance --features stubs --bin mkit-server-conformance
runner="${root}/rust/target/debug/mkit-server-conformance"
"${runner}" stub-hook --unsigned --listen "127.0.0.1:${stub_port}" >"${work}/stub.log" 2>&1 &
stub_pid=$!
deadline=$((SECONDS + 30))
until curl -fsS "${upstream}/__stub/calls" >"${work}/calls.json" 2>/dev/null; do
    if ! kill -0 "${stub_pid}" 2>/dev/null || [ "${SECONDS}" -ge "${deadline}" ]; then
        cat "${work}/stub.log" >&2
        exit 1
    fi
    sleep 0.1
done
(cd apps/vcs-worker && CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=true \
    CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS=true worker-build --release --features test-faults)
# The forwarder's settings are local to this run, with an absolute source path.
node - "${root}" "${upstream}" "${work}/forwarder.json" <<'NODE'
const fs = require('node:fs');
const [root, upstream, path] = process.argv.slice(2);
fs.writeFileSync(path, JSON.stringify({name:'mkit-hook-stub',
    main:root+'/apps/vcs-worker/tests/hook-stub/worker.mjs',
    compatibility_date:'2026-09-09', vars:{STUB_UPSTREAM:upstream}}));
NODE
set -m
(
    cd apps/vcs-worker
    exec npx --yes wrangler@4.134.0 dev -c wrangler.hooks.jsonc -c "${work}/forwarder.json" \
        --ip 127.0.0.1 --port "${port}" --persist-to "${work}/state" \
        --show-interactive-dev-session=false \
        --var "AUTH_AUDIENCE:${origin}" --var "AUTH_REPOSITORY:default" --var "SHARDING:single" \
        --var "TEST_OUTBOX_BACKLOG_ROWS:16" --var "TEST_TICKET_TTL_MS:10000"
) >"${work}/wrangler.log" 2>&1 &
main_pid=$!
set +m
deadline=$((SECONDS + 120))
until curl -fsS -X POST "${origin}/grpc.health.v1.Health/Check" \
    -H 'content-type: application/json' -H 'connect-protocol-version: 1' --data '{}' \
    >"${work}/health.json" 2>/dev/null; do
    if ! kill -0 "${main_pid}" 2>/dev/null || [ "${SECONDS}" -ge "${deadline}" ]; then
        tail -n 80 "${work}/wrangler.log" >&2
        exit 1
    fi
    sleep 0.5
done
for filter in admission. cors. outcomes.; do
    "${runner}" wire --base-url "${origin}" --auth auth-v2 --audience "${origin}" \
        --repository default --random-signer --atomic-advance --milestone M3 --sharding single \
        --hook-stub "${upstream}" --backlog-cap 16 \
        --features admission,hook-stub,tickets,timers,short-tickets,backlog-cap,combined-challenge-fields \
        --filter "${filter}" >"${work}/${filter}tap" 2>&1 || {
            cat "${work}/${filter}tap" >&2
            tail -n 80 "${work}/wrangler.log" >&2
            exit 1
        }
    cat "${work}/${filter}tap"
    if grep -q '# SKIP' "${work}/${filter}tap"; then
        echo "M3 case unexpectedly skipped" >&2
        exit 1
    fi
done
if grep -q 'Payment ey' "${work}/wrangler.log" "${work}/stub.log"; then
    echo 'payment credential appeared in a log' >&2
    exit 1
fi
echo '>> vcs-worker M3 hooks conformance passed (Free budget, at least nine outcomes)'
