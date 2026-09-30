#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Drive apps/vcs-worker's hook channel (WP-3.9, SPEC-SERVER §7.3) under a real
# local workerd: `wrangler dev` runs a stub hook Worker (apps/vcs-worker/tests/
# hook-stub) and the vcs-worker with `wrangler.hooks.jsonc` (HOOK_ROLES=admit,
# outcome and an unsigned ADMISSION_HOOK service binding to the stub). The
# black-box wire runner (mkit-server-conformance) makes the writes, and the
# stub records what the Worker sent it.
#
#   scripts/vcs-worker-hooks.sh
#
# Checks:
#   1. Admit allow: every admitted write is followed by exactly one Outcome
#      for its own reservation (committed, naming the deployment's audience),
#      and the binding carried no signature.
#   2. A challenge from Admit answers the client 402.
#   3. A hook that refuses Outcome is retried: the write succeeded, the
#      delivery is retained (503s recorded), and lands (200) once it recovers.
#   4. With the hook Worker stopped, writes answer `unavailable` (503).
#
# Needs what scripts/vcs-worker-conformance.sh needs (`worker-build`, Node.js
# with `npx`, curl, the Rust toolchain). Environment:
#   VCS_CONFORMANCE_PORT  the vcs-worker's local port (default 8791)
#   VCS_HOOKS_STUB_PORT   the stub's local port (default: that port + 1)
#   VCS_CONFORMANCE_KEEP  keep the state and log directory
#
# Run locally, at each WP that changes hook behavior and at milestone
# boundaries; it is not part of any CI job on feat/mkit-server.

set -euo pipefail

cd "$(dirname "$0")/.."
root="$(pwd)"

# The exact wrangler scripts/vcs-worker-conformance.sh uses.
WRANGLER_VERSION="4.134.0"
PORT="${VCS_CONFORMANCE_PORT:-8791}"
STUB_PORT="${VCS_HOOKS_STUB_PORT:-$((PORT + 1))}"
ORIGIN="http://127.0.0.1:${PORT}"
STUB="http://127.0.0.1:${STUB_PORT}"
REPOSITORY="default"
CASE="refs.update_any_then_read"
authority=0
if [ "${1:-}" = --authority ]; then authority=1; shift; fi
if [ $# -ne 0 ]; then echo "usage: $0 [--authority]" >&2; exit 2; fi

work="$(mktemp -d "${TMPDIR:-/tmp}/vcs-worker-hooks.XXXXXX")"
main_pid=""
stub_pid=""

stop_pid() {
    local pid="$1"
    if [ -n "${pid}" ]; then
        # `npx` forks wrangler, which forks workerd: stop the whole group.
        kill -- "-${pid}" 2>/dev/null || kill "${pid}" 2>/dev/null || true
        wait "${pid}" 2>/dev/null || true
    fi
}

cleanup() {
    local status=$?
    stop_pid "${main_pid}"
    stop_pid "${stub_pid}"
    if [ "${status}" -ne 0 ] || [ -n "${VCS_CONFORMANCE_KEEP:-}" ]; then
        echo "state and wrangler logs kept in ${work}" >&2
    else
        rm -rf "${work}"
    fi
    exit "${status}"
}
trap cleanup EXIT

# One registry for both dev servers, so the service binding finds the stub and
# never another run's Worker of the same name.
export WRANGLER_REGISTRY_PATH="${work}/registry"

# start_wrangler <name> <dir> <port> <wrangler dev args...>; sets `started_pid`.
start_wrangler() {
    local name="$1" dir="$2" port="$3"
    shift 3
    mkdir -p "${work}/${name}"
    echo ">> [${name}] starting wrangler ${WRANGLER_VERSION} dev on 127.0.0.1:${port}"
    set -m
    (
        cd "${dir}"
        exec env WRANGLER_SEND_METRICS=false npx --yes "wrangler@${WRANGLER_VERSION}" dev \
            --ip 127.0.0.1 --port "${port}" --persist-to "${work}/${name}/state" \
            --show-interactive-dev-session=false "$@"
    ) >"${work}/${name}/wrangler.log" 2>&1 &
    started_pid=$!
    set +m
    local deadline=$((SECONDS + 120))
    until curl -fsS -o /dev/null "http://127.0.0.1:${port}/__recorded" 2>/dev/null ||
        curl -sS -o /dev/null "http://127.0.0.1:${port}/" 2>/dev/null; do
        if ! kill -0 "${started_pid}" 2>/dev/null || [ "${SECONDS}" -ge "${deadline}" ]; then
            echo "[${name}] wrangler dev did not start; its log:" >&2
            tail -n 80 "${work}/${name}/wrangler.log" >&2
            exit 1
        fi
        sleep 0.5
    done
}

echo ">> building the conformance runner"
cargo build --manifest-path rust/Cargo.toml -p mkit-server-conformance \
    --bin mkit-server-conformance
runner="${root}/rust/target/debug/mkit-server-conformance"

echo ">> building apps/vcs-worker (worker-build --release)"
(cd apps/vcs-worker && CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=true \
    CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS=true worker-build --release)

start_wrangler stub apps/vcs-worker/tests/authority-stub "${STUB_PORT}" --config wrangler.jsonc
stub_pid="${started_pid}"
if [ "${authority}" -eq 1 ]; then
    ns="ed25519-0101010101010101010101010101010101010101010101010101010101010101"
    start_wrangler main apps/vcs-worker "${PORT}" --config wrangler.hooks.jsonc \
        --var "AUTH_AUDIENCE:${ORIGIN}" --var "ADDRESSING:multi" --var "SHARDING:d34" \
        --var "NAMESPACE_POLICY:allowlist" --var "NAMESPACE_ALLOWLIST:${ns}" \
        --var "HOOK_ROLES:authorize,admit,outcome" --var "AUTHORIZER_ROLE:authority" \
        --var "AUTHORITY_FENCE:true" \
        --var "AUTHORITY_KEYS:deployment ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c ${ns}"
else
    start_wrangler main apps/vcs-worker "${PORT}" --config wrangler.hooks.jsonc \
        --var "AUTH_AUDIENCE:${ORIGIN}" --var "AUTH_REPOSITORY:${REPOSITORY}" --var "SHARDING:single"
fi
main_pid="${started_pid}"

echo ">> waiting for grpc.health.v1.Health/Check to report SERVING (up to 120 s)"
deadline=$((SECONDS + 120))
until curl -fsS -X POST "${ORIGIN}/grpc.health.v1.Health/Check" \
    -H 'content-type: application/json' -H 'connect-protocol-version: 1' \
    --data '{}' 2>/dev/null | grep -q SERVING; do
    if ! kill -0 "${main_pid}" 2>/dev/null || [ "${SECONDS}" -ge "${deadline}" ]; then
        echo "the vcs-worker did not become healthy; its log:" >&2
        tail -n 80 "${work}/main/wrangler.log" >&2
        exit 1
    fi
    sleep 1
done
if ! grep -q '\[connected\]' "${work}/main/wrangler.log"; then
    # The binding connects when the stub registers; give it a moment.
    sleep 5
fi

if [ "${authority}" -eq 1 ]; then
    MKIT_AUTHORITY_PROBE_URL="${ORIGIN}" MKIT_AUTHORITY_STUB_URL="${STUB}" \
        cargo test --locked --manifest-path rust/Cargo.toml -p mkit-server-conformance \
            --test authority_worker -- --ignored
    echo ">> actual Worker D34 authority probe passed"
    exit 0
fi

# run_case <outfile>: one write case through the wire runner; its exit status.
run_case() {
    local out="$1" status=0
    "${runner}" wire --base-url "${ORIGIN}" --auth auth-v2 --audience "${ORIGIN}" \
        --repository "${REPOSITORY}" --random-signer --atomic-advance --fresh-target \
        --milestone M1 --max-pack-bytes 1073741824 \
        --features "health,strict-gzip-auth,tickets,multipart" --sharding single \
        --list-parallel 1 --filter "${CASE}" >"${out}" 2>&1 || status=$?
    return "${status}"
}

mode() { curl -fsS -X POST "${STUB}/__mode?$1" >/dev/null; }

# check <js>: evaluate the stub's recorded state `d` and the origin `origin`;
# the snippet returns true when its condition holds, or throws to fail.
check() {
    curl -fsS "${STUB}/__recorded" | node -e '
const d = JSON.parse(require("node:fs").readFileSync(0, "utf8"));
const origin = process.argv[1];
const ok = (() => { '"$1"' })();
process.exit(ok === true ? 0 : 1);
' "${ORIGIN}"
}

# wait_for <what> <secs> <js>: poll `check` until it holds.
wait_for() {
    local what="$1" secs="$2" js="$3" deadline=$((SECONDS + $2))
    until check "${js}" 2>/dev/null; do
        if [ "${SECONDS}" -ge "${deadline}" ]; then
            echo "timed out waiting for: ${what}" >&2
            curl -fsS "${STUB}/__recorded" >&2 || true
            tail -n 60 "${work}/main/wrangler.log" >&2
            exit 1
        fi
        sleep 1
    done
}

echo ">> 1. Admit allow: one Outcome per admitted reservation"
curl -fsS -X POST "${STUB}/__reset" >/dev/null
run_case "${work}/allow.tap" || { cat "${work}/allow.tap" >&2; exit 1; }
wait_for "an Outcome for every admitted write" 60 '
  const admitted = d.admits.filter((a) => a.reservationId);
  return admitted.length >= 2 &&
    admitted.every((a) => d.outcomes.some((o) => o.reservationId === a.reservationId && o.answered === 200));
'
check '
  const admitted = d.admits.filter((a) => a.reservationId).map((a) => a.reservationId);
  const answered = d.outcomes.filter((o) => o.answered === 200);
  if (new Set(admitted).size !== admitted.length) throw new Error("reused reservation id");
  for (const id of admitted) {
    const mine = answered.filter((o) => o.reservationId === id);
    if (mine.length !== 1) throw new Error(`reservation ${id}: ${mine.length} Outcomes`);
    if (mine[0].kind !== "committed") throw new Error(`reservation ${id}: ${mine[0].kind}`);
    if (mine[0].audience !== origin) throw new Error(`audience ${mine[0].audience}`);
  }
  if (answered.some((o) => !admitted.includes(o.reservationId))) throw new Error("stray Outcome");
  if (d.admits.some((a) => a.audience !== origin)) throw new Error("Admit audience");
  if (d.violations.length) throw new Error(JSON.stringify(d.violations));
  return true;
'
echo ">> Admit allow passed"

echo ">> 2. Admit challenge: the client is told 402"
mode "admit=challenge"
if run_case "${work}/challenge.tap"; then
    cat "${work}/challenge.tap" >&2
    echo "a write passed while the hook challenged" >&2
    exit 1
fi
grep -q 'HTTP 402' "${work}/challenge.tap" || { cat "${work}/challenge.tap" >&2; echo "no 402" >&2; exit 1; }
check 'return d.admits.some((a) => a.mode === "challenge" && !a.reservationId);'
mode "admit=allow"
echo ">> Admit challenge passed"

echo ">> 3. A refusing Outcome hook: retained, then delivered"
curl -fsS -X POST "${STUB}/__reset" >/dev/null
mode "outcome=fail"
run_case "${work}/retain.tap" || { cat "${work}/retain.tap" >&2; exit 1; }
wait_for "refused Outcome deliveries" 60 'return d.outcomes.filter((o) => o.answered === 503).length >= 2;'
check 'return d.outcomes.every((o) => o.answered === 503);'
mode "outcome=ok"
wait_for "the retained Outcomes to land" 90 '
  const admitted = d.admits.filter((a) => a.reservationId);
  return admitted.length >= 2 &&
    admitted.every((a) => d.outcomes.some((o) => o.reservationId === a.reservationId && o.answered === 200));
'
echo ">> retained delivery passed"

echo ">> 4. The hook Worker stopped: writes answer unavailable"
stop_pid "${stub_pid}"
stub_pid=""
sleep 3
if run_case "${work}/down.tap"; then
    cat "${work}/down.tap" >&2
    echo "a write passed with the hook Worker stopped" >&2
    exit 1
fi
grep -q 'unavailable (HTTP 503)' "${work}/down.tap" || {
    cat "${work}/down.tap" >&2
    echo "no unavailable/503" >&2
    exit 1
}
echo ">> hook down passed"
echo ">> vcs-worker hooks passed"
