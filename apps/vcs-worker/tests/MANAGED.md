# Local managed Worker tests

These tests run against real local workerd, R2 emulation, and the RefStore
SQLite Durable Object. They use the public auth-v2 test seed `07` repeated 32
times. Install local tools `worker-build`, Node/npm (for Wrangler), and Python
packages `blake3` and `PyNaCl`. No cloud account or deployment is involved.

From `apps/vcs-worker`:

```sh
worker-build --release --features managed-access,test-faults
npx --yes wrangler dev -c wrangler.managed.dev.jsonc --port 8791 --local
# In another terminal, with fresh .wrangler/state:
PYTHONDONTWRITEBYTECODE=1 python3 tests/managed_access.py
# Stop Wrangler, restart with the same config/state, then:
PYTHONDONTWRITEBYTECODE=1 python3 tests/managed_access.py http://localhost:8791 --verify-existing
```

The default artifact regression uses `worker-build --release`, then
`npx --yes wrangler dev -c wrangler.dev.jsonc --port 8791 --local
--var AUTH_AUDIENCE:http://localhost:8791 --var AUTH_REPOSITORY:default`, then
`PYTHONDONTWRITEBYTECODE=1 python3 tests/default_compat.py`.

For isolated state tests, give Wrangler `--persist-to` an empty directory made
with `mktemp -d /tmp/mkit-managed-test.XXXXXX`. The `--probe-uninitialized`
mode performs Get and Replace before bootstrap; inspect the exact RefStore
SQLite file under `<state>/v3/do/mkit-vcs-managed-local-test-RefStore/` and
check `SELECT COUNT(*) FROM managed_policy; SELECT COUNT(*) FROM
authenticated_operations;` both return zero. On the same fresh state,
`--verify-concurrency` sends eight Initialize requests with distinct fixed
nonces and eight Replace requests with a different distinct nonce set. Exactly
one of each commits; SQLite has generation `2` and two replay rows.

The following fault cases use a copy of that isolated state. **Stop Wrangler
before changing the SQLite test file**, then restart with the same
`--persist-to` directory and run the indicated mode:

| SQLite test-only change | Runtime mode | Expected policy/replay state |
|---|---|---|
| `UPDATE managed_policy SET schema_version=99` | `--verify-unavailable` | 503, no new rows |
| Restore version 1; `UPDATE managed_policy SET document='{invalid'` | `--verify-unavailable` | 503, no new rows |
| Restore valid document; set `generation` to the string `18446744073709551615` with SQLite `json_set` | `--verify-overflow` | 409, same generation/replay |
| Restore valid document; insert `authenticated_operations(scope,fingerprint,expires,reply)` values `('pending-test','pending-test',2000000000000,NULL)` | `--verify-pending` | 503, same policy |
| `CREATE TRIGGER managed_fail BEFORE UPDATE ON managed_policy BEGIN SELECT RAISE(ABORT,'test failure'); END` | `--verify-storage-failure` | 503, same policy and replay count |

For bootstrap rollback, use a second fresh state. Run
`--probe-uninitialized` to create empty tables, stop Wrangler, create
`CREATE TRIGGER managed_fail_insert BEFORE INSERT ON managed_policy BEGIN
SELECT RAISE(ABORT,'test failure'); END`, restart, and run
`--verify-init-failure`. Both policy and replay row counts stay zero. These
trigger and SQL changes are confined to temporary local test state; the
production binary has no injection routes. The `test-faults` feature exposes
only local test proxies for direct RefStore path and expired-proof assertions.

With an initialized local state, `--verify-chunked` sends signed
Transfer-Encoding: chunked requests without Content-Length at exactly 65,536
and 65,537 bytes. It checks the first succeeds and the second returns 413.
The implementation retains at most the cap in its accumulator; the SDK may
materialize one incoming chunk before the code can reject it, so this is not
an exact process-memory bound claim.
