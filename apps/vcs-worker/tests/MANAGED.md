# Local managed Worker tests

These tests run against real local workerd, R2 emulation, and the RefStore
SQLite Durable Object. They use the public auth-v2 test seed `07` repeated 32
times. Install local tools `worker-build`, Node/npm (for Wrangler), and Python
packages `blake3` and `PyNaCl` (`python3 -m pip install blake3 pynacl`
in a local environment). This run used `worker-build` 0.8.6, Wrangler
4.137.0, Python `blake3` 1.0.9 and PyNaCl 1.6.2. No cloud account or
deployment is involved.

From `apps/vcs-worker`:

```sh
worker-build --release --features managed-access,test-faults
npx --yes wrangler dev -c wrangler.managed.dev.jsonc --port 8791 --local
# In another terminal, with fresh .wrangler/state:
PYTHONDONTWRITEBYTECODE=1 python3 tests/managed_data.py
# Stop Wrangler, restart with the same config/state, then:
PYTHONDONTWRITEBYTECODE=1 python3 tests/managed_access.py http://localhost:8791 --verify-existing
```

`managed_data.py` initializes a fresh policy, exercises signed fixture
requests for all seven routes and five identities, then replaces the policy
to revoke the writer. Use a fresh `--persist-to` directory for each full run.
The fixture signs DownloadPack's protobuf message rather than Connect's
frame; it also sends malformed and compressed frames. `managed_access.py`
continues to cover authority-only bootstrap and SQLite fault cases; its old
seven-route-closure assertions apply only to the PR08a baseline and are
superseded by the complete managed data matrix here.

For managed replay and concurrency evidence, keep the managed test-faults
server running with an initialized state and run
`PYTHONDONTWRITEBYTECODE=1 python3 tests/managed_faults.py <state>` and
`PYTHONDONTWRITEBYTECODE=1 python3 tests/managed_races.py`. The fault test
reads SQLite quota and replay rows in that isolated local state; it proves
revocation denies an exact pending upload retry and that a post-put orphan
does not become a completed authorized operation. The race test exercises
both transaction orderings for UpdateRef and AdvanceRefs versus policy
replacement. To verify listing limits, stop Wrangler, run
`PYTHONDONTWRITEBYTECODE=1 python3 tests/managed_listing.py --seed <state>`
against this disposable state, restart Wrangler with the same `--persist-to`,
then run `PYTHONDONTWRITEBYTECODE=1 python3 tests/managed_listing.py --verify`.
It checks 256 versus 257 refs and a response above 64 KiB. This test-only
SQLite injection is never applied to a deployed repository.

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

Managed transfer memory trace: the outer request accumulator admits at most
4 MiB plus 64 KiB of envelope headroom; conversion to SDK bytes and Connect
decoding may temporarily retain copies. `UploadPack` then owns one bounded
pack before the conditional R2 put. `DownloadPack` checks R2 metadata, caps
each object-stream accumulation step at 4 MiB, then creates a protobuf chunk
and a buffered Connect response; those stages can also coexist briefly.
The single nonblocking transfer permit prevents concurrent large buffered
transfers in one isolate; admin traffic has its separate 64 KiB cap. Neither
these tests nor the SDK expose an exact peak-heap measurement or prove safety
for every Workers memory limit. A single upstream stream chunk may be
allocated before our incremental cap observes it.
