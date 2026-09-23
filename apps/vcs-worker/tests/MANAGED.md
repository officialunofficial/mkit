# Local managed Worker tests

These tests run against real local workerd, R2 emulation, and the RefStore
SQLite Durable Object. `tests/managed_grants.py` runs the owner-only MKHG lifecycle against
the same local Worker build. It covers registration, exact signed nonce
replay, concurrent renewal CAS, revocation, policy-generation invalidation
and live GetGrant; `--verify-existing` checks restart persistence. Set
`MKIT_GRANT_TEST_STATE` to the isolated Wrangler `--persist-to` directory;
the script refuses every mode without it, so no-effect claims always compare
real SQLite tables. Separate fresh state supports `--verify-expiry-replay`.
After the lifecycle and a restart, `--verify-capacity workspace|incarnation|bytes`
tests each independent lowered ceiling, with Wrangler restarted each time
under limits `1,5,1690`, `2,4,1690` or `2,5,1352` for this fixture.
Only the `test-faults` build adds owner-only `GetGrant.test_limits`; the test
asserts this actual parsed tuple, the three current SQLite counters and all
three prospective counters before claiming one quota caused its 429. A
deliberately wrong tuple must fail the assertion before attempting mutation.
`--verify-storage-fault` requires a test-only SQLite `BEFORE UPDATE` abort
trigger; `--verify-corrupt-schema` requires dropping `host_grant_meta`, both
only while Wrangler is stopped on disposable state. A separate fresh state
supports `--seed-overflow`, then (after stopping Wrangler)
`--patch-overflow-offline`, then (after restart) `--verify-generation-overflow`.
Never patch a live or non-disposable database. The local-only
`test-faults` feature may lower registry ceilings with
`--var GRANT_TEST_LIMITS:<workspace_count>,<incarnation_count>,<envelope_bytes>`;
each value must be positive and no greater than the production profile.

The other managed tests use the public auth-v2 test seed `07` repeated 32
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

For native-client interoperability, keep that server running after
`managed_data.py` and run the ignored `mkit-transport-connect` test from
`rust/` with `MKIT_MANAGED_TEST_URL=http://localhost:8791`:

```sh
cargo test -p mkit-transport-connect --test signed_reads \
  native_reads_match_managed_workerd_roles_and_revocation -- --ignored
```

It exercises all four native signed reads as reader and owner, and verifies
reader write denial, revoked-writer denial, mismatched repository, and unsigned
read denial against real workerd. It also reaches the same fixture at
`127.0.0.1:8791` to check a wrong signed audience; the fixture pins
`http://localhost:8791`. Denials must map to `AccessDenied`, and the owner
checks that the denied reader write created no ref. To exercise an active
native writer, restore
the fixture's reader and writer collaborators with an owner-signed policy
replacement, then run `native_writer_reads_and_writes_when_live -- --ignored`;
it writes only a throwaway ref in this isolated local state. To test reader
revocation, use the fixture's
owner identity to replace the disposable policy with no collaborators, then
run `native_revoked_reader_has_no_read_fallback -- --ignored` with the same
environment variable. The latter checks fresh attempts of all four methods.
An owner read proves the server is still healthy after revocation.
Do not run either ignored test against a live service or reuse local state.

For managed replay and concurrency evidence, keep the managed test-faults
server running with an initialized state and run
`PYTHONDONTWRITEBYTECODE=1 python3 tests/managed_faults.py <state>` and
`PYTHONDONTWRITEBYTECODE=1 python3 tests/managed_races.py`. The fault test
reads SQLite quota and replay rows in that isolated local state; it proves
fresh anonymous, nonmember, and reader upload denials leave the entire
quota/replay/ref tables unchanged and their unique R2 pack IDs absent. It
also proves revocation denies an exact pending upload retry and that a
post-put orphan does not become a completed authorized operation. The race
test exercises both transaction orderings for UpdateRef and AdvanceRefs
versus policy replacement. To verify listing limits, stop Wrangler, run
`PYTHONDONTWRITEBYTECODE=1 python3 tests/managed_listing.py --seed <state>`
against this disposable state, restart Wrangler with the same `--persist-to`,
then run `PYTHONDONTWRITEBYTECODE=1 python3 tests/managed_listing.py --verify`.
It checks 256 versus 257 refs and a response above 64 KiB. This test-only
SQLite injection is never applied to a deployed repository.

The default artifact regression uses `worker-build --release`, then
`npx --yes wrangler dev -c wrangler.dev.jsonc --port 8791 --local
--var AUTH_AUDIENCE:http://localhost:8791 --var AUTH_REPOSITORY:default`, then
`PYTHONDONTWRITEBYTECODE=1 python3 tests/default_compat.py`.

For owner Snapshot enrollment, build `worker-build --release --features
managed-access,test-faults`, then run the same local Wrangler config with
`--port 8791 --persist-to <fresh-mkit-c1-workerd-state>`,
`--var AUTH_AUDIENCE:http://localhost:8791`,
`--var AUTH_REPOSITORY:managed-test`, and
`--var MANAGED_OWNER_PUBLIC_KEY:ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c`.
Generate a small fixture with `cargo run --release --example snapshot_fixture --
<fixture-dir> 2 1024` and run `PYTHONDONTWRITEBYTECODE=1 python3
tests/managed_snapshots.py <fixture-dir>`. For a distinct reachable graph
above 128 MiB, use `65 2097142` and `--large --local-r2-seed`. The latter
seeds immutable hash-checked fixture packs through Wrangler's disposable
local R2 Explorer because the independent managed UploadPack write-window
quota blocks same-window setup; the enrollment service still reads and
verifies those R2 bytes normally. No deployment or cloud bucket is used.
The fixture also contains a small `selected.txt` for later private-reader
tests. This test checks every Continue saved-nonce replay and exact reached
bytes/object counts.
For the deliberate profile exclusion, generate a separate small fixture with
`--unsupported-pack` and run the same `managed_snapshots.py` command in a
fresh local state. A correctly framed v2/non-raw selected pack returns
terminal 422 `unsupported_profile` on its catalog Continue, including exact
saved-nonce replay.

`managed_snapshot_faults.py` uses only disposable local state. Set
`MKIT_SNAPSHOT_TEST_STATE` to the Wrangler persistence directory and
`MKIT_SNAPSHOT_SMALL_FIXTURE` to the small fixture. Run `--seed-live`, stop
Wrangler, run `--patch-idle-offline`, restart with the **same Worker name and
state**, and run `--verify-idle`; this proves cleanup alone recovers both
live slots with `max_rows=1`. The same stop/patch/restart pattern supports
`--patch-high-offline`/`--verify-high`,
`--patch-exhaust-offline`/`--verify-exhaust`,
`--patch-overflow-offline`/`--verify-overflow`, and, on a separate completed
job, `--patch-ready-expiry-offline`/`--verify-ready-retention`. The patch
modes directly alter local SQLite and must never target a real repository.
`--patch-corrupt-offline`/`--verify-corrupt` demonstrates checksum fail-closed
behavior on another disposable seeded state.
For the 128-terminal reservation boundary, seed a fresh state, stop workerd,
run `--patch-terminal-127-offline`, restart, then run
`--verify-terminal-cancel` or `--verify-terminal-ready`. Repeat on a second
fresh state for the other path. The local SQL fixture contains 127 valid
terminal summaries; Begin admits one live job but rejects another without
reserving a nonce, and ordinary Cancel or completed validation yields exactly
128 terminal summaries with no live job. This is deliberately isolated from
the seven-day cleanup test.
For asynchronous interleaving, use a fresh state and add
`--var SNAPSHOT_TEST_R2_PAUSE_MS:3000` with the `test-faults` build. After
`--seed-live`, run `--verify-interleave`: a charged Continue pauses before
its R2 GET while GetPolicy remains responsive, exact pending replay returns
202 despite the heavy permit, another new heavy claim returns 429, and
Cancel fences the late result. The pause variable is compiled out of the
ordinary managed build. In another fresh seeded state,
`--verify-request-expiry` signs a one-second request expiry and verifies
that a three-second R2 pause cannot advance its semantic revision while
the already charged read reservation remains durable.

One local large-fixture measurement used `snapshot_resource.mjs` against
the named `core:user:mkit-vcs-managed-local-test` workerd inspector target.
The ignored generated Worker JS was temporarily instrumented to expose its
wasm memory and then rebuilt to remove that exposure. Across 215 samples in
26.7 seconds during enrollment, observed maxima were 43,593,340 bytes JS
heap used, 12,320,768 bytes wasm memory, and 31,388,636 backing-storage
bytes; the V8 profiler recorded 2,323 samples. The separate workerd child
process RSS sampled after completion was 44,016 KiB. These are sampled
observations, not exact isolate peaks or additive memory quantities. The
fixture reached 136,318,176 distinct canonical bytes in 66 selected packs,
68 objects, 138 Continue claims and 204 charged R2 operations. The fixture
uses near-2 MiB random objects and a tiny editable file; it is not a dense
4 MiB-pack worst-case or proof that all independent ceilings are jointly
attainable.

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
