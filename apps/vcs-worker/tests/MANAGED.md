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

For PR10c2 disclosure, use the same managed build and a fresh per-fixture
`--persist-to` state. After `managed_snapshots.py` reaches `ready`, run
`managed_disclosure.py <small-fixture> --hold`: it registers a signed live
grant, reads raw MKWB, then checks subject/path/context/JSON/auth denials. The
`--renew` option derives the next generation from the registry; `--revoke`
checks a final denial. With `--var C2_TEST_PAUSE_MS:1000` and
`MKIT_C2_TEST_STATE=<state>`, run `managed_disclosure_race.py <small-fixture>`
after `--hold`: it observes the first test-only R2 range, revokes the grant
while the read awaits, asserts owner-admin responsiveness, and requires a
409/no-MKWB result with no dangling lease. Its `renew`, `policy`, `head` and
`packmap` modes exercise the corresponding live-context changes on separate
or explicitly restored disposable states. The pause and range spy are compiled out without
`test-faults`.

For the large hidden corpus, generate `65 2097142`, then use
`MKIT_SNAPSHOT_R2_BUCKET=mkit-vcs-managed-local-test` with
`managed_snapshots.py <large-fixture> --large --local-r2-seed`. In that same
state, `MKIT_C2_TEST_STATE=<state> managed_disclosure_large.py
<large-fixture>` reads only `selected.txt`. A local workerd run enrolled
136,318,176 reachable canonical bytes and returned a 3,450-byte MKWB with
three range GETs (Commit, Tree, selected Blob), all from the small root pack;
none of the 65 hidden large packs were read. This is a local-R2 seeded
large-base proof, not an ordinary-upload-window or deployed isolate result.

For the post-cleanup dependency check, stop Wrangler on a ready small-fixture
state and run `managed_disclosure_cleanup.py --age <state>`; this test-only
patch ages the private checksummed job row. Restart Wrangler with that state,
then run `managed_disclosure_cleanup.py --cleanup <state> <small-fixture>`.
The real owner `CleanupSnapshots` route removes ready-summary and seen rows
while retaining the certified catalog/index, and a renewed live grant still
reads MKWB. One local run removed six rows and returned 1,520 MKWB bytes.
Never point these patch modes at a real repository.
`managed_disclosure_leasecap.py` separately seeds expired physical lease rows
while Wrangler is stopped. In actual workerd, 15 rows admit one transient read
lease and return 200; 16 rows return typed 429 without a new row. Real owner
CleanupSnapshots removed the 16 expired rows, after which a read returned 200.
The same fixture uses unrelated expired bookkeeping rows (not fake enrolled
certificates) to exercise the repository-global branch: 63 rows admit a
transient read, 64 return 429, and owner cleanup restores 200.
For lease-error classification, while Wrangler is stopped on separate
disposable certified states, `managed_disclosure_leasecap.py --fault <state>
missing-cert` removes the current certificate and `--fault <state>
corrupt-schema` removes an index table. Restart each state, then use
`--probe-fault <state> <fixture> 409 conflict` or `503 unavailable`.
Both were executed on actual local workerd with renewed live grants, no
MKWB and no retained lease; this distinguishes healthy absent readiness
from corrupt storage. These destructive SQL fixtures must never target a
real repository.

For the file-cap edge, enroll separate `snapshot_fixture` states with one
file of 262144 and 262145 bytes. `managed_disclosure_boundary.py <fixture>
200` accepts the exact 256 KiB case (262,641-byte MKWB); the `429` variant
requires typed `resource_exhausted` and no bundle for the one-byte-over case.
The C2 witness/bundle/visit ceilings are independent; these cases do not
measure every joint maximum, dense Tree or ChunkedBlob positions. Native
`hosted_workerd.rs` separately performs an actual signed Connect client read
against the local managed Worker, while `signed_reads.rs` tests single-attempt
redirect, stalled-header/body timeout and oversized-response refusal.
`disclosure_resource_fixture` generates ordinary-uploadable raw-v1 fixtures
for a one-Tree witness at exactly 1 MiB and one byte over, two distinct
ancestor Trees with those aggregate lengths, four/five selected paths sharing
one 256 KiB Blob (logical 1 MiB / 1.25 MiB selected content), and a
ChunkedBlob with 32,768 positions repeating an empty chunk ID plus one
nonempty final chunk. `managed_disclosure_resources.py` enrolls each through
the actual C1 routes, registers exact-path MKHG, checks the C2 status and
test-fault R2 read IDs. The one-Tree witness fixtures each required 3,653
Continue claims before readiness (respectively 61,906,160 and 61,906,219
cumulatively charged C1 read bytes, 3,654 C1 R2 operations each). Actual C2
returned 200 at the exact 1,048,576-byte boundary and 429 at 1,048,577.
After the witness pre-read
fix, the over case issued only the base Commit range, not the Tree range.
The shared-four case returned 200 with one shared Blob range and a 262,785-byte
MKWB; shared-five returned 429 without a bundle. These are measured local
profiles, not a promise all independent maxima jointly complete.
The two-Tree aggregate-witness fixtures both enrolled through 3,655 C1
attempts (respectively 61,903,365 and 61,903,424 charged C1 bytes, 3,656
C1 R2 operations). C2 returned a 1,049,306-byte MKWB for the exact 1 MiB
aggregate witness with four distinct R2 ranges. One byte over returned
typed 429/no MKWB after only the Commit and parent Tree ranges: the known
overflowing child Tree was not fetched.
The 32,768-position ChunkedBlob enrolled through 519 durable C1 attempts
(65,540 work units, 539,307,925 cumulatively charged read bytes, 33,288 R2
operations) after one transient local Miniflare connection loss and successful
saved-job resume. That is C1 enrollment cost, not C2 disclosure cost. The
subsequent C2 request returned a 1,049,182-byte verified MKWB after five
distinct R2 ranges. A sampled `ps -axo pid,rss,command` during enrollment
showed the two local `workerd serve` processes at roughly 22–24 MiB and
76–78 MiB RSS; this is a point-in-time host-process observation, not a peak
Worker isolate or wasm heap measurement and not a deployed memory guarantee.
For C2 itself, the existing `snapshot_resource.mjs` inspector sampler attached
to the named `core:user:mkit-vcs-managed-local-test` isolate during eight
repeated nested-exact GetWorkspace reads. Across 367 samples in 45.1 seconds,
observed maxima were 5,843,480 bytes JS heap used and 4,032,221 backing-
storage bytes; the V8 profiler recorded 1,000 samples. Local Wrangler reported
177–1,308 ms wall durations for those eight reads, each returning the same
1,049,306-byte MKWB after four distinct ranges. The sampler did not expose
wasm memory in this production glue build, so wasm growth and exact peak
isolate/process memory remain unmeasured; JS/backing values are not additive.
Profiler sample count and wall time are not an isolated CPU-time measurement.

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
