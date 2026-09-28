## Purpose

This WP gives Workers deployments disaster recovery beyond the Durable Object 30-day point-in-time restore (PITR),
and gives both runtimes a way to move data between backends:
- every Durable Object (DO) periodically writes a consistent snapshot of its partition to R2;
- a core restore driver imports snapshots in a safe order;
- native gains `export` and `restore` subcommands.

## A. Fixed (do not change)

1. **Portable format:** M0-02 `store/maintenance.rs` (`mkitexp\0`, version 1, `EXPORT_END`) and `Importer` (`Fresh` /
   `Merge`), used **unchanged**. "The stream is not a snapshot": consistency must come from how you read it (B.2).
2. **Timers:** the kinds table (`timers/registry.rs`) has 1 LEASE_SWEEP, 2 TICKET_EXPIRY and 3 RELAY.
   **4 is this WP's.**
   - The handler contract: `fire` may run more than once, and effects outside the returned batch must be idempotent.
   - `Fired::Reschedule` must change the timer key.
3. **Restore constraints:**
   - **R-100:** a restored coordinator is marked lease-table-recovered before serving writes.
   - **R-102:** a restored source's relay sequence must end above every target's high-water mark `rh`, or be
     re-keyed.
   - **R-94/R-93:** `sm` / the sharding marker is present before any traffic.
   - **SPEC-WRITE-GRANTS §5 / §15:** a stored epoch never decreases.
4. **Cloudflare facts:**
   - DO SQLite calls are synchronous. A run of store calls with no JS await is an atomic snapshot; awaiting R2 lets
     other requests in.
   - R2 keys are ≤ 1,024 bytes.
   - The isolate has 128 MB of memory.
   - Free plan subrequest limits apply (R-88(7): `WORKERS_PLAN=free` stays).
   - PITR has no workers-rs binding.
5. **`ObjectBucket`** (`mkit-server-worker/src/r2.rs`) has put, head, get, delete and probe, and **no list**.

## B. Decided by the orchestrator (do not change)

### B.1 Timer kind 4, `BACKUP` (Worker only)

- **Registration:** in `adapter::ns_object`, for **every** `ShardClass`, when the optional `BACKUPS` R2 binding
  exists and `BACKUP_INTERVAL_MS` is not 0.
  - The default interval is 24 h.
  - If the binding is absent, log once with `log_failure` and register nothing.
  - Natively, nothing is registered.
- **Seeding:** after the **first committed batch containing a put** in an instance's lifetime, when the state row is
  absent, seed one kind-4 timer.
  - Use the WP-1.29a post-commit hook point.
  - **Never seed on reads.**
- **State row:** `bk 00`.
  - Add `TAG_BACKUP_STATE = "bk"` to `store/keys.rs`, with a layout-table row, parse support and the golden layout
    test. It is never pruned.
  - Value codec `BackupStateV1`: `{ last_export_ms, digest: [u8;32], r2_key, last_upload_ms }`.

### B.2 One `fire` equals one consistent snapshot

1. **Read** the whole partition with `export_page` in a loop, **synchronously**, with no await, encoding into one
   buffer in the M0-02 format. Exclude the `bk 00` row and every kind-4 timer row.
2. **Cap:** above `BACKUP_MAX_BYTES` (default 16 MiB), don't export. Log `backup_skipped_oversize` (structured, with
   `kind` and `bytes`) and reschedule; PITR covers these.
3. **Digest:** BLAKE3 over the encoded bytes.
4. **Skip:** if the digest is unchanged **and** `now − last_upload_ms < BACKUP_FORCE_REUPLOAD_MS` (default 28 days,
   below the retention rule), skip the upload.
5. **Otherwise, upload** once with `put`:
   - key: `backups/v1/<BACKUP_PREFIX or worker name>/<kind-tag>/<hex blake3(Partition::encode)>/<exported_at_ms, 13 digits>-<first 16 hex of digest>.kvlog`;
   - custom metadata: the hex `Partition::encode` (it fits in 8 KiB).
   - The records also carry the partition, so every object describes itself.
6. **Commit and reschedule:** return a `Reschedule` batch that updates `bk 00` guarded by `Equals` / `Absent`. An R2
   failure returns `Retry`.
7. **Budget:** the timer's time budget is checked only between timers, so one fire must stay within ~5 s of CPU at
   the cap. Measure it at 16 MiB in a host test and record the result.

### B.3 Core restore driver (`store/restore.rs`), generic over `NamespaceStore`

`restore(snapshots, target, opts)` imports in dependency order:

1. **The root `Namespace` partition first,** so `sm 00` exists before anything else.
2. **Coordinators.**
   - Import, then mark lease-table-recovered. Add a store-level function that writes `lr 00` exactly as
     `Pipeline::mark_lease_table_recovered` does, and share the code with it (R-100).
   - **Epoch:**
     - restoring in place, or `Merge` over a live store: set each namespace epoch to max(live, snapshot);
     - into a `Fresh` store: set the epoch to snapshot + 1, unless the operator passes `epoch_at_least`.
     - Revoked grants must never come back.
3. **Ref shards.** Re-key every restored relay row `or 00 <seq>` to `seq + RESTORE_SEQ_JUMP` (2^40), and set `os`
   to `restored_os + RESTORE_SEQ_JUMP`.
   - Relay rows are upserts only (R-102), so re-application is idempotent. Gaps in seq are harmless because targets
     compare only against `rh`. **Confirm this in code**, and cite the lines in the PR.
   - Delete any restored `rs 00` (1.23b's relay scan state), if present: a fresh cycle satisfies its invariant.
4. **Index and content shards.**
5. **Finally, drop restored kind-4 timer rows and `bk 00` rows**, so the restored deployment re-seeds its own
   backups.

Options:
- `Fresh` refuses non-empty partitions (existing `Importer` behaviour);
- `Merge` is allowed only with an explicit `--merge` flag.

### B.4 Native CLI

- **`mkit-server export --meta sqlite:<PATH> --out <DIR>`:**
  - enumerate partitions with `SELECT DISTINCT` on the partition column;
  - write one `.kvlog` per partition, named by the same hash scheme as B.2 (the `<kind-tag>/<hash>/` layout under
    `<DIR>`);
  - read everything inside **one read transaction**, so the export is consistent;
  - refuse a non-empty `<DIR>` with USAGE (64);
  - create files with mode 0600, following WP-1.29a's `backup`.
- **`mkit-server restore --meta sqlite:<NEW PATH> --from <DIR> [--merge] [--epoch-at-least N] [--sharding single|d34]`:**
  - runs B.3 into a new database;
  - records `--sharding` in `mkit_server_sharding` (R-93);
  - refuses an existing database unless `--merge` is given.
- **README:** a runbook covering:
  - PITR first, for anything within 30 days;
  - export and restore for disaster recovery and backend moves;
  - setting up the `BACKUPS` bucket and its lifecycle rule. The rule covers `backups/` only, and **never `packs/`**.
    The retention default is 35 days; this is a human deploy step, so add it to the 1.19 checklist note;
  - that a snapshot older than the maximum envelope validity carries no replay risk;
  - the known deferrals (C/D below).

### B.5 Worker import (tests only)

- A `test-faults`-gated route imports a `.kvlog` into a DO, for the wrangler-dev round trip.
- **No production import route:** that is deferred to the admin API (WP-5.11b).

### B.6 Plan

- Add row **R-112**:

  > WP-1.29b restore invariants:
  > - the epoch never decreases (in place: max; fresh: snapshot + 1 or `--epoch-at-least`);
  > - restored relay rows are re-keyed by 2^40;
  > - restored `rs`, `bk` and kind-4 rows are dropped;
  > - the root `sm` is imported first;
  > - coordinators are marked recovered (R-100).
  >
  > Deferred: a production Worker restore/PITR admin route (5.11b), segmented export above the size cap, index
  > reconcile after restore (after 1.28), a post-restore replay fence, and a GC hold ≥ backup retention (M5).

- Update the 1.29 row's dependencies to 1.25 and 1.23a.

## C. Your decisions

- The module layout.
- `BACKUP_PREFIX` defaulting.
- How the DO reaches the R2 bucket from the timer handler (capture `EnvBucket` in the adapter).
- The PITR bookmark: record `getCurrentBookmark()` in the object metadata via `js_sys::Reflect` if it's cheap, and
  make it fail soft under wrangler dev. It's optional.

## Tests (required)

1. **Snapshot consistency:** a host test proving that no write interleaves a `fire` (the synchronous read).
2. **The digest-skip and forced re-upload schedule,** with an injected clock.
3. **The oversize skip.**
4. **The key layout:** the maximum-size partition's key stays ≤ 1,024 bytes.
5. **The restore driver** (memory and SQLite):
   - the order: `sm` before anything else;
   - `lr` present on coordinators;
   - epoch max and +1 behaviour;
   - relay re-key: `os > rh` for every target, and relay delivery after restore reaches the targets exactly once in
     effect;
   - `rs`, `bk` and kind-4 rows dropped;
   - `Fresh` refuses non-empty.
6. **Native:**
   - `export` followed by `restore` gives equivalent partitions, except for the documented rewrites;
   - export under concurrent writes is consistent;
   - the CLI's USAGE refusals.
7. **Worker:** a wrangler-dev round trip, where an export from one DO imports through the test-faults route. Put it in
   the conformance script phase.
8. **Unchanged:** every existing test.

## D. Escalate (stop and report) if

- A synchronous snapshot at 16 MiB exceeds the DO CPU budget in measurement.
- R-102's re-key isn't provably safe from the code.
- Epoch handling needs a spec change.

## Gates

- `just ci-server`
- `cargo nextest run --locked -p mkit-server -p mkit-server-native -p mkit-server-worker --all-features`
- the wasm32 check and the worker build
- `scripts/check-wasm-dep-graph.sh`
- `scripts/vcs-worker-conformance.sh` (default phase, plus the round trip)

## Amendment 1 (orchestrator, 2026-09-27)

This amendment replaces B.3's Merge/in-place options, fixed relay jump,
and the corresponding B.4 CLI and test clauses. Restore is Fresh-only in
WP-1.29b. The driver and CLI have no Merge mode or `--merge` flag; an
existing target is refused. Workers PITR and the native physical `backup`
cover in-place recovery. In-place/Merge logical restore is deferred to
WP-5.11b.

The driver scans the complete supplied restore set before importing. For
each ref-shard source S, it reads snapshot `os_S` and every supplied target's
`rh[S]`, and computes `floor_S = max(snapshot_os_S, max supplied rh[S])`.
It then imports in dependency order, re-keys each restored `or <seq>` row to
`or <seq + floor_S>`, and writes `os_S = snapshot_os_S + floor_S`.
Checked arithmetic refuses overflow. The target is Fresh, so a target absent
from the set has no `rh[S]`; restored relay rows are upserts and can safely
be delivered again. The epoch becomes snapshot + 1, or the larger
`--epoch-at-least N` value. The native restore CLI accepts no `--merge`.

Required regressions include a supplied `rh[S]` greater than snapshot `os_S`,
an absent target, overflow refusal, epoch floor behavior, a non-empty target,
and a CLI USAGE refusal for `--merge`. R-112 records this scope and formula.
