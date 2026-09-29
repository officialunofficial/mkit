## Purpose

Under D34, ListRefs lists refs through a relay-maintained ref-name index spread over 16 RefIndex buckets. Every D34 ref
write updates the index through the outbox relay, in the same batch as the write, and deletions travel as relay
deletes. This removes the last D34 ListRefs refusal and every D34 ListRefs conformance skip. D34 stays opt-in until
1.28c.

## A. Fixed (do not change)

1. **STC §7.9:** ListRefs is eventual, and lag MUST only produce an older listing. Push CAS uses strong `ReadRef`.
2. **R-102:** relay rows are at-least-once and deduplicated by `rh`. **R-123:** the 1.28 split; the index row is
   `x 00 <repo> 00 <refname>` → the raw 32-byte id, live values only, in RefIndex partitions.
3. **R-127 (#1187):** a batch that appends relay rows carries the source's epoch lease.
4. **The ref-index fan-out is 16** (`D34Shards::ref_index`). The D34 AdvanceRefs pair rule keeps a head and its packmap
   in one ref shard. Their index buckets usually differ.
5. **The ticket cap is 7** (STC §4, SPEC-SERVER §15.2).

## B. Decided (do not change)

### B1. Keys and codec
- Add tag `x`: `TAG_REF_INDEX`, `ref_index_key`, `ref_index_prefix_range` (mirroring `ref_prefix_range`), a
  `ParsedKey::RefIndexEntry` arm, a row in the `keys.rs` doc table, and a golden.
- `RelayV1` gains `pub deletes: Vec<Key>`:
  - the DTO field is `#[serde(default, skip_serializing_if = "Vec::is_empty")]`, so rows without deletes encode
    byte-identically to today (golden);
  - validate key sizes;
  - reject a key present in both `puts` and `deletes`, and duplicate deletes;
  - unknown fields are still denied.
  - Update the "Deletions are excluded" doc.

### B2. Outbox and delivery
- `OutboxBuilder::relay_delete(target, keys)`. A put and a delete of the same key in one batch is `Invalid`.
- Row splitting counts **puts + deletes** ≤ `MAX_RELAY_PUTS`. Keep the constant's name and re-document it as
  "operations". A delete's bytes count as `3 + 2·len`.
- `deliver.rs`: each row appends its `Write::Delete`s after its puts, and `fitting_prefix` counts them.
- **Single-producer rule:** a key that is ever relay-deleted MUST have exactly one producer. State it in `deliver.rs`
  and INVARIANTS. It is compatible with #1195's "identical upserts from several producers", because `i` rows are never
  relay-deleted.

### B3. One builder per write
- `plan_write` owns one `OutboxBuilder` for any committed D34 write with refs.
- `advance::plan_consumption` takes `&mut OutboxBuilder` and no longer finishes its own.
- After the ref writes, a helper adds, for each `(name, new)` whose `ref_index(name) != source`:
  - `relay(bucket, [(x key, id)])` for `Some`;
  - `relay_delete(bucket, [x key])` for `None`.
- Then `relay_at(plan_time)` and `try_finish`.
- It always relays, even an unchanged id.
- Conflicts, replays and Single sharding produce no rows.
- Every UpdateRef and AdvanceRefs form (ticketed, direct, delete) goes through it.
- `read_ahead` and `WriteRequest::read_keys` include `os` and `oc` under D34 when the op writes refs. A steady-state
  D34 write stays at 2 store calls.

### B4. Op budget
- `ADVANCE_SHARED_OPS` = **25**, with its comment gaining "ref-index relay rows 2". The worst case at n = 7 is
  `9·7 + 25 = 88` of 100.
- The exact-count planner test becomes 88. It uses names whose buckets differ, and asserts that they differ. Single
  stays 77.
- The R-row corrects R-122's `9n+23` and R-123's `9n+21` to `9n+25`.

### B5. D34 ListRefs
- An `IndexBucket { store, partition }: BucketSource` over `x` rows.
- A row that fails to parse or decode, or sits in the wrong bucket, is `Corrupt`, which maps to `unavailable`.
- Replace the refusal in `list_refs_page` with 16 `IndexBucket`s built from `ref_index_partitions`. Single keeps
  `RefBucket`.
- Move `faults::run_timers` before the branch.
- Scans stay sequential.

### B6. Test seams (test-faults only)
- **Relay-delay:** extend #1187's `delay_relay_batch` to every AdvanceRefs form as well as UpdateRef.
- **`run_timers`:** also runs a `RelayHandler` on the named ref shard after `TestTimer`, until nothing is due.
- **`TestTimer` under D34:**
  - it reads `os`, and plans the `r` delete together with a relay delete to `ref_index(name)`, guarded on `os`;
  - it adds the relay kick;
  - it carries **no epoch lease**. This is a documented test-only exemption from R-127: the kind is compiled out of
    release builds, and a lease guard would stall it after the lease expires.

### B7. Conformance
- Delete `D34_LIST_REFS_SKIPS`, `sharding_skip_reason` and their self-test.
- Flip the code that pins the refusal:
  - `leases.bump_completes_and_writes_continue` to ok under D34;
  - `wire_binary.rs` to assert no D34 skips;
  - `d34_creation.rs` to `Ok`;
  - `profile.rs` and the native README.
- Listing cases that don't need test-faults use a shared bounded poll (`eventually_listed`: every 200 ms, up to
  `RELAY_LAG_BOUND_MS`), because they also run against real deployments.
- `timers.*` cases use `run_timers` for determinism.
- `paging_wire` waits until every ref is listed before asserting page shapes.

### B8. Spec and plan
- **STC §7.9** gains: "An index lags per bucket, so a listing need not reflect a single instant; a branch head and its
  packmap may appear at different ages." Add a version row.
- **R-134:**
  - the `x` layout;
  - `RelayV1.deletes` and the single-producer rule;
  - every D34 ref write relays its index row in the same batch (`9n+25`, 88 at n = 7);
  - the relay-delay fault covers AdvanceRefs;
  - the `TestTimer` lease exemption;
  - per-bucket lag;
  - R-116's reconcile must also relay deletes for index rows whose ref is absent.
- Fix the false comment at `store/partition.rs:~35` ("ref shards are found by scanning RefIndex"). Point it at the
  active-shard table and WP-5.3a.
- CHANGELOG entry.

## C. Your decisions

- The borrowing adapter for `run_timers`.
- How `WriteRequest` learns the index source: a new field, or derived from `lease.is_some()` plus the source partition.
- Module layout, for example `store/ref_index.rs`.
- **The Worker D34 phase's 10,000-ref listing case:** keep it if the runtime is acceptable. Otherwise pass
  `--list-refs 1000` in that phase only, and record the reason.

## D. Escalate (stop and report) if

- The n = 7 D34 advance exceeds 88 ops, or anything other than index relay rows grows the advance batch.
- Production changes exceed 1,500 lines.
- #1187 has not merged when you start. Report and wait; don't build your own relay-delay directive.

## Tests (required)

1. **Keys:** the `x` golden, the parse round trip, range bounds (`feat` vs `featx`), and repository isolation.
2. **Codec:**
   - a row without deletes is byte-identical to today;
   - `deletes` round-trips;
   - an overlapping, duplicate or oversize key is rejected;
   - an unknown field is denied.
3. **Outbox:**
   - `relay_delete` grouping;
   - a put and a delete of the same key is `Invalid`;
   - splitting at 96 operations counts deletes;
   - byte caps.
4. **Delivery:**
   - a put then a delete across rows in one target batch leaves the key absent;
   - redelivery is idempotent;
   - two updates deliver the last value;
   - hooks keep their 2 spare ops.
5. **Planning:**
   - UpdateRef produces 1 row;
   - AdvanceRefs produces 1 or 2 rows (same bucket and different buckets);
   - a delete produces relay deletes;
   - a conflict, a replay and Single produce none;
   - a ticketed advance has exactly one `os` pair and one kick.
6. **Budget:** exactly 88 at n = 7 on D34 with differing buckets; the const assert; Single 77.
7. **Read path:**
   - a property test on the real memory and SQLite stores: D34 pages over 16 buckets equal the sorted full listing;
   - prefix boundaries;
   - two-repository isolation;
   - a bucket failure and a misrouted row both give `unavailable`.
8. **Lag:**
   - before a relay tick, ReadRef sees a new ref and ListRefs doesn't;
   - after a delete and before the tick, ListRefs still lists it;
   - after the tick, both agree;
   - relay-delay on UpdateRef and on AdvanceRefs.
9. **Calls:** a spy store shows a steady-state D34 write is 2 calls, and a page is at most 16 bucket scans.
10. **`TestTimer` under D34:** it deletes `r` and relays the index delete, and `run_timers` delivers it.
11. **Wire:** all nine former skips pass under `--sharding d34` on native and in the Worker D34 phase; `leases.*` is ok.
12. **Native e2e:** `d34_creation.rs` lists `Ok`; the real relay driver delivers index rows.

## Gates

- `just ci-server`
- `cargo nextest run --locked -p mkit-server -p mkit-server-native -p mkit-server-conformance -p mkit-server-worker --all-features`
- the wasm32 check and the worker build
- `scripts/vcs-worker-conformance.sh`, in the default phase and with `--sharding d34 --test-faults`
