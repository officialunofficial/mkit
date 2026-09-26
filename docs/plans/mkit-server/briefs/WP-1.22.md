## Purpose

Today every row of a namespace lives in one partition (`SinglePartition`). D34 splits a namespace's state:
- a **namespace coordinator** (the namespace record, the repo registry, the grant epoch);
- one **ref shard** per (repo, ref), where a branch head and its packmap share one shard, so `AdvanceRefs` stays
  atomic;
- eventually consistent index shards (later WPs).

This WP:
- implements `D34Shards` behind the existing `ShardMap` seam;
- lays out the coordinator's namespace and repo records;
- makes the pipeline compute `creates_namespace`/`creates_repo` for multi-repo writes and commit creation through
  the coordinator;
- replaces WP-1.4's temporary "repo exists = has a ref row" check with the repo registry;
- adds a native `--sharding single|d34` option, default `single`.

**Not in this WP:**
- epoch leases and the config-version cache (WP-1.25);
- the ref-name index and ListRefs over D34 (WP-1.23/1.28);
- Durable Object classes for the new shard kinds (WP-1.8);
- namespace policy (WP-1.5);
- the per-namespace quota aggregate (WP-1.26).

## A. Fixed by the plan and specs (do not change)

1. **Plan:** `docs/plans/mkit-server/m1-m2-breakdown.md` "WP-1.22"; PRD D34 (`prd-snapshot.md`); `00-plan.md` R-76
   and P-22.
2. **Partitions already exist** (`store/partition.rs`): `Coordinator(ns)`, `Ref { ns, repo, shard_ref }`,
   `RepoIndex { ns, repo, prefix }`, `RefIndex { ns, repo, bucket }`. Their encodings are stable. **Do not change
   `Partition` or its encoding.**
3. **Fixed fan-outs:**
   - the membership shard is `RepoIndex` over `INDEX_FANOUT = 4096` (`store/content_index.rs:45`), taking the first
     12 bits of the pack id;
   - the ref-name index is `RefIndex` over `REF_INDEX_FANOUT = 16`.
   - Both are fixed forever (never resharded).
4. **Co-location:** `refs/heads/<x>` and `refs/mkit/packmap/<x>` (`mkit_core::refs::PACKMAP_REF_PREFIX`) MUST map to
   one ref shard (the `ShardMap::ref_shard` doc contract).
5. **Spec rules:**
   - SPEC-TRANSPORT-CONNECT §7.4 "Creation": a repository comes into existence with its first authorized write.
   - §7.5 "Creation signals": authorization and admission see `creates_namespace`/`creates_repo`.
   - §5.1 "No state on challenge": a challenged or denied request creates no namespace or repository.
6. **Store contract:** one batch is one partition (rule 6). Cross-partition steps are ordered by the pipeline.
7. **`FsLayoutStore`** (ssh, fs-layout) stays `SinglePartition` forever.
8. **Single-repository addressing is unchanged:**
   - the configured repo exists by configuration;
   - `creates_*` are always false;
   - no coordinator reads.

## B. Decided by the orchestrator (do not change)

### B.1 `ShardMap` trait changes (`pipeline/shard.rs`)

- Replace `fn ref_index(&self, repo: &RepoId) -> Partition` with:
  ```rust
  /// The ref-name index shard that holds `ref_name`.
  fn ref_index(&self, repo: &RepoId, ref_name: &str) -> Partition;
  /// Every ref-name index shard of `repo`, in bucket order.
  fn ref_index_partitions(&self, repo: &RepoId) -> Vec<Partition>;
  ```
- `SinglePartition`:
  - `ref_index` → `Namespace(ns)`;
  - `ref_index_partitions` → `vec![Namespace(ns)]`;
  - every other method unchanged.
- Update the call sites. ListRefs (`pipeline/mod.rs`): if `ref_index_partitions(repo).len() != 1`, return
  `unimplemented` "ListRefs under d34 sharding lands with WP-1.28", with `// TODO(WP-1.28)`. Otherwise scan that one
  partition, as today.

### B.2 `D34Shards` (new file `rust/crates/mkit-server/src/pipeline/shard/d34.rs`)

- Or `pipeline/shard_d34.rs` if you keep `shard.rs` a single file (C). Export it next to `SinglePartition`.
- **`ref_shard(repo, name)`** returns `Partition::Ref { ns, repo, shard_ref }`, where:
  - `refs/mkit/packmap/<x>` gives `shard_ref = "refs/heads/<x>"`;
  - `refs/heads/<x>` gives `shard_ref = "refs/heads/<x>"`;
  - every other ref gives `shard_ref = name`.
- **`coordinator(ns)`** returns `Partition::Coordinator(ns)`.
- **`membership(repo, pack)`** returns `RepoIndex { prefix: (u16::from(p[0]) << 4) | u16::from(p[1] >> 4) }`: the
  first 12 bits.
- **`ref_index(repo, name)`** returns `RefIndex { bucket }`, where
  `bucket = u16::from_be_bytes(blake3(name.as_bytes())[0..2]) % REF_INDEX_FANOUT`.
  - Add `pub const REF_INDEX_FANOUT: u16 = 16;` next to `INDEX_FANOUT`.
- **`ref_index_partitions(repo)`** returns the 16 buckets in order.
- **Golden:** `rust/tests/golden/shards/d34-mapping.json` with `MANIFEST.txt`.
  - It maps sample (repo, ref) pairs to encoded partitions (hex of `Partition::encode`) and sample pack ids to
    prefixes, including the head/packmap pair, a tag, a nested branch `refs/heads/a/b`, and the prefix edge values
    `0x000`, `0xfff` and `0x123`.
  - A test pins it, with `UPDATE_GOLDEN=1` to regenerate, following `mkit-git-bridge/tests/golden.rs`.

### B.3 New key layouts (`store/keys.rs`, each with a golden entry in the existing key-layout tests)

| Class | Partition | Key | Value |
|---|---|---|---|
| namespace record | coordinator | `nr 00` | codec `NamespaceRecord { created_at_ms: u64, config_version: u64 }` (version starts at 1) |
| repo record | coordinator | `rr 00 <repo>` | codec `RepoRecord { created_at_ms: u64 }` |
| repo-known marker | ref shard | `rk 00 <repo>` | empty |

- `rr` is the existing reserved `TAG_REPO_REGISTRY`: move it out of `RESERVED_TAGS` into a laid-out class.
- `nr` and `rk` are new tags; check they collide with no existing or reserved tag.
- `nl` stays reserved for WP-1.5.
- Codecs go in `store/codec.rs`, following the existing versioned-codec style, with round-trip and golden tests.
- Update the `keys.rs` module doc table.

### B.4 Creation facts and the coordinator (new `rust/crates/mkit-server/src/pipeline/coordinator.rs`)

1. **`Operation` gains `pub creation: Creation`,** where `Creation` is `#[non_exhaustive]` Debug, Clone, Copy,
   Default, PartialEq, Eq, with `pub namespace: bool` and `pub repo: bool`.
   - `AdmissionInput::new` copies `creates_namespace`/`creates_repo` from `op.creation`, replacing today's hardcoded
     `false`.
   - Document on both that these are the **pre-admission observation**: two racing first writes may both see
     `true`, and exactly one commits the creation.
2. **Where it runs, for multi-repo addressing writes only** (UpdateRef and AdvanceRefs; Multi pack RPCs are still
   `unimplemented` from WP-1.4). In `Pipeline::write`:
   - After the replay lookup, and before `authorize`: if `read_ahead`'s snapshot shows `rk 00 <repo>` present in the
     ref shard, set `Creation::default()`: the repo exists and no coordinator call is needed.
     - Otherwise do one `get_many` on `coordinator(ns)` for `[nr 00, rr 00 <repo>]`, and set
       `creation = { namespace: nr absent, repo: rr absent }`.
     - Add `rk 00 <repo>` to the keys `read_ahead` fetches: the same single `get_many`, so no extra call.
   - After admission returns `Allow`, and before `pre_receive`/`plan_and_apply`: if `creation.namespace ||
     creation.repo`, apply one coordinator batch.
     - It holds `Absent(nr 00)` + `Put(nr 00, …)` when `creation.namespace`, and `Absent(rr 00 <repo>)` +
       `Put(rr 00 <repo>, …)` when `creation.repo`.
     - `created_at_ms` is the business clock.
     - `Committed` sets `op.created = creation`: a new `pub created: Creation` field on `Operation`, the committed
       fact.
     - `PreconditionFailed` means another writer created it first. Re-read the two keys once; if both are now
       present, proceed with `op.created = Creation::default()`. Otherwise it is `internal`.
     - A challenge or denial never reaches this step (A.5).
   - In `plan_and_apply`, when `rk 00 <repo>` was absent in the snapshot, the ref-shard batch also puts
     `rk 00 <repo>` (with an `Absent` precondition, so a re-plan stays correct). Add a `mark_repo_known: bool` to
     the `WriteRequest` planner input.
3. **Cost targets** (tested with a call-counting store wrapper), for multi-repo writes under both `single` and
   `d34` sharding:

   | Write | Store calls |
   |---|---|
   | Steady state (`rk` present) | exactly 2: ref-shard `get_many` + ref-shard `apply` |
   | First write to a new ref shard of an existing repo | 3: + coordinator `get_many` |
   | First write creating the repo (and possibly the namespace) | 4: + coordinator `apply` |

4. **Order rationale** (put it in the module doc): coordinator rows commit **before** the ref write. A crash
   between the two leaves an empty registered repo, which ListRefs shows as empty. It never leaves refs in an
   unregistered repo, which reads would report as `not_found`.

### B.5 Repository existence (replaces WP-1.4's check)

- `require_repository` (`pipeline/mod.rs`, multi-repo addressing only) does `get(coordinator(ns), rr 00 <repo>)`.
  Absent gives `not_found` "repository not found".
- Delete the scan-based check and its `TODO(WP-1.22)`.
- Single addressing: no check (unchanged).
- The WP-1.4 isolation tests must keep passing unchanged, including same name in different namespaces.

### B.6 Where other rows live under D34 (document these; no new mechanism)

- **Replay records and quota rows** follow the write's partition, i.e. the ref shard (planners already use the
  write's `p`). Under `d34`, the default quota therefore counts per ref shard. The namespace aggregate is WP-1.26.
  Say so in `PipelineConfig::write_quota`'s doc and in the CHANGELOG.
- The **grant epoch** is still read from the write's partition in `read_ahead` (absent = 0). Coordinator-to-shard
  epoch propagation is WP-1.25 (epoch leases). Leave a `// TODO(WP-1.25)` at that read.
- The **legacy untargeted `UploadPack`** keeps using `coordinator(ns)` (`pipeline/upload.rs`), as today.

### B.7 Configuration

- **Native:** `mkit-server serve --sharding single|d34`, default `single`, for the SQLite metadata choice only.
  - `--sharding d34` with `--meta fs-layout` is a usage error (exit 64, `exit::USAGE`).
  - `PipelineConfig` gains `pub sharding: Sharding { Single, D34 }` (`#[non_exhaustive]`, default `Single`).
    `Pipeline::new` picks the `ShardMap` from it.
  - Keep however the pipeline currently holds `SinglePartition` (a type parameter or a boxed map) as C, but a
    deployment switches sharding only through config.
- **Worker:** no option. It stays `single` until WP-1.8 adds the DO classes. Assert in the adapter that the Worker
  config builds `Sharding::Single`.
- **`00-plan.md`:** add row `R-90`: "WP-1.22 defers the coordinator `config_version` isolate cache to WP-1.25, where
  `config_version` is delivered with the lease. Until then multi-repo reads that never touch a ref shard do one
  coordinator `get`."

## C. Your decisions (record each in the PR under "Executor decisions")

- How `Pipeline` holds the `ShardMap` (generic parameter vs `Arc<dyn ShardMap>`), within B.7's constraint.
- The module file layout for B.2/B.4.
- Helper names, and how `read_ahead` threads the extra `rk` key.
- Golden sample selection (B.2) beyond the required cases.
- Test organisation.

## Tests (required)

1. **Mapping:**
   - golden B.2;
   - head/packmap co-location, property-tested over random branch names;
   - every bucket is in `0..16` and every prefix in `0..4096`;
   - `ref_index_partitions` has 16 distinct entries.
2. **Creation**, in-process pipeline, over memory and SQLite, with `Addressing::Multi` under both `single` and `d34`:
   1. The first write to a new namespace gets `creation = {true, true}` at admission, and `op.created = {true, true}`.
   2. A second repo in the same namespace gets `{false, true}`.
   3. A write to an existing repo gets `{false, false}` and makes no coordinator call once `rk` exists.
   4. **Race:** two first writes to a new namespace, interleaved with a store wrapper so both read `nr` absent.
      Both admissions see `namespace: true`, exactly one gets `created.namespace == true`, and both writes commit.
   5. A challenged admission (a test `Admission` returning `Challenge`) leaves no `nr`/`rr` rows.
   6. A denied authorization leaves none either.
3. **Cost:** the call-count table in B.4.3, for both sharding modes.
4. **Atomicity:** under `d34`, `AdvanceRefs` commits head and packmap in one batch in one `Partition::Ref`. The
   existing CAS/conflict tests pass with `--sharding d34`, except ListRefs.
5. **Existence:** a Multi read of an unregistered repo gives `not_found`. After a first write, reads work. A crash
   simulated between the coordinator batch and the ref write (fail the ref apply) leaves ListRefs returning an empty
   list, not `not_found`.
6. **Wire:**
   - The spawned native binary runs the wire suite with `--sharding d34`.
   - ListRefs-dependent cases are skipped under a declared profile flag. Add `Profile.sharding_d34: bool`, or a
     `--sharding` runner option: your choice (C). Make the skip list explicit, and assert it's non-empty only for
     ListRefs cases.
   - Everything else passes. Also run the default `single` run as today.
7. **Unchanged:**
   - every existing server, native, worker and conformance test;
   - the ssh goldens;
   - `rust/tests/golden/` apart from the new `shards/` dir and any key-layout golden B.3 extends.

## D. Escalate (stop and report, do not improvise) if

- B.4's ordering can't guarantee "no state on challenge" (A.5) with the existing stage order.
- A replay-committed retry would reach the coordinator. It must not: the replay lookup precedes creation facts.
- `AdvanceRefs` under `d34` can't stay one batch, e.g. an existing caller pairs refs other than head/packmap.
- Changing `ShardMap::ref_index` breaks a caller outside `mkit-server`. Grep the workspace, including `apps/`.

## Gate additions

- `just ci-server`
- `cargo nextest run --locked -p mkit-server -p mkit-server-native -p mkit-server-conformance -p mkit-server-worker --all-features`
- the wasm32 check of `mkit-server`; the build of `mkit-server-worker`
- `scripts/vcs-worker-conformance.sh` (default phase), if wrangler is available: the Worker must be unchanged
