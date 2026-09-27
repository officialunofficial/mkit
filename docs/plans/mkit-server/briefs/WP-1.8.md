## Purpose

WP-1.22 added D34 partitions (namespace coordinator, per-branch ref shards, index shards). WP-1.24 added timers and
alarms. On Workers, every partition is still served by the single M0 class `RefStore`, and the Worker is forced to
`Sharding::Single`.

This WP:
- adds one Durable Object class per shard kind;
- routes D34 partitions to them;
- lets a Worker deployment opt into `d34` sharding, with a guard against switching it over existing data;
- moves the health probe off the M0 root object;
- fixes the alarm-overwrite race before the first I/O-doing timer handler (WP-1.23) lands.

The default stays `single`. WP-1.28 flips it.

## A. Fixed by the plan, specs and merged code (do not change)

1. **Plan:** `m1-m2-breakdown.md` "WP-1.8" (lines ~301–316); `00-plan.md` P-1 ("one DO class per shard kind
   (migration v2)"), C-2 (DO constraints), R-26, R-50, R-88(7) (`WORKERS_PLAN=free` stays) and R-93.
2. **Routing names are already fixed** in `mkit-server-worker/src/naming.rs:13-83`:
   - `REFSTORE` (`"root"` / `"n:<ns>"`);
   - `NS_COORD` (`"c:<ns>"`);
   - `REF_SHARD` (`"r:…"`);
   - `REPO_INDEX` (`"i:…"` for `RepoIndex` and `"x:…"` for `RefIndex`, which share one binding);
   - `CONTENT_INDEX` (`"ci:…"`).

   Do not change binding names, instance names or `Partition` encodings.
3. **The M0-16 rule:** `#[durable_object]` structs live in the final cdylib (`apps/vcs-worker`), never in a
   dependency (`briefs/WP-M0-16.md:200-201`, `ns_object.rs:236-238`).
4. **Wrangler:**
   - stay on `migrations` (not `exports`);
   - add classes only with a new, unique migration tag and `new_sqlite_classes`;
   - never `deleted_classes` in this WP, because `RefStore` still serves `single` deployments and is needed until
     WP-1.28's migration;
   - `WORKERS_PLAN=free` unchanged;
   - `compatibility_date` unchanged, since the pinned wrangler supports `2026-09-09`.
5. **`NsObject`/`serve` are kind-agnostic, and the wire carries the partition** (`wire.rs`). The Worker's addressing
   stays `Single`: Multi addressing on Workers is WP-1.5's.
6. **Under D34:**
   - `ListRefs` is `unimplemented` until WP-1.28 (`D34_LIST_REFS_SKIPS`, `wire/mod.rs:231-249`);
   - quota counts per ref shard until WP-1.26.

## B. Decided by the orchestrator (do not change)

### B.1 Classes (four new, plus `RefStore` kept)

| Class | Binding | Serves `Partition` kinds |
|---|---|---|
| `NsCoordinator` | `NS_COORD` | `Coordinator` |
| `RefShard` | `REF_SHARD` | `Ref` |
| `RepoIndexShard` | `REPO_INDEX` | `RepoIndex`, `RefIndex` |
| `ContentIndexShard` | `CONTENT_INDEX` | `ContentShard` |
| `RefStore` (unchanged) | `REFSTORE` | `Namespace` |

1. **In `mkit-server-worker`,** add `src/classes.rs`, with no `#[durable_object]` in it:
   - `pub enum ShardClass { RefStore, NsCoordinator, RefShard, RepoIndexShard, ContentIndexShard }`
     (`#[non_exhaustive]`);
   - `fn accepts(self, p: &Partition) -> bool`, per the table;
   - `fn binding(self) -> &'static str`.
2. **`adapter::ns_object(state, env)` becomes `adapter::ns_object(state, env, class: ShardClass)`.**
   - The capacity (`WORKERS_PLAN`) and the timer registry stay identical for every class.
   - The `class` parameter is the hook for per-kind handlers in 1.23 and 1.25.
3. **Kind guard:** `NsObject` stores its `ShardClass`. `serve` answers `NsReply::Err { kind: Invalid,
   message: "partition kind not served by this class" }` for a partition the class doesn't accept, before touching
   the store. Test this on the host through `serve`.
4. **In `apps/vcs-worker/src/worker_impl.rs`,** write out four `#[durable_object]` structs, each about 15 lines, the
   same shape as `RefStore`:
   - `new` → `adapter::ns_object(state, &env, ShardClass::X)`;
   - `fetch` → `object.handle(req)`;
   - `alarm` → `object.alarm()`.

   No macro. Re-export them from `lib.rs`, like `RefStore`.
5. **`wrangler.jsonc` and `wrangler.dev.jsonc`:**
   - add the four `durable_objects.bindings`;
   - append `{ "tag": "v2", "new_sqlite_classes": ["NsCoordinator", "RefShard", "RepoIndexShard",
     "ContentIndexShard"] }`, keeping `v1` as is.

### B.2 Worker sharding switch

- **Config:** a new var `SHARDING`, `single` (default when unset) or `d34`.
  - Parse it in `WorkerConfig::from_vars`. Any other value is a `ConfigError`, taking the same path as a missing
    `AUTH_*`.
  - `pipeline_config` sets `config.sharding` from it and removes both `TODO(WP-1.8)`s.
  - Replace the test `deployment_pipeline_keeps_single_sharding_until_do_dispatch` with parse tests: unset, both
    values, and an invalid value.
  - Add `SHARDING` to `wrangler.jsonc` vars, set to `"single"`, with a comment pointing to the guard below.
- **Guard** (mirrors native R-93):
  - Lay out a new key class in `store/keys.rs`: the **deployment sharding marker `sm 00`**. Its value is the UTF-8
    `"single"` or `"d34"`. It lives only in `Partition::Namespace(deployment_default)`, the `RefStore` "root" object.
    Add a golden entry, and update the module doc table.
  - Once per isolate (cache the result in a `OnceCell`/static in the adapter), before serving the first RPC, the
    Worker checks the marker through the ordinary `NamespaceStore` calls:
    - `get(root, sm)` is `Some(v)`: `v == mode` → OK; otherwise refuse.
    - It is `None`: if the root partition holds any other key (a `scan` of the full key range, limit 1), the data
      was written `single`, so `mode == d34` → refuse, and `mode == single` → put `sm = "single"` with
      `Precondition::Absent`.
    - If the root partition is empty, put `sm = mode` with `Precondition::Absent`.
    - `PreconditionFailed` → re-read once and compare.
  - **Refuse** means every RPC answers `unavailable` with public message `"deployment sharding mismatch"`, and the
    log line names both modes. This is the same class of response as a missing `AUTH_*` var.
  - Cost: at most three DO calls per isolate lifetime. Never per request.
  - Add row `R-94` to `00-plan.md`: "Worker sharding guard: `sm 00` marker in the root `RefStore` object, checked
    once per isolate; no single→d34 migration until WP-1.28."

### B.3 Probe off the root object

- `DoNamespaceStore` takes its probe partition from the adapter: `Namespace(root)` under `single`, and
  `Coordinator(deployment_default)` under `d34`. Health then no longer depends on `RefStore` under d34.
- Update `tests/stores.rs` for both modes.
- The test-faults stats hook (`adapter.rs:744-754`) stays on `Namespace(root)`. Under `d34` it answers HTTP 409
  `"stats hook is single-sharding only"`, so the growth case fails loudly instead of misreporting.

### B.4 Alarm-overwrite race (carry-forward from WP-1.24)

**The defect:**
- `NsObject::alarm()` finishes with `alarm_after_tick`'s Set/Delete (`ns_object.rs:381-384`).
- While `run_due` awaits, an interleaved `handle` Apply that puts a timer can set an alarm. `getAlarm` returns null
  during a running alarm handler (Cloudflare docs), so that Apply always sets its own.
- The final Set/Delete then overwrites it.

**The fix:**
1. Add a pure fn to `alarm.rs`:
   `alarm_after_tick_with_current(current: Option<i64>, next_wake: Option<u64>, now_ms: u64) -> AlarmAction`.
   - `current = Some(t)` → `Set(min(t, next_wake-as-alarm-time))`, or `Set(t)` when `next_wake` is `None`.
   - `current = None` → the old `alarm_after_tick` result.
   - Host tests cover every combination.
2. At the end of `alarm()`, call `get_alarm()` and apply the new fn.
3. In the PR, confirm from the Cloudflare docs whether a `get_alarm`→`set_alarm` pair inside an alarm handler can
   interleave with another request (input/output gates). Quote the passage.
   - If it can interleave, keep the fix. It's still strictly better, since it can only keep an earlier alarm.
   - Add a note to `INVARIANTS.md` either way.

### B.5 Placement

- **Vars:** `NAMESPACE_LOCATION_HINT` and `NAMESPACE_JURISDICTION`, both **deployment-wide**, both default none.
  - Read them into `WorkerConfig` and pass them to `StubTransport` as `Placement`.
  - Document in the vars comment and the crate docs that the jurisdiction is fixed for the deployment's lifetime:
    changing it re-maps every object name to new, empty objects.
  - An invalid jurisdiction value is a `ConfigError`.
- Add row `R-95` to `00-plan.md`: "R-50 narrowed: placement is per deployment, not per namespace. Per-namespace
  jurisdiction would be needed before routing to the namespace's own coordinator, which is circular."

### B.6 Conformance

- **`scripts/vcs-worker-conformance.sh` gains `--sharding d34`.** It sets the server var `SHARDING=d34` and passes
  `--sharding d34` to the runner.
  - Under d34 run **phase 1 only**, with and without `--test-faults`. With `--test-faults`, `timers.fire_on_schedule`
    exercises the `RefShard` alarm.
  - Phase 2 (quota, growth) stays single-only: quota counts per ref shard until 1.26, and the stats hook is root-only.
    Print why when skipping it.
- **Required runs, each recorded in the PR body:**
  - the default single run (unchanged);
  - `--test-faults` single;
  - `--sharding d34`;
  - `--sharding d34 --test-faults`.
- `RepoIndexShard` and `ContentIndexShard` receive no traffic until WP-1.23 and WP-4.10a. Say so in the PR. Their
  evidence is the host routing tests.

## C. Your decisions

- The internal shape of the isolate-cached guard (B.2) and where it runs in `adapter::fetch`.
- Test organisation and names.
- The wording of docs and comments.

## Tests (required)

1. **Host, `mkit-server-worker`** (using the `Loopback` harness in `tests/common`):
   - every partition kind routes to its binding;
   - the kind guard rejects foreign kinds per class;
   - isolation across namespaces and kinds;
   - both probe partitions.
2. **The guard:**
   - an empty root under `d34` records `d34`, and a later `single` isolate is refused;
   - existing single data (a ref row, no marker) under `d34` is refused;
   - under `single`, `single` is recorded;
   - the Absent race: two isolates, with the re-read path exercised through a store wrapper.
3. **Alarm:** host tests for `alarm_after_tick_with_current`.
4. **Config parsing:** `SHARDING`, `NAMESPACE_JURISDICTION` and `NAMESPACE_LOCATION_HINT`.
5. **Wire:** the four `vcs-worker-conformance.sh` runs of B.6.
6. **Unchanged:** every existing server, native, worker and conformance test. Goldens are unchanged except the `sm`
   key-layout entry.

## D. Escalate (stop and report) if

- wrangler rejects the `v2` migration in `wrangler dev` (e.g. a class-name or binding constraint). Quote the error.
- The isolate-once guard (B.2) can't run without adding a DO call to every request.
- Cloudflare docs contradict B.4's premise that `getAlarm` returns null during a running alarm, in a way that makes
  the fix wrong. Being unnecessary is not a reason to stop.

## Gates

- `just ci-server`
- `cargo nextest run --locked -p mkit-server-worker -p mkit-server --all-features`
- `cargo build --locked -p mkit-server-worker --target wasm32-unknown-unknown`
- The wasm32 build of `apps/vcs-worker` (`worker-build`, per `conventions.md:57-59`). Refresh
  `apps/vcs-worker/Cargo.lock` only if it goes stale (`conventions.md:66`).
- The four conformance runs of B.6. Wrangler has been available to earlier executors. If it isn't, that's a D-stop,
  because this WP's evidence is the Worker.
