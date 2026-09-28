## Purpose

WP-1.23a delivers relay rows natively. This WP does three things:
1. **Relay delivery on Workers:** registers the relay on the `RefShard` class and fixes the liveness gap WP-1.23a's
   review found (R-103);
2. **The membership read path:** `is_member`, and the `X-Mkit-Ref` read-your-writes hint (STC §7.9);
3. **Membership-scoped Multi pack reads:** wires `PackExists`/`DownloadPack` in Multi mode to membership, replacing
   the blanket `unimplemented` guard for reads.

The coordinator watermark (P-23) is **not** here. See B.6.

## A. Fixed (do not change)

1. **STC §7.9 (read it all):**
   - membership is eventually consistent, and a lag MUST only cause the listed outcomes;
   - the `X-Mkit-Ref` rules: it is resolved against that ref's strongly consistent shard in the same repository; an
     unknown or malformed value is a **no-op**, never an error; it is never part of the auth v2 canonical string; the
     answer is subject to the caller's view (a no-op in M1).
2. **STC §7.4 isolation:** no existence oracle. A pack that isn't a member of *this* repository is `exists = false`
   or `not_found`, whatever other repositories hold.
3. **WP-1.23a (merged):**
   - `relay::{RelayHandler, RelayBudget, RelayHook, NoHook, relay_watermark, RELAY_LAG_BOUND_MS}` and `deliver.rs`;
   - `kinds::RELAY = 3`;
   - R-101, R-102, R-103 in `00-plan.md`.
   - **R-103 must be fixed here, before Worker delivery.**
4. **WP-1.8 (merged):**
   - `ShardClass`, `adapter::ns_object(state, env, class)`;
   - `LeaseSweep` registered only on `NsCoordinator`;
   - the `TODO(WP-1.23b)` in the adapter;
   - `StubTransport` with deployment placement (R-95);
   - `DoNamespaceStore`.
5. **The membership key** is `m 00 <repo> 00 <pack:32>`: written in the ref shard (WP-1.7 `plan_membership`) and
   relayed unchanged to `shards.membership(repo, pack)`. Nothing writes `m` rows until WP-1.10, so tests plant them.

## B. Decided by the orchestrator (do not change)

### B.1 Worker relay registration

- In `adapter::ns_object`, for `ShardClass::RefShard` only, register
  `RelayHandler { target: DoNamespaceStore<StubTransport::new(env.clone(), cfg.placement)>, hook: NoHook, budget }`.
- If the Worker config can't be read inside the DO, log with `crate::log_failure` and register a handler whose
  `fire` returns `Retry`, **never** silently skipping delivery.
- **The budget for Workers:**
  - `max_rows = 128`, `max_targets = 8`;
  - a RELAY `max_per_tick` of 4;
  - document the subrequest arithmetic in a comment: ≤ 4 fires × 8 targets × 2 calls = 64 per alarm, under the
    Workers **Paid** default of 10,000.
  - On Free (50 subrequests), set `max_per_tick = 2` and `max_targets = 8`: 32 calls. Choose these by the existing
    `WORKERS_PLAN` var.

### B.2 The R-103 liveness fix (in `relay/deliver.rs`)

- Keep a per-fire **blocked** set of targets: those whose delivery failed this fire, plus those cut by `max_targets`.
- **Keep scanning past the contiguous window.** Rows of blocked targets are left in place; rows of unblocked targets
  are delivered in seq order.
- This is order-safe: only blocked targets' rows stay behind, and each target's own rows are still applied in
  ascending seq.
- **Cap per fire:** at most `4 × max_rows` rows inspected, and at most `MAX_FIRE_BYTES` (existing) decoded bytes.
- **An undecodable row:** deliver the decodable prefix before it, then stop with `Retry` (the row is still never
  skipped).
- Rate-limit the lag warning to once per fire per source.
- **Tests:**
  - a failing target with a backlog ≥ `max_rows` doesn't stall a healthy target;
  - `max_targets` failing targets don't starve the next one;
  - per-target seq order is preserved across fires;
  - the decodable prefix is delivered before a corrupt row.

### B.3 `is_member` (in `store/read.rs`)

```rust
pub async fn is_member<S: NamespaceStore>(store: &S, shards: &dyn ShardMap, repo: &RepoId, pack: &Hash,
                                          hint: Option<&str>) -> Result<bool, StoreError>
```

1. `get(shards.membership(repo, pack), m 00 <repo> 00 <pack>)`. Present → `true`.
2. Else, if `hint` is `Some(name)` and passes `refs::validate_ref_name` **and** `refs::is_served_ref_name`:
   `get(shards.ref_shard(repo, name), m key)`. Present → `true`.
3. Else → `false`.

A hint that fails validation is ignored: never an error, and no store call.

### B.4 `X-Mkit-Ref` on the pipeline

- Parse `x-mkit-ref` in `authenticate_inner` onto `Authenticated` as `ref_hint: Option<String>`.
  - Store it only if it's at most `MAX_REF_NAME_BYTES` and valid UTF-8; otherwise store `None` (a no-op).
  - It is **not** in `auth_v2::HEADER_NAMES`.
- Add it to `CORS_ALLOW_HEADERS` (`auth_v2.rs:~34`).

### B.5 Multi `PackExists`/`DownloadPack`

- In `Addressing::Multi`, **replace `require_pack_membership()` on these two reads** with `is_member(…, a.ref_hint)`.
  - Not a member → `PackExists` answers `exists = false`; `DownloadPack` answers `not_found` "pack not found".
  - A member → proceed to the blob store, as in Single mode.
- **Single mode is unchanged:** a stored pack is a member.
- `UploadPack` keeps its guard (WP-1.9b wires ticketed uploads).
- Remove the read-side `TODO(WP-1.10)`.
- Update the wire case `repository.packs_need_membership`: `PackExists`/`DownloadPack` now give `exists = false` /
  `not_found` for a non-member, and `UploadPack` is still `unimplemented`.
- **New wire cases, under `Feature::MultiRepo`:**
  - **isolation:** a pack planted as a member of repo A is invisible from repo B, including through
    `X-Mkit-Ref: refs/heads/main`;
  - **read-your-writes:** membership planted only in the ref shard (not relayed) is visible with the hint and
    invisible without it;
  - **no oracle:** a malformed hint is a no-op, with no error.

  Use test-faults planting helpers, following WP-1.24's directive pattern (a test-only
  `x-mkit-test-plant-member: <ref>` on `UpdateRef`), or plant in-process. Your choice (C).

### B.6 The coordinator watermark is split out

Add row **R-106** to `00-plan.md`:

> WP-1.23b ships the Worker relay, R-103 liveness and membership reads. The coordinator watermark (P-23) becomes
> WP-1.23c, which must land before WP-5.3a (GC) and WP-5.6 (takedown), its only consumers. It covers: the renewal
> payload carrying each shard's relay watermark; `ls` retention while a shard's outbox is undelivered (this changes
> `LeaseSweep`); and `namespace_relay_watermark()` as the minimum, with the coordinator keeping the running maximum
> per shard (the WP-1.23a lower bound can move backwards).

## C. Your decisions

- The planting mechanism for the wire cases (B.5).
- How the Worker config reaches `ns_object`, e.g. capturing `WorkerConfig` in the adapter.
- Test organisation.

## Tests (required)

1. B.2's liveness tests (core, memory and SQLite).
2. `is_member` unit tests: index hit, ref-shard hit via the hint, a miss, an invalid hint with no store call, and
   cross-repository isolation.
3. The Worker shape (host `Loopback` harness): a `RefShard`-registered relay delivers to a `RepoIndexShard` target,
   with the call count asserted.
4. **Wire:** the B.5 cases on the in-process Multi baseline. Also the vcs-worker `--sharding d34 --test-faults` phase,
   if the relay can be exercised there (planted rows).
5. **Unchanged:** Single-mode pack reads, and every existing test.

## D. Escalate (stop and report) if

- Registering the relay needs `mkit-server-worker` non-test changes beyond the adapter and a config accessor.
- B.2's order-safety argument fails for any schedule you find. Report the schedule.
- The existing `DownloadPack` streaming path can't take a membership check before the first byte without buffering.

## Gates

- `just ci-server`
- `cargo nextest run --locked -p mkit-server -p mkit-server-native -p mkit-server-conformance -p mkit-server-worker --all-features`
- the wasm32 check and the worker build
- `scripts/vcs-worker-conformance.sh` (default, and `--sharding d34 --test-faults`)
