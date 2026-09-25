# WP-M0-05a: Request pipeline core (PRD §5.4 stages as traits, auth modes, `ShardMap`, pure planners with `NotAfter` deadlines, unary RPC flow)

- **Milestone/track:** M0
- **Base:** `feat/mkit-server`; **branch:** `mkit-server/wp-m0-05a-pipeline-core`
- **Depends on:** M0-02a, M0-04
- **Size:** L (~1000–1300 lines incl. tests)
- **Reconciliation:** the first half of the former WP-M0-05, split by review 01 (00-plan.md R-72). The streaming
  half (`UploadSession`, `DownloadStream`, resumable `UploadPack`) and the `test-faults` seam are WP-M0-05b. Review 01
  also adds the commit deadline: every planned write batch carries `NotAfter` (R-61/R-62, P-21).

## Conventions

Same as WP-M0-01: TMPDIR, trailer, no CI polling, no proto change, a size check, workspace lints.

## Goal

Implement the transport-neutral request pipeline core in `mkit-server`: the §5.4 stages as traits with
wire-preserving default implementations, and the complete flow for the unary operations of `mkit.transport.v1`
(`ListRefs`, `ReadRef`, `UpdateRef`, `AdvanceRefs`, `PackExists`) plus health, over the storage contract. Behavior
must equal today's servers:

- `mkit serve --http`: bearer or no auth, no replay or quota
- `vcs-worker`: auth v2, replay, per-signer quota, atomic advance
- `mkit serve` ssh: transport identity, no replay

## PRD refs

§5.4 stages 0–9 (M0 implements 0–6; 7–9 are no-op hooks), §5.2, §5.3 (incl. the commit deadline), §6.2
"Retries", D10, D13. Overview Q14, Q16.

## Scope

**IN:** `pipeline` module with `Pipeline`, `PipelineConfig`, `AuthMode`, `RequestMeta`, `Authenticated`, hook traits
and default impls, the unary entry points, `ShardMap` + `SinglePartition`, pure planners with the bounded re-plan
loop and deadlines, tracing spans, `Metrics` calls, and an exhaustive unit test suite over the memory stores.

**OUT:** `begin_upload`/`UploadSession`/`download`/`DownloadStream` and the `test-faults` seam (M0-05b);
Connect/ssh bindings (M0-06, M0-12); real backends; multi-repo (M1); grants and epochs (M2; the precondition field
stays `None`); 402/challenges (M3: the `Challenge` variant exists but maps to `permission_denied` "admission
required"); receipts and outcomes delivery (M3/M5).

## Files

Create in `rust/crates/mkit-server/src/pipeline/`: `mod.rs` (Pipeline, config, entry points), `plan.rs` (pure
planners + the bounded re-plan loop + deadlines; `QuotaCharge` lives in `crate::quota`), `auth.rs` (stage 0/1),
`hooks.rs` (traits and defaults), `shard.rs` (`ShardMap`, `SinglePartition`), `tests.rs`. Modify `src/lib.rs`.

Reference behaviors: `apps/vcs-worker/src/worker_impl/auth.rs:48-116` (which procedures need auth v2),
`service.rs:183-569` (per-RPC flow), `refstore.rs:69-115, 360-383` (the transaction shape),
`rust/crates/mkit-cli/src/commands/serve/http.rs:96-148` (bearer gate on every unary **and** streaming RPC),
`rust/crates/mkit-transport-connect/src/service.rs:83-222` (native semantics).

## Design

```rust
pub struct PipelineConfig {
    pub addressing: Addressing,              // M0: Single
    pub auth: AuthMode,
    pub upload_limits: UploadLimits,         // binding supplies: 4 GiB native, 1 GiB ssh, 64 MiB Workers (used by M0-05b)
    pub download_chunk_max: usize,           // DOWNLOAD_CHUNK_MAX (used by M0-05b)
    pub write_quota: Option<QuotaLimits>,    // Some(DEFAULT_WRITE_QUOTA) for auth v2 deployments (vcs-worker parity)
    pub list_page_limit: u32,                // 1000
    pub max_apply_window: Duration,          // MAX_APPLY_WINDOW, default 10 s (00-plan P-21)
}
pub enum AuthMode {
    Open,                                    // unsafe-any HTTP, or trusted caller; no replay
    Bearer { token: Redacted },              // every RPC, unary and streaming (http.rs:96-148 parity); constant-time compare
    AuthV2(AuthV2Config),                    // writes only (UpdateRef, AdvanceRefs, UploadPack); reads unsigned (today)
    TransportIdentity,                       // ssh/enc: principal supplied by the binding; no replay
}
/// Everything stage 0 needs, without depending on any HTTP/Connect type.
pub struct RequestMeta<'a> {
    pub procedure: Procedure,
    pub header: &'a dyn Fn(&str) -> Option<String>,
    pub unary_body: Option<&'a [u8]>,          // exact request bytes (body commitment)
    pub transport_principal: Option<Principal>,
}
pub struct Authenticated { pub principal: Principal, pub auth: Option<VerifiedAuth> }

pub struct Pipeline<B, N, H = Hooks> { /* blobs: B, meta: N, hooks: H, shards: Arc<dyn ShardMap>, cfg, clock: Arc<dyn Clock>, metrics: Arc<dyn Metrics> */ }
impl<B: BlobStore, N: NamespaceStore, H: HookSet> Pipeline<B, N, H> {
    pub fn new(blobs: B, meta: N, hooks: H, cfg: PipelineConfig, clock: Arc<dyn Clock>, metrics: Arc<dyn Metrics>) -> Result<Self, ServerError>;
    // ^ validates: AuthV2 requires meta.capabilities() == { key_classes: All, atomic_multi_key: true }.
    //   Otherwise it's a startup error, so FsLayoutStore (RefsOnly) can't be combined with auth v2 (Q3/Q4 default).

    /// Stage 0a+1: verify credentials, map identity. Pure/sync; writes no state. Called from the binding's interceptor.
    pub fn authenticate(&self, meta: &RequestMeta<'_>) -> Result<Authenticated, ServerError>;

    pub async fn list_refs(&self, a: &Authenticated, prefix: &str) -> Result<Vec<RefEntry>, ServerError>;   // names prefix-stripped
    pub async fn read_ref(&self, a: &Authenticated, name: &str) -> Result<Option<Hash>, ServerError>;
    pub async fn update_ref(&self, a: &Authenticated, upd: RefUpdate) -> Result<UpdateRefResult, ServerError>;
    pub async fn advance_refs(&self, a: &Authenticated, head: RefUpdate, packmap: RefUpdate) -> Result<AdvanceOutcome, ServerError>;
    pub async fn pack_exists(&self, a: &Authenticated, key: PackKey) -> Result<bool, ServerError>;
    pub async fn health(&self) -> HealthStatus;                         // blobs.probe() && meta.probe()
    pub fn capabilities(&self) -> PipelineCapabilities;                 // atomic_advance (for bindings / future GetServerInfo)
}
```

Hook traits (the stage surface is settled now; M0 ships only the defaults):

```rust
pub trait Authorizer: MaybeSend + MaybeSync { fn authorize(&self, op: &Operation) -> impl Future<Output = Result<(), ServerError>> + MaybeSend; }
/// The full PRD §5.4 stage-3 input, present from M0 (reconciliation R-10). M0 fills: op, procedure-derived
/// fields, declared_bytes, pack_id, idempotency_key (the auth v2 nonce). creates_namespace/creates_repo are false
/// and new_to_repo_bytes is None until M1 (WP-1.22 / WP-1.9); grant comes from op.authz (M2). New-to-store bytes
/// are deliberately absent (pricing oracle; PRD §5.4 stage 3).
#[non_exhaustive]
pub struct AdmissionInput<'a> { pub op: &'a Operation, pub declared_bytes: u64, pub pack_id: Option<PackKey>,
    pub creates_namespace: bool, pub creates_repo: bool, pub new_to_repo_bytes: Option<u64>,
    pub idempotency_key: Option<&'a str> }
pub struct Challenge { pub scheme: String, pub value: String }
pub enum AdmissionDecision { Allow { charges: Vec<QuotaCharge>, reservation: Option<String> }, Challenge { challenges: Vec<Challenge>, description: String }, Deny(ServerError) }
pub trait Admission: MaybeSend + MaybeSync { fn admit(&self, input: &AdmissionInput<'_>) -> impl Future<Output = Result<AdmissionDecision, ServerError>> + MaybeSend; }
pub trait PreReceive: MaybeSend + MaybeSync { fn check(&self, op: &Operation, pack: Option<&BlobKey>) -> impl Future<Output = Result<(), ServerError>> + MaybeSend; }
pub trait ReceiptSigner: MaybeSend + MaybeSync { fn sign(&self, op: &Operation) -> impl Future<Output = Option<Vec<u8>>> + MaybeSend; }
pub trait OutcomeSink: MaybeSend + MaybeSync { fn deliver(&self, row: &OutboxRow) -> impl Future<Output = Result<(), ServerError>> + MaybeSend; }
pub trait HookSet: MaybeSend + MaybeSync { type Az: Authorizer; type Ad: Admission; type Pr: PreReceive; type Rs: ReceiptSigner; type Os: OutcomeSink;
    fn authorizer(&self) -> &Self::Az; fn admission(&self) -> &Self::Ad; fn pre_receive(&self) -> &Self::Pr; fn receipts(&self) -> &Self::Rs; fn outcomes(&self) -> &Self::Os; }
pub struct Hooks<Az = OpenAuthorizer, Ad = DefaultAdmission, Pr = NoPreReceive, Rs = NoReceipts, Os = NoOutcomes> { pub authorizer: Az, pub admission: Ad, pub pre_receive: Pr, pub receipts: Rs, pub outcomes: Os }
/// DefaultAdmission: for auth-v2 writes with cfg.write_quota = Some(l) → Allow{ charges: [QuotaCharge{ scope: QuotaScope::for_signer(ns, signer), ops: 1, bytes, limits: l }] }, else Allow{ charges: [] }.
/// (WP-1.5 adds the second, per-namespace charge; WP-3.2 extends AdmissionDecision with response headers.)
/// HookSet grows by associated type when a later WP adds a stage: ContentInspector (call shape WP-3.7,
/// implementation WP-5.5) and LeasePolicy (WP-5.2). Not in M0.
```

Shard routing (reconciliation R-29). Planners never hard-code a partition. They ask a `ShardMap`:

```rust
pub trait ShardMap: MaybeSend + MaybeSync {
    fn ref_shard(&self, repo: &RepoId, ref_name: &str) -> Partition;   // head and its packmap map to the same shard
    fn coordinator(&self, ns: &NamespaceKey) -> Partition;
    fn ref_index(&self, repo: &RepoId) -> Partition;
    fn membership(&self, repo: &RepoId, pack: &BlobKey) -> Partition;
}
/// M0 (and the fs-layout/ssh path forever): every method returns Partition::Namespace(repo.namespace).
pub struct SinglePartition;
```

M1 (WP-1.22) adds `D34Shards` and switches the Connect deployments to it; planners don't change, only the map.

**Planning model** (reconciliation R-18). The store only checks preconditions and applies puts/deletes (M0-02a), so
every write is planned here, in `pipeline/plan.rs`, as **read → decide → batch → apply**, with every value that
influenced the decision guarded by a precondition. Planners are pure functions from `(request, read snapshot,
plan_time)` to `Plan { batch, on_commit: Outcome }` and are unit-tested without a store. One `get_many` fetches the
whole snapshot (refs involved, replay record, quota state, grant epoch, layout version unless the store reports
`implicit_layout_version`), so a typical write costs one read round trip plus one `apply`.

**Commit deadline** (R-61/R-62, 00-plan P-21). `plan_time` is read from the injected `Clock` **without** any test
clock-skew adjustment (M0-05b's directive shifts business time only). Every write batch starts with
`NotAfter(plan_time + cfg.max_apply_window)`. The planner API takes an optional extra bound
(`Plan::deadline_cap: Option<u64>`) so WP-1.25 can pass `lease_expires − margin` without touching planners
(deadline = min of the two). On `PreconditionFailed` for the `NotAfter` index, the loop re-reads and re-plans with a
fresh `plan_time` (a late batch is simply retried); it counts toward `MAX_REPLAN`.

On any `PreconditionFailed` the planner re-reads and re-plans, at most `MAX_REPLAN = 8` times, then returns `aborted`
(retryable). This gives the same linearizable behavior as vcs-worker's single transaction (`refstore.rs:360-383`)
on any backend, including a single-writer KV store.

Stage flow per unary write (auth v2), matching PRD §5.4:

1. **Stage 0 (`authenticate`)**: verify the signature and window (`auth_v2::verify_unary`). Failure →
   `unauthenticated`.
2. **Stage 0 lookup**: `store::read::replay_lookup(scope)` → `replay::classify`:
   - `Return` → the stored result, without touching hooks
   - `FingerprintMismatch` → `invalid_argument` ("nonce reused for a different operation")
   - `RetryLater` → `aborted` (retryable)
   - `Resume` → only valid for `UploadPack` (M0-05b); for a unary op → `aborted`
   - `New` → continue
3. **Stage 1**: build `Operation` (principal `Signer`).
4. **Stage 2**: `authorizer.authorize(&op)`. The default allows.
5. **Stage 3**: `admission.admit`:
   - `Deny(e)` → e
   - `Challenge` → `permission_denied("admission required")` in M0, with nothing written
   - `Allow{charges}` → continue
6. **Stages 4–6 (plan + apply)**: one batch with preconditions `[NotAfter(deadline), Absent(replay),
   Equals|Absent(quota…), Equals|Absent(e) when op.authz.grant is set, Equals|Absent(ref₁), …]` and writes
   `[Put(replay, Committed(result)), Put(replay-expiry index), Put(quota…), Put/Delete(refs…)]`. If the CAS decision
   on the snapshot is a conflict, the batch writes only the replay record with the stored `Conflict` result, still
   guarded by the ref preconditions so the recorded conflict is consistent. Opportunistic pruning: when the snapshot
   shows expired replay/quota index entries (a bounded `scan` of ≤ 16 keys below `now`), the planner appends their
   deletes to the batch; nothing else prunes in M0.
7. **Outcome mapping** after `apply`:
   - `Committed` → the planned outcome (`UpdateRefResult`, `AdvanceOutcome` with `PackmapConflict` when the packmap
     CAS decided the conflict and `HeadConflict` for the head, preserving `refstore.rs:215-255` precedence)
   - `PreconditionFailed` on the replay key → re-run stage 0 classification on `observed` (another request won)
   - `PreconditionFailed` on `NotAfter` or elsewhere → re-plan (bounded), then `aborted`
   - quota exhaustion decided by the planner → `resource_exhausted(reason)` with **no** batch (nothing allocated)
   - an epoch precondition failure → `permission_denied` (M2; unreachable in M0)
   - `StoreError::Full` → retryable `unavailable` ("storage partition full") and a `mkit_server_partition_full`
     metric (00-plan P-24); never `resource_exhausted`

   Other store errors → `ServerError::internal` via `storage_error::describe_and_map` (redacted).

Non-auth-v2 modes skip the replay and quota parts: batches carry only `NotAfter` plus ref preconditions and writes.
That matches `FileTransport` semantics, where `advance_refs` uses the trait default two-write order unless the store
declares `atomic_multi_key`. For `atomic_multi_key = false` stores, the pipeline issues `[packmap, head]` as two
sequential single-key batches (each with its own `NotAfter`), reproducing `protocol.rs:581-600` exactly.

Tracing: `tracing::info_span!("mkit.server.rpc", procedure = %p, repo = %r, principal = kind)` around every entry
point, with `debug` events per stage (`stage = "authenticate" | "replay_lookup" | "authorize" | "admission" |
"apply"`). Never record header values; record at most `is_sensitive_header` names. Metrics: `METRIC_REQUESTS`
labeled `procedure` and `code` ("ok" or `Code`), `METRIC_LATENCY` (through `Clock` deltas).

## Tests to write first (`pipeline/tests.rs`; memory stores + `ManualClock`; sign with `ed25519-dalek` like `write_auth.rs:289-343`)

- `authv2_update_ref_happy_path_then_replay_returns_same_after_ref_moved`
- `authv2_nonce_reuse_different_op_is_invalid_argument`
- `authv2_missing_headers_is_unauthenticated`; `authv2_wrong_audience_unauthenticated`; `authv2_expired_unauthenticated`
- `authv2_reads_need_no_signature` (ListRefs/ReadRef/PackExists with no headers succeed)
- `quota_exhaustion_is_resource_exhausted_and_allocates_no_replay_record` (tiny `QuotaLimits`)
- `retry_after_quota_exhaustion_still_returns_stored_result` (PRD/spec: saved replies are checked before admission)
- `advance_refs_atomic_store_conflict_leaves_both_untouched` (packmap conflict and head conflict variants)
- `advance_refs_nonatomic_store_matches_trait_default_order` (reduced-capability memory store: packmap written, head
  conflict → `HeadConflict`, packmap stays written, as in `protocol.rs:581-600`)
- `bearer_mode_rejects_missing_or_wrong_token_on_reads_and_writes` (constant-time compare via `subtle` or a local
  ct-eq; `subtle` is already in the graph)
- `open_mode_allows_everything_without_replay`
- `transport_identity_mode_uses_binding_principal`
- `admission_challenge_maps_to_permission_denied_and_writes_nothing` (a test Admission that returns `Challenge`)
- `pipeline_new_rejects_authv2_over_refs_only_store`
- `refs_only_store_never_sees_layout_version_key`
- `plan_*` pure planner tests: CAS any/missing/match on a snapshot; conflict writes only the replay record; quota
  exhaustion yields no batch; every read value appears as a precondition and **every write batch starts with a
  `NotAfter` equal to `plan_time + max_apply_window` (or the cap when smaller)** (property test over random snapshots)
- `late_batch_fails_not_after_and_replans` (a `MemoryKv` wrapper that advances the store clock past the deadline
  between plan and apply once → the second attempt commits; N times → `aborted`, nothing written)
- `not_after_ignores_test_clock_skew` (planning under a skewed business clock still uses the real clock for the deadline)
- `store_full_maps_to_unavailable` (`MemoryKv::with_capacity_limit`)
- `replan_after_concurrent_writer_then_succeeds` and `replan_exhaustion_is_aborted_retryable` (a `MemoryKv` wrapper
  that mutates the guarded key between read and apply N times)
- `dropped_request_future_leaves_no_partial_state` (drop `update_ref` futures at every await point; the partition
  equals the pre- or post-state)
- `list_refs_strips_prefix_and_paginates` (page limit 2, 5 refs)
- `store_error_is_redacted` (a failing store's detail never appears in the `ServerError` Display)
- `admission_input_carries_nonce_and_declared_bytes` (spy Admission records the input)
- `replay_and_quota_rows_shrink_after_load` (R-31: 500 signed writes, advance the clock past the envelope window and
  two quota windows, run 20 more writes; the `p`/`px`/`q`/`qx` key counts return to ≤ the post-warmup baseline)

## Gate

```bash
export TMPDIR="$HOME/.cache/mkit-test-tmp"; mkdir -p "$TMPDIR"
cd rust && cargo fmt --check && cargo clippy --all-targets --all-features --workspace -- -D warnings
cargo nextest run -p mkit-server --all-features
cargo test --doc -p mkit-server
cargo check -p mkit-server --target wasm32-unknown-unknown --features memory
cd .. && just ci-scripts
```

## Acceptance criteria

- [ ] All listed tests pass. Stage order is visible in code as one function per stage.
- [ ] No transport types (`http`, `connectrpc`, `mkit_rpc`) are used in `pipeline/`.
- [ ] Auth v2 + quota + replay behavior for the unary RPCs equals vcs-worker's for every unary scenario in
      `apps/vcs-worker/tests/auth_v2.mjs` (replay, concurrent duplicates, nonce conflict, atomic advance).
- [ ] Bearer and Open modes equal `mkit serve --http` (no replay, no quota, non-atomic advance on FS-like stores).
- [ ] Every planned write batch carries a `NotAfter` deadline computed from the real clock; a late batch never
      commits.
- [ ] Nothing ever stores a challenge. There is no code path that constructs a `StoredResult` from
      `AdmissionDecision::Challenge`.
- [ ] Spans and metrics are emitted, and no header values are logged.
- [ ] wasm32 check passes.

## Risks / gotchas

- Bearer compare must be constant-time (`http.rs:111-117` rationale).
- Clock skew between the planner's clock and the backend's is real on Workers (Worker isolate vs DO) and natively
  zero. `MAX_APPLY_WINDOW` (10 s) must be much larger than any skew; document the assumption next to the constant.
- Unary writes finalize in the same apply, so an in-flight unary record can't normally be observed. It *can* be if a
  store crashes mid-transaction; then `aborted` is correct (overview Q5).
