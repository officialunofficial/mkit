# WP-M0-05b: Request pipeline streaming and faults (`UploadSession`, `DownloadStream`, resumable `UploadPack`, `test-faults` seam)

- **Milestone/track:** M0
- **Base:** `feat/mkit-server`; **branch:** `mkit-server/wp-m0-05b-pipeline-streaming`
- **Depends on:** M0-05a
- **Size:** M (~700–950 lines incl. tests)
- **Reconciliation:** the second half of the former WP-M0-05, split by review 01 (00-plan.md R-72). R-11 (test-fault
  seam) carries over. Every batch this WP plans uses M0-05a's planner API, so it inherits the `NotAfter` deadline.

## Conventions

Same as WP-M0-01: TMPDIR, trailer, no CI polling, no proto change, a size check, workspace lints.

## Goal

Complete the pipeline with the two streaming operations and the test seam later milestones build on:

- `begin_upload` + `UploadSession` (fresh, resume, replay) for `UploadPack`, with the in-flight replay model and
  memory bounded by one chunk
- `download` + `DownloadStream` for `DownloadPack`
- the `test-faults` seam: `FaultHooks` at five points and per-request `TestDirectives`

Behavior must equal `vcs-worker`'s resumable `UploadPack` (`auth_v2.mjs --fault after-reserve|after-put`) and
today's chunked downloads.

## PRD refs

§5.4 stages 0–6 for `UploadPack`, §5.2, §6.2 "Retries", D10. Overview Q5 (resume), Q17 (800 KiB chunks).

## Scope

**IN:** `pipeline/upload.rs` (UploadSession), `pipeline/download.rs` (DownloadStream), the `UploadPack` planners in
`pipeline/plan.rs`, `pipeline/faults.rs` (feature `test-faults`), the fault-point calls in the M0-05a unary flow,
tests. Modify `Cargo.toml` (feature `test-faults = []`).

**OUT:** Connect/ssh bindings (M0-06, M0-12); store-level faults (M0-16); multipart parts (M1).

## Design

```rust
impl<B: BlobStore, N: NamespaceStore, H: HookSet> Pipeline<B, N, H> {
    pub async fn begin_upload(&self, a: &Authenticated, pack_id: &[u8], total_bytes: Option<u64>) -> Result<UploadSession<'_, B, N, H>, ServerError>;
    pub async fn download(&self, a: &Authenticated, key: PackKey) -> Result<DownloadStream, ServerError>;
}
pub struct UploadSession<'p, B, N, H> { /* validator, sink, mode: Fresh|Resume|Replay, auth */ }
impl<'p, B: BlobStore, N: NamespaceStore, H: HookSet> UploadSession<'p, B, N, H> {
    pub async fn push(&mut self, chunk_pack_id: &[u8], offset: Option<u64>, data: bytes::Bytes, last: bool) -> Result<bool /*complete*/, ServerError>;
    pub async fn finish(self) -> Result<(), ServerError>;     // sink.commit() (BLAKE3) → pre_receive → finalize apply
    pub async fn abort(self);
}
pub struct DownloadStream { pub total_bytes: u64, pub chunks: BoxStream<'static, Result<DownloadChunk, ServerError>> }
pub struct DownloadChunk { pub offset: u64, pub data: bytes::Bytes, pub last: bool }
```

`UploadPack` flow (auth v2):
- the pack commitment check (`auth_v2::check_pack_commitment`) runs on `begin_upload` before any reservation
- batch `NotAfter(deadline)` + `Put(replay, InFlight{resumable:true})` + quota, before reading any chunk
  (vcs-worker `service.rs:432-440`)
- stream into `blobs.begin(key, total)`, then `sink.commit()`
- `pre_receive.check` (no-op)
- batch `NotAfter(deadline')` + `Equals(replay, InFlight) → Put(replay, Committed(UploadPack))`, with `deadline'`
  computed at this second plan (the upload itself may take long; only plan-to-apply is bounded)

`UploadSession` modes:
- `Fresh`: reserved now
- `Resume`: the in-flight resumable record with the same fingerprint. Re-stream and re-commit; don't charge quota
  again. This is the `auth_v2.mjs --fault after-reserve/after-put` parity.
- `Replay`: already committed. Re-stream and validate, `commit` returns `AlreadyPresent`, no apply. Returns OK,
  like today's vcs-worker, where the finalize call returns the stored reply.

Metrics: `METRIC_UPLOAD_BYTES`. Memory: the session holds at most one chunk; the sink bounds itself (M0-02a).

Test-fault seam (feature `test-faults`, never enabled by a release build; reconciliation R-11):

```rust
#[cfg(feature = "test-faults")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultPoint { AfterAuthenticate, AfterAuthorize, AfterReserve, AfterBlobCommit, BeforeFinalApply }
#[cfg(feature = "test-faults")]
pub trait FaultHooks: MaybeSend + MaybeSync {
    /// Called at each point. Ok → continue; Err → the pipeline returns that error as if the stage failed.
    /// An impl may also *wait* here: WP-1.25/2.8 build the authorize→apply barrier (revoke race, and the
    /// paused-write/expired-lease case of R-63, which pauses AFTER planning) on this seam.
    fn at(&self, point: FaultPoint, op: &Operation, directives: &TestDirectives) -> impl Future<Output = Result<(), ServerError>> + MaybeSend;
}
/// Per-request test directives parsed from headers only under `test-faults`:
/// `x-mkit-test-fault: <token>` (vcs-worker parity: `after-reserve`, `after-put`) and
/// `x-mkit-test-clock-skew-ms: <i64>` (added to the business clock for this request; lets black-box suites on
/// `wrangler dev` exercise expiry without sleeping — WP-1.14, WP-2.8). The skew NEVER feeds NotAfter deadlines,
/// which use the real clock (M0-05a); the backend evaluates them on its own clock anyway.
#[derive(Debug, Clone, Default)] pub struct TestDirectives { pub fault: Option<String>, pub clock_skew_ms: i64 }
```

`BeforeFinalApply` fires after the batch is planned (deadline fixed) and before `apply`, in the unary flow and in
`UploadSession::finish`, so a hook that waits there produces a genuinely late batch. `Pipeline::with_faults(impl
FaultHooks)` is the only way to install hooks. Without the feature the parsing code, the `FaultPoint` calls and the
header names don't exist in the binary (a doc note, or an optional test that greps the rlib for `x-mkit-test-`).

## Tests to write first (`pipeline/tests_stream.rs`; memory stores + `ManualClock`)

- `upload_resume_after_fault_does_not_recharge_quota` (`MemoryBlobStore::with_fault(Commit)`, then retry)
- `upload_replay_of_committed_op_succeeds_without_apply`
- `upload_commitment_mismatch_is_unauthenticated_before_reservation`
- `upload_hash_mismatch_never_visible` and `upload_framing_errors_map_codes` (spot-check 3 `UploadError` variants)
- `upload_oversize_declared_is_resource_exhausted`
- `upload_memory_bounded_by_one_chunk` (a counting sink)
- `upload_final_apply_deadline_is_computed_after_streaming` (a slow stream longer than `MAX_APPLY_WINDOW` still
  commits; a pause at `BeforeFinalApply` longer than the window re-plans)
- `download_missing_is_not_found_before_stream`; `download_chunks_contiguous_last` (0, 1 byte, exact multiple,
  remainder)
- `authv2_signed_stream_verified` (UploadPack with `pack:` commitment)
- `fault_after_reserve_then_retry_resumes` (`test-faults`; parity with `auth_v2.mjs --fault after-reserve`)
- `fault_hook_can_block_between_authorize_and_apply` and `fault_hook_before_final_apply_makes_a_late_batch` (a
  channel-gated FaultHooks; WP-1.25/2.8 build the revoke-race tests on them)
- `clock_skew_directive_shifts_now_for_one_request_only` and `clock_skew_directive_never_moves_deadlines`

## Gate

```bash
export TMPDIR="$HOME/.cache/mkit-test-tmp"; mkdir -p "$TMPDIR"
cd rust && cargo fmt --check && cargo clippy --all-targets --all-features --workspace -- -D warnings
cargo nextest run -p mkit-server --all-features
cargo test --doc -p mkit-server
cargo check -p mkit-server --target wasm32-unknown-unknown --features memory
cargo check -p mkit-server --target wasm32-unknown-unknown --features memory,test-faults
cd .. && just ci-scripts
```

## Acceptance criteria

- [ ] All listed tests pass.
- [ ] Auth v2 `UploadPack` behavior equals vcs-worker's (`auth_v2.mjs`: signed streaming, fault resume).
- [ ] No whole-pack buffer anywhere in `upload.rs`/`download.rs`; `DownloadStream.chunks` is `'static` and owns its
      data.
- [ ] wasm32 check passes, with and without `test-faults`.
- [ ] `test-faults` is off by default and not enabled by any binary crate's default features.

## Risks / gotchas

- `UploadSession` borrows the pipeline. Connect handlers own `Arc<Pipeline>` and must hold the Arc across the
  stream. Provide `UploadSession` over `&'p Pipeline` and let bindings use an owned `Arc` clone.
- `DownloadStream.chunks` must be `'static` (and `Send` on native) for Connect's `Response::stream_ok`. Build it from
  owned `BlobBody` data, never borrowing the pipeline.
- Resume vs `RetryLater`: only `UploadPack` reserves with `resumable: true` in M0.
