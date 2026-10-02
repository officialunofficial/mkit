//! Scheduled verification: the kind-7 slice machine (WP-4.8, R-171).
//!
//! A ticketed pack verifies in checkpointed slices, one per alarm fire, with
//! repository-isolated checks; Scheduled error priority and duplicate budget
//! charging follow R-171's stricter deployment rules. Each fire runs one phase
//! step of a [`VerifyJobV1`] and ends in `Fired::Reschedule`, whose batch
//! carries the job put guarded by the job row (and `vs`) as it was read, so a
//! duplicate fire loses. Rows a slice writes ahead of that batch (frames,
//! owed children, charged bases) are pure functions of the pack, so a crash
//! only replays them. Phases: `Decode`, `ClosureResolve`, `EmitIndex`,
//! `AwaitDelivery`, `Extract`, `Verify`, `Recheck`, `Watch`.
//!
//! Index rows are emitted only after the decode reaches `Done`
//! (SPEC-PACKFILE §11: entries are provisional until then), and `Verified` is
//! written only after the relay delivered them (R-130). A failure caused by
//! repository membership or the platform is a terminal [`Outcome`], never a
//! persisted `Rejected` (R-148).

use super::{
    IndexedConfig,
    budget::{Budgeted, PackWindows, SliceBudget, Window, WindowError, is_exhausted},
    checkpoint::{
        self, BaseRow, FrameRow, Kind, Outcome, Phase, VerifyJobV1, decode_base, decode_frame,
        encode_base, encode_frame, encode_job, parse_reference,
    },
    classify::{self, UploadType},
    resolve::{self, MemberCache, ResolveFailure},
    state::{self, VerificationV1},
};
use crate::pipeline::{LeaseParams, ShardMap, renew_for_relay};
use crate::relay::{commit_relay_rows, relay_delivered_through};
use crate::repo::RepoId;
use crate::rt::{BoxFuture, Clock};
use crate::store::{
    Batch, BatchOutcome, BlobStore, Cursor, Key, NamespaceStore, Partition, Precondition,
    StoreError, Value, Write,
    codec::TicketV1,
    codec::{self, decode_ticket},
    index::{self, IndexEntry, IndexValue, LocatedObject},
    keys,
};
use crate::telemetry::Metrics;
use crate::timers::{
    DueTimer, Fired, TimerCtx,
    registry::{TimerHandler, TimerKind, kinds},
};
use mkit_core::hash::{Hash, hash};
use mkit_core::object::Object;
use mkit_core::ops::graph::{ClosureMode, children};
use mkit_core::pack::window::{Step, WindowCursor, WindowReader};
use mkit_core::pack::{
    DecodeLimits, DeltaBaseSource, PackEntry, PackError, decode_entry_with, decode_frame_with,
};
use mkit_core::sign::verify_object_signature;
use mkit_core::transfer::decode_packlist;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;

mod extraction;

/// Fixed work units of one slice. A Worker fixes them for its plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SliceLimits {
    /// One window of the resumable decoder.
    pub window_bytes: u64,
    /// Bytes one slice may hold: window, carried entry, decoded entry, the
    /// in-pack cache and retained external bases. A single object over it
    /// gets `pack exceeds indexed decode budget` (a documented deployment
    /// limit, SPEC-SERVER §9.8).
    pub resident_bytes: u64,
    /// Calls that leave the object: R2 ranges and index or membership shards.
    pub max_subrequests: u32,
    /// Entries one slice may decode before its next checkpoint.
    pub max_entries: u32,
}

impl Default for SliceLimits {
    fn default() -> Self {
        Self {
            window_bytes: super::geometry::FRAME_PAYLOAD_BYTES,
            resident_bytes: super::geometry::RESIDENT_BYTES,
            max_subrequests: 256,
            max_entries: checkpoint::DEFAULT_ENTRY_CAP,
        }
    }
}

/// R-203: old/new ring growth is at most three 8 MiB windows; four MiB
/// covers bounded blocks and decoder tables. Decoder and object parsing do
/// not overlap. Reserve this scratch while retaining one reader window.
#[cfg(feature = "pack-ruzstd")]
const DECODER_SCRATCH_BYTES: u64 = 3 * (8 << 20) + (4 << 20);
/// A 16 MiB window, 28 MiB decoder, two delta streams and 1 MiB metadata
/// leave an LRU under 1 MiB; always retain its required newest base.
#[cfg(feature = "pack-ruzstd")]
const CACHE_BYTES: u64 = super::geometry::RESIDENT_BYTES
    - super::geometry::FRAME_PAYLOAD_BYTES
    - DECODER_SCRATCH_BYTES
    - 2 * super::geometry::DELTA_STREAM_BYTES
    - (1 << 20);
#[cfg(not(feature = "pack-ruzstd"))]
const CACHE_BYTES: u64 = super::geometry::ENTRY_CACHE_BYTES;
/// Slice failures on one cursor before its entry cap halves.
const ATTEMPTS_PER_CAP: u32 = 3;
/// Subrequests kept back when a slice decides to fetch its next entry.
const ENTRY_RESERVE: u32 = 64;
/// Each closure lookup has its own durable id boundary.
const CLOSURE_CHUNK: u32 = 1;
/// Frame rows per index emission slice.
const EMIT_PAGE: u32 = 64;
/// Rows per cleanup batch.
const CLEANUP_PAGE: u32 = 90;
/// Cleanup pages per fire.
const CLEANUP_ROUNDS: usize = 16;
/// Buffered idempotent rows per batch.
const WRITE_BATCH: usize = 90;
/// Retry wait while a base or child is inside the membership lag window.
const LAG_BACKOFF_MS: u64 = 15_000;
/// The longest a finished job waits before checking whether its ticket
/// closed: an hour, and never past the ticket's own expiry.
const WATCH_POLL_MS: u64 = 3_600_000;
/// Distinct member packs one job may depend on.
const MAX_SATISFYING: usize = index::MAX_LOOKUP_IDS;

/// The existing extraction extension of the `Extract` phase. Enabled Workers
/// use the internal upload callbacks; the disconnected default fails closed.
pub trait SliceExtension: crate::MaybeSend + crate::MaybeSync {
    /// Whether `object` must be extracted into the object store before its
    /// pack is `Verified`.
    fn needs_extraction(&self, object: &Object, cfg: &IndexedConfig) -> bool;

    /// Whether this existing extension supplies the internal upload callbacks.
    fn extraction_enabled(&self) -> bool {
        false
    }

    /// Start a root-pinned private object session after all source CVs verify.
    fn begin_object<'a>(
        &'a self,
        _key: crate::BlobKey,
        _plan: &'a mkit_core::upload_parts::PartPlan,
        _root: Hash,
        _cvs: &'a [Hash],
        _operation: Hash,
        _budget: &'a SliceBudget,
    ) -> BoxFuture<'a, Result<Option<Vec<u8>>, StoreError>> {
        Box::pin(async { Ok(None) })
    }

    /// Verify and commit one bounded private part, returning its opaque receipt.
    fn put_object_part<'a>(
        &'a self,
        _key: crate::BlobKey,
        _session: &'a [u8],
        _plan: &'a mkit_core::upload_parts::PartPlan,
        _index: u32,
        _cv: Hash,
        _bytes: Vec<u8>,
        _budget: &'a SliceBudget,
    ) -> BoxFuture<'a, Result<Option<Vec<u8>>, StoreError>> {
        Box::pin(async { Ok(None) })
    }

    /// Publish only the exact root-pinned parts selected by these receipts.
    fn complete_object<'a>(
        &'a self,
        _key: crate::BlobKey,
        _session: &'a [u8],
        _plan: &'a mkit_core::upload_parts::PartPlan,
        _parts: Vec<crate::PartRef>,
        _root: Hash,
        _budget: &'a SliceBudget,
    ) -> BoxFuture<'a, Result<Option<crate::CommitOutcome>, StoreError>> {
        Box::pin(async { Ok(None) })
    }

    /// Abort the private session; the default extension has no session.
    fn abort_object<'a>(
        &'a self,
        _key: crate::BlobKey,
        _session: &'a [u8],
        _plan: &'a mkit_core::upload_parts::PartPlan,
        _budget: &'a SliceBudget,
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async { Ok(()) })
    }
}

/// Every `ChunkedBlob` and every Blob of at least `extract_min_bytes` needs
/// extraction, and there is none yet: the job ends `ExtractionUnavailable`.
#[derive(Debug, Clone, Copy, Default)]
pub struct FailClosedExtraction;

impl SliceExtension for FailClosedExtraction {
    fn needs_extraction(&self, object: &Object, cfg: &IndexedConfig) -> bool {
        match object {
            Object::ChunkedBlob(_) => true,
            Object::Blob(blob) => blob.data.len() as u64 >= cfg.extract_min_bytes,
            _ => false,
        }
    }
}

/// The kind-7 handler. `remote` reaches other partitions (the Worker's
/// namespace client, budgeted per fire); the fire's own store serves the ref
/// shard's rows, timers and outbox.
pub struct VerifyTimer<R, B, W, X = FailClosedExtraction> {
    /// Cross-partition store: index shards, membership shards, coordinator.
    pub remote: R,
    /// Member packs, read for external bases.
    pub blobs: B,
    /// The ticketed pack's own windows.
    pub windows: W,
    /// Shard placement.
    pub shards: Arc<dyn ShardMap>,
    /// Indexed limits.
    pub cfg: IndexedConfig,
    /// Work units per slice.
    pub limits: SliceLimits,
    /// Epoch lease timing for the relay seam.
    pub lease: LeaseParams,
    /// Backend clock.
    pub clock: Arc<dyn Clock>,
    /// Metrics sink.
    pub metrics: Arc<dyn Metrics>,
    /// The extraction seam.
    pub extension: X,
}

impl<R, B, W, X> core::fmt::Debug for VerifyTimer<R, B, W, X> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VerifyTimer").finish_non_exhaustive()
    }
}

impl<S, R, B, W, X> TimerHandler<S> for VerifyTimer<R, B, W, X>
where
    S: NamespaceStore,
    R: NamespaceStore,
    B: BlobStore,
    W: PackWindows,
    X: SliceExtension,
{
    fn kind(&self) -> TimerKind {
        kinds::VERIFY
    }

    /// One slice per alarm: a slice spends most of an alarm's budget.
    fn max_per_tick(&self) -> Option<u32> {
        Some(1)
    }

    fn fire<'a>(
        &'a self,
        ctx: &'a TimerCtx<'a, S>,
        timer: &'a DueTimer,
    ) -> BoxFuture<'a, Result<Fired, StoreError>> {
        Box::pin(async move {
            let Some((name, pack)) = parse_reference(&timer.reference) else {
                tracing::warn!("malformed verification timer reference dropped");
                return Ok(Fired::Done(Batch::new()));
            };
            let namespace = match ctx.partition {
                Partition::Namespace(ns) | Partition::Ref { ns, .. } => ns.clone(),
                _ => {
                    return Err(StoreError::Corrupt(
                        "verification timer in wrong partition".into(),
                    ));
                }
            };
            let budget = SliceBudget::new(self.limits.max_subrequests);
            let remote = Budgeted::new(&self.remote, &budget);
            let blobs = Budgeted::new(&self.blobs, &budget);
            let run = Run {
                h: self,
                local: ctx.store,
                source: ctx.partition,
                repo: RepoId { namespace, name },
                pack,
                budget: &budget,
                remote: &remote,
                blobs: &blobs,
                now: ctx.now_ms,
            };
            run.slice(timer).await
        })
    }
}

/// How a phase step ends, other than by success.
enum Stop {
    /// A storage failure or spent budget: the fire fails and retries.
    Store(StoreError),
    /// Content-intrinsic failure, persisted as `Rejected` (§9.8).
    Reject(&'static str),
    /// A terminal result that is not persisted (R-148).
    Outcome(Outcome),
    /// Membership may still catch up: run again later.
    Wait(u64),
    /// Persist bounded reconstruction progress before the next alarm.
    Yield(u64),
    /// The source changed under the job: start over.
    Restart,
}

impl From<StoreError> for Stop {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

fn unavailable(reason: &'static str) -> Stop {
    Stop::Store(StoreError::Unavailable(reason.into()))
}

/// Recently decoded in-pack objects, kept as delta bases. The newest entry
/// stays even when it alone passes the cap.
#[derive(Default)]
struct Lru {
    map: BTreeMap<Hash, Arc<Vec<u8>>>,
    order: VecDeque<Hash>,
    bytes: u64,
}

impl Lru {
    fn insert(&mut self, id: Hash, bytes: Arc<Vec<u8>>) {
        let len = bytes.len() as u64;
        if self.map.insert(id, bytes).is_none() {
            self.order.push_back(id);
            self.bytes += len;
        }
        while self.bytes > CACHE_BYTES && self.order.len() > 1 {
            if let Some(old) = self.order.pop_front()
                && let Some(gone) = self.map.remove(&old)
            {
                self.bytes -= gone.len() as u64;
            }
        }
    }
}

struct CacheBases<'a>(&'a Lru);

impl DeltaBaseSource for CacheBases<'_> {
    const VERIFIED: bool = false;
    fn base(&mut self, id: &Hash) -> Result<Option<Vec<u8>>, PackError> {
        Ok(self.0.map.get(id).map(|bytes| bytes.as_ref().clone()))
    }
}

/// Per-slice memory: nothing in it is authoritative, rows are.
#[derive(Default)]
struct SliceState {
    guards: Vec<Precondition>,
    job_guard: Option<Value>,
    cache: Lru,
    memo: MemberCache,
    visiting: BTreeSet<(Hash, Hash, u64)>,
    frames: BTreeMap<Hash, FrameRow>,
    bases: BTreeMap<Hash, u32>,
    charged: BTreeSet<(Hash, Hash, u64)>,
    writes: Vec<Write>,
    settled: Vec<Write>,
    entry_idx: u64,
}

struct Run<'a, S, R, B, W, X> {
    h: &'a VerifyTimer<R, B, W, X>,
    local: &'a S,
    source: &'a Partition,
    repo: RepoId,
    pack: Hash,
    budget: &'a SliceBudget,
    remote: &'a Budgeted<'a, R>,
    blobs: &'a Budgeted<'a, B>,
    now: u64,
}

fn now_ms(clock: &dyn Clock) -> u64 {
    u64::try_from(clock.now_ms()).unwrap_or(0)
}

impl<S, R, B, W, X> Run<'_, S, R, B, W, X>
where
    S: NamespaceStore,
    R: NamespaceStore,
    B: BlobStore,
    W: PackWindows,
    X: SliceExtension,
{
    /// Preserve the original entry admission allowance. Two windows overlap
    /// only in `feed`; decoder scratch runs after the acquired window drops.
    /// Delta resolution releases the idle reader before decoding another frame.
    /// Cache retention separately reserves R-203's decoder working memory.
    fn decode_limits(&self) -> DecodeLimits {
        let limits = self.h.limits;
        super::geometry::decode_limits(limits.resident_bytes, limits.window_bytes)
    }

    fn deadline(&self) -> u64 {
        now_ms(self.h.clock.as_ref()).saturating_add(10_000)
    }

    fn job_key(&self) -> Key {
        keys::verify_job(&self.repo.name, &self.pack)
    }

    fn row(&self, sub: u8, id: &Hash) -> Key {
        keys::verify_row(&self.repo.name, &self.pack, sub, Some(id))
    }

    /// The timer's next due time: never the timer's own, so the key moves.
    fn due(&self, timer: &DueTimer, delay_ms: u64) -> u64 {
        now_ms(self.h.clock.as_ref())
            .max(self.now)
            .saturating_add(delay_ms)
            .max(timer.due_at_ms.saturating_add(1))
    }

    async fn slice(&self, timer: &DueTimer) -> Result<Fired, StoreError> {
        let fired = self.slice_inner(timer).await;
        if let Err(error) = &fired {
            tracing::warn!(%error, pack = %mkit_core::hash::to_hex(&self.pack), "verification slice failed");
        }
        self.h.metrics.gauge(
            crate::telemetry::METRIC_INDEX_SLICE_SUBREQUESTS,
            &[],
            f64::from(self.budget.used()),
        );
        fired
    }

    #[allow(clippy::too_many_lines)] // Phase results and their guarded checkpoint commit together.
    async fn slice_inner(&self, timer: &DueTimer) -> Result<Fired, StoreError> {
        let (job, state) =
            checkpoint::read_job(self.local, self.source, &self.repo.name, &self.pack).await?;
        let Some((mut job, mut raw)) = job else {
            return self.cleanup(timer, None, None).await;
        };
        if job.gone {
            return self.cleanup(timer, Some(raw), None).await;
        }
        let ticket = match self
            .local
            .get(self.source, &keys::ticket(&job.ticket_id))
            .await?
        {
            Some(value) => Some(decode_ticket(&value)?),
            None if job.phase == Phase::Extract
                && job.extraction.as_ref().is_some_and(|x| x.object.is_some()) =>
            {
                None
            }
            None => return self.cleanup(timer, Some(raw), Some(job.ticket_id)).await,
        };
        if job.phase == Phase::Watch {
            return self.watch(
                timer,
                job,
                &raw,
                state.is_none(),
                ticket
                    .as_ref()
                    .ok_or_else(|| StoreError::Corrupt("missing watch ticket".into()))?,
            );
        }
        if matches!(
            job.phase,
            Phase::Decode | Phase::ClosureResolve | Phase::Recheck
        ) {
            match self.begin_attempt(&mut job, &raw).await? {
                Some(next) => raw = next,
                None => return Err(StoreError::Unavailable("verification job contended".into())),
            }
        }
        let mut st = SliceState {
            job_guard: Some(raw.clone()),
            ..SliceState::default()
        };
        let mut held = None;
        let start = job.clone();
        let mut ran = job.phase;
        let mut result = self
            .step(&mut st, &mut job, state.as_ref(), &mut held)
            .await;
        // The phases after the decode are cheap: run them back to back while
        // each one finishes at once and the slice still has calls to spend.
        let mut chained = 0;
        while matches!(result, Ok(0))
            && ran != Phase::Decode
            && job.phase != ran
            && job.phase != Phase::Watch
            // Enter guarded lookup phases from a durable phase checkpoint.
            && !matches!(job.phase, Phase::ClosureResolve | Phase::Recheck | Phase::Extract)
            && chained < 6
            && self.budget.remaining() >= ENTRY_RESERVE
        {
            chained += 1;
            ran = job.phase;
            result = self
                .step(&mut st, &mut job, state.as_ref(), &mut held)
                .await;
        }
        let delay = match result {
            Ok(delay) | Err(Stop::Yield(delay)) => delay,
            Err(Stop::Store(error)) => {
                if is_exhausted(&error) {
                    tracing::warn!(pack = %mkit_core::hash::to_hex(&self.pack), phase = ?job.phase, "verification slice spent its subrequest budget");
                }
                return Err(error);
            }
            // Nothing this slice counted is persisted: the cursor did not move.
            Err(Stop::Wait(delay)) => {
                job = start;
                delay
            }
            Err(Stop::Restart) => {
                if job.restarts >= 3 {
                    return Err(StoreError::Unavailable("pack source keeps changing".into()));
                }
                job.restart();
                0
            }
            Err(Stop::Outcome(outcome)) => {
                job.outcome = Some(outcome);
                job.phase = Phase::Watch;
                0
            }
            Err(Stop::Reject(message)) => {
                held = Some(self.reject(state.as_ref(), held.as_ref(), message).await?);
                job.phase = Phase::Watch;
                0
            }
        };
        // A slice that ended by itself is not a killed one.
        job.attempts = 0;
        self.flush(&mut st).await?;
        let mut batch = Batch::new()
            .require(Precondition::NotAfter(self.deadline()))
            .require(Precondition::Equals(self.job_key(), raw.clone()));
        let vs = keys::verification(&self.repo.name, &self.pack);
        batch = batch.require(match held.or_else(|| state.map(|(_, raw)| raw)) {
            Some(raw) => Precondition::Equals(vs, raw),
            None => Precondition::Absent(vs),
        });
        // Closure deletions and the satisfying-pack list commit together.
        // A crash cannot discard the row before recording its dependency.
        batch.writes.extend(st.settled);
        batch.preconditions.extend(st.guards);
        let batch =
            checkpoint::write_job(batch, &mut job, Some(&raw), &self.repo.name, &self.pack)?;
        Ok(self.reschedule(timer, delay, batch))
    }

    /// A finished job waits for its ticket to close; the timer's next look is
    /// at expiry, or sooner. If `vs` vanished under it (a concurrent ticket's
    /// expiry) it verifies again rather than answer pending for ever.
    fn watch(
        &self,
        timer: &DueTimer,
        mut job: VerifyJobV1,
        raw: &Value,
        vs_missing: bool,
        ticket: &TicketV1,
    ) -> Result<Fired, StoreError> {
        let resume = job.closure_retry();
        if resume || (vs_missing && job.outcome.is_none()) {
            if resume {
                job.phase = Phase::Extract;
            } else {
                job.restart();
            }
            let batch = Batch::new()
                .require(Precondition::NotAfter(self.deadline()))
                .require(Precondition::Equals(self.job_key(), raw.clone()));
            let batch =
                checkpoint::write_job(batch, &mut job, Some(raw), &self.repo.name, &self.pack)?;
            return Ok(self.reschedule(timer, 0, batch));
        }
        let delay = ticket
            .expires_at_ms
            .saturating_add(1)
            .saturating_sub(self.now)
            .min(WATCH_POLL_MS);
        Ok(self.reschedule(timer, delay, Batch::new()))
    }

    fn reschedule(&self, timer: &DueTimer, delay_ms: u64, batch: Batch) -> Fired {
        Fired::Reschedule {
            due_at_ms: self.due(timer, delay_ms),
            value: timer.value.clone(),
            batch,
        }
    }

    /// Count the slice durably before working, so a slice the runtime kills
    /// leaves a mark: repeated kills shrink decode/closure work to one, then
    /// end the ticket with its phase's platform cap, never Rejected.
    async fn begin_attempt(
        &self,
        job: &mut VerifyJobV1,
        raw: &Value,
    ) -> Result<Option<Value>, StoreError> {
        let (cap, outcome) = if job.phase == Phase::Decode {
            job.entry_cap = job.entry_cap.min(self.h.limits.max_entries).max(1);
            (&mut job.entry_cap, Outcome::DecodeBudget)
        } else {
            job.closure_cap = job.closure_cap.clamp(1, 4);
            (&mut job.closure_cap, Outcome::ClosureCapped)
        };
        if job.attempts >= ATTEMPTS_PER_CAP {
            job.attempts = 0;
            if *cap <= 1 {
                job.outcome = Some(outcome);
                job.phase = Phase::Watch;
            } else {
                *cap = (*cap / 2).max(1);
            }
        }
        job.attempts += 1;
        let batch = Batch::new()
            .require(Precondition::NotAfter(self.deadline()))
            .require(Precondition::Equals(self.job_key(), raw.clone()));
        let batch = checkpoint::write_job(batch, job, Some(raw), &self.repo.name, &self.pack)?;
        let next = encode_job(job);
        Ok(matches!(
            self.local.apply(self.source, batch).await?,
            BatchOutcome::Committed
        )
        .then_some(next))
    }

    async fn reject(
        &self,
        state: Option<&(VerificationV1, Value)>,
        held: Option<&Value>,
        message: &'static str,
    ) -> Result<Value, StoreError> {
        if matches!(state, Some((VerificationV1::Verified { .. }, _))) {
            return Err(StoreError::Unavailable(
                "verified pack content unavailable".into(),
            ));
        }
        let rejected = VerificationV1::Rejected {
            code: "invalid_argument".into(),
            message: message.into(),
        };
        let written = state::write(
            self.local,
            self.source,
            &self.repo.name,
            &self.pack,
            held.or_else(|| state.map(|(_, raw)| raw)),
            &rejected,
            self.deadline(),
        )
        .await?;
        if !written {
            tracing::error!(pack = %mkit_core::hash::to_hex(&self.pack), "failed to persist rejected verification state");
            self.h
                .metrics
                .incr(crate::telemetry::METRIC_INDEX_REJECTED_WRITE_FAILED, &[], 1);
            return Err(StoreError::Unavailable(
                "rejected state not persisted".into(),
            ));
        }
        Ok(state::encode(&rejected))
    }

    /// Write out buffered idempotent rows.
    async fn flush(&self, st: &mut SliceState) -> Result<(), StoreError> {
        for chunk in std::mem::take(&mut st.writes).chunks(WRITE_BATCH) {
            let mut batch = Batch::new().require(Precondition::NotAfter(self.deadline()));
            if let Some(raw) = &st.job_guard {
                batch = batch.require(Precondition::Equals(self.job_key(), raw.clone()));
            }
            batch.writes.extend_from_slice(chunk);
            if !matches!(
                self.local.apply(self.source, batch).await?,
                BatchOutcome::Committed
            ) {
                return Err(StoreError::Unavailable(
                    "verification rows contended".into(),
                ));
            }
        }
        Ok(())
    }

    /// Delete a finished or abandoned job's rows, then `vs` unless the pack
    /// became a member (kind-2 self-cleaning, R-148). Local rows only, so
    /// several pages fit one fire.
    #[allow(clippy::too_many_lines)] // Keep peer lifetime guards and the Gone transition together.
    async fn cleanup(
        &self,
        timer: &DueTimer,
        mut job: Option<Value>,
        ticket: Option<Hash>,
    ) -> Result<Fired, StoreError> {
        let mut peer_guards = Vec::new();
        if let Some(raw) = &job {
            let current = checkpoint::decode_job(raw)?;
            for member in &current.extraction_group {
                if member.pack == self.pack {
                    continue;
                }
                let key = keys::verify_job(&self.repo.name, &member.pack);
                if let Some(raw) = self.local.get(self.source, &key).await? {
                    let peer = checkpoint::decode_job(&raw)?;
                    if peer.extraction_group == current.extraction_group
                        && !peer.gone
                        && !peer.usable()
                        && (peer.outcome.is_none() || peer.closure_retry())
                    {
                        let ticket_key = keys::ticket(&peer.ticket_id);
                        let ticket_raw = self.local.get(self.source, &ticket_key).await?;
                        let live = ticket_raw
                            .as_ref()
                            .map(decode_ticket)
                            .transpose()?
                            .is_some_and(|t| t.expires_at_ms > self.now);
                        if live || peer.extraction.as_ref().is_some_and(|x| x.object.is_some()) {
                            return Ok(self.reschedule(timer, 1_000, Batch::new()));
                        }
                        peer_guards.push(match ticket_raw {
                            Some(raw) => Precondition::Equals(ticket_key, raw),
                            None => Precondition::Absent(ticket_key),
                        });
                    }
                    peer_guards.push(Precondition::Equals(key, raw));
                } else {
                    peer_guards.push(Precondition::Absent(key));
                }
            }
        }
        if let Some(raw) = &job
            && !checkpoint::decode_job(raw)?.gone
        {
            let mut gone = VerifyJobV1 {
                gone: true,
                members_loaded: true,
                ..VerifyJobV1::default()
            };
            let mut batch = Batch::new()
                .require(Precondition::NotAfter(self.deadline()))
                .require(Precondition::Equals(self.job_key(), raw.clone()));
            batch.preconditions.extend(peer_guards);
            if let Some(id) = ticket {
                batch = batch.require(Precondition::Absent(keys::ticket(&id)));
            }
            let batch =
                checkpoint::write_job(batch, &mut gone, Some(raw), &self.repo.name, &self.pack)?;
            if !matches!(
                self.local.apply(self.source, batch).await?,
                BatchOutcome::Committed
            ) {
                return Err(StoreError::Unavailable("cleanup header contended".into()));
            }
            job = Some(encode_job(&gone));
        }
        let (start, end) = keys::verify_range(&self.repo.name, &self.pack, None);
        for _ in 0..CLEANUP_ROUNDS {
            let page = self
                .local
                .scan(self.source, &start, &end, None, CLEANUP_PAGE)
                .await?;
            let mut batch = Batch::new().require(Precondition::NotAfter(self.deadline()));
            batch = batch.require(match job.as_ref() {
                Some(raw) => Precondition::Equals(self.job_key(), raw.clone()),
                None => Precondition::Absent(self.job_key()),
            });
            if let Some(id) = ticket {
                batch = batch.require(Precondition::Absent(keys::ticket(&id)));
            }
            for (key, _) in &page.entries {
                if *key != self.job_key() {
                    batch = batch.delete(key.clone());
                }
            }
            if page.next.is_none() {
                let member = self
                    .local
                    .has(self.source, &keys::membership(&self.repo.name, &self.pack))
                    .await?;
                let key = keys::verification(&self.repo.name, &self.pack);
                if !member && let Some(raw) = self.local.get(self.source, &key).await? {
                    batch = batch
                        .require(Precondition::Absent(keys::membership(
                            &self.repo.name,
                            &self.pack,
                        )))
                        .require(Precondition::Equals(key.clone(), raw))
                        .delete(key);
                }
                return Ok(Fired::Done(batch));
            }
            if !matches!(
                self.local.apply(self.source, batch).await?,
                BatchOutcome::Committed
            ) {
                return Err(StoreError::Unavailable(
                    "verification cleanup contended".into(),
                ));
            }
        }
        Ok(self.reschedule(timer, 0, Batch::new()))
    }
}

impl<S, R, B, W, X> Run<'_, S, R, B, W, X>
where
    S: NamespaceStore,
    R: NamespaceStore,
    B: BlobStore,
    W: PackWindows,
    X: SliceExtension,
{
    async fn step(
        &self,
        st: &mut SliceState,
        job: &mut VerifyJobV1,
        state: Option<&(VerificationV1, Value)>,
        held: &mut Option<Value>,
    ) -> Result<u64, Stop> {
        match job.phase {
            Phase::Decode => self.decode(st, job, state, held).await,
            Phase::ClosureResolve => {
                if self.closure(st, job).await? {
                    job.phase = Phase::EmitIndex;
                    job.scan.clear();
                }
                Ok(0)
            }
            Phase::EmitIndex => self.emit(job).await,
            Phase::AwaitDelivery => self.await_delivery(job).await,
            Phase::Extract => {
                if self.h.extension.extraction_enabled() {
                    return self.extraction(st, job).await;
                }
                if job.extract_needed {
                    return Err(Stop::Outcome(Outcome::ExtractionUnavailable));
                }
                job.phase = Phase::Verify;
                Ok(0)
            }
            Phase::Verify => self.verify(job, state, held).await,
            Phase::Recheck => self.recheck(st, job).await,
            Phase::Watch => Ok(WATCH_POLL_MS),
        }
    }

    /// One bounded read of the pack, bound to the job's etag.
    async fn read(&self, job: &mut VerifyJobV1, offset: u64, len: u64) -> Result<Window, Stop> {
        let etag = super::etag::resolve(
            self.local,
            self.source,
            &self.repo.name,
            &self.pack,
            job.etag.as_deref(),
        )
        .await?;
        self.budget.charge()?;
        match self
            .h
            .windows
            .read(&self.pack, offset, len, etag.as_deref())
            .await
        {
            Ok(window) => {
                if job.etag.is_none() {
                    job.etag = Some(
                        super::etag::capture(
                            self.local,
                            self.source,
                            &self.repo.name,
                            &self.pack,
                            &window.etag,
                            self.deadline(),
                        )
                        .await?,
                    );
                }
                Ok(window)
            }
            Err(WindowError::EtagChanged) => Err(Stop::Restart),
            Err(WindowError::Missing | WindowError::Unavailable) => {
                Err(unavailable("pack window read failed"))
            }
        }
    }

    fn reader_error(job: &VerifyJobV1, error: &PackError) -> Stop {
        match error {
            PackError::PackfileTooLarge => Stop::Outcome(Outcome::DecodeBudget),
            _ if !job.cursor.is_empty() && job.restarts == 0 => Stop::Restart,
            _ => Stop::Reject("object hash mismatch"),
        }
    }

    /// A packlist is one small window. An advance can consume at most seven
    /// tickets, so a list naming more than a lookup and those can never pass
    /// the MKPL rule: it is capped at once, without storing the list.
    fn packlist(job: &mut VerifyJobV1, window: &Window, pack: &Hash) -> Result<u64, Stop> {
        job.kind = Kind::Packlist;
        if window.bytes.len() as u64 != job.pack_len {
            return Err(Stop::Outcome(Outcome::ClosureCapped));
        }
        if hash(&window.bytes) != *pack {
            return Err(Stop::Reject("object hash mismatch"));
        }
        let list =
            decode_packlist(&window.bytes).map_err(|_| Stop::Reject("object hash mismatch"))?;
        if list.packs.len() > index::MAX_LOOKUP_IDS + crate::store::outbox::MAX_TICKETS_PER_ADVANCE
        {
            return Err(Stop::Outcome(Outcome::ClosureCapped));
        }
        job.packlist_prev = list.prev;
        job.packlist = list.packs;
        job.phase = Phase::Verify;
        Ok(0)
    }

    #[allow(clippy::too_many_lines)] // One loop owns the slice's stop rules.
    async fn decode(
        &self,
        st: &mut SliceState,
        job: &mut VerifyJobV1,
        state: Option<&(VerificationV1, Value)>,
        held: &mut Option<Value>,
    ) -> Result<u64, Stop> {
        // Timer slices also use the current configuration, independently of
        // the consuming advance's guard.
        if job.pack_len > self.h.cfg.max_pack_bytes {
            return Err(Stop::Reject(super::PACK_CAP_MESSAGE));
        }
        // A fresh job or source restart must discard provisional rows first.
        // Delete one page with the guarded checkpoint, then try again.
        if job.kind == Kind::Unknown {
            let start = keys::verify_row(&self.repo.name, &self.pack, keys::VC_FRAME, None);
            let (_, end) = keys::verify_range(&self.repo.name, &self.pack, None);
            let page = self
                .local
                .scan(self.source, &start, &end, None, CLEANUP_PAGE)
                .await?;
            st.settled
                .extend(page.entries.into_iter().map(|(key, _)| Write::Delete(key)));
            if !st.settled.is_empty() {
                return Ok(0);
            }
        }
        match state {
            Some((VerificationV1::Rejected { .. }, _)) => {
                job.phase = Phase::Watch;
                return Ok(0);
            }
            Some((VerificationV1::Verified { pack_len, .. }, _)) if *pack_len != job.pack_len => {
                return Err(Stop::Store(StoreError::Corrupt(
                    "verified pack length changed".into(),
                )));
            }
            // Frames are still needed for the advance's closure check.
            Some((VerificationV1::Verified { .. }, _)) => {}
            other => {
                let pending = VerificationV1::Pending {
                    lease_until_ms: now_ms(self.h.clock.as_ref())
                        .saturating_add(state::VERIFICATION_LEASE_MS),
                };
                let prior = other.map(|(_, raw)| raw);
                if !state::write(
                    self.local,
                    self.source,
                    &self.repo.name,
                    &self.pack,
                    prior,
                    &pending,
                    self.deadline(),
                )
                .await?
                {
                    return Err(unavailable("verification state contended"));
                }
                *held = Some(state::encode(&pending));
            }
        }
        let window_bytes = self.h.limits.window_bytes;
        let mut preloaded = None;
        if job.kind == Kind::Unknown {
            let window = self.read(job, 0, job.pack_len.min(window_bytes)).await?;
            match classify::classify(&window.bytes) {
                Ok(UploadType::Packlist) => return Self::packlist(job, &window, &self.pack),
                Ok(UploadType::Pack) => {
                    job.kind = Kind::Pack;
                    job.version = window
                        .bytes
                        .get(4..8)
                        .and_then(|v| v.try_into().ok())
                        .map_or(0, u32::from_le_bytes);
                    preloaded = Some(window);
                }
                Err(_) => return Err(Stop::Reject("unknown upload type")),
            }
        }
        let limits = self.decode_limits();
        let mut reader = if job.cursor.is_empty() {
            WindowReader::new(job.pack_len, window_bytes, limits, Some(self.pack))
        } else {
            WindowCursor::from_bytes(&job.cursor)
                .and_then(|cursor| WindowReader::resume(&cursor, limits))
        }
        .map_err(|e| Self::reader_error(job, &e))?;
        let (mut fed, mut processed) = (0_u32, 0_u32);
        loop {
            match reader.step().map_err(|e| Self::reader_error(job, &e))? {
                Step::NeedWindow(request) => {
                    let window = match preloaded.take() {
                        Some(window)
                            if request.offset == 0 && window.bytes.len() as u64 == request.len =>
                        {
                            window
                        }
                        _ => self.read(job, request.offset, request.len).await?,
                    };
                    reader
                        .feed_owned(request.offset, window.bytes)
                        .map_err(|e| Self::reader_error(job, &e))?;
                    fed += 1;
                    job.windows_done = job.windows_done.saturating_add(1);
                }
                Step::Entry(entry) => {
                    let frame = reader
                        .last_frame()
                        .ok_or_else(|| unavailable("window reader lost its frame"))?;
                    // Nested base decoding must not retain an idle pack window
                    // alongside the acquired source frame and decoder scratch.
                    // Save the same post-entry boundary; this slice commits only
                    // after `entry` succeeds, as on every other checkpoint.
                    #[cfg(feature = "pack-ruzstd")]
                    if matches!(entry, PackEntry::Delta { .. }) {
                        let cursor = reader
                            .checkpoint()
                            .ok_or_else(|| unavailable("delta entry lost its boundary"))?;
                        drop(reader);
                        self.entry(st, job, frame, entry).await?;
                        job.cursor = cursor.to_bytes();
                        job.attempts = 0;
                        return Ok(0);
                    }
                    self.entry(st, job, frame, entry).await?;
                    processed += 1;
                    // One window of progress per slice: the resumed window
                    // and the next. Only an entry boundary can be saved.
                    if (fed >= 2
                        || processed >= job.entry_cap
                        || self.budget.remaining() < ENTRY_RESERVE)
                        && let Some(cursor) = reader.checkpoint()
                    {
                        job.cursor = cursor.to_bytes();
                        job.attempts = 0;
                        return Ok(0);
                    }
                }
                Step::Done(summary) => {
                    if u64::from(summary.entry_count) != job.entries {
                        return Err(Stop::Reject("object hash mismatch"));
                    }
                    if job.bad_signature {
                        return Err(Stop::Reject("bad signature"));
                    }
                    job.cursor.clear();
                    job.attempts = 0;
                    job.scan.clear();
                    job.owed = 0;
                    job.phase = Phase::ClosureResolve;
                    return Ok(0);
                }
                _ => return Err(unavailable("unexpected window reader step")),
            }
        }
    }

    async fn frame_row(&self, st: &mut SliceState, id: &Hash) -> Result<Option<FrameRow>, Stop> {
        if let Some(row) = st.frames.get(id) {
            return Ok(Some(*row));
        }
        let Some(value) = self
            .local
            .get(self.source, &self.row(keys::VC_FRAME, id))
            .await?
        else {
            return Ok(None);
        };
        let row = decode_frame(id, &value)?;
        st.frames.insert(*id, row);
        Ok(Some(row))
    }

    async fn base_depth(&self, st: &mut SliceState, id: &Hash) -> Result<u32, Stop> {
        if let Some(depth) = st.bases.get(id) {
            return Ok(*depth);
        }
        let depth = match self
            .local
            .get(self.source, &self.row(keys::VC_BASE, id))
            .await?
        {
            Some(value) => decode_base(&value)?.depth,
            None => 0,
        };
        st.bases.insert(*id, depth);
        Ok(depth)
    }

    /// Verify and record one decoded entry.
    #[allow(clippy::too_many_lines)] // Depth, budget, rows and checks share one entry's state.
    async fn entry(
        &self,
        st: &mut SliceState,
        job: &mut VerifyJobV1,
        frame: mkit_core::pack::window::FrameInfo,
        entry: PackEntry<'static>,
    ) -> Result<(), Stop> {
        let cap = self.h.cfg.max_delta_chain_depth;
        st.entry_idx = job.entries;
        st.memo = MemberCache::default();
        if frame.length > super::geometry::FRAME_BYTES {
            return Err(Stop::Outcome(Outcome::DecodeBudget));
        }
        let base = match &entry {
            PackEntry::Delta { base, .. } => Some(*base),
            PackEntry::Raw { .. } => None,
        };
        let (hops, external) = match base {
            None => (0, None),
            Some(b) => match self
                .frame_row(st, &b)
                .await?
                .filter(|row| row.value.frame_offset < frame.offset)
            {
                Some(row) => (row.value.chain_depth.saturating_add(1), row.external),
                None => (1, Some(b)),
            },
        };
        if hops > cap {
            return Err(Stop::Reject("delta chain too deep"));
        }
        if let Some(b) = base {
            self.ensure_base(st, job, b, frame.offset).await?;
        }
        if let Some(x) = external
            && hops.saturating_add(self.base_depth(st, &x).await?) > cap
        {
            return Err(Stop::Outcome(Outcome::ExternalTooDeep));
        }
        let limits = self.decode_limits();
        let (id, bytes) =
            decode_entry_with(entry, &mut CacheBases(&st.cache), limits).map_err(|e| {
                if matches!(e, PackError::PackfileTooLarge) {
                    Stop::Outcome(Outcome::DecodeBudget)
                } else {
                    Stop::Reject("object hash mismatch")
                }
            })?;
        crate::takedown::denial::require_clear(self.remote, &id)
            .await
            .map_err(|error| {
                if error.code() == crate::Code::PermissionDenied {
                    Stop::Outcome(Outcome::Blocked)
                } else {
                    unavailable("decoded object unavailable")
                }
            })?;
        let object = mkit_core::serialize::deserialize(&bytes)
            .map_err(|_| Stop::Reject("object hash mismatch"))?;
        crate::takedown::inventory::stage(
            self.remote,
            &self.pack,
            job.pack_len,
            &id,
            &object,
            base,
            self.now,
        )
        .await?;
        let size = bytes.len() as u64;
        let existing = self.frame_row(st, &id).await?;
        // A replayed entry meets its own row; a real duplicate meets an
        // earlier offset. Only the first occurrence counts (native staging).
        if existing.is_none_or(|row| row.value.frame_offset == frame.offset) {
            job.in_pack_bytes = job.in_pack_bytes.saturating_add(size);
            let budget = self.h.cfg.decode_budget;
            if job.in_pack_bytes > budget {
                return Err(Stop::Reject("pack exceeds indexed decode budget"));
            }
            if job.in_pack_bytes.saturating_add(job.external_bytes) > budget {
                return Err(Stop::Outcome(Outcome::DecodeBudget));
            }
            let row = FrameRow {
                value: IndexValue {
                    frame_offset: frame.offset,
                    frame_length: frame.length,
                    wire_type: frame.wire_type,
                    decoded_size: size,
                    chain_depth: hops,
                    delta_base: base,
                },
                object_type: object.object_type() as u8,
                external,
            };
            let encoded =
                encode_frame(&id, &row).map_err(|_| Stop::Reject("object hash mismatch"))?;
            st.writes
                .push(Write::Put(self.row(keys::VC_FRAME, &id), encoded));
            st.frames.insert(id, row);
            let fact = super::selection::SelectionFact::from_object(&object);
            let projection = super::selection::Projection::from_fact(id, &fact);
            for (index, references) in fact
                .references()
                .chunks(super::selection::REFERENCES_PER_PAGE)
                .enumerate()
            {
                let index = u32::try_from(index).expect("decoded entry bounds page count");
                st.writes.push(Write::Put(
                    self.row(keys::VC_CANDIDATE, &projection.page_id(index)),
                    projection.encode_page(index, references),
                ));
                if st.writes.len() >= WRITE_BATCH {
                    self.flush(st).await?;
                }
            }
            drop(fact);
            // The summary is written after its pages. Decode's durable phase
            // transition is the full-pack completion marker; partial pages
            // are provisional and replay identically after a lost reply.
            st.writes.push(Write::Put(
                self.row(keys::VC_CANDIDATE, &id),
                projection.encode(),
            ));
            if let Some(parents) = super::verify::history_parents(&object) {
                st.writes.push(Write::Put(
                    self.row(keys::VC_HISTORY, &id),
                    Value::new(parents.concat()),
                ));
            }
            for child in children(&object, ClosureMode::History) {
                st.writes.push(Write::Put(
                    self.row(keys::VC_CHILD, &child),
                    Value::default(),
                ));
                if st.writes.len() >= WRITE_BATCH {
                    self.flush(st).await?;
                }
            }
            if verify_object_signature(&object).is_err() {
                job.bad_signature = true;
            }
            if self.h.extension.needs_extraction(&object, &self.h.cfg) {
                job.extract_needed = true;
            }
        }
        if size <= super::geometry::ENTRY_CACHE_BYTES {
            st.cache.insert(id, Arc::from(bytes));
        }
        job.entries += 1;
        Ok(())
    }

    /// Put `base`'s canonical bytes in the cache: an earlier frame of this
    /// pack is re-read from storage, anything else is a repository member.
    fn ensure_base<'x>(
        &'x self,
        st: &'x mut SliceState,
        job: &'x mut VerifyJobV1,
        base: Hash,
        before: u64,
    ) -> BoxFuture<'x, Result<(), Stop>> {
        Box::pin(async move {
            if st.cache.map.contains_key(&base) {
                return Ok(());
            }
            match self
                .frame_row(st, &base)
                .await?
                .filter(|row| row.value.frame_offset < before)
            {
                Some(row) => {
                    let limits = self.decode_limits();
                    if row.value.frame_length > super::geometry::FRAME_BYTES
                        || row.value.decoded_size > limits.max_decoded_bytes
                        || row.value.chain_depth > self.h.cfg.max_delta_chain_depth
                    {
                        return Err(StoreError::Corrupt("invalid source frame".into()).into());
                    }
                    if let Some(next) = row.value.delta_base {
                        if self.frame_row(st, &next).await?.is_some_and(|p| {
                            p.value.frame_offset < row.value.frame_offset
                                && p.value.chain_depth >= row.value.chain_depth
                        }) {
                            return Err(StoreError::Corrupt("invalid source chain".into()).into());
                        }
                        self.ensure_base(st, job, next, row.value.frame_offset)
                            .await?;
                    }
                    let window = self
                        .read(job, row.value.frame_offset, row.value.frame_length)
                        .await?;
                    let (id, bytes) = decode_frame_with(
                        &window.bytes,
                        job.version,
                        &mut CacheBases(&st.cache),
                        limits,
                    )
                    .map_err(|_| Stop::Restart)?;
                    if id != base {
                        return Err(Stop::Restart);
                    }
                    st.cache.insert(base, Arc::from(bytes));
                    Ok(())
                }
                None => self.resolve_external(st, job, base).await,
            }
        })
    }

    fn missing(&self, job: &VerifyJobV1) -> Stop {
        if resolve::lagged(self.now, job.created_at_ms, self.h.cfg.relay_lag_bound_ms) {
            Stop::Wait(LAG_BACKOFF_MS)
        } else {
            Stop::Outcome(Outcome::BaseMissing)
        }
    }

    /// Resolve an external base through this repository's members only, and
    /// charge it (once per distinct base, however the slices fall).
    async fn resolve_external(
        &self,
        st: &mut SliceState,
        job: &mut VerifyJobV1,
        base: Hash,
    ) -> Result<(), Stop> {
        // A base this slice already resolved is in the member cache: no call.
        if let Some((_, (bytes, _))) = st.memo.rows().find(|((id, ..), _)| *id == base) {
            st.cache.insert(base, Arc::from(bytes.to_vec()));
            return Ok(());
        }
        let found = resolve::locate_split(
            self.remote,
            self.h.shards.as_ref(),
            &self.repo,
            &[base],
            self.h.metrics.as_ref(),
        )
        .await
        .map_err(|_| unavailable("index lookup failed"))?;
        let located: LocatedObject = match found.get(&base) {
            Some(Ok(Some(located))) => *located,
            Some(Err(_)) => return Err(Stop::Outcome(Outcome::BaseCapped)),
            _ => return Err(self.missing(job)),
        };
        let cfg = &self.h.cfg;
        // The memory bound of the retained members. The decode budget itself
        // is charged per distinct base by `charge_bases`, from persisted rows,
        // so it does not depend on what earlier slices retained.
        let memo_budget = self.decode_limits().max_decoded_bytes;
        let (canonical, _) = resolve::member_object(
            self.blobs,
            self.remote,
            self.h.shards.as_ref(),
            &self.repo,
            base,
            located,
            cfg.max_delta_chain_depth,
            memo_budget,
            &mut st.memo,
            &mut st.visiting,
            self.h.metrics.as_ref(),
        )
        .await
        .map_err(|failure| match failure {
            ResolveFailure::Missing => self.missing(job),
            ResolveFailure::Capped => Stop::Outcome(Outcome::BaseCapped),
            ResolveFailure::Corrupt(_) => unavailable("member content unavailable"),
            ResolveFailure::Other(error) => match error.public_message() {
                "pack exceeds indexed decode budget" => Stop::Outcome(Outcome::DecodeBudget),
                "delta chain too deep" => Stop::Outcome(Outcome::ExternalTooDeep),
                "object blocked" => Stop::Outcome(Outcome::Blocked),
                _ => unavailable("member content unavailable"),
            },
        })?;
        st.cache.insert(base, Arc::from(canonical.to_vec()));
        self.charge_bases(st, job).await?;
        // Dependencies and byte charges are staged for the enclosing flush. The LRU owns
        // the needed base; release the duplicate member chain before an outer
        // in-pack frame can start its decoder.
        st.memo = MemberCache::default();
        Ok(())
    }

    /// Charge each newly retained member object once: the row records the
    /// entry that first needed it, so a replayed entry charges again and a
    /// later entry does not.
    async fn charge_bases(&self, st: &mut SliceState, job: &mut VerifyJobV1) -> Result<(), Stop> {
        let fresh: Vec<_> = st
            .memo
            .rows()
            .filter(|(location, _)| !st.charged.contains(*location))
            .map(|(location, (bytes, depth))| (*location, bytes.len() as u64, *depth))
            .collect();
        for ((id, pack, offset), size, depth) in fresh {
            crate::takedown::inventory::dependency(
                self.remote,
                &self.pack,
                job.pack_len,
                &id,
                self.now,
            )
            .await?;
            st.writes.push(Write::Put(
                self.row(keys::VC_DEPENDENCY, &pack),
                Value::default(),
            ));
            st.charged.insert((id, pack, offset));
            let location = mkit_core::hash::domain_digest(
                b"mkit:vc-base:v1\0",
                &[
                    id.as_slice(),
                    pack.as_slice(),
                    offset.to_be_bytes().as_slice(),
                ]
                .concat(),
            );
            let prior = match self
                .local
                .get(self.source, &self.row(keys::VC_BASE, &location))
                .await?
            {
                Some(value) => Some(decode_base(&value)?),
                None => None,
            };
            if prior.is_none_or(|row| row.entry == st.entry_idx) {
                job.external_bytes = job.external_bytes.saturating_add(size);
                st.writes.push(Write::Put(
                    self.row(keys::VC_BASE, &location),
                    encode_base(&BaseRow {
                        size,
                        depth,
                        entry: st.entry_idx,
                    }),
                ));
                st.bases.insert(id, depth);
            } else if let Some(row) = prior {
                st.bases.insert(id, row.depth);
            }
            // Object-keyed zero-size rows carry depth; location-keyed rows
            // charge bytes. Equal bytes at different locations count twice.
            st.writes.push(Write::Put(
                self.row(keys::VC_BASE, &id),
                encode_base(&BaseRow {
                    size: 0,
                    depth,
                    entry: st.entry_idx,
                }),
            ));
        }
        if job.in_pack_bytes.saturating_add(job.external_bytes) > self.h.cfg.decode_budget {
            return Err(Stop::Outcome(Outcome::DecodeBudget));
        }
        Ok(())
    }

    /// Look owed closure children up in this repository's members. A child
    /// found in this pack's frames or in a member is settled and its row goes
    /// (the member is remembered in `satisfying`); what stays is exactly what
    /// no pack this job can see holds, the rows an advance and the final
    /// recheck read.
    async fn closure(&self, st: &mut SliceState, job: &mut VerifyJobV1) -> Result<bool, Stop> {
        let (start, end) = keys::verify_range(&self.repo.name, &self.pack, Some(keys::VC_CHILD));
        for _ in 0..job.closure_cap {
            if self.budget.remaining() < ENTRY_RESERVE
                || st.settled.len() + CLOSURE_CHUNK as usize > WRITE_BATCH
            {
                return Ok(false);
            }
            let cursor = (!job.scan.is_empty()).then(|| Cursor::new(job.scan.clone()));
            let page = self
                .local
                .scan(self.source, &start, &end, cursor.as_ref(), CLOSURE_CHUNK)
                .await?;
            let mut ids = Vec::new();
            for (key, _) in &page.entries {
                let Some(keys::ParsedKey::VerifyCursor { id: Some(id), .. }) = keys::parse(key)
                else {
                    return Err(Stop::Store(StoreError::Corrupt(
                        "bad owed child row".into(),
                    )));
                };
                ids.push(id);
            }
            if !ids.is_empty() {
                let frame_keys: Vec<_> =
                    ids.iter().map(|id| self.row(keys::VC_FRAME, id)).collect();
                let present = self.local.get_many(self.source, &frame_keys).await?;
                let mut wanted = Vec::new();
                for (id, row) in ids.iter().zip(present) {
                    if row.is_some() {
                        st.settled.push(Write::Delete(self.row(keys::VC_CHILD, id)));
                    } else {
                        wanted.push(*id);
                    }
                }
                if !wanted.is_empty() {
                    // Reserve the lesser of the lookup's worst case and a full
                    // slice. A larger single-id lookup is a terminal cap.
                    let reserve = self.h.limits.max_subrequests.min(
                        u32::try_from(index::MAX_LOOKUP_PAGES + index::MAX_LOOKUP_MEMBERSHIP_READS)
                            .unwrap_or(u32::MAX),
                    );
                    if self.budget.remaining() < reserve {
                        return Ok(false);
                    }
                    let found = resolve::locate_split(
                        self.remote,
                        self.h.shards.as_ref(),
                        &self.repo,
                        &wanted,
                        self.h.metrics.as_ref(),
                    )
                    .await
                    .map_err(|_| {
                        if self.budget.remaining() == 0 {
                            Stop::Outcome(Outcome::ClosureCapped)
                        } else {
                            unavailable("index lookup failed")
                        }
                    })?;
                    for id in wanted {
                        match found.get(&id) {
                            Some(Ok(Some(located))) => {
                                if !job.satisfying.contains(&located.pack) {
                                    if job.satisfying.len() >= MAX_SATISFYING {
                                        return Err(Stop::Outcome(Outcome::ClosureCapped));
                                    }
                                    job.satisfying.push(located.pack);
                                }
                                st.settled
                                    .push(Write::Delete(self.row(keys::VC_CHILD, &id)));
                            }
                            Some(Err(_)) => return Err(Stop::Outcome(Outcome::ClosureCapped)),
                            _ => job.owed += 1,
                        }
                    }
                }
            }
            let Some(next) = page.next else {
                job.scan.clear();
                return Ok(true);
            };
            job.scan = next.into_bytes().to_vec();
        }
        Ok(false)
    }

    /// Relay this pack's index rows, one page of frames per slice, after the
    /// decode reached `Done` (SPEC-PACKFILE §11).
    async fn emit(&self, job: &mut VerifyJobV1) -> Result<u64, Stop> {
        let (start, end) = keys::verify_range(&self.repo.name, &self.pack, Some(keys::VC_FRAME));
        let cursor = (!job.scan.is_empty()).then(|| Cursor::new(job.scan.clone()));
        let page = self
            .local
            .scan(self.source, &start, &end, cursor.as_ref(), EMIT_PAGE)
            .await?;
        let mut entries: Vec<IndexEntry> = Vec::with_capacity(page.entries.len());
        for (key, value) in &page.entries {
            let Some(keys::ParsedKey::VerifyCursor { id: Some(id), .. }) = keys::parse(key) else {
                return Err(Stop::Store(StoreError::Corrupt("bad frame row".into())));
            };
            entries.push(checkpoint::index_entry(id, &decode_frame(&id, value)?));
        }
        let clock = self.h.clock.as_ref();
        let plan = index::plan_index_rows(
            self.h.shards.as_ref(),
            &self.repo,
            self.source,
            &self.pack,
            &entries,
            now_ms(clock),
        )?;
        for direct in plan.direct {
            let mut batch = Batch::new().require(Precondition::NotAfter(self.deadline()));
            for (key, value) in direct.puts {
                if let Some(keys::ParsedKey::ObjectIndex { object, .. }) = keys::parse(&key) {
                    crate::takedown::denial::require_clear(self.remote, &object)
                        .await
                        .map_err(|error| {
                            if error.code() == crate::Code::PermissionDenied {
                                Stop::Outcome(Outcome::Blocked)
                            } else {
                                unavailable("index object unavailable")
                            }
                        })?;
                }
                batch = batch.put(key, value);
            }
            if !matches!(
                self.local.apply(&direct.target, batch).await?,
                BatchOutcome::Committed
            ) {
                return Err(unavailable("index rows contended"));
            }
        }
        if !plan.relay.is_empty() {
            let lease = if matches!(self.source, Partition::Ref { .. }) {
                Some(
                    renew_for_relay(
                        self.local,
                        self.remote,
                        self.h.shards.as_ref(),
                        clock,
                        self.h.metrics.as_ref(),
                        &self.repo,
                        self.source,
                        &self.h.lease,
                    )
                    .await
                    .map_err(|_| unavailable("epoch lease renewal failed"))?,
                )
            } else {
                None
            };
            commit_relay_rows(
                self.local,
                self.source,
                &plan.relay,
                now_ms(clock),
                self.deadline(),
                lease.as_ref(),
            )
            .await?;
            job.last_relay_seq = self
                .local
                .get(self.source, &keys::outbox_sequence())
                .await?
                .as_ref()
                .map(codec::decode_u64)
                .transpose()?;
        }
        if let Some(next) = page.next {
            job.scan = next.into_bytes().to_vec();
        } else {
            job.scan.clear();
            job.phase = Phase::AwaitDelivery;
        }
        Ok(0)
    }

    /// R-130: `Verified` only once the relay delivered every index row.
    async fn await_delivery(&self, job: &mut VerifyJobV1) -> Result<u64, Stop> {
        let delivered = match job.last_relay_seq {
            Some(seq) => relay_delivered_through(self.local, self.source, seq).await?,
            None => true,
        };
        if delivered {
            job.phase = Phase::Extract;
            return Ok(0);
        }
        Ok(2_000)
    }

    /// The guarded `Pending` to `Verified` transition, monotone.
    async fn verify(
        &self,
        job: &mut VerifyJobV1,
        state: Option<&(VerificationV1, Value)>,
        held: &mut Option<Value>,
    ) -> Result<u64, Stop> {
        let now = now_ms(self.h.clock.as_ref());
        if job.kind == Kind::Packlist {
            crate::takedown::inventory::stage_packlist(
                self.remote,
                &self.pack,
                job.pack_len,
                job.packlist_prev,
                &job.packlist,
                now,
            )
            .await?;
            // Verify owns scan after decoding; checkpoint its inventory position.
            let mut offset = if job.scan.is_empty() {
                0
            } else {
                codec::decode_u64(&Value::new(job.scan.clone()))?
            };
            let start =
                usize::try_from(offset).map_err(|_| unavailable("invalid inventory cursor"))?;
            let children = job
                .packlist
                .get(start..)
                .ok_or_else(|| unavailable("invalid inventory cursor"))?;
            for child in children {
                if self.budget.remaining() < ENTRY_RESERVE {
                    return Ok(1);
                }
                crate::takedown::inventory::dependency(
                    self.remote,
                    &self.pack,
                    job.pack_len,
                    child,
                    now,
                )
                .await?;
                offset += 1;
                job.scan = offset.to_be_bytes().to_vec();
            }
        }
        crate::takedown::inventory::complete(self.remote, &self.pack, job.pack_len, now).await?;
        job.scan.clear();
        match state {
            Some((VerificationV1::Rejected { .. }, _)) => {
                job.phase = Phase::Watch;
                return Ok(0);
            }
            Some((VerificationV1::Verified { pack_len, .. }, _)) if *pack_len == job.pack_len => {}
            Some((VerificationV1::Verified { .. }, _)) => {
                return Err(Stop::Store(StoreError::Corrupt(
                    "verified pack length changed".into(),
                )));
            }
            other => {
                let verified = VerificationV1::Verified {
                    pack_len: job.pack_len,
                    verified_at_ms: now,
                    publication: None,
                };
                let prior = other.map(|(_, raw)| raw);
                if !state::write(
                    self.local,
                    self.source,
                    &self.repo.name,
                    &self.pack,
                    prior,
                    &verified,
                    self.deadline(),
                )
                .await?
                {
                    return Err(unavailable("verification state contended"));
                }
                *held = Some(state::encode(&verified));
            }
        }
        if job.kind == Kind::Pack && job.owed > 0 {
            job.phase = Phase::Recheck;
        } else {
            job.closure_final_at_ms = Some(now);
            job.phase = Phase::Watch;
        }
        Ok(0)
    }

    /// One final look after the lag bound, so an advance can tell a child
    /// that is still catching up from one that is truly open.
    async fn recheck(&self, st: &mut SliceState, job: &mut VerifyJobV1) -> Result<u64, Stop> {
        let now = now_ms(self.h.clock.as_ref());
        if !job.final_pass {
            let end = job
                .created_at_ms
                .saturating_add(self.h.cfg.relay_lag_bound_ms);
            if now < end {
                return Ok(end - now + 1);
            }
            job.final_pass = true;
            job.owed = 0;
            job.scan.clear();
        }
        if self.closure(st, job).await? {
            job.closure_final_at_ms = Some(now);
            job.phase = Phase::Watch;
        }
        Ok(0)
    }
}
