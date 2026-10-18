//! Native repository push: bounded packs and conditioned ref publication.
use crate::packmap::packmap_ref;
use crate::{RemoteSource, SourceError, SyncError, SyncEvent, SyncObserver};
use mkit_core::hash::{HASH_LEN, Hash};
use mkit_core::pack::{self, PackWriter, PreparedDelta, PreparedRaw};
use mkit_core::protocol::{PackKey, UploadLimits};
use mkit_core::refs;
use mkit_core::store::{ObjectStore, StoreError};
use mkit_core::transfer;
use rayon::prelude::*;
use std::path::Path;
mod error;
mod force;
mod packmap;
mod split;
pub use error::PushError;
use packmap::{ChainAction, advance_packmap, commit_head, probe_chain};
pub use split::{MAX_CHAIN_COMMITS, MAX_SPLIT_STEPS, PushControl, StepAuthority, plan_push_steps};

struct PreparedPlan {
    pack: transfer::PackPlan,
    force: Option<force::Snapshot>,
}

struct PushContext<'a> {
    source: &'a dyn RemoteSource,
    observer: &'a dyn SyncObserver,
}
impl<'a> std::ops::Deref for PushContext<'a> {
    type Target = dyn RemoteSource + 'a;
    fn deref(&self) -> &Self::Target {
        self.source
    }
}
fn repository_operation_error(tx: &PushContext<'_>, error: SourceError) -> PushError {
    tx.repository_error(error).into()
}

/// How the tracking lease is used for a branch push.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushLease {
    /// Unconditional head update; split steps still lease the prior step.
    Force,
    /// Require the last locally tracked remote tip, allowing divergence.
    WithLease,
    /// Require both ancestry from the tracked tip and its live CAS lease.
    FastForward,
}
/// Repository refs to publish.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum PushTarget {
    All {
        force: bool,
    },
    Branch {
        local: String,
        remote: String,
        lease: PushLease,
    },
}
/// Caller-supplied policy. Nothing is loaded from config or the environment.
#[derive(Debug)]
#[non_exhaustive]
pub struct PushOptions<'a> {
    /// Branch mapping or mirror selection.
    pub target: PushTarget,
    /// Local tracking-ref namespace.
    pub remote_name: &'a str,
    /// Object-store durability schedule.
    pub sync_policy: mkit_core::store::SyncPolicy,
    /// Atomic pushes reset healthy chains past this depth; zero disables it.
    pub rebaseline_threshold: usize,
    /// Per-pack payload bound, further limited by the remote and format.
    pub pack_payload_cap: u64,
    /// Observer, split bounds, shallow boundaries and host authority hook.
    pub control: PushControl<'a>,
}
impl PushOptions<'_> {
    /// Select a branch mapping or mirror push.
    #[must_use]
    pub fn with_target(mut self, target: PushTarget) -> Self {
        self.target = target;
        self
    }
}
impl Default for PushOptions<'_> {
    fn default() -> Self {
        Self {
            target: PushTarget::All { force: false },
            remote_name: "default",
            sync_policy: mkit_core::store::SyncPolicy::Batch,
            rebaseline_threshold: 64,
            pack_payload_cap: pack::MAX_TOTAL_PAYLOAD,
            control: PushControl::default(),
        }
    }
}
/// Completed branches, advances and the selected single-branch tip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct PushReport {
    /// Completed branches.
    pub refs: usize,
    /// Published advances across completed branches.
    pub steps: usize,
    /// Tip of a selected single branch; absent for a mirror push.
    pub tip: Option<Hash>,
}
/// Push repository refs and durably record each published tracking ref.
/// The observer is supplied through `options.control.observer`.
pub fn push(
    dir: &Path,
    source: &dyn RemoteSource,
    options: &PushOptions<'_>,
) -> Result<PushReport, PushError> {
    if !source.supports_push() {
        return Err(SourceError::ProtocolError.into());
    }
    let layout = mkit_core::layout::discover(dir)?;
    let mut store = ObjectStore::open(&layout)?;
    store.set_sync_policy(options.sync_policy);
    let tx = PushContext {
        source,
        observer: options.control.observer,
    };
    push_refs(&layout, &store, &tx, options)
}
fn push_refs(
    layout: &mkit_core::layout::RepoLayout,
    store: &ObjectStore,
    tx: &PushContext<'_>,
    options: &PushOptions<'_>,
) -> Result<PushReport, PushError> {
    match &options.target {
        PushTarget::All { force } => {
            let refs_list = refs::list_refs_with(layout, crate::worktree::fanout_read_batch)?;
            let control = repository_control(layout, options)?;
            let mut tracking = refs::RemoteRefBatch::new(layout, options.remote_name)?;
            let mut report = PushReport {
                refs: 0,
                steps: 0,
                tip: None,
            };
            let result: Result<(), PushError> = (|| {
                for r in refs_list {
                    if tx.observer.cancelled() {
                        return Err(SyncError::Interrupted.into());
                    }
                    let Some(tip) = r.hash else { continue };
                    let condition = if *force {
                        refs::RefWriteCondition::Any
                    } else {
                        lease(layout, options.remote_name, &r.name)?
                    };
                    tx.observer.event(&SyncEvent::PushBranchStarted {
                        branch: r.name.clone(),
                    });
                    report.steps += run_steps(
                        tx,
                        store,
                        &r.name,
                        tip,
                        condition,
                        options.rebaseline_threshold,
                        options.pack_payload_cap,
                        &control,
                        &mut |published| Ok(tracking.write(&r.name, &published)?),
                    )?;
                    report.refs += 1;
                }
                Ok(())
            })();
            tracking.commit()?;
            result?;
            Ok(report)
        }
        PushTarget::Branch {
            local,
            remote,
            lease: policy,
        } => {
            let tip = refs::read_ref(layout, local)?
                .ok_or_else(|| SyncError::RemoteBranchMissing(local.clone()))?;
            if matches!(policy, PushLease::FastForward)
                && let Some(tracked) = refs::read_remote_ref(layout, options.remote_name, remote)?
                && !mkit_core::ops::merge::is_ancestor(store, tracked, tip)?
            {
                return Err(PushError::NonFastForwardPush {
                    branch: remote.clone(),
                });
            }
            let condition = if matches!(policy, PushLease::Force) {
                refs::RefWriteCondition::Any
            } else {
                lease(layout, options.remote_name, remote)?
            };
            let control = repository_control(layout, options)?;
            tx.observer.event(&SyncEvent::PushBranchStarted {
                branch: remote.clone(),
            });
            let steps = run_steps(
                tx,
                store,
                remote,
                tip,
                condition,
                options.rebaseline_threshold,
                options.pack_payload_cap,
                &control,
                &mut |published| {
                    Ok(refs::write_remote_ref(
                        layout,
                        options.remote_name,
                        remote,
                        &published,
                    )?)
                },
            )?;
            Ok(PushReport {
                refs: 1,
                steps,
                tip: Some(tip),
            })
        }
    }
}
fn repository_control<'a>(
    layout: &mkit_core::layout::RepoLayout,
    options: &PushOptions<'a>,
) -> Result<PushControl<'a>, PushError> {
    let mut control = PushControl {
        authority: options.control.authority,
        max_steps: options.control.max_steps,
        max_chain: options.control.max_chain,
        shallow: refs::load_shallow_boundaries(layout)?
            .unwrap_or_default()
            .into_iter()
            .collect(),
        observer: options.control.observer,
    };
    control.shallow.extend(&options.control.shallow);
    Ok(control)
}

fn lease(
    layout: &mkit_core::layout::RepoLayout,
    remote: &str,
    branch: &str,
) -> Result<refs::RefWriteCondition, PushError> {
    Ok(refs::read_remote_ref(layout, remote, branch)?.map_or(
        refs::RefWriteCondition::Missing,
        refs::RefWriteCondition::Match,
    ))
}
/// Push an already selected tip; the host records each published step.
#[allow(clippy::too_many_arguments)]
pub fn push_branch_steps(
    source: &dyn RemoteSource,
    store: &ObjectStore,
    branch: &str,
    tip: Hash,
    condition: refs::RefWriteCondition,
    rebaseline_threshold: usize,
    pack_payload_cap: u64,
    control: &PushControl<'_>,
    on_step: &mut dyn FnMut(Hash) -> Result<(), PushError>,
) -> Result<usize, PushError> {
    if !source.supports_push() {
        return Err(SourceError::ProtocolError.into());
    }
    let tx = PushContext {
        source,
        observer: control.observer,
    };
    run_steps(
        &tx,
        store,
        branch,
        tip,
        condition,
        rebaseline_threshold,
        pack_payload_cap,
        control,
        on_step,
    )
}

/// Why an advance was re-planned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RetryReason {
    /// The server no longer holds a delta base the plan relied on.
    #[error(
        "the server no longer holds a delta base this push relied on, so it must be re-sent as a full closure (ask the operator whether the repository was restored from an older copy)"
    )]
    LostDeltaBase,
    /// The upload ticket or packlist was rejected, so the push was planned
    /// again against the remote's current head, which may have moved.
    #[error(
        "the upload was rejected and the push was re-planned against the remote's current head, which may have moved (fetch and merge, then push again)"
    )]
    Replanned,
    /// A concurrent writer replaced the chain used by a force-push plan.
    #[error("the pack map changed under this force push and its transfer was re-planned")]
    PackmapChanged,
}

#[allow(clippy::too_many_arguments)]
fn run_steps(
    tx: &PushContext<'_>,
    store: &ObjectStore,
    branch: &str,
    tip: Hash,
    condition: refs::RefWriteCondition,
    rebaseline_threshold: usize,
    pack_payload_cap: u64,
    control: &PushControl<'_>,
    on_step: &mut dyn FnMut(Hash) -> Result<(), PushError>,
) -> Result<usize, PushError> {
    let limits = tx.upload_limits();
    if matches!(condition, refs::RefWriteCondition::Any) && tx.atomic_advance_status().is_none() {
        return Err(PushError::ForceCapabilityUnknown);
    }
    let mut single = |plan| {
        push_step_recovering(
            tx,
            store,
            branch,
            tip,
            condition,
            rebaseline_threshold,
            pack_payload_cap,
            plan,
        )?;
        on_step(tip)?;
        Ok(1)
    };
    if limits.tickets_per_advance.is_none() {
        return single(None);
    }
    refs::check_pushable_branch(branch)?;
    let remote_tip = tx.read_ref(&format!("refs/heads/{branch}"))?;
    let plan = transfer::plan_pack_with(store, tip, remote_tip, encode_delta_candidates_batch)?;
    let cap = effective_payload_cap(pack_payload_cap, limits.max_pack_bytes)?;
    if estimate_pack_sizes(store, &plan, cap, limits.max_pack_bytes)?.len()
        <= split::data_pack_budget(limits)
    {
        let force = force::snapshot(tx, branch, remote_tip, condition)?;
        return single(Some(PreparedPlan { pack: plan, force }));
    }
    // The estimate is uncompressed: a push that compresses into the budget
    // is not split (exact dry seal), and one against a remote tip this store
    // lacks is left to the head CAS rather than walking all of history.
    if remote_tip.is_some_and(|remote| !store.contains(&remote)) {
        return single(None);
    }
    match build_and_upload_packs(PackSink::Count, store, plan, cap, limits, tx.observer) {
        Err(PushError::PushTooLarge { .. }) => {}
        Err(PushError::Sync(SyncError::Interrupted)) => {
            return Err(PushError::Sync(SyncError::Interrupted));
        }
        _ => return single(None),
    }
    let steps = plan_push_steps(
        store,
        tip,
        remote_tip,
        limits,
        pack_payload_cap,
        control,
        condition,
        branch,
    )?;
    if steps.len() == 1 {
        return single(None);
    }
    let total = steps.len();
    let mut published: Option<Hash> = None;
    for (index, step_tip) in steps.into_iter().enumerate() {
        let step_condition = published.map_or(condition, refs::RefWriteCondition::Match);
        let mut landed = false;
        let outcome = (|| {
            if tx.observer.cancelled() {
                return Err(PushError::Sync(SyncError::Interrupted));
            }
            tx.observer.event(&SyncEvent::PushStep {
                index: index + 1,
                total,
            });
            push_step_recovering(
                tx,
                store,
                branch,
                step_tip,
                step_condition,
                rebaseline_threshold,
                pack_payload_cap,
                None,
            )?;
            landed = true;
            on_step(step_tip)?;
            tx.observer.event(&SyncEvent::PushStepCommitted {
                index: index + 1,
                total,
                tip: step_tip,
            });
            Ok(())
        })();
        if landed {
            published = Some(step_tip);
        }
        if let Err(cause) = outcome {
            return Err(match published {
                Some(head) => PushError::SplitInterrupted {
                    branch: branch.to_owned(),
                    head: mkit_core::hash::to_hex(&head),
                    published: index + usize::from(landed),
                    total,
                    cause: Box::new(cause),
                },
                None => cause,
            });
        }
    }
    Ok(total)
}

/// One advance to `tip` with the restart-once recovery: a rejected ticket or
/// packlist re-plans the same way, a missing delta base re-plans as the full
/// closure. `plan` is an already-computed plan against the remote's current
/// tip, used for the first attempt only.
#[allow(clippy::too_many_arguments)]
fn push_step_recovering(
    tx: &PushContext<'_>,
    store: &ObjectStore,
    branch: &str,
    tip: Hash,
    condition: refs::RefWriteCondition,
    rebaseline_threshold: usize,
    pack_payload_cap: u64,
    plan: Option<PreparedPlan>,
) -> Result<(), PushError> {
    if matches!(condition, refs::RefWriteCondition::Any) && tx.supports_atomic_advance() {
        refs::check_pushable_branch(branch)?;
        return force::push_step(
            tx,
            store,
            branch,
            tip,
            rebaseline_threshold,
            pack_payload_cap,
            plan,
        );
    }
    let plan = plan.map(|prepared| prepared.pack);
    let once = |retry, plan| {
        push_branch_once(
            tx,
            store,
            branch,
            tip,
            condition,
            rebaseline_threshold,
            pack_payload_cap,
            retry,
            plan,
        )
    };
    match once(None, plan) {
        Err(PushError::TicketRejected | PushError::PacklistNotInRepository) => {
            once(Some(RetryReason::Replanned), None)
        }
        Err(PushError::DeltaBaseUnavailable) => once(Some(RetryReason::LostDeltaBase), None),
        result => result,
    }
}

#[allow(clippy::too_many_arguments)]
fn push_branch_once(
    tx: &PushContext<'_>,
    store: &ObjectStore,
    branch: &str,
    tip: Hash,
    condition: refs::RefWriteCondition,
    rebaseline_threshold: usize,
    pack_payload_cap: u64,
    retry: Option<RetryReason>,
    preplanned: Option<transfer::PackPlan>,
) -> Result<(), PushError> {
    let force_self_contained = retry == Some(RetryReason::LostDeltaBase);
    // Both wire names must fit SPEC-REFS §3's bound; a local branch named
    // before `MAX_BRANCH_NAME_BYTES` existed may not. Say so by name
    // rather than as a transport's "invalid ref name".
    refs::check_pushable_branch(branch)?;
    // Diff against the remote's CURRENT tip so we send only what it lacks
    // and can delta against bases it already holds. Planning is an
    // optimization; the head CAS below remains authoritative.
    // A caller that already planned against the remote's current tip (the
    // split decision does) passes its plan, so it is diffed once.
    let mut plan = plan_branch(tx, store, branch, tip, force_self_contained, preplanned)?;

    let limits = tx.upload_limits();
    // Payload and serialized-byte limits are checked separately. Framing
    // overhead grows with the entry count, so a fixed margin is insufficient.
    let effective_cap = effective_payload_cap(pack_payload_cap, limits.max_pack_bytes)?;

    if plan.is_empty() {
        // Nothing to send — the remote already holds the closure; just move
        // the head (no packmap change needed, so no chain walk and no atomic
        // two-ref advance).
        return commit_head(tx, &format!("refs/heads/{branch}"), condition, &tip, branch);
    }

    if tx.observer.cancelled() {
        return Err(PushError::Sync(SyncError::Interrupted));
    }

    // Re-baseline decision (#406/#521), made only now that we know there IS
    // something to send: walk the current chain exactly once and decide
    // whether this push should reset the chain to a single self-contained
    // node instead of appending. When NOT re-baselining, the walk is cached
    // (`resolved_chain`) so `advance_packmap`'s append path can reuse it
    // instead of re-walking.
    //
    // A reset is committed together with the head; the ordered (non-atomic)
    // `advance_refs` fallback (packmap PUT then head PUT) would strand the
    // head at the old tip on a torn write, and a reset — unlike an append —
    // is not a superset of the prior chain, so it can't rebuild that stranded
    // closure. We therefore re-baseline ONLY when BOTH hold:
    //   * the transport advances both refs transactionally
    //     (`supports_atomic_advance`), AND
    //   * the head write is CAS-conditioned (not `Any`). Atomic force pushes
    //     use the guarded force driver before reaching this path. The `Any`
    //     calls left here belong to non-atomic sources and cannot reset.
    let mut rebaseline = false;
    let mut resolved_chain = None;
    if !force_self_contained
        && rebaseline_threshold > 0
        && let Some(pm) = tx.read_ref(&packmap_ref(branch))?
    {
        match probe_chain(tx, branch, pm) {
            Ok(chain)
                if chain.depth + 1 > rebaseline_threshold
                    && tx.supports_atomic_advance()
                    && !matches!(condition, refs::RefWriteCondition::Any) =>
            {
                rebaseline = true;
            }
            Ok(chain) => resolved_chain = Some(chain),
            Err(PushError::Sync(SyncError::PackChainInvalid { .. })) => {}
            Err(e) => return Err(e),
        }
    }

    if rebaseline {
        // Force a full-closure plan: no external bases, so the pack is
        // self-contained and safe to reset the chain onto.
        let full = transfer::plan_pack_with(store, tip, None, encode_delta_candidates_batch)?;
        let full_cap = effective_payload_cap(pack_payload_cap, limits.max_pack_bytes)?;
        if estimated_ticketed_count(
            &estimate_pack_sizes(store, &full, full_cap, limits.max_pack_bytes)?,
            limits,
        ) > split::data_pack_budget(limits)
        {
            rebaseline = false;
        } else {
            plan = full;
        }
    }

    // A retry re-planned the push: make sure the new plan still fits before
    // uploading any of it, so the failure leaves no half-uploaded advance.
    if let Some(reason) = retry
        && estimated_ticketed_count(
            &estimate_pack_sizes(store, &plan, effective_cap, limits.max_pack_bytes)?,
            limits,
        ) > split::data_pack_budget(limits)
        && let Err(PushError::PushTooLarge { packs, limit, .. }) = build_and_upload_packs(
            PackSink::Count,
            store,
            plan.clone(),
            effective_cap,
            limits,
            tx.observer,
        )
    {
        return Err(PushError::RetryTooLarge {
            reason,
            packs,
            limit,
        });
    }

    // No pre-flight PushTooLarge: the estimate uses uncompressed sizes, so it
    // would refuse pushes that compress into six packs. The seal-time gate is
    // exact and still stops before the seventh ticketed pack's BeginUpload.
    // (The re-baseline check above may use the conservative estimate: a false
    // "too many" only keeps the append plan.)

    // Build the plan into one or more payload-bounded packs (splitting
    // when the plan exceeds `pack_payload_cap`, issue #831) and upload
    // each as it's sealed. Raws first (non-blobs before blobs), then
    // deltas (their bases are external — resolved from the fetcher's
    // store via earlier packs, never a base introduced earlier in THIS
    // push — so no in-pack ordering is required across the split,
    // SPEC-PACKFILE §4).
    //
    // `self_contained` is read out before `plan` moves into
    // `build_and_upload_packs` (which consumes it by value so its
    // delta streams can be handed to the compression fan-out without
    // an extra clone — see that function's doc comment).
    let self_contained = plan.self_contained;
    let head_ref = format!("refs/heads/{branch}");
    let pack_keys = build_and_upload_packs(
        PackSink::Upload {
            tx,
            head_ref: &head_ref,
        },
        store,
        plan,
        effective_cap,
        limits,
        tx.observer,
    )?;

    // Chain the pack(s) onto the packmap AND move the head together
    // (#408): a transactional transport applies both atomically, the
    // default does packmap-then-head. Either way the head never lands
    // past a packmap that can't reconstruct it. `Append`'s
    // `self_contained` lets a full-closure push reset a broken chain
    // (unconditionally, on any transport); `ResetSelfContained`
    // proactively resets a healthy chain that has grown too deep, and
    // is only ever chosen above when the transport is atomic-capable
    // AND the head write is CAS-conditioned. A failed advance leaves
    // the head untouched.
    let action = if rebaseline {
        ChainAction::ResetSelfContained
    } else {
        ChainAction::Append { self_contained }
    };
    advance_packmap(
        tx,
        branch,
        &pack_keys,
        action,
        resolved_chain,
        condition,
        tip,
    )
}

fn plan_branch(
    tx: &PushContext<'_>,
    store: &ObjectStore,
    branch: &str,
    tip: Hash,
    force_self_contained: bool,
    preplanned: Option<transfer::PackPlan>,
) -> Result<transfer::PackPlan, PushError> {
    Ok(if let Some(plan) = preplanned {
        plan
    } else {
        let remote_tip = tx.read_ref(&format!("refs/heads/{branch}"))?;
        // Plan FIRST, against the remote's current tip (#521 perf): a no-op push
        // (the remote already holds this closure) yields an empty plan and takes
        // the cheap head-only path below WITHOUT walking the packmap chain. Only
        // a push that actually has objects to send pays the O(depth) chain probe.
        transfer::plan_pack_with(
            store,
            tip,
            if force_self_contained {
                None
            } else {
                remote_tip
            },
            encode_delta_candidates_batch,
        )?
    })
}

/// Build `plan`'s entries into one or more packs, each staying under
/// `payload_cap` bytes of wire payload, uploading each pack to `tx` as
/// soon as it's sealed. Returns the ordered pack keys — build order is
/// apply order, threaded straight into [`advance_packmap`].
///
/// A single linear left-to-right pass over the plan's already-ordered
/// `raw ++ deltas` sequence is enough: [`transfer::plan_pack`] never
/// deltas an entry against a base introduced earlier in THIS push
/// (every delta's base is already on the remote from a prior push), so
/// packs can be sealed independently the instant one would exceed the
/// cap — no intra-push base-ordering hazard to preserve across the
/// split.
///
/// Sizing uses a conservative *uncompressed* upper bound per entry
/// (`bytes.len()` for a raw, `HASH_LEN + stream.len()` for a delta)
/// checked against [`PackWriter::total_payload`]'s real (compressed)
/// running total, so a sealed pack never exceeds `payload_cap` — it may
/// under-fill when compression bites, yielding more packs than the
/// theoretical minimum, never fewer. Peak memory is one pack buffer
/// PLUS one prepared batch, not every pack (or the whole plan) held at
/// once: [`size_capped_batch_lens`] caps each batch at `payload_cap`
/// conservative bytes (the same budget the writer itself is bounded
/// by) as well as [`pack_fanout_threshold`]-many entries, so a plan
/// containing very large objects can't balloon a batch past what one
/// sealed pack would have held anyway — see that function's doc
/// comment for why both caps are needed.
///
/// Takes `plan` BY VALUE (not `&PackPlan`): the delta compression
/// fan-out needs owned `Vec<u8>` streams to hand to rayon, and
/// `plan.deltas` already owns them — draining them out here is zero
/// extra bytes copied, where borrowing would force a clone per entry
/// just to satisfy ownership. The caller reads whatever it needs off
/// `plan` (just `self_contained`) before making this call.
fn effective_payload_cap(requested: u64, advertised: Option<u64>) -> Result<u64, PushError> {
    // The serialized limit's overhead margin is exact and dynamic: header,
    // trailer and one frame per entry. `should_seal` applies it on each add.
    let cap = requested
        .min(pack::MAX_TOTAL_PAYLOAD)
        .min(advertised.unwrap_or(pack::MAX_TOTAL_PAYLOAD));
    if cap == 0 {
        return Err(PushError::from(SourceError::PayloadTooLarge(0)));
    }
    Ok(cap)
}

fn serialized_bound(payload: u64, entries: usize) -> u64 {
    payload
        .saturating_add((entries as u64).saturating_mul(pack::ENTRY_FRAME_LEN as u64))
        .saturating_add((pack::HEADER_LEN + pack::TRAILER_LEN) as u64)
}

fn ticketed_pack(limits: UploadLimits, serialized_size: u64) -> bool {
    limits.tickets_per_advance.is_some()
        && serialized_size >= limits.ticket_threshold_bytes.unwrap_or(0)
}

fn estimated_ticketed_count(sizes: &[u64], limits: UploadLimits) -> usize {
    sizes
        .iter()
        .filter(|&&size| ticketed_pack(limits, size))
        .count()
}

fn estimate_pack_sizes(
    store: &ObjectStore,
    plan: &transfer::PackPlan,
    payload_cap: u64,
    max_pack_bytes: Option<u64>,
) -> Result<Vec<u64>, PushError> {
    let mut packs = Vec::new();
    let mut payload = 0_u64;
    let mut entries = 0_usize;
    let sizes = plan
        .raw
        .iter()
        .map(|hash| store.object_metadata(hash).map(|meta| meta.len()))
        .collect::<Result<Vec<_>, _>>()?;
    for size in sizes.into_iter().chain(
        plan.deltas
            .iter()
            .map(|delta| (HASH_LEN + delta.stream.len()) as u64),
    ) {
        let next_payload = payload.saturating_add(size);
        if entries > 0
            && (next_payload > payload_cap
                || max_pack_bytes
                    .is_some_and(|limit| serialized_bound(next_payload, entries + 1) > limit))
        {
            packs.push(serialized_bound(payload, entries));
            payload = 0;
            entries = 0;
        }
        payload = payload.saturating_add(size);
        entries += 1;
    }
    if entries > 0 {
        packs.push(serialized_bound(payload, entries));
    }
    Ok(packs)
}

/// Where sealed packs go: to the remote, or nowhere (an exact local dry run of
/// the seal, for the split's pre-flight check).
#[derive(Clone, Copy)]
enum PackSink<'a> {
    Upload {
        tx: &'a PushContext<'a>,
        head_ref: &'a str,
    },
    Count,
}

fn build_and_upload_packs(
    sink: PackSink<'_>,
    store: &ObjectStore,
    plan: transfer::PackPlan,
    payload_cap: u64,
    limits: UploadLimits,
    observer: &dyn SyncObserver,
) -> Result<Vec<Hash>, PushError> {
    let mut pack_keys = Vec::new();
    let mut ticketed_count = 0;
    let mut w = PackWriter::new();
    let max_entries = pack_fanout_threshold().max(1);
    let transfer::PackPlan {
        raw, mut deltas, ..
    } = plan;

    // Raw entries: size each via a metadata `stat` (cheap — no content
    // read) so batches can be capped by real bytes, not just count,
    // *before* any object's content is actually read into memory.
    let raw_sizes: Vec<u64> = raw
        .iter()
        .map(|h| Ok(store.object_metadata(h)?.len()))
        .collect::<Result<_, PushError>>()?;
    let mut start = 0;
    for len in size_capped_batch_lens(&raw_sizes, payload_cap, max_entries) {
        let chunk = &raw[start..start + len];
        start += len;
        for entry in prepare_raw_batch(store, chunk)? {
            if should_seal(
                &w,
                entry.conservative_len() as u64,
                payload_cap,
                limits.max_pack_bytes,
            ) {
                seal_pack(
                    sink,
                    &mut w,
                    &mut pack_keys,
                    &mut ticketed_count,
                    limits,
                    observer,
                )?;
            }
            w.push_prepared_raw(entry)?;
            // Honest progress (#711): one real object just got staged into
            // the outgoing pack. Never git's fabricated
            // Enumerating/Counting/Compressing lines — see `SyncEvent`.
            report_packed(sink, observer);
        }
    }

    // Delta entries: sizes are already known (`stream.len()`, no I/O),
    // so batch lengths can be computed directly off them; `drain` then
    // moves each batch's `PlannedDelta`s out of `deltas` without
    // cloning their streams.
    let delta_sizes: Vec<u64> = deltas
        .iter()
        .map(|d| (HASH_LEN + d.stream.len()) as u64)
        .collect();
    for len in size_capped_batch_lens(&delta_sizes, payload_cap, max_entries) {
        let chunk: Vec<transfer::PlannedDelta> = deltas.drain(..len).collect();
        for entry in prepare_delta_batch(chunk) {
            if should_seal(
                &w,
                entry.conservative_len() as u64,
                payload_cap,
                limits.max_pack_bytes,
            ) {
                seal_pack(
                    sink,
                    &mut w,
                    &mut pack_keys,
                    &mut ticketed_count,
                    limits,
                    observer,
                )?;
            }
            w.push_prepared_delta(entry)?;
            report_packed(sink, observer);
        }
    }

    seal_pack(
        sink,
        &mut w,
        &mut pack_keys,
        &mut ticketed_count,
        limits,
        observer,
    )?;
    Ok(pack_keys)
}

/// Honest progress (#711): one real object just got staged into the outgoing
/// pack. Never git's fabricated Enumerating/Counting/Compressing lines — see
/// `SyncEvent`. A dry seal stages nothing to send and reports nothing.
fn report_packed(sink: PackSink<'_>, observer: &dyn SyncObserver) {
    if matches!(sink, PackSink::Upload { .. }) {
        observer.event(&SyncEvent::ObjectsPacked { count: 1 });
    }
}

/// Split `sizes` (each item's conservative uncompressed byte size, in
/// original order) into batch lengths such that each batch's summed
/// size stays at-or-under `payload_cap` bytes AND at-or-under
/// `max_entries` items — whichever limit a batch hits first ends it.
/// Mirrors [`should_seal`]'s "never true for an empty writer" escape
/// hatch: a single item over `payload_cap` on its own (an oversized
/// blob against a tiny test cap, say) still gets a one-item batch of
/// its own rather than looping forever or being silently dropped.
///
/// The byte cap exists so [`build_and_upload_packs`]'s per-batch
/// compression fan-out can't hold dramatically more raw content in
/// memory at once than the single pack buffer it's feeding already
/// does — without it, a count-only cap (`max_entries`, sized for
/// rayon dispatch overhead, not memory) could group hundreds of
/// near-`MAX_RAW_OBJECT_SIZE` (1 GiB) blobs into one batch and read +
/// compress all of them before any of `payload_cap`'s own bookkeeping
/// ever runs. The entry cap exists for the opposite corpus shape: many
/// small objects would otherwise form one enormous `payload_cap`-sized
/// (default 4 GiB) batch, both blowing past `pack_fanout_threshold`'s
/// bench-measured parallel-dispatch sizing and stalling progress
/// reporting for the whole batch's compression time.
fn size_capped_batch_lens(sizes: &[u64], payload_cap: u64, max_entries: usize) -> Vec<usize> {
    let mut lens = Vec::new();
    let mut running: u64 = 0;
    let mut count = 0usize;
    for &size in sizes {
        if count > 0 && (running.saturating_add(size) > payload_cap || count >= max_entries) {
            lens.push(count);
            running = 0;
            count = 0;
        }
        running += size;
        count += 1;
    }
    if count > 0 {
        lens.push(count);
    }
    lens
}

/// Entries-per-thread budget below which [`prepare_raw_batch`] /
/// [`prepare_delta_batch`] read + zstd-compress sequentially instead of
/// fanning out across rayon's thread pool, for a pool of a given size.
/// Same crossover shape as `add.rs`'s `HASH_FANOUT_FILES_PER_THREAD`
/// (PR #951) — rayon's pool-dispatch overhead loses to a plain loop
/// below a few entries per thread and wins clearly above it — measured
/// for the pack-build path specifically with `cargo bench -p
/// mkit-benches --bench pack_build_fanout`.
///
/// Also doubles as one of [`size_capped_batch_lens`]'s two caps: a
/// batch that isn't cut short by `payload_cap` first comes out exactly
/// this many entries long (until the final, possibly-shorter
/// remainder) — the same length `prepare_raw_batch`/
/// `prepare_delta_batch` compare against to decide sequential vs.
/// parallel, so a full-length batch always takes the parallel path.
const PACK_FANOUT_ENTRIES_PER_THREAD: usize = 8;

/// The per-batch entry count [`build_and_upload_packs`] fans out across
/// rayon at — see [`PACK_FANOUT_ENTRIES_PER_THREAD`].
fn pack_fanout_threshold() -> usize {
    crate::fanout::threshold(PACK_FANOUT_ENTRIES_PER_THREAD)
}

/// Read + compression-prepare one chunk of raw object hashes —
/// sequentially below [`pack_fanout_threshold`], via rayon's global
/// thread pool at or above it. Output mirrors `chunk`'s order 1:1
/// either way: `plan.raw` is already ordered (non-blobs before blobs,
/// each group in BLAKE3 order — see [`transfer::PackPlan`]'s doc
/// comment), and that order is the wire order the pack is built in, so
/// a parallel fan-out must not reshuffle it.
fn prepare_raw_batch(store: &ObjectStore, chunk: &[Hash]) -> Result<Vec<PreparedRaw>, PushError> {
    crate::fanout::try_map_seq_or_par(chunk, pack_fanout_threshold(), |h| {
        Ok(PackWriter::prepare_raw(*h, store.read(h)?))
    })
}

/// The delta-entry counterpart of [`prepare_raw_batch`]. Delta streams
/// are already resident in `chunk` (no store read needed), so this
/// only fans out the zstd compression step. Takes `chunk` by value —
/// `build_and_upload_packs` drains it straight out of `plan.deltas` —
/// so `PackWriter::prepare_delta` can take each stream by move instead
/// of cloning it.
fn prepare_delta_batch(chunk: Vec<transfer::PlannedDelta>) -> Vec<PreparedDelta> {
    if chunk.len() < pack_fanout_threshold() {
        return chunk
            .into_iter()
            .map(|d| PackWriter::prepare_delta(d.base, d.stream))
            .collect();
    }
    chunk
        .into_par_iter()
        .map(|d| PackWriter::prepare_delta(d.base, d.stream))
        .collect()
}

/// Entries-per-thread budget below which [`encode_delta_candidates_batch`]
/// diffs candidates sequentially instead of fanning out across rayon's
/// thread pool, for a pool of a given size. Same crossover shape as
/// [`PACK_FANOUT_ENTRIES_PER_THREAD`] but tuned separately, and lower:
/// each entry here pays two disk reads (target + base) plus
/// `delta::encode`'s block-hash-table build and greedy scan over the
/// target's full length — a heavier per-item cost than the
/// zstd-compression fan-out `PACK_FANOUT_ENTRIES_PER_THREAD` guards, so
/// fewer entries per thread are enough to amortize dispatch.
///
/// `cargo bench -p mkit-benches --bench delta_plan_fanout` on a 4-core
/// host, isolating `delta::encode` over synthetic 64 KiB
/// (FastCDC-average-sized) near-duplicate chunks:
///
///   n=256: sequential 46.99ms -> rayon 14.79ms (3.18x)
///   n=128: sequential 22.85ms -> rayon  7.57ms (3.02x)
///   n=64:  sequential 11.65ms -> rayon  3.67ms (3.18x)
///   n=32:  sequential  5.52ms -> rayon  1.74ms (3.18x)
///   n=16:  sequential  3.28ms -> rayon  1.22ms (2.69x)
///   n=8:   sequential  1.38ms -> rayon  0.70ms (1.97x)
///   n=4:   sequential  0.68ms -> rayon  0.42ms (1.63x)
///   n=2:   sequential  0.34ms -> rayon  0.33ms (roughly flat)
///   n=1:   sequential  0.17ms -> rayon  0.17ms (roughly flat)
///
/// Each candidate already costs ~0.17ms, comfortably above rayon's
/// microsecond-scale dispatch overhead, so the crossover falls at the
/// smallest candidate count worth fanning out at all rather than at a
/// larger multiple of the pool size the other fan-outs need.
const DELTA_PLAN_FANOUT_ENTRIES_PER_THREAD: usize = 1;

/// The candidate count [`encode_delta_candidates_batch`] fans out across
/// rayon at — see [`DELTA_PLAN_FANOUT_ENTRIES_PER_THREAD`].
fn delta_plan_fanout_threshold() -> usize {
    crate::fanout::threshold(DELTA_PLAN_FANOUT_ENTRIES_PER_THREAD)
}

/// [`transfer::plan_pack_with`]'s `encode_deltas` callback: diffs every
/// delta candidate `plan_pack_with` found — sequentially below
/// [`delta_plan_fanout_threshold`], via rayon's global thread pool at or
/// above it. Each candidate's `delta::encode` is independent of every
/// other candidate's (same shape as `prepare_raw_batch`'s per-object
/// compression fan-out), so a push touching many changed blobs
/// parallelizes the diffing itself, not just the downstream zstd pass
/// `prepare_delta_batch` already fans out.
///
/// Processes at most [`DELTA_CANDIDATE_BATCH_CAP`] candidates at a time.
/// Repeated bases share a cache capped at [`DELTA_BASE_CACHE_BYTES`];
/// one-use bases and bases that do not fit are read by each encoder as
/// before. Metadata checks avoid reading nonfitting bases twice. The
/// cache is dropped before the next batch. Active encoders' target/base
/// buffers and the accumulated encoded output are additional allocations;
/// imported blobs can reach the store's 1 GiB object limit.
///
/// Order matches `candidates` 1:1, including across batch boundaries,
/// satisfying `plan_pack_with`'s contract.
fn encode_delta_candidates_batch(
    store: &ObjectStore,
    candidates: &[transfer::DeltaCandidate],
) -> Result<Vec<Option<transfer::PlannedDelta>>, StoreError> {
    let mut results = Vec::with_capacity(candidates.len());
    for batch in candidates.chunks(DELTA_CANDIDATE_BATCH_CAP) {
        let base_bytes = cache_delta_bases(store, batch, DELTA_BASE_CACHE_BYTES)?;
        results.extend(crate::fanout::try_map_seq_or_par(
            batch,
            delta_plan_fanout_threshold(),
            |&c| match base_bytes.get(&c.base) {
                Some(bytes) => transfer::encode_delta_candidate_with_base(store, c, bytes),
                None => transfer::encode_delta_candidate(store, c),
            },
        )?);
    }
    Ok(results)
}

/// Maximum number of candidates whose base objects are cached together.
const DELTA_CANDIDATE_BATCH_CAP: usize = 64;

/// Maximum retained payload bytes for reused bases, independent of blob sizes.
const DELTA_BASE_CACHE_BYTES: usize = 64 * 1024 * 1024;

fn cache_delta_bases(
    store: &ObjectStore,
    candidates: &[transfer::DeltaCandidate],
    byte_budget: usize,
) -> Result<std::collections::HashMap<Hash, Vec<u8>>, StoreError> {
    let mut counts = std::collections::BTreeMap::<Hash, usize>::new();
    for candidate in candidates {
        *counts.entry(candidate.base).or_default() += 1;
    }
    let mut cache = std::collections::HashMap::new();
    let mut remaining = byte_budget;
    for (base, count) in counts {
        if count < 2 || remaining == 0 {
            continue;
        }
        if store.object_metadata(&base)?.len() > remaining as u64 {
            continue;
        }
        let bytes = store.read(&base)?;
        // Recheck after reading: metadata is only an optimization, never
        // authority for the retained byte bound if a file changes meanwhile.
        if bytes.len() <= remaining {
            remaining -= bytes.len();
            cache.insert(base, bytes);
        }
    }
    Ok(cache)
}

/// Would pushing an entry of (conservative, uncompressed) size
/// `add_bound` into `w` exceed `payload_cap`? Never true for an empty
/// writer — a single entry over the cap (only reachable with a
/// test-injected tiny cap; production entries are bounded well under
/// [`pack::MAX_TOTAL_PAYLOAD`] by [`mkit_core::store::MAX_RAW_OBJECT_SIZE`])
/// lands alone in its own pack rather than looping forever.
fn should_seal(
    w: &PackWriter,
    add_bound: u64,
    payload_cap: u64,
    max_pack_bytes: Option<u64>,
) -> bool {
    let next_payload = w.total_payload().saturating_add(add_bound);
    w.entry_count() > 0
        && (next_payload > payload_cap
            || max_pack_bytes
                .is_some_and(|limit| serialized_bound(next_payload, w.entry_count() + 1) > limit))
}

/// Finish `w`, upload it, record its key, and replace `w` with a fresh
/// empty writer so the caller can keep pushing entries into the next
/// pack.
fn seal_pack(
    sink: PackSink<'_>,
    w: &mut PackWriter,
    pack_keys: &mut Vec<Hash>,
    ticketed_count: &mut usize,
    limits: UploadLimits,
    observer: &dyn SyncObserver,
) -> Result<(), PushError> {
    if observer.cancelled() {
        return Err(PushError::Sync(SyncError::Interrupted));
    }
    let sealed = std::mem::replace(w, PackWriter::new());
    let pack = sealed.finish()?;
    let is_ticketed = ticketed_pack(limits, pack.len() as u64);
    let budget = split::data_pack_budget(limits);
    if is_ticketed && *ticketed_count >= budget {
        return Err(PushError::PushTooLarge {
            packs: *ticketed_count + 1,
            limit: budget,
            commit: None,
            holds_remote_head: false,
        });
    }
    if limits
        .max_pack_bytes
        .is_some_and(|limit| pack.len() as u64 > limit)
    {
        return Err(PushError::from(SourceError::PayloadTooLarge(pack.len())));
    }
    let pack_key = pack::pack_key(&pack);
    if let PackSink::Upload { tx, head_ref } = sink {
        tx.upload_pack_via_ref(&pack, &PackKey::from_hash(pack_key), head_ref)
            .map_err(|error| repository_operation_error(tx, error))?;
        // Upload is complete — report the real byte count handed to the
        // transport, not an estimate.
        observer.event(&SyncEvent::PackUploaded {
            bytes: pack.len() as u64,
        });
    }
    pack_keys.push(pack_key);
    if is_ticketed {
        *ticketed_count += 1;
    }
    Ok(())
}

#[cfg(test)]
mod packmap_tests;
#[cfg(test)]
mod tests {
    use super::*;
    use mkit_core::layout::RepoLayout;
    #[test]
    fn batch_lens_empty_input_is_no_batches() {
        assert_eq!(
            super::size_capped_batch_lens(&[], 1000, 10),
            Vec::<usize>::new()
        );
    }

    #[test]
    fn batch_lens_fits_one_batch_under_both_caps() {
        assert_eq!(
            super::size_capped_batch_lens(&[10, 10, 10], 1000, 10),
            vec![3]
        );
    }

    #[test]
    fn batch_lens_splits_on_byte_cap() {
        // Each item is 40 bytes; a 100-byte cap fits 2 per batch (80 <=
        // 100), not 3 (120 > 100) — entry cap (10) never binds here.
        assert_eq!(
            super::size_capped_batch_lens(&[40, 40, 40, 40, 40], 100, 10),
            vec![2, 2, 1]
        );
    }

    #[test]
    fn batch_lens_splits_on_entry_cap() {
        // Every item is tiny (1 byte), so the byte cap (10_000) never
        // binds — only the entry cap (2) does.
        assert_eq!(
            super::size_capped_batch_lens(&[1, 1, 1, 1, 1], 10_000, 2),
            vec![2, 2, 1]
        );
    }

    #[test]
    fn batch_lens_single_oversized_item_gets_its_own_batch() {
        // A lone item over `payload_cap` must not loop forever or be
        // dropped — mirrors `should_seal`'s "never true for an empty
        // writer" escape hatch.
        assert_eq!(super::size_capped_batch_lens(&[500], 100, 10), vec![1]);
        assert_eq!(
            super::size_capped_batch_lens(&[500, 10, 10], 100, 10),
            vec![1, 2]
        );
    }

    // =================================================================
    // `prepare_raw_batch` / `prepare_delta_batch` — order preservation
    // and error propagation across BOTH the sequential and the rayon
    // branch. `pack_fanout_threshold()` is read directly (rather than
    // hardcoding a count) so a chunk built at exactly that length
    // reliably lands in the parallel branch regardless of how many
    // cores the test happens to run on.
    // =================================================================

    fn store() -> (tempfile::TempDir, ObjectStore) {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = RepoLayout::single(dir.path());
        let store = ObjectStore::init(&layout).expect("init store");
        (dir, store)
    }

    #[test]
    fn prepare_raw_batch_preserves_order_sequential_and_parallel() {
        let (_dir, store) = store();
        for &n in &[1usize, super::pack_fanout_threshold()] {
            let hashes: Vec<mkit_core::hash::Hash> = (0..n)
                .map(|i| store.write(format!("raw entry #{i}").as_bytes()).unwrap())
                .collect();
            let prepared = super::prepare_raw_batch(&store, &hashes).expect("prepare raw batch");
            assert_eq!(
                prepared.iter().map(PreparedRaw::hash).collect::<Vec<_>>(),
                hashes,
                "prepare_raw_batch must preserve input order at n={n}"
            );
        }
    }

    #[test]
    fn prepare_raw_batch_propagates_a_missing_object_error_sequential_and_parallel() {
        let (_dir, store) = store();
        for &n in &[1usize, super::pack_fanout_threshold()] {
            let mut hashes: Vec<mkit_core::hash::Hash> = (0..n.saturating_sub(1))
                .map(|i| store.write(format!("raw entry #{i}").as_bytes()).unwrap())
                .collect();
            // A hash of content never written to the store — `store.read`
            // must fail with `ObjectNotFound`, and that failure must
            // surface through `prepare_raw_batch` rather than being
            // silently dropped or panicking on either branch.
            hashes.push(mkit_core::hash::hash(b"never written"));
            let err = super::prepare_raw_batch(&store, &hashes).expect_err(
                "a missing object must fail prepare_raw_batch instead of being dropped",
            );
            assert!(matches!(
                err,
                super::PushError::Sync(crate::SyncError::Store(
                    mkit_core::store::StoreError::ObjectNotFound(_)
                ))
            ));
        }
    }

    #[test]
    fn prepare_delta_batch_preserves_order_sequential_and_parallel() {
        use mkit_core::transfer::PlannedDelta;
        for &n in &[1usize, super::pack_fanout_threshold()] {
            let deltas: Vec<PlannedDelta> = (0..n)
                .map(|i| PlannedDelta {
                    target: mkit_core::hash::hash(format!("target #{i}").as_bytes()),
                    base: mkit_core::hash::hash(format!("base #{i}").as_bytes()),
                    stream: format!("delta stream #{i}").into_bytes(),
                })
                .collect();
            let expected_bases: Vec<_> = deltas.iter().map(|d| d.base).collect();
            let prepared = super::prepare_delta_batch(deltas);
            assert_eq!(
                prepared.iter().map(PreparedDelta::base).collect::<Vec<_>>(),
                expected_bases,
                "prepare_delta_batch must preserve input order at n={n}"
            );
        }
    }

    #[test]
    fn encode_delta_candidates_batch_preserves_order_sequential_and_parallel() {
        let (_dir, store) = store();
        for &n in &[
            1usize,
            super::delta_plan_fanout_threshold(),
            super::DELTA_CANDIDATE_BATCH_CAP * 2 + 1,
        ] {
            // Each candidate's base/target pair is a small, localized edit
            // of distinct-per-index content — a real delta candidate (the
            // encoded stream is smaller than the raw target), and distinct
            // across candidates so no candidate's result could accidentally
            // match another's and mask an ordering bug.
            let candidates: Vec<transfer::DeltaCandidate> = (0..n)
                .map(|i| {
                    let mut base_bytes =
                        format!("encode-delta-candidates-batch fixture #{i}\n").into_bytes();
                    base_bytes.extend_from_slice(
                        b"the quick brown fox jumps over the lazy dog\n"
                            .repeat(4)
                            .as_slice(),
                    );
                    let base = store.write(&base_bytes).unwrap();
                    let mut target_bytes = base_bytes.clone();
                    target_bytes.extend_from_slice(b"-- edited --\n");
                    let target = store.write(&target_bytes).unwrap();
                    transfer::DeltaCandidate { target, base }
                })
                .collect();

            // Ground truth: encode each candidate one at a time, in order.
            let expected: Vec<Option<Vec<u8>>> = candidates
                .iter()
                .map(|&c| {
                    transfer::encode_delta_candidate(&store, c)
                        .expect("encode delta candidate")
                        .map(|p| p.stream)
                })
                .collect();
            assert!(
                expected.iter().all(Option::is_some),
                "every fixture candidate must actually delta-encode smaller than raw"
            );

            let actual: Vec<Option<Vec<u8>>> =
                super::encode_delta_candidates_batch(&store, &candidates)
                    .expect("encode delta candidates batch")
                    .into_iter()
                    .map(|r| r.map(|p| p.stream))
                    .collect();
            assert_eq!(
                actual, expected,
                "encode_delta_candidates_batch must preserve input order at n={n}"
            );
        }
    }

    #[test]
    fn encode_delta_candidates_batch_propagates_a_missing_object_error_sequential_and_parallel() {
        let (_dir, store) = store();
        for &n in &[
            1usize,
            super::delta_plan_fanout_threshold(),
            super::DELTA_CANDIDATE_BATCH_CAP * 2 + 1,
        ] {
            let mut candidates: Vec<transfer::DeltaCandidate> = (0..n.saturating_sub(1))
                .map(|i| {
                    let base = store
                        .write(format!("present base #{i}").as_bytes())
                        .unwrap();
                    let target = store
                        .write(format!("present target #{i}").as_bytes())
                        .unwrap();
                    transfer::DeltaCandidate { target, base }
                })
                .collect();
            // A target hash never written to the store — `store.read` must
            // fail with `ObjectNotFound`, surfaced through
            // `encode_delta_candidates_batch` rather than dropped or
            // panicking, on either branch.
            candidates.push(transfer::DeltaCandidate {
                target: mkit_core::hash::hash(b"never written target"),
                base: mkit_core::hash::hash(b"never written base"),
            });
            let err = super::encode_delta_candidates_batch(&store, &candidates).expect_err(
                "a missing object must fail encode_delta_candidates_batch instead of being dropped",
            );
            assert!(matches!(
                err,
                mkit_core::store::StoreError::ObjectNotFound(_)
            ));
        }
    }

    #[test]
    fn delta_base_cache_respects_bytes_and_skips_single_use_bases() {
        let (_dir, store) = store();
        let mut candidates = Vec::new();
        for (value, size, uses) in [
            (b'a', 128usize, 2usize),
            (b'b', 128, 2),
            (b'c', 1024, 2),
            (b'd', 64, 1),
        ] {
            let base_bytes = vec![value; size];
            let base = store.write(&base_bytes).unwrap();
            let mut target_bytes = base_bytes;
            target_bytes.extend_from_slice(b"edited");
            let target = store.write(&target_bytes).unwrap();
            candidates.extend(std::iter::repeat_n(
                transfer::DeltaCandidate { target, base },
                uses,
            ));
        }
        // Only one of the two repeated 128-byte bases fits. The 1 KiB
        // base exceeds the budget and the 64-byte base is used only once.
        let cache = super::cache_delta_bases(&store, &candidates, 192).unwrap();
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.values().map(Vec::len).sum::<usize>(), 128);
    }

    #[test]
    fn delta_base_cache_does_not_read_past_a_failed_batch() {
        let (_dir, store) = store();
        let base = store.write(b"present base").unwrap();
        let missing_target = mkit_core::hash::hash(b"missing first-batch target");
        let mut candidates = vec![
            transfer::DeltaCandidate {
                target: missing_target,
                base,
            };
            super::DELTA_CANDIDATE_BATCH_CAP
        ];
        // If all bases are prefetched for the whole push, this missing base
        // fails first. Bounded processing must encounter the first batch's
        // missing target before it even tries to read the later base.
        candidates.extend(
            [transfer::DeltaCandidate {
                target: missing_target,
                base: mkit_core::hash::hash(b"missing later-batch base"),
            }; 2],
        );
        let err = super::encode_delta_candidates_batch(&store, &candidates).unwrap_err();
        assert!(matches!(
            err,
            mkit_core::store::StoreError::ObjectNotFound(h) if h == mkit_core::hash::to_hex(&missing_target)
        ));
    }
}
