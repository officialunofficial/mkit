//! Pure write planners (reconciliation R-18) and the commit deadline
//! (R-61/R-62, 00-plan P-21).
//!
//! The store only checks preconditions and applies writes, so every write
//! is planned here as **read → decide → batch**: [`plan_write`] is a pure
//! function of the request, a read [`Snapshot`] and a [`PlanClock`], and
//! every value it decided on is guarded by a precondition. The pipeline
//! applies the batch and re-plans when a guard fails.

use std::collections::BTreeMap;

use mkit_core::hash::Hash;
use mkit_core::protocol::AdvanceOutcome;
use mkit_core::refs::RefWriteCondition;

use crate::error::{AbortCause, ServerError};
use crate::op::{GrantRef, PresenceRequirement, RefUpdate};
use crate::quota::{self, NamespaceCharge, QuotaCharge, QuotaDecision, evaluate_quota};
use crate::refs::{CasDecision, evaluate_condition};
use crate::replay::{
    ReplayDecision, ReplayRecord, ReplayState, StoredRejection, StoredResult, UpdateRefResult,
    classify,
};
use crate::repo::{RepoId, RepoName};
use crate::storage_error::{StorageOp, describe_and_map};
use crate::store::keys::{self, LAYOUT_VERSION, ParsedKey};
use crate::store::outbox::{OutboxBuilder, Terminal};
use crate::store::{
    Batch, Key, MAX_BATCH_OPS, Partition, Precondition, Value, Write, codec, tickets,
};

use super::{ShardMap, internal, meta_error};

/// Actual backend support; never selected from deployment configuration.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthorityStore {
    RefsOnly,
    Inspected,
    Guarded,
}

impl AuthorityStore {
    pub(crate) fn from_capabilities(caps: crate::store::StoreCapabilities) -> Self {
        if caps.key_classes == crate::store::KeyClasses::RefsOnly {
            Self::RefsOnly
        } else if caps.atomic_multi_key {
            Self::Guarded
        } else {
            Self::Inspected
        }
    }
}

/// Most re-plans after a guard failed because another writer changed a
/// value the plan read; then the write is a retryable `aborted`.
pub(crate) const MAX_REPLAN: u32 = 8;

/// Most expired replay records, and separately most stale quota windows,
/// one sampled write prunes (each an index key plus its row). One write in
/// [`PRUNE_SAMPLE`] prunes, so this must be at least `PRUNE_SAMPLE` for
/// growth to stay bounded; the batch op cap trims it further
/// ([`MAX_BATCH_OPS`]). WP-1.24's alarm sweep replaces this.
pub(crate) const PRUNE_LIMIT: u32 = 16;

/// One write in this many runs the prune scans.
pub(crate) const PRUNE_SAMPLE: u8 = 8;

const _: () = assert!(PRUNE_LIMIT >= PRUNE_SAMPLE as u32);

/// Whether this write runs the prune scans: deterministically one in
/// [`PRUNE_SAMPLE`], by replay scope for a signed write, keeping the scans
/// off the hot path.
#[must_use]
pub(crate) fn prune_sampled(req: &WriteRequest<'_>, plan_time_ms: u64) -> bool {
    match req.replay {
        Some(replay) => replay.scope[0].is_multiple_of(PRUNE_SAMPLE),
        None => !req.charges.is_empty() && plan_time_ms.is_multiple_of(u64::from(PRUNE_SAMPLE)),
    }
}

/// The clocks one planning attempt uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PlanClock {
    /// Unix ms from the injected clock, never shifted by a test clock-skew
    /// directive. Only the commit deadline uses it.
    pub(crate) plan_time_ms: u64,
    /// Business time, Unix ms: quota windows and replay pruning.
    pub(crate) business_now_ms: i64,
    /// `PipelineConfig::max_apply_window`, in ms.
    pub(crate) max_apply_window_ms: u64,
    /// An extra bound on the deadline: WP-1.25 passes
    /// `lease_expires - margin` here without touching the planners.
    pub(crate) deadline_cap: Option<u64>,
}

impl PlanClock {
    /// `min(plan_time + max_apply_window, deadline_cap)`: the batch's
    /// `NotAfter`, which the backend checks on its own clock.
    #[must_use]
    pub(crate) fn deadline(&self) -> u64 {
        let window = self.plan_time_ms.saturating_add(self.max_apply_window_ms);
        self.deadline_cap.map_or(window, |cap| cap.min(window))
    }
}

/// The ref write being planned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) enum WriteKind {
    /// One conditional ref write.
    UpdateRef,
    /// Unary ticket opening, with replay and lease guards.
    BeginUpload,
    /// Packmap and head, in one batch.
    AdvanceRefs,
    /// An `UploadPack` reservation: the replay record `InFlight { resumable:
    /// true }` and the quota charge, before any chunk is read.
    UploadReserve,
    /// An `UploadPack` commit: the in-flight record becomes
    /// `Committed(UploadPack)`, guarded by `Equals` on the record read.
    UploadCommit,
}

/// The replay record a signed write commits with its effects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReplayGuard {
    /// The auth v2 replay scope.
    pub(crate) scope: Hash,
    /// The operation fingerprint.
    pub(crate) fingerprint: Hash,
    /// Envelope expiry, Unix ms.
    pub(crate) expires_at_ms: i64,
}

/// Multi planning context for a consuming packmap write (WP-1.15): the
/// session-uploaded packs' `m` rows and relay upserts join the ref batch.
/// No tickets, no outcome rows.
#[derive(Clone)]
pub(crate) struct ImplicitConsume<'a> {
    /// Pending packs, deduplicated by id.
    pub(crate) packs: &'a [Hash],
    /// The repository the packmap advances.
    pub(crate) repo_id: &'a RepoId,
    /// The ref partition this batch applies in.
    pub(crate) source: &'a Partition,
    /// Membership index routing.
    pub(crate) shards: &'a dyn super::ShardMap,
    /// The same packs with their sizes, for the repository stored-bytes counter.
    pub(crate) counted: &'a [(Hash, u64)],
}

/// A write to plan.
#[derive(Clone)]
#[non_exhaustive]
pub(crate) struct WriteRequest<'a> {
    /// Metadata inspection and CAS support, derived from the actual store.
    pub(crate) authority_store: AuthorityStore,
    /// The repository whose refs are written.
    pub(crate) repo: &'a RepoName,
    /// Fresh authoritative denial inputs retained across optimistic retries.
    pub(crate) denial_ids: Option<&'a std::collections::BTreeSet<Hash>>,
    pub(crate) denial_packs: &'a [Hash],
    /// What the refs are.
    pub(crate) kind: WriteKind,
    /// Ref writes in decision order: `[update]`, or `[packmap, head]`, so a
    /// packmap conflict takes precedence (`refstore.rs` parity).
    pub(crate) refs: &'a [RefUpdate],
    /// D34 index routing for a ref write; absent on Single and non-ref writes.
    pub(crate) ref_index: Option<(&'a RepoId, &'a Partition, &'a dyn ShardMap)>,
    /// The replay record to commit, for signed writes.
    pub(crate) replay: Option<ReplayGuard>,
    /// Quota charges from admission.
    pub(crate) charges: &'a [QuotaCharge],
    /// Built-in namespace quota; absent for Single defaults and uncharged tickets.
    pub(crate) namespace_charge: Option<NamespaceCharge>,
    /// The grant the write was authorized under (M2).
    pub(crate) grant: Option<GrantRef>,
    /// Trusted Authority generation at authorization, unchanged on retries.
    pub(crate) authority_generation: Option<u64>,
    /// D34 leased epoch and optional installation, guarded by the observed el.
    pub(crate) lease: Option<super::lease::LeaseWrite>,
    /// Whether to guard the layout version key: false on stores that
    /// report an implicit layout version.
    pub(crate) layout_version: bool,
    /// Ensure this ref shard knows its repository was registered.
    pub(crate) mark_repo_known: bool,
    /// Ticket opening or pre-admission answer.
    pub(crate) begin: Option<&'a super::begin::BeginWrite>,
    /// Ticketed advance context; rows are re-read at each planning attempt.
    pub(crate) advance: Option<super::advance::AdvanceWrite<'a>>,
    /// Implicit session-ticket consumption (Multi only), also re-planned.
    pub(crate) implicit: Option<ImplicitConsume<'a>>,
    /// A final rejection: upload `pre_receive`, or a replay-only built-in
    /// policy denial with no refs or other mutable effects.
    pub(crate) rejection: Option<&'a StoredRejection>,
    /// Paired publication context; absent only on ref-only stores.
    pub(crate) publication: Option<super::clearance::PublicationWrite<'a>>,
    /// A separately committed admission reservation, if one was granted.
    pub(crate) pending: Option<&'a super::reservation::PendingGuard>,
}

impl WriteRequest<'_> {
    pub(crate) fn for_store(&self, caps: crate::store::StoreCapabilities) -> Self {
        let mut request = self.clone();
        request.authority_store = AuthorityStore::from_capabilities(caps);
        request
    }

    /// Every key the planner reads, besides prune candidates.
    #[must_use]
    pub(crate) fn read_keys(&self) -> Vec<Key> {
        let mut out = Vec::new();
        if self.publication.is_some()
            && let Some(update) = self.refs.first()
        {
            let name = crate::store::publication::sequence_ref(&update.name);
            out.push(keys::publication(self.repo, &name));
            out.push(keys::ref_key(self.repo, &name));
            if let Some(packmap) = mkit_attest::grant::head_packmap(&name) {
                out.push(keys::ref_key(self.repo, &packmap));
            }
            out.extend([keys::outbox_sequence(), keys::outcome_backlog()]);
        }
        if let Some(super::begin::BeginWrite::Open(open)) = self.begin {
            out.extend(super::begin::open_keys(&open.spec));
        }
        if let Some(super::begin::BeginWrite::Return(crate::replay::BeginUploadResult::Ticket {
            id,
            ..
        })) = self.begin
        {
            out.push(keys::ticket(id));
        }
        if let Some(advance) = &self.advance {
            out.extend(advance.ids.iter().map(keys::ticket));
        }
        if let Some(implicit) = &self.implicit {
            out.push(keys::outbox_sequence());
            out.push(keys::outcome_backlog());
            if *implicit.source == implicit.shards.coordinator(&implicit.repo_id.namespace) {
                out.extend(crate::store::repo_storage::read_keys(
                    self.repo,
                    implicit.counted,
                ));
            } else {
                // Packs the shard already holds need no marker relay.
                out.extend(
                    implicit
                        .counted
                        .iter()
                        .map(|(pack, _)| keys::membership(self.repo, pack)),
                );
            }
        }
        if self.mark_repo_known {
            out.push(keys::repo_known(self.repo));
        }
        if self.layout_version {
            out.push(keys::layout_version());
        }
        if self.lease.is_some() {
            out.push(keys::epoch_lease());
        } else if self.grant.is_some() {
            out.push(keys::grant_epoch());
        }
        if self.lease.is_none() && self.authority_store != AuthorityStore::RefsOnly {
            out.push(keys::authority_generation());
            out.push(keys::lease_recovery());
        }
        out.extend(self.charges.iter().map(|c| keys::quota(&c.scope)));
        if let Some(charge) = self.namespace_charge {
            let window = charge.window;
            out.push(quota::counter_key(charge, window));
            if charge.rollup {
                out.push(keys::quota_view(window));
            }
        }
        out.extend(self.refs.iter().map(|r| keys::ref_key(self.repo, &r.name)));
        if self.ref_index.is_some() && !self.refs.is_empty() {
            out.extend([keys::outbox_sequence(), keys::outcome_backlog()]);
        }
        if let Some(pending) = self.pending {
            out.push(pending.key.clone());
            out.extend([keys::outbox_sequence(), keys::outcome_backlog()]);
        }
        if let Some(replay) = self.replay
            && (matches!(
                self.kind,
                WriteKind::UploadCommit | WriteKind::BeginUpload | WriteKind::AdvanceRefs
            ) || self.rejection.is_some())
        {
            out.push(keys::replay(&replay.scope));
        }
        out
    }
}

/// What a planning attempt read: key values plus the prune candidates of
/// `store::read::{expired_replay_keys, stale_quota_keys}`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Snapshot {
    values: BTreeMap<Key, Option<Value>>,
    /// Fixed quota window selected by the request's read-ahead.
    pub(crate) namespace_window: Option<u64>,
    /// Coordinator total read with a new shard's lease, installed by the
    /// accepted write so subsequent writes have a local view.
    pub(crate) namespace_seed: Option<(u64, Value)>,
    /// `(index, record)` pairs of expired replay records.
    pub(crate) expired_replays: Vec<(Key, Key)>,
    /// `(index, quota)` pairs of ended quota windows; their quota keys are
    /// read too.
    pub(crate) stale_quotas: Vec<(Key, Key)>,
}

impl Snapshot {
    /// Record that `key` held `value`.
    pub(crate) fn insert(&mut self, key: Key, value: Option<Value>) {
        self.values.insert(key, value);
    }

    /// Make a guard-raced key eligible for a fresh `get_many` while retaining
    /// unrelated read-ahead values needed by the later planner.
    pub(crate) fn remove(&mut self, key: &Key) {
        self.values.remove(key);
    }

    /// Whether `key` was read.
    #[must_use]
    pub(crate) fn contains(&self, key: &Key) -> bool {
        self.values.contains_key(key)
    }

    /// What `key` held; a key never read counts as absent.
    #[must_use]
    pub(crate) fn get(&self, key: &Key) -> Option<&Value> {
        debug_assert!(self.values.contains_key(key), "planner read an unread key");
        self.values.get(key).and_then(Option::as_ref)
    }
}

/// A planned batch and what it means.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Plan {
    /// The batch; its first precondition is always the `NotAfter`.
    pub(crate) batch: Batch,
    /// The result once the batch commits.
    pub(crate) on_commit: StoredResult,
    /// Index of the replay record's `Absent` guard.
    pub(crate) replay_index: Option<usize>,
    /// Index of the grant epoch guard.
    pub(crate) epoch_index: Option<usize>,
    /// Index of the pending row guard, never eligible for re-planning.
    pub(crate) pending_index: Option<usize>,
    /// The prune deletes alone, retried when a full partition rejects the
    /// batch (delete-only batches never fail with `Full`).
    pub(crate) prune: Option<Batch>,
    /// Index of the first prune guard: a failure at or after it is only
    /// the opportunistic prune losing a race, so the pipeline retries
    /// without the prune.
    pub(crate) prune_from: usize,
}

/// What [`plan_write`] decided.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) enum Planned {
    /// Apply this batch.
    Apply(Plan),
    /// Nothing to write: an unsigned write that conflicts on the snapshot.
    Done(StoredResult),
}

fn plan_namespace(
    req: &WriteRequest<'_>,
    snap: &Snapshot,
    clock: &PlanClock,
    pre: &mut Vec<Precondition>,
    puts: &mut Vec<Write>,
) -> Result<(), ServerError> {
    let Some(charge) = req.namespace_charge else {
        return Ok(());
    };
    debug_assert!(
        req.advance.is_none(),
        "ticketed advances must not charge quota"
    );
    let window = charge.window;
    let view_key = keys::quota_view(window);
    let stored_view = charge.rollup.then(|| snap.get(&view_key)).flatten();
    let seed = snap
        .namespace_seed
        .as_ref()
        .filter(|(seed_window, _)| *seed_window == window);
    quota::plan_namespace_after_admission(
        charge,
        snap.get(&quota::counter_key(charge, window)),
        stored_view.or_else(|| seed.map(|(_, value)| value)),
        clock.business_now_ms,
        clock.plan_time_ms,
        req.lease.is_some(),
        pre,
        puts,
    )?;
    if stored_view.is_none()
        && let Some((_, value)) = seed
    {
        puts.push(Write::Put(view_key, value.clone()));
    }
    Ok(())
}

fn add_ref_index_relays(req: &WriteRequest<'_>, outbox: &mut OutboxBuilder) {
    let Some((repo, source, shards)) = req.ref_index else {
        return;
    };
    for update in req.refs {
        let bucket = shards.ref_index(repo, &update.name);
        if bucket != *source {
            let key = keys::ref_index_key(req.repo, &update.name);
            match update.new {
                Some(id) => outbox.relay(&bucket, vec![(key, codec::encode_ref_id(&id))]),
                None => outbox.relay_delete(&bucket, vec![key]),
            }
        }
    }
}

/// Plan `req` on `snap` at `clock`.
///
/// # Errors
/// `resource_exhausted` when a quota charge is over budget (nothing is
/// written), `permission_denied` when the grant epoch moved, and `internal`
/// for an undecodable stored value or a newer layout version.
#[allow(clippy::too_many_lines)] // The ref, ticket, replay and prune fragments form one atomic plan.
pub(crate) fn plan_write(
    req: &WriteRequest<'_>,
    snap: &Snapshot,
    clock: &PlanClock,
) -> Result<Planned, ServerError> {
    if req.authority_generation.is_some() && req.authority_store != AuthorityStore::Guarded {
        return Err(ServerError::unavailable(
            "authority fencing requires transactional metadata",
        ));
    }
    // A racing retry may read ticket/reservation rows after its initial
    // replay observation. Resolve the committed answer before ticket planning.
    if let Some(pending) = req.pending
        && snap.get(&pending.key) != Some(&pending.value)
    {
        return Err(ServerError::unavailable(
            "admission reservation changed; retry",
        ));
    }
    if let Some(result) = replayed_write(req, snap)? {
        if req.pending.is_some() {
            return Err(ServerError::aborted_retryable(
                "operation already in flight; retry",
            ));
        }
        return Ok(Planned::Done(result));
    }
    let tickets = req
        .advance
        .as_ref()
        .map(|advance| super::advance::validate(snap, advance, clock.business_now_ms))
        .transpose()?;
    let deadline = Precondition::NotAfter(req.pending.map_or(clock.deadline(), |pending| {
        clock.deadline().min(pending.apply_deadline_ms)
    }));
    let mut pre = vec![deadline.clone()];
    let mut puts = Vec::new();

    if let Some(lease) = req.lease {
        pre.push(guard(keys::epoch_lease(), snap));
        if lease.install {
            puts.push(Write::Put(
                keys::epoch_lease(),
                codec::encode_epoch_lease(&lease.value),
            ));
        }
    }
    let epoch_index = match req.grant.as_ref() {
        Some(grant) => {
            if let Some(lease) = req.lease {
                if lease.value.epoch != grant.epoch {
                    return Err(epoch_moved());
                }
                // The el guard re-plans on failure, whereas Single's e guard
                // maps directly to permission_denied.
                None
            } else {
                let key = keys::grant_epoch();
                let stored = snap.get(&key).map(codec::decode_u64).transpose();
                if stored.map_err(corrupt)?.unwrap_or(0) != grant.epoch {
                    return Err(epoch_moved());
                }
                pre.push(guard(key, snap));
                Some(pre.len() - 1)
            }
        }
        None => None,
    };
    if req.lease.is_none() && req.authority_store != AuthorityStore::RefsOnly {
        let mode = snap
            .get(&keys::lease_recovery())
            .map(codec::decode_lease_recovery)
            .transpose()
            .map_err(corrupt)?;
        if req.authority_generation.is_none()
            && (snap.get(&keys::authority_generation()).is_some()
                || mode.is_some_and(|m| m.authority_fence == Some(true)))
        {
            return Err(ServerError::unavailable(
                "persisted authority fence requires enabled executor",
            ));
        }
        if req.authority_store == AuthorityStore::Guarded {
            pre.push(guard(keys::lease_recovery(), snap));
            if req.authority_generation.is_none() {
                pre.push(guard(keys::authority_generation(), snap));
            }
        }
    }
    if let Some(generation) = req.authority_generation {
        let current = if let Some(lease) = req.lease {
            lease
                .value
                .authority_generation
                .ok_or_else(|| ServerError::unavailable("lease missing authority generation"))?
        } else {
            snap.get(&keys::authority_generation())
                .map(codec::decode_u64)
                .transpose()
                .map_err(corrupt)?
                .unwrap_or(0)
        };
        if current != generation {
            return Err(crate::authority::moved());
        }
        if tickets.as_ref().is_some_and(|tickets| {
            tickets
                .iter()
                .any(|ticket| ticket.authority_generation != Some(generation))
        }) {
            return Err(crate::authority::moved());
        }
        if req.lease.is_none() {
            pre.push(guard(keys::authority_generation(), snap));
        }
    }
    if req.layout_version {
        let key = keys::layout_version();
        match snap.get(&key).map(codec::decode_u32).transpose() {
            Ok(None) => puts.push(Write::Put(key.clone(), codec::encode_u32(LAYOUT_VERSION))),
            Ok(Some(LAYOUT_VERSION)) => {}
            Ok(Some(newer)) => return Err(corrupt(format!("layout version {newer}"))),
            Err(e) => return Err(corrupt(e)),
        }
        pre.push(guard(key, snap));
    }
    if req.mark_repo_known {
        let key = keys::repo_known(req.repo);
        if snap.get(&key).is_none() {
            pre.push(Precondition::Absent(key.clone()));
            puts.push(Write::Put(key, Value::default()));
        }
    }
    for charge in req.charges {
        plan_charge(charge, snap, clock.business_now_ms, &mut pre, &mut puts)?;
    }
    plan_namespace(req, snap, clock, &mut pre, &mut puts)?;

    let (on_commit, ref_puts, conflict) =
        decide_write_result(req, snap, clock, &mut pre, &mut puts)?;
    if conflict && req.replay.is_none() && req.charges.is_empty() && req.pending.is_none() {
        return Ok(Planned::Done(on_commit));
    }
    if !conflict {
        puts.extend(ref_puts);
    }
    if req.advance.is_some()
        || req.ref_index.is_some() && !req.refs.is_empty()
        || !conflict && req.implicit.is_some()
        || req.pending.is_some() && req.kind != WriteKind::BeginUpload
        || req.publication.is_some() && !req.refs.is_empty()
    {
        // One outbox per batch: an implicit consuming packmap write can
        // also carry D34 ref-index relays, and two builders seeded from the
        // same snapshot would emit colliding `os` rows.
        let mut outbox = OutboxBuilder::new(
            snap.get(&keys::outbox_sequence()),
            snap.get(&keys::outcome_backlog()),
        )
        .map_err(meta_error)?;
        if !conflict && let (Some(advance), Some(tickets)) = (&req.advance, tickets.as_deref()) {
            super::advance::plan_consumption(
                snap,
                advance,
                tickets,
                req.refs,
                clock,
                &mut pre,
                &mut puts,
                &mut outbox,
                req.publication.is_none(),
            )?;
        }
        if !conflict && let Some(implicit) = &req.implicit {
            crate::store::repo_storage::plan_count(
                implicit.repo_id,
                implicit.counted,
                implicit.source,
                implicit.shards,
                |key| snap.get(key),
                |pack| snap.get(&keys::membership(req.repo, pack)).is_some(),
                clock.plan_time_ms,
                &mut outbox,
                &mut pre,
                &mut puts,
            )
            .map_err(meta_error)?;
        }
        if !conflict {
            add_ref_index_relays(req, &mut outbox);
            if let Some(implicit) = &req.implicit
                && req.publication.is_none()
            {
                tickets::plan_membership(
                    req.repo,
                    implicit.packs,
                    implicit.source,
                    implicit.shards,
                    implicit.repo_id,
                    &mut outbox,
                    &mut puts,
                );
            }
        }
        if !conflict
            && req.rejection.is_none()
            && !req.refs.is_empty()
            && let Some(publication) = &req.publication
        {
            let name = crate::store::publication::sequence_ref(&req.refs[0].name);
            let pair = super::clearance::resulting_pair(req.repo, req.refs, snap)?;
            let additions = tickets
                .as_ref()
                .map(|ts| ts.iter().map(|t| t.pack_id).collect())
                .or_else(|| req.implicit.as_ref().map(|i| i.packs.to_vec()))
                .unwrap_or_default();
            let operation = req.replay.map_or([0; 32], |r| r.scope);
            let mut advance = publication.prepared.cloned().unwrap_or_else(|| {
                super::clearance::immediate(pair.clone(), operation, additions.clone())
            });
            if advance.value != pair {
                return Err(ServerError::unavailable("publication pair changed; retry"));
            }
            if publication.prepared.is_some() {
                // The proof was computed against one publication row. Guarding
                // only the row read now would validate evidence derived from
                // an older one, so any difference refuses before commit.
                let current = crate::store::publication::Publication::decode(
                    snap.get(&keys::publication(req.repo, &name)),
                )
                .map_err(meta_error)?;
                match publication.bound {
                    Some(bound) if bound == super::clearance::PreparedAt::of(&current) => {}
                    Some(_) => {
                        return Err(ServerError::unavailable("publication state changed; retry"));
                    }
                    None => return Err(internal("publication proof is not bound to its state")),
                }
            }
            advance.additions = additions;
            advance.operation = operation;
            crate::store::publication::append(
                publication.repo,
                &name,
                publication.source,
                publication.shards,
                snap.get(&keys::publication(req.repo, &name)),
                advance,
                req.refs.iter().any(|u| u.new.is_none()),
                &mut pre,
                &mut puts,
                &mut outbox,
            )
            .map_err(meta_error)?;
        }
        if let Some(pending) = req.pending {
            let record = if conflict {
                codec::ReservationV1::Aborted {
                    repository: pending.repository.clone(),
                    occurred_at_ms: clock.plan_time_ms,
                    reason: codec::AbortReason::RefConflict,
                    detail: String::new(),
                    procedure: pending.procedure,
                }
            } else {
                codec::ReservationV1::Committed {
                    repository: pending.repository.clone(),
                    occurred_at_ms: clock.plan_time_ms,
                    bytes_stored: 0,
                    new_to_repo: 0,
                    new_to_store: 0,
                    refs: req
                        .refs
                        .iter()
                        .map(|update| codec::OutcomeRef {
                            name: update.name.clone(),
                            new: update.new,
                            deleted: update.new.is_none(),
                        })
                        .collect(),
                    procedure: pending.procedure,
                }
            };
            outbox.outcome(
                &pending.rid,
                &pending.value,
                Terminal::new(record).map_err(meta_error)?,
            );
        }
        outbox.relay_at(clock.plan_time_ms);
        outbox.try_finish(&mut pre, &mut puts).map_err(meta_error)?;
    }
    let pending_index = req.pending.and_then(|pending| pre.iter().position(|condition| matches!(condition, Precondition::Equals(key, value) if key == &pending.key && value == &pending.value)));

    let replay_index = match req.replay {
        Some(replay) => {
            let index = pre.len();
            if let Some(done) =
                plan_replay(req.kind, replay, snap, &on_commit, &mut pre, &mut puts)?
            {
                if req.pending.is_some() {
                    return Err(ServerError::aborted_retryable(
                        "operation already in flight; retry",
                    )
                    .with_abort_cause(AbortCause::ReplayRace));
                }
                return Ok(Planned::Done(done));
            }
            Some(index)
        }
        None => None,
    };

    let budget = MAX_BATCH_OPS.saturating_sub(pre.len() + puts.len());
    let prune = plan_prune(req, snap, &deadline, budget)?;
    // Prune deletes go first: a later write to the same key wins.
    let mut writes = prune.as_ref().map(|b| b.writes.clone()).unwrap_or_default();
    writes.extend(puts);
    let prune_from = pre.len();
    if let Some(prune) = &prune {
        pre.extend(prune.preconditions.iter().skip(1).cloned());
    }
    Ok(Planned::Apply(Plan {
        batch: Batch {
            preconditions: pre,
            writes,
        },
        on_commit,
        replay_index,
        epoch_index,
        pending_index,
        prune,
        prune_from,
    }))
}

fn replayed_write(
    req: &WriteRequest<'_>,
    snap: &Snapshot,
) -> Result<Option<StoredResult>, ServerError> {
    // A same-nonce retry returns the stored commit before ticket validation.
    // A re-signed retry after that commit instead sees a closed ticket; the
    // client resolves it through BeginUpload AlreadyPresent and ReadRef.
    if req.kind != WriteKind::BeginUpload
        && req.advance.is_none()
        && (req.rejection.is_none() || req.kind == WriteKind::UploadCommit)
    {
        return Ok(None);
    }
    let Some(replay) = req.replay else {
        return Ok(None);
    };
    let record = snap
        .get(&keys::replay(&replay.scope))
        .map(codec::decode_replay_record)
        .transpose()
        .map_err(corrupt)?;
    super::replay_answer(classify(record.as_ref(), &replay.fingerprint))
}

/// Decide ref conflicts or the ticket result before writing replay state.
fn decide_write_result(
    req: &WriteRequest<'_>,
    snap: &Snapshot,
    clock: &PlanClock,
    pre: &mut Vec<Precondition>,
    puts: &mut Vec<Write>,
) -> Result<(StoredResult, Vec<Write>, bool), ServerError> {
    if req.kind != WriteKind::UploadCommit
        && let Some(rejection) = req.rejection
    {
        return Ok((StoredResult::Rejected(rejection.clone()), Vec::new(), false));
    }
    // Quota IS charged on a CAS conflict, as in vcs-worker, where the
    // charge commits in the same transaction as the replay row: a conflict
    // still costs an operation and a ledger row, so the charge bounds
    // ledger growth per signer. PRD §5.4's separate `Aborted` transaction
    // is for M3 payment reservations, not this abuse quota.
    let (outcome, ref_puts) = decide_refs(req, snap, pre)?;
    let conflict = outcome.is_some();
    let ticket_result = req
        .begin
        .map(|b| super::begin::plan(b, snap, clock, pre, puts))
        .transpose()?;
    let on_commit = if let Some(result) = outcome.or(ticket_result) {
        result
    } else {
        match req.kind {
            WriteKind::BeginUpload => {
                return Err(ServerError::internal(
                    "ticket plan failed",
                    "missing BeginUpload plan",
                ));
            }
            WriteKind::UpdateRef => StoredResult::UpdateRef(UpdateRefResult::Committed),
            WriteKind::AdvanceRefs => StoredResult::AdvanceRefs(AdvanceOutcome::Committed),
            WriteKind::UploadReserve | WriteKind::UploadCommit => {
                req.rejection.map_or(StoredResult::UploadPack, |r| {
                    StoredResult::Rejected(r.clone())
                })
            }
        }
    };
    Ok((on_commit, ref_puts, conflict))
}

/// The replay record's guard and writes. A new record is guarded
/// `Absent`, written with its expiry index; an upload's commit guards the
/// in-flight record it read with `Equals`. `Some(result)` when an upload
/// being committed already committed: nothing to write.
fn plan_replay(
    kind: WriteKind,
    replay: ReplayGuard,
    snap: &Snapshot,
    on_commit: &StoredResult,
    pre: &mut Vec<Precondition>,
    puts: &mut Vec<Write>,
) -> Result<Option<StoredResult>, ServerError> {
    let key = keys::replay(&replay.scope);
    let state = match kind {
        WriteKind::UploadReserve => ReplayState::InFlight { resumable: true },
        _ => ReplayState::Committed(on_commit.clone()),
    };
    let record = ReplayRecord {
        fingerprint: replay.fingerprint,
        expires_at_ms: replay.expires_at_ms,
        state,
    };
    if kind == WriteKind::UploadCommit {
        let stored = snap.get(&key);
        let decoded = stored.map(codec::decode_replay_record).transpose();
        match (
            classify(decoded.map_err(corrupt)?.as_ref(), &replay.fingerprint),
            stored,
        ) {
            (ReplayDecision::Resume, Some(value)) => {
                pre.push(Precondition::Equals(key.clone(), value.clone()));
            }
            (ReplayDecision::Return(result), _) => return Ok(Some(result)),
            (ReplayDecision::FingerprintMismatch, _) => {
                return Err(ServerError::invalid_argument(
                    "nonce reused for a different operation",
                ));
            }
            _ => {
                return Err(ServerError::aborted_retryable(
                    "upload reservation lost; retry",
                ));
            }
        }
        puts.push(Write::Put(key, codec::encode_replay_record(&record)));
        return Ok(None);
    }
    pre.push(Precondition::Absent(key.clone()));
    puts.push(Write::Put(key, codec::encode_replay_record(&record)));
    let expires = u64::try_from(replay.expires_at_ms).unwrap_or(0);
    puts.push(Write::Put(
        keys::replay_expiry(expires, &replay.scope),
        Value::default(),
    ));
    Ok(None)
}

/// `Equals` on the value `key` held, or `Absent`.
fn guard(key: Key, snap: &Snapshot) -> Precondition {
    match snap.get(&key) {
        Some(value) => Precondition::Equals(key, value.clone()),
        None => Precondition::Absent(key),
    }
}

fn corrupt(detail: impl core::fmt::Display) -> ServerError {
    let (line, err) = describe_and_map(StorageOp::MetaDecode, detail);
    tracing::warn!(detail = %line, "undecodable stored value");
    err
}

/// The grant's epoch no longer holds (M2; unreachable in M0).
pub(crate) fn epoch_moved() -> ServerError {
    ServerError::permission_denied("write grant epoch changed; re-authorize")
        .with_abort_cause(AbortCause::EpochMismatch)
}

/// Evaluate one charge and add its guard and writes, keeping the window
/// index (`qx`) one-to-one with live quota rows.
pub(super) fn plan_charge(
    charge: &QuotaCharge,
    snap: &Snapshot,
    now: i64,
    pre: &mut Vec<Precondition>,
    puts: &mut Vec<Write>,
) -> Result<(), ServerError> {
    let key = keys::quota(&charge.scope);
    let current = snap.get(&key).map(codec::decode_quota_state).transpose();
    let current = current.map_err(corrupt)?;
    let state = match evaluate_quota(current, now, charge.bytes, &charge.limits) {
        QuotaDecision::Allowed(state) => state,
        QuotaDecision::Exhausted { reason } => return Err(ServerError::resource_exhausted(reason)),
    };
    let start = |s: i64| u64::try_from(s).unwrap_or(0);
    let old_start = current.map(|c| c.window_start);
    if old_start != Some(state.window_start) {
        if let Some(old) = old_start {
            puts.push(Write::Delete(keys::quota_window(start(old), &charge.scope)));
        }
        let index = keys::quota_window(start(state.window_start), &charge.scope);
        puts.push(Write::Put(index, Value::default()));
    }
    pre.push(guard(key.clone(), snap));
    puts.push(Write::Put(key, codec::encode_quota_state(&state)));
    Ok(())
}

/// Decide the ref writes in order. On the first conflict, return its
/// result: only the refs decided so far are guarded.
fn decide_refs(
    req: &WriteRequest<'_>,
    snap: &Snapshot,
    pre: &mut Vec<Precondition>,
) -> Result<(Option<StoredResult>, Vec<Write>), ServerError> {
    let mut puts = Vec::new();
    for (i, update) in req.refs.iter().enumerate() {
        let key = keys::ref_key(req.repo, &update.name);
        let current = snap.get(&key).map(codec::decode_ref_id).transpose();
        let current = current.map_err(corrupt)?;
        if let Some(requirement) = req
            .grant
            .as_ref()
            .and_then(|grant| grant.presence_requirement.as_ref())
        {
            let required = match requirement {
                PresenceRequirement::Absent(name) if name == &update.name => Some(false),
                PresenceRequirement::Present(name) if name == &update.name => Some(true),
                _ => None,
            };
            if let Some(required) = required {
                if current.is_some() != required {
                    return Err(ServerError::permission_denied(
                        "write grant rejected: ref scope",
                    ));
                }
                pre.push(if required {
                    Precondition::Present(key.clone())
                } else {
                    Precondition::Absent(key.clone())
                });
            }
        }
        match evaluate_condition(current.as_ref(), &update.condition) {
            CasDecision::Committed => {
                // `Any` commits whatever the ref holds: nothing to guard.
                if update.condition != RefWriteCondition::Any {
                    pre.push(guard(key.clone(), snap));
                }
                puts.push(match update.new {
                    Some(id) => Write::Put(key, codec::encode_ref_id(&id)),
                    None => Write::Delete(key),
                });
            }
            CasDecision::Conflict(_) => {
                pre.push(guard(key, snap));
                let result = match (req.kind, i) {
                    (WriteKind::UpdateRef, _) => {
                        StoredResult::UpdateRef(UpdateRefResult::Conflict { current })
                    }
                    (WriteKind::AdvanceRefs, 0) => {
                        StoredResult::AdvanceRefs(AdvanceOutcome::PackmapConflict)
                    }
                    // Uploads write no refs.
                    _ => StoredResult::AdvanceRefs(AdvanceOutcome::HeadConflict),
                };
                return Ok((Some(result), Vec::new()));
            }
            CasDecision::Invalid(msg) => return Err(ServerError::invalid_argument(msg)),
        }
    }
    Ok((None, puts))
}

/// The opportunistic prune: every expired replay record, and every stale
/// quota window not charged by this write (the charge rolls it over
/// itself). A quota row is deleted only while it still holds the window
/// its index names, guarded by `Equals`. At most `budget` operations, so
/// the combined batch stays within [`MAX_BATCH_OPS`].
fn plan_prune(
    req: &WriteRequest<'_>,
    snap: &Snapshot,
    deadline: &Precondition,
    budget: usize,
) -> Result<Option<Batch>, ServerError> {
    let mut batch = Batch::new().require(deadline.clone());
    let used = |b: &Batch| b.preconditions.len() - 1 + b.writes.len();
    for (index, record) in &snap.expired_replays {
        if used(&batch) + 2 > budget {
            break;
        }
        batch = batch.delete(index.clone()).delete(record.clone());
    }
    let charged: Vec<Key> = req.charges.iter().map(|c| keys::quota(&c.scope)).collect();
    for (index, quota) in &snap.stale_quotas {
        if used(&batch) + 3 > budget {
            break;
        }
        if charged.contains(quota) {
            continue;
        }
        batch = batch.delete(index.clone());
        let Some(value) = snap.get(quota) else {
            continue;
        };
        let state = codec::decode_quota_state(value).map_err(corrupt)?;
        let Some(ParsedKey::QuotaWindow {
            window_start_ms: indexed,
            ..
        }) = keys::parse(index)
        else {
            return Err(corrupt("malformed quota window key"));
        };
        if u64::try_from(state.window_start).ok() == Some(indexed) {
            batch = batch
                .require(Precondition::Equals(quota.clone(), value.clone()))
                .delete(quota.clone());
        }
    }
    Ok((!batch.writes.is_empty()).then_some(batch))
}
