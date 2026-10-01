//! The advance's side of scheduled verification (WP-4.8).
//!
//! In [`VerificationMode::Scheduled`](super::VerificationMode) an advance
//! never verifies. For each consumed ticket it reads the job and `vs` in one
//! call and checks the persisted result once the job has finished, or answers
//! `PendingVerification` while it has not. Nothing here is
//! stored for replay, and the advance batch is unchanged.
//!
//! Per-pack facts are the job's: identity, signatures, depth, index rows and
//! extraction. What depends on the whole consumed set is checked here, over
//! the jobs' rows: closure (children not in any consumed pack's frame table
//! must be members, §9.3(c)), the head's type, and the MKPL rule. Every
//! answer depends only on repository state and ticket age (no oracle, §9.4).

use super::{
    IndexedConfig,
    checkpoint::{
        ExtractionGroupMember, Kind, Outcome, Phase, VerifyJobV1, WINDOW_BYTES, decode_frame,
        hydrate_job, timer_reference, write_job,
    },
    resolve,
    state::VerificationV1,
    verify::{StagedCommits, closure_error, packlist_error},
};
use crate::ServerError;
use crate::pipeline::ShardMap;
use crate::repo::RepoId;
use crate::rt::Clock;
use crate::store::{
    Batch, BatchOutcome, BlobStore, Cursor, NamespaceStore, Partition, Precondition, Value,
    codec::TicketV1, index::MAX_LOOKUP_IDS, keys, read,
};
use crate::telemetry::Metrics;
use crate::timers::registry::kinds;
use mkit_core::hash::Hash;
use mkit_core::object::ObjectType;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// Owed children one advance reads per consumed pack before it gives up.
const MAX_LOCAL_CLOSURE_IDS: usize = 4096;
/// Rows per local frame lookup.
const LOCAL_PAGE: u32 = 256;
/// Owed children the advance looks up in the members itself, at most: the
/// slices already did, so this only catches a member that appeared since.
const MAX_ADVANCE_LOOKUP: usize = 64;
/// Leaves 256 calls for Scheduled ancestry and 144 for the other stages.
const ADVANCE_CALLS: u32 = 600;

fn storage_failed() -> ServerError {
    ServerError::unavailable("object storage request failed")
}

/// The retry hint of a pending answer: the windows a job still has to read,
/// from the job's own progress only, clamped to one to sixty seconds.
fn retry_after(job: Option<&VerifyJobV1>) -> u64 {
    let Some(job) = job else {
        return 1_000;
    };
    let total = job.pack_len.div_ceil(WINDOW_BYTES);
    let left = match job.phase {
        Phase::Decode => total.saturating_sub(u64::from(job.windows_done) / 2),
        _ => 1,
    };
    left.saturating_mul(1_000)
        .saturating_add(1_000)
        .clamp(1_000, 60_000)
}

fn stored_error(code: &str, message: &str) -> ServerError {
    if code == "invalid_argument" {
        ServerError::invalid_argument(message.to_owned())
    } else {
        ServerError::failed_precondition(message.to_owned())
    }
}

/// The permanent answer for a terminal job outcome.
fn outcome_error(outcome: Outcome, now: u64, ticket: &TicketV1, bound: u64) -> ServerError {
    match outcome {
        Outcome::BaseMissing => resolve::missing_base(now, ticket.created_at_ms, bound),
        Outcome::BaseCapped => {
            ServerError::failed_precondition("delta base not available in this repository")
        }
        Outcome::ClosureCapped => ServerError::invalid_argument("object index limit exceeded"),
        Outcome::ExternalTooDeep => ServerError::invalid_argument("delta chain too deep"),
        Outcome::DecodeBudget => {
            ServerError::invalid_argument("pack exceeds indexed decode budget")
        }
        Outcome::ExtractionUnavailable => {
            ServerError::unavailable("pack extraction is not available on this deployment")
        }
        Outcome::Blocked | Outcome::ObjectBlocked => {
            ServerError::permission_denied("object blocked")
        }
        Outcome::ClosureMissing | Outcome::OpenClosure => {
            ServerError::invalid_argument("open closure")
        }
        Outcome::PacklistMissing => {
            ServerError::invalid_argument("packlist lists a pack that is not in this repository")
        }
    }
}

/// Create the job of `ticket` and its first timer in one batch. Losing the
/// race to another advance is success: the job exists.
#[allow(clippy::too_many_arguments)]
pub async fn create_job<N: NamespaceStore>(
    store: &N,
    source: &Partition,
    repo: &RepoId,
    ticket: &TicketV1,
    ticket_id: Hash,
    clock: &dyn Clock,
    prior: Option<Value>,
) -> Result<(), ServerError> {
    let now = u64::try_from(clock.now_ms()).unwrap_or(0);
    let mut job = VerifyJobV1::new(
        ticket_id,
        ticket.created_at_ms,
        ticket.bytes,
        super::checkpoint::DEFAULT_ENTRY_CAP,
    );
    let key = keys::verify_job(&repo.name, &ticket.pack_id);
    let batch = Batch::new()
        .require(Precondition::NotAfter(now.saturating_add(10_000)))
        .require(match &prior {
            Some(raw) => Precondition::Equals(key.clone(), raw.clone()),
            None => Precondition::Absent(key.clone()),
        })
        .put(
            keys::timer(
                now,
                kinds::VERIFY.get(),
                &timer_reference(&repo.name, &ticket.pack_id),
            ),
            Value::default(),
        );
    let batch = write_job(batch, &mut job, prior.as_ref(), &repo.name, &ticket.pack_id)
        .map_err(|_| storage_failed())?;
    match store
        .apply(source, batch)
        .await
        .map_err(|_| storage_failed())?
    {
        BatchOutcome::Committed | BatchOutcome::PreconditionFailed { .. } => Ok(()),
        BatchOutcome::DeadlinePassed { .. } => Err(super::pending(1_000)),
    }
}

/// What one consumed ticket's rows say.
struct Consumed<'a> {
    ticket: &'a TicketV1,
    job: VerifyJobV1,
}

/// A new Advance may release a failed group only before extraction effects.
/// The exact failed observation is included in the replacement transaction.
async fn failed_group<N: NamespaceStore>(
    store: &N,
    source: &Partition,
    repo: &RepoId,
    job: &VerifyJobV1,
) -> Result<Option<Precondition>, ServerError> {
    for member in &job.extraction_group {
        let ticket = keys::ticket(&member.ticket);
        if store
            .get(source, &ticket)
            .await
            .map_err(|_| storage_failed())?
            .is_none()
        {
            return Ok(Some(Precondition::Absent(ticket)));
        }
        let state = keys::verification(&repo.name, &member.pack);
        if let Some(raw) = store
            .get(source, &state)
            .await
            .map_err(|_| storage_failed())?
            && matches!(
                super::state::decode(&raw).map_err(|_| storage_failed())?,
                VerificationV1::Rejected { .. }
            )
        {
            return Ok(Some(Precondition::Equals(state, raw)));
        }
        let key = keys::verify_job(&repo.name, &member.pack);
        if let Some(raw) = store
            .get(source, &key)
            .await
            .map_err(|_| storage_failed())?
            && {
                let peer = super::checkpoint::decode_job(&raw).map_err(|_| storage_failed())?;
                peer.gone || peer.outcome.is_some()
            }
        {
            return Ok(Some(Precondition::Equals(key, raw)));
        }
    }
    Ok(None)
}

/// A finished source remains pinned while an older group uses its facts.
/// Guard every finished peer before changing that source's retention group.
async fn finished_peers<N: NamespaceStore>(
    store: &N,
    source: &Partition,
    repo: &RepoId,
    job: &VerifyJobV1,
) -> Result<Vec<Precondition>, ServerError> {
    let mut guards = Vec::new();
    for member in &job.extraction_group {
        if member.ticket == job.ticket_id {
            continue;
        }
        let key = keys::verify_job(&repo.name, &member.pack);
        let raw = store
            .get(source, &key)
            .await
            .map_err(|_| storage_failed())?;
        if let Some(raw) = raw {
            let peer = super::checkpoint::decode_job(&raw).map_err(|_| storage_failed())?;
            if !peer.gone && !peer.usable() && peer.outcome.is_none() {
                return Err(super::pending(retry_after(Some(&peer))));
            }
            guards.push(Precondition::Equals(key, raw));
        } else {
            guards.push(Precondition::Absent(key));
        }
    }
    Ok(guards)
}

/// Claim every new member together. Waiting on a foreign unfinished group
/// creates no partial group: A+B and B+C serialize before either can extract.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)] // One atomic group claim.
async fn claim_extraction_group<N: NamespaceStore>(
    store: &N,
    source: &Partition,
    repo: &RepoId,
    tickets: &[TicketV1],
    ticket_ids: &[Hash],
    rows: &[Option<Value>],
    clock: &dyn Clock,
    bound: u64,
    head: Hash,
) -> Result<bool, ServerError> {
    let now = u64::try_from(clock.now_ms()).unwrap_or(0);
    let jobs = tickets
        .iter()
        .enumerate()
        .map(|(i, _)| {
            rows[2 * i]
                .as_ref()
                .map(super::checkpoint::decode_job)
                .transpose()
                .map_err(|_| storage_failed())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let states = tickets
        .iter()
        .enumerate()
        .map(|(i, _)| {
            rows[2 * i + 1]
                .as_ref()
                .map(super::state::decode)
                .transpose()
                .map_err(|_| storage_failed())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut packs = BTreeSet::new();
    for (i, ticket) in tickets.iter().enumerate() {
        if let Some(VerificationV1::Rejected { code, message }) = &states[i] {
            return Err(stored_error(code, message));
        }
        if !packs.insert(ticket.pack_id)
            && !matches!(states[i], Some(VerificationV1::Verified { pack_len, .. })
                    if pack_len == ticket.bytes)
        {
            // BeginUpload cannot produce two live tickets with this binding.
            // Synthetic fresh duplicates follow native's Pending behavior;
            // never claim contradictory owners for one pack-keyed job.
            return Err(super::pending(1_000));
        }
    }
    let mut new =
        jobs.iter()
            .zip(ticket_ids)
            .enumerate()
            .map(|(i, (job, id))| {
                job.as_ref().is_none_or(|job| {
                job.gone || job.ticket_id != *id
                    && !(job.usable()
                        && job.pack_len == tickets[i].bytes
                        && matches!(states[i], Some(VerificationV1::Verified { pack_len, .. })
                            if pack_len == tickets[i].bytes)
                        && tickets.iter().zip(ticket_ids).any(|(ticket, owner)| {
                            *owner == job.ticket_id && ticket.pack_id == tickets[i].pack_id
                        }))
            })
            })
            .collect::<Vec<_>>();
    let mut release = Vec::new();
    for (i, job) in jobs.iter().enumerate() {
        let Some(job) = job else {
            continue;
        };
        if job.gone {
            continue;
        }
        let changed = job.extraction_head != Some(head)
            || job
                .extraction_group
                .iter()
                .map(|m| (m.pack, m.ticket))
                .ne(tickets
                    .iter()
                    .zip(ticket_ids)
                    .map(|(t, id)| (t.pack_id, *id)));
        let before_effects = job
            .extraction
            .as_ref()
            .is_none_or(|x| x.object.is_none() && (x.stage <= 2 || (10..=13).contains(&x.stage)));
        if changed
            && before_effects
            && let Some(witness) = failed_group(store, source, repo, job).await?
        {
            new[i] |= !job.usable();
            release.push(witness);
        } else if new[i] && !job.usable() && !(before_effects && job.outcome.is_some()) {
            // The ticket index includes the signer, so another signer can
            // legitimately hold a distinct ticket for this same pack.
            return Err(super::pending(retry_after(Some(job))));
        }
        if new[i] && job.usable() {
            release.extend(finished_peers(store, source, repo, job).await?);
        }
    }
    if !new.iter().any(|new| *new) {
        return Ok(false);
    }
    let mut group = Vec::with_capacity(tickets.len());
    for (i, (ticket, id)) in tickets.iter().zip(ticket_ids).enumerate() {
        if let Some(VerificationV1::Rejected { code, message }) = &states[i] {
            return Err(stored_error(code, message));
        }
        let already_verified = match &states[i] {
            Some(VerificationV1::Verified { pack_len, .. }) if *pack_len == ticket.bytes => true,
            Some(VerificationV1::Verified { .. }) => return Err(storage_failed()),
            _ => false,
        };
        if !new[i]
            && let Some(job) = &jobs[i]
            && !(job.usable() && already_verified)
        {
            if let Some(outcome) = job.outcome {
                return Err(outcome_error(outcome, now, ticket, bound));
            }
            // A coherent group was committed atomically. Finding an unfinished
            // existing member alongside an unclaimed one means a foreign group
            // owns it.
            return Err(super::pending(retry_after(Some(job))));
        }
        group.push(ExtractionGroupMember {
            pack: ticket.pack_id,
            ticket: *id,
            bytes: ticket.bytes,
            created_at_ms: ticket.created_at_ms,
            already_verified,
        });
    }
    let mut batch = Batch::new().require(Precondition::NotAfter(now.saturating_add(10_000)));
    for guard in release {
        if !batch.preconditions.contains(&guard) {
            batch.preconditions.push(guard);
        }
    }
    for (i, (ticket, id)) in tickets.iter().zip(ticket_ids).enumerate() {
        let job_key = keys::verify_job(&repo.name, &ticket.pack_id);
        let state_key = keys::verification(&repo.name, &ticket.pack_id);
        batch = batch.require(Precondition::Equals(
            keys::ticket(id),
            crate::store::codec::encode_ticket(ticket),
        ));
        for (key, raw) in [
            (job_key.clone(), rows[2 * i].as_ref()),
            (state_key, rows[2 * i + 1].as_ref()),
        ] {
            batch = batch.require(match raw {
                Some(raw) => Precondition::Equals(key, raw.clone()),
                None => Precondition::Absent(key),
            });
        }
        if new[i]
            && !tickets[..i]
                .iter()
                .any(|prior| prior.pack_id == ticket.pack_id)
        {
            let mut job = VerifyJobV1::new(
                *id,
                ticket.created_at_ms,
                ticket.bytes,
                super::checkpoint::DEFAULT_ENTRY_CAP,
            );
            job.extraction_group.clone_from(&group);
            job.extraction_head = Some(head);
            batch = write_job(
                batch,
                &mut job,
                rows[2 * i].as_ref(),
                &repo.name,
                &ticket.pack_id,
            )
            .map_err(|_| storage_failed())?
            .put(
                keys::timer(
                    now,
                    kinds::VERIFY.get(),
                    &timer_reference(&repo.name, &ticket.pack_id),
                ),
                Value::default(),
            );
        } else if let Some(prior) = &jobs[i]
            && prior.usable()
            && prior.extraction_group != group
        {
            for guard in finished_peers(store, source, repo, prior).await? {
                if !batch.preconditions.contains(&guard) {
                    batch.preconditions.push(guard);
                }
            }
            let mut retained = prior.clone();
            retained.extraction_group.clone_from(&group);
            batch = write_job(
                batch,
                &mut retained,
                rows[2 * i].as_ref(),
                &repo.name,
                &ticket.pack_id,
            )
            .map_err(|_| storage_failed())?;
        }
    }
    match store
        .apply(source, batch)
        .await
        .map_err(|_| storage_failed())?
    {
        BatchOutcome::Committed => Ok(true),
        BatchOutcome::PreconditionFailed { .. } | BatchOutcome::DeadlinePassed { .. } => {
            Err(super::pending(1_000))
        }
    }
}

/// Reuse frozen group totals, otherwise merge sorted frame streams.
/// One 64-row raw page is live at a time; retained stream heads are only IDs/sizes.
async fn union_totals<N: NamespaceStore>(
    store: &N,
    source: &Partition,
    repo: &RepoId,
    ready: &[Consumed<'_>],
) -> Result<(usize, u64), ServerError> {
    struct Stream {
        pack: Hash,
        cursor: Option<Cursor>,
        done: bool,
        rows: VecDeque<(Hash, u64)>,
    }
    let ids = ready
        .iter()
        .map(|held| held.ticket.pack_id)
        .collect::<BTreeSet<_>>();
    for x in ready.iter().filter_map(|held| held.job.extraction.as_ref()) {
        let members = x
            .sources
            .iter()
            .map(|s| s.member.pack)
            .collect::<BTreeSet<_>>();
        if x.stage == 2 && x.object.is_none() && members == ids {
            return Ok((
                usize::try_from(x.staged_objects).map_err(|_| storage_failed())?,
                x.staged_bytes,
            ));
        }
    }
    let mut streams = ready
        .iter()
        .filter(|c| c.job.kind == Kind::Pack)
        .map(|c| Stream {
            pack: c.ticket.pack_id,
            cursor: None,
            done: false,
            rows: VecDeque::new(),
        })
        .collect::<Vec<_>>();
    let (mut objects, mut bytes) = (0usize, 0u64);
    loop {
        for stream in &mut streams {
            if stream.rows.is_empty() && !stream.done {
                let (start, end) =
                    keys::verify_range(&repo.name, &stream.pack, Some(keys::VC_FRAME));
                let page = store
                    .scan(source, &start, &end, stream.cursor.as_ref(), 64)
                    .await
                    .map_err(|_| storage_failed())?;
                for (key, raw) in page.entries {
                    let Some(keys::ParsedKey::VerifyCursor { id: Some(id), .. }) =
                        keys::parse(&key)
                    else {
                        return Err(storage_failed());
                    };
                    let frame = decode_frame(&id, &raw).map_err(|_| storage_failed())?;
                    stream.rows.push_back((id, frame.value.decoded_size));
                }
                stream.done = page.next.is_none();
                stream.cursor = page.next;
            }
        }
        let Some((id, size)) = streams.iter().filter_map(|s| s.rows.front()).min().copied() else {
            break;
        };
        for stream in &mut streams {
            if stream
                .rows
                .front()
                .is_some_and(|(candidate, _)| *candidate == id)
            {
                let (_, actual_size) = stream.rows.pop_front().ok_or_else(storage_failed)?;
                if actual_size != size {
                    return Err(storage_failed());
                }
            }
        }
        objects = objects.checked_add(1).ok_or_else(storage_failed)?;
        bytes = bytes.checked_add(size).ok_or_else(storage_failed)?;
    }
    Ok((objects, bytes))
}

/// The history edges the fast-forward check reads (WP-4.17), in the shape the
/// inline verifier stages them: the parents of the commits reachable from
/// `head` in the consumed packs, at most `max_ancestry_commits` of them. A
/// commit past that bound is not in the map, so the walk treats it as a
/// member and, finding none, leaves the ancestry unproven (the write is
/// denied): the Worker's ancestry cap of WP-4.17.
async fn staged_commits<N: NamespaceStore>(
    store: &N,
    source: &Partition,
    repo: &RepoId,
    ready: &[Consumed<'_>],
    head: Hash,
    cfg: IndexedConfig,
    totals: (usize, u64),
) -> Result<StagedCommits, ServerError> {
    let limit = cfg
        .max_ancestry_commits
        .min(super::SCHEDULED_MAX_ANCESTRY_COMMITS) as usize;
    let packs: Vec<_> = ready.iter().filter(|c| c.job.kind == Kind::Pack).collect();
    let mut parents = BTreeMap::new();
    let mut seen = BTreeSet::from([head]);
    let mut frontier = VecDeque::from([head]);
    while let Some(id) = frontier.pop_front() {
        if parents.len() >= limit {
            break;
        }
        for held in &packs {
            let key = keys::verify_row(
                &repo.name,
                &held.ticket.pack_id,
                keys::VC_HISTORY,
                Some(&id),
            );
            let Some(raw) = store
                .get(source, &key)
                .await
                .map_err(|_| storage_failed())?
            else {
                continue;
            };
            if raw.as_bytes().len() % 32 != 0 {
                return Err(storage_failed());
            }
            let edges: Vec<Hash> = raw
                .as_bytes()
                .chunks_exact(32)
                .map(|p| p.try_into().unwrap_or_default())
                .collect();
            for parent in &edges {
                if seen.insert(*parent) {
                    frontier.push_back(*parent);
                }
            }
            parents.insert(id, edges);
            break;
        }
    }
    let (objects, bytes) = totals;
    Ok(StagedCommits {
        denial_ids: BTreeSet::new(),
        denial_packs: Vec::new(),
        parents,
        objects,
        external_bases: BTreeSet::new(),
        inspection: None,
        bytes,
    })
}

/// Check every consumed ticket of one advance: `Ok` only when each pack is
/// verified, indexed and extracted, and the set's closure, head and packlists
/// hold. No ticket is consumed and no advance row is written.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub async fn check<B: BlobStore, N: NamespaceStore>(
    blobs: &B,
    store: &N,
    shards: &dyn ShardMap,
    repo: &RepoId,
    source: &Partition,
    tickets: &[TicketV1],
    ticket_ids: &[Hash],
    head: Hash,
    cfg: IndexedConfig,
    clock: &dyn Clock,
    metrics: &dyn Metrics,
) -> Result<StagedCommits, ServerError> {
    check_optional(
        blobs, store, shards, repo, source, tickets, ticket_ids, head, cfg, clock, metrics, None,
    )
    .await
}

/// Check scheduled verification and collect bounded added-pack file metadata.
///
/// # Errors
/// Existing verification errors or the launch whole-advance index-limit refusal.
#[allow(clippy::too_many_arguments)]
pub async fn check_inspected<B: BlobStore, N: NamespaceStore>(
    blobs: &B,
    store: &N,
    shards: &dyn ShardMap,
    repo: &RepoId,
    source: &Partition,
    tickets: &[TicketV1],
    ticket_ids: &[Hash],
    head: Hash,
    cfg: IndexedConfig,
    clock: &dyn Clock,
    metrics: &dyn Metrics,
    inspection_limit: usize,
) -> Result<StagedCommits, ServerError> {
    check_optional(
        blobs,
        store,
        shards,
        repo,
        source,
        tickets,
        ticket_ids,
        head,
        cfg,
        clock,
        metrics,
        Some(inspection_limit),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn check_optional<B: BlobStore, N: NamespaceStore>(
    blobs: &B,
    store: &N,
    shards: &dyn ShardMap,
    repo: &RepoId,
    source: &Partition,
    tickets: &[TicketV1],
    ticket_ids: &[Hash],
    head: Hash,
    cfg: IndexedConfig,
    clock: &dyn Clock,
    metrics: &dyn Metrics,
    inspection_limit: Option<usize>,
) -> Result<StagedCommits, ServerError> {
    let budget = super::budget::SliceBudget::new(if inspection_limit.is_some() {
        300
    } else {
        ADVANCE_CALLS
    });
    let result = check_inner(
        &super::budget::Budgeted::new(blobs, &budget),
        &super::budget::Budgeted::new(store, &budget),
        shards,
        repo,
        source,
        tickets,
        ticket_ids,
        head,
        cfg,
        clock,
        metrics,
        inspection_limit,
    )
    .await;
    if result.is_err() && budget.remaining() == 0 {
        return Err(ServerError::invalid_argument("object index limit exceeded"));
    }
    result
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn check_inner<B: BlobStore, N: NamespaceStore>(
    blobs: &B,
    store: &N,
    shards: &dyn ShardMap,
    repo: &RepoId,
    source: &Partition,
    tickets: &[TicketV1],
    ticket_ids: &[Hash],
    head: Hash,
    cfg: IndexedConfig,
    clock: &dyn Clock,
    metrics: &dyn Metrics,
    inspection_limit: Option<usize>,
) -> Result<StagedCommits, ServerError> {
    // A same-build restart may lower the advertised cap. Refuse before any
    // job read, claim, extraction group or usable-result reuse.
    for ticket in tickets {
        super::check_pack_cap(ticket.bytes, cfg.max_pack_bytes)?;
    }
    let now = u64::try_from(clock.now_ms()).unwrap_or(0);
    let bound = cfg.relay_lag_bound_ms;
    let wanted: Vec<_> = tickets
        .iter()
        .flat_map(|t| {
            [
                keys::verify_job(&repo.name, &t.pack_id),
                keys::verification(&repo.name, &t.pack_id),
            ]
        })
        .collect();
    let rows = store
        .get_many(source, &wanted)
        .await
        .map_err(|_| storage_failed())?;
    if rows.len() != wanted.len() {
        return Err(storage_failed());
    }
    if claim_extraction_group(
        store, source, repo, tickets, ticket_ids, &rows, clock, bound, head,
    )
    .await?
    {
        return Err(super::pending(1_000));
    }
    let mut ready = Vec::with_capacity(tickets.len());
    let mut inspection_packs = Vec::new();
    let mut ready_packs = BTreeSet::new();
    let mut pending: Option<u64> = None;
    for (i, (ticket, id)) in tickets.iter().zip(ticket_ids).enumerate() {
        let job = rows[2 * i]
            .as_ref()
            .map(super::checkpoint::decode_job)
            .transpose()
            .map_err(|_| storage_failed())?;
        let state = rows[2 * i + 1]
            .as_ref()
            .map(super::state::decode)
            .transpose()
            .map_err(|_| storage_failed())?;
        if let Some(VerificationV1::Rejected { code, message }) = &state {
            return Err(stored_error(code, message));
        }
        let Some(mut job) = job.filter(|job| !job.gone) else {
            create_job(store, source, repo, ticket, *id, clock, rows[2 * i].clone()).await?;
            pending = Some(pending.map_or(1_000, |p: u64| p.max(1_000)));
            continue;
        };
        let verified = matches!(
            &state,
            Some(VerificationV1::Verified { pack_len, .. }) if *pack_len == ticket.bytes
        );
        let same_request_owner = tickets
            .iter()
            .zip(ticket_ids)
            .any(|(other, owner)| *owner == job.ticket_id && other.pack_id == ticket.pack_id);
        if job.ticket_id != *id
            && !(job.usable() && job.pack_len == ticket.bytes && verified && same_request_owner)
        {
            create_job(store, source, repo, ticket, *id, clock, rows[2 * i].clone()).await?;
            pending = Some(pending.unwrap_or(0).max(retry_after(None)));
            continue;
        }
        if let Some(outcome) = job.outcome {
            return Err(outcome_error(outcome, now, ticket, bound));
        }
        if !(job.usable() && verified) {
            pending = Some(pending.unwrap_or(0).max(retry_after(Some(&job))));
            continue;
        }
        // Pack facts and decode charges belong to the consumed pack union.
        // Every ticket is still validated and consumed by the advance planner.
        if ready_packs.insert(ticket.pack_id) {
            hydrate_job(store, source, &repo.name, &ticket.pack_id, &mut job)
                .await
                .map_err(|_| storage_failed())?;
            if inspection_limit.is_some() && job.kind == Kind::Pack {
                inspection_packs.push(super::inspection::ScheduledPack {
                    pack: ticket.pack_id,
                    job: rows[2 * i].clone().ok_or_else(storage_failed)?,
                    verification: rows[2 * i + 1].clone().ok_or_else(storage_failed)?,
                    decoded_bytes: job.in_pack_bytes,
                });
            }
            ready.push(Consumed { ticket, job });
        }
    }
    if let Some(ms) = pending {
        return Err(super::pending(ms));
    }
    let inspection_count = ready
        .iter()
        .filter(|c| c.job.kind == Kind::Pack)
        .fold(0_u64, |sum, c| sum.saturating_add(c.job.entries));
    if let Some(limit) = inspection_limit {
        let entries = ready
            .iter()
            .filter(|c| c.job.kind == Kind::Pack)
            .fold(0_u64, |sum, c| sum.saturating_add(c.job.entries));
        super::inspection::InspectionSet::new(limit).preflight(entries)?;
    }
    let totals = union_totals(store, source, repo, &ready).await?;
    let decoded_total = ready.iter().fold(totals.1, |sum, held| {
        sum.saturating_add(held.job.external_bytes)
    });
    if decoded_total > cfg.decode_budget {
        return Err(ServerError::invalid_argument(
            "pack exceeds indexed decode budget",
        ));
    }
    let consumed: BTreeSet<Hash> = tickets.iter().map(|t| t.pack_id).collect();
    let packs: Vec<&Consumed<'_>> = ready.iter().filter(|c| c.job.kind == Kind::Pack).collect();

    // The member packs that satisfied a child must still be members: §12.2's
    // generation rule and GC, in the same batched read as the MKPL check.
    let satisfying: BTreeSet<Hash> = packs
        .iter()
        .flat_map(|c| c.job.satisfying.iter().copied())
        .filter(|pack| !consumed.contains(pack))
        .collect();
    // A dependency age distinguishes base misses from closure misses. Include
    // all intermediate source packs, even when co-consumed in this advance.
    let mut dependencies: BTreeMap<Hash, Option<u64>> =
        satisfying.into_iter().map(|pack| (pack, None)).collect();
    for held in &packs {
        let (start, end) =
            keys::verify_range(&repo.name, &held.ticket.pack_id, Some(keys::VC_DEPENDENCY));
        let mut cursor = None;
        loop {
            let page = store
                .scan(source, &start, &end, cursor.as_ref(), LOCAL_PAGE)
                .await
                .map_err(|_| storage_failed())?;
            for (key, _) in page.entries {
                let Some(keys::ParsedKey::VerifyCursor { id: Some(pack), .. }) = keys::parse(&key)
                else {
                    return Err(storage_failed());
                };
                let age = dependencies.entry(pack).or_default();
                *age = Some(age.map_or(held.ticket.created_at_ms, |prior| {
                    prior.min(held.ticket.created_at_ms)
                }));
            }
            match page.next {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }
    }
    let satisfying: Vec<Hash> = dependencies.keys().copied().collect();
    let mut closure_missing = false;
    for chunk in satisfying.chunks(MAX_LOOKUP_IDS) {
        let found = read::members_many(store, shards, repo, source, chunk)
            .await
            .map_err(|_| storage_failed())?;
        if found.len() != chunk.len() {
            return Err(storage_failed());
        }
        for (pack, member) in chunk.iter().zip(found) {
            if member {
                continue;
            }
            if let Some(created) = dependencies[pack] {
                return Err(resolve::missing_base(now, created, bound));
            }
            closure_missing = true;
        }
    }

    if closure_missing {
        let created = packs.first().map_or(now, |c| c.ticket.created_at_ms);
        return Err(closure_error(now, created, bound));
    }

    // Children no consumed pack's frame table holds must be repository members.
    let mut open: Option<&Consumed<'_>> = None;
    for owner in packs.iter().filter(|c| c.job.owed > 0) {
        let (start, end) =
            keys::verify_range(&repo.name, &owner.ticket.pack_id, Some(keys::VC_CHILD));
        let (mut cursor, mut seen) = (None::<Cursor>, 0);
        loop {
            let page = store
                .scan(source, &start, &end, cursor.as_ref(), LOCAL_PAGE)
                .await
                .map_err(|_| storage_failed())?;
            let ids: Vec<Hash> = page
                .entries
                .iter()
                .filter_map(|(key, _)| match keys::parse(key) {
                    Some(keys::ParsedKey::VerifyCursor { id: Some(id), .. }) => Some(id),
                    _ => None,
                })
                .collect();
            seen += ids.len();
            if seen > MAX_LOCAL_CLOSURE_IDS {
                return Err(ServerError::invalid_argument("object index limit exceeded"));
            }
            let mut left: BTreeSet<Hash> = ids.into_iter().collect();
            for held in &packs {
                if left.is_empty() {
                    break;
                }
                let want: Vec<_> = left.iter().copied().collect();
                let keys: Vec<_> = want
                    .iter()
                    .map(|id| {
                        keys::verify_row(&repo.name, &held.ticket.pack_id, keys::VC_FRAME, Some(id))
                    })
                    .collect();
                let found = store
                    .get_many(source, &keys)
                    .await
                    .map_err(|_| storage_failed())?;
                for (id, row) in want.iter().zip(found) {
                    if row.is_some() {
                        left.remove(id);
                    }
                }
            }
            // A child that became a member after the job looked is found now,
            // as an inline verifier would (a bounded, repository-only lookup).
            if !left.is_empty() && left.len() <= MAX_ADVANCE_LOOKUP {
                let want: Vec<Hash> = left.iter().copied().collect();
                let found = resolve::locate_split(store, shards, repo, &want, metrics).await?;
                for id in want {
                    match found.get(&id) {
                        Some(Ok(Some(_))) => {
                            left.remove(&id);
                        }
                        Some(Err(_)) => {
                            return Err(ServerError::invalid_argument(
                                "object index limit exceeded",
                            ));
                        }
                        _ => {}
                    }
                }
            }
            if !left.is_empty() {
                open = Some(owner);
                break;
            }
            match page.next {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }
        if open.is_some() {
            break;
        }
    }
    if let Some(owner) = open {
        // Inside the window the child may still arrive; past it, only a
        // finished final recheck may say the closure is open.
        let final_done = packs
            .iter()
            .filter(|c| c.job.owed > 0)
            .all(|c| c.job.closure_final_at_ms.is_some());
        if !final_done && !resolve::lagged(now, owner.ticket.created_at_ms, bound) {
            return Err(super::pending(1_000));
        }
        return Err(closure_error(now, owner.ticket.created_at_ms, bound));
    }

    // The head is a commit, remix or tag: in a consumed pack's frame table, or
    // a member.
    let mut head_type = None;
    for held in &packs {
        let key = keys::verify_row(
            &repo.name,
            &held.ticket.pack_id,
            keys::VC_FRAME,
            Some(&head),
        );
        if let Some(value) = store
            .get(source, &key)
            .await
            .map_err(|_| storage_failed())?
        {
            head_type = Some(
                decode_frame(&head, &value)
                    .map_err(|_| storage_failed())?
                    .object_type,
            );
            break;
        }
    }
    let created = tickets.iter().map(|t| t.created_at_ms).min().unwrap_or(now);
    match head_type {
        Some(t)
            if t == ObjectType::Commit as u8
                || t == ObjectType::Remix as u8
                || t == ObjectType::Tag as u8 => {}
        Some(_) => return Err(ServerError::invalid_argument("open closure")),
        None => {
            super::verify::verify_member_head(
                blobs,
                store,
                shards,
                repo,
                head,
                created,
                (cfg, clock, metrics),
            )
            .await?;
        }
    }

    // MKPL: every listed pack is consumed or a member.
    for list in ready.iter().filter(|c| c.job.kind == Kind::Packlist) {
        let missing: Vec<Hash> = list
            .job
            .packlist
            .iter()
            .copied()
            .filter(|p| !consumed.contains(p))
            .collect();
        if missing.is_empty() {
            continue;
        }
        if missing.len() > MAX_LOOKUP_IDS {
            tracing::error!(reason = "ids", "packlist membership lookup capped");
            metrics.incr(
                crate::telemetry::METRIC_INDEX_LOOKUP_CAPPED,
                &[("reason", "ids")],
                1,
            );
            return Err(ServerError::invalid_argument("object index limit exceeded"));
        }
        let found = read::members_many(store, shards, repo, source, &missing)
            .await
            .map_err(|_| storage_failed())?;
        if found.iter().any(|member| !member) {
            return Err(packlist_error(now, list.ticket.created_at_ms, bound));
        }
    }
    let mut staged = staged_commits(store, source, repo, &ready, head, cfg, totals).await?;
    staged.denial_packs = ready.iter().map(|held| held.ticket.pack_id).collect();
    staged
        .denial_ids
        .extend(staged.denial_packs.iter().copied());
    // vc6 includes every intermediate external source, even for surplus entries
    // and sources co-consumed by this advance; publication must not waive them.
    staged.external_bases = dependencies
        .into_iter()
        .filter_map(|(pack, age)| age.map(|_| pack))
        .collect();
    if let Some(limit) = inspection_limit {
        let mut set = super::inspection::InspectionSet::new(limit);
        set.reserve_added_count(inspection_count)?;
        set.defer_scheduled(inspection_packs, source.clone());
        staged.inspection = Some(set);
    }
    Ok(staged)
}
