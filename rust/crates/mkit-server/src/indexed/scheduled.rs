//! The advance's side of scheduled verification (WP-4.8).
//!
//! In [`VerificationMode::Scheduled`](super::VerificationMode) an advance
//! never verifies. For each consumed ticket it reads the job and `vs` in one
//! call and answers as the native inline verifier would once the job has
//! finished, or `PendingVerification` while it has not. Nothing here is
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
        Kind, Outcome, Phase, VerifyJobV1, WINDOW_BYTES, decode_frame, encode_job, timer_reference,
    },
    resolve,
    state::VerificationV1,
    verify::{closure_error, packlist_error},
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
use std::collections::BTreeSet;

/// Owed children one advance reads per consumed pack before it gives up.
const MAX_LOCAL_CLOSURE_IDS: usize = 4096;
/// Rows per local frame lookup.
const LOCAL_PAGE: u32 = 256;
/// Owed children the advance looks up in the members itself, at most: the
/// slices already did, so this only catches a member that appeared since.
const MAX_ADVANCE_LOOKUP: usize = 64;

fn storage_failed() -> ServerError {
    ServerError::unavailable("object storage request failed")
}

fn now_ms(clock: &dyn Clock) -> u64 {
    u64::try_from(clock.now_ms()).unwrap_or(0)
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
    }
}

/// Create the job of `ticket` and its first timer in one batch. Losing the
/// race to another advance is success: the job exists.
pub async fn create_job<N: NamespaceStore>(
    store: &N,
    source: &Partition,
    repo: &RepoId,
    ticket: &TicketV1,
    ticket_id: Hash,
    clock: &dyn Clock,
) -> Result<(), ServerError> {
    let now = now_ms(clock);
    let job = VerifyJobV1::new(
        ticket_id,
        ticket.created_at_ms,
        ticket.bytes,
        super::checkpoint::DEFAULT_ENTRY_CAP,
    );
    let key = keys::verify_job(&repo.name, &ticket.pack_id);
    let batch = Batch::new()
        .require(Precondition::NotAfter(now.saturating_add(10_000)))
        .require(Precondition::Absent(key.clone()))
        .put(key, encode_job(&job))
        .put(
            keys::timer(
                now,
                kinds::VERIFY.get(),
                &timer_reference(&repo.name, &ticket.pack_id),
            ),
            Value::default(),
        );
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

/// The type tag of a member object, reconstructed from its member pack: a
/// head that no consumed pack holds must still be a commit, remix or tag.
#[allow(clippy::too_many_arguments)]
async fn member_head_type<B: BlobStore, N: NamespaceStore>(
    blobs: &B,
    store: &N,
    shards: &dyn ShardMap,
    repo: &RepoId,
    head: Hash,
    cfg: IndexedConfig,
    (now, created): (u64, u64),
    metrics: &dyn Metrics,
) -> Result<u8, ServerError> {
    let bound = cfg.relay_lag_bound_ms;
    let found = resolve::locate_split(store, shards, repo, &[head], metrics).await?;
    let located = match found.get(&head) {
        Some(Ok(Some(located))) => *located,
        Some(Err(_)) => {
            return Err(ServerError::invalid_argument("object index limit exceeded"));
        }
        _ => return Err(closure_error(now, created, bound)),
    };
    let (bytes, _) = resolve::member_object(
        blobs,
        store,
        shards,
        repo,
        head,
        located,
        cfg.max_delta_chain_depth,
        cfg.decode_budget,
        &mut resolve::MemberCache::default(),
        &mut BTreeSet::new(),
        metrics,
    )
    .await
    .map_err(|failure| failure.public_error(now, created, bound))?;
    let object = mkit_core::serialize::deserialize(&bytes)
        .map_err(|_| ServerError::invalid_argument("object hash mismatch"))?;
    Ok(object.object_type() as u8)
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
) -> Result<(), ServerError> {
    let now = now_ms(clock);
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
    let mut ready = Vec::with_capacity(tickets.len());
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
        let Some(job) = job else {
            create_job(store, source, repo, ticket, *id, clock).await?;
            pending = Some(pending.map_or(1_000, |p: u64| p.max(1_000)));
            continue;
        };
        if job.ticket_id != *id {
            // Another ticket's job still holds this pack's rows. Its own
            // timer removes them once that ticket is gone; kick it.
            let batch = Batch::new().put(
                keys::timer(
                    now,
                    kinds::VERIFY.get(),
                    &timer_reference(&repo.name, &ticket.pack_id),
                ),
                Value::default(),
            );
            let _ = store.apply(source, batch).await;
            pending = Some(pending.unwrap_or(0).max(retry_after(None)));
            continue;
        }
        if let Some(outcome) = job.outcome {
            return Err(outcome_error(outcome, now, ticket, bound));
        }
        let verified = matches!(
            &state,
            Some(VerificationV1::Verified { pack_len, .. }) if *pack_len == ticket.bytes
        );
        if !(job.usable() && verified) {
            pending = Some(pending.unwrap_or(0).max(retry_after(Some(&job))));
            continue;
        }
        ready.push(Consumed { ticket, job });
    }
    if let Some(ms) = pending {
        return Err(super::pending(ms));
    }
    let consumed: BTreeSet<Hash> = tickets.iter().map(|t| t.pack_id).collect();
    let packs: Vec<&Consumed<'_>> = ready.iter().filter(|c| c.job.kind == Kind::Pack).collect();

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

    // The member packs that satisfied a child must still be members: §12.2's
    // generation rule and GC, in the same batched read as the MKPL check.
    let satisfying: BTreeSet<Hash> = packs
        .iter()
        .flat_map(|c| c.job.satisfying.iter().copied())
        .filter(|pack| !consumed.contains(pack))
        .collect();
    let satisfying: Vec<Hash> = satisfying.into_iter().collect();
    for chunk in satisfying.chunks(MAX_LOOKUP_IDS) {
        let found = read::members_many(store, shards, repo, source, chunk)
            .await
            .map_err(|_| storage_failed())?;
        if found.iter().any(|member| !member) {
            let created = packs.first().map_or(now, |c| c.ticket.created_at_ms);
            return Err(closure_error(now, created, bound));
        }
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
    let created = tickets.first().map_or(now, |t| t.created_at_ms);
    let head_type = match head_type {
        Some(kind) => kind,
        None => {
            member_head_type(
                blobs,
                store,
                shards,
                repo,
                head,
                cfg,
                (now, created),
                metrics,
            )
            .await?
        }
    };
    if !matches!(
        head_type,
        t if t == ObjectType::Commit as u8 || t == ObjectType::Remix as u8 || t == ObjectType::Tag as u8
    ) {
        return Err(ServerError::invalid_argument("open closure"));
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
    Ok(())
}
