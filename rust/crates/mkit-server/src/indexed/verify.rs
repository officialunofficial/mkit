//! Inline verification before a ticketed advance commits.
use crate::store::keys;

use super::{
    IndexedConfig,
    classify::{self, UploadType},
    entries::{FrameMeta, index_entries},
    extract::{self, Extractor, Renew},
    resolve,
    state::{self, VerificationV1},
};
use crate::pipeline::ShardMap;
use crate::repo::RepoId;
use crate::store::{
    codec::TicketV1,
    index::{self, IndexEntry},
    read,
};
use crate::telemetry::Metrics;
use crate::{
    Batch, BatchOutcome, BlobBody, BlobKey, BlobStore, BoxFuture, Clock, MultipartBlobStore,
    NamespaceStore, Partition, Precondition, ServerError,
};
use futures::StreamExt as _;
use mkit_core::hash::{Hash, hash};
use mkit_core::object::Object;
use mkit_core::ops::graph::{ClosureMode, children};
use mkit_core::pack::{
    DecodedEntry, DeltaBaseSource, PackDecodeCursor, PackError, decode_entries_with,
    delta_base_hashes,
};
use mkit_core::sign::verify_object_signature;
use mkit_core::transfer::decode_packlist;
use mkit_core::verify::{ObjectSource, VerifyError, verify_push};
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

fn storage_failed() -> ServerError {
    ServerError::unavailable("object storage request failed")
}
fn bad_object() -> ServerError {
    ServerError::invalid_argument("object hash mismatch")
}
fn decode_failure(error: ServerError, already_verified: bool, pack: &Hash) -> ServerError {
    if already_verified {
        tracing::error!(pack = %mkit_core::hash::to_hex(pack), "verified pack failed decode recheck");
        ServerError::unavailable("verified pack content inconsistency")
    } else {
        error
    }
}
pub(super) fn closure_error(now: u64, created: u64, bound: u64) -> ServerError {
    if resolve::lagged(now, created, bound) {
        ServerError::unavailable("repository membership not yet visible")
    } else {
        ServerError::invalid_argument("open closure")
    }
}
pub(super) fn packlist_error(now: u64, created: u64, bound: u64) -> ServerError {
    if resolve::lagged(now, created, bound) {
        ServerError::unavailable("repository membership not yet visible")
    } else {
        ServerError::invalid_argument("packlist lists a pack that is not in this repository")
    }
}

/// What a verified advance staged: the history edges of its commits, remixes
/// and tags (a tag has none), and the decoded bytes it holds, which the
/// fast-forward walk charges against the decode budget (WP-4.17).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct StagedCommits {
    /// Object id to its `parents`; only remix sources are never followed.
    pub parents: BTreeMap<Hash, Vec<Hash>>,
    /// Every staged object, of any type.
    pub objects: usize,
    /// Total decoded bytes of the staged objects.
    pub bytes: u64,
    /// Every external source pack used by any consumed entry, including surplus objects.
    pub external_bases: BTreeSet<Hash>,
    /// Current decoded IDs and all reused chain sources for fresh denial at apply.
    pub denial_ids: BTreeSet<Hash>,
    /// Immutable verified inventories, including canonical manifest pages.
    pub denial_packs: Vec<Hash>,
    /// Complete added-pack inspection metadata, only for configured inspection.
    pub inspection: Option<super::inspection::InspectionSet>,
}

/// The `parents` of a history object; `None` for a blob, tree or manifest.
pub(crate) fn history_parents(object: &Object) -> Option<Vec<Hash>> {
    match object {
        Object::Commit(commit) => Some(commit.parents.clone()),
        Object::Remix(remix) => Some(remix.parents.clone()),
        Object::Tag(_) => Some(Vec::new()),
        _ => None,
    }
}

/// Reconstruct a located member head and require a commit, remix or tag,
/// which `verify_push` does not check for a known frontier.
#[allow(clippy::too_many_arguments)]
async fn check_member_head_type<B: BlobStore, S: NamespaceStore>(
    blobs: &B,
    store: &S,
    shards: &dyn ShardMap,
    repo: &RepoId,
    head: Hash,
    located: index::LocatedObject,
    created: u64,
    budget: u64,
    (cfg, clock, metrics): (IndexedConfig, &dyn Clock, &dyn Metrics),
) -> Result<(), ServerError> {
    let mut memo = resolve::MemberCache::default();
    let mut visiting = BTreeSet::new();
    let (bytes, _) = resolve::member_object(
        blobs,
        store,
        shards,
        repo,
        head,
        located,
        cfg.max_delta_chain_depth,
        budget,
        &mut memo,
        &mut visiting,
        metrics,
    )
    .await
    .map_err(|failure| failure.public_error(now_ms(clock), created, cfg.relay_lag_bound_ms))?;
    let object = mkit_core::serialize::deserialize(&bytes).map_err(|_| bad_object())?;
    if history_parents(&object).is_none() {
        return Err(ServerError::invalid_argument("open closure"));
    }
    Ok(())
}

/// A ticketless non-delete head must be a commit, remix or tag member of
/// this repository (SPEC-SERVER §9.7). The miss answer is repository-scoped
/// and `created` opens the §9.4 lag window.
#[allow(clippy::too_many_arguments)]
pub async fn verify_member_head<B: BlobStore, S: NamespaceStore>(
    blobs: &B,
    store: &S,
    shards: &dyn ShardMap,
    repo: &RepoId,
    head: Hash,
    created: u64,
    (cfg, clock, metrics): (IndexedConfig, &dyn Clock, &dyn Metrics),
) -> Result<(), ServerError> {
    let found = resolve::locate_split(store, shards, repo, &[head], metrics).await?;
    match found.get(&head) {
        Some(Ok(Some(located))) => {
            check_member_head_type(
                blobs,
                store,
                shards,
                repo,
                head,
                *located,
                created,
                cfg.decode_budget,
                (cfg, clock, metrics),
            )
            .await
        }
        Some(Err(_)) => Err(ServerError::invalid_argument("object index limit exceeded")),
        _ => Err(closure_error(
            now_ms(clock),
            created,
            cfg.relay_lag_bound_ms,
        )),
    }
}

async fn pack_bytes<B: BlobStore>(
    blobs: &B,
    ticket: &TicketV1,
    cap: u64,
) -> Result<Vec<u8>, ServerError> {
    super::check_pack_cap(ticket.bytes, cap)?;
    let body = blobs
        .get(&BlobKey::pack(ticket.pack_id), None)
        .await
        .map_err(|_| storage_failed())?
        .ok_or_else(storage_failed)?;
    let capacity = usize::try_from(ticket.bytes).map_err(|_| bad_object())?;
    let mut bytes = Vec::new();
    match body {
        BlobBody::Bytes(chunk) => {
            if chunk.len() != capacity {
                return Err(storage_failed());
            }
            bytes.extend_from_slice(&chunk);
        }
        BlobBody::Stream { len, mut stream } => {
            if len != ticket.bytes {
                return Err(storage_failed());
            }
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(|_| storage_failed())?;
                if bytes.len().saturating_add(chunk.len()) > capacity {
                    return Err(storage_failed());
                }
                bytes.extend_from_slice(&chunk);
            }
        }
    }
    if bytes.len() != capacity || hash(&bytes) != ticket.pack_id {
        return Err(bad_object());
    }
    Ok(bytes)
}

struct Bases(BTreeMap<Hash, Arc<[u8]>>);
impl DeltaBaseSource for Bases {
    const VERIFIED: bool = false;
    fn base(&mut self, id: &Hash) -> Result<Option<Vec<u8>>, PackError> {
        Ok(self.0.get(id).map(|bytes| bytes.to_vec()))
    }
}

struct StagedSource<'a>(&'a BTreeMap<Hash, (Vec<u8>, Object, u64)>);
impl ObjectSource for StagedSource<'_> {
    fn fetch(&mut self, id: &Hash) -> Result<Option<Cow<'_, [u8]>>, VerifyError> {
        Ok(self
            .0
            .get(id)
            .map(|(bytes, _, _)| Cow::Borrowed(bytes.as_slice())))
    }
}

struct PackWork {
    ticket: TicketV1,
    entries: Vec<IndexEntry>,
    needs_index: bool,
}

struct HeldLease {
    raw: crate::Value,
    until_ms: u64,
}

fn now_ms(clock: &dyn Clock) -> u64 {
    u64::try_from(clock.now_ms()).unwrap_or(0)
}

fn deadline(clock: &dyn Clock) -> u64 {
    now_ms(clock).saturating_add(10_000)
}

async fn renew_pending<S: NamespaceStore>(
    store: &S,
    source: &Partition,
    repo: &RepoId,
    pack: &Hash,
    acquired: &mut BTreeMap<Hash, HeldLease>,
    clock: &dyn Clock,
) -> Result<(), ServerError> {
    let Some(held) = acquired.get_mut(pack) else {
        return Ok(());
    };
    let now = now_ms(clock);
    if held.until_ms.saturating_sub(now) >= state::VERIFICATION_LEASE_MS / 2 {
        return Ok(());
    }
    let until_ms = now.saturating_add(state::VERIFICATION_LEASE_MS);
    let next = VerificationV1::Pending {
        lease_until_ms: until_ms,
    };
    if !state::write(
        store,
        source,
        &repo.name,
        pack,
        Some(&held.raw),
        &next,
        deadline(clock),
    )
    .await
    .map_err(|_| super::pending(1_000))?
    {
        return Err(super::pending(1_000));
    }
    held.raw = state::encode(&next);
    held.until_ms = until_ms;
    Ok(())
}

/// The verification leases this call holds, renewed by the extractor.
struct Lease<'a, S> {
    store: &'a S,
    source: &'a Partition,
    repo: &'a RepoId,
    acquired: &'a mut BTreeMap<Hash, HeldLease>,
    clock: &'a dyn Clock,
}

impl<S: NamespaceStore> Renew for Lease<'_, S> {
    fn renew(&mut self) -> BoxFuture<'_, Result<(), ServerError>> {
        Box::pin(renew_all_pending(
            self.store,
            self.source,
            self.repo,
            &mut *self.acquired,
            self.clock,
        ))
    }
}

async fn renew_all_pending<S: NamespaceStore>(
    store: &S,
    source: &Partition,
    repo: &RepoId,
    acquired: &mut BTreeMap<Hash, HeldLease>,
    clock: &dyn Clock,
) -> Result<(), ServerError> {
    for pack in acquired.keys().copied().collect::<Vec<_>>() {
        renew_pending(store, source, repo, &pack, acquired, clock).await?;
    }
    Ok(())
}

async fn reject_content<S: NamespaceStore>(
    store: &S,
    source: &Partition,
    repo: &RepoId,
    pack: &Hash,
    acquired: &BTreeMap<Hash, HeldLease>,
    message: &str,
    clock: &dyn Clock,
    metrics: &dyn Metrics,
) -> ServerError {
    let Some(held) = acquired.get(pack) else {
        tracing::error!(pack = %mkit_core::hash::to_hex(pack), "verified pack failed content recheck");
        return ServerError::unavailable("verified pack content inconsistency");
    };
    if !matches!(
        state::write(
            store,
            source,
            &repo.name,
            pack,
            Some(&held.raw),
            &VerificationV1::Rejected {
                code: "invalid_argument".into(),
                message: message.into(),
            },
            deadline(clock),
        )
        .await,
        Ok(true)
    ) {
        tracing::error!(pack = %mkit_core::hash::to_hex(pack), code = "invalid_argument", "failed to persist rejected verification state");
        metrics.incr(crate::telemetry::METRIC_INDEX_REJECTED_WRITE_FAILED, &[], 1);
    }
    ServerError::invalid_argument(message.to_owned())
}

/// Verify every staged object, then extract the large ones into the object
/// store before each pack's `Verified` state is written (WP-4.10), so
/// `Verified` implies extracted, held and holder recorded. `ticket_ids` are
/// the consuming tickets' ids, parallel to `tickets`. No ticket is consumed
/// and no advance row is written.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub async fn verify_ticketed<B: MultipartBlobStore, S: NamespaceStore>(
    blobs: &B,
    store: &S,
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
    verify_ticketed_optional(
        blobs, store, shards, repo, source, tickets, ticket_ids, head, cfg, clock, metrics, None,
    )
    .await
}

/// Verify ticketed packs while gathering their bounded inspection metadata.
///
/// # Errors
/// The same verification errors, plus the whole-advance inspection size refusal.
#[allow(clippy::too_many_arguments)]
pub async fn verify_ticketed_inspected<B: MultipartBlobStore, S: NamespaceStore>(
    blobs: &B,
    store: &S,
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
    verify_ticketed_optional(
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
async fn verify_ticketed_optional<B: MultipartBlobStore, S: NamespaceStore>(
    blobs: &B,
    store: &S,
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
    // Check before inspection preflight or verification-state handling, so a
    // cached Verified pack returns the same cap error as a fresh pack.
    for ticket in tickets {
        super::check_pack_cap(ticket.bytes, cfg.max_pack_bytes)?;
    }
    let inspection_count = if let Some(limit) = inspection_limit {
        Some(super::inspection::preflight_native(blobs, tickets, limit).await?)
    } else {
        None
    };
    let mut acquired = BTreeMap::new();
    let result = boxed_verify_ticketed_inner(
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
        &mut acquired,
        inspection_limit.zip(inspection_count),
    )
    .await;
    if result.is_err() {
        for (pack, held) in acquired {
            if let Err(error) =
                state::clear_pending(store, source, &repo.name, &pack, &held.raw, deadline(clock))
                    .await
            {
                tracing::error!(%error, "failed to release pending verification lease");
            }
        }
    }
    result
}

// Keep the large verification state out of the enclosing futures' stack
// temporaries. Allocation stays at this helper boundary on every target.
#[allow(clippy::too_many_arguments)]
fn boxed_verify_ticketed_inner<'a, B: MultipartBlobStore, S: NamespaceStore>(
    blobs: &'a B,
    store: &'a S,
    shards: &'a dyn ShardMap,
    repo: &'a RepoId,
    source: &'a Partition,
    tickets: &'a [TicketV1],
    ticket_ids: &'a [Hash],
    head: Hash,
    cfg: IndexedConfig,
    clock: &'a dyn Clock,
    metrics: &'a dyn Metrics,
    acquired: &'a mut BTreeMap<Hash, HeldLease>,
    inspection_limit: Option<(usize, u64)>,
) -> BoxFuture<'a, Result<StagedCommits, ServerError>> {
    Box::pin(verify_ticketed_inner(
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
        acquired,
        inspection_limit,
    ))
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn verify_ticketed_inner<B: MultipartBlobStore, S: NamespaceStore>(
    blobs: &B,
    store: &S,
    shards: &dyn ShardMap,
    repo: &RepoId,
    source: &Partition,
    tickets: &[TicketV1],
    ticket_ids: &[Hash],
    head: Hash,
    cfg: IndexedConfig,
    clock: &dyn Clock,
    metrics: &dyn Metrics,
    acquired: &mut BTreeMap<Hash, HeldLease>,
    inspection_limit: Option<(usize, u64)>,
) -> Result<StagedCommits, ServerError> {
    let now = now_ms(clock);
    let consumed: BTreeSet<_> = tickets.iter().map(|ticket| ticket.pack_id).collect();
    let mut staged: BTreeMap<Hash, (Vec<u8>, Object, u64)> = BTreeMap::new();
    let mut staged_bytes = 0u64;
    let mut external_bases = BTreeSet::new();
    let mut staged_owner = BTreeMap::new();
    let mut denial_ids = BTreeSet::new();
    let mut work = Vec::with_capacity(tickets.len());
    let mut raw_packs = BTreeSet::new();
    let mut packlists = Vec::new();
    for ticket in tickets {
        renew_all_pending(store, source, repo, acquired, clock).await?;
        let observed = state::read(store, source, &repo.name, &ticket.pack_id)
            .await
            .map_err(|_| storage_failed())?;
        let already_verified = match &observed {
            Some((VerificationV1::Verified { pack_len, .. }, _)) if *pack_len == ticket.bytes => {
                true
            }
            Some((VerificationV1::Verified { .. }, _)) => {
                tracing::error!(pack = %mkit_core::hash::to_hex(&ticket.pack_id), "verified pack length changed");
                return Err(ServerError::unavailable(
                    "verified pack content inconsistency",
                ));
            }
            Some((VerificationV1::Rejected { code, message }, _)) => {
                return Err(if code == "invalid_argument" {
                    ServerError::invalid_argument(message.clone())
                } else {
                    ServerError::failed_precondition(message.clone())
                });
            }
            Some((state, _)) if state::concurrent_pending(state, now_ms(clock)).is_some() => {
                return Err(super::pending(1_000));
            }
            _ => false,
        };
        let pending_until_ms = now_ms(clock).saturating_add(state::VERIFICATION_LEASE_MS);
        let pending_raw = if already_verified {
            None
        } else {
            let pending = VerificationV1::Pending {
                lease_until_ms: pending_until_ms,
            };
            let prior = observed.as_ref().map(|(_, raw)| raw);
            if !state::write(
                store,
                source,
                &repo.name,
                &ticket.pack_id,
                prior,
                &pending,
                deadline(clock),
            )
            .await
            .map_err(|_| storage_failed())?
            {
                return Err(super::pending(1_000));
            }
            Some(state::encode(&pending))
        };
        if let Some(raw) = &pending_raw {
            acquired.insert(
                ticket.pack_id,
                HeldLease {
                    raw: raw.clone(),
                    until_ms: pending_until_ms,
                },
            );
        }
        let bytes = match pack_bytes(blobs, ticket, cfg.max_pack_bytes).await {
            Ok(bytes) => bytes,
            Err(_) if already_verified => {
                tracing::error!(pack = %mkit_core::hash::to_hex(&ticket.pack_id), "verified pack bytes changed");
                return Err(ServerError::unavailable(
                    "verified pack content inconsistency",
                ));
            }
            Err(error) if error.public_message() == "object hash mismatch" => {
                return Err(reject_content(
                    store,
                    source,
                    repo,
                    &ticket.pack_id,
                    acquired,
                    "object hash mismatch",
                    clock,
                    metrics,
                )
                .await);
            }
            Err(error) => return Err(error),
        };
        let Ok(kind) = classify::classify(&bytes) else {
            return Err(reject_content(
                store,
                source,
                repo,
                &ticket.pack_id,
                acquired,
                "unknown upload type",
                clock,
                metrics,
            )
            .await);
        };
        match kind {
            UploadType::Packlist => {
                let Ok(list) = decode_packlist(&bytes) else {
                    return Err(reject_content(
                        store,
                        source,
                        repo,
                        &ticket.pack_id,
                        acquired,
                        "object hash mismatch",
                        clock,
                        metrics,
                    )
                    .await);
                };
                crate::takedown::inventory::stage_packlist(
                    store,
                    &ticket.pack_id,
                    ticket.bytes,
                    list.prev,
                    &list.packs,
                    now_ms(clock),
                )
                .await
                .map_err(|_| storage_failed())?;
                for child in &list.packs {
                    crate::takedown::inventory::dependency(
                        store,
                        &ticket.pack_id,
                        ticket.bytes,
                        child,
                        now_ms(clock),
                    )
                    .await
                    .map_err(|_| storage_failed())?;
                }
                packlists.push((ticket.created_at_ms, list.packs));
                work.push(PackWork {
                    ticket: ticket.clone(),
                    entries: Vec::new(),
                    needs_index: pending_raw.is_some(),
                });
            }
            UploadType::Pack => {
                raw_packs.insert(ticket.pack_id);
                let Ok(base_ids) = delta_base_hashes(&bytes) else {
                    return Err(reject_content(
                        store,
                        source,
                        repo,
                        &ticket.pack_id,
                        acquired,
                        "object hash mismatch",
                        clock,
                        metrics,
                    )
                    .await);
                };
                // Locate all syntactic candidates in bounded batches. A
                // candidate's answer is used only if the decoder actually
                // asks for it; in-pack links never fetch member bytes or
                // emit capped-lookup metrics.
                let prelocated = resolve::locate_split_quiet(store, shards, repo, &base_ids)
                    .await
                    .ok();
                renew_all_pending(store, source, repo, acquired, clock).await?;
                let mut bases = Bases(BTreeMap::new());
                let mut depths = BTreeMap::new();
                let mut memo = resolve::MemberCache::default();
                let mut visiting = BTreeSet::new();
                // The resumable core decoder identifies actual external
                // bases in one pass. An earlier in-pack frame wins over any
                // matching member, so no such member frame is fetched.
                if let Ok(mut probe) = PackDecodeCursor::new(
                    &bytes,
                    super::geometry::entry_limits(cfg.decode_budget.saturating_sub(staged_bytes)),
                ) {
                    let mut probe_depths = BTreeMap::new();
                    loop {
                        let result = probe.resume(&mut bases, |entry| {
                            let hops = entry.delta_base.map_or(0, |base| {
                                probe_depths
                                    .get(&base)
                                    .copied()
                                    .unwrap_or(0_u32)
                                    .saturating_add(1)
                            });
                            if hops > cfg.max_delta_chain_depth {
                                return Err(PackError::PackfileTooLarge);
                            }
                            probe_depths.entry(entry.id).or_insert(hops);
                            Ok(())
                        });
                        renew_all_pending(store, source, repo, acquired, clock).await?;
                        let Err(PackError::DeltaBaseMissing(hex)) = result else {
                            break;
                        };
                        let base = mkit_core::hash::from_hex(&hex).map_err(|_| {
                            decode_failure(bad_object(), already_verified, &ticket.pack_id)
                        })?;
                        if !base_ids.contains(&base) || bases.0.contains_key(&base) {
                            return Err(decode_failure(
                                bad_object(),
                                already_verified,
                                &ticket.pack_id,
                            ));
                        }
                        let cached = prelocated
                            .as_ref()
                            .and_then(|answers| answers.get(&base))
                            .copied();
                        let answer = if matches!(cached, Some(Ok(Some(_)))) {
                            cached
                        } else {
                            let found =
                                resolve::locate_split(store, shards, repo, &[base], metrics)
                                    .await
                                    .map_err(|error| {
                                        decode_failure(error, already_verified, &ticket.pack_id)
                                    })?;
                            found.get(&base).copied()
                        };
                        let located = match answer {
                            Some(Ok(Some(located))) => located,
                            Some(Err(_)) => {
                                return Err(decode_failure(
                                    resolve::ResolveFailure::Capped.public_error(
                                        now_ms(clock),
                                        ticket.created_at_ms,
                                        cfg.relay_lag_bound_ms,
                                    ),
                                    already_verified,
                                    &ticket.pack_id,
                                ));
                            }
                            _ => {
                                return Err(decode_failure(
                                    resolve::missing_base(
                                        now_ms(clock),
                                        ticket.created_at_ms,
                                        cfg.relay_lag_bound_ms,
                                    ),
                                    already_verified,
                                    &ticket.pack_id,
                                ));
                            }
                        };
                        super::geometry::check_entry(
                            located.value.decoded_size,
                            located.value.frame_length,
                        )
                        .map_err(|_| {
                            ServerError::invalid_argument(resolve::DECODE_BUDGET_MESSAGE)
                        })?;
                        let budget = cfg.decode_budget.saturating_sub(staged_bytes);
                        let (canonical, depth) = resolve::member_object(
                            blobs,
                            store,
                            shards,
                            repo,
                            base,
                            located,
                            cfg.max_delta_chain_depth,
                            budget,
                            &mut memo,
                            &mut visiting,
                            metrics,
                        )
                        .await
                        .map_err(|failure| {
                            decode_failure(
                                failure.public_error(
                                    now_ms(clock),
                                    ticket.created_at_ms,
                                    cfg.relay_lag_bound_ms,
                                ),
                                already_verified,
                                &ticket.pack_id,
                            )
                        })?;
                        renew_all_pending(store, source, repo, acquired, clock).await?;
                        for ((id, _, _), _) in memo.rows() {
                            crate::takedown::inventory::dependency(
                                store,
                                &ticket.pack_id,
                                ticket.bytes,
                                id,
                                now_ms(clock),
                            )
                            .await
                            .map_err(|_| storage_failed())?;
                        }
                        bases.0.insert(base, canonical);
                        depths.insert(base, depth);
                        probe
                            .set_max_decoded_bytes(
                                cfg.decode_budget.saturating_sub(
                                    staged_bytes.saturating_add(memo.retained_bytes()),
                                ),
                            )
                            .map_err(|_| {
                                decode_failure(
                                    ServerError::invalid_argument(
                                        "pack exceeds indexed decode budget",
                                    ),
                                    already_verified,
                                    &ticket.pack_id,
                                )
                            })?;
                    }
                }
                let mut frames = Vec::new();
                let mut local_depths: BTreeMap<Hash, (u32, Option<Hash>)> = BTreeMap::new();
                let mut in_pack_depth_exceeded = false;
                let mut external_depth_exceeded = false;
                let decoded = decode_entries_with(
                    &bytes,
                    &mut bases,
                    super::geometry::entry_limits(
                        cfg.decode_budget
                            .saturating_sub(staged_bytes.saturating_add(memo.retained_bytes())),
                    ),
                    |entry: DecodedEntry<'_>| {
                        super::geometry::check_entry(entry.bytes.len() as u64, entry.frame_length)?;
                        let (hops, external) = match entry.delta_base {
                            None => (0, None),
                            Some(base) => match local_depths.get(&base) {
                                Some((depth, external)) => (depth.saturating_add(1), *external),
                                None => (1, Some(base)),
                            },
                        };
                        let total = hops.saturating_add(
                            external
                                .and_then(|base| depths.get(&base).copied())
                                .unwrap_or(0),
                        );
                        if hops > cfg.max_delta_chain_depth {
                            in_pack_depth_exceeded = true;
                            return Err(PackError::PackfileTooLarge);
                        }
                        if total > cfg.max_delta_chain_depth {
                            external_depth_exceeded = true;
                            return Err(PackError::PackfileTooLarge);
                        }
                        local_depths.entry(entry.id).or_insert((hops, external));
                        frames.push(FrameMeta {
                            id: entry.id,
                            frame_offset: entry.frame_offset,
                            frame_length: entry.frame_length,
                            wire_type: entry.wire_type,
                            delta_base: entry.delta_base,
                            decoded_size: entry.bytes.len() as u64,
                        });
                        if let std::collections::btree_map::Entry::Vacant(slot) =
                            staged.entry(entry.id)
                        {
                            staged_bytes = staged_bytes
                                .checked_add(entry.bytes.len() as u64)
                                .ok_or(PackError::PackfileTooLarge)?;
                            if staged_bytes.saturating_add(memo.retained_bytes())
                                > cfg.decode_budget
                            {
                                return Err(PackError::PackfileTooLarge);
                            }
                            slot.insert((entry.bytes.to_vec(), entry.object, ticket.created_at_ms));
                        }
                        staged_owner.entry(entry.id).or_insert(ticket.pack_id);
                        Ok(())
                    },
                );
                renew_all_pending(store, source, repo, acquired, clock).await?;
                if let Err(error) = decoded {
                    if in_pack_depth_exceeded {
                        return Err(reject_content(
                            store,
                            source,
                            repo,
                            &ticket.pack_id,
                            acquired,
                            "delta chain too deep",
                            clock,
                            metrics,
                        )
                        .await);
                    }
                    if external_depth_exceeded {
                        return Err(decode_failure(
                            ServerError::invalid_argument("delta chain too deep"),
                            already_verified,
                            &ticket.pack_id,
                        ));
                    }
                    let mapped = if let PackError::DeltaBaseMissing(hex) = &error {
                        let _ = hex;
                        resolve::missing_base(
                            now_ms(clock),
                            ticket.created_at_ms,
                            cfg.relay_lag_bound_ms,
                        )
                    } else if matches!(error, PackError::PackfileTooLarge) {
                        ServerError::invalid_argument("pack exceeds indexed decode budget")
                    } else {
                        bad_object()
                    };
                    if mapped.public_message() == "object hash mismatch" {
                        return Err(reject_content(
                            store,
                            source,
                            repo,
                            &ticket.pack_id,
                            acquired,
                            "object hash mismatch",
                            clock,
                            metrics,
                        )
                        .await);
                    }
                    return Err(decode_failure(mapped, already_verified, &ticket.pack_id));
                }
                external_bases.extend(memo.rows().map(|((_, pack, _), _)| *pack));
                let Ok(entries) = index_entries(&frames, cfg.max_delta_chain_depth) else {
                    return Err(reject_content(
                        store,
                        source,
                        repo,
                        &ticket.pack_id,
                        acquired,
                        "delta chain too deep",
                        clock,
                        metrics,
                    )
                    .await);
                };
                work.push(PackWork {
                    ticket: ticket.clone(),
                    entries,
                    needs_index: pending_raw.is_some(),
                });
            }
        }
    }
    for id in staged.keys() {
        crate::takedown::denial::require_clear(store, id).await?;
    }
    for (id, (_, object, _)) in &staged {
        if verify_object_signature(object).is_err() {
            let owner = staged_owner[id];
            return Err(reject_content(
                store,
                source,
                repo,
                &owner,
                acquired,
                "bad signature",
                clock,
                metrics,
            )
            .await);
        }
    }
    let mut needed: BTreeMap<Hash, u64> = BTreeMap::new();
    for (_, object, created) in staged.values() {
        for child in children(object, ClosureMode::History) {
            if !staged.contains_key(&child) {
                needed.entry(child).or_insert(*created);
            }
        }
    }
    if !staged.contains_key(&head) {
        needed.entry(head).or_insert_with(|| {
            tickets
                .iter()
                .map(|ticket| ticket.created_at_ms)
                .min()
                .unwrap_or(now)
        });
    }
    let mut member_head = None;
    if !needed.is_empty() {
        let ids: Vec<_> = needed.keys().copied().collect();
        let found = resolve::locate_split(store, shards, repo, &ids, metrics).await?;
        for (id, created) in needed {
            match found.get(&id) {
                Some(Ok(Some(located))) => {
                    if id == head {
                        member_head = Some((*located, created));
                    }
                }
                Some(Err(_)) => {
                    return Err(ServerError::invalid_argument("object index limit exceeded"));
                }
                _ => {
                    return Err(closure_error(
                        u64::try_from(clock.now_ms()).unwrap_or(0),
                        created,
                        cfg.relay_lag_bound_ms,
                    ));
                }
            }
        }
    }
    // `verify_push` skips known frontiers, including a known root's type.
    // Reconstruct a member head once so a blob/tree cannot become a tip.
    if let Some((located, created)) = member_head {
        check_member_head_type(
            blobs,
            store,
            shards,
            repo,
            head,
            located,
            created,
            cfg.decode_budget.saturating_sub(staged_bytes),
            (cfg, clock, metrics),
        )
        .await?;
    }
    let staged_ids: BTreeSet<_> = staged.keys().copied().collect();
    let report = verify_push(
        &[head],
        ClosureMode::History,
        &mut StagedSource(&staged),
        |id| !staged_ids.contains(id),
    )
    .map_err(|error| match error {
        VerifyError::TooManyClosureObjects => {
            ServerError::invalid_argument("object index limit exceeded")
        }
        VerifyError::ClosureRootWrongType(_) => ServerError::invalid_argument("open closure"),
        VerifyError::Store(_) => storage_failed(),
        _ => bad_object(),
    })?;
    if !report.bad_signatures.is_empty() {
        return Err(ServerError::invalid_argument("bad signature"));
    }
    if !report.corrupt.is_empty() {
        return Err(bad_object());
    }
    if !report.missing.is_empty() || !report.bad_tips.is_empty() {
        return Err(ServerError::invalid_argument("open closure"));
    }
    for (created, packs) in packlists {
        let missing: Vec<_> = packs
            .into_iter()
            .filter(|pack| !consumed.contains(pack))
            .collect();
        if missing.is_empty() {
            continue;
        }
        if missing.len() > index::MAX_LOOKUP_IDS {
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
            return Err(packlist_error(
                u64::try_from(clock.now_ms()).unwrap_or(0),
                created,
                cfg.relay_lag_bound_ms,
            ));
        }
    }
    let selected = extract::select(&staged, cfg.extract_min_bytes);
    if extract::selected_bytes(&staged, &selected) > cfg.effective_max_extract_bytes() {
        return Err(ServerError::invalid_argument(
            "pack exceeds indexed decode budget",
        ));
    }
    // One extractor per advance: its resolution counter is shared by every
    // manifest and chunk (R-163).
    let extractor = Extractor {
        blobs,
        store,
        shards,
        repo,
        cfg,
        clock,
        metrics,
        staged: &staged,
        staged_bytes,
        resolved: std::sync::atomic::AtomicU64::new(0),
        denial_pack: std::sync::Mutex::new(None),
    };
    for pack in &work {
        if !pack.needs_index {
            continue;
        }
        for entry in &pack.entries {
            let (_, object, _) = staged.get(&entry.object).ok_or_else(storage_failed)?;
            crate::takedown::inventory::stage(
                store,
                &pack.ticket.pack_id,
                pack.ticket.bytes,
                &entry.object,
                object,
                entry.value.delta_base,
                now_ms(clock),
            )
            .await
            .map_err(|_| storage_failed())?;
        }
        let plan = index::plan_index_rows_direct(
            shards,
            repo,
            source,
            &pack.ticket.pack_id,
            &pack.entries,
            now,
        )
        .map_err(|_| storage_failed())?;
        for direct in plan.direct {
            renew_all_pending(store, source, repo, acquired, clock).await?;
            let mut batch = Batch::new().require(Precondition::NotAfter(deadline(clock)));
            for (key, value) in direct.puts {
                if let Some(keys::ParsedKey::ObjectIndex { object, .. }) = keys::parse(&key) {
                    crate::takedown::denial::require_clear(store, &object).await?;
                }
                batch = batch.put(key, value);
            }
            if !matches!(
                store.apply(&direct.target, batch).await,
                Ok(BatchOutcome::Committed)
            ) {
                return Err(super::pending(1_000));
            }
        }
        // Extract this pack's objects (those it introduced) after its index
        // rows and before `Verified`. A retry re-takes each hold and skips
        // what is stored.
        let ticket_id = tickets
            .iter()
            .zip(ticket_ids)
            .find_map(|(t, id)| (t.pack_id == pack.ticket.pack_id).then_some(id))
            .ok_or_else(|| {
                ServerError::internal(
                    "object storage request failed",
                    "missing consumed ticket id",
                )
            })?;
        let mut lease = Lease {
            store,
            source,
            repo,
            acquired,
            clock,
        };
        *extractor.denial_pack.lock().map_err(|_| storage_failed())? =
            Some((pack.ticket.pack_id, pack.ticket.bytes));
        for (id, kind) in &selected {
            if staged_owner.get(id) == Some(&pack.ticket.pack_id) {
                // Boxed: the extraction future is large and rarely awaited.
                match Box::pin(extractor.extract(*id, *kind, ticket_id, &mut lease)).await {
                    Ok(()) => {}
                    Err(extract::ExtractError::Server(error)) => return Err(error),
                    // A manifest this push carries does not match its chunks:
                    // content-intrinsic, so the verdict is persisted (§9.8).
                    Err(extract::ExtractError::Content) => {
                        return Err(reject_content(
                            store,
                            source,
                            repo,
                            &pack.ticket.pack_id,
                            lease.acquired,
                            extract::MALFORMED_MESSAGE,
                            clock,
                            metrics,
                        )
                        .await);
                    }
                }
            }
        }
        crate::takedown::inventory::complete(
            store,
            &pack.ticket.pack_id,
            pack.ticket.bytes,
            now_ms(clock),
        )
        .await
        .map_err(|_| storage_failed())?;
        renew_all_pending(store, source, repo, acquired, clock).await?;
        let raw = &acquired[&pack.ticket.pack_id].raw;
        if !state::write(
            store,
            source,
            &repo.name,
            &pack.ticket.pack_id,
            Some(raw),
            &VerificationV1::Verified {
                pack_len: pack.ticket.bytes,
                verified_at_ms: now_ms(clock),
                publication: None,
            },
            deadline(clock),
        )
        .await
        .map_err(|_| super::pending(1_000))?
        {
            return Err(super::pending(1_000));
        }
        acquired.remove(&pack.ticket.pack_id);
    }
    let parents = staged
        .iter()
        .filter_map(|(id, (_, object, _))| Some((*id, history_parents(object)?)))
        .collect();
    denial_ids.extend(tickets.iter().map(|ticket| ticket.pack_id));
    let objects = staged.len();
    let mut inspection =
        inspection_limit.map(|(limit, _)| super::inspection::InspectionSet::new(limit));
    if let Some(set) = &mut inspection {
        if let Some((_, count)) = inspection_limit {
            set.reserve_added_count(count)?;
        }
        let entries = staged
            .into_iter()
            .map(|(id, (bytes, object, _))| {
                let object_type = object.object_type() as u8;
                super::inspection::NativeEntry {
                    id,
                    size: bytes.len() as u64,
                    object_type,
                }
            })
            .collect();
        for pack in raw_packs {
            set.add_raw_pack(pack);
        }
        set.defer_native(entries);
    }
    Ok(StagedCommits {
        denial_packs: tickets.iter().map(|ticket| ticket.pack_id).collect(),
        denial_ids,
        parents,
        objects,
        bytes: staged_bytes,
        external_bases,
        inspection,
    })
}
