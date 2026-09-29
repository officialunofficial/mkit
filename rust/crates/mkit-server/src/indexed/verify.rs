//! Inline verification before a ticketed advance commits.

use super::{
    IndexedConfig,
    classify::{self, UploadType},
    entries::{FrameMeta, index_entries},
    resolve,
    state::{self, VerificationV1},
};
use crate::pipeline::ShardMap;
use crate::repo::RepoId;
use crate::store::{
    codec::TicketV1,
    index::{self, IndexEntry, LocatedObject},
    keys, read,
};
use crate::telemetry::Metrics;
use crate::{
    Batch, BatchOutcome, BlobBody, BlobKey, BlobStore, ByteRange, Clock, NamespaceStore, Partition,
    Precondition, ServerError,
};
use futures::StreamExt as _;
use mkit_core::hash::{Hash, hash};
use mkit_core::object::Object;
use mkit_core::ops::graph::{ClosureMode, children};
use mkit_core::pack::{
    DecodeLimits, DecodedEntry, DeltaBaseSource, PackError, decode_entries_with, delta_base_hashes,
};
use mkit_core::sign::verify_object_signature;
use mkit_core::transfer::decode_packlist;
use mkit_core::verify::{ObjectSource, VerifyError, verify_push};
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

fn storage_failed() -> ServerError {
    ServerError::unavailable("object storage request failed")
}
fn bad_object() -> ServerError {
    ServerError::invalid_argument("object hash mismatch")
}
fn closure_error(now: u64, created: u64, bound: u64) -> ServerError {
    if resolve::lagged(now, created, bound) {
        ServerError::unavailable("repository membership not yet visible")
    } else {
        ServerError::invalid_argument("open closure")
    }
}
fn packlist_error(now: u64, created: u64, bound: u64) -> ServerError {
    if resolve::lagged(now, created, bound) {
        ServerError::unavailable("repository membership not yet visible")
    } else {
        ServerError::invalid_argument("packlist lists a pack that is not in this repository")
    }
}

async fn pack_bytes<B: BlobStore>(
    blobs: &B,
    ticket: &TicketV1,
    cap: u64,
) -> Result<Vec<u8>, ServerError> {
    if ticket.bytes > cap {
        return Err(ServerError::invalid_argument(
            "pack exceeds indexed max_pack_bytes",
        ));
    }
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

struct Bases(BTreeMap<Hash, Vec<u8>>);
impl DeltaBaseSource for Bases {
    const VERIFIED: bool = false;
    fn base(&mut self, id: &Hash) -> Result<Option<Vec<u8>>, PackError> {
        Ok(self.0.get(id).cloned())
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
    pending_raw: Option<crate::Value>,
}

async fn verified_kind<B: BlobStore>(blobs: &B, pack: Hash) -> Result<UploadType, ServerError> {
    let body = blobs
        .get(
            &BlobKey::pack(pack),
            Some(ByteRange {
                start: 0,
                end_inclusive: 3,
            }),
        )
        .await
        .map_err(|_| storage_failed())?
        .ok_or_else(storage_failed)?;
    let bytes = match body {
        BlobBody::Bytes(bytes) => bytes.to_vec(),
        BlobBody::Stream { mut stream, .. } => {
            let mut bytes = Vec::new();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(|_| storage_failed())?;
                if bytes.len().saturating_add(chunk.len()) > 4 {
                    return Err(storage_failed());
                }
                bytes.extend_from_slice(&chunk);
            }
            bytes
        }
    };
    if bytes.len() != 4 {
        return Err(storage_failed());
    }
    classify::classify(&bytes).map_err(|_| bad_object())
}

async fn locate_in_verified_packs<S: NamespaceStore>(
    store: &S,
    shards: &dyn ShardMap,
    repo: &RepoId,
    ids: &BTreeMap<Hash, u64>,
    packs: &[Hash],
) -> Result<BTreeMap<Hash, LocatedObject>, ServerError> {
    let mut found = BTreeMap::new();
    for id in ids.keys() {
        let partition = shards.object_index(repo, id);
        for pack_chunk in packs.chunks(256) {
            let keys: Vec<_> = pack_chunk
                .iter()
                .map(|pack| keys::object_index(&repo.name, id, pack))
                .collect();
            let values = store
                .get_many(&partition, &keys)
                .await
                .map_err(|_| storage_failed())?;
            if values.len() != keys.len() {
                return Err(storage_failed());
            }
            for (pack, value) in pack_chunk.iter().zip(values) {
                if let Some(value) = value {
                    let value = crate::store::codec::decode_object_index(id, &value)
                        .map_err(|_| storage_failed())?;
                    found.insert(*id, LocatedObject { pack: *pack, value });
                    break;
                }
            }
            if found.contains_key(id) {
                break;
            }
        }
    }
    Ok(found)
}

async fn reject_content<S: NamespaceStore>(
    store: &S,
    source: &Partition,
    repo: &RepoId,
    pack: &Hash,
    prior: Option<&crate::Value>,
    message: &str,
    deadline: u64,
) -> ServerError {
    if let Some(prior) = prior {
        let _ = state::write(
            store,
            source,
            &repo.name,
            pack,
            Some(prior),
            &VerificationV1::Rejected {
                code: "invalid_argument".into(),
                message: message.into(),
            },
            deadline,
        )
        .await;
    }
    ServerError::invalid_argument(message.to_owned())
}

/// Verify every staged object. The resulting id list is WP-4.10's
/// extraction seam; no ticket is consumed and no advance row is written.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub async fn verify_ticketed<B: BlobStore, S: NamespaceStore>(
    blobs: &B,
    store: &S,
    shards: &dyn ShardMap,
    repo: &RepoId,
    source: &Partition,
    tickets: &[TicketV1],
    head: Hash,
    cfg: IndexedConfig,
    clock: &dyn Clock,
    metrics: &dyn Metrics,
) -> Result<Vec<Hash>, ServerError> {
    let mut acquired = Vec::new();
    let result = verify_ticketed_inner(
        blobs,
        store,
        shards,
        repo,
        source,
        tickets,
        head,
        cfg,
        clock,
        metrics,
        &mut acquired,
    )
    .await;
    if result.is_err() {
        let deadline = u64::try_from(clock.now_ms())
            .unwrap_or(0)
            .saturating_add(10_000);
        for (pack, raw) in acquired {
            if let Err(error) =
                state::clear_pending(store, source, &repo.name, &pack, &raw, deadline).await
            {
                tracing::error!(%error, "failed to release pending verification lease");
            }
        }
    }
    result
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn verify_ticketed_inner<B: BlobStore, S: NamespaceStore>(
    blobs: &B,
    store: &S,
    shards: &dyn ShardMap,
    repo: &RepoId,
    source: &Partition,
    tickets: &[TicketV1],
    head: Hash,
    cfg: IndexedConfig,
    clock: &dyn Clock,
    metrics: &dyn Metrics,
    acquired: &mut Vec<(Hash, crate::Value)>,
) -> Result<Vec<Hash>, ServerError> {
    let now = u64::try_from(clock.now_ms()).unwrap_or(0);
    let deadline = now.saturating_add(10_000);
    let consumed: BTreeSet<_> = tickets.iter().map(|ticket| ticket.pack_id).collect();
    let mut staged: BTreeMap<Hash, (Vec<u8>, Object, u64)> = BTreeMap::new();
    let mut staged_bytes = 0u64;
    let mut staged_owner = BTreeMap::new();
    let mut work = Vec::with_capacity(tickets.len());
    let mut pending_by_pack = BTreeMap::new();
    let mut packlists = Vec::new();
    let mut verified_packs = Vec::new();
    for ticket in tickets {
        let observed = state::read(store, source, &repo.name, &ticket.pack_id)
            .await
            .map_err(|_| storage_failed())?;
        let already_verified = match &observed {
            Some((VerificationV1::Verified { pack_len, .. }, _)) if *pack_len == ticket.bytes => {
                true
            }
            Some((VerificationV1::Verified { .. }, _)) => return Err(bad_object()),
            Some((VerificationV1::Rejected { code, message }, _)) => {
                return Err(if code == "invalid_argument" {
                    ServerError::invalid_argument(message.clone())
                } else {
                    ServerError::failed_precondition(message.clone())
                });
            }
            Some((state, _)) if state::concurrent_pending(state, now).is_some() => {
                return Err(super::pending(1_000));
            }
            _ => false,
        };
        let pending_raw = if already_verified {
            None
        } else {
            let pending = VerificationV1::Pending {
                lease_until_ms: now.saturating_add(state::VERIFICATION_LEASE_MS),
            };
            let prior = observed.as_ref().map(|(_, raw)| raw);
            if !state::write(
                store,
                source,
                &repo.name,
                &ticket.pack_id,
                prior,
                &pending,
                deadline,
            )
            .await
            .map_err(|_| storage_failed())?
            {
                return Err(super::pending(1_000));
            }
            Some(state::encode(&pending))
        };
        if let Some(raw) = &pending_raw {
            acquired.push((ticket.pack_id, raw.clone()));
        }
        if already_verified {
            match verified_kind(blobs, ticket.pack_id).await? {
                UploadType::Pack => verified_packs.push(ticket.pack_id),
                UploadType::Packlist => {
                    let bytes = pack_bytes(blobs, ticket, cfg.max_pack_bytes).await?;
                    let list = decode_packlist(&bytes).map_err(|_| bad_object())?;
                    packlists.push((ticket.created_at_ms, list.packs));
                }
            }
            continue;
        }
        if let Some(raw) = &pending_raw {
            pending_by_pack.insert(ticket.pack_id, raw.clone());
        }
        let bytes = pack_bytes(blobs, ticket, cfg.max_pack_bytes).await?;
        let Ok(kind) = classify::classify(&bytes) else {
            return Err(reject_content(
                store,
                source,
                repo,
                &ticket.pack_id,
                pending_raw.as_ref(),
                "unknown upload type",
                deadline,
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
                        pending_raw.as_ref(),
                        "object hash mismatch",
                        deadline,
                    )
                    .await);
                };
                packlists.push((ticket.created_at_ms, list.packs));
                work.push(PackWork {
                    ticket: ticket.clone(),
                    entries: Vec::new(),
                    pending_raw,
                });
            }
            UploadType::Pack => {
                let Ok(base_ids) = delta_base_hashes(&bytes) else {
                    return Err(reject_content(
                        store,
                        source,
                        repo,
                        &ticket.pack_id,
                        pending_raw.as_ref(),
                        "object hash mismatch",
                        deadline,
                    )
                    .await);
                };
                // A syntactic base may be supplied by an earlier frame in
                // this pack. Defer a repository lookup failure until the
                // decoder actually asks for an external base.
                let (locations, lookup_error) =
                    match resolve::locate_split(store, shards, repo, &base_ids, metrics).await {
                        Ok(locations) => (locations, None),
                        Err(error) => (BTreeMap::new(), Some(error)),
                    };
                let mut bases = Bases(BTreeMap::new());
                let mut base_errors = BTreeMap::new();
                let mut depths = BTreeMap::new();
                let mut memo = BTreeMap::new();
                let mut visiting = BTreeSet::new();
                for base in base_ids {
                    match locations.get(&base) {
                        Some(Ok(Some(located))) => {
                            match resolve::member_object(
                                blobs,
                                store,
                                shards,
                                repo,
                                base,
                                *located,
                                cfg.max_delta_chain_depth,
                                cfg.decode_budget,
                                &mut memo,
                                &mut visiting,
                                metrics,
                            )
                            .await
                            {
                                Ok((canonical, depth)) => {
                                    bases.0.insert(base, canonical);
                                    depths.insert(base, depth);
                                }
                                Err(error) => {
                                    base_errors.insert(base, error);
                                }
                            }
                        }
                        Some(Err(_)) => {
                            base_errors.insert(base, resolve::ResolveFailure::Capped);
                        }
                        _ => {}
                    }
                }
                let mut frames = Vec::new();
                let mut local_depths: BTreeMap<Hash, (u32, Option<Hash>)> = BTreeMap::new();
                let mut depth_exceeded = false;
                let decoded = decode_entries_with(
                    &bytes,
                    &mut bases,
                    DecodeLimits::default().with_max_decoded_bytes(cfg.decode_budget),
                    |entry: DecodedEntry<'_>| {
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
                        if total > cfg.max_delta_chain_depth {
                            depth_exceeded = true;
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
                            if staged_bytes > cfg.decode_budget {
                                return Err(PackError::PackfileTooLarge);
                            }
                            slot.insert((entry.bytes.to_vec(), entry.object, ticket.created_at_ms));
                        }
                        staged_owner.entry(entry.id).or_insert(ticket.pack_id);
                        Ok(())
                    },
                );
                if let Err(error) = decoded {
                    if depth_exceeded {
                        return Err(reject_content(
                            store,
                            source,
                            repo,
                            &ticket.pack_id,
                            pending_raw.as_ref(),
                            "delta chain too deep",
                            deadline,
                        )
                        .await);
                    }
                    let mapped = if let PackError::DeltaBaseMissing(hex) = &error {
                        if let Some(error) = lookup_error {
                            return Err(error);
                        }
                        let deferred = mkit_core::hash::from_hex(hex)
                            .ok()
                            .and_then(|id| base_errors.remove(&id));
                        match deferred {
                            Some(error) => error.public_error(
                                u64::try_from(clock.now_ms()).unwrap_or(0),
                                ticket.created_at_ms,
                                cfg.relay_lag_bound_ms,
                            ),
                            None => resolve::missing_base(
                                u64::try_from(clock.now_ms()).unwrap_or(0),
                                ticket.created_at_ms,
                                cfg.relay_lag_bound_ms,
                            ),
                        }
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
                            pending_raw.as_ref(),
                            "object hash mismatch",
                            deadline,
                        )
                        .await);
                    }
                    return Err(mapped);
                }
                let Ok(entries) = index_entries(&frames, cfg.max_delta_chain_depth) else {
                    return Err(reject_content(
                        store,
                        source,
                        repo,
                        &ticket.pack_id,
                        pending_raw.as_ref(),
                        "delta chain too deep",
                        deadline,
                    )
                    .await);
                };
                work.push(PackWork {
                    ticket: ticket.clone(),
                    entries,
                    pending_raw,
                });
            }
        }
    }
    for (id, (_, object, _)) in &staged {
        if verify_object_signature(object).is_err() {
            let owner = staged_owner[id];
            return Err(reject_content(
                store,
                source,
                repo,
                &owner,
                pending_by_pack.get(&owner),
                "bad signature",
                deadline,
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
        needed
            .entry(head)
            .or_insert_with(|| tickets.first().map_or(now, |ticket| ticket.created_at_ms));
    }
    let mut member_head = None;
    if !verified_packs.is_empty() && !needed.is_empty() {
        let found = locate_in_verified_packs(store, shards, repo, &needed, &verified_packs).await?;
        for (id, located) in found {
            if id == head {
                member_head = Some((located, needed[&id]));
            }
            needed.remove(&id);
        }
    }
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
        let mut memo = BTreeMap::new();
        let mut visiting = BTreeSet::new();
        let (bytes, _) = resolve::member_object(
            blobs,
            store,
            shards,
            repo,
            head,
            located,
            cfg.max_delta_chain_depth,
            cfg.decode_budget,
            &mut memo,
            &mut visiting,
            metrics,
        )
        .await
        .map_err(|failure| {
            failure.public_error(
                u64::try_from(clock.now_ms()).unwrap_or(0),
                created,
                cfg.relay_lag_bound_ms,
            )
        })?;
        let object = mkit_core::serialize::deserialize(&bytes).map_err(|_| bad_object())?;
        if !matches!(
            object,
            Object::Commit(_) | Object::Remix(_) | Object::Tag(_)
        ) {
            return Err(ServerError::invalid_argument("open closure"));
        }
    }
    let staged_ids: BTreeSet<_> = staged.keys().copied().collect();
    let report = verify_push(
        &[head],
        ClosureMode::History,
        &mut StagedSource(&staged),
        |id| !staged_ids.contains(id),
    )
    .map_err(|_| bad_object())?;
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
    for pack in &work {
        let Some(raw) = &pack.pending_raw else {
            continue;
        };
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
            let mut batch = Batch::new().require(Precondition::NotAfter(deadline));
            for (key, value) in direct.puts {
                batch = batch.put(key, value);
            }
            if !matches!(
                store.apply(&direct.target, batch).await,
                Ok(BatchOutcome::Committed)
            ) {
                return Err(super::pending(1_000));
            }
        }
        if !state::write(
            store,
            source,
            &repo.name,
            &pack.ticket.pack_id,
            Some(raw),
            &VerificationV1::Verified {
                pack_len: pack.ticket.bytes,
                verified_at_ms: now,
            },
            deadline,
        )
        .await
        .map_err(|_| super::pending(1_000))?
        {
            return Err(super::pending(1_000));
        }
    }
    Ok(staged_ids.into_iter().collect())
}
