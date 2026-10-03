//! One durable acquisition, discovery or independently owned retention step.
use super::{
    LocalStore, Service, acquisition, closure, copy, discovery, intent, inventory, source,
};
use crate::indexed::budget::{Budgeted, SliceBudget};
use crate::pipeline::ShardMap;
use crate::store::{BlobKey, BlobStore, ContentIndex, StoreError};
use crate::timers::{DueTimer, Fired, TimerCtx, TimerHandler, TimerKind, registry::kinds};
use crate::{
    Addressing, Batch, Clock, Cursor, Key, NamespaceStore, Partition, Precondition, RepoId, Value,
};
use mkit_core::hash::{Hash, to_hex};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

fn bad() -> StoreError {
    StoreError::Corrupt("invalid preservation work".into())
}
fn value<T: Serialize>(v: &T) -> Result<Value, StoreError> {
    intent::encode(v).map_err(|_| bad())
}
fn decode<T: serde::de::DeserializeOwned>(v: &Value) -> Result<T, StoreError> {
    intent::decode(v).map_err(|_| bad())
}
pub(super) fn key(tag: &[u8], action: &Hash, tail: &[u8]) -> Key {
    Key::new(
        [
            b"b\0\xffpreservation\0".as_slice(),
            tag,
            b"\0",
            action,
            tail,
        ]
        .concat(),
    )
}
pub(super) fn range(tag: &[u8], action: &Hash) -> (Key, Key) {
    let start = key(tag, action, &[]);
    let end = prefix_end(&start);
    (start, end)
}
fn known_holder_key(id: &Hash, object: &Hash, repo: &RepoId) -> Key {
    key(
        b"known-holder",
        id,
        &[
            object.as_slice(),
            repo.namespace.as_str().as_bytes(),
            b"\0",
            repo.name.as_str().as_bytes(),
        ]
        .concat(),
    )
}
fn holder_context() -> Result<Value, StoreError> {
    value(
        &serde_json::json!({"contextComplete":false,"signerMetadata":"unavailable_in_existing_source"}),
    )
}
fn prefix_end(start: &Key) -> Key {
    let mut bytes = start.as_bytes().to_vec();
    while bytes.last() == Some(&255) {
        bytes.pop();
    }
    if let Some(last) = bytes.last_mut() {
        *last += 1;
    }
    Key::new(bytes)
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum Phase {
    Seed,
    Acquire,
    Closure,
    Discover,
    Retain,
    Purging,
    Purged,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum Verification {
    CanonicalPending,
    ManifestClosurePending,
    SourceCorrupt,
    Verified,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct State {
    pub version: u8,
    pub phase: Phase,
    pub retain_until: u64,
    pub hold: bool,
    pub purged: bool,
    pub purge_after: Option<Vec<u8>>,
    pub resume_phase: Phase,
    pub next_purge_at: u64,
    pub verification: Verification,
    pub discovery_complete: bool,
    pub seed: usize,
    pub discovery: Option<discovery::DiscoveryState>,
    pub current: Option<Hash>,
    pub verified_objects: u64,
}
impl State {
    pub(super) fn acquisition_complete(&self) -> bool {
        self.verification == Verification::Verified
    }
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ObjectInfo {
    pub kind: u8,
    pub size: u64,
    pub copied: u64,
    pub chunks: u32,
    pub verified: bool,
    pub source_failed: bool,
    pub holders: Option<Vec<u8>>,
    pub holders_done: bool,
    pub namespace_after: Option<Vec<u8>>,
}
/// All runtime dependencies; preservation is a separately provisioned blob store.
pub struct Work<N, B, P> {
    pub metadata: N,
    /// Automatic cache purge settings shared with signed and late intake.
    pub purge: Option<crate::purge::PurgeConfig>,
    pub serving: B,
    pub preserved: P,
    pub root: Partition,
    pub shards: Arc<dyn ShardMap>,
    pub addressing: Addressing,
    pub retention_ms: u64,
    pub discovery_margin_ms: u64,
    pub profile: acquisition::Profile,
    pub clock: Arc<dyn Clock>,
}
impl<N, B, P> std::fmt::Debug for Work<N, B, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreservationWork")
            .field("root", &self.root)
            .finish_non_exhaustive()
    }
}
impl<N: NamespaceStore + Clone, B: BlobStore, P: BlobStore> Work<N, B, P> {
    /// Prepare guarded legal-hold state for the signed admin framework.
    /// Commit with the operator's audit and replay result; no public route exists yet.
    ///
    /// # Errors
    /// Unknown requests, ended purge ownership, storage errors or invalid retention.
    pub async fn plan_legal_hold<S: NamespaceStore>(
        &self,
        store: &S,
        id: Hash,
        enabled: bool,
        now: u64,
    ) -> Result<Batch, StoreError> {
        let service = Service::new(
            LocalStore::new(store, &self.root, store),
            self.root.clone(),
            self.shards.clone(),
        )
        .with_purge(self.purge.clone());
        let (record, _) = service
            .record(store, &id)
            .await
            .map_err(|_| bad())?
            .ok_or_else(bad)?;
        let (mut state, old) = self.state(store, &id, record.created).await?;
        if enabled && (state.purged || state.phase == Phase::Purging) {
            return Err(StoreError::unavailable(
                "preservation purge already owns request",
            ));
        }
        state.hold = enabled;
        let state_key = key(b"state", &id, &[]);
        Ok(Batch::new()
            .require(old.map_or_else(
                || Precondition::Absent(state_key.clone()),
                |old| Precondition::Equals(state_key.clone(), old),
            ))
            .require(Precondition::NotAfter(
                now.saturating_add(crate::store::CONTENT_APPLY_WINDOW_MS),
            ))
            .put(state_key, value(&state)?)
            .put(
                crate::store::keys::timer(now.saturating_add(1), kinds::TAKEDOWN_WORK.get(), &id),
                Value::default(),
            ))
    }
    pub(super) async fn state<S: NamespaceStore>(
        &self,
        store: &S,
        id: &Hash,
        created: u64,
    ) -> Result<(State, Option<Value>), StoreError> {
        let raw = store.get(&self.root, &key(b"state", id, &[])).await?;
        let state = if let Some(raw) = &raw {
            decode(raw)?
        } else {
            State {
                version: 1,
                phase: Phase::Seed,
                retain_until: created
                    .checked_add(self.retention_ms)
                    .filter(|n| *n <= i64::MAX.unsigned_abs())
                    .ok_or_else(bad)?,
                hold: false,
                purged: false,
                purge_after: None,
                resume_phase: Phase::Seed,
                next_purge_at: 0,
                verification: Verification::CanonicalPending,
                discovery_complete: false,
                seed: 0,
                discovery: None,
                current: None,
                verified_objects: 0,
            }
        };
        if state.version != 1
            || self.retention_ms == 0
            || state.retain_until < created
            || state.hold && matches!(state.phase, Phase::Purging | Phase::Purged)
        {
            return Err(bad());
        }
        Ok((state, raw))
    }
    pub(super) async fn info<S: NamespaceStore>(
        &self,
        store: &S,
        id: &Hash,
        object: &Hash,
    ) -> Result<ObjectInfo, StoreError> {
        store
            .get(&self.root, &key(b"object", id, object))
            .await?
            .map(|v| decode(&v))
            .transpose()
            .map(Option::unwrap_or_default)
    }
    async fn plan_cache_purge<S: NamespaceStore>(
        &self,
        store: &S,
        id: &Hash,
        object: &Hash,
        repo: &RepoId,
        now: u64,
        local_budget: &crate::purge::SliceBudget,
    ) -> Result<Batch, StoreError> {
        if self.purge.is_none() {
            return Ok(Batch::new());
        }
        let marker = known_holder_key(id, object, repo);
        if store.get(&self.root, &marker).await?.is_some() {
            return Ok(Batch::new());
        }
        let operation = format!(
            "discovery:{}",
            to_hex(&mkit_core::hash::hash(
                &[id.as_slice(), object.as_slice()].concat()
            ))
        );
        let batch = crate::purge::automatic::plan_repository(
            self.purge.as_ref(),
            store,
            &self.root,
            repo,
            crate::purge::Trigger::Takedown,
            &operation,
            now,
        )
        .await?;
        // Invalidating early is safe on a failed checkpoint; the returned
        // durable responsibility is committed with the holder/discovery cursor.
        crate::purge::automatic::invalidate_repository(
            self.purge.as_ref(),
            &self.root,
            repo,
            crate::purge::Trigger::Takedown,
            &operation,
            local_budget,
        )
        .await;
        Ok(batch
            .require(Precondition::Absent(marker.clone()))
            .put(marker, holder_context()?))
    }
    fn enqueue(mut batch: Batch, id: &Hash, object: &Hash, kind: u8) -> Batch {
        let row = key(b"todo", id, object);
        batch.writes.retain(|write| match write {
            crate::Write::Put(key, _) | crate::Write::Delete(key) => key != &row,
        });
        batch.put(row, Value::new(vec![kind]))
    }
    #[allow(clippy::too_many_lines)] // Each branch performs one bounded checkpoint transition.
    pub(super) async fn step<S: NamespaceStore>(
        &self,
        store: &S,
        id: Hash,
        now: u64,
        budget: &SliceBudget,
    ) -> Result<Fired, StoreError> {
        let local_budget = crate::purge::SliceBudget::with_parent(64, budget.clone());
        let service = Service::new(
            LocalStore::new(store, &self.root, store),
            self.root.clone(),
            self.shards.clone(),
        )
        .with_purge(self.purge.clone());
        service
            .resume_with_local_budget(id, now, budget, &local_budget)
            .await
            .map_err(|_| StoreError::unavailable("denial activation pending"))?;
        let (record, _) = service
            .record(store, &id)
            .await
            .map_err(|_| bad())?
            .ok_or_else(bad)?;
        let (mut state, old) = self.state(store, &id, record.created).await?;
        if state.seed > record.actions.len() {
            return Err(bad());
        }
        let serving = Budgeted::new(&self.serving, budget);
        let preserved = Budgeted::new(&self.preserved, budget);
        let mut batch = Batch::new();
        let mut event = "PreservationCheckpoint";
        let mut audit_targets = vec![to_hex(&id)];
        if !state.hold
            && state.phase != Phase::Purging
            && (now >= state.retain_until && !state.purged
                || state.purged && now >= state.next_purge_at)
        {
            state.purge_after = None;
            state.resume_phase = state.phase;
            state.phase = Phase::Purging;
            event = "PreservationPurgeStarted";
        } else if state.phase == Phase::Seed {
            if let Some(pack) = record.pack {
                let (start, end) = range(b"pack-todo", &id);
                if state.seed == 0 {
                    batch = batch
                        .put(
                            key(b"pack-todo", &id, &pack),
                            value(&inventory::InventoryCursor::default())?,
                        )
                        .put(key(b"pack-seen", &id, &pack), Value::default());
                    state.seed = 1;
                } else if let Some((row, raw)) = store
                    .scan(&self.root, &start, &end, None, 1)
                    .await?
                    .entries
                    .first()
                {
                    let pack: Hash = row
                        .as_bytes()
                        .strip_prefix(start.as_bytes())
                        .ok_or_else(bad)?
                        .try_into()
                        .map_err(|_| bad())?;
                    let (next, entries, done) = inventory::next(store, &pack, decode(raw)?).await?;
                    for (object, entry) in entries {
                        if entry.kind == 0 && inventory::has_seal(store, &object).await? {
                            let seen = key(b"pack-seen", &id, &object);
                            if store.get(&self.root, &seen).await?.is_none() {
                                batch = batch.put(seen, Value::default()).put(
                                    key(b"pack-todo", &id, &object),
                                    value(&inventory::InventoryCursor::default())?,
                                );
                            }
                        } else {
                            batch = Self::enqueue(batch, &id, &object, entry.kind);
                        }
                    }
                    if done {
                        batch = batch
                            .delete(row.clone())
                            .put(key(b"discover", &id, &pack), Value::new(vec![1]));
                    } else {
                        batch = batch.put(row.clone(), value(&next)?);
                    }
                } else {
                    state.phase = Phase::Acquire;
                }
            } else {
                for reference in record.actions.iter().skip(state.seed).take(32) {
                    batch = Self::enqueue(batch, &id, &reference.object, 0)
                        .put(key(b"discover", &id, &reference.object), Value::default());
                    state.seed += 1;
                }
                if state.seed == record.actions.len() {
                    state.phase = Phase::Acquire;
                }
            }
        } else if state.phase == Phase::Acquire && state.purged {
            state.phase = Phase::Discover;
        } else if state.phase == Phase::Acquire {
            let (start, end) = range(b"todo", &id);
            let page = store.scan(&self.root, &start, &end, None, 1).await?;
            if let Some((todo, expected)) = page.entries.first() {
                let object: Hash = todo
                    .as_bytes()
                    .strip_prefix(start.as_bytes())
                    .ok_or_else(bad)?
                    .try_into()
                    .map_err(|_| bad())?;
                let mut info = self.info(store, &id, &object).await?;
                let repo = intent::repository(&record.repository).map_err(|_| bad())?;
                let checkpoint_key = key(b"source", &id, &object);
                let old_checkpoint = store.get(&self.root, &checkpoint_key).await?;
                let checkpoint = old_checkpoint
                    .as_ref()
                    .map(decode::<source::Checkpoint>)
                    .transpose()?
                    .unwrap_or_else(|| source::Checkpoint::new(object));
                let prefix = key(b"source-frame", &id, &object);
                if info.source_failed {
                    // A later manifest may reference the same failed member.
                    batch = batch.delete(todo.clone());
                } else if checkpoint.next.is_some() {
                    let next = source::step(
                        store,
                        self.shards.as_ref(),
                        &repo,
                        &prefix,
                        &self.profile,
                        checkpoint,
                    )
                    .await?;
                    if next.checkpoint.next.is_none() {
                        event = "PreservationSourceSelected";
                    }
                    batch.writes.extend(next.batch.writes);
                    batch.preconditions.extend(next.batch.preconditions);
                    batch = batch
                        .require(old_checkpoint.map_or_else(
                            || Precondition::Absent(checkpoint_key.clone()),
                            |raw| Precondition::Equals(checkpoint_key.clone(), raw),
                        ))
                        .put(checkpoint_key, value(&next.checkpoint)?);
                } else {
                    let source = acquisition::resolve_selected(
                        &serving,
                        store,
                        self.shards.as_ref(),
                        &repo,
                        object,
                        &self.profile,
                        &self.root,
                        &prefix,
                    )
                    .await;
                    let source = match source {
                        Ok(source) => Some(source),
                        Err(error) if error.code() == crate::Code::DataLoss => {
                            let row = Key::new([prefix.as_bytes(), &0u32.to_be_bytes()].concat());
                            let raw = store.get(&self.root, &row).await?.ok_or_else(bad)?;
                            let (_, selected) = source::decode_frame(&raw)?;
                            audit_targets.extend([to_hex(&object), to_hex(&selected.pack)]);
                            info.source_failed = true;
                            info.verified = false;
                            state.verification = Verification::SourceCorrupt;
                            // Keep selected source rows as provenance; remove only its pending work.
                            batch = batch
                                .require(Precondition::Equals(
                                    checkpoint_key,
                                    old_checkpoint.ok_or_else(bad)?,
                                ))
                                .require(Precondition::Equals(row, raw))
                                .delete(todo.clone())
                                .put(key(b"object", &id, &object), value(&info)?)
                                .put(key(b"discover", &id, &object), Value::default());
                            event = "PreservationSourceCorrupt";
                            None
                        }
                        Err(_) => {
                            return Err(StoreError::unavailable("preservation source unavailable"));
                        }
                    };
                    if let Some(source) = source {
                        if expected.as_bytes().len() != 1
                            || expected.as_bytes()[0] != 0 && expected.as_bytes()[0] != source.kind
                            || record.pack.is_none() && !matches!(source.kind, 1 | 5)
                        {
                            return Err(bad());
                        }
                        let size = u64::try_from(source.canonical.len()).map_err(|_| bad())?;
                        if info.copied > size
                            || info.kind != 0 && (info.kind != source.kind || info.size != size)
                        {
                            return Err(bad());
                        }
                        // Reassembly validation runs over preserved bytes after every child is acquired.
                        if source.kind == 5 && state.verification != Verification::SourceCorrupt {
                            state.verification = Verification::ManifestClosurePending;
                        }
                        info.kind = source.kind;
                        info.size = size;
                        for _ in 0..8 {
                            let offset = usize::try_from(info.copied).map_err(|_| bad())?;
                            if offset == source.canonical.len() {
                                break;
                            }
                            let end = source
                                .canonical
                                .len()
                                .min(offset.saturating_add(copy::PIECE_BYTES));
                            // Reserve PUT and its immutable-existence HEAD before the sink runs.
                            budget.charge()?;
                            budget.charge()?;
                            let piece = copy::plan(
                                &id,
                                &object,
                                info.copied,
                                &source.canonical[offset..end],
                            )?;
                            let piece_key = key(
                                b"piece",
                                &id,
                                &[object.as_slice(), &info.copied.to_be_bytes()].concat(),
                            );
                            let mut intent = crate::admin::plan_system(
                                store,
                                &self.root,
                                "system:timer",
                                "system:timer/PreservationPieceIntent",
                                &[to_hex(&id)],
                                now,
                            )
                            .await
                            .map_err(|_| bad())?;
                            intent = intent
                                .require(Precondition::Equals(
                                    key(b"state", &id, &[]),
                                    old.clone().ok_or_else(bad)?,
                                ))
                                .require(Precondition::NotAfter(if state.hold {
                                    u64::try_from(self.clock.now_ms())
                                        .map_err(|_| bad())?
                                        .saturating_add(crate::store::CONTENT_APPLY_WINDOW_MS)
                                } else {
                                    state.retain_until
                                }))
                                .put(piece_key, value(&piece)?);
                            if store.apply(&self.root, intent).await?
                                != crate::BatchOutcome::Committed
                            {
                                return Err(StoreError::unavailable("preservation intent raced"));
                            }
                            copy::write(
                                &preserved,
                                &id,
                                &object,
                                info.copied,
                                &source.canonical[offset..end],
                            )
                            .await?;
                            info.copied = u64::try_from(end).map_err(|_| bad())?;
                        }
                        if info.copied == size {
                            let count = if source.kind == 5 {
                                u32::from_le_bytes(
                                    source
                                        .canonical
                                        .get(18..22)
                                        .ok_or_else(bad)?
                                        .try_into()
                                        .map_err(|_| bad())?,
                                )
                            } else {
                                0
                            };
                            if info.chunks > count {
                                return Err(bad());
                            }
                            for index in info.chunks..count.min(info.chunks.saturating_add(64)) {
                                let offset = 22 + usize::try_from(index).map_err(|_| bad())? * 32;
                                let chunk: Hash = source
                                    .canonical
                                    .get(offset..offset + 32)
                                    .ok_or_else(bad)?
                                    .try_into()
                                    .map_err(|_| bad())?;
                                let child = self.info(store, &id, &chunk).await?;
                                if child.kind != 0 && child.kind != 1 {
                                    return Err(bad());
                                }
                                let done = child.verified || child.source_failed;
                                if !done {
                                    batch = Self::enqueue(batch, &id, &chunk, 1);
                                }
                                info.chunks += 1;
                            }
                            if info.chunks == count {
                                info.verified = true;
                                state.verified_objects =
                                    state.verified_objects.checked_add(1).ok_or_else(bad)?;
                                batch = batch
                                    .delete(todo.clone())
                                    .put(key(b"discover", &id, &object), Value::default());
                                if source.kind == 5 {
                                    batch = batch.put(
                                        key(b"closure", &id, &object),
                                        value(&closure::Checkpoint::default())?,
                                    );
                                }
                            }
                        }
                        batch = batch.put(key(b"object", &id, &object), value(&info)?);
                    }
                }
            } else {
                if state.verification == Verification::CanonicalPending {
                    state.verification = Verification::Verified;
                }
                state.phase = if state.verification == Verification::ManifestClosurePending {
                    Phase::Closure
                } else {
                    Phase::Discover
                };
                event = match state.verification {
                    Verification::Verified => "PreservationVerified",
                    Verification::SourceCorrupt => "PreservationAcquisitionIncomplete",
                    _ => "PreservationClosurePending",
                };
            }
        } else if state.phase == Phase::Closure && state.purged {
            state.phase = Phase::Discover;
        } else if state.phase == Phase::Closure {
            let (start, end) = range(b"closure", &id);
            let page = store.scan(&self.root, &start, &end, None, 1).await?;
            if let Some((row, raw)) = page.entries.first() {
                let manifest: Hash = row
                    .as_bytes()
                    .strip_prefix(start.as_bytes())
                    .ok_or_else(bad)?
                    .try_into()
                    .map_err(|_| bad())?;
                let info = self.info(store, &id, &manifest).await?;
                let next = closure::step(
                    store,
                    &preserved,
                    &self.root,
                    &id,
                    &manifest,
                    &info,
                    decode(raw)?,
                )
                .await?;
                batch = if next.complete {
                    batch.delete(row.clone())
                } else {
                    batch.put(row.clone(), value(&next.checkpoint)?)
                };
            } else {
                state.verification = Verification::Verified;
                state.phase = Phase::Discover;
                event = "PreservationVerified";
            }
        } else if state.phase == Phase::Discover {
            let (start, end) = range(b"discover", &id);
            let page = store.scan(&self.root, &start, &end, None, 1).await?;
            if let Some((todo, kind)) = page.entries.first() {
                let object: Hash = todo
                    .as_bytes()
                    .strip_prefix(start.as_bytes())
                    .ok_or_else(bad)?
                    .try_into()
                    .map_err(|_| bad())?;
                let is_pack = kind.as_bytes() == [1];
                let mut info = self.info(store, &id, &object).await?;
                if info.holders_done {
                    if state.current.is_some_and(|old| old != object) {
                        return Err(bad());
                    }
                    state.current = Some(object);
                    let mut checkpoint = state.discovery.take().map_or_else(
                        || {
                            discovery::DiscoveryState::new(
                                &self.addressing,
                                &intent::repository(&record.repository)
                                    .map_err(|_| bad())?
                                    .namespace,
                                record.created,
                                self.discovery_margin_ms,
                            )
                        },
                        Ok,
                    )?;
                    let mut candidates_done = false;
                    if checkpoint.traversed() && !checkpoint.exhaustive() {
                        let start = key(b"known-ns", &id, &object);
                        let cursor = info.namespace_after.clone().map(Cursor::new);
                        let page = store
                            .scan(&self.root, &start, &prefix_end(&start), cursor.as_ref(), 1)
                            .await?;
                        if let Some((candidate, _)) = page.entries.first() {
                            let name = std::str::from_utf8(
                                candidate
                                    .as_bytes()
                                    .strip_prefix(start.as_bytes())
                                    .ok_or_else(bad)?,
                            )
                            .map_err(|_| bad())?;
                            let namespace = if name == "root" {
                                crate::NamespaceKey::deployment_default()
                            } else {
                                crate::NamespaceKey::from_namespace(
                                    &mkit_core::repo_identity::Namespace::parse(name)
                                        .map_err(|_| bad())?,
                                )
                            };
                            checkpoint.next_candidate(&namespace)?;
                            info.namespace_after = Some(candidate.as_bytes().to_vec());
                            batch = batch.put(key(b"object", &id, &object), value(&info)?);
                        } else {
                            candidates_done = true;
                            state.discovery = None;
                            state.current = None;
                            batch = batch.delete(todo.clone());
                        }
                    }
                    if !candidates_done {
                        let next = discovery::step(
                            store,
                            self.shards.as_ref(),
                            &self.root,
                            &id,
                            &object,
                            is_pack,
                            now,
                            checkpoint,
                        )
                        .await?;
                        if let Some(repo) = &next.repository {
                            let purge = self
                                .plan_cache_purge(store, &id, &object, repo, now, &local_budget)
                                .await?;
                            batch.preconditions.extend(purge.preconditions);
                            batch.writes.extend(purge.writes);
                        }
                        batch.preconditions.extend(next.batch.preconditions);
                        batch.writes.extend(next.batch.writes);
                        if next.complete {
                            batch = batch.delete(todo.clone());
                            state.current = None;
                        } else {
                            state.discovery = Some(next.state);
                        }
                    }
                } else {
                    let cursor = info.holders.clone().map(Cursor::new);
                    let holders = ContentIndex::new(crate::store::BorrowedStore(store))
                        .holders(&object, cursor.as_ref(), 1)
                        .await?;
                    for holder in holders.holders {
                        batch = batch.put(
                            key(
                                b"known-ns",
                                &id,
                                &[object.as_slice(), holder.ns.as_str().as_bytes()].concat(),
                            ),
                            Value::default(),
                        );
                        let repo = RepoId {
                            namespace: holder.ns,
                            name: holder.repo,
                        };
                        let purge = self
                            .plan_cache_purge(store, &id, &object, &repo, now, &local_budget)
                            .await?;
                        batch.preconditions.extend(purge.preconditions);
                        batch.writes.extend(purge.writes);
                        if self.purge.is_none() {
                            batch =
                                batch.put(known_holder_key(&id, &object, &repo), holder_context()?);
                        }
                    }
                    info.holders = holders.next.map(|c| c.as_bytes().to_vec());
                    info.holders_done = info.holders.is_none();
                    batch = batch.put(key(b"object", &id, &object), value(&info)?);
                }
            } else {
                state.phase = if state.purged {
                    Phase::Purged
                } else {
                    Phase::Retain
                };
                state.discovery_complete = state.acquisition_complete()
                    && !matches!(&self.addressing, Addressing::Multi(multi) if matches!(multi.namespace_policy, crate::policy::NamespacePolicy::Any { .. }));
                event = if state.discovery_complete {
                    "PreservationDiscoveryComplete"
                } else {
                    "PreservationDiscoveryIncomplete"
                };
            }
        } else if state.phase == Phase::Purging {
            let (start, end) = range(b"piece", &id);
            let page = store
                .scan(
                    &self.root,
                    &start,
                    &end,
                    state.purge_after.clone().map(Cursor::new).as_ref(),
                    1,
                )
                .await?;
            if let Some((row, raw)) = page.entries.first() {
                let piece: copy::Piece = decode(raw)?;
                if row
                    != &key(
                        b"piece",
                        &id,
                        &[piece.object.as_slice(), &piece.offset.to_be_bytes()].concat(),
                    )
                {
                    return Err(bad());
                }
                // Purging is durable before DELETE; legal hold cannot enter this phase.
                if copy::read(&preserved, &id, &piece).await?.is_some() {
                    budget.charge()?;
                    budget.charge()?;
                    preserved.delete(&BlobKey::pack(piece.storage)).await?;
                }
                // Keep the intent: a delayed PUT remains discoverable on every later pass.
                state.purge_after = Some(row.as_bytes().to_vec());
                event = "PreservationPiecePurged";
            } else {
                state.phase = match state.resume_phase {
                    Phase::Acquire | Phase::Closure => Phase::Discover,
                    Phase::Retain => Phase::Purged,
                    other => other,
                };
                state.purged = true;
                state.next_purge_at = now.saturating_add(3_600_000);
                event = "PreservationPurgeComplete";
            }
        }
        let audit = crate::admin::plan_system(
            store,
            &self.root,
            "system:timer",
            &format!("system:timer/{event}"),
            &audit_targets,
            now,
        )
        .await
        .map_err(|_| bad())?;
        batch.preconditions.extend(audit.preconditions);
        batch.writes.extend(audit.writes);
        let state_key = key(b"state", &id, &[]);
        batch = batch
            .require(old.map_or_else(
                || Precondition::Absent(state_key.clone()),
                |old| Precondition::Equals(state_key.clone(), old),
            ))
            .require(Precondition::NotAfter(
                u64::try_from(self.clock.now_ms())
                    .map_err(|_| bad())?
                    .saturating_add(crate::store::CONTENT_APPLY_WINDOW_MS),
            ))
            .put(state_key, value(&state)?);
        let delay = if state.phase == Phase::Purged || state.phase == Phase::Retain && state.hold {
            3_600_000
        } else if state.phase == Phase::Retain {
            state
                .retain_until
                .saturating_sub(now)
                .clamp(1_000, 3_600_000)
        } else {
            1_000
        };
        Ok(Fired::Reschedule {
            due_at_ms: now.saturating_add(delay),
            value: Value::default(),
            batch,
        })
    }
}
impl<S: NamespaceStore, N: NamespaceStore + Clone, B: BlobStore, P: BlobStore> TimerHandler<S>
    for Work<N, B, P>
{
    fn kind(&self) -> TimerKind {
        kinds::TAKEDOWN_WORK
    }
    fn max_per_tick(&self) -> Option<u32> {
        Some(1)
    }
    fn fire<'a>(
        &'a self,
        ctx: &'a TimerCtx<'a, S>,
        timer: &'a DueTimer,
    ) -> crate::BoxFuture<'a, Result<Fired, StoreError>> {
        Box::pin(async move {
            if ctx.partition != &self.root || timer.kind != kinds::TAKEDOWN_WORK {
                return Err(bad());
            }
            let id = timer.reference.as_ref().try_into().map_err(|_| bad())?;
            let local = LocalStore::new(ctx.store, ctx.partition, &self.metadata);
            let budget = SliceBudget::new(self.profile.slice_calls());
            let store = Budgeted::new(&local, &budget);
            self.step(&store, id, ctx.now_ms, &budget).await
        })
    }
}

#[cfg(all(test, feature = "memory"))]
#[path = "work_tests.rs"]
mod tests;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::too_many_lines)]
mod stored_v050_tests {
    crate::stored_golden::tests!(takedown_work);
}
