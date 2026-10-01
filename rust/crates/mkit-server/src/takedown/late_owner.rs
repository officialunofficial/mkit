//! Real durable ownership of an exact late-holder request before timer-13 acknowledgment.
use super::{denial, intent, late::LateAcceptance, local::LocalStore};
use crate::indexed::budget::{Budgeted, SliceBudget};
use crate::relay::ContentTakedownV1;
use crate::store::{BorrowedStore, ContentIndex, StoreError, content_shard, keys};
use crate::{Batch, BatchOutcome, BoxFuture, Key, NamespaceStore, Partition, Precondition, Value};
use mkit_core::hash::{Hash, hash, to_hex};

pub(super) fn source_key(id: &Hash) -> Key {
    Key::new([b"b\0\xfflate-source\0".as_slice(), id].concat())
}
pub(super) fn request_id(request: &ContentTakedownV1) -> Hash {
    hash(
        &[
            b"mkit-late-takedown:v1\0".as_slice(),
            &request.identity.intent,
        ]
        .concat(),
    )
}
fn corrupt() -> StoreError {
    StoreError::Corrupt("late takedown ownership mismatch".into())
}
fn unavailable() -> StoreError {
    StoreError::unavailable("late takedown ownership unavailable")
}
/// Audited owning request and timer responsibility, using the caller's local partition.
#[derive(Clone)]
pub struct LateOwner<N> {
    store: N,
    root: Partition,
    purge: Option<crate::purge::PurgeConfig>,
}
impl<N> std::fmt::Debug for LateOwner<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LateOwner")
            .field("root", &self.root)
            .finish_non_exhaustive()
    }
}
impl<N> LateOwner<N> {
    /// Construct the real callback over local-aware metadata and the owning root.
    pub fn new(store: N, root: Partition) -> Self {
        Self {
            store,
            root,
            purge: None,
        }
    }
    /// Attach automatic invalidation for durable late-holder ownership.
    #[must_use]
    pub fn with_purge(mut self, purge: Option<crate::purge::PurgeConfig>) -> Self {
        self.purge = purge;
        self
    }
}
impl<N: NamespaceStore> LateAcceptance for LateOwner<N> {
    #[allow(clippy::too_many_lines)] // Exact source, staged action and root acceptance form one replayable lifecycle.
    fn accept<'a, S: NamespaceStore>(
        &'a self,
        local: &'a S,
        partition: &'a Partition,
        request: &'a ContentTakedownV1,
        now: u64,
        budget: &'a SliceBudget,
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async move {
            let source = request.encode()?;
            ContentTakedownV1::decode(&source)?;
            if content_shard(&request.identity.object) != *partition
                || request
                    .ready_at_ms
                    .is_none_or(|ready| ready < request.queued_at_ms || ready > now)
            {
                return Err(corrupt());
            }
            let local_store = LocalStore::new(local, partition, &self.store);
            let store = Budgeted::new(&local_store, budget);
            let id = request_id(request);
            let object = request.identity.object;
            let staged_key = intent::staged_key(&object, &id);
            let provenance = source_key(&id);
            let digest = to_hex(&hash(source.as_bytes()));
            let staged = if let Some(raw) = store.get(partition, &staged_key).await? {
                let staged: denial::StoredAction = intent::decode(&raw).map_err(|_| corrupt())?;
                if staged.action.id != hash(&[id.as_slice(), object.as_slice()].concat())
                    || staged.action.takedown_id != id
                    || staged.action.blocked_at_ms != request.queued_at_ms
                    || staged.action.reason != "manual"
                {
                    return Err(corrupt());
                }
                staged
            } else {
                let current = store.get(partition, &denial::action_key(&object)).await?;
                let action = denial::BlockAction {
                    id: hash(&[id.as_slice(), object.as_slice()].concat()),
                    takedown_id: id,
                    reason: "manual".into(),
                    blocked_at_ms: request.queued_at_ms,
                    chunk_ids: vec![],
                };
                let mut staged = if let Some(old) =
                    denial::decode_actions(current.as_ref())?.into_iter().next()
                {
                    old
                } else {
                    denial::stage_action(&store, &object, &action, now).await?
                };
                staged.action = action;
                let raw = intent::encode(&staged).map_err(|_| corrupt())?;
                if store
                    .apply(
                        partition,
                        Batch::new()
                            .require(Precondition::Absent(staged_key.clone()))
                            .put(staged_key.clone(), raw.clone()),
                    )
                    .await?
                    != BatchOutcome::Committed
                    && store.get(partition, &staged_key).await? != Some(raw)
                {
                    return Err(unavailable());
                }
                staged
            };
            let descriptor = intent::encode(&staged).map_err(|_| corrupt())?;
            let record = intent::Record {
                version: 1,
                id,
                digest: digest.clone(),
                operation: format!("late:{}", to_hex(&request.identity.intent)),
                repository: format!(
                    "{}/{}",
                    request.identity.holder.ns.as_str(),
                    request.identity.holder.repo.as_str()
                ),
                reason: request.blocked.reason.clone(),
                reason_token: "manual".into(),
                created: request.queued_at_ms,
                pack: staged.pack_scope,
                actions: vec![intent::Reference {
                    object,
                    descriptor_hash: hash(descriptor.as_bytes()),
                }],
                activation_cursor: 0,
                preservation_pending: true,
            };
            let record_key = intent::request_key(&id);
            let record_raw = intent::encode(&record).map_err(|_| corrupt())?;
            let mut accepted = false;
            for _ in 0..16 {
                if let Some(raw) = store.get(&self.root, &record_key).await? {
                    let mut old: intent::Record = intent::decode(&raw).map_err(|_| corrupt())?;
                    if old.activation_cursor > 1 {
                        return Err(corrupt());
                    }
                    old.activation_cursor = 0;
                    old.preservation_pending = true;
                    if intent::encode(&old).map_err(|_| corrupt())? != record_raw
                        || store.get(&self.root, &provenance).await? != Some(source.clone())
                    {
                        return Err(corrupt());
                    }
                    accepted = true;
                    break;
                }
                let mut batch = crate::admin::plan_system(
                    &store,
                    &self.root,
                    "system:timer",
                    "system:timer/late-takedown",
                    &[to_hex(&id), record.repository.clone()],
                    now,
                )
                .await?
                .require(Precondition::Absent(record_key.clone()))
                .require(Precondition::Absent(provenance.clone()))
                .put(record_key.clone(), record_raw.clone())
                .put(provenance.clone(), source.clone())
                .put(
                    keys::timer(
                        now,
                        crate::timers::registry::kinds::TAKEDOWN_WORK.get(),
                        &id,
                    ),
                    Value::default(),
                );
                let purge = crate::purge::automatic::plan_repository(
                    self.purge.as_ref(),
                    &store,
                    &self.root,
                    &intent::repository(&record.repository).map_err(|_| corrupt())?,
                    crate::purge::Trigger::Takedown,
                    &record.operation,
                    now,
                )
                .await?;
                batch.preconditions.extend(purge.preconditions);
                batch.writes.extend(purge.writes);
                if store.apply(&self.root, batch).await? == BatchOutcome::Committed {
                    accepted = true;
                    break;
                }
            }
            if !accepted {
                return Err(unavailable());
            }
            let repo = intent::repository(&record.repository).map_err(|_| corrupt())?;
            crate::purge::automatic::invalidate_repository(
                self.purge.as_ref(),
                &self.root,
                &repo,
                crate::purge::Trigger::Takedown,
                &record.operation,
            )
            .await;
            let operation = format!("activation:{}", to_hex(&staged.action.id));
            let purge = crate::purge::automatic::plan_repository(
                self.purge.as_ref(),
                &store,
                partition,
                &repo,
                crate::purge::Trigger::Takedown,
                &operation,
                now,
            )
            .await?;
            ContentIndex::new(BorrowedStore(&store))
                .install_stored_block_action_with_batch(&object, &staged, now, purge)
                .await?;
            crate::purge::automatic::invalidate_repository(
                self.purge.as_ref(),
                partition,
                &repo,
                crate::purge::Trigger::Takedown,
                &operation,
            )
            .await;
            Ok(())
        })
    }
}

#[cfg(test)]
#[path = "late_owner_tests.rs"]
mod tests;
