//! Checkpointed holder discovery over configured or provable namespace roots.
use crate::pipeline::{MAX_APPLY_WINDOW, ShardMap};
use crate::store::{BlobKey, Cursor, StoreError, codec, keys, watermark};
use crate::{
    Addressing, Batch, Key, NamespaceKey, NamespaceStore, Partition, RepoId, RepoName, Value,
};
use mkit_core::hash::Hash;
use serde::{Deserialize, Serialize};
use watermark::namespace_relay_watermark_step;
type RecoveryMarkers = (Option<Vec<u8>>, Option<Vec<u8>>);

/// Durable checkpoint; commit it atomically with the returned context batch.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryState {
    version: u8,
    namespaces: Vec<String>,
    exhaustive: bool,
    addressing_single: bool,
    single_repo: Option<(String, String)>,
    safety_cut: u64,
    namespace: usize,
    phase: u8,
    registry_cursor: Option<Vec<u8>>,
    shard_cursor: Option<Vec<u8>>,
    object_cursor: Option<Vec<u8>>,
    repo: Option<String>,
    watermark: Option<Vec<u8>>,
    generation: Option<RecoveryMarkers>,
    binding: Option<(Hash, Hash, bool)>,
}
fn bad() -> StoreError {
    StoreError::Corrupt("invalid takedown discovery checkpoint/source".into())
}
impl DiscoveryState {
    /// Bind namespace configuration, the named source and the safety cut.
    pub fn new(
        addressing: &Addressing,
        named_namespace: &NamespaceKey,
        created: u64,
        margin: u64,
    ) -> Result<Self, StoreError> {
        let exhaustive = !matches!(addressing, Addressing::Multi(multi) if matches!(multi.namespace_policy, crate::policy::NamespacePolicy::Any { .. }));
        let namespaces = if exhaustive {
            super::configured_namespaces(addressing)
        } else {
            vec![named_namespace.clone()]
        };
        if namespaces.is_empty() || margin == 0 {
            return Err(bad());
        }
        let mut roots: Vec<_> = namespaces
            .into_iter()
            .map(|ns| ns.as_str().to_owned())
            .collect();
        roots.sort();
        roots.dedup();
        if exhaustive && !roots.iter().any(|root| root == named_namespace.as_str()) {
            return Err(bad());
        }
        let single_repo = match addressing {
            Addressing::Single { repo } => Some((
                repo.namespace.as_str().to_owned(),
                repo.name.as_str().to_owned(),
            )),
            Addressing::Multi(_) => None,
        };
        Ok(Self {
            version: 1,
            namespaces: roots,
            exhaustive,
            addressing_single: single_repo.is_some(),
            single_repo,
            safety_cut: created
                .checked_add(u64::try_from(MAX_APPLY_WINDOW.as_millis()).map_err(|_| bad())?)
                .and_then(|v| v.checked_add(margin))
                .ok_or_else(bad)?,
            ..Self::default()
        })
    }
    /// Whether the accepted namespace universe is exhaustive.
    #[must_use]
    pub fn exhaustive(&self) -> bool {
        self.exhaustive
    }
    /// Whether the current namespace candidate traversal finished.
    #[must_use]
    pub fn traversed(&self) -> bool {
        self.namespace == self.namespaces.len()
    }
    /// Resume one streamed known-holder namespace under the original cut and binding.
    /// The caller owns its durable namespace-page cursor; repeats are idempotent.
    pub fn next_candidate(&mut self, namespace: &NamespaceKey) -> Result<(), StoreError> {
        if self.exhaustive || !self.traversed() {
            return Err(bad());
        }
        self.namespaces = vec![namespace.as_str().to_owned()];
        self.namespace = 0;
        Ok(())
    }
}
async fn member_context<S: NamespaceStore>(
    store: &S,
    shards: &dyn ShardMap,
    repo: &RepoId,
    action: &Hash,
    object: &Hash,
    pack_id: &Hash,
) -> Result<Option<(Key, Value)>, StoreError> {
    if let Some(member) = store
        .get(
            &shards.membership(repo, &BlobKey::pack(*pack_id)),
            &keys::membership(&repo.name, pack_id),
        )
        .await?
    {
        if !member.as_bytes().is_empty() {
            return Err(bad());
        }
        let identity = format!("{}\0{}\0", repo.namespace.as_str(), repo.name.as_str());
        let key = Key::new(
            [
                b"b\0\xffdiscovery-context\0".as_slice(),
                action,
                object,
                identity.as_bytes(),
                pack_id,
            ]
            .concat(),
        );
        let value = serde_json::to_vec(&serde_json::json!({"version":1,"pack":pack_id,"known_signers":[],
                        "signer_metadata":"unavailable_in_existing_source","context_complete":false})).map_err(|_| bad())?;
        return Ok(Some((key, Value::new(value))));
    }
    Ok(None)
}

/// One bounded step; a successful read is not durable until the caller commits.
#[derive(Debug)]
pub struct DiscoveryStep {
    /// Checkpoint to commit alongside `batch` under the workflow's CAS guard.
    pub state: DiscoveryState,
    /// Context writes for `root`; this function performs no storage mutations.
    pub batch: Batch,
    /// Repository with confirmed membership in this bounded step.
    pub repository: Option<RepoId>,
    /// All exhaustive roots passed watermarks and applicable configured-repository
    /// or registry/active-shard enumeration.
    /// Any always returns false; this never claims verified preservation completion.
    pub complete: bool,
    /// This candidate traversal finished; Any remains non-exhaustive and incomplete.
    pub traversed: bool,
}
/// One watermark page, repository candidate or object-index row per call.
/// Use the alarm's budgeted/local-aware store; never explicitly route a self call.
#[allow(
    clippy::too_many_lines,
    clippy::too_many_arguments,
    reason = "Keep the mutually exclusive bounded checkpoint transitions together."
)]
pub async fn step<S: NamespaceStore>(
    store: &S,
    shards: &dyn ShardMap,
    _root: &Partition,
    action: &Hash,
    object: &Hash,
    is_pack: bool,
    now: u64,
    mut state: DiscoveryState,
) -> Result<DiscoveryStep, StoreError> {
    if state.version != 1
        || state.namespaces.is_empty()
        || state.namespace > state.namespaces.len()
        || state.phase > 3
        || state.addressing_single != state.single_repo.is_some()
        || (state.phase > 0 && (state.generation.is_none() || state.binding.is_none()))
        || state
            .binding
            .is_some_and(|b| b != (*action, *object, is_pack))
    {
        return Err(bad());
    }
    state.binding = Some((*action, *object, is_pack));
    let mut batch = Batch::new();
    let mut repository = None;
    if state.namespace < state.namespaces.len() && now > state.safety_cut {
        let ns = NamespaceKey::from_stored(state.namespaces[state.namespace].clone());
        let coordinator = shards.coordinator(&ns);
        if state.addressing_single
            && state.single_repo.as_ref().is_none_or(|(namespace, _)| {
                state.namespaces.len() != 1 || *namespace != ns.as_str()
            })
        {
            return Err(bad());
        }
        let generation = watermark::check_recovery(store, &coordinator, None)
            .await
            .map_err(|_| bad())?;
        let generation = (
            generation.0.map(|v| v.as_bytes().to_vec()),
            generation.1.map(|v| v.as_bytes().to_vec()),
        );
        if state
            .generation
            .as_ref()
            .is_some_and(|old| old != &generation)
        {
            state.phase = 0;
            state.registry_cursor = None;
            state.shard_cursor = None;
            state.object_cursor = None;
            state.repo = None;
            state.watermark = None;
            state.generation = None;
            return Ok(DiscoveryStep {
                state,
                batch,
                repository,
                complete: false,
                traversed: false,
            });
        }
        state.generation = Some(generation);
        if let Some(name) = state.repo.clone() {
            let repo = RepoId {
                namespace: ns,
                name: RepoName::new(name).map_err(|_| bad())?,
            };
            if is_pack {
                if let Some((key, value)) =
                    member_context(store, shards, &repo, action, object, object).await?
                {
                    batch = batch.put(key, value);
                    repository = Some(repo.clone());
                }
                state.repo = None;
            } else {
                let (start, end) = keys::object_index_range(&repo.name, object);
                let cursor = state.object_cursor.clone().map(Cursor::new);
                let page = store
                    .scan(
                        &shards.object_index(&repo, object),
                        &start,
                        &end,
                        cursor.as_ref(),
                        1,
                    )
                    .await?;
                for (key, value) in page.entries {
                    let Some(keys::ParsedKey::ObjectIndex {
                        repo: indexed_repo,
                        object: indexed_object,
                        pack_id,
                    }) = keys::parse(&key)
                    else {
                        return Err(bad());
                    };
                    if indexed_repo != repo.name || indexed_object != *object {
                        return Err(bad());
                    }
                    codec::decode_object_index(object, &value)?;
                    if let Some((key, value)) =
                        member_context(store, shards, &repo, action, object, &pack_id).await?
                    {
                        batch = batch.put(key, value);
                        repository = Some(repo.clone());
                    }
                }
                state.object_cursor = page.next.map(|c| c.as_bytes().to_vec());
                if state.object_cursor.is_none() {
                    state.repo = None;
                }
            }
        } else if state.phase == 0 {
            let value = if matches!(coordinator, Partition::Namespace(_)) {
                Some(crate::relay::relay_watermark(store, &coordinator, now).await?)
            } else {
                let checkpoint = state
                    .watermark
                    .as_deref()
                    .map(watermark::WatermarkCheckpoint::decode)
                    .transpose()?;
                match namespace_relay_watermark_step(store, &coordinator, now, checkpoint, 1)
                    .await
                    .map_err(|_| bad())?
                {
                    watermark::WatermarkStep::Pending(next) => {
                        state.watermark = Some(next.encode());
                        None
                    }
                    watermark::WatermarkStep::Complete(value) => {
                        state.watermark = None;
                        Some(value)
                    }
                }
            };
            if value.is_some_and(|v| v > state.safety_cut) {
                state.phase = if state.addressing_single { 3 } else { 1 };
                if state.addressing_single {
                    state.repo = state.single_repo.as_ref().map(|(_, name)| name.clone());
                }
            }
        } else if state.phase == 1 {
            let (start, end) = keys::class_range(keys::TAG_REPO_REGISTRY);
            let cursor = state.registry_cursor.clone().map(Cursor::new);
            let page = store
                .scan(&coordinator, &start, &end, cursor.as_ref(), 1)
                .await?;
            for (key, value) in page.entries {
                let Some(keys::ParsedKey::RepoRecord(repo)) = keys::parse(&key) else {
                    return Err(bad());
                };
                codec::decode_repo_record(&value)?;
                state.repo = Some(repo.as_str().to_owned());
            }
            state.registry_cursor = page.next.map(|c| c.as_bytes().to_vec());
            if state.registry_cursor.is_none() {
                state.phase = 2;
            }
        } else if state.phase == 2 {
            if matches!(coordinator, Partition::Namespace(_)) {
                state.phase = 3;
            } else {
                let cursor = state.shard_cursor.clone().map(Cursor::new);
                let page = watermark::active_shards(store, &coordinator, cursor.as_ref(), 1)
                    .await
                    .map_err(|_| bad())?;
                for partition in page.shards {
                    let Partition::Ref { repo, .. } = partition else {
                        return Err(bad());
                    };
                    state.repo = Some(repo.as_str().to_owned());
                }
                state.shard_cursor = page.next.map(|c| c.as_bytes().to_vec());
                if state.shard_cursor.is_none() {
                    state.phase = 3;
                }
            }
        } else {
            state.namespace += 1;
            state.phase = 0;
            state.generation = None;
            state.registry_cursor = None;
            state.shard_cursor = None;
        }
    }
    let traversed = state.traversed();
    let complete = traversed && state.exhaustive();
    Ok(DiscoveryStep {
        state,
        batch,
        repository,
        complete,
        traversed,
    })
}

#[cfg(all(test, feature = "memory"))]
#[path = "discovery_tests.rs"]
mod tests;
