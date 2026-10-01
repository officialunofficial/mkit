use super::{
    denial::{BlockAction, StoredAction},
    inventory,
};
use crate::{
    Batch, BatchOutcome, Key, NamespaceKey, NamespaceStore, Partition, Precondition, RepoId,
    RepoName, ServerError, Value,
    admin::{AdminOperations, Prepared, Response},
    indexed::budget::{Budgeted, SliceBudget},
    pipeline::ShardMap,
    store::{BorrowedStore, ContentIndex, content_shard, keys},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use mkit_core::hash::{Hash, hash, to_hex};
use serde::{Deserialize, Serialize};
use serde_json::{Value as Json, json};
use std::{collections::BTreeSet, sync::Arc};
const CALLS: u32 = 4_000;
fn invalid() -> ServerError {
    ServerError::invalid_argument("invalid takedown request")
}
fn unavailable() -> ServerError {
    ServerError::unavailable("takedown storage unavailable")
}
pub(super) fn encode<T: Serialize>(value: &T) -> Result<Value, ServerError> {
    let bytes = serde_json::to_vec(value).map_err(|_| unavailable())?;
    if bytes.len() > crate::MAX_VALUE_BYTES {
        return Err(invalid());
    }
    Ok(Value::new(bytes))
}
pub(super) fn decode<T: serde::de::DeserializeOwned>(raw: &Value) -> Result<T, ServerError> {
    serde_json::from_slice(raw.as_bytes()).map_err(|_| unavailable())
}
fn key(prefix: &[u8], id: &Hash) -> Key {
    Key::new([prefix, id].concat())
}
pub(super) fn request_key(id: &Hash) -> Key {
    key(b"b\0\xffrequest\0", id)
}
pub(super) fn staged_key(object: &Hash, id: &Hash) -> Key {
    Key::new([b"b\0".as_slice(), object, b"\0intent\0", id].concat())
}
fn bounded_text(s: &str, max: usize, required: bool) -> bool {
    (!required || !s.is_empty()) && s.len() <= max && !s.chars().any(char::is_control)
}
pub(super) fn reason_token(s: &str) -> bool {
    matches!(s, "legal" | "policy" | "malware" | "abuse" | "manual")
        || s.strip_prefix("x-").is_some_and(|s| {
            !s.is_empty()
                && s.len() <= 62
                && s.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b".-".contains(&b))
        })
}
fn parse_id(s: &str) -> Result<Hash, ServerError> {
    let raw = STANDARD.decode(s).map_err(|_| invalid())?;
    if STANDARD.encode(&raw) != s {
        return Err(invalid());
    }
    raw.try_into().map_err(|_| invalid())
}
pub(super) fn repository(s: &str) -> Result<RepoId, ServerError> {
    let (ns, name) = s.rsplit_once('/').ok_or_else(invalid)?;
    mkit_core::repo_identity::validate_name(name).map_err(|_| invalid())?;
    let namespace = if ns == "root" {
        NamespaceKey::deployment_default()
    } else {
        NamespaceKey::from_namespace(
            &mkit_core::repo_identity::Namespace::parse(ns).map_err(|_| invalid())?,
        )
    };
    Ok(RepoId {
        namespace,
        name: RepoName::new(name)?,
    })
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Request {
    #[serde(alias = "operation_id")]
    operation_id: String,
    repository: String,
    #[serde(default, alias = "object_ids")]
    object_ids: Vec<String>,
    #[serde(default, alias = "pack_id")]
    pack_id: Option<String>,
    reason: String,
    #[serde(default, alias = "reason_token")]
    reason_token: Option<String>,
    #[serde(default, alias = "operator_label")]
    operator_label: String,
    #[serde(default)]
    level: Option<Json>,
}
impl Request {
    pub(super) fn parse(input: &Json) -> Result<Self, ServerError> {
        let value: Self = serde_json::from_value(input.clone()).map_err(|_| invalid())?;
        if !bounded_text(&value.operation_id, 128, true)
            || !value
                .operation_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
            || !bounded_text(&value.reason, 512, true)
            || !bounded_text(&value.operator_label, 128, false)
            || value.object_ids.is_empty() == value.pack_id.is_none()
            || value.object_ids.len() > 256
            || value
                .level
                .as_ref()
                .is_some_and(|v| v != "TAKEDOWN_LEVEL_CONTENT" && v != 1)
            || !reason_token(value.reason_token.as_deref().unwrap_or("manual"))
        {
            return Err(invalid());
        }
        repository(&value.repository)?;
        let ids = value
            .object_ids
            .iter()
            .map(|s| parse_id(s))
            .collect::<Result<BTreeSet<_>, _>>()?;
        if ids.len() != value.object_ids.len() {
            return Err(invalid());
        }
        if let Some(pack) = &value.pack_id {
            parse_id(pack)?;
        }
        Ok(value)
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Reference {
    pub(super) object: Hash,
    pub(super) descriptor_hash: Hash,
}
/// Durable launch handoff: denial progress is independent of preservation completion.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub(super) version: u8,
    pub(super) id: Hash,
    pub(super) digest: String,
    pub(super) operation: String,
    pub(super) repository: String,
    pub(super) reason: String,
    pub(super) reason_token: String,
    pub(super) created: u64,
    pub(super) pack: Option<Hash>,
    pub(super) actions: Vec<Reference>,
    pub(super) activation_cursor: usize,
    pub(super) preservation_pending: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Draft {
    version: u8,
    id: Hash,
    digest: String,
    pub(super) created: u64,
}
/// Factory-only operator extension. Production adapters remain disabled until PR2.
#[derive(Clone)]
pub struct Service<N> {
    pub(super) store: N,
    root: Partition,
    shards: Arc<dyn ShardMap>,
    purge: Option<crate::purge::PurgeConfig>,
}
impl<N> std::fmt::Debug for Service<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TakedownIntentService")
            .field("root", &self.root)
            .finish_non_exhaustive()
    }
}
impl<N: NamespaceStore + Clone> Service<N> {
    /// Construct the inert intent extension over durable operator metadata.
    pub fn new(store: N, root: Partition, shards: Arc<dyn ShardMap>) -> Self {
        Self {
            store,
            root,
            shards,
            purge: None,
        }
    }
    /// Attach configured automatic cache invalidation for accepted actions.
    #[must_use]
    pub fn with_purge(mut self, purge: Option<crate::purge::PurgeConfig>) -> Self {
        self.purge = purge;
        self
    }
    pub(super) async fn draft<S: NamespaceStore>(
        &self,
        store: &S,
        id: Hash,
        digest: &str,
        now: u64,
    ) -> Result<Draft, ServerError> {
        let key = key(b"b\0\xffintent-draft\0", &id);
        let draft = Draft {
            version: 1,
            id,
            digest: digest.into(),
            created: now,
        };
        let value = encode(&draft)?;
        for _ in 0..16 {
            if let Some(old) = store
                .get(&self.root, &key)
                .await
                .map_err(|_| unavailable())?
            {
                let old: Draft = decode(&old)?;
                if old.version != 1 || old.id != id || old.digest != digest {
                    return Err(invalid());
                }
                return Ok(old);
            }
            if store
                .apply(
                    &self.root,
                    Batch::new()
                        .require(Precondition::Absent(key.clone()))
                        .put(key.clone(), value.clone()),
                )
                .await
                .map_err(|_| unavailable())?
                == BatchOutcome::Committed
            {
                return Ok(draft);
            }
        }
        Err(unavailable())
    }
    pub(super) async fn record<S: NamespaceStore>(
        &self,
        store: &S,
        id: &Hash,
    ) -> Result<Option<(Record, Value)>, ServerError> {
        store
            .get(&self.root, &request_key(id))
            .await
            .map_err(|_| unavailable())?
            .map(|raw| {
                let record: Record = decode(&raw)?;
                if record.version != 1
                    || record.id != *id
                    || record.actions.is_empty()
                    || record.actions.len() > 256
                    || record
                        .actions
                        .windows(2)
                        .any(|w| w[0].object >= w[1].object)
                    || record.pack.is_some_and(|pack| {
                        record.actions.len() != 1 || record.actions[0].object != pack
                    })
                    || record.activation_cursor > record.actions.len()
                    || !record.preservation_pending
                {
                    return Err(unavailable());
                }
                Ok((record, raw))
            })
            .transpose()
    }
    /// Resume bounded denial activation; the preservation timer remains owned by PR2.
    /// # Errors
    /// Missing/corrupt accepted work, unavailable storage or exhausted call budget.
    pub async fn resume(
        &self,
        id: Hash,
        now: u64,
        request_budget: &SliceBudget,
    ) -> Result<(), ServerError> {
        let local = crate::purge::SliceBudget::with_parent(64, request_budget.clone());
        self.resume_with_local_budget(id, now, request_budget, &local)
            .await
    }
    pub(crate) async fn resume_with_local_budget(
        &self,
        id: Hash,
        now: u64,
        request_budget: &SliceBudget,
        local_budget: &crate::purge::SliceBudget,
    ) -> Result<(), ServerError> {
        let phase_budget = SliceBudget::new(CALLS);
        let request_store = Budgeted::new(&self.store, request_budget);
        let store = Budgeted::new(&request_store, &phase_budget);
        for _ in 0..(256 + 16) {
            let (record, old) = self.record(&store, &id).await?.ok_or_else(unavailable)?;
            let Some(reference) = record.actions.get(record.activation_cursor) else {
                return Ok(());
            };
            let raw = store
                .get(
                    &content_shard(&reference.object),
                    &staged_key(&reference.object, &id),
                )
                .await
                .map_err(|_| unavailable())?
                .ok_or_else(unavailable)?;
            if hash(raw.as_bytes()) != reference.descriptor_hash {
                return Err(unavailable());
            }
            let staged: StoredAction = decode(&raw)?;
            if staged.action.takedown_id != id
                || staged.action.reason != record.reason_token
                || staged.action.blocked_at_ms != record.created
                || staged.action.id != hash(&[id.as_slice(), reference.object.as_slice()].concat())
            {
                return Err(unavailable());
            }
            let repo = repository(&record.repository)?;
            let partition = content_shard(&reference.object);
            let operation = format!("activation:{}", to_hex(&staged.action.id));
            let purge = crate::purge::automatic::plan_repository(
                self.purge.as_ref(),
                &store,
                &partition,
                &repo,
                crate::purge::Trigger::Takedown,
                &operation,
                now,
            )
            .await
            .map_err(|_| unavailable())?;
            ContentIndex::new(BorrowedStore(&store))
                .install_stored_block_action_with_batch(&reference.object, &staged, now, purge)
                .await
                .map_err(|_| unavailable())?;
            crate::purge::automatic::invalidate_repository(
                self.purge.as_ref(),
                &partition,
                &repo,
                crate::purge::Trigger::Takedown,
                &operation,
                local_budget,
            )
            .await;
            let mut next = record.clone();
            next.activation_cursor += 1;
            let mut batch = crate::admin::plan_system(
                &store,
                &self.root,
                "system:relay",
                "system:relay/takedown-activation",
                &[to_hex(&id), to_hex(&reference.object)],
                now,
            )
            .await
            .map_err(|_| unavailable())?;
            batch
                .preconditions
                .push(Precondition::Equals(request_key(&id), old));
            batch
                .writes
                .push(crate::store::Write::Put(request_key(&id), encode(&next)?));
            store
                .apply(&self.root, batch)
                .await
                .map_err(|_| unavailable())?;
        }
        Err(unavailable())
    }
}
impl<N: NamespaceStore + Clone> AdminOperations for Service<N> {
    #[allow(clippy::too_many_lines)] // Immutable staging and root acceptance share one replayable lifecycle.
    fn plan<'a>(
        &'a self,
        path: &'a str,
        input: &'a Json,
        digest: &'a str,
        now: u64,
        request_budget: &'a SliceBudget,
    ) -> crate::BoxFuture<'a, Result<Prepared, ServerError>> {
        Box::pin(async move {
            if path != crate::admin::TAKEDOWN_PATH {
                return Err(invalid());
            }
            let request = Request::parse(input)?;
            let id = hash(
                &[
                    b"mkit-takedown:v1\0".as_slice(),
                    request.operation_id.as_bytes(),
                ]
                .concat(),
            );
            let response = Response::json(&json!({"takedownId":to_hex(&id),"complete":false}));
            let mut prepared = Prepared {
                batch: Batch::new(),
                response,
                operation_id: request.operation_id.clone(),
                label: request.operator_label.clone(),
                targets: vec![request.repository.clone()],
                details: request.reason.clone(),
            };
            let phase_budget = SliceBudget::new(CALLS);
            let request_store = Budgeted::new(&self.store, request_budget);
            let store = Budgeted::new(&request_store, &phase_budget);
            if let Some((existing, _)) = self.record(&store, &id).await? {
                if existing.digest != digest {
                    return Err(invalid());
                }
                return Ok(prepared);
            }
            let draft = self.draft(&store, id, digest, now).await?;
            let repo = repository(&request.repository)?;
            let pack = request.pack_id.as_deref().map(parse_id).transpose()?;
            let objects = if let Some(pack) = pack {
                vec![pack]
            } else {
                request
                    .object_ids
                    .iter()
                    .map(|s| parse_id(s))
                    .collect::<Result<BTreeSet<_>, _>>()?
                    .into_iter()
                    .collect()
            };
            let token = request.reason_token.unwrap_or_else(|| "manual".into());
            let mut actions = Vec::new();
            for object in objects {
                let action = BlockAction {
                    id: hash(&[id.as_slice(), object.as_slice()].concat()),
                    takedown_id: id,
                    reason: token.clone(),
                    blocked_at_ms: draft.created,
                    chunk_ids: Vec::new(),
                };
                let staged = if pack.is_some() {
                    inventory::prepare_pack(
                        &store,
                        self.shards.as_ref(),
                        &repo,
                        &object,
                        action,
                        now,
                    )
                    .await
                } else {
                    inventory::prepare_object(
                        &store,
                        self.shards.as_ref(),
                        &repo,
                        &object,
                        action,
                        now,
                    )
                    .await
                }
                .map_err(|_| unavailable())?;
                let value = encode(&staged)?;
                let key = staged_key(&object, &id);
                let partition = content_shard(&object);
                if let Some(existing) = store
                    .get(&partition, &key)
                    .await
                    .map_err(|_| unavailable())?
                {
                    if existing != value {
                        return Err(invalid());
                    }
                } else {
                    match store
                        .apply(
                            &partition,
                            Batch::new()
                                .require(Precondition::Absent(key.clone()))
                                .put(key.clone(), value.clone()),
                        )
                        .await
                        .map_err(|_| unavailable())?
                    {
                        BatchOutcome::Committed => {}
                        _ => {
                            if store
                                .get(&partition, &key)
                                .await
                                .map_err(|_| unavailable())?
                                != Some(value.clone())
                            {
                                return Err(unavailable());
                            }
                        }
                    }
                }
                actions.push(Reference {
                    object,
                    descriptor_hash: hash(value.as_bytes()),
                });
            }
            let record = Record {
                version: 1,
                id,
                digest: digest.into(),
                operation: request.operation_id,
                repository: request.repository,
                reason: request.reason,
                reason_token: token,
                created: draft.created,
                pack,
                actions,
                activation_cursor: 0,
                preservation_pending: true,
            };
            prepared.batch = Batch::new()
                .require(Precondition::Absent(request_key(&id)))
                .put(request_key(&id), encode(&record)?)
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
                &repo,
                crate::purge::Trigger::Takedown,
                &format!("acceptance:{}", to_hex(&id)),
                now,
            )
            .await
            .map_err(|_| unavailable())?;
            prepared.batch.preconditions.extend(purge.preconditions);
            prepared.batch.writes.extend(purge.writes);
            Ok(prepared)
        })
    }
    fn after_commit<'a>(
        &'a self,
        path: &'a str,
        _input: &'a Json,
        response: Response,
        now: u64,
        request_budget: &'a SliceBudget,
    ) -> crate::BoxFuture<'a, Result<Response, ServerError>> {
        Box::pin(async move {
            if path == crate::admin::TAKEDOWN_PATH && response.status == 200 {
                let local_budget =
                    crate::purge::SliceBudget::with_parent(64, request_budget.clone());
                let reply: Json =
                    serde_json::from_slice(&response.body).map_err(|_| unavailable())?;
                let id = mkit_core::hash::from_hex(
                    reply["takedownId"].as_str().ok_or_else(unavailable)?,
                )
                .map_err(|_| unavailable())?;
                if self.purge.is_some() {
                    let (record, _) = self
                        .record(&Budgeted::new(&self.store, request_budget), &id)
                        .await?
                        .ok_or_else(unavailable)?;
                    crate::purge::automatic::invalidate_repository(
                        self.purge.as_ref(),
                        &self.root,
                        &repository(&record.repository)?,
                        crate::purge::Trigger::Takedown,
                        &format!("acceptance:{}", to_hex(&id)),
                        &local_budget,
                    )
                    .await;
                }
                self.resume_with_local_budget(id, now, request_budget, &local_budget)
                    .await?;
            }
            Ok(response)
        })
    }
}
