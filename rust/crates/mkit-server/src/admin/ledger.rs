use base64::{Engine as _, engine::general_purpose::STANDARD};
use mkit_core::hash::{hash, to_hex};
use serde::{Deserialize, Serialize};
use serde_json::{Value as Json, json};

use crate::{
    Batch, BatchOutcome, Code, Key, NamespaceStore, Partition, Precondition, ServerError,
    StoreError, Value,
};

use super::{
    AUDIT_PATH, BodyCapture, Engine, Headers, MAX_BODY, Response,
    auth::{self, Verified},
    payload,
};

const RETRIES: usize = 16;
const PAGE_BYTES: usize = 256 * 1024;

#[derive(Default, Serialize, Deserialize)]
pub(super) struct Head {
    pub(super) seq: u64,
    pub(super) hash: String,
}
#[derive(Serialize, Deserialize)]
struct Nonce {
    digest: String,
    path: String,
    expiry_ms: u64,
    result: Option<Response>,
}
#[derive(Serialize, Deserialize)]
struct Operation {
    digest: String,
    path: String,
    result: Response,
}

/// A durable operation replay or an acceptance batch for a new operation.
#[derive(Debug)]
pub enum OperationReplay {
    /// The original response, including stable action identity and pending state.
    Existing(Response),
    /// Merge this guarded batch with the operation's action and audit acceptance.
    New(Batch),
}
/// Plan persistent operation-id deduplication after authentication and role checks.
/// A new action must commit this batch atomically with its audit and intent.
/// # Errors
/// Invalid identities, changed logical requests, or unavailable/corrupt storage.
pub async fn plan_operation<S: NamespaceStore>(
    store: &S,
    partition: &Partition,
    operation_id: &str,
    path: &str,
    digest: &str,
    result: Response,
) -> Result<OperationReplay, ServerError> {
    if !auth::identifier(operation_id, 128, true)
        || !path.starts_with(super::PREFIX)
        || digest
            .strip_prefix("body:")
            .and_then(auth::hex::<32>)
            .is_none()
    {
        return Err(auth::invalid("invalid operation replay identity"));
    }
    let key = key("ao", operation_id.as_bytes());
    if let Some(value) = store.get(partition, &key).await.map_err(store_error)? {
        let first: Operation = decode(&value)?;
        if first.digest != digest || first.path != path {
            return Err(auth::invalid(
                "operation id reused with a different request",
            ));
        }
        return Ok(OperationReplay::Existing(first.result));
    }
    let value = encode(&Operation {
        digest: digest.into(),
        path: path.into(),
        result,
    })?;
    Ok(OperationReplay::New(
        Batch::new()
            .require(Precondition::Absent(key.clone()))
            .put(key, value),
    ))
}

fn key(tag: &str, suffix: &[u8]) -> Key {
    Key::new([tag.as_bytes(), b"\0", suffix].concat())
}
pub(super) fn head_key() -> Key {
    key("ah", b"")
}
fn entry_key(seq: u64) -> Key {
    key("ae", &seq.to_be_bytes())
}
fn store_error(_: StoreError) -> ServerError {
    ServerError::new(Code::Unavailable, "admin storage unavailable")
}
pub(super) fn encode<T: Serialize>(value: &T) -> Result<Value, ServerError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|_| ServerError::new(Code::Internal, "admin encoding failed"))?;
    if bytes.len() > crate::MAX_VALUE_BYTES {
        return Err(ServerError::new(
            Code::Internal,
            "admin replay result exceeds storage bound",
        ));
    }
    Ok(Value::new(bytes))
}
pub(super) fn decode<T: serde::de::DeserializeOwned>(value: &Value) -> Result<T, ServerError> {
    serde_json::from_slice(value.as_bytes())
        .map_err(|_| ServerError::new(Code::DataLoss, "corrupt admin ledger"))
}
pub(super) fn guarded(batch: Batch, key: Key, old: Option<Value>) -> Batch {
    batch.require(match old {
        Some(value) => Precondition::Equals(key, value),
        None => Precondition::Absent(key),
    })
}
fn previous(head: &Head) -> String {
    if head.seq == 0 {
        "00".repeat(32)
    } else {
        head.hash.clone()
    }
}
pub(super) fn decode_head(value: Option<&Value>) -> Result<Head, ServerError> {
    let head: Head = value.map_or_else(|| Ok(Head::default()), decode)?;
    if head.seq > 0 && auth::hex::<32>(&head.hash).is_none() {
        return Err(ServerError::new(Code::DataLoss, "corrupt audit head"));
    }
    Ok(head)
}
fn hash_entry(entry: &Json) -> Result<String, ServerError> {
    let mut value = entry.clone();
    value
        .as_object_mut()
        .ok_or_else(|| ServerError::new(Code::DataLoss, "corrupt audit entry"))?
        .remove("entryHash");
    // Every key is fixed ASCII, integers are decimal strings, and there are no
    // floats: serde_json's sorted map and UTF-8 string encoding are JCS here.
    let mut bytes = b"mkit-admin-audit:v1".to_vec();
    bytes.extend(
        serde_json::to_vec(&value)
            .map_err(|_| ServerError::new(Code::Internal, "audit encoding failed"))?,
    );
    Ok(to_hex(&hash(&bytes)))
}
#[allow(clippy::too_many_arguments)] // Every fixed canonical audit field is explicit at its three append sites.
pub(super) fn audit_entry(
    head: &Head,
    actor: &str,
    path: &str,
    digest: &str,
    nonce: &str,
    operation: &str,
    label: &str,
    targets: &[String],
    result: &Response,
    details: &str,
    now: u64,
) -> Result<(Json, Head), ServerError> {
    let seq = head
        .seq
        .checked_add(1)
        .ok_or_else(|| ServerError::new(Code::Internal, "audit sequence exhausted"))?;
    let outcome = if result.status == 200 {
        json!({"code":"ok","message":""})
    } else {
        serde_json::from_slice::<Json>(&result.body)
            .map_err(|_| ServerError::new(Code::Internal, "invalid audit result"))?
    };
    let mut entry = json!({"seq":seq.to_string(),"recordedAtMs":now.to_string(),"actor":actor,"procedure":path,
        "requestDigest":digest,"nonce":nonce,"targets":targets,"result":outcome,"details":details,"prevHash":previous(head)});
    if !operation.is_empty() {
        entry["operationId"] = json!(operation);
    }
    if !label.is_empty() {
        entry["operatorLabel"] = json!(label);
    }
    let entry_hash = hash_entry(&entry)?;
    entry["entryHash"] = json!(entry_hash);
    Ok((
        entry,
        Head {
            seq,
            hash: entry_hash,
        },
    ))
}

/// Plan an automatic action's audit append; combine this batch with the action
/// acceptance batch and retry planning if any CAS guard loses.
///
/// # Errors
/// Invalid automatic actor/target or corrupt/unavailable audit storage.
pub async fn plan_system<S: NamespaceStore>(
    store: &S,
    partition: &Partition,
    actor: &str,
    procedure: &str,
    targets: &[String],
    now_ms: u64,
) -> Result<Batch, StoreError> {
    if !matches!(actor, "system:inspector" | "system:timer" | "system:relay")
        || !procedure.starts_with(&format!("{actor}/"))
        || procedure.len() > 256
        || procedure.chars().any(char::is_control)
        || targets.len() > 256
        || targets
            .iter()
            .any(|t| t.len() > 1024 || t.chars().any(char::is_control))
    {
        return Err(StoreError::Invalid("invalid system audit identity".into()));
    }
    let old = store.get(partition, &head_key()).await?;
    let head =
        decode_head(old.as_ref()).map_err(|_| StoreError::Invalid("corrupt audit head".into()))?;
    let (entry, next) = audit_entry(
        &head,
        actor,
        procedure,
        "",
        "",
        "",
        "",
        targets,
        &Response::json(&json!({})),
        "",
        now_ms,
    )
    .map_err(|_| StoreError::Invalid("invalid audit entry".into()))?;
    let batch = guarded(Batch::new(), head_key(), old)
        .put(
            entry_key(next.seq),
            encode(&entry).map_err(|_| StoreError::Invalid("audit entry too large".into()))?,
        )
        .put(
            head_key(),
            encode(&next).map_err(|_| StoreError::Invalid("invalid audit head".into()))?,
        );
    Ok(batch)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReadInput {
    #[serde(alias = "from_seq")]
    from_seq: Json,
    #[serde(alias = "page_size")]
    page_size: Json,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PurgeInput {
    #[serde(alias = "operation_id")]
    operation_id: String,
    #[serde(default)]
    repository: String,
    #[serde(default)]
    namespace: String,
    #[serde(default, alias = "url_paths")]
    url_paths: Vec<String>,
    #[serde(default, alias = "object_ids")]
    object_ids: Vec<String>,
    #[serde(default)]
    refs: Vec<String>,
    reason: String,
    #[serde(default, alias = "operator_label")]
    operator_label: String,
}
enum Action {
    Read(u64, u32),
    Failure(ServerError),
    Extension(Json),
}
impl<S: NamespaceStore> Engine<S> {
    #[allow(clippy::too_many_lines)] // Authentication, durable nonce reservation and terminal audited dispatch share one lifecycle.
    pub(super) async fn dispatch(
        &self,
        path: &str,
        headers: &Headers,
        wire: &BodyCapture,
        decoded: Option<Result<Vec<u8>, ServerError>>,
        now: i64,
        streaming: bool,
    ) -> Result<Response, ServerError> {
        let verified = self.config.verify(path, headers, wire, now)?;
        let budget = crate::indexed::budget::SliceBudget::new(9_000);
        let nonce_key = key("an", verified.replay_key.as_bytes());
        let nonce = Nonce {
            digest: verified.digest.clone(),
            path: path.to_owned(),
            expiry_ms: verified.expiry_ms,
            result: None,
        };
        let nonce_value = encode(&nonce)?;
        match self
            .store
            .apply(
                &self.partition,
                Batch::new()
                    .require(Precondition::Absent(nonce_key.clone()))
                    .put(nonce_key.clone(), nonce_value.clone()),
            )
            .await
            .map_err(store_error)?
        {
            BatchOutcome::Committed => {}
            BatchOutcome::PreconditionFailed {
                observed: Some(existing),
                ..
            } => {
                let old: Nonce = decode(&existing)?;
                if old.digest != verified.digest || old.path != path {
                    return self
                        .conflict(
                            &verified,
                            now,
                            "admin nonce reused with a different request",
                        )
                        .await;
                }
                if path == super::READ_PRESERVED_PATH && !streaming {
                    return self
                        .record_result(
                            &verified,
                            now,
                            Response::error(&ServerError::failed_precondition(
                                "streaming admin adapter required",
                            )),
                        )
                        .await;
                }
                let Some(result) = old.result else {
                    return self
                        .record_result(
                            &verified,
                            now,
                            Response::error(&ServerError::new(
                                Code::Aborted,
                                "admin request is in flight",
                            )),
                        )
                        .await;
                };
                return self
                    .finish_extension(
                        &verified,
                        wire,
                        decoded.as_ref(),
                        result,
                        now,
                        &budget,
                        true,
                    )
                    .await;
            }
            _ => {
                return Err(ServerError::new(
                    Code::Unavailable,
                    "admin nonce reservation failed",
                ));
            }
        }
        let decoded_reply = decoded.clone();
        let action = if !verified.roles.contains("all")
            && !verified.roles.contains(if path == AUDIT_PATH {
                "audit"
            } else {
                "moderation"
            }) {
            Action::Failure(ServerError::permission_denied(
                "admin key lacks required role",
            ))
        } else if path == super::READ_PRESERVED_PATH && !streaming {
            Action::Failure(ServerError::failed_precondition(
                "streaming admin adapter required",
            ))
        } else if wire.oversized {
            Action::Failure(auth::invalid("admin request exceeds 1 MiB"))
        } else {
            let bytes = decoded.unwrap_or_else(|| Ok(wire.bytes.clone()));
            match bytes.and_then(|bytes| {
                if bytes.len() > MAX_BODY {
                    return Err(auth::invalid("decoded admin request exceeds 1 MiB"));
                }
                let body = payload(path, &bytes)?;
                if path == AUDIT_PATH {
                    let input: ReadInput = serde_json::from_slice(body)
                        .map_err(|_| auth::invalid("invalid ReadAuditLog JSON"))?;
                    let number = |j: &Json| {
                        j.as_str()
                            .and_then(auth::decimal_u64)
                            .or_else(|| j.as_u64())
                    };
                    let from = number(&input.from_seq)
                        .filter(|n| *n >= 1)
                        .ok_or_else(|| auth::invalid("invalid audit sequence"))?;
                    let size = number(&input.page_size)
                        .filter(|n| (1..=100).contains(n))
                        .ok_or_else(|| auth::invalid("invalid audit page size"))?;
                    Ok(Action::Read(
                        from,
                        u32::try_from(size)
                            .map_err(|_| auth::invalid("invalid audit page size"))?,
                    ))
                } else if path == super::PURGE_PATH
                    || super::extension_path(path) && self.operations.is_some()
                {
                    let input = serde_json::from_slice(body)
                        .map_err(|_| auth::invalid("invalid admin JSON"))?;
                    Ok(Action::Extension(input))
                } else {
                    Err(ServerError::new(
                        Code::Unimplemented,
                        "admin operation is outside the launch subset",
                    ))
                }
            }) {
                Ok(action) => action,
                Err(error) => Action::Failure(error),
            }
        };
        let response = self
            .complete(&verified, &nonce_key, &nonce_value, action, now, &budget)
            .await?;
        self.finish_extension(
            &verified,
            wire,
            decoded_reply.as_ref(),
            response,
            now,
            &budget,
            false,
        )
        .await
    }

    async fn conflict(
        &self,
        verified: &Verified,
        now: i64,
        message: &str,
    ) -> Result<Response, ServerError> {
        self.record_result(verified, now, Response::error(&auth::invalid(message)))
            .await
    }

    pub(super) async fn record_result(
        &self,
        verified: &Verified,
        now: i64,
        result: Response,
    ) -> Result<Response, ServerError> {
        for _ in 0..RETRIES {
            let old = self
                .store
                .get(&self.partition, &head_key())
                .await
                .map_err(store_error)?;
            let head = decode_head(old.as_ref())?;
            let (entry, next) = audit_entry(
                &head,
                &verified.actor,
                &verified.path,
                &verified.digest,
                &verified.nonce,
                "",
                "",
                &[],
                &result,
                "",
                u64::try_from(now).unwrap_or(0),
            )?;
            let batch = guarded(Batch::new(), head_key(), old)
                .put(entry_key(next.seq), encode(&entry)?)
                .put(head_key(), encode(&next)?);
            if self
                .store
                .apply(&self.partition, batch)
                .await
                .map_err(store_error)?
                == BatchOutcome::Committed
            {
                return Ok(result);
            }
        }
        Err(ServerError::new(Code::Unavailable, "audit contention"))
    }

    #[allow(clippy::too_many_lines)] // Audit, action acceptance, replay and purge effects must be assembled in one guarded transaction.
    async fn complete(
        &self,
        verified: &Verified,
        nonce_key: &Key,
        nonce_value: &Value,
        action: Action,
        now: i64,
        budget: &crate::indexed::budget::SliceBudget,
    ) -> Result<Response, ServerError> {
        let now = u64::try_from(now)
            .map_err(|_| ServerError::new(Code::Unavailable, "invalid backend clock"))?;
        for _ in 0..RETRIES {
            let old = self
                .store
                .get(&self.partition, &head_key())
                .await
                .map_err(store_error)?;
            let head = decode_head(old.as_ref())?;
            let mut batch = guarded(Batch::new(), head_key(), old);
            let mut metadata = (String::new(), String::new(), Vec::new(), String::new());
            let response = match &action {
                Action::Failure(error) => Response::error(error),
                Action::Read(from, size) => {
                    let result = self.read_page(&head, *from, *size).await;
                    result.unwrap_or_else(|e| Response::error(&e))
                }
                Action::Extension(input) => {
                    let planned = if verified.path == super::PURGE_PATH {
                        self.plan_purge(input, &verified.digest, now).await
                    } else if let Some(service) = &self.operations {
                        service
                            .plan(&verified.path, input, &verified.digest, now, budget)
                            .await
                    } else {
                        Err(ServerError::new(
                            Code::Unimplemented,
                            "admin operation unavailable",
                        ))
                    };
                    match planned {
                        Err(error) => Response::error(&error),
                        Ok(prepared) => {
                            metadata = (
                                prepared.operation_id,
                                prepared.label,
                                prepared.targets,
                                prepared.details,
                            );
                            let replay = if metadata.0.is_empty() {
                                Ok(OperationReplay::New(Batch::new()))
                            } else {
                                plan_operation(
                                    &self.store,
                                    &self.partition,
                                    &metadata.0,
                                    &verified.path,
                                    &verified.digest,
                                    prepared.response.clone(),
                                )
                                .await
                            };
                            match replay {
                                Ok(OperationReplay::Existing(result)) => result,
                                Ok(OperationReplay::New(replay)) => {
                                    batch.preconditions.extend(prepared.batch.preconditions);
                                    batch.writes.extend(prepared.batch.writes);
                                    batch.preconditions.extend(replay.preconditions);
                                    batch.writes.extend(replay.writes);
                                    prepared.response
                                }
                                Err(error) => Response::error(&error),
                            }
                        }
                    }
                }
            };
            let (entry, next) = audit_entry(
                &head,
                &verified.actor,
                &verified.path,
                &verified.digest,
                &verified.nonce,
                &metadata.0,
                &metadata.1,
                &metadata.2,
                &response,
                &metadata.3,
                now,
            )?;
            let terminal = Nonce {
                digest: verified.digest.clone(),
                path: verified.path.clone(),
                expiry_ms: verified.expiry_ms,
                result: Some(response.clone()),
            };
            let batch = batch
                .require(Precondition::Equals(nonce_key.clone(), nonce_value.clone()))
                .put(entry_key(next.seq), encode(&entry)?)
                .put(head_key(), encode(&next)?)
                .put(nonce_key.clone(), encode(&terminal)?);
            if self
                .store
                .apply(&self.partition, batch)
                .await
                .map_err(store_error)?
                == BatchOutcome::Committed
            {
                return Ok(response);
            }
        }
        Err(ServerError::new(
            Code::Unavailable,
            "admin acceptance contention",
        ))
    }

    async fn finish_extension(
        &self,
        verified: &Verified,
        wire: &BodyCapture,
        decoded: Option<&Result<Vec<u8>, ServerError>>,
        response: Response,
        now: i64,
        budget: &crate::indexed::budget::SliceBudget,
        replayed: bool,
    ) -> Result<Response, ServerError> {
        if response.status != 200
            || !matches!(
                verified.path.as_str(),
                super::TAKEDOWN_PATH | super::READ_PRESERVED_PATH
            )
        {
            return Ok(response);
        }
        let Some(service) = &self.operations else {
            return Err(ServerError::unavailable("takedown service unavailable"));
        };
        if !verified.roles.contains("moderation") && !verified.roles.contains("all") {
            return self
                .record_result(
                    verified,
                    now,
                    Response::error(&ServerError::permission_denied(
                        "admin key lacks required role",
                    )),
                )
                .await;
        }
        let bytes = match decoded {
            Some(Ok(bytes)) => bytes.as_slice(),
            Some(Err(error)) => {
                return self
                    .record_result(verified, now, Response::error(error))
                    .await;
            }
            None => &wire.bytes,
        };
        let input = serde_json::from_slice(payload(&verified.path, bytes)?)
            .map_err(|_| auth::invalid("invalid admin JSON"))?;
        if verified.path == super::READ_PRESERVED_PATH {
            // The stored descriptor carries no bytes. Every retry performs fresh
            // policy/ownership checks and commits its own acceptance audit.
            let result = service
                .plan(
                    &verified.path,
                    &input,
                    &verified.digest,
                    u64::try_from(now).map_err(|_| auth::invalid("invalid clock"))?,
                    budget,
                )
                .await
                .map_or_else(|e| Response::error(&e), |p| p.response);
            return if replayed || result.status != 200 {
                self.record_result(verified, now, result).await
            } else {
                Ok(result)
            };
        }
        match service
            .after_commit(
                &verified.path,
                &input,
                response,
                u64::try_from(now).map_err(|_| auth::invalid("invalid clock"))?,
                budget,
            )
            .await
        {
            Ok(response) => Ok(response),
            Err(error) => {
                self.record_result(verified, now, Response::error(&error))
                    .await
            }
        }
    }

    async fn plan_purge(
        &self,
        input: &Json,
        digest: &str,
        now: u64,
    ) -> Result<super::Prepared, ServerError> {
        let input: PurgeInput = serde_json::from_value(input.clone())
            .map_err(|_| auth::invalid("invalid PurgeCache JSON"))?;
        if !auth::identifier(&input.operation_id, 128, true)
            || input.reason.is_empty()
            || input.reason.len() > 4096
            || input.operator_label.len() > 256
            || input
                .reason
                .chars()
                .chain(input.operator_label.chars())
                .any(char::is_control)
        {
            return Err(auth::invalid("invalid purge identity or reason"));
        }
        let id = to_hex(&hash(
            format!(
                "mkit-manual-purge:v1\0{}\0{}",
                self.config.audience, input.operation_id
            )
            .as_bytes(),
        ));
        let request = crate::purge::Request {
            purge_id: id.clone(),
            audience: self.config.audience.clone(),
            repository: input.repository,
            namespace: input.namespace,
            trigger: crate::purge::Trigger::Manual,
            url_paths: input.url_paths,
            object_ids: input.object_ids,
            refs: input.refs,
        };
        request
            .validate()
            .map_err(|_| auth::invalid("invalid purge selectors"))?;
        let mut prepared = super::Prepared {
            batch: Batch::new(),
            response: Response::json(&json!({"purgeId":id})),
            operation_id: input.operation_id,
            label: input.operator_label,
            targets: vec![request.scope().into()],
            details: input.reason,
        };
        if let OperationReplay::Existing(response) = plan_operation(
            &self.store,
            &self.partition,
            &prepared.operation_id,
            super::PURGE_PATH,
            digest,
            prepared.response.clone(),
        )
        .await?
        {
            prepared.response = response;
            return Ok(prepared);
        }
        if !self.purge_enabled {
            return Err(ServerError::failed_precondition(
                "purge interface not configured",
            ));
        }
        let rows = self
            .store
            .get_many(
                &self.partition,
                &[
                    crate::store::keys::outcome_backlog(),
                    crate::store::keys::cache_purge_generation(request.scope()),
                ],
            )
            .await
            .map_err(store_error)?;
        if rows.len() != 2 {
            return Err(ServerError::new(Code::DataLoss, "invalid purge state"));
        }
        prepared.batch =
            crate::purge::plan_enqueue(&request, now, rows[0].as_ref(), rows[1].as_ref())
                .map_err(store_error)?;
        Ok(prepared)
    }

    async fn read_page(&self, head: &Head, from: u64, size: u32) -> Result<Response, ServerError> {
        if from > head.seq.saturating_add(1) {
            return Err(auth::invalid("audit sequence beyond chain head"));
        }
        let mut entries = Vec::new();
        let mut next = from;
        let mut previous_hash = if from == 1 {
            "00".repeat(32)
        } else {
            let row = self
                .store
                .get(&self.partition, &entry_key(from - 1))
                .await
                .map_err(store_error)?
                .ok_or_else(|| ServerError::new(Code::DataLoss, "audit sequence gap"))?;
            let entry: Json = decode(&row)?;
            if hash_entry(&entry)? != entry["entryHash"].as_str().unwrap_or("") {
                return Err(ServerError::new(Code::DataLoss, "audit hash mismatch"));
            }
            entry["entryHash"]
                .as_str()
                .ok_or_else(|| ServerError::new(Code::DataLoss, "invalid audit hash"))?
                .to_owned()
        };
        let mut bytes = 0usize;
        // Eight bounded values use at most 4 MiB before decoding. A full
        // 100-entry page costs at most thirteen DO reads, rather than 100.
        'pages: while next <= head.seq && entries.len() < size as usize {
            let count = (size as usize - entries.len()).min(8).min(
                usize::try_from(head.seq - next)
                    .unwrap_or(usize::MAX)
                    .saturating_add(1),
            );
            let keys: Vec<_> = (0..count).map(|i| entry_key(next + i as u64)).collect();
            let rows = self
                .store
                .get_many(&self.partition, &keys)
                .await
                .map_err(store_error)?;
            if rows.len() != count {
                return Err(ServerError::new(Code::DataLoss, "invalid audit read count"));
            }
            for row in rows {
                let row =
                    row.ok_or_else(|| ServerError::new(Code::DataLoss, "audit sequence gap"))?;
                if bytes.saturating_add(row.as_bytes().len()) > PAGE_BYTES && !entries.is_empty() {
                    break 'pages;
                }
                bytes = bytes.saturating_add(row.as_bytes().len());
                let mut entry: Json = decode(&row)?;
                let entry_hash = hash_entry(&entry)?;
                if entry["seq"].as_str().and_then(auth::decimal_u64) != Some(next)
                    || entry["prevHash"] != previous_hash
                    || entry["entryHash"] != entry_hash
                {
                    return Err(ServerError::new(
                        Code::DataLoss,
                        "audit chain continuity failure",
                    ));
                }
                previous_hash = entry_hash;
                for field in ["prevHash", "entryHash"] {
                    let raw = auth::hex::<32>(entry[field].as_str().unwrap_or(""))
                        .ok_or_else(|| ServerError::new(Code::DataLoss, "invalid audit hash"))?;
                    entry[field] = json!(STANDARD.encode(raw));
                }
                entries.push(entry);
                next = next
                    .checked_add(1)
                    .ok_or_else(|| ServerError::new(Code::DataLoss, "audit sequence overflow"))?;
            }
        }
        if next > head.seq && previous_hash != previous(head) {
            return Err(ServerError::new(
                Code::DataLoss,
                "audit chain head mismatch",
            ));
        }
        let head_hash = auth::hex::<32>(&previous(head))
            .ok_or_else(|| ServerError::new(Code::DataLoss, "corrupt audit head"))?;
        Response::stream(
            &json!({"entries":entries,"nextSeq":next.to_string(),"chainHead":STANDARD.encode(head_hash),
            "chainHeadSeq":head.seq.to_string(),"checkpointHash":STANDARD.encode([0u8;32]),"checkpointSeq":"0"}),
        )
    }
}
