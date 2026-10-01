//! Restricted launch catalog on the existing signed operator transaction.
use super::{
    Service, copy, intent,
    work::{self, ObjectInfo, Phase, State, Work},
};
use crate::{
    Batch, BlobStore, Code, Cursor, Key, NamespaceStore, ServerError,
    admin::{self, AdminOperations, Prepared, PreservedPiece, Response},
    indexed::budget::{Budgeted, SliceBudget},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use mkit_core::hash::{Hash, from_hex, to_hex};
use serde::{Deserialize, Serialize};
use serde_json::{Value as Json, json};
const PAGE_BYTES: usize = 256 * 1024;
const REQUEST_PREFIX: &[u8] = b"b\0\xffrequest\0";
fn invalid() -> ServerError {
    ServerError::invalid_argument("invalid restricted admin request")
}
fn storage(_: crate::StoreError) -> ServerError {
    ServerError::unavailable("preservation storage unavailable")
}
fn corrupt() -> ServerError {
    ServerError::new(Code::DataLoss, "invalid preserved copy metadata")
}
fn id(s: &str) -> Result<Hash, ServerError> {
    from_hex(s)
        .ok()
        .filter(|id| to_hex(id) == s)
        .ok_or_else(invalid)
}
fn object_id(s: &str) -> Result<Hash, ServerError> {
    let bytes = STANDARD.decode(s).map_err(|_| invalid())?;
    if STANDARD.encode(&bytes) != s {
        return Err(invalid());
    }
    bytes.try_into().map_err(|_| invalid())
}
fn number(value: &Json) -> Result<u64, ServerError> {
    value
        .as_str()
        .and_then(admin::auth::decimal_u64)
        .or_else(|| value.as_u64())
        .ok_or_else(invalid)
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Get {
    #[serde(alias = "takedown_id")]
    takedown_id: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Hold {
    #[serde(alias = "takedown_id")]
    takedown_id: String,
    enabled: bool,
    reason: String,
    #[serde(default, alias = "operator_label")]
    operator_label: String,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Read {
    #[serde(alias = "takedown_id")]
    takedown_id: String,
    #[serde(alias = "object_id")]
    object_id: String,
    #[serde(default)]
    offset: Json,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct List {
    #[serde(default)]
    scope: Option<Scope>,
    #[serde(alias = "page_size")]
    page_size: Json,
    #[serde(default, alias = "page_token")]
    page_token: String,
}
#[derive(Default, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Scope {
    #[serde(default)]
    repository: Option<String>,
    #[serde(default)]
    namespace: Option<String>,
}
impl Scope {
    fn validate(&self) -> Result<(), ServerError> {
        match (&self.repository, &self.namespace) {
            (Some(repo), None) => {
                intent::repository(repo)?;
            }
            (None, Some(ns)) => {
                intent::repository(&format!("{ns}/repo"))?;
            }
            (None, None) => {}
            _ => return Err(invalid()),
        }
        Ok(())
    }
    fn matches(&self, repo: &str) -> bool {
        self.repository.is_none() && self.namespace.is_none()
            || self.repository.as_deref() == Some(repo)
            || self.namespace.as_deref() == repo.rsplit_once('/').map(|(ns, _)| ns)
    }
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PageToken {
    scope: Scope,
    after: String,
}
fn prepared(response: Response, targets: Vec<String>) -> Prepared {
    Prepared {
        batch: Batch::new(),
        response,
        operation_id: String::new(),
        label: String::new(),
        targets,
        details: String::new(),
    }
}
impl<N: NamespaceStore + Clone, B: BlobStore, P: BlobStore> Work<N, B, P> {
    async fn record_state<S: NamespaceStore>(
        &self,
        store: &S,
        action: &Hash,
    ) -> Result<(intent::Record, State), ServerError> {
        let service = Service::new(
            self.metadata.clone(),
            self.root.clone(),
            self.shards.clone(),
        );
        let (record, _) = service
            .record(store, action)
            .await?
            .ok_or_else(|| ServerError::new(Code::NotFound, "takedown not found"))?;
        let (state, _) = self
            .state(store, action, record.created)
            .await
            .map_err(storage)?;
        Ok((record, state))
    }
    async fn status<S: NamespaceStore>(
        &self,
        store: &S,
        action: &Hash,
    ) -> Result<Json, ServerError> {
        let (record, state) = self.record_state(store, action).await?;
        let any = matches!(&self.addressing, crate::Addressing::Multi(multi) if matches!(multi.namespace_policy, crate::policy::NamespacePolicy::Any { .. }));
        let discovery = if state.discovery_complete && !any {
            "complete"
        } else if state.phase == Phase::Retain || state.resume_phase == Phase::Retain {
            "incomplete"
        } else if state.acquisition_complete() {
            "in_progress"
        } else {
            "pending"
        };
        Ok(
            json!({"takedownId":to_hex(action), "level":"TAKEDOWN_LEVEL_CONTENT",
            "objectIds":if record.pack.is_some() { vec![] } else { record.actions.iter().map(|a| STANDARD.encode(a.object)).collect::<Vec<_>>() },
            "repository":record.repository, "namespace":intent::repository(&record.repository)?.namespace.as_str(),
            "reason":record.reason, "reasonToken":record.reason_token, "complete":false,
            "createdAtMs":record.created.to_string(), "retentionUntilMs":state.retain_until.to_string(),
            "acquisitionPending":!state.acquisition_complete(), "preservationVerified":state.acquisition_complete(),
            "discoveryStatus":discovery, "legalHold":state.hold, "preservationPurged":state.purged}),
        )
    }
    async fn list<S: NamespaceStore>(
        &self,
        store: &S,
        input: &Json,
    ) -> Result<Prepared, ServerError> {
        let input: List = serde_json::from_value(input.clone()).map_err(|_| invalid())?;
        let scope = input.scope.unwrap_or_default();
        scope.validate()?;
        let page_size = u32::try_from(number(&input.page_size)?).map_err(|_| invalid())?;
        if !(1..=100).contains(&page_size) || input.page_token.len() > 2048 {
            return Err(invalid());
        }
        let cursor = if input.page_token.is_empty() {
            None
        } else {
            let raw = STANDARD.decode(&input.page_token).map_err(|_| invalid())?;
            if STANDARD.encode(&raw) != input.page_token {
                return Err(invalid());
            }
            let token: PageToken = serde_json::from_slice(&raw).map_err(|_| invalid())?;
            if token.scope != scope {
                return Err(invalid());
            }
            Some(Cursor::new(
                intent::request_key(&id(&token.after)?).as_bytes().to_vec(),
            ))
        };
        let start = Key::new(REQUEST_PREFIX.to_vec());
        let mut end = REQUEST_PREFIX.to_vec();
        *end.last_mut().ok_or_else(invalid)? = 1;
        let page = store
            .scan(
                &self.root,
                &start,
                &Key::new(end),
                cursor.as_ref(),
                page_size,
            )
            .await
            .map_err(storage)?;
        let mut records = Vec::new();
        let mut bytes = 0;
        let mut after = None;
        let mut more = page.next.is_some();
        for (key, raw) in &page.entries {
            let action: Hash = key
                .as_bytes()
                .strip_prefix(REQUEST_PREFIX)
                .ok_or_else(corrupt)?
                .try_into()
                .map_err(|_| corrupt())?;
            let record: intent::Record = intent::decode(raw)?;
            if record.id != action {
                return Err(corrupt());
            }
            if scope.matches(&record.repository) {
                let status = self.status(store, &action).await?;
                let size = serde_json::to_vec(&status).map_err(|_| corrupt())?.len();
                if bytes + size > PAGE_BYTES {
                    more = true;
                    break;
                }
                bytes += size;
                records.push(status);
            }
            after = Some(action);
        }
        let token = if more {
            let token = PageToken {
                scope,
                after: to_hex(&after.ok_or_else(corrupt)?),
            };
            STANDARD.encode(serde_json::to_vec(&token).map_err(|_| corrupt())?)
        } else {
            String::new()
        };
        Ok(prepared(
            Response::json(&json!({"takedowns":records,"nextPageToken":token})),
            vec![],
        ))
    }
    async fn readable<S: NamespaceStore>(
        &self,
        store: &S,
        read: &Read,
    ) -> Result<(Hash, Hash, u64, ObjectInfo), ServerError> {
        let action = id(&read.takedown_id)?;
        let object = object_id(&read.object_id)?;
        let offset = if read.offset.is_null() {
            0
        } else {
            number(&read.offset)?
        };
        let (_, state) = self.record_state(store, &action).await?;
        let now = u64::try_from(self.clock.now_ms())
            .map_err(|_| storage(crate::StoreError::unavailable("clock")))?;
        if state.purged
            || matches!(state.phase, Phase::Purging | Phase::Purged)
            || !state.hold && now >= state.retain_until
        {
            return Err(ServerError::failed_precondition(
                "preservation retention has ended",
            ));
        }
        let info = self.info(store, &action, &object).await.map_err(storage)?;
        if !state.acquisition_complete() || !info.verified || info.copied != info.size {
            return Err(ServerError::new(Code::NotFound, "object not preserved"));
        }
        if offset > info.size {
            return Err(invalid());
        }
        Ok((action, object, offset, info))
    }
}
impl<N: NamespaceStore + Clone, B: BlobStore, P: BlobStore> AdminOperations for Work<N, B, P> {
    fn preserved_now_ms(&self) -> Result<i64, ServerError> {
        let now = self.clock.now_ms();
        if now < 0 {
            return Err(ServerError::unavailable("preservation clock unavailable"));
        }
        Ok(now)
    }
    fn plan<'a>(
        &'a self,
        path: &'a str,
        input: &'a Json,
        digest: &'a str,
        now: u64,
        budget: &'a SliceBudget,
    ) -> crate::BoxFuture<'a, Result<Prepared, ServerError>> {
        Box::pin(async move {
            let store = Budgeted::new(&self.metadata, budget);
            match path {
                admin::TAKEDOWN_PATH => {
                    Service::new(
                        self.metadata.clone(),
                        self.root.clone(),
                        self.shards.clone(),
                    )
                    .plan(path, input, digest, now, budget)
                    .await
                }
                admin::GET_TAKEDOWN_PATH => {
                    let input: Get =
                        serde_json::from_value(input.clone()).map_err(|_| invalid())?;
                    Ok(prepared(
                        Response::json(
                            &json!({"takedown":self.status(&store, &id(&input.takedown_id)?).await?}),
                        ),
                        vec![input.takedown_id],
                    ))
                }
                admin::LIST_TAKEDOWNS_PATH => self.list(&store, input).await,
                admin::SET_LEGAL_HOLD_PATH => {
                    let input: Hold =
                        serde_json::from_value(input.clone()).map_err(|_| invalid())?;
                    if input.reason.is_empty()
                        || input.reason.len() > 512
                        || input.operator_label.len() > 128
                        || input
                            .reason
                            .chars()
                            .chain(input.operator_label.chars())
                            .any(char::is_control)
                    {
                        return Err(invalid());
                    }
                    let action = id(&input.takedown_id)?;
                    self.record_state(&store, &action).await?;
                    let batch = self
                        .plan_legal_hold(&store, action, input.enabled, now)
                        .await
                        .map_err(|_| {
                            ServerError::failed_precondition("preservation legal hold unavailable")
                        })?;
                    let mut prepared = prepared(
                        Response::json(&json!({"enabled":input.enabled})),
                        vec![input.takedown_id],
                    );
                    prepared.batch = batch;
                    prepared.label = input.operator_label;
                    prepared.details = input.reason;
                    Ok(prepared)
                }
                admin::READ_PRESERVED_PATH => {
                    let mut read: Read =
                        serde_json::from_value(input.clone()).map_err(|_| invalid())?;
                    let (_, _, offset, _) = self.readable(&store, &read).await?;
                    read.offset = json!(offset.to_string());
                    Ok(prepared(
                        Response::json(&serde_json::to_value(&read).map_err(|_| invalid())?),
                        vec![read.takedown_id, read.object_id],
                    ))
                }
                _ => Err(ServerError::new(
                    Code::Unimplemented,
                    "admin operation unavailable",
                )),
            }
        })
    }
    fn after_commit<'a>(
        &'a self,
        path: &'a str,
        input: &'a Json,
        response: Response,
        now: u64,
        budget: &'a SliceBudget,
    ) -> crate::BoxFuture<'a, Result<Response, ServerError>> {
        Box::pin(async move {
            Service::new(
                self.metadata.clone(),
                self.root.clone(),
                self.shards.clone(),
            )
            .after_commit(path, input, response, now, budget)
            .await
        })
    }
    fn preserved_piece<'a>(
        &'a self,
        descriptor: &'a Json,
    ) -> crate::BoxFuture<'a, Result<PreservedPiece, ServerError>> {
        Box::pin(async move {
            let read: Read = serde_json::from_value(descriptor.clone()).map_err(|_| invalid())?;
            let budget = SliceBudget::new(16);
            let store = Budgeted::new(&self.metadata, &budget);
            let (action, object, offset, info) = self.readable(&store, &read).await?;
            let data = if offset == info.size {
                Bytes::new()
            } else {
                let start = offset / copy::PIECE_BYTES as u64 * copy::PIECE_BYTES as u64;
                let raw = store
                    .get(
                        &self.root,
                        &work::key(
                            b"piece",
                            &action,
                            &[object.as_slice(), &start.to_be_bytes()].concat(),
                        ),
                    )
                    .await
                    .map_err(storage)?
                    .ok_or_else(|| {
                        ServerError::new(Code::NotFound, "preserved piece unavailable")
                    })?;
                let piece: copy::Piece = intent::decode(&raw)?;
                let expected = (info.size - start).min(copy::PIECE_BYTES as u64);
                if piece.object != object
                    || piece.offset != start
                    || u64::from(piece.length) != expected
                {
                    return Err(corrupt());
                }
                let bytes = copy::read(&Budgeted::new(&self.preserved, &budget), &action, &piece)
                    .await
                    .map_err(|_| corrupt())?
                    .ok_or_else(|| {
                        ServerError::new(Code::NotFound, "preserved piece unavailable")
                    })?;
                bytes.slice(usize::try_from(offset - start).map_err(|_| corrupt())?..)
            };
            // A purge or retention transition during I/O cannot authorize this piece.
            let (_, _, _, current) = self.readable(&store, &read).await?;
            if current.size != info.size || current.kind != info.kind {
                return Err(corrupt());
            }
            let last = offset.checked_add(data.len() as u64).ok_or_else(corrupt)? == info.size;
            Ok(PreservedPiece { data, offset, last })
        })
    }
}

#[cfg(all(test, feature = "memory"))]
#[path = "admin_tests.rs"]
mod tests;
