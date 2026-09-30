use base64::{Engine as _, engine::general_purpose::STANDARD};
use mkit_core::hash::{hash, to_hex};
use serde::{Deserialize, Serialize};
use serde_json::{Value as Json, json};

use crate::{Batch, BatchOutcome, Code, Key, NamespaceStore, Partition, Precondition, ServerError, StoreError, Value, purge, store::keys};

use super::{AUDIT_PATH, BodyCapture, Engine, Headers, MAX_BODY, PURGE_PATH, Response, auth::{self, Verified}, payload};

const RETRIES: usize = 16;
const PAGE_BYTES: usize = 256 * 1024;

#[derive(Default, Serialize, Deserialize)]
struct Head { seq:u64, hash:String }
#[derive(Serialize, Deserialize)]
struct Nonce { digest:String, path:String, expiry_ms:u64, result:Option<Response> }
#[derive(Serialize, Deserialize)]
struct Operation { digest:String, path:String, result:Response }

fn key(tag:&str,suffix:&[u8]) -> Key { Key::new([tag.as_bytes(), b"\0", suffix].concat()) }
fn head_key() -> Key { key("ah",b"") }
fn entry_key(seq:u64) -> Key { key("ae",&seq.to_be_bytes()) }
fn store_error(_:StoreError) -> ServerError { ServerError::new(Code::Unavailable,"admin storage unavailable") }
fn encode<T:Serialize>(value:&T) -> Result<Value,ServerError> {
    let bytes = serde_json::to_vec(value).map_err(|_| ServerError::new(Code::Internal,"admin encoding failed"))?;
    if bytes.len() > crate::MAX_VALUE_BYTES { return Err(ServerError::new(Code::Internal,"admin replay result exceeds storage bound")); }
    Ok(Value::new(bytes))
}
fn decode<T:serde::de::DeserializeOwned>(value:&Value) -> Result<T,ServerError> {
    serde_json::from_slice(value.as_bytes()).map_err(|_| ServerError::new(Code::DataLoss,"corrupt admin ledger"))
}
fn guarded(batch:Batch,key:Key,old:Option<Value>) -> Batch {
    batch.require(old.map_or_else(|| Precondition::Absent(key.clone()),|v| Precondition::Equals(key,v)))
}
fn previous(head:&Head) -> String { if head.seq == 0 { "00".repeat(32) } else { head.hash.clone() } }
fn decode_head(value:Option<&Value>) -> Result<Head,ServerError> {
    let head:Head = value.map_or_else(|| Ok(Head::default()),decode)?;
    if head.seq > 0 && auth::hex::<32>(&head.hash).is_none() {
        return Err(ServerError::new(Code::DataLoss,"corrupt audit head"));
    }
    Ok(head)
}
fn hash_entry(entry:&Json) -> Result<String,ServerError> {
    let mut value = entry.clone();
    value.as_object_mut().ok_or_else(|| ServerError::new(Code::DataLoss,"corrupt audit entry"))?.remove("entryHash");
    // Every key is fixed ASCII, integers are decimal strings, and there are no
    // floats: serde_json's sorted map and UTF-8 string encoding are JCS here.
    let mut bytes = b"mkit-admin-audit:v1".to_vec();
    bytes.extend(serde_json::to_vec(&value).map_err(|_| ServerError::new(Code::Internal,"audit encoding failed"))?);
    Ok(to_hex(&hash(&bytes)))
}
fn audit_entry(head:&Head,actor:&str,path:&str,digest:&str,nonce:&str,operation:&str,label:&str,targets:&[String],result:&Response,details:&str,now:u64) -> Result<(Json,Head),ServerError> {
    let seq = head.seq.checked_add(1).ok_or_else(|| ServerError::new(Code::Internal,"audit sequence exhausted"))?;
    let outcome = if result.status == 200 { json!({"code":"ok","message":""}) } else {
        serde_json::from_slice::<Json>(&result.body).map_err(|_| ServerError::new(Code::Internal,"invalid audit result"))?
    };
    let mut entry = json!({"seq":seq.to_string(),"recordedAtMs":now.to_string(),"actor":actor,"procedure":path,
        "requestDigest":digest,"nonce":nonce,"targets":targets,"result":outcome,"details":details,"prevHash":previous(head)});
    if !operation.is_empty() { entry["operationId"] = json!(operation); }
    if !label.is_empty() { entry["operatorLabel"] = json!(label); }
    let entry_hash = hash_entry(&entry)?;
    entry["entryHash"] = json!(entry_hash);
    Ok((entry,Head { seq,hash:entry_hash }))
}

/// Plan an automatic action's audit append; combine this batch with the action
/// acceptance batch and retry planning if any CAS guard loses.
///
/// # Errors
/// Invalid automatic actor/target or corrupt/unavailable audit storage.
pub async fn plan_system<S:NamespaceStore>(store:&S,partition:&Partition,actor:&str,procedure:&str,targets:&[String],now_ms:u64) -> Result<Batch,StoreError> {
    if !matches!(actor,"system:inspector"|"system:timer"|"system:relay")
        || !procedure.starts_with(&format!("{actor}/")) || procedure.len()>256
        || procedure.chars().any(char::is_control) || targets.len()>256
        || targets.iter().any(|t| t.len()>1024 || t.chars().any(char::is_control)) {
        return Err(StoreError::Invalid("invalid system audit identity".into()));
    }
    let old = store.get(partition,&head_key()).await?;
    let head = decode_head(old.as_ref())
        .map_err(|_| StoreError::Invalid("corrupt audit head".into()))?;
    let (entry,next) = audit_entry(&head,actor,procedure,"","","","",targets,&Response::json(&json!({})),"",now_ms)
        .map_err(|_| StoreError::Invalid("invalid audit entry".into()))?;
    let batch = guarded(Batch::new(),head_key(),old)
        .put(entry_key(next.seq),encode(&entry).map_err(|_| StoreError::Invalid("audit entry too large".into()))?)
        .put(head_key(),encode(&next).map_err(|_| StoreError::Invalid("invalid audit head".into()))?);
    Ok(batch)
}

/// Audits automatic purge acceptance in the deployment's root partition before
/// any namespace or repository effect. Stable intents make a cross-DO retry
/// resume the accepted action without appending another audit entry.
#[derive(Clone,Debug)]
pub struct SystemAudit<S> { store:S, root:Partition }
impl<S> SystemAudit<S> {
    /// The metadata store and the same root partition used by [`Engine`].
    pub fn new(store:S,root:Partition) -> Self { Self {store,root} }
}
impl<S:NamespaceStore> purge::AutomaticAudit for SystemAudit<S> {
    fn plan<'a>(&'a self,_partition:&'a Partition,request:&'a purge::Request,now_ms:u64) -> crate::BoxFuture<'a,Result<Batch,StoreError>> {
        Box::pin(async move {
            let intent_key = key("ai",request.purge_id.as_bytes());
            let intent = serde_json::to_vec(request).map(Value::new).map_err(|_| StoreError::Invalid("invalid automatic purge intent".into()))?;
            if intent.as_bytes().len()>crate::MAX_VALUE_BYTES { return Err(StoreError::Invalid("automatic intent too large".into())); }
            for _ in 0..RETRIES {
                if let Some(old) = self.store.get(&self.root,&intent_key).await? {
                    if old!=intent { return Err(StoreError::Invalid("automatic purge id reused".into())); }
                    return Ok(Batch::new());
                }
                let actor = match request.trigger {
                    purge::Trigger::Takedown | purge::Trigger::Suspension => "system:inspector",
                    purge::Trigger::LeaseDeletion => "system:timer",
                    _ => "system:relay",
                };
                let mut batch = plan_system(&self.store,&self.root,actor,&format!("{actor}/cache-purge"),&[request.scope()],now_ms).await?;
                batch = batch.require(Precondition::Absent(intent_key.clone())).put(intent_key.clone(),intent.clone());
                if self.store.apply(&self.root,batch).await? == BatchOutcome::Committed { return Ok(Batch::new()); }
            }
            Err(StoreError::Invalid("automatic audit contention".into()))
        })
    }
}

#[derive(Default,Deserialize)]
#[serde(default,rename_all="camelCase",deny_unknown_fields)]
struct PurgeInput {
    #[serde(alias="operation_id")] operation_id:String,
    repository:String, namespace:String,
    #[serde(alias="url_paths")] url_paths:Vec<String>,
    #[serde(alias="object_ids")] object_ids:Vec<String>,
    refs:Vec<String>, reason:String,
    #[serde(alias="operator_label")] operator_label:String,
}
#[derive(Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct ReadInput {
    #[serde(alias="from_seq")] from_seq:Json,
    #[serde(alias="page_size")] page_size:Json,
}
enum Action { Purge(purge::Request,String,String), Read(u64,u32), Failure(ServerError) }
fn bounded_text(s:&str,max:usize) -> bool { s.len()<=max && !s.chars().any(char::is_control) }

impl<S:NamespaceStore> Engine<S> {
    pub(super) async fn dispatch(&self,path:&str,headers:&Headers,wire:&BodyCapture,decoded:Option<Result<Vec<u8>,ServerError>>,now:i64) -> Result<Response,ServerError> {
        let verified = self.config.verify(path,headers,wire,now)?;
        let nonce_key = key("an",verified.replay_key.as_bytes());
        let nonce = Nonce { digest:verified.digest.clone(),path:path.to_owned(),expiry_ms:verified.expiry_ms,result:None };
        let nonce_value = encode(&nonce)?;
        match self.store.apply(&self.partition,Batch::new().require(Precondition::Absent(nonce_key.clone())).put(nonce_key.clone(),nonce_value.clone())).await.map_err(store_error)? {
            BatchOutcome::Committed => {},
            BatchOutcome::PreconditionFailed { observed:Some(existing),.. } => {
                let old:Nonce = decode(&existing)?;
                if old.digest!=verified.digest || old.path!=path { return self.conflict(&verified,now,"admin nonce reused with a different request").await; }
                return old.result.ok_or_else(|| ServerError::new(Code::Aborted,"admin request is in flight"));
            }
            _ => return Err(ServerError::new(Code::Unavailable,"admin nonce reservation failed")),
        }
        let action = if !verified.roles.contains("all") && !verified.roles.contains(if path == AUDIT_PATH { "audit" } else { "moderation" }) {
            Action::Failure(ServerError::permission_denied("admin key lacks required role"))
        } else if wire.oversized {
            Action::Failure(auth::invalid("admin request exceeds 1 MiB"))
        } else {
            let bytes = decoded.unwrap_or_else(|| Ok(wire.bytes.clone()));
            match bytes.and_then(|bytes| {
                if bytes.len()>MAX_BODY { return Err(auth::invalid("decoded admin request exceeds 1 MiB")); }
                let body = payload(path,&bytes)?;
                if path == PURGE_PATH {
                    let input:PurgeInput = serde_json::from_slice(body).map_err(|_| auth::invalid("invalid PurgeCache JSON"))?;
                    if !auth::identifier(&input.operation_id,128,true) || !bounded_text(&input.reason,512) || !bounded_text(&input.operator_label,128) {
                        return Err(auth::invalid("invalid admin operation id, reason or label"));
                    }
                    let request = purge::Request {
                        purge_id:format!("purge:{}",to_hex(&hash(format!("{}\n{}",verified.actor,verified.nonce).as_bytes()))),
                        audience:self.config.audience.clone(),repository:input.repository,namespace:input.namespace,
                        trigger:purge::Trigger::Manual,url_paths:input.url_paths,object_ids:input.object_ids,refs:input.refs,
                    };
                    request.validate().map_err(|_| auth::invalid("invalid purge selectors"))?;
                    if !self.purge_enabled { return Err(ServerError::failed_precondition("no cache purge interface configured")); }
                    Ok(Action::Purge(request,input.operation_id,input.operator_label))
                } else if path == AUDIT_PATH {
                    let input:ReadInput = serde_json::from_slice(body).map_err(|_| auth::invalid("invalid ReadAuditLog JSON"))?;
                    let number = |j:&Json| j.as_str().and_then(auth::decimal_u64).or_else(|| j.as_u64());
                    let from = number(&input.from_seq).filter(|n| *n>=1).ok_or_else(|| auth::invalid("invalid audit sequence"))?;
                    let size = number(&input.page_size).filter(|n| (1..=100).contains(n)).ok_or_else(|| auth::invalid("invalid audit page size"))?;
                    Ok(Action::Read(from,u32::try_from(size).map_err(|_| auth::invalid("invalid audit page size"))?))
                } else { Err(ServerError::new(Code::Unimplemented,"admin operation is outside the launch subset")) }
            }) { Ok(action)=>action, Err(error)=>Action::Failure(error) }
        };
        self.complete(&verified,&nonce_key,&nonce_value,action,now).await
    }

    async fn conflict(&self,verified:&Verified,now:i64,message:&str) -> Result<Response,ServerError> {
        let result = Response::error(&auth::invalid(message));
        for _ in 0..RETRIES {
            let old = self.store.get(&self.partition,&head_key()).await.map_err(store_error)?;
            let head = decode_head(old.as_ref())?;
            let (entry,next) = audit_entry(&head,&verified.actor,&verified.path,&verified.digest,&verified.nonce,"","",&[],&result,"",u64::try_from(now).unwrap_or(0))?;
            let batch = guarded(Batch::new(),head_key(),old).put(entry_key(next.seq),encode(&entry)?).put(head_key(),encode(&next)?);
            if self.store.apply(&self.partition,batch).await.map_err(store_error)? == BatchOutcome::Committed { return Ok(result); }
        }
        Err(ServerError::new(Code::Unavailable,"audit contention"))
    }

    async fn complete(&self,verified:&Verified,nonce_key:&Key,nonce_value:&Value,action:Action,now:i64) -> Result<Response,ServerError> {
        let now = u64::try_from(now).map_err(|_| ServerError::new(Code::Unavailable,"invalid backend clock"))?;
        for _ in 0..RETRIES {
            let old = self.store.get(&self.partition,&head_key()).await.map_err(store_error)?;
            let head = decode_head(old.as_ref())?;
            let mut batch = guarded(Batch::new(),head_key(),old);
            let (response,operation,label,targets) = match &action {
                Action::Failure(error) => (Response::error(error),"","",Vec::new()),
                Action::Read(from,size) => {
                    let result = self.read_page(&head,*from,*size).await;
                    (result.unwrap_or_else(|e| Response::error(&e)),"","",Vec::new())
                }
                Action::Purge(request,operation,label) => {
                    let operation_key = key("ao",operation.as_bytes());
                    if let Some(value) = self.store.get(&self.partition,&operation_key).await.map_err(store_error)? {
                        let first:Operation = decode(&value)?;
                        if first.digest!=verified.digest || first.path!=verified.path {
                            let response = Response::error(&auth::invalid("operation id reused with a different request"));
                            (response,operation.as_str(),label.as_str(),vec![request.scope()])
                        } else {
                            // Cross-nonce operation retries preserve the first accepted
                            // identity/result without creating another action or audit.
                            let terminal = Nonce { digest:verified.digest.clone(),path:verified.path.clone(),expiry_ms:verified.expiry_ms,result:Some(first.result.clone()) };
                            let batch = Batch::new().require(Precondition::Equals(nonce_key.clone(),nonce_value.clone())).put(nonce_key.clone(),encode(&terminal)?);
                            if self.store.apply(&self.partition,batch).await.map_err(store_error)? != BatchOutcome::Committed { return Err(ServerError::new(Code::Aborted,"admin nonce completion raced")); }
                            return Ok(first.result);
                        }
                    } else {
                        let backlog = self.store.get(&self.partition,&keys::outcome_backlog()).await.map_err(store_error)?;
                        let generation = self.store.get(&self.partition,&keys::cache_purge_generation(&request.scope())).await.map_err(store_error)?;
                        let planned = purge::plan_enqueue(request,now,backlog.as_ref(),generation.as_ref()).map_err(store_error)?;
                        batch.preconditions.extend(planned.preconditions); batch.writes.extend(planned.writes);
                        let response = Response::json(&json!({"purgeId":request.purge_id}));
                        batch = batch.require(Precondition::Absent(operation_key.clone())).put(operation_key,encode(&Operation { digest:verified.digest.clone(),path:verified.path.clone(),result:response.clone() })?);
                        (response,operation.as_str(),label.as_str(),vec![request.scope()])
                    }
                }
            };
            let (entry,next) = audit_entry(&head,&verified.actor,&verified.path,&verified.digest,&verified.nonce,operation,label,&targets,&response,"",now)?;
            let terminal = Nonce { digest:verified.digest.clone(),path:verified.path.clone(),expiry_ms:verified.expiry_ms,result:Some(response.clone()) };
            batch = batch.require(Precondition::Equals(nonce_key.clone(),nonce_value.clone()))
                .put(entry_key(next.seq),encode(&entry)?).put(head_key(),encode(&next)?).put(nonce_key.clone(),encode(&terminal)?);
            if self.store.apply(&self.partition,batch).await.map_err(store_error)? == BatchOutcome::Committed { return Ok(response); }
        }
        Err(ServerError::new(Code::Unavailable,"admin acceptance contention"))
    }

    async fn read_page(&self,head:&Head,from:u64,size:u32) -> Result<Response,ServerError> {
        if from > head.seq.saturating_add(1) { return Err(auth::invalid("audit sequence beyond chain head")); }
        let mut entries = Vec::new();
        let mut next = from;
        let mut previous_hash = if from == 1 { "00".repeat(32) } else {
            let row = self.store.get(&self.partition,&entry_key(from-1)).await.map_err(store_error)?.ok_or_else(|| ServerError::new(Code::DataLoss,"audit sequence gap"))?;
            let entry:Json = decode(&row)?;
            if hash_entry(&entry)? != entry["entryHash"].as_str().unwrap_or("") { return Err(ServerError::new(Code::DataLoss,"audit hash mismatch")); }
            entry["entryHash"].as_str().ok_or_else(|| ServerError::new(Code::DataLoss,"invalid audit hash"))?.to_owned()
        };
        let mut bytes = 0usize;
        while next <= head.seq && entries.len() < size as usize {
            let row = self.store.get(&self.partition,&entry_key(next)).await.map_err(store_error)?.ok_or_else(|| ServerError::new(Code::DataLoss,"audit sequence gap"))?;
            if bytes.saturating_add(row.as_bytes().len())>PAGE_BYTES && !entries.is_empty() { break; }
            bytes = bytes.saturating_add(row.as_bytes().len());
            let mut entry:Json = decode(&row)?;
            let entry_hash = hash_entry(&entry)?;
            if entry["seq"] != next.to_string() || entry["prevHash"] != previous_hash || entry["entryHash"] != entry_hash {
                return Err(ServerError::new(Code::DataLoss,"audit chain continuity failure"));
            }
            previous_hash = entry_hash;
            for field in ["prevHash","entryHash"] {
                let raw = auth::hex::<32>(entry[field].as_str().unwrap_or("")).ok_or_else(|| ServerError::new(Code::DataLoss,"invalid audit hash"))?;
                entry[field] = json!(STANDARD.encode(raw));
            }
            entries.push(entry); next = next.checked_add(1).ok_or_else(|| ServerError::new(Code::DataLoss,"audit sequence overflow"))?;
        }
        if next>head.seq && previous_hash!=previous(head) { return Err(ServerError::new(Code::DataLoss,"audit chain head mismatch")); }
        let head_hash = auth::hex::<32>(&previous(head)).ok_or_else(|| ServerError::new(Code::DataLoss,"corrupt audit head"))?;
        Response::stream(&json!({"entries":entries,"nextSeq":next.to_string(),"chainHead":STANDARD.encode(head_hash),
            "chainHeadSeq":head.seq.to_string(),"checkpointHash":STANDARD.encode([0u8;32]),"checkpointSeq":"0"}))
    }
}
