use super::*;
use crate::timers::TimerHandler;
use crate::{Batch, NamespaceKey, NamespaceStore, Value, memory::MemoryKv};
use ed25519_dalek::{Signer, SigningKey};
use mkit_core::hash::{hash, to_hex};
use serde_json::json;

fn config(roles: &[&str]) -> Config {
    let key = SigningKey::from_bytes(&[71; 32]);
    Config::parse("https://server.example", &json!({"version":1,"keys":[{"keyId":"operator","alg":"ed25519","publicKey":to_hex(key.verifying_key().as_bytes()),"roles":roles}]}).to_string()).unwrap()
}
fn request(path: &str, value: &serde_json::Value, nonce: u8) -> (Headers, BodyCapture) {
    let mut bytes = value.to_string().into_bytes();
    if path == AUDIT_PATH {
        let mut framed = vec![0];
        framed.extend_from_slice(&u32::try_from(bytes.len()).unwrap().to_be_bytes());
        framed.append(&mut bytes);
        bytes = framed;
    }
    signed_bytes(path, &bytes, nonce)
}
fn signed_bytes(path: &str, bytes: &[u8], nonce: u8) -> (Headers, BodyCapture) {
    let mut capture = BodyCapture::default();
    capture.push(bytes);
    let nonce = to_hex(&[nonce; 32]);
    let digest = capture.digest();
    let canonical = format!(
        "mkit-admin:v1\noperator\nhttps://server.example\n{path}\n{digest}\n0\n60000\n{nonce}"
    );
    let signature = SigningKey::from_bytes(&[71; 32])
        .sign(&hash(canonical.as_bytes()))
        .to_bytes()
        .iter()
        .fold(String::new(), |mut text, b| {
            use std::fmt::Write as _;
            write!(text, "{b:02x}").unwrap();
            text
        });
    let values = [
        "1".to_owned(),
        "operator".into(),
        "https://server.example".into(),
        "0".into(),
        "60000".into(),
        nonce,
        digest,
        signature,
    ];
    (
        auth::HEADER_NAMES
            .into_iter()
            .zip(values)
            .map(|(n, v)| (n.into(), v))
            .collect(),
        capture,
    )
}
fn partition() -> Partition {
    Partition::Namespace(NamespaceKey::deployment_default())
}
fn purge_body() -> serde_json::Value {
    json!({"operationId":"operation-1","repository":"root/repo","reason":"manual","operatorLabel":"on-call"})
}

async fn purge_timers(store: &MemoryKv) -> Vec<(crate::Key, Value)> {
    store
        .scan(
            &partition(),
            &crate::Key::new(b"w\0".to_vec()),
            &crate::Key::new(b"w\x01".to_vec()),
            None,
            100,
        )
        .await
        .unwrap()
        .entries
}

#[tokio::test]
async fn manual_purge_acceptance_is_durable_and_operation_replay_cannot_duplicate_work() {
    use crate::store::{codec, keys};
    let store = std::sync::Arc::new(MemoryKv::default());
    let engine = Engine::new(store.clone(), partition(), config(&["moderation"])).with_purge(true);
    let input = purge_body();
    let (headers, body) = request(PURGE_PATH, &input, 80);
    let accepted = engine.handle(PURGE_PATH, &headers, &body, 100).await;
    assert_eq!(accepted.status, 200);
    let result: serde_json::Value = serde_json::from_slice(&accepted.body).unwrap();
    let id = result["purgeId"].as_str().unwrap();
    assert!(!id.is_empty());
    let pending = crate::purge::read_request(&store, &partition(), id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(pending.repository, "root/repo");
    assert_eq!(pending.trigger, crate::purge::Trigger::Manual);
    let timers = purge_timers(&store).await;
    assert_eq!(timers.len(), 1);
    assert!(
        matches!(keys::parse(&timers[0].0), Some(keys::ParsedKey::Timer { kind: 11, reference, .. }) if reference == id.as_bytes())
    );
    let backlog = store
        .get(&partition(), &keys::outcome_backlog())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(codec::decode_backlog(&backlog).unwrap().rows, 1);
    let generation = store
        .get(&partition(), &keys::cache_purge_generation("root/repo"))
        .await
        .unwrap();
    assert_eq!(
        engine.handle(PURGE_PATH, &headers, &body, 101).await,
        accepted
    );
    assert_eq!(head(&store).await, 1);
    let restarted =
        Engine::new(store.clone(), partition(), config(&["moderation"])).with_purge(true);
    let (headers, body) = request(PURGE_PATH, &input, 81);
    assert_eq!(
        restarted.handle(PURGE_PATH, &headers, &body, 200).await,
        accepted
    );
    assert_eq!(head(&store).await, 2);
    let mut changed = input.clone();
    changed["repository"] = json!("root/other");
    let (headers, body) = request(PURGE_PATH, &changed, 82);
    assert_eq!(
        restarted
            .handle(PURGE_PATH, &headers, &body, 300)
            .await
            .status,
        400
    );
    assert_eq!(head(&store).await, 3);
    assert_eq!(purge_timers(&store).await, timers);
    assert_eq!(
        store
            .get(&partition(), &keys::outcome_backlog())
            .await
            .unwrap(),
        Some(backlog)
    );
    assert_eq!(
        store
            .get(&partition(), &keys::cache_purge_generation("root/repo"))
            .await
            .unwrap(),
        generation
    );
    assert!(
        store
            .get(&partition(), &keys::cache_purge_generation("root/other"))
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        crate::purge::read_request(&store, &partition(), id)
            .await
            .unwrap(),
        Some(pending)
    );
    let reader = Engine::new(store.clone(), partition(), config(&["audit"]));
    let (headers, body) = request(AUDIT_PATH, &json!({"fromSeq":"1","pageSize":100}), 83);
    let audit = page(&reader.handle(AUDIT_PATH, &headers, &body, 301).await);
    assert_eq!(audit["entries"][0]["operationId"], "operation-1");
    assert_eq!(audit["entries"][0]["operatorLabel"], "on-call");
    assert_eq!(audit["entries"][0]["details"], "manual");
    assert_eq!(audit["entries"][2]["result"]["code"], "invalid_argument");
}

#[tokio::test]
async fn manual_purge_role_and_mixed_credentials_cannot_enqueue_work() {
    let store = std::sync::Arc::new(MemoryKv::default());
    let moderator =
        Engine::new(store.clone(), partition(), config(&["moderation"])).with_purge(true);
    let audit_only = Engine::new(store.clone(), partition(), config(&["audit"]));
    let (mut headers, body) = request(PURGE_PATH, &purge_body(), 84);
    headers.push(("x-write-grant".into(), "client-grant".into()));
    assert_eq!(
        moderator
            .handle(PURGE_PATH, &headers, &body, 100)
            .await
            .status,
        400
    );
    assert_eq!(head(&store).await, 0);
    assert!(purge_timers(&store).await.is_empty());
    headers.pop();
    assert_eq!(
        audit_only
            .handle(PURGE_PATH, &headers, &body, 101)
            .await
            .status,
        403
    );
    assert_eq!(head(&store).await, 1);
    assert!(purge_timers(&store).await.is_empty());
    assert!(
        store
            .get(&partition(), &crate::store::keys::outcome_backlog())
            .await
            .unwrap()
            .is_none()
    );
    let mut invalid = purge_body();
    invalid["urlPaths"] = json!(["/objects/secret?token=never"]);
    let (headers, body) = request(PURGE_PATH, &invalid, 85);
    assert_eq!(
        moderator
            .handle(PURGE_PATH, &headers, &body, 102)
            .await
            .status,
        400
    );
    assert_eq!(head(&store).await, 2);
    assert!(purge_timers(&store).await.is_empty());
    let (headers, body) = request(PURGE_PATH, &purge_body(), 86);
    assert_eq!(
        moderator
            .handle(PURGE_PATH, &headers, &body, 103)
            .await
            .status,
        200
    );
    assert_eq!(purge_timers(&store).await.len(), 1);
    let (headers, body) = request(AUDIT_PATH, &json!({"fromSeq":"1","pageSize":100}), 87);
    let audit = page(&audit_only.handle(AUDIT_PATH, &headers, &body, 104).await);
    assert_eq!(audit["entries"][0]["result"]["code"], "permission_denied");
    assert_eq!(audit["entries"][1]["result"]["code"], "invalid_argument");
    assert_eq!(audit["entries"][2]["result"]["code"], "ok");
}

struct RestartPurgeSink(std::sync::Arc<std::sync::Mutex<Vec<crate::purge::Request>>>);
impl crate::purge::PurgeSink for RestartPurgeSink {
    fn deliver<'a>(
        &'a self,
        request: &'a crate::purge::Request,
    ) -> crate::BoxFuture<'a, Result<(), crate::StoreError>> {
        Box::pin(async move {
            let mut calls = self.0.lock().unwrap();
            calls.push(request.clone());
            if calls.len() == 1 {
                Err(crate::StoreError::unavailable("global purge unavailable"))
            } else {
                Ok(())
            }
        })
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // Delivery, restart and audited completion form one durable lifecycle.
async fn manual_purge_completion_is_audited_only_after_durable_global_acknowledgement() {
    use crate::purge::{NoLocalCache, PurgeDelivery, SliceBudget};
    use crate::timers::{TickBudget, TimerRegistry, run_due};
    use std::sync::{Arc, Mutex};
    let store = Arc::new(MemoryKv::default());
    let engine = Engine::new(store.clone(), partition(), config(&["moderation"])).with_purge(true);
    let (headers, body) = request(PURGE_PATH, &purge_body(), 88);
    let accepted = engine.handle(PURGE_PATH, &headers, &body, 100).await;
    assert_eq!(accepted.status, 200);
    let json: serde_json::Value = serde_json::from_slice(&accepted.body).unwrap();
    let id = json["purgeId"].as_str().unwrap();
    let work = crate::purge::read_request(&store, &partition(), id)
        .await
        .unwrap()
        .unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let registry = || {
        TimerRegistry::new().register(PurgeDelivery::new(
            Arc::new(NoLocalCache),
            Some(Arc::new(RestartPurgeSink(calls.clone()))),
            SliceBudget::new(2),
        ))
    };
    let clock = crate::ManualClock::new(100);
    run_due(
        &store,
        &partition(),
        &registry(),
        &clock,
        100,
        &TickBudget::new(1, 1, 16, 1000),
    )
    .await
    .unwrap();
    assert_eq!(
        head(&store).await,
        1,
        "failed delivery cannot audit completion"
    );
    assert_eq!(
        crate::purge::read_request(&store, &partition(), id)
            .await
            .unwrap(),
        Some(work.clone())
    );
    let queued = purge_timers(&store).await;
    assert_eq!(queued.len(), 1);
    let Some(crate::store::keys::ParsedKey::Timer { due_at_ms, .. }) =
        crate::store::keys::parse(&queued[0].0)
    else {
        panic!("retry timer expected");
    };
    clock.set(i64::try_from(due_at_ms).unwrap());
    run_due(
        &store,
        &partition(),
        &registry(),
        &clock,
        due_at_ms,
        &TickBudget::new(1, 1, 16, 1000),
    )
    .await
    .unwrap();
    assert_eq!(*calls.lock().unwrap(), [work.clone(), work]);
    assert_eq!(head(&store).await, 2);
    assert!(purge_timers(&store).await.is_empty());
    assert!(
        crate::purge::read_request(&store, &partition(), id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .get(&partition(), &crate::store::keys::outcome_backlog())
            .await
            .unwrap()
            .is_none()
    );
    // A fresh signed retry after completion replays acceptance without resurrecting work.
    let (headers, body) = request(PURGE_PATH, &purge_body(), 89);
    assert_eq!(
        engine
            .handle(
                PURGE_PATH,
                &headers,
                &body,
                i64::try_from(due_at_ms).unwrap()
            )
            .await,
        accepted
    );
    assert!(purge_timers(&store).await.is_empty());
    let reader = Engine::new(store.clone(), partition(), config(&["audit"]));
    let (headers, body) = request(AUDIT_PATH, &json!({"fromSeq":"1","pageSize":100}), 90);
    let audit = page(
        &reader
            .handle(
                AUDIT_PATH,
                &headers,
                &body,
                i64::try_from(due_at_ms).unwrap(),
            )
            .await,
    );
    assert_eq!(audit["entries"][1]["actor"], "system:timer");
    assert_eq!(
        audit["entries"][1]["procedure"],
        "system:timer/PurgeCacheComplete"
    );
    assert_eq!(audit["entries"][1]["targets"], json!([id]));
    assert_eq!(audit["entries"][1]["result"]["code"], "ok");
    assert_eq!(
        audit["entries"][1]["prevHash"],
        audit["entries"][0]["entryHash"]
    );
    run_due(
        &store,
        &partition(),
        &registry(),
        &clock,
        due_at_ms,
        &TickBudget::new(1, 1, 16, 1000),
    )
    .await
    .unwrap();
    assert_eq!(
        head(&store).await,
        4,
        "empty timer run cannot append completion twice"
    );
}
async fn head(store: &MemoryKv) -> u64 {
    store
        .get(&partition(), &crate::Key::new(b"ah\0".to_vec()))
        .await
        .unwrap()
        .map_or(0, |v| {
            serde_json::from_slice::<serde_json::Value>(v.as_bytes()).unwrap()["seq"]
                .as_u64()
                .unwrap()
        })
}
#[tokio::test]
async fn authenticated_denials_and_audit_reads_extend_gapless_chain() {
    let store = std::sync::Arc::new(MemoryKv::default());
    let engine = Engine::new(store.clone(), partition(), config(&["audit"]));
    let (headers, body) = request(PURGE_PATH, &purge_body(), 3);
    let denied = engine.handle(PURGE_PATH, &headers, &body, 1).await;
    assert_eq!(denied.status, 403);
    assert_eq!(engine.handle(PURGE_PATH, &headers, &body, 2).await, denied);
    assert_eq!(head(&store).await, 1);
    let (headers, body) = request(AUDIT_PATH, &json!({"fromSeq":"1","pageSize":100}), 4);
    let response = engine.handle(AUDIT_PATH, &headers, &body, 2).await;
    assert_eq!(response.status, 200);
    assert_eq!(head(&store).await, 2);
    assert_eq!(
        engine.handle(AUDIT_PATH, &headers, &body, 3).await,
        response
    );
    assert_eq!(head(&store).await, 2);
}
#[tokio::test]
async fn forged_and_mixed_credentials_cannot_reserve_nonce_or_audit() {
    let store = std::sync::Arc::new(MemoryKv::default());
    let engine = Engine::new(store.clone(), partition(), config(&["all"]));
    let (mut headers, body) = request(PURGE_PATH, &purge_body(), 5);
    headers.push(("x-write-grant".into(), "opaque".into()));
    assert_eq!(
        engine.handle(PURGE_PATH, &headers, &body, 1).await.status,
        400
    );
    headers.pop();
    headers.last_mut().unwrap().1 = "00".repeat(64);
    assert_eq!(
        engine.handle(PURGE_PATH, &headers, &body, 1).await.status,
        401
    );
    assert_eq!(head(&store).await, 0);
    // The store remains usable, not an error-hiding fake.
    store
        .apply(
            &partition(),
            Batch::new().put(crate::Key::new(b"proof".to_vec()), Value::default()),
        )
        .await
        .unwrap();
}

fn page(response: &Response) -> serde_json::Value {
    assert_eq!(response.content_type, "application/connect+json");
    assert_eq!(response.body[0], 0);
    let length = u32::from_be_bytes(response.body[1..5].try_into().unwrap()) as usize;
    let value = serde_json::from_slice(&response.body[5..5 + length]).unwrap();
    assert_eq!(response.body[5 + length], 2);
    value
}

#[tokio::test]
async fn read_export_fixes_snapshot_before_auditing_and_replays_exact_bytes() {
    let store = std::sync::Arc::new(MemoryKv::default());
    let engine = Engine::new(store.clone(), partition(), config(&["audit"]));
    let input = json!({"fromSeq":"1","pageSize":100});
    let (headers, body) = request(AUDIT_PATH, &input, 31);
    let first = engine.handle(AUDIT_PATH, &headers, &body, 1).await;
    let empty = page(&first);
    assert_eq!(empty["chainHeadSeq"], "0");
    assert_eq!(empty["checkpointSeq"], "0");
    assert_eq!(empty["entries"], json!([]));
    assert_eq!(empty["nextSeq"], "1");
    assert_eq!(head(&store).await, 1);
    let (headers2, body2) = request(AUDIT_PATH, &input, 32);
    let second = engine.handle(AUDIT_PATH, &headers2, &body2, 2).await;
    let exported = page(&second);
    assert_eq!(exported["chainHeadSeq"], "1");
    assert_eq!(exported["entries"].as_array().unwrap().len(), 1);
    assert_eq!(exported["entries"][0]["procedure"], AUDIT_PATH);
    assert_eq!(exported["entries"][0]["entryHash"], exported["chainHead"]);
    assert_eq!(exported["nextSeq"], "2");
    assert_eq!(head(&store).await, 2);
    let restarted =
        Engine::new(store.clone(), partition(), config(&["moderation"])).with_purge(true);
    assert_eq!(
        restarted.handle(AUDIT_PATH, &headers, &body, 3).await,
        first
    );
    assert_eq!(head(&store).await, 2);
}

#[tokio::test]
async fn read_role_denial_is_terminal_even_after_role_change() {
    let store = std::sync::Arc::new(MemoryKv::default());
    let (headers, body) = request(AUDIT_PATH, &json!({"fromSeq":"1","pageSize":1}), 33);
    let first = Engine::new(store.clone(), partition(), config(&["moderation"]))
        .handle(AUDIT_PATH, &headers, &body, 1)
        .await;
    assert_eq!(first.status, 403);
    let restarted = Engine::new(store.clone(), partition(), config(&["audit"]));
    assert_eq!(
        restarted.handle(AUDIT_PATH, &headers, &body, 2).await,
        first
    );
    assert_eq!(head(&store).await, 1);
}

#[tokio::test]
async fn admin_envelope_rejects_duplicate_joined_mixed_and_changed_signed_fields() {
    let store = std::sync::Arc::new(MemoryKv::default());
    let engine = Engine::new(store.clone(), partition(), config(&["audit"]));
    let (headers, body) = request(AUDIT_PATH, &json!({"fromSeq":"1","pageSize":1}), 34);
    for name in HEADER_NAMES {
        let mut repeated = headers.clone();
        repeated.push((name.to_uppercase(), "1".into()));
        assert_eq!(
            engine.handle(AUDIT_PATH, &repeated, &body, 1).await.status,
            401
        );
        let mut joined = headers.clone();
        joined
            .iter_mut()
            .find(|(n, _)| n == name)
            .unwrap()
            .1
            .push_str(",1");
        assert_eq!(
            engine.handle(AUDIT_PATH, &joined, &body, 1).await.status,
            401
        );
    }
    for name in crate::auth_v2::HEADER_NAMES {
        let mut mixed = headers.clone();
        mixed.push((name.into(), "value".into()));
        assert_eq!(
            engine.handle(AUDIT_PATH, &mixed, &body, 1).await.status,
            400
        );
    }
    assert_eq!(
        engine.handle(PURGE_PATH, &headers, &body, 1).await.status,
        401
    );
    assert_eq!(
        engine
            .handle(AUDIT_PATH, &headers, &body, 60_000)
            .await
            .status,
        401
    );
    let mut changed = body.clone();
    changed.push(b" ");
    assert_eq!(
        engine
            .handle(AUDIT_PATH, &headers, &changed, 1)
            .await
            .status,
        401
    );
    let mut origin = headers.clone();
    origin
        .iter_mut()
        .find(|(n, _)| n == "x-mkit-admin-audience")
        .unwrap()
        .1 = "https://other.example".into();
    assert_eq!(
        engine.handle(AUDIT_PATH, &origin, &body, 1).await.status,
        401
    );
    assert_eq!(head(&store).await, 0);
}

#[tokio::test]
async fn authenticated_oversize_failure_is_audited_and_replayed() {
    let store = std::sync::Arc::new(MemoryKv::default());
    let engine = Engine::new(store.clone(), partition(), config(&["audit"]));
    let (headers, body) = signed_bytes(AUDIT_PATH, &vec![b' '; MAX_BODY + 1], 35);
    assert_eq!(body.bytes.len(), MAX_BODY);
    let first = engine.handle(AUDIT_PATH, &headers, &body, 1).await;
    assert_eq!(first.status, 400);
    assert_eq!(engine.handle(AUDIT_PATH, &headers, &body, 2).await, first);
    assert_eq!(head(&store).await, 1);
}

#[tokio::test]
async fn nonce_request_conflict_cannot_replace_original_read_result() {
    let store = std::sync::Arc::new(MemoryKv::default());
    let engine = Engine::new(store.clone(), partition(), config(&["audit"]));
    let (headers, body) = request(AUDIT_PATH, &json!({"fromSeq":"1","pageSize":1}), 36);
    let original = engine.handle(AUDIT_PATH, &headers, &body, 1).await;
    let (changed_headers, changed_body) =
        request(AUDIT_PATH, &json!({"fromSeq":"1","pageSize":2}), 36);
    assert_eq!(
        engine
            .handle(AUDIT_PATH, &changed_headers, &changed_body, 2)
            .await
            .status,
        400
    );
    assert_eq!(
        engine.handle(AUDIT_PATH, &headers, &body, 3).await,
        original
    );
    assert_eq!(head(&store).await, 2);
}

#[tokio::test]
async fn audit_export_refuses_gap_and_tampered_entry() {
    for delete in [false, true] {
        let store = std::sync::Arc::new(MemoryKv::default());
        let engine = Engine::new(store.clone(), partition(), config(&["audit"]));
        let input = json!({"fromSeq":"1","pageSize":100});
        let (headers, body) = request(AUDIT_PATH, &input, 37);
        assert_eq!(
            engine.handle(AUDIT_PATH, &headers, &body, 1).await.status,
            200
        );
        let key = crate::Key::new([b"ae\0".as_slice(), &1_u64.to_be_bytes()].concat());
        let batch = if delete {
            Batch::new().delete(key)
        } else {
            let row = store.get(&partition(), &key).await.unwrap().unwrap();
            let mut entry: serde_json::Value = serde_json::from_slice(row.as_bytes()).unwrap();
            entry["details"] = json!("tampered");
            Batch::new().put(key, Value::new(serde_json::to_vec(&entry).unwrap()))
        };
        store.apply(&partition(), batch).await.unwrap();
        let (headers, body) = request(AUDIT_PATH, &input, 38);
        let failure = engine.handle(AUDIT_PATH, &headers, &body, 2).await;
        assert_eq!(failure.status, 500);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&failure.body).unwrap()["code"],
            "data_loss"
        );
        assert_eq!(head(&store).await, 2);
    }
}

fn automatic_request() -> crate::purge::Request {
    crate::purge::Request {
        purge_id: "automatic-1".into(),
        audience: "https://server.example".into(),
        repository: "root/repo".into(),
        namespace: String::new(),
        trigger: crate::purge::Trigger::VisibilityChange,
        url_paths: Vec::new(),
        object_ids: Vec::new(),
        refs: Vec::new(),
    }
}

#[tokio::test]
async fn automatic_audit_does_not_commit_when_trigger_apply_loses() {
    use crate::purge::AutomaticAudit;
    let store = std::sync::Arc::new(MemoryKv::with_clock(std::sync::Arc::new(
        crate::ManualClock::new(1),
    )));
    let audit = SystemAudit::new(store.clone(), partition());
    let mut batch = audit
        .plan(&partition(), &automatic_request(), "automatic-op", 1)
        .await
        .unwrap();
    let work = crate::purge::plan_enqueue(&automatic_request(), 1, None, None).unwrap();
    batch.preconditions.extend(work.preconditions);
    batch.writes.extend(work.writes);
    let state_key = crate::Key::new(b"state".to_vec());
    store
        .apply(
            &partition(),
            Batch::new().put(state_key.clone(), Value::new(b"before".to_vec())),
        )
        .await
        .unwrap();
    batch = batch.require(crate::Precondition::Absent(state_key));
    assert!(matches!(
        store.apply(&partition(), batch).await.unwrap(),
        crate::BatchOutcome::PreconditionFailed { .. }
    ));
    assert_eq!(head(&store).await, 0);
    for key in [
        crate::store::keys::cache_purge("automatic-1").unwrap(),
        crate::store::keys::timer(1, 11, b"automatic-1"),
        crate::store::keys::relay(1),
        crate::store::keys::outbox_sequence(),
        crate::store::keys::cache_purge_generation("root/repo"),
    ] {
        assert!(store.get(&partition(), &key).await.unwrap().is_none());
    }
}

#[derive(Clone)]
struct CountedStore {
    inner: std::sync::Arc<MemoryKv>,
    calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    fail_checkpoint: bool,
    fail_terminal_once: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
}
impl NamespaceStore for CountedStore {
    fn capabilities(&self) -> crate::StoreCapabilities {
        self.inner.capabilities()
    }
    async fn get(&self, p: &Partition, k: &crate::Key) -> Result<Option<Value>, crate::StoreError> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.get(p, k).await
    }
    async fn get_many(
        &self,
        p: &Partition,
        keys: &[crate::Key],
    ) -> Result<Vec<Option<Value>>, crate::StoreError> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.get_many(p, keys).await
    }
    async fn scan(
        &self,
        p: &Partition,
        start: &crate::Key,
        end: &crate::Key,
        after: Option<&crate::Cursor>,
        limit: u32,
    ) -> Result<crate::ScanPage, crate::StoreError> {
        self.inner.scan(p, start, end, after, limit).await
    }
    async fn apply(
        &self,
        p: &Partition,
        batch: Batch,
    ) -> Result<crate::BatchOutcome, crate::StoreError> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if self.fail_checkpoint
            && batch
                .writes
                .iter()
                .any(|w| matches!(w, crate::Write::Delete(k) if k.as_bytes().starts_with(b"or\0")))
        {
            return Err(crate::StoreError::unavailable(std::io::Error::other(
                "crash before source checkpoint",
            )));
        }
        let terminal = batch.writes.iter().any(|w| matches!(w, crate::Write::Put(k,v) if k.as_bytes().starts_with(b"an\0") && serde_json::from_slice::<serde_json::Value>(v.as_bytes()).ok().is_some_and(|row| row.get("result").is_some_and(|result| !result.is_null()))));
        let outcome = self.inner.apply(p, batch).await?;
        if terminal
            && self
                .fail_terminal_once
                .as_ref()
                .is_some_and(|fail| fail.swap(false, std::sync::atomic::Ordering::SeqCst))
        {
            return Err(crate::StoreError::unavailable(std::io::Error::other(
                "lost terminal commit acknowledgement",
            )));
        }
        Ok(outcome)
    }
    async fn stats(&self, p: &Partition) -> Result<crate::PartitionStats, crate::StoreError> {
        self.inner.stats(p).await
    }
    async fn probe(&self) -> Result<(), crate::StoreError> {
        self.inner.probe().await
    }
}

#[tokio::test]
async fn full_audit_page_stays_within_free_worker_request_budget() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let inner = std::sync::Arc::new(MemoryKv::default());
    for i in 0..100 {
        let batch = plan_system(
            &inner,
            &partition(),
            "system:relay",
            "system:relay/test",
            &[],
            i,
        )
        .await
        .unwrap();
        inner.apply(&partition(), batch).await.unwrap();
    }
    let calls = std::sync::Arc::new(AtomicUsize::new(0));
    let store = CountedStore {
        inner: inner.clone(),
        calls: calls.clone(),
        fail_checkpoint: false,
        fail_terminal_once: None,
    };
    let engine = Engine::new(store, partition(), config(&["audit"]));
    let (headers, body) = request(AUDIT_PATH, &json!({"fromSeq":"1","pageSize":100}), 39);
    let response = engine.handle(AUDIT_PATH, &headers, &body, 101).await;
    assert_eq!(response.status, 200);
    assert_eq!(page(&response)["entries"].as_array().unwrap().len(), 100);
    assert!(
        calls.load(Ordering::SeqCst) <= 20,
        "{} store calls",
        calls.load(Ordering::SeqCst)
    );
}

#[tokio::test]
async fn operation_id_replays_first_identity_and_refuses_changed_content() {
    let store = std::sync::Arc::new(MemoryKv::default());
    let digest = format!("body:{}", to_hex(&hash(b"logical request")));
    let response = Response::json(&json!({"actionId":"first-action","complete":false}));
    let OperationReplay::New(batch) = plan_operation(
        &store,
        &partition(),
        "operation-1",
        PURGE_PATH,
        &digest,
        response.clone(),
    )
    .await
    .unwrap() else {
        panic!("new operation expected")
    };
    store.apply(&partition(), batch).await.unwrap();
    let replay = plan_operation(
        &store,
        &partition(),
        "operation-1",
        PURGE_PATH,
        &digest,
        Response::json(&json!({"actionId":"wrong-second-action"})),
    )
    .await
    .unwrap();
    assert!(matches!(replay, OperationReplay::Existing(result) if result == response));
    assert!(
        plan_operation(
            &store,
            &partition(),
            "operation-1",
            AUDIT_PATH,
            &digest,
            response.clone()
        )
        .await
        .is_err()
    );
    let changed = format!("body:{}", to_hex(&hash(b"different")));
    assert!(
        plan_operation(
            &store,
            &partition(),
            "operation-1",
            PURGE_PATH,
            &changed,
            response
        )
        .await
        .is_err()
    );
}

fn source_partition(prefix: u16) -> Partition {
    Partition::RepoIndex {
        ns: NamespaceKey::deployment_default(),
        repo: crate::RepoName::new("repo").unwrap(),
        prefix,
    }
}
fn root_partition() -> Partition {
    Partition::Coordinator(NamespaceKey::deployment_default())
}
async fn fire_audit_relay(
    store: &std::sync::Arc<MemoryKv>,
    source: &Partition,
    now_ms: u64,
) -> crate::timers::Fired {
    let handler = crate::relay::RelayHandler {
        target: store.clone(),
        hook: AuditRelayHook::new(store.clone(), root_partition()),
        budget: crate::relay::RelayBudget::default(),
    };
    handler
        .fire(
            &crate::timers::TimerCtx {
                store,
                partition: source,
                now_ms,
            },
            &crate::timers::DueTimer {
                due_at_ms: now_ms,
                kind: crate::timers::registry::kinds::RELAY,
                reference: bytes::Bytes::default(),
                value: Value::default(),
            },
        )
        .await
        .unwrap()
}
async fn root_head(store: &std::sync::Arc<MemoryKv>) -> u64 {
    store
        .get(&root_partition(), &crate::Key::new(b"ah\0".to_vec()))
        .await
        .unwrap()
        .map_or(0, |v| {
            serde_json::from_slice::<serde_json::Value>(v.as_bytes()).unwrap()["seq"]
                .as_u64()
                .unwrap()
        })
}

#[tokio::test]
async fn committed_automatic_purge_recovers_relay_and_target_checkpoint_crash() {
    use crate::purge::AutomaticAudit;
    let store = std::sync::Arc::new(MemoryKv::with_clock(std::sync::Arc::new(
        crate::ManualClock::new(100),
    )));
    let source = source_partition(0);
    let audit = SystemAudit::new(store.clone(), root_partition());
    let request = automatic_request();
    let mut batch = audit
        .plan(&source, &request, "stable-op", 100)
        .await
        .unwrap();
    let purge = crate::purge::plan_enqueue(&request, 100, None, None).unwrap();
    batch.preconditions.extend(purge.preconditions);
    batch.writes.extend(purge.writes);
    batch = batch.put(crate::Key::new(b"suspended".to_vec()), Value::new(vec![1]));
    store.apply(&source, batch).await.unwrap();
    assert_eq!(root_head(&store).await, 0);
    assert!(
        store
            .get(&source, &crate::store::keys::relay(1))
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        crate::purge::read_request(&store, &source, &request.purge_id)
            .await
            .unwrap()
            .is_some()
    );
    // Reject the source checkpoint after the target transaction commits.
    let crashing_source = CountedStore {
        inner: store.clone(),
        calls: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        fail_checkpoint: true,
        fail_terminal_once: None,
    };
    let handler = crate::relay::RelayHandler {
        target: store.clone(),
        hook: AuditRelayHook::new(store.clone(), root_partition()),
        budget: crate::relay::RelayBudget::default(),
    };
    assert!(
        handler
            .fire(
                &crate::timers::TimerCtx {
                    store: &crashing_source,
                    partition: &source,
                    now_ms: 100
                },
                &crate::timers::DueTimer {
                    due_at_ms: 100,
                    kind: crate::timers::registry::kinds::RELAY,
                    reference: bytes::Bytes::default(),
                    value: Value::default()
                }
            )
            .await
            .is_err()
    );
    assert_eq!(root_head(&store).await, 1);
    assert!(
        store
            .get(&source, &crate::store::keys::relay(1))
            .await
            .unwrap()
            .is_some()
    );
    let recovered = fire_audit_relay(&store, &source, 100).await;
    assert_eq!(root_head(&store).await, 1);
    let batch = match recovered {
        crate::timers::Fired::Done(batch) | crate::timers::Fired::Reschedule { batch, .. } => batch,
        crate::timers::Fired::Retry => panic!("retry did not make progress"),
    };
    store.apply(&source, batch).await.unwrap();
    assert!(
        store
            .get(&source, &crate::store::keys::relay(1))
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn automatic_relay_duplicate_reordered_sources_keep_gapless_chain() {
    use crate::purge::AutomaticAudit;
    let store = std::sync::Arc::new(MemoryKv::with_clock(std::sync::Arc::new(
        crate::ManualClock::new(200),
    )));
    let audit = SystemAudit::new(store.clone(), root_partition());
    for (prefix, now) in [(1, 200), (0, 100)] {
        let source = source_partition(prefix);
        let mut request = automatic_request();
        request.purge_id = format!("automatic-{prefix}");
        let batch = audit
            .plan(&source, &request, "same-op-different-source", now)
            .await
            .unwrap();
        store.apply(&source, batch).await.unwrap();
        drop(fire_audit_relay(&store, &source, 200).await);
        // Retry source delivery after its target apply but before source cleanup.
        drop(fire_audit_relay(&store, &source, 200).await);
    }
    assert_eq!(root_head(&store).await, 2);
    let engine = Engine::new(store.clone(), root_partition(), config(&["audit"]));
    let (headers, body) = request(AUDIT_PATH, &json!({"fromSeq":"1","pageSize":100}), 40);
    let response = engine.handle(AUDIT_PATH, &headers, &body, 201).await;
    assert_eq!(response.status, 200);
    let exported = page(&response);
    let details: serde_json::Value =
        serde_json::from_str(exported["entries"][0]["details"].as_str().unwrap()).unwrap();
    assert_eq!(details["purgeId"], "automatic-1");
    assert_eq!(
        details["sourcePartitionHash"],
        mkit_core::hash::to_hex(&mkit_core::hash::hash(
            &source_partition(1).encode().unwrap()
        ))
    );
    assert_eq!(details["trigger"], "CACHE_PURGE_TRIGGER_VISIBILITY_CHANGE");
    assert_eq!(exported["entries"][0]["recordedAtMs"], "200");
    assert_eq!(exported["entries"][1]["recordedAtMs"], "100");
    assert_eq!(
        exported["entries"][1]["prevHash"],
        exported["entries"][0]["entryHash"]
    );
    assert_eq!(exported["chainHeadSeq"], "2");
}

#[tokio::test]
async fn worker_audit_extension_budget_caps_target_batch_at_one_hundred() {
    use crate::relay::RelayHook;
    let store = std::sync::Arc::new(MemoryKv::default());
    let audit = SystemAudit::new(store, root_partition());
    let reserve = AuditReserveHook::new(root_partition());
    let mut rows = Vec::new();
    for n in 0..33 {
        let mut request = automatic_request();
        request.purge_id = format!("audit-budget-{n}");
        rows.push((
            n + 1,
            audit
                .relay_row(&source_partition(0), &request, "op", 1)
                .unwrap(),
        ));
    }
    let batch_for = |rows: &[(u64, crate::store::codec::RelayV1)]| {
        let mut batch = Batch::new();
        for (_, row) in rows {
            for (key, value) in &row.puts {
                batch = batch.put(key.clone(), value.clone());
            }
        }
        let key = crate::store::keys::relay_high_water(&source_partition(0)).unwrap();
        batch
            .require(crate::Precondition::Absent(key.clone()))
            .put(key, crate::store::codec::encode_u64(rows.last().unwrap().0))
    };
    let mut caps = crate::StoreCapabilities::full();
    caps.reserved_batch_ops = reserve.reserved_ops(&root_partition(), &rows[..32]);
    assert!(batch_for(&rows[..32]).validate(&caps).is_ok());
    caps.reserved_batch_ops = reserve.reserved_ops(&root_partition(), &rows);
    assert!(batch_for(&rows).validate(&caps).is_err());
    assert_eq!(reserve.reserved_ops(&source_partition(0), &rows), 0);
}

#[tokio::test]
async fn automatic_receipt_deduplicates_distinct_relay_rows_and_refuses_reuse() {
    let store = std::sync::Arc::new(MemoryKv::default());
    let audit = SystemAudit::new(store.clone(), root_partition());
    let request = automatic_request();
    let row = audit
        .relay_row(&source_partition(0), &request, "op", 1)
        .unwrap();
    for seq in [1, 2] {
        let (key, value) = row.puts[0].clone();
        let watermark = crate::store::keys::relay_high_water(&source_partition(0)).unwrap();
        let old = store.get(&root_partition(), &watermark).await.unwrap();
        let mut batch = Batch::new()
            .put(key, value)
            .put(watermark.clone(), crate::store::codec::encode_u64(seq));
        batch = batch.require(match old {
            Some(v) => crate::Precondition::Equals(watermark, v),
            None => crate::Precondition::Absent(watermark),
        });
        let head_key = crate::Key::new(b"ah\0".to_vec());
        let receipt_key = row.puts[0].0.clone();
        let head = store.get(&root_partition(), &head_key).await.unwrap();
        let receipt = store.get(&root_partition(), &receipt_key).await.unwrap();
        extend_audit_batch(&root_partition(), &mut batch, |key| {
            Ok(if *key == head_key {
                head.clone()
            } else {
                receipt.clone()
            })
        })
        .unwrap();
        batch.validate(&crate::StoreCapabilities::full()).unwrap();
        assert_eq!(
            store.apply(&root_partition(), batch).await.unwrap(),
            crate::BatchOutcome::Committed
        );
        assert_eq!(root_head(&store).await, 1);
    }
    let mut changed = request;
    changed.repository = "root/other-repo".into();
    let changed = audit
        .relay_row(&source_partition(0), &changed, "op", 1)
        .unwrap();
    let head = store
        .get(&root_partition(), &crate::Key::new(b"ah\0".to_vec()))
        .await
        .unwrap();
    let receipt = store.get(&root_partition(), &row.puts[0].0).await.unwrap();
    let mut batch = Batch::new().put(changed.puts[0].0.clone(), changed.puts[0].1.clone());
    assert!(
        extend_audit_batch(&root_partition(), &mut batch, |key| Ok(
            if key.as_bytes().starts_with(b"ah\0") {
                head.clone()
            } else {
                receipt.clone()
            }
        ))
        .is_err()
    );
    assert_eq!(root_head(&store).await, 1);
}

#[tokio::test]
async fn unknown_terminal_commit_returns_stored_result_after_restart() {
    use std::sync::atomic::{AtomicBool, AtomicUsize};
    let inner = std::sync::Arc::new(MemoryKv::default());
    let store = CountedStore {
        inner: inner.clone(),
        calls: std::sync::Arc::new(AtomicUsize::new(0)),
        fail_checkpoint: false,
        fail_terminal_once: Some(std::sync::Arc::new(AtomicBool::new(true))),
    };
    let engine = Engine::new(store, partition(), config(&["audit"]));
    let (headers, body) = request(AUDIT_PATH, &json!({"fromSeq":"1","pageSize":1}), 41);
    // Storage committed the response and audit, but its acknowledgement was lost.
    let uncertain = engine.handle(AUDIT_PATH, &headers, &body, 1).await;
    assert_eq!(uncertain.status, 503);
    assert_eq!(head(&inner).await, 1);
    let restarted = Engine::new(inner.clone(), partition(), config(&["moderation"]));
    let replay = restarted.handle(AUDIT_PATH, &headers, &body, 2).await;
    assert_eq!(replay.status, 200);
    assert_eq!(page(&replay)["chainHeadSeq"], "0");
    assert_eq!(
        restarted.handle(AUDIT_PATH, &headers, &body, 3).await,
        replay
    );
    assert_eq!(head(&inner).await, 1);
}

#[test]
fn automatic_audit_details_are_bounded_for_long_valid_source_identity() {
    let source = Partition::Ref {
        ns: crate::NamespaceKey::deployment_default(),
        repo: crate::RepoName::new("repo").unwrap(),
        shard_ref: format!("refs/heads/{}", "a".repeat(200)),
    };
    let mut request = automatic_request();
    request.purge_id = "p".repeat(128);
    let audit = SystemAudit::new(MemoryKv::default(), root_partition());
    let row = audit.relay_row(&source, &request, "op", 1).unwrap();
    let mut batch = Batch::new();
    for (key, value) in row.puts {
        batch = batch.put(key, value);
    }
    extend_audit_batch(&root_partition(), &mut batch, |_| Ok(None)).unwrap();
    let entry = batch
        .writes
        .iter()
        .find_map(|write| match write {
            crate::Write::Put(key, value) if key.as_bytes().starts_with(b"ae\0") => Some(
                serde_json::from_slice::<serde_json::Value>(value.as_bytes()).expect("audit entry"),
            ),
            _ => None,
        })
        .unwrap();
    let details = entry["details"].as_str().unwrap();
    assert!(details.len() <= 512);
    let details: serde_json::Value = serde_json::from_str(details).unwrap();
    assert_eq!(details["purgeId"], request.purge_id);
    assert_eq!(
        details["sourcePartitionHash"],
        mkit_core::hash::to_hex(&mkit_core::hash::hash(&source.encode().unwrap()))
    );
}

#[tokio::test]
async fn fresh_nonce_purge_replay_survives_removed_purge_configuration() {
    let store = std::sync::Arc::new(MemoryKv::default());
    let enabled = Engine::new(store.clone(), partition(), config(&["moderation"])).with_purge(true);
    let input = purge_body();
    let (headers, body) = request(PURGE_PATH, &input, 111);
    let first = enabled.handle(PURGE_PATH, &headers, &body, 100).await;
    assert_eq!(first.status, 200);
    let timers = purge_timers(&store).await;
    assert_eq!(timers.len(), 1);
    let disabled = Engine::new(store.clone(), partition(), config(&["moderation"]));
    assert_eq!(
        disabled.handle(PURGE_PATH, &headers, &body, 101).await,
        first
    );
    let (headers, body) = request(PURGE_PATH, &input, 112);
    assert_eq!(
        disabled.handle(PURGE_PATH, &headers, &body, 102).await,
        first
    );
    assert_eq!(purge_timers(&store).await, timers);
    let mut changed = input;
    changed["reason"] = json!("changed reason");
    let (headers, body) = request(PURGE_PATH, &changed, 113);
    assert_eq!(
        disabled
            .handle(PURGE_PATH, &headers, &body, 103)
            .await
            .status,
        400
    );
    assert_eq!(purge_timers(&store).await, timers);
    assert_eq!(head(&store).await, 3);
}
