use super::*;
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
async fn purge_replay_survives_restart_and_role_change_without_duplicate_effects() {
    let store = std::sync::Arc::new(MemoryKv::default());
    let (headers, body) = request(PURGE_PATH, &purge_body(), 1);
    let first = Engine::new(store.clone(), partition(), config(&["moderation"]), true)
        .handle(PURGE_PATH, &headers, &body, 1)
        .await;
    assert_eq!(first.status, 200);
    let restarted = Engine::new(store.clone(), partition(), config(&["audit"]), true);
    assert_eq!(
        restarted.handle(PURGE_PATH, &headers, &body, 2).await,
        first
    );
    assert_eq!(head(&store).await, 1);
    let (headers, body) = request(PURGE_PATH, &purge_body(), 2);
    let second = Engine::new(store.clone(), partition(), config(&["moderation"]), true)
        .handle(PURGE_PATH, &headers, &body, 2)
        .await;
    assert_eq!(second, first);
    assert_eq!(head(&store).await, 1);
}
#[tokio::test]
async fn authenticated_denials_and_audit_reads_extend_gapless_chain() {
    let store = std::sync::Arc::new(MemoryKv::default());
    let engine = Engine::new(store.clone(), partition(), config(&["audit"]), true);
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
    let engine = Engine::new(store.clone(), partition(), config(&["all"]), true);
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
    let engine = Engine::new(store.clone(), partition(), config(&["audit"]), false);
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
    let restarted = Engine::new(store.clone(), partition(), config(&["moderation"]), false);
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
    let first = Engine::new(store.clone(), partition(), config(&["moderation"]), false)
        .handle(AUDIT_PATH, &headers, &body, 1)
        .await;
    assert_eq!(first.status, 403);
    let restarted = Engine::new(store.clone(), partition(), config(&["audit"]), false);
    assert_eq!(
        restarted.handle(AUDIT_PATH, &headers, &body, 2).await,
        first
    );
    assert_eq!(head(&store).await, 1);
}

#[tokio::test]
async fn admin_envelope_rejects_duplicate_joined_mixed_and_changed_signed_fields() {
    let store = std::sync::Arc::new(MemoryKv::default());
    let engine = Engine::new(store.clone(), partition(), config(&["audit"]), false);
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
    let engine = Engine::new(store.clone(), partition(), config(&["audit"]), false);
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
    let engine = Engine::new(store.clone(), partition(), config(&["audit"]), false);
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
        let engine = Engine::new(store.clone(), partition(), config(&["audit"]), false);
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
    let store = std::sync::Arc::new(MemoryKv::default());
    let audit = SystemAudit::new(store.clone(), partition());
    let mut batch = audit
        .plan(&partition(), &automatic_request(), 1)
        .await
        .unwrap();
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
    assert!(
        store
            .get(&partition(), &crate::Key::new(b"ai\0automatic-1".to_vec()))
            .await
            .unwrap()
            .is_none()
    );
}
