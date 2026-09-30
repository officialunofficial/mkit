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
    let mut capture = BodyCapture::default();
    capture.push(&bytes);
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
