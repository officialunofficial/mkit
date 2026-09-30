//! Actual Worker D34 authority fence probe; run by vcs-worker-hooks.sh --authority.
#![allow(clippy::unwrap_used)]
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use ed25519_dalek::{Signer as _, SigningKey};
use mkit_core::hash::{hash, to_hex};
use mkit_server_conformance::wire::{
    client::{Client, Rpc},
    sign::{Signer, now_ms},
};
use serde_json::json;
use url::Url;
const NS: &str = "ed25519-0101010101010101010101010101010101010101010101010101010101010101";
const SET: &str = "/mkit.transport.v1.TransportService/SetAuthorityGeneration";
fn statement(audience: &str, generation: u64) -> String {
    let now = now_ms();
    let bytes = format!(
        "mkit-authority-generation:v1\ndeployment\n{NS}\n{generation}\n{audience}\n{now}\n{}\n{}",
        now + 60000,
        to_hex(&hash(b"worker-authority"))
    );
    let signature = SigningKey::from_bytes(&[7; 32]).sign(&hash(bytes.as_bytes()));
    format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(bytes),
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    )
}
#[tokio::test]
#[ignore = "requires disposable local Worker D34 and the hook stub"]
async fn worker_d34_authority_barrier_rejects_stale_facts_and_ticket_staging() {
    let origin = std::env::var("MKIT_AUTHORITY_PROBE_URL").unwrap();
    let client = Client::new(&Url::parse(&origin).unwrap()).unwrap();
    let stub =
        Client::new(&Url::parse(&std::env::var("MKIT_AUTHORITY_STUB_URL").unwrap()).unwrap())
            .unwrap();
    let signer = Signer::new([2; 32], &origin, &format!("{NS}/fenced"));
    let path = Rpc::UpdateRef.procedure();
    let body=serde_json::to_vec(&json!({"name":"refs/heads/fence","newId":STANDARD.encode([1u8;32]),"expectation":"REF_EXPECTATION_ANY"})).unwrap();
    let signed = signer.sign_body(path, &body);
    assert_eq!(
        client
            .post(path, "application/json", &signed.headers, body.clone())
            .await
            .unwrap()
            .status,
        200
    );
    // Setter is authorized solely by its deployment statement, outside the write envelope.
    let target = serde_json::to_vec(&json!({"signedStatement":statement(&origin,1)})).unwrap();
    assert_eq!(
        client
            .post(SET, "application/json", &[], target.clone())
            .await
            .unwrap()
            .status,
        200
    );
    assert_eq!(
        client
            .post(SET, "application/json", &[], target)
            .await
            .unwrap()
            .status,
        200
    );
    let stale = signer.sign_body(path, &body);
    let rejected = client
        .post(path, "application/json", &stale.headers, body.clone())
        .await
        .unwrap();
    assert_eq!(
        rejected.status,
        403,
        "{}",
        String::from_utf8_lossy(&rejected.body)
    );
    // An old result can replay without recommitting.
    assert_eq!(
        client
            .post(path, "application/json", &signed.headers, body.clone())
            .await
            .unwrap()
            .status,
        200
    );
    assert_eq!(
        stub.post("/__mode?generation=1", "application/json", &[], vec![])
            .await
            .unwrap()
            .status,
        200
    );
    let fresh = signer.sign_body(path, &body);
    assert_eq!(
        client
            .post(path, "application/json", &fresh.headers, body)
            .await
            .unwrap()
            .status,
        200
    );
    let begin_path = Rpc::BeginUpload.procedure();
    let begin = serde_json::to_vec(
        &json!({"ref":"refs/heads/fence","packId":STANDARD.encode([3u8;32]),"bytes":"10"}),
    )
    .unwrap();
    let signed = signer.sign_body(begin_path, &begin);
    let response = client
        .post(begin_path, "application/json", &signed.headers, begin)
        .await
        .unwrap();
    assert_eq!(
        response.status,
        200,
        "{}",
        String::from_utf8_lossy(&response.body)
    );
    let ticket: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    let token = ticket["ticket"]["token"].as_str().unwrap();
    let target = serde_json::to_vec(&json!({"signedStatement":statement(&origin,2)})).unwrap();
    assert_eq!(
        client
            .post(SET, "application/json", &[], target)
            .await
            .unwrap()
            .status,
        200
    );
    let complete = serde_json::to_vec(&json!({"ticketToken":token})).unwrap();
    let signed = signer.sign_body(Rpc::CompleteUpload.procedure(), &complete);
    assert_eq!(
        client
            .post(
                Rpc::CompleteUpload.procedure(),
                "application/json",
                &signed.headers,
                complete
            )
            .await
            .unwrap()
            .status,
        403
    );
}
