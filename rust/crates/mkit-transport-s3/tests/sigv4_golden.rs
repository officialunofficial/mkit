#![allow(clippy::doc_markdown)]
//! Phase 7d SigV4 golden-vector check.
//!
//! Loads `rust/tests/golden/phase7/sigv4_basic.bin` (a JSON blob with
//! fixed inputs + expected outputs) and asserts that the signer
//! produces byte-identical `canonical_request`, `string_to_sign`, and
//! final `signature_hex` for those inputs. If this test fails, either
//! fix the code or re-generate the fixture intentionally.

use std::path::PathBuf;

use mkit_transport_s3::sigv4::{Credentials, sign_request};
use serde_json::Value;

fn load_golden() -> Value {
    // Resolve the path relative to this crate's directory so the test
    // works whether it's run from the workspace root or the crate dir.
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../../tests/golden/phase7/sigv4_basic.bin");
    let bytes = std::fs::read(&path)
        .unwrap_or_else(|e| panic!("could not read golden fixture at {}: {e}", path.display()));
    serde_json::from_slice(&bytes).expect("golden fixture is valid JSON")
}

#[test]
fn sigv4_canonical_request_matches_golden() {
    let v = load_golden();
    let creds = Credentials {
        access_key_id: v["access_key_id"].as_str().unwrap().into(),
        secret_access_key: v["secret_access_key"].as_str().unwrap().into(),
        region: v["region"].as_str().unwrap().into(),
    };
    let method = v["method"].as_str().unwrap();
    let path = v["path"].as_str().unwrap();
    let query = v["query"].as_str().unwrap();
    let payload = v["payload"].as_str().unwrap().as_bytes();
    let endpoint = v["endpoint"].as_str().unwrap();
    let timestamp = v["timestamp"].as_i64().unwrap();

    let signed = sign_request(&creds, method, path, query, payload, endpoint, timestamp);

    assert_eq!(
        signed.canonical_request,
        v["canonical_request"].as_str().unwrap(),
        "canonical_request diverges from golden"
    );
}

#[test]
fn sigv4_string_to_sign_matches_golden() {
    let v = load_golden();
    let creds = Credentials {
        access_key_id: v["access_key_id"].as_str().unwrap().into(),
        secret_access_key: v["secret_access_key"].as_str().unwrap().into(),
        region: v["region"].as_str().unwrap().into(),
    };
    let signed = sign_request(
        &creds,
        v["method"].as_str().unwrap(),
        v["path"].as_str().unwrap(),
        v["query"].as_str().unwrap(),
        v["payload"].as_str().unwrap().as_bytes(),
        v["endpoint"].as_str().unwrap(),
        v["timestamp"].as_i64().unwrap(),
    );
    assert_eq!(
        signed.string_to_sign,
        v["string_to_sign"].as_str().unwrap(),
        "string_to_sign diverges from golden"
    );
}

#[test]
fn sigv4_signature_matches_golden() {
    let v = load_golden();
    let creds = Credentials {
        access_key_id: v["access_key_id"].as_str().unwrap().into(),
        secret_access_key: v["secret_access_key"].as_str().unwrap().into(),
        region: v["region"].as_str().unwrap().into(),
    };
    let signed = sign_request(
        &creds,
        v["method"].as_str().unwrap(),
        v["path"].as_str().unwrap(),
        v["query"].as_str().unwrap(),
        v["payload"].as_str().unwrap().as_bytes(),
        v["endpoint"].as_str().unwrap(),
        v["timestamp"].as_i64().unwrap(),
    );
    assert_eq!(
        signed.signature_hex,
        v["signature_hex"].as_str().unwrap(),
        "signature_hex diverges from golden"
    );
    // Also assert the Authorization header includes the expected signature.
    assert!(
        signed.authorization.ends_with(&format!(
            "Signature={}",
            v["signature_hex"].as_str().unwrap()
        )),
        "Authorization header did not end with the expected Signature=<hex>"
    );
}
