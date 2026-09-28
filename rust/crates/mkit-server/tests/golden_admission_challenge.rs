//! Pins the STC §5.1 detail, its Connect error, and the HTTP 402 body shape.
//! `UPDATE_GOLDEN=1` refreshes these three fixtures and their manifest entries.
#![cfg(feature = "connect")]
#![allow(clippy::unwrap_used)] // Fixture failures are assertions.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use buffa::Message;
use connectrpc::{ConnectError, ErrorCode};
use mkit_core::hash::{hash, to_hex};
use mkit_server::connect::proto::mkit::transport::v1::{AdmissionChallenge, Challenge};
use mkit_server::{ADMISSION_CHALLENGE_TYPE, Code, ServerError};

const FILES: [&str; 3] = [
    "admission-challenge.bin",
    "admission-challenge.json",
    "admission-challenge-error.json",
];

fn golden_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/golden/transport")
}

fn challenge(scheme: &str, value: &str) -> Challenge {
    Challenge {
        scheme: Some(scheme.into()),
        value: Some(value.into()),
        ..Default::default()
    }
}

fn fixture() -> AdmissionChallenge {
    AdmissionChallenge {
        challenges: vec![
            challenge(
                "mpp",
                "Payment id=\"fake-example-not-valid\", method=\"tempo\", intent=\"charge\", request=\"fake-example-request-not-valid\"",
            ),
            challenge("x402", "fake-example-payment-required-not-valid"),
        ],
        description: Some("Example upload payment required.".into()),
        ..Default::default()
    }
}

fn update(dir: &Path, fixtures: &[Vec<u8>; 3]) {
    for (name, bytes) in FILES.iter().zip(fixtures) {
        fs::write(dir.join(name), bytes).unwrap();
    }
    let manifest_path = dir.join("MANIFEST.txt");
    let stored = fs::read_to_string(&manifest_path).unwrap();
    let mut manifest = String::new();
    for line in stored.lines() {
        if !line
            .split_whitespace()
            .next()
            .is_some_and(|name| FILES.contains(&name))
        {
            manifest.push_str(line);
            manifest.push('\n');
        }
    }
    for (name, bytes) in FILES.iter().zip(fixtures) {
        writeln!(manifest, "{name} {}", to_hex(&hash(bytes))).unwrap();
    }
    fs::write(manifest_path, manifest).unwrap();
}

fn assert_manifest(dir: &Path) {
    let manifest = fs::read_to_string(dir.join("MANIFEST.txt")).unwrap();
    let mut covered = BTreeSet::new();
    for line in manifest.lines().filter(|line| !line.starts_with('#')) {
        let columns: Vec<_> = line.split_whitespace().collect();
        assert_eq!(columns.len(), 2, "invalid manifest entry: {line}");
        let name = columns[0];
        assert!(covered.insert(name), "duplicate manifest entry: {name}");
        let path = if name.contains('.') {
            dir.join(name)
        } else {
            dir.join(format!("{name}.bin"))
        };
        assert_eq!(
            columns[1],
            to_hex(&hash(&fs::read(path).unwrap())),
            "fixture: {name}"
        );
    }
    for name in FILES {
        assert!(covered.contains(name), "manifest omits {name}");
    }
}

#[test]
fn golden_admission_challenge() {
    let dir = golden_dir();
    let message = fixture();
    let binary = message.encode_to_vec();
    let json = format!("{}\n", serde_json::to_string(&message).unwrap()).into_bytes();

    let server_error = ServerError::admission_challenge(binary.clone().into());
    assert_eq!(server_error.http_status(), Some(402));
    assert_eq!(server_error.code(), Code::PermissionDenied);
    let error: ConnectError = server_error.into();
    assert_eq!(error.code, ErrorCode::PermissionDenied);
    let mut error_json = error.to_json().to_vec();
    error_json.push(b'\n');
    let fixtures = [binary, json, error_json];
    if std::env::var("UPDATE_GOLDEN").as_deref() == Ok("1") {
        update(&dir, &fixtures);
    }
    assert_manifest(&dir);
    for (name, expected) in FILES.iter().zip(&fixtures) {
        assert_eq!(&fs::read(dir.join(name)).unwrap(), expected, "{name}");
    }

    let from_binary =
        AdmissionChallenge::decode_from_slice(&fs::read(dir.join(FILES[0])).unwrap()).unwrap();
    let from_json: AdmissionChallenge =
        serde_json::from_slice(&fs::read(dir.join(FILES[1])).unwrap()).unwrap();
    assert_eq!(from_binary, message);
    assert_eq!(from_json, message);
    assert_eq!(from_binary.encode_to_vec(), fixtures[0]);
    assert_eq!(from_json.encode_to_vec(), fixtures[0]);

    let decoded_error: ConnectError =
        serde_json::from_slice(&fs::read(dir.join(FILES[2])).unwrap()).unwrap();
    assert_eq!(decoded_error.code, ErrorCode::PermissionDenied);
    assert_eq!(decoded_error.message, error.message);
    assert_eq!(decoded_error.details.len(), 1);
    let detail = &decoded_error.details[0];
    assert_eq!(detail.type_url, ADMISSION_CHALLENGE_TYPE); // bare name, no type.googleapis.com/ prefix
    let payload = STANDARD_NO_PAD
        .decode(detail.value.as_ref().unwrap())
        .unwrap();
    assert_eq!(payload, fixtures[0]);
    assert_eq!(
        AdmissionChallenge::decode_from_slice(&payload).unwrap(),
        message
    );
}

#[test]
fn http_objects_challenge_body_uses_the_same_message_shape() {
    let path = golden_dir().join("../http-objects/response-cases.json");
    let cases: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    let body = cases["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "challenge")
        .unwrap()["expect"]["body_json"]
        .clone();
    let message: AdmissionChallenge = serde_json::from_value(body.clone()).unwrap();
    assert_eq!(message.challenges.len(), 1);
    assert_eq!(serde_json::to_value(&message).unwrap(), body);
}

#[test]
fn absent_description_is_the_empty_client_value() {
    // Servers omit an empty description; clients interpret absence as "" (WP-3.1 B2).
    let message = AdmissionChallenge {
        challenges: vec![challenge("mpp", "opaque")],
        ..Default::default()
    };
    assert_eq!(message.description.as_deref().unwrap_or(""), "");
    assert_eq!(
        AdmissionChallenge::decode_from_slice(&message.encode_to_vec())
            .unwrap()
            .description,
        None
    );
    assert!(
        serde_json::to_value(&message).unwrap()["description"].is_null(),
        "an unset description is omitted from protobuf JSON"
    );
}
