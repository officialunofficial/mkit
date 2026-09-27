//! Pins the indexed-mode detail and Connect error bytes (STC §7.6,
//! SPEC-SERVER §9.5 and §16). `UPDATE_GOLDEN=1` updates only these fixtures
//! and their manifest entries; the pre-existing transport vectors stay fixed.
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
use mkit_server::connect::proto::mkit::transport::v1::PendingVerification;
use mkit_server::{Code, ErrorDetail, ServerError};

const FILES: [&str; 3] = [
    "pending-verification.bin",
    "pending-verification.json",
    "pending-verification-error.json",
];
const TYPE: &str = "mkit.transport.v1.PendingVerification";

fn golden_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/golden/transport")
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
        // Older framing entries name binary stems; newer entries name files.
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
fn golden_pending_verification() {
    let dir = golden_dir();
    let message = PendingVerification {
        retry_after_ms: Some(5000),
        ..Default::default()
    };
    let binary = message.encode_to_vec();
    assert_eq!(binary, [0x08, 0x88, 0x27]); // field 1, varint 5000
    let json = format!("{}\n", serde_json::to_string(&message).unwrap()).into_bytes();
    assert_eq!(json, b"{\"retryAfterMs\":5000}\n");

    // Exercise the production ServerError conversion and Connect serializer.
    let error: ConnectError = ServerError::new(Code::Unavailable, "pack verification pending")
        .with_detail(ErrorDetail {
            type_name: TYPE.into(),
            value: binary.clone().into(),
        })
        .into();
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
        PendingVerification::decode_from_slice(&fs::read(dir.join(FILES[0])).unwrap()).unwrap();
    let from_json: PendingVerification =
        serde_json::from_slice(&fs::read(dir.join(FILES[1])).unwrap()).unwrap();
    assert_eq!(from_binary, message);
    assert_eq!(from_json, message);
    assert_eq!(from_binary.encode_to_vec(), fixtures[0]);
    assert_eq!(from_json.encode_to_vec(), fixtures[0]);

    let decoded_error: ConnectError =
        serde_json::from_slice(&fs::read(dir.join(FILES[2])).unwrap()).unwrap();
    assert_eq!(decoded_error.code, ErrorCode::Unavailable);
    assert_eq!(decoded_error.message, error.message);
    assert_eq!(decoded_error.details.len(), 1);
    let detail = &decoded_error.details[0];
    assert_eq!(detail.type_url, TYPE);
    assert_eq!(detail.value.as_deref(), Some("CIgn"));
    let payload = STANDARD_NO_PAD
        .decode(detail.value.as_ref().unwrap())
        .unwrap();
    assert_eq!(payload, fixtures[0]);
    assert_eq!(
        PendingVerification::decode_from_slice(&payload).unwrap(),
        message
    );
}
