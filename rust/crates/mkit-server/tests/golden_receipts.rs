//! Independent, test-local JCS/PAE encoder and verifier for SPEC-SERVER §15.
//! `UPDATE_GOLDEN=1` deliberately refreshes the labelled fixture set.
#![cfg(feature = "connect")]
#![allow(clippy::unwrap_used)] // Golden construction and failures are assertions.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use mkit_core::hash::{hash, to_hex, to_hex_bytes};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const PREDICATE_TYPE: &str =
    "https://github.com/officialunofficial/mkit/spec/predicate/storage-receipt/v1";
const PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";
const STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";
const SEED: [u8; 32] = [0x42; 32];
const RETIRED_SEED: [u8; 32] = [0x43; 32];
const REPOSITORY: &str =
    "ed25519-2222222222222222222222222222222222222222222222222222222222222222/demo";
const ORIGIN: &str = "https://store.example.test";
const REF: &str = "refs/heads/main";
const TARGET: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const PREVIOUS: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const PACKMAP: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

fn directory() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/golden/receipts")
}

// Fixture strings are ASCII, integers are small or encoded as strings, and
// object keys are sorted recursively. This is a deliberately local JCS path.
fn jcs(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<_> = map.iter().collect();
            entries.sort_by_key(|(key, _)| *key);
            let body = entries
                .into_iter()
                .map(|(key, value)| {
                    format!("{}:{}", serde_json::to_string(key).unwrap(), jcs(value))
                })
                .collect::<Vec<_>>()
                .join(",");
            format!("{{{body}}}")
        }
        Value::Array(items) => format!("[{}]", items.iter().map(jcs).collect::<Vec<_>>().join(",")),
        Value::Number(number) => {
            assert!(number.is_i64() || number.is_u64());
            number.to_string()
        }
        _ => serde_json::to_string(value).unwrap(),
    }
}

fn pae(payload: &[u8]) -> Vec<u8> {
    let mut bytes = format!("DSSEv1 {} {} ", PAYLOAD_TYPE.len(), PAYLOAD_TYPE).into_bytes();
    bytes.extend_from_slice(payload.len().to_string().as_bytes());
    bytes.push(b' ');
    bytes.extend_from_slice(payload);
    bytes
}

fn key_id(seed: [u8; 32]) -> String {
    to_hex(&hash(
        &SigningKey::from_bytes(&seed).verifying_key().to_bytes(),
    ))
}

fn scope_bytes(repository: &str, ref_name: &str) -> Vec<u8> {
    format!("{repository}\n{ref_name}").into_bytes()
}

fn advance(predicate: &Value, subject: &str) -> Value {
    json!({
        "_type": STATEMENT_TYPE,
        "predicate": predicate,
        "predicateType": PREDICATE_TYPE,
        "subject": [{"digest": {"blake3": subject}, "name": "target"}]
    })
}

fn statements() -> BTreeMap<&'static str, Value> {
    let opaque = advance(
        &json!({
            "kind": "advance", "origin": ORIGIN, "repository": REPOSITORY,
            "ref": REF, "advance_sequence": "1", "target": TARGET,
            "packmap": PACKMAP, "deleted": false, "mode": "opaque",
            "closure_verified": false,
            "added_packs": [{"id": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", "bytes": "2048"}],
            "added_bytes": "2048",
            "storage_lease": {"scope": "repository", "expires_unix_ms": "1760000000000", "grace_ms": "86400000", "suspension_ms": "604800000"},
            "reservations": [{"id": "res-opaque-1", "external_ref": "contract:order-17"}],
            "issued_unix_ms": "1750000000000", "key_id": key_id(SEED)
        }),
        TARGET,
    );
    let indexed = advance(
        &json!({
            "kind": "advance", "origin": ORIGIN, "repository": REPOSITORY,
            "ref": REF, "advance_sequence": "2", "target": PREVIOUS,
            "packmap": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "previous": TARGET, "deleted": false, "mode": "indexed",
            "closure_verified": true,
            "added_packs": [
                {"id": "1111111111111111111111111111111111111111111111111111111111111111", "bytes": "1000"},
                {"id": "2222222222222222222222222222222222222222222222222222222222222222", "bytes": "3000"}
            ],
            "added_bytes": "4000",
            "storage_lease": {"scope": "ref", "expires_unix_ms": "1770000000000", "grace_ms": "0", "suspension_ms": "86400000"},
            "reservations": [{"id": "res-indexed-1"}],
            "issued_unix_ms": "1750000000001", "key_id": key_id(SEED)
        }),
        PREVIOUS,
    );
    let deletion = advance(
        &json!({
            "kind": "advance", "origin": ORIGIN, "repository": REPOSITORY,
            "ref": REF, "advance_sequence": "3", "target": PREVIOUS, "packmap": PACKMAP,
            "previous": PREVIOUS, "deleted": true, "mode": "opaque",
            "closure_verified": false, "added_packs": [], "added_bytes": "0",
            "storage_lease": {"permanent": true}, "reservations": [],
            "issued_unix_ms": "1750000000002", "key_id": key_id(SEED)
        }),
        PREVIOUS,
    );
    let scope = scope_bytes(REPOSITORY, REF);
    let lease = json!({
        "_type": STATEMENT_TYPE,
        "predicate": {
            "kind": "lease", "origin": ORIGIN,
            "scope": {"repository": REPOSITORY, "ref": REF},
            "terms": {"expires_unix_ms": "1770000000000", "grace_ms": "0", "suspension_ms": "86400000"},
            "effective_state": "active", "cause": "RENEWAL", "lease_version": "4",
            "issued_unix_ms": "1750000000003", "key_id": key_id(SEED)
        },
        "predicateType": PREDICATE_TYPE,
        "subject": [{
            "digest": {"blake3": to_hex(&hash(&scope)), "sha256": to_hex_bytes(&Sha256::digest(&scope))},
            "name": "scope"
        }]
    });
    BTreeMap::from([
        ("advance-opaque", opaque),
        ("advance-indexed", indexed),
        ("deletion", deletion),
        ("lease", lease),
    ])
}

fn envelope(statement: &Value) -> Vec<u8> {
    let payload = jcs(statement);
    let signature = SigningKey::from_bytes(&SEED).sign(&pae(payload.as_bytes()));
    let value = json!({
        "payload": STANDARD.encode(payload.as_bytes()),
        "payloadType": PAYLOAD_TYPE,
        "signatures": [{
            "keyid": format!("blake3:{}", key_id(SEED)),
            "sig": STANDARD.encode(signature.to_bytes())
        }]
    });
    jcs(&value).into_bytes()
}

fn key_list() -> Value {
    let current = SigningKey::from_bytes(&SEED).verifying_key().to_bytes();
    let retired = SigningKey::from_bytes(&RETIRED_SEED)
        .verifying_key()
        .to_bytes();
    json!({
        "version": 1,
        "keys": [
            {"keyId": key_id(RETIRED_SEED), "alg": "ed25519", "publicKey": to_hex_bytes(&retired),
             "notBeforeMs": "1600000000000", "notAfterMs": "1700000000000"},
            {"keyId": key_id(SEED), "alg": "ed25519", "publicKey": to_hex_bytes(&current),
             "notBeforeMs": "1700000000000", "notAfterMs": "1800000000000"}
        ]
    })
}

fn fixtures() -> BTreeMap<String, Vec<u8>> {
    let mut files = BTreeMap::new();
    for (name, statement) in statements() {
        files.insert(
            format!("{name}.statement.json"),
            jcs(&statement).into_bytes(),
        );
        files.insert(format!("{name}.dsse.json"), envelope(&statement));
    }
    let mut wrong_type = statements()["advance-opaque"].clone();
    wrong_type["predicateType"] = json!("https://example.test/other/v1");
    files.insert("wrong-predicate.dsse.json".into(), envelope(&wrong_type));
    let mut wrong_subject = statements()["advance-opaque"].clone();
    wrong_subject["subject"][0]["digest"]["blake3"] = json!(PREVIOUS);
    files.insert(
        "subject-mismatch.dsse.json".into(),
        envelope(&wrong_subject),
    );
    let mut expired = statements()["advance-opaque"].clone();
    expired["predicate"]["issued_unix_ms"] = json!("1900000000000");
    files.insert("key-outside-window.dsse.json".into(), envelope(&expired));
    files.insert("key-list.json".into(), jcs(&key_list()).into_bytes());
    files.insert(
        "test-seed.json".into(),
        (serde_json::to_string_pretty(&json!({
            "label": "TEST KEY ONLY — public golden fixture, never use in a deployment",
            "seed_hex": to_hex_bytes(&SEED),
            "retired_seed_hex": to_hex_bytes(&RETIRED_SEED),
            "key_id": key_id(SEED)
        }))
        .unwrap()
            + "\n")
            .into_bytes(),
    );
    files
}

fn manifest(files: &BTreeMap<String, Vec<u8>>) -> String {
    let mut out = String::from(
        "# Storage-receipt golden vectors (SPEC-SERVER §15)\n\
         # TEST KEYS ONLY; generated by golden_receipts\n\
         # Format: <name> <blake3-hex-of-file-bytes>\n",
    );
    for (name, bytes) in files {
        writeln!(out, "{name} {}", to_hex(&hash(bytes))).unwrap();
    }
    out
}

fn verify(bytes: &[u8], keys: &Value) -> Result<(), &'static str> {
    if bytes.len() > 65_536 {
        return Err("size");
    }
    let value: Value = serde_json::from_slice(bytes).map_err(|_| "envelope")?;
    if jcs(&value).as_bytes() != bytes {
        return Err("envelope canonicality");
    }
    if value["payloadType"] != PAYLOAD_TYPE {
        return Err("payload type");
    }
    let payload = STANDARD
        .decode(value["payload"].as_str().ok_or("payload")?)
        .map_err(|_| "payload")?;
    let statement: Value = serde_json::from_slice(&payload).map_err(|_| "statement")?;
    if jcs(&statement).as_bytes() != payload {
        return Err("statement canonicality");
    }
    let signatures = value["signatures"].as_array().ok_or("signatures")?;
    if signatures.len() != 1 {
        return Err("signatures");
    }
    let keyid = signatures[0]["keyid"].as_str().ok_or("keyid")?;
    let body = keyid.strip_prefix("blake3:").ok_or("keyid")?;
    if statement["predicate"]["key_id"] != body {
        return Err("keyid binding");
    }
    let key = keys["keys"]
        .as_array()
        .ok_or("key list")?
        .iter()
        .find(|key| key["keyId"] == body)
        .ok_or("key absent")?;
    let issued: i64 = statement["predicate"]["issued_unix_ms"]
        .as_str()
        .ok_or("issued")?
        .parse()
        .map_err(|_| "issued")?;
    let before: i64 = key["notBeforeMs"]
        .as_str()
        .ok_or("before")?
        .parse()
        .unwrap();
    let after: i64 = key["notAfterMs"].as_str().ok_or("after")?.parse().unwrap();
    let public = hex_bytes(key["publicKey"].as_str().ok_or("public key")?);
    if to_hex(&hash(&public)) != body {
        return Err("key id digest");
    }
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&public.try_into().unwrap())
        .map_err(|_| "public key")?;
    let signature = STANDARD
        .decode(signatures[0]["sig"].as_str().ok_or("signature")?)
        .map_err(|_| "signature")?;
    verifying_key
        .verify(
            &pae(&payload),
            &Signature::try_from(signature.as_slice()).unwrap(),
        )
        .map_err(|_| "signature")?;
    if statement["_type"] != STATEMENT_TYPE || statement["predicateType"] != PREDICATE_TYPE {
        return Err("predicate type");
    }
    if issued < before || issued >= after {
        return Err("key window");
    }
    let subject = &statement["subject"][0]["digest"];
    let predicate = &statement["predicate"];
    match predicate["kind"].as_str().ok_or("kind")? {
        "advance" => {
            if subject["blake3"] != predicate["target"] || subject.get("sha256").is_some() {
                return Err("subject binding");
            }
        }
        "lease" => {
            let repository = predicate["scope"]["repository"].as_str().ok_or("scope")?;
            let ref_name = predicate["scope"]["ref"].as_str().ok_or("scope")?;
            let scope = scope_bytes(repository, ref_name);
            if subject["blake3"] != to_hex(&hash(&scope))
                || subject["sha256"] != to_hex_bytes(&Sha256::digest(&scope))
            {
                return Err("subject binding");
            }
        }
        _ => return Err("kind"),
    }
    Ok(())
}

fn hex_bytes(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn golden_receipts() {
    let dir = directory();
    let files = fixtures();
    let expected_manifest = manifest(&files);
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        fs::create_dir_all(&dir).unwrap();
        for (name, bytes) in &files {
            fs::write(dir.join(name), bytes).unwrap();
        }
        fs::write(dir.join("MANIFEST.txt"), &expected_manifest).unwrap();
    }
    let actual_names: BTreeSet<_> = fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    let expected_names: BTreeSet<_> = files
        .keys()
        .cloned()
        .chain(std::iter::once("MANIFEST.txt".to_owned()))
        .collect();
    assert_eq!(actual_names, expected_names);
    for (name, expected) in &files {
        assert_eq!(&fs::read(dir.join(name)).unwrap(), expected, "{name}");
    }
    assert_eq!(
        fs::read_to_string(dir.join("MANIFEST.txt")).unwrap(),
        expected_manifest
    );

    let keys = key_list();
    for name in ["advance-opaque", "advance-indexed", "deletion", "lease"] {
        assert_eq!(verify(&files[&format!("{name}.dsse.json")], &keys), Ok(()));
    }
    for (name, error) in [
        ("wrong-predicate", "predicate type"),
        ("subject-mismatch", "subject binding"),
        ("key-outside-window", "key window"),
    ] {
        assert_eq!(
            verify(&files[&format!("{name}.dsse.json")], &keys),
            Err(error),
            "{name}"
        );
    }
    let mut wrong_lease_scope = statements()["lease"].clone();
    wrong_lease_scope["predicate"]["scope"]["repository"] =
        json!("ed25519-3333333333333333333333333333333333333333333333333333333333333333/demo");
    assert_eq!(
        verify(&envelope(&wrong_lease_scope), &keys),
        Err("subject binding")
    );
}
