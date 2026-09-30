//! Pins the stateless ticket-token encoding and public error classes. Updating
//! this fixture preserves every other upload golden and manifest entry.
#![allow(clippy::unwrap_used)] // Fixture failures are assertions.

use std::fs;
use std::path::{Path, PathBuf};

use mkit_core::hash::{from_hex, hash, to_hex, to_hex_bytes};
use mkit_server::upload::token::{TicketClaims, TicketKeys};
use serde_json::{Value, json};

const NAME: &str = "ticket-token-v1.json";
const NOW: u64 = 1_700_000_000_000;
const KEY_ID: &str = "test-2026.1";
const SECRET: [u8; 32] = [7; 32];

fn claims() -> TicketClaims {
    TicketClaims {
        authority_generation: None,
        ticket_id: [0x11; 32],
        audience: "https://api.example.test".into(),
        repository: format!("ed25519-{}/demo", "22".repeat(32)),
        signer: [0x22; 32],
        pack_id: [0x33; 32],
        bytes: 16_777_217,
        part_size: 8_388_608,
        expires_at_ms: NOW + 86_400_000,
        upload_session: Vec::new(),
    }
}

fn fixture() -> Value {
    let keys = TicketKeys::new(vec![(KEY_ID.into(), SECRET)]).unwrap();
    let claims = claims();
    let token = keys.mint(&claims);
    let mut flipped = token.clone();
    *flipped.last_mut().unwrap() ^= 1;
    let unknown = TicketKeys::new(vec![("unknown".into(), SECRET)])
        .unwrap()
        .mint(&claims);
    let mut garbage = token[..token.len() - 32].to_vec();
    garbage.push(0);
    let key = blake3::derive_key("mkit-server ticket token v1", &SECRET);
    let tag = blake3::keyed_hash(&key, &garbage);
    garbage.extend_from_slice(tag.as_bytes());
    let failure = |name: &str, token: &[u8], now: u64, code: &str| {
        json!({
            "name": name, "token_hex": to_hex_bytes(token), "now_ms": now, "code": code,
        })
    };
    json!({
        "spec": "SPEC-TRANSPORT-CONNECT §7.6",
        "note": "TEST SECRET ONLY; BLAKE3 derive_key context mkit-server ticket token v1",
        "key_id": KEY_ID,
        "secret_hex": to_hex(&SECRET),
        "claims": {
            "ticket_id": to_hex(&claims.ticket_id), "audience": claims.audience,
            "repository": claims.repository, "signer": to_hex(&claims.signer),
            "pack_id": to_hex(&claims.pack_id), "bytes": claims.bytes,
            "part_size": claims.part_size, "expires_at_ms": claims.expires_at_ms,
            "upload_session_hex": to_hex_bytes(&claims.upload_session),
        },
        "token_hex": to_hex_bytes(&token),
        "failures": [
            failure("wrong_key", &token, NOW, "failed_precondition"),
            failure("unknown_key_id", &unknown, NOW, "failed_precondition"),
            failure("flipped_tag", &flipped, NOW, "failed_precondition"),
            failure("truncated", &token[..token.len() - 1], NOW, "failed_precondition"),
            failure("authenticated_garbage", &garbage, NOW, "failed_precondition"),
            failure("expired", &token, claims.expires_at_ms, "failed_precondition"),
            failure("binding_mismatch", &token, NOW, "permission_denied"),
        ],
    })
}

fn dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/golden/uploads")
}

fn update(dir: &Path, bytes: &[u8]) {
    fs::write(dir.join(NAME), bytes).unwrap();
    let manifest = fs::read_to_string(dir.join("MANIFEST.txt")).unwrap();
    let mut lines: Vec<_> = manifest
        .lines()
        .filter(|line| !line.starts_with(&format!("{NAME} ")))
        .map(str::to_owned)
        .collect();
    lines.push(format!("{NAME} {}", to_hex(&hash(bytes))));
    fs::write(dir.join("MANIFEST.txt"), lines.join("\n") + "\n").unwrap();
}

fn bytes_from_hex(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn golden_ticket_token_v1() {
    let expected = serde_json::to_string_pretty(&fixture()).unwrap() + "\n";
    if std::env::var("UPDATE_GOLDEN").as_deref() == Ok("1") {
        update(&dir(), expected.as_bytes());
    }
    let stored = fs::read(dir().join(NAME)).unwrap();
    assert_eq!(stored, expected.as_bytes());
    let manifest = fs::read_to_string(dir().join("MANIFEST.txt")).unwrap();
    let pins: Vec<_> = manifest
        .lines()
        .filter_map(|line| line.strip_prefix(&format!("{NAME} ")))
        .collect();
    assert_eq!(pins, [to_hex(&hash(&stored))]);

    let fixture: Value = serde_json::from_slice(&stored).unwrap();
    let keys = TicketKeys::new(vec![(
        fixture["key_id"].as_str().unwrap().into(),
        from_hex(fixture["secret_hex"].as_str().unwrap()).unwrap(),
    )])
    .unwrap();
    let token = bytes_from_hex(fixture["token_hex"].as_str().unwrap());
    assert_eq!(keys.verify(&token, NOW).unwrap(), claims());
    for failure in fixture["failures"].as_array().unwrap() {
        let token = bytes_from_hex(failure["token_hex"].as_str().unwrap());
        let now = failure["now_ms"].as_u64().unwrap();
        let error = match failure["name"].as_str().unwrap() {
            "wrong_key" => TicketKeys::new(vec![(KEY_ID.into(), [8; 32])])
                .unwrap()
                .verify(&token, now)
                .unwrap_err(),
            "binding_mismatch" => keys
                .verify(&token, now)
                .unwrap()
                .check_binding(
                    "https://wrong.example.test",
                    &claims().repository,
                    &claims().signer,
                    &claims().pack_id,
                    claims().bytes,
                )
                .unwrap_err(),
            _ => keys.verify(&token, now).unwrap_err(),
        };
        assert_eq!(
            error.code().as_str(),
            failure["code"].as_str().unwrap(),
            "{}",
            failure["name"]
        );
    }
}

#[test]
fn golden_ticket_token_v2_authority() {
    // Independently computed with the Python BLAKE3 binding.
    let name = "ticket-token-v2-authority.json";
    let stored = fs::read(dir().join(name)).unwrap();
    let fixture: Value = serde_json::from_slice(&stored).unwrap();
    let keys = TicketKeys::new(vec![(KEY_ID.into(), SECRET)]).unwrap();
    let mut claims = claims();
    claims.authority_generation = Some(7);
    let token = bytes_from_hex(fixture["token_hex"].as_str().unwrap());
    assert_eq!(keys.mint(&claims), token);
    assert_eq!(keys.verify(&token, NOW).unwrap(), claims);
    let manifest = fs::read_to_string(dir().join("MANIFEST.txt")).unwrap();
    let pins: Vec<_> = manifest
        .lines()
        .filter_map(|line| line.strip_prefix(&format!("{name} ")))
        .collect();
    assert_eq!(pins, [to_hex(&hash(&stored))]);
}
