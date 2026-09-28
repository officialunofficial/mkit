use std::fs;
use std::path::Path;

use mkit_core::hash::{hash, to_hex, to_hex_bytes};
use serde_json::{Value, json};

use super::*;
use crate::error::Code;

fn keys() -> TicketKeys {
    TicketKeys::new(vec![("current".into(), [7; 32]), ("old".into(), [8; 32])]).unwrap()
}

fn bytes_from_hex(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn receipt_roundtrip_under_rotation_and_unknown_key() {
    let old = TicketKeys::new(vec![("old".into(), [8; 32])]).unwrap();
    let receipt = mint(&old, &[0x11; 32], 2, &[0x33; 32], 5, b"etag").unwrap();
    let parsed = verify(&keys(), &receipt).unwrap();
    assert_eq!(parsed.ticket_id, [0x11; 32]);
    assert_eq!(parsed.index, 2);
    assert_eq!(parsed.subtree, [0x33; 32]);
    assert_eq!(parsed.len, 5);
    assert_eq!(parsed.tag, b"etag");
    let unknown = TicketKeys::new(vec![("new".into(), [9; 32])]).unwrap();
    assert_eq!(
        verify(&unknown, &receipt).unwrap_err().code(),
        Code::InvalidArgument
    );
}

#[test]
fn golden_part_receipt_v1() {
    let keys = keys();
    let minted = mint(&keys, &[0x11; 32], 3, &[0x22; 32], 8_388_608, b"part-tag").unwrap();
    let mut forged = minted.clone();
    *forged.last_mut().unwrap() ^= 1;
    let mut unknown = minted.clone();
    unknown[2..9].copy_from_slice(b"unknown");
    let truncated = minted[..minted.len() - 1].to_vec();
    let failure = |name: &str, bytes: &[u8]| {
        json!({
            "name": name, "receipt_hex": to_hex_bytes(bytes), "code": "invalid_argument",
        })
    };
    let fixture = json!({
        "spec": "SPEC-TRANSPORT-CONNECT §7.6",
        "note": "TEST SECRET ONLY; BLAKE3 derive_key context mkit-server part receipt v1",
        "key_id": "current",
        "secret_hex": to_hex(&[7; 32]),
        "ticket_id": to_hex(&[0x11; 32]),
        "index": 3,
        "subtree": to_hex(&[0x22; 32]),
        "len": 8_388_608,
        "tag_hex": to_hex_bytes(b"part-tag"),
        "receipt_hex": to_hex_bytes(&minted),
        "failures": [
            failure("bad_mac", &forged),
            failure("unknown_key_id", &unknown),
            failure("malformed", &truncated),
        ],
    });
    let expected = serde_json::to_string_pretty(&fixture).unwrap() + "\n";
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/golden/uploads");
    let name = "part-receipt-v1.json";
    if std::env::var("UPDATE_GOLDEN").as_deref() == Ok("1") {
        fs::write(dir.join(name), &expected).unwrap();
        let manifest = fs::read_to_string(dir.join("MANIFEST.txt")).unwrap();
        let mut lines: Vec<_> = manifest
            .lines()
            .filter(|line| !line.starts_with(&format!("{name} ")))
            .map(str::to_owned)
            .collect();
        lines.push(format!("{name} {}", to_hex(&hash(expected.as_bytes()))));
        fs::write(dir.join("MANIFEST.txt"), lines.join("\n") + "\n").unwrap();
    }
    let stored = fs::read(dir.join(name)).unwrap();
    assert_eq!(stored, expected.as_bytes());
    let manifest = fs::read_to_string(dir.join("MANIFEST.txt")).unwrap();
    assert!(manifest.contains(&format!("{name} {}", to_hex(&hash(&stored)))));
    let parsed: Value = serde_json::from_slice(&stored).unwrap();
    let receipt = bytes_from_hex(parsed["receipt_hex"].as_str().unwrap());
    assert_eq!(verify(&keys, &receipt).unwrap().index, 3);
    for failure in parsed["failures"].as_array().unwrap() {
        let bytes = bytes_from_hex(failure["receipt_hex"].as_str().unwrap());
        assert_eq!(
            verify(&keys, &bytes).unwrap_err().code(),
            Code::InvalidArgument
        );
    }
}
