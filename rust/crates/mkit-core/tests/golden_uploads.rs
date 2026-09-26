//! Golden vectors for resumable part uploads (SPEC-TRANSPORT-CONNECT §7.6).
//!
//! Two independent halves, like `golden_disclosure.rs`:
//!
//! * `MKIT_WRITE_GOLDEN=1` (re)writes `rust/tests/golden/uploads/
//!   {subtree-merge.json,MANIFEST.txt}` and `rust/tests/golden/auth-v2/part.json`.
//! * The normal run reads ONLY the committed files and checks them.
//!
//! Inputs are never stored: vector input byte `i` is `i % 251`, the BLAKE3
//! test-vector rule. The normative vectors use an 8 MiB part size. The
//! `"test_geometry": true` vectors use 1 KiB and 4 KiB parts, which the spec
//! does not allow; they exist for a fast independent cross-check of deeper,
//! unbalanced trees. The public `PartPlan` rejects that geometry, so this test
//! hashes those parts with `blake3::hazmat` directly, and the module's own
//! `small_geometry_goldens_match_module` unit test checks them through
//! `PartPlan::new_small`. `scripts/golden/blake3_subtree_ref.py` is the
//! independent pure-Python cross-check of every file here.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::fs;
use std::path::PathBuf;

use blake3::hazmat::HasherExt;
use ed25519_dalek::{Signer, SigningKey};
use mkit_core::hash::{hash, to_hex, to_hex_bytes};
use mkit_core::pack::pack_key;
use mkit_core::upload_parts::{
    ChainingValue, MIN_PART_SIZE, PartHasher, PartPlan, merge_to_root, part_subtree_cv,
};
use mkit_core::write_auth::{
    self, ContentCommitment, Context, ExpectedCommitment, Headers, Operation, PartCommitment,
};
use serde_json::{Value, json};

const KIB: u64 = 1024;
const MIB: u64 = 1024 * KIB;

fn golden_root() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop(); // crates/
    d.pop(); // rust/
    d.push("tests");
    d.push("golden");
    d
}

fn writing() -> bool {
    std::env::var("MKIT_WRITE_GOLDEN").is_ok()
}

/// Regenerate every fixture once per test process when writing.
fn maybe_write() {
    static WRITE: std::sync::Once = std::sync::Once::new();
    if writing() {
        WRITE.call_once(write_all);
    }
}

fn input(len: u64) -> Vec<u8> {
    // Repeat one 251-byte period: fast even in an unoptimized test build.
    let period: Vec<u8> = (0..251u8).collect();
    let len = usize_of(len);
    let mut out = Vec::with_capacity(len + period.len());
    while out.len() < len {
        out.extend_from_slice(&period);
    }
    out.truncate(len);
    out
}

fn usize_of(n: u64) -> usize {
    usize::try_from(n).unwrap()
}

/// `(name, test_geometry, part_size, total)`.
fn geometries() -> Vec<(String, bool, u64, u64)> {
    let mut out = vec![
        ("8mib-2parts-last-1".into(), false, 8 * MIB, 8 * MIB + 1),
        (
            "8mib-3parts-last-1023".into(),
            false,
            8 * MIB,
            16 * MIB + 1023,
        ),
        (
            "8mib-3parts-last-1024".into(),
            false,
            8 * MIB,
            16 * MIB + 1024,
        ),
        (
            "8mib-3parts-last-1025".into(),
            false,
            8 * MIB,
            16 * MIB + 1025,
        ),
        (
            "8mib-5parts-last-8mib-minus-1".into(),
            false,
            8 * MIB,
            40 * MIB - 1,
        ),
        ("8mib-8parts-full".into(), false, 8 * MIB, 64 * MIB),
    ];
    for (part_size, lasts) in [
        (KIB, [1, 513, 1023, 700, 1, 300]),
        (4 * KIB, [1, 1025, 4095, 2048, 3000, 1]),
    ] {
        for (parts, last) in [2u64, 3, 5, 8, 9, 17].into_iter().zip(lasts) {
            out.push((
                format!("{}kib-{parts}parts-last-{last}", part_size / KIB),
                true,
                part_size,
                (parts - 1) * part_size + last,
            ));
        }
    }
    out
}

/// A part CV straight from `blake3::hazmat`, for any geometry.
fn hazmat_cv(offset: u64, bytes: &[u8]) -> ChainingValue {
    let mut hasher = blake3::Hasher::new();
    hasher.set_input_offset(offset);
    hasher.update(bytes);
    hasher.finalize_non_root()
}

/// `(index, offset, len, cv)` per part, and the root.
fn compute(
    test_geometry: bool,
    part_size: u64,
    total: u64,
) -> (Vec<(u64, u64, u64, String)>, String) {
    let data = input(total);
    let whole = hash(&data);
    assert_eq!(whole, pack_key(&data));
    let count = total.div_ceil(part_size);
    let mut parts = Vec::new();
    let mut cvs = Vec::new();
    for index in 0..count {
        let offset = index * part_size;
        let len = part_size.min(total - offset);
        let bytes = &data[usize_of(offset)..usize_of(offset + len)];
        let cv = if test_geometry {
            hazmat_cv(offset, bytes)
        } else {
            let plan = PartPlan::new(total, part_size, u32::MAX).unwrap();
            let index = u32::try_from(index).unwrap();
            assert_eq!(plan.offset(index), Ok(offset));
            assert_eq!(plan.expected_len(index), Ok(len));
            // Stream in uneven slices. The last part also goes through the
            // one-shot path (cheap: never more than 8 MiB of rehashing).
            let mut hasher = PartHasher::new(&plan, index).unwrap();
            for slice in bytes.chunks(usize_of(3 * MIB + 7)) {
                hasher.update(slice).unwrap();
            }
            let cv = hasher.finalize().unwrap();
            if index + 1 == plan.count() {
                assert_eq!(cv, part_subtree_cv(&plan, index, bytes).unwrap());
            }
            cv
        };
        parts.push((index, offset, len, to_hex(&cv)));
        cvs.push(cv);
    }
    if !test_geometry {
        let plan = PartPlan::new(total, part_size, u32::MAX).unwrap();
        assert_eq!(merge_to_root(&plan, &cvs), Ok(whole));
    }
    (parts, to_hex(&whole))
}

fn vector_json(name: &str, test_geometry: bool, part_size: u64, total: u64) -> Value {
    let (parts, root) = compute(test_geometry, part_size, total);
    json!({
        "name": name,
        "test_geometry": test_geometry,
        "part_size": part_size,
        "total": total,
        "parts": parts
            .into_iter()
            .map(|(index, offset, len, cv)| json!({
                "index": index, "offset": offset, "len": len, "cv": cv,
            }))
            .collect::<Vec<_>>(),
        "root": root,
    })
}

const SEED: [u8; 32] = [7; 32];
const AUDIENCE: &str = "https://api.example.test";
const PROCEDURE: &str = "/mkit.transport.v1.TransportService/UploadPart";
const CREATED_AT: i64 = 1_700_000_000_000;
const EXPIRES_AT: i64 = 1_700_000_300_000;
const TICKET: [u8; 32] = [0x5a; 32];

fn write_all() {
    let vectors: Vec<Value> = geometries()
        .into_iter()
        .map(|(name, test_geometry, part_size, total)| {
            vector_json(&name, test_geometry, part_size, total)
        })
        .collect();
    let merge = json!({
        "spec": "SPEC-TRANSPORT-CONNECT §7.6",
        "input_rule": "byte[i] = i % 251",
        "note": "test_geometry vectors use part sizes below the 8 MiB minimum; they are test-only geometry",
        "vectors": vectors,
    });
    let dir = golden_root().join("uploads");
    fs::create_dir_all(&dir).unwrap();
    let text = serde_json::to_string_pretty(&merge).unwrap() + "\n";
    fs::write(dir.join("subtree-merge.json"), &text).unwrap();
    fs::write(
        dir.join("MANIFEST.txt"),
        format!(
            "# SPEC-TRANSPORT-CONNECT §7.6 part-upload golden vectors (deterministic)\n\
             # Produced by `MKIT_WRITE_GOLDEN=1 cargo test -p mkit-core --test golden_uploads`\n\
             # Cross-checked by `python3 scripts/golden/blake3_subtree_ref.py`\n\
             # Format: <name> <blake3-hex-of-file-bytes>\n\
             subtree-merge.json {}\n",
            to_hex(&hash(text.as_bytes()))
        ),
    )
    .unwrap();

    let source = &merge["vectors"][0];
    assert_eq!(source["name"], "8mib-2parts-last-1");
    let part = &source["parts"][1];
    let subtree = part["cv"].as_str().unwrap();
    let len = part["len"].as_u64().unwrap();
    let key = SigningKey::from_bytes(&SEED);
    let public_key = to_hex(&key.verifying_key().to_bytes());
    let repository = format!("ed25519-{public_key}/demo");
    let commitment = ContentCommitment::Part(PartCommitment {
        ticket: TICKET,
        index: 1,
        subtree: mkit_core::hash::from_hex(subtree).unwrap(),
        len,
    })
    .to_string();
    let nonce = "ab".repeat(32);
    let operation = Operation {
        context: Context {
            audience: AUDIENCE,
            repository: &repository,
        },
        procedure: PROCEDURE,
        commitment: &commitment,
        created_at: CREATED_AT,
        expires_at: EXPIRES_AT,
        nonce: &nonce,
    };
    let digest = operation.digest().unwrap();
    let fixture = json!({
        "version": 2,
        "audience": AUDIENCE,
        "repository": repository,
        "procedure": PROCEDURE,
        "ticket": to_hex(&TICKET),
        "index": 1,
        "subtree": subtree,
        "len": len,
        "subtree_source": "uploads/subtree-merge.json 8mib-2parts-last-1 part 1",
        "created_at": CREATED_AT,
        "expires_at": EXPIRES_AT,
        "nonce": nonce,
        "seed": to_hex(&SEED),
        "commitment": commitment,
        "canonical": operation.canonical().unwrap(),
        "signing_digest": to_hex(&digest),
        "public_key": public_key,
        "signature": to_hex_bytes(&key.sign(&digest).to_bytes()),
    });
    fs::write(
        golden_root().join("auth-v2").join("part.json"),
        serde_json::to_string_pretty(&fixture).unwrap() + "\n",
    )
    .unwrap();
}

fn read_json(path: &[&str]) -> (String, Value) {
    let mut file = golden_root();
    for p in path {
        file.push(p);
    }
    let text = fs::read_to_string(&file).unwrap();
    let value = serde_json::from_str(&text).unwrap();
    (text, value)
}

#[test]
fn subtree_merge_vectors_verify() {
    maybe_write();
    let (text, fixture) = read_json(&["uploads", "subtree-merge.json"]);
    let manifest = fs::read_to_string(golden_root().join("uploads").join("MANIFEST.txt")).unwrap();
    let pinned = manifest
        .lines()
        .find_map(|line| line.strip_prefix("subtree-merge.json "))
        .unwrap();
    assert_eq!(pinned, to_hex(&hash(text.as_bytes())), "MANIFEST.txt pin");

    let vectors = fixture["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), geometries().len());
    let mut normative = 0;
    for vector in vectors {
        let name = vector["name"].as_str().unwrap();
        let test_geometry = vector["test_geometry"].as_bool().unwrap();
        let part_size = vector["part_size"].as_u64().unwrap();
        let total = vector["total"].as_u64().unwrap();
        assert_eq!(test_geometry, part_size < MIN_PART_SIZE, "{name}");
        if !test_geometry {
            normative += 1;
        }
        // Recompute from the input rule; `compute` also asserts
        // merge_to_root == blake3::hash == pack_key for normative geometry.
        assert_eq!(
            &vector_json(name, test_geometry, part_size, total),
            vector,
            "{name}"
        );
    }
    assert_eq!(normative, 6);
}

#[test]
fn auth_v2_part_golden_verifies() {
    maybe_write();
    let (_, fixture) = read_json(&["auth-v2", "part.json"]);
    let field = |name: &str| fixture[name].as_str().unwrap();
    let operation = Operation {
        context: Context {
            audience: field("audience"),
            repository: field("repository"),
        },
        procedure: field("procedure"),
        commitment: field("commitment"),
        created_at: fixture["created_at"].as_i64().unwrap(),
        expires_at: fixture["expires_at"].as_i64().unwrap(),
        nonce: field("nonce"),
    };
    assert_eq!(operation.canonical().unwrap(), field("canonical"));
    let digest = operation.digest().unwrap();
    assert_eq!(to_hex(&digest), field("signing_digest"));

    // The commitment is built from the named fields and the merge vector.
    let expected = ContentCommitment::Part(PartCommitment {
        ticket: mkit_core::hash::from_hex(field("ticket")).unwrap(),
        index: u32::try_from(fixture["index"].as_u64().unwrap()).unwrap(),
        subtree: mkit_core::hash::from_hex(field("subtree")).unwrap(),
        len: fixture["len"].as_u64().unwrap(),
    });
    assert_eq!(ContentCommitment::parse(field("commitment")), Ok(expected));
    let (_, merge) = read_json(&["uploads", "subtree-merge.json"]);
    assert_eq!(merge["vectors"][0]["name"], "8mib-2parts-last-1");
    assert_eq!(merge["vectors"][0]["parts"][1]["cv"], fixture["subtree"]);
    assert_eq!(merge["vectors"][0]["parts"][1]["len"], fixture["len"]);

    let key = SigningKey::from_bytes(&mkit_core::hash::from_hex(field("seed")).unwrap());
    assert_eq!(to_hex(&key.verifying_key().to_bytes()), field("public_key"));
    assert_eq!(
        field("repository"),
        format!("ed25519-{}/demo", field("public_key"))
    );
    let public_key = mkit_core::hash::from_hex(field("public_key")).unwrap();
    let signature: [u8; 64] = hex::decode(field("signature")).unwrap().try_into().unwrap();
    assert_eq!(key.sign(&digest).to_bytes(), signature);
    let now = operation.created_at + 1;
    operation
        .verify(operation.context, now, &public_key, &signature)
        .unwrap();

    let headers = Headers {
        version: Some("2".into()),
        audience: Some(field("audience").into()),
        repository: Some(field("repository").into()),
        public_key: Some(field("public_key").into()),
        signature: Some(field("signature").into()),
        digest: None,
        commitment: Some(field("commitment").into()),
        created_at: Some(operation.created_at.to_string()),
        expires_at: Some(operation.expires_at.to_string()),
        idempotency_key: Some(field("nonce").into()),
    };
    let authorized = write_auth::verify_headers_with(
        operation.context,
        operation.procedure,
        ExpectedCommitment::PartStream,
        now,
        &headers,
    )
    .unwrap();
    assert_eq!(authorized.fingerprint, field("signing_digest"));
    assert_eq!(authorized.content_commitment(), Ok(expected));
    assert!(
        write_auth::verify_headers_with(
            operation.context,
            operation.procedure,
            ExpectedCommitment::PartStream,
            operation.expires_at + 1,
            &headers,
        )
        .is_err()
    );
}
