//! Committed vectors for the SPEC-PARTIAL-WORKSPACES durable local-state
//! envelopes (`MKWS`/`MKST`/`MKPN`/`MKAC`/`MKGM`/`MKCR`).
//!
//! Accepted vectors are captured from REAL workspace transitions — the
//! member and pointer bytes are read off `.mkit-scoped/` after `create`,
//! `replace_stage`, `save_pending`, and `record_outcome`, never built by
//! hand. Reject vectors are independently byte-constructed corruptions.
//! Vectors are regenerated only with `MKIT_WRITE_GOLDEN=1`; the consumer
//! test reads committed files and checks the MANIFEST digests.
#![allow(clippy::unwrap_used)]

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use mkit_core::Identity;
use mkit_core::hash::{Hash, hash, to_hex};
use mkit_core::partial::{
    AcceptedStateV1, FileReplacement, PartialLimits, PartialPath, PendingOperationV1,
    PendingOutcomeV1, PendingStateV1, RemotePublicationTargetV1, ScopedWorkspaceLayout,
    StageStateV1, WorkspaceStateV1, build_partial_snapshot, export_partial_update,
    prepare_partial_commit, replace_files,
};
use mkit_core::sign::{KeyPair, sign_commit};
use serde_json::{Value, json};

mod common;

fn golden_dir() -> PathBuf {
    let mut root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.pop();
    root.pop();
    root.join("tests/golden/partial_local")
}

fn writing() -> bool {
    std::env::var("MKIT_WRITE_GOLDEN").is_ok()
}

fn selected_paths() -> Vec<PartialPath> {
    vec![
        vec![b"exec.sh".to_vec()],
        vec![b"shallow.txt".to_vec()],
        vec![b"sub".to_vec(), b"deep".to_vec(), b"deep.txt".to_vec()],
    ]
}

/// The `generations/<manifest-digest>` directory CURRENT selects.
fn current_generation_dir(root: &Path) -> PathBuf {
    let current = fs::read(root.join(".mkit-scoped/CURRENT")).unwrap();
    let digest = Hash::try_from(&current[13..45]).unwrap();
    root.join(".mkit-scoped/generations").join(to_hex(&digest))
}

struct Vector {
    name: &'static str,
    description: &'static str,
    magic: &'static str,
    bytes: Vec<u8>,
    expect: &'static str,
    error: Option<&'static str>,
}

/// Drive a real workspace through create → stage → pending → accepted and
/// capture the member/pointer bytes of the pending generation (which
/// carries MKWS+MKST+MKPN+MKGM) plus the accepted generation (MKAC).
#[allow(clippy::too_many_lines)] // one end-to-end capture fixture, kept together for auditability
fn build_accepted() -> Vec<Vector> {
    let fixture = common::build_fixture();
    let limits = PartialLimits::V1;
    let paths = selected_paths();
    let bundle =
        build_partial_snapshot(&fixture.store, fixture.commit_id, &paths, &limits).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let layout = ScopedWorkspaceLayout::create(
        &dir.path().join("ws"),
        fixture.commit_id,
        &paths,
        &bundle.encode(&limits).unwrap(),
        limits,
        Some(
            RemotePublicationTargetV1::new(
                "https://example.invalid/mkit",
                "example/repo",
                "refs/heads/main",
            )
            .unwrap(),
        ),
    )
    .unwrap();

    // Stage a real edit so MKST carries required objects.
    let staged = layout
        .replace_stage(
            0,
            &[FileReplacement::bytes(
                vec![b"shallow.txt".to_vec()],
                b"staged golden content\n".to_vec(),
            )],
        )
        .unwrap();

    // Save a real pending update carrying an operation pair.
    let verified = staged.verified();
    let feed = vec![FileReplacement::bytes(
        vec![b"shallow.txt".to_vec()],
        b"staged golden content\n".to_vec(),
    )];
    let prepared = replace_files(verified, &feed, &limits).unwrap();
    let key = KeyPair::from_seed([0x42; 32]);
    let unsigned = prepare_partial_commit(
        verified,
        &prepared,
        Identity::ed25519(key.public.0),
        key.public.0,
        b"golden pending operation".to_vec(),
        1_726_400_000,
        &limits,
    )
    .unwrap();
    let mut signed = unsigned.clone();
    signed.signature = sign_commit(&signed, &key).unwrap().0;
    let update = export_partial_update(verified, &prepared, &unsigned, &signed, &limits).unwrap();
    let update_bytes = update.encode(&limits).unwrap();
    let pending_state = layout
        .save_pending(
            1,
            &unsigned,
            &signed,
            &update_bytes,
            Some(PendingOperationV1 {
                operation_id: [0xA1; 32],
                request_fingerprint: [0xB2; 32],
            }),
        )
        .unwrap();

    let pending_gen = current_generation_dir(layout.root());
    let pending_current = fs::read(layout.root().join(".mkit-scoped/CURRENT")).unwrap();
    let workspace_bin = fs::read(pending_gen.join("workspace.bin")).unwrap();
    let stage_bin = fs::read(pending_gen.join("stage.bin")).unwrap();
    let pending_bin = fs::read(pending_gen.join("pending.bin")).unwrap();
    let manifest_bin = fs::read(pending_gen.join("manifest.bin")).unwrap();

    // Accept: produces the MKAC-bearing generation.
    let identity = pending_state.pending().unwrap().identity();
    layout
        .record_outcome(
            pending_state.workspace().transaction_generation(),
            &identity,
            PendingOutcomeV1::Accepted,
        )
        .unwrap();
    let accepted_gen = current_generation_dir(layout.root());
    let accepted_bin = fs::read(accepted_gen.join("accepted.bin")).unwrap();
    let accepted_manifest = fs::read(accepted_gen.join("manifest.bin")).unwrap();
    let accepted_current = fs::read(layout.root().join(".mkit-scoped/CURRENT")).unwrap();

    vec![
        Vector {
            name: "workspace_v1",
            description: "MKWS from the pending generation: selection, limits, target present.",
            magic: "MKWS",
            bytes: workspace_bin,
            expect: "accept",
            error: None,
        },
        Vector {
            name: "stage_v1",
            description: "MKST from the pending generation: one staged edit plus required objects.",
            magic: "MKST",
            bytes: stage_bin,
            expect: "accept",
            error: None,
        },
        Vector {
            name: "pending_v1",
            description: "MKPN in Prepared status with an operation id/fingerprint pair.",
            magic: "MKPN",
            bytes: pending_bin,
            expect: "accept",
            error: None,
        },
        Vector {
            name: "accepted_v1",
            description: "MKAC from the accepted generation: prior base, revision 1, candidate.",
            magic: "MKAC",
            bytes: accepted_bin,
            expect: "accept",
            error: None,
        },
        Vector {
            name: "manifest_v1",
            description: "MKGM selecting workspace+stage+pending members (no accepted member).",
            magic: "MKGM",
            bytes: manifest_bin,
            expect: "accept",
            error: None,
        },
        Vector {
            name: "current_v1",
            description: "MKCR pointing at the pending generation's manifest digest.",
            magic: "MKCR",
            bytes: pending_current,
            expect: "accept",
            error: None,
        },
        Vector {
            name: "manifest_accepted_v1",
            description: "MKGM from the accepted generation: accepted member present, pending gone.",
            magic: "MKGM",
            bytes: accepted_manifest,
            expect: "accept",
            error: None,
        },
        Vector {
            name: "current_accepted_v1",
            description: "MKCR pointing at the accepted generation's manifest digest.",
            magic: "MKCR",
            bytes: accepted_current,
            expect: "accept",
            error: None,
        },
    ]
}

/// Recompute the trailing BLAKE3 checksum over `magic‖version‖payload`
/// after byte-level surgery, so the corruption reaches the payload
/// decoder rather than failing integrity first.
fn reseal(mut bytes: Vec<u8>) -> Vec<u8> {
    let body_len = bytes.len() - 32;
    let checksum = hash(&bytes[..body_len]);
    bytes.truncate(body_len);
    bytes.extend_from_slice(&checksum);
    bytes
}

fn build_rejects(accepts: &[Vector]) -> Vec<Vector> {
    let ws = &accepts
        .iter()
        .find(|v| v.name == "workspace_v1")
        .unwrap()
        .bytes;
    let pn = &accepts
        .iter()
        .find(|v| v.name == "pending_v1")
        .unwrap()
        .bytes;

    // Bad checksum: corrupt the last byte without resealing.
    let mut bad_checksum = ws.clone();
    let last = bad_checksum.len() - 1;
    bad_checksum[last] ^= 0xFF;

    // Unsupported version: bump the version byte, then reseal so the
    // version check — not the checksum — is what fires.
    let mut bad_version = ws.clone();
    bad_version[4] = 2;
    let bad_version = reseal(bad_version);

    // Trailing payload byte: insert inside the payload, then reseal.
    let mut trailing = ws.clone();
    trailing.insert(trailing.len() - 32, 0);
    let trailing = reseal(trailing);

    // Non-minimal varint on the MKWS selection count (absolute offset
    // 5 + 32 + 8 + 8 + 32 + 32 = 117).
    let mut nonminimal = ws.clone();
    let count = nonminimal[117];
    assert!(count < 0x80);
    nonminimal.splice(117..118, [count | 0x80, 0x00]);
    let nonminimal = reseal(nonminimal);

    // Unknown option tag: the MKPN operation tag sits at absolute offset
    // 158, right after the status byte (this fixture carries an operation
    // pair → 1); set it to 2.
    let mut bad_tag = pn.clone();
    assert_eq!(bad_tag[158], 1);
    bad_tag[158] = 2;
    let bad_tag = reseal(bad_tag);

    // Unknown pending status: payload offset 152 → absolute 157.
    let mut bad_status = pn.clone();
    assert_eq!(bad_status[157], 0);
    bad_status[157] = 9;
    let bad_status = reseal(bad_status);

    vec![
        Vector {
            name: "neg_bad_checksum",
            description: "MKWS envelope whose trailing checksum does not match the bytes.",
            magic: "MKWS",
            bytes: bad_checksum,
            expect: "reject",
            error: Some("ChecksumMismatch"),
        },
        Vector {
            name: "neg_unsupported_version",
            description: "MKWS envelope declaring version 2.",
            magic: "MKWS",
            bytes: bad_version,
            expect: "reject",
            error: Some("UnsupportedVersion"),
        },
        Vector {
            name: "neg_trailing_byte",
            description: "MKWS payload with one byte after the declared fields.",
            magic: "MKWS",
            bytes: trailing,
            expect: "reject",
            error: Some("NonCanonical"),
        },
        Vector {
            name: "neg_nonminimal_varint",
            description: "MKWS selection count encoded as a two-byte non-minimal varint.",
            magic: "MKWS",
            bytes: nonminimal,
            expect: "reject",
            error: Some("NonCanonical"),
        },
        Vector {
            name: "neg_unknown_option_tag",
            description: "MKPN operation tag set to 2 (only 0/1 are defined).",
            magic: "MKPN",
            bytes: bad_tag,
            expect: "reject",
            error: Some("NonCanonical"),
        },
        Vector {
            name: "neg_unknown_status",
            description: "MKPN status byte set to 9 (only 0..=3 are defined).",
            magic: "MKPN",
            bytes: bad_status,
            expect: "reject",
            error: Some("NonCanonical"),
        },
    ]
}

fn write_all() {
    let dir = golden_dir();
    fs::create_dir_all(&dir).unwrap();
    let accepts = build_accepted();
    let vectors: Vec<Vector> = accepts
        .iter()
        .map(|v| Vector {
            name: v.name,
            description: v.description,
            magic: v.magic,
            bytes: v.bytes.clone(),
            expect: v.expect,
            error: v.error,
        })
        .chain(build_rejects(&accepts))
        .collect();
    let mut manifest = String::from("# name blake3\n");
    for vector in &vectors {
        let digest = to_hex(&hash(&vector.bytes));
        fs::write(dir.join(format!("{}.bin", vector.name)), &vector.bytes).unwrap();
        let sidecar = json!({
            "name": vector.name,
            "description": vector.description,
            "magic": vector.magic,
            "blake3": digest,
            "size": vector.bytes.len(),
            "expect": vector.expect,
            "error": vector.error,
        });
        fs::write(
            dir.join(format!("{}.json", vector.name)),
            format!("{}\n", serde_json::to_string_pretty(&sidecar).unwrap()),
        )
        .unwrap();
        writeln!(manifest, "{} {}", vector.name, digest).unwrap();
    }
    fs::write(dir.join("MANIFEST.txt"), manifest).unwrap();
}

#[test]
fn write_golden_partial_local_vectors_if_requested() {
    if writing() {
        write_all();
    }
}

/// Verify the flat-BLAKE3 checksum of a `[magic][version][payload][checksum]`
/// envelope without touching any decoder — an independent structural check
/// for the manifest/pointer vectors whose types are crate-private.
fn envelope_integrity(bytes: &[u8], magic: &[u8]) {
    assert!(bytes.len() >= 37, "envelope too short");
    assert_eq!(&bytes[..4], magic);
    assert_eq!(bytes[4], 1, "version");
    let (body, checksum) = bytes.split_at(bytes.len() - 32);
    assert_eq!(hash(body), *<&Hash>::try_from(checksum).unwrap());
}

/// Hand-parse the MKGM payload: `[generation u64][ws][st][pend tag+digest?][acc tag+digest?]`.
fn manifest_digests(bytes: &[u8]) -> (Hash, Hash, Option<Hash>, Option<Hash>) {
    let payload = &bytes[5..bytes.len() - 32];
    let ws = Hash::try_from(&payload[8..40]).unwrap();
    let st = Hash::try_from(&payload[40..72]).unwrap();
    let mut pos = 72;
    let tagged = |pos: &mut usize| {
        let present = payload[*pos] == 1;
        *pos += 1;
        if present {
            let digest = Hash::try_from(&payload[*pos..*pos + 32]).unwrap();
            *pos += 32;
            Some(digest)
        } else {
            None
        }
    };
    let pend = tagged(&mut pos);
    let acc = tagged(&mut pos);
    (ws, st, pend, acc)
}

/// Hand-parse the MKCR payload: `[generation u64][manifest digest]`.
fn current_manifest_digest(bytes: &[u8]) -> Hash {
    let payload = &bytes[5..bytes.len() - 32];
    Hash::try_from(&payload[8..40]).unwrap()
}

#[test]
fn committed_partial_local_vectors_verify() {
    if writing() {
        return;
    }
    let dir = golden_dir();
    let manifest = fs::read_to_string(dir.join("MANIFEST.txt")).unwrap();
    let mut count = 0;
    let mut members = std::collections::HashMap::<String, Vec<u8>>::default();
    for line in manifest
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        let (name, digest) = line.split_once(' ').unwrap();
        let bytes = fs::read(dir.join(format!("{name}.bin"))).unwrap();
        assert_eq!(to_hex(&hash(&bytes)), digest, "{name} digest");
        let sidecar: Value =
            serde_json::from_str(&fs::read_to_string(dir.join(format!("{name}.json"))).unwrap())
                .unwrap();
        assert_eq!(sidecar["blake3"], digest);
        assert_eq!(
            usize::try_from(sidecar["size"].as_u64().unwrap()).unwrap(),
            bytes.len()
        );
        assert_eq!(&bytes[..4], sidecar["magic"].as_str().unwrap().as_bytes());
        members.insert(name.to_owned(), bytes.clone());
        match sidecar["expect"].as_str().unwrap() {
            "accept" => {
                match sidecar["magic"].as_str().unwrap() {
                    "MKWS" => WorkspaceStateV1::decode(&bytes)
                        .map_or_else(|e| panic!("{name}: {e:?}"), |_| ()),
                    "MKST" => StageStateV1::decode(&bytes)
                        .map_or_else(|e| panic!("{name}: {e:?}"), |_| ()),
                    "MKPN" => PendingStateV1::decode(&bytes)
                        .map_or_else(|e| panic!("{name}: {e:?}"), |_| ()),
                    "MKAC" => AcceptedStateV1::decode(&bytes)
                        .map_or_else(|e| panic!("{name}: {e:?}"), |_| ()),
                    magic @ ("MKGM" | "MKCR") => envelope_integrity(&bytes, magic.as_bytes()),
                    other => panic!("{name}: unknown magic {other}"),
                }
            }
            "reject" => {
                let decode: Result<(), mkit_core::partial::PartialStateError> =
                    match sidecar["magic"].as_str().unwrap() {
                        "MKWS" => WorkspaceStateV1::decode(&bytes).map(|_| ()),
                        "MKPN" => PendingStateV1::decode(&bytes).map(|_| ()),
                        other => panic!("{name}: unknown reject magic {other}"),
                    };
                let error = decode.expect_err(name);
                let expected = sidecar["error"].as_str().unwrap();
                assert!(
                    format!("{error:?}").starts_with(expected),
                    "{name}: expected {expected}, got {error:?}"
                );
            }
            other => panic!("{name}: unknown expectation {other}"),
        }
        count += 1;
    }
    assert!(count >= 14);

    // Cross-vector digest chain: the pending manifest selects the
    // committed workspace/stage/pending members and CURRENT names it.
    let (ws_d, st_d, pn_d, ac_d) = manifest_digests(&members["manifest_v1"]);
    assert_eq!(ws_d, hash(&members["workspace_v1"]));
    assert_eq!(st_d, hash(&members["stage_v1"]));
    assert_eq!(pn_d.unwrap(), hash(&members["pending_v1"]));
    assert!(ac_d.is_none());
    assert_eq!(
        current_manifest_digest(&members["current_v1"]),
        hash(&members["manifest_v1"])
    );
    // The accepted manifest carries accepted (not pending) and its
    // CURRENT names it.
    let (_w, _s, pn, ac) = manifest_digests(&members["manifest_accepted_v1"]);
    assert!(pn.is_none());
    assert_eq!(ac.unwrap(), hash(&members["accepted_v1"]));
    assert_eq!(
        current_manifest_digest(&members["current_accepted_v1"]),
        hash(&members["manifest_accepted_v1"])
    );
}
