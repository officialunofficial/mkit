//! Committed vectors for SPEC-PARTIAL-WORKSPACES `MKWB` v1 bundles.
#![allow(clippy::unwrap_used)]

use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;

use commonware_codec::Write as CodecWrite;
use mkit_core::hash::{Hash, from_hex, hash, to_hex};
use mkit_core::object::Object;
use mkit_core::partial::{
    PartialError, PartialLimits, PartialPath, PartialSnapshotBundle, build_partial_snapshot,
    verify_partial_snapshot,
};
use serde_json::{Value, json};

mod common;

fn golden_dir() -> PathBuf {
    let mut root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.pop();
    root.pop();
    root.join("tests/golden/partial_workspace")
}

fn writing() -> bool {
    std::env::var("MKIT_WRITE_GOLDEN").is_ok()
}

fn wire_bundle(base: &Hash, paths: &[PartialPath], objects: &[(Hash, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"MKWB");
    out.push(1);
    base.write(&mut out);
    paths.len().write(&mut out);
    for path in paths {
        path.len().write(&mut out);
        for component in path {
            component.as_slice().write(&mut out);
        }
    }
    objects.len().write(&mut out);
    for (id, bytes) in objects {
        id.write(&mut out);
        bytes.as_slice().write(&mut out);
    }
    out
}

fn bundle_objects(bundle: &PartialSnapshotBundle) -> Vec<(Hash, Vec<u8>)> {
    bundle
        .objects()
        .iter()
        .map(|object| (*object.id(), object.canonical_bytes().to_vec()))
        .collect()
}

struct Vector {
    name: &'static str,
    description: &'static str,
    bytes: Vec<u8>,
    expected_base: Hash,
    expected_paths: Vec<PartialPath>,
    expect: &'static str,
    error: Option<&'static str>,
}

#[allow(clippy::too_many_lines)]
fn build_vectors() -> Vec<Vector> {
    let fixture = common::build_fixture();
    let limits = PartialLimits::default();
    let plain_paths = vec![vec![b"shallow.txt".to_vec()]];
    let chunked_paths = vec![vec![b"chunked.bin".to_vec()]];
    let shared_paths = vec![
        vec![b"exec.sh".to_vec()],
        vec![b"range.bin".to_vec()],
        vec![b"shallow.txt".to_vec()],
    ];
    let plain =
        build_partial_snapshot(&fixture.store, fixture.commit_id, &plain_paths, &limits).unwrap();
    let chunked =
        build_partial_snapshot(&fixture.store, fixture.commit_id, &chunked_paths, &limits).unwrap();
    let shared =
        build_partial_snapshot(&fixture.store, fixture.commit_id, &shared_paths, &limits).unwrap();
    let mut vectors = vec![
        Vector {
            name: "plain_file",
            description: "One inline Blob with its complete root Tree.",
            bytes: plain.encode(&limits).unwrap(),
            expected_base: fixture.commit_id,
            expected_paths: plain_paths.clone(),
            expect: "accept",
            error: None,
        },
        Vector {
            name: "chunked_file",
            description: "One ChunkedBlob with every ordered Blob chunk.",
            bytes: chunked.encode(&limits).unwrap(),
            expected_base: fixture.commit_id,
            expected_paths: chunked_paths.clone(),
            expect: "accept",
            error: None,
        },
        Vector {
            name: "shared_ancestor",
            description: "Three selected files share one deduplicated ancestor Tree.",
            bytes: shared.encode(&limits).unwrap(),
            expected_base: fixture.commit_id,
            expected_paths: shared_paths,
            expect: "accept",
            error: None,
        },
    ];

    let mut missing_chunk = bundle_objects(&chunked);
    let Object::Tree(root) = fixture.store.read_object(&fixture.tree_hash).unwrap() else {
        panic!("fixture root tree");
    };
    let chunked_id = root
        .entries
        .iter()
        .find(|entry| entry.name == b"chunked.bin")
        .unwrap()
        .object_hash;
    let Object::ChunkedBlob(manifest) = fixture.store.read_object(&chunked_id).unwrap() else {
        panic!("fixture chunked blob");
    };
    missing_chunk.retain(|(id, _)| *id != manifest.chunks[0]);
    vectors.push(Vector {
        name: "neg_missing_chunk",
        description: "The selected ChunkedBlob omits a referenced chunk.",
        bytes: wire_bundle(&fixture.commit_id, &chunked_paths, &missing_chunk),
        expected_base: fixture.commit_id,
        expected_paths: chunked_paths.clone(),
        expect: "reject",
        error: Some("InsufficientWitness"),
    });

    let mut extra = bundle_objects(&plain);
    let extra_id = root
        .entries
        .iter()
        .find(|entry| entry.name == b"range.bin")
        .unwrap()
        .object_hash;
    extra.push((extra_id, fixture.store.read(&extra_id).unwrap()));
    extra.sort_by_key(|(id, _)| *id);
    vectors.push(Vector {
        name: "neg_unsolicited_payload",
        description: "An unselected sibling payload is unsolicited.",
        bytes: wire_bundle(&fixture.commit_id, &plain_paths, &extra),
        expected_base: fixture.commit_id,
        expected_paths: plain_paths.clone(),
        expect: "reject",
        error: Some("NonCanonical"),
    });

    let mut duplicate = bundle_objects(&plain);
    duplicate.push(duplicate[0].clone());
    duplicate.sort_by_key(|(id, _)| *id);
    vectors.push(Vector {
        name: "neg_duplicate_object_id",
        description: "The objects vector repeats one id.",
        bytes: wire_bundle(&fixture.commit_id, &plain_paths, &duplicate),
        expected_base: fixture.commit_id,
        expected_paths: plain_paths.clone(),
        expect: "reject",
        error: Some("NonCanonical"),
    });

    let mut trailing = plain.encode(&limits).unwrap();
    trailing.push(0);
    vectors.push(Vector {
        name: "neg_trailing_byte",
        description: "A byte follows the declared bundle body.",
        bytes: trailing,
        expected_base: fixture.commit_id,
        expected_paths: plain_paths.clone(),
        expect: "reject",
        error: Some("NonCanonical"),
    });

    let mut nonminimal = plain.encode(&limits).unwrap();
    let path_count_offset = 5 + fixture.commit_id.len();
    assert_eq!(nonminimal[path_count_offset], 1);
    nonminimal.splice(path_count_offset..=path_count_offset, [0x81, 0x00]);
    vectors.push(Vector {
        name: "neg_nonminimal_varint",
        description: "The selected-path count uses a non-minimal varint.",
        bytes: nonminimal,
        expected_base: fixture.commit_id,
        expected_paths: plain_paths.clone(),
        expect: "reject",
        error: Some("NonCanonical"),
    });

    vectors.push(Vector {
        name: "neg_wrong_expected_base",
        description: "Valid bytes are checked against an independent wrong base.",
        bytes: plain.encode(&limits).unwrap(),
        expected_base: [0xA5; 32],
        expected_paths: plain_paths,
        expect: "reject",
        error: Some("BaseMismatch"),
    });
    vectors
}

fn path_json(paths: &[PartialPath]) -> Value {
    json!(
        paths
            .iter()
            .map(|path| path.iter().map(hex::encode).collect::<Vec<_>>())
            .collect::<Vec<_>>()
    )
}

fn write_all() {
    let dir = golden_dir();
    fs::create_dir_all(&dir).unwrap();
    let mut manifest = String::from("# name blake3\n");
    for vector in build_vectors() {
        let digest = to_hex(&hash(&vector.bytes));
        fs::write(dir.join(format!("{}.bin", vector.name)), &vector.bytes).unwrap();
        let sidecar = json!({
            "name": vector.name,
            "description": vector.description,
            "blake3": digest,
            "size": vector.bytes.len(),
            "expected_base_hex": to_hex(&vector.expected_base),
            "expected_paths_hex": path_json(&vector.expected_paths),
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
fn write_golden_partial_workspace_vectors_if_requested() {
    if writing() {
        write_all();
    }
}

fn read_paths(value: &Value) -> Vec<PartialPath> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|path| {
            path.as_array()
                .unwrap()
                .iter()
                .map(|component| hex::decode(component.as_str().unwrap()).unwrap())
                .collect()
        })
        .collect()
}

#[test]
fn committed_partial_workspace_vectors_verify() {
    if writing() {
        return;
    }
    let manifest = fs::read_to_string(golden_dir().join("MANIFEST.txt")).unwrap();
    let mut count = 0;
    for line in manifest
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        let (name, digest) = line.split_once(' ').unwrap();
        let bytes = fs::read(golden_dir().join(format!("{name}.bin"))).unwrap();
        assert_eq!(to_hex(&hash(&bytes)), digest);
        let sidecar: Value = serde_json::from_str(
            &fs::read_to_string(golden_dir().join(format!("{name}.json"))).unwrap(),
        )
        .unwrap();
        assert_eq!(sidecar["blake3"], digest);
        assert_eq!(
            usize::try_from(sidecar["size"].as_u64().unwrap()).unwrap(),
            bytes.len()
        );
        let base = from_hex(sidecar["expected_base_hex"].as_str().unwrap()).unwrap();
        let paths = read_paths(&sidecar["expected_paths_hex"]);
        let result = verify_partial_snapshot(base, &paths, &bytes, &PartialLimits::default());
        match sidecar["expect"].as_str().unwrap() {
            "accept" => {
                let verified = result.unwrap_or_else(|error| panic!("{name}: {error:?}"));
                assert_eq!(verified.paths(), paths);
                assert_eq!(verified.files().len(), paths.len());
            }
            "reject" => {
                let error = result.expect_err(name);
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
    assert!(count >= 9);
}

#[allow(dead_code)]
fn _assert_error_is_public(_: PartialError) {}
