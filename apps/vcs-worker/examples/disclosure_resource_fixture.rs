// SPDX-License-Identifier: MIT OR Apache-2.0
//! Deterministic, disposable selected-disclosure resource fixtures.
//! Usage: cargo run --example disclosure_resource_fixture -- <directory> <mode>
//! Modes: wide_exact, wide_over, nested_witness_exact,
//! nested_witness_over, shared4, shared5, manifest.

use mkit_core::{
    hash::{Hash, hash},
    object::{
        Blob, ChunkedBlob, Commit, EntryMode, Identity, Object, Tree, TreeEntry, id_from_object,
    },
    ops::graph::ClosureMode,
    pack::PackWriter,
    partial::{
        PartialError, PartialLimits, PartialPath, PartialSnapshotBuilder, verify_partial_snapshot,
    },
    serialize::serialize,
    sign::{KeyPair, sign_commit},
    transfer::encode_packlist,
    verify::verify_closure,
};
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    path::Path,
};

const MIB: usize = 1024 * 1024;

fn insert(objects: &mut BTreeMap<Hash, (String, Vec<u8>)>, object: Object) -> Hash {
    let kind = match &object {
        Object::Blob(_) => "Blob",
        Object::Tree(_) => "Tree",
        Object::ChunkedBlob(_) => "ChunkedBlob",
        Object::Commit(_) => "Commit",
        _ => unreachable!("fixture types are closed"),
    };
    let bytes = serialize(&object).expect("canonical fixture object");
    let id = id_from_object(&object, &bytes);
    if let Some((prior_kind, prior)) = objects.insert(id, (kind.to_owned(), bytes.clone())) {
        assert_eq!(prior_kind, kind);
        assert_eq!(prior, bytes);
    }
    id
}

fn selected_limits() -> PartialLimits {
    PartialLimits {
        max_bundle_bytes: 4 * MIB,
        max_witness_bytes: MIB,
        max_total_selected_bytes: MIB,
        max_selected_file_bytes: 256 * 1024,
        max_objects: 2_048,
        max_tree_visits: 2_048,
        max_base_object_bytes: 2 * MIB,
        max_tree_object_bytes: 2 * MIB,
        max_object_bytes: 2 * MIB,
        ..PartialLimits::V1
    }
}

fn path(name: &[u8]) -> PartialPath {
    vec![name.to_vec()]
}

struct Fixture {
    root: Hash,
    objects: BTreeMap<Hash, (String, Vec<u8>)>,
    paths: Vec<PartialPath>,
    witness_bytes: usize,
    content_bytes: usize,
    positions: usize,
}

fn make_fixture(mode: &str) -> Fixture {
    let mut objects = BTreeMap::new();
    let mut entries = Vec::new();
    let mut paths = Vec::new();
    let mut extra_witness_bytes = 0;
    let (witness_bytes, content_bytes, positions) = match mode {
        "wide_exact" | "wide_over" | "nested_witness_exact" | "nested_witness_over" => {
            let blob = insert(
                &mut objects,
                Object::Blob(Blob {
                    data: b"x".to_vec(),
                }),
            );
            // Tree serialization is 10 bytes of framing plus 37+name.len()
            // per entry. 3,591 names of 255 bytes land six bytes above 1 MiB;
            // shorten only the final name to target exact and one-over.
            for index in 0..3_591 {
                let suffix = if index == 3_590 {
                    if mode == "wide_exact" {
                        244
                    } else if mode == "wide_over" {
                        245
                    } else if mode == "nested_witness_exact" {
                        194
                    } else {
                        195
                    }
                } else {
                    250
                };
                let name = format!("{index:04}-{}", "x".repeat(suffix)).into_bytes();
                if index == 0 {
                    paths.push(if mode.starts_with("nested") {
                        vec![b"dir".to_vec(), name.clone()]
                    } else {
                        path(&name)
                    });
                }
                entries.push(TreeEntry {
                    name,
                    mode: EntryMode::Blob,
                    object_hash: blob,
                });
            }
            (
                if mode.ends_with("exact") {
                    MIB
                } else {
                    MIB + 1
                },
                1,
                0,
            )
        }
        "shared4" | "shared5" => {
            let data = vec![b's'; 256 * 1024];
            let blob = insert(&mut objects, Object::Blob(Blob { data }));
            let count = if mode == "shared4" { 4 } else { 5 };
            for index in 0..count {
                let name = format!("file{index}").into_bytes();
                paths.push(path(&name));
                entries.push(TreeEntry {
                    name,
                    mode: EntryMode::Blob,
                    object_hash: blob,
                });
            }
            (0, count * 256 * 1024, 0)
        }
        "manifest" => {
            let empty = insert(&mut objects, Object::Blob(Blob { data: Vec::new() }));
            let one = insert(&mut objects, Object::Blob(Blob { data: vec![b'm'] }));
            let mut chunks = vec![empty; 32_768];
            chunks[32_767] = one;
            let file = insert(
                &mut objects,
                Object::ChunkedBlob(ChunkedBlob {
                    total_size: 1,
                    chunk_size: 0,
                    chunks,
                }),
            );
            let name = b"manifest.bin".to_vec();
            paths.push(path(&name));
            entries.push(TreeEntry {
                name,
                mode: EntryMode::Blob,
                object_hash: file,
            });
            (0, 1, 32_768)
        }
        _ => panic!("unknown disclosure resource mode"),
    };
    if mode.starts_with("nested") {
        let child = insert(&mut objects, Object::Tree(Tree { entries }));
        extra_witness_bytes = objects.get(&child).expect("child Tree").1.len();
        entries = vec![TreeEntry {
            name: b"dir".to_vec(),
            mode: EntryMode::Tree,
            object_hash: child,
        }];
    }
    let tree = insert(&mut objects, Object::Tree(Tree { entries }));
    let actual_witness = objects.get(&tree).expect("tree").1.len() + extra_witness_bytes;
    if witness_bytes != 0 {
        assert_eq!(actual_witness, witness_bytes);
    }
    let key = KeyPair::from_seed([73; 32]);
    let mut commit = Commit::new_unannotated(
        tree,
        Vec::new(),
        Identity::ed25519(key.public.0),
        key.public.0,
        b"hosted disclosure resource fixture".to_vec(),
        1,
        [0; 64],
    );
    commit.signature = sign_commit(&commit, &key).expect("signed fixture root").0;
    let root = insert(&mut objects, Object::Commit(commit));
    Fixture {
        root,
        objects,
        paths,
        witness_bytes: actual_witness,
        content_bytes,
        positions,
    }
}

fn validate(
    root: Hash,
    objects: &BTreeMap<Hash, (String, Vec<u8>)>,
    paths: &[PartialPath],
    mode: &str,
) -> BTreeSet<Hash> {
    let report = verify_closure(
        &root,
        ClosureMode::Snapshot,
        objects.values().map(|(_, bytes)| bytes.as_slice()),
    )
    .expect("Snapshot closure verification");
    assert!(report.is_complete() && report.unreferenced.is_empty());
    assert_eq!(
        report.verified,
        objects.len(),
        "deduplicated union equals Snapshot"
    );
    let limits = selected_limits();
    let mut builder =
        PartialSnapshotBuilder::new(root, paths, &limits).expect("valid selected paths");
    let mut requested = BTreeSet::new();
    let outcome = loop {
        let Some(request) = builder.next_request() else {
            break builder.finish().and_then(|bundle| bundle.encode(&limits));
        };
        requested.insert(request.id());
        let bytes = objects
            .get(&request.id())
            .expect("every requested ID is in Snapshot")
            .1
            .clone();
        match builder.supply(bytes) {
            Ok(next) => builder = next,
            Err(error) => break Err(error),
        }
    };
    if matches!(
        mode,
        "wide_exact" | "nested_witness_exact" | "shared4" | "manifest"
    ) {
        let bytes = outcome.expect("positive hosted selected bundle");
        verify_partial_snapshot(root, paths, &bytes, &limits).expect("positive selected verifier");
        assert_eq!(requested, objects.keys().copied().collect());
    } else {
        let actual = outcome.expect_err("over-budget fixture must refuse");
        assert!(
            if mode == "wide_over" || mode == "nested_witness_over" {
                matches!(actual, PartialError::WitnessTooLarge)
            } else {
                matches!(actual, PartialError::WorkspaceTooLarge)
            },
            "refusal must hit intended hosted bound: {actual:?}"
        );
    }
    requested
}

fn main() {
    let args: Vec<String> = env::args().collect();
    assert_eq!(args.len(), 3, "directory and mode required");
    let directory = Path::new(&args[1]);
    let mode = args[2].as_str();
    let Fixture {
        root,
        objects,
        paths,
        witness_bytes,
        content_bytes,
        positions,
    } = make_fixture(mode);
    let positive = matches!(
        mode,
        "wide_exact" | "nested_witness_exact" | "shared4" | "manifest"
    );
    let requested = validate(root, &objects, &paths, mode);
    let mut writer = PackWriter::new_raw_only();
    for (id, (_, bytes)) in &objects {
        writer.push_raw(*id, bytes).expect("raw pack entry");
    }
    let pack = writer.finish().expect("raw-v1 pack");
    assert!(pack.len() <= 4 * MIB, "ordinary managed pack cap");
    let pack_bytes = pack.len();
    let pack_key = hash(&pack);
    let tip = encode_packlist(None, &[pack_key]).expect("ordinary MKPL tip");
    let tip_key = hash(&tip);
    fs::create_dir_all(directory).expect("temporary fixture directory");
    fs::write(
        directory.join(format!("{}.pack", hex::encode(pack_key))),
        pack,
    )
    .expect("pack file");
    fs::write(
        directory.join(format!("{}.pack", hex::encode(tip_key))),
        tip,
    )
    .expect("tip file");
    let unique_canonical_bytes: u64 = objects.values().map(|(_, bytes)| bytes.len() as u64).sum();
    // Full logical selected dependencies are all objects in these deliberately
    // minimal fixtures. An over-budget builder may stop before requesting all.
    let required_read_ids: BTreeSet<_> = objects.keys().map(hex::encode).collect();
    let observed_builder_read_ids: BTreeSet<_> = requested.iter().map(hex::encode).collect();
    let manifest = json!({
        "mode": mode,
        "root": hex::encode(root),
        "tip": hex::encode(tip_key),
        "selected": [hex::encode(pack_key)],
        "selected_paths": paths.iter().map(|path| path.iter().map(|part| String::from_utf8(part.clone()).expect("UTF-8 fixture")).collect::<Vec<_>>()).collect::<Vec<_>>(),
        "expected_status": if positive { 200 } else { 429 },
        "expected_disclosure_status": if positive { 200 } else { 429 },
        "expected_code": if positive { serde_json::Value::Null } else { json!("resource_exhausted") },
        "tested_bound": if mode.starts_with("wide") || mode.starts_with("nested") { "max_witness_bytes" } else if mode.starts_with("shared") { "max_total_selected_bytes" } else { "manifest_positions_cpu" },
        "unique_canonical_bytes": unique_canonical_bytes,
        "pack_bytes": pack_bytes,
        "witness_tree_bytes": witness_bytes,
        "selected_content_bytes": content_bytes,
        "manifest_positions": positions,
        "required_read_ids": required_read_ids,
        "observed_builder_read_ids": observed_builder_read_ids,
        "objects": objects.iter().map(|(id, (kind, bytes))| json!({"id": hex::encode(id), "type": kind, "canonical_bytes": bytes.len()})).collect::<Vec<_>>(),
        "blob_count": objects.values().filter(|(kind, _)| kind == "Blob").count(),
        "blob_bytes": objects.values().filter(|(kind, _)| kind == "Blob").map(|(_, bytes)| bytes.len() - 10).sum::<usize>(),
        "shared_content": mode.starts_with("wide") || mode.starts_with("nested") || mode.starts_with("shared"),
    });
    fs::write(
        directory.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).expect("JSON"),
    )
    .expect("manifest file");
    println!("{manifest}");
}
