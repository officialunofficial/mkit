// SPDX-License-Identifier: MIT OR Apache-2.0
//! Deterministic disposable hosted-submission fixtures for local workerd tests.
//! Usage: cargo run --manifest-path apps/vcs-worker/Cargo.toml --example
//! submission_resource_fixture -- <empty-output-directory> <small|large>.
//! Signing keys and timestamps are fixed TEST material. This generator measures
//! fixture bytes; it does not claim Worker admission success.

use std::{
    collections::BTreeMap,
    env, fs,
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
};

use mkit_core::{
    Commit, EntryMode, FileReplacement, Hash, Identity, Object, PartialLimits, PartialPath, Tree,
    TreeEntry, export_partial_update,
    hash::{hash, to_hex},
    object::{Blob, id_from_object},
    pack::{CheckedRawPack, PackWriter, RawPackLimits},
    partial::{
        PartialSnapshotBuilder, prepare_partial_commit, replace_files, verify_partial_snapshot,
    },
    serialize::{deserialize, serialize},
    sign::{KeyPair, sign_commit},
    transfer::encode_packlist,
};
use serde_json::{Value, json};

const MIB: usize = 1024 * 1024;
const LARGE_BLOB_COUNT: usize = 132;
const LARGE_BLOB_BYTES: usize = MIB;
const SMALL_BLOB_COUNT: usize = 4;
const SMALL_BLOB_BYTES: usize = 16 * 1024;
const BASE_SEED: [u8; 32] = [0x31; 32];
const SUBJECT_SEED: [u8; 32] = [0x52; 32];
const TEST_TIMESTAMP: u64 = 1_726_400_000;

#[derive(Clone)]
struct InventoryEntry {
    id: Hash,
    kind: &'static str,
    canonical_bytes: usize,
    pack_key: Hash,
}

fn write_new(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap_or_else(|error| panic!("refusing to overwrite {}: {error}", path.display()));
    file.write_all(bytes).expect("write fixture bytes");
    file.sync_all().expect("sync fixture bytes");
}

fn write_pack(
    directory: &Path,
    objects: &[(Hash, Vec<u8>, &'static str)],
) -> (Hash, Vec<InventoryEntry>) {
    let mut writer = PackWriter::new_raw_only();
    for (id, bytes, _) in objects {
        writer.push_raw(*id, bytes).expect("raw canonical object");
    }
    let bytes = writer.finish().expect("raw-v1 pack");
    assert!(bytes.len() <= 4 * MIB, "ordinary pack exceeds 4 MiB");
    let key = hash(&bytes);
    write_new(&directory.join(format!("{}.pack", to_hex(&key))), &bytes);
    let entries = objects
        .iter()
        .map(|(id, bytes, kind)| InventoryEntry {
            id: *id,
            kind,
            canonical_bytes: bytes.len(),
            pack_key: key,
        })
        .collect();
    (key, entries)
}

fn deterministic_blob(index: usize, size: usize) -> Vec<u8> {
    // Distinct deterministic TEST byte streams; never repeat a payload across paths.
    let mut bytes = vec![0; size];
    let mut state = (index as u64 + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    for chunk in bytes.chunks_mut(8) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        chunk.copy_from_slice(&state.to_le_bytes()[..chunk.len()]);
    }
    bytes
}

fn canonical_object(object: &Object) -> (Hash, Vec<u8>, &'static str) {
    let kind = match object {
        Object::Blob(_) => "Blob",
        Object::Tree(_) => "Tree",
        Object::Commit(_) => "Commit",
        _ => panic!("unsupported fixture object kind"),
    };
    let bytes = serialize(object).expect("canonical object encoding");
    let id = id_from_object(object, &bytes);
    (id, bytes, kind)
}

fn test_only_directory(path: &Path) {
    if path.exists() {
        assert!(
            fs::read_dir(path)
                .expect("inspect output directory")
                .next()
                .is_none(),
            "output directory must be empty"
        );
    } else {
        fs::create_dir_all(path).expect("create explicit output directory");
    }
}

fn build_base(
    directory: &Path,
    mode: &str,
) -> (
    Hash,
    Hash,
    Vec<Hash>,
    Vec<InventoryEntry>,
    u64,
    BTreeMap<Hash, Vec<u8>>,
) {
    let (blob_count, blob_size) = match mode {
        "small" => (SMALL_BLOB_COUNT, SMALL_BLOB_BYTES),
        "large" => (LARGE_BLOB_COUNT, LARGE_BLOB_BYTES),
        _ => panic!("mode must be small or large"),
    };
    let base_key = KeyPair::from_seed(BASE_SEED);
    let mut tree_entries = Vec::with_capacity(blob_count + 1);
    let mut pack_keys = Vec::new();
    let mut inventory = Vec::new();
    let mut selected_source = BTreeMap::new();
    let mut group: Vec<(Hash, Vec<u8>, &'static str)> = Vec::with_capacity(3);

    for index in 0..blob_count {
        let (id, bytes, kind) = canonical_object(&Object::Blob(Blob {
            data: deterministic_blob(index, blob_size),
        }));
        tree_entries.push(TreeEntry {
            name: format!("hidden-{index:04}.bin").into_bytes(),
            mode: EntryMode::Blob,
            object_hash: id,
        });
        group.push((id, bytes, kind));
        if group.len() == 3 || index + 1 == blob_count {
            let (pack_key, mut packed) = write_pack(directory, &group);
            pack_keys.push(pack_key);
            inventory.append(&mut packed);
            group.clear();
        }
    }

    let selected_path = vec![b"selected.txt".to_vec()];
    let (selected_id, selected_bytes, selected_kind) = canonical_object(&Object::Blob(Blob {
        data: b"original selected content\n".to_vec(),
    }));
    tree_entries.push(TreeEntry {
        name: selected_path[0].clone(),
        mode: EntryMode::Blob,
        object_hash: selected_id,
    });
    selected_source.insert(selected_id, selected_bytes.clone());
    let (pack_key, mut packed) = write_pack(
        directory,
        &[(selected_id, selected_bytes.clone(), selected_kind)],
    );
    pack_keys.push(pack_key);
    inventory.append(&mut packed);

    let (tree_id, tree_bytes, tree_kind) = canonical_object(&Object::Tree(Tree {
        entries: tree_entries,
    }));
    selected_source.insert(tree_id, tree_bytes.clone());
    let mut commit = Commit::new_unannotated(
        tree_id,
        Vec::new(),
        Identity::ed25519(base_key.public.0),
        base_key.public.0,
        b"TEST hosted-submission resource base".to_vec(),
        TEST_TIMESTAMP,
        [0; 64],
    );
    commit.signature = sign_commit(&commit, &base_key)
        .expect("TEST base signature")
        .0;
    let (base_root, commit_bytes, commit_kind) = canonical_object(&Object::Commit(commit));
    selected_source.insert(base_root, commit_bytes.clone());
    let (pack_key, mut packed) = write_pack(
        directory,
        &[
            (tree_id, tree_bytes, tree_kind),
            (base_root, commit_bytes, commit_kind),
        ],
    );
    pack_keys.push(pack_key);
    inventory.append(&mut packed);

    pack_keys.sort();
    pack_keys.dedup();
    assert!(pack_keys.len() <= 128, "C1 pack selection must stay <=128");
    let tip_bytes = encode_packlist(None, &pack_keys).expect("ordinary MKPL tip");
    let base_tip = hash(&tip_bytes);
    write_new(
        &directory.join(format!("{}.pack", to_hex(&base_tip))),
        &tip_bytes,
    );
    let mut unique_by_id = BTreeMap::new();
    for entry in &inventory {
        if let Some(prior) = unique_by_id.insert(entry.id, entry.canonical_bytes) {
            assert_eq!(
                prior, entry.canonical_bytes,
                "one object ID has one canonical size"
            );
        }
    }
    assert_eq!(
        unique_by_id.len(),
        inventory.len(),
        "fixture object IDs are distinct"
    );
    let total: u64 = unique_by_id.values().map(|size| *size as u64).sum();
    if mode == "large" {
        assert!(
            total > 128 * MIB as u64,
            "large base must exceed 128 MiB distinct canonical bytes"
        );
    }
    assert_eq!(inventory.len(), blob_count + 3);
    (
        base_root,
        base_tip,
        pack_keys,
        inventory,
        total,
        selected_source,
    )
}

fn make_update(
    base_root: Hash,
    source_objects: &BTreeMap<Hash, Vec<u8>>,
) -> (
    Vec<u8>,
    Hash,
    Vec<InventoryEntry>,
    usize,
    Vec<PartialPath>,
    KeyPair,
) {
    let paths = vec![vec![b"selected.txt".to_vec()]];
    let limits = PartialLimits::V1;
    let mut builder =
        PartialSnapshotBuilder::new(base_root, &paths, &limits).expect("valid TEST selection");
    while let Some(request) = builder.next_request() {
        let bytes = source_objects
            .get(&request.id())
            .unwrap_or_else(|| {
                panic!(
                    "selected-only producer requested unretained hidden object {}",
                    to_hex(&request.id())
                )
            })
            .clone();
        builder = builder
            .supply(bytes)
            .expect("real authenticated partial materialization");
    }
    let bundle = builder.finish().expect("complete selected snapshot");
    let bundle_bytes = bundle.encode(&limits).expect("canonical MKWB");
    let verified = verify_partial_snapshot(base_root, &paths, &bundle_bytes, &limits)
        .expect("real partial snapshot verifier");
    let replacement = b"TEST agent-authenticated hosted edit\n".to_vec();
    assert!(replacement.len() <= 256 * 1024);
    let prepared = replace_files(
        &verified,
        &[FileReplacement::bytes(
            paths[0].clone(),
            replacement.clone(),
        )],
        &limits,
    )
    .expect("selected replacement");
    let subject = KeyPair::from_seed(SUBJECT_SEED);
    let unsigned = prepare_partial_commit(
        &verified,
        &prepared,
        Identity::ed25519(subject.public.0),
        subject.public.0,
        b"TEST agent-signed hosted submission".to_vec(),
        TEST_TIMESTAMP + 1,
        &limits,
    )
    .expect("ordinary one-parent candidate commit");
    let mut signed = unsigned.clone();
    signed.signature = sign_commit(&signed, &subject)
        .expect("TEST agent signature")
        .0;
    let update = export_partial_update(&verified, &prepared, &unsigned, &signed, &limits)
        .expect("ordinary partial update");
    assert_eq!(*update.base_id(), base_root);
    let candidate_root = *update.candidate_id();
    let update_bytes = update.encode(&limits).expect("canonical MKWU");
    assert!(update_bytes.len() <= 4 * MIB, "host MKWU cap");
    assert!(update.pack_bytes().len() <= 3 * MIB, "host raw-pack cap");
    let supplied_pack_bytes = update.pack_bytes().len();

    let (blob_id, _, blob_kind) = canonical_object(&Object::Blob(Blob { data: replacement }));
    let mut expected_supplied_inventory: Vec<InventoryEntry> = prepared
        .produced_objects()
        .map(|(id, bytes)| InventoryEntry {
            id: *id,
            kind: if *id == blob_id { blob_kind } else { "Tree" },
            canonical_bytes: bytes.len(),
            pack_key: *update.pack_hash(),
        })
        .collect();
    let (commit_id, commit_bytes, commit_kind) = canonical_object(&Object::Commit(signed));
    assert_eq!(commit_id, candidate_root);
    expected_supplied_inventory.push(InventoryEntry {
        id: commit_id,
        kind: commit_kind,
        canonical_bytes: commit_bytes.len(),
        pack_key: *update.pack_hash(),
    });
    assert!(
        expected_supplied_inventory
            .iter()
            .any(|entry| entry.id == blob_id)
    );
    let expected_ids: BTreeMap<_, _> = expected_supplied_inventory
        .iter()
        .map(|entry| (entry.id, (entry.canonical_bytes, entry.kind)))
        .collect();
    assert_eq!(
        expected_ids.len(),
        expected_supplied_inventory.len(),
        "expected supplied inventory is unique"
    );

    // Independently enumerate the exact embedded raw-v1 pack with core's
    // checked reader. These are supplied/update objects, not the full
    // candidate Snapshot closure (which also inherits hidden base Blobs).
    let checked = CheckedRawPack::open(
        update.pack_bytes(),
        *update.pack_hash(),
        RawPackLimits {
            max_pack_bytes: 3 * MIB,
            max_entries: 2_048,
            max_entry_bytes: 2 * MIB,
            max_payload_bytes: (3 * MIB) as u64,
        },
    )
    .expect("exact supplied pack framing, key, and raw-v1 profile");
    let supplied_inventory: Vec<InventoryEntry> = checked
        .entries()
        .map(|entry| {
            let payload = entry.payload();
            let object: Object = deserialize(payload).expect("canonical supplied object");
            let (id, canonical, kind) = canonical_object(&object);
            assert_eq!(
                canonical.as_slice(),
                payload,
                "canonical supplied object bytes"
            );
            InventoryEntry {
                id,
                kind,
                canonical_bytes: payload.len(),
                pack_key: *update.pack_hash(),
            }
        })
        .collect();
    let actual_ids: BTreeMap<_, _> = supplied_inventory
        .iter()
        .map(|entry| (entry.id, (entry.canonical_bytes, entry.kind)))
        .collect();
    assert_eq!(
        actual_ids.len(),
        supplied_inventory.len(),
        "supplied IDs are unique"
    );
    assert_eq!(actual_ids, expected_ids, "exact supplied update inventory");
    assert_eq!(checked.entry_count() as usize, supplied_inventory.len());
    (
        update_bytes,
        candidate_root,
        supplied_inventory,
        supplied_pack_bytes,
        paths,
        subject,
    )
}

fn inventory_json(inventory: &[InventoryEntry]) -> Vec<Value> {
    let mut entries: Vec<_> = inventory
        .iter()
        .map(|entry| {
            json!({
                "id": to_hex(&entry.id),
                "type": entry.kind,
                "canonical_bytes": entry.canonical_bytes,
                "pack_key": to_hex(&entry.pack_key),
            })
        })
        .collect();
    entries.sort_by(|left, right| left["id"].as_str().cmp(&right["id"].as_str()));
    entries
}

fn main() {
    let args: Vec<String> = env::args().collect();
    assert_eq!(
        args.len(),
        3,
        "explicit output directory and small|large mode required"
    );
    let directory = PathBuf::from(&args[1]);
    let mode = args[2].as_str();
    assert!(matches!(mode, "small" | "large"), "unknown fixture mode");
    test_only_directory(&directory);

    let (
        base_root,
        base_tip,
        selected_pack_keys,
        base_inventory,
        base_unique_canonical_bytes,
        source_objects,
    ) = build_base(&directory, mode);
    let (
        update_bytes,
        candidate_root,
        supplied_inventory,
        supplied_pack_bytes,
        selected_paths,
        subject,
    ) = make_update(base_root, &source_objects);
    let update_digest = hash(&update_bytes);
    write_new(&directory.join("update.mkwu"), &update_bytes);

    let pack_file_map: BTreeMap<String, String> = selected_pack_keys
        .iter()
        .map(|key| (to_hex(key), format!("{}.pack", to_hex(key))))
        .chain(std::iter::once((
            to_hex(&base_tip),
            format!("{}.pack", to_hex(&base_tip)),
        )))
        .collect();
    let supplied_inventory = inventory_json(&supplied_inventory);
    let base_inventory = inventory_json(&base_inventory);
    let supplied_unique_canonical_bytes = supplied_inventory
        .iter()
        .map(|entry| entry["canonical_bytes"].as_u64().unwrap_or_default())
        .sum::<u64>();
    let embedded_pack_key = supplied_inventory
        .first()
        .and_then(|entry| entry["pack_key"].as_str())
        .expect("supplied inventory pack key");
    let manifest = json!({
        "mode": mode,
        "base_root": to_hex(&base_root),
        "base_tip": to_hex(&base_tip),
        "selected_pack_keys": selected_pack_keys.iter().map(to_hex).collect::<Vec<_>>(),
        "base_unique_canonical_bytes": base_unique_canonical_bytes,
        "candidate_root": to_hex(&candidate_root),
        "update_file": "update.mkwu",
        "update_digest": to_hex(&update_digest),
        "update_len": update_bytes.len(),
        "embedded_pack_key": embedded_pack_key,
        "selected_paths": selected_paths.iter().map(|path| path.iter()
            .map(|part| String::from_utf8(part.clone()).expect("UTF-8 path"))
            .collect::<Vec<_>>()).collect::<Vec<_>>(),
        "subject_seed_hex": hex::encode(SUBJECT_SEED),
        "subject_public_key": to_hex(&subject.public.0),
        "expected_validation": "validated",
        "base_object_count": base_inventory.len(),
        "base_pack_count": selected_pack_keys.len(),
        "base_inventory": base_inventory,
        "supplied_object_count": supplied_inventory.len(),
        "supplied_inventory": supplied_inventory,
        "supplied_pack_bytes": supplied_pack_bytes,
        "supplied_unique_canonical_bytes": supplied_unique_canonical_bytes,
        "output_files": {
            "base_packs_and_tip": pack_file_map,
            "update": "update.mkwu",
            "manifest": "manifest.json",
        },
        "test_material": true,
    });
    write_new(
        &directory.join("manifest.json"),
        &serde_json::to_vec_pretty(&manifest).expect("manifest JSON"),
    );
    println!("{manifest}");
}
