// SPDX-License-Identifier: MIT OR Apache-2.0
//! Disposable signed MKWU cases for hosted selection and origin boundaries.
//! Usage: cargo run --example submission_adversarial_fixture -- <empty-dir>
//!        <fit_exact|fit_over|missing_origin|mode_mismatch|graft_hidden|preserved_mode>

use std::{collections::BTreeMap, env, fs, fs::OpenOptions, io::Write, path::Path};

use mkit_core::{
    Commit, EntryMode, FileReplacement, Hash, Identity, Object, PartialLimits, PartialPath,
    PartialUpdate, Tree, TreeEntry, export_partial_update,
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
const BASE_SEED: [u8; 32] = [0x31; 32];
const SUBJECT_SEED: [u8; 32] = [0x52; 32];
const TIMESTAMP: u64 = 1_726_400_000;

fn write_new(path: &Path, bytes: &[u8]) {
    let mut out = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap_or_else(|e| panic!("refusing to overwrite {}: {e}", path.display()));
    out.write_all(bytes).expect("write fixture");
    out.sync_all().expect("sync fixture");
}
fn canonical(object: &Object) -> (Hash, Vec<u8>, &'static str) {
    let kind = match object {
        Object::Blob(_) => "Blob",
        Object::Tree(_) => "Tree",
        Object::Commit(_) => "Commit",
        _ => panic!("fixture kind"),
    };
    let bytes = serialize(object).expect("canonical object");
    (id_from_object(object, &bytes), bytes, kind)
}
fn pack(directory: &Path, objects: &[(Hash, Vec<u8>, &'static str)]) -> (Hash, Vec<Value>) {
    let mut writer = PackWriter::new_raw_only();
    for (id, bytes, _) in objects {
        writer.push_raw(*id, bytes).expect("raw entry");
    }
    let bytes = writer.finish().expect("raw pack");
    assert!(bytes.len() <= 4 * MIB);
    let key = hash(&bytes);
    write_new(&directory.join(format!("{}.pack", to_hex(&key))), &bytes);
    let inventory = objects
        .iter()
        .map(|(id, bytes, kind)| {
            json!({
                "id":to_hex(id),"type":kind,"canonical_bytes":bytes.len(),"pack_key":to_hex(&key),
            })
        })
        .collect();
    (key, inventory)
}
fn encode_varint(out: &mut Vec<u8>, mut value: usize) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}
fn rebuild_update_pack(
    update: &PartialUpdate,
    bytes: &[u8],
    new_pack: &[u8],
    candidate: Option<Hash>,
) -> Vec<u8> {
    let prefix = &bytes[..bytes.len() - update.pack_bytes().len()];
    let old_hash = update.pack_hash();
    let positions: Vec<_> = prefix
        .windows(32)
        .enumerate()
        .filter_map(|(i, w)| (w == old_hash).then_some(i))
        .collect();
    assert_eq!(positions.len(), 1, "one pack hash field");
    let mut rebuilt = prefix[..positions[0]].to_vec();
    if let Some(candidate) = candidate {
        rebuilt[37..69].copy_from_slice(&candidate);
    }
    rebuilt.extend_from_slice(&hash(new_pack));
    rebuilt.extend_from_slice(&(new_pack.len() as u64).to_be_bytes());
    encode_varint(&mut rebuilt, new_pack.len());
    rebuilt.extend_from_slice(new_pack);
    rebuilt
}
fn replace_raw_pack(update: &PartialUpdate, bytes: &[u8], omit: Hash) -> Vec<u8> {
    let checked = CheckedRawPack::open(
        update.pack_bytes(),
        *update.pack_hash(),
        RawPackLimits {
            max_pack_bytes: 3 * MIB,
            max_entries: 2048,
            max_entry_bytes: 2 * MIB,
            max_payload_bytes: (3 * MIB) as u64,
        },
    )
    .expect("generated raw pack");
    let mut writer = PackWriter::new_raw_only();
    let mut removed = false;
    for entry in checked.entries() {
        let object: Object = deserialize(entry.payload()).expect("canonical supplied object");
        let id = id_from_object(&object, entry.payload());
        if id == omit {
            removed = true;
            continue;
        }
        writer
            .push_raw(id, entry.payload())
            .expect("remaining raw object");
    }
    assert!(removed, "changed object was supplied before omission");
    let new_pack = writer.finish().expect("shortened raw pack");
    rebuild_update_pack(update, bytes, &new_pack, None)
}

fn main() {
    let args: Vec<_> = env::args().collect();
    assert_eq!(args.len(), 3, "directory and mode required");
    let directory = Path::new(&args[1]);
    let mode = args[2].as_str();
    assert!(matches!(
        mode,
        "fit_exact"
            | "fit_over"
            | "missing_origin"
            | "mode_mismatch"
            | "graft_hidden"
            | "preserved_mode"
    ));
    if directory.exists() {
        assert!(
            fs::read_dir(directory).expect("directory").next().is_none(),
            "output must be empty"
        );
    } else {
        fs::create_dir_all(directory).expect("output directory");
    }
    let replacement = if mode == "fit_over" {
        b"edits".to_vec()
    } else {
        b"edit".to_vec()
    };
    let base_key = KeyPair::from_seed(BASE_SEED);
    let subject = KeyPair::from_seed(SUBJECT_SEED);
    let mut entries = Vec::new();
    let mut base_blobs = Vec::new();
    let mut source = BTreeMap::new();
    let mut paths: Vec<PartialPath> = Vec::new();
    for index in 0..4 {
        let name = format!("file{index}.bin").into_bytes();
        let content = vec![index as u8 + 1; 256 * 1024 - 1];
        let (id, bytes, kind) = canonical(&Object::Blob(Blob { data: content }));
        entries.push(TreeEntry {
            name: name.clone(),
            mode: EntryMode::Blob,
            object_hash: id,
        });
        paths.push(vec![name]);
        source.insert(id, bytes.clone());
        base_blobs.push((id, bytes, kind));
    }
    // The new file hash already exists in an unselected base path. Its
    // representation must nevertheless be supplied in the MKWU raw pack.
    let (same_id, same_bytes, same_kind) = canonical(&Object::Blob(Blob {
        data: replacement.clone(),
    }));
    entries.push(TreeEntry {
        name: b"same-as-new.bin".to_vec(),
        mode: EntryMode::Blob,
        object_hash: same_id,
    });
    source.insert(same_id, same_bytes.clone());
    base_blobs.push((same_id, same_bytes, same_kind));
    let (old_id, old_bytes, old_kind) = canonical(&Object::Blob(Blob {
        data: b"old".to_vec(),
    }));
    entries.push(TreeEntry {
        name: b"selected.txt".to_vec(),
        mode: EntryMode::Blob,
        object_hash: old_id,
    });
    paths.push(vec![b"selected.txt".to_vec()]);
    source.insert(old_id, old_bytes.clone());
    base_blobs.push((old_id, old_bytes, old_kind));
    if mode == "graft_hidden" {
        paths.remove(0);
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    let (blob_pack, mut base_inventory) = pack(directory, &base_blobs);
    let (tree_id, tree_bytes, tree_kind) = canonical(&Object::Tree(Tree { entries }));
    source.insert(tree_id, tree_bytes.clone());
    let mut commit = Commit::new_unannotated(
        tree_id,
        Vec::new(),
        Identity::ed25519(base_key.public.0),
        base_key.public.0,
        b"TEST adversarial base".to_vec(),
        TIMESTAMP,
        [0; 64],
    );
    commit.signature = sign_commit(&commit, &base_key).expect("base signature").0;
    let (base_root, commit_bytes, commit_kind) = canonical(&Object::Commit(commit));
    source.insert(base_root, commit_bytes.clone());
    let (root_pack, mut root_inventory) = pack(
        directory,
        &[
            (tree_id, tree_bytes, tree_kind),
            (base_root, commit_bytes, commit_kind),
        ],
    );
    base_inventory.append(&mut root_inventory);
    let mut selected_pack_keys = vec![blob_pack, root_pack];
    selected_pack_keys.sort();
    let tip_bytes = encode_packlist(None, &selected_pack_keys).expect("MKPL tip");
    let tip = hash(&tip_bytes);
    write_new(
        &directory.join(format!("{}.pack", to_hex(&tip))),
        &tip_bytes,
    );
    let limits = PartialLimits::V1;
    let mut builder = PartialSnapshotBuilder::new(base_root, &paths, &limits).expect("selection");
    while let Some(request) = builder.next_request() {
        let requested_id = request.id();
        let canonical = source.get(&requested_id).expect("selected source").clone();
        builder = builder.supply(canonical).expect("materialize");
    }
    let bundle = builder.finish().expect("complete bundle");
    let encoded = bundle.encode(&limits).expect("encode bundle");
    let verified = verify_partial_snapshot(base_root, &paths, &encoded, &limits)
        .expect("verify selected base");
    let prepared = replace_files(
        &verified,
        &[FileReplacement::bytes(
            vec![b"selected.txt".to_vec()],
            replacement,
        )],
        &limits,
    )
    .expect("replacement");
    let unsigned = prepare_partial_commit(
        &verified,
        &prepared,
        Identity::ed25519(subject.public.0),
        subject.public.0,
        b"TEST adversarial update".to_vec(),
        TIMESTAMP + 1,
        &limits,
    )
    .expect("candidate");
    let mut signed = unsigned.clone();
    signed.signature = sign_commit(&signed, &subject).expect("subject signature").0;
    let update = export_partial_update(&verified, &prepared, &unsigned, &signed, &limits)
        .expect("portable update");
    let mut update_bytes = update.encode(&limits).expect("MKWU");
    let mut candidate_root = *update.candidate_id();
    if mode == "missing_origin" {
        update_bytes = replace_raw_pack(&update, &update_bytes, same_id);
    }
    if mode == "graft_hidden" || mode == "preserved_mode" {
        let (old_tree_id, old_tree_bytes) = prepared
            .produced_objects()
            .find(|(_, bytes)| matches!(deserialize(bytes), Ok(Object::Tree(_))))
            .map(|(id, bytes)| (*id, bytes.to_vec()))
            .expect("produced root Tree");
        let Object::Tree(mut tree) = deserialize(&old_tree_bytes).expect("produced Tree") else {
            unreachable!()
        };
        let entry = tree
            .entries
            .iter_mut()
            .find(|entry| entry.name == b"file0.bin")
            .expect("hidden entry");
        if mode == "graft_hidden" {
            entry.object_hash = base_blobs[1].0; // Existing base-only origin, undeclared path.
        } else {
            entry.mode = EntryMode::Executable; // No declared change record for this preserved mode.
        }
        let (new_tree_id, new_tree_bytes, _) = canonical(&Object::Tree(tree));
        let mut graft_commit = signed.clone();
        graft_commit.tree_hash = new_tree_id;
        graft_commit.signature = sign_commit(&graft_commit, &subject)
            .expect("graft signature")
            .0;
        let (new_commit_id, new_commit_bytes, _) = canonical(&Object::Commit(graft_commit));
        candidate_root = new_commit_id;
        let checked = CheckedRawPack::open(
            update.pack_bytes(),
            *update.pack_hash(),
            RawPackLimits {
                max_pack_bytes: 3 * MIB,
                max_entries: 2048,
                max_entry_bytes: 2 * MIB,
                max_payload_bytes: (3 * MIB) as u64,
            },
        )
        .expect("generated raw pack");
        let mut replacement_inventory = BTreeMap::new();
        for raw in checked.entries() {
            let object: Object = deserialize(raw.payload()).expect("supplied object");
            let id = id_from_object(&object, raw.payload());
            if id != old_tree_id && id != *update.candidate_id() {
                replacement_inventory.insert(id, raw.payload().to_vec());
            }
        }
        replacement_inventory.insert(new_tree_id, new_tree_bytes);
        replacement_inventory.insert(new_commit_id, new_commit_bytes);
        let mut writer = PackWriter::new_raw_only();
        for (id, bytes) in replacement_inventory {
            writer.push_raw(id, &bytes).expect("replacement raw object");
        }
        let new_pack = writer.finish().expect("grafted raw pack");
        update_bytes = rebuild_update_pack(&update, &update_bytes, &new_pack, Some(new_commit_id));
    }
    if mode == "mode_mismatch" {
        let needle = b"selected.txt";
        let positions: Vec<_> = update_bytes
            .windows(needle.len())
            .enumerate()
            .filter_map(|(i, w)| (w == needle).then_some(i))
            .collect();
        assert_eq!(positions.len(), 2, "declared path and candidate Tree entry");
        let mode_offset = positions[0] + needle.len();
        assert_eq!(update_bytes[mode_offset], EntryMode::Blob as u8);
        update_bytes[mode_offset] = EntryMode::Tree as u8;
    }
    assert!(update_bytes.len() <= 4 * MIB);
    if mode.starts_with("fit_") || mode == "graft_hidden" || mode == "preserved_mode" {
        PartialUpdate::decode(&update_bytes, &limits)
            .unwrap_or_else(|error| panic!("portable {mode} intake: {error:?}"));
    } else {
        assert!(
            PartialUpdate::decode(&update_bytes, &limits).is_err(),
            "negative MKWU must fail portable intake"
        );
    }
    write_new(&directory.join("update.mkwu"), &update_bytes);
    let selected_paths: Vec<Value> = paths
        .iter()
        .map(|path| {
            json!(
                path.iter()
                    .map(|p| String::from_utf8(p.clone()).expect("UTF-8"))
                    .collect::<Vec<_>>()
            )
        })
        .collect();
    let expected_status = if mode == "fit_exact" {
        "validated"
    } else {
        "refused"
    };
    let expected_code = if mode == "fit_over" {
        "resource_exhausted"
    } else if matches!(mode, "missing_origin" | "graft_hidden" | "preserved_mode") {
        "invalid_candidate"
    } else {
        "unsupported_profile"
    };
    let base_object_count = base_inventory.len();
    let base_unique_canonical_bytes = base_inventory
        .iter()
        .map(|v| v["canonical_bytes"].as_u64().unwrap())
        .sum::<u64>();
    let manifest = json!({
        "mode":mode,"test_material":true,"base_root":to_hex(&base_root),"base_tip":to_hex(&tip),
        "selected_pack_keys":selected_pack_keys.iter().map(to_hex).collect::<Vec<_>>(),
        "base_inventory":base_inventory,"base_object_count":base_object_count,
        "base_unique_canonical_bytes":base_unique_canonical_bytes,
        "candidate_root":to_hex(&candidate_root),"update_file":"update.mkwu",
        "update_digest":to_hex(&hash(&update_bytes)),"update_len":update_bytes.len(),
        "selected_paths":selected_paths,"subject_seed_hex":hex::encode(SUBJECT_SEED),
        "subject_public_key":to_hex(&subject.public.0),"expected_validation":expected_status,
        "expected_code":expected_code,"hidden_equal_supplied_id":to_hex(&same_id),
        "selected_post_edit_bytes":4*(256*1024-1)+if mode=="fit_over" {5}else{4},
        "output_files":{"base_packs_and_tip":selected_pack_keys.iter().chain(std::iter::once(&tip)).map(|key|(to_hex(key),format!("{}.pack",to_hex(key)))).collect::<BTreeMap<_,_>>(),"update":"update.mkwu","manifest":"manifest.json"},
    });
    write_new(
        &directory.join("manifest.json"),
        &serde_json::to_vec_pretty(&manifest).expect("manifest"),
    );
    println!("{manifest}");
}
