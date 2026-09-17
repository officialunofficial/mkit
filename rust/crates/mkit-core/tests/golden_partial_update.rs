//! Committed MKWU v1 vectors. Writing is explicitly gated; normal tests only
//! consume checked-in bytes.
#![allow(clippy::similar_names)] // signer/signed names mirror the protocol roles
#![allow(clippy::too_many_lines)] // keep each generated vector table auditable in one place
#![allow(clippy::unwrap_used)] // unwrap is the assertion in golden test helpers

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use mkit_core::object::id_from_object;
use mkit_core::pack::{PackEntries, PackEntry, PackWriter, pack_key};
use mkit_core::sign::{KeyPair, sign_commit};
use mkit_core::{
    Commit, EntryMode, FileReplacement, Hash, Identity, Object, ObjectStore, PartialError,
    PartialLimits, PartialUpdate, RepoLayout, Tree, TreeEntry, build_partial_snapshot,
    export_partial_update, prepare_partial_commit, replace_files, serialize,
    verify_partial_snapshot,
};

const VECTOR_NAMES: &[&str] = &[
    "ordinary_update",
    "neg_pack_length",
    "neg_pack_hash",
    "neg_trailing",
    "neg_duplicate_object",
    "neg_extra_object",
    "neg_delta_entry",
    "neg_compressed_entry",
    "neg_v2_raw_pack",
    "neg_candidate_annotations",
    "neg_candidate_message_limit",
    "neg_chunk_total_mismatch",
];

type Vector = (
    &'static str,
    Vec<u8>,
    bool,
    &'static str,
    Option<&'static str>,
);

fn golden_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/golden/partial_update")
}

fn put(store: &ObjectStore, object: &Object) -> Hash {
    let bytes = serialize(object).unwrap();
    let id = id_from_object(object, &bytes);
    assert_eq!(store.write(&bytes).unwrap(), id);
    id
}

fn accepted_update() -> Vec<u8> {
    accepted_update_with_content(vec![b'x'; 4096])
}

fn accepted_update_with_content(content: Vec<u8>) -> Vec<u8> {
    let dir = tempfile::tempdir().unwrap();
    let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
    let old = mkit_core::store_file_object(&store, b"old golden bytes").unwrap();
    let root = put(
        &store,
        &Object::Tree(Tree {
            entries: vec![TreeEntry {
                name: b"a.txt".to_vec(),
                mode: EntryMode::Blob,
                object_hash: old,
            }],
        }),
    );
    let base_key = KeyPair::from_seed([21; 32]);
    let mut base = Commit::new_unannotated(
        root,
        vec![],
        Identity::ed25519(base_key.public.0),
        base_key.public.0,
        b"golden base".to_vec(),
        1_700_000_000,
        [0; 64],
    );
    base.signature = sign_commit(&base, &base_key).unwrap().0;
    let base_id = put(&store, &Object::Commit(base));
    let paths = vec![vec![b"a.txt".to_vec()]];
    let limits = PartialLimits::V1;
    let bundle = build_partial_snapshot(&store, base_id, &paths, &limits).unwrap();
    let verified =
        verify_partial_snapshot(base_id, &paths, &bundle.encode(&limits).unwrap(), &limits)
            .unwrap();
    let prepared = replace_files(
        &verified,
        &[FileReplacement::bytes(paths[0].clone(), content)],
        &limits,
    )
    .unwrap();
    let signer = KeyPair::from_seed([22; 32]);
    let unsigned = prepare_partial_commit(
        &verified,
        &prepared,
        Identity::opaque(b"golden author".to_vec()),
        signer.public.0,
        b"golden partial update".to_vec(),
        1_700_000_001,
        &limits,
    )
    .unwrap();
    let mut signed = unsigned.clone();
    signed.signature = sign_commit(&signed, &signer).unwrap().0;
    export_partial_update(&verified, &prepared, &unsigned, &signed, &limits)
        .unwrap()
        .encode(&limits)
        .unwrap()
}

fn read_varint(bytes: &[u8], pos: &mut usize) -> usize {
    let mut value = 0usize;
    let mut shift = 0;
    loop {
        let byte = bytes[*pos];
        *pos += 1;
        value |= usize::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return value;
        }
        shift += 7;
    }
}

fn write_varint(out: &mut Vec<u8>, mut value: usize) {
    loop {
        let mut byte = u8::try_from(value & 0x7f).expect("seven bits fit in u8");
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            return;
        }
    }
}

fn update_layout(bytes: &[u8]) -> (usize, usize, usize, usize) {
    let mut pos = 5 + 32 + 32;
    let changes = read_varint(bytes, &mut pos);
    for _ in 0..changes {
        let components = read_varint(bytes, &mut pos);
        for _ in 0..components {
            let len = read_varint(bytes, &mut pos);
            pos += len;
        }
        pos += 1 + 32 + 32;
    }
    let hash = pos;
    let declared_len = hash + 32;
    let vec_len = declared_len + 8;
    let mut pack = vec_len;
    let _ = read_varint(bytes, &mut pack);
    (hash, declared_len, vec_len, pack)
}

fn replace_pack(update: &[u8], pack: &[u8]) -> Vec<u8> {
    let (hash, _, _, _) = update_layout(update);
    let mut out = update[..hash].to_vec();
    out.extend_from_slice(&pack_key(pack));
    out.extend_from_slice(&(pack.len() as u64).to_be_bytes());
    write_varint(&mut out, pack.len());
    out.extend_from_slice(pack);
    out
}

fn raw_entries(update: &[u8]) -> Vec<(Hash, Vec<u8>)> {
    let (_, _, _, pack) = update_layout(update);
    PackEntries::new(&update[pack..])
        .unwrap()
        .map(|entry| match entry.unwrap() {
            PackEntry::Raw { bytes } => {
                let object = mkit_core::deserialize(bytes.as_ref()).unwrap();
                (id_from_object(&object, bytes.as_ref()), bytes.into_owned())
            }
            PackEntry::Delta { .. } => unreachable!(),
        })
        .collect()
}

fn make_pack(entries: &[(Hash, Vec<u8>)]) -> Vec<u8> {
    let mut writer = PackWriter::new_raw_only();
    for (id, bytes) in entries {
        writer.push_raw(*id, bytes).unwrap();
    }
    writer.finish().unwrap()
}

fn make_compressed_pack(entries: &[(Hash, Vec<u8>)]) -> Vec<u8> {
    let mut writer = PackWriter::new();
    for (id, bytes) in entries {
        writer.push_raw(*id, bytes).unwrap();
    }
    let pack = writer.finish().unwrap();
    assert_eq!(u32::from_le_bytes(pack[4..8].try_into().unwrap()), 2);
    assert!(!PackEntries::new(&pack).unwrap().is_raw_only());
    let dir = tempfile::tempdir().unwrap();
    let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
    mkit_core::PackReader::read(&pack, &store).expect("well-formed compressed pack");
    pack
}

fn make_delta_pack(entries: &[(Hash, Vec<u8>)]) -> Vec<u8> {
    assert!(entries.len() >= 2);
    let mut pack = Vec::new();
    pack.extend_from_slice(b"MKIT");
    pack.extend_from_slice(&1u32.to_le_bytes());
    pack.extend_from_slice(&u32::try_from(entries.len()).unwrap().to_le_bytes());
    for (index, (_, bytes)) in entries.iter().enumerate() {
        if index == 1 {
            let stream = mkit_core::delta::encode(&entries[0].1, bytes).unwrap();
            let payload_len = 32usize.checked_add(stream.len()).unwrap();
            pack.push(0x02);
            pack.extend_from_slice(&u32::try_from(payload_len).unwrap().to_le_bytes());
            pack.extend_from_slice(&entries[0].0);
            pack.extend_from_slice(&stream);
        } else {
            pack.push(0x00);
            pack.extend_from_slice(&u32::try_from(bytes.len()).unwrap().to_le_bytes());
            pack.extend_from_slice(bytes);
        }
    }
    let trailer = mkit_core::hash::hash(&pack);
    pack.extend_from_slice(&trailer);
    assert!(!PackEntries::new(&pack).unwrap().is_raw_only());
    let dir = tempfile::tempdir().unwrap();
    let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
    mkit_core::PackReader::read(&pack, &store).expect("well-formed delta pack");
    pack
}

fn replace_candidate(update: &[u8], mutate: impl FnOnce(&mut Commit)) -> Vec<u8> {
    let old_id: Hash = update[37..69].try_into().unwrap();
    let mut entries = raw_entries(update);
    let (_, candidate_bytes) = entries
        .iter_mut()
        .find(|(id, _)| *id == old_id)
        .expect("candidate entry");
    let Object::Commit(mut candidate) = mkit_core::deserialize(candidate_bytes).unwrap() else {
        panic!("candidate Commit")
    };
    mutate(&mut candidate);
    *candidate_bytes = serialize(&Object::Commit(candidate.clone())).unwrap();
    let new_id = id_from_object(&Object::Commit(candidate), candidate_bytes);
    entries.iter_mut().find(|(id, _)| *id == old_id).unwrap().0 = new_id;
    entries.sort_by_key(|(id, _)| *id);
    let mut out = replace_pack(update, &make_pack(&entries));
    out[37..69].copy_from_slice(&new_id);
    out
}

fn chunk_total_mismatch_update() -> Vec<u8> {
    let update = accepted_update_with_content(vec![b'q'; 1024 * 1024 + 1]);
    let mut entries = raw_entries(&update);

    let manifest_index = entries
        .iter()
        .position(|(_, bytes)| matches!(mkit_core::deserialize(bytes), Ok(Object::ChunkedBlob(_))))
        .expect("chunked representation");
    let old_manifest_id = entries[manifest_index].0;
    let Object::ChunkedBlob(mut manifest) =
        mkit_core::deserialize(&entries[manifest_index].1).unwrap()
    else {
        unreachable!()
    };
    manifest.total_size += 1;
    let manifest_object = Object::ChunkedBlob(manifest);
    let manifest_bytes = serialize(&manifest_object).unwrap();
    let new_manifest_id = id_from_object(&manifest_object, &manifest_bytes);
    entries[manifest_index] = (new_manifest_id, manifest_bytes);

    let tree_index = entries
        .iter()
        .position(|(_, bytes)| {
            matches!(
                mkit_core::deserialize(bytes),
                Ok(Object::Tree(Tree { ref entries }))
                    if entries.iter().any(|entry| entry.object_hash == old_manifest_id)
            )
        })
        .expect("candidate root Tree");
    let old_tree_id = entries[tree_index].0;
    let Object::Tree(mut tree) = mkit_core::deserialize(&entries[tree_index].1).unwrap() else {
        unreachable!()
    };
    tree.entries
        .iter_mut()
        .find(|entry| entry.object_hash == old_manifest_id)
        .unwrap()
        .object_hash = new_manifest_id;
    let tree_object = Object::Tree(tree);
    let tree_bytes = serialize(&tree_object).unwrap();
    let new_tree_id = id_from_object(&tree_object, &tree_bytes);
    entries[tree_index] = (new_tree_id, tree_bytes);

    let commit_index = entries
        .iter()
        .position(|(_, bytes)| {
            matches!(
                mkit_core::deserialize(bytes),
                Ok(Object::Commit(Commit { tree_hash, .. })) if tree_hash == old_tree_id
            )
        })
        .expect("candidate Commit");
    let Object::Commit(mut candidate) = mkit_core::deserialize(&entries[commit_index].1).unwrap()
    else {
        unreachable!()
    };
    candidate.tree_hash = new_tree_id;
    candidate.signature = sign_commit(&candidate, &KeyPair::from_seed([22; 32]))
        .unwrap()
        .0;
    let candidate_object = Object::Commit(candidate);
    let candidate_bytes = serialize(&candidate_object).unwrap();
    let new_candidate_id = id_from_object(&candidate_object, &candidate_bytes);
    entries[commit_index] = (new_candidate_id, candidate_bytes);
    entries.sort_by_key(|(id, _)| *id);

    let mut out = replace_pack(&update, &make_pack(&entries));
    out[37..69].copy_from_slice(&new_candidate_id);
    let new_id_offset = first_change_new_id_offset(&out);
    out[new_id_offset..new_id_offset + 32].copy_from_slice(&new_manifest_id);
    out
}

fn first_change_new_id_offset(bytes: &[u8]) -> usize {
    let mut pos = 5 + 32 + 32;
    assert_eq!(read_varint(bytes, &mut pos), 1);
    let components = read_varint(bytes, &mut pos);
    for _ in 0..components {
        let len = read_varint(bytes, &mut pos);
        pos += len;
    }
    pos + 1 + 32
}

fn rehash_pack(pack: &mut [u8]) {
    let split = pack.len() - 32;
    let trailer = mkit_core::hash::hash(&pack[..split]);
    pack[split..].copy_from_slice(&trailer);
}

fn vectors() -> Vec<Vector> {
    let accept = accepted_update();
    let (_, length, _, pack_offset) = update_layout(&accept);

    let mut bad_length = accept.clone();
    let declared = u64::from_be_bytes(bad_length[length..length + 8].try_into().unwrap());
    bad_length[length..length + 8].copy_from_slice(&(declared + 1).to_be_bytes());

    let mut bad_hash = accept.clone();
    let (hash, _, _, _) = update_layout(&bad_hash);
    bad_hash[hash + 11] ^= 0x80;

    let mut trailing = accept.clone();
    trailing.push(0);

    let entries = raw_entries(&accept);
    let mut duplicate_entries = entries.clone();
    duplicate_entries.insert(1, entries[0].clone());
    let duplicate = replace_pack(&accept, &make_pack(&duplicate_entries));

    let extra_obj = Object::Blob(mkit_core::Blob {
        data: b"extra".to_vec(),
    });
    let extra_bytes = serialize(&extra_obj).unwrap();
    let extra_id = id_from_object(&extra_obj, &extra_bytes);
    let mut extra_entries = entries.clone();
    extra_entries.push((extra_id, extra_bytes));
    extra_entries.sort_by_key(|(id, _)| *id);
    let extra = replace_pack(&accept, &make_pack(&extra_entries));

    let delta = replace_pack(&accept, &make_delta_pack(&entries));
    let compressed = replace_pack(&accept, &make_compressed_pack(&entries));

    let mut v2_raw_pack = accept[pack_offset..].to_vec();
    v2_raw_pack[4..8].copy_from_slice(&2u32.to_le_bytes());
    rehash_pack(&mut v2_raw_pack);
    let v2_raw = replace_pack(&accept, &v2_raw_pack);

    let annotated = replace_candidate(&accept, |candidate| candidate.message_hash = [0x55; 32]);
    let oversized_message = replace_candidate(&accept, |candidate| {
        candidate.message = vec![b'm'; PartialLimits::V1.max_commit_message_bytes + 1];
        let signer = KeyPair::from_seed([22; 32]);
        candidate.signature = sign_commit(candidate, &signer).unwrap().0;
    });
    let chunk_total_mismatch = chunk_total_mismatch_update();

    vec![
        (
            "ordinary_update",
            accept,
            true,
            "canonical ordinary signed partial update",
            None,
        ),
        (
            "neg_pack_length",
            bad_length,
            false,
            "declared pack length mismatch",
            Some("submission_too_large"),
        ),
        (
            "neg_pack_hash",
            bad_hash,
            false,
            "outer pack identity mismatch",
            Some("invalid_update_pack"),
        ),
        (
            "neg_trailing",
            trailing,
            false,
            "trailing update byte",
            Some("submission_too_large"),
        ),
        (
            "neg_duplicate_object",
            duplicate,
            false,
            "duplicate raw object id",
            Some("invalid_update_pack"),
        ),
        (
            "neg_extra_object",
            extra,
            false,
            "object outside exact inventory",
            Some("invalid_update_pack"),
        ),
        (
            "neg_delta_entry",
            delta,
            false,
            "well-formed delta entry forbidden",
            Some("invalid_update_pack"),
        ),
        (
            "neg_compressed_entry",
            compressed,
            false,
            "well-formed compressed entry forbidden",
            Some("invalid_update_pack"),
        ),
        (
            "neg_v2_raw_pack",
            v2_raw,
            false,
            "v2 pack forbidden even when every entry is raw",
            Some("invalid_update_pack"),
        ),
        (
            "neg_candidate_annotations",
            annotated,
            false,
            "unsigned Commit annotations must remain absent",
            Some("commit_mismatch"),
        ),
        (
            "neg_candidate_message_limit",
            oversized_message,
            false,
            "candidate message exceeds the partial-update bound",
            Some("submission_too_large"),
        ),
        (
            "neg_chunk_total_mismatch",
            chunk_total_mismatch,
            false,
            "canonical signed graph has a ChunkedBlob size mismatch",
            Some("invalid_chunk_layout"),
        ),
    ]
}

#[test]
fn committed_partial_update_vectors() {
    if std::env::var_os("MKIT_WRITE_GOLDEN").as_deref() == Some(std::ffi::OsStr::new("1")) {
        return;
    }
    let limits = PartialLimits::V1;
    let dir = golden_dir();
    let manifest = fs::read_to_string(dir.join("MANIFEST.txt")).unwrap();
    let records = manifest.lines().collect::<Vec<_>>();
    assert_eq!(records.len(), VECTOR_NAMES.len());
    for (record, expected_name) in records.iter().zip(VECTOR_NAMES) {
        let (manifest_hash, file) = record.split_once("  ").expect("manifest record");
        assert_eq!(file, &format!("{expected_name}.bin"));
        let bytes = fs::read(dir.join(file)).unwrap();
        let actual_hash = hex::encode(mkit_core::hash::hash(&bytes));
        assert_eq!(manifest_hash, actual_hash);

        let sidecar: serde_json::Value =
            serde_json::from_slice(&fs::read(dir.join(format!("{expected_name}.json"))).unwrap())
                .unwrap();
        assert_eq!(sidecar["name"], *expected_name);
        assert_eq!(sidecar["bytes"], bytes.len());
        assert_eq!(sidecar["blake3"], actual_hash);
        let accept = sidecar["accept"].as_bool().expect("accept boolean");
        match (accept, PartialUpdate::decode(&bytes, &limits)) {
            (true, Ok(_)) => assert!(sidecar["expected_error"].is_null()),
            (false, Err(error)) => assert_eq!(
                sidecar["expected_error"].as_str().expect("expected error"),
                partial_error_code(&error),
                "{expected_name}"
            ),
            (true, Err(error)) => panic!("{expected_name} rejected: {error}"),
            (false, Ok(_)) => panic!("{expected_name} unexpectedly accepted"),
        }
    }
}

#[test]
fn write_partial_update_vectors_when_explicitly_enabled() {
    if std::env::var_os("MKIT_WRITE_GOLDEN").as_deref() != Some(std::ffi::OsStr::new("1")) {
        return;
    }
    let dir = golden_dir();
    fs::create_dir_all(&dir).unwrap();
    let mut manifest = String::new();
    for (name, bytes, accept, reason, expected_error) in vectors() {
        let file = format!("{name}.bin");
        fs::write(dir.join(&file), &bytes).unwrap();
        let sidecar = serde_json::json!({
            "name": name,
            "accept": accept,
            "reason": reason,
            "expected_error": expected_error,
            "bytes": bytes.len(),
            "blake3": hex::encode(mkit_core::hash::hash(&bytes)),
        });
        fs::write(
            dir.join(format!("{name}.json")),
            format!("{}\n", serde_json::to_string_pretty(&sidecar).unwrap()),
        )
        .unwrap();
        writeln!(
            manifest,
            "{}  {}",
            hex::encode(mkit_core::hash::hash(&bytes)),
            file
        )
        .expect("writing to String cannot fail");
    }
    fs::write(dir.join("MANIFEST.txt"), manifest).unwrap();
}

fn partial_error_code(error: &PartialError) -> &'static str {
    match error {
        PartialError::SubmissionTooLarge => "submission_too_large",
        PartialError::InvalidUpdatePack => "invalid_update_pack",
        PartialError::CommitMismatch => "commit_mismatch",
        PartialError::ValidationBudgetExceeded => "validation_budget_exceeded",
        PartialError::WorkspaceTooLarge => "workspace_too_large",
        PartialError::InvalidChunkLayout => "invalid_chunk_layout",
        _ => "unexpected_error",
    }
}
