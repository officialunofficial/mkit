// SPDX-License-Identifier: MIT OR Apache-2.0
//! Deterministic, throwaway raw-v1 Snapshot fixture for local workerd tests.
//! Usage: cargo run --example snapshot_fixture -- <directory> <blob_count> <blob_bytes>

use mkit_core::{
    hash::{Hash, hash},
    object::{Blob, Commit, EntryMode, Identity, Object, Tree, TreeEntry, id_from_object},
    pack::PackWriter,
    serialize::serialize,
    sign::{KeyPair, sign_commit},
    transfer::encode_packlist,
};
use serde_json::json;
use std::{env, fs, path::Path};

fn encoded(object: &Object) -> (Hash, Vec<u8>) {
    let bytes = serialize(object).expect("canonical fixture object");
    (id_from_object(object, &bytes), bytes)
}

fn pack(objects: &[(Hash, Vec<u8>)]) -> Vec<u8> {
    let mut writer = PackWriter::new_raw_only();
    for (id, bytes) in objects {
        writer.push_raw(*id, bytes).expect("raw fixture entry");
    }
    writer.finish().expect("raw fixture pack")
}

fn main() {
    let args: Vec<String> = env::args().collect();
    assert!(
        args.len() == 4 || (args.len() == 5 && args[4] == "--unsupported-pack"),
        "directory, blob_count, blob_bytes, optional --unsupported-pack required"
    );
    let directory = Path::new(&args[1]);
    let count: usize = args[2].parse().expect("count");
    let size: usize = args[3].parse().expect("size");
    let unsupported = args.len() == 5;
    assert!((1..=126).contains(&count) && (1..=2 * 1024 * 1024 - 10).contains(&size));
    fs::create_dir_all(directory).expect("temporary fixture directory");
    let mut packs = Vec::new();
    let mut entries = Vec::new();
    let mut unique_canonical_bytes = 0u64;
    for index in 0..count {
        // Each object has a distinct deterministic byte stream, not copies
        // of one repeated blob dressed up as a large repository.
        let mut data = vec![0u8; size];
        let mut state = (index as u64 + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15);
        for chunk in data.chunks_mut(8) {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            chunk.copy_from_slice(&state.to_le_bytes()[..chunk.len()]);
        }
        let (id, bytes) = encoded(&Object::Blob(Blob { data }));
        unique_canonical_bytes += bytes.len() as u64;
        let mut payload = pack(&[(id, bytes)]);
        if unsupported && index == 0 {
            // A correctly framed v2/non-raw pack, not damaged R2 bytes.
            // The hosted initial profile deliberately excludes this carrier.
            payload[4..8].copy_from_slice(&2u32.to_le_bytes());
            payload[12] = 3;
            let trailer = payload.len() - 32;
            let digest = hash(&payload[..trailer]);
            payload[trailer..].copy_from_slice(&digest);
        }
        let key = hash(&payload);
        fs::write(
            directory.join(format!("{}.pack", hex::encode(key))),
            payload,
        )
        .expect("pack file");
        packs.push(key);
        entries.push(TreeEntry {
            name: format!("file{index:04}").into_bytes(),
            mode: EntryMode::Blob,
            object_hash: id,
        });
    }
    // A tiny ordinary file makes the large hidden corpus usable by later
    // private selected-read/edit fixtures without relaxing the 256 KiB file
    // cap. Its name sorts after fileNNNN.
    let editable = (count >= 65).then(|| {
        encoded(&Object::Blob(Blob {
            data: b"editable hosted file\n".to_vec(),
        }))
    });
    if let Some((id, bytes)) = &editable {
        unique_canonical_bytes += bytes.len() as u64;
        entries.push(TreeEntry {
            name: b"selected.txt".to_vec(),
            mode: EntryMode::Blob,
            object_hash: *id,
        });
    }
    let (tree_id, tree_bytes) = encoded(&Object::Tree(Tree { entries }));
    let key = KeyPair::from_seed([73; 32]);
    let mut root = Commit::new_unannotated(
        tree_id,
        Vec::new(),
        Identity::ed25519(key.public.0),
        key.public.0,
        b"hosted snapshot resource fixture".to_vec(),
        1,
        [0; 64],
    );
    root.signature = sign_commit(&root, &key).expect("signed fixture root").0;
    let (root_id, root_bytes) = encoded(&Object::Commit(root));
    unique_canonical_bytes += (tree_bytes.len() + root_bytes.len()) as u64;
    let mut root_objects = Vec::new();
    if let Some(editable) = editable {
        root_objects.push(editable);
    }
    root_objects.push((tree_id, tree_bytes));
    root_objects.push((root_id, root_bytes));
    let root_pack = pack(&root_objects);
    let root_pack_key = hash(&root_pack);
    fs::write(
        directory.join(format!("{}.pack", hex::encode(root_pack_key))),
        root_pack,
    )
    .expect("root pack");
    packs.push(root_pack_key);
    let tip = encode_packlist(None, &packs).expect("packmap tip");
    let tip_key = hash(&tip);
    fs::write(
        directory.join(format!("{}.pack", hex::encode(tip_key))),
        tip,
    )
    .expect("tip");
    let mut selected: Vec<_> = packs.iter().map(hex::encode).collect();
    selected.sort();
    let manifest = json!({
        "root": hex::encode(root_id), "tip": hex::encode(tip_key),
        "selected": selected, "unique_canonical_bytes": unique_canonical_bytes,
        "blob_count": count, "blob_bytes": size,
        "editable_path": if count >= 65 { Some("selected.txt") } else { None },
        "unsupported_profile": unsupported,
    });
    fs::write(
        directory.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .expect("manifest");
    println!("{}", manifest);
}
