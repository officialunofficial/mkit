//! Per-entry work-charge guard for the indexed default profile.
//!
//! The fixture matches the README sizing table: raw 4 KiB blobs under leaf
//! trees, one root tree, and three commits. `VerifyLimits::indexed()` is
//! sized from measured work on this shape; an accounting change that grows
//! the per-entry charge past the bound fails here before it fails hosts.
use super::*;

/// Upper bound on cumulative charged work per pack entry on this fixture.
///
/// Measured at 84,586 units per entry on this tree shape at 5,009 entries
/// (the charge grows slowly with index size; see the README table). The
/// bound leaves roughly 30% for accounting drift on this exact fixture.
const WORK_PER_ENTRY_BOUND: u64 = 110_000;

fn unique_blob(ordinal: u64) -> (Hash, Vec<u8>) {
    let mut data = vec![0u8; 4096];
    let mut state = 0x9E37_79B9_7F4A_7C15_u64 ^ ordinal.wrapping_mul(0x100_0000_01B3);
    for chunk in data.chunks_mut(8) {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let word = state.to_le_bytes();
        chunk.copy_from_slice(&word[..chunk.len()]);
    }
    data[..8].copy_from_slice(&ordinal.to_le_bytes());
    blob(&data)
}

/// `blobs` raw 4 KiB entries, leaf trees of at most 1000 entries, one root
/// tree, and three chained signed commits.
fn budget_pack(blobs: u64) -> Vec<u8> {
    let mut writer = PackWriter::new_raw_only();
    let mut entries = Vec::new();
    let mut leaves = Vec::new();
    for ordinal in 0..blobs {
        let (id, bytes) = unique_blob(ordinal);
        writer.push_raw(id, &bytes).unwrap();
        entries.push(TreeEntry {
            name: format!("file-{ordinal:05}").into_bytes(),
            mode: EntryMode::Blob,
            object_hash: id,
        });
        if entries.len() == 1000 {
            let (id, bytes) = canonical(&Object::Tree(Tree {
                entries: std::mem::take(&mut entries),
            }));
            writer.push_raw(id, &bytes).unwrap();
            leaves.push(id);
        }
    }
    if !entries.is_empty() {
        let (id, bytes) = canonical(&Object::Tree(Tree { entries }));
        writer.push_raw(id, &bytes).unwrap();
        leaves.push(id);
    }
    let root = if leaves.len() == 1 {
        leaves[0]
    } else {
        let (id, bytes) = canonical(&Object::Tree(Tree {
            entries: leaves
                .iter()
                .enumerate()
                .map(|(n, id)| TreeEntry {
                    name: format!("dir-{n:03}").into_bytes(),
                    mode: EntryMode::Tree,
                    object_hash: *id,
                })
                .collect(),
        }));
        writer.push_raw(id, &bytes).unwrap();
        id
    };
    let mut parents = Vec::new();
    for _ in 1..=3 {
        let (id, bytes) = signed_commit(root, parents);
        writer.push_raw(id, &bytes).unwrap();
        parents = vec![id];
    }
    writer.finish().unwrap()
}

#[test]
fn indexed_default_work_per_entry_stays_under_bound() {
    let pack = budget_pack(5_000);
    let mut host = Host::new(&pack);
    let mut machine = driver(&pack);
    let verified = host.finish(&mut machine).unwrap();
    let entries = verified.counts().entries;
    let work = machine.usage().work;
    assert!(
        work <= entries * WORK_PER_ENTRY_BOUND,
        "work {work} over {entries} entries exceeds the {WORK_PER_ENTRY_BOUND}-unit \
         per-entry bound; an accounting change inflated the per-entry charge"
    );
}
