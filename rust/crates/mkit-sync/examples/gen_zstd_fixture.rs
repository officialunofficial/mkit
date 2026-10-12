//! Regenerates `tests/fixtures/zstd.pack`: a signed one-commit history whose
//! blob is large and repetitive enough that the pack carries a zstd entry.
//! Needs the `pack-zstd` feature (on by default).
//!
//!     cargo run -p mkit-sync --example gen_zstd_fixture
#![allow(clippy::unwrap_used)]
use mkit_core::object::{Blob, Commit, EntryMode, Identity, Object, Tree, TreeEntry};
use mkit_core::pack::PackWriter;
use mkit_core::sign::{KeyPair, sign_commit};

fn main() {
    let key = KeyPair::from_seed([0x11; 32]);
    let blob = Object::Blob(Blob {
        data: "mkit compresses repetitive text well. "
            .repeat(256)
            .into_bytes(),
    });
    let tree = Object::Tree(Tree {
        entries: vec![TreeEntry {
            name: b"big.txt".to_vec(),
            mode: EntryMode::Blob,
            object_hash: blob.id().unwrap(),
        }],
    });
    let mut commit = Commit::new_unannotated(
        tree.id().unwrap(),
        vec![],
        Identity::ed25519(key.public.0),
        key.public.0,
        b"compressed".to_vec(),
        1_700_000_000,
        [0; 64],
    );
    commit.signature = sign_commit(&commit, &key).unwrap().0;
    let commit = Object::Commit(commit);
    let mut writer = PackWriter::new();
    for object in [&blob, &tree, &commit] {
        writer
            .push_raw(
                object.id().unwrap(),
                &mkit_core::serialize::serialize(object).unwrap(),
            )
            .unwrap();
    }
    let pack = writer.finish().unwrap();
    std::fs::write("crates/mkit-sync/tests/fixtures/zstd.pack", &pack).unwrap();
    println!("tip {}", mkit_core::hash::to_hex(&commit.id().unwrap()));
    println!("pack bytes {}", pack.len());
}
