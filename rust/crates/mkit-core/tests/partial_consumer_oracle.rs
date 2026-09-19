//! Independent recipient oracle for actual workspace-worker download artifacts.
//! See apps/workspace-worker/partial-resource.md for the opt-in local recipe.
#![allow(clippy::unwrap_used)]

use mkit_core::ClosureMode;
use mkit_core::object::Object;
use mkit_core::partial::{PartialLimits, PartialUpdate};
use mkit_core::verify::verify_closure_store;
use mkit_core::worktree::store_file_object;

mod common;

#[test]
#[ignore = "requires actual Worker/runner outputs in MKIT_PARTIAL_ORACLE_DIR"]
fn downloaded_updates_reconstruct_complete_base_and_preserve_hidden_entries() {
    let directory = std::path::PathBuf::from(
        std::env::var_os("MKIT_PARTIAL_ORACLE_DIR").expect("set MKIT_PARTIAL_ORACLE_DIR"),
    );
    for (name, replacement) in [
        ("download", b"wasm parity".as_slice()),
        ("runner", b"runner replacement".as_slice()),
    ] {
        let bytes = std::fs::read(directory.join(format!("{name}.mkwu"))).unwrap();
        // A pristine complete base, independently rebuilt by the established
        // disclosure fixture producer, not the consumer's storage or overlay.
        let fixture = common::build_fixture();
        let update = PartialUpdate::decode(&bytes, &PartialLimits::V1).unwrap();
        assert_eq!(*update.base_id(), fixture.commit_id);
        assert_eq!(
            update.changed_paths().cloned().collect::<Vec<_>>(),
            vec![vec![b"shallow.txt".to_vec()]]
        );
        mkit_core::PackReader::read(update.pack_bytes(), &fixture.store).unwrap();
        let Object::Commit(commit) = fixture.store.read_object(update.candidate_id()).unwrap()
        else {
            panic!("ordinary Commit required");
        };
        mkit_core::verify_commit(&commit).unwrap();
        assert_eq!(commit.parents, vec![fixture.commit_id]);
        // Prove completeness before the independent root oracle writes anything.
        let closure =
            verify_closure_store(&fixture.store, update.candidate_id(), ClosureMode::Snapshot)
                .unwrap();
        assert!(
            closure.is_complete(),
            "complete base + downloaded update must close"
        );
        let Object::Tree(mut expected) = fixture.store.read_object(&fixture.tree_hash).unwrap()
        else {
            panic!("base Tree required");
        };
        let replacement_id = store_file_object(&fixture.store, replacement).unwrap();
        expected
            .entries
            .iter_mut()
            .find(|entry| entry.name == b"shallow.txt")
            .unwrap()
            .object_hash = replacement_id;
        let expected_bytes = mkit_core::serialize(&Object::Tree(expected)).unwrap();
        let expected_id = fixture.store.write(&expected_bytes).unwrap();
        assert_eq!(
            commit.tree_hash, expected_id,
            "all untouched triples must be preserved"
        );
    }
}
