//! File semantics must survive alternative valid chunk boundaries.
#![allow(clippy::unwrap_used)]
use mkit_core::{
    index,
    layout::RepoLayout,
    object::{Blob, ChunkedBlob, Object},
    serialize,
    store::ObjectStore,
};
use std::{
    fs,
    path::Path,
    process::{Command, Output},
};

fn run(root: &Path, args: &[&str]) -> Output {
    let config = tempfile::tempdir().unwrap();
    Command::new(env!("CARGO_BIN_EXE_mkit"))
        .args(args)
        .current_dir(root)
        .env("XDG_CONFIG_HOME", config.path())
        .output()
        .unwrap()
}
fn ok(root: &Path, args: &[&str]) -> Output {
    let out = run(root, args);
    assert!(
        out.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out
}
fn fixture() -> (tempfile::TempDir, mkit_core::hash::Hash) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    ok(root, &["init"]);
    ok(root, &["keygen"]);
    fs::write(root.join("a"), b"abcdef").unwrap();
    ok(root, &["add", "a"]);
    let layout = RepoLayout::single(root);
    let store = ObjectStore::open(&layout).unwrap();
    let mut chunks = Vec::new();
    for data in [b"ab".as_slice(), b"cdef".as_slice()] {
        chunks.push(
            store
                .write(
                    &serialize::serialize(&Object::Blob(Blob {
                        data: data.to_vec(),
                    }))
                    .unwrap(),
                )
                .unwrap(),
        );
    }
    let h = store
        .write(
            &serialize::serialize(&Object::ChunkedBlob(ChunkedBlob {
                total_size: 6,
                chunk_size: 0,
                chunks,
            }))
            .unwrap(),
        )
        .unwrap();
    let mut idx = index::read_index(&layout).unwrap();
    idx.entries[0].object_hash = h;
    idx.entries[0].mtime_ns = 0;
    idx.entries[0].ctime_ns = 0;
    index::write_index(&layout, &idx).unwrap();
    ok(root, &["commit", "-m", "alternative chunks"]);
    (dir, h)
}

#[test]
fn status_diff_and_restage_preserve_chunked_identity() {
    let (dir, hash) = fixture();
    let root = dir.path();
    assert!(ok(root, &["status", "--porcelain"]).stdout.is_empty());
    assert!(ok(root, &["diff"]).stdout.is_empty());
    for args in [&["add", "a"][..], &["add", "-u"], &["add", "-A"]] {
        // Invalidate stat cache to force comparison against the canonical writer.
        let layout = RepoLayout::single(root);
        let mut idx = index::read_index(&layout).unwrap();
        idx.entries[0].mtime_ns = 0;
        idx.entries[0].ctime_ns = 0;
        index::write_index(&layout, &idx).unwrap();
        ok(root, args);
        assert_eq!(
            index::read_index(&layout).unwrap().entries[0].object_hash,
            hash
        );
        assert!(ok(root, &["diff", "--staged"]).stdout.is_empty());
    }
}

#[test]
fn clean_alternative_representation_does_not_block_rm_or_restore() {
    let (dir, _) = fixture();
    ok(dir.path(), &["restore", "a"]);
    ok(dir.path(), &["rm", "a"]);
    assert!(!dir.path().join("a").exists());
}

#[test]
fn changed_bytes_still_block_rm() {
    let (dir, _) = fixture();
    fs::write(dir.path().join("a"), b"abcdeg").unwrap();
    assert!(!run(dir.path(), &["rm", "a"]).status.success());
    assert_eq!(fs::read(dir.path().join("a")).unwrap(), b"abcdeg");
}

#[cfg(unix)]
#[test]
fn mode_and_type_changes_still_block_overwrite() {
    use std::os::unix::fs::PermissionsExt;
    for command in ["rm", "restore"] {
        let (dir, _) = fixture();
        let path = dir.path().join("a");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(
            !run(dir.path(), &[command, "a"]).status.success(),
            "{command} must preserve chmod-only changes"
        );
        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink("abcdef", &path).unwrap();
        assert!(
            !run(dir.path(), &[command, "a"]).status.success(),
            "{command} must preserve a type change with identical payload"
        );
    }
}

#[test]
fn status_rename_uses_content_across_representations() {
    let (dir, old_hash) = fixture();
    let root = dir.path();
    fs::rename(root.join("a"), root.join("b")).unwrap();
    ok(root, &["add", "-A"]);
    let idx = index::read_index(&RepoLayout::single(root)).unwrap();
    let added = &idx.entries[idx.find_entry("b").unwrap()];
    assert_ne!(added.object_hash, old_hash);
    assert_eq!(
        String::from_utf8(ok(root, &["status", "--porcelain"]).stdout).unwrap(),
        "R  a -> b\n"
    );
}
