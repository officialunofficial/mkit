//! `mkit export-legacy` (#713) end-to-end against a pinned golden
//! pre-merkle repository fixture.
//!
//! The fixture under `rust/tests/golden/legacy-export/repo/` is a tiny
//! repository (one blob, a nested tree, one signed commit on `main`)
//! written using the HISTORICAL flat-BLAKE3 addressing rule (no
//! `.mkit/format` marker), reproducing what a repository built before
//! PR #414 (merkle object addressing) looks like on disk. It uses the
//! CURRENT `serialize`/id functions to build those bytes — the object
//! byte LAYOUT never changed (SPEC-MERKLE-OBJECTS §7 / SPEC-OBJECTS
//! §12), only the bytes->id function, so this reproduces genuine
//! pre-#414 bytes deterministically without needing to build a
//! historical mkit binary.
//!
//! Default mode is read-only assertion (the repo convention — see
//! `rust/crates/mkit-git-bridge/tests/golden.rs`). Set `UPDATE_GOLDEN=1`
//! to (re)write the fixture after a deliberate change to the builder
//! below.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use mkit_core::hash::{self, Hash};
use mkit_core::layout::RepoLayout;
use mkit_core::object::{Blob, Commit, EntryMode, Identity, Object, Tree, TreeEntry};
use mkit_core::sign::{self, KeyPair};
use mkit_core::store::ObjectStore;

/// Fixed author seed so the fixture's bytes (and therefore its legacy
/// flat-hash ids, pinned in `MANIFEST.txt`) are 100% reproducible.
const AUTHOR_SEED: [u8; 32] = [0x37; 32];
const FIXED_TIMESTAMP: u64 = 1_700_000_000;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("..")
}

fn golden_dir() -> PathBuf {
    repo_root().join("rust/tests/golden/legacy-export")
}

fn mkit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_mkit")
}

struct FixtureIds {
    blob: Hash,
    inner_tree: Hash,
    root_tree: Hash,
    commit: Hash,
}

/// Build the legacy (pre-merkle) fixture repository at `root`: raw
/// object files addressed by FLAT BLAKE3 (the historical rule for
/// every type, including `Tree`), no `.mkit/format` marker, a `main`
/// branch, and symbolic `HEAD`.
fn build_legacy_repo(root: &Path) -> FixtureIds {
    let objects = root.join(".mkit").join("objects");
    let flat_write = |bytes: &[u8]| -> Hash {
        let h = hash::hash(bytes);
        let hex = hash::to_hex(&h);
        let dir = objects.join(&hex[..2]);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(&hex[2..]), bytes).unwrap();
        h
    };

    let author_kp = KeyPair::from_seed(AUTHOR_SEED);

    let blob_bytes = mkit_core::serialize(&Object::Blob(Blob {
        data: b"hello legacy world\n".to_vec(),
    }))
    .unwrap();
    let blob = flat_write(&blob_bytes);

    let inner_tree_bytes = mkit_core::serialize(&Object::Tree(Tree {
        entries: vec![TreeEntry {
            name: b"file.txt".to_vec(),
            mode: EntryMode::Blob,
            object_hash: blob,
        }],
    }))
    .unwrap();
    let inner_tree = flat_write(&inner_tree_bytes);

    let root_tree_bytes = mkit_core::serialize(&Object::Tree(Tree {
        entries: vec![TreeEntry {
            name: b"subdir".to_vec(),
            mode: EntryMode::Tree,
            object_hash: inner_tree,
        }],
    }))
    .unwrap();
    let root_tree = flat_write(&root_tree_bytes);

    let mut c = Commit::new_unannotated(
        root_tree,
        vec![],
        Identity::ed25519(author_kp.public.0),
        author_kp.public.0,
        b"legacy root commit".to_vec(),
        FIXED_TIMESTAMP,
        [0u8; 64],
    );
    c.signature = sign::sign_commit(&c, &author_kp).unwrap().0;
    let commit_bytes = mkit_core::serialize(&Object::Commit(c)).unwrap();
    let commit = flat_write(&commit_bytes);

    fs::create_dir_all(root.join(".mkit/refs/heads")).unwrap();
    fs::write(
        root.join(".mkit/refs/heads/main"),
        format!("{}\n", hash::to_hex(&commit)),
    )
    .unwrap();
    fs::write(root.join(".mkit/HEAD"), "ref: refs/heads/main\n").unwrap();

    FixtureIds {
        blob,
        inner_tree,
        root_tree,
        commit,
    }
}

fn write_manifest(dir: &Path, ids: &FixtureIds) {
    let manifest = format!(
        "# issue #713 legacy-export fixture. Pre-merkle (flat-BLAKE3) repo, fixed author \
         seed [0x37;32], fixed timestamp {FIXED_TIMESTAMP}.\n\
         # Regenerate with: UPDATE_GOLDEN=1 cargo test -p mkit-cli --test export_legacy_command\n\
         blob {}\n\
         inner_tree {}\n\
         root_tree {}\n\
         commit {}\n",
        hash::to_hex(&ids.blob),
        hash::to_hex(&ids.inner_tree),
        hash::to_hex(&ids.root_tree),
        hash::to_hex(&ids.commit),
    );
    fs::write(dir.join("MANIFEST.txt"), manifest).unwrap();
}

fn read_manifest_ids(dir: &Path) -> Option<FixtureIds> {
    let text = fs::read_to_string(dir.join("MANIFEST.txt")).ok()?;
    let mut map = std::collections::HashMap::new();
    for line in text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let mut parts = line.split(' ');
        let name = parts.next()?;
        let hex = parts.next()?;
        map.insert(name.to_owned(), hash::from_hex(hex).ok()?);
    }
    Some(FixtureIds {
        blob: *map.get("blob")?,
        inner_tree: *map.get("inner_tree")?,
        root_tree: *map.get("root_tree")?,
        commit: *map.get("commit")?,
    })
}

/// Recursively copy a directory tree (fixture -> tempdir), since the
/// command must never touch the checked-in golden fixture.
fn copy_dir_all(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).unwrap();
    for entry in fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let ty = entry.file_type().unwrap();
        let dst_path = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_all(&entry.path(), &dst_path);
        } else {
            fs::copy(entry.path(), &dst_path).unwrap();
        }
    }
}

#[test]
fn golden_fixture_matches_pinned_ids() {
    let dir = golden_dir();

    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        let repo_dir = dir.join("repo");
        if repo_dir.exists() {
            fs::remove_dir_all(&repo_dir).unwrap();
        }
        fs::create_dir_all(&repo_dir).unwrap();
        let ids = build_legacy_repo(&repo_dir);
        write_manifest(&dir, &ids);
        eprintln!(
            "legacy-export golden fixture rewritten at {}",
            dir.display()
        );
        return;
    }

    let pinned = read_manifest_ids(&dir)
        .expect("golden fixture missing — run UPDATE_GOLDEN=1 once (see MANIFEST.txt)");
    // Rebuild in a scratch dir and confirm the deterministic builder
    // still reproduces the pinned ids — a drift here means the
    // "historical" byte layout accidentally changed and the checked-in
    // fixture no longer represents genuine pre-merkle bytes.
    let scratch = tempfile::tempdir().unwrap();
    let fresh = build_legacy_repo(scratch.path());
    assert_eq!(fresh.blob, pinned.blob, "blob id drift");
    assert_eq!(fresh.inner_tree, pinned.inner_tree, "inner tree id drift");
    assert_eq!(fresh.root_tree, pinned.root_tree, "root tree id drift");
    assert_eq!(fresh.commit, pinned.commit, "commit id drift");
}

#[test]
fn export_legacy_translates_pinned_fixture_to_current_format() {
    let pinned = read_manifest_ids(&golden_dir())
        .expect("golden fixture missing — run UPDATE_GOLDEN=1 once (see MANIFEST.txt)");

    let workdir = tempfile::tempdir().unwrap();
    let src = workdir.path().join("src");
    let dst = workdir.path().join("dst");
    copy_dir_all(&golden_dir().join("repo"), &src);

    let xdg = tempfile::tempdir().unwrap();
    let out = Command::new(mkit_bin())
        .args([
            "export-legacy",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
            "--json",
        ])
        .env("XDG_CONFIG_HOME", xdg.path())
        .output()
        .expect("spawn mkit export-legacy");
    assert!(
        out.status.success(),
        "export-legacy failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // The source repo must be untouched — export-legacy is read-only.
    let src_commit_hex = fs::read_to_string(src.join(".mkit/refs/heads/main"))
        .unwrap()
        .trim()
        .to_owned();
    assert_eq!(src_commit_hex, hash::to_hex(&pinned.commit));
    assert!(
        !src.join(".mkit/format").exists(),
        "source must stay unmarked/untouched"
    );

    // `dst` opens cleanly under the current format via the real
    // command surface (proves the format marker + re-signed commit
    // are both genuinely valid, not just structurally present).
    let verify_out = Command::new(mkit_bin())
        .args(["verify", "HEAD"])
        .current_dir(&dst)
        .env("XDG_CONFIG_HOME", xdg.path())
        .output()
        .expect("spawn mkit verify");
    assert!(
        verify_out.status.success(),
        "translated HEAD commit must verify: stderr={}",
        String::from_utf8_lossy(&verify_out.stderr)
    );

    // Library-level content walk: matching CONTENT, not matching
    // object IDs (ids are expected to change — SPEC-MERKLE-OBJECTS §7).
    let dst_layout = RepoLayout::single(dst.clone());
    let dst_store = ObjectStore::open(&dst_layout).expect("dst must open under the current format");

    let new_commit_hex = fs::read_to_string(dst.join(".mkit/refs/heads/main"))
        .unwrap()
        .trim()
        .to_owned();
    let new_commit_id = hash::from_hex(&new_commit_hex).unwrap();
    assert_ne!(
        new_commit_id, pinned.commit,
        "translated commit id must differ from the legacy id"
    );

    let Object::Commit(new_commit) = dst_store.read_object(&new_commit_id).unwrap() else {
        panic!("HEAD is not a commit");
    };
    assert_eq!(new_commit.message, b"legacy root commit");
    assert_eq!(new_commit.timestamp, FIXED_TIMESTAMP);
    assert_eq!(
        new_commit.author,
        Identity::ed25519(KeyPair::from_seed(AUTHOR_SEED).public.0),
        "original author identity is preserved"
    );
    assert_ne!(
        new_commit.tree_hash, pinned.root_tree,
        "translated root tree id must differ from the legacy id"
    );

    let Object::Tree(new_root_tree) = dst_store.read_object(&new_commit.tree_hash).unwrap() else {
        panic!("expected a tree");
    };
    assert_eq!(new_root_tree.entries.len(), 1);
    assert_eq!(new_root_tree.entries[0].name, b"subdir");
    assert_eq!(new_root_tree.entries[0].mode, EntryMode::Tree);

    let Object::Tree(new_inner_tree) = dst_store
        .read_object(&new_root_tree.entries[0].object_hash)
        .unwrap()
    else {
        panic!("expected a tree");
    };
    assert_eq!(new_inner_tree.entries.len(), 1);
    assert_eq!(new_inner_tree.entries[0].name, b"file.txt");
    // Blob content-addressing is unaffected by the merkle change.
    assert_eq!(new_inner_tree.entries[0].object_hash, pinned.blob);

    let Object::Blob(new_blob) = dst_store.read_object(&pinned.blob).unwrap() else {
        panic!("expected a blob");
    };
    assert_eq!(new_blob.data, b"hello legacy world\n");
}

#[test]
fn export_legacy_refuses_to_overwrite_existing_destination() {
    let workdir = tempfile::tempdir().unwrap();
    let src = workdir.path().join("src");
    let dst = workdir.path().join("dst");
    copy_dir_all(&golden_dir().join("repo"), &src);
    fs::create_dir_all(dst.join(".mkit")).unwrap();

    let xdg = tempfile::tempdir().unwrap();
    let out = Command::new(mkit_bin())
        .args([
            "export-legacy",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        ])
        .env("XDG_CONFIG_HOME", xdg.path())
        .output()
        .expect("spawn mkit export-legacy");
    assert!(!out.status.success(), "must refuse an existing destination");
}

#[test]
fn export_legacy_refuses_current_format_source() {
    let workdir = tempfile::tempdir().unwrap();
    let src = workdir.path().join("src");
    let dst = workdir.path().join("dst");
    let src_layout = RepoLayout::single(src.clone());
    ObjectStore::init(&src_layout).unwrap();

    let xdg = tempfile::tempdir().unwrap();
    let out = Command::new(mkit_bin())
        .args([
            "export-legacy",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        ])
        .env("XDG_CONFIG_HOME", xdg.path())
        .output()
        .expect("spawn mkit export-legacy");
    assert!(
        !out.status.success(),
        "must refuse a repo that already declares the current format"
    );
    assert!(
        !dst.exists(),
        "must not create dst on refusal to init before writing"
    );
}
