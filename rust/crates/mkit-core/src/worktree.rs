//! Worktree → tree-object builder — port of `src/worktree.zig`.
//!
//! Walks a directory, applies `.mkitignore`, hashes each file as a
//! [`Blob`](crate::object::Blob), recurses on subdirectories, validates
//! symlink targets against path-traversal, and writes a single root
//! [`Tree`](crate::object::Tree) into the supplied [`ObjectStore`].
//!
//! Differences from the Zig original:
//!
//! - **No `FastCDC` chunking**. The `chunked_blob` path lives in the
//!   PACK agent's scope (`src/chunker.rs` + `src/pack.rs`); this
//!   module rejects files larger than [`CHUNK_THRESHOLD`] with
//!   [`WorktreeError::FileTooLarge`] until the chunker is wired in.
//!   v1 small-repo flows are unaffected.
//! - We never follow symlinks while walking. Linux/macOS `read_link`
//!   reports the target verbatim and we hash it as a blob the same
//!   way the Zig source does.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::hash::Hash;
use crate::ignore::{self, IgnoreList};
use crate::object::{EntryMode, Object, Tree, TreeEntry};
use crate::serialize;
use crate::store::ObjectStore;

/// Files larger than this go through the (not-yet-ported) chunker.
/// Mirrors the Zig `chunk_threshold` (1 MiB).
pub const CHUNK_THRESHOLD: u64 = 1024 * 1024;

/// Hard cap on a single file. Matches the Zig source.
pub const MAX_FILE_BYTES: u64 = 1024 * 1024 * 1024;

/// Errors returned by this module.
#[derive(Debug, thiserror::Error)]
pub enum WorktreeError {
    /// `read_link` returned a target that fails [`validate_symlink_target`].
    #[error("symlink target '{0}' is invalid (absolute or contains '..')")]
    InvalidSymlinkTarget(String),
    /// File exceeded [`MAX_FILE_BYTES`].
    #[error("file '{0}' exceeds the {MAX_FILE_BYTES} byte limit")]
    FileTooLarge(PathBuf),
    /// File exceeded [`CHUNK_THRESHOLD`] but the chunker port is not
    /// yet in place. Tracked separately from [`Self::FileTooLarge`] so
    /// downstream call sites can detect and re-route once PACK lands.
    #[error("file '{0}' exceeds {CHUNK_THRESHOLD} bytes; chunker not yet ported")]
    NeedsChunker(PathBuf),
    /// Path component had non-UTF-8 bytes; tree entry names must be UTF-8.
    #[error("path component is not valid UTF-8")]
    InvalidUtf8,
    /// Underlying I/O failure.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// Error encoding/serialising an object on its way into the store.
    #[error(transparent)]
    Object(#[from] crate::object::MkitError),
    /// Error returned by the object store.
    #[error(transparent)]
    Store(#[from] crate::store::StoreError),
}

/// Result alias used throughout this module.
pub type WorktreeResult<T> = Result<T, WorktreeError>;

/// Validate a symlink target: must be relative and contain no `..`
/// segments. Mirrors `src/worktree.zig::validateSymlinkTarget`.
#[must_use]
pub fn validate_symlink_target(target: &str) -> bool {
    if target.is_empty() {
        return false;
    }
    if target.starts_with('/') {
        return false;
    }
    for part in target.split('/') {
        if part == ".." {
            return false;
        }
    }
    true
}

/// Build a tree object for `dir` and its subdirectories. Honours
/// `.mkitignore` loaded from `dir`.
///
/// # Errors
/// See [`WorktreeError`].
pub fn build_tree(store: &ObjectStore, dir: &Path) -> WorktreeResult<Hash> {
    let ignores = ignore::load(dir).map_err(|e| match e {
        crate::ignore::IgnoreError::Io(io) => WorktreeError::Io(io),
        crate::ignore::IgnoreError::FileTooLarge => {
            WorktreeError::Io(io::Error::other(".mkitignore exceeds 1 MiB"))
        }
    })?;
    build_tree_inner(store, dir, &ignores)
}

fn build_tree_inner(store: &ObjectStore, dir: &Path, ignores: &IgnoreList) -> WorktreeResult<Hash> {
    let mut entries: Vec<TreeEntry> = Vec::new();

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let file_name = entry.file_name();
        let name_str = file_name
            .to_str()
            .ok_or(WorktreeError::InvalidUtf8)?
            .to_string();
        // `symlink_metadata` does not follow symlinks — same effect as
        // the Zig source's `follow_symlinks = false` stat.
        let meta = entry.path().symlink_metadata()?;
        let is_dir = meta.is_dir();
        if ignores.is_ignored(&name_str, is_dir) {
            continue;
        }

        if meta.file_type().is_file() {
            let h = hash_file(store, &entry.path())?;
            entries.push(TreeEntry {
                name: name_str.into_bytes(),
                mode: EntryMode::Blob,
                object_hash: h,
            });
        } else if meta.file_type().is_dir() {
            let h = build_tree_inner(store, &entry.path(), ignores)?;
            entries.push(TreeEntry {
                name: name_str.into_bytes(),
                mode: EntryMode::Tree,
                object_hash: h,
            });
        } else if meta.file_type().is_symlink() {
            let target = fs::read_link(entry.path())?;
            let target_str = target
                .to_str()
                .ok_or(WorktreeError::InvalidUtf8)?
                .to_string();
            if !validate_symlink_target(&target_str) {
                return Err(WorktreeError::InvalidSymlinkTarget(target_str));
            }
            let blob = Object::Blob(crate::object::Blob {
                data: target_str.as_bytes().to_vec(),
            });
            let bytes = serialize::serialize(&blob)?;
            let h = store.write(&bytes)?;
            entries.push(TreeEntry {
                name: name_str.into_bytes(),
                mode: EntryMode::Symlink,
                object_hash: h,
            });
        } else {
            // Block / char / fifo / socket — silently skip, same as Zig.
        }
    }

    entries.sort_by(|a, b| a.name.cmp(&b.name));
    let tree = Object::Tree(Tree { entries });
    let bytes = serialize::serialize(&tree)?;
    Ok(store.write(&bytes)?)
}

/// Read a file from disk, hash it as a [`Blob`](crate::object::Blob),
/// store it, and return the hash. Rejects files larger than
/// [`CHUNK_THRESHOLD`] with [`WorktreeError::NeedsChunker`] until the
/// PACK agent's chunker lands.
///
/// # Errors
/// See [`WorktreeError`].
pub fn hash_file(store: &ObjectStore, path: &Path) -> WorktreeResult<Hash> {
    let pre_meta = path.symlink_metadata()?;
    if !pre_meta.file_type().is_file() {
        return Err(WorktreeError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "hash_file: path is not a regular file",
        )));
    }
    if pre_meta.len() > MAX_FILE_BYTES {
        return Err(WorktreeError::FileTooLarge(path.to_path_buf()));
    }
    if pre_meta.len() > CHUNK_THRESHOLD {
        return Err(WorktreeError::NeedsChunker(path.to_path_buf()));
    }
    let data = fs::read(path)?;
    let blob = Object::Blob(crate::object::Blob { data });
    let bytes = serialize::serialize(&blob)?;
    Ok(store.write(&bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::ObjectType;
    use tempfile::TempDir;

    fn fresh_store() -> (TempDir, ObjectStore) {
        let dir = TempDir::new().unwrap();
        let store = ObjectStore::init(dir.path()).unwrap();
        (dir, store)
    }

    #[test]
    fn validate_symlink_targets() {
        assert!(validate_symlink_target("hello"));
        assert!(validate_symlink_target("sub/dir/file"));
        assert!(!validate_symlink_target(""));
        assert!(!validate_symlink_target("/etc/passwd"));
        assert!(!validate_symlink_target("../escape"));
        assert!(!validate_symlink_target("a/../b"));
    }

    #[test]
    fn build_tree_from_empty_dir() {
        let (_sd, store) = fresh_store();
        let work = TempDir::new().unwrap();
        let h = build_tree(&store, work.path()).unwrap();
        let obj = store.read_object(&h).unwrap();
        match obj {
            Object::Tree(t) => assert_eq!(t.entries.len(), 0),
            other => panic!("expected tree, got {other:?}"),
        }
    }

    #[test]
    fn build_tree_with_single_file() {
        let (_sd, store) = fresh_store();
        let work = TempDir::new().unwrap();
        fs::write(work.path().join("hello.txt"), b"hello world").unwrap();
        let h = build_tree(&store, work.path()).unwrap();
        let obj = store.read_object(&h).unwrap();
        let Object::Tree(t) = obj else {
            panic!("expected tree");
        };
        assert_eq!(t.entries.len(), 1);
        assert_eq!(t.entries[0].name.as_slice(), b"hello.txt");
        assert_eq!(t.entries[0].mode, EntryMode::Blob);
        let blob_obj = store.read_object(&t.entries[0].object_hash).unwrap();
        let Object::Blob(b) = blob_obj else {
            panic!("expected blob");
        };
        assert_eq!(b.data, b"hello world");
    }

    #[test]
    fn build_tree_with_nested_directories() {
        let (_sd, store) = fresh_store();
        let work = TempDir::new().unwrap();
        fs::write(work.path().join("a.txt"), b"file a").unwrap();
        fs::create_dir(work.path().join("subdir")).unwrap();
        fs::write(work.path().join("subdir/b.txt"), b"file b").unwrap();
        let h = build_tree(&store, work.path()).unwrap();
        let obj = store.read_object(&h).unwrap();
        let Object::Tree(t) = obj else {
            panic!("expected tree");
        };
        assert_eq!(t.entries.len(), 2);
        // Sorted lex: a.txt first, subdir second.
        assert_eq!(t.entries[0].name.as_slice(), b"a.txt");
        assert_eq!(t.entries[1].name.as_slice(), b"subdir");
        assert_eq!(t.entries[1].mode, EntryMode::Tree);
        let sub = store.read_object(&t.entries[1].object_hash).unwrap();
        let Object::Tree(st) = sub else {
            panic!("expected tree");
        };
        assert_eq!(st.entries.len(), 1);
        assert_eq!(st.entries[0].name.as_slice(), b"b.txt");
    }

    #[test]
    fn build_tree_skips_mkit_directory() {
        let (_sd, store) = fresh_store();
        let work = TempDir::new().unwrap();
        fs::create_dir(work.path().join(".mkit")).unwrap();
        fs::write(work.path().join(".mkit/should_skip"), b"").unwrap();
        fs::write(work.path().join("keep.txt"), b"kept").unwrap();
        let h = build_tree(&store, work.path()).unwrap();
        let obj = store.read_object(&h).unwrap();
        let Object::Tree(t) = obj else {
            panic!("expected tree");
        };
        assert_eq!(t.entries.len(), 1);
        assert_eq!(t.entries[0].name.as_slice(), b"keep.txt");
    }

    #[test]
    fn build_tree_is_deterministic() {
        let (_sd, store) = fresh_store();
        let work = TempDir::new().unwrap();
        fs::write(work.path().join("z.txt"), b"z").unwrap();
        fs::write(work.path().join("a.txt"), b"a").unwrap();
        let h1 = build_tree(&store, work.path()).unwrap();
        let h2 = build_tree(&store, work.path()).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn build_tree_respects_mkitignore() {
        let (_sd, store) = fresh_store();
        let work = TempDir::new().unwrap();
        fs::write(work.path().join(".mkitignore"), b"*.log\n").unwrap();
        fs::write(work.path().join("keep.txt"), b"kept").unwrap();
        fs::write(work.path().join("debug.log"), b"ignored").unwrap();
        let h = build_tree(&store, work.path()).unwrap();
        let obj = store.read_object(&h).unwrap();
        let Object::Tree(t) = obj else {
            panic!("expected tree");
        };
        // .mkitignore + keep.txt, but not debug.log.
        assert_eq!(t.entries.len(), 2);
        assert_eq!(t.entries[0].name.as_slice(), b".mkitignore");
        assert_eq!(t.entries[1].name.as_slice(), b"keep.txt");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_invalid_symlink_targets() {
        use std::os::unix::fs::symlink;
        let (_sd, store) = fresh_store();
        let work = TempDir::new().unwrap();
        symlink("/etc/passwd", work.path().join("bad-link")).unwrap();
        let err = build_tree(&store, work.path()).unwrap_err();
        assert!(matches!(err, WorktreeError::InvalidSymlinkTarget(_)));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_dotdot_symlink_targets() {
        use std::os::unix::fs::symlink;
        let (_sd, store) = fresh_store();
        let work = TempDir::new().unwrap();
        symlink("../../etc/passwd", work.path().join("bad-link")).unwrap();
        let err = build_tree(&store, work.path()).unwrap_err();
        assert!(matches!(err, WorktreeError::InvalidSymlinkTarget(_)));
    }

    #[test]
    fn small_file_stays_as_regular_blob() {
        let (_sd, store) = fresh_store();
        let work = TempDir::new().unwrap();
        fs::write(work.path().join("small.txt"), b"hello world").unwrap();
        let h = build_tree(&store, work.path()).unwrap();
        let obj = store.read_object(&h).unwrap();
        let Object::Tree(t) = obj else {
            panic!("expected tree");
        };
        let entry = store.read_object(&t.entries[0].object_hash).unwrap();
        assert_eq!(entry.object_type(), ObjectType::Blob);
    }

    #[test]
    fn large_file_returns_needs_chunker() {
        let (_sd, store) = fresh_store();
        let work = TempDir::new().unwrap();
        let big = vec![0u8; usize::try_from(CHUNK_THRESHOLD + 1024).unwrap()];
        fs::write(work.path().join("big.bin"), &big).unwrap();
        let err = build_tree(&store, work.path()).unwrap_err();
        assert!(matches!(err, WorktreeError::NeedsChunker(_)));
    }
}
