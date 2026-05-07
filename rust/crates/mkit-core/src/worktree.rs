//! Worktree → tree-object builder.
//!
//! Walks a directory, applies `.mkitignore`, hashes each file as a
//! [`Blob`](crate::object::Blob), recurses on subdirectories, validates
//! symlink targets against path-traversal, and writes a single root
//! [`Tree`](crate::object::Tree) into the supplied [`ObjectStore`].
//!
//! Notes:
//!
//! - **No `FastCDC` chunking in this module**. The `chunked_blob` path
//!   lives in [`crate::chunker`] + [`crate::pack`]; this module rejects
//!   files larger than [`CHUNK_THRESHOLD`] with
//!   [`WorktreeError::FileTooLarge`]. v1 small-repo flows are
//!   unaffected.
//! - We never follow symlinks while walking. Linux/macOS `read_link`
//!   reports the target verbatim and we hash it as a blob.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::hash::Hash;
use crate::ignore::{self, IgnoreList};
use crate::object::{EntryMode, Object, Tree, TreeEntry};
use crate::serialize;
use crate::store::ObjectStore;

/// Files larger than this go through the chunker (1 MiB).
pub const CHUNK_THRESHOLD: u64 = 1024 * 1024;

/// Hard cap on a single file (1 GiB).
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
/// segments.
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
        // `symlink_metadata` does not follow symlinks.
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
            // Block / char / fifo / socket — silently skip.
        }
    }

    entries.sort_by(|a, b| a.name.cmp(&b.name));
    let tree = Object::Tree(Tree { entries });
    let bytes = serialize::serialize(&tree)?;
    Ok(store.write(&bytes)?)
}

/// Build a tree object from an [`Index`] (the staging area).
///
/// Walks the flat list of entries, groups them by directory, and
/// recursively materialises sub-tree objects so the on-disk shape
/// matches what [`build_tree`] would produce for the same set of
/// paths. Entries with [`crate::index::EntryStatus::Removed`] are
/// excluded; everything else maps to an [`EntryMode`] one-to-one.
///
/// # Errors
/// - [`WorktreeError::Io`] on a [`crate::object::TreeEntry::validate_name`]
///   failure (the path's leaf segment is reserved or alias-prone).
/// - Wraps [`crate::MkitError`] surfaced by `serialize` / `store.write`.
#[allow(clippy::items_after_statements, clippy::too_many_lines)]
pub fn build_tree_from_index(
    store: &ObjectStore,
    index: &crate::index::Index,
) -> WorktreeResult<Hash> {
    use crate::index::EntryStatus;

    // Build an in-memory directory tree. Each node is either a leaf
    // (one staged blob/symlink) or a directory containing children.
    #[derive(Default)]
    struct Node {
        // Subdirectory name → child node.
        children: std::collections::BTreeMap<String, Node>,
        // Leaf entries directly under this dir: name → (mode, hash).
        leaves: std::collections::BTreeMap<String, (EntryMode, Hash)>,
    }

    let mut root = Node::default();

    for entry in &index.entries {
        if entry.status == EntryStatus::Removed {
            continue;
        }
        let mode = match entry.status {
            EntryStatus::Blob => EntryMode::Blob,
            EntryStatus::Executable => EntryMode::Executable,
            EntryStatus::Symlink => EntryMode::Symlink,
            EntryStatus::Tree => {
                // Reserved-but-unused per SPEC-INDEX §3. Reject for
                // now; if a subtree-staging design lands later it
                // can populate this branch.
                return Err(WorktreeError::Io(io::Error::other(
                    "index entry uses reserved Tree status (subtree staging not implemented)",
                )));
            }
            EntryStatus::Removed => unreachable!("filtered above"),
        };
        if !matches!(store.read_object(&entry.object_hash)?, Object::Blob(_)) {
            return Err(WorktreeError::Io(io::Error::other(format!(
                "index entry '{}' points to a non-blob object",
                entry.path
            ))));
        }

        // Split "a/b/c.txt" into ["a", "b"] + "c.txt".
        let segments: Vec<&str> = entry.path.split('/').collect();
        let Some((leaf, dirs)) = segments.split_last() else {
            return Err(WorktreeError::Io(io::Error::other("empty index path")));
        };
        if leaf.is_empty() {
            return Err(WorktreeError::Io(io::Error::other(
                "trailing slash in index path",
            )));
        }

        let mut node = &mut root;
        let mut walked = String::new();
        for seg in dirs {
            if seg.is_empty() {
                return Err(WorktreeError::Io(io::Error::other(
                    "empty path segment in index",
                )));
            }
            // Collision: this segment was previously staged as a blob
            // (e.g. earlier index entry was `a` as a file, this one
            // is `a/b`). Tree object format requires unique entry
            // names per directory; emitting both would produce an
            // invalid tree the deserializer rejects under its strict
            // ascending-name rule.
            if node.leaves.contains_key(*seg) {
                let conflicting = if walked.is_empty() {
                    (*seg).to_string()
                } else {
                    format!("{walked}/{seg}")
                };
                return Err(WorktreeError::Io(io::Error::other(format!(
                    "index path conflict: '{conflicting}' is staged as both a file and a directory"
                ))));
            }
            walked = if walked.is_empty() {
                (*seg).to_string()
            } else {
                format!("{walked}/{seg}")
            };
            node = node.children.entry((*seg).to_string()).or_default();
        }
        // The reverse collision: this entry's leaf name already exists
        // as a child directory under the same parent (an earlier
        // entry staged `a/b` and now this one stages `a` as a file).
        if node.children.contains_key(*leaf) {
            let conflicting = if walked.is_empty() {
                (*leaf).to_string()
            } else {
                format!("{walked}/{leaf}")
            };
            return Err(WorktreeError::Io(io::Error::other(format!(
                "index path conflict: '{conflicting}' is staged as both a file and a directory"
            ))));
        }
        node.leaves
            .insert((*leaf).to_string(), (mode, entry.object_hash));
    }

    fn write_node(store: &ObjectStore, node: &Node) -> WorktreeResult<Hash> {
        let mut entries: Vec<TreeEntry> = Vec::new();

        // Subdirectories first (alphabetical via BTreeMap).
        for (name, child) in &node.children {
            let h = write_node(store, child)?;
            let bytes = name.as_bytes().to_vec();
            if !crate::object::TreeEntry::validate_name(&bytes) {
                return Err(WorktreeError::Io(io::Error::other(format!(
                    "invalid tree entry name: {name:?}"
                ))));
            }
            entries.push(TreeEntry {
                name: bytes,
                mode: EntryMode::Tree,
                object_hash: h,
            });
        }

        // Then leaves.
        for (name, (mode, hash)) in &node.leaves {
            let bytes = name.as_bytes().to_vec();
            if !crate::object::TreeEntry::validate_name(&bytes) {
                return Err(WorktreeError::Io(io::Error::other(format!(
                    "invalid tree entry name: {name:?}"
                ))));
            }
            entries.push(TreeEntry {
                name: bytes,
                mode: *mode,
                object_hash: *hash,
            });
        }

        // Tree-entry order is name-ascending per SPEC-OBJECTS §4.
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        let tree = Object::Tree(Tree { entries });
        let bytes = serialize::serialize(&tree)?;
        Ok(store.write(&bytes)?)
    }

    write_node(store, &root)
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

    // ---- build_tree_from_index — the staging-area path -------------

    use crate::index::{EntryStatus, Index, IndexEntry};

    fn write_blob(store: &ObjectStore, bytes: &[u8]) -> Hash {
        let blob = Object::Blob(crate::object::Blob {
            data: bytes.to_vec(),
        });
        let body = serialize::serialize(&blob).unwrap();
        store.write(&body).unwrap()
    }

    #[test]
    fn from_index_empty_returns_empty_tree() {
        let (_sd, store) = fresh_store();
        let idx = Index::new();
        let h = build_tree_from_index(&store, &idx).unwrap();
        let Object::Tree(t) = store.read_object(&h).unwrap() else {
            panic!("expected tree");
        };
        assert!(t.entries.is_empty());
    }

    #[test]
    fn from_index_single_file_at_root() {
        let (_sd, store) = fresh_store();
        let blob_hash = write_blob(&store, b"hello world");
        let mut idx = Index::new();
        idx.entries.push(IndexEntry {
            path: "hello.txt".into(),
            status: EntryStatus::Blob,
            object_hash: blob_hash,
        });
        let h = build_tree_from_index(&store, &idx).unwrap();
        let Object::Tree(t) = store.read_object(&h).unwrap() else {
            panic!();
        };
        assert_eq!(t.entries.len(), 1);
        assert_eq!(t.entries[0].name, b"hello.txt");
        assert_eq!(t.entries[0].mode, EntryMode::Blob);
        assert_eq!(t.entries[0].object_hash, blob_hash);
    }

    #[test]
    fn from_index_nested_paths_build_subtrees() {
        let (_sd, store) = fresh_store();
        let a = write_blob(&store, b"file a");
        let b = write_blob(&store, b"file b");
        let mut idx = Index::new();
        idx.entries.push(IndexEntry {
            path: "a.txt".into(),
            status: EntryStatus::Blob,
            object_hash: a,
        });
        idx.entries.push(IndexEntry {
            path: "subdir/b.txt".into(),
            status: EntryStatus::Blob,
            object_hash: b,
        });
        let root_hash = build_tree_from_index(&store, &idx).unwrap();
        let Object::Tree(root) = store.read_object(&root_hash).unwrap() else {
            panic!();
        };
        assert_eq!(root.entries.len(), 2);
        assert_eq!(root.entries[0].name, b"a.txt");
        assert_eq!(root.entries[0].mode, EntryMode::Blob);
        assert_eq!(root.entries[1].name, b"subdir");
        assert_eq!(root.entries[1].mode, EntryMode::Tree);

        let Object::Tree(sub) = store.read_object(&root.entries[1].object_hash).unwrap() else {
            panic!();
        };
        assert_eq!(sub.entries.len(), 1);
        assert_eq!(sub.entries[0].name, b"b.txt");
        assert_eq!(sub.entries[0].object_hash, b);
    }

    #[test]
    fn from_index_removed_entries_are_skipped() {
        let (_sd, store) = fresh_store();
        let a = write_blob(&store, b"keep me");
        let mut idx = Index::new();
        idx.entries.push(IndexEntry {
            path: "keep.txt".into(),
            status: EntryStatus::Blob,
            object_hash: a,
        });
        idx.entries.push(IndexEntry {
            path: "drop.txt".into(),
            status: EntryStatus::Removed,
            object_hash: [0; 32],
        });
        let h = build_tree_from_index(&store, &idx).unwrap();
        let Object::Tree(t) = store.read_object(&h).unwrap() else {
            panic!();
        };
        assert_eq!(t.entries.len(), 1);
        assert_eq!(t.entries[0].name, b"keep.txt");
    }

    #[test]
    fn from_index_executable_and_symlink_modes_pass_through() {
        let (_sd, store) = fresh_store();
        let exec = write_blob(&store, b"#!/bin/sh");
        let link = write_blob(&store, b"target.txt");
        let mut idx = Index::new();
        idx.entries.push(IndexEntry {
            path: "run.sh".into(),
            status: EntryStatus::Executable,
            object_hash: exec,
        });
        idx.entries.push(IndexEntry {
            path: "link".into(),
            status: EntryStatus::Symlink,
            object_hash: link,
        });
        let h = build_tree_from_index(&store, &idx).unwrap();
        let Object::Tree(t) = store.read_object(&h).unwrap() else {
            panic!();
        };
        let by_name: std::collections::HashMap<&[u8], &TreeEntry> =
            t.entries.iter().map(|e| (e.name.as_slice(), e)).collect();
        assert_eq!(by_name[&b"run.sh"[..]].mode, EntryMode::Executable);
        assert_eq!(by_name[&b"link"[..]].mode, EntryMode::Symlink);
    }

    #[test]
    fn from_index_entries_are_sorted_by_name() {
        let (_sd, store) = fresh_store();
        let a = write_blob(&store, b"x");
        let mut idx = Index::new();
        // Insert out-of-order; the on-disk Tree must still be sorted
        // (SPEC-OBJECTS §4 normative).
        idx.entries.push(IndexEntry {
            path: "z.txt".into(),
            status: EntryStatus::Blob,
            object_hash: a,
        });
        idx.entries.push(IndexEntry {
            path: "a.txt".into(),
            status: EntryStatus::Blob,
            object_hash: a,
        });
        idx.entries.push(IndexEntry {
            path: "m.txt".into(),
            status: EntryStatus::Blob,
            object_hash: a,
        });
        let h = build_tree_from_index(&store, &idx).unwrap();
        let Object::Tree(t) = store.read_object(&h).unwrap() else {
            panic!();
        };
        let names: Vec<&[u8]> = t.entries.iter().map(|e| e.name.as_slice()).collect();
        assert_eq!(names, vec![&b"a.txt"[..], b"m.txt", b"z.txt"]);
    }

    #[test]
    fn from_index_rejects_trailing_slash() {
        let (_sd, store) = fresh_store();
        let h = write_blob(&store, b"x");
        let mut idx = Index::new();
        idx.entries.push(IndexEntry {
            path: "dir/".into(),
            status: EntryStatus::Blob,
            object_hash: h,
        });
        let err = build_tree_from_index(&store, &idx).unwrap_err();
        assert!(matches!(err, WorktreeError::Io(_)));
    }

    #[test]
    fn from_index_rejects_empty_segment() {
        let (_sd, store) = fresh_store();
        let h = write_blob(&store, b"x");
        let mut idx = Index::new();
        idx.entries.push(IndexEntry {
            path: "a//b.txt".into(),
            status: EntryStatus::Blob,
            object_hash: h,
        });
        let err = build_tree_from_index(&store, &idx).unwrap_err();
        assert!(matches!(err, WorktreeError::Io(_)));
    }

    #[test]
    fn from_index_rejects_reserved_name() {
        let (_sd, store) = fresh_store();
        let h = write_blob(&store, b"x");
        let mut idx = Index::new();
        // ".mkit" is rejected by TreeEntry::validate_name as repo
        // metadata aliasing.
        idx.entries.push(IndexEntry {
            path: ".mkit".into(),
            status: EntryStatus::Blob,
            object_hash: h,
        });
        let err = build_tree_from_index(&store, &idx).unwrap_err();
        assert!(matches!(err, WorktreeError::Io(_)));
    }

    /// The most important invariant: for a worktree whose contents
    /// match the index entry-for-entry, `build_tree` and
    /// `build_tree_from_index` MUST produce the identical root hash.
    /// If this drifts, attestations signed under one path won't
    /// verify against trees built under the other.
    #[test]
    fn from_index_matches_build_tree_for_equivalent_worktree() {
        let (_sd, store) = fresh_store();

        // Build the same content two ways:
        //   1. drop files on disk, call build_tree.
        //   2. write blobs to the store directly, populate an index,
        //      call build_tree_from_index.
        let work = TempDir::new().unwrap();
        fs::write(work.path().join("a.txt"), b"alpha").unwrap();
        fs::create_dir(work.path().join("dir")).unwrap();
        fs::write(work.path().join("dir/b.txt"), b"beta").unwrap();
        fs::write(work.path().join("dir/c.txt"), b"gamma").unwrap();
        let worktree_root = build_tree(&store, work.path()).unwrap();

        let a = write_blob(&store, b"alpha");
        let b = write_blob(&store, b"beta");
        let c = write_blob(&store, b"gamma");
        let mut idx = Index::new();
        idx.entries.push(IndexEntry {
            path: "a.txt".into(),
            status: EntryStatus::Blob,
            object_hash: a,
        });
        idx.entries.push(IndexEntry {
            path: "dir/b.txt".into(),
            status: EntryStatus::Blob,
            object_hash: b,
        });
        idx.entries.push(IndexEntry {
            path: "dir/c.txt".into(),
            status: EntryStatus::Blob,
            object_hash: c,
        });
        let index_root = build_tree_from_index(&store, &idx).unwrap();

        assert_eq!(
            worktree_root, index_root,
            "build_tree_from_index must produce the same root hash as build_tree for equivalent contents"
        );
    }

    #[test]
    fn from_index_deeply_nested_paths_build_chain_of_subtrees() {
        let (_sd, store) = fresh_store();
        let h = write_blob(&store, b"deep");
        let mut idx = Index::new();
        idx.entries.push(IndexEntry {
            path: "a/b/c/d/e.txt".into(),
            status: EntryStatus::Blob,
            object_hash: h,
        });
        let root = build_tree_from_index(&store, &idx).unwrap();
        let Object::Tree(t) = store.read_object(&root).unwrap() else {
            panic!();
        };
        assert_eq!(t.entries.len(), 1);
        assert_eq!(t.entries[0].name, b"a");
        assert_eq!(t.entries[0].mode, EntryMode::Tree);
        // Walk down to the leaf.
        let mut cursor = t.entries[0].object_hash;
        for seg in [b"b" as &[u8], b"c", b"d"] {
            let Object::Tree(t) = store.read_object(&cursor).unwrap() else {
                panic!();
            };
            assert_eq!(t.entries.len(), 1);
            assert_eq!(t.entries[0].name, seg);
            cursor = t.entries[0].object_hash;
        }
        let Object::Tree(t) = store.read_object(&cursor).unwrap() else {
            panic!();
        };
        assert_eq!(t.entries[0].name, b"e.txt");
        assert_eq!(t.entries[0].object_hash, h);
    }

    /// Path-collision: an index that stakes the same name as both a
    /// blob and a directory MUST be rejected. Without the check the
    /// builder would happily emit two `TreeEntries` with name `a`
    /// (one Blob, one Tree), which the deserializer rejects under
    /// its strict ascending-name rule. We catch it earlier with a
    /// clearer error so the user knows which path needs unstaging.
    /// (Reviewer finding 2 on PR #103.)
    #[test]
    fn from_index_rejects_blob_then_subdir_collision() {
        let (_sd, store) = fresh_store();
        let h = write_blob(&store, b"x");
        let mut idx = Index::new();
        idx.entries.push(IndexEntry {
            path: "a".into(),
            status: EntryStatus::Blob,
            object_hash: h,
        });
        idx.entries.push(IndexEntry {
            path: "a/b".into(),
            status: EntryStatus::Blob,
            object_hash: h,
        });
        let err = build_tree_from_index(&store, &idx).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("conflict") || msg.contains("collision") || msg.contains("'a'"),
            "expected collision error mentioning the path, got: {msg}"
        );
    }

    /// Same collision in the opposite stage order: subdir entry
    /// staged first, then a blob at the parent.
    #[test]
    fn from_index_rejects_subdir_then_blob_collision() {
        let (_sd, store) = fresh_store();
        let h = write_blob(&store, b"x");
        let mut idx = Index::new();
        idx.entries.push(IndexEntry {
            path: "a/b".into(),
            status: EntryStatus::Blob,
            object_hash: h,
        });
        idx.entries.push(IndexEntry {
            path: "a".into(),
            status: EntryStatus::Blob,
            object_hash: h,
        });
        assert!(build_tree_from_index(&store, &idx).is_err());
    }

    /// All-Removed index → empty root tree, NOT an error.
    /// (Reviewer finding 1 on PR #103.) `staged_count()` excludes
    /// Removed entries by design; the tree builder does too. The
    /// resulting empty tree is a valid commit target — applying a
    /// removals-only changeset to a tree that previously contained
    /// those paths produces an empty root.
    #[test]
    fn from_index_all_removed_produces_empty_tree() {
        let (_sd, store) = fresh_store();
        let mut idx = Index::new();
        idx.entries.push(IndexEntry {
            path: "gone.txt".into(),
            status: EntryStatus::Removed,
            object_hash: [0; 32],
        });
        let h = build_tree_from_index(&store, &idx).unwrap();
        let Object::Tree(t) = store.read_object(&h).unwrap() else {
            panic!();
        };
        assert!(t.entries.is_empty());
    }

    /// Sanity: `ObjectType::Tree` is what we materialise. Pin so a
    /// future enum reshuffle catches us.
    #[test]
    fn from_index_root_is_a_tree_object() {
        let (_sd, store) = fresh_store();
        let idx = Index::new();
        let h = build_tree_from_index(&store, &idx).unwrap();
        let obj = store.read_object(&h).unwrap();
        assert_eq!(obj.object_type(), ObjectType::Tree);
    }

    #[test]
    fn from_index_rejects_missing_blob_object() {
        let (_sd, store) = fresh_store();
        let mut idx = Index::new();
        idx.entries.push(IndexEntry {
            path: "missing.txt".into(),
            status: EntryStatus::Blob,
            object_hash: [42; 32],
        });

        let err = build_tree_from_index(&store, &idx).unwrap_err();
        assert!(matches!(err, WorktreeError::Store(_)));
    }

    #[test]
    fn from_index_rejects_non_blob_object_for_blob_status() {
        let (_sd, store) = fresh_store();
        let tree = Object::Tree(Tree { entries: vec![] });
        let body = serialize::serialize(&tree).unwrap();
        let tree_hash = store.write(&body).unwrap();
        let mut idx = Index::new();
        idx.entries.push(IndexEntry {
            path: "not-a-blob.txt".into(),
            status: EntryStatus::Blob,
            object_hash: tree_hash,
        });

        let err = build_tree_from_index(&store, &idx).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("non-blob"),
            "expected non-blob index object error, got: {msg}"
        );
    }
}
