//! Worktree → tree-object builder.
//!
//! Walks a directory, applies `.mkitignore`, hashes each file as a
//! [`Blob`](crate::object::Blob), recurses on subdirectories, validates
//! symlink targets against path-traversal, and writes a single root
//! [`Tree`] into the supplied [`ObjectStore`].
//!
//! Notes:
//!
//! - Files at or below [`CHUNK_THRESHOLD`] are stored as a single
//!   [`Blob`](crate::object::Blob). Files above the threshold are
//!   chunked with [`crate::chunker::FastCdc::v1`]; each chunk is
//!   stored as a `Blob` and the file is represented by a
//!   [`ChunkedBlob`] manifest whose hash
//!   is what lands in the parent tree.
//! - We never follow symlinks while walking. Linux/macOS `read_link`
//!   reports the target verbatim and we hash it as a blob.

use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use crate::chunker::{ChunkIterator, FastCdc};
use crate::hash::Hash;
use crate::ignore::{self, IgnoreList};
use crate::index::{self, Index};
use crate::object::{ChunkedBlob, EntryMode, Object, Tree, TreeEntry};
use crate::serialize;
use crate::store::{ObjectSink, ObjectStore};

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

/// A hash-time stat observation: while building a tree we re-hashed
/// `path` (its cache was absent or racy-smudged) and the result equals
/// the staging index's hash — so the stat captured from the OPENED file
/// descriptor *before* its content was read proves the entry clean.
/// `status` consumes these to heal the stat cache without ever pairing
/// a post-verification stat with a pre-verification hash (the unsound
/// verify-then-stat order).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatObservation {
    /// Repo-relative path, `/`-separated (index path form).
    pub path: String,
    /// The content hash the re-hash produced (== the index entry's).
    pub object_hash: Hash,
    /// Stat fields captured from the opened fd before the read, in
    /// [`stat_cache_fields`] order.
    pub mtime_ns: u64,
    pub size: u64,
    pub ino: u64,
    pub ctime_ns: u64,
}

/// Build a tree object for `dir` and its subdirectories. Honours the
/// `.gitignore` + `.mkitignore` ignore files loaded from `dir`.
///
/// Ignore rules only exclude **untracked** content: a path that is tracked
/// (or whose subtree holds tracked content) is always included even if it
/// matches an ignore rule, so a tracked file matching `.gitignore` is never
/// dropped from the worktree snapshot (which would misreport it as a deletion
/// in status/diff). The staging index at `<dir>/.mkit/index` provides the
/// tracked set; an absent index means nothing is tracked.
///
/// # Errors
/// See [`WorktreeError`].
pub fn build_tree<S: ObjectSink + ?Sized>(sink: &S, dir: &Path) -> WorktreeResult<Hash> {
    build_tree_filtered(sink, dir, None)
}

/// Like [`build_tree`], but the caller supplies the authoritative tracked
/// set (`index`). Callers that seed their index from `HEAD` when no index
/// file exists yet (status, restore safety) MUST pass it here so a tracked
/// file that matches an ignore rule is not dropped right after a checkout.
/// `None` falls back to the on-disk `<dir>/.mkit/index` (empty if absent).
///
/// # Errors
/// See [`WorktreeError`].
pub fn build_tree_filtered<S: ObjectSink + ?Sized>(
    sink: &S,
    dir: &Path,
    index: Option<&Index>,
) -> WorktreeResult<Hash> {
    build_tree_filtered_observed(sink, dir, index, &mut Vec::new())
}

/// [`build_tree_filtered`] that additionally reports every
/// [`StatObservation`] (file re-hashed to a hash matching its index
/// entry) into `observations`, so callers can heal the stat cache from
/// hash-time stats.
///
/// # Errors
/// See [`WorktreeError`].
pub fn build_tree_filtered_observed<S: ObjectSink + ?Sized>(
    sink: &S,
    dir: &Path,
    index: Option<&Index>,
    observations: &mut Vec<StatObservation>,
) -> WorktreeResult<Hash> {
    let ignores = ignore::load(dir).map_err(|e| match e {
        crate::ignore::IgnoreError::Io(io) => WorktreeError::Io(io),
        crate::ignore::IgnoreError::FileTooLarge => {
            WorktreeError::Io(io::Error::other("ignore file exceeds 1 MiB"))
        }
    })?;
    // Tracked set for ignore exemption: the caller's index if given, else the
    // on-disk index (missing/unreadable = empty = nothing tracked).
    let loaded;
    let index = if let Some(i) = index {
        i
    } else {
        loaded = index::read_index(dir).unwrap_or_default();
        &loaded
    };
    // O(1) per-file entry lookups; `Index::find_entry` is a linear scan
    // and the walk consults it once per regular file.
    let by_path: std::collections::HashMap<&str, &crate::index::IndexEntry> =
        index.entries.iter().map(|e| (e.path.as_str(), e)).collect();
    build_tree_inner(
        sink,
        dir,
        "",
        &ignores,
        index,
        &by_path,
        false,
        observations,
    )
}

/// `rel_dir` is the path of `dir` relative to the repo root (empty at the
/// root), so ignore patterns can be matched against full repo-relative paths
/// rather than bare basenames. `parent_ignored` carries down whether an
/// ancestor directory is ignored (git "everything under an excluded dir is
/// excluded"); `index` is the tracked set used to exempt tracked content.
#[allow(clippy::too_many_arguments)]
fn build_tree_inner<S: ObjectSink + ?Sized>(
    sink: &S,
    dir: &Path,
    rel_dir: &str,
    ignores: &IgnoreList,
    index: &Index,
    by_path: &std::collections::HashMap<&str, &crate::index::IndexEntry>,
    parent_ignored: bool,
    observations: &mut Vec<StatObservation>,
) -> WorktreeResult<Hash> {
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
        let rel_path = if rel_dir.is_empty() {
            name_str.clone()
        } else {
            format!("{rel_dir}/{name_str}")
        };
        // Exclude ignored content, but only when it is UNTRACKED — a tracked
        // path (or a dir holding tracked content) is always kept so status/
        // diff see it. An ignored dir with tracked content is descended into
        // (carrying the ignored bit) so its untracked children stay excluded.
        let entry_ignored = parent_ignored || ignores.is_ignored(&rel_path, is_dir);
        if entry_ignored && !index.tracks_path_or_descendant(&rel_path) {
            continue;
        }

        let name_bytes = name_str.as_bytes();
        if !TreeEntry::validate_name(name_bytes) {
            return Err(WorktreeError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid tree entry name: {name_str:?}"),
            )));
        }

        if meta.file_type().is_file() {
            // Stat cache: when the staging index proves this file's
            // content via mtime+size+ino+ctime (+exec class), reuse the
            // staged hash without opening the file — O(stat) instead of
            // O(content) for unchanged files. The object was stored at
            // `add` time, so the tree reference stays resolvable.
            let indexed = by_path.get(rel_path.as_str()).copied();
            let cached = indexed.filter(|e| stat_matches(e, &meta));
            let (object_hash, mode) = if let Some(e) = cached {
                (e.object_hash, entry_mode_from_file_metadata(&meta))
            } else {
                let (h, opened_meta) = hash_file_with_metadata(sink, &entry.path())?;
                // Cache miss that re-hashed back to the staged hash:
                // report the observation (stat captured from the opened
                // fd BEFORE the content read) so callers can heal the
                // racy-smudged cache soundly.
                if let Some(e) = indexed
                    && e.object_hash == h
                {
                    let (mtime_ns, size, ino, ctime_ns) = stat_cache_fields(&opened_meta);
                    observations.push(StatObservation {
                        path: rel_path.clone(),
                        object_hash: h,
                        mtime_ns,
                        size,
                        ino,
                        ctime_ns,
                    });
                }
                (h, entry_mode_from_file_metadata(&opened_meta))
            };
            entries.push(TreeEntry {
                name: name_str.into_bytes(),
                mode,
                object_hash,
            });
        } else if meta.file_type().is_dir() {
            // A directory on disk at a path tracked as a *file* shadows that
            // tracked entry. git reports only the tracked-side deletion and
            // suppresses the directory's contents as untracked (#288); mirror
            // that by leaving the whole subtree out of the snapshot, so the
            // tracked file reads as deleted and nothing inside surfaces.
            if index.has_tracked_file_at(&rel_path) {
                continue;
            }
            let h = build_tree_inner(
                sink,
                &entry.path(),
                &rel_path,
                ignores,
                index,
                by_path,
                entry_ignored,
                observations,
            )?;
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
            let target_bytes = target_str.as_bytes();
            let prologue = serialize::blob_prologue(target_bytes.len())?;
            let h = sink.put_parts(&[&prologue, target_bytes])?;
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
    Ok(sink.put(&bytes)?)
}

/// Build a tree object from an [`Index`] (the staging area).
///
/// Walks the flat list of entries, groups them by directory, and
/// recursively materialises sub-tree objects so the on-disk shape
/// matches what [`build_tree`] would produce for the same set of
/// paths. Entries with [`crate::index::EntryStatus::Removed`] are
/// excluded; everything else maps to an [`EntryMode`] one-to-one.
///
/// A file entry (Blob/Executable) may address either a single
/// [`Blob`](crate::object::Blob) or, for content above
/// [`CHUNK_THRESHOLD`], a [`ChunkedBlob`]
/// manifest — exactly the two shapes `store_file_object` (and hence
/// `add`/`hash_file`/`build_tree`) can produce. Symlink entries must be
/// a single `Blob`. Any other object kind under a file entry is rejected.
///
/// # Errors
/// - [`WorktreeError::Io`] on a [`crate::object::TreeEntry::validate_name`]
///   failure (the path's leaf segment is reserved or alias-prone), or
///   when a file entry points at a non-blob/non-chunked-blob object.
/// - Wraps [`crate::MkitError`] surfaced by `serialize` / `store.write`.
pub fn build_tree_from_index(
    store: &ObjectStore,
    index: &crate::index::Index,
) -> WorktreeResult<Hash> {
    build_tree_from_index_with(store, store, index)
}

/// [`build_tree_from_index`] writing tree objects through `sink` —
/// pass a [`WriteBatch`](crate::batch::WriteBatch) to amortise the
/// flush cost of all materialised trees into the batch's single commit.
/// `store` is still needed read-only to validate that staged hashes
/// point at blob-shaped objects (a sink cannot read).
///
/// # Errors
/// See [`build_tree_from_index`].
#[allow(clippy::items_after_statements, clippy::too_many_lines)]
pub fn build_tree_from_index_with<S: ObjectSink + ?Sized>(
    store: &ObjectStore,
    sink: &S,
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
    let mut seen_paths = std::collections::HashSet::with_capacity(index.entries.len());

    for entry in &index.entries {
        if !seen_paths.insert(entry.path.as_str()) {
            return Err(WorktreeError::Io(io::Error::other(format!(
                "duplicate index path: '{}'",
                entry.path
            ))));
        }
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
        // A regular file (Blob/Executable) may be stored as a single
        // Blob or, for content above CHUNK_THRESHOLD, a ChunkedBlob
        // manifest — `add`/`hash_file`/`build_tree` all route through
        // `store_file_object`. A Symlink is always a single Blob (its
        // target path). Accept both blob shapes for file entries so the
        // commit/index path agrees with the worktree-hashing path; a
        // tree/commit/etc. under a file entry is still rejected.
        match store.read_object(&entry.object_hash)? {
            Object::Blob(_) => {}
            Object::ChunkedBlob(_) if mode != EntryMode::Symlink => {}
            other => {
                return Err(WorktreeError::Io(io::Error::other(format!(
                    "index entry '{}' points to a non-blob object (got {})",
                    entry.path,
                    other.object_type().name()
                ))));
            }
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
        if node
            .leaves
            .insert((*leaf).to_string(), (mode, entry.object_hash))
            .is_some()
        {
            let duplicate = if walked.is_empty() {
                (*leaf).to_string()
            } else {
                format!("{walked}/{leaf}")
            };
            return Err(WorktreeError::Io(io::Error::other(format!(
                "duplicate index path: '{duplicate}'"
            ))));
        }
    }

    fn write_node<S: ObjectSink + ?Sized>(sink: &S, node: &Node) -> WorktreeResult<Hash> {
        let mut entries: Vec<TreeEntry> = Vec::new();

        // Subdirectories first (alphabetical via BTreeMap).
        for (name, child) in &node.children {
            let h = write_node(sink, child)?;
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
        Ok(sink.put(&bytes)?)
    }

    write_node(sink, &root)
}

/// Read a file from disk, hash it, store it, and return the
/// content-address of the resulting object.
///
/// Files at or below [`CHUNK_THRESHOLD`] become a single
/// [`Blob`](crate::object::Blob). Files above the threshold are split
/// with [`FastCdc::v1`]; each chunk is stored as a `Blob`, and the
/// file is represented by a [`ChunkedBlob`]
/// manifest whose hash is returned and lands in the parent tree. See
/// `SPEC-FASTCDC.md` and `SPEC-OBJECTS.md` §7.
///
/// # Errors
/// See [`WorktreeError`].
pub fn hash_file<S: ObjectSink + ?Sized>(sink: &S, path: &Path) -> WorktreeResult<Hash> {
    hash_file_with_metadata(sink, path).map(|(hash, _)| hash)
}

/// Read a regular file without following the final path component on
/// Unix, enforcing [`MAX_FILE_BYTES`] against both the opened handle's
/// metadata and the actual bytes read.
pub fn read_regular_file_bounded(path: &Path) -> WorktreeResult<(fs::Metadata, Vec<u8>)> {
    let mut file = open_regular_file(path)?;
    let meta = file.metadata()?;
    if !meta.file_type().is_file() {
        return Err(WorktreeError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path is not a regular file",
        )));
    }
    if meta.len() > MAX_FILE_BYTES {
        return Err(WorktreeError::FileTooLarge(path.to_path_buf()));
    }
    let initial_capacity = usize::try_from(meta.len().min(CHUNK_THRESHOLD))
        .map_err(|_| WorktreeError::FileTooLarge(path.to_path_buf()))?;
    let mut data = Vec::with_capacity(initial_capacity);
    file.by_ref()
        .take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut data)?;
    if u64::try_from(data.len()).unwrap_or(u64::MAX) > MAX_FILE_BYTES {
        return Err(WorktreeError::FileTooLarge(path.to_path_buf()));
    }
    Ok((meta, data))
}

fn hash_file_with_metadata<S: ObjectSink + ?Sized>(
    sink: &S,
    path: &Path,
) -> WorktreeResult<(Hash, fs::Metadata)> {
    let (meta, data) = read_regular_file_bounded(path)?;
    let hash = store_file_object(sink, &data)?;
    Ok((hash, meta))
}

/// Store a regular file's bytes as the canonical object and return its
/// content-address.
///
/// This is the single source of truth for how file content maps to an
/// object hash, shared by [`hash_file`], [`build_tree`], and `mkit add`
/// so all three agree on the representation:
///
/// - At or below [`CHUNK_THRESHOLD`]: a single
///   [`Blob`](crate::object::Blob).
/// - Above the threshold: `FastCdc::v1` chunks, each stored as a `Blob`,
///   addressed by a [`ChunkedBlob`] manifest.
///
/// # Errors
/// See [`WorktreeError`].
pub fn store_file_object<S: ObjectSink + ?Sized>(sink: &S, data: &[u8]) -> WorktreeResult<Hash> {
    if u64::try_from(data.len()).unwrap_or(u64::MAX) <= CHUNK_THRESHOLD {
        // Zero-copy: the canonical Blob bytes are `prologue ‖ data`
        // (pinned to serialize() by proptest), so the sink can hash and
        // write straight from the source buffer.
        let prologue = serialize::blob_prologue(data.len())?;
        return Ok(sink.put_parts(&[&prologue, data])?);
    }

    // Large file: split with FastCDC v1 via the public ChunkIterator,
    // store each chunk as a Blob, and assemble a ChunkedBlob manifest.
    // Per-manifest chunk count is bounded by serialize::MAX_CHUNKS
    // (1_000_000); MAX_FILE_BYTES (1 GiB) ÷ FastCDC MIN_SIZE (16 KiB)
    // = ~65k, well under the cap.
    let total_size = data.len() as u64;
    let chunks: Vec<Hash> = ChunkIterator::new(FastCdc::v1(), data)
        .map(|b| {
            let chunk = &data[b.offset..b.offset + b.length];
            let prologue = serialize::blob_prologue(chunk.len())?;
            Ok::<_, WorktreeError>(sink.put_parts(&[&prologue, chunk])?)
        })
        .collect::<Result<_, _>>()?;

    let manifest = Object::ChunkedBlob(ChunkedBlob {
        total_size,
        chunk_size: 0, // 0 = content-defined (FastCDC) per SPEC-OBJECTS §7
        chunks,
    });
    let manifest_bytes = serialize::serialize(&manifest)?;
    Ok(sink.put(&manifest_bytes)?)
}

/// Content-address `data` exactly as [`store_file_object`] would,
/// **without storing anything**. Computes per-chunk blob hashes via the
/// streaming hasher and assembles the `ChunkedBlob` manifest in memory.
/// Backs change detection (`status`, `rm`, restore safety checks) where
/// only the answer "would this file hash to X?" is needed — writing
/// objects there would turn a read-only query into store mutation.
/// Equivalence with `store_file_object` is pinned by test.
///
/// # Errors
/// [`WorktreeError::Object`] if a length exceeds the wire-format cap.
pub fn hash_file_object(data: &[u8]) -> WorktreeResult<Hash> {
    let hash_parts = |parts: &[&[u8]]| {
        let mut hasher = crate::hash::Hasher::new();
        for p in parts {
            hasher.update(p);
        }
        hasher.finalize()
    };
    if u64::try_from(data.len()).unwrap_or(u64::MAX) <= CHUNK_THRESHOLD {
        let prologue = serialize::blob_prologue(data.len())?;
        return Ok(hash_parts(&[&prologue, data]));
    }
    let total_size = data.len() as u64;
    let chunks: Vec<Hash> = ChunkIterator::new(FastCdc::v1(), data)
        .map(|b| {
            let chunk = &data[b.offset..b.offset + b.length];
            let prologue = serialize::blob_prologue(chunk.len())?;
            Ok::<_, WorktreeError>(hash_parts(&[&prologue, chunk]))
        })
        .collect::<Result<_, _>>()?;
    let manifest = Object::ChunkedBlob(ChunkedBlob {
        total_size,
        chunk_size: 0,
        chunks,
    });
    Ok(crate::hash::hash(&serialize::serialize(&manifest)?))
}

/// A file's mtime as nanoseconds since the Unix epoch, saturating; `0`
/// (the "no cache" sentinel) when the mtime is unavailable or predates
/// the epoch.
#[must_use]
pub fn mtime_nanos(meta: &fs::Metadata) -> u64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
}

/// The full stat-cache observation for `meta`, in index-entry field
/// order: `(mtime_ns, size, ino, ctime_ns)`. The single producer-side
/// dual of [`stat_matches`] — every site that records the cache uses
/// this so the recorded and compared field sets can never drift.
/// `ino`/`ctime_ns` are 0 (= don't check) on platforms without them.
#[must_use]
pub fn stat_cache_fields(meta: &fs::Metadata) -> (u64, u64, u64, u64) {
    #[cfg(unix)]
    let (ino, ctime_ns) = {
        use std::os::unix::fs::MetadataExt;
        let ctime_ns = u64::try_from(meta.ctime())
            .ok()
            .and_then(|s| s.checked_mul(1_000_000_000))
            .and_then(|ns| ns.checked_add(u64::try_from(meta.ctime_nsec()).unwrap_or(0)))
            .unwrap_or(0);
        (meta.ino(), ctime_ns)
    };
    #[cfg(not(unix))]
    let (ino, ctime_ns) = (0u64, 0u64);
    (mtime_nanos(meta), meta.len(), ino, ctime_ns)
}

/// True iff `meta` proves the worktree file behind `entry` is
/// byte-identical to `entry.object_hash` without reading it: the cached
/// mtime is nonzero (cache present, not racy-smudged) and equal, the
/// size is equal, the inode and ctime match when recorded (catching
/// replace-by-rename and `touch -r`-style timestamp restoration —
/// ctime cannot be set from userspace), and the live mode's exec class
/// matches the staged status. Symlink entries never stat-match — the
/// target re-read is cheap and `meta` semantics differ.
#[must_use]
pub fn stat_matches(entry: &crate::index::IndexEntry, meta: &fs::Metadata) -> bool {
    use crate::index::EntryStatus;
    if entry.mtime_ns == 0 || !meta.is_file() {
        return false;
    }
    let (mtime_ns, size, ino, ctime_ns) = stat_cache_fields(meta);
    if size != entry.size || mtime_ns != entry.mtime_ns {
        return false;
    }
    // ino/ctime: compare only when both sides have a value — a v2 entry
    // recorded on a platform without them (0) stays usable elsewhere.
    if entry.ino != 0 && ino != 0 && ino != entry.ino {
        return false;
    }
    if entry.ctime_ns != 0 && ctime_ns != 0 && ctime_ns != entry.ctime_ns {
        return false;
    }
    match entry.status {
        // On non-unix the exec bit is not observable in the filesystem
        // mode, so the recorded status is the source of truth — both
        // classes stat-match (previously Executable entries could never
        // match there, silently defeating the cache).
        #[cfg(not(unix))]
        EntryStatus::Blob | EntryStatus::Executable => true,
        #[cfg(unix)]
        EntryStatus::Blob => entry_mode_from_file_metadata(meta) == EntryMode::Blob,
        #[cfg(unix)]
        EntryStatus::Executable => entry_mode_from_file_metadata(meta) == EntryMode::Executable,
        EntryStatus::Symlink | EntryStatus::Removed | EntryStatus::Tree => false,
    }
}

/// Reassemble the full byte content of a `Blob` or `ChunkedBlob` object
/// addressed by `hash`.
///
/// A plain [`Blob`](crate::object::Blob) returns its bytes directly. A
/// [`ChunkedBlob`] manifest is reassembled
/// by concatenating each referenced chunk (every chunk must itself be a
/// `Blob`). This is the shared counterpart to [`store_file_object`] and
/// backs `mkit cat`, `mkit diff`, conflict rendering, and blame so they
/// all reconstruct large-file content the same way.
///
/// # Errors
/// - [`WorktreeError::Store`] if `hash` or any chunk is missing.
/// - [`WorktreeError::Io`] if `hash` (or a chunk) resolves to an object
///   that is neither a `Blob` nor a `ChunkedBlob` of `Blob`s.
pub fn read_blob<S: crate::store::ObjectSource + ?Sized>(
    store: &S,
    hash: &Hash,
) -> WorktreeResult<Vec<u8>> {
    match store.read_object(hash)? {
        Object::Blob(b) => Ok(b.data),
        Object::ChunkedBlob(manifest) => {
            let mut data = Vec::with_capacity(usize::try_from(manifest.total_size).unwrap_or(0));
            for chunk in &manifest.chunks {
                match store.read_object(chunk)? {
                    Object::Blob(b) => data.extend_from_slice(&b.data),
                    other => {
                        return Err(WorktreeError::Io(io::Error::other(format!(
                            "chunk {} is not a blob (got {})",
                            crate::hash::to_hex(chunk),
                            other.object_type().name()
                        ))));
                    }
                }
            }
            Ok(data)
        }
        other => Err(WorktreeError::Io(io::Error::other(format!(
            "object {} is not a blob (got {})",
            crate::hash::to_hex(hash),
            other.object_type().name()
        )))),
    }
}

#[cfg(unix)]
fn open_regular_file(path: &Path) -> io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(not(unix))]
fn open_regular_file(path: &Path) -> io::Result<fs::File> {
    // Best-effort direct-symlink rejection on platforms without the
    // Unix O_NOFOLLOW path. This does not close the swap race, but it
    // keeps normal symlinks from being treated as regular files.
    let meta = path.symlink_metadata()?;
    if !meta.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path is not a regular file",
        ));
    }
    fs::File::open(path)
}

#[cfg(unix)]
fn entry_mode_from_file_metadata(meta: &fs::Metadata) -> EntryMode {
    use std::os::unix::fs::PermissionsExt;

    if meta.permissions().mode() & 0o111 != 0 {
        EntryMode::Executable
    } else {
        EntryMode::Blob
    }
}

#[cfg(not(unix))]
fn entry_mode_from_file_metadata(_meta: &fs::Metadata) -> EntryMode {
    EntryMode::Blob
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

    #[cfg(unix)]
    #[test]
    fn build_tree_marks_executable_regular_files() {
        use std::os::unix::fs::PermissionsExt;

        let (_sd, store) = fresh_store();
        let work = TempDir::new().unwrap();
        let script = work.path().join("run.sh");
        fs::write(&script, b"#!/bin/sh\n").unwrap();
        let mut perms = fs::metadata(&script).unwrap().permissions();
        perms.set_mode(perms.mode() | 0o111);
        fs::set_permissions(&script, perms).unwrap();

        let h = build_tree(&store, work.path()).unwrap();
        let Object::Tree(t) = store.read_object(&h).unwrap() else {
            panic!("expected tree");
        };
        assert_eq!(t.entries[0].name.as_slice(), b"run.sh");
        assert_eq!(t.entries[0].mode, EntryMode::Executable);
    }

    #[cfg(unix)]
    #[test]
    fn build_tree_rejects_invalid_entry_name_before_writing_tree() {
        let (_sd, store) = fresh_store();
        let work = TempDir::new().unwrap();
        fs::write(work.path().join("bad."), b"bad name").unwrap();

        let err = build_tree(&store, work.path()).unwrap_err();
        assert!(matches!(err, WorktreeError::Io(_)));
    }

    #[cfg(unix)]
    #[test]
    fn hash_file_rejects_final_component_symlink() {
        use std::os::unix::fs::symlink;

        let (_sd, store) = fresh_store();
        let work = TempDir::new().unwrap();
        fs::write(work.path().join("target.txt"), b"target").unwrap();
        symlink("target.txt", work.path().join("link.txt")).unwrap();

        let err = hash_file(&store, &work.path().join("link.txt")).unwrap_err();
        assert!(matches!(err, WorktreeError::Io(_)));
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
    fn large_file_becomes_chunked_blob() {
        // File > CHUNK_THRESHOLD should land as a ChunkedBlob manifest
        // pointing at one Blob per FastCDC chunk. We pseudo-randomize
        // the buffer so FastCDC sees real boundary candidates instead
        // of running the entire file as one max-sized chunk.
        let (_sd, store) = fresh_store();
        let work = TempDir::new().unwrap();
        let n = usize::try_from(CHUNK_THRESHOLD).unwrap() + 256 * 1024;
        let mut big = Vec::with_capacity(n);
        let mut state: u64 = 0x00C0_FFEE;
        for _ in 0..n {
            // splitmix64-ish; same construction as the gear table seed.
            state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^= z >> 31;
            big.push((z & 0xFF) as u8);
        }
        fs::write(work.path().join("big.bin"), &big).unwrap();

        let tree_hash = build_tree(&store, work.path()).unwrap();
        let Object::Tree(t) = store.read_object(&tree_hash).unwrap() else {
            panic!("expected tree");
        };
        assert_eq!(t.entries.len(), 1);

        let entry_hash = t.entries[0].object_hash;
        let entry = store.read_object(&entry_hash).unwrap();
        let Object::ChunkedBlob(manifest) = entry else {
            panic!("expected chunked_blob, got {entry:?}");
        };

        assert_eq!(manifest.total_size, n as u64);
        assert_eq!(manifest.chunk_size, 0, "0 = content-defined (FastCDC)");
        assert!(!manifest.chunks.is_empty());
        // Every chunk hash must resolve to a Blob in the store, and
        // the concatenation must reproduce the original file bytes.
        let mut reassembled: Vec<u8> = Vec::with_capacity(n);
        for h in &manifest.chunks {
            let Object::Blob(b) = store.read_object(h).unwrap() else {
                panic!("chunk did not resolve to a Blob");
            };
            reassembled.extend_from_slice(&b.data);
        }
        assert_eq!(reassembled, big, "chunks must round-trip the source");
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
            mtime_ns: 0,
            size: 0,
            ino: 0,
            ctime_ns: 0,
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
            mtime_ns: 0,
            size: 0,
            ino: 0,
            ctime_ns: 0,
        });
        idx.entries.push(IndexEntry {
            path: "subdir/b.txt".into(),
            status: EntryStatus::Blob,
            object_hash: b,
            mtime_ns: 0,
            size: 0,
            ino: 0,
            ctime_ns: 0,
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
            mtime_ns: 0,
            size: 0,
            ino: 0,
            ctime_ns: 0,
        });
        idx.entries.push(IndexEntry {
            path: "drop.txt".into(),
            status: EntryStatus::Removed,
            object_hash: [0; 32],
            mtime_ns: 0,
            size: 0,
            ino: 0,
            ctime_ns: 0,
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
            mtime_ns: 0,
            size: 0,
            ino: 0,
            ctime_ns: 0,
        });
        idx.entries.push(IndexEntry {
            path: "link".into(),
            status: EntryStatus::Symlink,
            object_hash: link,
            mtime_ns: 0,
            size: 0,
            ino: 0,
            ctime_ns: 0,
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
            mtime_ns: 0,
            size: 0,
            ino: 0,
            ctime_ns: 0,
        });
        idx.entries.push(IndexEntry {
            path: "a.txt".into(),
            status: EntryStatus::Blob,
            object_hash: a,
            mtime_ns: 0,
            size: 0,
            ino: 0,
            ctime_ns: 0,
        });
        idx.entries.push(IndexEntry {
            path: "m.txt".into(),
            status: EntryStatus::Blob,
            object_hash: a,
            mtime_ns: 0,
            size: 0,
            ino: 0,
            ctime_ns: 0,
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
            mtime_ns: 0,
            size: 0,
            ino: 0,
            ctime_ns: 0,
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
            mtime_ns: 0,
            size: 0,
            ino: 0,
            ctime_ns: 0,
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
            mtime_ns: 0,
            size: 0,
            ino: 0,
            ctime_ns: 0,
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
            mtime_ns: 0,
            size: 0,
            ino: 0,
            ctime_ns: 0,
        });
        idx.entries.push(IndexEntry {
            path: "dir/b.txt".into(),
            status: EntryStatus::Blob,
            object_hash: b,
            mtime_ns: 0,
            size: 0,
            ino: 0,
            ctime_ns: 0,
        });
        idx.entries.push(IndexEntry {
            path: "dir/c.txt".into(),
            status: EntryStatus::Blob,
            object_hash: c,
            mtime_ns: 0,
            size: 0,
            ino: 0,
            ctime_ns: 0,
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
            mtime_ns: 0,
            size: 0,
            ino: 0,
            ctime_ns: 0,
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
            mtime_ns: 0,
            size: 0,
            ino: 0,
            ctime_ns: 0,
        });
        idx.entries.push(IndexEntry {
            path: "a/b".into(),
            status: EntryStatus::Blob,
            object_hash: h,
            mtime_ns: 0,
            size: 0,
            ino: 0,
            ctime_ns: 0,
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
            mtime_ns: 0,
            size: 0,
            ino: 0,
            ctime_ns: 0,
        });
        idx.entries.push(IndexEntry {
            path: "a".into(),
            status: EntryStatus::Blob,
            object_hash: h,
            mtime_ns: 0,
            size: 0,
            ino: 0,
            ctime_ns: 0,
        });
        assert!(build_tree_from_index(&store, &idx).is_err());
    }

    #[test]
    fn from_index_rejects_duplicate_exact_path() {
        let (_sd, store) = fresh_store();
        let a = write_blob(&store, b"a");
        let b = write_blob(&store, b"b");
        let mut idx = Index::new();
        idx.entries.push(IndexEntry {
            path: "same.txt".into(),
            status: EntryStatus::Blob,
            object_hash: a,
            mtime_ns: 0,
            size: 0,
            ino: 0,
            ctime_ns: 0,
        });
        idx.entries.push(IndexEntry {
            path: "same.txt".into(),
            status: EntryStatus::Blob,
            object_hash: b,
            mtime_ns: 0,
            size: 0,
            ino: 0,
            ctime_ns: 0,
        });

        let err = build_tree_from_index(&store, &idx).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("duplicate index path"), "got: {msg}");
    }

    #[test]
    fn from_index_rejects_duplicate_removed_and_live_path() {
        let (_sd, store) = fresh_store();
        let h = write_blob(&store, b"live");
        let mut idx = Index::new();
        idx.entries.push(IndexEntry {
            path: "same.txt".into(),
            status: EntryStatus::Removed,
            object_hash: [0; 32],
            mtime_ns: 0,
            size: 0,
            ino: 0,
            ctime_ns: 0,
        });
        idx.entries.push(IndexEntry {
            path: "same.txt".into(),
            status: EntryStatus::Blob,
            object_hash: h,
            mtime_ns: 0,
            size: 0,
            ino: 0,
            ctime_ns: 0,
        });

        let err = build_tree_from_index(&store, &idx).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("duplicate index path"), "got: {msg}");
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
            mtime_ns: 0,
            size: 0,
            ino: 0,
            ctime_ns: 0,
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
            mtime_ns: 0,
            size: 0,
            ino: 0,
            ctime_ns: 0,
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
            mtime_ns: 0,
            size: 0,
            ino: 0,
            ctime_ns: 0,
        });

        let err = build_tree_from_index(&store, &idx).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("non-blob"),
            "expected non-blob index object error, got: {msg}"
        );
    }

    /// A file entry whose object is a `ChunkedBlob` (the canonical
    /// representation for > `CHUNK_THRESHOLD` content) is accepted by the
    /// commit/index tree builder, NOT rejected as "non-blob" (#203). The
    /// resulting tree carries an `EntryMode::Blob` pointing at the
    /// manifest, exactly as `build_tree` produces for a large worktree
    /// file.
    #[test]
    fn from_index_accepts_chunked_blob_for_file_entry() {
        let (_sd, store) = fresh_store();
        // Build a > CHUNK_THRESHOLD file's content and store it via the
        // shared object path (lands as a ChunkedBlob).
        let n = usize::try_from(CHUNK_THRESHOLD).unwrap() + 256 * 1024;
        let mut big = Vec::with_capacity(n);
        let mut state: u64 = 0x00C0_FFEE;
        for _ in 0..n {
            state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^= z >> 31;
            big.push((z & 0xFF) as u8);
        }
        let chunked_hash = store_file_object(&store, &big).unwrap();
        assert!(
            matches!(
                store.read_object(&chunked_hash).unwrap(),
                Object::ChunkedBlob(_)
            ),
            "fixture must be a ChunkedBlob"
        );

        let mut idx = Index::new();
        idx.entries.push(IndexEntry {
            path: "big.bin".into(),
            status: EntryStatus::Blob,
            object_hash: chunked_hash,
            mtime_ns: 0,
            size: 0,
            ino: 0,
            ctime_ns: 0,
        });
        let root = build_tree_from_index(&store, &idx).unwrap();
        let Object::Tree(t) = store.read_object(&root).unwrap() else {
            panic!("expected tree");
        };
        assert_eq!(t.entries.len(), 1);
        assert_eq!(t.entries[0].name, b"big.bin");
        assert_eq!(t.entries[0].mode, EntryMode::Blob);
        assert_eq!(t.entries[0].object_hash, chunked_hash);
        // Reassembly via the shared helper round-trips the source bytes.
        assert_eq!(read_blob(&store, &chunked_hash).unwrap(), big);
    }

    /// A symlink entry MUST still address a single `Blob` (its target
    /// path); a `ChunkedBlob` under a symlink entry is rejected.
    #[test]
    fn from_index_rejects_chunked_blob_for_symlink_entry() {
        let (_sd, store) = fresh_store();
        let n = usize::try_from(CHUNK_THRESHOLD).unwrap() + 256 * 1024;
        let big = vec![0xABu8; n];
        let chunked_hash = store_file_object(&store, &big).unwrap();
        let mut idx = Index::new();
        idx.entries.push(IndexEntry {
            path: "link".into(),
            status: EntryStatus::Symlink,
            object_hash: chunked_hash,
            mtime_ns: 0,
            size: 0,
            ino: 0,
            ctime_ns: 0,
        });
        let err = build_tree_from_index(&store, &idx).unwrap_err();
        assert!(format!("{err}").contains("non-blob"));
    }

    // ---- batched / zero-copy ingest ----------------------------------

    /// Same chunked input through a batch and through the plain store
    /// must produce the identical manifest hash and identical readable
    /// bytes — this transitively pins the zero-copy `put_parts` chunk
    /// path to the golden `ChunkedBlob` vectors.
    #[test]
    fn store_file_object_via_batch_equals_via_store() {
        // 3 MiB of varied bytes: above CHUNK_THRESHOLD, multiple chunks.
        let data: Vec<u8> = (0..3 * 1024 * 1024u32)
            .map(|i| u8::try_from((i.wrapping_mul(2_654_435_761)) % 251).unwrap())
            .collect();

        let (_d1, store1) = fresh_store();
        let h_store = store_file_object(&store1, &data).unwrap();

        let (_d2, store2) = fresh_store();
        let batch = store2.batch();
        let h_batch = store_file_object(&batch, &data).unwrap();
        batch.commit().unwrap();

        assert_eq!(h_store, h_batch, "sink choice must not change hashes");
        assert_eq!(
            read_blob(&store1, &h_store).unwrap(),
            read_blob(&store2, &h_batch).unwrap(),
        );

        // Small (single-blob) shape too.
        let small = b"under the chunk threshold";
        let h1 = store_file_object(&store1, small).unwrap();
        let batch2 = store2.batch();
        let h2 = store_file_object(&batch2, small).unwrap();
        batch2.commit().unwrap();
        assert_eq!(h1, h2);
    }

    /// Committing a staged index must cost exactly one full flush no
    /// matter how many tree objects it materialises.
    #[test]
    fn build_tree_from_index_with_batch_single_flush() {
        use crate::batch::testing::{Ev, RecordingSyncer};
        use crate::index::{EntryStatus, Index, IndexEntry};
        use std::sync::Arc;

        let (_sd, mut store) = fresh_store();
        // Stage 20 files across nested dirs (many tree objects).
        let mut idx = Index::default();
        for i in 0..20 {
            let blob = Object::Blob(crate::object::Blob {
                data: format!("file {i}").into_bytes(),
            });
            let bytes = serialize::serialize(&blob).unwrap();
            let h = store.write(&bytes).unwrap();
            idx.entries.push(IndexEntry {
                status: EntryStatus::Blob,
                object_hash: h,
                path: format!("d{}/sub/f{i}.txt", i % 5),
                mtime_ns: 0,
                size: 0,
                ino: 0,
                ctime_ns: 0,
            });
        }

        let rec = Arc::new(RecordingSyncer::default());
        store.set_syncer(rec.clone());

        let batch = store.batch();
        let tree_h = build_tree_from_index_with(&store, &batch, &idx).unwrap();
        batch.commit().unwrap();

        let fulls = rec
            .events()
            .iter()
            .filter(|e| matches!(e, Ev::Full(_)))
            .count();
        assert_eq!(fulls, 2, "tree materialisation flush cost must be constant");
        assert!(store.read_object(&tree_h).is_ok());

        // Equivalence: the per-object path yields the same root hash.
        let (_sd2, store2) = fresh_store();
        for i in 0..20 {
            let blob = Object::Blob(crate::object::Blob {
                data: format!("file {i}").into_bytes(),
            });
            store2.write(&serialize::serialize(&blob).unwrap()).unwrap();
        }
        assert_eq!(tree_h, build_tree_from_index(&store2, &idx).unwrap());
    }

    // ---- pure hashing + stat cache ------------------------------------

    /// `hash_file_object` must agree with `store_file_object` on every
    /// input shape (single blob, chunked) without touching any store.
    #[test]
    fn hash_file_object_equals_store_file_object() {
        let threshold = usize::try_from(CHUNK_THRESHOLD).unwrap();
        for len in [0usize, 1, 1024, threshold, 3 * 1024 * 1024] {
            let data: Vec<u8> = (0..len)
                .map(|i| u8::try_from((i * 31 + 7) % 251).unwrap())
                .collect();
            let (_sd, store) = fresh_store();
            let stored = store_file_object(&store, &data).unwrap();
            let pure = hash_file_object(&data).unwrap();
            assert_eq!(stored, pure, "len {len}: pure hash must match stored hash");
        }
    }

    #[test]
    fn hash_file_object_writes_nothing() {
        let (_sd, store) = fresh_store();
        let data = vec![0xAB; 2 * 1024 * 1024]; // chunked shape
        let _ = hash_file_object(&data).unwrap();
        assert!(
            store.iter_object_hashes().unwrap().is_empty(),
            "pure hashing must not create objects"
        );
    }

    fn meta_of(p: &Path) -> fs::Metadata {
        p.symlink_metadata().unwrap()
    }

    #[test]
    fn stat_matches_requires_nonzero_mtime_and_equal_fields() {
        let work = TempDir::new().unwrap();
        let f = work.path().join("a.txt");
        fs::write(&f, b"hello").unwrap();
        let meta = meta_of(&f);
        let entry = crate::index::IndexEntry {
            path: "a.txt".into(),
            status: crate::index::EntryStatus::Blob,
            object_hash: crate::hash::hash(b"irrelevant"),
            mtime_ns: mtime_nanos(&meta),
            size: meta.len(),
            ino: 0,
            ctime_ns: 0,
        };
        assert!(stat_matches(&entry, &meta));

        // Zero mtime sentinel: never matches.
        let mut zeroed = entry.clone();
        zeroed.mtime_ns = 0;
        assert!(!stat_matches(&zeroed, &meta), "zero sentinel must re-hash");

        // Size mismatch.
        let mut wrong_size = entry.clone();
        wrong_size.size += 1;
        assert!(!stat_matches(&wrong_size, &meta));

        // Mtime mismatch.
        let mut wrong_time = entry.clone();
        wrong_time.mtime_ns ^= 1;
        assert!(!stat_matches(&wrong_time, &meta));
    }

    #[cfg(unix)]
    #[test]
    fn stat_matches_detects_exec_bit_flip() {
        use std::os::unix::fs::PermissionsExt;
        let work = TempDir::new().unwrap();
        let f = work.path().join("run.sh");
        fs::write(&f, b"#!/bin/sh\n").unwrap();
        let meta = meta_of(&f);
        let entry = crate::index::IndexEntry {
            path: "run.sh".into(),
            status: crate::index::EntryStatus::Blob,
            object_hash: crate::hash::hash(b"x"),
            mtime_ns: mtime_nanos(&meta),
            size: meta.len(),
            ino: 0,
            ctime_ns: 0,
        };
        assert!(stat_matches(&entry, &meta));
        // chmod +x without touching content, then restore the mtime so
        // ONLY the mode differs — the exec-class check must still fire.
        let mtime = meta.modified().unwrap();
        fs::set_permissions(&f, fs::Permissions::from_mode(0o755)).unwrap();
        let f_handle = fs::File::options().write(true).open(&f).unwrap();
        f_handle
            .set_times(fs::FileTimes::new().set_modified(mtime))
            .unwrap();
        drop(f_handle);
        let meta2 = meta_of(&f);
        assert_eq!(mtime_nanos(&meta2), entry.mtime_ns, "mtime restored");
        assert!(
            !stat_matches(&entry, &meta2),
            "exec-bit flip must invalidate a Blob-status cache hit"
        );
    }

    /// The killer observable: a stat-matched file is NEVER opened. With
    /// the file made unreadable (chmod 000), the tree build still
    /// succeeds and reuses the staged hash.
    #[cfg(unix)]
    #[test]
    fn build_tree_reuses_hash_on_stat_match_without_reading_file() {
        use std::os::unix::fs::PermissionsExt;
        let (_sd, store) = fresh_store();
        let work = TempDir::new().unwrap();
        let f = work.path().join("locked.txt");
        fs::write(&f, b"cached content").unwrap();

        let staged_hash = store_file_object(&store, b"cached content").unwrap();
        let meta = meta_of(&f);
        let idx = crate::index::Index {
            entries: vec![crate::index::IndexEntry {
                path: "locked.txt".into(),
                status: crate::index::EntryStatus::Blob,
                object_hash: staged_hash,
                mtime_ns: mtime_nanos(&meta),
                size: meta.len(),
                ino: 0,
                ctime_ns: 0,
            }],
        };

        // Make any read attempt error out.
        fs::set_permissions(&f, fs::Permissions::from_mode(0o000)).unwrap();
        let result = build_tree_filtered(&store, work.path(), Some(&idx));
        fs::set_permissions(&f, fs::Permissions::from_mode(0o644)).unwrap();
        let tree_h = result.expect("stat match must skip the file read");

        let Object::Tree(t) = store.read_object(&tree_h).unwrap() else {
            panic!("expected tree");
        };
        assert_eq!(t.entries.len(), 1);
        assert_eq!(t.entries[0].object_hash, staged_hash);

        // Same content hashed normally yields the identical tree.
        let (_sd2, store2) = fresh_store();
        let f2_dir = TempDir::new().unwrap();
        fs::write(f2_dir.path().join("locked.txt"), b"cached content").unwrap();
        let plain = build_tree(&store2, f2_dir.path()).unwrap();
        assert_eq!(plain, tree_h, "cache hit must not change tree hashes");
    }

    /// Replace-by-rename with preserved mtime+size must be caught by
    /// the inode check: the replacement file has a different ino.
    #[cfg(unix)]
    #[test]
    fn stat_mismatch_on_inode_rehashes() {
        let work = TempDir::new().unwrap();
        let f = work.path().join("swap.txt");
        fs::write(&f, b"original").unwrap();
        let meta = meta_of(&f);
        let (mtime_ns, size, ino, ctime_ns) = stat_cache_fields(&meta);
        let entry = crate::index::IndexEntry {
            path: "swap.txt".into(),
            status: crate::index::EntryStatus::Blob,
            object_hash: crate::hash::hash(b"original"),
            mtime_ns,
            size,
            ino,
            ctime_ns,
        };
        assert!(stat_matches(&entry, &meta));

        // Same-size replacement via rename with timestamps restored —
        // the tar -x / rsync -t / mv-of-prepared-file shape.
        let staging = work.path().join(".swap.new");
        fs::write(&staging, b"REPLACED").unwrap(); // same 8-byte size
        let fh = fs::File::options().write(true).open(&staging).unwrap();
        fh.set_times(fs::FileTimes::new().set_modified(meta.modified().unwrap()))
            .unwrap();
        drop(fh);
        fs::rename(&staging, &f).unwrap();
        let meta2 = meta_of(&f);
        assert_eq!(meta2.len(), entry.size, "size preserved by the swap");
        assert!(
            !stat_matches(&entry, &meta2),
            "a renamed-in replacement must not stat-match (ino differs)"
        );
    }

    /// A recorded ctime that disagrees with the live one must miss —
    /// ctime cannot be restored from userspace, so `touch -r` after an
    /// in-place edit is caught even when mtime+size+ino all match.
    #[test]
    fn stat_mismatch_on_ctime_rehashes() {
        let work = TempDir::new().unwrap();
        let f = work.path().join("touched.txt");
        fs::write(&f, b"content").unwrap();
        let meta = meta_of(&f);
        let (mtime_ns, size, ino, ctime_ns) = stat_cache_fields(&meta);
        if ctime_ns == 0 {
            return; // platform without ctime — check not applicable
        }
        let entry = crate::index::IndexEntry {
            path: "touched.txt".into(),
            status: crate::index::EntryStatus::Blob,
            object_hash: crate::hash::hash(b"content"),
            mtime_ns,
            size,
            ino,
            ctime_ns: ctime_ns ^ 1,
        };
        assert!(
            !stat_matches(&entry, &meta),
            "ctime disagreement must invalidate the cache"
        );
    }

    /// The worktree walk must report hash-time observations for entries
    /// whose cache was absent but whose content re-hashed to the staged
    /// hash — and the observation must carry the fd-stat, enabling the
    /// status command to heal the cache soundly.
    #[test]
    fn build_tree_observed_reports_clean_rehashes() {
        let (_sd, store) = fresh_store();
        let work = TempDir::new().unwrap();
        fs::write(work.path().join("clean.txt"), b"clean bytes").unwrap();
        fs::write(work.path().join("dirty.txt"), b"new content").unwrap();

        let clean_hash = store_file_object(&store, b"clean bytes").unwrap();
        let stale_hash = crate::hash::hash(b"old content");
        let idx = crate::index::Index {
            entries: vec![
                crate::index::IndexEntry {
                    path: "clean.txt".into(),
                    status: crate::index::EntryStatus::Blob,
                    object_hash: clean_hash,
                    mtime_ns: 0, // racy-smudged: forces a re-hash
                    size: 0,
                    ino: 0,
                    ctime_ns: 0,
                },
                crate::index::IndexEntry {
                    path: "dirty.txt".into(),
                    status: crate::index::EntryStatus::Blob,
                    object_hash: stale_hash,
                    mtime_ns: 0,
                    size: 0,
                    ino: 0,
                    ctime_ns: 0,
                },
            ],
        };
        let mut obs = Vec::new();
        build_tree_filtered_observed(&store, work.path(), Some(&idx), &mut obs).unwrap();

        assert_eq!(obs.len(), 1, "only the verified-clean entry is observed");
        let o = &obs[0];
        assert_eq!(o.path, "clean.txt");
        assert_eq!(o.object_hash, clean_hash);
        let meta = meta_of(&work.path().join("clean.txt"));
        let (mtime_ns, size, _ino, _ctime) = stat_cache_fields(&meta);
        assert_eq!(o.mtime_ns, mtime_ns, "observation carries the fd stat");
        assert_eq!(o.size, size);
    }

    /// A stat MISMATCH must fall back to re-hashing the live content.
    #[test]
    fn build_tree_rehashes_on_stat_mismatch() {
        let (_sd, store) = fresh_store();
        let work = TempDir::new().unwrap();
        let f = work.path().join("changed.txt");
        fs::write(&f, b"new content").unwrap();
        let stale_hash = crate::hash::hash(b"not the real object");
        let meta = meta_of(&f);
        let idx = crate::index::Index {
            entries: vec![crate::index::IndexEntry {
                path: "changed.txt".into(),
                status: crate::index::EntryStatus::Blob,
                object_hash: stale_hash,
                // size deliberately wrong → mismatch → re-hash.
                mtime_ns: mtime_nanos(&meta),
                size: meta.len() + 1,
                ino: 0,
                ctime_ns: 0,
            }],
        };
        let tree_h = build_tree_filtered(&store, work.path(), Some(&idx)).unwrap();
        let Object::Tree(t) = store.read_object(&tree_h).unwrap() else {
            panic!("expected tree");
        };
        assert_ne!(
            t.entries[0].object_hash, stale_hash,
            "mismatched stat must not reuse the stale hash"
        );
        assert_eq!(
            t.entries[0].object_hash,
            store_file_object(&store, b"new content").unwrap()
        );
    }
}
