//! Restore.
//!
//! Materialises a stored [`Tree`](crate::object::Tree) into a target
//! directory: writes blobs as files, recurses into subtrees as
//! directories, creates symlinks for symlink entries, and (when
//! `clean=true`) deletes anything in the target dir that is not in the
//! tree (preserving `.mkit/` and `.git/`).
//!
//! ### Symlink invariant
//!
//! Like `worktree::build_tree`, this module **never follows external
//! symlinks**. Symlinks created here always have a relative,
//! `..`-free target — checked by [`worktree::validate_symlink_target`]
//! before the symlink is materialised.
//!
//! ### Sparse checkout
//!
//! When `RestoreOptions.sparse_patterns` is set, only files whose
//! computed full path (relative to the root) matches the pattern set
//! are restored. Pattern grammar:
//!
//! - Lines beginning with `#` are comments. Empty lines are skipped.
//! - Leading `!` negates the pattern.
//! - Trailing `/` makes the pattern dir-only.
//! - Patterns are evaluated in order; **last match wins**. No match =
//!   excluded.
//! - Bare names without a `/` also match against the basename of
//!   nested files.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::hash::Hash;
use crate::ignore::{self, IgnoreList};
use crate::object::{self, EntryMode, Object, TreeEntry};
use crate::store::{MAX_TREE_DEPTH, ObjectStore};
use crate::worktree;

const SPARSE_FILE: &str = ".mkit/sparse-checkout";
const MAX_SPARSE_BYTES: u64 = 1024 * 1024;

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Errors raised by this module.
#[derive(Debug, thiserror::Error)]
pub enum RestoreError {
    #[error("requested object is not a tree")]
    NotATree,
    #[error("requested object is not a blob or chunked-blob")]
    NotABlob,
    #[error("symlink target '{0}' is invalid (absolute or contains '..')")]
    InvalidSymlinkTarget(String),
    #[error("path '{0}' is occupied by something other than a directory")]
    NotADirectory(PathBuf),
    #[error("path component is not valid UTF-8")]
    InvalidUtf8,
    #[error("tree nesting exceeds {} levels", MAX_TREE_DEPTH)]
    TreeTooDeep,
    #[error(transparent)]
    Object(#[from] object::MkitError),
    #[error(transparent)]
    Store(#[from] crate::store::StoreError),
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Result alias.
pub type RestoreResult<T> = Result<T, RestoreError>;

/// One sparse-checkout pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SparsePattern {
    pub pattern: String,
    pub negated: bool,
    pub dir_only: bool,
}

/// Options for [`restore_tree`].
#[derive(Debug, Clone)]
pub struct RestoreOptions {
    /// If `true`, delete anything in the target dir that is not in the
    /// tree (preserving `.mkit/` and `.git/`). Default `true`.
    pub clean: bool,
    /// If `Some`, only restore entries whose path matches the patterns.
    pub sparse_patterns: Option<Vec<SparsePattern>>,
}

impl Default for RestoreOptions {
    fn default() -> Self {
        Self {
            clean: true,
            sparse_patterns: None,
        }
    }
}

impl RestoreOptions {
    /// Same as `Default::default()`. Provided as a non-trait constructor
    /// so call sites that prefer an explicit name can use it.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

/// Parse the contents of a `.mkit/sparse-checkout` file into patterns.
#[must_use]
pub fn parse_sparse_patterns(content: &str) -> Vec<SparsePattern> {
    let mut out = Vec::new();
    for raw in content.split('\n') {
        let line = raw.trim_end_matches(['\r', ' ']);
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (negated, rest) = if let Some(stripped) = line.strip_prefix('!') {
            (true, stripped)
        } else {
            (false, line)
        };
        let (dir_only, pat) = if let Some(stripped) = rest.strip_suffix('/') {
            (true, stripped)
        } else {
            (false, rest)
        };
        if pat.is_empty() {
            continue;
        }
        out.push(SparsePattern {
            pattern: pat.to_string(),
            negated,
            dir_only,
        });
    }
    out
}

/// True iff `path` matches at least one (non-negated, last-match-wins)
/// pattern in `patterns`.
#[must_use]
pub fn matches_sparse(patterns: &[SparsePattern], path: &str, is_dir: bool) -> bool {
    let mut matched = false;
    for pat in patterns {
        if path_matches_pattern(&pat.pattern, path) {
            if pat.dir_only && !is_dir {
                let pat_stripped = pat.pattern.strip_suffix('/').unwrap_or(&pat.pattern);
                if pat_stripped == path {
                    continue;
                }
            }
            matched = !pat.negated;
        }
    }
    matched
}

/// True iff a directory at `dir_prefix` could contain matched
/// descendants. Used to short-circuit recursion under sparse mode.
#[must_use]
pub fn could_match_descendant(patterns: &[SparsePattern], dir_prefix: &str) -> bool {
    for pat in patterns {
        if pat.negated {
            continue;
        }
        if pat.pattern.starts_with(dir_prefix) {
            return true;
        }
        if dir_prefix.starts_with(&pat.pattern) {
            return true;
        }
        if !dir_prefix.is_empty()
            && !dir_prefix.ends_with('/')
            && pat.pattern.len() > dir_prefix.len()
            && pat.pattern.starts_with(dir_prefix)
            && pat.pattern.as_bytes()[dir_prefix.len()] == b'/'
        {
            return true;
        }
    }
    false
}

/// Load patterns from `<repo_root>/.mkit/sparse-checkout`. Returns
/// `Ok(None)` if the file does not exist or has zero patterns.
///
/// # Errors
/// - [`RestoreError::Io`] for filesystem failures other than "not found".
pub fn load_sparse_checkout(repo_root: &Path) -> RestoreResult<Option<Vec<SparsePattern>>> {
    let path = repo_root.join(SPARSE_FILE);
    let meta = match fs::metadata(&path) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(RestoreError::Io(e)),
    };
    if meta.len() > MAX_SPARSE_BYTES {
        return Err(RestoreError::Io(io::Error::other(
            "sparse-checkout too large",
        )));
    }
    let raw = fs::read_to_string(&path)?;
    let patterns = parse_sparse_patterns(&raw);
    if patterns.is_empty() {
        Ok(None)
    } else {
        Ok(Some(patterns))
    }
}

/// Write a sparse-checkout file (one pattern per line). Atomic on the
/// destination.
///
/// # Errors
/// - [`RestoreError::Io`] for filesystem failures.
pub fn write_sparse_checkout(repo_root: &Path, lines: &[&str]) -> RestoreResult<()> {
    let mkit_dir = repo_root.join(".mkit");
    fs::create_dir_all(&mkit_dir)?;
    let mut buf = String::new();
    for l in lines {
        buf.push_str(l);
        buf.push('\n');
    }
    let path = repo_root.join(SPARSE_FILE);
    crate::atomic::write_atomic(&path, buf.as_bytes(), true)?;
    Ok(())
}

fn path_matches_pattern(pattern: &str, path: &str) -> bool {
    let pat = pattern.strip_suffix('/').unwrap_or(pattern);
    if pat == path {
        return true;
    }
    if path.len() > pat.len() && path.starts_with(pat) && path.as_bytes()[pat.len()] == b'/' {
        return true;
    }
    if !pat.contains('/')
        && let Some(last) = path.rfind('/')
    {
        let basename = &path[last + 1..];
        if basename == pat {
            return true;
        }
    }
    false
}

/// Summary of a [`restore_tree_to_worktree`] call. Counts mirror the
/// material the caller (`mkit checkout`) prints to the user, and the
/// integration tests assert on these counts directly so the CLI output
/// is trustable without scraping stdout.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RestoreReport {
    /// Number of regular / executable files materialised.
    pub files_written: u32,
    /// Number of symlinks materialised.
    pub symlinks_written: u32,
    /// Number of directories created (or that already existed as dirs).
    pub directories_created: u32,
    /// Number of tree entries skipped because they matched `.mkitignore`.
    pub skipped_by_ignore: u32,
}

/// Materialise `tree_hash` into `root` as a working tree.
///
/// Thin wrapper around [`restore_tree`] that additionally:
/// 1. Loads `<root>/.mkitignore` and skips any matched entries — the
///    checkout path MUST NOT overwrite files the user deliberately
///    ignored (editor swapfiles, local-only build artefacts, …).
/// 2. Returns a [`RestoreReport`] with counts the `mkit checkout` UX
///    prints for the user.
///
/// Symlink safety is inherited from [`restore_tree`] /
/// [`worktree::validate_symlink_target`]: targets are validated BEFORE
/// the symlink is created, and any target that is absolute or contains
/// `..` is rejected with [`RestoreError::InvalidSymlinkTarget`]. The
/// net effect is that no symlink produced by this function can point
/// outside `root`.
///
/// # Errors
///
/// Same variants as [`restore_tree`]. [`RestoreError::InvalidSymlinkTarget`]
/// on a rejected target is the load-bearing "outside-of-root" check.
pub fn restore_tree_to_worktree(
    store: &ObjectStore,
    tree: &Hash,
    root: &Path,
    opts: &RestoreOptions,
) -> RestoreResult<RestoreReport> {
    // Load the root-level ignore list. Missing = empty list.
    let ignore_list = match ignore::load(root) {
        Ok(il) => il,
        Err(_) => IgnoreList::new(),
    };
    fs::create_dir_all(root)?;
    let mut report = RestoreReport::default();
    restore_tree_to_worktree_inner(store, *tree, root, opts, "", &ignore_list, &mut report, 0)?;
    Ok(report)
}

#[allow(clippy::too_many_arguments)]
fn restore_tree_to_worktree_inner(
    store: &ObjectStore,
    tree_hash: Hash,
    target_dir: &Path,
    options: &RestoreOptions,
    path_prefix: &str,
    ignore: &IgnoreList,
    report: &mut RestoreReport,
    depth: usize,
) -> RestoreResult<()> {
    if depth > MAX_TREE_DEPTH {
        return Err(RestoreError::TreeTooDeep);
    }
    let obj = store.read_object(&tree_hash)?;
    let Object::Tree(tree) = obj else {
        return Err(RestoreError::NotATree);
    };

    if options.clean {
        clean_directory_with_ignore(
            target_dir,
            &tree.entries,
            options.sparse_patterns.as_deref(),
            path_prefix,
            ignore,
        )?;
    }

    for entry in &tree.entries {
        if !crate::object::TreeEntry::validate_name(&entry.name) {
            continue;
        }
        let name = std::str::from_utf8(&entry.name).map_err(|_| RestoreError::InvalidUtf8)?;
        let full_path = if path_prefix.is_empty() {
            name.to_string()
        } else {
            format!("{path_prefix}/{name}")
        };
        let is_dir = entry.mode == EntryMode::Tree;
        // Match against the repo-relative path (anchored/multi-segment aware).
        if ignore.is_ignored(&full_path, is_dir) {
            report.skipped_by_ignore += 1;
            continue;
        }
        match entry.mode {
            EntryMode::Blob | EntryMode::Executable => {
                if let Some(patterns) = options.sparse_patterns.as_deref()
                    && !matches_sparse(patterns, &full_path, false)
                {
                    continue;
                }
                restore_blob(
                    store,
                    target_dir,
                    name,
                    entry.object_hash,
                    entry.mode == EntryMode::Executable,
                )?;
                report.files_written += 1;
            }
            EntryMode::Tree => {
                if let Some(patterns) = options.sparse_patterns.as_deref()
                    && !could_match_descendant(patterns, &full_path)
                {
                    continue;
                }
                ensure_directory(target_dir, name)?;
                report.directories_created += 1;
                let dir_path = target_dir.join(name);
                let dir_meta = fs::symlink_metadata(&dir_path)?;
                if !dir_meta.is_dir() {
                    return Err(RestoreError::NotADirectory(dir_path));
                }
                restore_tree_to_worktree_inner(
                    store,
                    entry.object_hash,
                    &dir_path,
                    options,
                    &full_path,
                    ignore,
                    report,
                    depth + 1,
                )?;
            }
            EntryMode::Symlink => {
                if let Some(patterns) = options.sparse_patterns.as_deref()
                    && !matches_sparse(patterns, &full_path, false)
                {
                    continue;
                }
                restore_symlink(store, target_dir, name, entry.object_hash)?;
                report.symlinks_written += 1;
            }
        }
    }
    Ok(())
}

/// Materialise `tree_hash` into `target_dir`. See module docs for the
/// invariants.
///
/// # Errors
/// - [`RestoreError::NotATree`] if `tree_hash` is not a tree object.
/// - [`RestoreError::InvalidSymlinkTarget`] if a symlink entry's target
///   is absolute or contains `..`.
pub fn restore_tree(
    store: &ObjectStore,
    tree_hash: Hash,
    target_dir: &Path,
    options: &RestoreOptions,
) -> RestoreResult<()> {
    fs::create_dir_all(target_dir)?;
    restore_tree_inner(store, tree_hash, target_dir, options, "")
}

fn restore_tree_inner(
    store: &ObjectStore,
    tree_hash: Hash,
    target_dir: &Path,
    options: &RestoreOptions,
    path_prefix: &str,
) -> RestoreResult<()> {
    let obj = store.read_object(&tree_hash)?;
    let Object::Tree(tree) = obj else {
        return Err(RestoreError::NotATree);
    };

    if options.clean {
        clean_directory(
            target_dir,
            &tree.entries,
            options.sparse_patterns.as_deref(),
            path_prefix,
        )?;
    }

    for entry in &tree.entries {
        if !crate::object::TreeEntry::validate_name(&entry.name) {
            continue;
        }
        let name = std::str::from_utf8(&entry.name).map_err(|_| RestoreError::InvalidUtf8)?;
        let full_path = if path_prefix.is_empty() {
            name.to_string()
        } else {
            format!("{path_prefix}/{name}")
        };
        match entry.mode {
            EntryMode::Blob | EntryMode::Executable => {
                if let Some(patterns) = options.sparse_patterns.as_deref()
                    && !matches_sparse(patterns, &full_path, false)
                {
                    continue;
                }
                restore_blob(
                    store,
                    target_dir,
                    name,
                    entry.object_hash,
                    entry.mode == EntryMode::Executable,
                )?;
            }
            EntryMode::Tree => {
                if let Some(patterns) = options.sparse_patterns.as_deref()
                    && !could_match_descendant(patterns, &full_path)
                {
                    continue;
                }
                ensure_directory(target_dir, name)?;
                let dir_path = target_dir.join(name);
                // Refuse to follow a symlink that took the place of the dir.
                let dir_meta = fs::symlink_metadata(&dir_path)?;
                if !dir_meta.is_dir() {
                    return Err(RestoreError::NotADirectory(dir_path));
                }
                restore_tree_inner(store, entry.object_hash, &dir_path, options, &full_path)?;
            }
            EntryMode::Symlink => {
                if let Some(patterns) = options.sparse_patterns.as_deref()
                    && !matches_sparse(patterns, &full_path, false)
                {
                    continue;
                }
                restore_symlink(store, target_dir, name, entry.object_hash)?;
            }
        }
    }
    Ok(())
}

fn restore_blob(
    store: &ObjectStore,
    dir: &Path,
    name: &str,
    blob_hash: Hash,
    executable: bool,
) -> RestoreResult<()> {
    let obj = store.read_object(&blob_hash)?;
    match obj {
        Object::Blob(b) => write_file_atomic(dir, name, &b.data, executable)?,
        Object::ChunkedBlob(cb) => {
            let mut buf: Vec<u8> = Vec::with_capacity(usize::try_from(cb.total_size).unwrap_or(0));
            for ch in cb.chunks {
                let chunk_obj = store.read_object(&ch)?;
                let Object::Blob(b) = chunk_obj else {
                    return Err(RestoreError::NotABlob);
                };
                buf.extend_from_slice(&b.data);
            }
            write_file_atomic(dir, name, &buf, executable)?;
        }
        _ => return Err(RestoreError::NotABlob),
    }
    Ok(())
}

fn restore_symlink(
    store: &ObjectStore,
    dir: &Path,
    name: &str,
    blob_hash: Hash,
) -> RestoreResult<()> {
    let obj = store.read_object(&blob_hash)?;
    let Object::Blob(b) = obj else {
        return Err(RestoreError::NotABlob);
    };
    let target = std::str::from_utf8(&b.data).map_err(|_| RestoreError::InvalidUtf8)?;
    if !worktree::validate_symlink_target(target) {
        return Err(RestoreError::InvalidSymlinkTarget(target.to_string()));
    }
    let tmp_name = make_tmp_sibling_name(name);
    let tmp_path = dir.join(&tmp_name);
    let final_path = dir.join(name);
    let _ = fs::remove_file(&tmp_path);
    create_symlink(target, &tmp_path)?;
    prepare_path_for_rename(&final_path)?;
    fs::rename(&tmp_path, &final_path)?;
    Ok(())
}

#[cfg(unix)]
fn create_symlink(target: &str, link: &Path) -> io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(windows)]
fn create_symlink(target: &str, link: &Path) -> io::Result<()> {
    // Symlinks on Windows require either Developer Mode or admin
    // privileges. We pick `symlink_file` because every blob is a file
    // when materialised through this code path.
    std::os::windows::fs::symlink_file(target, link)
}

#[cfg(not(any(unix, windows)))]
fn create_symlink(_target: &str, _link: &Path) -> io::Result<()> {
    // Targets without a filesystem (notably `wasm32-unknown-unknown`)
    // cannot materialise symlinks. The demo wasm crate does not exercise
    // the restore path; this stub exists so the crate still compiles.
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "symlink creation is not supported on this target",
    ))
}

fn write_file_atomic(dir: &Path, name: &str, data: &[u8], executable: bool) -> io::Result<()> {
    let tmp_name = make_tmp_sibling_name(name);
    let tmp_path = dir.join(&tmp_name);
    let final_path = dir.join(name);
    {
        let _ = fs::remove_file(&tmp_path);
        let mut tmp = fs::File::create(&tmp_path)?;
        tmp.write_all(data)?;
        tmp.sync_all()?;
        if executable {
            apply_executable_bit(&tmp_path)?;
        }
    }
    prepare_path_for_rename(&final_path)?;
    fs::rename(&tmp_path, &final_path)?;
    Ok(())
}

#[cfg(unix)]
fn apply_executable_bit(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perm = fs::metadata(path)?.permissions();
    perm.set_mode(0o755);
    fs::set_permissions(path, perm)
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
fn apply_executable_bit(_path: &Path) -> io::Result<()> {
    Ok(())
}

fn ensure_directory(parent: &Path, name: &str) -> io::Result<()> {
    let path = parent.join(name);
    match fs::symlink_metadata(&path) {
        Ok(meta) if meta.is_dir() => return Ok(()),
        Ok(_) => fs::remove_file(&path)?,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    match fs::create_dir_all(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            let meta = fs::symlink_metadata(&path)?;
            if meta.is_dir() {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "expected directory",
                ))
            }
        }
        Err(e) => Err(e),
    }
}

fn prepare_path_for_rename(final_path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(final_path) {
        Ok(meta) if meta.is_dir() => fs::remove_dir_all(final_path),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

fn make_tmp_sibling_name(name: &str) -> String {
    let pid = process::id();
    let counter = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!(".{name}.tmp.{pid}.{counter}")
}

fn clean_directory(
    target_dir: &Path,
    tree_entries: &[TreeEntry],
    sparse_patterns: Option<&[SparsePattern]>,
    path_prefix: &str,
) -> RestoreResult<()> {
    struct CleanItem {
        name: String,
        is_dir: bool,
    }
    let mut to_delete: Vec<CleanItem> = Vec::new();

    let read = match fs::read_dir(target_dir) {
        Ok(r) => r,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(RestoreError::Io(e)),
    };
    for entry in read {
        let entry = entry?;
        let file_name = entry.file_name();
        let name_str = file_name
            .to_str()
            .ok_or(RestoreError::InvalidUtf8)?
            .to_string();
        // Hard-coded repo-metadata guard. Compared ASCII case-insensitively
        // so case-insensitive filesystems (macOS default, Windows) can't
        // smuggle a `.MKIT` or `.Git` entry past the sweep (Git CVE-
        // 2021-21300 family).
        if name_str.eq_ignore_ascii_case(".mkit") || name_str.eq_ignore_ascii_case(".git") {
            continue;
        }
        if name_str == ".mkitignore" {
            continue;
        }
        let mut found = false;
        for te in tree_entries {
            if te.name.as_slice() == name_str.as_bytes() {
                found = true;
                break;
            }
        }
        if found {
            continue;
        }
        let meta = entry.metadata()?;
        let is_dir = meta.is_dir();
        if let Some(patterns) = sparse_patterns {
            let full_path = if path_prefix.is_empty() {
                name_str.clone()
            } else {
                format!("{path_prefix}/{name_str}")
            };
            let allow = matches_sparse(patterns, &full_path, is_dir)
                || (is_dir && could_match_descendant(patterns, &full_path));
            if !allow {
                continue;
            }
        }
        to_delete.push(CleanItem {
            name: name_str,
            is_dir,
        });
    }

    for item in to_delete {
        let path = target_dir.join(&item.name);
        if item.is_dir {
            let _ = fs::remove_dir_all(&path);
        } else {
            let _ = fs::remove_file(&path);
        }
    }
    Ok(())
}

/// Like [`clean_directory`] but additionally skips filesystem entries
/// whose basename matches the `ignore` list — used by the worktree
/// checkout path so locally-ignored artefacts (editor swapfiles, build
/// outputs) survive the cleanup.
fn clean_directory_with_ignore(
    target_dir: &Path,
    tree_entries: &[TreeEntry],
    sparse_patterns: Option<&[SparsePattern]>,
    path_prefix: &str,
    ignore: &IgnoreList,
) -> RestoreResult<()> {
    struct CleanItem {
        name: String,
        is_dir: bool,
    }
    let mut to_delete: Vec<CleanItem> = Vec::new();

    let read = match fs::read_dir(target_dir) {
        Ok(r) => r,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(RestoreError::Io(e)),
    };
    for entry in read {
        let entry = entry?;
        let file_name = entry.file_name();
        let name_str = file_name
            .to_str()
            .ok_or(RestoreError::InvalidUtf8)?
            .to_string();
        // Hard-coded repo-metadata guard, ASCII case-insensitive.
        if name_str.eq_ignore_ascii_case(".mkit") || name_str.eq_ignore_ascii_case(".git") {
            continue;
        }
        if name_str == ".mkitignore" || name_str == ".gitignore" {
            continue;
        }
        let mut found = false;
        for te in tree_entries {
            if te.name.as_slice() == name_str.as_bytes() {
                found = true;
                break;
            }
        }
        if found {
            continue;
        }
        let meta = entry.metadata()?;
        let is_dir = meta.is_dir();
        let full_path = if path_prefix.is_empty() {
            name_str.clone()
        } else {
            format!("{path_prefix}/{name_str}")
        };
        // Respect ignore rules — don't touch locally-ignored files. Match on
        // the repo-relative path (anchored/multi-segment aware).
        if ignore.is_ignored(&full_path, is_dir) {
            continue;
        }
        if let Some(patterns) = sparse_patterns {
            let allow = matches_sparse(patterns, &full_path, is_dir)
                || (is_dir && could_match_descendant(patterns, &full_path));
            if !allow {
                continue;
            }
        }
        to_delete.push(CleanItem {
            name: name_str,
            is_dir,
        });
    }

    for item in to_delete {
        let path = target_dir.join(&item.name);
        if item.is_dir {
            let _ = fs::remove_dir_all(&path);
        } else {
            let _ = fs::remove_file(&path);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::{Tree, TreeEntry};
    use crate::serialize;
    use tempfile::TempDir;

    fn fresh_store() -> (TempDir, ObjectStore) {
        let dir = TempDir::new().unwrap();
        let store = ObjectStore::init(dir.path()).unwrap();
        (dir, store)
    }

    fn put_blob(store: &ObjectStore, data: &[u8]) -> Hash {
        let bytes = serialize::serialize(&Object::Blob(crate::object::Blob {
            data: data.to_vec(),
        }))
        .unwrap();
        store.write(&bytes).unwrap()
    }

    fn put_tree_with(store: &ObjectStore, entries: Vec<TreeEntry>) -> Hash {
        let bytes = serialize::serialize(&Object::Tree(Tree { entries })).unwrap();
        store.write(&bytes).unwrap()
    }

    #[test]
    fn parse_sparse_basic() {
        let content = "# comment line\nsrc\n!tests\ndocs/\n\nREADME.md\n";
        let p = parse_sparse_patterns(content);
        assert_eq!(p.len(), 4);
        assert_eq!(p[0].pattern, "src");
        assert!(!p[0].negated);
        assert!(!p[0].dir_only);
        assert_eq!(p[1].pattern, "tests");
        assert!(p[1].negated);
        assert_eq!(p[2].pattern, "docs");
        assert!(p[2].dir_only);
        assert_eq!(p[3].pattern, "README.md");
    }

    #[test]
    fn matches_sparse_exact_and_prefix() {
        let p = vec![SparsePattern {
            pattern: "src".to_string(),
            negated: false,
            dir_only: false,
        }];
        assert!(matches_sparse(&p, "src/main.rs", false));
        assert!(matches_sparse(&p, "src/lib/util.rs", false));
        assert!(!matches_sparse(&p, "tests/foo", false));
    }

    #[test]
    fn matches_sparse_negation() {
        let p = vec![
            SparsePattern {
                pattern: "src".to_string(),
                negated: false,
                dir_only: false,
            },
            SparsePattern {
                pattern: "src/secret".to_string(),
                negated: true,
                dir_only: false,
            },
        ];
        assert!(matches_sparse(&p, "src/main.rs", false));
        assert!(!matches_sparse(&p, "src/secret/key.pem", false));
    }

    #[test]
    fn matches_sparse_dir_only() {
        let p = vec![SparsePattern {
            pattern: "build".to_string(),
            negated: false,
            dir_only: true,
        }];
        assert!(matches_sparse(&p, "build", true));
        assert!(!matches_sparse(&p, "build", false));
    }

    #[test]
    fn matches_sparse_last_match_wins() {
        let p = vec![
            SparsePattern {
                pattern: "src".to_string(),
                negated: false,
                dir_only: false,
            },
            SparsePattern {
                pattern: "src".to_string(),
                negated: true,
                dir_only: false,
            },
        ];
        assert!(!matches_sparse(&p, "src/main.rs", false));
    }

    #[test]
    fn matches_sparse_bare_basename() {
        let p = vec![SparsePattern {
            pattern: "Makefile".to_string(),
            negated: false,
            dir_only: false,
        }];
        assert!(matches_sparse(&p, "Makefile", false));
        assert!(matches_sparse(&p, "sub/Makefile", false));
        assert!(!matches_sparse(&p, "Makefile.bak", false));
    }

    #[test]
    fn could_match_descendant_basic() {
        let p = vec![SparsePattern {
            pattern: "src/lib".to_string(),
            negated: false,
            dir_only: false,
        }];
        assert!(could_match_descendant(&p, "src"));
        assert!(could_match_descendant(&p, "src/lib"));
        assert!(!could_match_descendant(&p, "tests"));
    }

    #[test]
    fn restore_empty_tree_creates_no_files() {
        let (_d, store) = fresh_store();
        let target = TempDir::new().unwrap();
        let tree_h = put_tree_with(&store, vec![]);
        restore_tree(&store, tree_h, target.path(), &RestoreOptions::default()).unwrap();
        let count = fs::read_dir(target.path()).unwrap().count();
        assert_eq!(count, 0);
    }

    #[test]
    fn restore_single_file() {
        let (_d, store) = fresh_store();
        let target = TempDir::new().unwrap();
        let blob = put_blob(&store, b"hello");
        let tree = put_tree_with(
            &store,
            vec![TreeEntry {
                name: b"file.txt".to_vec(),
                mode: EntryMode::Blob,
                object_hash: blob,
            }],
        );
        restore_tree(&store, tree, target.path(), &RestoreOptions::default()).unwrap();
        let content = fs::read(target.path().join("file.txt")).unwrap();
        assert_eq!(content, b"hello");
    }

    #[test]
    fn restore_nested_directories() {
        let (_d, store) = fresh_store();
        let target = TempDir::new().unwrap();
        let blob = put_blob(&store, b"const main = 0;");
        let inner = put_tree_with(
            &store,
            vec![TreeEntry {
                name: b"main.rs".to_vec(),
                mode: EntryMode::Blob,
                object_hash: blob,
            }],
        );
        let root = put_tree_with(
            &store,
            vec![TreeEntry {
                name: b"src".to_vec(),
                mode: EntryMode::Tree,
                object_hash: inner,
            }],
        );
        restore_tree(&store, root, target.path(), &RestoreOptions::default()).unwrap();
        let content = fs::read(target.path().join("src/main.rs")).unwrap();
        assert_eq!(content, b"const main = 0;");
    }

    #[test]
    fn restore_overwrites_existing_files() {
        let (_d, store) = fresh_store();
        let target = TempDir::new().unwrap();
        fs::write(target.path().join("file.txt"), b"old").unwrap();
        let blob = put_blob(&store, b"new");
        let tree = put_tree_with(
            &store,
            vec![TreeEntry {
                name: b"file.txt".to_vec(),
                mode: EntryMode::Blob,
                object_hash: blob,
            }],
        );
        restore_tree(&store, tree, target.path(), &RestoreOptions::default()).unwrap();
        assert_eq!(fs::read(target.path().join("file.txt")).unwrap(), b"new");
    }

    #[test]
    fn restore_removes_untracked_when_clean() {
        let (_d, store) = fresh_store();
        let target = TempDir::new().unwrap();
        fs::write(target.path().join("extra.txt"), b"gone").unwrap();
        let blob = put_blob(&store, b"keep");
        let tree = put_tree_with(
            &store,
            vec![TreeEntry {
                name: b"tracked.txt".to_vec(),
                mode: EntryMode::Blob,
                object_hash: blob,
            }],
        );
        restore_tree(&store, tree, target.path(), &RestoreOptions::default()).unwrap();
        assert!(!target.path().join("extra.txt").exists());
        assert_eq!(
            fs::read(target.path().join("tracked.txt")).unwrap(),
            b"keep"
        );
    }

    #[test]
    fn restore_clean_false_keeps_untracked() {
        let (_d, store) = fresh_store();
        let target = TempDir::new().unwrap();
        fs::write(target.path().join("extra.txt"), b"survive").unwrap();
        let blob = put_blob(&store, b"keep");
        let tree = put_tree_with(
            &store,
            vec![TreeEntry {
                name: b"tracked.txt".to_vec(),
                mode: EntryMode::Blob,
                object_hash: blob,
            }],
        );
        restore_tree(
            &store,
            tree,
            target.path(),
            &RestoreOptions {
                clean: false,
                sparse_patterns: None,
            },
        )
        .unwrap();
        assert_eq!(
            fs::read(target.path().join("extra.txt")).unwrap(),
            b"survive"
        );
    }

    #[test]
    fn restore_preserves_mkit_directory() {
        let (_d, store) = fresh_store();
        let target = TempDir::new().unwrap();
        fs::create_dir_all(target.path().join(".mkit")).unwrap();
        fs::write(target.path().join(".mkit/config"), b"important").unwrap();
        let tree = put_tree_with(&store, vec![]);
        restore_tree(&store, tree, target.path(), &RestoreOptions::default()).unwrap();
        assert_eq!(
            fs::read(target.path().join(".mkit/config")).unwrap(),
            b"important"
        );
    }

    #[test]
    fn clean_directory_preserves_case_variant_mkit_and_git() {
        // Regression for Git CVE-2021-21300 family: on case-insensitive
        // filesystems a worktree directory named `.MKIT` or `.Git` must
        // never be swept by `clean_directory`, otherwise a hostile tree
        // entry could trick restore into deleting repo metadata.
        let target = TempDir::new().unwrap();
        fs::create_dir_all(target.path().join(".MKIT")).unwrap();
        fs::write(target.path().join(".MKIT/config"), b"meta").unwrap();
        fs::create_dir_all(target.path().join(".Git")).unwrap();
        fs::write(target.path().join(".Git/HEAD"), b"ref").unwrap();
        // Empty tree — without the case-insensitive guard, everything
        // unknown is removed.
        clean_directory(target.path(), &[], None, "").unwrap();
        assert!(
            target.path().join(".MKIT/config").exists(),
            ".MKIT swept by clean_directory (case-fold bypass)"
        );
        assert!(
            target.path().join(".Git/HEAD").exists(),
            ".Git swept by clean_directory (case-fold bypass)"
        );
    }

    #[test]
    fn clean_directory_with_ignore_preserves_case_variant_mkit_and_git() {
        let target = TempDir::new().unwrap();
        fs::create_dir_all(target.path().join(".MKIT")).unwrap();
        fs::write(target.path().join(".MKIT/config"), b"meta").unwrap();
        fs::create_dir_all(target.path().join(".GIT")).unwrap();
        fs::write(target.path().join(".GIT/HEAD"), b"ref").unwrap();
        let ignore = crate::ignore::IgnoreList::new();
        clean_directory_with_ignore(target.path(), &[], None, "", &ignore).unwrap();
        assert!(
            target.path().join(".MKIT/config").exists(),
            ".MKIT swept by clean_directory_with_ignore (case-fold bypass)"
        );
        assert!(
            target.path().join(".GIT/HEAD").exists(),
            ".GIT swept by clean_directory_with_ignore (case-fold bypass)"
        );
    }

    #[test]
    fn restore_chunked_blob_reassembled() {
        let (_d, store) = fresh_store();
        let target = TempDir::new().unwrap();
        let c0 = put_blob(&store, b"Hello, ");
        let c1 = put_blob(&store, b"chunked ");
        let c2 = put_blob(&store, b"world!");
        let cb = Object::ChunkedBlob(crate::object::ChunkedBlob {
            total_size: 7 + 8 + 6,
            chunk_size: 64 * 1024,
            chunks: vec![c0, c1, c2],
        });
        let cb_h = store.write(&serialize::serialize(&cb).unwrap()).unwrap();
        let tree = put_tree_with(
            &store,
            vec![TreeEntry {
                name: b"out.txt".to_vec(),
                mode: EntryMode::Blob,
                object_hash: cb_h,
            }],
        );
        restore_tree(&store, tree, target.path(), &RestoreOptions::default()).unwrap();
        let content = fs::read(target.path().join("out.txt")).unwrap();
        assert_eq!(content, b"Hello, chunked world!");
    }

    #[cfg(unix)]
    #[test]
    fn restore_with_symlink() {
        let (_d, store) = fresh_store();
        let target = TempDir::new().unwrap();
        let link_target = put_blob(&store, b"target.txt");
        let file = put_blob(&store, b"real");
        let tree = put_tree_with(
            &store,
            vec![
                TreeEntry {
                    name: b"link".to_vec(),
                    mode: EntryMode::Symlink,
                    object_hash: link_target,
                },
                TreeEntry {
                    name: b"target.txt".to_vec(),
                    mode: EntryMode::Blob,
                    object_hash: file,
                },
            ],
        );
        restore_tree(&store, tree, target.path(), &RestoreOptions::default()).unwrap();
        let read = fs::read_link(target.path().join("link")).unwrap();
        assert_eq!(read.to_str().unwrap(), "target.txt");
        assert_eq!(fs::read(target.path().join("target.txt")).unwrap(), b"real");
    }

    #[cfg(unix)]
    #[test]
    fn restore_rejects_invalid_symlink_targets() {
        let (_d, store) = fresh_store();
        let target = TempDir::new().unwrap();
        let bad = put_blob(&store, b"/etc/passwd");
        let tree = put_tree_with(
            &store,
            vec![TreeEntry {
                name: b"link".to_vec(),
                mode: EntryMode::Symlink,
                object_hash: bad,
            }],
        );
        let err =
            restore_tree(&store, tree, target.path(), &RestoreOptions::default()).unwrap_err();
        assert!(matches!(err, RestoreError::InvalidSymlinkTarget(_)));
    }

    #[test]
    fn sparse_restore_only_restores_matched() {
        let (_d, store) = fresh_store();
        let target = TempDir::new().unwrap();
        let main = put_blob(&store, b"pub fn main(){}");
        let test = put_blob(&store, b"test {}");
        let readme = put_blob(&store, b"# Project");
        let src = put_tree_with(
            &store,
            vec![TreeEntry {
                name: b"main.rs".to_vec(),
                mode: EntryMode::Blob,
                object_hash: main,
            }],
        );
        let tests = put_tree_with(
            &store,
            vec![TreeEntry {
                name: b"test.rs".to_vec(),
                mode: EntryMode::Blob,
                object_hash: test,
            }],
        );
        let root = put_tree_with(
            &store,
            vec![
                TreeEntry {
                    name: b"README.md".to_vec(),
                    mode: EntryMode::Blob,
                    object_hash: readme,
                },
                TreeEntry {
                    name: b"src".to_vec(),
                    mode: EntryMode::Tree,
                    object_hash: src,
                },
                TreeEntry {
                    name: b"tests".to_vec(),
                    mode: EntryMode::Tree,
                    object_hash: tests,
                },
            ],
        );
        let opts = RestoreOptions {
            clean: true,
            sparse_patterns: Some(vec![SparsePattern {
                pattern: "src".to_string(),
                negated: false,
                dir_only: false,
            }]),
        };
        restore_tree(&store, root, target.path(), &opts).unwrap();
        assert!(target.path().join("src/main.rs").exists());
        assert!(!target.path().join("tests/test.rs").exists());
        assert!(!target.path().join("README.md").exists());
    }

    #[test]
    fn sparse_restore_with_negation_excludes_subtree() {
        let (_d, store) = fresh_store();
        let target = TempDir::new().unwrap();
        let main = put_blob(&store, b"main");
        let key = put_blob(&store, b"secret");
        let secret_tree = put_tree_with(
            &store,
            vec![TreeEntry {
                name: b"key.pem".to_vec(),
                mode: EntryMode::Blob,
                object_hash: key,
            }],
        );
        let src = put_tree_with(
            &store,
            vec![
                TreeEntry {
                    name: b"main.rs".to_vec(),
                    mode: EntryMode::Blob,
                    object_hash: main,
                },
                TreeEntry {
                    name: b"secret".to_vec(),
                    mode: EntryMode::Tree,
                    object_hash: secret_tree,
                },
            ],
        );
        let root = put_tree_with(
            &store,
            vec![TreeEntry {
                name: b"src".to_vec(),
                mode: EntryMode::Tree,
                object_hash: src,
            }],
        );
        let opts = RestoreOptions {
            clean: true,
            sparse_patterns: Some(vec![
                SparsePattern {
                    pattern: "src".to_string(),
                    negated: false,
                    dir_only: false,
                },
                SparsePattern {
                    pattern: "src/secret".to_string(),
                    negated: true,
                    dir_only: false,
                },
            ]),
        };
        restore_tree(&store, root, target.path(), &opts).unwrap();
        assert!(target.path().join("src/main.rs").exists());
        assert!(!target.path().join("src/secret/key.pem").exists());
    }

    #[test]
    fn sparse_checkout_roundtrip() {
        let target = TempDir::new().unwrap();
        write_sparse_checkout(target.path(), &["src", "!src/secret", "docs/"]).unwrap();
        let p = load_sparse_checkout(target.path()).unwrap().unwrap();
        assert_eq!(p.len(), 3);
        assert_eq!(p[0].pattern, "src");
        assert!(p[1].negated);
        assert!(p[2].dir_only);
    }

    #[test]
    fn load_sparse_checkout_returns_none_when_missing() {
        let target = TempDir::new().unwrap();
        fs::create_dir_all(target.path().join(".mkit")).unwrap();
        let p = load_sparse_checkout(target.path()).unwrap();
        assert!(p.is_none());
    }

    // =================================================================
    // restore_tree_to_worktree — checkout-facing wrapper.
    // =================================================================

    #[test]
    fn worktree_restore_counts_files_and_dirs() {
        let (_d, store) = fresh_store();
        let target = TempDir::new().unwrap();
        let blob_a = put_blob(&store, b"a");
        let blob_b = put_blob(&store, b"b");
        let sub = put_tree_with(
            &store,
            vec![TreeEntry {
                name: b"b.txt".to_vec(),
                mode: EntryMode::Blob,
                object_hash: blob_b,
            }],
        );
        let root = put_tree_with(
            &store,
            vec![
                TreeEntry {
                    name: b"a.txt".to_vec(),
                    mode: EntryMode::Blob,
                    object_hash: blob_a,
                },
                TreeEntry {
                    name: b"sub".to_vec(),
                    mode: EntryMode::Tree,
                    object_hash: sub,
                },
            ],
        );
        let report =
            restore_tree_to_worktree(&store, &root, target.path(), &RestoreOptions::default())
                .unwrap();
        assert_eq!(report.files_written, 2);
        assert_eq!(report.directories_created, 1);
        assert!(target.path().join("a.txt").exists());
        assert!(target.path().join("sub/b.txt").exists());
    }

    #[test]
    fn worktree_restore_respects_mkitignore() {
        let (_d, store) = fresh_store();
        let target = TempDir::new().unwrap();
        // Pre-seed an ignore file + a locally-present-but-ignored file
        // that must NOT be deleted.
        fs::write(target.path().join(".mkitignore"), "secret.txt\n").unwrap();
        fs::write(target.path().join("secret.txt"), b"local-only").unwrap();
        let secret_blob = put_blob(&store, b"COMMITTED-SECRET");
        let ok_blob = put_blob(&store, b"ok");
        let root = put_tree_with(
            &store,
            vec![
                TreeEntry {
                    name: b"ok.txt".to_vec(),
                    mode: EntryMode::Blob,
                    object_hash: ok_blob,
                },
                TreeEntry {
                    name: b"secret.txt".to_vec(),
                    mode: EntryMode::Blob,
                    object_hash: secret_blob,
                },
            ],
        );
        // With `clean=true` (default) the checkout sweep must still
        // leave the ignored file alone: the ignore check covers both
        // tree-entry restoration AND the cleanup sweep.
        let report =
            restore_tree_to_worktree(&store, &root, target.path(), &RestoreOptions::default())
                .unwrap();
        assert_eq!(report.files_written, 1);
        assert_eq!(report.skipped_by_ignore, 1);
        assert_eq!(
            fs::read(target.path().join("secret.txt")).unwrap(),
            b"local-only"
        );
        assert_eq!(fs::read(target.path().join("ok.txt")).unwrap(), b"ok");
    }

    #[cfg(unix)]
    #[test]
    fn worktree_restore_rejects_escaping_symlink() {
        let (_d, store) = fresh_store();
        let target = TempDir::new().unwrap();
        let bad = put_blob(&store, b"../outside");
        let root = put_tree_with(
            &store,
            vec![TreeEntry {
                name: b"link".to_vec(),
                mode: EntryMode::Symlink,
                object_hash: bad,
            }],
        );
        let err =
            restore_tree_to_worktree(&store, &root, target.path(), &RestoreOptions::default())
                .unwrap_err();
        assert!(matches!(err, RestoreError::InvalidSymlinkTarget(_)));
    }
}
