//! Worktree and ref primitives a pull's fast-forward builds on: restore
//! safety (refuse to overwrite user work), materialising a tree together with
//! the index, and history-aware branch writes.
//!
//! These are also what the `mkit` command line's `checkout`, `reset`,
//! `restore` and friends use, so they live in one place.

use std::fs;
use std::path::Path;

use mkit_core::hash::Hash;
use mkit_core::index::Index;
use mkit_core::layout::RepoLayout;
use mkit_core::object::Object;
use mkit_core::ops::diff::{DiffKind, diff_trees};
use mkit_core::ops::restore::{RestoreOptions, matches_sparse, restore_tree_to_worktree_with};
use mkit_core::refs::{self, RefError, RefWriteCondition};
use mkit_core::store::ObjectStore;
use mkit_core::worktree as core_worktree;

/// Rewrite `.mkit/index` so it exactly mirrors `tree_hash`.
///
/// `mkit commit` now signs the index, so commands that move HEAD and
/// materialize a committed tree must keep the index aligned with that
/// snapshot.
pub fn sync_index_to_tree(
    layout: &RepoLayout,
    store: &ObjectStore,
    tree_hash: Hash,
) -> Result<(), String> {
    let mut idx =
        mkit_core::index::from_tree(store, tree_hash).map_err(|e| format!("index: {e}"))?;
    // Tree-derived entries carry no stat cache. Carry it over from the
    // outgoing index wherever path AND object hash agree: a later stat
    // match against the old observation still proves the same bytes,
    // so commit/checkout don't wipe the O(stat) fast path.
    if let Ok(old) = mkit_core::index::read_index(layout) {
        // O(1) lookups: find_entry is a linear scan and this loop runs
        // once per tree entry (was O(n²) per commit/checkout).
        let by_path: std::collections::HashMap<&str, &mkit_core::index::IndexEntry> =
            old.entries.iter().map(|o| (o.path.as_str(), o)).collect();
        for e in &mut idx.entries {
            if let Some(o) = by_path.get(e.path.as_str())
                && o.object_hash == e.object_hash
                && o.status == e.status
            {
                e.mtime_ns = o.mtime_ns;
                e.size = o.size;
                e.ino = o.ino;
                e.ctime_ns = o.ctime_ns;
            }
        }
    }
    mkit_core::index::write_index(layout, &idx).map_err(|e| format!("write index: {e}"))
}

/// Materialise `tree_hash` and align the index while preserving `.mkitignore` entries.
pub fn restore_worktree_and_index(
    layout: &RepoLayout,
    store: &ObjectStore,
    tree_hash: Hash,
) -> Result<(), String> {
    restore_tree_to_worktree_with(
        store,
        &tree_hash,
        None,
        layout.worktree_root(),
        &RestoreOptions::default(),
        &crate::restore_fanout::read_chunks_fanout,
    )
    .map_err(|e| format!("restore worktree: {e}"))?;
    sync_index_to_tree(layout, store, tree_hash)
}

/// Refuse a destructive restore when the index/worktree contains user work.
pub fn ensure_restore_safe(
    layout: &RepoLayout,
    store: &ObjectStore,
    target_tree: Hash,
) -> Result<(), String> {
    ensure_restore_safe_with_options(layout, store, target_tree, &RestoreOptions::default())
}

/// Refuse a destructive restore when affected index/worktree paths contain user work.
pub fn ensure_restore_safe_with_options(
    layout: &RepoLayout,
    store: &ObjectStore,
    target_tree: Hash,
    options: &RestoreOptions,
) -> Result<(), String> {
    let root = layout.worktree_root();
    let current_tree = current_head_tree(layout, store)?;
    let idx = read_or_seed_index_from_head(layout, store)?;
    // Safety-check snapshot trees are ephemeral — in-memory overlay,
    // no durability cost, no garbage objects in the store.
    let snapshot = mkit_core::store::EphemeralSink::new(store);
    let index_tree = core_worktree::build_tree_from_index_with(store, &snapshot, &idx, false)
        .map_err(|e| format!("check index state: {e}"))?;

    let staged = diff_trees(&snapshot, current_tree, Some(index_tree))
        .map_err(|e| format!("check staged changes: {e}"))?;
    if let Some(entry) = staged
        .entries
        .iter()
        .find(|entry| restore_affects_path(options, &entry.path))
    {
        return Err(format!(
            "restore would overwrite staged changes; commit, stash, or reset '{}' first",
            entry.path
        ));
    }

    let worktree_tree = core_worktree::build_tree_filtered_observed_with_source(
        &snapshot,
        &snapshot,
        root,
        Some(&idx),
        &mut Vec::new(),
    )
    .map_err(|e| format!("check working tree changes: {e}"))?;
    let unstaged = diff_trees(&snapshot, Some(index_tree), Some(worktree_tree))
        .map_err(|e| format!("check working tree changes: {e}"))?;
    if let Some(entry) = unstaged
        .entries
        .iter()
        .find(|entry| entry.kind != DiffKind::Added && restore_affects_path(options, &entry.path))
    {
        return Err(format!(
            "restore would overwrite local changes; commit, stash, or reset '{}' first",
            entry.path
        ));
    }

    let target_writes = diff_trees(&snapshot, Some(index_tree), Some(target_tree))
        .map_err(|e| format!("check restore target: {e}"))?
        .entries
        .into_iter()
        .filter(|entry| entry.kind != DiffKind::Removed)
        .filter(|entry| restore_affects_path(options, &entry.path))
        .map(|entry| entry.path)
        .collect::<Vec<_>>();
    if target_writes.is_empty() && !options.clean {
        return Ok(());
    }

    let ignore = mkit_core::ignore::load(root).map_err(|e| format!("read ignore file: {e}"))?;
    let mut worktree_paths = Vec::new();
    collect_worktree_paths(root, root, "", &mut worktree_paths)
        .map_err(|e| format!("check untracked paths: {e}"))?;
    if let Some(path) = worktree_paths.iter().find(|path| {
        !index_tracks_path_or_descendant(&idx, path)
            && target_writes
                .iter()
                .any(|target| paths_overlap(path, target))
    }) {
        return Err(format!(
            "restore would overwrite untracked path '{path}'; move or remove it first"
        ));
    }

    if options.clean
        && let Some(path) = worktree_paths.iter().find(|path| {
            !index_tracks_path_or_descendant(&idx, path)
                && restore_affects_path(options, path)
                && *path != ".mkitignore"
                && *path != ".gitignore"
                && !is_ignored_worktree_path(root, &ignore, path)
        })
    {
        return Err(format!(
            "restore would remove untracked path '{path}'; move or remove it first"
        ));
    }

    Ok(())
}

#[must_use]
pub fn restore_affects_path(options: &RestoreOptions, path: &str) -> bool {
    options
        .sparse_patterns
        .as_deref()
        .is_none_or(|patterns| matches_sparse(patterns, path, false))
}

pub fn collect_worktree_paths(
    root: &Path,
    dir: &Path,
    prefix: &str,
    out: &mut Vec<String>,
) -> std::io::Result<()> {
    let read = match fs::read_dir(dir) {
        Ok(read) => read,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    for entry in read {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if name.eq_ignore_ascii_case(".mkit") || name.eq_ignore_ascii_case(".git") {
            continue;
        }
        let path = if prefix.is_empty() {
            name.to_string()
        } else {
            format!("{prefix}/{name}")
        };
        out.push(path.clone());
        let full_path = root.join(&path);
        let meta = fs::symlink_metadata(&full_path)?;
        if meta.is_dir() {
            collect_worktree_paths(root, &full_path, &path, out)?;
        }
    }
    Ok(())
}

#[must_use]
pub fn index_tracks_path_or_descendant(index: &Index, path: &str) -> bool {
    // Delegates to `Index::tracks_path_or_descendant`, which answers via
    // the maintained `path -> position` map in `O(log n + k)` instead of
    // this function's old `O(n)` full scan (issue #708) — `add_tree` calls
    // this once per directory/file it walks.
    index.tracks_path_or_descendant(path)
}

#[must_use]
pub fn paths_overlap(left: &str, right: &str) -> bool {
    index_path_matches_or_descends(left, right) || index_path_descends_from(right, left)
}

#[must_use]
pub fn index_path_matches_or_descends(path: &str, base: &str) -> bool {
    path == base || index_path_descends_from(path, base)
}

#[must_use]
pub fn index_path_descends_from(path: &str, base: &str) -> bool {
    path.len() > base.len()
        && path.starts_with(base)
        && path.as_bytes().get(base.len()) == Some(&b'/')
}

#[must_use]
pub fn is_ignored_worktree_path(
    root: &Path,
    ignore: &mkit_core::ignore::IgnoreList,
    path: &str,
) -> bool {
    let full_path = root.join(path);
    let Ok(meta) = fs::symlink_metadata(&full_path) else {
        return false;
    };
    // Match on the repo-relative path, and treat a path under an ignored
    // directory as ignored too (no top-down walk here to carry that bit).
    ignore.is_ignored_with_ancestors(path, meta.is_dir())
}

pub fn current_head_tree(layout: &RepoLayout, store: &ObjectStore) -> Result<Option<Hash>, String> {
    let Some(head_hash) = refs::resolve_head(layout).map_err(|e| format!("resolve HEAD: {e}"))?
    else {
        return Ok(None);
    };
    match store
        .read_object(&head_hash)
        .map_err(|e| format!("read HEAD: {e}"))?
    {
        Object::Commit(c) => Ok(Some(c.tree_hash)),
        Object::Remix(r) => Ok(Some(r.tree_hash)),
        _ => Err("HEAD does not resolve to a commit or remix".to_string()),
    }
}

/// Read the index, seeding an absent/empty one from HEAD when possible.
///
/// This lets old repositories or manually removed indexes keep the
/// expected staging invariant: adding/removing one path starts from the
/// current commit snapshot instead of making the next commit forget all
/// unchanged tracked files.
pub fn read_or_seed_index_from_head(
    layout: &RepoLayout,
    store: &ObjectStore,
) -> Result<mkit_core::index::Index, String> {
    let idx = mkit_core::index::read_index(layout).map_err(|e| format!("read index: {e}"))?;
    if !idx.entries.is_empty() {
        return Ok(idx);
    }

    let Some(head_hash) =
        mkit_core::refs::resolve_head(layout).map_err(|e| format!("resolve HEAD: {e}"))?
    else {
        return Ok(idx);
    };
    match store
        .read_object(&head_hash)
        .map_err(|e| format!("read HEAD: {e}"))?
    {
        Object::Commit(c) => mkit_core::index::from_tree(store, c.tree_hash)
            .map_err(|e| format!("index from HEAD: {e}")),
        Object::Remix(r) => mkit_core::index::from_tree(store, r.tree_hash)
            .map_err(|e| format!("index from HEAD: {e}")),
        _ => Err("HEAD does not resolve to a commit or remix".to_string()),
    }
}

/// Publish a branch tip and a versioned first-parent ancestry snapshot when
/// history-mmr is enabled. The helper locks history then the full ref identity;
/// pending publication is recovered before accepting another write.
/// Detached HEAD updates do not claim branch
/// membership and continue through their existing per-worktree path.
pub fn write_ref_recording_history(
    layout: &RepoLayout,
    branch: &str,
    condition: RefWriteCondition,
    new_hash: &Hash,
) -> Result<(), RefError> {
    #[cfg(feature = "history-mmr")]
    {
        let store = ObjectStore::open(layout)
            .map_err(|e| RefError::InvalidRef(format!("{branch}: open object store: {e}")))?;
        refs::update_ref_with_ancestry(layout, branch, condition, new_hash, &store)
    }
    #[cfg(not(feature = "history-mmr"))]
    {
        refs::update_ref(layout, branch, condition, new_hash)
    }
}

/// [`refs::list_remote_refs_with`], with the per-ref read fanned out across
/// rayon's pool once there is enough work to amortise dispatch.
pub fn list_remote_refs_parallel(
    layout: &RepoLayout,
    remote: &str,
) -> Result<Vec<refs::Ref>, RefError> {
    refs::list_remote_refs_with(layout, remote, fanout_read_batch)
}

/// Ref-read fan-out per thread. Ref files are tiny (65 bytes) and the
/// per-entry cost is dominated by syscall overhead, not compute.
const LIST_REFS_FANOUT_ENTRIES_PER_THREAD: usize = 2;

/// The `read_batch` shared by every parallel ref-listing wrapper: fans
/// [`refs::read_ref_candidate`] out across rayon once there is enough work.
#[must_use]
pub fn fanout_read_batch(candidates: &[refs::RefCandidate]) -> Vec<refs::RefReadOutcome> {
    crate::fanout::map_seq_or_par(
        candidates,
        crate::fanout::threshold(LIST_REFS_FANOUT_ENTRIES_PER_THREAD),
        |c, _| refs::read_ref_candidate(c),
    )
}
