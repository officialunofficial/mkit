//! `mkit restore [--staged] [--worktree] [--source <rev>] [-f] <path>...`
//! — discard worktree changes for path(s), or unstage them.
//!
//! Mirrors the everyday halves of `git restore`:
//!
//! - **default (no `--staged`)** — restore the worktree file(s) for each
//!   path from the index (the staged content), discarding uncommitted
//!   worktree edits. Reuses the #176 "don't clobber user work" spirit: a
//!   worktree file whose content diverges from the staged blob is refused
//!   without `-f/--force`, so an accidental `restore` never silently eats
//!   an un-staged edit.
//! - **`--staged`** — restore the index entry for each path from
//!   `HEAD` (i.e. unstage it), leaving the worktree file exactly as it
//!   is. This touches only `.mkit/index`, never the worktree, so it
//!   needs no dirty guard and no `--force`.
//! - **`--staged --worktree`** (both) — unstage AND discard the worktree
//!   edit in one step (worktree restored from `HEAD` since the staged
//!   entry is being reset to `HEAD` too); the dirty guard still applies
//!   to the worktree half.
//! - **`--source <rev>`** — take the restored content from `<rev>`'s tree
//!   (resolved via the shared revspec resolver) instead of the index/HEAD
//!   default.
//!
//! A path that names a directory restores every tracked entry at or
//! below it. Restoring the worktree never *removes* extra files; it only
//! rewrites the named tracked paths from the source tree.

use std::ffi::OsString;
use std::io::Write;
use std::path::{Component, Path, PathBuf};

use clap::Parser;
use mkit_core::hash::Hash;
use mkit_core::index::{self, EntryStatus, Index, IndexEntry};
use mkit_core::object::Object;
use mkit_core::ops::restore::{RestoreOptions, SparsePattern, restore_tree_to_worktree};
use mkit_core::store::ObjectStore;
use mkit_core::worktree;

use crate::clap_shim;
use crate::exit;

#[derive(Debug, Parser)]
#[command(
    name = "mkit restore",
    about = "Restore worktree files (discard local changes) or unstage them."
)]
struct RestoreOpts {
    /// Restore the index entry (unstage) instead of, or in addition to,
    /// the worktree file. When given alone the worktree is left
    /// untouched; combine with `--worktree` to do both.
    #[arg(short = 'S', long)]
    staged: bool,

    /// Restore the worktree file. This is the implicit default unless
    /// `--staged` is given; pass it explicitly to restore both the index
    /// and the worktree (`--staged --worktree`).
    #[arg(short = 'W', long)]
    worktree: bool,

    /// Take the restored content from this revision's tree instead of
    /// the default source (the index for `--worktree`, `HEAD` for
    /// `--staged`). Accepts the shared revspec grammar (branch, tag,
    /// `HEAD`, full/short hash, `~n`/`^`).
    #[arg(long, value_name = "REV")]
    source: Option<String>,

    /// Overwrite worktree files even when they differ from the source
    /// (otherwise locally-modified files are refused to avoid data loss).
    #[arg(short = 'f', long)]
    force: bool,

    /// Paths to restore. A directory path restores every tracked entry
    /// at or below it.
    #[arg(required = true)]
    paths: Vec<String>,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<RestoreOpts>("mkit restore", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let mkit_dir = cwd.join(mkit_core::MKIT_DIR);
    let store = match ObjectStore::open(&cwd) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("not a mkit repo: {e}"), exit::GENERAL_ERROR),
    };
    let _lock = match super::acquire_worktree_lock(&cwd) {
        Ok(l) => l,
        Err(code) => return code,
    };

    // Default target selection: with no flag (or only `--worktree`) we
    // restore the worktree; `--staged` alone restores the index only;
    // `--staged --worktree` does both.
    let do_staged = opts.staged;
    let do_worktree = opts.worktree || !opts.staged;

    let mut idx = match super::read_or_seed_index_from_head(&cwd, &store) {
        Ok(i) => i,
        Err(e) => return emit_err(&e, exit::GENERAL_ERROR),
    };

    // HEAD's tree (None on an unborn branch) — the source for `--staged`
    // unstaging, and the worktree source when a path is not in the index.
    let head_tree = match super::current_head_tree(&cwd, &store) {
        Ok(t) => t,
        Err(e) => return emit_err(&e, exit::GENERAL_ERROR),
    };

    // Resolve an explicit `--source <rev>` to its tree once. When set it
    // overrides both the index (worktree restore) and HEAD (unstage).
    let source_tree: Option<Hash> = match &opts.source {
        Some(spec) => match resolve_source_tree(&store, &mkit_dir, spec) {
            Ok(t) => Some(t),
            Err((msg, code)) => return emit_err(&msg, code),
        },
        None => None,
    };

    // Build the per-path index snapshot we restore the index from /
    // against. For unstaging this is `--source` (when given) or HEAD; for
    // the worktree-source fallback it is the same. Computing it once keeps
    // the path lookups O(1) per arg.
    let restore_index: Option<Index> = match resolve_restore_index(&store, source_tree, head_tree) {
        Ok(i) => i,
        Err(e) => return emit_err(&e, exit::GENERAL_ERROR),
    };

    // Resolve every pathspec to a repo-relative path.
    let mut rels: Vec<String> = Vec::with_capacity(opts.paths.len());
    for raw in &opts.paths {
        match index_path_for_arg(&cwd, Path::new(raw)) {
            Ok(p) => rels.push(p),
            Err(e) => return emit_err(&e, exit::DATAERR),
        }
    }

    if do_staged && let Err(code) = restore_staged(&cwd, &mut idx, restore_index.as_ref(), &rels) {
        return code;
    }

    if do_worktree
        && let Err(code) = restore_worktree(
            &cwd,
            &store,
            &idx,
            restore_index.as_ref(),
            &rels,
            source_tree.is_some(),
            opts.force,
        )
    {
        return code;
    }

    exit::OK
}

/// Resolve `--source <rev>` to a tree hash via the shared resolver.
fn resolve_source_tree(
    store: &ObjectStore,
    mkit_dir: &Path,
    spec: &str,
) -> Result<Hash, (String, u8)> {
    let commit = super::revspec::resolve_revision(store, mkit_dir, spec)
        .map_err(|e| (format!("bad --source '{spec}': {e}"), exit::GENERAL_ERROR))?;
    match store.read_object(&commit) {
        Ok(Object::Commit(c)) => Ok(c.tree_hash),
        Ok(Object::Remix(r)) => Ok(r.tree_hash),
        Ok(Object::Tree(_)) => Ok(commit),
        Ok(_) => Err((
            format!("--source '{spec}' does not resolve to a commit or tree"),
            exit::GENERAL_ERROR,
        )),
        Err(e) => Err((format!("read --source object: {e}"), exit::GENERAL_ERROR)),
    }
}

/// The index snapshot the restore sources from: `--source`'s tree when
/// supplied, else HEAD's tree. `None` means "no source" (unborn HEAD and
/// no `--source`), in which case unstaging removes the entry and the
/// worktree-source fallback finds nothing.
fn resolve_restore_index(
    store: &ObjectStore,
    source_tree: Option<Hash>,
    head_tree: Option<Hash>,
) -> Result<Option<Index>, String> {
    let tree = source_tree.or(head_tree);
    match tree {
        Some(t) => index::from_tree(store, t)
            .map(Some)
            .map_err(|e| format!("read source tree: {e}")),
        None => Ok(None),
    }
}

/// `--staged`: reset each matching index entry to the source snapshot
/// (HEAD/`--source`). A path present in the source becomes its source
/// entry; a path absent from the source is dropped from the index
/// (it was newly staged, so unstaging removes it entirely).
fn restore_staged(
    cwd: &Path,
    idx: &mut Index,
    restore_index: Option<&Index>,
    rels: &[String],
) -> Result<(), u8> {
    let mut matched_any = false;
    for rel in rels {
        let in_index = entry_matches(idx, rel);
        let in_source = restore_index
            .map(|src| entry_matches(src, rel))
            .unwrap_or_default();
        if in_index.is_empty() && in_source.is_empty() {
            return Err(emit_err(
                &format!("pathspec '{rel}' did not match any tracked or staged files"),
                exit::GENERAL_ERROR,
            ));
        }
        matched_any = true;

        // Every path that exists in either side and is at-or-below `rel`.
        let mut affected: Vec<String> = in_index
            .iter()
            .chain(in_source.iter())
            .map(|e| e.path.clone())
            .collect();
        affected.sort_unstable();
        affected.dedup();

        for path in affected {
            let source_entry =
                restore_index.and_then(|src| src.entries.iter().find(|e| e.path == path).cloned());
            apply_index_restore(idx, &path, source_entry);
        }
    }

    if !matched_any {
        return Ok(());
    }
    index::write_index(cwd, idx)
        .map_err(|e| emit_err(&format!("write index: {e}"), exit::CANTCREAT))
}

/// Overwrite (or remove) the index entry for `path` from `source`.
fn apply_index_restore(idx: &mut Index, path: &str, source: Option<IndexEntry>) {
    match source {
        Some(src) => {
            if let Some(pos) = idx.entries.iter().position(|e| e.path == path) {
                idx.entries[pos] = src;
            } else {
                idx.entries.push(src);
            }
        }
        None => {
            // Not present in the source: unstaging removes it from the
            // index entirely (it was a freshly-staged add).
            idx.entries.retain(|e| e.path != path);
        }
    }
}

/// Worktree restore: for each matching tracked path, rewrite the worktree
/// file from the source tree. Refuses (unless `force`) to clobber a
/// worktree file whose content diverges from the *index* entry, mirroring
/// the #176 destructive-restore guards.
fn restore_worktree(
    cwd: &Path,
    store: &ObjectStore,
    idx: &Index,
    restore_index: Option<&Index>,
    rels: &[String],
    explicit_source: bool,
    force: bool,
) -> Result<(), u8> {
    // The source for the worktree content: an explicit `--source`/HEAD
    // snapshot when one is set, otherwise the live index.
    let source = if explicit_source {
        restore_index.unwrap_or(idx)
    } else {
        idx
    };

    // Gather the tracked source entries each pathspec selects.
    let mut to_write: Vec<IndexEntry> = Vec::new();
    for rel in rels {
        let matches = entry_matches(source, rel);
        if matches.is_empty() {
            return Err(emit_err(
                &format!("pathspec '{rel}' did not match any tracked files"),
                exit::GENERAL_ERROR,
            ));
        }
        to_write.extend(matches);
    }
    to_write.sort_by(|a, b| a.path.cmp(&b.path));
    to_write.dedup_by(|a, b| a.path == b.path);

    // Dirty guard (unless --force): refuse to overwrite a worktree file
    // that diverges from its *index* entry — that is an un-staged edit
    // the user would lose. A path absent from the index, or whose
    // worktree content matches the index, is safe to rewrite.
    if !force {
        for entry in &to_write {
            if let Some(reason) = dirty_reason(cwd, store, idx, &entry.path) {
                return Err(emit_err(&reason, exit::GENERAL_ERROR));
            }
        }
    }

    // Materialise each selected path from the source tree using the
    // existing restore machinery (chunked-blob reassembly, exec-bit and
    // symlink handling, escape checks). We restore from the source tree
    // with `clean: false` (never delete neighbours) and a sparse pattern
    // anchored to exactly the selected paths.
    let source_tree = match worktree::build_tree_from_index(store, source) {
        Ok(t) => t,
        Err(e) => {
            return Err(emit_err(
                &format!("build source tree: {e}"),
                exit::GENERAL_ERROR,
            ));
        }
    };
    let patterns: Vec<SparsePattern> = to_write
        .iter()
        .map(|e| SparsePattern {
            pattern: e.path.clone(),
            negated: false,
            dir_only: false,
        })
        .collect();
    let restore_opts = RestoreOptions {
        clean: false,
        sparse_patterns: Some(patterns),
    };
    if let Err(e) = restore_tree_to_worktree(store, &source_tree, cwd, &restore_opts) {
        return Err(emit_err(&format!("restore worktree: {e}"), exit::CANTCREAT));
    }
    Ok(())
}

/// Tracked entries (status != Removed) at or below `rel`.
fn entry_matches(idx: &Index, rel: &str) -> Vec<IndexEntry> {
    idx.entries
        .iter()
        .filter(|e| {
            e.status != EntryStatus::Removed && super::index_path_matches_or_descends(&e.path, rel)
        })
        .cloned()
        .collect()
}

/// Return `Some(reason)` when the worktree file for `path` exists but
/// diverges from its staged (index) blob — the un-staged edit a worktree
/// restore would silently discard. Mirrors `rm`'s dirty check.
fn dirty_reason(root: &Path, _store: &ObjectStore, idx: &Index, path: &str) -> Option<String> {
    let staged = idx
        .entries
        .iter()
        .find(|e| e.path == path && e.status != EntryStatus::Removed)?;
    let abs = root.join(path);
    let meta = abs.symlink_metadata().ok()?;
    let work_hash = if meta.file_type().is_symlink() {
        let target = std::fs::read_link(&abs).ok()?;
        let target_str = target.to_str()?;
        symlink_blob_hash(target_str)?
    } else if meta.file_type().is_file() {
        worktree::read_regular_file_bounded(&abs)
            .ok()
            .and_then(|(_, data)| worktree::hash_file_object(&data).ok())?
    } else {
        // No worktree file (or a non-file): nothing to clobber.
        return None;
    };
    if work_hash == staged.object_hash {
        None
    } else {
        Some(format!(
            "'{path}' has unstaged changes; use --force to discard them"
        ))
    }
}

/// Hash a symlink target as a blob (matching `worktree`/`add` semantics).
fn symlink_blob_hash(target: &str) -> Option<Hash> {
    // Pure content-addressing — change detection must not write to the
    // store. Byte layout pinned to serialize() via blob_prologue.
    let prologue = mkit_core::serialize::blob_prologue(target.len()).ok()?;
    let mut hasher = mkit_core::hash::Hasher::new();
    hasher.update(&prologue).update(target.as_bytes());
    Some(hasher.finalize())
}

/// Normalise a CLI path argument into a repo-relative index path.
/// Mirrors `rm`'s resolver: absolute args are made relative to the repo
/// root, `.`/`..` are folded, and the result is validated.
fn index_path_for_arg(root: &Path, arg: &Path) -> Result<String, String> {
    let rel = if arg.is_absolute() {
        absolute_arg_to_repo_relative(root, arg)?
    } else {
        arg.to_path_buf()
    };

    let mut parts: Vec<String> = Vec::new();
    for component in rel.as_path().components() {
        match component {
            Component::Normal(part) => {
                let part = part
                    .to_str()
                    .ok_or_else(|| "path is not valid UTF-8".to_string())?;
                parts.push(part.to_string());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                if parts.pop().is_none() {
                    return Err(format!("invalid path: {}", arg.display()));
                }
            }
            Component::Prefix(_) | Component::RootDir => {
                return Err(format!("invalid path: {}", arg.display()));
            }
        }
    }

    let path = parts.join("/");
    if !index::validate_index_path(&path) {
        return Err(format!("invalid path: {path}"));
    }
    Ok(path)
}

fn absolute_arg_to_repo_relative(root: &Path, arg: &Path) -> Result<PathBuf, String> {
    let root = root.canonicalize().map_err(|e| format!("repo root: {e}"))?;

    if let Ok(rel) = arg.strip_prefix(&root) {
        return Ok(rel.to_path_buf());
    }

    let mut suffix: Vec<OsString> = vec![
        arg.file_name()
            .ok_or_else(|| format!("invalid path: {}", arg.display()))?
            .to_os_string(),
    ];
    let mut ancestor = arg
        .parent()
        .ok_or_else(|| format!("invalid path: {}", arg.display()))?;
    while ancestor.symlink_metadata().is_err() {
        let name = ancestor
            .file_name()
            .ok_or_else(|| format!("path is outside repository: {}", arg.display()))?;
        suffix.push(name.to_os_string());
        ancestor = ancestor
            .parent()
            .ok_or_else(|| format!("path is outside repository: {}", arg.display()))?;
    }

    let mut normalized = ancestor
        .canonicalize()
        .map_err(|e| format!("path {}: {e}", ancestor.display()))?;
    for component in suffix.iter().rev() {
        normalized.push(component);
    }

    normalized
        .strip_prefix(&root)
        .map(Path::to_path_buf)
        .map_err(|_| format!("path is outside repository: {}", arg.display()))
}

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}
