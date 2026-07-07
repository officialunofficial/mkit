//! Stash.
//!
//! On-disk format (`<repo_root>/.mkit/stash`) is a tagged binary
//! manifest:
//!
//! ```text
//! magic   : 4   bytes  "MKST"
//! count   : u32 LE
//! entries : count *
//!     commit_hash  : 32 bytes
//!     parent_hash  : 32 bytes
//!     timestamp    : u32 LE (Unix seconds, saturating)
//!     msg_len      : u16 LE
//!     message      : msg_len bytes
//! ```
//!
//! New stashes are prepended (LIFO).

use std::fmt::Write as _;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::atomic;
use crate::hash::{Hash, ZERO};
use crate::index::{self, Index};
use crate::layout::RepoLayout;
use crate::object::{Blob, Commit, EntryMode, Identity, Object, Tree, TreeEntry};
use crate::ops::diff::{DiffKind, DiffResult, diff_trees};
use crate::ops::restore::{self, RestoreOptions};
use crate::refs;
use crate::serialize;
use crate::store::ObjectStore;
use crate::worktree;

/// Magic bytes for the stash manifest: `MKST` ("`MKit` `STash`").
pub const MAGIC: [u8; 4] = *b"MKST";

/// Stash manifest path under the repo root.
pub const STASH_FILE: &str = ".mkit/stash";

/// Hard cap on manifest size (16 MiB).
pub const MAX_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;

/// Maximum stash message length (`u16` on the wire).
pub const MAX_MESSAGE_LEN: usize = u16::MAX as usize;

/// Minimum on-wire entry size, used to sanity-check attacker-supplied
/// `count` up-front during deserialise (so a tiny buffer declaring a huge
/// `count` cannot drive a large pre-allocation). Layout:
/// `commit_hash` (32) + `parent_hash` (32) + `timestamp` (4) +
/// `msg_len` (2) + message (0).
const MIN_ENTRY_BYTES: u64 = 32 + 32 + 4 + 2;

/// One entry in the stash stack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StashEntry {
    pub commit_hash: Hash,
    pub parent_hash: Hash,
    pub timestamp: u32,
    pub message: String,
}

/// The full stash stack (newest first).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StashList {
    pub entries: Vec<StashEntry>,
}

/// Errors raised by this module.
#[derive(Debug, thiserror::Error)]
pub enum StashError {
    #[error("stash index {0} is out of range")]
    IndexOutOfRange(usize),
    #[error("stash manifest exceeds the {MAX_MANIFEST_BYTES}-byte limit")]
    ManifestTooLarge,
    #[error("stash manifest format is invalid")]
    InvalidFormat,
    #[error("stash message exceeds {MAX_MESSAGE_LEN} bytes")]
    MessageTooLong,
    #[error("stash commit object is not a Commit")]
    NotACommit,
    #[error(transparent)]
    Diff(#[from] crate::store::StoreError),
    #[error(transparent)]
    Object(#[from] crate::object::MkitError),
    #[error(transparent)]
    Refs(#[from] crate::refs::RefError),
    #[error(transparent)]
    Index(#[from] crate::index::IndexError),
    #[error(transparent)]
    Worktree(#[from] crate::worktree::WorktreeError),
    #[error(transparent)]
    Restore(#[from] crate::ops::restore::RestoreError),
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Result alias.
pub type StashResult<T> = Result<T, StashError>;

/// Save the worktree as a stash entry, then reset the worktree to
/// HEAD:
///
/// 1. Build a tree from `repo_root` (skipping `.mkit/`).
/// 2. Resolve HEAD to a parent (or none for first commit).
/// 3. Create an unsigned `Commit` over that tree with `Ed25519` zero
///    pubkey author and zeroed signer/signature.
/// 4. Prepend a new [`StashEntry`] to the manifest.
/// 5. Restore the worktree to HEAD's tree.
/// 6. Truncate the index.
pub fn save(store: &ObjectStore, layout: &RepoLayout, message: &str) -> StashResult<()> {
    if message.len() > MAX_MESSAGE_LEN {
        return Err(StashError::MessageTooLong);
    }

    // One durability batch over the worktree snapshot, the staged-index
    // snapshot, and both commits — committed before the manifest write
    // that references them.
    let batch = store.batch();
    let tree_hash = worktree::build_tree(&batch, layout.worktree_root())?;
    let head_hash = refs::resolve_head(layout)?;

    let timestamp_u64 = unix_seconds_now();
    let zero_pk = [0u8; 32];

    // Capture the staged index as its own commit and record it as the
    // stash commit's SECOND parent (git-style `[HEAD, I]`), so
    // `stash pop/apply --index` can restore the staged state later. It is
    // reachable from the stash commit, so `gc` retains it (graph closure
    // follows every parent). Older single-parent entries simply carry no
    // index snapshot, and `--index` is a no-op for them.
    //
    // The index commit's tree is a fixed two-entry WRAPPER:
    //   `i` — a blob holding the SERIALIZED index. Unlike a tree, this
    //         preserves staged DELETIONS (`Removed` entries); a tree can
    //         only encode present paths.
    //   `t` — the staged-content tree (`build_tree_from_index`). It keeps the
    //         blobs of staged present files gc-reachable, since the serialized
    //         index blob is opaque to the gc graph walk.
    // The two reserved names can never collide with a tracked path, and this
    // tree is never materialized into a worktree (only the `i` blob is read
    // back on `--index`).
    //
    // A missing or empty index already reads as `Ok(Index::new())`, so the
    // `?` only surfaces a genuine error (corrupt/locked/oversized index).
    let staged = index::read_index(layout)?;
    let staged_tree = worktree::build_tree_from_index_with(store, &batch, &staged, true)?;
    let index_blob = batch.write(&serialize::serialize(&Object::Blob(Blob {
        data: staged.serialize(),
    }))?)?;
    let wrapper = Object::Tree(Tree {
        entries: vec![
            TreeEntry {
                name: b"i".to_vec(),
                mode: EntryMode::Blob,
                object_hash: index_blob,
            },
            TreeEntry {
                name: b"t".to_vec(),
                mode: EntryMode::Tree,
                object_hash: staged_tree,
            },
        ],
    });
    let wrapper_hash = batch.write(&serialize::serialize(&wrapper)?)?;
    let index_parents = head_hash.into_iter().collect::<Vec<_>>();
    let index_commit = Object::Commit(Commit::new_unannotated(
        wrapper_hash,
        index_parents,
        Identity::ed25519(zero_pk),
        [0u8; 32],
        b"index".to_vec(),
        timestamp_u64,
        [0u8; 64],
    ));
    let index_commit_hash = batch.write(&serialize::serialize(&index_commit)?)?;

    // Worktree commit: parents are `[HEAD, index_commit]` (HEAD omitted
    // when there is none), so the index snapshot is always the last parent
    // when a HEAD exists.
    let mut parents = head_hash.into_iter().collect::<Vec<_>>();
    parents.push(index_commit_hash);
    let commit = Object::Commit(Commit::new_unannotated(
        tree_hash,
        parents,
        Identity::ed25519(zero_pk),
        [0u8; 32],
        message.as_bytes().to_vec(),
        timestamp_u64,
        [0u8; 64],
    ));
    let commit_bytes = serialize::serialize(&commit)?;
    let stash_hash = batch.write(&commit_bytes)?;
    batch.commit()?;

    // Prepend the new entry.
    let mut list = read_list(layout)?;
    let ts_u32: u32 = timestamp_u64.try_into().unwrap_or(u32::MAX);
    let new_entry = StashEntry {
        commit_hash: stash_hash,
        parent_hash: head_hash.unwrap_or(ZERO),
        timestamp: ts_u32,
        message: message.to_string(),
    };
    list.entries.insert(0, new_entry);
    write_list(layout, &list)?;

    // Restore the worktree to HEAD's tree. In an UNBORN repo there is no HEAD,
    // so clear EVERY path captured in the worktree snapshot (tracked AND
    // untracked) — mirroring the HEAD case, where `restore_tree` removes
    // everything not in HEAD. Removing only the staged entries would leave
    // untracked files that the snapshot also captured, and a later
    // `pop`/`pop --index` would then refuse to overwrite them.
    if let Some(hh) = head_hash {
        let head_obj = store.read_object(&hh)?;
        if let Object::Commit(c) = head_obj {
            restore::restore_tree(
                store,
                c.tree_hash,
                layout.worktree_root(),
                &RestoreOptions::default(),
            )?;
        }
    } else {
        let snapshot = index::from_tree(store, tree_hash)?;
        for e in &snapshot.entries {
            let abs = layout.worktree_root().join(&e.path);
            if let Err(err) = std::fs::remove_file(&abs)
                && err.kind() != std::io::ErrorKind::NotFound
            {
                return Err(StashError::Io(err));
            }
            // Remove now-empty parent directories up to the repo root, so a
            // later `pop` can recreate the path without tripping the "would
            // overwrite untracked directory" guard.
            let mut parent = abs.parent();
            while let Some(dir) = parent {
                if dir == layout.worktree_root() || std::fs::remove_dir(dir).is_err() {
                    break;
                }
                parent = dir.parent();
            }
        }
    }

    // Clear the index.
    let _ = index::write_index(layout, &Index::new());
    Ok(())
}

/// List all stashes (newest first).
///
/// # Errors
/// - [`StashError::ManifestTooLarge`] / [`StashError::InvalidFormat`]
///   for a corrupt or oversized manifest.
pub fn list(layout: &RepoLayout) -> StashResult<StashList> {
    read_list(layout)
}

/// Resolve the tree hash recorded by stash entry `idx` (newest = 0)
/// without mutating anything. Callers use this to run a restore-safety
/// pre-flight (the #176 guard) over the stash tree before [`pop`].
///
/// # Errors
/// - [`StashError::IndexOutOfRange`] if `idx` is past the end.
/// - [`StashError::NotACommit`] if the stored object is not a Commit.
pub fn entry_tree_hash(store: &ObjectStore, layout: &RepoLayout, idx: usize) -> StashResult<Hash> {
    let list = read_list(layout)?;
    if idx >= list.entries.len() {
        return Err(StashError::IndexOutOfRange(idx));
    }
    let obj = store.read_object(&list.entries[idx].commit_hash)?;
    let Object::Commit(commit) = obj else {
        return Err(StashError::NotACommit);
    };
    Ok(commit.tree_hash)
}

/// The full staged index recorded by stash entry `idx`, if any.
///
/// New stashes record the staged state as the stash commit's second parent,
/// whose tree is a `{ i: <serialized-index blob>, t: <staged tree> }` wrapper
/// (see [`save`]); this reads back the `i` blob and deserializes it, so
/// `stash pop/apply --index` can restore the EXACT index — including staged
/// deletions (`Removed` entries), which a tree cannot represent.
///
/// Returns `Ok(None)` for entries that carry no index snapshot: those created
/// before the feature / saved with no HEAD (single parent), where `--index`
/// is a no-op.
///
/// # Errors
/// - [`StashError::IndexOutOfRange`] if `idx` is past the end.
/// - [`StashError::NotACommit`] if a stored object is not a Commit.
/// - [`StashError::Index`] if the serialized index blob is malformed.
pub fn entry_index(
    store: &ObjectStore,
    layout: &RepoLayout,
    idx: usize,
) -> StashResult<Option<Index>> {
    let list = read_list(layout)?;
    if idx >= list.entries.len() {
        return Err(StashError::IndexOutOfRange(idx));
    }
    let Object::Commit(stash_commit) = store.read_object(&list.entries[idx].commit_hash)? else {
        return Err(StashError::NotACommit);
    };
    // The index snapshot, when present, is always the LAST parent:
    //   [HEAD, index]  (normal)           -> parents[1]
    //   [index]        (unborn, no HEAD)  -> parents[0]
    //   [HEAD]         (legacy, no index) -> parents[0] IS the HEAD commit
    let Some(index_commit) = stash_commit.parents.last() else {
        return Ok(None);
    };
    // Disambiguate via the manifest's `parent_hash` (= HEAD at save time, or
    // ZERO when unborn) — NOT by sniffing the tree shape. The last parent
    // equals `parent_hash` EXACTLY for a legacy single-parent `[HEAD]` stash
    // (parent_hash=HEAD, last=HEAD): that carries no index snapshot, so return
    // None without inspecting the HEAD root tree (a legacy HEAD whose root
    // happens to contain top-level `i`/`t` files must NOT be misread as a
    // wrapper). For every other shape — `[HEAD, index]` (last=index≠HEAD) and
    // unborn `[index]` (last=index≠ZERO) — an index wrapper IS expected, so a
    // non-Tree / missing-marker / bad-blob is CORRUPTION and must fail closed
    // (never silently drop the only staged-state copy).
    let parent_hash = list.entries[idx].parent_hash;
    if *index_commit == parent_hash {
        return Ok(None);
    }
    let Object::Commit(index_commit) = store.read_object(index_commit)? else {
        return Err(StashError::NotACommit);
    };
    // The current-format index snapshot is a WRAPPER tree carrying BOTH the
    // serialized index blob (`i`) and the staged content tree (`t`).
    let Object::Tree(wrapper) = store.read_object(&index_commit.tree_hash)? else {
        return Err(StashError::InvalidFormat);
    };
    let has_index_blob = wrapper.entries.iter().any(|e| e.name == b"i");
    let has_content_tree = wrapper.entries.iter().any(|e| e.name == b"t");
    if !(has_index_blob && has_content_tree) {
        return Err(StashError::InvalidFormat);
    }
    // A malformed blob is likewise corruption: fail closed and preserve the
    // only staged-state copy, rather than silently dropping it (which
    // `pop --index` would then treat as "no index" and discard).
    let blob_entry = wrapper
        .entries
        .iter()
        .find(|e| e.name == b"i")
        .ok_or(StashError::InvalidFormat)?;
    let Object::Blob(blob) = store.read_object(&blob_entry.object_hash)? else {
        return Err(StashError::InvalidFormat);
    };
    Ok(Some(index::deserialize(&blob.data)?))
}

/// Pop a stash: restore its tree into the worktree and remove the
/// entry. Index 0 = newest.
///
/// # Safety against data loss
/// This restores **unconditionally** — it does not itself run the #176
/// destructive-restore guard, because that guard lives in the CLI layer
/// (`commands::ensure_restore_safe`). Callers that expose `pop` to users
/// **must** run [`entry_tree_hash`] + the guard first so uncommitted
/// edits on unrelated paths are never clobbered. The stash entry is
/// dropped only after a successful restore (restore failure short-
/// circuits via `?`, leaving the entry in place for a retry).
///
/// # Errors
/// - [`StashError::IndexOutOfRange`] if `index` is past the end.
pub fn pop(store: &ObjectStore, layout: &RepoLayout, idx: usize) -> StashResult<()> {
    let mut list = read_list(layout)?;
    if idx >= list.entries.len() {
        return Err(StashError::IndexOutOfRange(idx));
    }
    let entry = list.entries[idx].clone();
    let obj = store.read_object(&entry.commit_hash)?;
    let Object::Commit(commit) = obj else {
        return Err(StashError::NotACommit);
    };
    // Record the popped commit in the recovery log BEFORE removing the
    // manifest entry: restored worktree files are not crash-durable
    // (ops/restore writes them unflushed), and the manifest entry is
    // the stash commit's only gc root. Without this, a power loss in
    // the writeback window could lose both the restored bytes and the
    // only pointer for re-running the restore. The recovery log is a
    // durable gc root (SPEC-GC), so the commit stays reachable and
    // recoverable until the grace window expires.
    let ts = unix_seconds_now();
    crate::ops::recovery::record(
        layout,
        &crate::ops::recovery::RecoveryEntry {
            timestamp: ts,
            op: "stash-pop".to_string(),
            superseded: entry.commit_hash,
            branch: String::new(),
        },
    )
    .map_err(|e| StashError::Io(io::Error::other(format!("recovery log: {e}"))))?;
    restore::restore_tree(
        store,
        commit.tree_hash,
        layout.worktree_root(),
        &RestoreOptions::default(),
    )?;
    list.entries.remove(idx);
    write_list(layout, &list)?;
    Ok(())
}

/// Finalize a pop whose worktree (and, for `--index`, staged index) the
/// caller has already restored: record the popped commit in the recovery
/// log, then remove the manifest entry. Index 0 = newest.
///
/// Split out of [`pop`] so `pop --index` can restore the staged index
/// (a separate, fallible step in the CLI) **before** dropping the entry —
/// a failure there then leaves the stash in place for a normal retry,
/// rather than dropping it with the index half-restored.
///
/// # Errors
/// - [`StashError::IndexOutOfRange`] if `idx` is past the end.
pub fn pop_finalize(layout: &RepoLayout, idx: usize) -> StashResult<()> {
    let mut list = read_list(layout)?;
    if idx >= list.entries.len() {
        return Err(StashError::IndexOutOfRange(idx));
    }
    let entry = list.entries[idx].clone();
    let ts = unix_seconds_now();
    crate::ops::recovery::record(
        layout,
        &crate::ops::recovery::RecoveryEntry {
            timestamp: ts,
            op: "stash-pop".to_string(),
            superseded: entry.commit_hash,
            branch: String::new(),
        },
    )
    .map_err(|e| StashError::Io(io::Error::other(format!("recovery log: {e}"))))?;
    list.entries.remove(idx);
    write_list(layout, &list)?;
    Ok(())
}

/// Apply a stash entry's tree to the worktree **without** removing the
/// entry. Index 0 = newest. This is the non-destructive complement to
/// [`pop`]: it leaves the stash stack untouched so the same entry can be
/// re-applied or popped later.
///
/// # Safety against data loss
/// Like [`pop`], this restores **unconditionally** — it does not run the
/// #176 destructive-restore guard itself. Callers exposing `apply` to
/// users **must** run [`entry_tree_hash`] + `ensure_restore_safe` first,
/// exactly as `pop` does, so uncommitted edits on unrelated paths are
/// never clobbered.
///
/// # Errors
/// - [`StashError::IndexOutOfRange`] if `idx` is past the end.
/// - [`StashError::NotACommit`] if the stored object is not a Commit.
pub fn apply(store: &ObjectStore, layout: &RepoLayout, idx: usize) -> StashResult<()> {
    let list = read_list(layout)?;
    if idx >= list.entries.len() {
        return Err(StashError::IndexOutOfRange(idx));
    }
    let entry = &list.entries[idx];
    let obj = store.read_object(&entry.commit_hash)?;
    let Object::Commit(commit) = obj else {
        return Err(StashError::NotACommit);
    };
    restore::restore_tree(
        store,
        commit.tree_hash,
        layout.worktree_root(),
        &RestoreOptions::default(),
    )?;
    Ok(())
}

/// Drop **all** stash entries, leaving an empty stack. Idempotent — a
/// missing or already-empty manifest is not an error.
///
/// # Errors
/// - [`StashError::Io`] if the manifest cannot be written.
pub fn clear(layout: &RepoLayout) -> StashResult<()> {
    write_list(layout, &StashList::default())
}

/// Render `stash show [<stash>]` output: header + unified-diff-style listing.
///
/// Output format:
/// ```text
/// stash@{<idx>}: <message>
/// Date: <unix-timestamp>
///
/// <A|M|D> <path>
/// ...
/// ```
///
/// # Errors
/// - [`StashError::IndexOutOfRange`] if `idx` is past the end.
/// - [`StashError::NotACommit`] if the stored object is not a Commit.
/// - Store/object errors if objects cannot be read.
pub fn render_stash_show(
    store: &ObjectStore,
    layout: &RepoLayout,
    idx: usize,
) -> StashResult<String> {
    let list = read_list(layout)?;
    if idx >= list.entries.len() {
        return Err(StashError::IndexOutOfRange(idx));
    }
    let entry = &list.entries[idx];

    // Load the stash commit to get its tree.
    let stash_obj = store.read_object(&entry.commit_hash)?;
    let Object::Commit(stash_commit) = stash_obj else {
        return Err(StashError::NotACommit);
    };

    // Resolve parent tree (None if parent is the zero hash or commit load fails).
    let parent_tree: Option<Hash> = if entry.parent_hash == ZERO {
        None
    } else {
        match store.read_object(&entry.parent_hash) {
            Ok(Object::Commit(parent_commit)) => Some(parent_commit.tree_hash),
            _ => None,
        }
    };

    let diff = diff_trees(store, parent_tree, Some(stash_commit.tree_hash))?;

    let mut out = String::new();
    let _ = writeln!(out, "stash@{{{idx}}}: {}", entry.message);
    let _ = writeln!(out, "Date: {}", entry.timestamp);
    let _ = writeln!(out);
    for e in &diff.entries {
        let tag = match e.kind {
            DiffKind::Added => "A",
            DiffKind::Removed => "D",
            DiffKind::Modified => "M",
            DiffKind::ModeChanged => "T",
            DiffKind::Renamed => "R",
        };
        let _ = writeln!(out, "{tag} {}", e.path);
    }
    Ok(out)
}

/// Show the diff for a stash entry (raw [`DiffResult`]).
///
/// # Errors
/// - [`StashError::IndexOutOfRange`] if `idx` is past the end.
/// - [`StashError::NotACommit`] if the stash commit object is not a Commit.
pub fn show_diff(store: &ObjectStore, layout: &RepoLayout, idx: usize) -> StashResult<DiffResult> {
    let list = read_list(layout)?;
    if idx >= list.entries.len() {
        return Err(StashError::IndexOutOfRange(idx));
    }
    let entry = &list.entries[idx];

    let stash_obj = store.read_object(&entry.commit_hash)?;
    let Object::Commit(stash_commit) = stash_obj else {
        return Err(StashError::NotACommit);
    };

    let parent_tree: Option<Hash> = if entry.parent_hash == ZERO {
        None
    } else {
        match store.read_object(&entry.parent_hash) {
            Ok(Object::Commit(parent_commit)) => Some(parent_commit.tree_hash),
            _ => None,
        }
    };

    Ok(diff_trees(
        store,
        parent_tree,
        Some(stash_commit.tree_hash),
    )?)
}

/// Drop a stash without applying it.
///
/// # Errors
/// - [`StashError::IndexOutOfRange`] if `index` is past the end.
pub fn drop(layout: &RepoLayout, idx: usize) -> StashResult<()> {
    let mut list = read_list(layout)?;
    if idx >= list.entries.len() {
        return Err(StashError::IndexOutOfRange(idx));
    }
    list.entries.remove(idx);
    write_list(layout, &list)?;
    Ok(())
}

// -- Manifest IO -------------------------------------------------------------

fn stash_path(layout: &RepoLayout) -> PathBuf {
    layout.stash_file()
}

fn read_list(layout: &RepoLayout) -> StashResult<StashList> {
    let path = stash_path(layout);
    let meta = match fs::metadata(&path) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(StashList::default()),
        Err(e) => return Err(StashError::Io(e)),
    };
    if meta.len() == 0 {
        return Ok(StashList::default());
    }
    if meta.len() > MAX_MANIFEST_BYTES {
        return Err(StashError::ManifestTooLarge);
    }
    let data = fs::read(&path)?;
    deserialize_list(&data)
}

fn write_list(layout: &RepoLayout, list: &StashList) -> StashResult<()> {
    let bytes = serialize_list(list)?;
    let path = stash_path(layout);
    atomic::write_atomic(&path, &bytes, true)?;
    Ok(())
}

/// Write a [`StashList`] to disk. Public only for integration-test goldens.
///
/// # Panics
/// Panics if serialization or the write fails (test-only helper).
pub fn write_list_test_only(layout: &RepoLayout, list: &StashList) {
    write_list(layout, list).expect("write_list_test_only failed");
}

/// Encode a [`StashList`] as the on-disk manifest. Public for goldens.
///
/// # Errors
/// - [`StashError::MessageTooLong`] if any entry message exceeds [`MAX_MESSAGE_LEN`].
pub fn serialize_list(list: &StashList) -> StashResult<Vec<u8>> {
    let mut total = 4 + 4;
    for e in &list.entries {
        if e.message.len() > MAX_MESSAGE_LEN {
            return Err(StashError::MessageTooLong);
        }
        total += 32 + 32 + 4 + 2 + e.message.len();
    }
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(
        &u32::try_from(list.entries.len())
            .unwrap_or(u32::MAX)
            .to_le_bytes(),
    );
    for e in &list.entries {
        out.extend_from_slice(&e.commit_hash);
        out.extend_from_slice(&e.parent_hash);
        out.extend_from_slice(&e.timestamp.to_le_bytes());
        let len_u16 = u16::try_from(e.message.len()).map_err(|_| StashError::MessageTooLong)?;
        out.extend_from_slice(&len_u16.to_le_bytes());
        out.extend_from_slice(e.message.as_bytes());
    }
    Ok(out)
}

/// Decode the on-disk manifest. Public for goldens.
///
/// # Errors
/// - [`StashError::InvalidFormat`] if the bytes are malformed.
pub fn deserialize_list(data: &[u8]) -> StashResult<StashList> {
    if data.len() < 8 {
        return Err(StashError::InvalidFormat);
    }
    if &data[..4] != MAGIC.as_slice() {
        return Err(StashError::InvalidFormat);
    }
    let count = u32::from_le_bytes(
        data[4..8]
            .try_into()
            .map_err(|_| StashError::InvalidFormat)?,
    ) as usize;
    // Reject an attacker-supplied `count` that cannot possibly fit in
    // the remaining body. With [`MIN_ENTRY_BYTES`] = 70 (empty message)
    // an 8-byte header declaring count = u32::MAX is rejected here
    // instead of driving `Vec::with_capacity(u32::MAX)`.
    if (count as u64).saturating_mul(MIN_ENTRY_BYTES) > data.len() as u64 {
        return Err(StashError::InvalidFormat);
    }
    let mut entries = Vec::with_capacity(count);
    let mut pos = 8usize;
    for _ in 0..count {
        if pos + 32 + 32 + 4 + 2 > data.len() {
            return Err(StashError::InvalidFormat);
        }
        let mut commit_hash = [0u8; 32];
        commit_hash.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;
        let mut parent_hash = [0u8; 32];
        parent_hash.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;
        let timestamp = u32::from_le_bytes(
            data[pos..pos + 4]
                .try_into()
                .map_err(|_| StashError::InvalidFormat)?,
        );
        pos += 4;
        let msg_len = u16::from_le_bytes(
            data[pos..pos + 2]
                .try_into()
                .map_err(|_| StashError::InvalidFormat)?,
        ) as usize;
        pos += 2;
        if pos + msg_len > data.len() {
            return Err(StashError::InvalidFormat);
        }
        let msg = String::from_utf8(data[pos..pos + msg_len].to_vec())
            .map_err(|_| StashError::InvalidFormat)?;
        pos += msg_len;
        entries.push(StashEntry {
            commit_hash,
            parent_hash,
            timestamp,
            message: msg,
        });
    }
    Ok(StashList { entries })
}

fn unix_seconds_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash;
    use crate::object::{Blob, Commit, EntryMode, Identity, Object, Tree, TreeEntry};
    use crate::ops::diff::DiffKind;
    use crate::serialize;
    use crate::store::ObjectStore;
    use tempfile::TempDir;

    fn fresh_store() -> (TempDir, ObjectStore) {
        let dir = TempDir::new().unwrap();
        let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
        (dir, store)
    }

    fn put_blob_data(store: &ObjectStore, data: &[u8]) -> Hash {
        let obj = Object::Blob(Blob {
            data: data.to_vec(),
        });
        store.write(&serialize::serialize(&obj).unwrap()).unwrap()
    }

    fn put_tree_entries(store: &ObjectStore, entries: Vec<TreeEntry>) -> Hash {
        let obj = Object::Tree(Tree { entries });
        store.write(&serialize::serialize(&obj).unwrap()).unwrap()
    }

    fn put_commit_obj(store: &ObjectStore, tree_h: Hash, parents: Vec<Hash>, ts: u64) -> Hash {
        let commit = Object::Commit(Commit::new_unannotated(
            tree_h,
            parents,
            Identity::ed25519([0u8; 32]),
            [0u8; 32],
            b"msg".to_vec(),
            ts,
            [0u8; 64],
        ));
        store
            .write(&serialize::serialize(&commit).unwrap())
            .unwrap()
    }

    /// Build a deterministic stash fixture: parent commit has `existing.txt`,
    /// stash commit adds `new.txt` and modifies `existing.txt`.
    fn build_stash_fixture(store: &ObjectStore, layout: &RepoLayout) {
        // Parent tree: one file "existing.txt"
        let blob_v1 = put_blob_data(store, b"original content");
        let parent_tree = put_tree_entries(
            store,
            vec![TreeEntry {
                name: b"existing.txt".to_vec(),
                mode: EntryMode::Blob,
                object_hash: blob_v1,
            }],
        );
        let parent_commit = put_commit_obj(store, parent_tree, vec![], 1_000_000);

        // Stash tree: existing.txt modified + new.txt added
        let blob_v2 = put_blob_data(store, b"modified content");
        let blob_new = put_blob_data(store, b"brand new file");
        let stash_tree = put_tree_entries(
            store,
            vec![
                TreeEntry {
                    name: b"existing.txt".to_vec(),
                    mode: EntryMode::Blob,
                    object_hash: blob_v2,
                },
                TreeEntry {
                    name: b"new.txt".to_vec(),
                    mode: EntryMode::Blob,
                    object_hash: blob_new,
                },
            ],
        );
        let stash_commit = put_commit_obj(store, stash_tree, vec![parent_commit], 1_000_001);

        let list = StashList {
            entries: vec![StashEntry {
                commit_hash: stash_commit,
                parent_hash: parent_commit,
                timestamp: 1_000_001_u32,
                message: "WIP: stash message".to_string(),
            }],
        };
        write_list(layout, &list).unwrap();
    }

    #[test]
    fn show_diff_returns_correct_entries() {
        let (tmp, store) = fresh_store();
        let layout = RepoLayout::single(tmp.path());
        build_stash_fixture(&store, &layout);

        let diff = show_diff(&store, &layout, 0).unwrap();
        assert_eq!(diff.entries.len(), 2, "expected 2 diff entries");

        let existing = diff.entries.iter().find(|e| e.path == "existing.txt");
        let new_f = diff.entries.iter().find(|e| e.path == "new.txt");
        assert!(existing.is_some(), "existing.txt must appear in diff");
        assert!(new_f.is_some(), "new.txt must appear in diff");
        assert_eq!(existing.unwrap().kind, DiffKind::Modified);
        assert_eq!(new_f.unwrap().kind, DiffKind::Added);
    }

    #[test]
    fn render_stash_show_header_and_entries() {
        let (tmp, store) = fresh_store();
        let layout = RepoLayout::single(tmp.path());
        build_stash_fixture(&store, &layout);

        let output = render_stash_show(&store, &layout, 0).unwrap();
        assert!(
            output.contains("stash@{0}:"),
            "missing stash header: {output}"
        );
        assert!(
            output.contains("WIP: stash message"),
            "missing message: {output}"
        );
        assert!(output.contains("Date:"), "missing date line: {output}");
        assert!(
            output.contains("M existing.txt"),
            "missing modified entry: {output}"
        );
        assert!(
            output.contains("A new.txt"),
            "missing added entry: {output}"
        );
    }

    #[test]
    fn apply_restores_tree_and_keeps_entry() {
        let (tmp, store) = fresh_store();
        let layout = RepoLayout::single(tmp.path());
        build_stash_fixture(&store, &layout);
        assert_eq!(read_list(&layout).unwrap().entries.len(), 1);

        apply(&store, &layout, 0).unwrap();

        // The stash tree was materialised into the worktree.
        assert_eq!(
            fs::read(tmp.path().join("existing.txt")).unwrap(),
            b"modified content"
        );
        assert_eq!(
            fs::read(tmp.path().join("new.txt")).unwrap(),
            b"brand new file"
        );
        // ...and the entry is still on the stack (apply, not pop).
        assert_eq!(
            read_list(&layout).unwrap().entries.len(),
            1,
            "apply must not drop the entry"
        );
    }

    #[test]
    fn entry_index_round_trips_index_including_staged_deletions() {
        // A real `save` records the FULL serialized index (not a tree), so a
        // staged deletion (`Removed` entry) — which a tree cannot encode —
        // survives `entry_index`.
        let dir = tempfile::TempDir::new().unwrap();
        let layout = RepoLayout::single(dir.path());
        let store = ObjectStore::init(&layout).unwrap();
        let blob_a = put_blob_data(&store, b"a");
        let tree = put_tree_entries(
            &store,
            vec![TreeEntry {
                name: b"a.txt".to_vec(),
                mode: EntryMode::Blob,
                object_hash: blob_a,
            }],
        );
        let head = put_commit_obj(&store, tree, vec![], 5);
        refs::write_head_branch(&layout, "main").unwrap();
        refs::write_ref(&layout, "main", &head).unwrap();
        std::fs::write(dir.path().join("a.txt"), b"a").unwrap();

        // Stage `a.txt` (present) and a deletion of `b.txt` (Removed).
        let staged = Index {
            entries: vec![
                index::IndexEntry {
                    path: "a.txt".to_string(),
                    status: index::EntryStatus::Blob,
                    object_hash: blob_a,
                    mtime_ns: 0,
                    size: 0,
                    ino: 0,
                    ctime_ns: 0,
                },
                index::IndexEntry {
                    path: "b.txt".to_string(),
                    status: index::EntryStatus::Removed,
                    object_hash: ZERO,
                    mtime_ns: 0,
                    size: 0,
                    ino: 0,
                    ctime_ns: 0,
                },
            ],
        };
        index::write_index(&layout, &staged).unwrap();

        save(&store, &layout, "wip").unwrap();

        let restored = entry_index(&store, &layout, 0)
            .unwrap()
            .expect("save must record an index snapshot");
        let b = restored
            .entries
            .iter()
            .find(|e| e.path == "b.txt")
            .expect("the staged deletion must be present");
        assert_eq!(
            b.status,
            index::EntryStatus::Removed,
            "staged deletion must round-trip as Removed"
        );
        assert!(
            restored
                .entries
                .iter()
                .any(|e| e.path == "a.txt" && e.status == index::EntryStatus::Blob),
            "the present staged file must round-trip too"
        );
    }

    #[test]
    fn entry_index_none_for_single_parent_entry() {
        // Historical single-parent (`[HEAD]`) entries carry no index
        // snapshot, so `--index` is a no-op for them.
        let (tmp, store) = fresh_store();
        let layout = RepoLayout::single(tmp.path());
        build_stash_fixture(&store, &layout);
        assert!(entry_index(&store, &layout, 0).unwrap().is_none());
    }

    #[test]
    fn entry_index_fails_closed_on_corrupt_multiparent_wrapper() {
        // A 2-parent stash `[HEAD, index]` is always current-format, so its
        // last parent MUST be a valid `i`/`t` wrapper. A non-wrapper tree
        // there is corruption — `entry_index` must FAIL CLOSED (InvalidFormat)
        // rather than silently return None, which would let `pop --index` drop
        // the only staged-state copy.
        let (tmp, store) = fresh_store();
        let root = &RepoLayout::single(tmp.path());
        let head_tree = put_tree_entries(&store, vec![]);
        let head_commit = put_commit_obj(&store, head_tree, vec![], 1);
        // A bogus "index" commit whose tree lacks the i/t wrapper markers.
        let bogus_tree = put_tree_entries(
            &store,
            vec![TreeEntry {
                name: b"not_a_wrapper".to_vec(),
                mode: EntryMode::Blob,
                object_hash: put_blob_data(&store, b"junk"),
            }],
        );
        let bogus_index_commit = put_commit_obj(&store, bogus_tree, vec![head_commit], 2);
        let stash_commit =
            put_commit_obj(&store, head_tree, vec![head_commit, bogus_index_commit], 3);
        write_list(
            root,
            &StashList {
                entries: vec![StashEntry {
                    commit_hash: stash_commit,
                    parent_hash: head_commit,
                    timestamp: 3,
                    message: "WIP".to_string(),
                }],
            },
        )
        .unwrap();
        assert!(
            matches!(entry_index(&store, root, 0), Err(StashError::InvalidFormat)),
            "a corrupt multi-parent wrapper must fail closed"
        );
    }

    #[test]
    fn entry_index_fails_closed_on_corrupt_unborn_wrapper() {
        // A single-parent UNBORN `[index]` stash (parent_hash == ZERO) whose
        // wrapper is corrupt must ALSO fail closed — disambiguated by
        // parent_hash, not parent count.
        let (tmp, store) = fresh_store();
        let root = &RepoLayout::single(tmp.path());
        let bogus_tree = put_tree_entries(
            &store,
            vec![TreeEntry {
                name: b"junk".to_vec(),
                mode: EntryMode::Blob,
                object_hash: put_blob_data(&store, b"x"),
            }],
        );
        let index_commit = put_commit_obj(&store, bogus_tree, vec![], 1);
        let stash_commit = put_commit_obj(&store, bogus_tree, vec![index_commit], 2);
        write_list(
            root,
            &StashList {
                entries: vec![StashEntry {
                    commit_hash: stash_commit,
                    parent_hash: ZERO, // unborn: no HEAD
                    timestamp: 2,
                    message: "WIP".to_string(),
                }],
            },
        )
        .unwrap();
        assert!(
            matches!(entry_index(&store, root, 0), Err(StashError::InvalidFormat)),
            "a corrupt unborn [index] wrapper must fail closed"
        );
    }

    #[test]
    fn entry_index_legacy_head_with_coincidental_markers_reads_as_none() {
        // A LEGACY single-parent `[HEAD]` stash (parent_hash == sole parent)
        // whose HEAD root tree HAPPENS to carry top-level `i`+`t` files must be
        // treated as no-index (parent_hash short-circuit), NOT misread as a
        // wrapper.
        let (tmp, store) = fresh_store();
        let root = &RepoLayout::single(tmp.path());
        let head_tree = put_tree_entries(
            &store,
            vec![
                TreeEntry {
                    name: b"i".to_vec(),
                    mode: EntryMode::Blob,
                    object_hash: put_blob_data(&store, b"not an index"),
                },
                TreeEntry {
                    name: b"t".to_vec(),
                    mode: EntryMode::Blob,
                    object_hash: put_blob_data(&store, b"whatever"),
                },
            ],
        );
        let head_commit = put_commit_obj(&store, head_tree, vec![], 1);
        let stash_commit = put_commit_obj(&store, head_tree, vec![head_commit], 2);
        write_list(
            root,
            &StashList {
                entries: vec![StashEntry {
                    commit_hash: stash_commit,
                    parent_hash: head_commit, // legacy: parent_hash == sole parent
                    timestamp: 2,
                    message: "legacy".to_string(),
                }],
            },
        )
        .unwrap();
        assert!(
            entry_index(&store, root, 0).unwrap().is_none(),
            "legacy [HEAD] must read as no-index regardless of tree shape"
        );
    }

    #[test]
    fn apply_out_of_range_returns_error() {
        let (tmp, _store) = fresh_store();
        let layout = RepoLayout::single(tmp.path());
        let store = ObjectStore::open(&layout).unwrap();
        let err = apply(&store, &layout, 0).unwrap_err();
        assert!(matches!(err, StashError::IndexOutOfRange(0)));
    }

    #[test]
    fn clear_empties_the_stack() {
        let (tmp, store) = fresh_store();
        let layout = RepoLayout::single(tmp.path());
        build_stash_fixture(&store, &layout);
        assert_eq!(read_list(&layout).unwrap().entries.len(), 1);

        clear(&layout).unwrap();
        assert!(read_list(&layout).unwrap().entries.is_empty());

        // Idempotent: clearing an already-empty stack is fine.
        clear(&layout).unwrap();
        assert!(read_list(&layout).unwrap().entries.is_empty());
    }

    #[test]
    fn show_diff_out_of_range_returns_error() {
        let (tmp, _store) = fresh_store();
        let layout = RepoLayout::single(tmp.path());
        let store = ObjectStore::open(&layout).unwrap();
        let err = show_diff(&store, &layout, 0).unwrap_err();
        assert!(matches!(err, StashError::IndexOutOfRange(0)));
    }

    #[test]
    fn manifest_roundtrip_two_entries() {
        let list = StashList {
            entries: vec![
                StashEntry {
                    commit_hash: hash::hash(b"commit1"),
                    parent_hash: hash::hash(b"parent1"),
                    timestamp: 1000,
                    message: "first stash".to_string(),
                },
                StashEntry {
                    commit_hash: hash::hash(b"commit2"),
                    parent_hash: ZERO,
                    timestamp: 2000,
                    message: "second stash".to_string(),
                },
            ],
        };
        let bytes = serialize_list(&list).unwrap();
        let back = deserialize_list(&bytes).unwrap();
        assert_eq!(back, list);
    }

    #[test]
    fn deserialize_rejects_short_data() {
        assert!(matches!(
            deserialize_list(&[0u8; 4]),
            Err(StashError::InvalidFormat)
        ));
    }

    #[test]
    fn deserialize_rejects_bad_magic() {
        assert!(matches!(
            deserialize_list(&[b'X', b'Y', b'Z', b'W', 0, 0, 0, 0]),
            Err(StashError::InvalidFormat)
        ));
    }

    #[test]
    fn deserialize_rejects_bogus_huge_count() {
        // G12 regression: an 8-byte manifest whose header declares
        // count = u32::MAX must be rejected up-front — the decoder
        // must NOT call `Vec::with_capacity(u32::MAX)` nor loop that
        // many times.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC.as_slice());
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        // No entries follow.
        assert!(matches!(
            deserialize_list(&bytes),
            Err(StashError::InvalidFormat)
        ));
    }
    /// `pop` must record the popped commit in the recovery log BEFORE
    /// dropping the manifest entry — the only pointer keeping the stash
    /// commit gc-reachable while the (unflushed) worktree restore is in
    /// the writeback window.
    #[test]
    fn pop_records_recovery_entry_for_popped_commit() {
        let dir = tempfile::TempDir::new().unwrap();
        let layout = RepoLayout::single(dir.path());
        let store = ObjectStore::init(&layout).unwrap();
        std::fs::write(dir.path().join("file.txt"), b"stash me").unwrap();
        save(&store, &layout, "wip").unwrap();
        let entry_hash = read_list(&layout).unwrap().entries[0].commit_hash;

        pop(&store, &layout, 0).unwrap();

        let log = crate::ops::recovery::read_all(&layout).unwrap();
        assert!(
            log.iter()
                .any(|e| e.op == "stash-pop" && e.superseded == entry_hash),
            "popped stash commit must be recorded as recoverable; log: {log:?}"
        );
        assert!(read_list(&layout).unwrap().entries.is_empty());
    }
}
