//! Repository path layout: the single authority for resolving on-disk
//! state under `.mkit/` (issue #493, Phase 0).
//!
//! Every piece of repository state is classified into exactly one of two
//! directories:
//!
//! - the **common dir** — state shared by every working tree of the
//!   repository: the object store, refs, config, signing keys, the
//!   history MMR, the recovery log, attestations, transport caches;
//! - the **worktree state dir** — state private to one working tree:
//!   `HEAD`, the staging index, in-progress-operation files
//!   (`MERGE_HEAD`, `rebase-apply/`, …), the stash, and the worktree
//!   lock.
//!
//! In the classic single-worktree layout both directories are the same
//! `<root>/.mkit/`, so [`RepoLayout::single`] produces byte-identical
//! paths to the historical ad-hoc joins. In a **linked** working tree
//! (#493 Phase 1) they differ: the linked tree's per-tree state lives
//! under the main repository's `.mkit/worktrees/<id>/`, and the linked
//! tree's own `.mkit` is a plain FILE — the pointer file — instead of
//! a directory. Nothing outside this module may assume the two
//! directories coincide.
//!
//! # Linked-worktree on-disk model (#493 Phase 1)
//!
//! ```text
//! <main>/.mkit/                       # common dir (shared state)
//!   worktrees/<id>/                   # one per linked tree
//!     commondir                       # path to the common dir, `../..`
//!     mkitdir                         # abs path of the tree's pointer file
//!     HEAD, index, ORIG_HEAD, ...     # per-tree state, as classified below
//! <linked-tree>/.mkit                 # pointer FILE, not a directory:
//!     `mkitdir: <path to .mkit/worktrees/<id>>\n`
//! ```
//!
//! The pointer path may be absolute or relative to the linked tree
//! root; `commondir` may be absolute or relative to the state dir.
//! Both files are UTF-8, single-line, LF-terminated, and capped at
//! [`MAX_POINTER_FILE_BYTES`]. Discovery ([`discover`]) fails closed on
//! any malformed or dangling pointer; a `.mkit` DIRECTORY (every
//! pre-Phase-1 repository) always resolves to the single-worktree
//! layout, byte-identical to before.
//!
//! # Classification table
//!
//! | Path (relative)          | Class    | Owner module            |
//! |--------------------------|----------|-------------------------|
//! | `objects/`               | common   | [`crate::store`]        |
//! | `format`                 | common   | [`crate::store`]        |
//! | `refs/` (+`heads`,`tags`,`remotes`) | common | [`crate::refs`] |
//! | `shallow`                | common   | [`crate::refs`]         |
//! | `config`                 | common   | CLI config              |
//! | `keys/`                  | common   | CLI config              |
//! | `history/`               | common   | [`crate::history`] (feature-gated) |
//! | `recovery-log`           | common   | [`crate::ops::recovery`] |
//! | `attestations/`          | common   | `mkit-attest`           |
//! | `applied-packs/`         | common   | CLI remote dispatch (redownload cache, never a gc root) |
//! | `git/`                   | common   | `mkit-git-bridge`       |
//! | `sparse/`                | common   | CLI sparse bitmap cache |
//! | `pack-shards/`           | common   | CLI pack-shard output   |
//! | `HEAD`                   | worktree | [`crate::refs`]         |
//! | `index`                  | worktree | [`crate::index`]        |
//! | `ORIG_HEAD`              | worktree | [`crate::ops::conflict_state`] |
//! | `MERGE_HEAD`/`MERGE_MSG` | worktree | [`crate::ops::conflict_state`] |
//! | `CHERRY_PICK_HEAD`/`_MSG`| worktree | [`crate::ops::conflict_state`] |
//! | `REVERT_HEAD`/`_MSG`     | worktree | [`crate::ops::conflict_state`] |
//! | `mkit-conflicts`         | worktree | [`crate::ops::conflict_state`] |
//! | `MKIT_OP_RESULT`         | worktree | [`crate::ops::conflict_state`] |
//! | `rebase-apply/`          | worktree | [`crate::ops::rebase`]  |
//! | `bisect`                 | worktree | [`crate::ops::bisect`]  |
//! | `stash`                  | worktree | [`crate::ops::stash`]   |
//! | `sparse-checkout`        | worktree | [`crate::ops::restore`] |
//! | `worktree.lock`          | worktree | CLI lock helper         |
//!
//! Rationale for the git-divergent entries: `shallow` is shared because
//! it constrains the one shared object graph; the stash is per-worktree
//! (unlike git's `refs/stash`) because mkit's stash is a worktree-state
//! manifest, not a ref — #493 specifies stash as tree-local.
//!
//! # Invariants
//!
//! - Both directories always end in a final `.mkit` component (a linked
//!   tree's state dir will live *under* the main `.mkit`; that still
//!   satisfies the prefix rule below).
//! - Every accessor resolves strictly inside `common_dir()` or
//!   `worktree_state_dir()`; no accessor ever escapes them.
//! - [`RepoLayout::single`] guarantees `common_dir() ==
//!   worktree_state_dir() == worktree_root().join(".mkit")`.

use std::path::{Path, PathBuf};

use crate::ops::bisect::BISECT_FILE;
use crate::ops::conflict_state::{
    CHERRY_PICK_HEAD, CHERRY_PICK_MSG, CONFLICTS_FILE, MERGE_HEAD, MERGE_MSG, ORIG_HEAD,
    RESULT_TREE, REVERT_HEAD, REVERT_MSG,
};
use crate::ops::rebase::REBASE_DIR;
use crate::ops::recovery::RECOVERY_LOG;
use crate::refs::{HEAD_FILE, HEADS_DIR, REFS_DIR, REMOTES_DIR, SHALLOW_FILE, TAGS_DIR};
use crate::store::{FORMAT_FILE, MKIT_DIR, OBJECTS_DIR};

/// Commit-history MMR directory name under the common dir. Canonical
/// here (rather than in [`crate::history`]) because that module is
/// feature-gated while the layout is not; `history::HISTORY_DIR`
/// re-points at this constant.
pub const HISTORY_DIR_NAME: &str = "history";
/// Config file name under the common dir (written by the CLI).
pub const CONFIG_FILE_NAME: &str = "config";
/// Repository signing-key directory name under the common dir.
pub const KEYS_DIR_NAME: &str = "keys";
/// Staging-index file name under the worktree state dir.
pub const INDEX_FILE_NAME: &str = "index";
/// Stash manifest file name under the worktree state dir.
pub const STASH_FILE_NAME: &str = "stash";
/// Sparse-checkout filter file name under the worktree state dir.
pub const SPARSE_CHECKOUT_FILE_NAME: &str = "sparse-checkout";
/// Attestation store directory name under the common dir.
pub const ATTESTATIONS_DIR_NAME: &str = "attestations";
/// Per-remote applied-pack record directory name under the common dir.
/// A redownload-avoidance cache — never a gc root source (#409).
pub const APPLIED_PACKS_DIR_NAME: &str = "applied-packs";
/// Git-bridge per-remote state directory name under the common dir.
pub const GIT_STATE_DIR_NAME: &str = "git";
/// Sparse bitmap-cache directory name under the common dir.
pub const SPARSE_CACHE_DIR_NAME: &str = "sparse";
/// Default pack-shard output directory name under the common dir.
pub const PACK_SHARDS_DIR_NAME: &str = "pack-shards";
/// Directory under the common dir holding one per-tree state dir per
/// linked worktree.
pub const WORKTREES_DIR_NAME: &str = "worktrees";
/// Prefix of the linked-tree pointer file (`<tree>/.mkit` as a FILE):
/// `mkitdir: <path>\n` — the analog of git's `gitdir:` file.
pub const POINTER_PREFIX: &str = "mkitdir: ";
/// File inside a per-tree state dir recording the path back to the
/// common dir (relative to the state dir, or absolute). Written as
/// `../..` by `worktree add`.
pub const COMMONDIR_FILE_NAME: &str = "commondir";
/// File inside a per-tree state dir recording the absolute path of the
/// linked tree's pointer file — the back-pointer `worktree prune`
/// checks before deleting a state dir.
pub const BACKPOINTER_FILE_NAME: &str = "mkitdir";
/// Hard cap on the pointer, `commondir`, and back-pointer files. Far
/// above any real path, small enough that a corrupt or hostile file
/// cannot balloon discovery.
pub const MAX_POINTER_FILE_BYTES: u64 = 4096;

/// Resolved repository layout: worktree root plus the two state
/// directories (see the module docs for the classification table).
///
/// Cheap to clone; construction never touches the filesystem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoLayout {
    /// Directory containing the working files (the parent of `.mkit`
    /// in the single-worktree layout).
    worktree_root: PathBuf,
    /// Shared state directory (`<main root>/.mkit`).
    common_dir: PathBuf,
    /// Per-worktree state directory. Equal to `common_dir` in the
    /// single-worktree layout.
    worktree_state_dir: PathBuf,
}

impl RepoLayout {
    /// Layout of a classic single-worktree repository rooted at
    /// `worktree_root`: common dir and worktree state dir are both
    /// `<worktree_root>/.mkit`.
    #[must_use]
    pub fn single(worktree_root: impl Into<PathBuf>) -> Self {
        let worktree_root = worktree_root.into();
        let mkit = worktree_root.join(MKIT_DIR);
        Self {
            worktree_root,
            common_dir: mkit.clone(),
            worktree_state_dir: mkit,
        }
    }

    /// The working-tree root (directory whose files are under version
    /// control).
    #[must_use]
    pub fn worktree_root(&self) -> &Path {
        &self.worktree_root
    }

    /// Shared state directory. Everything in it is common to all
    /// working trees of the repository.
    #[must_use]
    pub fn common_dir(&self) -> &Path {
        &self.common_dir
    }

    /// Per-worktree state directory. Everything in it belongs to this
    /// working tree only.
    #[must_use]
    pub fn worktree_state_dir(&self) -> &Path {
        &self.worktree_state_dir
    }

    /// `true` when common dir and worktree state dir coincide (the
    /// classic single-worktree layout).
    #[must_use]
    pub fn is_single(&self) -> bool {
        self.common_dir == self.worktree_state_dir
    }

    /// Layout of a linked working tree (#493 Phase 1): working files at
    /// `worktree_root`, per-tree state in `worktree_state_dir` (a
    /// `worktrees/<id>` dir under the main repository's common dir),
    /// shared state in `common_dir`.
    ///
    /// Pure construction — no filesystem access, no validation beyond
    /// types. Production code obtains linked layouts via [`discover`],
    /// which validates the on-disk pointers; this constructor is the
    /// seam `discover` and `worktree add` build on.
    #[must_use]
    pub fn linked(
        worktree_root: impl Into<PathBuf>,
        worktree_state_dir: impl Into<PathBuf>,
        common_dir: impl Into<PathBuf>,
    ) -> Self {
        Self {
            worktree_root: worktree_root.into(),
            common_dir: common_dir.into(),
            worktree_state_dir: worktree_state_dir.into(),
        }
    }

    /// `worktrees/` — the common-dir directory holding every linked
    /// tree's per-tree state dir.
    #[must_use]
    pub fn worktrees_dir(&self) -> PathBuf {
        self.common_dir.join(WORKTREES_DIR_NAME)
    }

    /// The per-tree state dir a linked worktree with `id` would use:
    /// `worktrees/<id>` under the common dir. The caller must have
    /// validated `id` via [`validate_worktree_id`].
    #[must_use]
    pub fn worktree_state_dir_for(&self, id: &str) -> PathBuf {
        self.worktrees_dir().join(id)
    }

    // ------------------------------------------------------------------
    // Common-dir (shared) state.
    // ------------------------------------------------------------------

    /// `objects/` — the content-addressed object store.
    #[must_use]
    pub fn objects_dir(&self) -> PathBuf {
        self.common_dir.join(OBJECTS_DIR)
    }

    /// `format` — the object-addressing format marker.
    #[must_use]
    pub fn format_file(&self) -> PathBuf {
        self.common_dir.join(FORMAT_FILE)
    }

    /// `refs/` — the ref tree root.
    #[must_use]
    pub fn refs_dir(&self) -> PathBuf {
        self.common_dir.join(REFS_DIR)
    }

    /// `refs/heads/` — branch refs.
    #[must_use]
    pub fn heads_dir(&self) -> PathBuf {
        self.common_dir.join(HEADS_DIR)
    }

    /// `refs/tags/` — tag refs.
    #[must_use]
    pub fn tags_dir(&self) -> PathBuf {
        self.common_dir.join(TAGS_DIR)
    }

    /// `refs/remotes/` — remote-tracking refs.
    #[must_use]
    pub fn remotes_dir(&self) -> PathBuf {
        self.common_dir.join(REMOTES_DIR)
    }

    /// `shallow` — the shallow-clone boundary. Shared: it constrains
    /// the one object graph every worktree reads.
    #[must_use]
    pub fn shallow_file(&self) -> PathBuf {
        self.common_dir.join(SHALLOW_FILE)
    }

    /// `config` — the repository config file.
    #[must_use]
    pub fn config_file(&self) -> PathBuf {
        self.common_dir.join(CONFIG_FILE_NAME)
    }

    /// `keys/` — repository-local signing keys.
    #[must_use]
    pub fn keys_dir(&self) -> PathBuf {
        self.common_dir.join(KEYS_DIR_NAME)
    }

    /// `history/` — the append-only commit-history MMR.
    #[must_use]
    pub fn history_dir(&self) -> PathBuf {
        self.common_dir.join(HISTORY_DIR_NAME)
    }

    /// `recovery-log` — the append-only superseded-commit log.
    #[must_use]
    pub fn recovery_log_file(&self) -> PathBuf {
        self.common_dir.join(RECOVERY_LOG)
    }

    /// `attestations/` — the DSSE attestation store.
    #[must_use]
    pub fn attestations_dir(&self) -> PathBuf {
        self.common_dir.join(ATTESTATIONS_DIR_NAME)
    }

    /// `applied-packs/` — per-remote applied-pack records. A
    /// redownload-avoidance cache; never a gc root source, always safe
    /// to delete.
    #[must_use]
    pub fn applied_packs_dir(&self) -> PathBuf {
        self.common_dir.join(APPLIED_PACKS_DIR_NAME)
    }

    /// `git/` — git-bridge per-remote state.
    #[must_use]
    pub fn git_state_dir(&self) -> PathBuf {
        self.common_dir.join(GIT_STATE_DIR_NAME)
    }

    /// `sparse/` — the verifiable sparse-checkout bitmap cache
    /// (keyed by tree hash, so shared).
    #[must_use]
    pub fn sparse_cache_dir(&self) -> PathBuf {
        self.common_dir.join(SPARSE_CACHE_DIR_NAME)
    }

    /// `pack-shards/` — default output directory for pack shards.
    #[must_use]
    pub fn pack_shards_dir(&self) -> PathBuf {
        self.common_dir.join(PACK_SHARDS_DIR_NAME)
    }

    // ------------------------------------------------------------------
    // Per-worktree state.
    // ------------------------------------------------------------------

    /// `HEAD` — this worktree's checked-out branch or detached commit.
    #[must_use]
    pub fn head_file(&self) -> PathBuf {
        self.worktree_state_dir.join(HEAD_FILE)
    }

    /// `index` — this worktree's staging index.
    #[must_use]
    pub fn index_file(&self) -> PathBuf {
        self.worktree_state_dir.join(INDEX_FILE_NAME)
    }

    /// `ORIG_HEAD` — pre-operation HEAD snapshot.
    #[must_use]
    pub fn orig_head_file(&self) -> PathBuf {
        self.worktree_state_dir.join(ORIG_HEAD)
    }

    /// `MERGE_HEAD` — in-progress merge counterpart commit.
    #[must_use]
    pub fn merge_head_file(&self) -> PathBuf {
        self.worktree_state_dir.join(MERGE_HEAD)
    }

    /// `MERGE_MSG` — in-progress merge message.
    #[must_use]
    pub fn merge_msg_file(&self) -> PathBuf {
        self.worktree_state_dir.join(MERGE_MSG)
    }

    /// `CHERRY_PICK_HEAD` — in-progress cherry-pick source commit.
    #[must_use]
    pub fn cherry_pick_head_file(&self) -> PathBuf {
        self.worktree_state_dir.join(CHERRY_PICK_HEAD)
    }

    /// `CHERRY_PICK_MSG` — in-progress cherry-pick message.
    #[must_use]
    pub fn cherry_pick_msg_file(&self) -> PathBuf {
        self.worktree_state_dir.join(CHERRY_PICK_MSG)
    }

    /// `REVERT_HEAD` — in-progress revert source commit.
    #[must_use]
    pub fn revert_head_file(&self) -> PathBuf {
        self.worktree_state_dir.join(REVERT_HEAD)
    }

    /// `REVERT_MSG` — in-progress revert message.
    #[must_use]
    pub fn revert_msg_file(&self) -> PathBuf {
        self.worktree_state_dir.join(REVERT_MSG)
    }

    /// `mkit-conflicts` — conflict sidecar for the in-progress op.
    #[must_use]
    pub fn conflicts_file(&self) -> PathBuf {
        self.worktree_state_dir.join(CONFLICTS_FILE)
    }

    /// `MKIT_OP_RESULT` — full result tree of the in-progress op.
    #[must_use]
    pub fn result_tree_file(&self) -> PathBuf {
        self.worktree_state_dir.join(RESULT_TREE)
    }

    /// `rebase-apply/` — in-progress rebase state.
    #[must_use]
    pub fn rebase_dir(&self) -> PathBuf {
        self.worktree_state_dir.join(REBASE_DIR)
    }

    /// `bisect` — in-progress bisect state.
    #[must_use]
    pub fn bisect_file(&self) -> PathBuf {
        self.worktree_state_dir.join(BISECT_FILE)
    }

    /// `stash` — this worktree's stash manifest (tree-local by #493).
    #[must_use]
    pub fn stash_file(&self) -> PathBuf {
        self.worktree_state_dir.join(STASH_FILE_NAME)
    }

    /// `sparse-checkout` — this worktree's sparse filter spec.
    #[must_use]
    pub fn sparse_checkout_file(&self) -> PathBuf {
        self.worktree_state_dir.join(SPARSE_CHECKOUT_FILE_NAME)
    }
}

/// Errors surfaced by [`discover`] on a broken linked-worktree setup.
///
/// A repository whose `.mkit` is a directory (every single-worktree
/// repository) can never produce one of these — discovery only engages
/// the fail-closed path once `.mkit` is a pointer FILE.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DiscoverError {
    #[error("worktree pointer {0}: {1}")]
    PointerUnreadable(PathBuf, std::io::Error),
    #[error("worktree pointer {0} is malformed: expected a single `{POINTER_PREFIX}<path>` line")]
    PointerMalformed(PathBuf),
    #[error("worktree pointer {0} exceeds {MAX_POINTER_FILE_BYTES} bytes — refusing to parse")]
    PointerTooLarge(PathBuf),
    #[error(
        "worktree state dir {0} is missing or not a directory — was this worktree pruned? \
         run `mkit worktree` maintenance from the main repository"
    )]
    StateDirMissing(PathBuf),
    #[error("worktree commondir file {0}: {1}")]
    CommonDirUnreadable(PathBuf, std::io::Error),
    #[error("worktree common dir {0} is missing or not a directory")]
    CommonDirMissing(PathBuf),
}

/// Validate a linked-worktree id (the `worktrees/<id>` directory name).
///
/// Same shape as the git-bridge remote-name rule: ASCII alphanumeric
/// plus `.`, `_`, `-`; non-empty; at most 255 bytes; never `.` or `..`.
/// Keeps the id a single safe path component — no separators, no
/// traversal, no NUL.
#[must_use]
pub fn validate_worktree_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 255
        && id != "."
        && id != ".."
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
}

/// Read a single-line, LF-terminated, size-capped pointer-style file
/// (`.mkit` pointer, `commondir`, back-pointer). Returns the line
/// without its trailing newline. `Ok(None)` when the file is absent.
fn read_capped_line(path: &Path) -> Result<Option<String>, DiscoverError> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(DiscoverError::PointerUnreadable(path.to_path_buf(), e)),
    };
    if meta.len() > MAX_POINTER_FILE_BYTES {
        return Err(DiscoverError::PointerTooLarge(path.to_path_buf()));
    }
    let raw =
        std::fs::read(path).map_err(|e| DiscoverError::PointerUnreadable(path.to_path_buf(), e))?;
    let text = std::str::from_utf8(&raw)
        .map_err(|_| DiscoverError::PointerMalformed(path.to_path_buf()))?;
    let line = text
        .strip_suffix('\n')
        .map_or(text, |l| l.strip_suffix('\r').unwrap_or(l));
    if line.is_empty() || line.contains('\n') {
        return Err(DiscoverError::PointerMalformed(path.to_path_buf()));
    }
    Ok(Some(line.to_owned()))
}

/// Write the linked-tree pointer file: `<tree>/.mkit` containing
/// `mkitdir: <state_dir>\n`. Used by `worktree add` (#493 Phase 2);
/// public now so the format has exactly one writer and one reader.
///
/// # Errors
/// Propagates filesystem errors from the atomic write.
pub fn write_pointer_file(tree_root: &Path, state_dir: &Path) -> std::io::Result<()> {
    let body = format!("{POINTER_PREFIX}{}\n", state_dir.display());
    crate::atomic::write_atomic(&tree_root.join(MKIT_DIR), body.as_bytes(), false)
}

/// Resolve the [`RepoLayout`] for the repository whose working tree is
/// rooted at `worktree_root` (#493 Phase 1 discovery).
///
/// - `.mkit` is a directory, or absent: the classic single-worktree
///   layout ([`RepoLayout::single`]) — absence is NOT an error here so
///   the store-open path keeps producing today's "not a repository"
///   diagnostics unchanged.
/// - `.mkit` is a FILE: a linked worktree. The pointer is parsed
///   (`mkitdir: <path>`, absolute or relative to `worktree_root`), the
///   per-tree state dir must exist, and the common dir is resolved via
///   the state dir's `commondir` file (defaulting to `../..` when the
///   file is absent, matching what `worktree add` writes) and must
///   exist. Every failure along that chain is a typed, fail-closed
///   [`DiscoverError`] — a broken linked tree must never silently
///   degrade into "operate on some other directory".
///
/// # Errors
/// See [`DiscoverError`].
pub fn discover(worktree_root: &Path) -> Result<RepoLayout, DiscoverError> {
    let dot_mkit = worktree_root.join(MKIT_DIR);
    let Ok(meta) = std::fs::symlink_metadata(&dot_mkit) else {
        return Ok(RepoLayout::single(worktree_root));
    };
    if meta.is_dir() {
        return Ok(RepoLayout::single(worktree_root));
    }

    // `.mkit` exists and is not a directory: pointer file (or garbage).
    let Some(line) = read_capped_line(&dot_mkit)? else {
        // Raced away between the two stats; treat like absent.
        return Ok(RepoLayout::single(worktree_root));
    };
    let Some(target) = line.strip_prefix(POINTER_PREFIX) else {
        return Err(DiscoverError::PointerMalformed(dot_mkit));
    };
    let target = Path::new(target);
    let state_dir = if target.is_absolute() {
        target.to_path_buf()
    } else {
        worktree_root.join(target)
    };
    // Canonicalize so identity comparisons against registry paths hold
    // even through symlinked tempdir prefixes (macOS `/var`).
    let state_dir = state_dir
        .canonicalize()
        .map_err(|_| DiscoverError::StateDirMissing(state_dir.clone()))?;
    if !state_dir.is_dir() {
        return Err(DiscoverError::StateDirMissing(state_dir));
    }

    let commondir_file = state_dir.join(COMMONDIR_FILE_NAME);
    let common_dir = match read_capped_line(&commondir_file) {
        Ok(Some(rel)) => {
            let p = Path::new(&rel);
            if p.is_absolute() {
                p.to_path_buf()
            } else {
                state_dir.join(p)
            }
        }
        // Absent commondir: the layout `worktree add` writes puts the
        // state dir exactly two levels under the common dir.
        Ok(None) => state_dir.join("../.."),
        Err(DiscoverError::PointerUnreadable(p, e)) => {
            return Err(DiscoverError::CommonDirUnreadable(p, e));
        }
        Err(e) => return Err(e),
    };
    // Normalize the `../..` hops so every accessor yields a clean path.
    let common_dir = common_dir
        .canonicalize()
        .map_err(|_| DiscoverError::CommonDirMissing(common_dir.clone()))?;
    if !common_dir.is_dir() {
        return Err(DiscoverError::CommonDirMissing(common_dir));
    }

    Ok(RepoLayout::linked(worktree_root, state_dir, common_dir))
}

/// One entry of the linked-worktree registry (`<common>/worktrees/*`),
/// as reported by [`worktrees`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorktreeEntry {
    /// The registry id (the `worktrees/<id>` directory name).
    pub id: String,
    /// The per-tree state dir (`<common>/worktrees/<id>`).
    pub state_dir: PathBuf,
    /// The linked tree's root, derived from the back-pointer file
    /// (its parent, since the back-pointer names `<tree>/.mkit`).
    /// `None` when the entry is broken — see `prunable`.
    pub tree_root: Option<PathBuf>,
    /// `Some(reason)` when the entry no longer corresponds to a live
    /// linked tree and `worktree prune` may delete its state dir:
    /// missing/unreadable back-pointer, vanished tree, or a tree whose
    /// pointer no longer points back at this state dir.
    pub prunable: Option<String>,
}

/// Enumerate the linked-worktree registry of `layout`'s repository,
/// sorted by id. The main worktree is NOT an entry — its state dir is
/// the common dir itself.
///
/// Ids that fail [`validate_worktree_id`] and non-directory entries
/// are reported as prunable rather than skipped, so `worktree list`
/// and `worktree prune` see the same picture and nothing lingers
/// invisibly.
///
/// # Errors
/// [`DiscoverError::PointerUnreadable`] only for an unreadable
/// `worktrees/` directory itself; a missing `worktrees/` dir yields an
/// empty list.
pub fn worktrees(layout: &RepoLayout) -> Result<Vec<WorktreeEntry>, DiscoverError> {
    let dir = layout.worktrees_dir();
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(DiscoverError::PointerUnreadable(dir, e)),
    };
    let mut out = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| DiscoverError::PointerUnreadable(dir.clone(), e))?;
        let id = entry.file_name().to_string_lossy().into_owned();
        let state_dir = entry.path();
        let mut wt = WorktreeEntry {
            id: id.clone(),
            state_dir: state_dir.clone(),
            tree_root: None,
            prunable: None,
        };
        if !validate_worktree_id(&id) || !state_dir.is_dir() {
            wt.prunable = Some("invalid registry entry".to_owned());
            out.push(wt);
            continue;
        }
        // Follow the back-pointer to the tree and verify the tree's
        // pointer still points back HERE — a moved/re-created tree
        // must not be claimed by a stale registry entry.
        match read_capped_line(&state_dir.join(BACKPOINTER_FILE_NAME)) {
            Ok(Some(back)) => {
                let pointer_path = PathBuf::from(back);
                let tree_root = pointer_path.parent().map(Path::to_path_buf);
                match discover_pointer_target(&pointer_path) {
                    Some(target) if paths_refer_to_same(&target, &state_dir) => {
                        wt.tree_root = tree_root;
                    }
                    Some(_) => {
                        wt.tree_root = tree_root;
                        wt.prunable =
                            Some("tree's pointer no longer points at this state dir".to_owned());
                    }
                    None => {
                        wt.tree_root = tree_root;
                        wt.prunable = Some("linked tree is gone".to_owned());
                    }
                }
            }
            Ok(None) => wt.prunable = Some("back-pointer file missing".to_owned()),
            Err(_) => wt.prunable = Some("back-pointer file unreadable".to_owned()),
        }
        out.push(wt);
    }
    out.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(out)
}

/// Every per-tree STATE layout of the repository, for cross-worktree
/// root collection (#493 Phase 3): the main tree first, then one
/// layout per `worktrees/<id>` state dir that exists on disk — in
/// deterministic order (main, then ids ascending), so multi-lock
/// acquisition over the result cannot deadlock against itself.
///
/// Deliberately INCLUDES prunable registry entries whose state dir is
/// still present: until `worktree prune` reaps a state dir, whatever
/// its HEAD/index/op-state pin stays pinned — gc must never treat "the
/// tree wandered off" as "its staged objects are garbage".
///
/// For entries whose linked tree root is unknown (broken back-pointer)
/// the layout's `worktree_root` falls back to the state dir itself;
/// root collection never touches worktree files, only state.
///
/// # Errors
/// Propagates registry enumeration failures — callers (gc) must abort,
/// never prune on a partial view.
pub fn all_state_layouts(layout: &RepoLayout) -> Result<Vec<RepoLayout>, DiscoverError> {
    let mut out = Vec::new();
    let main_root = layout
        .common_dir()
        .parent()
        .map_or_else(|| PathBuf::from("/"), Path::to_path_buf);
    out.push(RepoLayout::linked(
        main_root,
        layout.common_dir(),
        layout.common_dir(),
    ));
    for wt in worktrees(layout)? {
        if !wt.state_dir.is_dir() {
            continue;
        }
        let root = wt.tree_root.clone().unwrap_or_else(|| wt.state_dir.clone());
        out.push(RepoLayout::linked(root, wt.state_dir, layout.common_dir()));
    }
    Ok(out)
}

/// Best-effort read of a pointer file's target (absolute or relative
/// to the pointer's parent). `None` when the file is missing or
/// malformed — callers use this for registry health checks, where a
/// broken pointer means "prunable", not "abort".
fn discover_pointer_target(pointer_path: &Path) -> Option<PathBuf> {
    let line = read_capped_line(pointer_path).ok().flatten()?;
    let target = line.strip_prefix(POINTER_PREFIX)?;
    let target = Path::new(target);
    if target.is_absolute() {
        Some(target.to_path_buf())
    } else {
        Some(pointer_path.parent()?.join(target))
    }
}

/// Path equality up to canonicalization, tolerant of either side not
/// existing (falls back to literal comparison).
fn paths_refer_to_same(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(ca), Ok(cb)) => ca == cb,
        _ => a == b,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every accessor, paired with its expected `.mkit`-relative path in
    /// the single-worktree layout and its class. The golden strings are
    /// the exact historical joins — Phase 0 must be byte-identical.
    fn accessor_table(l: &RepoLayout) -> Vec<(&'static str, PathBuf, &'static str, Class)> {
        use Class::{Common, Worktree};
        vec![
            ("objects_dir", l.objects_dir(), "objects", Common),
            ("format_file", l.format_file(), "format", Common),
            ("refs_dir", l.refs_dir(), "refs", Common),
            ("heads_dir", l.heads_dir(), "refs/heads", Common),
            ("tags_dir", l.tags_dir(), "refs/tags", Common),
            ("remotes_dir", l.remotes_dir(), "refs/remotes", Common),
            ("shallow_file", l.shallow_file(), "shallow", Common),
            ("config_file", l.config_file(), "config", Common),
            ("keys_dir", l.keys_dir(), "keys", Common),
            ("history_dir", l.history_dir(), "history", Common),
            (
                "recovery_log_file",
                l.recovery_log_file(),
                "recovery-log",
                Common,
            ),
            (
                "attestations_dir",
                l.attestations_dir(),
                "attestations",
                Common,
            ),
            (
                "applied_packs_dir",
                l.applied_packs_dir(),
                "applied-packs",
                Common,
            ),
            ("git_state_dir", l.git_state_dir(), "git", Common),
            ("sparse_cache_dir", l.sparse_cache_dir(), "sparse", Common),
            (
                "pack_shards_dir",
                l.pack_shards_dir(),
                "pack-shards",
                Common,
            ),
            ("head_file", l.head_file(), "HEAD", Worktree),
            ("index_file", l.index_file(), "index", Worktree),
            ("orig_head_file", l.orig_head_file(), "ORIG_HEAD", Worktree),
            (
                "merge_head_file",
                l.merge_head_file(),
                "MERGE_HEAD",
                Worktree,
            ),
            ("merge_msg_file", l.merge_msg_file(), "MERGE_MSG", Worktree),
            (
                "cherry_pick_head_file",
                l.cherry_pick_head_file(),
                "CHERRY_PICK_HEAD",
                Worktree,
            ),
            (
                "cherry_pick_msg_file",
                l.cherry_pick_msg_file(),
                "CHERRY_PICK_MSG",
                Worktree,
            ),
            (
                "revert_head_file",
                l.revert_head_file(),
                "REVERT_HEAD",
                Worktree,
            ),
            (
                "revert_msg_file",
                l.revert_msg_file(),
                "REVERT_MSG",
                Worktree,
            ),
            (
                "conflicts_file",
                l.conflicts_file(),
                "mkit-conflicts",
                Worktree,
            ),
            (
                "result_tree_file",
                l.result_tree_file(),
                "MKIT_OP_RESULT",
                Worktree,
            ),
            ("rebase_dir", l.rebase_dir(), "rebase-apply", Worktree),
            ("bisect_file", l.bisect_file(), "bisect", Worktree),
            ("stash_file", l.stash_file(), "stash", Worktree),
            (
                "sparse_checkout_file",
                l.sparse_checkout_file(),
                "sparse-checkout",
                Worktree,
            ),
        ]
    }

    #[derive(PartialEq, Clone, Copy, Debug)]
    enum Class {
        Common,
        Worktree,
    }

    /// Phase 0 golden invariant: in the single-worktree layout every
    /// accessor equals the historical `<root>/.mkit/<relative>` join,
    /// byte for byte.
    #[test]
    fn single_layout_paths_match_legacy_joins() {
        let root = Path::new("/repo");
        let l = RepoLayout::single(root);
        let legacy_mkit = root.join(MKIT_DIR);
        for (name, got, relative, _class) in accessor_table(&l) {
            assert_eq!(got, legacy_mkit.join(relative), "accessor {name}");
        }
    }

    /// Single-mode structural invariant.
    #[test]
    fn single_layout_dirs_coincide() {
        let l = RepoLayout::single("/repo");
        assert!(l.is_single());
        assert_eq!(l.common_dir(), l.worktree_state_dir());
        assert_eq!(l.common_dir(), Path::new("/repo/.mkit"));
        assert_eq!(l.worktree_root(), Path::new("/repo"));
    }

    /// Containment invariant: every accessor resolves strictly inside
    /// the directory its class prescribes — nothing escapes `.mkit`.
    #[test]
    fn accessors_stay_inside_their_class_dir() {
        let l = RepoLayout::single("/repo");
        for (name, got, _relative, class) in accessor_table(&l) {
            let class_dir = match class {
                Class::Common => l.common_dir(),
                Class::Worktree => l.worktree_state_dir(),
            };
            assert!(
                got.starts_with(class_dir) && got != class_dir,
                "accessor {name} must resolve strictly inside {}",
                class_dir.display()
            );
            // No parent-dir or absolute components smuggled in past the
            // class dir: re-joining the stripped suffix must round-trip.
            let suffix = got.strip_prefix(class_dir).unwrap();
            assert!(
                suffix
                    .components()
                    .all(|c| matches!(c, std::path::Component::Normal(_))),
                "accessor {name} suffix {} must be plain components",
                suffix.display()
            );
        }
    }

    /// The layout constants that duplicate cross-crate literals must
    /// stay in lock-step with the historical on-disk names.
    #[test]
    fn cross_crate_names_are_pinned() {
        assert_eq!(CONFIG_FILE_NAME, "config");
        assert_eq!(KEYS_DIR_NAME, "keys");
        assert_eq!(INDEX_FILE_NAME, "index");
        assert_eq!(STASH_FILE_NAME, "stash");
        assert_eq!(SPARSE_CHECKOUT_FILE_NAME, "sparse-checkout");
        assert_eq!(ATTESTATIONS_DIR_NAME, "attestations");
        assert_eq!(APPLIED_PACKS_DIR_NAME, "applied-packs");
        assert_eq!(GIT_STATE_DIR_NAME, "git");
        assert_eq!(SPARSE_CACHE_DIR_NAME, "sparse");
        assert_eq!(PACK_SHARDS_DIR_NAME, "pack-shards");
        // Legacy prefix-embedding constants remain valid views of the
        // same locations.
        assert_eq!(
            Path::new(crate::index::INDEX_FILE),
            Path::new(MKIT_DIR).join(INDEX_FILE_NAME)
        );
        assert_eq!(
            Path::new(crate::ops::stash::STASH_FILE),
            Path::new(MKIT_DIR).join(STASH_FILE_NAME)
        );
    }

    /// Construction is pure — no filesystem access — so a layout for a
    /// not-yet-created repository is representable (init needs this).
    #[test]
    fn construction_is_pure() {
        let l = RepoLayout::single("/definitely/not/a/real/path");
        assert_eq!(
            l.objects_dir(),
            Path::new("/definitely/not/a/real/path/.mkit/objects")
        );
    }

    /// Linked-mode classification invariant: with distinct dirs, every
    /// accessor resolves under the dir its class prescribes — the whole
    /// point of the seam.
    #[test]
    fn linked_layout_splits_accessors_by_class() {
        let l = RepoLayout::linked(
            "/trees/feature-x",
            "/main/.mkit/worktrees/feature-x",
            "/main/.mkit",
        );
        assert!(!l.is_single());
        // NOTE: the state dir deliberately nests UNDER the common dir
        // (`.mkit/worktrees/<id>`), so "under the common dir" is
        // trivially true for everything; the leak checks that matter
        // are (a) worktree-class accessors resolve under the state
        // dir, and (b) common-class accessors do NOT.
        for (name, got, _relative, class) in accessor_table(&l) {
            match class {
                Class::Common => {
                    assert!(
                        got.starts_with(l.common_dir()),
                        "accessor {name} must live under the common dir"
                    );
                    assert!(
                        !got.starts_with(l.worktree_state_dir()),
                        "shared accessor {name} leaked into the per-tree state dir"
                    );
                }
                Class::Worktree => {
                    assert!(
                        got.starts_with(l.worktree_state_dir()),
                        "per-tree accessor {name} must live under the state dir"
                    );
                }
            }
        }
        // The per-tree state dirs of OTHER worktrees live under the
        // common dir's worktrees/, not under this tree's state dir.
        assert_eq!(
            l.worktree_state_dir_for("other"),
            Path::new("/main/.mkit/worktrees/other")
        );
    }

    #[test]
    fn worktree_id_grammar() {
        for ok in ["feature-x", "a", "wt.1", "A_B-c.d", &"x".repeat(255)] {
            assert!(validate_worktree_id(ok), "{ok:?} should be valid");
        }
        for bad in [
            "",
            ".",
            "..",
            "a/b",
            "a\\b",
            "a b",
            "a\0b",
            "\u{e9}clair",
            &"x".repeat(256),
        ] {
            assert!(!validate_worktree_id(bad), "{bad:?} should be rejected");
        }
    }

    // ---- discover() ---------------------------------------------------

    fn scaffold_linked(tmp: &Path) -> (PathBuf, PathBuf, PathBuf) {
        let main = tmp.join("main");
        let tree = tmp.join("tree");
        let state = main.join(".mkit/worktrees/tree");
        std::fs::create_dir_all(main.join(".mkit/objects")).unwrap();
        std::fs::create_dir_all(&state).unwrap();
        std::fs::create_dir_all(&tree).unwrap();
        write_pointer_file(&tree, &state).unwrap();
        (main, tree, state)
    }

    #[test]
    fn discover_dir_and_absent_yield_single() {
        let tmp = tempfile::tempdir().unwrap();
        // Absent .mkit: single (store open reports not-a-repo later).
        let l = discover(tmp.path()).unwrap();
        assert!(l.is_single());
        // Directory .mkit: single, byte-identical to Phase 0.
        std::fs::create_dir_all(tmp.path().join(".mkit")).unwrap();
        let l = discover(tmp.path()).unwrap();
        assert!(l.is_single());
        assert_eq!(l.common_dir(), tmp.path().join(".mkit"));
    }

    #[test]
    fn discover_follows_pointer_to_linked_layout() {
        let tmp = tempfile::tempdir().unwrap();
        let (main, tree, state) = scaffold_linked(tmp.path());
        let l = discover(&tree).unwrap();
        assert!(!l.is_single());
        assert_eq!(l.worktree_root(), tree.as_path());
        // State dir is canonicalized by discovery (symlinked tempdir
        // prefixes must not defeat cross-tree identity comparisons).
        assert_eq!(
            l.worktree_state_dir(),
            state.canonicalize().unwrap().as_path()
        );
        // commondir file absent => ../.. default, canonicalized.
        assert_eq!(
            l.common_dir(),
            main.join(".mkit").canonicalize().unwrap().as_path()
        );
        // The seam in action: HEAD is per-tree, refs are shared.
        assert_eq!(l.head_file(), state.canonicalize().unwrap().join("HEAD"));
        assert!(l.heads_dir().starts_with(l.common_dir()));
    }

    #[test]
    fn discover_honors_explicit_commondir_file() {
        let tmp = tempfile::tempdir().unwrap();
        let (main, tree, state) = scaffold_linked(tmp.path());
        std::fs::write(state.join(COMMONDIR_FILE_NAME), "../..\n").unwrap();
        let l = discover(&tree).unwrap();
        assert_eq!(
            l.common_dir(),
            main.join(".mkit").canonicalize().unwrap().as_path()
        );
        // Absolute commondir works too.
        std::fs::write(
            state.join(COMMONDIR_FILE_NAME),
            format!("{}\n", main.join(".mkit").display()),
        )
        .unwrap();
        let l = discover(&tree).unwrap();
        assert_eq!(
            l.common_dir(),
            main.join(".mkit").canonicalize().unwrap().as_path()
        );
    }

    #[test]
    fn discover_accepts_relative_pointer_target() {
        let tmp = tempfile::tempdir().unwrap();
        let (_main, tree, state) = scaffold_linked(tmp.path());
        std::fs::write(
            tree.join(MKIT_DIR),
            "mkitdir: ../main/.mkit/worktrees/tree\n",
        )
        .unwrap();
        let l = discover(&tree).unwrap();
        assert_eq!(
            l.worktree_state_dir(),
            tree.join("../main/.mkit/worktrees/tree")
                .canonicalize()
                .unwrap()
        );
        assert!(l.worktree_state_dir().is_dir());
        let _ = state;
    }

    /// Fail-closed matrix: every malformed/dangling pointer shape is a
    /// typed error, never a silent fallback to some other directory.
    #[test]
    fn discover_fails_closed_on_broken_pointers() {
        let tmp = tempfile::tempdir().unwrap();
        let (_main, tree, state) = scaffold_linked(tmp.path());
        let pointer = tree.join(MKIT_DIR);

        // Wrong prefix.
        std::fs::write(&pointer, "gitdir: /somewhere\n").unwrap();
        assert!(matches!(
            discover(&tree),
            Err(DiscoverError::PointerMalformed(_))
        ));
        // Empty.
        std::fs::write(&pointer, "").unwrap();
        assert!(matches!(
            discover(&tree),
            Err(DiscoverError::PointerMalformed(_))
        ));
        // Multi-line.
        std::fs::write(&pointer, "mkitdir: /a\nmkitdir: /b\n").unwrap();
        assert!(matches!(
            discover(&tree),
            Err(DiscoverError::PointerMalformed(_))
        ));
        // Non-UTF-8.
        std::fs::write(&pointer, [0x6d, 0x6b, 0xff, 0xfe]).unwrap();
        assert!(matches!(
            discover(&tree),
            Err(DiscoverError::PointerMalformed(_))
        ));
        // Oversized.
        std::fs::write(
            &pointer,
            format!(
                "mkitdir: /{}\n",
                "x".repeat(usize::try_from(MAX_POINTER_FILE_BYTES).unwrap())
            ),
        )
        .unwrap();
        assert!(matches!(
            discover(&tree),
            Err(DiscoverError::PointerTooLarge(_))
        ));
        // Dangling target (state dir removed — a pruned worktree).
        write_pointer_file(&tree, &state).unwrap();
        std::fs::remove_dir_all(&state).unwrap();
        assert!(matches!(
            discover(&tree),
            Err(DiscoverError::StateDirMissing(_))
        ));
    }

    #[test]
    fn discover_fails_closed_on_missing_common_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let (main, tree, state) = scaffold_linked(tmp.path());
        // commondir points somewhere that does not exist.
        std::fs::write(state.join(COMMONDIR_FILE_NAME), "../../nope\n").unwrap();
        assert!(matches!(
            discover(&tree),
            Err(DiscoverError::CommonDirMissing(_))
        ));
        let _ = main;
    }

    /// The pointer file has exactly one writer and one reader; pin the
    /// bytes so the format cannot drift silently.
    #[test]
    fn pointer_file_golden_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        write_pointer_file(tmp.path(), Path::new("/main/.mkit/worktrees/w1")).unwrap();
        let bytes = std::fs::read(tmp.path().join(MKIT_DIR)).unwrap();
        assert_eq!(bytes, b"mkitdir: /main/.mkit/worktrees/w1\n");
    }
}
