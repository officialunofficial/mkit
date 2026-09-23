//! Repository path layout: the single authority for resolving on-disk
//! state under `.mkit/` (issue #493, Phase 0).
//!
//! Every piece of repository state is classified into exactly one of two
//! directories:
//!
//! - the **common dir** — state shared by every working tree of the
//!   repository: the object store, refs, config, signing keys, the
//!   history MMB, the recovery log, attestations, transport caches;
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
//! | `recovery-log`           | common   | [`crate::ops::recovery`] |
//! | `attestations/`          | common   | `mkit-attest`           |
//! | `applied-packs/`         | common   | CLI remote dispatch (redownload cache, never a gc root) |
//! | `git/`                   | common   | `mkit-git-bridge`       |
//! | `sparse/`                | common   | CLI sparse witness cache |
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
//! | `serve.lock`             | common   | CLI `serve` guard (SPEC-CONCURRENCY §2/§3.1) |
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
/// Sparse witness-cache directory name under the common dir.
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

/// Exact bytes of the `.mkit` marker file at a scoped-workspace root
/// (SPEC-PARTIAL-WORKSPACES local state): `mkit-scoped: 1\n`.
pub(crate) const SCOPED_MARKER: &[u8] = b"mkit-scoped: 1\n";
/// Prefix that any malformed scoped marker still starts with.
pub(crate) const SCOPED_MARKER_PREFIX: &[u8] = b"mkit-scoped:";
/// Metadata directory name of a scoped workspace.
pub(crate) const SCOPED_STATE_DIR: &str = ".mkit-scoped";

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

    /// `sparse/` — the verifiable sparse-checkout witness cache
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
        "worktree pointer {0} is a symlink — pointer, commondir, and back-pointer files \
         must be regular files"
    )]
    PointerSymlink(PathBuf),
    #[error(
        "worktree state dir {0} is missing or not a directory — was this worktree pruned? \
         run `mkit worktree` maintenance from the main repository"
    )]
    StateDirMissing(PathBuf),
    #[error("worktree commondir file {0}: {1}")]
    CommonDirUnreadable(PathBuf, std::io::Error),
    #[error("worktree common dir {0} is missing or not a directory")]
    CommonDirMissing(PathBuf),
    #[error("{0} is a scoped mkit workspace; ordinary repository commands do not apply here")]
    ScopedWorkspace(PathBuf),
    #[error("{0} has a malformed scoped-workspace marker (.mkit)")]
    ScopedMarkerCorrupt(PathBuf),
    #[error(
        "{0} contains recognizable scoped-workspace metadata but no complete install — \
         the scoped root is incomplete or torn"
    )]
    ScopedInstallIncomplete(PathBuf),
    #[error("{0} mixes ordinary repository state with scoped-workspace authority")]
    ScopedLayoutConflict(PathBuf),
    #[error("filesystem error while checking {0} for scoped-workspace authority: {1}")]
    Io(PathBuf, std::io::Error),
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
    // Reject symlinks outright: `symlink_metadata` sizes the LINK
    // itself, so a hostile `.mkit -> /dev/zero` in an untarred tree
    // would sail past the byte cap while `fs::read` follows the link
    // into an unbounded read. Pointer-style files are plain regular
    // files by spec (SPEC-WORKTREE §2).
    if meta.file_type().is_symlink() {
        return Err(DiscoverError::PointerSymlink(path.to_path_buf()));
    }
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
    check_scoped_boundary(worktree_root)?;
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

/// Scoped-workspace authority found at one directory — shared by
/// [`discover`], the [`crate::store::ObjectStore`] open/init guards, and
/// scoped-workspace creation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScopedAuthority {
    /// No scoped marker or recognizable scoped metadata.
    None,
    /// `.mkit` is a regular file with the exact scoped marker bytes.
    Scoped,
    /// `.mkit` is a regular file beginning `mkit-scoped:` but is not the
    /// exact marker.
    CorruptMarker,
    /// Recognizable scoped metadata exists with no scoped marker and no
    /// ordinary `.mkit` authority.
    Incomplete,
    /// Ordinary `.mkit` authority (directory or linked pointer) overlaps
    /// recognizable scoped metadata.
    Conflict,
}

/// The scoped-authority classifier. On the supported native targets it
/// is anchored under safely opened directory descriptors so no component
/// or leaf of the scoped metadata can be a followed symlink, swapped
/// FIFO, or outside-root read. The fallback keeps the lstat+open shape
/// for targets without the descriptor primitives (discovery there is
/// inert — `mkit` is not supported on them).
mod scoped_classify {
    use super::{
        MAX_POINTER_FILE_BYTES, MKIT_DIR, POINTER_PREFIX, SCOPED_MARKER, SCOPED_MARKER_PREFIX,
        SCOPED_STATE_DIR, ScopedAuthority,
    };

    /// The shared decision: marker bytes (or absence) against whether
    /// recognizable scoped metadata was found. `marker` is the opened
    /// regular file's content prefix; `marker_dir` means `.mkit` is a
    /// directory; `marker_nonregular` means it exists but can never be
    /// the marker (symlink, FIFO, device).
    fn decide(marker: Marker, scoped_state: bool) -> ScopedAuthority {
        match marker {
            // A `.mkit` that exists but is not a regular file (symlink,
            // FIFO, device) can never be the scoped marker — and the
            // classifier must not follow it to find out what it names.
            // Recognized scoped state without its regular-file marker is
            // an incomplete-install boundary, not "no authority":
            // refusing here is what stops the ancestor walk from
            // reaching a parent repository. Absence decides identically.
            Marker::Absent | Marker::NonRegular => {
                if scoped_state {
                    ScopedAuthority::Incomplete
                } else {
                    ScopedAuthority::None
                }
            }
            Marker::Directory => {
                if scoped_state {
                    ScopedAuthority::Conflict
                } else {
                    ScopedAuthority::None
                }
            }
            Marker::Regular(bytes) => {
                if bytes == SCOPED_MARKER {
                    return ScopedAuthority::Scoped;
                }
                if bytes.starts_with(SCOPED_MARKER_PREFIX) {
                    return ScopedAuthority::CorruptMarker;
                }
                if scoped_state {
                    return if bytes.starts_with(POINTER_PREFIX.as_bytes()) {
                        ScopedAuthority::Conflict
                    } else {
                        ScopedAuthority::Incomplete
                    };
                }
                ScopedAuthority::None
            }
        }
    }

    /// What the `.mkit` name at a classified root turned out to be.
    enum Marker {
        Absent,
        Directory,
        NonRegular,
        Regular(Vec<u8>),
    }

    /// Descriptor-anchored classifier: every probe opens components
    /// `O_NOFOLLOW` beneath the parent directory descriptor, validates
    /// the opened descriptor's metadata, and reads bounded prefixes.
    #[cfg(all(unix, not(target_arch = "wasm32")))]
    mod descriptor {
        use super::{
            MAX_POINTER_FILE_BYTES, MKIT_DIR, Marker, SCOPED_STATE_DIR, ScopedAuthority, decide,
        };
        use crate::partial::sys::{self, OpenMode, SysError};
        use std::io;
        use std::path::Path;

        fn sys_io(error: SysError) -> io::Error {
            match error {
                SysError::Io(e) => e,
                SysError::AlreadyExists => {
                    io::Error::new(io::ErrorKind::AlreadyExists, "name exists")
                }
                SysError::Unsupported => io::Error::new(io::ErrorKind::Unsupported, "unsupported"),
            }
        }

        /// Read up to `cap` bytes of the opened file — looped so one
        /// short read cannot underfill the requested prefix.
        fn read_prefix(file: &sys::File, cap: usize) -> io::Result<Vec<u8>> {
            let mut buf = vec![0u8; cap];
            let mut filled = 0usize;
            while filled < cap {
                match file.read(&mut buf[filled..]) {
                    Ok(0) => break,
                    Ok(n) => filled += n,
                    Err(e) => return Err(sys_io(e)),
                }
            }
            buf.truncate(filled);
            Ok(buf)
        }

        /// Read the prefix of `dir/name`; `Ok(None)` when the leaf is
        /// absent OR cannot be scoped evidence — a symlink, FIFO,
        /// directory, or other non-regular entry is simply not an
        /// authority leaf: it is never followed and never blocks, but it
        /// also cannot hide genuine authority found elsewhere beneath
        /// `.mkit-scoped`. Genuine I/O errors still propagate.
        fn read_leaf(dir: &sys::DirFd, name: &[u8], cap: usize) -> io::Result<Option<Vec<u8>>> {
            let file = match sys::open_file(dir, name, OpenMode::Read) {
                Ok(file) => file,
                Err(e) if e.is_not_found() || e.is_symlink() => return Ok(None),
                Err(e) => return Err(sys_io(e)),
            };
            let meta = file.metadata().map_err(sys_io)?;
            if !meta.is_file() {
                return Ok(None);
            }
            Ok(Some(read_prefix(&file, cap)?))
        }

        /// True when `root_fd`'s `.mkit-scoped` carries recognizable
        /// scoped metadata: a `CURRENT` file beginning `MKCR`, or a
        /// lowercase-64-hex `generations/<digest>/` containing
        /// `manifest.bin` beginning `MKGM`. A bare `.mkit-scoped`
        /// directory, `workspace.lock`, or unrelated contents —
        /// including a same-named `generations` regular file or FIFO —
        /// are NOT authority and must not fail the walk.
        fn scoped_state_recognized(root_fd: &sys::DirFd) -> io::Result<bool> {
            let state = match sys::open_dir(root_fd, SCOPED_STATE_DIR.as_bytes()) {
                Ok(fd) => fd,
                Err(e) if e.is_not_found() || e.is_symlink() || e.is_not_dir() => {
                    return Ok(false);
                }
                Err(e) => return Err(sys_io(e)),
            };
            if let Some(prefix) = read_leaf(&state, b"CURRENT", 4)?
                && prefix == b"MKCR"
            {
                return Ok(true);
            }
            let generations = match sys::open_dir(&state, b"generations") {
                Ok(fd) => fd,
                Err(e) if e.is_not_found() || e.is_symlink() || e.is_not_dir() => {
                    return Ok(false);
                }
                Err(e) => return Err(sys_io(e)),
            };
            let mut entries = generations.read_dir().map_err(sys_io)?;
            while let Some((name, _is_dir)) = entries.next_entry().map_err(sys_io)? {
                if name.len() != crate::hash::HEX_LEN
                    || !name
                        .iter()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
                {
                    continue;
                }
                // The name alone is not authority — open the component
                // no-follow and validate what it actually is.
                let generation = match sys::open_dir(&generations, &name) {
                    Ok(fd) => fd,
                    Err(e) if e.is_not_found() || e.is_symlink() || e.is_not_dir() => {
                        continue;
                    }
                    Err(e) => return Err(sys_io(e)),
                };
                if let Some(prefix) = read_leaf(&generation, b"manifest.bin", 4)?
                    && prefix == b"MKGM"
                {
                    return Ok(true);
                }
            }
            Ok(false)
        }

        /// Classify the scoped-workspace authority at exactly `root`.
        pub(crate) fn classify_scoped_root(root: &Path) -> io::Result<ScopedAuthority> {
            let root_fd = match sys::open_dir_path(root) {
                Ok(fd) => fd,
                // A textual ancestor that does not exist or is not a
                // directory carries no authority itself.
                Err(e) if e.is_not_found() || e.is_not_dir() => {
                    return Ok(ScopedAuthority::None);
                }
                Err(e) if e.is_symlink() => {
                    // A symlinked directory ancestor — reachable only
                    // through the textual fallback, since `start` is
                    // canonicalized — names a real directory that may
                    // itself hold authority. Resolve the DIRECTORY once,
                    // then keep every metadata probe no-follow beneath
                    // it; the metadata path itself is never canonicalized.
                    match std::fs::canonicalize(root)
                        .ok()
                        .and_then(|real| sys::open_dir_path(&real).ok())
                    {
                        Some(fd) => fd,
                        None => return Ok(ScopedAuthority::None),
                    }
                }
                Err(e) => return Err(sys_io(e)),
            };
            let scoped_state = scoped_state_recognized(&root_fd)?;
            let marker = match sys::open_file(&root_fd, MKIT_DIR.as_bytes(), OpenMode::Read) {
                Ok(file) => {
                    let meta = file.metadata().map_err(sys_io)?;
                    if meta.is_dir() {
                        Marker::Directory
                    } else if !meta.is_file() {
                        Marker::NonRegular
                    } else {
                        let cap = usize::try_from(MAX_POINTER_FILE_BYTES).unwrap_or(usize::MAX);
                        Marker::Regular(read_prefix(&file, cap)?)
                    }
                }
                Err(e) if e.is_not_found() => Marker::Absent,
                Err(e) if e.is_symlink() => Marker::NonRegular,
                Err(e) => return Err(sys_io(e)),
            };
            Ok(decide(marker, scoped_state))
        }
    }

    /// Path-based fallback for targets without the descriptor
    /// primitives; discovery is not exercised there.
    #[cfg(not(all(unix, not(target_arch = "wasm32"))))]
    mod paths {
        use super::{
            MAX_POINTER_FILE_BYTES, MKIT_DIR, Marker, SCOPED_STATE_DIR, ScopedAuthority, decide,
        };
        use std::io;
        use std::path::Path;

        /// Read at most `cap` bytes of `path`; `Ok(None)` when the leaf
        /// is absent OR cannot be scoped evidence — a symlink or other
        /// non-regular entry is never authority, mirroring the
        /// descriptor classifier's `read_leaf`.
        fn read_prefix(path: &Path, cap: usize) -> io::Result<Option<Vec<u8>>> {
            use std::io::Read;
            let meta = match std::fs::symlink_metadata(path) {
                Ok(meta) => meta,
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(e) => return Err(e),
            };
            if !meta.is_file() {
                return Ok(None);
            }
            let mut file = std::fs::File::open(path)?;
            let mut buf = vec![0u8; cap];
            let mut filled = 0usize;
            while filled < cap {
                match file.read(&mut buf[filled..]) {
                    Ok(0) => break,
                    Ok(n) => filled += n,
                    Err(e) => return Err(e),
                }
            }
            buf.truncate(filled);
            Ok(Some(buf))
        }

        fn scoped_state_recognized(root: &Path) -> io::Result<bool> {
            let dir = root.join(SCOPED_STATE_DIR);
            match std::fs::symlink_metadata(&dir) {
                Ok(meta) => {
                    if !meta.is_dir() {
                        return Ok(false);
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
                Err(e) => return Err(e),
            }
            if let Some(prefix) = read_prefix(&dir.join("CURRENT"), 4)?
                && prefix == b"MKCR"
            {
                return Ok(true);
            }
            let generations = dir.join("generations");
            // A same-named regular file, symlink, or FIFO is unrelated —
            // never authority and never an error.
            match std::fs::symlink_metadata(&generations) {
                Ok(meta) => {
                    if !meta.is_dir() {
                        return Ok(false);
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
                Err(e) => return Err(e),
            }
            let entries = match std::fs::read_dir(&generations) {
                Ok(e) => e,
                // Swapped to a non-directory between the metadata check
                // and open: still an unrelated shape, not an I/O failure.
                Err(e)
                    if e.kind() == io::ErrorKind::NotFound
                        || e.kind() == io::ErrorKind::NotADirectory =>
                {
                    return Ok(false);
                }
                Err(e) => return Err(e),
            };
            for entry in entries {
                let entry = entry?;
                let name = entry.file_name();
                let Some(name) = name.to_str() else {
                    continue;
                };
                if name.len() != crate::hash::HEX_LEN
                    || !name
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    || !entry.file_type()?.is_dir()
                {
                    continue;
                }
                if let Some(prefix) = read_prefix(&entry.path().join("manifest.bin"), 4)?
                    && prefix == b"MKGM"
                {
                    return Ok(true);
                }
            }
            Ok(false)
        }

        pub(crate) fn classify_scoped_root(root: &Path) -> io::Result<ScopedAuthority> {
            let scoped_state = scoped_state_recognized(root)?;
            let dot_mkit = root.join(MKIT_DIR);
            let meta = match std::fs::symlink_metadata(&dot_mkit) {
                Ok(m) => m,
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    return Ok(decide(Marker::Absent, scoped_state));
                }
                Err(e) => return Err(e),
            };
            if meta.is_dir() {
                return Ok(decide(Marker::Directory, scoped_state));
            }
            if !meta.is_file() {
                return Ok(decide(Marker::NonRegular, scoped_state));
            }
            let cap = usize::try_from(MAX_POINTER_FILE_BYTES).unwrap_or(usize::MAX);
            let bytes = read_prefix(&dot_mkit, cap)?.unwrap_or_default();
            Ok(decide(Marker::Regular(bytes), scoped_state))
        }
    }

    #[cfg(all(unix, not(target_arch = "wasm32")))]
    pub(crate) use descriptor::classify_scoped_root;
    #[cfg(not(all(unix, not(target_arch = "wasm32"))))]
    pub(crate) use paths::classify_scoped_root;
}

pub(crate) use scoped_classify::classify_scoped_root;

/// Refuse any scoped-workspace authority at `start` or above it, so
/// ordinary operations invoked inside a scoped root fail before they can
/// reach an ancestor repository or create files. Shared by [`discover`],
/// `ObjectStore` open/init, and callers that walk ancestors themselves.
pub fn check_scoped_boundary(start: &Path) -> Result<(), DiscoverError> {
    // Resolve the longest EXISTING prefix of `start` before walking: a
    // relative `start` would stop at its textual top and never see an
    // enclosing scoped root, and a symlinked prefix must resolve to the
    // directory it actually names. `canonicalize` needs the path to
    // exist, so when `start` (or a deeper probe) is missing, walk the
    // probe upward until a prefix resolves — its canonical form follows
    // a caller's directory alias to the REAL directory, whose real
    // ancestors may carry scoped authority the textual chain never
    // reaches (an alias can name a directory INSIDE a scoped root, not
    // just the root itself). Missing suffix components cannot contain
    // authority, so nothing between `start` and the resolved prefix is
    // lost. A start with no canonicalizable prefix falls back to its
    // absolute textual form, where per-ancestor probes still surface
    // genuine permission and I/O errors.
    let absolute = if start.is_absolute() {
        start.to_path_buf()
    } else {
        match std::env::current_dir() {
            Ok(cwd) => cwd.join(start),
            Err(_) => start.to_path_buf(),
        }
    };
    let mut probe = absolute.as_path();
    let resolved = loop {
        match probe.canonicalize() {
            Ok(real) => break real,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                ) =>
            {
                match probe.parent() {
                    Some(parent) if parent != probe => probe = parent,
                    _ => break absolute.clone(),
                }
            }
            // Permission/other resolution failures keep the textual
            // chain: `classify_scoped_root` surfaces the real error
            // from the first ancestor its no-follow probes can read.
            Err(_) => break absolute.clone(),
        }
    };
    for dir in resolved.ancestors() {
        match classify_scoped_root(dir).map_err(|e| DiscoverError::Io(dir.to_path_buf(), e))? {
            ScopedAuthority::None => {}
            ScopedAuthority::Scoped => {
                return Err(DiscoverError::ScopedWorkspace(dir.to_path_buf()));
            }
            ScopedAuthority::CorruptMarker => {
                return Err(DiscoverError::ScopedMarkerCorrupt(dir.to_path_buf()));
            }
            ScopedAuthority::Incomplete => {
                return Err(DiscoverError::ScopedInstallIncomplete(dir.to_path_buf()));
            }
            ScopedAuthority::Conflict => {
                return Err(DiscoverError::ScopedLayoutConflict(dir.to_path_buf()));
            }
        }
    }
    Ok(())
}

/// True when `root` carries ordinary `.mkit` authority — a directory or
/// any regular file — used by scoped-workspace creation to reject
/// nesting inside an ordinary or linked repository.
#[cfg(all(unix, not(target_arch = "wasm32")))]
pub(crate) fn has_ordinary_authority(root: &Path) -> std::io::Result<bool> {
    match std::fs::symlink_metadata(root.join(MKIT_DIR)) {
        Ok(meta) => Ok(meta.is_dir() || meta.is_file() || meta.file_type().is_symlink()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
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
        // Symlinked pointer: the byte cap sizes the LINK, so a link to
        // a huge (or unbounded, e.g. /dev/zero) target must be
        // rejected outright, never followed.
        #[cfg(unix)]
        {
            std::fs::remove_file(&pointer).unwrap();
            let huge = tmp.path().join("huge");
            std::fs::write(&huge, format!("mkitdir: /{}\n", "x".repeat(8192))).unwrap();
            std::os::unix::fs::symlink(&huge, &pointer).unwrap();
            assert!(matches!(
                discover(&tree),
                Err(DiscoverError::PointerSymlink(_))
            ));
        }

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

    /// A directory carrying recognizable scoped metadata without the
    /// exact marker: `.mkit-scoped/CURRENT` beginning `MKCR`.
    fn scaffold_incomplete(root: &Path) {
        let scoped = root.join(SCOPED_STATE_DIR);
        std::fs::create_dir_all(&scoped).unwrap();
        std::fs::write(scoped.join("CURRENT"), b"MKCR\x01rest").unwrap();
    }

    #[test]
    fn scoped_boundary_refuses_every_authority_shape() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("ws");
        std::fs::create_dir(&root).unwrap();

        // Exact marker → scoped workspace.
        std::fs::write(root.join(MKIT_DIR), SCOPED_MARKER).unwrap();
        assert!(matches!(
            check_scoped_boundary(&root),
            Err(DiscoverError::ScopedWorkspace(_))
        ));
        assert!(matches!(
            check_scoped_boundary(&root.join("nested/deep")),
            Err(DiscoverError::ScopedWorkspace(_))
        ));

        // Marker that begins like a scoped marker but is not exact.
        std::fs::write(root.join(MKIT_DIR), b"mkit-scoped: 2\n").unwrap();
        assert!(matches!(
            check_scoped_boundary(&root),
            Err(DiscoverError::ScopedMarkerCorrupt(_))
        ));

        // Recognizable scoped metadata without a marker → incomplete.
        std::fs::remove_file(root.join(MKIT_DIR)).unwrap();
        scaffold_incomplete(&root);
        assert!(matches!(
            check_scoped_boundary(&root),
            Err(DiscoverError::ScopedInstallIncomplete(_))
        ));

        // Ordinary `.mkit` directory overlapping scoped metadata → conflict.
        std::fs::create_dir(root.join(MKIT_DIR)).unwrap();
        assert!(matches!(
            check_scoped_boundary(&root),
            Err(DiscoverError::ScopedLayoutConflict(_))
        ));

        // A generation dir with an MKGM manifest alone also counts as
        // recognizable scoped metadata.
        let orphan = tmp.path().join("orphan");
        let gen_dir = orphan.join(format!(
            "{SCOPED_STATE_DIR}/generations/{}",
            "a".repeat(crate::hash::HEX_LEN)
        ));
        std::fs::create_dir_all(&gen_dir).unwrap();
        std::fs::write(gen_dir.join("manifest.bin"), b"MKGM\x01rest").unwrap();
        assert!(matches!(
            check_scoped_boundary(&orphan),
            Err(DiscoverError::ScopedInstallIncomplete(_))
        ));
    }

    #[test]
    fn unrelated_scoped_named_directory_is_not_authority() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("plain");
        std::fs::create_dir(&root).unwrap();
        // A bare `.mkit-scoped` dir, a lock file, and junk content are
        // all unrelated state — none establish scoped authority.
        let scoped = root.join(SCOPED_STATE_DIR);
        std::fs::create_dir(&scoped).unwrap();
        std::fs::write(scoped.join("workspace.lock"), b"").unwrap();
        std::fs::write(scoped.join("service-junk"), b"x").unwrap();
        check_scoped_boundary(&root).unwrap();
        assert!(discover(&root).unwrap().is_single());
    }

    /// A `CURRENT` DIRECTORY inside an otherwise ordinary repository —
    /// e.g. a tracked `.mkit-scoped/CURRENT/user-file.txt` — is not
    /// scoped authority: the name alone creates none. Ordinary
    /// discover/open must keep working.
    #[test]
    fn unrelated_current_directory_keeps_ordinary_repository_usable() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("repo");
        std::fs::create_dir_all(root.join(MKIT_DIR).join("objects")).unwrap();
        std::fs::write(
            root.join(MKIT_DIR).join("format"),
            format!("{}\n", crate::store::FORMAT_VALUE),
        )
        .unwrap();
        let current_dir = root.join(SCOPED_STATE_DIR).join("CURRENT");
        std::fs::create_dir_all(&current_dir).unwrap();
        std::fs::write(current_dir.join("user-file.txt"), b"tracked").unwrap();
        check_scoped_boundary(&root).unwrap();
        assert!(discover(&root).is_ok());
        assert!(crate::store::ObjectStore::open(&RepoLayout::single(&root)).is_ok());
        assert!(discover(&root.join("deep/nested")).is_ok());
    }

    /// A symlinked `CURRENT` or `manifest.bin` is never followed and
    /// never evidence: the name alone does not create authority, and the
    /// outside file's `MKCR`/`MKGM` bytes are never even read.
    #[test]
    #[cfg(unix)]
    fn symlinked_scoped_metadata_is_unrelated_never_authority() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("repo");
        std::fs::create_dir_all(root.join(MKIT_DIR)).unwrap();
        let scoped = root.join(SCOPED_STATE_DIR);
        std::fs::create_dir(&scoped).unwrap();
        let outside = tmp.path().join("outside-current");
        std::fs::write(&outside, b"MKCR\x01rest").unwrap();
        std::os::unix::fs::symlink(&outside, scoped.join("CURRENT")).unwrap();
        check_scoped_boundary(&root).unwrap();
        assert!(
            discover(&root).is_ok(),
            "a symlinked CURRENT is unrelated, not authority"
        );
        // A symlinked manifest.bin inside a real generations dir is the
        // same: skipped, not followed, not evidence.
        std::fs::remove_file(scoped.join("CURRENT")).unwrap();
        let gen_dir = scoped.join(format!("generations/{}", "b".repeat(crate::hash::HEX_LEN)));
        std::fs::create_dir_all(&gen_dir).unwrap();
        let outside_manifest = tmp.path().join("outside-manifest");
        std::fs::write(&outside_manifest, b"MKGM\x01rest").unwrap();
        std::os::unix::fs::symlink(&outside_manifest, gen_dir.join("manifest.bin")).unwrap();
        check_scoped_boundary(&root).unwrap();
        assert!(discover(&root).is_ok());
    }

    /// A nonregular `CURRENT` cannot hide genuine scoped authority: a
    /// real `MKGM` generation manifest still classifies the root as an
    /// incomplete install when no valid marker exists, and the exact
    /// marker is authority regardless.
    #[test]
    #[cfg(unix)]
    fn nonregular_current_does_not_hide_genuine_authority() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("ws");
        let scoped = root.join(SCOPED_STATE_DIR);
        // CURRENT as a directory + genuine MKGM manifest + no marker.
        std::fs::create_dir_all(scoped.join("CURRENT")).unwrap();
        let gen_dir = scoped.join(format!("generations/{}", "d".repeat(crate::hash::HEX_LEN)));
        std::fs::create_dir_all(&gen_dir).unwrap();
        std::fs::write(gen_dir.join("manifest.bin"), b"MKGM\x01rest").unwrap();
        assert!(matches!(
            check_scoped_boundary(&root),
            Err(DiscoverError::ScopedInstallIncomplete(_))
        ));
        // The exact scoped marker is authority on its own.
        std::fs::write(root.join(MKIT_DIR), SCOPED_MARKER).unwrap();
        assert!(matches!(
            check_scoped_boundary(&root),
            Err(DiscoverError::ScopedWorkspace(_))
        ));
    }

    /// A `.mkit` that exists but is not a regular file (symlink, FIFO,
    /// device) can never be the scoped marker. Recognized scoped
    /// metadata beneath it is still an incomplete-install boundary —
    /// never "no authority" that lets the ancestor walk reach a parent
    /// repository.
    #[test]
    #[cfg(unix)]
    fn nonregular_marker_over_scoped_state_is_incomplete() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("repo");
        std::fs::create_dir_all(repo.join(MKIT_DIR)).unwrap();
        let root = repo.join("ws");
        std::fs::create_dir(&root).unwrap();
        scaffold_incomplete(&root);
        // `.mkit` as a symlink (pointing anywhere — the classifier must
        // not follow it) overlapping scoped metadata.
        std::os::unix::fs::symlink(repo.join(MKIT_DIR), root.join(MKIT_DIR)).unwrap();
        assert!(matches!(
            check_scoped_boundary(&root),
            Err(DiscoverError::ScopedInstallIncomplete(_))
        ));
        assert!(matches!(
            discover(&root.join("deep")),
            Err(DiscoverError::ScopedInstallIncomplete(_))
        ));
    }

    /// A `generations` symlink to an external directory must never be
    /// followed: the outside MKGM manifest is not scoped authority and
    /// must not even be read. The descriptor-anchored classifier opens
    /// the component no-follow, so this unrelated shape leaves ordinary
    /// discovery working.
    #[test]
    #[cfg(unix)]
    fn generations_symlink_is_never_followed() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("repo");
        // Ordinary repository with a scoped-named dir whose `generations`
        // component is a symlink to external manifest content.
        std::fs::create_dir_all(root.join(MKIT_DIR)).unwrap();
        std::fs::create_dir(root.join(SCOPED_STATE_DIR)).unwrap();
        let outside = tmp.path().join("outside");
        let gen_dir = outside.join("a".repeat(crate::hash::HEX_LEN));
        std::fs::create_dir_all(&gen_dir).unwrap();
        std::fs::write(gen_dir.join("manifest.bin"), b"MKGM\x01rest").unwrap();
        std::os::unix::fs::symlink(&outside, root.join(SCOPED_STATE_DIR).join("generations"))
            .unwrap();
        check_scoped_boundary(&root).unwrap();
        assert!(discover(&root).is_ok());
        assert!(discover(&root.join("nested")).is_ok());
    }

    /// An unrelated `.mkit-scoped/generations` REGULAR FILE inside an
    /// ordinary repository is a name collision, not scoped authority —
    /// ordinary discovery, open, and status must keep working.
    #[test]
    fn unrelated_mkit_scoped_entries_do_not_break_ordinary_repos() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("repo");
        std::fs::create_dir_all(root.join(MKIT_DIR).join("objects")).unwrap();
        std::fs::write(
            root.join(MKIT_DIR).join("format"),
            format!("{}\n", crate::store::FORMAT_VALUE),
        )
        .unwrap();
        let scoped = root.join(SCOPED_STATE_DIR);
        std::fs::create_dir(&scoped).unwrap();
        // A same-named regular file where a scoped directory could be:
        // nothing recognizable, so it must not become authority — and
        // must not error the walk either.
        std::fs::write(scoped.join("generations"), b"unrelated").unwrap();
        check_scoped_boundary(&root).unwrap();
        assert!(discover(&root).is_ok());
        assert!(crate::store::ObjectStore::open(&RepoLayout::single(&root)).is_ok());
        // The same shape nested below the invocation directory.
        assert!(discover(&root.join("deep/nested")).is_ok());
        // `.mkit-scoped` as a regular file or symlink is likewise
        // unrelated.
        let other = tmp.path().join("other");
        std::fs::create_dir_all(other.join(MKIT_DIR)).unwrap();
        std::fs::write(other.join(SCOPED_STATE_DIR), b"unrelated").unwrap();
        check_scoped_boundary(&other).unwrap();
        #[cfg(unix)]
        {
            let linked = tmp.path().join("linked");
            std::fs::create_dir_all(linked.join(MKIT_DIR)).unwrap();
            std::os::unix::fs::symlink(scoped.as_path(), linked.join(SCOPED_STATE_DIR)).unwrap();
            check_scoped_boundary(&linked).unwrap();
        }
    }

    /// A FIFO named `generations` is unrelated, not authority — the
    /// classifier must reject-by-shape without blocking and without
    /// converting the type mismatch into an I/O failure.
    #[test]
    #[cfg(unix)]
    fn generations_fifo_is_unrelated_not_authority() {
        use std::os::unix::ffi::OsStrExt;
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("repo");
        std::fs::create_dir_all(root.join(MKIT_DIR)).unwrap();
        let scoped = root.join(SCOPED_STATE_DIR);
        std::fs::create_dir(&scoped).unwrap();
        let fifo = scoped.join("generations");
        let c_path = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: mkfifo(2) on a CString path inside our own tempdir.
        #[allow(unsafe_code)]
        let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
        assert_eq!(rc, 0);
        check_scoped_boundary(&root).unwrap();
        assert!(discover(&root).is_ok());
    }

    /// A FIFO substituted for `CURRENT` or `manifest.bin` is unrelated,
    /// not authority — the nonblocking descriptor open never stalls on
    /// the pipe, and a nonregular leaf cannot hide a genuine `MKGM`
    /// manifest beside it.
    #[test]
    #[cfg(unix)]
    fn fifo_state_leaves_are_unrelated_not_authority() {
        use std::os::unix::ffi::OsStrExt;
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("repo");
        std::fs::create_dir_all(root.join(MKIT_DIR)).unwrap();
        let scoped = root.join(SCOPED_STATE_DIR);
        std::fs::create_dir(&scoped).unwrap();
        let mkfifo = |path: &Path| {
            let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
            // SAFETY: mkfifo(2) on a CString path inside our own tempdir.
            #[allow(unsafe_code)]
            let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
            assert_eq!(rc, 0);
        };
        // Alone, a FIFO `CURRENT` or `manifest.bin` is unrelated — the
        // classifier never blocks on it and finds no authority.
        mkfifo(&scoped.join("CURRENT"));
        check_scoped_boundary(&root).unwrap();
        assert!(discover(&root).is_ok());
        let gen_dir = scoped.join(format!("generations/{}", "c".repeat(crate::hash::HEX_LEN)));
        std::fs::create_dir_all(&gen_dir).unwrap();
        mkfifo(&gen_dir.join("manifest.bin"));
        check_scoped_boundary(&root).unwrap();
        // But a REAL manifest beside the nonregular `CURRENT` is genuine
        // authority — with no marker the root is an incomplete install.
        std::fs::remove_dir_all(root.join(MKIT_DIR)).unwrap();
        std::fs::remove_file(gen_dir.join("manifest.bin")).unwrap();
        std::fs::write(gen_dir.join("manifest.bin"), b"MKGM\x01rest").unwrap();
        assert!(matches!(
            check_scoped_boundary(&root),
            Err(DiscoverError::ScopedInstallIncomplete(_))
        ));
    }

    /// A scoped workspace reached only through a directory alias must
    /// still bound ordinary operations: `alias/missing-descendant` has a
    /// canonicalizable-prefix symlink the ancestor walk must resolve —
    /// `ObjectStore::init` past it must refuse and create nothing.
    #[test]
    #[cfg(unix)]
    fn scoped_boundary_through_alias_with_missing_descendant() {
        let tmp = tempfile::tempdir().unwrap();
        // A recognized scoped install: exact marker + MKCR CURRENT.
        let real = tmp.path().join("real-scoped");
        std::fs::create_dir_all(real.join(SCOPED_STATE_DIR)).unwrap();
        std::fs::write(real.join(MKIT_DIR), SCOPED_MARKER).unwrap();
        std::fs::write(real.join(SCOPED_STATE_DIR).join("CURRENT"), b"MKCR\x01rest").unwrap();
        // The alias names the scoped root; the descendant is missing.
        let alias = tmp.path().join("alias");
        std::os::unix::fs::symlink(&real, &alias).unwrap();
        let missing = alias.join("new-missing-directory");
        // The boundary check must find the scoped root through the
        // alias — on macOS `O_NOFOLLOW|O_DIRECTORY` on the leaf symlink
        // surfaces as ENOTDIR, which must be distinguished from a
        // genuine non-directory.
        assert!(matches!(
            check_scoped_boundary(&missing),
            Err(DiscoverError::ScopedWorkspace(_))
        ));
        // A textual form exercising the non-canonicalized ancestor walk.
        assert!(matches!(
            check_scoped_boundary(&alias.join("sub/../new-missing-directory")),
            Err(DiscoverError::ScopedWorkspace(_))
        ));
        // The real mutation seam: init must refuse BEFORE creating
        // anything beneath the scoped root.
        assert!(matches!(
            crate::store::ObjectStore::init(&RepoLayout::single(&missing)),
            Err(crate::StoreError::ScopedBoundary(
                DiscoverError::ScopedWorkspace(_)
            ))
        ));
        assert!(!missing.exists() && !real.join("new-missing-directory").exists());
        assert!(!real.join(MKIT_DIR).join("objects").exists());
        // An aliased NON-scoped parent still works — the alias itself is
        // not the refusal, the authority beneath it is.
        let ordinary = tmp.path().join("ordinary");
        std::fs::create_dir(&ordinary).unwrap();
        let ordinary_alias = tmp.path().join("ordinary-alias");
        std::os::unix::fs::symlink(&ordinary, &ordinary_alias).unwrap();
        let fresh = ordinary_alias.join("fresh");
        crate::store::ObjectStore::init(&RepoLayout::single(&fresh)).unwrap();
        assert!(
            ordinary
                .join("fresh")
                .join(MKIT_DIR)
                .join("objects")
                .is_dir()
        );
    }

    /// The alias may name a directory INSIDE the scoped root, not only
    /// the root itself: `alias -> scoped-root/subdir`, with a missing
    /// descendant beneath it. The textual ancestors of
    /// `alias/new-dir` never spell the scoped root, so the boundary
    /// walk must resolve the alias to the real directory and continue
    /// on ITS ancestors — where the marker actually lives.
    #[test]
    #[cfg(unix)]
    fn scoped_boundary_through_alias_into_scoped_subdir() {
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("real-scoped");
        let subdir = real.join("existing-subdir");
        std::fs::create_dir_all(&subdir).unwrap();
        std::fs::create_dir_all(real.join(SCOPED_STATE_DIR)).unwrap();
        std::fs::write(real.join(MKIT_DIR), SCOPED_MARKER).unwrap();
        std::fs::write(real.join(SCOPED_STATE_DIR).join("CURRENT"), b"MKCR\x01rest").unwrap();
        // The alias names an interior directory of the scoped root.
        let external = tmp.path().join("external-parent");
        std::fs::create_dir(&external).unwrap();
        let alias = external.join("alias");
        std::os::unix::fs::symlink(&subdir, &alias).unwrap();
        // One missing component and several: neither can hide the real
        // enclosing root.
        for missing in [
            alias.join("new-directory"),
            alias.join("new-directory").join("deeper"),
        ] {
            assert!(
                matches!(
                    check_scoped_boundary(&missing),
                    Err(DiscoverError::ScopedWorkspace(_)),
                ),
                "missing path through interior alias must refuse: {missing:?}"
            );
            assert!(
                matches!(
                    crate::store::ObjectStore::init(&RepoLayout::single(&missing)),
                    Err(crate::StoreError::ScopedBoundary(
                        DiscoverError::ScopedWorkspace(_)
                    )),
                ),
                "init through interior alias must refuse: {missing:?}"
            );
            assert!(!missing.exists());
        }
        assert!(!subdir.join("new-directory").exists());
        assert!(!real.join(MKIT_DIR).join("objects").exists());
        // The alias did not corrupt the workspace's own authority.
        assert!(matches!(
            check_scoped_boundary(&real),
            Err(DiscoverError::ScopedWorkspace(_))
        ));
        // A missing destination beneath an ordinary aliased directory
        // remains supported — the alias is not the refusal.
        let plain = tmp.path().join("plain");
        std::fs::create_dir(&plain).unwrap();
        let plain_alias = tmp.path().join("plain-alias");
        std::os::unix::fs::symlink(&plain, &plain_alias).unwrap();
        let init = plain_alias.join("repo");
        crate::store::ObjectStore::init(&RepoLayout::single(&init)).unwrap();
        assert!(plain.join("repo").join(MKIT_DIR).join("objects").is_dir());
    }

    /// Recognizable scoped authority still refuses once a same-named
    /// unrelated entry is ruled out: real `MKCR`/`MKGM` content beneath
    /// `.mkit-scoped` with no valid marker.
    #[test]
    #[cfg(unix)]
    fn real_scoped_authority_still_refuses_after_unrelated_filtering() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("repo");
        std::fs::create_dir_all(repo.join(MKIT_DIR)).unwrap();
        let root = repo.join("ws");
        std::fs::create_dir(&root).unwrap();
        // Real MKCR bytes plus unrelated junk in the same directory:
        // the junk does not weaken the recognized authority.
        let scoped = root.join(SCOPED_STATE_DIR);
        std::fs::create_dir(&scoped).unwrap();
        std::fs::write(scoped.join("CURRENT"), b"MKCR\x01rest").unwrap();
        std::fs::write(scoped.join("generations"), b"unrelated").unwrap();
        assert!(matches!(
            check_scoped_boundary(&root),
            Err(DiscoverError::ScopedInstallIncomplete(_))
        ));
        assert!(matches!(
            discover(&root.join("deep")),
            Err(DiscoverError::ScopedInstallIncomplete(_))
        ));
    }

    #[test]
    fn scoped_boundary_precedes_ancestor_repo_discovery() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("repo");
        std::fs::create_dir_all(repo.join(MKIT_DIR)).unwrap();
        // A scoped root nested inside an ordinary repository: discovery
        // from below must refuse, not walk up into `repo`.
        let ws = repo.join("sub/ws");
        std::fs::create_dir_all(&ws).unwrap();
        std::fs::write(ws.join(MKIT_DIR), SCOPED_MARKER).unwrap();
        assert!(matches!(
            discover(&ws.join("deep")),
            Err(DiscoverError::ScopedWorkspace(_))
        ));
    }
}
