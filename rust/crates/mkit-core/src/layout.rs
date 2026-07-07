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
//! paths to the historical ad-hoc joins. Linked working trees (later
//! phases of #493) will construct layouts whose two directories differ;
//! nothing outside this module may assume they coincide.
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
}
