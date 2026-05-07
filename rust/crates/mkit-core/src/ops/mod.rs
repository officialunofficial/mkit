//! `mkit_core::ops` — high-level history operations on top of the
//! content-addressed object store.
//!
//! Submodules are split by concern. Public surface is intentionally
//! narrow.

// Phase 5a — diff / graph / merge / cherry_pick (OPS1).
pub mod cherry_pick;
pub mod diff;
pub mod graph;
pub mod merge;

// Phase 5b — rebase / bisect / blame / stash / restore (OPS2).
pub mod bisect;
pub mod blame;
pub mod rebase;
pub mod restore;
pub mod stash;

pub use cherry_pick::{CherryPickError, CherryPickResult, cherry_pick};
pub use diff::{
    DiffEntry, DiffError, DiffKind, DiffResult, StatusEntry, StatusStaging, diff_trees, status_diff,
};
pub use graph::{collect_ancestor_set, reachable_objects};
pub use merge::{Conflict, ConflictKind, MergeResult, find_merge_base, is_ancestor, merge_trees};
pub use restore::{RestoreOptions, RestoreReport, restore_tree_to_worktree};
