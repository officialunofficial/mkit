//! `mkit_core::ops` — high-level history operations on top of the
//! content-addressed object store.
//!
//! Submodules are split by concern. Public surface is intentionally
//! narrow.

// OPS1 — diff / graph / merge / cherry_pick.
pub mod cherry_pick;
pub mod conflict_state;
pub mod diff;
pub mod gc;
pub mod graph;
pub mod merge;
pub mod revert;

// OPS2 — rebase / bisect / blame / stash / restore.
pub mod bisect;
pub mod blame;
pub mod rebase;
pub mod recovery;
pub mod restore;
pub mod stash;

pub use cherry_pick::{CherryPickError, CherryPickResult, cherry_pick};
pub use conflict_state::{
    CherryPickState, ConflictRecord, ConflictStateError, MergeState, RevertState,
    any_op_in_progress, in_progress_op_name,
};
pub use diff::{
    BINARY_SNIFF_LEN, DEFAULT_CONTEXT_LINES, DiffEntry, DiffError, DiffKind, DiffResult, HunkLine,
    HunkLineKind, PatchHunk, StatusEntry, StatusStaging, WhitespaceMode, apply_hunks_subset,
    detect_exact_renames, diff_line_counts, diff_trees, enumerate_hunks, is_binary,
    merge_blob_3way, status_diff, status_diff_observed, text_patch, unified_hunks,
    unified_hunks_opts,
};
pub use gc::{GcReport, GcRootsError, collect_roots, live_objects, run_gc};
pub use graph::{
    collect_ancestor_set, reachable_closure, reachable_closure_checked, reachable_objects,
};
pub use merge::{Conflict, ConflictKind, MergeResult, find_merge_base, is_ancestor, merge_trees};
pub use recovery::{RecoveryEntry, RecoveryError, RetentionPolicy};
pub use restore::{RestoreOptions, RestoreReport, restore_tree_to_worktree};
pub use revert::{RevertError, RevertResult, revert};
