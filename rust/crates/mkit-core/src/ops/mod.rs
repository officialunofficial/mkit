//! `mkit_core::ops` — high-level history operations on top of the
//! content-addressed object store.
//!
//! Each submodule is a Rust port of the matching Zig file on `main` —
//! the Zig source IS the contract (no dedicated SPEC docs for these
//! ops). Public surface is intentionally narrow and matches the Zig
//! API names 1:1 modulo Rust's `snake_case` ↔ camelCase swap so
//! cross-implementation diagnostics line up.
//!
//! Submodules are split by concern; parallel agent tracks add new
//! submodules APPEND-ONLY so they merge cleanly.
//!
//! NOTE: the Zig `diff.statusDiff` helper depends on
//! `worktree.build_tree` (Phase 4, now merged). The library half of
//! diff (tree vs tree) is ported here; `status_diff` follow-up tracked
//! in the rewrite plan.

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
// Phase 5a-statusdiff: append-only addition of status_diff surface.
pub use diff::{
    DiffEntry, DiffError, DiffKind, DiffResult, StatusEntry, StatusStaging, diff_trees, status_diff,
};
pub use graph::collect_ancestor_set;
pub use merge::{Conflict, ConflictKind, MergeResult, find_merge_base, is_ancestor, merge_trees};
