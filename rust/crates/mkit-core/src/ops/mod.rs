//! High-level history operations on top of the content-addressed
//! object store.
//!
//! Each submodule here is a direct Rust port of the matching Zig file
//! on `main` — the Zig source IS the contract (no dedicated SPEC docs).
//!
//! Public surface is intentionally narrow and matches the Zig API names
//! 1:1 modulo Rust's `snake_case` ↔ camelCase swap so cross-implementation
//! diagnostics (`conflict at src/main.zig (modify_modify)`, etc.)
//! line up.
//!
//! NOTE: the Zig `diff.statusDiff` helper depends on `worktree.buildTree`,
//! which is part of an as-yet-unmerged Phase 4 track. The library half of
//! diff (tree vs tree) is fully ported here; `statusDiff` is intentionally
//! deferred until the worktree module lands on `rewrite/rust`.

pub mod cherry_pick;
pub mod diff;
pub mod graph;
pub mod merge;

pub use cherry_pick::{CherryPickError, CherryPickResult, cherry_pick};
pub use diff::{DiffEntry, DiffKind, DiffResult, diff_trees};
pub use graph::collect_ancestor_set;
pub use merge::{Conflict, ConflictKind, MergeResult, find_merge_base, is_ancestor, merge_trees};
