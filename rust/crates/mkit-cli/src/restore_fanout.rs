//! Rayon-backed `read_chunks` for
//! `mkit_core::ops::restore::restore_tree_to_worktree_with`. The
//! implementation lives in `mkit-sync`, whose pull uses it too; this module
//! re-exports it so call sites keep one path.

pub(crate) use mkit_sync::restore_fanout::read_chunks_fanout;
