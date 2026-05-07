//! Subcommand implementations. Each top-level command is its own
//! module.
//!
//! Dispatch lives in `main.rs`; business logic lives in library
//! crates; this module is the thin presentation shim.

pub mod add;
pub mod attest;
pub mod attest_factory;
pub mod bisect;
pub mod blame;
pub mod branch;
pub mod cat;
pub mod checkout;
pub mod cherry_pick;
pub mod clone;
pub mod commit;
pub mod config_cmd;
pub mod diff;
pub mod fetch;
pub mod hash_cmd;
pub mod init;
pub mod keygen;
pub mod log;
pub mod merge;
pub mod pull;
pub mod push;
pub mod rebase;
pub mod remote;
pub mod rm;
pub mod serve;
pub mod sparse_checkout;
pub mod stash;
pub mod status;
pub mod tag;
pub mod tree;
pub mod verify;
pub mod verify_attest;

use crate::exit;
use mkit_core::hash::Hash;
use mkit_core::object::Object;
use mkit_core::store::ObjectStore;
use std::io::Write;
use std::path::Path;

/// Shared helper: emit a "not yet wired" notice and return the
/// tempfail exit code. Commands whose backing state-machines haven't
/// been wired into the CLI yet say so honestly rather than pretending
/// to work.
#[must_use]
pub fn not_yet_ported(cmd: &str) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: `mkit {cmd}` is not yet wired");
    exit::TEMPFAIL
}

/// Shared helper: print a usage error and return the USAGE exit code.
#[must_use]
pub fn usage_error(msg: &str) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    exit::USAGE
}

/// Rewrite `.mkit/index` so it exactly mirrors `tree_hash`.
///
/// `mkit commit` now signs the index, so commands that move HEAD and
/// materialize a committed tree must keep the index aligned with that
/// snapshot.
pub fn sync_index_to_tree(root: &Path, store: &ObjectStore, tree_hash: Hash) -> Result<(), String> {
    let idx = mkit_core::index::from_tree(store, tree_hash).map_err(|e| format!("index: {e}"))?;
    mkit_core::index::write_index(root, &idx).map_err(|e| format!("write index: {e}"))
}

/// Read the index, seeding an absent/empty one from HEAD when possible.
///
/// This lets old repositories or manually removed indexes keep the
/// expected staging invariant: adding/removing one path starts from the
/// current commit snapshot instead of making the next commit forget all
/// unchanged tracked files.
pub fn read_or_seed_index_from_head(
    root: &Path,
    store: &ObjectStore,
) -> Result<mkit_core::index::Index, String> {
    let idx = mkit_core::index::read_index(root).map_err(|e| format!("read index: {e}"))?;
    if !idx.entries.is_empty() {
        return Ok(idx);
    }

    let mkit_dir = root.join(mkit_core::MKIT_DIR);
    let Some(head_hash) =
        mkit_core::refs::resolve_head(&mkit_dir).map_err(|e| format!("resolve HEAD: {e}"))?
    else {
        return Ok(idx);
    };
    match store
        .read_object(&head_hash)
        .map_err(|e| format!("read HEAD: {e}"))?
    {
        Object::Commit(c) => mkit_core::index::from_tree(store, c.tree_hash)
            .map_err(|e| format!("index from HEAD: {e}")),
        Object::Remix(r) => mkit_core::index::from_tree(store, r.tree_hash)
            .map_err(|e| format!("index from HEAD: {e}")),
        _ => Err("HEAD does not resolve to a commit or remix".to_string()),
    }
}
