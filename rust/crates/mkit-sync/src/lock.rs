//! The per-worktree lock a fetch publishes under, and the served-repository
//! probe that accompanies it.

use mkit_core::layout::RepoLayout;
use mkit_core::repo_lock::{self, RepoLock};

use crate::error::SyncError;
use crate::observer::{SyncEvent, SyncObserver};

/// Basename of the repo-level lock that serialises worktree and index
/// read-modify-write commands.
pub const WORKTREE_LOCK: &str = "worktree.lock";

/// Basename of the shared lock a live `mkit serve` process holds for its
/// whole lifetime. Local mutating commands never take it; they only probe it.
pub const SERVE_LOCK: &str = "serve.lock";

/// Tell `observer` when at least one server process is currently alive
/// against `layout`'s common dir. Detection, not coordination: a probe
/// failure is swallowed.
pub fn warn_if_served(layout: &RepoLayout, observer: &dyn SyncObserver) {
    if let Ok(false) = repo_lock::probe_exclusive(layout.common_dir(), SERVE_LOCK) {
        observer.event(&SyncEvent::RepositoryServed {
            worktree_root: layout.worktree_root().to_path_buf(),
        });
    }
}

/// Take the worktree lock with the default timeout, then run the
/// served-repository probe. Every site that takes [`WORKTREE_LOCK`] directly
/// must go through here so the probe cannot be forgotten.
pub(crate) fn acquire_worktree_lock(
    layout: &RepoLayout,
    observer: &dyn SyncObserver,
) -> Result<RepoLock, SyncError> {
    let lock = repo_lock::acquire_default(layout.worktree_state_dir(), WORKTREE_LOCK)?;
    warn_if_served(layout, observer);
    Ok(lock)
}
