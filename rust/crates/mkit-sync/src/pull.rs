//! Pulling: fetch, then fast-forward the local branch, HEAD and worktree.

use std::path::Path;

use mkit_core::hash::Hash;
use mkit_core::layout::RepoLayout;
use mkit_core::object::Object;
use mkit_core::ops::merge::is_ancestor;
use mkit_core::refs::{self, Head};
use mkit_core::store::ObjectStore;

use crate::SyncOptions;
use crate::error::SyncError;
use crate::fetch::{FetchReport, fetch_objects};
use crate::lock::acquire_worktree_lock;
use crate::observer::SyncObserver;
use crate::source::RemoteSource;
use crate::worktree::{
    ensure_restore_safe, list_remote_refs_parallel, restore_worktree_and_index,
    write_ref_recording_history,
};

/// What a pull did to the local branch.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PullOutcome {
    /// The remote advertises no branches, so there was nothing to land.
    NoRemoteBranches,
    /// The local branch already pointed at the remote tip.
    UpToDate { branch: String },
    /// The branch, HEAD and worktree moved to the remote tip.
    FastForwarded {
        branch: String,
        /// The previous tip, `None` for a branch that did not exist yet.
        old: Option<Hash>,
        new: Hash,
    },
}

/// What a pull did.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PullReport {
    pub fetch: FetchReport,
    pub outcome: PullOutcome,
}

/// Open the object store of `layout` with the options' durability schedule.
pub(crate) fn open_store(
    layout: &RepoLayout,
    options: &SyncOptions,
) -> Result<ObjectStore, SyncError> {
    let mut store = ObjectStore::open(layout)?;
    store.set_sync_policy(options.sync_policy);
    Ok(store)
}

/// Fetch the remote's refs, then fast-forward the current local branch from
/// `refs/remotes/<remote>/<branch>`. Fresh repos with no local branch tip
/// initialise from the current branch's remote-tracking ref, or the first
/// advertised remote branch when the current default branch is absent.
/// Anything that is not a fast-forward is refused with
/// [`SyncError::NonFastForwardPull`].
///
/// `options.target_branch`, when `Some`, overrides which remote branch to land
/// on (used by clone `-b <branch>`): it MUST exist among the remote's refs or
/// the call fails with [`SyncError::RemoteBranchMissing`] rather than silently
/// falling back to another branch.
///
/// # Locking
///
/// The fetch phase takes the repo lock itself, narrowly and per branch, around
/// only the local unpack and remote-ref publish window; no lock is held across
/// the network transfer. The fast-forward phase then takes the worktree lock
/// around just the branch ref, HEAD and worktree update. The objects the
/// remote tip points at are already reachable via the remote-tracking ref
/// published during the fetch, so this lock's job is worktree-mutation
/// exclusivity against concurrent commands, not GC protection.
pub fn pull(
    dir: &Path,
    source: &dyn RemoteSource,
    remote: &str,
    options: &SyncOptions,
    observer: &dyn SyncObserver,
) -> Result<PullReport, SyncError> {
    let layout = mkit_core::layout::discover(dir)?;
    let store = open_store(&layout, options)?;
    let fetch = fetch_objects(&store, &layout, source, observer, remote, options)?;
    let remote_refs = list_remote_refs_parallel(&layout, remote)?
        .into_iter()
        .filter_map(|r| r.hash.map(|hash| (r.name, hash)))
        .collect::<Vec<_>>();
    if remote_refs.is_empty() {
        return Ok(PullReport {
            fetch,
            outcome: PullOutcome::NoRemoteBranches,
        });
    }

    let _lock = acquire_worktree_lock(&layout, observer)?;
    let target_branch = options.target_branch.as_deref();
    let original_head = refs::read_head(&layout).ok();
    let (branch, local_tip, remote_tip) = match &original_head {
        Some(Head::Branch(head_branch)) => {
            let want_branch = target_branch.unwrap_or(head_branch.as_str());
            let local_tip = refs::read_ref(&layout, want_branch)?;
            let selected = if local_tip.is_some() || target_branch.is_some() {
                // An explicit target (or an already-committed local branch of
                // that name) must match exactly: no silent fallback to a
                // different branch.
                remote_refs
                    .iter()
                    .find(|(name, _)| name == want_branch)
                    .ok_or_else(|| SyncError::RemoteBranchMissing(want_branch.to_owned()))?
            } else {
                remote_refs
                    .iter()
                    .find(|(name, _)| name == want_branch)
                    .unwrap_or(&remote_refs[0])
            };
            (selected.0.clone(), local_tip, selected.1)
        }
        Some(Head::Detached(_)) => return Err(SyncError::DetachedHead),
        None => (remote_refs[0].0.clone(), None, remote_refs[0].1),
    };

    let ref_condition = if let Some(local_tip) = local_tip {
        if local_tip == remote_tip {
            return Ok(PullReport {
                fetch,
                outcome: PullOutcome::UpToDate { branch },
            });
        }
        if !is_ancestor(&store, local_tip, remote_tip)? {
            return Err(SyncError::NonFastForwardPull { branch });
        }
        refs::RefWriteCondition::Match(local_tip)
    } else {
        refs::RefWriteCondition::Missing
    };

    let tree = load_tree_hash(&store, remote_tip)?;
    ensure_restore_safe(&layout, &store, tree).map_err(SyncError::RestoreSafety)?;
    write_ref_recording_history(&layout, &branch, ref_condition, &remote_tip)?;
    if let Err(e) = refs::write_head_branch(&layout, &branch) {
        rollback_pull_ref(&layout, &branch, local_tip, remote_tip)?;
        return Err(e.into());
    }
    if let Err(e) = restore_worktree_and_index(&layout, &store, tree) {
        if let Err(rollback) =
            rollback_pull_ref_and_head(&layout, &branch, local_tip, remote_tip, original_head)
        {
            return Err(SyncError::RestoreSafety(format!(
                "{e}; additionally failed to roll back ref: {rollback}"
            )));
        }
        return Err(SyncError::RestoreSafety(e));
    }
    Ok(PullReport {
        fetch,
        outcome: PullOutcome::FastForwarded {
            branch,
            old: local_tip,
            new: remote_tip,
        },
    })
}

/// Fetch every remote branch into its remote-tracking ref, without touching
/// the local branches, HEAD or worktree.
pub fn fetch(
    dir: &Path,
    source: &dyn RemoteSource,
    remote: &str,
    options: &SyncOptions,
    observer: &dyn SyncObserver,
) -> Result<FetchReport, SyncError> {
    let layout = mkit_core::layout::discover(dir)?;
    // No outer lock: `fetch_objects` takes the repo lock itself, narrowly and
    // per branch, around only the local unpack and ref-publish window.
    let store = open_store(&layout, options)?;
    fetch_objects(&store, &layout, source, observer, remote, options)
}

fn rollback_pull_ref_and_head(
    layout: &RepoLayout,
    branch: &str,
    local_tip: Option<Hash>,
    remote_tip: Hash,
    original_head: Option<Head>,
) -> Result<(), String> {
    rollback_pull_ref(layout, branch, local_tip, remote_tip).map_err(|e| e.to_string())?;
    match original_head {
        Some(Head::Branch(name)) => refs::write_head_branch(layout, &name),
        Some(Head::Detached(hash)) => refs::write_head_detached(layout, &hash),
        None => Ok(()),
    }
    .map_err(|e| e.to_string())
}

fn rollback_pull_ref(
    layout: &RepoLayout,
    branch: &str,
    local_tip: Option<Hash>,
    remote_tip: Hash,
) -> Result<(), refs::RefError> {
    if let Some(local_tip) = local_tip {
        write_ref_recording_history(
            layout,
            branch,
            refs::RefWriteCondition::Match(remote_tip),
            &local_tip,
        )
    } else if refs::read_ref(layout, branch)? == Some(remote_tip) {
        refs::delete_ref(layout, branch)
    } else {
        Ok(())
    }
}

fn load_tree_hash(store: &ObjectStore, commit_hash: Hash) -> Result<Hash, SyncError> {
    match store.read_object(&commit_hash)? {
        Object::Commit(c) => Ok(c.tree_hash),
        Object::Remix(r) => Ok(r.tree_hash),
        _ => Err(SyncError::NotCommit),
    }
}
