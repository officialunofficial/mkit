//! Progress, warnings and cancellation, without printing.
//!
//! The library never writes to stdout or stderr. Everything a command line
//! would print is delivered to a [`SyncObserver`] as a typed
//! [`SyncEvent`]; an embedder that wants silence passes [`NoopObserver`].

use std::path::PathBuf;

/// Something worth telling the user about, delivered while a sync runs.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SyncEvent {
    /// A pack was unpacked into the object store.
    ObjectsUnpacked { count: usize },
    /// A listed branch was deleted on the remote since the listing (the
    /// listing is eventual); it was skipped and its tracking ref left alone.
    BranchSkippedStale { branch: String },
    /// The applied-packs cache could not be read; the fetch continues
    /// without redownload avoidance.
    AppliedPacksUnreadable { remote: String, error: String },
    /// The applied-packs cache claimed packs the object store lacks; it is
    /// cleared and the branch's whole chain is fetched again.
    AppliedPacksStale {
        remote: String,
        branch: String,
        cause: String,
    },
    /// The applied-packs cache could not be written. Objects still landed;
    /// the cache is rebuilt by the next fetch.
    AppliedPacksPersistFailed { remote: String, error: String },
    /// A live server process is serving this repository, so a worktree
    /// mutation is not coordinated with it.
    RepositoryServed { worktree_root: PathBuf },
}

/// Receives [`SyncEvent`]s and can cancel a sync at its checkpoints.
pub trait SyncObserver {
    /// Called synchronously, on the calling thread, as events happen.
    fn event(&self, _event: &SyncEvent) {}

    /// Polled at every checkpoint between network or disk steps. Returning
    /// `true` makes the call fail with
    /// [`SyncError::Interrupted`](crate::SyncError::Interrupted).
    fn cancelled(&self) -> bool {
        false
    }
}

/// An observer that ignores every event and never cancels.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopObserver;

impl SyncObserver for NoopObserver {}
