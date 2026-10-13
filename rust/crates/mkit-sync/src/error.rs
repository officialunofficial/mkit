//! The error type of every fallible `mkit-sync` call.

use crate::SourceError;
use mkit_core::layout::DiscoverError;
use mkit_core::ops::restore::RestoreError;
use mkit_core::pack::PackError;
use mkit_core::refs::RefError;
use mkit_core::repo_lock::LockError;
use mkit_core::store::StoreError;
use mkit_core::transfer::PackListError;

/// Why a clone, fetch or pull failed.
///
/// Display text is part of the contract the `mkit` command line relies on:
/// it prints these messages verbatim.
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    /// The caller's [`SyncObserver::cancelled`](crate::SyncObserver::cancelled)
    /// returned `true` at a checkpoint. The transfer is half-finished, but no
    /// remote-tracking ref was published for a branch that had not completed,
    /// so retrying is safe.
    #[error("interrupted")]
    Interrupted,
    /// A multi-part upload was interrupted (reported by a remote source whose
    /// error classifier recognises it; see
    /// [`TransportSource::with_error_classifier`](crate::TransportSource::with_error_classifier)).
    #[error("{0}")]
    UploadInterrupted(String),
    /// The remote has no such repository.
    #[error(
        "repository `{identity}` not found at {origin}; check the remote URL path against the server's configured name (an empty path selects `default` on a single-repository deployment)"
    )]
    RepositoryNotFound {
        identity: String,
        origin: String,
        source: SourceError,
    },
    #[error("transport: {0}")]
    Source(#[from] SourceError),
    #[error("refs: {0}")]
    Refs(#[from] RefError),
    #[error("repo lock: {0}")]
    RepoLock(#[from] LockError),
    #[error("worktree discovery: {0}")]
    Discover(#[from] DiscoverError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("store: {0}")]
    Store(#[from] StoreError),
    #[error("pack: {0}")]
    Pack(#[from] PackError),
    #[error("packlist: {0}")]
    PackList(#[from] PackListError),
    /// A pull needs HEAD to name a branch.
    #[error("pull requires HEAD to point at a branch")]
    DetachedHead,
    /// The requested (or only candidate) branch is not on the remote.
    #[error("remote branch '{0}' not found")]
    RemoteBranchMissing(String),
    /// The pull would not be a fast-forward; pull refuses anything else.
    #[error("pull would not fast-forward branch '{branch}'; merge or rebase first")]
    NonFastForwardPull { branch: String },
    /// Updating the working tree would lose local work, or failed.
    #[error("restore safety: {0}")]
    RestoreSafety(String),
    #[error("object is not a commit")]
    NotCommit,
    #[error("restore: {0}")]
    Restore(#[from] RestoreError),
    /// A packmap chain was malformed: too deep, cyclic, or a node could not
    /// be downloaded or decoded. A corrupt or hostile remote.
    #[error("pack map chain for branch '{branch}' is malformed (too deep, cyclic, or unreadable)")]
    PackChainInvalid {
        branch: String,
        source: Option<SourceError>,
    },
    /// The remote advertised a branch but no packmap for it.
    #[error("remote advertised branch '{0}' but no pack map to reconstruct it")]
    PackmapMissing(String),
    /// The packmap names a pack the remote does not hold.
    #[error("remote advertised pack {pack} for branch '{branch}' but does not hold it")]
    AdvertisedPackMissing {
        branch: String,
        pack: String,
        source: SourceError,
    },
    /// After unpacking the whole chain an object reachable from the tip is
    /// still absent locally.
    #[error("remote is missing object {0} needed to reconstruct the ref")]
    RemoteMissingObject(String),
    /// The fetched tip's closure exceeds the verification cap, so
    /// completeness could not be confirmed. Fails closed.
    #[error(
        "fetched history is too large to verify (closure exceeds the {0}-object cap); refusing to publish an unverified ref"
    )]
    ClosureTooLarge(usize),
    /// A commit, remix or tag introduced by this fetch failed Ed25519
    /// signature verification. Never retried as local staleness.
    #[error("object {hash} failed signature verification: {reason}")]
    UnsignedOrInvalidObject { hash: String, reason: String },
    /// A remote name is not a legal ref name, so it cannot name a record
    /// under `.mkit/applied-packs/`.
    #[error("invalid remote name for applied-packs record: '{0}'")]
    InvalidRemoteName(String),
}
