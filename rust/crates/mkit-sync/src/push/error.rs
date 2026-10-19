use super::RetryReason;

#[derive(Debug, thiserror::Error)]
pub enum PushError {
    #[error(transparent)]
    Sync(#[from] crate::SyncError),
    /// Capability discovery failed or was invalid. No upload or ref write
    /// was attempted, because another client may know the server can reset
    /// the packmap atomically.
    #[error(
        "force push requires successful atomic-advance capability discovery; reconnect and retry"
    )]
    ForceCapabilityUnknown,
    /// A CAS ref write was rejected because the remote moved under us
    /// (non-fast-forward). Callers map this to an actionable
    /// fetch-then-retry / `--force-with-lease` hint.
    #[error(
        "updates were rejected for branch '{branch}' (non-fast-forward); fetch and merge first, or re-run with --force-with-lease / --force"
    )]
    NonFastForwardPush { branch: String },
    /// The branch's packmap pointer could not be durably advanced under
    /// sustained concurrent pushes. The branch ref was NOT moved, so the
    /// remote stays consistent; the push is safe to retry.
    #[error(
        "could not establish the pack map for branch '{branch}' under concurrent pushes; retry"
    )]
    PackmapContended { branch: String },
    /// One advance would need more data packs than the server permits per
    /// advance. `commit` names the single commit or merge that cannot be split
    /// further when the refusal came from the pre-flight dry seal, before
    /// anything was published; without it the seal-time backstop fired.
    #[error(
        "push needs {packs} data packs but this server permits {limit} per advance{}{}; ask the operator to raise max_pack_bytes",
        .commit.as_ref().map_or_else(String::new, |c| format!(" ({c} cannot be split further)")),
        if *.holds_remote_head {
            " (it is the first commit that contains the remote head: rebase onto the remote head, or merge it in a smaller or earlier commit)"
        } else {
            ""
        }
    )]
    PushTooLarge {
        packs: usize,
        limit: usize,
        commit: Option<String>,
        /// The unsplittable commit is the first that contains the remote head,
        /// so the split could not cut before it.
        holds_remote_head: bool,
    },
    /// A retry of one advance (a rejected ticket, a lost delta base) re-planned
    /// the push and the new plan no longer fits one advance. Found by a dry
    /// seal, so nothing was uploaded for the retry.
    #[error(
        "{reason}, and the retry needs {packs} data packs but this server permits {limit} per advance; nothing was uploaded for the retry"
    )]
    RetryTooLarge {
        reason: RetryReason,
        packs: usize,
        limit: usize,
    },
    /// A split push would exceed a bound (steps or chain length). Nothing was
    /// published.
    #[error("{0}")]
    PushSplitLimit(String),
    /// The stored grants do not authorize every advance of a split push.
    /// Nothing was published.
    #[error("{0}")]
    PushNotAuthorized(String),
    /// A split push failed after publishing some advances. `head` is the last
    /// advance this push published, a first-parent ancestor of the local tip
    /// (another pusher may have moved the branch since); re-running the push
    /// resumes from the remote branch unless a concurrent push caused the
    /// failure.
    #[error(
        "{cause}; {published} of {total} advances were published and the last published advance was {head} on branch '{branch}'{}",
        resume_hint(.cause)
    )]
    SplitInterrupted {
        branch: String,
        head: String,
        published: usize,
        total: usize,
        cause: Box<PushError>,
    },
    #[error("upload ticket was rejected after the push was retried")]
    TicketRejected,
    #[error("delta base is unavailable after a restart")]
    DeltaBaseUnavailable,
    #[error("packlist still names a pack absent from this repository after retry")]
    PacklistNotInRepository,
}

fn resume_hint(cause: &PushError) -> &'static str {
    if matches!(cause, PushError::NonFastForwardPush { .. }) {
        "; the branch was moved by another push, so fetch and merge before pushing again"
    } else {
        "; re-run the push to resume"
    }
}

impl From<crate::SourceError> for PushError {
    fn from(error: crate::SourceError) -> Self {
        Self::Sync(crate::SyncError::Source(error))
    }
}

impl From<mkit_core::refs::RefError> for PushError {
    fn from(error: mkit_core::refs::RefError) -> Self {
        Self::Sync(crate::SyncError::Refs(error))
    }
}

impl From<mkit_core::store::StoreError> for PushError {
    fn from(error: mkit_core::store::StoreError) -> Self {
        Self::Sync(crate::SyncError::Store(error))
    }
}

impl From<mkit_core::pack::PackError> for PushError {
    fn from(error: mkit_core::pack::PackError) -> Self {
        Self::Sync(crate::SyncError::Pack(error))
    }
}

impl From<mkit_core::transfer::PackListError> for PushError {
    fn from(error: mkit_core::transfer::PackListError) -> Self {
        Self::Sync(crate::SyncError::PackList(error))
    }
}

impl From<mkit_core::layout::DiscoverError> for PushError {
    fn from(error: mkit_core::layout::DiscoverError) -> Self {
        Self::Sync(crate::SyncError::Discover(error))
    }
}

impl From<std::io::Error> for PushError {
    fn from(error: std::io::Error) -> Self {
        Self::Sync(crate::SyncError::Io(error))
    }
}
