//! Durable Object classes and the partition kinds each serves.

use crate::naming::{CONTENT_INDEX, NS_COORD, REF_SHARD, REFSTORE, REPO_INDEX};
use mkit_server::Partition;

/// A deployment's Durable Object class. The exported structs live in its cdylib.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ShardClass {
    /// Single-sharding namespace store.
    RefStore,
    /// D34 namespace coordinator.
    NsCoordinator,
    /// D34 branch ref store.
    RefShard,
    /// Repository and ref-name indexes share this class.
    RepoIndexShard,
    /// Global content index store.
    ContentIndexShard,
}

impl ShardClass {
    /// Stable class label for physical storage pressure. Both index kinds
    /// share the repository-index class and therefore its pressure label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::RefStore => "namespace",
            Self::NsCoordinator => "coordinator",
            Self::RefShard => "ref",
            Self::RepoIndexShard => "repo_index",
            Self::ContentIndexShard => "content",
        }
    }

    /// Whether this class serves the partition kind.
    #[must_use]
    pub fn accepts(self, p: &Partition) -> bool {
        matches!(
            (self, p),
            (Self::RefStore, Partition::Namespace(_))
                | (Self::NsCoordinator, Partition::Coordinator(_))
                | (Self::RefShard, Partition::Ref { .. })
                | (
                    Self::RepoIndexShard,
                    Partition::RepoIndex { .. } | Partition::RefIndex { .. }
                )
                | (Self::ContentIndexShard, Partition::ContentShard(_))
        )
    }

    /// The deployment binding for this class.
    #[must_use]
    pub fn binding(self) -> &'static str {
        match self {
            Self::RefStore => REFSTORE,
            Self::NsCoordinator => NS_COORD,
            Self::RefShard => REF_SHARD,
            Self::RepoIndexShard => REPO_INDEX,
            Self::ContentIndexShard => CONTENT_INDEX,
        }
    }
}
