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
    /// Stable class label for physical storage pressure.
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

    /// Physical partition-kind label, including the two index kinds served
    /// by the same Durable Object class.
    #[must_use]
    pub const fn partition_label(self, p: &Partition) -> &'static str {
        match p {
            Partition::RepoIndex { .. } => "repo_index",
            Partition::RefIndex { .. } => "ref_index",
            _ => self.label(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use mkit_server::telemetry::pressure::{self, PressureLevel, PressureState};
    use mkit_server::{NamespaceKey, RepoName};

    #[test]
    fn index_pressure_labels_and_thresholds_cover_both_partition_kinds() {
        let ns = NamespaceKey::deployment_default();
        let repo = RepoName::new("one").unwrap();
        let partitions = [
            (
                Partition::RepoIndex {
                    ns: ns.clone(),
                    repo: repo.clone(),
                    prefix: 0,
                },
                "repo_index",
            ),
            (
                Partition::RefIndex {
                    ns,
                    repo,
                    bucket: 0,
                },
                "ref_index",
            ),
        ];
        for (partition, label) in partitions {
            assert_eq!(
                ShardClass::RepoIndexShard.partition_label(&partition),
                label
            );
            assert_eq!(
                pressure::observe(PressureState::default(), 70, 100, 0).1,
                [PressureLevel::Warn]
            );
            assert_eq!(
                pressure::observe(PressureState::default(), 90, 100, 0).1,
                [PressureLevel::Critical]
            );
        }
    }
}
