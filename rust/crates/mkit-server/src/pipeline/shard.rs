//! Shard routing (PRD §5.3, D34; reconciliation R-29). Planners never
//! hard-code a partition: they ask a [`ShardMap`]. M1 (WP-1.22) adds the
//! D34 map and switches the Connect deployments to it; the planners stay
//! the same.

use crate::repo::{NamespaceKey, RepoId};
use crate::rt::{MaybeSend, MaybeSync};
use crate::store::{BlobKey, Partition};

/// Maps an operation's rows to the partition that holds them.
pub trait ShardMap: MaybeSend + MaybeSync {
    /// The ref shard of `ref_name`: its head, replay records and quota
    /// counters. A branch head and its packmap MUST map to the same shard,
    /// so an `AdvanceRefs` commits in one batch.
    fn ref_shard(&self, repo: &RepoId, ref_name: &str) -> Partition;

    /// The namespace coordinator: configuration and the grant epoch.
    fn coordinator(&self, ns: &NamespaceKey) -> Partition;

    /// The ref-name index `ListRefs` reads.
    fn ref_index(&self, repo: &RepoId) -> Partition;

    /// The membership shard of `pack`.
    fn membership(&self, repo: &RepoId, pack: &BlobKey) -> Partition;
}

/// Every row of a namespace in one partition: M0, and the fs-layout and
/// ssh path for good.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SinglePartition;

impl ShardMap for SinglePartition {
    fn ref_shard(&self, repo: &RepoId, _ref_name: &str) -> Partition {
        Partition::Namespace(repo.namespace.clone())
    }

    fn coordinator(&self, ns: &NamespaceKey) -> Partition {
        Partition::Namespace(ns.clone())
    }

    fn ref_index(&self, repo: &RepoId) -> Partition {
        Partition::Namespace(repo.namespace.clone())
    }

    fn membership(&self, repo: &RepoId, _pack: &BlobKey) -> Partition {
        Partition::Namespace(repo.namespace.clone())
    }
}
