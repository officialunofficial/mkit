//! Monotonic mutation stamps for bounded fork source proofs.
//!
//! The backend increments each stamp in the same atomic batch as the facts it
//! invalidates. A stamp is never removed or reset, including when those facts
//! are deleted. Corrupt or exhausted counters refuse the complete batch.

use super::{Batch, Key, Partition};

/// Append one atomic mutation stamp without adding a writer snapshot read.
pub(crate) fn bump(batch: Batch, key: &Key) -> Batch {
    batch.increment(key.clone())
}

/// Repository-index partitions maintained by the sharded fork deployment.
/// Single-partition writes keep their existing batches; they do not offer fork.
pub(crate) fn index_partition(partition: &Partition) -> bool {
    matches!(partition, Partition::RepoIndex { .. })
}
