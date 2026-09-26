//! The optional in-process write gate ([`super::Pipeline::with_write_gate`]).

use core::hash::BuildHasher as _;
use std::collections::hash_map::RandomState;

use tokio::sync::{Mutex, MutexGuard};

use crate::store::Partition;

/// Lock stripes: partitions that hash alike share one.
const STRIPES: usize = 64;

/// Serializes the read-plan-apply loops of one partition within this
/// process, the way a Durable Object's input gate serializes them on
/// Workers. Writes that share a key (a signer's quota window) then never
/// race each other into [`super::plan::MAX_REPLAN`] re-plans.
///
/// Waiters enter in arrival order (`tokio::sync::Mutex` is FIFO-fair, and
/// needs no tokio runtime), so no write starves. Stripes are chosen with a
/// per-process random key, so a client cannot aim its partitions at one
/// stripe to stall another partition's writes.
pub(super) struct WriteGate {
    stripes: Vec<Mutex<()>>,
    keys: RandomState,
}

impl WriteGate {
    pub(super) fn new() -> Self {
        Self {
            stripes: (0..STRIPES).map(|_| Mutex::new(())).collect(),
            keys: RandomState::new(),
        }
    }

    /// `p`'s stripe.
    fn stripe(&self, p: &Partition) -> usize {
        // Truncation is fine: only the stripe index matters.
        #[allow(clippy::cast_possible_truncation)]
        let h = self.keys.hash_one(p) as usize;
        h % self.stripes.len()
    }

    /// Wait for `p`'s stripe.
    pub(super) async fn enter(&self, p: &Partition) -> MutexGuard<'_, ()> {
        self.stripes[self.stripe(p)].lock().await
    }
}

#[cfg(test)]
mod tests {
    use core::time::Duration;

    use super::*;
    use crate::repo::NamespaceKey;

    #[tokio::test]
    async fn one_partition_enters_one_at_a_time() {
        let gate = WriteGate::new();
        let p = Partition::Namespace(NamespaceKey::deployment_default());
        let held = gate.enter(&p).await;
        // Blocked while the first guard lives.
        let waited = tokio::time::timeout(Duration::from_millis(50), gate.enter(&p)).await;
        assert!(waited.is_err());
        drop(held);
        let _second = gate.enter(&p).await;
    }

    #[test]
    fn stripes_are_keyed_per_gate() {
        // Two gates key their hashers independently: over many partitions
        // their stripe choices differ somewhere.
        let (a, b) = (WriteGate::new(), WriteGate::new());
        let differs = (0..64).any(|i| {
            let p = Partition::decode(format!("n{i}\0").as_bytes()).unwrap();
            a.stripe(&p) != b.stripe(&p)
        });
        assert!(differs);
    }
}
