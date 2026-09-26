//! The optional in-process write gate ([`super::Pipeline::with_write_gate`]).

use core::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;

use futures_util::lock::{Mutex, MutexGuard};

use crate::store::Partition;

/// Lock stripes: partitions that hash alike share one.
const STRIPES: usize = 64;

/// Serializes the read-plan-apply loops of one partition within this
/// process, the way a Durable Object's input gate serializes them on
/// Workers. Writes that share a key (a signer's quota window) then never
/// race each other into [`super::plan::MAX_REPLAN`] re-plans.
pub(super) struct WriteGate {
    stripes: Vec<Mutex<()>>,
}

impl WriteGate {
    pub(super) fn new() -> Self {
        Self {
            stripes: (0..STRIPES).map(|_| Mutex::new(())).collect(),
        }
    }

    /// Wait for `p`'s stripe.
    pub(super) async fn enter(&self, p: &Partition) -> MutexGuard<'_, ()> {
        let mut h = DefaultHasher::new();
        p.hash(&mut h);
        // Truncation is fine: only the stripe index matters.
        #[allow(clippy::cast_possible_truncation)]
        let i = h.finish() as usize % self.stripes.len();
        self.stripes[i].lock().await
    }
}

#[cfg(test)]
mod tests {
    use futures_executor::block_on;
    use futures_util::FutureExt as _;

    use super::*;
    use crate::repo::NamespaceKey;

    #[test]
    fn one_partition_enters_one_at_a_time() {
        let gate = WriteGate::new();
        let p = Partition::Namespace(NamespaceKey::deployment_default());
        block_on(async {
            let held = gate.enter(&p).await;
            let mut second = core::pin::pin!(gate.enter(&p));
            // Pending while the first guard lives.
            assert!(second.as_mut().now_or_never().is_none());
            drop(held);
            assert!(second.as_mut().now_or_never().is_some());
        });
    }
}
