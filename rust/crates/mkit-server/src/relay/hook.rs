//! Target-batch extension point for later index and content consumers.

use crate::rt::{BoxFuture, MaybeSend, MaybeSync};
use crate::store::{Key, Partition, Precondition, StoreError, Value, Write, codec::RelayV1};

/// Runs before each target apply attempt, including retries on contention or
/// shrinking a combined group to fit hook additions within the store limits.
/// Added effects must fit the batch limits and tolerate repeated delivery.
/// An error leaves this target's rows queued and does not block other targets.
pub trait RelayHook: MaybeSend + MaybeSync {
    /// Additional raw observations, batched with the target watermark read.
    /// The delivery engine deduplicates and bounds this declaration before IO.
    fn read_keys(
        &self,
        _target: &Partition,
        _rows: &[(u64, RelayV1)],
    ) -> Result<Vec<Key>, StoreError> {
        Ok(Vec::new())
    }

    /// Extend using the declared snapshot, without hidden IO. Older hooks
    /// retain their original callback; production content hooks override this.
    fn before_apply_observed<'a>(
        &'a self,
        target: &'a Partition,
        rows: &'a [(u64, RelayV1)],
        _observed: &'a [(Key, Option<Value>)],
        pre: &'a mut Vec<Precondition>,
        writes: &'a mut Vec<Write>,
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        self.before_apply(target, rows, pre, writes)
    }

    /// Target-local extensions may reserve operations before a remote apply.
    /// The relay shrinks groups until their base effects and this reserve fit.
    fn reserved_ops(&self, _target: &Partition, _rows: &[(u64, RelayV1)]) -> usize {
        0
    }

    /// Extend the atomic target batch, or fail delivery for this target.
    fn before_apply<'a>(
        &'a self,
        target: &'a Partition,
        rows: &'a [(u64, RelayV1)],
        pre: &'a mut Vec<Precondition>,
        writes: &'a mut Vec<Write>,
    ) -> BoxFuture<'a, Result<(), StoreError>>;
}

/// Default hook: adds nothing.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoHook;
impl RelayHook for NoHook {
    fn before_apply<'a>(
        &'a self,
        _target: &'a Partition,
        _rows: &'a [(u64, RelayV1)],
        _pre: &'a mut Vec<Precondition>,
        _writes: &'a mut Vec<Write>,
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async { Ok(()) })
    }
}
