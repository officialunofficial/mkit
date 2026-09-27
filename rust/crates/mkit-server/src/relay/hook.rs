//! Target-batch extension point for later index and content consumers.

use crate::rt::{BoxFuture, MaybeSend, MaybeSync};
use crate::store::{Partition, Precondition, StoreError, Write, codec::RelayV1};

/// Runs before each target apply attempt, including retries on contention or
/// shrinking a combined group to fit hook additions within the store limits.
/// Added effects must fit the batch limits and tolerate repeated delivery.
/// An error leaves this target's rows queued and does not block other targets.
pub trait RelayHook: MaybeSend + MaybeSync {
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
