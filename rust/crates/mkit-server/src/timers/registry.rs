//! Timer kind allocations and startup handler registration.

use super::{DueTimer, Fired, TimerCtx};
use crate::rt::{BoxFuture, MaybeSend, MaybeSync};
use crate::store::{NamespaceStore, StoreError};
use std::collections::BTreeMap;

/// A timer's stable codec and handler identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TimerKind(u8);
impl TimerKind {
    /// Wrap a kind number. Zero cannot be registered.
    #[must_use]
    pub const fn new(kind: u8) -> Self {
        Self(kind)
    }
    /// The encoded number.
    #[must_use]
    pub fn get(self) -> u8 {
        self.0
    }
}

/// Kind allocations. A new kind takes the next free number; numbers are never reused.
///
/// | Numbers | Allocation |
/// |---|---|
/// | 0 | Invalid |
/// | 1..=0xEF | Production, currently unallocated |
/// | 0xF0..=0xFE | Reserved for tests |
/// | 0xFF | TEST (`test-faults` only) |
pub mod kinds {
    /// Ref deletion used only by test drivers and directives.
    #[cfg(feature = "test-faults")]
    pub const TEST: super::TimerKind = super::TimerKind::new(0xFF);
}

/// Handles a due timer in its own partition.
///
/// `fire` may run more than once for the same timer. Every effect outside
/// the returned batch MUST be idempotent. Effects inside the batch are
/// applied at most once per timer row (guarded by the row's original value).
/// Allow room for the core's precondition and delete, plus a reschedule Put,
/// within the store's batch limits. Cross-partition effects require an outbox.
pub trait TimerHandler<S: NamespaceStore>: MaybeSend + MaybeSync {
    /// The kind this handler decodes.
    fn kind(&self) -> TimerKind;
    /// Overrides `TickBudget::max_per_kind` for this kind.
    fn max_per_tick(&self) -> Option<u32> {
        None
    }
    /// Prepare effects; the core atomically guards and removes the timer.
    fn fire<'a>(
        &'a self,
        ctx: &'a TimerCtx<'a, S>,
        timer: &'a DueTimer,
    ) -> BoxFuture<'a, Result<Fired, StoreError>>;
}

/// Handlers registered once at driver startup, indexed by stable kind number.
pub struct TimerRegistry<S> {
    handlers: BTreeMap<TimerKind, Box<dyn TimerHandler<S>>>,
}
impl<S: NamespaceStore> TimerRegistry<S> {
    /// An empty registry; unknown kinds remain stored for newer binaries.
    #[must_use]
    pub fn new() -> Self {
        Self {
            handlers: BTreeMap::new(),
        }
    }
    /// Register a handler.
    ///
    /// # Panics
    /// If its kind is already registered or is zero (a startup programming error).
    #[must_use]
    pub fn register(mut self, handler: impl TimerHandler<S> + 'static) -> Self {
        let kind = handler.kind();
        assert_ne!(kind.get(), 0, "timer kind zero is invalid");
        assert!(
            !self.handlers.contains_key(&kind),
            "timer kind already registered"
        );
        self.handlers.insert(kind, Box::new(handler));
        self
    }
    pub(super) fn get(&self, kind: TimerKind) -> Option<&dyn TimerHandler<S>> {
        self.handlers.get(&kind).map(Box::as_ref)
    }
}
impl<S: NamespaceStore> Default for TimerRegistry<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> core::fmt::Debug for TimerRegistry<S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TimerRegistry")
            .field("kinds", &self.handlers.keys().collect::<Vec<_>>())
            .finish()
    }
}
