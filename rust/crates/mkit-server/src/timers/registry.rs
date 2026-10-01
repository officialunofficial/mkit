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

/// Kind allocations. A new kind takes the next free number; shipped kinds are never reused.
/// R-190 allocates kind 15 to checkpointed takedown and preservation work.
///
/// | Numbers | Allocation |
/// |---|---|
/// | 0 | Invalid |
/// | 1 | LEASE_SWEEP (WP-1.25) |
/// | 2 | TICKET_EXPIRY (handler added in WP-1.14) |
/// | 3 | RELAY (WP-1.23a) |
/// | 4 | BACKUP (Worker only, WP-1.29b) |
/// | 5 | QUOTA_ROLLUP (WP-1.26a) |
/// | 6 | Reserved |
/// | 7 | VERIFY (scheduled indexed verification, WP-4.8) |
/// | 8 | OUTCOME_DELIVERY (WP-3.3) |
/// | 9 | RESERVATION_RECONCILE (WP-3.3) |
/// | 10 | PUBLISHED_VIEW (Worker only, WP-1.21) |
/// | 11 | CACHE_PURGE (WP-5.10) |
/// | 12 | PUBLICATION_RECHECK (WP-5.4, R-182) |
/// | 13 | CONTENT_TAKEDOWN_REQUEST (WP-4.10b, R-186) |
/// | 14 | INSPECTION (reserved for WP-5.5a, R-198) |
/// | 15 | TAKEDOWN_WORK (WP-5.6a, R-190) |
/// | 16..=0xEF | Production, unallocated |
/// | 0xF0..=0xFE | Reserved for tests |
/// | 0xFF | TEST (`test-faults` only) |
pub mod kinds {
    /// Expired coordinator epoch-lease table rows.
    pub const LEASE_SWEEP: super::TimerKind = super::TimerKind::new(1);
    /// Ticket expiry.
    pub const TICKET_EXPIRY: super::TimerKind = super::TimerKind::new(2);
    /// Source-side outbox delivery.
    pub const RELAY: super::TimerKind = super::TimerKind::new(3);
    /// Per-partition Worker snapshot export.
    pub const BACKUP: super::TimerKind = super::TimerKind::new(4);
    /// Ref-shard namespace quota reconciliation.
    pub const QUOTA_ROLLUP: super::TimerKind = super::TimerKind::new(5);
    /// Checkpointed slices of a ticketed pack's scheduled verification.
    pub const VERIFY: super::TimerKind = super::TimerKind::new(7);
    /// Deliver durable terminal outcomes.
    pub const OUTCOME_DELIVERY: super::TimerKind = super::TimerKind::new(8);
    /// Settle abandoned pending reservations.
    pub const RESERVATION_RECONCILE: super::TimerKind = super::TimerKind::new(9);
    /// Published ref-index snapshots (explicit Worker opt-in only).
    pub const PUBLISHED_VIEW: super::TimerKind = super::TimerKind::new(10);
    /// Materialize a durable late-holder takedown handoff; not takedown completion.
    pub const CONTENT_TAKEDOWN_REQUEST: super::TimerKind = super::TimerKind::new(13);
    /// Durable local and shared cache purge.
    pub const CACHE_PURGE: super::TimerKind = super::TimerKind::new(11);
    /// Retained inspection and published-membership dependency clearance.
    pub const PUBLICATION_RECHECK: super::TimerKind = super::TimerKind::new(12);
    /// Preservation acquisition, holder discovery and audited retention purge.
    pub const TAKEDOWN_WORK: super::TimerKind = super::TimerKind::new(15);
    /// Ref deletion used only by test drivers and directives.
    #[cfg(feature = "test-faults")]
    pub const TEST: super::TimerKind = super::TimerKind::new(0xFF);
}

/// Handles a due timer in its own partition.
///
/// `fire` may run more than once for the same timer. Every effect outside
/// the returned batch MUST be idempotent. Effects inside the batch are
/// applied at most once per timer row (guarded by the row's original value).
/// Allow room for the core's Equals/Delete and a reschedule Absent/Put
/// within the store's batch limits. Cross-partition effects require an outbox.
pub trait TimerHandler<S: NamespaceStore>: MaybeSend + MaybeSync {
    /// The kind this handler decodes.
    fn kind(&self) -> TimerKind;
    /// Lowers the shared `TickBudget::max_per_kind` allowance for this kind.
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
pub struct TimerRegistry<'a, S> {
    handlers: BTreeMap<TimerKind, Box<dyn TimerHandler<S> + 'a>>,
}
impl<'a, S: NamespaceStore> TimerRegistry<'a, S> {
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
    pub fn register(mut self, handler: impl TimerHandler<S> + 'a) -> Self {
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
impl<S: NamespaceStore> Default for TimerRegistry<'_, S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> core::fmt::Debug for TimerRegistry<'_, S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TimerRegistry")
            .field("kinds", &self.handlers.keys().collect::<Vec<_>>())
            .finish()
    }
}
