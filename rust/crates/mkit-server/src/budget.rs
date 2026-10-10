//! Shared call and operation allowances for requests and checkpointed work.

use crate::StoreError;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

pub(crate) const EXHAUSTED_MESSAGE: &str = "verification slice subrequest budget exhausted";

// Preserve the existing error text and exhaustion detector while allowing
// telemetry to recognize a refusal without inspecting backend messages.
#[derive(Debug, thiserror::Error)]
#[error("{EXHAUSTED_MESSAGE}")]
pub(crate) struct BudgetExhausted;

/// A shared call counter with a fixed limit.
///
/// A [`Self::child`] draws from its parent too, so a nested slice can never
/// grant more than the enclosing allowance has left. Every refusal is
/// remembered ([`Self::refused`]) on the budget that refused and on its
/// children, so a caller classifies capacity from the ledger itself rather than
/// from where the last call happened to land.
#[derive(Debug, Clone)]
pub struct SliceBudget {
    used: Arc<AtomicU32>,
    limit: u32,
    refused: Arc<AtomicBool>,
    parent: Option<Box<SliceBudget>>,
}

impl SliceBudget {
    /// An operation allowance drawing from an enclosing call budget.
    #[must_use]
    pub fn with_parent(limit: u32, parent: Self) -> Self {
        Self {
            parent: Some(Box::new(parent)),
            ..Self::new(limit)
        }
    }

    /// Reset the local operation counter once at alarm entry.
    pub fn reset(&self) {
        self.used.store(0, Ordering::SeqCst);
    }

    /// Reserve local purge operations before dispatch. A parent refusal keeps
    /// the local reservation charged, matching checkpointed invalidation.
    #[must_use]
    pub fn charge_operations(&self, operations: u32) -> bool {
        let reserved = self
            .used
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                used.checked_add(operations)
                    .filter(|total| *total <= self.limit)
            })
            .is_ok();
        reserved
            && self
                .parent
                .as_ref()
                .is_none_or(|parent| parent.charge_many(operations).is_ok())
    }

    /// A budget of `limit` calls.
    #[must_use]
    pub fn new(limit: u32) -> Self {
        Self {
            used: Arc::new(AtomicU32::new(0)),
            limit,
            refused: Arc::new(AtomicBool::new(false)),
            parent: None,
        }
    }

    /// A slice of at most `limit` calls that also spends this budget.
    #[must_use]
    pub fn child(&self, limit: u32) -> Self {
        Self {
            used: Arc::new(AtomicU32::new(0)),
            limit,
            refused: Arc::new(AtomicBool::new(false)),
            parent: Some(Box::new(self.clone())),
        }
    }

    /// Calls charged so far.
    #[must_use]
    pub fn used(&self) -> u32 {
        self.used.load(Ordering::SeqCst)
    }

    /// The fixed limit of this budget alone.
    #[must_use]
    pub fn limit(&self) -> u32 {
        self.limit
    }

    /// Calls left, including every ancestor's allowance.
    #[must_use]
    pub fn remaining(&self) -> u32 {
        let own = self.limit.saturating_sub(self.used());
        self.parent
            .as_ref()
            .map_or(own, |parent| own.min(parent.remaining()))
    }

    /// Whether any charge was ever refused by this budget or an ancestor.
    #[must_use]
    pub fn refused(&self) -> bool {
        self.refused.load(Ordering::SeqCst)
            || self.parent.as_ref().is_some_and(|parent| parent.refused())
    }

    /// Whether this budget's own ancestors, not its own slice limit, refused.
    #[must_use]
    pub fn ancestor_refused(&self) -> bool {
        self.parent.as_ref().is_some_and(|parent| parent.refused())
    }

    /// Charge one call, failing once the limit is spent. The failing call is
    /// not counted, so an exhausted budget stays exhausted.
    ///
    /// # Errors
    /// `StoreError::Unavailable`: a spent budget is not a CAS race.
    pub fn charge(&self) -> Result<(), StoreError> {
        self.charge_many(1)
    }

    /// Reserve a combined operation before any external effect.
    /// # Errors
    /// Exhausted shared allowance, without partially charging the reservation.
    pub fn charge_many(&self, calls: u32) -> Result<(), StoreError> {
        let reserved = self
            .used
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                used.checked_add(calls).filter(|total| *total <= self.limit)
            })
            .is_ok();
        let granted = reserved
            && match &self.parent {
                Some(parent) => {
                    let granted = parent.charge_many(calls).is_ok();
                    if !granted {
                        self.used.fetch_sub(calls, Ordering::SeqCst);
                    }
                    granted
                }
                None => true,
            };
        if granted {
            return Ok(());
        }
        self.refused.store(true, Ordering::SeqCst);
        Err(StoreError::unavailable(BudgetExhausted))
    }
}

/// Whether `error` is [`SliceBudget`] running out.
#[must_use]
pub fn is_exhausted(error: &StoreError) -> bool {
    matches!(error, StoreError::Unavailable(reason) if reason.to_string().contains("subrequest budget"))
}
