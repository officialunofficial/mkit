//! One typed call allowance for a publication request (SPEC-SERVER §10.2).
//!
//! Preparation, dependency visibility and every final-denial retry draw from
//! the same ledger. Nested slices are children of it, never extra allowance.
//! The proof share stops short of the request's whole allowance so that the
//! snapshot reads, lease check, checkpoint and final commit still fit.
use crate::ServerError;
use crate::indexed::budget::SliceBudget;

/// The Workers request allowance this ledger is a share of.
pub(crate) const REQUEST_CALLS: u32 = 9_000;
/// Calls kept back for snapshot, authority and lease reads, the checkpoint
/// write and the final commit, which are not proof work.
pub(crate) const SETTLEMENT_RESERVE: u32 = 64;
/// Pair verification's own slice of the proof share.
pub(crate) const VERIFY_SLICE_CALLS: u32 = 256;

/// The request-local publication ledger.
#[derive(Debug, Clone)]
pub(crate) struct PublicationBudget {
    proof: SliceBudget,
}

impl PublicationBudget {
    pub(crate) fn new() -> Self {
        #[cfg(test)]
        let budget = Self::with_request_calls(tests::OVERRIDE.get().unwrap_or(REQUEST_CALLS));
        #[cfg(not(test))]
        let budget = Self::with_request_calls(REQUEST_CALLS);
        #[cfg(test)]
        tests::LAST.with(|last| *last.borrow_mut() = Some(budget.clone()));
        budget
    }

    pub(crate) fn with_request_calls(request: u32) -> Self {
        Self {
            proof: SliceBudget::new(request.saturating_sub(SETTLEMENT_RESERVE)),
        }
    }

    /// The proof share every phase of this request draws from.
    pub(crate) fn proof(&self) -> &SliceBudget {
        &self.proof
    }

    /// Pair verification's slice: a child of the proof share.
    pub(crate) fn verify_slice(&self) -> SliceBudget {
        self.proof.child(VERIFY_SLICE_CALLS)
    }

    /// Execution capacity ran out; the content was never judged invalid.
    pub(crate) fn capacity_error() -> ServerError {
        ServerError::unavailable("publication verification capacity exhausted")
    }

    /// Classify a failed phase by the ledger, not by the error's shape or by
    /// where the last call landed. A refused charge means the evidence is
    /// incomplete, so any verdict that is not a positive denial is capacity.
    pub(crate) fn settle<T>(
        budget: &SliceBudget,
        result: Result<T, ServerError>,
    ) -> Result<T, ServerError> {
        match result {
            Err(error) if budget.refused() && error.code() != crate::Code::PermissionDenied => {
                Err(Self::capacity_error())
            }
            other => other,
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    thread_local! {
        /// Request allowance for the next ledgers built on this thread.
        pub(crate) static OVERRIDE: Cell<Option<u32>> = const { Cell::new(None) };
        /// The most recently built ledger, to read what a request spent.
        pub(crate) static LAST: RefCell<Option<PublicationBudget>> = const { RefCell::new(None) };
    }

    #[test]
    fn proof_share_reserves_settlement_headroom() {
        let budget = PublicationBudget::with_request_calls(REQUEST_CALLS);
        assert_eq!(budget.proof().limit(), REQUEST_CALLS - SETTLEMENT_RESERVE);
        let verify = budget.verify_slice();
        assert_eq!(verify.limit(), VERIFY_SLICE_CALLS);
        // A slice never grants more than the whole share has left.
        for _ in 0..VERIFY_SLICE_CALLS {
            verify.charge().unwrap();
        }
        assert!(verify.charge().is_err());
        assert_eq!(budget.proof().used(), VERIFY_SLICE_CALLS);
        assert!(verify.refused() && !budget.proof().refused());
        assert_eq!(PublicationBudget::with_request_calls(10).proof().limit(), 0);
    }

    #[test]
    fn settle_reads_the_ledger_not_the_error_shape() {
        let budget = SliceBudget::new(1);
        let closed = || Err::<(), _>(ServerError::invalid_argument("open closure"));
        // A genuine verdict with no refused charge is unchanged.
        let kept = PublicationBudget::settle(&budget, closed()).unwrap_err();
        assert_eq!(kept.public_message(), "open closure");
        budget.charge().unwrap();
        assert!(budget.charge().is_err());
        // After a refusal even a lossy `open closure` is only capacity.
        let capacity = PublicationBudget::settle(&budget, closed()).unwrap_err();
        assert_eq!(capacity.code(), crate::Code::Unavailable);
        // A positive denial stays a denial.
        let denied = PublicationBudget::settle(
            &budget,
            Err::<(), _>(ServerError::permission_denied("object blocked")),
        )
        .unwrap_err();
        assert_eq!(denied.code(), crate::Code::PermissionDenied);
    }
}
