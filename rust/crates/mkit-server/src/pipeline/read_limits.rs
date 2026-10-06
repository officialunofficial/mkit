//! Accounting shared by additive object-reader sessions.
use super::object_reader::OBJECT_READER_CALLS;
use crate::http_objects::resolve::Budget;
use crate::indexed::budget::{EncodedBudget, SliceBudget};
use std::sync::atomic::Ordering;

/// Aggregate allowances for calls sharing one [`ReaderSession`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ReadLimits {
    /// Storage and authorization call units. Ranged blob reads are charged two
    /// units each, conservatively: the Workers adapter issues one backend call
    /// for a bounded range, and an adapter without that shortcut issues two.
    pub storage_calls: u32,
    /// Canonical bytes decoded, including proof ancestors and delta bases.
    pub decoded_bytes: u64,
    /// Encoded pack-range bytes reserved before I/O, including repeated reads.
    pub encoded_bytes: u64,
    /// Canonical output bytes; duplicate outputs count individually.
    pub output_bytes: u64,
}
impl ReadLimits {
    /// Construct explicit aggregate allowances. Zero allows no work in that dimension.
    #[must_use]
    pub const fn new(
        storage_calls: u32,
        decoded_bytes: u64,
        encoded_bytes: u64,
        output_bytes: u64,
    ) -> Self {
        Self {
            storage_calls,
            decoded_bytes,
            encoded_bytes,
            output_bytes,
        }
    }
}
impl Default for ReadLimits {
    fn default() -> Self {
        Self::new(OBJECT_READER_CALLS, 256 << 20, u64::MAX, 256 << 20)
    }
}
/// A ledger for sequential reader calls, retained even after a failed call.
/// Metadata calls charge proof work but emit no canonical output bytes.
/// Existing per-call HTTP allowances and embedder-supplied `SliceBudget`s
/// still apply. Create one session per request, and retain the same reader for
/// its sequential batches. Roots are captured during session initialization
/// (the first batch needing proof), not at an atomic repository-wide timestamp.
/// For general-ID reads, start a new session to observe commits before proof
/// expiry. Selected-ref history/path helpers instead capture a fresh selected
/// ref on every operation, replacing proofs without refunding allowances or
/// extending the request deadline. Proofs expire
/// after the configured reachability lag; the next batch captures fresh roots
/// without resetting allowances or the request deadline.
///
/// The request deadline defaults to `HttpObjectsConfig::read_deadline` from the
/// first batch, or the earlier explicit [`Self::with_deadline`] value. Expiry
/// never slides on hits. Reusing a session with another reader or verified
/// credential resets only proofs, never budgets or the request deadline.
/// Authorization, membership and takedown decisions remain live on every batch.
#[derive(Debug)]
#[non_exhaustive]
pub struct ReaderSession {
    pub(crate) io: IoLedger,
    pub(crate) proofs: super::read_proofs::ReadProofs,
    limits: ReadLimits,
    decoded: u64,
    output: OutputBudget,
}
impl ReaderSession {
    /// Start an empty ledger with explicit limits.
    #[must_use]
    pub fn new(limits: ReadLimits) -> Self {
        Self {
            io: IoLedger {
                calls: SliceBudget::new(limits.storage_calls),
                encoded: EncodedBudget::new(limits.encoded_bytes),
            },
            proofs: super::read_proofs::ReadProofs::default(),
            limits,
            decoded: 0,
            output: OutputBudget {
                used: 0,
                limit: limits.output_bytes,
            },
        }
    }
    /// Start a session with an absolute deadline in the pipeline clock's Unix
    /// milliseconds. Proof hits never extend this deadline or reachability lag.
    #[must_use]
    pub fn with_deadline(limits: ReadLimits, deadline_ms: u64) -> Self {
        Self {
            proofs: super::read_proofs::ReadProofs::with_deadline(deadline_ms),
            ..Self::new(limits)
        }
    }
    /// Snapshot consumed allowances; encoded reservations include failed I/O.
    #[must_use]
    pub fn used(&self) -> ReadLimits {
        ReadLimits::new(
            self.io.calls.used(),
            self.decoded,
            self.io.encoded.used.load(Ordering::SeqCst),
            self.output.used,
        )
    }
    pub(crate) fn split_with_proofs(
        &mut self,
        per_call: u64,
    ) -> (
        &IoLedger,
        DecodeCharge<'_>,
        &mut OutputBudget,
        &mut super::read_proofs::ReadProofs,
    ) {
        let initial = per_call.min(self.limits.decoded_bytes.saturating_sub(self.decoded));
        (
            &self.io,
            DecodeCharge {
                budget: Budget(initial),
                initial,
                used: &mut self.decoded,
            },
            &mut self.output,
            &mut self.proofs,
        )
    }
    #[cfg(test)]
    pub(crate) fn split(
        &mut self,
        per_call: u64,
    ) -> (&IoLedger, DecodeCharge<'_>, &mut OutputBudget) {
        let (io, charge, output, _) = self.split_with_proofs(per_call);
        (io, charge, output)
    }
}
impl Default for ReaderSession {
    fn default() -> Self {
        Self::new(ReadLimits::default())
    }
}
#[derive(Debug)]
pub(crate) struct IoLedger {
    pub calls: SliceBudget,
    pub encoded: EncodedBudget,
}
#[derive(Debug)]
pub(crate) struct OutputBudget {
    pub used: u64,
    limit: u64,
}
impl OutputBudget {
    pub(crate) fn remaining(&self) -> u64 {
        self.limit.saturating_sub(self.used)
    }
}
// Settles decoded work on failure and cancellation as well as success.
pub(crate) struct DecodeCharge<'a> {
    pub budget: Budget,
    initial: u64,
    used: &'a mut u64,
}
impl Drop for DecodeCharge<'_> {
    fn drop(&mut self) {
        *self.used = self
            .used
            .saturating_add(self.initial.saturating_sub(self.budget.0));
    }
}
