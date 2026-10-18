//! Explicit finite execution limits, separate from normative content ceilings.
//!
//! Nested operations share one charged budget; copying configuration never
//! resets work. The framing implementation owns the cumulative counter.

/// Caller execution ceilings. No default means unlimited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifyLimits {
    /// Maximum bytes in one acquisition range.
    pub acquisition_bytes: u64,
    /// Peak simultaneous primitive-owned bytes, including worker scratch.
    pub resident_bytes: u64,
    /// Maximum bytes per evidence page.
    pub page_bytes: u64,
    /// Page-cache size in `page_bytes` units: the driver caches at most
    /// `page_bytes * resident_pages` bytes of pages, charged at actual sizes.
    pub resident_pages: u32,
    /// Maximum checkpoint envelope bytes.
    pub checkpoint_bytes: u64,
    /// Evidence bytes the host holds at once: pages handed to it, not released.
    pub evidence_bytes: u64,
    /// Evidence pages the host holds at once: pages handed to it, not released.
    pub evidence_pages: u64,
    /// Cumulative decoded canonical bytes.
    pub decoded_bytes: u64,
    /// Cumulative dependency edges, counting occurrences.
    pub dependency_edges: u64,
    /// Cumulative external fact lookups.
    pub external_lookups: u64,
    /// Cumulative abstract work units.
    pub work: u64,
}
impl VerifyLimits {
    /// Finite indexed execution profile. These are execution budgets, not wire caps.
    ///
    /// ```
    /// let limits = mkit_primitives::limits::VerifyLimits::indexed();
    /// assert_eq!(limits.acquisition_bytes, 1_048_576);
    /// ```
    #[must_use]
    pub const fn indexed() -> Self {
        Self {
            acquisition_bytes: 1 << 20,
            resident_bytes: 64 << 20,
            page_bytes: 1 << 20,
            resident_pages: 4,
            checkpoint_bytes: 1 << 20,
            evidence_bytes: 4 << 30,
            evidence_pages: 1_000_000,
            decoded_bytes: 4 << 30,
            dependency_edges: 10_000_000,
            external_lookups: 10_000_000,
            work: 1_000_000_000,
        }
    }
}
/// Normative indexed content ceilings, distinct from execution exhaustion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexedProfile {
    /// Advertised pack-byte ceiling.
    pub pack_bytes: u64,
    /// Configured cumulative canonical decode ceiling.
    pub decoded_bytes: u64,
    /// Advertised effective delta depth.
    pub delta_depth: u32,
}

/// Explicit finite decision output budget; no unlimited default.
///
/// The decision owner charges exact public refusal messages cumulatively before
/// guarded construction. Exhaustion is an execution failure, never truncation
/// or a new invalid-content rule. Entry points land with that owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecisionLimits {
    /// Maximum cumulative owned public refusal-message bytes.
    pub public_message_bytes: u32,
}

/// Finite limits for one evidence-codec operation and every nested page.
///
/// Proof decoding shares one work/allocation budget across the whole path.
/// Borrowed input remains host-owned; its length is still checked against the
/// appropriate input cap before parsing or hashing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvidenceLimits {
    /// Largest encoded page, including its binding and framing.
    pub page_bytes: u64,
    /// Largest value in one leaf record.
    pub value_bytes: u64,
    /// Largest encoded proof, including all embedded pages.
    pub proof_bytes: u64,
    /// Maximum root-to-leaf path length.
    pub proof_pages: u32,
    /// Cumulative parsing, copying, and hashing work units.
    pub work: u64,
    /// Cumulative bytes allocated by this operation.
    pub allocated_bytes: u64,
}

impl EvidenceLimits {
    /// Bounded codec profile for indexed evidence.
    #[must_use]
    pub const fn indexed() -> Self {
        Self {
            page_bytes: 1 << 20,
            value_bytes: 1 << 20,
            proof_bytes: 16 << 20,
            proof_pages: 16,
            work: 128 << 20,
            allocated_bytes: 4 << 20,
        }
    }
}
