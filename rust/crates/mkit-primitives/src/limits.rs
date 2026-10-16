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
    /// Maximum bytes per retained evidence page.
    pub page_bytes: u64,
    /// Maximum simultaneously resident evidence pages.
    pub resident_pages: u32,
    /// Maximum checkpoint envelope bytes.
    pub checkpoint_bytes: u64,
    /// Cumulative retained evidence bytes.
    pub evidence_bytes: u64,
    /// Cumulative retained page count.
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
