//! Execution allowances for repository closure, separate from content rules.

/// Finite caller execution ceilings. Exhaustion never establishes closure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClosureLimits {
    /// Distinct reached IDs, including verified frontier stops; at most ten million.
    pub items: u64,
    /// Reference occurrences, including repeated chunk IDs.
    pub edges: u64,
    /// Maximum depth of a newly entered object; roots have depth zero.
    pub depth: u64,
    /// Cumulative canonical bytes acquired for integrity checks.
    pub decoded_bytes: u64,
    /// Maximum canonical response length.
    pub object_bytes: u64,
    /// Maximum primitive-owned memory, including outstanding response allowances.
    pub resident_bytes: u64,
    /// Cumulative retained evidence bytes.
    pub evidence_bytes: u64,
    /// Cumulative retained evidence pages.
    pub evidence_pages: u64,
    /// Maximum distinct missing IDs.
    pub missing_items: u64,
    /// Maximum membership IDs in one frontier request.
    pub membership_batch: u32,
    /// Cumulative abstract work, including bytes hashed and journal records scanned.
    pub work: u64,
}
impl ClosureLimits {
    /// Finite indexed allowances; lower values are execution policy, not content rules.
    #[must_use]
    pub const fn indexed() -> Self {
        Self {
            items: 10_000_000,
            edges: 100_000_000,
            depth: 10_000_000,
            decoded_bytes: 4 << 30,
            object_bytes: 16 << 20,
            resident_bytes: 64 << 20,
            evidence_bytes: 8 << 30,
            evidence_pages: 40_000_000,
            missing_items: 100_000,
            membership_batch: 4096,
            work: 4_000_000_000,
        }
    }
}
