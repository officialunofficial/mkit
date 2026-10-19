use super::{RefDecisionLimits, checks::failure, decide::push_guard};
use crate::{
    decision::{AcceptanceBasis, Guarded, RequiredGuard, WriteDecision},
    error::{Failure, FailureCode},
    evidence::PackSource,
};

impl Guarded<WriteDecision> {
    /// Attach acceptance dependencies to a plain single-ref or paired write.
    ///
    /// A host that accepts packs through its own path must call this before
    /// lowering a write that relies on that acceptance. `packs` is the complete
    /// list of newly accepted packs the write relies on, supplied by the host;
    /// ref targets alone cannot identify their containing packs. Each must be
    /// covered by at least one basis using [`AcceptanceBasis::covers`] (identity
    /// and exact length, or an explicit unrestricted host attestation).
    /// Deletions and writes relying on no new content need no basis.
    ///
    /// Every basis must belong to this decision's repository, even for replay
    /// or refusal decisions. All its guards join the sealed requirements, so
    /// [`super::check_guard_completeness`] audits them exactly as for ticketed
    /// acceptance. Exact duplicates collapse; contradictory expectations for
    /// one identity fail closed. Distinct binding digests coexist, as in the
    /// ticketed path. Decision effects and source fences are retained verbatim.
    ///
    /// This consuming method keeps the frozen request constructors unchanged
    /// and prevents effects from being separated from their added guards.
    /// Empty `bases` and `packs` return the original decision unchanged.
    /// `limits` bounds this attachment's input facts, fixed-size guard bytes and
    /// comparison work, and the total resulting guard count; acquisition and
    /// the original decision have their own allowances.
    ///
    /// ```
    /// use mkit_primitives::{
    ///     decision::{AcceptanceBasis, Guarded, WriteDecision, ref_write::RefDecisionLimits},
    ///     error::Failure,
    ///     evidence::PackSource,
    /// };
    /// fn attach(
    ///     decision: Guarded<WriteDecision>, basis: &AcceptanceBasis,
    ///     pack: PackSource, limits: RefDecisionLimits,
    /// ) -> Result<Guarded<WriteDecision>, Failure> {
    ///     decision.with_acceptance_basis(std::slice::from_ref(basis), &[pack], limits)
    /// }
    /// ```
    ///
    /// # Errors
    /// `InvalidResponse` for another repository, an uncovered pack, or
    /// contradictory guards; `ResourceLimit` for an exhausted allowance.
    pub fn with_acceptance_basis(
        mut self,
        bases: &[AcceptanceBasis],
        packs: &[PackSource],
        limits: RefDecisionLimits,
    ) -> Result<Self, Failure> {
        if bases.is_empty() && packs.is_empty() {
            return Ok(self);
        }
        let resource = || failure(FailureCode::ResourceLimit);
        let mut facts = bases.len().checked_add(packs.len()).ok_or_else(resource)?;
        if facts > limits.facts as usize {
            return Err(resource());
        }
        let mut guard_count = 0usize;
        let mut pack_count = packs.len();
        for basis in bases {
            pack_count = pack_count
                .checked_add(basis.pack_count())
                .ok_or_else(resource)?;
            guard_count = guard_count
                .checked_add(basis.guards().len())
                .ok_or_else(resource)?;
        }
        facts = facts
            .checked_add(guard_count)
            .and_then(|n| n.checked_add(pack_count))
            .ok_or_else(resource)?;
        let comparisons = facts
            .checked_add(self.required.len())
            .ok_or_else(resource)?;
        let work = comparisons
            .checked_mul(comparisons)
            .and_then(|n| n.checked_mul(8));
        // Basis guards contain only fixed-size witness, version, binding and
        // member facts. Charge their full enum size before cloning any of them.
        let bytes = guard_count
            .checked_mul(std::mem::size_of::<RequiredGuard>())
            .and_then(|n| {
                pack_count
                    .checked_mul(std::mem::size_of::<PackSource>())
                    .and_then(|packs| n.checked_add(packs))
            });
        if facts > limits.facts as usize
            || work.is_none_or(|n| n as u64 > limits.work)
            || bytes.is_none_or(|n| n as u64 > limits.bytes)
            || self.required.len() > limits.guards as usize
        {
            return Err(resource());
        }
        if bases
            .iter()
            .any(|basis| basis.repository() != self.repository)
            || packs
                .iter()
                .any(|pack| !bases.iter().any(|basis| basis.covers(&pack.id, pack.len)))
        {
            return Err(failure(FailureCode::InvalidResponse));
        }
        for basis in bases {
            for guard in basis.guards() {
                push_guard(&mut self.required, limits.guards, guard.clone())?;
            }
        }
        Ok(self)
    }
}
