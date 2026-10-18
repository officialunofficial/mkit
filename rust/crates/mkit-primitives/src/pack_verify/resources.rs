//! Shared accounting, including reservations around opaque core decoder calls.
use crate::{
    error::{BoundedDetail, Failure, FailureCode, Location},
    limits::VerifyLimits,
};

/// Cumulative work and evidence charges and simultaneous owned-memory bounds.
///
/// Resident charges include conservative reservations for core decoder scratch.
/// They are upper bounds, rather than an allocator's measurement. Host-owned
/// source and retained-page storage have a separate host budget.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResourceUsage {
    /// Current primitive-owned bytes, including outstanding reservations.
    pub resident_bytes: u64,
    /// Largest simultaneous resident charge.
    pub peak_resident_bytes: u64,
    /// Bytes of evidence pages the host holds: handed to it and not yet released.
    pub evidence_bytes: u64,
    /// Evidence pages the host holds: handed to it and not yet released.
    pub evidence_pages: u64,
    /// Cumulative charged work; replay consumes work again.
    pub work: u64,
}

#[derive(Debug)]
pub(super) struct Resources {
    limits: VerifyLimits,
    usage: ResourceUsage,
    protected_work: u64,
}

fn exhausted() -> Failure {
    Failure {
        code: FailureCode::ResourceLimit,
        location: Location::default(),
        detail: BoundedDetail::None,
    }
}

fn add(current: u64, amount: u64, ceiling: u64) -> Result<u64, Failure> {
    current
        .checked_add(amount)
        .filter(|next| *next <= ceiling)
        .ok_or_else(exhausted)
}

impl Resources {
    pub(super) fn new(limits: VerifyLimits) -> Result<Self, Failure> {
        let page_reservation = limits
            .page_bytes
            .checked_mul(u64::from(limits.resident_pages))
            .ok_or_else(exhausted)?;
        if !(64 << 10..=64 << 20).contains(&limits.acquisition_bytes)
            || !limits.acquisition_bytes.is_power_of_two()
            || limits.page_bytes == 0
            || limits.resident_pages == 0
            || limits.checkpoint_bytes == 0
            || limits.evidence_pages == 0
            || limits.evidence_bytes < limits.page_bytes
            || page_reservation > limits.resident_bytes
            || limits.work == 0
        {
            return Err(exhausted());
        }
        Ok(Self {
            limits,
            usage: ResourceUsage::default(),
            protected_work: 0,
        })
    }

    pub(super) fn resume(limits: VerifyLimits, usage: ResourceUsage) -> Result<Self, Failure> {
        let mut resources = Self::new(limits)?;
        if usage.resident_bytes > usage.peak_resident_bytes
            || usage.peak_resident_bytes > limits.resident_bytes
            || usage.evidence_bytes > limits.evidence_bytes
            || usage.evidence_pages > limits.evidence_pages
            || usage.work > limits.work
        {
            return Err(exhausted());
        }
        // Restored buffers are acquired and charged afresh. Cumulative work,
        // evidence, and the prior peak survive; cold resume cannot reset them.
        resources.usage = ResourceUsage {
            resident_bytes: 0,
            ..usage
        };
        Ok(resources)
    }

    pub(super) const fn usage(&self) -> ResourceUsage {
        self.usage
    }

    pub(super) fn reserve(&mut self, bytes: u64) -> Result<(), Failure> {
        let next = add(self.usage.resident_bytes, bytes, self.limits.resident_bytes)?;
        self.usage.resident_bytes = next;
        self.usage.peak_resident_bytes = self.usage.peak_resident_bytes.max(next);
        Ok(())
    }

    /// Resident bytes still unreserved under the ceiling.
    pub(super) const fn available(&self) -> u64 {
        self.limits
            .resident_bytes
            .saturating_sub(self.usage.resident_bytes)
    }

    pub(super) fn release(&mut self, bytes: u64) -> Result<(), Failure> {
        self.usage.resident_bytes = self
            .usage
            .resident_bytes
            .checked_sub(bytes)
            .ok_or_else(exhausted)?;
        Ok(())
    }

    /// Protect future source hashing from ordinary entry and evidence work.
    pub(super) fn protect_work(&mut self, units: u64) -> Result<(), Failure> {
        let protected = add(self.protected_work, units, self.limits.work)?;
        add(self.usage.work, protected, self.limits.work)?;
        self.protected_work = protected;
        Ok(())
    }

    pub(super) fn remaining_work(&self) -> u64 {
        self.limits.work - self.usage.work - self.protected_work
    }

    pub(super) fn work(&mut self, units: u64) -> Result<(), Failure> {
        let ceiling = self
            .limits
            .work
            .checked_sub(self.protected_work)
            .ok_or_else(exhausted)?;
        self.usage.work = add(self.usage.work, units, ceiling)?;
        Ok(())
    }

    pub(super) fn integrity_work(&mut self, units: u64) -> Result<(), Failure> {
        let protected = self
            .protected_work
            .checked_sub(units)
            .ok_or_else(exhausted)?;
        let work = add(self.usage.work, units, self.limits.work)?;
        self.protected_work = protected;
        self.usage.work = work;
        Ok(())
    }

    /// Reserve the maximum before an opaque bounded operation, then charge its
    /// measured logical units. Unused permits were never performed work.
    pub(super) fn finish_work(&mut self, reserved: u64, used: u64) -> Result<(), Failure> {
        let unused = reserved.checked_sub(used).ok_or_else(exhausted)?;
        self.usage.work = self.usage.work.checked_sub(unused).ok_or_else(exhausted)?;
        Ok(())
    }

    /// Counts a page handed to the host against the live-page ceilings.
    pub(super) fn evidence(&mut self, bytes: u64) -> Result<(), Failure> {
        let next_bytes = add(self.usage.evidence_bytes, bytes, self.limits.evidence_bytes)?;
        let next_pages = add(self.usage.evidence_pages, 1, self.limits.evidence_pages)?;
        self.usage.evidence_bytes = next_bytes;
        self.usage.evidence_pages = next_pages;
        Ok(())
    }

    /// Uncounts a page the host was told to drop.
    pub(super) fn release_evidence(&mut self, bytes: u64) -> Result<(), Failure> {
        let next_bytes = self
            .usage
            .evidence_bytes
            .checked_sub(bytes)
            .ok_or_else(exhausted)?;
        let next_pages = self
            .usage
            .evidence_pages
            .checked_sub(1)
            .ok_or_else(exhausted)?;
        self.usage.evidence_bytes = next_bytes;
        self.usage.evidence_pages = next_pages;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocation_and_work_refuse_before_state_advances() {
        let mut resources = Resources::new(VerifyLimits::indexed()).unwrap();
        resources.reserve(63 << 20).unwrap();
        let before = resources.usage();
        assert!(resources.reserve(2 << 20).is_err());
        assert_eq!(resources.usage(), before);
        resources.release(63 << 20).unwrap();
        assert_eq!(resources.usage().resident_bytes, 0);
        assert_eq!(resources.usage().peak_resident_bytes, 63 << 20);
        resources.work(100).unwrap();
        resources.finish_work(100, 7).unwrap();
        assert_eq!(resources.usage().work, 7);
        assert!(resources.work(u64::MAX).is_err());
        assert_eq!(resources.usage().work, 7);
    }

    #[test]
    fn protected_hash_work_survives_ordinary_exhaustion() {
        let mut resources = Resources::new(VerifyLimits {
            work: 100,
            ..VerifyLimits::indexed()
        })
        .unwrap();
        resources.work(10).unwrap();
        resources.protect_work(70).unwrap();
        assert_eq!(resources.remaining_work(), 20);
        let before = resources.usage();
        assert!(resources.work(21).is_err());
        assert!(resources.protect_work(21).is_err());
        assert_eq!(resources.usage(), before);
        assert_eq!(resources.remaining_work(), 20);
        resources.integrity_work(70).unwrap();
        assert_eq!(resources.usage().work, 80);
        assert_eq!(resources.remaining_work(), 20);
        assert!(resources.integrity_work(1).is_err());
        resources.work(20).unwrap();
        assert_eq!(resources.usage().work, 100);
    }

    #[test]
    fn retention_and_resume_do_not_reset_cumulative_budgets() {
        let limits = VerifyLimits {
            evidence_pages: 1,
            ..VerifyLimits::indexed()
        };
        let mut resources = Resources::new(limits).unwrap();
        resources.evidence(128).unwrap();
        resources.work(19).unwrap();
        resources.reserve(512).unwrap();
        let before = resources.usage();
        assert!(resources.evidence(1).is_err());
        assert_eq!(resources.usage(), before);
        let mut resumed = Resources::resume(limits, before).unwrap();
        assert_eq!(resumed.usage().resident_bytes, 0);
        assert_eq!(resumed.usage().peak_resident_bytes, 512);
        assert_eq!(resumed.usage().work, 19);
        assert!(resumed.evidence(1).is_err());
    }

    #[test]
    fn released_evidence_frees_the_live_page_ceiling() {
        let limits = VerifyLimits {
            evidence_pages: 2,
            ..VerifyLimits::indexed()
        };
        let mut resources = Resources::new(limits).unwrap();
        resources.evidence(100).unwrap();
        resources.evidence(50).unwrap();
        assert!(resources.evidence(1).is_err());
        resources.release_evidence(100).unwrap();
        assert_eq!(resources.usage().evidence_pages, 1);
        assert_eq!(resources.usage().evidence_bytes, 50);
        resources.evidence(7).unwrap();
        // Releasing more than was ever counted is a ledger defect.
        assert!(resources.release_evidence(1 << 20).is_err());
        assert_eq!(resources.usage().evidence_pages, 2);
    }

    #[test]
    fn impossible_geometry_and_counter_overflow_refuse() {
        for limits in [
            VerifyLimits {
                acquisition_bytes: 7,
                ..VerifyLimits::indexed()
            },
            VerifyLimits {
                page_bytes: u64::MAX,
                ..VerifyLimits::indexed()
            },
            VerifyLimits {
                resident_pages: 0,
                ..VerifyLimits::indexed()
            },
        ] {
            assert!(Resources::new(limits).is_err());
        }
        assert!(
            Resources::resume(
                VerifyLimits::indexed(),
                ResourceUsage {
                    resident_bytes: 2,
                    peak_resident_bytes: 1,
                    ..ResourceUsage::default()
                }
            )
            .is_err()
        );
    }
}
