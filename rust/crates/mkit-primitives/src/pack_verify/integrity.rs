//! First-pass integrity with explicit completed-subtree checkpoints.
use super::ByteRange;
use crate::{
    codec::failure,
    error::{Failure, FailureCode},
    evidence::PackSource,
};
use mkit_core::{
    hash::{Hash, Hasher},
    pack::{MAX_ENTRIES, MAX_TOTAL_PAYLOAD},
    upload_parts::{MIN_PART_SIZE, PartHasher, PartPlan, merge_to_root},
};

pub(super) const SUBTREE_BYTES: u64 = MIN_PART_SIZE;
pub(super) const MAX_PACK_BYTES: u64 = MAX_TOTAL_PAYLOAD + MAX_ENTRIES as u64 * 5 + 44;
const MAX_SUBTREES: u32 = 518;

fn invalid() -> Failure {
    failure(FailureCode::InvalidCheckpoint)
}
fn resource() -> Failure {
    failure(FailureCode::ResourceLimit)
}

#[derive(Debug)]
struct HashStream {
    total: u64,
    seen: u64,
    small: Option<Hasher>,
    plan: Option<PartPlan>,
    active: Option<PartHasher>,
    cvs: Vec<Hash>,
    root: Option<Hash>,
}

impl HashStream {
    fn new(total: u64) -> Result<Self, Failure> {
        Self::resume(total, 0, Vec::new(), None)
    }

    fn resume(
        total: u64,
        seen: u64,
        mut cvs: Vec<Hash>,
        root: Option<Hash>,
    ) -> Result<Self, Failure> {
        if total == 0 || total > MAX_PACK_BYTES || seen > total {
            return Err(invalid());
        }
        if total <= SUBTREE_BYTES {
            if !cvs.is_empty()
                || !((seen == 0 && root.is_none()) || (seen == total && root.is_some()))
            {
                return Err(invalid());
            }
            return Ok(Self {
                total,
                seen,
                small: if seen == 0 { Some(Hasher::new()) } else { None },
                plan: None,
                active: None,
                cvs,
                root,
            });
        }
        let plan = PartPlan::new(total, SUBTREE_BYTES, MAX_SUBTREES).map_err(|_| invalid())?;
        let completed = if seen == total {
            u64::from(plan.count())
        } else {
            seen / SUBTREE_BYTES
        };
        if (seen != total && !seen.is_multiple_of(SUBTREE_BYTES))
            || u64::try_from(cvs.len()).map_err(|_| resource())? != completed
            || root.is_some() != (seen == total)
        {
            return Err(invalid());
        }
        if let Some(expected) = root
            && merge_to_root(&plan, &cvs).map_err(|_| invalid())? != expected
        {
            return Err(invalid());
        }
        let count = usize::try_from(plan.count()).map_err(|_| resource())?;
        cvs.try_reserve_exact(count.checked_sub(cvs.len()).ok_or_else(invalid)?)
            .map_err(|_| resource())?;
        let active = if seen == total {
            None
        } else {
            Some(
                PartHasher::new(&plan, u32::try_from(completed).map_err(|_| invalid())?)
                    .map_err(|_| invalid())?,
            )
        };
        Ok(Self {
            total,
            seen,
            small: None,
            plan: Some(plan),
            active,
            cvs,
            root,
        })
    }

    fn update(&mut self, bytes: &[u8]) -> Result<(), Failure> {
        let len = u64::try_from(bytes.len()).map_err(|_| resource())?;
        let end = self
            .seen
            .checked_add(len)
            .filter(|end| *end <= self.total)
            .ok_or_else(invalid)?;
        if let Some(hasher) = &mut self.small {
            hasher.update(bytes);
            if end == self.total {
                self.root = Some(hasher.finalize());
                self.small = None;
            }
        } else if let Some(plan) = self.plan {
            let active = self.active.as_mut().ok_or_else(invalid)?;
            active.update(bytes).map_err(|_| invalid())?;
            if end.is_multiple_of(SUBTREE_BYTES) || end == self.total {
                let cv = self
                    .active
                    .take()
                    .ok_or_else(invalid)?
                    .finalize()
                    .map_err(|_| invalid())?;
                // Capacity was fallibly admitted at construction, before any bytes.
                self.cvs.push(cv);
                if end == self.total {
                    self.root = Some(merge_to_root(&plan, &self.cvs).map_err(|_| invalid())?);
                } else {
                    self.active = Some(
                        PartHasher::new(
                            &plan,
                            u32::try_from(self.cvs.len()).map_err(|_| resource())?,
                        )
                        .map_err(|_| invalid())?,
                    );
                }
            }
        } else if len != 0 {
            return Err(invalid());
        }
        self.seen = end;
        Ok(())
    }

    fn ready(&self) -> bool {
        self.root.is_some() || self.seen.is_multiple_of(SUBTREE_BYTES)
    }
}

/// Borrowed safe-boundary state; no decoder or hasher internals are encoded.
#[derive(Debug, Clone, Copy)]
pub(super) struct IntegrityFrontier<'a> {
    pub offset: u64,
    pub whole_cvs: &'a [Hash],
    pub trailer_cvs: &'a [Hash],
    pub whole_root: Option<Hash>,
    pub trailer_root: Option<Hash>,
    pub trailer: Hash,
    pub trailer_used: u8,
}

#[derive(Debug)]
pub(super) struct RestoredIntegrity {
    pub offset: u64,
    pub whole_cvs: Vec<Hash>,
    pub trailer_cvs: Vec<Hash>,
    pub whole_root: Option<Hash>,
    pub trailer_root: Option<Hash>,
    pub trailer: Hash,
    pub trailer_used: u8,
}

#[derive(Debug)]
pub(super) struct IntegrityPass {
    source: PackSource,
    position: u64,
    whole: HashStream,
    preceding: HashStream,
    trailer: Hash,
    trailer_used: u8,
}

impl IntegrityPass {
    pub(super) fn reservation(len: u64) -> Result<u64, Failure> {
        if !(44..=MAX_PACK_BYTES).contains(&len) {
            return Err(invalid());
        }
        let cvs = [len, len - 32].into_iter().try_fold(0_u64, |sum, total| {
            let count = if total > SUBTREE_BYTES {
                total.div_ceil(SUBTREE_BYTES)
            } else {
                0
            };
            sum.checked_add(count.checked_mul(32).ok_or_else(resource)?)
                .ok_or_else(resource)
        })?;
        cvs.checked_add(u64::try_from(std::mem::size_of::<Self>()).map_err(|_| resource())?)
            .ok_or_else(resource)
    }

    pub(super) fn new(source: PackSource) -> Result<Self, Failure> {
        if !(44..=MAX_PACK_BYTES).contains(&source.len) {
            return Err(invalid());
        }
        Ok(Self {
            source,
            position: 0,
            whole: HashStream::new(source.len)?,
            preceding: HashStream::new(source.len - 32)?,
            trailer: [0; 32],
            trailer_used: 0,
        })
    }

    pub(super) fn resume(source: PackSource, restored: RestoredIntegrity) -> Result<Self, Failure> {
        let RestoredIntegrity {
            offset,
            whole_cvs,
            trailer_cvs,
            whole_root,
            trailer_root,
            trailer,
            trailer_used,
        } = restored;
        if !(44..=MAX_PACK_BYTES).contains(&source.len)
            || offset > source.len
            || (offset != source.len && !offset.is_multiple_of(SUBTREE_BYTES))
            || u64::from(trailer_used) != offset.saturating_sub(source.len - 32)
            || trailer
                .get(usize::from(trailer_used)..)
                .is_none_or(|tail| tail.iter().any(|byte| *byte != 0))
        {
            return Err(invalid());
        }
        Ok(Self {
            source,
            position: offset,
            whole: HashStream::resume(source.len, offset, whole_cvs, whole_root)?,
            preceding: HashStream::resume(
                source.len - 32,
                offset.min(source.len - 32),
                trailer_cvs,
                trailer_root,
            )?,
            trailer,
            trailer_used,
        })
    }

    pub(super) fn next(&self, acquisition: u64) -> Option<ByteRange> {
        let remaining = self.source.len.checked_sub(self.position)?;
        if remaining == 0 {
            return None;
        }
        Some(ByteRange {
            offset: self.position,
            len: remaining
                .min(acquisition)
                .min(SUBTREE_BYTES - self.position % SUBTREE_BYTES),
        })
    }

    pub(super) fn feed(&mut self, offset: u64, bytes: &[u8]) -> Result<(), Failure> {
        let len = u64::try_from(bytes.len()).map_err(|_| resource())?;
        if offset != self.position
            || len == 0
            || len > SUBTREE_BYTES - offset % SUBTREE_BYTES
            || offset
                .checked_add(len)
                .is_none_or(|end| end > self.source.len)
        {
            return Err(failure(FailureCode::InvalidResponse));
        }
        let before_trailer = (self.source.len - 32).saturating_sub(offset).min(len);
        let prefix_len = usize::try_from(before_trailer).map_err(|_| resource())?;
        self.whole.update(bytes)?;
        if before_trailer > 0 {
            self.preceding.update(&bytes[..prefix_len])?;
        }
        let tail = &bytes[prefix_len..];
        let begin = usize::from(self.trailer_used);
        let end = begin.checked_add(tail.len()).ok_or_else(invalid)?;
        self.trailer
            .get_mut(begin..end)
            .ok_or_else(invalid)?
            .copy_from_slice(tail);
        self.trailer_used = u8::try_from(end).map_err(|_| invalid())?;
        self.position = offset.checked_add(len).ok_or_else(invalid)?;
        Ok(())
    }

    pub(super) fn frontier(&self) -> Option<IntegrityFrontier<'_>> {
        if !self.whole.ready() || !self.preceding.ready() {
            return None;
        }
        Some(IntegrityFrontier {
            offset: self.position,
            whole_cvs: &self.whole.cvs,
            trailer_cvs: &self.preceding.cvs,
            whole_root: self.whole.root,
            trailer_root: self.preceding.root,
            trailer: self.trailer,
            trailer_used: self.trailer_used,
        })
    }

    pub(super) fn verify(&self) -> Result<Hash, Failure> {
        if self.position != self.source.len
            || self.trailer_used != 32
            || self.preceding.root != Some(self.trailer)
            || self.whole.root != Some(self.source.id)
        {
            return Err(failure(FailureCode::PackfileCorrupted));
        }
        Ok(self.trailer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::SourceBinding;
    use mkit_core::hash;

    fn source(bytes: &[u8]) -> PackSource {
        PackSource {
            id: hash::hash(bytes),
            len: u64::try_from(bytes.len()).unwrap(),
            binding: SourceBinding([7; 32]),
        }
    }

    #[test]
    fn both_trees_match_ordinary_blake3_across_subtree_and_trailer_boundaries() {
        for len in [
            44, 1_048_589, 8_388_608, 8_388_609, 8_388_639, 8_388_640, 8_388_641, 16_777_233,
        ] {
            let mut bytes = vec![3; len];
            let trailer = hash::hash(&bytes[..len - 32]);
            bytes[len - 32..].copy_from_slice(&trailer);
            let mut pass = IntegrityPass::new(source(&bytes)).unwrap();
            while let Some(range) = pass.next(1 << 20) {
                let begin = usize::try_from(range.offset).unwrap();
                let end = begin + usize::try_from(range.len).unwrap();
                pass.feed(range.offset, &bytes[begin..end]).unwrap();
                if let Some(frontier) = pass.frontier() {
                    pass = IntegrityPass::resume(
                        source(&bytes),
                        RestoredIntegrity {
                            offset: frontier.offset,
                            whole_cvs: frontier.whole_cvs.to_vec(),
                            trailer_cvs: frontier.trailer_cvs.to_vec(),
                            whole_root: frontier.whole_root,
                            trailer_root: frontier.trailer_root,
                            trailer: frontier.trailer,
                            trailer_used: frontier.trailer_used,
                        },
                    )
                    .unwrap();
                }
            }
            assert_eq!(pass.verify().unwrap(), trailer);
            assert!(IntegrityPass::reservation(u64::try_from(len).unwrap()).unwrap() < 64 << 10);
        }
    }

    fn empty_restore() -> RestoredIntegrity {
        RestoredIntegrity {
            offset: 0,
            whole_cvs: Vec::new(),
            trailer_cvs: Vec::new(),
            whole_root: None,
            trailer_root: None,
            trailer: [0; 32],
            trailer_used: 0,
        }
    }

    #[test]
    fn wrong_identity_mutation_and_inconsistent_resume_never_complete() {
        let mut bytes = [0; 44];
        let trailer = hash::hash(&bytes[..12]);
        bytes[12..].copy_from_slice(&trailer);
        let expected = source(&bytes);
        bytes[0] = 1;
        let mut pass = IntegrityPass::new(expected).unwrap();
        pass.feed(0, &bytes).unwrap();
        assert_eq!(
            pass.verify().unwrap_err().code,
            FailureCode::PackfileCorrupted
        );
        for restored in [
            RestoredIntegrity {
                offset: 1,
                ..empty_restore()
            },
            RestoredIntegrity {
                whole_cvs: vec![[0; 32]],
                ..empty_restore()
            },
            RestoredIntegrity {
                trailer: [1; 32],
                ..empty_restore()
            },
        ] {
            assert!(IntegrityPass::resume(expected, restored).is_err());
        }
        assert!(IntegrityPass::reservation(MAX_PACK_BYTES).unwrap() < 64 << 10);
    }
}
