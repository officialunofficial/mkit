//! Bounded ownership reuse of authenticated, fixed-size objects-index leaves.
use super::{
    Descent, FANOUT, Failure, FailureCode, Hash, Index, PageCommitment, PageKind, VecDeque,
    failure, invalid,
};
use std::collections::HashMap;

const CAPACITY: usize = 512;
const QUEUE_CAPACITY: usize = 2 * CAPACITY;
const SLOT_BYTES: u64 = 8192;
const VALUE_BYTES: usize = super::super::records::OBJECT_BYTES;

#[derive(Debug)]
struct Leaf {
    commitment: PageCommitment,
    records: Vec<(Hash, Vec<u8>)>,
    generation: u64,
}

#[derive(Debug)]
pub(super) struct DecodedLeaves {
    entries: HashMap<Hash, Leaf>,
    order: VecDeque<(Hash, u64)>,
    generation: u64,
}

impl Index {
    pub(in super::super) const fn decoded_leaf_reservation() -> u64 {
        CAPACITY as u64 * SLOT_BYTES
    }

    pub(in super::super) fn decoded_leaves_allowed(&self) -> bool {
        self.state
            .0
            .as_ref()
            .is_some_and(|state| state.decoded_allowed)
    }

    pub(in super::super) fn prevent_decoded_leaves(&mut self) {
        if let Some(state) = self.state.0.as_mut() {
            state.decoded_allowed = false;
        }
    }

    pub(in super::super) fn decoded_leaves_enabled(&self) -> bool {
        self.state
            .0
            .as_ref()
            .is_some_and(|state| state.leaves.is_some())
    }

    pub(in super::super) fn enable_decoded_leaves(&mut self) -> Result<(), Failure> {
        if self.kind != PageKind::Objects || self.state.get()?.leaves.is_some() {
            return Err(invalid());
        }
        let mut entries = HashMap::new();
        entries
            .try_reserve(CAPACITY)
            .map_err(|_| failure(FailureCode::ResourceLimit))?;
        let mut order = VecDeque::new();
        order
            .try_reserve_exact(QUEUE_CAPACITY)
            .map_err(|_| failure(FailureCode::ResourceLimit))?;
        self.state.get_mut()?.leaves = Some(DecodedLeaves {
            entries,
            order,
            generation: 0,
        });
        Ok(())
    }

    pub(in super::super) fn disable_decoded_leaves(&mut self) -> u64 {
        if self
            .state
            .0
            .as_mut()
            .and_then(|state| state.leaves.take())
            .is_some()
        {
            Self::decoded_leaf_reservation()
        } else {
            0
        }
    }

    pub(super) fn take_decoded_leaf(
        &mut self,
        commitment: PageCommitment,
    ) -> Option<Vec<(Hash, Vec<u8>)>> {
        let cache = self.state.0.as_mut()?.leaves.as_mut()?;
        if cache.entries.get(&commitment.digest)?.commitment != commitment {
            return None;
        }
        cache
            .entries
            .remove(&commitment.digest)
            .map(|leaf| leaf.records)
    }

    pub(in super::super) fn forget_decoded_leaf(&mut self, commitment: PageCommitment) {
        if let Some(cache) = self
            .state
            .0
            .as_mut()
            .and_then(|state| state.leaves.as_mut())
        {
            cache.entries.remove(&commitment.digest);
        }
    }

    pub(in super::super) fn recycle_descent(&mut self, descent: Descent) {
        self.cache_decoded_leaf(descent.leaf, descent.records);
    }

    pub(super) fn cache_decoded_leaf(
        &mut self,
        commitment: PageCommitment,
        records: Vec<(Hash, Vec<u8>)>,
    ) {
        let Some(cache) = self
            .state
            .0
            .as_mut()
            .and_then(|state| state.leaves.as_mut())
        else {
            return;
        };
        // Four KiB covers record ownership (including capacity 32 after an
        // insertion), and the other four cover map/queue bookkeeping. Reject
        // unusual records from this optional cache without affecting validity.
        if records.capacity() > 2 * FANOUT
            || records.len() > FANOUT
            || records
                .iter()
                .any(|(_, value)| value.len() != VALUE_BYTES || value.capacity() > VALUE_BYTES)
        {
            return;
        }
        while cache.order.len() >= QUEUE_CAPACITY || cache.entries.len() >= CAPACITY {
            let Some((digest, generation)) = cache.order.pop_front() else {
                return;
            };
            if cache
                .entries
                .get(&digest)
                .is_some_and(|leaf| leaf.generation == generation)
            {
                cache.entries.remove(&digest);
            }
        }
        // The finite work ceiling precludes generation wraparound; declining a
        // cache insertion would still preserve the ordinary decoding path.
        let Some(generation) = cache.generation.checked_add(1) else {
            return;
        };
        cache.generation = generation;
        cache.entries.insert(
            commitment.digest,
            Leaf {
                commitment,
                records,
                generation,
            },
        );
        cache.order.push_back((commitment.digest, generation));
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        Budget, EncodedPage, Event, EvidenceBinding, EvidenceLimits, LeafRecord, encode_leaf,
    };
    use super::*;
    use crate::evidence::{
        PackSource, ProfileId, RepositoryId, RulesetBinding, SourceBinding, pages::INDEXED_RULESET,
    };

    fn fixture() -> (Index, EncodedPage, Vec<(Hash, Vec<u8>)>) {
        let binding = EvidenceBinding {
            source: PackSource {
                id: [1; 32],
                len: 44,
                binding: SourceBinding([2; 32]),
            },
            repository: RepositoryId([3; 32]),
            ruleset: RulesetBinding {
                ruleset: INDEXED_RULESET,
                profile: ProfileId::Indexed,
            },
        };
        let records = vec![([4; 32], vec![5; VALUE_BYTES])];
        let page = encode_leaf(
            binding,
            PageKind::Objects,
            &[LeafRecord {
                key: records[0].0,
                value: &records[0].1,
            }],
            EvidenceLimits::indexed(),
        )
        .unwrap();
        let index = Index::resume(
            PageKind::Objects,
            binding,
            EvidenceLimits::indexed(),
            page.commitment(),
            1,
        )
        .unwrap();
        (index, page, records)
    }

    #[test]
    fn decoded_leaf_reuse_moves_records_and_preserves_authentication_and_work() {
        let (mut index, page, records) = fixture();
        let (mut eager, _, _) = fixture();
        index.enable_decoded_leaves().unwrap();
        let outer = records.as_ptr();
        let inner = records[0].1.as_ptr();
        index.cache_decoded_leaf(page.commitment(), records);
        let mut corrupt = page.bytes().to_vec();
        *corrupt.last_mut().unwrap() ^= 1;
        let mut op = index.descend([4; 32]);
        let mut reference = eager.descend([4; 32]);
        let mut bad_budget = Budget::new(u64::MAX, u64::MAX);
        let mut bad_reference = Budget::new(u64::MAX, u64::MAX);
        assert_eq!(
            index.feed(&mut op, &corrupt, &mut bad_budget),
            eager.feed(&mut reference, &corrupt, &mut bad_reference)
        );
        assert_eq!(bad_budget.remaining(), bad_reference.remaining());
        assert!(
            index
                .state
                .get()
                .unwrap()
                .leaves
                .as_ref()
                .unwrap()
                .entries
                .contains_key(&page.commitment().digest)
        );
        for resident in [true, false] {
            let mut budget = Budget::new(u64::MAX, u64::MAX);
            let mut reference_budget = Budget::new(u64::MAX, u64::MAX);
            index
                .feed_page(&mut op, page.bytes(), &mut budget, resident)
                .unwrap();
            eager
                .feed_page(
                    &mut reference,
                    page.bytes(),
                    &mut reference_budget,
                    resident,
                )
                .unwrap();
            assert_eq!(budget.remaining(), reference_budget.remaining());
            let Event::Descended(descent) = index.poll(&mut op).unwrap() else {
                panic!("leaf")
            };
            assert_eq!(descent.records.as_ptr(), outer);
            assert_eq!(descent.records[0].1.as_ptr(), inner);
            index.recycle_descent(*descent);
            op = index.descend([4; 32]);
            reference = eager.descend([4; 32]);
        }
    }

    #[test]
    fn decoded_leaf_fifo_is_bounded_across_recycling_and_supersession() {
        let (mut index, page, records) = fixture();
        index.enable_decoded_leaves().unwrap();
        for n in 0..4096_u32 {
            let mut commitment = page.commitment();
            commitment.digest[..4].copy_from_slice(&n.to_le_bytes());
            index.cache_decoded_leaf(commitment, records.clone());
            let owned = index.take_decoded_leaf(commitment).unwrap();
            index.cache_decoded_leaf(commitment, owned);
            if n % 3 == 0 {
                index.forget_decoded_leaf(commitment);
            }
            let cache = index.state.get().unwrap().leaves.as_ref().unwrap();
            assert!(cache.entries.len() <= CAPACITY);
            assert!(cache.order.len() <= QUEUE_CAPACITY);
        }
        assert_eq!(
            index.disable_decoded_leaves(),
            Index::decoded_leaf_reservation()
        );
        assert!(!index.decoded_leaves_enabled());
    }
}
