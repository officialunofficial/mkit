//! Bounded, local-only object collection for partial edits.

use std::collections::BTreeMap;
use std::sync::Mutex;

use crate::hash::Hash;
use crate::object::object_id_from_parts;
use crate::store::{MAX_RAW_OBJECT_SIZE, ObjectSink, StoreError, StoreResult};

use super::{PartialError, PartialLimits};

const PACK_FIXED_BYTES: usize = 12 + 32;
const PACK_ENTRY_FRAMING: usize = 1 + 4;

#[derive(Default)]
struct State {
    objects: BTreeMap<Hash, Vec<u8>>,
    pack_bytes: usize,
    failure: Option<CollectorFailure>,
}

#[derive(Clone, Copy)]
enum CollectorFailure {
    Count,
    Size,
}

/// An `ObjectSink` that never consults a backing store and charges the exact
/// raw-pack framing before retaining a newly produced object.
pub(crate) struct BoundedCollector {
    state: Mutex<State>,
    max_objects: usize,
    max_object_bytes: usize,
    max_pack_bytes: usize,
}

impl BoundedCollector {
    pub(crate) fn new(limits: &PartialLimits) -> Result<Self, PartialError> {
        if !limits.is_v1_subset() || PACK_FIXED_BYTES > limits.max_raw_pack_bytes {
            return Err(PartialError::ValidationBudgetExceeded);
        }
        Ok(Self {
            state: Mutex::new(State {
                objects: BTreeMap::new(),
                pack_bytes: PACK_FIXED_BYTES,
                failure: None,
            }),
            max_objects: limits.max_update_objects,
            max_object_bytes: limits.max_object_bytes,
            max_pack_bytes: limits.max_raw_pack_bytes,
        })
    }

    pub(crate) fn into_objects(self) -> BTreeMap<Hash, Vec<u8>> {
        self.state.into_inner().expect("collector mutex").objects
    }

    pub(crate) fn object_bytes(&self, id: &Hash) -> Option<Vec<u8>> {
        self.state
            .lock()
            .expect("collector mutex")
            .objects
            .get(id)
            .cloned()
    }

    pub(crate) fn translate_error(&self, error: StoreError) -> PartialError {
        match self.state.lock().expect("collector mutex").failure {
            Some(CollectorFailure::Count) => PartialError::ValidationBudgetExceeded,
            Some(CollectorFailure::Size) => PartialError::SubmissionTooLarge,
            None => PartialError::Source(error),
        }
    }
}

impl ObjectSink for BoundedCollector {
    fn put(&self, bytes: &[u8]) -> StoreResult<Hash> {
        self.put_parts(&[bytes])
    }

    fn put_parts(&self, parts: &[&[u8]]) -> StoreResult<Hash> {
        let total = parts.iter().try_fold(0usize, |sum, part| {
            sum.checked_add(part.len())
                .ok_or(StoreError::ObjectTooLarge)
        })?;
        if total == 0 {
            return Err(StoreError::ObjectTooLarge);
        }
        if total > self.max_object_bytes || total > MAX_RAW_OBJECT_SIZE {
            self.state.lock().expect("collector mutex").failure = Some(CollectorFailure::Size);
            return Err(StoreError::ObjectTooLarge);
        }
        let id = object_id_from_parts(parts);
        let mut state = self.state.lock().expect("collector mutex");
        if let Some(existing) = state.objects.get(&id) {
            if !parts_equal(existing, parts, total) {
                state.failure = Some(CollectorFailure::Size);
                return Err(StoreError::ObjectTooLarge);
            }
            return Ok(id);
        }
        if state.objects.len() >= self.max_objects {
            state.failure = Some(CollectorFailure::Count);
            return Err(StoreError::ObjectTooLarge);
        }
        let next = state
            .pack_bytes
            .checked_add(PACK_ENTRY_FRAMING)
            .and_then(|n| n.checked_add(total))
            .ok_or(StoreError::ObjectTooLarge)?;
        if next > self.max_pack_bytes {
            state.failure = Some(CollectorFailure::Size);
            return Err(StoreError::ObjectTooLarge);
        }
        let mut bytes = Vec::with_capacity(total);
        for part in parts {
            bytes.extend_from_slice(part);
        }
        state.pack_bytes = next;
        state.objects.insert(id, bytes);
        Ok(id)
    }

    fn has(&self, id: &Hash) -> bool {
        self.state
            .lock()
            .expect("collector mutex")
            .objects
            .contains_key(id)
    }
}

fn parts_equal(existing: &[u8], parts: &[&[u8]], total: usize) -> bool {
    if existing.len() != total {
        return false;
    }
    let mut offset = 0usize;
    for part in parts {
        let end = offset
            .checked_add(part.len())
            .expect("validated parts length cannot overflow");
        if existing.get(offset..end) != Some(*part) {
            return false;
        }
        offset = end;
    }
    true
}
