//! Bounded read/write overlay for synchronous object algorithms.

use std::collections::BTreeMap;
use std::sync::Mutex;

use super::{MAX_RAW_OBJECT_SIZE, ObjectSink, ObjectSource, StoreError, StoreResult};
use crate::hash::Hash;
use crate::object::{object_id_from_bytes, object_id_from_parts};

/// Caller-selected aggregate budgets for one overlay's lifetime.
/// Reads (including misses and repeated reads) consume calls; successful reads
/// consume canonical bytes. Writes consume retained bytes and distinct objects.
/// These budgets are not refunded on errors. Prefetch/source memory is separate.
#[derive(Debug, Clone, Copy)]
pub struct MemoryOverlayLimits {
    pub read_calls: usize,
    pub read_bytes: usize,
    pub written_bytes: usize,
    pub written_objects: usize,
}

#[derive(Debug, Default)]
struct State {
    objects: BTreeMap<Hash, Vec<u8>>,
    read_calls: usize,
    read_bytes: usize,
    written_bytes: usize,
}

/// In-memory sink whose reads resolve emitted objects before falling through to
/// an [`ObjectSource`] (typically a prefetched [`super::MemorySource`]).
/// A successful `put` is immediately readable, including by later operations.
/// No filesystem, signing, refs, or publication policy is involved.
///
/// Limits bound retained output and aggregate read work, including graph walks.
/// The caller must separately bound prefetch bytes/object count and the maximum
/// size returned by its source: a read allocates before its byte debit, and tree
/// decoding/text merge have temporary allocations proportional to input size.
/// A failed operation can leave earlier writes in the overlay; discard it to
/// abandon those outputs. There is no rollback or budget reset.
#[derive(Debug)]
pub struct MemoryOverlay<S> {
    source: S,
    limits: MemoryOverlayLimits,
    state: Mutex<State>,
}

impl<S> MemoryOverlay<S> {
    /// Create an empty write overlay with explicit budgets (no unlimited default).
    #[must_use]
    pub fn new(source: S, limits: MemoryOverlayLimits) -> Self {
        Self {
            source,
            limits,
            state: Mutex::new(State::default()),
        }
    }
}

fn debit(used: &mut usize, amount: usize, cap: usize, name: &'static str) -> StoreResult<()> {
    let next = used
        .checked_add(amount)
        .filter(|&next| next <= cap)
        .ok_or(StoreError::OperationLimitExceeded(name))?;
    *used = next;
    Ok(())
}

impl<S: ObjectSource> ObjectSource for MemoryOverlay<S> {
    fn read(&self, id: &Hash) -> StoreResult<Vec<u8>> {
        let mut state = self.state.lock().expect("memory overlay mutex");
        debit(
            &mut state.read_calls,
            1,
            self.limits.read_calls,
            "read calls",
        )?;
        // Charge before cloning an overlay hit. Source misses also consume calls.
        if let Some(bytes) = state.objects.get(id) {
            let len = bytes.len();
            debit(
                &mut state.read_bytes,
                len,
                self.limits.read_bytes,
                "read bytes",
            )?;
            return Ok(state.objects[id].clone());
        }
        drop(state);
        let bytes = self.source.read(id)?;
        let mut state = self.state.lock().expect("memory overlay mutex");
        debit(
            &mut state.read_bytes,
            bytes.len(),
            self.limits.read_bytes,
            "read bytes",
        )?;
        Ok(bytes)
    }
}

impl<S> ObjectSink for MemoryOverlay<S> {
    fn put(&self, bytes: &[u8]) -> StoreResult<Hash> {
        self.put_parts(&[bytes])
    }

    fn put_parts(&self, parts: &[&[u8]]) -> StoreResult<Hash> {
        let len = parts
            .iter()
            .try_fold(0usize, |len, part| len.checked_add(part.len()))
            .filter(|&len| len <= MAX_RAW_OBJECT_SIZE)
            .ok_or(StoreError::ObjectTooLarge)?;
        // No object larger than the entire retention cap can be a dedup hit.
        // Reject it before Merkle hashing can buffer multipart canonical bytes.
        if len > self.limits.written_bytes {
            return Err(StoreError::OperationLimitExceeded("written bytes"));
        }
        let mut state = self.state.lock().expect("memory overlay mutex");
        // Check budgets before allocating new output. Dedup hits remain
        // available when the retention budget is full.
        let nonempty = parts
            .iter()
            .position(|part| !part.is_empty())
            .unwrap_or(parts.len());
        let parts = &parts[nonempty..];
        let id = match parts {
            [bytes] => object_id_from_bytes(bytes),
            _ => object_id_from_parts(parts),
        };
        if state.objects.contains_key(&id) {
            return Ok(id);
        }
        if state.objects.len() >= self.limits.written_objects {
            return Err(StoreError::OperationLimitExceeded("written objects"));
        }
        debit(
            &mut state.written_bytes,
            len,
            self.limits.written_bytes,
            "written bytes",
        )?;
        let mut bytes = Vec::with_capacity(len);
        for part in parts {
            bytes.extend_from_slice(part);
        }
        state.objects.insert(id, bytes);
        Ok(id)
    }

    fn has(&self, id: &Hash) -> bool {
        self.state
            .lock()
            .expect("memory overlay mutex")
            .objects
            .contains_key(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::{Blob, Commit, Identity, Object};
    use crate::serialize;
    use crate::store::MemorySource;

    fn limits() -> MemoryOverlayLimits {
        MemoryOverlayLimits {
            read_calls: 100,
            read_bytes: 1024 * 1024,
            written_bytes: 1024 * 1024,
            written_objects: 100,
        }
    }

    fn blob(data: &[u8]) -> Vec<u8> {
        serialize::serialize(&Object::Blob(Blob {
            data: data.to_vec(),
        }))
        .unwrap()
    }

    #[test]
    fn retention_limits_fail_before_insert_and_dedup_is_free() {
        let bytes = blob(b"a");
        let overlay = MemoryOverlay::new(
            MemorySource::default(),
            MemoryOverlayLimits {
                written_bytes: bytes.len(),
                written_objects: 1,
                ..limits()
            },
        );
        let id = overlay.put(&bytes).unwrap();
        assert_eq!(overlay.put_parts(&[&bytes[..4], &bytes[4..]]).unwrap(), id);
        assert_eq!(overlay.read(&id).unwrap(), bytes);
        assert!(overlay.has(&id));
        assert!(matches!(
            overlay.put(&blob(b"b")),
            Err(StoreError::OperationLimitExceeded("written objects"))
        ));
        let overlay = MemoryOverlay::new(
            MemorySource::default(),
            MemoryOverlayLimits {
                written_bytes: bytes.len() - 1,
                ..limits()
            },
        );
        assert!(matches!(
            overlay.put(&bytes),
            Err(StoreError::OperationLimitExceeded("written bytes"))
        ));
        assert!(!overlay.has(&id));
        assert_eq!(overlay.state.lock().unwrap().written_bytes, 0);
    }

    #[test]
    fn repeated_reads_and_missing_objects_consume_budget() {
        let bytes = blob(b"a");
        let id = crate::object::object_id_from_bytes(&bytes);
        let mut source = MemorySource::default();
        source.insert(id, bytes.clone()).unwrap();
        let overlay = MemoryOverlay::new(
            source,
            MemoryOverlayLimits {
                read_calls: 2,
                read_bytes: bytes.len(),
                ..limits()
            },
        );
        assert!(matches!(
            overlay.read(&[0; 32]),
            Err(StoreError::ObjectNotFound(_))
        ));
        assert_eq!(overlay.read(&id).unwrap(), bytes);
        assert!(matches!(
            overlay.read(&id),
            Err(StoreError::OperationLimitExceeded("read calls"))
        ));
        let overlay = MemoryOverlay::new(
            MemorySource::default(),
            MemoryOverlayLimits {
                read_bytes: bytes.len(),
                ..limits()
            },
        );
        overlay.put(&bytes).unwrap();
        overlay.read(&id).unwrap();
        assert!(matches!(
            overlay.read(&id),
            Err(StoreError::OperationLimitExceeded("read bytes"))
        ));
    }

    #[test]
    fn graph_budget_errors_propagate_instead_of_returning_partial_answers() {
        let mut source = MemorySource::default();
        let missing = [1; 32];
        let commit = Object::Commit(Commit {
            tree_hash: [0; 32],
            parents: vec![missing],
            author: Identity::ed25519([0; 32]),
            signer: [0; 32],
            message: vec![],
            timestamp: 0,
            message_hash: [0; 32],
            content_digest: [0; 32],
            signature: [0; 64],
        });
        let id = commit.id().unwrap();
        source
            .insert(id, serialize::serialize(&commit).unwrap())
            .unwrap();
        for op in 0..3 {
            let overlay = MemoryOverlay::new(
                source_for(&source, id),
                MemoryOverlayLimits {
                    read_calls: 1,
                    ..limits()
                },
            );
            let error = match op {
                0 => crate::ops::is_ancestor(&overlay, [2; 32], id).unwrap_err(),
                1 => crate::ops::find_merge_base(&overlay, id, [2; 32]).unwrap_err(),
                _ => crate::ops::collect_ancestor_set(
                    &overlay,
                    id,
                    &mut std::collections::HashSet::new(),
                )
                .unwrap_err(),
            };
            assert!(matches!(
                error,
                StoreError::OperationLimitExceeded("read calls")
            ));
        }
    }

    #[test]
    fn multipart_merkle_identity_ignores_leading_empty_parts() {
        let overlay = MemoryOverlay::new(MemorySource::default(), limits());
        let object = Object::Tree(crate::object::Tree { entries: vec![] });
        let bytes = serialize::serialize(&object).unwrap();
        let id = overlay.put_parts(&[&[], &bytes[..1], &bytes[1..]]).unwrap();
        assert_eq!(id, object.id().unwrap());
        assert_eq!(overlay.read_object(&id).unwrap(), object);
    }

    fn source_for(source: &MemorySource, id: Hash) -> MemorySource {
        let mut copy = MemorySource::default();
        copy.insert(id, source.read(&id).unwrap()).unwrap();
        copy
    }
}
