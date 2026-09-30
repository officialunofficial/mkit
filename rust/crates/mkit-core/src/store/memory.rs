use super::{MAX_RAW_OBJECT_SIZE, ObjectSource, StoreError, StoreResult, check_hash};
use crate::hash::{Hash, to_hex};
use crate::object::object_id_from_bytes;
use std::collections::BTreeMap;
/// Canonical object bytes prefetched into memory by an embedding application.
/// Fetch asynchronously, insert canonical bytes, then use
/// [`crate::verify::build_disclosure_from`] or [`crate::ops::diff::diff_trees`].
/// The host owns authorization and aggregate memory limits.
#[derive(Debug, Default)]
pub struct MemorySource {
    objects: BTreeMap<Hash, Vec<u8>>,
}
impl MemorySource {
    /// Insert prefetched canonical bytes under their expected object ID.
    /// An invalid insertion leaves the previous value intact.
    ///
    /// # Errors
    /// [`StoreError::ObjectTooLarge`] or [`StoreError::HashMismatch`].
    pub fn insert(&mut self, id: Hash, bytes: Vec<u8>) -> StoreResult<()> {
        if bytes.len() > MAX_RAW_OBJECT_SIZE {
            return Err(StoreError::ObjectTooLarge);
        }
        check_hash(&id, &object_id_from_bytes(&bytes))?;
        self.objects.insert(id, bytes);
        Ok(())
    }
    fn bytes(&self, id: &Hash) -> StoreResult<&[u8]> {
        self.objects
            .get(id)
            .map(Vec::as_slice)
            .ok_or_else(|| StoreError::ObjectNotFound(to_hex(id)))
    }
}
impl ObjectSource for MemorySource {
    fn read(&self, id: &Hash) -> StoreResult<Vec<u8>> {
        let bytes = self.bytes(id)?;
        check_hash(id, &object_id_from_bytes(bytes))?;
        Ok(bytes.to_vec())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::{Blob, ChunkedBlob, EntryMode, Tree, TreeEntry};
    use crate::{object::Object, serialize};

    fn put(source: &mut MemorySource, object: &Object) -> Hash {
        let id = object.id().unwrap();
        source
            .insert(id, serialize::serialize(object).unwrap())
            .unwrap();
        id
    }

    #[test]
    fn prefetched_blob_tree_and_manifest_use_their_canonical_ids() {
        let mut source = MemorySource::default();
        let blob = Object::Blob(Blob {
            data: b"chunk".to_vec(),
        });
        let chunk = put(&mut source, &blob);
        let manifest = Object::ChunkedBlob(ChunkedBlob {
            total_size: 5,
            chunk_size: 0,
            chunks: vec![chunk],
        });
        let file = put(&mut source, &manifest);
        let tree = Object::Tree(Tree {
            entries: vec![TreeEntry {
                name: b"file".to_vec(),
                mode: EntryMode::Blob,
                object_hash: file,
            }],
        });
        let root = put(&mut source, &tree);
        let source: &dyn ObjectSource = &source;
        for (id, object) in [(chunk, blob), (file, manifest), (root, tree)] {
            assert_eq!(
                source.read(&id).unwrap(),
                serialize::serialize(&object).unwrap()
            );
            assert_eq!(source.read_object(&id).unwrap(), object);
        }
        assert!(matches!(
            source.read(&[0; 32]),
            Err(StoreError::ObjectNotFound(_))
        ));
    }

    #[test]
    fn failed_insert_preserves_previous_bytes_and_reads_verify_again() {
        let mut source = MemorySource::default();
        let object = Object::Blob(Blob {
            data: b"valid".to_vec(),
        });
        let id = put(&mut source, &object);
        assert!(matches!(
            source.insert(id, b"invalid".to_vec()),
            Err(StoreError::HashMismatch { .. })
        ));
        assert_eq!(source.read_object(&id).unwrap(), object);
        // Simulate memory corruption to prove insertion-time checking is not
        // the only integrity boundary, including through read_unverified.
        source.objects.get_mut(&id).unwrap()[0] ^= 0xff;
        for result in [source.read(&id), source.read_unverified(&id)] {
            assert!(matches!(result, Err(StoreError::HashMismatch { .. })));
        }
        assert!(matches!(
            source.read_object(&id),
            Err(StoreError::HashMismatch { .. })
        ));
    }

    #[test]
    fn prefetched_manifest_builds_the_same_disclosure_as_the_durable_source() {
        use crate::object::{Commit, Identity};
        use crate::sign::{KeyPair, sign_commit};
        use crate::verify::{Selector, build_disclosure, build_disclosure_from, verify_disclosure};

        let dir = tempfile::TempDir::new().unwrap();
        let store = super::super::ObjectStore::init(&crate::layout::RepoLayout::single(dir.path()))
            .unwrap();
        let mut source = MemorySource::default();
        let mut add = |object: Object| {
            let bytes = serialize::serialize(&object).unwrap();
            let id = store.write(&bytes).unwrap();
            source.insert(id, bytes.clone()).unwrap();
            id
        };
        let chunk = add(Object::Blob(Blob {
            data: b"chunk".to_vec(),
        }));
        let manifest = add(Object::ChunkedBlob(ChunkedBlob {
            total_size: 5,
            chunk_size: 0,
            chunks: vec![chunk],
        }));
        let tree = add(Object::Tree(Tree {
            entries: vec![TreeEntry {
                name: b"file".to_vec(),
                mode: EntryMode::Blob,
                object_hash: manifest,
            }],
        }));
        let key = KeyPair::from_seed([7; 32]);
        let mut commit = Commit {
            tree_hash: tree,
            parents: vec![],
            author: Identity::ed25519(key.public.0),
            signer: key.public.0,
            message: b"prefetch fixture".to_vec(),
            timestamp: 1_726_300_000,
            message_hash: [0; 32],
            content_digest: [0; 32],
            signature: [0; 64],
        };
        commit.signature = sign_commit(&commit, &key).unwrap().0;
        let id = add(Object::Commit(commit));
        for selector in [Selector::Object, Selector::Chunk(0)] {
            let bundle = build_disclosure_from(&source, &id, &[b"file"], selector).unwrap();
            assert_eq!(
                bundle,
                build_disclosure(&store, &id, &[b"file"], selector).unwrap()
            );
            let verified = verify_disclosure(&id, &bundle).unwrap();
            assert!(verified.signature_valid);
            assert_eq!(verified.leaf_id, manifest);
        }
        // A Merkle object's canonical bytes must be checked on read too.
        source
            .objects
            .get_mut(&tree)
            .unwrap()
            .last_mut()
            .map(|byte| *byte ^= 1)
            .unwrap();
        assert!(matches!(
            source.read(&tree),
            Err(StoreError::HashMismatch { .. })
        ));
        assert!(matches!(
            source.read_object(&tree),
            Err(StoreError::HashMismatch { .. })
        ));
    }
}
