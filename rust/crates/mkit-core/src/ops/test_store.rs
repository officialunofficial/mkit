//! The existing operation corpus, parameterized over durable and memory backends.
//! Each operation runs twice with identical inputs; compare the complete result
//! (hash, conflicts, messages, or typed error), then keep the durable result.

use std::fmt::Debug;
use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::hash::Hash;
use crate::object::Object;
use crate::store::{
    MemoryOverlay, MemoryOverlayLimits, MemorySource, ObjectSink, ObjectSource, ObjectStore,
    StoreResult,
};

pub(super) trait SourceSink: ObjectSource + ObjectSink {}
impl<T: ObjectSource + ObjectSink> SourceSink for T {}

#[derive(Debug, Default)]
struct Prefetched(Mutex<MemorySource>);
impl ObjectSource for Prefetched {
    fn read(&self, id: &Hash) -> StoreResult<Vec<u8>> {
        self.0.lock().unwrap().read(id)
    }
}

pub(super) struct CorpusStore {
    durable: ObjectStore,
    input: Arc<Prefetched>,
    memory: MemoryOverlay<Arc<Prefetched>>,
}

impl ObjectSource for Arc<Prefetched> {
    fn read(&self, id: &Hash) -> StoreResult<Vec<u8>> {
        self.as_ref().read(id)
    }
}

impl CorpusStore {
    pub(super) fn new(path: &Path) -> Self {
        let input = Arc::new(Prefetched::default());
        Self {
            durable: ObjectStore::init(&crate::layout::RepoLayout::single(path)).unwrap(),
            memory: MemoryOverlay::new(
                input.clone(),
                MemoryOverlayLimits {
                    read_calls: 100_000,
                    read_bytes: 64 * 1024 * 1024,
                    written_bytes: 16 * 1024 * 1024,
                    written_objects: 10_000,
                },
            ),
            input,
        }
    }

    pub(super) fn write(&self, bytes: &[u8]) -> StoreResult<Hash> {
        let id = self.durable.write(bytes)?;
        self.input.0.lock().unwrap().insert(id, bytes.to_vec())?;
        Ok(id)
    }

    pub(super) fn read_object(&self, id: &Hash) -> StoreResult<Object> {
        let durable = self.durable.read_object(id)?;
        assert_eq!(durable, self.memory.read_object(id)?);
        Ok(durable)
    }

    pub(super) fn compare<T: Debug + PartialEq, E: Debug>(
        &self,
        operation: impl Fn(&dyn SourceSink) -> Result<T, E>,
    ) -> Result<T, E> {
        let backends: [&dyn SourceSink; 2] = [&self.durable, &self.memory];
        let mut results = backends.into_iter().map(operation);
        let durable = results.next().unwrap();
        let memory = results.next().unwrap();
        match (&durable, &memory) {
            (Ok(durable), Ok(memory)) => assert_eq!(durable, memory),
            (Err(durable), Err(memory)) => {
                assert_eq!(format!("{durable:?}"), format!("{memory:?}"));
            }
            _ => panic!("backend results differ: {durable:?}, {memory:?}"),
        }
        durable
    }
}
