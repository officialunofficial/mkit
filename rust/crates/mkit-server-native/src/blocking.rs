//! `Blocking<S>`: run a store whose bodies are synchronous on tokio's
//! blocking pool.

use std::fmt;
use std::sync::Arc;

use futures_executor::block_on;
use mkit_server::{
    Batch, BatchOutcome, Cursor, Key, NamespaceStore, Partition, PartitionStats, ScanPage,
    StoreCapabilities, StoreError, StoreMaintenance, Value,
};

/// Runs every call of the wrapped store on `tokio::task::spawn_blocking`,
/// so its synchronous I/O (a `SQLite` transaction, a file write) never
/// stalls an async worker thread.
///
/// Cancellation-safe (normative rule 4): the blocking task runs to
/// completion even if the awaiting future is dropped, so a dropped `apply`
/// commits fully or not at all, possibly after the drop. A panic in the
/// store is reported as [`StoreError::Unavailable`], and the store stays
/// usable if its own locks survive panics.
///
/// The calls must run inside a tokio runtime.
pub struct Blocking<S> {
    inner: Arc<S>,
}

impl<S> Blocking<S> {
    /// Wrap `store`.
    #[must_use]
    pub fn new(store: S) -> Self {
        Self {
            inner: Arc::new(store),
        }
    }

    /// The wrapped store, for synchronous callers.
    #[must_use]
    pub fn inner(&self) -> &Arc<S> {
        &self.inner
    }
}

impl<S> Clone for Blocking<S> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<S: fmt::Debug> fmt::Debug for Blocking<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Blocking").field(&self.inner).finish()
    }
}

impl<S: Send + Sync + 'static> Blocking<S> {
    /// Run `f` on the store on a blocking thread.
    async fn run<T, F>(&self, f: F) -> Result<T, StoreError>
    where
        T: Send + 'static,
        F: FnOnce(&S) -> Result<T, StoreError> + Send + 'static,
    {
        let inner = Arc::clone(&self.inner);
        match tokio::task::spawn_blocking(move || f(&inner)).await {
            Ok(result) => result,
            Err(e) if e.is_panic() => Err(StoreError::unavailable("store call panicked")),
            Err(_) => Err(StoreError::unavailable("store call cancelled")),
        }
    }
}

impl<S: NamespaceStore + Send + Sync + 'static> NamespaceStore for Blocking<S> {
    fn capabilities(&self) -> StoreCapabilities {
        self.inner.capabilities()
    }

    async fn get(&self, p: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
        let (p, key) = (p.clone(), key.clone());
        self.run(move |s| block_on(s.get(&p, &key))).await
    }

    async fn has(&self, p: &Partition, key: &Key) -> Result<bool, StoreError> {
        let (p, key) = (p.clone(), key.clone());
        self.run(move |s| block_on(s.has(&p, &key))).await
    }

    async fn get_many(
        &self,
        p: &Partition,
        keys: &[Key],
    ) -> Result<Vec<Option<Value>>, StoreError> {
        let (p, keys) = (p.clone(), keys.to_vec());
        self.run(move |s| block_on(s.get_many(&p, &keys))).await
    }

    async fn scan(
        &self,
        p: &Partition,
        start: &Key,
        end: &Key,
        after: Option<&Cursor>,
        limit: u32,
    ) -> Result<ScanPage, StoreError> {
        let (p, start, end, after) = (p.clone(), start.clone(), end.clone(), after.cloned());
        self.run(move |s| block_on(s.scan(&p, &start, &end, after.as_ref(), limit)))
            .await
    }

    async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        let p = p.clone();
        self.run(move |s| block_on(s.apply(&p, batch))).await
    }

    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        let p = p.clone();
        self.run(move |s| block_on(s.stats(&p))).await
    }

    async fn probe(&self) -> Result<(), StoreError> {
        self.run(|s| block_on(s.probe())).await
    }
}

impl<S: StoreMaintenance + Send + Sync + 'static> StoreMaintenance for Blocking<S> {
    fn layout_version(&self) -> u32 {
        self.inner.layout_version()
    }

    async fn migrate(&self) -> Result<u32, StoreError> {
        self.run(|s| block_on(s.migrate())).await
    }

    async fn backup_to(&self, dest: &str) -> Result<(), StoreError> {
        let dest = dest.to_owned();
        self.run(move |s| block_on(s.backup_to(&dest))).await
    }
}
