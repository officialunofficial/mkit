//! Deployment denial policy at the key-read and activation boundaries.
use super::{
    Batch, BatchOutcome, Cursor, Key, NamespaceStore, Partition, PartitionStats, Precondition,
    RangeScan, ReadReservation, ScanPage, StoreCapabilities, StoreError, Value, Write,
};

/// Store facade for a pipeline's takedown-denial mode. Only exact block and
/// denial-action reads and absence guards are omitted. Activation and guards
/// requiring an existing denial row are refused;
/// inventory and reference-page keys and their writes remain live.
///
/// With denial disabled, a batch that installs denial rows or requires their
/// presence or exact value returns [`StoreError::TakedownDenialDisabled`] before
/// I/O. Only denial absence guards are omitted; other guards and writes remain
/// unchanged.
#[derive(Debug, Clone, Copy)]
pub struct DenialReads<S> {
    store: S,
    enabled: bool,
}
impl<S> DenialReads<S> {
    /// Use the deployment's `PipelineConfig::takedown_denial` value.
    #[must_use]
    pub fn new(store: S, takedown_denial: bool) -> Self {
        Self {
            store,
            enabled: takedown_denial,
        }
    }

    /// Avoid denial-only prefetch planning and reservations when disabled.
    pub(crate) fn enabled_ids<I: Iterator>(&self, ids: I) -> std::iter::Take<I> {
        ids.take(if self.enabled { usize::MAX } else { 0 })
    }

    fn omitted(&self, partition: &Partition, key: &Key) -> bool {
        if self.enabled {
            return false;
        }
        let Some(raw) = key.as_bytes().strip_prefix(b"b\0") else {
            return false;
        };
        let object = match raw {
            bytes if bytes.len() == 32 => bytes,
            bytes if bytes.len() == 40 && &bytes[32..] == b"\0actions" => &bytes[..32],
            _ => return false,
        };
        let Ok(object) = <&[u8; 32]>::try_from(object) else {
            return false;
        };
        *partition == super::content_shard(object)
    }
}
impl<S: NamespaceStore> NamespaceStore for DenialReads<S> {
    fn capabilities(&self) -> StoreCapabilities {
        self.store.capabilities()
    }
    fn reader_admission(&self) -> bool {
        self.store.reader_admission()
    }
    fn read_call_allowance(&self) -> Option<u32> {
        self.store.read_call_allowance()
    }
    fn reserve_read_calls(&self, calls: u32) -> Result<Option<ReadReservation>, StoreError> {
        self.store.reserve_read_calls(calls)
    }
    async fn has(&self, partition: &Partition, key: &Key) -> Result<bool, StoreError> {
        if self.omitted(partition, key) {
            return Ok(false);
        }
        self.store.has(partition, key).await
    }
    async fn get(&self, partition: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
        if self.omitted(partition, key) {
            return Ok(None);
        }
        self.store.get(partition, key).await
    }
    async fn get_many(
        &self,
        partition: &Partition,
        keys: &[Key],
    ) -> Result<Vec<Option<Value>>, StoreError> {
        if self.enabled {
            return self.store.get_many(partition, keys).await;
        }
        let kept: Vec<_> = keys
            .iter()
            .filter(|key| !self.omitted(partition, key))
            .cloned()
            .collect();
        if kept.len() == keys.len() {
            return self.store.get_many(partition, keys).await;
        }
        let values = if kept.is_empty() {
            Vec::new()
        } else {
            self.store.get_many(partition, &kept).await?
        };
        if values.len() != kept.len() {
            return Err(StoreError::MalformedReply("short denial-mode read".into()));
        }
        let mut values = values.into_iter();
        Ok(keys
            .iter()
            .map(|key| {
                if self.omitted(partition, key) {
                    None
                } else {
                    values.next().flatten()
                }
            })
            .collect())
    }
    async fn scan(
        &self,
        partition: &Partition,
        start: &Key,
        end: &Key,
        after: Option<&Cursor>,
        limit: u32,
    ) -> Result<ScanPage, StoreError> {
        self.store.scan(partition, start, end, after, limit).await
    }
    async fn scan_many(
        &self,
        partition: &Partition,
        ranges: &[RangeScan],
    ) -> Result<Vec<ScanPage>, StoreError> {
        self.store.scan_many(partition, ranges).await
    }
    async fn apply(
        &self,
        partition: &Partition,
        mut batch: Batch,
    ) -> Result<BatchOutcome, StoreError> {
        if self.enabled {
            return self.store.apply(partition, batch).await;
        }
        // Reject activation rather than dropping any write from the batch.
        if batch
            .writes
            .iter()
            .any(|write| matches!(write, Write::Put(key, _) if self.omitted(partition, key)))
        {
            return Err(StoreError::TakedownDenialDisabled);
        }
        // Clear mode cannot satisfy a guard requiring an existing denial row.
        // Refuse before I/O rather than committing that guard's ordinary writes.
        if batch.preconditions.iter().any(|guard| match guard {
            Precondition::Present(key) | Precondition::Equals(key, _) => {
                self.omitted(partition, key)
            }
            Precondition::Absent(_) | Precondition::NotAfter(_) => false,
        }) {
            return Err(StoreError::TakedownDenialDisabled);
        }
        let omitted = |guard: &Precondition| match guard {
            Precondition::Absent(key) => self.omitted(partition, key),
            Precondition::Present(_) | Precondition::Equals(_, _) | Precondition::NotAfter(_) => {
                false
            }
        };
        if !batch.preconditions.iter().any(omitted) {
            return self.store.apply(partition, batch).await;
        }
        // Removing denial guards must not admit an originally oversized batch.
        batch.validate(&self.store.capabilities())?;
        let mut original = Vec::with_capacity(batch.preconditions.len());
        batch.preconditions = batch
            .preconditions
            .into_iter()
            .enumerate()
            .filter_map(|(index, guard)| {
                if omitted(&guard) {
                    None
                } else {
                    original.push(index);
                    Some(guard)
                }
            })
            .collect();
        match self.store.apply(partition, batch).await? {
            BatchOutcome::PreconditionFailed { index, observed } => {
                Ok(BatchOutcome::PreconditionFailed {
                    index: *original.get(index).ok_or_else(|| {
                        StoreError::MalformedReply("invalid filtered precondition index".into())
                    })?,
                    observed,
                })
            }
            outcome => Ok(outcome),
        }
    }
    async fn stats(&self, partition: &Partition) -> Result<PartitionStats, StoreError> {
        self.store.stats(partition).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.store.probe().await
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::MemoryKv;
    use crate::store::keys;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Observed {
        inner: MemoryKv,
        reads: Mutex<Vec<Vec<Key>>>,
        batches: Mutex<Vec<Batch>>,
        has_reads: Mutex<Vec<(Partition, Key)>>,
        has_reply: Option<bool>,
        refuse_get: bool,
    }
    impl NamespaceStore for Observed {
        fn capabilities(&self) -> StoreCapabilities {
            self.inner.capabilities()
        }
        async fn get(&self, p: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
            self.reads.lock().unwrap().push(vec![key.clone()]);
            if self.refuse_get {
                return Err(StoreError::unavailable("get is unavailable"));
            }
            self.inner.get(p, key).await
        }
        async fn has(&self, p: &Partition, key: &Key) -> Result<bool, StoreError> {
            self.has_reads
                .lock()
                .unwrap()
                .push((p.clone(), key.clone()));
            match self.has_reply {
                Some(reply) => Ok(reply),
                None => self.inner.has(p, key).await,
            }
        }
        async fn get_many(
            &self,
            p: &Partition,
            keys: &[Key],
        ) -> Result<Vec<Option<Value>>, StoreError> {
            self.reads.lock().unwrap().push(keys.to_vec());
            self.inner.get_many(p, keys).await
        }
        async fn scan(
            &self,
            p: &Partition,
            start: &Key,
            end: &Key,
            after: Option<&Cursor>,
            limit: u32,
        ) -> Result<ScanPage, StoreError> {
            self.inner.scan(p, start, end, after, limit).await
        }
        async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
            self.batches.lock().unwrap().push(batch.clone());
            self.inner.apply(p, batch).await
        }
        async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
            self.inner.stats(p).await
        }
        async fn probe(&self) -> Result<(), StoreError> {
            self.inner.probe().await
        }
    }
    #[tokio::test]
    async fn off_filters_only_exact_denial_rows_and_preserves_mixed_order_and_writes() {
        let store = Observed::default();
        let id = [3; 32];
        let partition = crate::store::content_shard(&id);
        let block = keys::block(&id);
        let action = crate::takedown::denial::action_key(&id);
        let inventory = Key::new([block.as_bytes(), b"\0inventory-head"].concat());
        let holder = keys::holder(
            &id,
            &crate::NamespaceKey::deployment_default(),
            &crate::RepoName::new("repo").unwrap(),
        )
        .unwrap();
        let gate = DenialReads::new(&store, false);
        let value = Value::new(vec![7]);
        let batch = Batch::new()
            .put(inventory.clone(), value.clone())
            .put(holder.clone(), value.clone());
        assert_eq!(
            gate.apply(&partition, batch).await.unwrap(),
            BatchOutcome::Committed
        );
        assert_eq!(
            gate.get_many(&partition, &[block.clone(), action.clone()])
                .await
                .unwrap(),
            [None, None]
        );
        assert!(gate.get(&partition, &block).await.unwrap().is_none());
        assert!(store.reads.lock().unwrap().is_empty());
        assert_eq!(
            gate.get_many(
                &partition,
                &[
                    holder.clone(),
                    block.clone(),
                    inventory.clone(),
                    action.clone(),
                    holder.clone()
                ]
            )
            .await
            .unwrap(),
            [
                Some(value.clone()),
                None,
                Some(value.clone()),
                None,
                Some(value)
            ]
        );
        assert_eq!(
            *store.reads.lock().unwrap(),
            [vec![holder.clone(), inventory, holder]]
        );
        // A block-shaped key in another partition is ordinary storage data.
        gate.get(&Partition::ContentShard(0), &block).await.unwrap();
        assert_eq!(store.reads.lock().unwrap().last(), Some(&vec![block]));
    }
    #[tokio::test]
    async fn on_forwards_identical_keys_and_replies() {
        let store = Observed::default();
        let id = [8; 32];
        let partition = crate::store::content_shard(&id);
        let keys = [keys::block(&id), crate::takedown::denial::action_key(&id)];
        let raw = Value::new(vec![255]);
        store
            .inner
            .apply(&partition, Batch::new().put(keys[1].clone(), raw.clone()))
            .await
            .unwrap();
        let gate = DenialReads::new(&store, true);
        assert_eq!(
            gate.get_many(&partition, &keys).await.unwrap(),
            [None, Some(raw)]
        );
        assert_eq!(*store.reads.lock().unwrap(), [keys.to_vec()]);
        let batch = Batch::new()
            .require(Precondition::Absent(keys[0].clone()))
            .put(keys[0].clone(), Value::new(vec![1]));
        assert_eq!(
            gate.apply(&partition, batch.clone()).await.unwrap(),
            BatchOutcome::Committed
        );
        assert_eq!(*store.batches.lock().unwrap(), [batch]);
    }
    #[tokio::test]
    async fn off_denial_waves_do_not_reserve_an_admitted_call_budget() {
        let store = Observed::default();
        let budget = crate::indexed::budget::SliceBudget::new(0);
        let io = crate::store::read_io::ReadIo::new();
        let admitted = crate::indexed::budget::Budgeted::new(&store, &budget).with_io(&io);
        let gate = DenialReads::new(&admitted, false);
        assert!(gate.reader_admission());
        crate::takedown::denial::require_clear_many(
            &gate,
            gate.enabled_ids((0..12).map(|n| [n; 32])),
        )
        .await
        .unwrap();
        assert_eq!(budget.used(), 0);
        assert!(store.reads.lock().unwrap().is_empty());
    }
    #[tokio::test]
    async fn off_apply_omits_denial_guards_preserves_other_guards_writes_and_failure_indices() {
        let store = Observed::default();
        let id = [3; 32];
        let partition = crate::store::content_shard(&id);
        let block = keys::block(&id);
        let action = crate::takedown::denial::action_key(&id);
        let ordinary = keys::object_state(&id);
        let value = Value::new(vec![9]);
        let writes = vec![Write::Put(ordinary.clone(), value.clone())];
        let gate = DenialReads::new(&store, false);
        let denied_guard = Precondition::Absent(block.clone());
        let ordinary_guard = Precondition::Absent(ordinary.clone());
        let batch = Batch {
            preconditions: vec![
                denied_guard.clone(),
                ordinary_guard.clone(),
                Precondition::Absent(action.clone()),
            ],
            writes: writes.clone(),
        };
        assert_eq!(
            gate.apply(&partition, batch).await.unwrap(),
            BatchOutcome::Committed
        );
        let forwarded = store.batches.lock().unwrap()[0].clone();
        assert_eq!(forwarded.preconditions, [ordinary_guard]);
        assert_eq!(forwarded.writes, writes);
        let failure = gate
            .apply(
                &partition,
                Batch::new()
                    .require(denied_guard)
                    .require(Precondition::Absent(ordinary.clone()))
                    .put(ordinary.clone(), Value::new(vec![10])),
            )
            .await
            .unwrap();
        assert_eq!(
            failure,
            BatchOutcome::PreconditionFailed {
                index: 1,
                observed: Some(value)
            }
        );
        let calls = store.batches.lock().unwrap().len();
        for key in [block.clone(), action] {
            let error = gate
                .apply(
                    &partition,
                    Batch::new()
                        .put(ordinary.clone(), Value::new(vec![11]))
                        .put(key, Value::new(vec![255])),
                )
                .await
                .unwrap_err();
            assert!(matches!(error, StoreError::TakedownDenialDisabled));
        }
        assert_eq!(store.batches.lock().unwrap().len(), calls);
        for key in [block.clone(), crate::takedown::denial::action_key(&id)] {
            for guard in [
                Precondition::Present(key.clone()),
                Precondition::Equals(key, Value::new(vec![255])),
            ] {
                let error = gate
                    .apply(
                        &partition,
                        Batch::new()
                            .require(Precondition::Absent(block.clone()))
                            .require(guard)
                            .put(ordinary.clone(), Value::new(vec![12])),
                    )
                    .await
                    .unwrap_err();
                assert!(matches!(error, StoreError::TakedownDenialDisabled));
            }
        }
        assert_eq!(store.batches.lock().unwrap().len(), calls);
        assert!(store.reads.lock().unwrap().is_empty());
        let oversized = Batch {
            preconditions: vec![Precondition::Absent(block); super::super::MAX_BATCH_OPS + 1],
            writes: Vec::new(),
        };
        assert!(matches!(
            gate.apply(&partition, oversized).await.unwrap_err(),
            StoreError::Invalid(_)
        ));
        assert_eq!(store.batches.lock().unwrap().len(), calls);
    }
    #[tokio::test]
    async fn has_forwards_backend_semantics_and_omits_only_disabled_denial_rows() {
        let store = Observed {
            has_reply: Some(true),
            refuse_get: true,
            ..Observed::default()
        };
        let id = [3; 32];
        let partition = super::super::content_shard(&id);
        let block = keys::block(&id);
        let action = crate::takedown::denial::action_key(&id);
        let ordinary = Key::new(b"ordinary".to_vec());
        assert!(store.get(&partition, &ordinary).await.is_err());
        store.reads.lock().unwrap().clear();
        for enabled in [true, false] {
            let gate = DenialReads::new(&store, enabled);
            assert_eq!(gate.has(&partition, &block).await.unwrap(), enabled);
            assert_eq!(gate.has(&partition, &action).await.unwrap(), enabled);
            assert!(gate.has(&partition, &ordinary).await.unwrap());
        }
        // An exact block-shaped key in another partition is ordinary data.
        let other = Partition::ContentShard(0);
        assert_ne!(partition, other);
        assert!(
            DenialReads::new(&store, false)
                .has(&other, &block)
                .await
                .unwrap()
        );
        assert_eq!(
            *store.has_reads.lock().unwrap(),
            [
                (partition.clone(), block.clone()),
                (partition.clone(), action),
                (partition.clone(), ordinary.clone()),
                (partition, ordinary),
                (other, block),
            ]
        );
        assert!(
            store.reads.lock().unwrap().is_empty(),
            "has must never fall back to get"
        );
    }
}
