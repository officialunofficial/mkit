//! Coordinator relay watermark and shard enumeration. The value is a lower
//! bound on the commit time of every undelivered relay row. Consumers compare
//! it against `T + MAX_APPLY_WINDOW + margin`. A new shard's first report may
//! be stale-low, so the namespace result can decrease without recovery;
//! recovery can reset maxima too.

use crate::store::{
    Batch, BatchOutcome, Cursor, Key, NamespaceStore, Partition, Precondition, ScanPage,
    StoreError, codec, keys,
};

const PAGE_SIZE: u32 = 128;

/// A recovery fence or a failed coordinator read.
#[derive(Debug, thiserror::Error)]
pub enum WatermarkError {
    /// The lease table was restored and awaits R-116 reconciliation.
    #[error("coordinator lease table is recovering")]
    Recovering,
    /// A storage or codec failure; consumers fail closed.
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// A resumable scan. The cursor is an opaque store cursor for the `ls` range;
/// the ceiling and minimum preserve the original scan-time bound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatermarkCheckpoint {
    coordinator: Partition,
    cursor: Cursor,
    ceiling_ms: u64,
    minimum_ms: u64,
    recovery_generation: RecoveryGeneration,
}

/// The exact recovery and reconciliation marker values observed at scan start.
pub type RecoveryGeneration = (Option<crate::store::Value>, Option<crate::store::Value>);

fn encode_marker(bytes: &mut Vec<u8>, marker: Option<&crate::store::Value>) {
    match marker {
        Some(value) => {
            bytes.extend_from_slice(
                &u32::try_from(value.as_bytes().len())
                    .expect("store value length fits u32")
                    .to_be_bytes(),
            );
            bytes.extend_from_slice(value.as_bytes());
        }
        None => bytes.extend_from_slice(&u32::MAX.to_be_bytes()),
    }
}

fn decode_marker(bytes: &[u8], at: &mut usize) -> Result<Option<crate::store::Value>, StoreError> {
    let len = u32::from_be_bytes(
        bytes
            .get(*at..*at + 4)
            .and_then(|slice| slice.try_into().ok())
            .ok_or_else(|| StoreError::Invalid("truncated watermark generation".into()))?,
    );
    *at += 4;
    if len == u32::MAX {
        return Ok(None);
    }
    let end = at
        .checked_add(
            usize::try_from(len)
                .map_err(|_| StoreError::Invalid("invalid watermark generation length".into()))?,
        )
        .ok_or_else(|| StoreError::Invalid("invalid watermark generation length".into()))?;
    let value = bytes
        .get(*at..end)
        .ok_or_else(|| StoreError::Invalid("truncated watermark generation".into()))?;
    *at = end;
    Ok(Some(crate::store::Value::new(value.to_vec())))
}

impl WatermarkCheckpoint {
    /// Stable binary form: version, partition length and bytes, scan ceiling,
    /// partial minimum, exact recovery markers, then opaque cursor bytes.
    ///
    /// # Panics
    /// A checkpoint created for an invalid or oversized partition cannot encode.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let partition = self
            .coordinator
            .encode()
            .expect("coordinator identity encodes");
        let mut bytes = Vec::with_capacity(27 + partition.len() + self.cursor.as_bytes().len());
        bytes.push(2);
        bytes.extend_from_slice(
            &u16::try_from(partition.len())
                .expect("partition length fits")
                .to_be_bytes(),
        );
        bytes.extend_from_slice(&partition);
        bytes.extend_from_slice(&self.ceiling_ms.to_be_bytes());
        bytes.extend_from_slice(&self.minimum_ms.to_be_bytes());
        encode_marker(&mut bytes, self.recovery_generation.0.as_ref());
        encode_marker(&mut bytes, self.recovery_generation.1.as_ref());
        bytes.extend_from_slice(self.cursor.as_bytes());
        bytes
    }

    /// Decode a checkpoint supplied by the previous scan step.
    pub fn decode(bytes: &[u8]) -> Result<Self, StoreError> {
        if bytes.len() < 28 || bytes[0] != 2 {
            return Err(StoreError::Invalid("invalid watermark checkpoint".into()));
        }
        let part_len = usize::from(u16::from_be_bytes([bytes[1], bytes[2]]));
        let end = 3usize
            .checked_add(part_len)
            .and_then(|n| n.checked_add(16))
            .ok_or_else(|| StoreError::Invalid("invalid watermark checkpoint length".into()))?;
        if bytes.len() < end + 9 {
            return Err(StoreError::Invalid("truncated watermark checkpoint".into()));
        }
        let partition = bytes
            .get(3..3 + part_len)
            .ok_or_else(|| StoreError::Invalid("truncated coordinator identity".into()))?;
        let coordinator = Partition::decode(partition)?;
        let ceiling_ms = u64::from_be_bytes(
            bytes
                .get(end - 16..end - 8)
                .and_then(|slice| slice.try_into().ok())
                .ok_or_else(|| StoreError::Invalid("truncated watermark ceiling".into()))?,
        );
        let minimum_ms = u64::from_be_bytes(
            bytes
                .get(end - 8..end)
                .and_then(|slice| slice.try_into().ok())
                .ok_or_else(|| StoreError::Invalid("truncated watermark minimum".into()))?,
        );
        if minimum_ms > ceiling_ms {
            return Err(StoreError::Invalid("invalid watermark minimum".into()));
        }
        let mut at = end;
        let recovery = decode_marker(bytes, &mut at)?;
        let reconcile = decode_marker(bytes, &mut at)?;
        if bytes.len() <= at {
            return Err(StoreError::Invalid("truncated watermark cursor".into()));
        }
        recovery
            .as_ref()
            .map(codec::decode_lease_recovery)
            .transpose()?;
        reconcile.as_ref().map(codec::decode_u64).transpose()?;
        Ok(Self {
            coordinator,
            cursor: Cursor::new(bytes[at..].to_vec()),
            ceiling_ms,
            minimum_ms,
            recovery_generation: (recovery, reconcile),
        })
    }
}

/// One bounded scan step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatermarkStep {
    /// More pages remain; resume with this checkpoint.
    Pending(WatermarkCheckpoint),
    /// The namespace lower bound, capped at scan start.
    Complete(u64),
}

/// Check the durable recovery fence before reading a watermark or shard set.
pub async fn check_recovery<S: NamespaceStore>(
    store: &S,
    coordinator: &Partition,
    expected: Option<&RecoveryGeneration>,
) -> Result<RecoveryGeneration, WatermarkError> {
    if !matches!(
        coordinator,
        Partition::Coordinator(_) | Partition::Namespace(_)
    ) {
        return Err(WatermarkError::Store(StoreError::Invalid(
            "watermark requires namespace coordinator".into(),
        )));
    }
    let rows = store
        .get_many(
            coordinator,
            &[keys::lease_recovery(), keys::lease_reconcile()],
        )
        .await?;
    let [recovery, reconcile] = rows.as_slice() else {
        return Err(WatermarkError::Store(StoreError::Corrupt(
            "recovery get_many length".into(),
        )));
    };
    let generation = (recovery.clone(), reconcile.clone());
    if expected.is_some_and(|prior| *prior != generation) {
        return Err(WatermarkError::Store(StoreError::Invalid(
            "watermark checkpoint recovery generation changed".into(),
        )));
    }
    let recovered = recovery
        .as_ref()
        .map(codec::decode_lease_recovery)
        .transpose()?;
    let reconciled = reconcile.as_ref().map(codec::decode_u64).transpose()?;
    if recovered.is_some_and(|lr| reconciled.is_none_or(|at| at <= lr.resumed_at_ms)) {
        return Err(WatermarkError::Recovering);
    }
    Ok(generation)
}

/// Mark the current recovery generation reconciled, only after an external
/// R-116 driver has rebuilt the lease and index tables. A concurrent new
/// recovery defeats the guarded write.
pub async fn mark_lease_table_reconciled<S: NamespaceStore>(
    store: &S,
    coordinator: &Partition,
    at_ms: u64,
) -> Result<(), StoreError> {
    if !matches!(
        coordinator,
        Partition::Coordinator(_) | Partition::Namespace(_)
    ) {
        return Err(StoreError::Invalid(
            "reconciliation requires namespace coordinator".into(),
        ));
    }
    let key = keys::lease_recovery();
    let value = store
        .get(coordinator, &key)
        .await?
        .ok_or_else(|| StoreError::Invalid("no lease recovery to reconcile".into()))?;
    let recovery = codec::decode_lease_recovery(&value)?;
    let later = recovery
        .resumed_at_ms
        .checked_add(1)
        .ok_or_else(|| StoreError::Invalid("lease recovery time has no successor".into()))?;
    let timestamp = at_ms.max(later);
    let batch = Batch::new()
        .require(Precondition::Equals(key, value))
        .put(keys::lease_reconcile(), codec::encode_u64(timestamp));
    match store.apply(coordinator, batch).await? {
        BatchOutcome::Committed => Ok(()),
        _ => Err(StoreError::Corrupt(
            "lease reconciliation raced recovery".into(),
        )),
    }
}

fn decode_shard(
    key: &Key,
    value: &crate::store::Value,
    coordinator: &Partition,
) -> Result<(Partition, u64), StoreError> {
    let Some(keys::ParsedKey::LeasedShard { repo, shard_ref }) = keys::parse(key) else {
        return Err(StoreError::Corrupt("invalid leased shard key".into()));
    };
    let Partition::Coordinator(ns) = coordinator else {
        return Err(StoreError::Invalid(
            "watermark requires coordinator partition".into(),
        ));
    };
    let row = codec::decode_leased_shard(value)?;
    Ok((
        Partition::Ref {
            ns: ns.clone(),
            repo,
            shard_ref,
        },
        row.relay_watermark_ms,
    ))
}

/// Scan one page of the coordinator table. Workers consumers call this
/// resumable step. A new shard can enter behind the cursor only after a new
/// lease grant, so its first relay commit is after the checkpoint ceiling.
/// Existing rows retain their running maximum.
pub async fn namespace_relay_watermark_step<S: NamespaceStore>(
    store: &S,
    coordinator: &Partition,
    now_ms: u64,
    checkpoint: Option<WatermarkCheckpoint>,
    limit: u32,
) -> Result<WatermarkStep, WatermarkError> {
    if !matches!(coordinator, Partition::Coordinator(_)) {
        return Err(WatermarkError::Store(StoreError::Invalid(
            "watermark scan requires coordinator partition".into(),
        )));
    }
    let generation = check_recovery(
        store,
        coordinator,
        checkpoint.as_ref().map(|c| &c.recovery_generation),
    )
    .await?;
    let (start, end) = keys::class_range(keys::TAG_LEASED_SHARD);
    let (cursor, ceiling_ms, mut minimum_ms) = match checkpoint {
        Some(c) if c.coordinator == *coordinator => (Some(c.cursor), c.ceiling_ms, c.minimum_ms),
        Some(_) => {
            return Err(WatermarkError::Store(StoreError::Invalid(
                "watermark checkpoint belongs to another coordinator".into(),
            )));
        }
        None => (None, now_ms, now_ms),
    };
    let page = store
        .scan(coordinator, &start, &end, cursor.as_ref(), limit.max(1))
        .await?;
    for (key, value) in &page.entries {
        minimum_ms = minimum_ms.min(decode_shard(key, value, coordinator)?.1);
    }
    Ok(if let Some(cursor) = page.next {
        WatermarkStep::Pending(WatermarkCheckpoint {
            coordinator: coordinator.clone(),
            cursor,
            ceiling_ms,
            minimum_ms,
            recovery_generation: generation,
        })
    } else {
        check_recovery(store, coordinator, Some(&generation)).await?;
        WatermarkStep::Complete(minimum_ms)
    })
}

/// Minimum of scan-start `now_ms` and all shard maxima. Native consumers may
/// use this full scan; Workers use [`namespace_relay_watermark_step`]. The
/// caller compares it against `T + MAX_APPLY_WINDOW + margin`. It can decrease
/// when a new shard enters with a stale-low report or on restore.
pub async fn namespace_relay_watermark<S: NamespaceStore>(
    store: &S,
    coordinator: &Partition,
    now_ms: u64,
) -> Result<u64, WatermarkError> {
    let mut checkpoint = None;
    loop {
        match namespace_relay_watermark_step(store, coordinator, now_ms, checkpoint, PAGE_SIZE)
            .await?
        {
            WatermarkStep::Pending(next) => checkpoint = Some(next),
            WatermarkStep::Complete(value) => return Ok(value),
        }
    }
}

/// A page of all coordinator ref-shard rows, including expired rows kept for
/// an undelivered outbox. This is the shard set GC must include.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveShardsPage {
    /// Ref shard identities.
    pub shards: Vec<Partition>,
    /// Opaque continuation cursor.
    pub next: Option<Cursor>,
}

/// Scan coordinator shard rows, failing on recovery or any undecodable row.
pub async fn active_shards<S: NamespaceStore>(
    store: &S,
    coordinator: &Partition,
    cursor: Option<&Cursor>,
    limit: u32,
) -> Result<ActiveShardsPage, WatermarkError> {
    if !matches!(coordinator, Partition::Coordinator(_)) {
        return Err(WatermarkError::Store(StoreError::Invalid(
            "shard scan requires coordinator partition".into(),
        )));
    }
    check_recovery(store, coordinator, None).await?;
    let (start, end) = keys::class_range(keys::TAG_LEASED_SHARD);
    let ScanPage { entries, next } = store
        .scan(coordinator, &start, &end, cursor, limit.max(1))
        .await?;
    let shards = entries
        .iter()
        .map(|(key, value)| decode_shard(key, value, coordinator).map(|(p, _)| p))
        .collect::<Result<_, _>>()?;
    Ok(ActiveShardsPage { shards, next })
}

#[cfg(all(test, feature = "memory"))]
mod tests {
    use super::*;
    use crate::memory::MemoryKv;
    use crate::repo::{NamespaceKey, RepoName};
    use crate::store::{Batch, BatchOutcome, PartitionStats, StoreCapabilities, Value};
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    struct RecoverDuringScan {
        inner: Arc<MemoryKv>,
        once: AtomicBool,
    }

    impl NamespaceStore for RecoverDuringScan {
        fn capabilities(&self) -> StoreCapabilities {
            self.inner.capabilities()
        }
        async fn get(&self, p: &Partition, k: &Key) -> Result<Option<Value>, StoreError> {
            self.inner.get(p, k).await
        }
        async fn get_many(
            &self,
            p: &Partition,
            keys: &[Key],
        ) -> Result<Vec<Option<Value>>, StoreError> {
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
            let page = self.inner.scan(p, start, end, after, limit).await?;
            if self.once.swap(false, Ordering::SeqCst) {
                self.inner
                    .apply(
                        p,
                        Batch::new().put(
                            keys::lease_recovery(),
                            codec::encode_lease_recovery(&codec::LeaseRecovery {
                                resumed_at_ms: 110,
                            }),
                        ),
                    )
                    .await?;
            }
            Ok(page)
        }
        async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
            self.inner.apply(p, batch).await
        }
        async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
            self.inner.stats(p).await
        }
        async fn probe(&self) -> Result<(), StoreError> {
            self.inner.probe().await
        }
    }

    fn coordinator() -> Partition {
        Partition::Coordinator(NamespaceKey::deployment_default())
    }
    fn repo(n: u8) -> RepoName {
        RepoName::new(format!("r{n}")).expect("test repository name")
    }
    fn source(n: u8) -> Partition {
        Partition::Ref {
            ns: NamespaceKey::deployment_default(),
            repo: repo(n),
            shard_ref: "refs/heads/main".into(),
        }
    }
    fn lease(watermark: u64, expiry: u64) -> codec::LeasedShard {
        codec::LeasedShard {
            epoch: 1,
            expires_at_ms: expiry,
            acked_epoch: 1,
            relay_watermark_ms: watermark,
            sweep_due_ms: expiry,
        }
    }
    async fn put_lease(store: &MemoryKv, n: u8, watermark: u64, expiry: u64) {
        store
            .apply(
                &coordinator(),
                Batch::new().put(
                    keys::leased_shard(&repo(n), "refs/heads/main"),
                    codec::encode_leased_shard(&lease(watermark, expiry)),
                ),
            )
            .await
            .expect("insert test lease");
    }
    #[tokio::test]
    async fn pages_and_inserts_preserve_scan_start_ceiling() {
        let store = MemoryKv::default();
        put_lease(&store, 0, 40, 200).await;
        put_lease(&store, 2, 90, 200).await;
        let WatermarkStep::Pending(checkpoint) =
            namespace_relay_watermark_step(&store, &coordinator(), 100, None, 1)
                .await
                .unwrap()
        else {
            panic!("first page");
        };
        let encoded = checkpoint.encode();
        let checkpoint = WatermarkCheckpoint::decode(&encoded).unwrap();
        let other = Partition::Coordinator(NamespaceKey::from_stored("another".into()));
        assert!(matches!(
            namespace_relay_watermark_step(&store, &other, 150, Some(checkpoint.clone()), 1).await,
            Err(WatermarkError::Store(StoreError::Invalid(_)))
        ));
        put_lease(&store, 1, 70, 200).await;
        let WatermarkStep::Pending(checkpoint) =
            namespace_relay_watermark_step(&store, &coordinator(), 150, Some(checkpoint), 1)
                .await
                .unwrap()
        else {
            panic!("second page");
        };
        let WatermarkStep::Complete(value) =
            namespace_relay_watermark_step(&store, &coordinator(), 150, Some(checkpoint), 1)
                .await
                .unwrap()
        else {
            panic!("third page");
        };
        assert_eq!(value, 40);
        let page = active_shards(&store, &coordinator(), None, 1)
            .await
            .unwrap();
        assert_eq!(page.shards, vec![source(0)]);
        assert!(page.next.is_some());
    }

    #[tokio::test]
    async fn resume_rejects_a_new_recovery_generation() {
        let store = MemoryKv::default();
        put_lease(&store, 0, 40, 200).await;
        put_lease(&store, 1, 90, 200).await;
        store
            .apply(
                &coordinator(),
                Batch::new()
                    .put(
                        keys::lease_recovery(),
                        codec::encode_lease_recovery(&codec::LeaseRecovery { resumed_at_ms: 90 }),
                    )
                    .put(keys::lease_reconcile(), codec::encode_u64(91)),
            )
            .await
            .unwrap();
        let WatermarkStep::Pending(checkpoint) =
            namespace_relay_watermark_step(&store, &coordinator(), 100, None, 1)
                .await
                .unwrap()
        else {
            panic!("first page");
        };
        let checkpoint = WatermarkCheckpoint::decode(&checkpoint.encode()).unwrap();
        store
            .apply(
                &coordinator(),
                Batch::new()
                    .put(
                        keys::lease_recovery(),
                        codec::encode_lease_recovery(&codec::LeaseRecovery { resumed_at_ms: 110 }),
                    )
                    .put(keys::lease_reconcile(), codec::encode_u64(111)),
            )
            .await
            .unwrap();
        assert!(matches!(
            namespace_relay_watermark_step(
                &store,
                &coordinator(),
                120,
                Some(checkpoint.clone()),
                1
            )
            .await,
            Err(WatermarkError::Store(StoreError::Invalid(_)))
        ));
        store
            .apply(
                &coordinator(),
                Batch::new()
                    .put(
                        keys::lease_recovery(),
                        codec::encode_lease_recovery(&codec::LeaseRecovery { resumed_at_ms: 130 }),
                    )
                    .delete(keys::lease_reconcile()),
            )
            .await
            .unwrap();
        assert!(matches!(
            namespace_relay_watermark_step(
                &store,
                &coordinator(),
                140,
                Some(checkpoint.clone()),
                1
            )
            .await,
            Err(WatermarkError::Store(StoreError::Invalid(_)))
        ));
        store
            .apply(
                &coordinator(),
                Batch::new().put(keys::lease_recovery(), Value::new(&b"corrupt marker"[..])),
            )
            .await
            .unwrap();
        assert!(matches!(
            namespace_relay_watermark_step(&store, &coordinator(), 150, Some(checkpoint), 1).await,
            Err(WatermarkError::Store(StoreError::Invalid(_)))
        ));
    }

    #[tokio::test]
    async fn final_page_rechecks_recovery_generation() {
        let inner = Arc::new(MemoryKv::default());
        put_lease(inner.as_ref(), 0, 40, 200).await;
        let store = RecoverDuringScan {
            inner,
            once: AtomicBool::new(true),
        };
        assert!(matches!(
            namespace_relay_watermark_step(&store, &coordinator(), 100, None, 10).await,
            Err(WatermarkError::Store(StoreError::Invalid(_)))
        ));
    }

    #[tokio::test]
    async fn a_new_row_behind_the_cursor_is_excluded_by_the_scan_ceiling() {
        let store = MemoryKv::default();
        put_lease(&store, 1, 80, 200).await;
        put_lease(&store, 2, 90, 200).await;
        let WatermarkStep::Pending(checkpoint) =
            namespace_relay_watermark_step(&store, &coordinator(), 100, None, 1)
                .await
                .unwrap()
        else {
            panic!("first page");
        };
        put_lease(&store, 0, 0, 200).await;
        let WatermarkStep::Complete(value) =
            namespace_relay_watermark_step(&store, &coordinator(), 120, Some(checkpoint), 1)
                .await
                .unwrap()
        else {
            panic!("last page");
        };
        assert_eq!(value, 80);
        assert!(value <= 100, "the scan-start ceiling remains binding");
    }

    #[tokio::test]
    async fn corruption_and_recovery_fail_closed() {
        let store = MemoryKv::default();
        store
            .apply(
                &coordinator(),
                Batch::new().put(
                    keys::leased_shard(&repo(0), "refs/heads/main"),
                    Value::new(&b"bad"[..]),
                ),
            )
            .await
            .unwrap();
        assert!(matches!(
            namespace_relay_watermark(&store, &coordinator(), 100).await,
            Err(WatermarkError::Store(StoreError::Corrupt(_)))
        ));
        assert!(
            active_shards(&store, &coordinator(), None, 10)
                .await
                .is_err()
        );
        store
            .apply(
                &coordinator(),
                Batch::new().put(
                    keys::lease_recovery(),
                    codec::encode_lease_recovery(&codec::LeaseRecovery { resumed_at_ms: 100 }),
                ),
            )
            .await
            .unwrap();
        assert!(matches!(
            namespace_relay_watermark(&store, &coordinator(), 200).await,
            Err(WatermarkError::Recovering)
        ));
        mark_lease_table_reconciled(&store, &coordinator(), 101)
            .await
            .unwrap();
        assert!(matches!(
            namespace_relay_watermark(&store, &coordinator(), 200).await,
            Err(WatermarkError::Store(StoreError::Corrupt(_)))
        ));
    }
}
