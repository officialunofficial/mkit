//! Coordinator relay watermark and shard enumeration. Consumers add their
//! lease clock margin to the threshold they compare against this value.
//! Recovery may reset maxima, so the result is not monotonic across restore.

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
    cursor: Cursor,
    ceiling_ms: u64,
    minimum_ms: u64,
}

impl WatermarkCheckpoint {
    /// Stable binary form: version, scan ceiling, partial minimum, cursor bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(17 + self.cursor.as_bytes().len());
        bytes.push(1);
        bytes.extend_from_slice(&self.ceiling_ms.to_be_bytes());
        bytes.extend_from_slice(&self.minimum_ms.to_be_bytes());
        bytes.extend_from_slice(self.cursor.as_bytes());
        bytes
    }

    /// Decode a checkpoint supplied by the previous scan step.
    pub fn decode(bytes: &[u8]) -> Result<Self, StoreError> {
        if bytes.len() <= 17 || bytes[0] != 1 {
            return Err(StoreError::Invalid("invalid watermark checkpoint".into()));
        }
        let ceiling_ms = u64::from_be_bytes(bytes[1..9].try_into().expect("eight bytes"));
        let minimum_ms = u64::from_be_bytes(bytes[9..17].try_into().expect("eight bytes"));
        if minimum_ms > ceiling_ms {
            return Err(StoreError::Invalid("invalid watermark minimum".into()));
        }
        Ok(Self {
            cursor: Cursor::new(bytes[17..].to_vec()),
            ceiling_ms,
            minimum_ms,
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
) -> Result<(), WatermarkError> {
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
    let recovered = recovery
        .as_ref()
        .map(codec::decode_lease_recovery)
        .transpose()?;
    let reconciled = reconcile.as_ref().map(codec::decode_u64).transpose()?;
    if recovered.is_some_and(|lr| reconciled.is_none_or(|at| at <= lr.resumed_at_ms)) {
        return Err(WatermarkError::Recovering);
    }
    Ok(())
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

/// Scan one page of the coordinator table. A new shard can enter behind the
/// cursor only after a new lease grant, so its first relay commit is after
/// the checkpoint ceiling. Existing rows retain their running maximum.
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
    check_recovery(store, coordinator).await?;
    let (start, end) = keys::class_range(keys::TAG_LEASED_SHARD);
    let (cursor, ceiling_ms, mut minimum_ms) = match checkpoint {
        Some(c) => (Some(c.cursor), c.ceiling_ms, c.minimum_ms),
        None => (None, now_ms, now_ms),
    };
    let page = store
        .scan(coordinator, &start, &end, cursor.as_ref(), limit.max(1))
        .await?;
    for (key, value) in &page.entries {
        minimum_ms = minimum_ms.min(decode_shard(key, value, coordinator)?.1);
    }
    Ok(match page.next {
        Some(cursor) => WatermarkStep::Pending(WatermarkCheckpoint {
            cursor,
            ceiling_ms,
            minimum_ms,
        }),
        None => WatermarkStep::Complete(minimum_ms),
    })
}

/// Minimum of scan-start `now_ms` and all shard maxima. The caller adds the
/// lease clock margin to its safety threshold. This may decrease on restore.
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
    check_recovery(store, coordinator).await?;
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
    use crate::store::{Batch, Value};
    use proptest::prelude::*;

    fn coordinator() -> Partition {
        Partition::Coordinator(NamespaceKey::deployment_default())
    }
    fn repo(n: u8) -> RepoName {
        RepoName::new(format!("r{n}")).unwrap()
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
            .unwrap();
    }
    async fn put_relay(store: &MemoryKv, n: u8, seq: u64, at_ms: u64) {
        let value = codec::encode_relay(&codec::RelayV1 {
            at_ms,
            target: coordinator(),
            puts: vec![(Key::new(&b"x\0"[..]), Value::default())],
        })
        .unwrap();
        store
            .apply(&source(n), Batch::new().put(keys::relay(seq), value))
            .await
            .unwrap();
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

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]
        #[test]
        fn random_interleavings_never_pass_an_undelivered_commit(actions in prop::collection::vec((0u8..5, 0u8..3, 1u8..8), 40..150)) {
            futures_executor::block_on(async {
                let store = MemoryKv::default();
                let mut now = 100u64;
                let mut next_seq = [0u64; 3];
                let mut undelivered = Vec::<(u8, u64, u64)>::new();
                for (action, n, step) in actions {
                    now += u64::from(step);
                    let key = keys::leased_shard(&repo(n), "refs/heads/main");
                    match action {
                        0 => {
                            let report = crate::relay::relay_watermark(&store, &source(n), now).await.unwrap();
                            let old = store.get(&coordinator(), &key).await.unwrap().map(|v| codec::decode_leased_shard(&v).unwrap());
                            put_lease(&store, n, old.map_or(report, |l| l.relay_watermark_ms.max(report)), now + 20).await;
                            next_seq[usize::from(n)] += 1;
                            let seq = next_seq[usize::from(n)];
                            put_relay(&store, n, seq, now).await;
                            undelivered.push((n, seq, now));
                        }
                        1 => {
                            let report = crate::relay::relay_watermark(&store, &source(n), now).await.unwrap();
                            let old = store.get(&coordinator(), &key).await.unwrap().map(|v| codec::decode_leased_shard(&v).unwrap());
                            if let Some(old) = old {
                                put_lease(&store, n, old.relay_watermark_ms.max(report), now + 20).await;
                            }
                        }
                        2 => {
                            if let Some(pos) = undelivered.iter().position(|(shard, _, _)| *shard == n) {
                                let (_, seq, _) = undelivered.remove(pos);
                                store.apply(&source(n), Batch::new().delete(keys::relay(seq))).await.unwrap();
                            }
                        }
                        3 => {
                            if let Some(value) = store.get(&coordinator(), &key).await.unwrap() {
                                let mut old = codec::decode_leased_shard(&value).unwrap();
                                if old.expires_at_ms <= now {
                                    let (report, empty) = crate::relay::source_relay_state(&store, &source(n), now).await.unwrap();
                                    if empty {
                                        store.apply(&coordinator(), Batch::new().delete(key)).await.unwrap();
                                    } else {
                                        old.relay_watermark_ms = old.relay_watermark_ms.max(report);
                                        old.sweep_due_ms = now + 10;
                                        store.apply(&coordinator(), Batch::new().put(key, codec::encode_leased_shard(&old))).await.unwrap();
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                    let watermark = namespace_relay_watermark(&store, &coordinator(), now).await.unwrap();
                    for &(_, _, committed_at) in &undelivered {
                        prop_assert!(watermark <= committed_at, "watermark {watermark} passed undelivered commit {committed_at}");
                    }
                }
                Ok(())
            })?;
        }
    }
}
