//! Local durable publication-maintenance barriers, outside portable KV export.
//! These receipts prove a local pause only, never inventory completeness or
//! permission to seal a publication root. Target admission provides guarded resume.
use super::{SqlConn, SqlError, SqlKvStore, SqlValue};
use mkit_server::store::adapter_spi::publication_fence::Generation;
use mkit_server::{Partition, StoreError};

const TABLE_PRESENT: &str =
    "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'mkit_publication_pause'";
const CREATE: &str = "CREATE TABLE IF NOT EXISTS mkit_publication_pause (part BLOB PRIMARY KEY NOT NULL, generation BLOB NOT NULL) WITHOUT ROWID";
const GET: &str = "SELECT generation FROM mkit_publication_pause WHERE part = ?1";
const PUT: &str = "INSERT INTO mkit_publication_pause (part, generation) VALUES (?1, ?2) ON CONFLICT (part) DO UPDATE SET generation = excluded.generation";
const MAX_GENERATION_BYTES: usize = 512;
const MAX_PARTITION_BYTES: usize = 4 * 1024;

pub(super) fn encoded_generation(generation: &Generation) -> Result<Vec<u8>, SqlError> {
    let mut value = vec![1];
    value.extend(
        serde_json::to_vec(generation)
            .map_err(|_| SqlError::Corrupt("publication pause generation"))?,
    );
    if value.len() > MAX_GENERATION_BYTES {
        return Err(SqlError::Corrupt("publication pause generation bound"));
    }
    Ok(value)
}
pub(super) fn read<C: SqlConn>(conn: &C, part: &SqlValue) -> Result<Option<Generation>, SqlError> {
    if conn.query(TABLE_PRESENT, &[])?.is_empty() {
        return Ok(None);
    }
    let rows = conn.query(GET, std::slice::from_ref(part))?;
    if rows.len() > 1 {
        return Err(SqlError::Corrupt("duplicate publication pause"));
    }
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    let Some(SqlValue::Blob(raw)) = row.first() else {
        return Err(SqlError::Corrupt("publication pause generation column"));
    };
    if raw.len() > MAX_GENERATION_BYTES || raw.first() != Some(&1) {
        return Err(SqlError::Corrupt("publication pause generation version"));
    }
    let generation: Generation = serde_json::from_slice(&raw[1..])
        .map_err(|_| SqlError::Corrupt("publication pause generation"))?;
    if encoded_generation(&generation)?.as_slice() != raw {
        return Err(SqlError::Corrupt("noncanonical publication pause"));
    }
    Ok(Some(generation))
}

pub(super) fn reject_paused_writes<C: SqlConn>(
    conn: &C,
    part: &SqlValue,
    batch: &mkit_server::Batch,
) -> Result<(), SqlError> {
    if !batch.writes.is_empty() && read(conn, part)?.is_some() {
        return Err(SqlError::PublicationPaused);
    }
    Ok(())
}

/// Evidence from a committed local maintenance transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PauseReceipt {
    partition: Partition,
    generation: Generation,
}
impl PauseReceipt {
    /// Logical partition touched by the responding executor.
    #[must_use]
    pub fn partition(&self) -> &Partition {
        &self.partition
    }
    /// External recovery identity bound into its local barrier.
    #[must_use]
    pub fn generation(&self) -> Generation {
        self.generation
    }
}
impl<C: SqlConn> SqlKvStore<C> {
    /// Pause under a trusted external generation and expected previous identity.
    /// Calling this does not grant a global bootstrap receipt.
    pub fn pause_publication(
        &self,
        partition: &Partition,
        previous: Option<Generation>,
        generation: Generation,
    ) -> Result<PauseReceipt, StoreError> {
        let encoded = partition.encode()?.to_vec();
        if encoded.len() > MAX_PARTITION_BYTES {
            return Err(StoreError::Invalid(
                "publication pause partition bound".into(),
            ));
        }
        let part = SqlValue::Blob(encoded);
        let value = SqlValue::Blob(encoded_generation(&generation)?);
        let soft_limit = self.metadata_soft_limit();
        self.conn().transaction(Box::new(move |conn| {
            let current = read(&conn, &part)?;
            if current == Some(generation) {
                return Ok(());
            }
            if current != previous {
                return Err(SqlError::Constraint);
            }
            // Metadata cannot consume the reserve needed by pruning. Exact
            // retries above returned without writing, even at the soft cap.
            if let Some(limit) = soft_limit
                && conn.size_bytes()? >= limit
            {
                return Err(SqlError::Full);
            }
            conn.exec(CREATE, &[])?;
            conn.exec(PUT, &[part, value])?;
            Ok(())
        }))?;
        Ok(PauseReceipt {
            partition: partition.clone(),
            generation,
        })
    }
    /// Fresh local pause observation. It is not an external incarnation proof.
    pub fn publication_paused(&self, partition: &Partition) -> Result<bool, StoreError> {
        Ok(read(self.conn(), &SqlValue::Blob(partition.encode()?.to_vec()))?.is_some())
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::test_sqlite::RusqliteConn;
    use futures::executor::block_on;
    use mkit_server::{Batch, BatchOutcome, Key, NamespaceKey, NamespaceStore, Value};
    fn generation(number: u64) -> Generation {
        Generation {
            incarnation: [43; 32],
            number,
        }
    }
    #[test]
    fn persisted_pause_generation_matches_version_one_golden() {
        let conn = RusqliteConn::open_in_memory().unwrap();
        let store = SqlKvStore::open(conn.clone()).unwrap();
        let part = Partition::Namespace(NamespaceKey::deployment_default());
        store.pause_publication(&part, None, generation(1)).unwrap();
        let golden =
            include_str!("../../../../tests/golden/publication-fence/pause-generation-v1.json");
        let mut expected = vec![1];
        expected.extend_from_slice(golden.trim_end().as_bytes());
        let rows = conn
            .query(GET, &[SqlValue::Blob(part.encode().unwrap().to_vec())])
            .unwrap();
        assert_eq!(rows, vec![vec![SqlValue::Blob(expected)]]);
    }
    #[test]
    fn pause_metadata_preserves_capacity_reserve_and_exact_retries() {
        use super::super::Capacity;
        block_on(async {
            for existing_pause in [false, true] {
                let conn = RusqliteConn::open_in_memory().unwrap();
                // Deliberately small physical cap to exercise admission with
                // real SQLite pages rather than mocking a reported size.
                let store = SqlKvStore::open_with_capacity(
                    conn.clone(),
                    Capacity::new(1 << 20).with_reserve(1 << 19),
                )
                .unwrap();
                let paused = Partition::Namespace(NamespaceKey::deployment_default());
                let writable = Partition::Coordinator(NamespaceKey::deployment_default());
                let prior = if existing_pause {
                    Some(
                        store
                            .pause_publication(&paused, None, generation(1))
                            .unwrap(),
                    )
                } else {
                    None
                };
                let mut reached_cap = false;
                for index in 0u32..128 {
                    let result = store
                        .apply(
                            &writable,
                            Batch::new().put(
                                Key::new(index.to_be_bytes().to_vec()),
                                Value::new(vec![7; 16 * 1024]),
                            ),
                        )
                        .await;
                    match result {
                        Ok(BatchOutcome::Committed) => {}
                        Err(StoreError::Full) => {
                            reached_cap = true;
                            break;
                        }
                        other => panic!("unexpected fill outcome: {other:?}"),
                    }
                }
                assert!(reached_cap);
                let bytes_before = conn.size_bytes().unwrap();
                let previous = existing_pause.then_some(generation(1));
                assert!(
                    matches!(
                        store.pause_publication(&paused, previous, generation(2)),
                        Err(StoreError::Full)
                    ),
                    "new or changed pause metadata must not consume the pruning reserve"
                );
                assert_eq!(conn.size_bytes().unwrap(), bytes_before);
                if let Some(prior) = prior {
                    assert_eq!(
                        store
                            .pause_publication(&paused, None, generation(1))
                            .unwrap(),
                        prior
                    );
                    assert_eq!(conn.size_bytes().unwrap(), bytes_before);
                } else {
                    assert!(
                        conn.query(TABLE_PRESENT, &[]).unwrap().is_empty(),
                        "capacity refusal must precede even lazy table creation"
                    );
                }
                assert_eq!(
                    store
                        .apply(
                            &writable,
                            Batch::new().delete(Key::new(0u32.to_be_bytes().to_vec()))
                        )
                        .await
                        .unwrap(),
                    BatchOutcome::Committed
                );
                assert!(
                    store
                        .get(&writable, &Key::new(0u32.to_be_bytes().to_vec()))
                        .await
                        .unwrap()
                        .is_none()
                );
            }
        });
    }
    #[test]
    fn durable_pause_rejects_prepared_writes_and_survives_reopen() {
        block_on(async {
            let conn = RusqliteConn::open_in_memory().unwrap();
            let first = SqlKvStore::open(conn.clone()).unwrap();
            let already_open = SqlKvStore::open(conn.clone()).unwrap();
            let part = Partition::Namespace(NamespaceKey::deployment_default());
            let write = Batch::new().put(Key::new(b"value".to_vec()), Value::new(vec![1]));
            assert_eq!(
                first.apply(&part, write.clone()).await.unwrap(),
                BatchOutcome::Committed
            );
            let receipt = first.pause_publication(&part, None, generation(1)).unwrap();
            assert_eq!(receipt.partition(), &part);
            assert_eq!(receipt.generation(), generation(1));
            for store in [&first, &already_open, &SqlKvStore::open(conn).unwrap()] {
                assert!(matches!(
                    store.apply(&part, write.clone()).await,
                    Err(StoreError::Unavailable(_))
                ));
                assert_eq!(
                    store
                        .get(&part, &Key::new(b"value".to_vec()))
                        .await
                        .unwrap(),
                    Some(Value::new(vec![1]))
                );
            }
        });
    }
    #[test]
    fn pause_identity_retries_are_idempotent_and_rebinding_cannot_overwrite() {
        let store = SqlKvStore::open(RusqliteConn::open_in_memory().unwrap()).unwrap();
        let part = Partition::Namespace(NamespaceKey::deployment_default());
        let first = store.pause_publication(&part, None, generation(1)).unwrap();
        assert_eq!(
            store.pause_publication(&part, None, generation(1)).unwrap(),
            first
        );
        assert!(store.pause_publication(&part, None, generation(2)).is_err());
        assert_eq!(
            store
                .pause_publication(&part, Some(generation(1)), generation(2))
                .unwrap()
                .generation(),
            generation(2)
        );
        assert!(
            store
                .pause_publication(&part, Some(generation(1)), generation(3))
                .is_err()
        );
    }
    #[test]
    fn paused_transaction_extensions_cannot_introduce_writes() {
        let store = SqlKvStore::open(RusqliteConn::open_in_memory().unwrap()).unwrap();
        let part = Partition::Namespace(NamespaceKey::deployment_default());
        store.pause_publication(&part, None, generation(1)).unwrap();
        assert!(matches!(
            store.apply_extended(&part, Batch::new(), |_, batch, _| {
                batch.writes.push(mkit_server::Write::Put(
                    Key::new(b"late".to_vec()),
                    Value::new(vec![1]),
                ));
                Ok(())
            }),
            Err(StoreError::Unavailable(_))
        ));
    }
    #[test]
    fn portable_import_cannot_restore_or_clear_the_local_pause() {
        use mkit_server::store::{ImportMode, Importer, export_header, export_page};
        block_on(async {
            let donor = mkit_server::MemoryKv::default();
            let target = SqlKvStore::open(RusqliteConn::open_in_memory().unwrap()).unwrap();
            let part = Partition::Namespace(NamespaceKey::deployment_default());
            let key = Key::new(b"restored".to_vec());
            donor
                .apply(&part, Batch::new().put(key.clone(), Value::new(vec![7])))
                .await
                .unwrap();
            target
                .pause_publication(&part, None, generation(1))
                .unwrap();
            assert!(
                export_page(&target, &part, None, 100)
                    .await
                    .unwrap()
                    .records
                    .is_empty(),
                "pause metadata is outside SDK KV export"
            );
            let header = export_header(&donor, &part, 1_000).await.unwrap();
            let records = export_page(&donor, &part, None, 100).await.unwrap().records;
            for mode in [ImportMode::Fresh, ImportMode::Merge] {
                let mut importer = Importer::new(&target, &header, mode).unwrap();
                for record in records.clone() {
                    importer.push(record).await.unwrap();
                }
                assert!(matches!(
                    importer.finish().await,
                    Err(StoreError::Unavailable(_))
                ));
                assert!(target.publication_paused(&part).unwrap());
                assert!(target.get(&part, &key).await.unwrap().is_none());
            }
            let other = Partition::Coordinator(NamespaceKey::deployment_default());
            assert_eq!(
                target
                    .apply(&other, Batch::new().put(key, Value::new(vec![2])))
                    .await
                    .unwrap(),
                BatchOutcome::Committed
            );
        });
    }
    #[test]
    fn malformed_pause_metadata_cannot_be_overwritten_or_allow_writes() {
        block_on(async {
            let conn = RusqliteConn::open_in_memory().unwrap();
            let store = SqlKvStore::open(conn.clone()).unwrap();
            let part = Partition::Namespace(NamespaceKey::deployment_default());
            store.pause_publication(&part, None, generation(1)).unwrap();
            conn.exec(
                PUT,
                &[
                    SqlValue::Blob(part.encode().unwrap().to_vec()),
                    SqlValue::Blob(vec![2]),
                ],
            )
            .unwrap();
            assert!(matches!(
                store.publication_paused(&part),
                Err(StoreError::Corrupt(_))
            ));
            assert!(
                store
                    .pause_publication(&part, Some(generation(1)), generation(2))
                    .is_err()
            );
            assert!(matches!(
                store
                    .apply(
                        &part,
                        Batch::new().put(Key::new(b"blocked".to_vec()), Value::new(vec![2]))
                    )
                    .await,
                Err(StoreError::Corrupt(_))
            ));
        });
    }
}
