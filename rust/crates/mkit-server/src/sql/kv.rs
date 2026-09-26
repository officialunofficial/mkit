//! `SqlKvStore`: the [`NamespaceStore`] contract over one `kv` table.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Mutex, PoisonError};

use super::{Capacity, Row, SqlConn, SqlError, SqlValue, TxFn, blob, count, schema};
use crate::store::{
    Batch, BatchOutcome, Cursor, Key, NamespaceStore, Partition, PartitionStats, Precondition,
    ScanPage, StoreCapabilities, StoreError, StoreMaintenance, Value, Write,
};

/// Keys per `get_many` statement: one partition parameter plus this many
/// keys stays far below [`super::MAX_BOUND_PARAMS`].
pub const GET_MANY_CHUNK: usize = 64;

/// How long a partition's [`NamespaceStore::stats`] is cached, ms.
const STATS_TTL_MS: u64 = 60_000;
/// Most partitions whose stats are cached at once.
const STATS_CACHE_MAX: usize = 4096;

pub(super) const GET: &str = "SELECT value FROM kv WHERE part = ?1 AND key = ?2";
pub(super) const PUT: &str = "INSERT INTO kv (part, key, value) VALUES (?1, ?2, ?3) \
     ON CONFLICT (part, key) DO UPDATE SET value = excluded.value";
pub(super) const DELETE: &str = "DELETE FROM kv WHERE part = ?1 AND key = ?2";
pub(super) const SCAN_FROM: &str = "SELECT key, value FROM kv \
     WHERE part = ?1 AND key >= ?2 AND key < ?3 ORDER BY key LIMIT ?4";
pub(super) const SCAN_AFTER: &str = "SELECT key, value FROM kv \
     WHERE part = ?1 AND key > ?2 AND key < ?3 ORDER BY key LIMIT ?4";
pub(super) const STATS: &str =
    "SELECT COUNT(*), SUM(length(key) + length(value)) FROM kv WHERE part = ?1";
pub(super) const PROBE: &str = "SELECT 1";

/// The `get_many` statement for `n` keys (`?2` … `?{n+1}`).
pub(super) fn get_many_sql(n: usize) -> String {
    let marks: Vec<String> = (2..n + 2).map(|i| format!("?{i}")).collect();
    format!(
        "SELECT key, value FROM kv WHERE part = ?1 AND key IN ({})",
        marks.join(", ")
    )
}

/// The [`NamespaceStore`] contract (and [`StoreMaintenance`]) over any
/// [`SqlConn`]: full capabilities, every batch one [`SqlConn::transaction`].
///
/// With a [`Capacity`], a batch holding a put returns [`StoreError::Full`]
/// once the database uses [`Capacity::soft_limit`] bytes or more, checked
/// inside its transaction; delete-only batches are never refused, and the
/// reserve above the soft limit keeps them from hitting the engine limit
/// (normative rule 7). An engine `Full` on a delete-only batch is reported
/// as [`StoreError::Unavailable`], never `Full`.
///
/// Every method is synchronous inside: its future completes on first poll.
/// On a native server wrap it in `mkit-server-native`'s `Blocking`, which
/// runs each call on a blocking thread.
pub struct SqlKvStore<C> {
    conn: C,
    schema_version: AtomicU32,
    stats: Mutex<HashMap<Vec<u8>, (u64, PartitionStats)>>,
    capacity: Option<Capacity>,
}

impl<C> fmt::Debug for SqlKvStore<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SqlKvStore")
            .field(
                "schema_version",
                &self.schema_version.load(Ordering::Relaxed),
            )
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
    }
}

impl<C: SqlConn> SqlKvStore<C> {
    /// A store over `conn`, after migrating its schema
    /// ([`schema::migrate`]).
    ///
    /// # Errors
    /// [`StoreError::Unsupported`] for a database with a newer schema than
    /// this binary's; the engine's error otherwise.
    pub fn open(conn: C) -> Result<Self, StoreError> {
        let version = schema::migrate(&conn)?;
        Ok(Self {
            conn,
            schema_version: AtomicU32::new(version),
            stats: Mutex::default(),
            capacity: None,
        })
    }

    /// [`Self::open`], capped at `capacity`: the connection enforces the
    /// hard cap ([`SqlConn::set_size_limit`]) and the store the soft limit.
    ///
    /// # Errors
    /// As [`Self::open`].
    pub fn open_with_capacity(conn: C, capacity: Capacity) -> Result<Self, StoreError> {
        let mut store = Self::open(conn)?;
        store.conn.set_size_limit(capacity.cap_bytes())?;
        store.capacity = Some(capacity);
        Ok(store)
    }

    /// The cap, if any.
    #[must_use]
    pub fn capacity(&self) -> Option<Capacity> {
        self.capacity
    }

    /// The connection.
    #[must_use]
    pub fn conn(&self) -> &C {
        &self.conn
    }

    /// Forget cached [`NamespaceStore::stats`], so the next call reads the
    /// table.
    pub fn clear_stats_cache(&self) {
        self.stats
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
    }
}

fn part(p: &Partition) -> Result<SqlValue, StoreError> {
    Ok(SqlValue::Blob(p.encode()?.to_vec()))
}

fn key_param(key: &Key) -> SqlValue {
    SqlValue::Blob(key.as_bytes().to_vec())
}

fn read<C: SqlConn>(conn: &C, part: &SqlValue, key: &Key) -> Result<Option<Value>, SqlError> {
    let mut rows = conn.query(GET, &[part.clone(), key_param(key)])?;
    rows.first_mut()
        .map(|row| blob(row, 0).map(Value::new))
        .transpose()
}

/// The transaction body of `apply`: read the backend clock once, check the
/// preconditions in order, refuse a batch with a put at the soft limit,
/// then write.
fn check_and_write<C: SqlConn>(
    conn: &C,
    part: &SqlValue,
    batch: Batch,
    soft_limit: Option<u64>,
) -> Result<BatchOutcome, SqlError> {
    // Rule 8: the backend's own clock, read inside the transaction.
    let now = conn.now_ms();
    for (index, pre) in batch.preconditions.iter().enumerate() {
        let (holds, observed) = match pre {
            Precondition::NotAfter(deadline) if now > *deadline => {
                return Ok(BatchOutcome::DeadlinePassed { backend_now: now });
            }
            Precondition::NotAfter(_) => continue,
            Precondition::Absent(key) => {
                let current = read(conn, part, key)?;
                (current.is_none(), current)
            }
            Precondition::Present(key) => (read(conn, part, key)?.is_some(), None),
            Precondition::Equals(key, value) => {
                let current = read(conn, part, key)?;
                (current.as_ref() == Some(value), current)
            }
        };
        if !holds {
            return Ok(BatchOutcome::PreconditionFailed { index, observed });
        }
    }
    if let Some(limit) = soft_limit
        && batch.has_put()
        && conn.size_bytes()? >= limit
    {
        return Err(SqlError::Full);
    }
    for write in batch.writes {
        match write {
            Write::Put(key, value) => {
                let value = SqlValue::Blob(value.into_bytes().into());
                conn.exec(PUT, &[part.clone(), key_param(&key), value])?
            }
            Write::Delete(key) => conn.exec(DELETE, &[part.clone(), key_param(&key)])?,
        };
    }
    Ok(BatchOutcome::Committed)
}

fn entry(mut row: Row) -> Result<(Key, Value), SqlError> {
    Ok((Key::new(blob(&mut row, 0)?), Value::new(blob(&mut row, 1)?)))
}

impl<C: SqlConn> NamespaceStore for SqlKvStore<C> {
    fn capabilities(&self) -> StoreCapabilities {
        StoreCapabilities::full()
    }

    async fn get(&self, p: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
        Ok(read(&self.conn, &part(p)?, key)?)
    }

    async fn get_many(
        &self,
        p: &Partition,
        keys: &[Key],
    ) -> Result<Vec<Option<Value>>, StoreError> {
        let part = part(p)?;
        let mut found: HashMap<Vec<u8>, Value> = HashMap::new();
        for chunk in keys.chunks(GET_MANY_CHUNK) {
            let params: Vec<SqlValue> = core::iter::once(part.clone())
                .chain(chunk.iter().map(key_param))
                .collect();
            for row in self.conn.query(&get_many_sql(chunk.len()), &params)? {
                let (key, value) = entry(row)?;
                found.insert(key.into_bytes().into(), value);
            }
        }
        Ok(keys
            .iter()
            .map(|key| found.get(key.as_bytes()).cloned())
            .collect())
    }

    async fn scan(
        &self,
        p: &Partition,
        start: &Key,
        end: &Key,
        after: Option<&Cursor>,
        limit: u32,
    ) -> Result<ScanPage, StoreError> {
        if limit == 0 {
            return Err(StoreError::Invalid("scan limit must be at least 1".into()));
        }
        let (sql, lower) = match after {
            None => (SCAN_FROM, start.as_bytes()),
            // Every cursor this range returns is one of its keys.
            Some(c) if start.as_bytes() <= c.as_bytes() && c.as_bytes() < end.as_bytes() => {
                (SCAN_AFTER, c.as_bytes())
            }
            Some(_) => {
                return Err(StoreError::Invalid(
                    "scan cursor outside the scanned range".into(),
                ));
            }
        };
        if lower >= end.as_bytes() {
            return Ok(ScanPage::default());
        }
        let params = [
            part(p)?,
            SqlValue::Blob(lower.to_vec()),
            key_param(end),
            SqlValue::Integer(i64::from(limit) + 1),
        ];
        let mut entries = self
            .conn
            .query(sql, &params)?
            .into_iter()
            .map(entry)
            .collect::<Result<Vec<_>, _>>()?;
        let want = usize::try_from(limit).unwrap_or(usize::MAX);
        let next = (entries.len() > want).then(|| {
            entries.truncate(want);
            Cursor::new(entries[want - 1].0.clone().into_bytes())
        });
        Ok(ScanPage { entries, next })
    }

    async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        batch.validate(&self.capabilities())?;
        let part = part(p)?;
        let adds = batch.has_put();
        let soft_limit = self.capacity.map(|c| c.soft_limit());
        // The batch and the partition move into the owned transaction body.
        let body: TxFn<C, BatchOutcome> =
            Box::new(move |conn: C| check_and_write(&conn, &part, batch, soft_limit));
        match self.conn.transaction(body) {
            Ok(outcome) => Ok(outcome),
            // Rule 7: a delete-only batch never reports `Full`. Reaching
            // the engine limit here means the reserve was too small; the
            // batch rolled back.
            Err(SqlError::Full) if !adds => Err(StoreError::unavailable(
                "database full during a delete-only batch",
            )),
            Err(e) => Err(e.into()),
        }
    }

    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        let name = p.encode()?.to_vec();
        let now = self.conn.now_ms();
        let fresh = |at: u64| at <= now && now - at < STATS_TTL_MS;
        {
            let cache = self.stats.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some((at, stats)) = cache.get(&name)
                && fresh(*at)
            {
                return Ok(*stats);
            }
        }
        let rows = self.conn.query(STATS, &[SqlValue::Blob(name.clone())])?;
        let row = rows
            .first()
            .ok_or(SqlError::Corrupt("stats returned no row"))?;
        let stats = PartitionStats {
            bytes: count(row, 1)?,
            keys: Some(count(row, 0)?),
        };
        let mut cache = self.stats.lock().unwrap_or_else(PoisonError::into_inner);
        if cache.len() >= STATS_CACHE_MAX {
            cache.retain(|_, (at, _)| fresh(*at));
            if cache.len() >= STATS_CACHE_MAX {
                cache.clear();
            }
        }
        cache.insert(name, (now, stats));
        Ok(stats)
    }

    async fn probe(&self) -> Result<(), StoreError> {
        self.conn.query(PROBE, &[])?;
        Ok(())
    }
}

impl<C: SqlConn> StoreMaintenance for SqlKvStore<C> {
    fn layout_version(&self) -> u32 {
        self.schema_version.load(Ordering::Relaxed)
    }

    async fn migrate(&self) -> Result<u32, StoreError> {
        let version = schema::migrate(&self.conn)?;
        self.schema_version.store(version, Ordering::Relaxed);
        Ok(version)
    }

    /// The connection's backup ([`SqlConn::backup_to`]):
    /// [`StoreError::Unsupported`] unless the backend has one.
    async fn backup_to(&self, dest: &str) -> Result<(), StoreError> {
        self.conn.backup_to(dest)
    }
}
