//! `RusqliteConn`: the [`SqlConn`] over a local `SQLite` file (rusqlite,
//! with `SQLite` bundled).

use std::cell::Cell;
use std::fmt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use mkit_server::sql::{
    GET_MANY_CHUNK, Row, SqlConn, SqlError, SqlKvStore, SqlValue, TxFn, batch_growth_bytes,
};
use mkit_server::{Clock, Redacted, StoreError, SystemClock};
use parking_lot::ReentrantMutex;
use rusqlite::types::{ToSqlOutput, ValueRef};
use rusqlite::{Connection, ErrorCode, Transaction, TransactionBehavior, params_from_iter};

use crate::Blocking;

#[cfg(test)]
mod tests;

/// The native `SQLite` metadata store: [`SqlKvStore`] over
/// [`RusqliteConn`], run on tokio's blocking pool.
///
/// ```
/// use mkit_server::sql::{Capacity, SqlKvStore};
/// use mkit_server::{Batch, BatchOutcome, Key, NamespaceStore, Partition, Value};
/// use mkit_server_native::{Blocking, RusqliteConn, SqliteKvStore};
///
/// # tokio::runtime::Builder::new_multi_thread().build().unwrap().block_on(async {
/// let dir = tempfile::tempdir().unwrap();
/// let conn = RusqliteConn::open(dir.path().join("meta.sqlite3")).unwrap();
/// // A 1 GiB hard cap; batches with a put stop at the soft limit below it.
/// let capacity = Capacity::new(1 << 30);
/// let store: SqliteKvStore = Blocking::new(SqlKvStore::open_with_capacity(conn, capacity).unwrap());
/// let p = Partition::decode(b"ndefault\0").unwrap();
/// let (key, value) = (Key::new(&b"r\0main"[..]), Value::new(&b"1"[..]));
/// let batch = Batch::new().put(key.clone(), value.clone());
/// assert_eq!(store.apply(&p, batch).await.unwrap(), BatchOutcome::Committed);
/// assert_eq!(store.get(&p, &key).await.unwrap(), Some(value));
/// # });
/// ```
pub type SqliteKvStore = Blocking<SqlKvStore<RusqliteConn>>;

/// How long a writer waits for another process's write lock.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// Prepared statements kept per connection: every `get_many` chunk shape
/// plus the fixed statements.
const STATEMENT_CACHE: usize = GET_MANY_CHUNK + 32;

/// The connection and whether one of our transactions is open on it.
struct Shared {
    conn: Connection,
    in_tx: Cell<bool>,
}

/// Clears `in_tx` when the transaction body ends, even by panic.
struct TxFlag<'a>(&'a Cell<bool>);

impl Drop for TxFlag<'_> {
    fn drop(&mut self) {
        self.0.set(false);
    }
}

/// A cloneable handle on one rusqlite [`Connection`].
///
/// Opened with `journal_mode = WAL`, `busy_timeout = 5000` and
/// `synchronous = FULL`: a committed batch is on disk before `apply`
/// returns, as durable as the fsync'd ref files it replaces. Every clone
/// shares one connection behind a reentrant lock: statements from
/// different threads run one at a time, and a transaction holds the lock
/// for its whole body, so the body's own statements (on the same thread)
/// run inside it. The lock never poisons: a panicking body rolls its
/// transaction back and releases it.
///
/// `SQLITE_FULL` is [`SqlError::Full`] only when the database is at its
/// page limit ([`SqlConn::set_size_limit`]). A full host disk reports the
/// same code; it is a backend error (`StoreError::Unavailable`), because
/// deleting rows would not help.
///
/// [`SqlConn::now_ms`] reads the host clock, or the clock given to
/// [`Self::with_clock`].
#[derive(Clone)]
pub struct RusqliteConn {
    shared: Arc<ReentrantMutex<Shared>>,
    clock: Arc<dyn Clock>,
}

impl fmt::Debug for RusqliteConn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RusqliteConn").finish_non_exhaustive()
    }
}

fn redacted(e: &rusqlite::Error) -> SqlError {
    SqlError::Backend(Redacted::new(e.to_string()))
}

fn pragma(conn: &Connection, sql: &str) -> Result<u64, SqlError> {
    let n: i64 = conn
        .query_row(sql, [], |row| row.get(0))
        .map_err(|e| redacted(&e))?;
    u64::try_from(n).map_err(|_| SqlError::Corrupt("negative pragma value"))
}

/// Whether a database of `page_count` pages is at its limit of
/// `max_page_count`: within one batch's growth of it. A failed statement
/// (or transaction) is rolled back before its error is seen, so the page
/// count no longer includes the pages that did not fit.
fn at_page_limit(page_count: u64, max_page_count: u64, page_size: u64) -> bool {
    let slack = batch_growth_bytes(page_size) / page_size;
    page_count.saturating_add(slack) >= max_page_count
}

fn page_limit_reached(conn: &Connection) -> Result<bool, SqlError> {
    Ok(at_page_limit(
        pragma(conn, "PRAGMA page_count")?,
        pragma(conn, "PRAGMA max_page_count")?,
        pragma(conn, "PRAGMA page_size")?,
    ))
}

/// Map a rusqlite error on `conn` (see [`RusqliteConn`] for `SQLITE_FULL`).
fn map_err(conn: &Connection, e: &rusqlite::Error) -> SqlError {
    match e.sqlite_error_code() {
        Some(ErrorCode::DiskFull) if matches!(page_limit_reached(conn), Ok(true)) => SqlError::Full,
        Some(ErrorCode::ConstraintViolation) => SqlError::Constraint,
        _ => redacted(e),
    }
}

fn bind(params: &[SqlValue]) -> impl Iterator<Item = ToSqlOutput<'_>> {
    params.iter().map(|p| {
        ToSqlOutput::Borrowed(match p {
            SqlValue::Null => ValueRef::Null,
            SqlValue::Integer(n) => ValueRef::Integer(*n),
            SqlValue::Text(s) => ValueRef::Text(s.as_bytes()),
            SqlValue::Blob(b) => ValueRef::Blob(b),
        })
    })
}

fn column(value: ValueRef<'_>) -> Result<SqlValue, SqlError> {
    Ok(match value {
        ValueRef::Null => SqlValue::Null,
        ValueRef::Integer(n) => SqlValue::Integer(n),
        ValueRef::Real(_) => return Err(SqlError::Corrupt("unexpected real column")),
        ValueRef::Text(t) => SqlValue::Text(
            String::from_utf8(t.to_vec()).map_err(|_| SqlError::Corrupt("non-UTF-8 text"))?,
        ),
        ValueRef::Blob(b) => SqlValue::Blob(b.to_vec()),
    })
}

impl RusqliteConn {
    /// Open (creating if missing) the database file at `path`.
    ///
    /// # Errors
    /// The engine's error, redacted.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, SqlError> {
        Self::init(Connection::open(path).map_err(|e| redacted(&e))?)
    }

    /// A private in-memory database, gone when the last clone drops. Not
    /// durable: for tests and ephemeral deployments.
    ///
    /// # Errors
    /// The engine's error, redacted.
    pub fn open_in_memory() -> Result<Self, SqlError> {
        Self::init(Connection::open_in_memory().map_err(|e| redacted(&e))?)
    }

    fn init(conn: Connection) -> Result<Self, SqlError> {
        let err = |e: rusqlite::Error| redacted(&e);
        conn.busy_timeout(BUSY_TIMEOUT).map_err(err)?;
        // An in-memory database answers "memory": it has no WAL.
        conn.pragma_update_and_check(None, "journal_mode", "WAL", |_| Ok(()))
            .map_err(err)?;
        conn.pragma_update(None, "synchronous", "FULL")
            .map_err(err)?;
        conn.set_prepared_statement_cache_capacity(STATEMENT_CACHE);
        Ok(Self {
            shared: Arc::new(ReentrantMutex::new(Shared {
                conn,
                in_tx: Cell::new(false),
            })),
            clock: Arc::new(SystemClock),
        })
    }

    /// Use `clock` for [`SqlConn::now_ms`] instead of the host clock.
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    fn pragma(&self, sql: &str) -> Result<u64, SqlError> {
        pragma(&self.shared.lock().conn, sql)
    }

    /// Whether a transaction is open on the connection.
    #[cfg(test)]
    pub(crate) fn in_transaction(&self) -> bool {
        !self.shared.lock().conn.is_autocommit()
    }

    /// Pages in the file, free ones included.
    #[cfg(test)]
    pub(crate) fn page_count(&self) -> u64 {
        self.pragma("PRAGMA page_count").unwrap()
    }
}

impl SqlConn for RusqliteConn {
    fn exec(&self, sql: &str, params: &[SqlValue]) -> Result<u64, SqlError> {
        let shared = self.shared.lock();
        let conn = &shared.conn;
        let mut stmt = conn.prepare_cached(sql).map_err(|e| map_err(conn, &e))?;
        let changed = stmt
            .execute(params_from_iter(bind(params)))
            .map_err(|e| map_err(conn, &e))?;
        Ok(changed as u64)
    }

    fn query(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Row>, SqlError> {
        let shared = self.shared.lock();
        let conn = &shared.conn;
        let err = |e: rusqlite::Error| map_err(conn, &e);
        let mut stmt = conn.prepare_cached(sql).map_err(err)?;
        let width = stmt.column_count();
        let mut rows = stmt.query(params_from_iter(bind(params))).map_err(err)?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().map_err(err)? {
            let columns = (0..width)
                .map(|i| column(row.get_ref(i).map_err(err)?))
                .collect::<Result<Row, _>>()?;
            out.push(columns);
        }
        Ok(out)
    }

    /// `BEGIN IMMEDIATE` through rusqlite's [`Transaction`], so a writer
    /// takes the write lock before it reads its preconditions. Dropping the
    /// transaction (an `Err` from `f`, or a panic) rolls it back. A stale
    /// transaction left open on the connection (a rollback that failed) is
    /// rolled back first, with a warning; a nested call from `f` is an
    /// error.
    fn transaction<T: 'static>(&self, f: TxFn<Self, T>) -> Result<T, SqlError> {
        let shared = self.shared.lock();
        let conn = &shared.conn;
        if shared.in_tx.get() {
            return Err(SqlError::Backend(Redacted::new(
                "nested sqlite transaction",
            )));
        }
        if !conn.is_autocommit() {
            tracing::warn!("sqlite: rolling back a stale open transaction");
            conn.execute_batch("ROLLBACK")
                .map_err(|e| map_err(conn, &e))?;
        }
        let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate)
            .map_err(|e| map_err(conn, &e))?;
        shared.in_tx.set(true);
        let flag = TxFlag(&shared.in_tx);
        let out = f(self.clone())?;
        drop(flag);
        tx.commit().map_err(|e| map_err(conn, &e))?;
        Ok(out)
    }

    fn now_ms(&self) -> u64 {
        u64::try_from(self.clock.now_ms()).unwrap_or(u64::MAX)
    }

    /// `(page_count - freelist_count) * page_size`.
    fn size_bytes(&self) -> Result<u64, SqlError> {
        let shared = self.shared.lock();
        let conn = &shared.conn;
        let used = pragma(conn, "PRAGMA page_count")?
            .saturating_sub(pragma(conn, "PRAGMA freelist_count")?);
        Ok(used * pragma(conn, "PRAGMA page_size")?)
    }

    /// `max_page_count = max(bytes / page_size, 1)`, never below the pages
    /// in use. Per connection; not stored in the file.
    fn set_size_limit(&self, bytes: u64) -> Result<(), SqlError> {
        let pages = (bytes / self.pragma("PRAGMA page_size")?).max(1);
        self.pragma(&format!("PRAGMA max_page_count = {pages}"))?;
        Ok(())
    }

    /// `VACUUM INTO dest`: a consistent, compacted copy of the whole
    /// database (every partition) at the path `dest`, which must not exist.
    fn backup_to(&self, dest: &str) -> Result<(), StoreError> {
        self.exec("VACUUM INTO ?1", &[SqlValue::Text(dest.to_owned())])?;
        Ok(())
    }
}
