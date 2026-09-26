//! The shared SQL backend (`sql` feature): the [`NamespaceStore`] contract
//! implemented once over `SQLite`, on the tiny synchronous [`SqlConn`]
//! trait.
//!
//! `rusqlite` (`mkit-server-native`) and Durable Object `SQLite` (a later
//! adapter) both implement [`SqlConn`], so the native backend and every
//! per-partition Durable Object run the same statements and the same
//! physical [`schema`] migrations. SQL is an internal detail of this
//! backend: nothing above [`NamespaceStore`] sees it.
//!
//! Every statement stays within Durable Object limits: at most
//! [`MAX_BOUND_PARAMS`] bound parameters, and no transaction-control
//! statement ([`SqlConn::transaction`] owns atomicity).
//!
//! [`NamespaceStore`]: crate::NamespaceStore

mod capacity;
mod kv;
pub mod schema;
#[cfg(test)]
mod tests;

pub use capacity::{
    Capacity, DEFAULT_PAGE_SIZE, RESERVE_TREE_DEPTH, batch_growth_bytes, reserve_floor,
};
pub use kv::{GET_MANY_CHUNK, SqlKvStore};

use crate::error::Redacted;
use crate::rt::{MaybeSend, MaybeSync};
use crate::store::StoreError;

/// Most bound parameters in one statement: the Durable Object SQL limit
/// (<https://developers.cloudflare.com/durable-objects/platform/limits/>).
/// [`SqlKvStore`] never binds more.
pub const MAX_BOUND_PARAMS: usize = 100;

/// A bound parameter or a result column: the four storage classes both
/// `rusqlite` and Durable Object SQL bind (no `REAL`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SqlValue {
    /// `NULL`.
    Null,
    /// A 64-bit signed integer.
    Integer(i64),
    /// UTF-8 text.
    Text(String),
    /// Raw bytes. Blobs compare by `memcmp`, then length: raw byte order.
    Blob(Vec<u8>),
}

/// One result row, its columns in select order.
pub type Row = Vec<SqlValue>;

/// Why a SQL call failed. The backend's own message never reaches a client:
/// it is kept [`Redacted`] for the server-side log only.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SqlError {
    /// The engine failed (I/O, busy past its timeout, a malformed
    /// statement). The outcome of a failed transaction is a rollback.
    #[error("sql backend error")]
    Backend(Redacted),
    /// A constraint was violated.
    #[error("sql constraint violated")]
    Constraint,
    /// The database is at its size cap (`SQLITE_FULL`): writes that add data
    /// fail, reads and deletes keep working.
    #[error("sql database full")]
    Full,
    /// A row did not have the expected shape.
    #[error("corrupt sql row: {0}")]
    Corrupt(&'static str),
}

impl From<SqlError> for StoreError {
    fn from(e: SqlError) -> Self {
        match e {
            SqlError::Full => Self::Full,
            SqlError::Corrupt(what) => Self::Corrupt(what.into()),
            e @ (SqlError::Backend(_) | SqlError::Constraint) => Self::unavailable(e),
        }
    }
}

/// The transaction body [`SqlConn::transaction`] runs: owned and `'static`.
pub type TxFn<C, T> = Box<dyn FnOnce(C) -> Result<T, SqlError> + 'static>;

/// A synchronous SQL connection: a cheaply cloneable handle (`rusqlite`:
/// a shared, locked `Connection`; a Durable Object: its storage handle).
///
/// Synchronous on purpose: Durable Object `sql.exec` and `transactionSync`
/// are synchronous, and so is `rusqlite`. A native server runs a store over
/// it on a blocking thread (`mkit-server-native`'s `Blocking`).
pub trait SqlConn: MaybeSend + MaybeSync + Clone + 'static {
    /// Run one statement that returns no rows; the number of rows changed.
    fn exec(&self, sql: &str, params: &[SqlValue]) -> Result<u64, SqlError>;

    /// Run one statement and collect its rows.
    fn query(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Row>, SqlError>;

    /// Run `f` atomically and synchronously: commit if it returns `Ok`,
    /// roll back if it returns `Err` or panics. `f` receives a handle for
    /// its statements.
    ///
    /// An implementation never issues transaction-control SQL itself:
    /// Durable Objects reject those statements and require
    /// `storage.transactionSync`; `rusqlite` uses its `Transaction` type.
    /// `f` never awaits, which is what makes `apply` cancellation-safe
    /// (normative rule 4).
    ///
    /// `f` is owned and `'static` (not a borrowed `FnMut`): the Durable
    /// Object bridge wraps it in a `'static` wasm-bindgen closure, and this
    /// crate forbids `unsafe`.
    fn transaction<T: 'static>(&self, f: TxFn<Self, T>) -> Result<T, SqlError>;

    /// The backend's own clock, Unix ms, for [`Precondition::NotAfter`]
    /// (normative rule 8): the host's system clock natively, `Date.now()` on
    /// a Durable Object. A reading before the epoch is `u64::MAX`, so every
    /// deadline fails closed.
    ///
    /// [`Precondition::NotAfter`]: crate::Precondition::NotAfter
    fn now_ms(&self) -> u64;

    /// Bytes the database uses, for the soft cap ([`Capacity`]): pages
    /// holding data (natively `(page_count - freelist_count) * page_size`;
    /// free pages are reused before the file grows), `databaseSize` on a
    /// Durable Object. Called inside a transaction.
    fn size_bytes(&self) -> Result<u64, SqlError>;

    /// Enforce a hard size limit of about `bytes` at the engine (natively
    /// `max_page_count`). The default does nothing: a Durable Object has a
    /// fixed limit of its own, which the [`Capacity`] must not exceed.
    fn set_size_limit(&self, bytes: u64) -> Result<(), SqlError> {
        let _ = bytes;
        Ok(())
    }

    /// Write a consistent backend-native backup of the whole database to
    /// `dest` (natively a file path, via `VACUUM INTO`). The default is
    /// [`StoreError::Unsupported`]: back such a backend up with the
    /// portable export (`store::export_partition`).
    fn backup_to(&self, dest: &str) -> Result<(), StoreError> {
        let _ = dest;
        Err(StoreError::Unsupported(
            "this SQL backend has no physical backup; use the portable export".into(),
        ))
    }
}

/// Column `i` of `row` as a blob, moved out of the row.
pub(crate) fn blob(row: &mut Row, i: usize) -> Result<Vec<u8>, SqlError> {
    match row.get_mut(i) {
        Some(SqlValue::Blob(b)) => Ok(core::mem::take(b)),
        _ => Err(SqlError::Corrupt("expected a blob column")),
    }
}

/// Column `i` of `row` as a non-negative integer (`NULL` reads as 0, for
/// aggregates over no rows).
pub(crate) fn count(row: &Row, i: usize) -> Result<u64, SqlError> {
    match row.get(i) {
        Some(SqlValue::Null) => Ok(0),
        Some(SqlValue::Integer(n)) => {
            u64::try_from(*n).map_err(|_| SqlError::Corrupt("negative count"))
        }
        _ => Err(SqlError::Corrupt("expected an integer column")),
    }
}
