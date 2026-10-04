//! Atomic current-schema bootstrap and strict reopen checks.
//!
//! Every statement runs on `rusqlite` and on Durable Object `SQLite`: no
//! `ATTACH`, no `PRAGMA`, no transaction control. The version lives in the
//! one-row `mkit_schema` table (not `PRAGMA user_version`, which Durable
//! Objects do not allow). Unsupported stores must be reset.
//!
//! The `kv` table is keyed by `(part, key)`. `part` is the
//! [`Partition::encode`](mkit_server::Partition::encode) bytes, so one native
//! file holds every partition; a Durable Object holds one partition.
//! The `kv_timers` partial index finds each partition's earliest timer.

use super::{SqlConn, SqlError, SqlValue, count};
use mkit_server::store::StoreError;

/// Current schema statements, installed together with the version row.
pub const BOOTSTRAP: &[&str] = &[
    "CREATE TABLE mkit_schema (id INTEGER PRIMARY KEY CHECK (id = 1), version INTEGER NOT NULL)",
    "CREATE TABLE kv (part BLOB NOT NULL, key BLOB NOT NULL, \
     value BLOB NOT NULL, PRIMARY KEY (part, key)) WITHOUT ROWID",
    "CREATE INDEX kv_timers ON kv (key, part) WHERE key >= x'7700' AND key < x'7701'",
];

const READ_VERSION: &str = "SELECT version FROM mkit_schema WHERE id = 1";
const WRITE_VERSION: &str = "INSERT INTO mkit_schema (id, version) VALUES (1, ?1)";
const SCHEMA_PRESENT: &str =
    "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'mkit_schema'";
const STORE_OBJECTS: &str = "SELECT 1 FROM sqlite_master WHERE \
    (type = 'table' AND name IN ('mkit_schema', 'kv')) OR (type = 'index' AND name = 'kv_timers')";

/// The schema version this binary requires.
pub const SCHEMA_VERSION: u32 = 2;

/// The version recorded in the database: 0 if the marker row is missing.
fn stored_version<C: SqlConn>(conn: &C) -> Result<u32, SqlError> {
    match conn.query(READ_VERSION, &[])?.first() {
        None => Ok(0),
        Some(row) => u32::try_from(count(row, 0)?).map_err(|_| SqlError::Corrupt("schema version")),
    }
}

/// Check an existing database without writing schema rows.
///
/// # Errors
/// The database's version is not exactly this binary's, its schema is incomplete,
/// or it cannot be read.
pub fn require_current<C: SqlConn>(conn: &C) -> Result<u32, StoreError> {
    let version = if conn.query(SCHEMA_PRESENT, &[])?.is_empty() {
        0
    } else {
        stored_version(conn)?
    };
    if version != SCHEMA_VERSION {
        return Err(StoreError::Unsupported(format!(
            "database schema version {version} differs from binary version {SCHEMA_VERSION}; reset the store"
        ).into()));
    }
    if conn.query(STORE_OBJECTS, &[])?.len() != BOOTSTRAP.len() {
        return Err(StoreError::Corrupt("incomplete SQL schema".into()));
    }
    Ok(version)
}

/// Initialize a fresh store atomically, or reopen only the current schema.
/// Concurrent openers check under the same transaction as creation.
///
/// # Errors
/// An existing noncurrent or incomplete store is refused without changes;
/// backend failures roll back all bootstrap statements and the marker.
pub fn initialize<C: SqlConn>(conn: &C) -> Result<u32, StoreError> {
    conn.transaction(Box::new(|c: C| {
        if !c.query(STORE_OBJECTS, &[])?.is_empty() {
            return Ok(require_current(&c));
        }
        for statement in BOOTSTRAP {
            c.exec(statement, &[])?;
        }
        c.exec(WRITE_VERSION, &[SqlValue::Integer(SCHEMA_VERSION.into())])?;
        Ok(Ok(SCHEMA_VERSION))
    }))?
}
