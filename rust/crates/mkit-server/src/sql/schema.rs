//! The physical schema and its versioned, forward-only migrations.
//!
//! Every statement runs on `rusqlite` and on Durable Object `SQLite`: no
//! `ATTACH`, no `PRAGMA`, no transaction control. The version lives in the
//! one-row `mkit_schema` table (not `PRAGMA user_version`, which Durable
//! Objects do not allow).
//!
//! Logical layout changes (new key classes, new row kinds) need **no**
//! physical migration: they are key layouts, versioned by the `v` row
//! (`store::keys::layout_version`). A physical migration changes only the
//! `kv` table's shape.
//!
//! Physical v1: one `kv` table keyed by `(part, key)`. `part` is the
//! [`Partition::encode`](crate::Partition::encode) bytes, so one native
//! file holds every partition (a D34 shard is a `part` value); a Durable
//! Object holds one partition, and the column is constant there. It is a
//! `BLOB`, not `TEXT`: the encoding's components end in `0x00`, which
//! `SQLite` text functions treat as a terminator.

use super::{SqlConn, SqlError, SqlValue, TxFn, count};
use crate::store::StoreError;

/// One physical migration: its statements run in one transaction, which
/// then records `version`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Migration {
    /// The schema version this migration reaches.
    pub version: u32,
    /// Its statements, in order. Each is idempotent (`IF NOT EXISTS`).
    pub statements: &'static [&'static str],
}

/// The version table, created before anything reads it.
pub const BOOTSTRAP: &str = "CREATE TABLE IF NOT EXISTS mkit_schema \
     (id INTEGER PRIMARY KEY CHECK (id = 1), version INTEGER NOT NULL)";

const READ_VERSION: &str = "SELECT version FROM mkit_schema WHERE id = 1";
const WRITE_VERSION: &str = "INSERT INTO mkit_schema (id, version) VALUES (1, ?1) \
     ON CONFLICT (id) DO UPDATE SET version = excluded.version";

/// Every migration, in ascending version order.
pub const MIGRATIONS: &[Migration] = &[Migration {
    version: 1,
    statements: &[
        "CREATE TABLE IF NOT EXISTS kv (part BLOB NOT NULL, key BLOB NOT NULL, \
         value BLOB NOT NULL, PRIMARY KEY (part, key)) WITHOUT ROWID",
    ],
}];

/// The schema version this binary expects: the last migration's.
pub const SCHEMA_VERSION: u32 = 1;

/// The version recorded in the database: 0 for a new one.
fn stored_version<C: SqlConn>(conn: &C) -> Result<u32, SqlError> {
    match conn.query(READ_VERSION, &[])?.first() {
        None => Ok(0),
        Some(row) => u32::try_from(count(row, 0)?).map_err(|_| SqlError::Corrupt("schema version")),
    }
}

enum Step {
    Applied,
    Done(u32),
}

/// Bring the database to [`SCHEMA_VERSION`]; returns the version reached.
/// Each missing migration runs in its own transaction, which re-reads the
/// version first, so concurrent openers apply it once. Idempotent.
///
/// # Errors
/// [`StoreError::Unsupported`] if the database records a newer version than
/// this binary's (there is no downgrade; nothing is changed); the engine's
/// error otherwise.
pub fn migrate<C: SqlConn>(conn: &C) -> Result<u32, StoreError> {
    loop {
        let step: TxFn<C, Step> = Box::new(|c: C| {
            c.exec(BOOTSTRAP, &[])?;
            let current = stored_version(&c)?;
            let Some(next) = MIGRATIONS.iter().find(|m| m.version > current) else {
                return Ok(Step::Done(current));
            };
            for statement in next.statements {
                c.exec(statement, &[])?;
            }
            c.exec(WRITE_VERSION, &[SqlValue::Integer(next.version.into())])?;
            Ok(Step::Applied)
        });
        match conn.transaction(step)? {
            Step::Applied => {}
            Step::Done(version) if version > SCHEMA_VERSION => {
                return Err(StoreError::Unsupported(
                    "database schema is newer than this binary".into(),
                ));
            }
            Step::Done(version) => return Ok(version),
        }
    }
}
