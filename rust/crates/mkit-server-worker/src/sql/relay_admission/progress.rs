//! Current-generation applied progress. Outside portable KV, but included in
//! physical SQL backups; recovery must allocate a fresh external generation.
use super::{Batch, Generation, Precondition, SqlConn, SqlError, SqlValue, StoreError, Write};
use mkit_server::store::{MAX_BATCH_BYTES, StoreCapabilities};
use serde::{Deserialize, Serialize};

const PRESENT: &str =
    "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'mkit_relay_progress'";
const CREATE: &str = "CREATE TABLE IF NOT EXISTS mkit_relay_progress (part BLOB NOT NULL, source BLOB NOT NULL, value BLOB NOT NULL, PRIMARY KEY (part, source)) WITHOUT ROWID";
pub(super) const GET: &str =
    "SELECT value FROM mkit_relay_progress WHERE part = ?1 AND source = ?2";
pub(super) const PUT: &str = "INSERT INTO mkit_relay_progress (part, source, value) VALUES (?1, ?2, ?3) ON CONFLICT (part, source) DO UPDATE SET value = excluded.value";
const MAX_ROW_BYTES: usize = 512;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u8,
    generation: Generation,
    through: u64,
}
pub(super) fn encode(generation: Generation, through: u64) -> Result<Vec<u8>, SqlError> {
    if through == 0 {
        return Err(SqlError::Corrupt("zero relay applied progress"));
    }
    let raw = serde_json::to_vec(&Record {
        version: 1,
        generation,
        through,
    })
    .map_err(|_| SqlError::Corrupt("relay progress encoding"))?;
    if raw.len() > MAX_ROW_BYTES {
        return Err(SqlError::Corrupt("relay progress bound"));
    }
    Ok(raw)
}
pub(super) fn read<C: SqlConn>(
    conn: &C,
    target: &SqlValue,
    source: &SqlValue,
    generation: Generation,
) -> Result<(Option<Vec<u8>>, u64), SqlError> {
    if conn.query(PRESENT, &[])?.is_empty() {
        return Ok((None, 0));
    }
    let rows = conn.query(GET, &[target.clone(), source.clone()])?;
    if rows.len() > 1 {
        return Err(SqlError::Corrupt("duplicate relay progress"));
    }
    let Some(row) = rows.first() else {
        return Ok((None, 0));
    };
    let Some(SqlValue::Blob(raw)) = row.first() else {
        return Err(SqlError::Corrupt("relay progress column"));
    };
    if raw.len() > MAX_ROW_BYTES {
        return Err(SqlError::Corrupt("relay progress bound"));
    }
    let record: Record =
        serde_json::from_slice(raw).map_err(|_| SqlError::Corrupt("relay progress record"))?;
    if record.version != 1 || encode(record.generation, record.through)? != *raw {
        return Err(SqlError::Corrupt(
            "relay progress version or canonical encoding",
        ));
    }
    let through = if record.generation == generation {
        record.through
    } else {
        0
    };
    Ok((Some(raw.clone()), through))
}
pub(super) fn write<C: SqlConn>(
    conn: &C,
    target: &SqlValue,
    source: &SqlValue,
    next: Vec<u8>,
) -> Result<(), SqlError> {
    conn.exec(CREATE, &[])?;
    conn.exec(PUT, &[target.clone(), source.clone(), SqlValue::Blob(next)])?;
    Ok(())
}
/// Account for the private exact-CAS and put, including both composite keys and
/// old/new values, without presenting metadata as portable KV writes.
pub(super) fn validate_batch(
    batch: &Batch,
    mut caps: StoreCapabilities,
    target: &SqlValue,
    source: &SqlValue,
    prior: Option<&[u8]>,
    next: &[u8],
) -> Result<(), StoreError> {
    caps.reserved_batch_ops = caps.reserved_batch_ops.checked_add(2).ok_or_else(|| {
        StoreError::Invalid("relay progress operation reservation overflow".into())
    })?;
    batch.validate(&caps)?;
    let (SqlValue::Blob(target), SqlValue::Blob(source)) = (target, source) else {
        return Err(StoreError::Corrupt(
            "relay progress partition columns".into(),
        ));
    };
    let private = (target.len() + source.len()) * 2 + prior.map_or(0, <[u8]>::len) + next.len();
    let guards = batch
        .preconditions
        .iter()
        .map(|pre| match pre {
            Precondition::Absent(key) | Precondition::Present(key) => key.as_bytes().len(),
            Precondition::Equals(key, value) => key.as_bytes().len() + value.as_bytes().len(),
            Precondition::NotAfter(_) => 0,
        })
        .sum::<usize>();
    let writes = batch
        .writes
        .iter()
        .map(|write| match write {
            Write::Put(key, value) => key.as_bytes().len() + value.as_bytes().len(),
            Write::Delete(key) => key.as_bytes().len(),
        })
        .sum::<usize>();
    if guards + writes + private > MAX_BATCH_BYTES {
        return Err(StoreError::Invalid(
            "relay progress exceeds batch byte allowance".into(),
        ));
    }
    Ok(())
}
