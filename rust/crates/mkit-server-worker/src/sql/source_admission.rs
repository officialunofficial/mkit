//! Source-local enrollment, outside portable KV. These APIs remain factory-off.
//! A local generation does not prove external identity, bootstrap completeness,
//! ordered delivery or permission to clean up retained relay rows.
use super::{SqlConn, SqlError, SqlKvStore, SqlValue, kv, publication_maintenance};
use mkit_server::store::adapter_spi::{codec, keys, publication_fence::Generation};
use mkit_server::store::{MAX_BATCH_BYTES, StoreCapabilities};
use mkit_server::{
    Batch, BatchOutcome, Key, NamespaceStore, Partition, Precondition, StoreError, Value, Write,
};
use std::collections::BTreeSet;

const PRESENT: &str =
    "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'mkit_source_admission'";
const CREATE: &str = "CREATE TABLE IF NOT EXISTS mkit_source_admission (part BLOB PRIMARY KEY NOT NULL, generation BLOB NOT NULL) WITHOUT ROWID";
const GET: &str = "SELECT generation FROM mkit_source_admission WHERE part = ?1";
const PUT: &str = "INSERT INTO mkit_source_admission (part, generation) VALUES (?1, ?2) ON CONFLICT (part) DO UPDATE SET generation = excluded.generation";
const REMOVE_PAUSE: &str = "DELETE FROM mkit_publication_pause WHERE part = ?1";

fn source_part(source: &Partition) -> Result<SqlValue, StoreError> {
    if !matches!(source, Partition::Ref { .. }) {
        return Err(StoreError::Invalid("source admission requires Ref".into()));
    }
    let encoded = source.encode()?.to_vec();
    if encoded.len() > 4096 {
        return Err(StoreError::Invalid(
            "source admission partition bound".into(),
        ));
    }
    Ok(SqlValue::Blob(encoded))
}
fn read<C: SqlConn>(conn: &C, part: &SqlValue) -> Result<Option<Generation>, SqlError> {
    if conn.query(PRESENT, &[])?.is_empty() {
        return Ok(None);
    }
    let rows = conn.query(GET, std::slice::from_ref(part))?;
    if rows.len() > 1 {
        return Err(SqlError::Corrupt("duplicate source admission"));
    }
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    let Some(SqlValue::Blob(raw)) = row.first() else {
        return Err(SqlError::Corrupt("source admission column"));
    };
    if raw.len() > 512 || raw.first() != Some(&1) {
        return Err(SqlError::Corrupt("source admission version"));
    }
    let generation: Generation = serde_json::from_slice(&raw[1..])
        .map_err(|_| SqlError::Corrupt("source admission generation"))?;
    if publication_maintenance::encoded_generation(&generation)?.as_slice() != raw {
        return Err(SqlError::Corrupt("noncanonical source admission"));
    }
    Ok(Some(generation))
}
fn write_key(write: &Write) -> &Key {
    match write {
        Write::Put(key, _) | Write::Delete(key) => key,
    }
}

pub(super) fn validate<C: SqlConn>(
    conn: &C,
    part: &SqlValue,
    batch: &Batch,
    admitted: Option<Generation>,
) -> Result<(), SqlError> {
    let Some(generation) = admitted else {
        if !batch.writes.is_empty() && read(conn, part)?.is_some() {
            return Err(SqlError::Constraint);
        }
        return Ok(());
    };
    if read(conn, part)? != Some(generation) {
        return Err(SqlError::Constraint);
    }
    if publication_maintenance::read(conn, part)?.is_some() {
        return Err(SqlError::PublicationPaused);
    }
    let SqlValue::Blob(encoded) = part else {
        return Err(SqlError::Corrupt("source admission partition column"));
    };
    let source = Partition::decode(encoded)
        .map_err(|_| SqlError::Corrupt("source admission partition encoding"))?;
    mkit_server::store::adapter_spi::publication_fence::validate_source_generation(
        &source,
        batch,
        generation,
        |key| kv::read(conn, part, key).map_err(StoreError::from),
    )
    .map_err(|_| SqlError::Corrupt("source marker admission generation"))?;
    validate_private_guard(part, batch, generation)?;
    validate_outbox(conn, part, batch)
}
fn validate_private_guard(
    part: &SqlValue,
    batch: &Batch,
    generation: Generation,
) -> Result<(), SqlError> {
    let mut caps = StoreCapabilities::full();
    caps.reserved_batch_ops = 1;
    batch
        .validate(&caps)
        .map_err(|_| SqlError::Corrupt("source admission operation allowance"))?;
    let SqlValue::Blob(part) = part else {
        return Err(SqlError::Corrupt("source admission partition column"));
    };
    let private = part.len() + publication_maintenance::encoded_generation(&generation)?.len();
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
        return Err(SqlError::Corrupt("source admission byte allowance"));
    }
    Ok(())
}
fn validate_outbox<C: SqlConn>(conn: &C, part: &SqlValue, batch: &Batch) -> Result<(), SqlError> {
    let os = keys::outbox_sequence();
    let sequences: Vec<_> = batch
        .writes
        .iter()
        .filter(|write| write_key(write) == &os)
        .collect();
    let relays: Vec<_> = batch
        .writes
        .iter()
        .filter(|write| write_key(write).as_bytes().starts_with(b"or\0"))
        .collect();
    if sequences.is_empty() && relays.is_empty() {
        return Ok(());
    }
    let [Write::Put(_, next)] = sequences.as_slice() else {
        return Err(SqlError::Corrupt("source outbox requires one sequence put"));
    };
    let next = codec::decode_u64(next).map_err(|_| SqlError::Corrupt("source outbox sequence"))?;
    let observed = kv::read(conn, part, &os)?;
    let previous = observed
        .as_ref()
        .map(codec::decode_u64)
        .transpose()
        .map_err(|_| SqlError::Corrupt("source prior outbox sequence"))?
        .unwrap_or(0);
    let expected = observed.map_or_else(
        || Precondition::Absent(os.clone()),
        |value| Precondition::Equals(os.clone(), value),
    );
    let guards: Vec<_> = batch.preconditions.iter().filter(|pre| matches!(pre, Precondition::Absent(key) | Precondition::Present(key) | Precondition::Equals(key, _) if *key == os)).collect();
    if guards.as_slice() != [&expected] || next <= previous {
        return Err(SqlError::Corrupt("source outbox exact monotonic guard"));
    }
    let mut seen = BTreeSet::new();
    for write in relays {
        let Write::Put(key, raw) = write else {
            return Err(SqlError::Corrupt("source relay cleanup requires receipt"));
        };
        let Some(keys::ParsedKey::Relay(sequence)) = keys::parse(key) else {
            return Err(SqlError::Corrupt("source relay key"));
        };
        if !seen.insert(sequence)
            || sequence <= previous
            || sequence > next
            || kv::read(conn, part, key)?.is_some()
        {
            return Err(SqlError::Corrupt("source relay allocation or rewrite"));
        }
        codec::decode_relay(raw).map_err(|_| SqlError::Corrupt("source relay encoding"))?;
    }
    Ok(())
}
impl<C: SqlConn> SqlKvStore<C> {
    /// Enroll under an exact maintenance pause and expected previous identity.
    /// The trusted integration must never reuse an incarnation after restore.
    /// This proves only a local mutation barrier, not global bootstrap readiness.
    pub fn activate_source_admission(
        &self,
        source: &Partition,
        previous: Option<Generation>,
        generation: Generation,
    ) -> Result<(), StoreError> {
        let part = source_part(source)?;
        let value = SqlValue::Blob(publication_maintenance::encoded_generation(&generation)?);
        let limit = self.metadata_soft_limit();
        self.conn().transaction(Box::new(move |conn| {
            let current = read(&conn, &part)?;
            let pause = publication_maintenance::read(&conn, &part)?;
            if current == Some(generation) && pause.is_none() {
                return Ok(());
            }
            if current != previous || pause != Some(generation) {
                return Err(SqlError::Constraint);
            }
            if let Some(limit) = limit
                && conn.size_bytes()? >= limit
            {
                return Err(SqlError::Full);
            }
            conn.exec(CREATE, &[])?;
            conn.exec(PUT, &[part.clone(), value])?;
            conn.exec(REMOVE_PAUSE, &[part])?;
            Ok(())
        }))?;
        Ok(())
    }
    /// Explicitly admitted source apply. Final SQL rechecks generation/pause,
    /// original effects and guards, and source publication/outbox invariants.
    /// Relay cleanup is refused until a typed generation-bound receipt exists.
    pub fn apply_admitted_source<F>(
        &self,
        source: &Partition,
        generation: Generation,
        batch: Batch,
        extend: F,
    ) -> Result<BatchOutcome, StoreError>
    where
        F: FnOnce(
                &dyn Fn(&Key) -> Result<Option<Value>, SqlError>,
                &mut Batch,
                u64,
            ) -> Result<(), SqlError>
            + 'static,
    {
        let part = source_part(source)?;
        batch.validate(&self.capabilities())?;
        let original_writes = batch.writes.clone();
        let original_guards = batch.preconditions.clone();
        let limit = self.metadata_soft_limit();
        Ok(self.conn().transaction(Box::new(move |conn| {
            kv::check_and_write_extended_source(
                &conn,
                &part,
                batch,
                limit,
                generation,
                move |get, batch, now| {
                    extend(get, batch, now)?;
                    if !batch.writes.starts_with(&original_writes)
                        || !batch.preconditions.starts_with(&original_guards)
                        || batch.writes[original_writes.len()..].iter().any(|write| {
                            original_writes
                                .iter()
                                .any(|original| write_key(original) == write_key(write))
                        })
                    {
                        return Err(SqlError::Corrupt(
                            "extension altered admitted source effects",
                        ));
                    }
                    Ok(())
                },
            )
        }))?)
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "source_admission_tests.rs"]
mod tests;
