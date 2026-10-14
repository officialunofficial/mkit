//! Permanent target-local admission, outside portable KV export/import.
//! These APIs are not factory wired. The caller must independently establish
//! current external generation and reconcile legacy effects before activation.
//! A `VerifiedRelay` proves an actual retained source row, not those preconditions.
//! Production activation remains disabled: integration must enforce a complete
//! ordered source prefix, including auxiliary-only rows that the current intent
//! proof cannot cover. Source sequences interleave destinations and need not be
//! contiguous. Bootstrap must also prove restored source/target counter ordering:
//! rebinding admission to a new generation does not give a legacy raw rh row
//! new-generation delivery provenance. An old target rh=100 cannot acknowledge
//! a new source sequence=6 after restoring its outbox counter to 5.
use super::{SqlConn, SqlError, SqlKvStore, SqlValue, kv, publication_maintenance};
use mkit_server::store::adapter_spi::{
    codec, keys,
    publication_fence::{Generation, VerifiedRelay},
};
use mkit_server::{
    Batch, BatchOutcome, Key, NamespaceStore, Partition, Precondition, StoreError, Value, Write,
};

mod progress;

const PRESENT: &str =
    "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'mkit_relay_admission'";
const CREATE: &str = "CREATE TABLE IF NOT EXISTS mkit_relay_admission (part BLOB PRIMARY KEY NOT NULL, generation BLOB NOT NULL) WITHOUT ROWID";
const GET: &str = "SELECT generation FROM mkit_relay_admission WHERE part = ?1";
const PUT: &str = "INSERT INTO mkit_relay_admission (part, generation) VALUES (?1, ?2) ON CONFLICT (part) DO UPDATE SET generation = excluded.generation";
const REMOVE_PAUSE: &str = "DELETE FROM mkit_publication_pause WHERE part = ?1";

fn target_part(partition: &Partition) -> Result<SqlValue, StoreError> {
    if !matches!(partition, Partition::RefIndex { .. }) {
        return Err(StoreError::Invalid(
            "relay admission requires RefIndex".into(),
        ));
    }
    let bytes = partition.encode()?.to_vec();
    if bytes.len() > 4096 {
        return Err(StoreError::Invalid(
            "relay admission partition bound".into(),
        ));
    }
    Ok(SqlValue::Blob(bytes))
}
fn read<C: SqlConn>(conn: &C, part: &SqlValue) -> Result<Option<Generation>, SqlError> {
    if conn.query(PRESENT, &[])?.is_empty() {
        return Ok(None);
    }
    let rows = conn.query(GET, std::slice::from_ref(part))?;
    if rows.len() > 1 {
        return Err(SqlError::Corrupt("duplicate relay admission"));
    }
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    let Some(SqlValue::Blob(raw)) = row.first() else {
        return Err(SqlError::Corrupt("relay admission column"));
    };
    if raw.len() > 512 || raw.first() != Some(&1) {
        return Err(SqlError::Corrupt("relay admission version"));
    }
    let generation: Generation = serde_json::from_slice(&raw[1..])
        .map_err(|_| SqlError::Corrupt("relay admission generation"))?;
    if publication_maintenance::encoded_generation(&generation)?.as_slice() != raw {
        return Err(SqlError::Corrupt("noncanonical relay admission"));
    }
    Ok(Some(generation))
}
fn require_generation<C: SqlConn>(
    conn: &C,
    part: &SqlValue,
    generation: Generation,
) -> Result<(), SqlError> {
    if read(conn, part)? != Some(generation) {
        return Err(SqlError::Constraint);
    }
    if publication_maintenance::read(conn, part)?.is_some() {
        return Err(SqlError::PublicationPaused);
    }
    Ok(())
}
fn protected(key: &Key) -> bool {
    key.as_bytes().starts_with(b"py\0") || key.as_bytes().starts_with(b"rh\0")
}
fn write_key(write: &Write) -> &Key {
    match write {
        Write::Put(key, _) | Write::Delete(key) => key,
    }
}
/// Called on the final extended batch by every SQL KV apply path.
pub(super) fn validate<C: SqlConn>(
    conn: &C,
    part: &SqlValue,
    batch: &Batch,
    admitted: Option<Generation>,
) -> Result<(), SqlError> {
    if let Some(generation) = admitted {
        return require_generation(conn, part, generation);
    }
    if batch.writes.iter().any(|write| protected(write_key(write))) && read(conn, part)?.is_some() {
        return Err(SqlError::Constraint);
    }
    Ok(())
}

/// Admission, private applied progress and compatibility rh in one SQL cut.
/// Private fields prevent constructing an arbitrary admitted watermark.
#[derive(Debug, Clone)]
pub struct RelayAdmissionSnapshot {
    target: Partition,
    source: Partition,
    generation: Generation,
    observed: Option<Value>,
    watermark: u64,
    compatibility_watermark: u64,
    progress: Option<Vec<u8>>,
}
/// Fresh target-local delivery evidence. Private fields prevent substituting a
/// caller watermark or raw compatibility rh. This proves local applied progress,
/// not current external authority; recovery still needs enforced pause-before-
/// rotation ordering before using a receipt for source cleanup.
#[derive(Debug, Clone)]
pub struct TargetProgressReceipt {
    target: Partition,
    source: Partition,
    generation: Generation,
    through: u64,
}
impl TargetProgressReceipt {
    /// Complete logical target partition.
    #[must_use]
    pub fn target(&self) -> &Partition {
        &self.target
    }
    /// Complete logical source partition.
    #[must_use]
    pub fn source(&self) -> &Partition {
        &self.source
    }
    /// Local admission generation in which these effects committed.
    #[must_use]
    pub fn generation(&self) -> Generation {
        self.generation
    }
    /// Applied source sequence; not inherited from compatibility rh.
    #[must_use]
    pub fn through(&self) -> u64 {
        self.through
    }
}
impl RelayAdmissionSnapshot {
    /// Proven applied progress in this local admission generation only.
    /// This is not external identity or a coordinator completion receipt.
    #[must_use]
    pub fn watermark(&self) -> u64 {
        self.watermark
    }
}
fn admitted_batch(
    snapshot: &RelayAdmissionSnapshot,
    proofs: &[VerifiedRelay],
) -> Result<(Batch, u64), StoreError> {
    if proofs.is_empty() || proofs.len() > mkit_server::store::MAX_BATCH_OPS {
        return Err(StoreError::Invalid("invalid admitted relay count".into()));
    }
    let rh = keys::relay_high_water(&snapshot.source)?;
    let mut batch = Batch::new().require(match &snapshot.observed {
        Some(value) => Precondition::Equals(rh.clone(), value.clone()),
        None => Precondition::Absent(rh.clone()),
    });
    let mut sequence = snapshot.watermark;
    for proof in proofs {
        if proof.target() != &snapshot.target
            || proof.intent().generation() != snapshot.generation
            || proof.intent().source()? != snapshot.source
            || proof.intent() != proofs[0].intent()
            || proof.sequence() <= sequence
        {
            return Err(StoreError::Invalid("admitted relay proof binding".into()));
        }
        let row = codec::decode_relay(proof.row())?;
        if row.target != snapshot.target
            || row
                .puts
                .iter()
                .any(|(key, _)| key.as_bytes().starts_with(b"rh\0"))
            || row
                .deletes
                .iter()
                .any(|key| key.as_bytes().starts_with(b"rh\0"))
        {
            return Err(StoreError::Invalid(
                "admitted relay destination or watermark effect".into(),
            ));
        }
        batch.writes.extend(
            row.puts
                .into_iter()
                .map(|(key, value)| Write::Put(key, value)),
        );
        batch
            .writes
            .extend(row.deletes.into_iter().map(Write::Delete));
        sequence = proof.sequence();
    }
    let bound = proofs[0]
        .intent()
        .targets()
        .iter()
        .find(|bound| {
            bound
                .partition()
                .is_ok_and(|target| target == snapshot.target)
        })
        .ok_or_else(|| StoreError::Invalid("admitted relay target binding".into()))?;
    let included: std::collections::BTreeSet<_> =
        proofs.iter().map(VerifiedRelay::sequence).collect();
    if bound.relays().iter().any(|binding| {
        binding.sequence() > snapshot.watermark
            && binding.sequence() <= sequence
            && !included.contains(&binding.sequence())
    }) {
        return Err(StoreError::Invalid(
            "admitted relay skipped a bound message".into(),
        ));
    }
    if batch.writes.len() > mkit_server::store::adapter_spi::outbox::MAX_RELAY_PUTS {
        return Err(StoreError::Invalid(
            "admitted relay message batch bound".into(),
        ));
    }
    batch.writes.push(Write::Put(
        rh,
        codec::encode_u64(snapshot.compatibility_watermark.max(sequence)),
    ));
    Ok((batch, sequence))
}

impl<C: SqlConn> SqlKvStore<C> {
    /// Bind a permanent target generation and resume under its matching pause.
    /// Exact resumed retries do not write or consume the pruning reserve.
    /// The trusted caller must never reuse a generation after restore/rotation.
    /// It must first enforce full legacy reconciliation and consistent source/
    /// target counter ordering. Matching pause alone does not prove either.
    /// This local primitive must remain unwired until those barriers exist.
    pub fn activate_relay_admission(
        &self,
        target: &Partition,
        previous: Option<Generation>,
        generation: Generation,
    ) -> Result<(), StoreError> {
        let part = target_part(target)?;
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
    /// Observe admission, generation-bound progress and raw rh atomically.
    /// Raw rh never supplies applied progress. Admission still proves no external
    /// identity, legacy reconciliation or complete source-prefix ordering.
    pub fn relay_admission_snapshot(
        &self,
        target: &Partition,
        source: &Partition,
        generation: Generation,
    ) -> Result<RelayAdmissionSnapshot, StoreError> {
        let part = target_part(target)?;
        let rh = keys::relay_high_water(source)?;
        let source_encoded = SqlValue::Blob(source.encode()?.to_vec());
        let (observed, compatibility_watermark, progress, watermark) =
            self.conn().transaction(Box::new(move |conn| {
                require_generation(&conn, &part, generation)?;
                let observed = kv::read(&conn, &part, &rh)?;
                let watermark = observed
                    .as_ref()
                    .map(codec::decode_u64)
                    .transpose()
                    .map_err(|_| SqlError::Corrupt("relay admission watermark"))?
                    .unwrap_or(0);
                let (progress, applied) =
                    progress::read(&conn, &part, &source_encoded, generation)?;
                Ok((observed, watermark, progress, applied))
            }))?;
        Ok(RelayAdmissionSnapshot {
            target: target.clone(),
            source: source.clone(),
            generation,
            observed,
            watermark,
            compatibility_watermark,
            progress,
        })
    }
    /// Observe admission and private applied progress in one fresh SQL cut.
    /// Returns no receipt for absent or older-generation progress. A receipt
    /// proves actual local delivery, never current external authority.
    pub fn target_progress_receipt(
        &self,
        target: &Partition,
        source: &Partition,
        generation: Generation,
    ) -> Result<Option<TargetProgressReceipt>, StoreError> {
        let part = target_part(target)?;
        let encoded_source = SqlValue::Blob(source.encode()?.to_vec());
        let through = self.conn().transaction(Box::new(move |conn| {
            require_generation(&conn, &part, generation)?;
            Ok(progress::read(&conn, &part, &encoded_source, generation)?.1)
        }))?;
        Ok((through != 0).then(|| TargetProgressReceipt {
            target: target.clone(),
            source: source.clone(),
            generation,
            through,
        }))
    }
    /// Confirm a duplicate using fresh admission and private applied progress,
    /// even after source cleanup. Raw rh never supplies a duplicate proof.
    /// Only an integration-owned requested sequence may be supplied; this is not
    /// an exact source-row proof or publication coordinator completion receipt.
    /// Older-generation progress is ignored, even when compatibility rh is high.
    /// This does not establish current external identity or bootstrap readiness.
    pub fn admitted_relay_duplicate(
        &self,
        snapshot: &RelayAdmissionSnapshot,
        sequence: u64,
    ) -> Result<bool, StoreError> {
        if sequence == 0 {
            return Err(StoreError::Invalid("zero relay duplicate sequence".into()));
        }
        Ok(self
            .target_progress_receipt(&snapshot.target, &snapshot.source, snapshot.generation)?
            .is_some_and(|receipt| receipt.through() >= sequence))
    }
    /// Reconstruct complete bound messages and rh CAS from one verified intent.
    /// Every bound message through the new watermark must be supplied. The caller
    /// must separately prove no omitted auxiliary-only row precedes it; current
    /// `VerifiedRelay` cannot establish that full source-prefix condition.
    /// Extensions may add guards and auxiliary writes, but cannot edit any relay
    /// effect, shadow its keys, or introduce py/rh mutations. Final generation,
    /// pause, guards and extended batch limits are checked at SQL commit.
    pub fn apply_admitted_relay<F>(
        &self,
        snapshot: &RelayAdmissionSnapshot,
        proofs: &[VerifiedRelay],
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
        let (batch, through) = admitted_batch(snapshot, proofs)?;
        let part = target_part(&snapshot.target)?;
        let source = SqlValue::Blob(snapshot.source.encode()?.to_vec());
        let expected_progress = snapshot.progress.clone();
        let next = progress::encode(snapshot.generation, through)?;
        let caps = self.capabilities();
        progress::validate_batch(
            &batch,
            caps,
            &part,
            &source,
            expected_progress.as_deref(),
            &next,
        )?;
        let original_writes = batch.writes.clone();
        let original_guards = batch.preconditions.clone();
        let generation = snapshot.generation;
        let limit = self.metadata_soft_limit();
        Ok(self.conn().transaction(Box::new(move |conn| {
            let progress_part = part.clone();
            let progress_source = source.clone();
            let next_for_validation = next.clone();
            let progress_conn = conn.clone();
            let outcome = kv::check_and_write_extended_admitted(
                &conn,
                &part,
                batch,
                limit,
                Some(generation),
                move |get, batch, now| {
                    if progress::read(&progress_conn, &progress_part, &progress_source, generation)?
                        .0
                        != expected_progress
                    {
                        return Err(SqlError::Constraint);
                    }
                    extend(get, batch, now)?;
                    if !batch.writes.starts_with(&original_writes)
                        || !batch.preconditions.starts_with(&original_guards)
                        || batch.writes[original_writes.len()..].iter().any(|write| {
                            protected(write_key(write))
                                || original_writes
                                    .iter()
                                    .any(|original| write_key(original) == write_key(write))
                        })
                    {
                        return Err(SqlError::Corrupt(
                            "extension altered admitted relay effects",
                        ));
                    }
                    progress::validate_batch(
                        batch,
                        caps,
                        &progress_part,
                        &progress_source,
                        expected_progress.as_deref(),
                        &next_for_validation,
                    )
                    .map_err(|_| SqlError::Corrupt("extended relay progress batch allowance"))?;
                    Ok(())
                },
            )?;
            if outcome == BatchOutcome::Committed {
                progress::write(&conn, &part, &source, next)?;
            }
            Ok(outcome)
        }))?)
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests;
