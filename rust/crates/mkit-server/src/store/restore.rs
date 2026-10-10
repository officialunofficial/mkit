//! Restore portable partition exports into a quiesced, fresh store.
//!
//! The input is validated and every supplied target partition is checked
//! before the first write. A caller must provide a newly empty store and keep
//! traffic off it until restore succeeds: this trait cannot enumerate
//! unsupplied partitions, and restore is not atomic across partitions. For
//! relay sources, a successful restore raises each queued sequence and `os`
//! by `max(snapshot os, supplied target rh)`. Queued sequences then exceed
//! supplied watermarks. If `os` was absent, the first future allocation is
//! one above the restored watermark. Fresh targets contain only supplied
//! partitions; missing relay sources and coordinators are rejected unless
//! the operator explicitly requests their safe reconstruction.
//! Already delivered rows no longer exist on the source. Re-keying cannot
//! fill an older target's missing membership or index rows; R-116 requires
//! post-restore reconciliation before GA.
//! Restored coordinator `ls` maxima reset to zero; every restored ref shard
//! with queued relay rows gets an expired, sweepable `ls` row. The recovery
//! marker fences watermark reads until R-116 reconciliation completes.

#[cfg(test)]
use std::collections::{BTreeMap, BTreeSet};

use super::codec::{self, LeaseRecovery};
#[cfg(test)]
use super::keys::ParsedKey;
use super::{Batch, BatchOutcome, NamespaceStore, Partition, StoreError, keys};
#[cfg(test)]
use super::{ExportHeader, ExportReader, ExportRecord, ImportMode, Importer, export_page};
#[cfg(test)]
use crate::repo::NamespaceKey;
#[cfg(test)]
use crate::timers::lease_sweep::lease_reference;
#[cfg(test)]
use crate::timers::registry::kinds;

/// Parameters for a restore into empty partitions.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg(test)]
pub(crate) struct RestoreOptions {
    /// Require at least this epoch in restored namespace coordinators.
    pub epoch_at_least: Option<u64>,
    /// The restore clock reading used for the lease-table recovery marker.
    pub recovered_at_ms: u64,
    /// Reconstruct missing sources and coordinators (requires an epoch floor
    /// for missing coordinators).
    pub allow_incomplete: bool,
}

/// Counts committed by a successful restore.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg(test)]
pub(crate) struct RestoreReport {
    /// Number of distinct imported partitions.
    pub partitions: usize,
    /// Number of imported records, including the rewritten epoch and sequence.
    pub records: u64,
    /// Missing relay sources reconstructed with a sequence floor.
    pub missing_sources: Vec<Partition>,
    /// Missing namespace coordinators reconstructed with a new epoch.
    pub missing_coordinators: Vec<Partition>,
}

#[derive(Debug)]
#[cfg(test)]
struct SnapshotInfo {
    index: usize,
    partition: Partition,
    header: ExportHeader,
    epoch: u64,
    outbox_sequence: u64,
    has_outbox_sequence: bool,
    max_relay_sequence: u64,
    has_relay: bool,
    sharding_marker: Option<ExportRecord>,
    inspection_marker: Option<ExportRecord>,
    authority_fence: bool,
    authority_generation: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(test)]
enum ShardingMode {
    Single,
    D34,
}

#[cfg(test)]
impl ShardingMode {
    fn coordinator(self, partition: &Partition) -> bool {
        match self {
            Self::Single => matches!(partition, Partition::Namespace(_)),
            Self::D34 => matches!(partition, Partition::Coordinator(_)),
        }
    }
}

#[cfg(test)]
fn invalid(message: &'static str) -> StoreError {
    StoreError::Invalid(message.into())
}

fn corrupt(message: &'static str) -> StoreError {
    StoreError::Corrupt(message.into())
}

#[cfg(test)]
fn priority(info: &SnapshotInfo) -> u8 {
    if info.sharding_marker.is_some() {
        return 0;
    }
    match info.partition {
        Partition::Namespace(_) => 1,
        Partition::Coordinator(_) => 2,
        Partition::Ref { .. } => 3,
        Partition::RefIndex { .. } | Partition::RepoIndex { .. } => 4,
        Partition::ContentShard(_) => 5,
    }
}

#[cfg(test)]
fn inspect(
    index: usize,
    bytes: &[u8],
    seen: &mut BTreeSet<Partition>,
    watermarks: &mut BTreeMap<Partition, u64>,
) -> Result<SnapshotInfo, StoreError> {
    let (header, reader) = ExportReader::new(bytes)?;
    let mut partition = None;
    let mut epoch = 0;
    let mut outbox_sequence = 0;
    let mut has_outbox_sequence = false;
    let mut max_relay_sequence = 0;
    let mut has_relay = false;
    let mut sharding_marker = None;
    let mut inspection_marker = None;
    let mut authority_fence = false;
    let mut authority_generation = None;
    for record in reader {
        let record = record?;
        match &partition {
            Some(p) if p != &record.partition => {
                return Err(invalid("snapshot contains multiple partitions"));
            }
            None => partition = Some(record.partition.clone()),
            _ => {}
        }
        if record.key == keys::authority_generation() {
            authority_generation = Some(codec::decode_u64(&record.value)?);
            authority_fence = true;
        } else if record.key == keys::epoch_lease() {
            authority_generation = codec::decode_epoch_lease(&record.value)?.authority_generation;
            authority_fence |= authority_generation.is_some();
        } else if record.key == keys::lease_recovery() {
            authority_fence |=
                codec::decode_lease_recovery(&record.value)?.authority_fence == Some(true);
        }
        validate_inspection_record(&record)?;
        match keys::parse(&record.key) {
            Some(ParsedKey::Ticket(_)) => {
                let ticket = codec::decode_ticket(&record.value)?;
                authority_generation = authority_generation.max(ticket.authority_generation);
                authority_fence |= ticket.authority_generation.is_some();
            }
            Some(ParsedKey::GrantEpoch) => epoch = codec::decode_u64(&record.value)?,
            Some(ParsedKey::OutboxSequence) => {
                outbox_sequence = codec::decode_u64(&record.value)?;
                has_outbox_sequence = true;
            }
            Some(ParsedKey::Relay(seq)) => {
                has_relay = true;
                if seq == 0 {
                    return Err(corrupt("relay sequence is zero"));
                }
                codec::decode_relay(&record.value)?;
                max_relay_sequence = max_relay_sequence.max(seq);
            }
            Some(ParsedKey::LayoutVersion)
                if codec::decode_u32(&record.value)? != keys::LAYOUT_VERSION =>
            {
                return Err(StoreError::Unsupported(
                    "snapshot layout differs from this binary".into(),
                ));
            }
            Some(ParsedKey::RelayHighWater(source)) => {
                let rh = codec::decode_u64(&record.value)?;
                let prior = watermarks.entry(source).or_default();
                *prior = (*prior).max(rh);
            }
            Some(ParsedKey::ShardingMarker) => sharding_marker = Some(record),
            Some(ParsedKey::InspectionMarker) => inspection_marker = Some(record),
            _ => {}
        }
    }
    let partition = partition.ok_or_else(|| invalid("snapshot contains no partition records"))?;
    if !seen.insert(partition.clone()) {
        return Err(invalid("duplicate partition snapshot"));
    }
    validate_sequences(max_relay_sequence, outbox_sequence, has_outbox_sequence)?;
    if sharding_marker.is_some()
        && partition != Partition::Namespace(NamespaceKey::deployment_default())
    {
        return Err(corrupt("sharding marker outside root namespace partition"));
    }
    if inspection_marker.is_some()
        && partition != Partition::Namespace(NamespaceKey::deployment_default())
    {
        return Err(corrupt(
            "inspection marker outside root namespace partition",
        ));
    }
    Ok(SnapshotInfo {
        index,
        partition,
        header,
        epoch,
        outbox_sequence,
        has_outbox_sequence,
        max_relay_sequence,
        has_relay,
        sharding_marker,
        inspection_marker,
        authority_fence,
        authority_generation,
    })
}

#[cfg(test)]
fn validate_sequences(
    max_relay_sequence: u64,
    outbox_sequence: u64,
    has_outbox_sequence: bool,
) -> Result<(), StoreError> {
    if max_relay_sequence > outbox_sequence {
        return Err(corrupt("relay sequence exceeds outbox sequence"));
    }
    if max_relay_sequence > 0 && outbox_sequence == 0 {
        return Err(corrupt("relay rows require an outbox sequence"));
    }
    if has_outbox_sequence && outbox_sequence == 0 {
        return Err(corrupt("outbox sequence is zero"));
    }
    Ok(())
}

#[cfg(test)]
fn validate_inspection_record(record: &ExportRecord) -> Result<(), StoreError> {
    match keys::parse(&record.key) {
        Some(ParsedKey::InspectionMarker) if record.value.as_bytes() != b"on" => {
            Err(corrupt("invalid inspection marker"))
        }
        Some(ParsedKey::InspectionFlag { repo, id }) => {
            inspection_partition(&record.partition, &repo, true)?;
            if super::inspection_flags::decode_flag(&record.value)?.id != id {
                return Err(corrupt("inspection flag id disagrees with key"));
            }
            Ok(())
        }
        Some(ParsedKey::InspectionVersion(repo)) => {
            inspection_partition(&record.partition, &repo, true)?;
            if codec::decode_u64(&record.value)? == 0 {
                return Err(corrupt("inspection registry version is zero"));
            }
            Ok(())
        }
        Some(ParsedKey::InspectionHold { repo, .. }) => {
            inspection_partition(&record.partition, &repo, true)?;
            if !record.value.as_bytes().is_empty() {
                return Err(corrupt("invalid inspection hold row"));
            }
            Ok(())
        }
        Some(ParsedKey::InspectionHoldIndex { repo, .. }) => {
            inspection_partition(&record.partition, &repo, false)?;
            super::inspection_holds::validate_advance_hold(&record.value)
        }
        Some(ParsedKey::InspectionHoldManifest { repo, .. }) => {
            inspection_partition(&record.partition, &repo, true)?;
            super::inspection_holds::validate_manifest(&record.value)
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
fn inspection_partition(
    partition: &Partition,
    repo: &crate::RepoName,
    registry: bool,
) -> Result<(), StoreError> {
    match partition {
        Partition::Namespace(_) => Ok(()),
        Partition::RepoIndex {
            repo: stored,
            prefix: 0,
            ..
        } if registry && stored == repo => Ok(()),
        Partition::Ref { repo: stored, .. } if !registry && stored == repo => Ok(()),
        _ => Err(corrupt("inspection row outside its authority partition")),
    }
}

#[cfg(test)]
fn should_drop(record: &ExportRecord) -> bool {
    record.key == keys::revoke_cursor(false)
        || record.key == keys::revoke_cursor(true)
        || record.key == keys::backup_state()
        || record.key == keys::epoch_lease()
        || record.key == keys::relay_scan()
        || record.key == keys::lease_reconcile()
        || matches!(
            keys::parse(&record.key),
            Some(ParsedKey::Timer { kind, .. }) if kind == kinds::BACKUP.get() || kind == kinds::LEASE_SWEEP.get()
        )
}

/// Write `lr 00` exactly as the pipeline's recovery declaration does.
///
/// This must finish before a restored coordinator serves writes.
pub(crate) async fn mark_lease_table_recovered<S: NamespaceStore>(
    store: &S,
    partition: &Partition,
    recovered_at_ms: u64,
) -> Result<(), StoreError> {
    let key = keys::lease_recovery();
    let prior = store.get(partition, &key).await?;
    let authority = store.get(partition, &keys::authority_generation()).await?;
    if let Some(value) = authority.as_ref() {
        codec::decode_u64(value)?;
    }
    let mode = prior
        .as_ref()
        .map(codec::decode_lease_recovery)
        .transpose()?;
    if mode.is_some_and(|m| m.authority_fence == Some(true)) && authority.is_none() {
        return Err(corrupt("fenced recovery requires authority generation"));
    }
    let batch = Batch::new()
        .require(match authority.as_ref() {
            Some(value) => super::Precondition::Equals(keys::authority_generation(), value.clone()),
            None => super::Precondition::Absent(keys::authority_generation()),
        })
        .require(match prior.as_ref() {
            Some(value) => super::Precondition::Equals(key.clone(), value.clone()),
            None => super::Precondition::Absent(key.clone()),
        })
        .delete(keys::lease_reconcile())
        .delete(keys::revoke_cursor(false))
        .delete(keys::revoke_cursor(true))
        .put(
            key,
            codec::encode_lease_recovery(&LeaseRecovery {
                authority_fence: authority.as_ref().map(|_| true),
                authority_ready: authority
                    .as_ref()
                    .map(|_| mode.is_some_and(|m| m.authority_ready == Some(true))),
                activation_only: None,
                resumed_at_ms: recovered_at_ms,
            }),
        );
    match store.apply(partition, batch).await? {
        BatchOutcome::Committed => Ok(()),
        _ => Err(StoreError::unavailable(
            "recovery marker batch did not commit",
        )),
    }
}

#[cfg(test)]
struct RestorePlan {
    infos: Vec<SnapshotInfo>,
    shifts: BTreeMap<Partition, u64>,
    mode: ShardingMode,
    missing_sources: Vec<(Partition, u64)>,
    missing_coordinators: Vec<Partition>,
}

#[cfg(test)]
const EPOCH_RESTORE_JUMP: u64 = 1 << 32;

#[cfg(test)]
fn namespace(partition: &Partition) -> Option<&NamespaceKey> {
    match partition {
        Partition::Namespace(ns)
        | Partition::Coordinator(ns)
        | Partition::Ref { ns, .. }
        | Partition::RefIndex { ns, .. }
        | Partition::RepoIndex { ns, .. } => Some(ns),
        Partition::ContentShard(_) => None,
    }
}

#[cfg(test)]
struct Completeness {
    sources: BTreeSet<Partition>,
    missing_sources: Vec<(Partition, u64)>,
    missing_coordinators: Vec<Partition>,
}

#[cfg(test)]
fn check_completeness(
    infos: &[SnapshotInfo],
    seen: &BTreeSet<Partition>,
    watermarks: &BTreeMap<Partition, u64>,
    mode: ShardingMode,
    opts: RestoreOptions,
) -> Result<Completeness, StoreError> {
    let sources: BTreeSet<_> = infos
        .iter()
        .filter(|info| info.has_outbox_sequence || info.has_relay)
        .map(|info| info.partition.clone())
        .collect();
    let missing_sources: Vec<_> = watermarks
        .iter()
        .filter(|(source, _)| !sources.contains(*source))
        .map(|(source, floor)| (source.clone(), *floor))
        .collect();
    let required_coordinators: BTreeSet<_> = infos
        .iter()
        .map(|info| &info.partition)
        .chain(missing_sources.iter().map(|(source, _)| source))
        .filter(|partition| match mode {
            ShardingMode::Single => matches!(partition, Partition::Namespace(_)),
            ShardingMode::D34 => matches!(
                partition,
                Partition::Ref { .. } | Partition::RefIndex { .. } | Partition::RepoIndex { .. }
            ),
        })
        .filter_map(namespace)
        .map(|ns| match mode {
            ShardingMode::Single => Partition::Namespace(ns.clone()),
            ShardingMode::D34 => Partition::Coordinator(ns.clone()),
        })
        .collect();
    let missing_coordinators: Vec<_> = required_coordinators.difference(seen).cloned().collect();
    if !missing_sources.is_empty() && !opts.allow_incomplete {
        return Err(StoreError::Invalid(
            format!("missing relay sources: {missing_sources:?}").into(),
        ));
    }
    if !missing_coordinators.is_empty() && (!opts.allow_incomplete || opts.epoch_at_least.is_none())
    {
        return Err(StoreError::Invalid(format!("missing namespace coordinators (requires --allow-incomplete and --epoch-at-least): {missing_coordinators:?}").into()));
    }
    // A missing coordinator's history is unknown, so the floor must exceed any
    // epoch a namespace plausibly issued; grants compare epochs by equality.
    if !missing_coordinators.is_empty()
        && opts
            .epoch_at_least
            .is_some_and(|floor| floor < EPOCH_RESTORE_JUMP)
    {
        return Err(StoreError::Invalid(
            format!(
                "--epoch-at-least must be at least {EPOCH_RESTORE_JUMP} for missing coordinators"
            )
            .into(),
        ));
    }
    for partition in sources
        .iter()
        .chain(missing_sources.iter().map(|(partition, _)| partition))
    {
        if !matches!(partition, Partition::Ref { .. }) {
            return Err(invalid("relay high-water names a non-ref source"));
        }
    }
    Ok(Completeness {
        sources,
        missing_sources,
        missing_coordinators,
    })
}

#[allow(clippy::too_many_lines)] // All portable input, fence and arithmetic checks must finish before any import writes.
#[cfg(test)]
async fn prepare<S: NamespaceStore>(
    snapshots: &[Vec<u8>],
    target: &S,
    opts: RestoreOptions,
) -> Result<RestorePlan, StoreError> {
    let mut seen = BTreeSet::new();
    let mut watermarks = BTreeMap::new();
    let mut infos = Vec::new();
    for (index, bytes) in snapshots.iter().enumerate() {
        let (_, mut reader) = ExportReader::new(bytes)?;
        if reader.next().transpose()?.is_none() {
            tracing::warn!(index, "skipping recordless restore archive");
            continue;
        }
        infos.push(inspect(index, bytes, &mut seen, &mut watermarks)?);
    }
    let marker = infos
        .iter()
        .find_map(|info| info.sharding_marker.as_ref())
        .ok_or_else(|| invalid("restore requires the root sharding marker"))?;
    let mode = match marker.value.as_bytes() {
        b"single" => ShardingMode::Single,
        b"d34" => ShardingMode::D34,
        _ => return Err(corrupt("invalid sharding marker")),
    };
    let Completeness {
        sources,
        missing_sources,
        missing_coordinators,
    } = check_completeness(&infos, &seen, &watermarks, mode, opts)?;
    for info in &infos {
        let incompatible = match mode {
            ShardingMode::Single => matches!(
                info.partition,
                Partition::Coordinator(_)
                    | Partition::Ref { .. }
                    | Partition::RepoIndex { .. }
                    | Partition::RefIndex { .. }
            ),
            ShardingMode::D34 => {
                matches!(info.partition, Partition::Namespace(_)) && info.sharding_marker.is_none()
            }
        };
        if incompatible {
            return Err(invalid("snapshot partition conflicts with sharding marker"));
        }
    }
    for info in infos.iter().filter(|info| info.authority_fence) {
        let owner = infos.iter().find(|candidate| {
            mode.coordinator(&candidate.partition)
                && namespace(&candidate.partition) == namespace(&info.partition)
        });
        if owner.is_none_or(|owner| {
            owner.authority_generation.is_none()
                || info.authority_generation > owner.authority_generation
        }) {
            return Err(invalid(
                "fenced snapshot requires authoritative generation without rollback",
            ));
        }
    }
    for coordinator in &missing_coordinators {
        if infos.iter().any(|info| {
            info.authority_fence && namespace(&info.partition) == namespace(coordinator)
        }) {
            return Err(invalid(
                "fenced namespace coordinator cannot be reconstructed without authority state",
            ));
        }
    }
    for partition in missing_sources
        .iter()
        .map(|(p, _)| p)
        .chain(missing_coordinators.iter())
    {
        let page = export_page(target, partition, None, 1).await?;
        if !page.records.is_empty() {
            return Err(invalid("restore target partition is not empty"));
        }
    }

    // Preflight every supplied partition before the first Importer batch.
    for info in &infos {
        Importer::new(target, &info.header, ImportMode::Fresh)?;
        let page = export_page(target, &info.partition, None, 1).await?;
        if !page.records.is_empty() {
            return Err(invalid("restore target partition is not empty"));
        }
    }

    // Check all arithmetic before writing anything. Every shifted row and
    // future allocation then starts above the largest supplied target rh.
    let mut shifts = BTreeMap::new();
    for info in &infos {
        if sources.contains(&info.partition) {
            let shift = info
                .outbox_sequence
                .max(*watermarks.get(&info.partition).unwrap_or(&0));
            info.outbox_sequence
                .checked_add(shift)
                .and_then(|next| next.checked_add(1))
                .ok_or_else(|| invalid("restore relay sequence overflow"))?;
            info.max_relay_sequence
                .checked_add(shift)
                .ok_or_else(|| invalid("restore relay sequence overflow"))?;
            shifts.insert(info.partition.clone(), shift);
        }
        if mode.coordinator(&info.partition) {
            info.epoch
                .checked_add(EPOCH_RESTORE_JUMP)
                .ok_or_else(|| invalid("restore epoch overflow"))?;
        }
    }

    infos.sort_by_key(|info| (priority(info), info.partition.clone()));
    Ok(RestorePlan {
        infos,
        shifts,
        mode,
        missing_sources,
        missing_coordinators,
    })
}

#[cfg(test)]
async fn import_one<S: NamespaceStore>(
    bytes: &[u8],
    target: &S,
    info: &SnapshotInfo,
    shift: Option<u64>,
    mode: ShardingMode,
    opts: RestoreOptions,
) -> Result<u64, StoreError> {
    let (_, reader) = ExportReader::new(bytes)?;
    let mut importer = Importer::new(target, &info.header, ImportMode::Fresh)?;
    if let Some(marker) = &info.sharding_marker {
        importer.push(marker.clone()).await?;
    }
    if let Some(marker) = &info.inspection_marker {
        importer.push(marker.clone()).await?;
    }
    for record in reader {
        let mut record = record?;
        if record.key == keys::sharding_marker() && info.sharding_marker.is_some() {
            continue;
        }
        if record.key == keys::inspection_marker() && info.inspection_marker.is_some() {
            continue;
        }
        if should_drop(&record)
            || (mode.coordinator(&info.partition) && record.key == keys::grant_epoch())
        {
            continue;
        }
        if let Some(shift) = shift {
            match keys::parse(&record.key) {
                Some(ParsedKey::Relay(seq)) => {
                    record.key = keys::relay(
                        seq.checked_add(shift)
                            .ok_or_else(|| invalid("restore relay sequence overflow"))?,
                    );
                }
                Some(ParsedKey::OutboxSequence) => {
                    record.value = codec::encode_u64(
                        info.outbox_sequence
                            .checked_add(shift)
                            .ok_or_else(|| invalid("restore relay sequence overflow"))?,
                    );
                }
                _ => {}
            }
        }
        if let Some(ParsedKey::LeasedShard { repo, shard_ref }) = keys::parse(&record.key) {
            let mut row = codec::decode_leased_shard(&record.value)?;
            row.expires_at_ms = opts.recovered_at_ms;
            row.relay_watermark_ms = 0;
            row.sweep_due_ms = opts.recovered_at_ms;
            record.value = codec::encode_leased_shard(&row);
            importer.push(record).await?;
            importer
                .push(ExportRecord::new(
                    info.partition.clone(),
                    keys::timer(
                        opts.recovered_at_ms,
                        kinds::LEASE_SWEEP.get(),
                        &lease_reference(&repo, &shard_ref),
                    ),
                    super::Value::default(),
                ))
                .await?;
            continue;
        }
        importer.push(record).await?;
    }
    if mode.coordinator(&info.partition) {
        let epoch = info
            .epoch
            .checked_add(EPOCH_RESTORE_JUMP)
            .ok_or_else(|| invalid("restore epoch overflow"))?
            .max(opts.epoch_at_least.unwrap_or(0));
        importer
            .push(ExportRecord::new(
                info.partition.clone(),
                keys::grant_epoch(),
                codec::encode_u64(epoch),
            ))
            .await?;
    }
    if let Some(shift) = shift
        && !info.has_outbox_sequence
        && shift > 0
    {
        importer
            .push(ExportRecord::new(
                info.partition.clone(),
                keys::outbox_sequence(),
                codec::encode_u64(shift),
            ))
            .await?;
    }
    let records = importer.finish().await?;
    if mode.coordinator(&info.partition) {
        mark_lease_table_recovered(target, &info.partition, opts.recovered_at_ms).await?;
    }
    Ok(records)
}

#[cfg(test)]
async fn create_missing_sources<S: NamespaceStore>(
    target: &S,
    sources: &[(Partition, u64)],
    supplied: &BTreeSet<Partition>,
    report: &mut RestoreReport,
) -> Result<(), StoreError> {
    for (partition, floor) in sources {
        if *floor > 0 {
            match target
                .apply(
                    partition,
                    Batch::new().put(keys::outbox_sequence(), codec::encode_u64(*floor)),
                )
                .await?
            {
                BatchOutcome::Committed => {}
                _ => {
                    return Err(StoreError::unavailable(
                        "missing relay source creation did not commit",
                    ));
                }
            }
        }
        report.records += u64::from(*floor > 0);
        if !supplied.contains(partition) {
            report.partitions += 1;
        }
        report.missing_sources.push(partition.clone());
    }
    Ok(())
}

#[cfg(test)]
async fn seed_relay_leases<S: NamespaceStore>(
    target: &S,
    sources: Vec<Partition>,
    recovered_at_ms: u64,
    report: &mut RestoreReport,
) -> Result<(), StoreError> {
    for source in sources {
        let Partition::Ref {
            ns,
            repo,
            shard_ref,
        } = source
        else {
            unreachable!("relay sources were filtered to ref shards")
        };
        let coordinator = Partition::Coordinator(ns);
        let key = keys::leased_shard(&repo, &shard_ref);
        if target.get(&coordinator, &key).await?.is_some() {
            continue;
        }
        let epoch = target
            .get(&coordinator, &keys::grant_epoch())
            .await?
            .as_ref()
            .map(codec::decode_u64)
            .transpose()?
            .unwrap_or(0);
        let authority_generation = target
            .get(&coordinator, &keys::authority_generation())
            .await?
            .as_ref()
            .map(codec::decode_u64)
            .transpose()?;
        let row = codec::LeasedShard {
            authority_generation,
            acked_authority_generation: authority_generation,
            epoch,
            expires_at_ms: recovered_at_ms,
            acked_epoch: epoch,
            relay_watermark_ms: 0,
            sweep_due_ms: recovered_at_ms,
        };
        let batch = Batch::new().put(key, codec::encode_leased_shard(&row)).put(
            keys::timer(
                recovered_at_ms,
                kinds::LEASE_SWEEP.get(),
                &lease_reference(&repo, &shard_ref),
            ),
            super::Value::default(),
        );
        match target.apply(&coordinator, batch).await? {
            BatchOutcome::Committed => report.records += 2,
            _ => {
                return Err(StoreError::Corrupt(
                    "restored relay lease row did not commit".into(),
                ));
            }
        }
    }
    Ok(())
}

/// Restore exports into a fresh store, in dependency order.
///
/// Each nonempty export must contain exactly one partition. Recordless
/// exports are skipped with a warning because their header cannot identify
/// a target partition. All input and all supplied target
/// emptiness checks complete before any partition is written. This function
/// is intended for an offline, newly empty target: imports span batches.
///
/// # Errors
/// Malformed or duplicate snapshots, non-empty supplied target partitions,
/// epoch or relay sequence overflow, or a store failure.
#[cfg(test)]
pub(crate) async fn restore<S: NamespaceStore>(
    snapshots: &[Vec<u8>],
    target: &S,
    opts: RestoreOptions,
) -> Result<RestoreReport, StoreError> {
    let plan = prepare(snapshots, target, opts).await?;
    let supplied: BTreeSet<_> = plan
        .infos
        .iter()
        .map(|info| info.partition.clone())
        .collect();
    let relay_sources: Vec<Partition> = plan
        .infos
        .iter()
        .filter(|info| info.has_relay && matches!(info.partition, Partition::Ref { .. }))
        .map(|info| info.partition.clone())
        .collect();
    let mut report = RestoreReport::default();
    let mut wrote_missing_coordinators = false;
    let mut wrote_missing_sources = false;
    for info in plan.infos {
        if !wrote_missing_coordinators && priority(&info) > 2 {
            for partition in &plan.missing_coordinators {
                let epoch = opts
                    .epoch_at_least
                    .ok_or_else(|| invalid("missing coordinator epoch floor"))?;
                match target
                    .apply(
                        partition,
                        Batch::new().put(keys::grant_epoch(), codec::encode_u64(epoch)),
                    )
                    .await?
                {
                    BatchOutcome::Committed => {}
                    _ => {
                        return Err(StoreError::unavailable(
                            "missing coordinator creation did not commit",
                        ));
                    }
                }
                mark_lease_table_recovered(target, partition, opts.recovered_at_ms).await?;
                report.records += 2;
                report.partitions += 1;
                report.missing_coordinators.push(partition.clone());
            }
            wrote_missing_coordinators = true;
        }
        if !wrote_missing_sources && priority(&info) > 3 {
            create_missing_sources(target, &plan.missing_sources, &supplied, &mut report).await?;
            wrote_missing_sources = true;
        }
        report.records += import_one(
            &snapshots[info.index],
            target,
            &info,
            plan.shifts.get(&info.partition).copied(),
            plan.mode,
            opts,
        )
        .await?;
        report.partitions += 1;
    }
    if !wrote_missing_sources {
        create_missing_sources(target, &plan.missing_sources, &supplied, &mut report).await?;
    }
    seed_relay_leases(target, relay_sources, opts.recovered_at_ms, &mut report).await?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use futures_executor::block_on;

    use super::*;
    use crate::memory::MemoryKv;
    use crate::relay::{NoHook, RelayBudget, RelayHandler};
    use crate::repo::{NamespaceKey, RepoName};
    use crate::store::{
        Cursor, EXPORT_END, Key, PartitionStats, ScanPage, StoreCapabilities, Value, Write,
        encode_export_header, encode_export_record,
    };
    use crate::timers::{DueTimer, TimerCtx, TimerHandler, registry::kinds};

    fn root() -> Partition {
        Partition::Namespace(NamespaceKey::deployment_default())
    }

    fn coordinator() -> Partition {
        Partition::Coordinator(NamespaceKey::deployment_default())
    }

    fn source() -> Partition {
        Partition::Ref {
            ns: NamespaceKey::deployment_default(),
            repo: RepoName::new("repo").unwrap(),
            shard_ref: "refs/heads/main".into(),
        }
    }

    fn target() -> Partition {
        Partition::RepoIndex {
            ns: NamespaceKey::deployment_default(),
            repo: RepoName::new("repo").unwrap(),
            prefix: 1,
        }
    }

    fn empty_target() -> Partition {
        Partition::ContentShard(7)
    }

    fn old_lease() -> Value {
        codec::encode_epoch_lease(&codec::EpochLease {
            authority_ready: None,
            authority_generation: None,
            epoch: 7,
            expires_at_ms: 999_999,
            config_version: 1,
        })
    }

    fn snapshot(partition: &Partition, rows: Vec<(Key, Value)>) -> Vec<u8> {
        let header = ExportHeader::new(keys::LAYOUT_VERSION, 100);
        let mut bytes = encode_export_header(&header).to_vec();
        for (key, value) in rows {
            bytes.extend_from_slice(
                &encode_export_record(&ExportRecord::new(partition.clone(), key, value)).unwrap(),
            );
        }
        bytes.extend_from_slice(&EXPORT_END);
        bytes
    }

    #[derive(Default)]
    struct RootFirst {
        inner: MemoryKv,
        writes: Mutex<Vec<Partition>>,
    }

    impl NamespaceStore for RootFirst {
        fn capabilities(&self) -> StoreCapabilities {
            self.inner.capabilities()
        }

        async fn get(&self, p: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
            self.inner.get(p, key).await
        }

        async fn scan(
            &self,
            p: &Partition,
            start: &Key,
            end: &Key,
            after: Option<&Cursor>,
            limit: u32,
        ) -> Result<ScanPage, StoreError> {
            self.inner.scan(p, start, end, after, limit).await
        }

        async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
            if p == &root() && self.writes.lock().unwrap().is_empty() {
                assert!(matches!(
                    batch.writes.first(),
                    Some(Write::Put(key, _)) if key == &keys::sharding_marker()
                ));
            }
            if p != &root()
                && self
                    .inner
                    .get(&root(), &keys::sharding_marker())
                    .await?
                    .is_none()
            {
                return Err(invalid("root marker was not imported first"));
            }
            self.writes.lock().unwrap().push(p.clone());
            self.inner.apply(p, batch).await
        }

        async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
            self.inner.stats(p).await
        }

        async fn probe(&self) -> Result<(), StoreError> {
            self.inner.probe().await
        }
    }

    fn assert_delivers_once(store: RootFirst, shift: u64) {
        let handler = RelayHandler {
            target: store,
            hook: NoHook,
            budget: RelayBudget::default(),
        };
        let source_partition = source();
        let ctx = TimerCtx {
            store: &handler.target,
            partition: &source_partition,
            now_ms: 200,
        };
        let timer = DueTimer {
            due_at_ms: 200,
            kind: kinds::RELAY,
            reference: bytes::Bytes::default(),
            value: Value::default(),
        };
        block_on(handler.fire(&ctx, &timer)).unwrap();
        for (partition, key, seq) in [
            (target(), Key::new(b"m\0x".to_vec()), 2 + shift),
            (empty_target(), Key::new(b"m\0y".to_vec()), 3 + shift),
        ] {
            assert_eq!(
                block_on(handler.target.get(&partition, &key)).unwrap(),
                Some(Value::default())
            );
            assert_eq!(
                block_on(
                    handler
                        .target
                        .get(&partition, &keys::relay_high_water(&source()).unwrap())
                )
                .unwrap(),
                Some(codec::encode_u64(seq))
            );
        }
        let count_target_applies = || {
            handler
                .target
                .writes
                .lock()
                .unwrap()
                .iter()
                .filter(|p| **p == target() || **p == empty_target())
                .count()
        };
        let first = count_target_applies();
        block_on(handler.fire(&ctx, &timer)).unwrap();
        assert_eq!(
            count_target_applies(),
            first,
            "repeat fire has no second target effect"
        );
    }

    fn assert_restored_lease_rows(store: &RootFirst) {
        for name in ["other", "repo"] {
            let repo = RepoName::new(name).expect("test repository name");
            let row = block_on(store.get(
                &coordinator(),
                &keys::leased_shard(&repo, "refs/heads/main"),
            ))
            .expect("read restored lease")
            .expect("restored lease exists");
            let row = codec::decode_leased_shard(&row).expect("decode restored lease");
            assert_eq!(row.relay_watermark_ms, 0);
            assert_eq!(row.expires_at_ms, 500);
            assert_eq!(row.sweep_due_ms, 500);
            assert!(
                block_on(store.get(
                    &coordinator(),
                    &keys::timer(
                        500,
                        kinds::LEASE_SWEEP.get(),
                        &lease_reference(&repo, "refs/heads/main")
                    )
                ))
                .expect("read restored sweep timer")
                .is_some()
            );
        }
        assert!(
            block_on(store.get(
                &coordinator(),
                &keys::timer(
                    999_999,
                    kinds::LEASE_SWEEP.get(),
                    &lease_reference(
                        &RepoName::new("other").expect("test repository name"),
                        "refs/heads/main"
                    )
                )
            ))
            .expect("read old sweep timer")
            .is_none()
        );
    }

    fn assert_restored_source_rows(
        store: RootFirst,
        relay: Value,
        relay_to_empty: Value,
        shift: u64,
    ) {
        assert_eq!(
            block_on(store.get(&source(), &keys::outbox_sequence()))
                .expect("read restored source sequence"),
            Some(codec::encode_u64(3 + shift))
        );
        assert_eq!(
            block_on(store.get(&source(), &keys::relay(2 + shift)))
                .expect("read first restored relay"),
            Some(relay)
        );
        assert_eq!(
            block_on(store.get(&source(), &keys::relay(3 + shift)))
                .expect("read second restored relay"),
            Some(relay_to_empty)
        );
        for key in [
            keys::relay(2),
            keys::epoch_lease(),
            keys::relay_scan(),
            keys::backup_state(),
            keys::timer(123, kinds::BACKUP.get(), b""),
        ] {
            assert_eq!(
                block_on(store.get(&source(), &key)).expect("read discarded source row"),
                None
            );
        }
        assert_delivers_once(store, shift);
    }

    #[test]
    fn fresh_restore_orders_root_and_rewrites_recovery_epoch_and_relay() {
        let index = snapshot(
            &target(),
            vec![(
                keys::relay_high_water(&source()).unwrap(),
                codec::encode_u64(10),
            )],
        );
        let relay_to = |target, key: &[u8]| {
            codec::encode_relay(&codec::RelayV1 {
                at_ms: 100,
                target,
                puts: vec![(Key::new(key.to_vec()), Value::default())],
                deletes: Vec::new(),
            })
            .unwrap()
        };
        let relay = relay_to(target(), b"m\0x");
        let relay_to_empty = relay_to(empty_target(), b"m\0y");
        let ref_shard = snapshot(
            &source(),
            vec![
                (keys::outbox_sequence(), codec::encode_u64(3)),
                (keys::relay(2), relay.clone()),
                (keys::relay(3), relay_to_empty.clone()),
                (keys::epoch_lease(), old_lease()),
                (keys::relay_scan(), Value::default()),
                (keys::backup_state(), Value::default()),
                (keys::timer(123, kinds::BACKUP.get(), b""), Value::default()),
            ],
        );
        let coordinator_snapshot = snapshot(
            &coordinator(),
            vec![
                (keys::grant_epoch(), codec::encode_u64(7)),
                (
                    keys::leased_shard(&RepoName::new("other").unwrap(), "refs/heads/main"),
                    codec::encode_leased_shard(&codec::LeasedShard {
                        authority_generation: None,
                        acked_authority_generation: None,
                        epoch: 7,
                        expires_at_ms: 999_999,
                        acked_epoch: 7,
                        relay_watermark_ms: 888_888,
                        sweep_due_ms: 999_999,
                    }),
                ),
                (
                    keys::timer(
                        999_999,
                        kinds::LEASE_SWEEP.get(),
                        &lease_reference(&RepoName::new("other").unwrap(), "refs/heads/main"),
                    ),
                    Value::default(),
                ),
            ],
        );
        let root_snapshot = snapshot(
            &root(),
            vec![(keys::sharding_marker(), Value::new(b"d34".to_vec()))],
        );
        let store = RootFirst::default();
        let report = block_on(restore(
            &[index, ref_shard, coordinator_snapshot, root_snapshot],
            &store,
            RestoreOptions {
                epoch_at_least: Some(11),
                recovered_at_ms: 500,
                allow_incomplete: false,
            },
        ))
        .unwrap();
        assert_eq!(report.partitions, 4);
        assert_eq!(store.writes.lock().unwrap().first(), Some(&root()));
        assert_eq!(
            block_on(store.get(&coordinator(), &keys::grant_epoch())).unwrap(),
            Some(codec::encode_u64(7 + EPOCH_RESTORE_JUMP))
        );
        let lr = block_on(store.get(&coordinator(), &keys::lease_recovery()))
            .unwrap()
            .unwrap();
        assert_eq!(
            codec::decode_lease_recovery(&lr).unwrap().resumed_at_ms,
            500
        );
        assert_restored_lease_rows(&store);
        let writes = store.writes.lock().unwrap();
        let coordinator_write = writes.iter().position(|p| p == &coordinator()).unwrap();
        let ref_write = writes.iter().position(|p| p == &source()).unwrap();
        assert!(coordinator_write < ref_write);
        drop(writes);
        assert_eq!(
            block_on(store.get(&root(), &keys::grant_epoch())).unwrap(),
            None,
            "the D34 root marker is not a coordinator"
        );
        assert_eq!(
            block_on(store.get(&root(), &keys::lease_recovery())).unwrap(),
            None
        );
        assert_restored_source_rows(store, relay, relay_to_empty, 10);
    }

    #[test]
    fn fresh_preflight_refuses_nonempty_without_partial_root_import() {
        let root_snapshot = snapshot(
            &root(),
            vec![(keys::sharding_marker(), Value::new(b"d34".to_vec()))],
        );
        let coordinator_snapshot = snapshot(
            &coordinator(),
            vec![(keys::grant_epoch(), codec::encode_u64(8))],
        );
        let store = MemoryKv::default();
        block_on(store.apply(
            &coordinator(),
            Batch::new().put(keys::grant_epoch(), codec::encode_u64(9)),
        ))
        .unwrap();
        assert!(matches!(
            block_on(restore(
                &[root_snapshot, coordinator_snapshot],
                &store,
                RestoreOptions::default()
            )),
            Err(StoreError::Invalid(_))
        ));
        assert_eq!(
            block_on(store.get(&root(), &keys::sharding_marker())).unwrap(),
            None
        );
    }

    #[test]
    fn malformed_and_overflowing_snapshots_fail_before_writes() {
        let root_snapshot = snapshot(
            &root(),
            vec![(keys::sharding_marker(), Value::new(b"d34".to_vec()))],
        );
        let store = MemoryKv::default();
        assert!(matches!(
            block_on(restore(&[], &store, RestoreOptions::default())),
            Err(StoreError::Invalid(_))
        ));
        assert!(matches!(
            block_on(restore(
                &[root_snapshot.clone(), root_snapshot.clone()],
                &store,
                RestoreOptions::default()
            )),
            Err(StoreError::Invalid(_))
        ));
        let empty = [
            encode_export_header(&ExportHeader::new(keys::LAYOUT_VERSION, 0)).as_ref(),
            &EXPORT_END,
        ]
        .concat();
        assert!(matches!(
            block_on(restore(&[empty], &store, RestoreOptions::default())),
            Err(StoreError::Invalid(_))
        ));
        let overflowing = snapshot(
            &source(),
            vec![(keys::outbox_sequence(), codec::encode_u64(u64::MAX))],
        );
        let coordinator_snapshot = snapshot(
            &coordinator(),
            vec![(keys::grant_epoch(), codec::encode_u64(1))],
        );
        let err = block_on(restore(
            &[root_snapshot, coordinator_snapshot, overflowing],
            &store,
            RestoreOptions::default(),
        ))
        .unwrap_err();
        assert!(err.to_string().contains("restore relay sequence overflow"));
        assert_eq!(
            block_on(store.get(&root(), &keys::sharding_marker())).unwrap(),
            None
        );
    }

    #[test]
    fn single_namespace_epoch_rises_and_declares_recovery() {
        let snapshot = snapshot(
            &root(),
            vec![
                (keys::sharding_marker(), Value::new(b"single".to_vec())),
                (keys::grant_epoch(), codec::encode_u64(7)),
            ],
        );
        let store = MemoryKv::default();
        block_on(restore(
            &[snapshot],
            &store,
            RestoreOptions {
                epoch_at_least: None,
                recovered_at_ms: 44,
                allow_incomplete: false,
            },
        ))
        .unwrap();
        assert_eq!(
            block_on(store.get(&root(), &keys::grant_epoch())).unwrap(),
            Some(codec::encode_u64(7 + EPOCH_RESTORE_JUMP))
        );
        let lr = block_on(store.get(&root(), &keys::lease_recovery()))
            .unwrap()
            .unwrap();
        assert_eq!(codec::decode_lease_recovery(&lr).unwrap().resumed_at_ms, 44);
    }

    #[test]
    fn restore_refuses_a_snapshot_from_another_layout_version() {
        for version in [keys::LAYOUT_VERSION - 1, keys::LAYOUT_VERSION + 1] {
            let snap = snapshot(
                &source(),
                vec![(keys::layout_version(), codec::encode_u32(version))],
            );
            let store = MemoryKv::default();
            let result = block_on(restore(
                &[snap],
                &store,
                RestoreOptions {
                    allow_incomplete: true,
                    ..RestoreOptions::default()
                },
            ));
            assert!(
                matches!(result, Err(StoreError::Unsupported(_))),
                "{version}"
            );
        }
    }

    #[test]
    fn absent_outbox_sequence_starts_next_allocation_above_target_watermark() {
        let root_snapshot = snapshot(
            &root(),
            vec![(keys::sharding_marker(), Value::new(b"d34".to_vec()))],
        );
        let ref_snapshot = snapshot(
            &source(),
            vec![(
                keys::layout_version(),
                codec::encode_u32(keys::LAYOUT_VERSION),
            )],
        );
        let index_snapshot = snapshot(
            &target(),
            vec![(
                keys::relay_high_water(&source()).unwrap(),
                codec::encode_u64(5),
            )],
        );
        let store = MemoryKv::default();
        block_on(restore(
            &[ref_snapshot, index_snapshot, root_snapshot],
            &store,
            RestoreOptions {
                allow_incomplete: true,
                epoch_at_least: Some(EPOCH_RESTORE_JUMP + 99),
                ..RestoreOptions::default()
            },
        ))
        .unwrap();
        let os = block_on(store.get(&source(), &keys::outbox_sequence()))
            .unwrap()
            .unwrap();
        assert_eq!(codec::decode_u64(&os).unwrap(), 5);
        assert!(codec::decode_u64(&os).unwrap() + 1 > 5);
    }

    #[test]
    fn missing_source_is_refused_or_reconstructed_above_target_watermark() {
        let archives = [
            snapshot(
                &root(),
                vec![(keys::sharding_marker(), Value::new(b"d34".to_vec()))],
            ),
            snapshot(
                &coordinator(),
                vec![(keys::grant_epoch(), codec::encode_u64(1))],
            ),
            snapshot(
                &target(),
                vec![(
                    keys::relay_high_water(&source()).unwrap(),
                    codec::encode_u64(10),
                )],
            ),
        ];
        let store = RootFirst::default();
        let err = block_on(restore(&archives, &store, RestoreOptions::default())).unwrap_err();
        assert!(err.to_string().contains("missing relay sources"));
        assert!(err.to_string().contains("refs/heads/main"));
        let report = block_on(restore(
            &archives,
            &store,
            RestoreOptions {
                allow_incomplete: true,
                ..RestoreOptions::default()
            },
        ))
        .unwrap();
        assert_eq!(report.missing_sources, vec![source()]);
        assert_eq!(
            block_on(store.get(&source(), &keys::outbox_sequence())).unwrap(),
            Some(codec::encode_u64(10))
        );
        let relay = codec::encode_relay(&codec::RelayV1 {
            at_ms: 100,
            target: target(),
            puts: vec![(
                Key::new(b"m\0new".as_slice()),
                Value::new(b"delivered".as_slice()),
            )],
            deletes: Vec::new(),
        })
        .unwrap();
        block_on(
            store.apply(
                &source(),
                Batch::new()
                    .put(keys::outbox_sequence(), codec::encode_u64(11))
                    .put(keys::relay(11), relay),
            ),
        )
        .unwrap();
        let handler = RelayHandler {
            target: store,
            hook: NoHook,
            budget: RelayBudget::default(),
        };
        let ctx = TimerCtx {
            store: &handler.target,
            partition: &source(),
            now_ms: 200,
        };
        let timer = DueTimer {
            due_at_ms: 200,
            kind: kinds::RELAY,
            reference: bytes::Bytes::default(),
            value: Value::default(),
        };
        block_on(handler.fire(&ctx, &timer)).unwrap();
        assert_eq!(
            block_on(
                handler
                    .target
                    .get(&target(), &Key::new(b"m\0new".as_slice()))
            )
            .unwrap(),
            Some(Value::new(b"delivered".as_slice()))
        );
        assert_eq!(
            block_on(
                handler
                    .target
                    .get(&target(), &keys::relay_high_water(&source()).unwrap())
            )
            .unwrap(),
            Some(codec::encode_u64(11))
        );
    }

    #[test]
    fn missing_coordinator_requires_both_flags_and_is_recovered_before_ref() {
        let archives = [
            snapshot(
                &root(),
                vec![(keys::sharding_marker(), Value::new(b"d34".to_vec()))],
            ),
            snapshot(
                &source(),
                vec![(keys::outbox_sequence(), codec::encode_u64(1))],
            ),
        ];
        let store = RootFirst::default();
        for opts in [
            RestoreOptions::default(),
            RestoreOptions {
                allow_incomplete: true,
                ..RestoreOptions::default()
            },
        ] {
            let err = block_on(restore(&archives, &store, opts)).unwrap_err();
            assert!(err.to_string().contains("missing namespace coordinators"));
        }
        let low = block_on(restore(
            &archives,
            &store,
            RestoreOptions {
                allow_incomplete: true,
                epoch_at_least: Some(42),
                ..RestoreOptions::default()
            },
        ))
        .unwrap_err();
        assert!(low.to_string().contains("must be at least"));
        let floor = EPOCH_RESTORE_JUMP + 42;
        let report = block_on(restore(
            &archives,
            &store,
            RestoreOptions {
                allow_incomplete: true,
                epoch_at_least: Some(floor),
                ..RestoreOptions::default()
            },
        ))
        .unwrap();
        assert_eq!(report.missing_coordinators, vec![coordinator()]);
        assert_eq!(
            block_on(store.get(&coordinator(), &keys::grant_epoch())).unwrap(),
            Some(codec::encode_u64(floor))
        );
        assert!(
            block_on(store.get(&coordinator(), &keys::lease_recovery()))
                .unwrap()
                .is_some()
        );
        let writes = store.writes.lock().unwrap();
        assert!(
            writes.iter().position(|p| p == &coordinator()).unwrap()
                < writes.iter().position(|p| p == &source()).unwrap()
        );
    }

    #[test]
    fn older_target_cannot_recover_already_delivered_rows() {
        let archives = [
            snapshot(
                &root(),
                vec![(keys::sharding_marker(), Value::new(b"d34".to_vec()))],
            ),
            snapshot(
                &coordinator(),
                vec![(keys::grant_epoch(), codec::encode_u64(1))],
            ),
            snapshot(
                &source(),
                vec![(keys::outbox_sequence(), codec::encode_u64(5))],
            ),
            snapshot(
                &target(),
                vec![(
                    keys::relay_high_water(&source()).unwrap(),
                    codec::encode_u64(2),
                )],
            ),
        ];
        let store = MemoryKv::default();
        block_on(restore(&archives, &store, RestoreOptions::default())).unwrap();
        let os = block_on(store.get(&source(), &keys::outbox_sequence()))
            .unwrap()
            .unwrap();
        assert!(codec::decode_u64(&os).unwrap() > 2);
        assert_eq!(
            block_on(store.get(&target(), &Key::new(b"m\0already-delivered".as_slice()))).unwrap(),
            None
        );
    }

    #[test]
    fn epoch_floor_and_overflow() {
        let root_archive = snapshot(
            &root(),
            vec![
                (keys::sharding_marker(), Value::new(b"single".to_vec())),
                (keys::grant_epoch(), codec::encode_u64(7)),
            ],
        );
        let store = MemoryKv::default();
        block_on(restore(
            &[root_archive],
            &store,
            RestoreOptions {
                epoch_at_least: Some(EPOCH_RESTORE_JUMP + 100),
                ..RestoreOptions::default()
            },
        ))
        .unwrap();
        assert_eq!(
            block_on(store.get(&root(), &keys::grant_epoch())).unwrap(),
            Some(codec::encode_u64(EPOCH_RESTORE_JUMP + 100))
        );
        let overflow = snapshot(
            &root(),
            vec![
                (keys::sharding_marker(), Value::new(b"single".to_vec())),
                (
                    keys::grant_epoch(),
                    codec::encode_u64(u64::MAX - EPOCH_RESTORE_JUMP + 1),
                ),
            ],
        );
        assert!(matches!(
            block_on(restore(
                &[overflow],
                &MemoryKv::default(),
                RestoreOptions::default()
            )),
            Err(StoreError::Invalid(_))
        ));
    }
    #[test]
    fn fenced_restore_preserves_mode_without_business_creation_and_rejects_missing_state() {
        let mode = codec::LeaseRecovery {
            authority_fence: Some(true),
            authority_ready: Some(true),
            activation_only: Some(true),
            resumed_at_ms: 0,
        };
        let archives = [
            snapshot(
                &root(),
                vec![(keys::sharding_marker(), Value::new(b"d34".to_vec()))],
            ),
            snapshot(
                &coordinator(),
                vec![
                    (keys::authority_generation(), codec::encode_u64(7)),
                    (keys::lease_recovery(), codec::encode_lease_recovery(&mode)),
                ],
            ),
        ];
        let store = MemoryKv::default();
        block_on(restore(
            &archives,
            &store,
            RestoreOptions {
                recovered_at_ms: 100,
                ..RestoreOptions::default()
            },
        ))
        .unwrap();
        assert_eq!(
            block_on(store.get(&coordinator(), &keys::authority_generation())).unwrap(),
            Some(codec::encode_u64(7))
        );
        assert!(
            block_on(store.get(&coordinator(), &keys::namespace_record()))
                .unwrap()
                .is_none()
        );
        let raw = block_on(store.get(&coordinator(), &keys::lease_recovery()))
            .unwrap()
            .unwrap();
        let recovered = codec::decode_lease_recovery(&raw).unwrap();
        assert_eq!(recovered.authority_fence, Some(true));
        assert_eq!(recovered.authority_ready, Some(true));
        assert_eq!(recovered.recovery_time(), Some(100));
        let lease = codec::EpochLease {
            epoch: 0,
            config_version: 1,
            expires_at_ms: 1000,
            authority_generation: Some(7),
            authority_ready: Some(true),
        };
        let incomplete = [
            snapshot(
                &root(),
                vec![(keys::sharding_marker(), Value::new(b"d34".to_vec()))],
            ),
            snapshot(
                &source(),
                vec![(keys::epoch_lease(), codec::encode_epoch_lease(&lease))],
            ),
        ];
        let fresh = MemoryKv::default();
        assert!(
            block_on(restore(
                &incomplete,
                &fresh,
                RestoreOptions {
                    allow_incomplete: true,
                    epoch_at_least: Some(0),
                    ..RestoreOptions::default()
                }
            ))
            .is_err()
        );
        assert!(
            block_on(fresh.get(&root(), &keys::sharding_marker()))
                .unwrap()
                .is_none()
        );
    }
}
