//! Restore portable partition exports into a quiesced, fresh store.
//!
//! The input is validated and every supplied target partition is checked
//! before the first write. A caller must provide a newly empty store and keep
//! traffic off it until restore succeeds: this trait cannot enumerate
//! unsupplied partitions, and restore is not atomic across partitions. For
//! relay sources, a successful restore raises each queued sequence and `os`
//! by `max(snapshot os, supplied target rh)`. Queued sequences then exceed
//! supplied watermarks. If `os` was absent, the first future allocation is
//! one above the restored watermark. The Fresh precondition makes the
//! supplied target set complete for a newly created deployment.

use std::collections::{BTreeMap, BTreeSet};

use super::codec::{self, LeaseRecovery};
use super::keys::{self, ParsedKey};
use super::{
    Batch, BatchOutcome, ExportHeader, ExportReader, ExportRecord, ImportMode, Importer,
    NamespaceStore, Partition, StoreError, export_page,
};
use crate::repo::NamespaceKey;

/// Parameters for a restore into empty partitions.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RestoreOptions {
    /// Require at least this epoch in restored namespace coordinators.
    pub epoch_at_least: Option<u64>,
    /// The restore clock reading used for the lease-table recovery marker.
    pub recovered_at_ms: u64,
}

/// Counts committed by a successful restore.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RestoreReport {
    /// Number of distinct imported partitions.
    pub partitions: usize,
    /// Number of imported records, including the rewritten epoch and sequence.
    pub records: u64,
}

#[derive(Debug)]
struct SnapshotInfo {
    index: usize,
    partition: Partition,
    header: ExportHeader,
    epoch: u64,
    outbox_sequence: u64,
    has_outbox_sequence: bool,
    max_relay_sequence: u64,
    sharding_marker: Option<ExportRecord>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShardingMode {
    Single,
    D34,
}

impl ShardingMode {
    fn coordinator(self, partition: &Partition) -> bool {
        match self {
            Self::Single => matches!(partition, Partition::Namespace(_)),
            Self::D34 => matches!(partition, Partition::Coordinator(_)),
        }
    }
}

fn invalid(message: &'static str) -> StoreError {
    StoreError::Invalid(message.into())
}

fn corrupt(message: &'static str) -> StoreError {
    StoreError::Corrupt(message.into())
}

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
    let mut sharding_marker = None;
    for record in reader {
        let record = record?;
        match &partition {
            Some(p) if p != &record.partition => {
                return Err(invalid("snapshot contains multiple partitions"));
            }
            None => partition = Some(record.partition.clone()),
            _ => {}
        }
        match keys::parse(&record.key) {
            Some(ParsedKey::GrantEpoch) => epoch = codec::decode_u64(&record.value)?,
            Some(ParsedKey::OutboxSequence) => {
                outbox_sequence = codec::decode_u64(&record.value)?;
                has_outbox_sequence = true;
            }
            Some(ParsedKey::Relay(seq)) => {
                if seq == 0 {
                    return Err(corrupt("relay sequence is zero"));
                }
                codec::decode_relay(&record.value)?;
                max_relay_sequence = max_relay_sequence.max(seq);
            }
            Some(ParsedKey::LayoutVersion)
                if codec::decode_u32(&record.value)? > keys::LAYOUT_VERSION =>
            {
                return Err(StoreError::Unsupported(
                    "snapshot layout is newer than this binary".into(),
                ));
            }
            Some(ParsedKey::RelayHighWater(source)) => {
                let rh = codec::decode_u64(&record.value)?;
                let prior = watermarks.entry(source).or_default();
                *prior = (*prior).max(rh);
            }
            Some(ParsedKey::ShardingMarker) => sharding_marker = Some(record),
            _ => {}
        }
    }
    let partition = partition.ok_or_else(|| invalid("snapshot contains no partition records"))?;
    if !seen.insert(partition.clone()) {
        return Err(invalid("duplicate partition snapshot"));
    }
    if max_relay_sequence > outbox_sequence {
        return Err(corrupt("relay sequence exceeds outbox sequence"));
    }
    if max_relay_sequence > 0 && outbox_sequence == 0 {
        return Err(corrupt("relay rows require an outbox sequence"));
    }
    if has_outbox_sequence && outbox_sequence == 0 {
        return Err(corrupt("outbox sequence is zero"));
    }
    if sharding_marker.is_some()
        && partition != Partition::Namespace(NamespaceKey::deployment_default())
    {
        return Err(corrupt("sharding marker outside root namespace partition"));
    }
    Ok(SnapshotInfo {
        index,
        partition,
        header,
        epoch,
        outbox_sequence,
        has_outbox_sequence,
        max_relay_sequence,
        sharding_marker,
    })
}

fn should_drop(record: &ExportRecord) -> bool {
    record.key == keys::backup_state()
        || record.key == keys::epoch_lease()
        || record.key.as_bytes() == b"rs\0"
        || matches!(
            keys::parse(&record.key),
            Some(ParsedKey::Timer { kind: 4, .. })
        )
}

/// Write `lr 00` exactly as the pipeline's recovery declaration does.
///
/// This must finish before a restored coordinator serves writes.
pub async fn mark_lease_table_recovered<S: NamespaceStore>(
    store: &S,
    partition: &Partition,
    recovered_at_ms: u64,
) -> Result<(), StoreError> {
    let batch = Batch::new().put(
        keys::lease_recovery(),
        codec::encode_lease_recovery(&LeaseRecovery {
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

struct RestorePlan {
    infos: Vec<SnapshotInfo>,
    shifts: BTreeMap<Partition, u64>,
    mode: ShardingMode,
}

async fn prepare<S: NamespaceStore>(
    snapshots: &[Vec<u8>],
    target: &S,
) -> Result<RestorePlan, StoreError> {
    let mut seen = BTreeSet::new();
    let mut watermarks = BTreeMap::new();
    let mut infos = snapshots
        .iter()
        .enumerate()
        .map(|(index, bytes)| inspect(index, bytes, &mut seen, &mut watermarks))
        .collect::<Result<Vec<_>, _>>()?;
    let marker = infos
        .iter()
        .find_map(|info| info.sharding_marker.as_ref())
        .ok_or_else(|| invalid("restore requires the root sharding marker"))?;
    let mode = match marker.value.as_bytes() {
        b"single" => ShardingMode::Single,
        b"d34" => ShardingMode::D34,
        _ => return Err(corrupt("invalid sharding marker")),
    };
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
        if matches!(info.partition, Partition::Ref { .. }) {
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
                .checked_add(1)
                .ok_or_else(|| invalid("restore epoch overflow"))?;
        }
    }

    infos.sort_by_key(|info| (priority(info), info.partition.clone()));
    Ok(RestorePlan {
        infos,
        shifts,
        mode,
    })
}

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
    for record in reader {
        let mut record = record?;
        if record.key == keys::sharding_marker() && info.sharding_marker.is_some() {
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
        importer.push(record).await?;
    }
    if mode.coordinator(&info.partition) {
        let epoch = info
            .epoch
            .checked_add(1)
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

/// Restore exports into a fresh store, in dependency order.
///
/// Each export must contain exactly one partition and at least one record.
/// The export format has no partition in its header, so a recordless export
/// cannot identify the target partition. All input and all supplied target
/// emptiness checks complete before any partition is written. This function
/// is intended for an offline, newly empty target: imports span batches.
///
/// # Errors
/// Malformed or duplicate snapshots, non-empty supplied target partitions,
/// epoch or relay sequence overflow, or a store failure.
pub async fn restore<S: NamespaceStore>(
    snapshots: &[Vec<u8>],
    target: &S,
    opts: RestoreOptions,
) -> Result<RestoreReport, StoreError> {
    let plan = prepare(snapshots, target).await?;
    let mut report = RestoreReport::default();
    for info in plan.infos {
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

    #[test]
    fn fresh_restore_orders_root_and_rewrites_recovery_epoch_and_relay() {
        let index = snapshot(
            &target(),
            vec![(
                keys::relay_high_water(&source()).unwrap(),
                codec::encode_u64(10),
            )],
        );
        let relay = codec::encode_relay(&codec::RelayV1 {
            at_ms: 100,
            target: target(),
            puts: vec![(Key::new(b"m\0x".to_vec()), Value::default())],
        })
        .unwrap();
        let relay_to_empty = codec::encode_relay(&codec::RelayV1 {
            at_ms: 100,
            target: empty_target(),
            puts: vec![(Key::new(b"m\0y".to_vec()), Value::default())],
        })
        .unwrap();
        let ref_shard = snapshot(
            &source(),
            vec![
                (keys::outbox_sequence(), codec::encode_u64(3)),
                (keys::relay(2), relay.clone()),
                (keys::relay(3), relay_to_empty.clone()),
                (keys::epoch_lease(), old_lease()),
                (Key::new(b"rs\0".to_vec()), Value::default()),
                (keys::backup_state(), Value::default()),
                (keys::timer(123, 4, b""), Value::default()),
            ],
        );
        let coordinator_snapshot = snapshot(
            &coordinator(),
            vec![(keys::grant_epoch(), codec::encode_u64(7))],
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
            },
        ))
        .unwrap();
        assert_eq!(report.partitions, 4);
        assert_eq!(store.writes.lock().unwrap().first(), Some(&root()));
        assert_eq!(
            block_on(store.get(&coordinator(), &keys::grant_epoch())).unwrap(),
            Some(codec::encode_u64(11))
        );
        let lr = block_on(store.get(&coordinator(), &keys::lease_recovery()))
            .unwrap()
            .unwrap();
        assert_eq!(
            codec::decode_lease_recovery(&lr).unwrap().resumed_at_ms,
            500
        );
        assert_eq!(
            block_on(store.get(&root(), &keys::grant_epoch())).unwrap(),
            None,
            "the D34 root marker is not a coordinator"
        );
        assert_eq!(
            block_on(store.get(&root(), &keys::lease_recovery())).unwrap(),
            None
        );
        let shift = 10;
        assert_eq!(
            block_on(store.get(&source(), &keys::outbox_sequence())).unwrap(),
            Some(codec::encode_u64(3 + shift))
        );
        assert_eq!(
            block_on(store.get(&source(), &keys::relay(2 + shift))).unwrap(),
            Some(relay)
        );
        assert_eq!(
            block_on(store.get(&source(), &keys::relay(3 + shift))).unwrap(),
            Some(relay_to_empty)
        );
        for key in [
            keys::relay(2),
            keys::epoch_lease(),
            Key::new(b"rs\0".to_vec()),
            keys::backup_state(),
            keys::timer(123, 4, b""),
        ] {
            assert_eq!(block_on(store.get(&source(), &key)).unwrap(), None);
        }

        assert_delivers_once(store, shift);
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
        assert!(matches!(
            block_on(restore(
                &[root_snapshot, overflowing],
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
            },
        ))
        .unwrap();
        assert_eq!(
            block_on(store.get(&root(), &keys::grant_epoch())).unwrap(),
            Some(codec::encode_u64(8))
        );
        let lr = block_on(store.get(&root(), &keys::lease_recovery()))
            .unwrap()
            .unwrap();
        assert_eq!(codec::decode_lease_recovery(&lr).unwrap().resumed_at_ms, 44);
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
            RestoreOptions::default(),
        ))
        .unwrap();
        let os = block_on(store.get(&source(), &keys::outbox_sequence()))
            .unwrap()
            .unwrap();
        assert_eq!(codec::decode_u64(&os).unwrap(), 5);
        assert!(codec::decode_u64(&os).unwrap() + 1 > 5);
    }
}
