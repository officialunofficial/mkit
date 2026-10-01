//! Durable deployment inspection mode on the Memory backend.
#![cfg(feature = "memory")]
#![allow(clippy::unwrap_used)]

use futures_executor::block_on;
use mkit_server::store::inspection_mode::{Outcome, check_mode};
use mkit_server::store::restore::{RestoreOptions, restore};
use mkit_server::store::{
    EXPORT_END, ExportRecord, encode_export_header, encode_export_record, export_header,
    export_page, keys,
};
use mkit_server::{Batch, MemoryKv, NamespaceKey, NamespaceStore, Partition, Value};

fn root() -> Partition {
    Partition::Namespace(NamespaceKey::deployment_default())
}

#[test]
fn pipeline_config_defaults_inspection_off() {
    let config = mkit_server::pipeline::PipelineConfig::new(
        mkit_server::Addressing::Single {
            repo: mkit_server::RepoId {
                namespace: NamespaceKey::deployment_default(),
                name: mkit_server::RepoName::new("project").unwrap(),
            },
        },
        mkit_server::pipeline::AuthMode::TransportIdentity,
        mkit_server::upload::UploadLimits {
            max_total_bytes: 1024,
            max_chunks: 1,
        },
    );
    assert!(!config.inspection_mode);
}
fn put(store: &MemoryKv, key: mkit_server::Key, bytes: &[u8]) {
    block_on(store.apply(&root(), Batch::new().put(key, Value::new(bytes.to_vec())))).unwrap();
}
fn archive(store: &MemoryKv) -> Vec<u8> {
    archive_partition(store, &root())
}
fn archive_partition(store: &MemoryKv, partition: &Partition) -> Vec<u8> {
    let header = block_on(export_header(store, partition, 0)).unwrap();
    let page = block_on(export_page(store, partition, None, 100)).unwrap();
    assert!(page.next.is_none());
    let mut bytes = encode_export_header(&header).to_vec();
    for record in page.records {
        bytes.extend(encode_export_record(&record).unwrap());
    }
    bytes.extend(EXPORT_END);
    bytes
}

#[test]
fn restore_retains_registry_and_per_advance_hold_rows_in_single_and_d34() {
    use mkit_server::store::codec;
    use mkit_server::store::inspection_flags::{FlagInstall, FlagSource, FlagV1, encode_flag};
    let ns = NamespaceKey::deployment_default();
    let repo = mkit_server::RepoName::new("project").unwrap();
    let id = [1; 32];
    let advance = [2; 32];
    let flag = encode_flag(
        &FlagV1::new(FlagInstall {
            id,
            reason: "review".into(),
            source: FlagSource {
                inspector: "moderator".into(),
                inspection_id: "inspect-1".into(),
                ref_name: "refs/heads/main".into(),
                sequence: 1,
            },
        })
        .unwrap(),
    )
    .unwrap();
    let manifest = Value::new([vec![1], id.to_vec()].concat());
    for d34 in [false, true] {
        let source = MemoryKv::default();
        assert_eq!(block_on(check_mode(&source, true)).unwrap(), Outcome::Ok);
        put(
            &source,
            keys::sharding_marker(),
            if d34 { b"d34" } else { b"single" },
        );
        let registry = if d34 {
            Partition::RepoIndex {
                ns: ns.clone(),
                repo: repo.clone(),
                prefix: 0,
            }
        } else {
            root()
        };
        let refs = if d34 {
            Partition::Ref {
                ns: ns.clone(),
                repo: repo.clone(),
                shard_ref: "refs/heads/main".into(),
            }
        } else {
            root()
        };
        let rows = [
            (
                registry.clone(),
                keys::inspection_flag(&repo, &id),
                flag.clone(),
            ),
            (
                registry.clone(),
                keys::inspection_version(&repo),
                codec::encode_u64(1),
            ),
            (
                refs.clone(),
                keys::inspection_hold(&repo, &id, &advance),
                Value::default(),
            ),
            (
                refs.clone(),
                keys::inspection_hold_index(&repo, &advance),
                manifest.clone(),
            ),
        ];
        for (partition, key, value) in &rows {
            block_on(source.apply(partition, Batch::new().put(key.clone(), value.clone())))
                .unwrap();
        }
        let mut archives = vec![archive(&source)];
        if d34 {
            let coordinator = Partition::Coordinator(ns.clone());
            block_on(source.apply(
                &coordinator,
                Batch::new().put(keys::grant_epoch(), codec::encode_u64(1)),
            ))
            .unwrap();
            archives.extend([
                archive_partition(&source, &coordinator),
                archive_partition(&source, &registry),
                archive_partition(&source, &refs),
            ]);
        }
        let restored = MemoryKv::default();
        block_on(restore(&archives, &restored, RestoreOptions::default())).unwrap();
        for (partition, key, expected) in &rows {
            assert_eq!(
                block_on(restored.get(partition, key)).unwrap().as_ref(),
                Some(expected)
            );
        }
        assert_eq!(
            block_on(check_mode(&restored, false)).unwrap(),
            Outcome::Disabled
        );
    }
}

/// A competing first ordinary write installs the logical layout row between
/// the empty scan and activation's apply; the second CAS must refuse it.
struct LateWrite(MemoryKv);
impl NamespaceStore for LateWrite {
    fn capabilities(&self) -> mkit_server::StoreCapabilities {
        self.0.capabilities()
    }
    async fn get(
        &self,
        p: &Partition,
        k: &mkit_server::Key,
    ) -> Result<Option<Value>, mkit_server::StoreError> {
        self.0.get(p, k).await
    }
    async fn scan(
        &self,
        p: &Partition,
        s: &mkit_server::Key,
        e: &mkit_server::Key,
        a: Option<&mkit_server::Cursor>,
        limit: u32,
    ) -> Result<mkit_server::ScanPage, mkit_server::StoreError> {
        assert_eq!(limit, 1);
        self.0.scan(p, s, e, a, limit).await
    }
    async fn apply(
        &self,
        p: &Partition,
        batch: Batch,
    ) -> Result<mkit_server::BatchOutcome, mkit_server::StoreError> {
        self.0
            .apply(
                p,
                Batch::new().put(
                    keys::layout_version(),
                    mkit_server::store::codec::encode_u32(keys::LAYOUT_VERSION),
                ),
            )
            .await?;
        self.0.apply(p, batch).await
    }
    async fn stats(
        &self,
        p: &Partition,
    ) -> Result<mkit_server::PartitionStats, mkit_server::StoreError> {
        self.0.stats(p).await
    }
    async fn probe(&self) -> Result<(), mkit_server::StoreError> {
        self.0.probe().await
    }
}

#[test]
fn memory_write_between_empty_probe_and_marker_apply_refuses_activation() {
    let store = LateWrite(MemoryKv::default());
    assert_eq!(
        block_on(check_mode(&store, true)).unwrap(),
        Outcome::NonEmpty
    );
    assert_eq!(
        block_on(store.get(&root(), &keys::inspection_marker())).unwrap(),
        None
    );
}

#[test]
fn memory_empty_activation_and_one_way_restart_with_zero_inspectors() {
    let store = MemoryKv::default();
    assert_eq!(block_on(check_mode(&store, false)).unwrap(), Outcome::Ok);
    assert_eq!(
        block_on(store.get(&root(), &keys::inspection_marker())).unwrap(),
        None
    );
    assert_eq!(block_on(check_mode(&store, true)).unwrap(), Outcome::Ok);
    assert_eq!(block_on(check_mode(&store, true)).unwrap(), Outcome::Ok);
    assert_eq!(
        block_on(store.get(&root(), &keys::inspection_marker())).unwrap(),
        Some(Value::new(b"on".to_vec()))
    );
    assert_eq!(
        block_on(check_mode(&store, false)).unwrap(),
        Outcome::Disabled
    );
}

#[test]
fn memory_nonempty_store_and_bootstrap_rows_refuse_first_activation() {
    for key in [
        keys::layout_version(),
        keys::sharding_marker(),
        keys::addressing_marker(),
        mkit_server::Key::new(b"data".as_slice()),
    ] {
        let store = MemoryKv::default();
        put(&store, key, b"single");
        assert_eq!(
            block_on(check_mode(&store, true)).unwrap(),
            Outcome::NonEmpty
        );
        assert_eq!(block_on(check_mode(&store, false)).unwrap(), Outcome::Ok);
        assert_eq!(
            block_on(store.get(&root(), &keys::inspection_marker())).unwrap(),
            None
        );
    }
}

#[test]
fn memory_corrupt_marker_fails_closed_even_when_disabled() {
    for bad in [b"".as_slice(), b"off", b"ON", b"on\0", b"single"] {
        let store = MemoryKv::default();
        put(&store, keys::inspection_marker(), bad);
        for enabled in [false, true] {
            assert_eq!(
                block_on(check_mode(&store, enabled)).unwrap(),
                Outcome::Corrupt
            );
        }
    }
}

#[test]
fn memory_export_restore_preserves_inspection_mode() {
    let store = MemoryKv::default();
    assert_eq!(block_on(check_mode(&store, true)).unwrap(), Outcome::Ok);
    put(&store, keys::sharding_marker(), b"single");
    let restored = MemoryKv::default();
    block_on(restore(
        &[archive(&store)],
        &restored,
        RestoreOptions::default(),
    ))
    .unwrap();
    assert_eq!(block_on(check_mode(&restored, true)).unwrap(), Outcome::Ok);
    assert_eq!(
        block_on(check_mode(&restored, false)).unwrap(),
        Outcome::Disabled
    );
}

#[test]
fn restore_rejects_invalid_or_misplaced_inspection_marker_before_writes() {
    for (partition, value) in [
        (root(), b"off".as_slice()),
        (Partition::ContentShard(1), b"on".as_slice()),
    ] {
        let header = mkit_server::store::ExportHeader::new(keys::LAYOUT_VERSION, 0);
        let mut bytes = encode_export_header(&header).to_vec();
        bytes.extend(
            encode_export_record(&ExportRecord::new(
                partition,
                keys::inspection_marker(),
                Value::new(value.to_vec()),
            ))
            .unwrap(),
        );
        bytes.extend(EXPORT_END);
        let store = MemoryKv::default();
        assert!(matches!(
            block_on(restore(&[bytes], &store, RestoreOptions::default())),
            Err(mkit_server::StoreError::Corrupt(_))
        ));
        assert_eq!(
            block_on(store.get(&root(), &keys::inspection_marker())).unwrap(),
            None
        );
    }
}
