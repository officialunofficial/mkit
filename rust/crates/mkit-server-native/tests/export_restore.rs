//! Native portable export and restore commands.
#![cfg(feature = "http")]
#![allow(clippy::unwrap_used)]

use std::path::Path;
use std::process::Command;

use mkit_server::pipeline::Sharding;
use mkit_server::sql::{SqlConn, SqlKvStore, SqlValue};
use mkit_server::store::{Batch, BatchOutcome, Key, NamespaceStore, Partition, Value, codec, keys};
use mkit_server::{NamespaceKey, RepoName};
use mkit_server_native::{RusqliteConn, exit, server};

const BIN: &str = env!("CARGO_BIN_EXE_mkit-server");

fn put(store: &SqlKvStore<RusqliteConn>, partition: &Partition, key: &[u8], value: &[u8]) {
    assert_eq!(
        futures::executor::block_on(store.apply(
            partition,
            Batch::new().put(Key::new(key.to_vec()), Value::new(value.to_vec())),
        ))
        .unwrap(),
        BatchOutcome::Committed
    );
}

fn assert_single_restored(target: &Path) {
    let target_conn = RusqliteConn::open(target).unwrap();
    let target_store = SqlKvStore::open(target_conn.clone()).unwrap();
    let root = Partition::decode(b"nroot\0").unwrap();
    let content = Partition::ContentShard(7);
    let get = |p: &Partition, key: Key| {
        futures::executor::block_on(target_store.get(p, &key))
            .unwrap()
            .unwrap()
    };
    assert_eq!(
        get(&root, Key::new(b"r\0main".as_slice())).as_bytes(),
        b"commit-1"
    );
    assert_eq!(
        get(&content, Key::new(b"x\0item".as_slice())).as_bytes(),
        b"present"
    );
    assert_eq!(get(&root, keys::sharding_marker()).as_bytes(), b"single");
    assert_eq!(
        target_conn
            .query("SELECT mode FROM mkit_server_sharding WHERE id = 1", &[])
            .unwrap(),
        vec![vec![SqlValue::Text("single".to_owned())]]
    );
}

fn seed_d34_invariants(store: &SqlKvStore<RusqliteConn>) -> (Partition, Partition, Partition) {
    put(store, &Partition::ContentShard(1), b"x\0item", b"yes");
    let ns = NamespaceKey::deployment_default();
    let repo = RepoName::new("project").unwrap();
    let coordinator = Partition::Coordinator(ns.clone());
    let source_ref = Partition::Ref {
        ns: ns.clone(),
        repo: repo.clone(),
        shard_ref: "refs/heads/main".into(),
    };
    let target_index = Partition::RefIndex {
        ns,
        repo,
        bucket: 1,
    };
    put(
        store,
        &coordinator,
        keys::grant_epoch().as_bytes(),
        codec::encode_u64(5).as_bytes(),
    );
    put(
        store,
        &source_ref,
        keys::outbox_sequence().as_bytes(),
        codec::encode_u64(3).as_bytes(),
    );
    let relay = codec::RelayV1 {
        at_ms: 1,
        target: target_index.clone(),
        puts: vec![(
            Key::new(b"ri\0item".as_slice()),
            Value::new(b"present".as_slice()),
        )],
    };
    put(
        store,
        &source_ref,
        keys::relay(2).as_bytes(),
        codec::encode_relay(&relay).unwrap().as_bytes(),
    );
    put(store, &source_ref, b"rs\0", b"stale-scan");
    put(
        store,
        &source_ref,
        keys::backup_state().as_bytes(),
        b"stale-backup",
    );
    put(
        store,
        &source_ref,
        keys::timer(7, 4, b"backup").as_bytes(),
        b"backup",
    );
    put(
        store,
        &target_index,
        keys::relay_high_water(&source_ref).unwrap().as_bytes(),
        codec::encode_u64(10).as_bytes(),
    );
    (coordinator, source_ref, target_index)
}

#[test]
fn export_restore_roundtrip_and_usage_refusals() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source.sqlite3");
    let wrong_meta_out = dir.path().join("wrong-meta");
    let refused = Command::new(BIN)
        .args(["export", "--meta", "fs-layout", "--out"])
        .arg(&wrong_meta_out)
        .output()
        .unwrap();
    assert_eq!(refused.status.code(), Some(i32::from(exit::USAGE)));
    assert!(!wrong_meta_out.exists());
    let conn = RusqliteConn::open(&source).unwrap();
    let store = SqlKvStore::open(conn).unwrap();
    let root = Partition::decode(b"nroot\0").unwrap();
    let content = Partition::ContentShard(7);
    put(&store, &root, b"r\0main", b"commit-1");
    put(&store, &content, b"x\0item", b"present");

    let meta = format!("sqlite:{}", source.display());
    let out = dir.path().join("portable");
    let exported = Command::new(BIN)
        .args(["export", "--meta", &meta, "--out"])
        .arg(&out)
        .output()
        .unwrap();
    assert!(
        exported.status.success(),
        "{}",
        String::from_utf8_lossy(&exported.stderr)
    );
    let archive = out.join("namespace");
    assert!(archive.is_dir());
    let refused = Command::new(BIN)
        .args(["export", "--meta", &meta, "--out"])
        .arg(&out)
        .output()
        .unwrap();
    assert_eq!(refused.status.code(), Some(i32::from(exit::USAGE)));

    let target = dir.path().join("target.sqlite3");
    let target_meta = format!("sqlite:{}", target.display());
    let refused = Command::new(BIN)
        .args(["restore", "--meta", "fs-layout", "--from"])
        .arg(&out)
        .output()
        .unwrap();
    assert_eq!(refused.status.code(), Some(i32::from(exit::USAGE)));
    let restored = Command::new(BIN)
        .args(["restore", "--meta", &target_meta, "--from"])
        .arg(&out)
        .output()
        .unwrap();
    assert!(
        restored.status.success(),
        "{}",
        String::from_utf8_lossy(&restored.stderr)
    );
    assert_single_restored(&target);
    let refused = Command::new(BIN)
        .args(["restore", "--meta", &target_meta, "--from"])
        .arg(&out)
        .output()
        .unwrap();
    assert_eq!(refused.status.code(), Some(i32::from(exit::USAGE)));
    let refused = Command::new(BIN)
        .args(["restore", "--meta", &target_meta, "--from"])
        .arg(&out)
        .arg("--merge")
        .output()
        .unwrap();
    assert_eq!(refused.status.code(), Some(i32::from(exit::USAGE)));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let file = std::fs::read_dir(
            std::fs::read_dir(archive)
                .unwrap()
                .next()
                .unwrap()
                .unwrap()
                .path(),
        )
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
        assert_eq!(
            std::fs::metadata(file).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn d34_archive_creates_root_marker_and_checks_restore_mode() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source.sqlite3");
    let conn = RusqliteConn::open(&source).unwrap();
    let store = SqlKvStore::open(conn.clone()).unwrap();
    server::bind_sharding(&conn, Sharding::D34, &source).unwrap();
    let (coordinator, source_ref, target_index) = seed_d34_invariants(&store);
    let out = dir.path().join("export");
    let source_meta = format!("sqlite:{}", source.display());
    assert!(
        Command::new(BIN)
            .args(["export", "--meta", &source_meta, "--out"])
            .arg(&out)
            .status()
            .unwrap()
            .success()
    );

    let target = dir.path().join("target.sqlite3");
    let target_meta = format!("sqlite:{}", target.display());
    let mismatch = Command::new(BIN)
        .args(["restore", "--meta", &target_meta, "--from"])
        .arg(&out)
        .output()
        .unwrap();
    assert_eq!(mismatch.status.code(), Some(i32::from(exit::USAGE)));
    assert!(!target.exists());
    let restored = Command::new(BIN)
        .args(["restore", "--meta", &target_meta, "--from"])
        .arg(&out)
        .args(["--sharding", "d34"])
        .output()
        .unwrap();
    assert!(
        restored.status.success(),
        "{}",
        String::from_utf8_lossy(&restored.stderr)
    );
    let target_conn = RusqliteConn::open(&target).unwrap();
    let target_store = SqlKvStore::open(target_conn).unwrap();
    let root = Partition::decode(b"nroot\0").unwrap();
    assert_eq!(
        futures::executor::block_on(target_store.get(&root, &keys::sharding_marker()))
            .unwrap()
            .unwrap()
            .as_bytes(),
        b"d34"
    );
    let get =
        |p: &Partition, key: Key| futures::executor::block_on(target_store.get(p, &key)).unwrap();
    assert_eq!(
        codec::decode_u64(&get(&coordinator, keys::grant_epoch()).unwrap()).unwrap(),
        6
    );
    assert!(get(&coordinator, keys::lease_recovery()).is_some());
    assert_eq!(
        codec::decode_u64(&get(&source_ref, keys::outbox_sequence()).unwrap()).unwrap(),
        13
    );
    assert!(get(&source_ref, keys::relay(2)).is_none());
    assert!(get(&source_ref, keys::relay(12)).is_some());
    assert!(get(&source_ref, Key::new(b"rs\0".as_slice())).is_none());
    assert!(get(&source_ref, keys::backup_state()).is_none());
    assert!(get(&source_ref, keys::timer(7, 4, b"backup")).is_none());
    assert_eq!(
        codec::decode_u64(
            &get(&target_index, keys::relay_high_water(&source_ref).unwrap()).unwrap()
        )
        .unwrap(),
        10
    );
}
