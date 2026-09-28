//! Native portable export and restore commands.
#![cfg(feature = "http")]
#![allow(clippy::unwrap_used)]

use std::path::Path;
use std::process::Command;

use mkit_server::pipeline::Sharding;
use mkit_server::sql::{SqlConn, SqlKvStore, SqlValue};
use mkit_server::store::{
    Batch, BatchOutcome, EXPORT_END, ExportHeader, Key, NamespaceStore, Partition, Value, codec,
    encode_export_header, keys,
};
use mkit_server::timers::registry::kinds;
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

fn stable_rows(path: &Path) -> Vec<Vec<SqlValue>> {
    let conn = RusqliteConn::open(path).unwrap();
    conn.query("SELECT part, key, value FROM kv ORDER BY part, key", &[])
        .unwrap().into_iter().filter(|row| {
            let SqlValue::Blob(raw_key) = &row[1] else { panic!("non-blob key") };
            let key = Key::new(raw_key.clone());
            key != keys::sharding_marker()
                && key != keys::layout_version() // Importer materializes the archive layout.
                && key != keys::grant_epoch()
                && key != keys::outbox_sequence()
                && key != keys::relay_scan()
                && key != keys::backup_state()
                && key != keys::lease_recovery()
                && key != keys::epoch_lease()
                && !matches!(keys::parse(&key), Some(keys::ParsedKey::Relay(_)))
                && !matches!(keys::parse(&key), Some(keys::ParsedKey::Timer { kind, .. }) if kind == kinds::BACKUP.get())
        }).collect()
}

fn add_recordless_archive(out: &Path) {
    let dir = out.join("content/recordless");
    std::fs::create_dir_all(&dir).unwrap();
    let bytes = [
        encode_export_header(&ExportHeader::new(keys::LAYOUT_VERSION, 0)).as_ref(),
        &EXPORT_END,
    ]
    .concat();
    std::fs::write(dir.join("empty.kvlog"), bytes).unwrap();
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
    add_recordless_archive(&out);
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
    assert!(String::from_utf8_lossy(&restored.stderr).contains("skipping recordless archive"));
    assert_single_restored(&target);
    assert_eq!(stable_rows(&source), stable_rows(&target));
    let refused = Command::new(BIN)
        .args(["restore", "--meta", &target_meta, "--from"])
        .arg(&out)
        .output()
        .unwrap();
    assert_eq!(refused.status.code(), Some(i32::from(exit::USAGE)));
    let merge_path = dir.path().join("merge-refusal.sqlite3");
    let merge_meta = format!("sqlite:{}", merge_path.display());
    let refused = Command::new(BIN)
        .args(["restore", "--meta", &merge_meta, "--from"])
        .arg(&out)
        .arg("--merge")
        .output()
        .unwrap();
    assert_eq!(refused.status.code(), Some(i32::from(exit::USAGE)));
    assert!(!merge_path.exists());

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
        assert_eq!(
            std::fs::metadata(out).unwrap().permissions().mode() & 0o777,
            0o700
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
        5 + (1 << 32)
    );
    assert!(get(&coordinator, keys::lease_recovery()).is_some());
    assert_eq!(
        codec::decode_u64(&get(&source_ref, keys::outbox_sequence()).unwrap()).unwrap(),
        13
    );
    assert!(get(&source_ref, keys::relay(2)).is_none());
    assert!(get(&source_ref, keys::relay(12)).is_some());
    assert!(get(&source_ref, keys::relay_scan()).is_none());
    assert!(get(&source_ref, keys::backup_state()).is_none());
    assert!(get(&source_ref, keys::timer(7, kinds::BACKUP.get(), b"backup")).is_none());
    assert_eq!(
        codec::decode_u64(
            &get(&target_index, keys::relay_high_water(&source_ref).unwrap()).unwrap()
        )
        .unwrap(),
        10
    );
    assert_eq!(stable_rows(&source), stable_rows(&target));
}

#[test]
fn export_refuses_older_schema_without_migrating_it() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("old.sqlite3");
    let conn = RusqliteConn::open(&source).unwrap();
    let _ = SqlKvStore::open(conn.clone()).unwrap();
    conn.exec("UPDATE mkit_schema SET version = 1 WHERE id = 1", &[])
        .unwrap();
    conn.exec("DROP INDEX kv_timers", &[]).unwrap();
    let meta = format!("sqlite:{}", source.display());
    let result = Command::new(BIN)
        .args(["export", "--meta", &meta, "--out"])
        .arg(dir.path().join("out"))
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(i32::from(exit::DATAERR)));
    assert!(String::from_utf8_lossy(&result.stderr).contains("schema version 1"));
    assert_eq!(
        conn.query("SELECT version FROM mkit_schema WHERE id = 1", &[])
            .unwrap(),
        vec![vec![SqlValue::Integer(1)]]
    );
    assert!(
        conn.query(
            "SELECT name FROM sqlite_master WHERE type = 'index' AND name = 'kv_timers'",
            &[]
        )
        .unwrap()
        .is_empty()
    );
}

#[test]
fn malformed_and_duplicate_archives_exit_dataerr() {
    use mkit_core::hash::{hash, to_hex};

    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source.sqlite3");
    let conn = RusqliteConn::open(&source).unwrap();
    let store = SqlKvStore::open(conn).unwrap();
    put(
        &store,
        &Partition::decode(b"nroot\0").unwrap(),
        b"r\0main",
        b"one",
    );
    let archive = dir.path().join("archive");
    let meta = format!("sqlite:{}", source.display());
    assert!(
        Command::new(BIN)
            .args(["export", "--meta", &meta, "--out"])
            .arg(&archive)
            .status()
            .unwrap()
            .success()
    );
    let hash_dir = std::fs::read_dir(archive.join("namespace"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let file = std::fs::read_dir(&hash_dir)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let original = std::fs::read(&file).unwrap();
    let mut second = original.clone();
    let at = u64::from_be_bytes(second[13..21].try_into().unwrap()) + 1;
    second[13..21].copy_from_slice(&at.to_be_bytes());
    let digest = to_hex(&hash(&second));
    let duplicate = hash_dir.join(format!("{at:013}-{}.kvlog", &digest[..16]));
    std::fs::write(&duplicate, &second).unwrap();
    let target = dir.path().join("duplicate.sqlite3");
    let target_meta = format!("sqlite:{}", target.display());
    let result = Command::new(BIN)
        .args(["restore", "--meta", &target_meta, "--from"])
        .arg(&archive)
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(i32::from(exit::DATAERR)));
    assert!(!target.exists());
    std::fs::remove_file(&duplicate).unwrap();
    let mut malformed = original;
    malformed[0] = b'X';
    std::fs::write(&file, malformed).unwrap();
    let result = Command::new(BIN)
        .args(["restore", "--meta", &target_meta, "--from"])
        .arg(&archive)
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(i32::from(exit::DATAERR)));
    assert!(!target.exists());
}

#[test]
fn native_allow_incomplete_reconstructs_missing_source_and_coordinator() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source.sqlite3");
    let conn = RusqliteConn::open(&source).unwrap();
    let store = SqlKvStore::open(conn.clone()).unwrap();
    server::bind_sharding(&conn, Sharding::D34, &source).unwrap();
    let ns = NamespaceKey::deployment_default();
    let repo = RepoName::new("repo").unwrap();
    let relay_source = Partition::Ref {
        ns: ns.clone(),
        repo: repo.clone(),
        shard_ref: "refs/heads/main".into(),
    };
    let index = Partition::RepoIndex {
        ns: ns.clone(),
        repo,
        prefix: 1,
    };
    put(
        &store,
        &index,
        keys::relay_high_water(&relay_source).unwrap().as_bytes(),
        codec::encode_u64(10).as_bytes(),
    );
    let archive = dir.path().join("archive");
    let source_meta = format!("sqlite:{}", source.display());
    assert!(
        Command::new(BIN)
            .args(["export", "--meta", &source_meta, "--out"])
            .arg(&archive)
            .status()
            .unwrap()
            .success()
    );
    let target = dir.path().join("target.sqlite3");
    let target_meta = format!("sqlite:{}", target.display());
    let base = || {
        let mut command = Command::new(BIN);
        command
            .args(["restore", "--meta", &target_meta, "--from"])
            .arg(&archive)
            .args(["--sharding", "d34"]);
        command
    };
    let refused = base().output().unwrap();
    assert_eq!(refused.status.code(), Some(i32::from(exit::DATAERR)));
    assert!(String::from_utf8_lossy(&refused.stderr).contains("missing relay sources"));
    let refused = base().arg("--allow-incomplete").output().unwrap();
    assert_eq!(refused.status.code(), Some(i32::from(exit::DATAERR)));
    assert!(String::from_utf8_lossy(&refused.stderr).contains("missing namespace coordinators"));
    let restored = base()
        .args(["--allow-incomplete", "--epoch-at-least", "4294967338"])
        .output()
        .unwrap();
    assert!(
        restored.status.success(),
        "{}",
        String::from_utf8_lossy(&restored.stderr)
    );
    assert!(
        String::from_utf8_lossy(&restored.stderr).contains("reconstructed missing relay sources")
    );
    assert!(
        String::from_utf8_lossy(&restored.stderr).contains("reconstructed missing coordinators")
    );
    let target_store = SqlKvStore::open(RusqliteConn::open(&target).unwrap()).unwrap();
    assert_eq!(
        futures::executor::block_on(target_store.get(&relay_source, &keys::outbox_sequence()))
            .unwrap(),
        Some(codec::encode_u64(10))
    );
    let coordinator = Partition::Coordinator(ns);
    assert_eq!(
        futures::executor::block_on(target_store.get(&coordinator, &keys::grant_epoch())).unwrap(),
        Some(codec::encode_u64(4_294_967_338))
    );
    assert!(
        futures::executor::block_on(target_store.get(&coordinator, &keys::lease_recovery()))
            .unwrap()
            .is_some()
    );
}
