//! Physical backup CLI over a live WAL database.
#![cfg(feature = "http")]
#![allow(clippy::unwrap_used)]

use std::process::Command;

use mkit_server::sql::{SqlConn, SqlKvStore};
use mkit_server::{Batch, BatchOutcome, Key, NamespaceStore, Partition, Value};
use mkit_server_native::{RusqliteConn, exit};

const BIN: &str = env!("CARGO_BIN_EXE_mkit-server");

#[test]
fn backup_copies_committed_rows_with_source_open_and_refuses_existing_output() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("meta.sqlite3");
    let conn = RusqliteConn::open(&source).unwrap();
    let store = SqlKvStore::open(conn.clone()).unwrap();
    let partition = Partition::decode(b"ndefault\0").unwrap();
    let key = Key::new(b"r\0main".as_slice());
    let value = Value::new(b"committed".as_slice());
    assert_eq!(
        futures::executor::block_on(
            store.apply(&partition, Batch::new().put(key.clone(), value.clone()))
        )
        .unwrap(),
        BatchOutcome::Committed
    );
    // conn/store remain live; the committed row may still be in the WAL.
    let output = dir.path().join("backup.sqlite3");
    let meta = format!("sqlite:{}", source.display());
    let result = Command::new(BIN)
        .args(["backup", "--meta", &meta, "--out"])
        .arg(&output)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let stdout = String::from_utf8(result.stdout).unwrap();
    assert!(stdout.contains(output.to_str().unwrap()));
    assert!(stdout.contains(&format!(
        "{} bytes",
        std::fs::metadata(&output).unwrap().len()
    )));
    let restored_conn = RusqliteConn::open(&output).unwrap();
    let restored = SqlKvStore::open(restored_conn.clone()).unwrap();
    assert_eq!(
        futures::executor::block_on(restored.get(&partition, &key)).unwrap(),
        Some(value)
    );
    let source_rows = conn
        .query("SELECT part, key, value FROM kv ORDER BY part, key", &[])
        .unwrap();
    assert_eq!(
        restored_conn
            .query("SELECT part, key, value FROM kv ORDER BY part, key", &[])
            .unwrap(),
        source_rows
    );
    drop(restored);
    drop(restored_conn);
    let bytes = std::fs::read(&output).unwrap();
    let refused = Command::new(BIN)
        .args(["backup", "--meta", &meta, "--out"])
        .arg(&output)
        .output()
        .unwrap();
    assert_eq!(refused.status.code(), Some(i32::from(exit::USAGE)));
    assert_eq!(std::fs::read(&output).unwrap(), bytes);
    // SQLite itself allows an empty VACUUM INTO target; our CLI refuses it.
    let empty = dir.path().join("empty.sqlite3");
    std::fs::write(&empty, []).unwrap();
    let refused = Command::new(BIN)
        .args(["backup", "--meta", &meta, "--out"])
        .arg(&empty)
        .output()
        .unwrap();
    assert_eq!(refused.status.code(), Some(i32::from(exit::USAGE)));
    assert_eq!(std::fs::metadata(empty).unwrap().len(), 0);
}

#[test]
fn backup_rejects_non_sqlite_meta_and_does_not_create_missing_source() {
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("backup.sqlite3");
    let refused = Command::new(BIN)
        .args(["backup", "--meta", "fs-layout", "--out"])
        .arg(&output)
        .output()
        .unwrap();
    assert_eq!(refused.status.code(), Some(i32::from(exit::USAGE)));
    let source = dir.path().join("missing.sqlite3");
    let meta = format!("sqlite:{}", source.display());
    let refused = Command::new(BIN)
        .args(["backup", "--meta", &meta, "--out"])
        .arg(&output)
        .output()
        .unwrap();
    assert_eq!(refused.status.code(), Some(i32::from(exit::NOINPUT)));
    assert!(!source.exists());
    assert!(!output.exists());
}
