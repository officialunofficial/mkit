//! Portable `SQLite` export and restore for the native operator CLI.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use mkit_core::hash::{hash, to_hex};
use mkit_server::sql::{SqlConn, SqlKvStore, SqlValue};
use mkit_server::store::{
    EXPORT_END, ExportReader, ExportRecord, Partition, StoreError, Value, encode_export_header,
    encode_export_record, export_header, export_page, keys,
};
use mkit_server::{Clock, NamespaceKey, SystemClock};

use crate::RusqliteConn;
use crate::config::{MetaArg, ShardingArg};
use crate::exit;
use crate::server;

type CliError = (u8, String);

fn usage(message: impl Into<String>) -> CliError {
    (exit::USAGE, message.into())
}

fn unavailable(error: impl std::fmt::Display) -> CliError {
    (exit::UNAVAILABLE, error.to_string())
}

fn dataerr(error: impl std::fmt::Display) -> CliError {
    (exit::DATAERR, error.to_string())
}

fn archive_error(error: StoreError) -> CliError {
    match error {
        StoreError::Invalid(_) | StoreError::Corrupt(_) | StoreError::Unsupported(_) => {
            dataerr(error)
        }
        _ => unavailable(error),
    }
}

fn create_private_dir(path: &Path) -> std::io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(path)
}

fn sqlite_path<'a>(meta: &'a MetaArg, command: &str) -> Result<&'a Path, CliError> {
    match meta {
        MetaArg::Sqlite(path) => Ok(path),
        MetaArg::FsLayout => Err(usage(format!("{command}: --meta must be sqlite:<PATH>"))),
    }
}

fn writable_file(path: &Path) -> Result<File, StoreError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options
        .open(path)
        .map_err(|e| StoreError::unavailable(e.to_string()))
}

fn ensure_empty_dir(path: &Path) -> Result<(), CliError> {
    match fs::read_dir(path) {
        Ok(mut entries) => {
            if entries.next().is_some() {
                return Err(usage(format!("--out {} is not empty", path.display())));
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            create_private_dir(path).map_err(unavailable)?;
        }
        Err(_) if path.exists() => {
            return Err(usage(format!(
                "--out {} is not a directory",
                path.display()
            )));
        }
        Err(e) => return Err(unavailable(e)),
    }
    Ok(())
}

fn export_partition_bytes(
    store: &SqlKvStore<RusqliteConn>,
    partition: &Partition,
    now_ms: u64,
    sharding: &str,
) -> Result<Vec<u8>, StoreError> {
    let header = futures_executor::block_on(export_header(store, partition, now_ms))?;
    let mut bytes = encode_export_header(&header).to_vec();
    let root = Partition::Namespace(NamespaceKey::deployment_default());
    let mut records = Vec::new();
    let mut after = None;
    loop {
        let page = futures_executor::block_on(export_page(store, partition, after.as_ref(), 256))?;
        records.extend(page.records);
        match page.next {
            Some(next) => after = Some(next),
            None => break,
        }
    }
    if *partition == root {
        let marker = keys::sharding_marker();
        if let Some(existing) = records.iter().find(|record| record.key == marker) {
            if existing.value.as_bytes() != sharding.as_bytes() {
                return Err(StoreError::Corrupt(
                    "sharding marker disagrees with native mode".into(),
                ));
            }
        } else {
            records.push(ExportRecord::new(
                root,
                marker,
                Value::new(sharding.as_bytes().to_vec()),
            ));
            records.sort_by(|a, b| a.key.cmp(&b.key));
        }
    }
    for record in records {
        bytes.extend_from_slice(&encode_export_record(&record)?);
    }
    bytes.extend_from_slice(&EXPORT_END);
    Ok(bytes)
}

fn relative_name(partition: &Partition, bytes: &[u8], now_ms: u64) -> Result<PathBuf, StoreError> {
    let part_hash = to_hex(&hash(&partition.encode()?));
    let digest = to_hex(&hash(bytes));
    Ok(PathBuf::from(partition.kind())
        .join(part_hash)
        .join(format!("{now_ms:013}-{}.kvlog", &digest[..16])))
}

fn distinct_partitions(conn: &RusqliteConn) -> Result<Vec<Partition>, StoreError> {
    conn.query("SELECT DISTINCT part FROM kv ORDER BY part", &[])?
        .into_iter()
        .map(|row| match row.as_slice() {
            [SqlValue::Blob(part)] => Partition::decode(part),
            _ => Err(StoreError::Corrupt("invalid partition column".into())),
        })
        .collect()
}

fn archived_sharding(conn: &RusqliteConn) -> Result<&'static str, StoreError> {
    let has_table = !conn
        .query(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'mkit_server_sharding'",
            &[],
        )?
        .is_empty();
    if !has_table {
        return Ok("single");
    }
    let rows = conn.query("SELECT mode FROM mkit_server_sharding WHERE id = 1", &[])?;
    match rows.as_slice() {
        [row] if row.as_slice() == [SqlValue::Text("single".to_owned())] => Ok("single"),
        [row] if row.as_slice() == [SqlValue::Text("d34".to_owned())] => Ok("d34"),
        _ => Err(StoreError::Corrupt("invalid native sharding record".into())),
    }
}

/// Export every native partition under one read transaction.
///
/// # Errors
/// Invalid paths, a nonempty output directory, corrupt partition data, or
/// `SQLite` and filesystem failures.
pub fn export(meta: &MetaArg, out: &Path) -> Result<(usize, u64), CliError> {
    export_with_hook(meta, out, |_| {})
}

fn export_with_hook(
    meta: &MetaArg,
    out: &Path,
    mut after_partition: impl FnMut(usize),
) -> Result<(usize, u64), CliError> {
    let source = sqlite_path(meta, "export")?;
    if !source.is_file() {
        return Err((
            exit::NOINPUT,
            format!(
                "--meta sqlite:{} is not an existing database file",
                source.display()
            ),
        ));
    }
    ensure_empty_dir(out)?;
    let conn = RusqliteConn::open(source).map_err(unavailable)?;
    let store = SqlKvStore::open_existing(conn.clone()).map_err(dataerr)?;
    let now_ms = u64::try_from(SystemClock.now_ms()).unwrap_or(u64::MAX);
    conn.read_transaction(|| {
        let mut total_bytes = 0_u64;
        let sharding = archived_sharding(&conn)?;
        let mut partitions = distinct_partitions(&conn)?;
        let root = Partition::Namespace(NamespaceKey::deployment_default());
        if !partitions.contains(&root) {
            partitions.push(root);
        }
        for (index, partition) in partitions.iter().enumerate() {
            let bytes = export_partition_bytes(&store, partition, now_ms, sharding)?;
            let path = out.join(relative_name(partition, &bytes, now_ms)?);
            create_private_dir(path.parent().expect("export name has a parent"))
                .map_err(|e| StoreError::unavailable(e.to_string()))?;
            let mut file = writable_file(&path)?;
            file.write_all(&bytes)
                .map_err(|e| StoreError::unavailable(e.to_string()))?;
            total_bytes = total_bytes.saturating_add(bytes.len() as u64);
            after_partition(index);
        }
        Ok((partitions.len(), total_bytes))
    })
    .map_err(unavailable)
}

fn read_snapshots(from: &Path) -> Result<(Vec<Vec<u8>>, Vec<PathBuf>), CliError> {
    let mut snapshots = Vec::new();
    let mut skipped = Vec::new();
    let kinds = fs::read_dir(from).map_err(unavailable)?;
    for kind in kinds {
        let kind = kind.map_err(unavailable)?;
        if !kind.file_type().map_err(unavailable)?.is_dir() {
            return Err(usage("--from contains an unexpected entry"));
        }
        for digest in fs::read_dir(kind.path()).map_err(unavailable)? {
            let digest = digest.map_err(unavailable)?;
            if !digest.file_type().map_err(unavailable)?.is_dir() {
                return Err(usage("--from contains an unexpected entry"));
            }
            for file in fs::read_dir(digest.path()).map_err(unavailable)? {
                let file = file.map_err(unavailable)?;
                if !file.file_type().map_err(unavailable)?.is_file()
                    || file.path().extension().is_none_or(|ext| ext != "kvlog")
                {
                    return Err(usage("--from contains an unexpected entry"));
                }
                let bytes = fs::read(file.path()).map_err(unavailable)?;
                let (_, reader) = ExportReader::new(&bytes).map_err(archive_error)?;
                let mut records = reader
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(archive_error)?;
                let Some(first) = records.pop() else {
                    skipped.push(file.path());
                    continue;
                };
                let expected = from.join(
                    relative_name(
                        &first.partition,
                        &bytes,
                        ExportReader::new(&bytes)
                            .map_err(archive_error)?
                            .0
                            .exported_at_ms,
                    )
                    .map_err(archive_error)?,
                );
                if expected != file.path() || records.iter().any(|r| r.partition != first.partition)
                {
                    return Err(dataerr("--from contains a misplaced partition export"));
                }
                snapshots.push(bytes);
            }
        }
    }
    if snapshots.is_empty() {
        return Err(usage("--from contains no .kvlog files"));
    }
    Ok((snapshots, skipped))
}

fn archive_sharding(snapshots: &[Vec<u8>]) -> Result<&'static str, CliError> {
    let root = Partition::Namespace(NamespaceKey::deployment_default());
    let mut mode = None;
    for bytes in snapshots {
        let (_, reader) = ExportReader::new(bytes).map_err(archive_error)?;
        for record in reader {
            let record = record.map_err(archive_error)?;
            if record.partition == root && record.key == keys::sharding_marker() {
                if mode.is_some() {
                    return Err(dataerr("duplicate root sharding marker"));
                }
                mode = Some(match record.value.as_bytes() {
                    b"single" => "single",
                    b"d34" => "d34",
                    _ => return Err(dataerr("invalid root sharding marker")),
                });
            }
        }
    }
    mode.ok_or_else(|| dataerr("--from has no root sharding marker"))
}

/// Restore portable snapshots into a new `SQLite` database.
///
/// # Errors
/// Invalid archives or paths, sharding mismatches, an existing target, or
/// `SQLite` and filesystem failures.
pub fn restore(
    meta: &MetaArg,
    from: &Path,
    epoch_at_least: Option<u64>,
    allow_incomplete: bool,
    sharding: ShardingArg,
) -> Result<(mkit_server::store::restore::RestoreReport, Vec<PathBuf>), CliError> {
    let dest = sqlite_path(meta, "restore")?;
    if dest.exists() {
        return Err(usage(format!(
            "--meta sqlite:{} already exists",
            dest.display()
        )));
    }
    let (snapshots, skipped) = read_snapshots(from)?;
    let archived_mode = archive_sharding(&snapshots)?;
    let selected_mode = match sharding {
        ShardingArg::Single => "single",
        ShardingArg::D34 => "d34",
    };
    if archived_mode != selected_mode {
        return Err(usage(format!(
            "--sharding {selected_mode} disagrees with archive mode {archived_mode}"
        )));
    }
    // Atomically claim the new path; this also starts the database owner-only.
    match writable_file(dest) {
        Ok(file) => drop(file),
        Err(_) if dest.exists() => {
            return Err(usage(format!(
                "--meta sqlite:{} already exists",
                dest.display()
            )));
        }
        Err(e) => return Err(unavailable(e)),
    }
    let result = (|| {
        let conn = RusqliteConn::open(dest).map_err(unavailable)?;
        let store = SqlKvStore::open(conn.clone()).map_err(unavailable)?;
        let mode = match sharding {
            ShardingArg::Single => mkit_server::pipeline::Sharding::Single,
            ShardingArg::D34 => mkit_server::pipeline::Sharding::D34,
        };
        server::bind_sharding(&conn, mode, dest).map_err(|e| (e.code, e.message))?;
        let report = futures_executor::block_on(mkit_server::store::restore::restore(
            &snapshots,
            &store,
            mkit_server::store::restore::RestoreOptions {
                epoch_at_least,
                recovered_at_ms: u64::try_from(SystemClock.now_ms()).unwrap_or(u64::MAX),
                allow_incomplete,
            },
        ))
        .map_err(archive_error)?;
        Ok((report, skipped))
    })();
    if result.is_err() {
        let _ = fs::remove_file(dest);
        for suffix in ["-wal", "-shm"] {
            let mut sidecar = dest.as_os_str().to_os_string();
            sidecar.push(suffix);
            let _ = fs::remove_file(PathBuf::from(sidecar));
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use mkit_server::store::{Batch, BatchOutcome, Key, NamespaceStore, Value};

    #[test]
    fn export_sees_one_wal_snapshot_across_partitions() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source.sqlite3");
        let writer = RusqliteConn::open(&source).unwrap();
        let store = SqlKvStore::open(writer.clone()).unwrap();
        let first = Partition::decode(b"nroot\0").unwrap();
        let second = Partition::decode(b"s1\0").unwrap();
        let key = Key::new(b"r\0main".as_slice());
        for p in [&first, &second] {
            assert_eq!(
                futures_executor::block_on(store.apply(
                    p,
                    Batch::new().put(key.clone(), Value::new(b"old".as_slice()))
                ))
                .unwrap(),
                BatchOutcome::Committed
            );
        }
        let out = dir.path().join("out");
        let mut wrote = false;
        export_with_hook(&MetaArg::Sqlite(source), &out, |index| {
            if index == 0 {
                for p in [&first, &second] {
                    futures_executor::block_on(store.apply(
                        p,
                        Batch::new().put(key.clone(), Value::new(b"new".as_slice())),
                    ))
                    .unwrap();
                }
                wrote = true;
            }
        })
        .unwrap();
        assert!(wrote);
        for bytes in read_snapshots(&out).unwrap().0 {
            let (_, reader) = ExportReader::new(&bytes).unwrap();
            let records = reader.collect::<Result<Vec<_>, _>>().unwrap();
            assert!(
                records
                    .iter()
                    .any(|r| r.key == key && r.value.as_bytes() == b"old")
            );
        }
    }
}
