//! Atomic write helper shared by `refs`, `index`, and friends.
//!
//! The same `temp + fsync + rename + parent-dir-fsync` pattern lives in
//! `store::write_atomic`; we keep this copy `pub(crate)` instead of
//! reaching into `store` so the two subsystems can be developed
//! independently and so future changes to one don't ripple into the
//! other. The behaviour is identical.

use std::fs;
#[cfg(unix)]
use std::fs::File;
use std::io::{self, Write};
use std::path::Path;
use std::process;
use std::sync::atomic::{AtomicU64, Ordering};

use tempfile::NamedTempFile;

static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Atomically write `bytes` to `final_path`. Creates the parent
/// directory if `make_parents` is `true`.
pub(crate) fn write_atomic(final_path: &Path, bytes: &[u8], make_parents: bool) -> io::Result<()> {
    let parent = final_path
        .parent()
        .expect("atomic::write_atomic: path has parent");
    if make_parents {
        fs::create_dir_all(parent)?;
    }
    let file_name = final_path
        .file_name()
        .expect("atomic::write_atomic: path has file name")
        .to_string_lossy();
    let pid = process::id();
    let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp_name = format!(".{file_name}.tmp.{pid}.{seq}");

    let mut tmp = NamedTempFile::with_prefix_in(tmp_name, parent)?;
    tmp.as_file_mut().write_all(bytes)?;
    tmp.as_file_mut().sync_all()?;
    tmp.persist(final_path).map_err(|e| e.error)?;

    sync_parent_dir(parent)?;
    Ok(())
}

/// Create-new (`O_EXCL`) variant for the `.missing` CAS condition: the
/// caller wants the write to fail with `AlreadyExists` if `final_path`
/// already has anything there.
///
/// Returns `Ok(true)` on success, `Ok(false)` if the path already
/// existed, or an `Err` for any other I/O failure.
pub(crate) fn write_create_new(
    final_path: &Path,
    bytes: &[u8],
    make_parents: bool,
) -> io::Result<bool> {
    let parent = final_path
        .parent()
        .expect("atomic::write_create_new: path has parent");
    if make_parents {
        fs::create_dir_all(parent)?;
    }

    // Write into a sibling temp file first, fsync it, then atomically
    // rename into place with replace-existing semantics disabled. This
    // combines `O_EXCL` exclusivity on the destination with atomicity on
    // the payload: a crash mid-write leaves only the temp file behind,
    // never a half-written `final_path` that later readers would see as
    // a corrupt ref. Writing straight into `final_path` with `O_EXCL`
    // (the previous approach) poisons the slot on partial-write failure.
    let file_name = final_path
        .file_name()
        .expect("atomic::write_create_new: path has file name")
        .to_string_lossy();
    let pid = process::id();
    let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp_name = format!(".{file_name}.tmp.{pid}.{seq}");

    let mut tmp = NamedTempFile::with_prefix_in(tmp_name, parent)?;
    tmp.as_file_mut().write_all(bytes)?;
    tmp.as_file_mut().sync_all()?;

    // `persist_noclobber` uses `renameat2(RENAME_NOREPLACE)` on Linux
    // and `link(2) + unlink(2)` on other Unix; on Windows it uses
    // `MoveFileExW` without `MOVEFILE_REPLACE_EXISTING`. It returns
    // `io::ErrorKind::AlreadyExists` if the destination exists.
    match tmp.persist_noclobber(final_path) {
        Ok(_file) => {
            sync_parent_dir(parent)?;
            Ok(true)
        }
        Err(e) if e.error.kind() == io::ErrorKind::AlreadyExists => {
            // `persist_noclobber` on failure returns the `NamedTempFile`
            // back to us via `e.file`, which `Drop` will unlink. Nothing
            // leaks.
            Ok(false)
        }
        Err(e) => Err(e.error),
    }
}

#[cfg(unix)]
pub(crate) fn sync_parent_dir(parent: &Path) -> io::Result<()> {
    match File::open(parent) {
        Ok(dir) => dir.sync_all(),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
pub(crate) fn sync_parent_dir(_parent: &Path) -> io::Result<()> {
    Ok(())
}
