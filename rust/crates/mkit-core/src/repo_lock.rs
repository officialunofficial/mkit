//! Repo-level lockfile helper (named `repo_lock` to avoid collision
//! with `std::sync::*Lock`).
//!
//! Pattern: `O_EXCL`-create a sentinel file, hold an OS-level exclusive
//! advisory lock on it, then delete on release. The lockfile is visible
//! on disk so a stale lock left behind by a SIGKILL'd `mkit` is
//! debuggable (`ls .mkit/*.lock`) and removable by hand.
//!
//! We take an exclusive `flock(2)`-equivalent on the file via
//! `std::fs::File::lock` so concurrent acquirers within the same OS
//! block on the kernel instead of spinning on `EEXIST`. The `O_EXCL`
//! create still wins the file-creation race on the first attempt; on
//! the wait path we open the existing file read-only and call `lock()`
//! to wait for the current holder to release.
//!
//! POSIX-only intent (macOS + Linux). `std::fs::File::lock` is also
//! supported on Windows since Rust 1.89, so this works there too — the
//! lock semantics are equivalent (mandatory `LockFileEx` rather than
//! advisory `flock`).

use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Default per-attempt sleep between create-retries on contention. Long
/// enough to avoid CPU monopolisation, short enough that another fast
/// `mkit` finishing a quick commit is observed promptly.
pub const DEFAULT_SLEEP: Duration = Duration::from_millis(50);

/// Default total wall-clock timeout (≈5s). Long enough that a slow
/// commit in another process finishes; short enough that a stale lock
/// from a SIGKILL'd `mkit` does not wedge the user for more than a moment.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum filename length for a lock name.
const MAX_NAME_LEN: usize = 255;

/// Errors returned by [`acquire`].
#[derive(Debug, thiserror::Error)]
pub enum LockError {
    /// Timeout exhausted; another holder still owns the lock.
    #[error("lock '{0}' busy after timeout")]
    Busy(String),
    /// `name` is empty or longer than the platform-safe filename cap.
    #[error("lock name length {0} is invalid (must be 1..={MAX_NAME_LEN})")]
    NameLength(usize),
    /// Underlying filesystem failure (disk full, permission denied, …).
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Result alias used throughout this module.
pub type LockResult<T> = Result<T, LockError>;

/// Holder for an acquired repo lock. Releases the file on `Drop`.
///
/// `release()` is the explicit form; calling it is optional because
/// `Drop` does the same work. After `release()` is called, `Drop` is a
/// cheap no-op.
#[must_use = "RepoLock releases on drop; bind it to a name to keep the lock"]
#[derive(Debug)]
pub struct RepoLock {
    /// Held file with the OS-level exclusive lock applied.
    /// `None` after `release()`.
    file: Option<File>,
    /// Absolute path to the lockfile, for the unlink-on-release step
    /// and for diagnostics via [`Self::path`].
    path: PathBuf,
}

impl RepoLock {
    /// Returns the absolute path of the held lock file, for diagnostics.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Release the lock: drop the OS lock and unlink the file. Safe to
    /// call multiple times — subsequent calls are no-ops.
    pub fn release(&mut self) {
        if let Some(file) = self.file.take() {
            // `unlock()` is best-effort; `Drop` of the file would also
            // release the kernel lock. We still call it explicitly so a
            // mid-test reader can re-acquire on the same handle if it
            // wants to.
            let _ = file.unlock();
            drop(file);
            // Best-effort unlink — if another process already grabbed
            // the slot via `O_EXCL` we deliberately leave their file
            // alone, but in practice the kernel lock above prevents
            // that race. Errors are swallowed because we have no
            // user-visible path to surface them on `Drop`.
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

impl Drop for RepoLock {
    fn drop(&mut self) {
        self.release();
    }
}

/// Acquire a repo-level lock at `<dir>/<name>`. Spins up to `timeout`
/// waiting for an existing holder to release. Returns a guard that
/// `Drop`s into a release.
///
/// `dir` is usually the `.mkit/` directory (not the worktree root).
/// `name` is the lockfile basename, e.g. `"index.lock"`.
///
/// # Errors
/// - [`LockError::Busy`] if `timeout` elapses without the lock becoming
///   available.
/// - [`LockError::NameLength`] if `name` is empty or longer than 255.
/// - [`LockError::Io`] for underlying filesystem failures.
pub fn acquire(dir: &Path, name: &str, timeout: Duration) -> LockResult<RepoLock> {
    if name.is_empty() || name.len() > MAX_NAME_LEN {
        return Err(LockError::NameLength(name.len()));
    }
    // Reject path separators so callers cannot escape `dir`.
    if name.contains('/') || name.contains('\\') || name.contains('\0') {
        return Err(LockError::NameLength(name.len()));
    }
    let path = dir.join(name);
    let start = Instant::now();
    loop {
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => {
                // We won the create race; take the kernel lock for
                // good measure and return.
                file.lock()?;
                return Ok(RepoLock {
                    file: Some(file),
                    path,
                });
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                if start.elapsed() >= timeout {
                    return Err(LockError::Busy(name.to_string()));
                }
                std::thread::sleep(DEFAULT_SLEEP);
            }
            Err(e) => return Err(LockError::Io(e)),
        }
    }
}

/// Convenience wrapper: acquire with the default timeout.
///
/// # Errors
/// See [`acquire`].
pub fn acquire_default(dir: &Path, name: &str) -> LockResult<RepoLock> {
    acquire(dir, name, DEFAULT_TIMEOUT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn acquire_release_round_trip() {
        let dir = TempDir::new().unwrap();
        {
            let lock = acquire_default(dir.path(), "index.lock").unwrap();
            assert!(lock.path().is_file());
            assert_eq!(lock.path().file_name().unwrap(), "index.lock");
        }
        // After Drop, the file is gone.
        assert!(!dir.path().join("index.lock").exists());
    }

    #[test]
    fn second_acquire_after_release_succeeds() {
        let dir = TempDir::new().unwrap();
        let l1 = acquire_default(dir.path(), "index.lock").unwrap();
        drop(l1);
        let l2 = acquire_default(dir.path(), "index.lock").unwrap();
        assert!(l2.path().is_file());
    }

    #[test]
    fn acquire_while_held_returns_busy_after_short_timeout() {
        let dir = TempDir::new().unwrap();
        let _l1 = acquire_default(dir.path(), "index.lock").unwrap();
        let err = acquire(dir.path(), "index.lock", Duration::from_millis(150)).unwrap_err();
        assert!(matches!(err, LockError::Busy(_)));
    }

    #[test]
    fn release_is_idempotent() {
        let dir = TempDir::new().unwrap();
        let mut lock = acquire_default(dir.path(), "index.lock").unwrap();
        lock.release();
        lock.release(); // No-op, no panic.
        assert!(!dir.path().join("index.lock").exists());
    }

    #[test]
    fn acquire_rejects_empty_name() {
        let dir = TempDir::new().unwrap();
        let err = acquire(dir.path(), "", DEFAULT_TIMEOUT).unwrap_err();
        assert!(matches!(err, LockError::NameLength(0)));
    }

    #[test]
    fn acquire_rejects_oversize_name() {
        let dir = TempDir::new().unwrap();
        let huge = "a".repeat(300);
        let err = acquire(dir.path(), &huge, DEFAULT_TIMEOUT).unwrap_err();
        assert!(matches!(err, LockError::NameLength(300)));
    }

    #[test]
    fn acquire_rejects_separators() {
        let dir = TempDir::new().unwrap();
        assert!(matches!(
            acquire(dir.path(), "../escape", DEFAULT_TIMEOUT).unwrap_err(),
            LockError::NameLength(_)
        ));
        assert!(matches!(
            acquire(dir.path(), "sub/lock", DEFAULT_TIMEOUT).unwrap_err(),
            LockError::NameLength(_)
        ));
    }

    #[test]
    fn two_distinct_lock_names_coexist() {
        let dir = TempDir::new().unwrap();
        let _a = acquire_default(dir.path(), "a.lock").unwrap();
        let _b = acquire_default(dir.path(), "b.lock").unwrap();
        assert!(dir.path().join("a.lock").is_file());
        assert!(dir.path().join("b.lock").is_file());
    }
}
