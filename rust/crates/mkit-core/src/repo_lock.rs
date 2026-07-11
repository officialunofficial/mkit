//! Repo-level lockfile helper (named `repo_lock` to avoid collision
//! with `std::sync::*Lock`).
//!
//! Pattern (mirrors `mkit-transport-file`'s `RefLock`): open-or-create a
//! **never-unlinked** sentinel file at `<dir>/<name>` and take an
//! OS-level exclusive advisory lock on it via `std::fs::File::lock`.
//! Mutual exclusion comes entirely from the kernel lock, never from the
//! sentinel's presence/absence on disk — so the file is *not* removed on
//! release. That structurally removes the stale-vs-live ambiguity a
//! delete-on-release design has: a sentinel orphaned by a SIGKILL'd
//! `mkit` looks identical on disk to one backing a live holder, but the
//! kernel already knows the difference, because it releases the
//! process's `flock` the moment its file descriptors close (including on
//! sudden process death). A waiter that actually blocks on that kernel
//! lock therefore never confuses the two: `ls .mkit/*.lock` will show
//! the file whether or not anyone holds it — use `lsof`/`fuser` (or a
//! bounded acquire attempt) to check liveness, not existence.
//!
//! Acquisition first tries a non-blocking [`File::try_lock`] (the
//! uncontended fast path costs no thread spawn). On contention, a helper
//! thread performs the real blocking `lock()` call and reports back over
//! a channel; the caller bounds the wait with `recv_timeout(timeout)`.
//! If `timeout` elapses first, the caller gives up and returns
//! [`LockError::Busy`] — but the helper thread is not abandoned holding
//! anything: when it eventually wins the kernel lock (because the
//! original, live holder finally released), its `send` back to the
//! (already-dropped) receiver fails, handing the locked `File` back to
//! the helper thread, which drops it immediately, releasing the kernel
//! lock rather than leaking it into an unreachable holder.
//!
//! POSIX-only intent (macOS + Linux). `std::fs::File::lock` is also
//! supported on Windows since Rust 1.89, so this works there too — the
//! lock semantics are equivalent (mandatory `LockFileEx` rather than
//! advisory `flock`).
//!
//! # Network-filesystem caveat
//!
//! Every guarantee this module makes — including the fail-closed
//! GC-vs-writer exclusion `SPEC-GC.md` relies on — assumes `<dir>` is a
//! genuinely local filesystem (or a well-behaved local-only virtual one
//! such as tmpfs). `flock`/`fcntl` advisory locking is **not reliably
//! coherent across NFS clients**: `NFSv3` offloads locking to a separate,
//! frequently-absent `rpc.statd`/NLM side channel that many exports run
//! without, and even where present, servers vary in whether a lock
//! actually excludes a *different host's* holder rather than only
//! callers on the same NFS client. `NFSv4`'s advertised in-protocol
//! locking is closer to POSIX semantics but still depends on
//! server/client support and is not something this module verifies at
//! runtime. The same caution applies to SMB/CIFS mounts and to most
//! FUSE-backed network filesystems. A `.mkit/` directory served from
//! such a mount can silently lose the mutual-exclusion property this
//! module documents above: two processes on different hosts (or even
//! the same host, depending on client/server behavior) may both believe
//! they hold the lock. This module performs no detection of the
//! underlying filesystem type and has no fallback locking strategy for
//! this case — repositories that must be shared across hosts should use
//! one of mkit's network transports (see `docs/specs/SPEC-TRANSPORT.md`)
//! rather than a shared network-mounted `.mkit/` directory. See
//! `docs/THREAT-MODEL.md` §7 for how this affects mkit's fail-closed
//! locking claims.

use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};

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
    /// `name` contains a path separator (`/`, `\`) or a NUL byte. A
    /// length-based classification would be misleading here — the
    /// value's length is fine; it's the contents that are wrong.
    #[error("lock name contains an invalid character (`/`, `\\`, or NUL): {0:?}")]
    InvalidName(String),
    /// Underlying filesystem failure (disk full, permission denied, …).
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Result alias used throughout this module.
pub type LockResult<T> = Result<T, LockError>;

/// Holder for an acquired repo lock. Releases the kernel lock on `Drop`.
///
/// `release()` is the explicit form; calling it is optional because
/// `Drop` does the same work. After `release()` is called, `Drop` is a
/// cheap no-op.
///
/// The sentinel file at [`Self::path`] is **never** removed by
/// `release`/`Drop` — see the module doc for why a never-unlinked
/// sentinel is what makes stale-vs-live holder confusion structurally
/// impossible.
#[must_use = "RepoLock releases on drop; bind it to a name to keep the lock"]
#[derive(Debug)]
pub struct RepoLock {
    /// Held file with the OS-level exclusive lock applied.
    /// `None` after `release()`.
    file: Option<File>,
    /// Absolute path to the (never-unlinked) lockfile, for diagnostics
    /// via [`Self::path`].
    path: PathBuf,
}

impl RepoLock {
    /// Returns the absolute path of the held lock file, for diagnostics.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Release the lock: drop the OS lock. The sentinel file itself is
    /// left on disk (see module doc). Safe to call multiple times —
    /// subsequent calls are no-ops.
    pub fn release(&mut self) {
        if let Some(file) = self.file.take() {
            // `unlock()` is best-effort; `Drop` of the file would also
            // release the kernel lock. We still call it explicitly so a
            // mid-test reader can re-acquire on the same handle if it
            // wants to.
            let _ = file.unlock();
            drop(file);
        }
    }
}

impl Drop for RepoLock {
    fn drop(&mut self) {
        self.release();
    }
}

/// Acquire a repo-level lock at `<dir>/<name>`. Waits up to `timeout`
/// for an existing holder to release, blocking on the kernel lock
/// (no polling) rather than spinning. Returns a guard that `Drop`s into
/// a release.
///
/// `dir` is usually the `.mkit/` directory (not the worktree root).
/// `name` is the lockfile basename, e.g. `"index.lock"`.
///
/// # Errors
/// - [`LockError::Busy`] if `timeout` elapses without the lock becoming
///   available.
/// - [`LockError::NameLength`] if `name` is empty or longer than 255.
/// - [`LockError::InvalidName`] if `name` contains a path separator
///   (`/`, `\`) or a NUL byte.
/// - [`LockError::Io`] for underlying filesystem failures.
pub fn acquire(dir: &Path, name: &str, timeout: Duration) -> LockResult<RepoLock> {
    if name.is_empty() || name.len() > MAX_NAME_LEN {
        return Err(LockError::NameLength(name.len()));
    }
    // Reject path separators and NUL so callers cannot escape `dir`
    // nor embed bytes the platform filesystem treats specially. These
    // are CONTENT violations, not LENGTH violations — hence a
    // dedicated variant.
    if name.contains('/') || name.contains('\\') || name.contains('\0') {
        return Err(LockError::InvalidName(name.to_string()));
    }
    let path = dir.join(name);
    let start = Instant::now();

    // Open-or-create the never-unlinked sentinel. Unlike the old
    // `O_EXCL`-create-new scheme, whether this call creates the file or
    // reopens an existing one carries no meaning — the file's mere
    // presence says nothing about whether anyone holds the kernel lock.
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)?;

    // Fast path: try the non-blocking lock first so the common
    // uncontended case never pays for a thread spawn.
    match file.try_lock() {
        Ok(()) => {
            return Ok(RepoLock {
                file: Some(file),
                path,
            });
        }
        Err(std::fs::TryLockError::Error(e)) => return Err(LockError::Io(e)),
        Err(std::fs::TryLockError::WouldBlock) => {}
    }

    let remaining = timeout.saturating_sub(start.elapsed());
    if remaining.is_zero() {
        return Err(LockError::Busy(name.to_string()));
    }

    // Slow path: block on the kernel lock for real. A helper thread
    // performs the blocking `lock()` call (which cannot itself be
    // bounded by a timeout) and reports back over a channel; this
    // thread bounds the *wait* with `recv_timeout`. See the module doc
    // for how an abandoned wait (timeout wins the race) avoids leaking
    // the lock into an unreachable holder.
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let result = file.lock().map(|()| file);
        let _ = tx.send(result);
    });

    match rx.recv_timeout(remaining) {
        Ok(Ok(file)) => Ok(RepoLock {
            file: Some(file),
            path,
        }),
        Ok(Err(e)) => Err(LockError::Io(e)),
        Err(mpsc::RecvTimeoutError::Timeout) => Err(LockError::Busy(name.to_string())),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(LockError::Io(io::Error::other(
            "repo lock wait thread exited without reporting a result",
        ))),
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
        // Never-unlinked sentinel: the file persists after Drop/release
        // (see module doc) — only the kernel lock is released. Re-acquire
        // promptly to prove the lock itself is actually free.
        assert!(
            dir.path().join("index.lock").exists(),
            "sentinel file must persist after release"
        );
        let l2 = acquire(dir.path(), "index.lock", Duration::from_millis(200)).unwrap();
        drop(l2);
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
        // Sentinel persists (never unlinked); the kernel lock is free.
        assert!(dir.path().join("index.lock").exists());
        let l2 = acquire(dir.path(), "index.lock", Duration::from_millis(200)).unwrap();
        drop(l2);
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
            LockError::InvalidName(_)
        ));
        assert!(matches!(
            acquire(dir.path(), "sub/lock", DEFAULT_TIMEOUT).unwrap_err(),
            LockError::InvalidName(_)
        ));
    }

    #[test]
    fn acquire_rejects_backslash_and_nul() {
        let dir = TempDir::new().unwrap();
        assert!(matches!(
            acquire(dir.path(), "has\\backslash", DEFAULT_TIMEOUT).unwrap_err(),
            LockError::InvalidName(_)
        ));
        assert!(matches!(
            acquire(dir.path(), "has\0nul", DEFAULT_TIMEOUT).unwrap_err(),
            LockError::InvalidName(_)
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

    // -----------------------------------------------------------------
    // #635 / INV-16 / INV-17 — blocking-wait regression tests.
    // -----------------------------------------------------------------

    /// INV-16: a lockfile orphaned by a process that died mid-hold must
    /// not permanently wedge future acquires.
    ///
    /// We simulate "a process acquired the lock and was SIGKILL'd before
    /// it could run its release/unlink cleanup" without a real
    /// subprocess: create + `flock` the sentinel directly (bypassing
    /// `acquire`, which would also register the normal release path),
    /// then `drop` the handle without unlinking the file. Dropping the
    /// `File` closes its descriptor, which releases the kernel `flock`
    /// exactly as a killed process's fd closing would — but the sentinel
    /// file itself is left behind on disk, exactly as `O_EXCL`-created
    /// lockfiles are on a real SIGKILL.
    ///
    /// Against the old poll-`O_EXCL` wait loop this wedges forever: every
    /// `acquire` sees `AlreadyExists` on `create_new`, never checks
    /// whether the kernel lock is actually free, and burns the full
    /// timeout before failing `Busy` — even though nobody holds it.
    #[test]
    fn orphaned_lock_does_not_wedge_future_acquire() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("index.lock");

        {
            let orphan = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .unwrap();
            orphan.lock().unwrap();
            // Simulates the fd closing on process death: releases the
            // kernel lock but leaves the sentinel file on disk.
            drop(orphan);
        }
        assert!(
            path.exists(),
            "orphaned sentinel file must remain on disk after the simulated death"
        );

        // Nobody holds the kernel lock anymore, so a fresh acquire must
        // succeed well within a bounded timeout rather than burning it.
        let start = Instant::now();
        let lock = acquire(dir.path(), "index.lock", Duration::from_secs(2))
            .expect("acquire must succeed once the orphaned holder's kernel lock is free");
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_millis(500),
            "acquire should not pay anywhere near the timeout on an orphaned lock, took {elapsed:?}"
        );
        drop(lock);
    }

    /// INV-8/INV-16: a genuinely blocking waiter must observe the actual
    /// release event promptly, not merely "eventually, after polling
    /// catches up." A holder thread releases well before the acquirer's
    /// timeout; the acquirer must return success shortly after that
    /// release rather than needing to reach the timeout.
    #[test]
    fn waiter_observes_release_from_a_live_holder_without_timing_out() {
        let dir = TempDir::new().unwrap();
        let dir_path = dir.path().to_path_buf();

        let holder = acquire_default(&dir_path, "index.lock").unwrap();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let holder_thread = std::thread::spawn(move || {
            // Hold the lock until told to let go.
            let _ = release_rx.recv();
            drop(holder);
        });

        let waiter_dir = dir_path.clone();
        let waiter = std::thread::spawn(move || {
            let start = Instant::now();
            let lock = acquire(&waiter_dir, "index.lock", Duration::from_secs(5))
                .expect("waiter must observe the release rather than timing out");
            (lock, start.elapsed())
        });

        // Let the holder sit on the lock briefly, then release it. The
        // waiter's bounded 5s timeout is generous; what matters is that
        // it does not need anywhere near that long once release happens.
        std::thread::sleep(Duration::from_millis(150));
        release_tx.send(()).unwrap();
        holder_thread.join().unwrap();

        let (lock, elapsed) = waiter.join().unwrap();
        assert!(
            elapsed < Duration::from_secs(2),
            "waiter should wake up promptly on release, not approach the 5s timeout, took {elapsed:?}"
        );
        drop(lock);
    }
}
