#![cfg_attr(not(test), deny(clippy::print_stdout, clippy::print_stderr))]
#![doc = include_str!("../README.md")]
//!
//! Local-filesystem [`Transport`] implementation.
//!
//! This is a real local/served transport, not a test-only fixture: it is
//! the backend for `mkit+file://` remotes and for repositories served via
//! `mkit serve`. It also doubles as the in-tree test transport.
//!
//! Stores pack files under `<root>/packs/<64-hex>` and ref files under
//! `<root>/refs/...`.
//!
//! ## On-disk layout
//!
//! ```text
//! <root>/
//!   packs/<64-hex>          — raw pack bytes, written atomically
//!   refs/heads/main         — 65-byte wire (64-hex + '\n')
//!   refs/tags/v1.0          — nested dirs created on demand
//! ```
//!
//! ## CAS atomicity guarantees
//!
//! | Variant   | Mechanism                                              | Race behaviour |
//! |-----------|--------------------------------------------------------|----------------|
//! | `Any`     | `write_atomic`: tmp file → `fsync` → `rename` → parent | Last writer wins. Concurrent writers never expose a half-written file because `rename(2)` is atomic on POSIX. |
//! | `Missing` | `write_create_new`: same tmp+fsync, then a hard-link    | Only the first writer succeeds. If two concurrent callers both see "absent" before writing, only one `link(2)` wins; the other gets `AlreadyExists` → `RefConflict`. |
//! | `Match(H)`| OS file-lock + in-process `Mutex` around read-then-`write_atomic` | Atomic across processes on the same on-disk root. The OS exclusive lock on `<root>/.mkit/refs/.lock` serialises every `Match` CAS critical section; the in-process `Mutex` keeps multi-threaded callers from racing each other before they hit the file lock. |
//!
//! Cross-process atomicity for `Match` is achieved via
//! [`std::fs::File::lock`] (stable as of Rust 1.89) on a sentinel file
//! `<root>/.mkit/refs/.lock`. The lock is held for the duration of the
//! read-compare-write sequence and released on `Drop` (including on
//! panic). The in-process `Mutex` is retained as a fast-path optimisation
//! and to serialise lock acquisition fairly within one process.
//!
//! Every ref write takes both locks, whatever its condition.
//! [`FileTransport::with_ref_lock`] hands the same lock to callers that
//! read, decide and write several files as one step (a metadata store's
//! check-and-write), through [`LockedRefs`].

#![forbid(unsafe_code)]

use std::fs;
use std::io::{self, ErrorKind};
use std::path::{Component, Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use mkit_core::hash::Hash;
use mkit_core::protocol::{PackKey, RefWriteCondition, Transport, TransportError, TransportResult};
use mkit_core::refs::{
    Ref, decode_ref_wire, encode_ref_wire, validate_ref_name, validate_ref_name_grammar,
    validate_ref_prefix,
};

// We need write_atomic and write_create_new from mkit_core's private `atomic`
// module. Since they are `pub(crate)`, we re-implement them locally here.
// The logic is identical to `mkit_core::atomic`.

use std::process;
use std::sync::atomic::{AtomicU64, Ordering};

static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// A fresh temp-file path next to `dest`: `.<file name>.tmp.<pid>.<seq>`
/// in `dest`'s directory. Every temp file this crate writes is named here,
/// from one process-wide counter, so two writers in one process never pick
/// the same name, and writers in different processes differ by pid. A
/// streaming writer that publishes into the same layout (a blob store
/// writing `packs/`) names its temp files here too, so it can never
/// collide with this crate's own writes.
///
/// # Errors
/// `InvalidInput` if `dest` has no parent directory or no file name.
pub fn temp_path(dest: &Path) -> io::Result<PathBuf> {
    let parent = dest
        .parent()
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, "destination path has no parent"))?;
    let file_name = dest
        .file_name()
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, "destination has no file name"))?
        .to_string_lossy();
    let pid = process::id();
    let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
    Ok(parent.join(format!(".{file_name}.tmp.{pid}.{seq}")))
}

/// Atomically write `bytes` to `dest` using a temp-file + fsync +
/// rename + parent-dir-fsync sequence. Creates parent dirs when
/// `make_parents` is `true`. Mirrors `mkit_core::atomic::write_atomic`.
fn write_atomic(dest: &Path, bytes: &[u8], make_parents: bool) -> io::Result<()> {
    let parent = dest
        .parent()
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, "destination path has no parent"))?;
    if make_parents {
        create_dir_all_durably(parent)?;
    }

    let tmp_path = temp_path(dest)?;

    {
        use std::io::Write;
        let mut f = fs::File::create(&tmp_path)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }

    fs::rename(&tmp_path, dest)?;
    // Make the rename's dirent durable. Propagated (not best-effort
    // discarded): on power loss a swallowed parent-dir fsync could lose a
    // committed ref/pack write. Matches `mkit_core::atomic::write_atomic`,
    // which propagates its `sync_parent_dir(parent)?` the same way.
    sync_parent(parent)?;
    Ok(())
}

/// Exclusive-create variant: writes `bytes` to `dest` only if `dest`
/// does not already exist. Returns `Ok(true)` on success, `Ok(false)`
/// if the destination was already present. Mirrors
/// `mkit_core::atomic::write_create_new`.
fn write_create_new(dest: &Path, bytes: &[u8], make_parents: bool) -> io::Result<bool> {
    let parent = dest
        .parent()
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, "destination path has no parent"))?;
    if make_parents {
        create_dir_all_durably(parent)?;
    }

    let tmp_path = temp_path(dest)?;

    {
        use std::io::Write;
        let mut f = fs::File::create(&tmp_path)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }

    // Hard-link tmp → dest (atomic, fails with AlreadyExists if dest exists).
    match fs::hard_link(&tmp_path, dest) {
        Ok(()) => {
            let _ = fs::remove_file(&tmp_path);
            // Make the hard-link's dirent durable. Propagated (not
            // best-effort discarded): on power loss a swallowed
            // parent-dir fsync could lose a committed ref write. Matches
            // `mkit_core::atomic::write_create_new`.
            sync_parent(parent)?;
            Ok(true)
        }
        Err(e) if e.kind() == ErrorKind::AlreadyExists => {
            let _ = fs::remove_file(&tmp_path);
            Ok(false)
        }
        Err(e) => {
            let _ = fs::remove_file(&tmp_path);
            Err(e)
        }
    }
}

/// Fsync a directory, making completed renames/hard-links durable.
///
/// The result is propagated by callers (not discarded) so a power loss
/// cannot silently lose a committed ref/pack write. A `NotFound` is
/// tolerated as success — the directory only vanishes if a concurrent
/// actor removed it, in which case there is nothing left to make
/// durable. Mirrors `mkit_core::atomic::sync_parent_dir`.
///
/// Unix-only: opening a directory with a plain [`fs::File::open`] (no
/// `FILE_FLAG_BACKUP_SEMANTICS`) fails on Windows with `ERROR_ACCESS_DENIED`
/// (os error 5) — this crate's `write_atomic`/`write_create_new` were
/// silently failing every ref/pack write on Windows through this path
/// before the platform split below was added (caught by the `windows-smoke`
/// CI job; `mkit_core::atomic::sync_parent_dir`, which this mirrors, already
/// had this split). Directory-fsync is a POSIX durability idiom with no
/// direct Windows equivalent reachable from safe `std::fs`, so the
/// non-Unix arm is a deliberate no-op, not a partial implementation.
#[cfg(unix)]
fn sync_parent(dir: &Path) -> io::Result<()> {
    match fs::File::open(dir) {
        Ok(d) => d.sync_all(),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
fn sync_parent(_dir: &Path) -> io::Result<()> {
    Ok(())
}

/// Fsync directory `dir`, making the renames, links and removals already
/// done in it durable: what every write of this crate does after its
/// rename. A missing `dir` counts as success; on non-Unix targets this is a
/// no-op (see `sync_parent`). For writers that publish into the same
/// layout with their own temp file (see [`temp_path`]).
///
/// # Errors
/// The directory could not be opened or synced.
pub fn sync_dir(dir: &Path) -> io::Result<()> {
    sync_parent(dir)
}

/// [`fs::create_dir_all`], then fsync the parent of every directory it
/// created, top-most first, so a file later published in `dir` does not
/// vanish with its directory on power loss. A no-op when `dir` exists.
///
/// # Errors
/// A directory could not be created or a parent could not be synced.
pub fn create_dir_all_durably(dir: &Path) -> io::Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    let missing: Vec<&Path> = dir
        .ancestors()
        .take_while(|d| !d.as_os_str().is_empty() && !d.exists())
        .collect();
    fs::create_dir_all(dir)?;
    for created in missing.iter().rev() {
        if let Some(parent) = created.parent().filter(|p| !p.as_os_str().is_empty()) {
            sync_parent(parent)?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Cross-process ref lock
// ---------------------------------------------------------------------------

/// RAII guard around an OS-level exclusive file lock on the per-repo
/// sentinel file `<root>/.mkit/refs/.lock`. Used to serialise `Match`
/// CAS critical sections across processes that share the same on-disk
/// root.
///
/// On `Drop` (including on panic-unwind) the kernel releases the lock
/// when the underlying `File` handle is closed; we also call
/// [`std::fs::File::unlock`] explicitly to surface any I/O error in
/// debug builds via the panic path (it is otherwise silently
/// discarded — best-effort).
///
/// We deliberately do **not** lock the ref file itself. Refs are
/// written via tmp + atomic `rename`, which produces a brand-new inode
/// each time; a lock taken on the previous inode would migrate to an
/// abandoned file and stop providing mutual exclusion.
///
/// v1 uses blocking [`File::lock`](std::fs::File::lock) (formerly `lock_exclusive`); refs
/// updates are user-driven and serialisation is the desired behaviour.
/// A future v2 could expose `try_lock` for fail-fast contention
/// handling.
#[must_use = "lock is released on drop; bind to a named guard"]
struct RefLock {
    file: fs::File,
}

impl RefLock {
    /// Acquire the exclusive lock on `<root>/.mkit/refs/.lock`,
    /// creating the lock file (and its parent directories) on first
    /// use. Blocks until the lock can be taken.
    fn acquire(root: &Path) -> io::Result<Self> {
        let lock_dir = mkit_core::layout::RepoLayout::single(root).refs_dir();
        fs::create_dir_all(&lock_dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Best-effort: tighten parent dir permissions to 0700 on
            // creation. Ignore errors on filesystems that do not
            // support POSIX permissions (e.g. FAT-on-removable-media).
            let _ = fs::set_permissions(&lock_dir, fs::Permissions::from_mode(0o700));
        }

        let lock_path = lock_dir.join(".lock");
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600));
        }

        // Blocking exclusive lock. Stable since Rust 1.89.
        file.lock()?;
        Ok(Self { file })
    }
}

impl Drop for RefLock {
    fn drop(&mut self) {
        // Best-effort explicit unlock. The kernel also releases when
        // the file handle is closed, which covers the panic-unwind
        // path.
        let _ = self.file.unlock();
    }
}

// ---------------------------------------------------------------------------
// FileTransport
// ---------------------------------------------------------------------------

/// Local-filesystem transport. Every instance holds a root `PathBuf`
/// and a `Mutex` protecting the `Match` CAS read-then-write sequence
/// within a process. Cross-process atomicity is supplied separately
/// by `RefLock`, which takes an OS exclusive lock on
/// `<root>/.mkit/refs/.lock` for the duration of the CAS critical
/// section.
///
/// The `Mutex` is unit-typed (zero overhead for lock/unlock when
/// uncontended); all other operations (`Any`, `Missing`, pack I/O) do
/// **not** acquire it.
#[derive(Debug)]
pub struct FileTransport {
    root: PathBuf,
    /// Serialises `Match` CAS within a single process.
    cas_lock: Mutex<()>,
}

/// Canonicalize `path`, or — if it does not exist yet — canonicalize its
/// closest existing ancestor and re-attach the not-yet-created trailing
/// components. This resolves any symlinked parent already on disk while
/// still yielding the full intended path (comparing only the ancestor
/// would wrongly reject legitimate writes when the root itself does not
/// exist yet). Returns `None` only if nothing along the ancestor chain
/// can be canonicalized.
fn canonicalize_with_missing_tail(path: &Path) -> Option<PathBuf> {
    if let Ok(c) = fs::canonicalize(path) {
        return Some(c);
    }
    let mut ancestor = path.parent();
    while let Some(p) = ancestor {
        if let Ok(c) = fs::canonicalize(p) {
            return Some(match path.strip_prefix(p) {
                Ok(rel) => c.join(rel),
                Err(_) => c,
            });
        }
        ancestor = p.parent();
    }
    None
}

impl FileTransport {
    /// Create a `FileTransport` rooted at `root`. The root directory does
    /// not need to exist yet: sub-directories (`packs/`, `refs/`) and the
    /// root itself are created on demand by the write paths. The
    /// path-escape guard canonicalises the root lazily at use time, so a
    /// root that does not exist at construction (or one that lives under a
    /// symlinked parent, e.g. macOS `/tmp` -> `/private/tmp`) does not
    /// spuriously trip the guard.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            cas_lock: Mutex::new(()),
        }
    }

    /// Resolve the comparison base for the path-escape guard: the
    /// canonical form of `root` if it (or its closest existing ancestor)
    /// exists on disk, else the literal `root`.
    ///
    /// Computed lazily on every guard check rather than cached at
    /// construction. Caching the construction-time value silently disables
    /// the guard whenever the root does not exist yet (it would store the
    /// non-canonical literal path) or lives under a symlinked parent: a
    /// legitimate ref then canonicalises to the resolved `/private/...`
    /// form which does not start with the stored `/tmp/...` prefix, so the
    /// guard rejects valid writes. Re-deriving here keeps the base
    /// canonical once the directory exists.
    fn canonical_root(&self) -> PathBuf {
        canonicalize_with_missing_tail(&self.root).unwrap_or_else(|| self.root.clone())
    }

    /// [`RefFileError::MetaElsewhere`] if the root carries
    /// [`SERVER_META_MARKER`]. A marker that cannot be checked is refused
    /// too (fail closed).
    fn refuse_if_meta_elsewhere(&self) -> Result<(), RefFileError> {
        let marker = self.root.join(SERVER_META_MARKER);
        match fs::symlink_metadata(&marker) {
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
            Ok(_) => Err(RefFileError::MetaElsewhere(marker)),
            Err(e) => Err(RefFileError::Io(e)),
        }
    }

    fn pack_path(&self, key: &PackKey) -> PathBuf {
        self.root.join("packs").join(key.to_hex())
    }

    fn ref_path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    /// Path-escape guard: verify that `path` (whether it already exists
    /// or not) resolves under the (lazily canonicalised) transport root.
    /// Returns `Ok(())` on success, or a `RemoteError` if the operation
    /// would escape the transport tree via a pre-existing symlink.
    ///
    /// - If `path` exists, `canonicalize(path)` is compared against the
    ///   canonical root. A canonicalize failure here (e.g. `EACCES`/`ELOOP`
    ///   on a component) is a hard error — fail closed rather than fall
    ///   back to a lenient check on a path-traversal boundary.
    /// - If `path` does not exist yet, [`canonicalize_with_missing_tail`]
    ///   canonicalises its closest existing ancestor (following any
    ///   symlinked parent already on disk) and re-attaches the missing
    ///   tail; that result must sit under the canonical root.
    fn check_ref_path(&self, path: &Path) -> TransportResult<()> {
        let canonical_root = self.canonical_root();
        let resolved = if path.exists() {
            fs::canonicalize(path).map_err(|e| {
                TransportError::RemoteError(format!("canonicalize ref path failed: {e}"))
            })?
        } else {
            canonicalize_with_missing_tail(path).unwrap_or_else(|| path.to_path_buf())
        };

        if resolved.starts_with(&canonical_root) {
            Ok(())
        } else {
            Err(TransportError::RemoteError(format!(
                "path escape: {} resolves outside transport root",
                path.display()
            )))
        }
    }

    /// The transport root: `packs/`, `refs/` and `.mkit/` live under it.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Run `f` holding the ref mutation lock: this transport's in-process
    /// mutex, then the OS exclusive lock on `<root>/.mkit/refs/.lock`
    /// (created on first use). Every ref write takes it, including
    /// [`Transport::update_ref`], so what `f` reads, decides and writes
    /// through [`LockedRefs`] is one step that no other writer on the same
    /// root, in this process or another, can interleave with. Blocks until
    /// the lock is free. `f` is synchronous, so nothing holds the lock
    /// across an `.await`.
    ///
    /// A panic in `f` releases both locks. The in-process mutex guards no
    /// data (the state is the files, and every write is one atomic rename),
    /// so a panic never poisons the transport: the next caller recovers it.
    ///
    /// # Errors
    /// [`RefFileError::Io`] if the lock file cannot be created or locked;
    /// `f` did not run.
    pub fn with_ref_lock<T>(
        &self,
        f: impl FnOnce(&LockedRefs<'_>) -> T,
    ) -> Result<T, RefFileError> {
        let _process_guard = self.cas_lock.lock().unwrap_or_else(PoisonError::into_inner);
        let _xproc_guard = RefLock::acquire(&self.root).map_err(RefFileError::Io)?;
        Ok(f(&LockedRefs { tx: self }))
    }

    /// The ref's id, strictly: like [`Transport::read_ref`], but a ref file
    /// that does not hold a ref wire is [`RefFileError::Corrupt`] rather
    /// than absent. A directory where the ref file would be is no ref.
    ///
    /// # Errors
    /// [`RefFileError::InvalidName`], [`RefFileError::Escape`] for the
    /// path-escape guard, [`RefFileError::Corrupt`], or I/O.
    pub fn read_ref_strict(&self, name: &str) -> Result<Option<Hash>, RefFileError> {
        if !validate_ref_name(name) {
            return Err(RefFileError::InvalidName(name.to_owned()));
        }
        let path = self.ref_path(name);
        if path.is_dir() {
            return Ok(None);
        }
        if path.exists() {
            self.guard_ref_path(&path)?;
        }
        match fs::read(&path) {
            Ok(bytes) => decode_ref_wire(&bytes)
                .map(Some)
                .ok_or_else(|| RefFileError::Corrupt(name.to_owned())),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(RefFileError::Io(e)),
        }
    }

    /// Every ref file under `prefix` (a directory, e.g. `refs/`), with its
    /// full name and its id, or `None` for a file whose name is a valid
    /// ref name (by the grammar: a name over
    /// [`mkit_core::refs::MAX_REF_NAME_BYTES`] is listed, for the caller to
    /// skip loudly) but that does not hold a ref wire, which
    /// [`Transport::list_refs`] skips silently: the caller decides whether
    /// to skip it loudly or fail. Symlinks, temp and lock files are
    /// skipped, as there. Sorted by name.
    ///
    /// # Errors
    /// [`RefFileError::InvalidName`] for an invalid prefix, or I/O.
    pub fn list_ref_files(
        &self,
        prefix: &str,
    ) -> Result<Vec<(String, Option<Hash>)>, RefFileError> {
        let trimmed = prefix.trim_end_matches('/');
        if !validate_ref_name(trimmed) {
            return Err(RefFileError::InvalidName(prefix.to_owned()));
        }
        let mut out = Vec::new();
        let mut dirs = vec![self.root.join(trimmed)];
        while let Some(dir) = dirs.pop() {
            let entries = match fs::read_dir(&dir) {
                Ok(entries) => entries,
                Err(e) if e.kind() == ErrorKind::NotFound => continue,
                Err(e) => return Err(RefFileError::Io(e)),
            };
            for entry in entries {
                let entry = entry.map_err(RefFileError::Io)?;
                let path = entry.path();
                let file_type = entry.file_type().map_err(RefFileError::Io)?;
                if file_type.is_dir() {
                    dirs.push(path);
                    continue;
                }
                let Ok(rel) = path.strip_prefix(&self.root) else {
                    continue;
                };
                let name = rel.to_string_lossy().replace('\\', "/");
                // The grammar without the length bound: a ref file named
                // before SPEC-REFS §3 bounded names is reported, so the
                // caller can skip it loudly.
                if !file_type.is_file() || !validate_ref_name_grammar(&name) {
                    continue; // a symlink, a temp or lock file, or no ref name
                }
                let bytes = fs::read(&path).map_err(RefFileError::Io)?;
                out.push((name, decode_ref_wire(&bytes)));
            }
        }
        out.sort();
        Ok(out)
    }

    /// The path of a server-owned file: `rel` must be a plain relative path
    /// (normal components only) under [`SERVER_DIR`], and must not resolve
    /// outside `<root>/.mkit/server` through a symlink. The only files
    /// [`LockedRefs::write_file`] and [`LockedRefs::remove_file`] touch.
    ///
    /// # Errors
    /// [`RefFileError::Escape`] for any other path.
    pub fn server_path(&self, rel: &Path) -> Result<PathBuf, RefFileError> {
        let plain = rel.components().all(|c| matches!(c, Component::Normal(_)));
        let inside = rel
            .strip_prefix(SERVER_DIR)
            .is_ok_and(|r| r.components().next().is_some());
        if !plain || !inside {
            return Err(RefFileError::Escape(format!(
                "path escape: {} is not a path under {SERVER_DIR}",
                rel.display()
            )));
        }
        let path = self.root.join(rel);
        let base = self.canonical_root().join(SERVER_DIR);
        let resolved = if path.exists() {
            fs::canonicalize(&path).map_err(RefFileError::Io)?
        } else {
            canonicalize_with_missing_tail(&path).unwrap_or_else(|| path.clone())
        };
        if resolved.starts_with(&base) {
            Ok(path)
        } else {
            Err(RefFileError::Escape(format!(
                "path escape: {} resolves outside {SERVER_DIR}",
                path.display()
            )))
        }
    }

    /// [`Self::check_ref_path`] as a [`RefFileError`].
    fn guard_ref_path(&self, path: &Path) -> Result<(), RefFileError> {
        self.check_ref_path(path).map_err(|e| match e {
            TransportError::RemoteError(msg) => RefFileError::Escape(msg),
            other => RefFileError::Escape(other.to_string()),
        })
    }

    /// Whether writing a ref file at `dest` clashes with another ref: a
    /// directory is where the file would go, or a file is where one of its
    /// directories would go.
    fn ref_clash(&self, dest: &Path) -> bool {
        dest.is_dir()
            || dest
                .ancestors()
                .skip(1)
                .take_while(|d| *d != self.root)
                .any(Path::is_file)
    }

    /// Remove the directories between `path` and `<root>/<first component
    /// of name>` that are empty, innermost first; best-effort.
    fn prune_empty_parents(&self, path: &Path, name: &str) {
        let stop = self.root.join(name.split('/').next().unwrap_or(name));
        for dir in path.ancestors().skip(1) {
            if dir == stop || !dir.starts_with(&stop) || fs::remove_dir(dir).is_err() {
                break;
            }
            if let Some(parent) = dir.parent() {
                let _ = sync_parent(parent);
            }
        }
    }
}

/// The directory, under a [`FileTransport`] root, of files a server keeps
/// next to the refs ([`LockedRefs::write_file`]).
pub const SERVER_DIR: &str = ".mkit/server";

/// The marker, under a [`FileTransport`] root, that a `mkit-server --meta
/// sqlite:` deployment writes: the root's refs live in that server's
/// `SQLite` database, not in ref files. Every ref write through this
/// transport refuses a marked root ([`RefFileError::MetaElsewhere`]), so a
/// local push or `mkit serve` cannot keep a second, diverging copy of the
/// refs. Reads still work.
pub const SERVER_META_MARKER: &str = ".mkit/server-meta";

/// Why a strict ref-file operation ([`LockedRefs`],
/// [`FileTransport::read_ref_strict`], [`FileTransport::list_ref_files`],
/// [`FileTransport::server_path`]) failed. It converts into the
/// [`TransportError`] the [`Transport`] verbs return.
#[derive(Debug)]
#[non_exhaustive]
pub enum RefFileError {
    /// Not a valid ref name, or the ref clashes with another: a directory
    /// is where its file would go, or a file where its directory would.
    InvalidName(String),
    /// A path the operation may not touch: outside [`SERVER_DIR`], or
    /// resolving outside the root through a symlink.
    Escape(String),
    /// The CAS condition did not hold.
    Conflict,
    /// A ref file exists but does not hold a ref wire.
    Corrupt(String),
    /// I/O failed.
    Io(io::Error),
    /// The root carries [`SERVER_META_MARKER`]: its refs live in a
    /// `mkit-server` `SQLite` database, so no ref file may be written. The
    /// marker's path.
    MetaElsewhere(PathBuf),
}

impl std::fmt::Display for RefFileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MetaElsewhere(marker) => write!(
                f,
                "refusing to write ref files: this root's refs live in a mkit-server SQLite \
                 database (marker {}); push to that server instead",
                marker.display()
            ),
            Self::InvalidName(name) => write!(f, "invalid or clashing ref name: {name}"),
            Self::Escape(msg) => f.write_str(msg),
            Self::Conflict => f.write_str("ref CAS precondition failed"),
            Self::Corrupt(name) => write!(f, "ref file {name} does not hold a ref id"),
            Self::Io(e) => write!(f, "ref file I/O error: {e}"),
        }
    }
}

impl std::error::Error for RefFileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<RefFileError> for TransportError {
    fn from(e: RefFileError) -> Self {
        match e {
            RefFileError::InvalidName(name) => Self::InvalidRef(name),
            RefFileError::Conflict => Self::RefConflict,
            other => Self::RemoteError(other.to_string()),
        }
    }
}

/// The ref files (and the server files under [`SERVER_DIR`]) of a
/// [`FileTransport`] root while [`FileTransport::with_ref_lock`] holds the
/// ref lock. Writes are the transport's CAS and atomic writes, without
/// taking the lock again.
#[derive(Debug)]
pub struct LockedRefs<'a> {
    tx: &'a FileTransport,
}

impl LockedRefs<'_> {
    /// The ref's id: [`FileTransport::read_ref_strict`].
    ///
    /// # Errors
    /// As [`FileTransport::read_ref_strict`].
    pub fn read_ref(&self, name: &str) -> Result<Option<Hash>, RefFileError> {
        self.tx.read_ref_strict(name)
    }

    /// The CAS write of [`Transport::update_ref`], under the lock already
    /// held. A ref that clashes with another (a directory where its file
    /// would go, or a file where its directory would) is
    /// [`RefFileError::InvalidName`].
    ///
    /// # Errors
    /// [`RefFileError::InvalidName`], [`RefFileError::Escape`],
    /// [`RefFileError::Conflict`], or I/O.
    pub fn update_ref(
        &self,
        name: &str,
        condition: RefWriteCondition,
        hash: &Hash,
    ) -> Result<(), RefFileError> {
        if !validate_ref_name(name) {
            return Err(RefFileError::InvalidName(name.to_owned()));
        }
        self.tx.refuse_if_meta_elsewhere()?;
        let dest = self.tx.ref_path(name);
        self.tx.guard_ref_path(&dest)?;
        if self.tx.ref_clash(&dest) {
            return Err(RefFileError::InvalidName(name.to_owned()));
        }
        let wire = encode_ref_wire(hash);

        match condition {
            // Unconditional atomic overwrite.
            RefWriteCondition::Any => write_atomic(&dest, &wire, true).map_err(RefFileError::Io),

            RefWriteCondition::Missing => {
                // Exclusive create: succeeds only when the file is absent.
                match write_create_new(&dest, &wire, true) {
                    Ok(true) => Ok(()),
                    Ok(false) => Err(RefFileError::Conflict),
                    Err(e) => Err(RefFileError::Io(e)),
                }
            }

            RefWriteCondition::Match(expected) => {
                match read_ref_raw(&dest).map_err(RefFileError::Io)? {
                    Some(c) if c == expected => {}
                    _ => return Err(RefFileError::Conflict),
                }
                write_atomic(&dest, &wire, true).map_err(RefFileError::Io)
            }
        }
    }

    /// Remove the ref file, fsync its directory, then remove the
    /// directories it left empty below the name's first component (so
    /// `refs/` stays); `false` if there was no ref file.
    ///
    /// # Errors
    /// [`RefFileError::InvalidName`], [`RefFileError::Escape`], or I/O.
    pub fn delete_ref(&self, name: &str) -> Result<bool, RefFileError> {
        if !validate_ref_name(name) {
            return Err(RefFileError::InvalidName(name.to_owned()));
        }
        self.tx.refuse_if_meta_elsewhere()?;
        let path = self.tx.ref_path(name);
        self.tx.guard_ref_path(&path)?;
        if path.is_dir() {
            return Ok(false);
        }
        let removed = remove_durably(&path).map_err(RefFileError::Io)?;
        if removed {
            self.tx.prune_empty_parents(&path, name);
        }
        Ok(removed)
    }

    /// Atomically replace the server file at `rel` (see
    /// [`FileTransport::server_path`]) with `bytes`, creating its
    /// directories: the same temp file, fsync, rename and directory fsync
    /// as a ref write.
    ///
    /// # Errors
    /// [`RefFileError::Escape`] for a path outside [`SERVER_DIR`], or I/O.
    pub fn write_file(&self, rel: &Path, bytes: &[u8]) -> Result<(), RefFileError> {
        self.tx.refuse_if_meta_elsewhere()?;
        let path = self.tx.server_path(rel)?;
        write_atomic(&path, bytes, true).map_err(RefFileError::Io)
    }

    /// Remove the server file at `rel` (see [`FileTransport::server_path`]),
    /// then fsync its directory; `false` if it was absent.
    ///
    /// # Errors
    /// [`RefFileError::Escape`] for a path outside [`SERVER_DIR`], or I/O.
    pub fn remove_file(&self, rel: &Path) -> Result<bool, RefFileError> {
        self.tx.refuse_if_meta_elsewhere()?;
        let path = self.tx.server_path(rel)?;
        remove_durably(&path).map_err(RefFileError::Io)
    }
}

/// Remove `path`, then fsync its directory; `false` if it was absent.
fn remove_durably(path: &Path) -> io::Result<bool> {
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    }
    if let Some(parent) = path.parent() {
        sync_parent(parent)?;
    }
    Ok(true)
}

impl Transport for FileTransport {
    // ------------------------------------------------------------------
    // Pack verbs
    // ------------------------------------------------------------------

    fn upload_pack(&self, bytes: &[u8], key: &PackKey) -> TransportResult<()> {
        let dest = self.pack_path(key);
        write_atomic(&dest, bytes, true)
            .map_err(|e| TransportError::RemoteError(format!("upload_pack I/O error: {e}")))
    }

    fn download_pack(&self, key: &PackKey) -> TransportResult<Vec<u8>> {
        let path = self.pack_path(key);
        match fs::read(&path) {
            Ok(bytes) => Ok(bytes),
            Err(e) if e.kind() == ErrorKind::NotFound => Err(TransportError::PackNotFound),
            Err(e) => Err(TransportError::RemoteError(format!(
                "download_pack I/O error: {e}"
            ))),
        }
    }

    fn pack_exists(&self, key: &PackKey) -> TransportResult<bool> {
        Ok(self.pack_path(key).exists())
    }

    // ------------------------------------------------------------------
    // Ref verbs
    // ------------------------------------------------------------------

    fn update_ref(
        &self,
        name: &str,
        condition: RefWriteCondition,
        hash: &Hash,
    ) -> TransportResult<()> {
        if !validate_ref_name(name) {
            return Err(TransportError::InvalidRef(name.to_owned()));
        }
        // Every condition participates: an unconditional write must not
        // interleave between a Match read and its publication.
        Ok(self.with_ref_lock(|refs| refs.update_ref(name, condition, hash))??)
    }

    fn read_ref(&self, name: &str) -> TransportResult<Option<Hash>> {
        if !validate_ref_name(name) {
            return Err(TransportError::InvalidRef(name.to_owned()));
        }
        let path = self.ref_path(name);
        // Path-escape guard: if the file already exists, it must
        // canonicalise under the transport root. If it does not exist
        // the read will return `None` via `read_ref_raw` unchanged.
        if path.exists() {
            self.check_ref_path(&path)?;
        }
        read_ref_raw(&path)
            .map_err(|e| TransportError::RemoteError(format!("read_ref I/O error: {e}")))
    }

    fn list_refs(&self, prefix: &str) -> TransportResult<Vec<Ref>> {
        if !validate_ref_prefix(prefix) {
            return Err(TransportError::InvalidRef(prefix.to_owned()));
        }

        let prefix_trimmed = prefix.trim_end_matches('/');
        let dir = if prefix_trimmed.is_empty() {
            self.root.clone()
        } else {
            self.root.join(prefix_trimmed)
        };

        let mut out = Vec::new();
        collect_refs(&dir, &dir, &mut out)?;
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Read and decode the hash from a ref file. Returns `None` if the
/// file does not exist; propagates other I/O errors.
fn read_ref_raw(path: &Path) -> io::Result<Option<Hash>> {
    match fs::read(path) {
        Ok(bytes) => Ok(decode_ref_wire(&bytes)),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Recursively walk `dir`, collecting all ref files whose full logical
/// name starts with `prefix`. Entries are pushed to `out` with the
/// prefix stripped.
///
/// `root_dir` is the directory corresponding to `prefix_trimmed` (the
/// first call uses `prefix_trimmed`'s directory). `current_dir` is the
/// directory currently being iterated. We track the relative path from
/// `root_dir` to each file to build the suffix name.
fn collect_refs(root_dir: &Path, current_dir: &Path, out: &mut Vec<Ref>) -> TransportResult<()> {
    let entries = match fs::read_dir(current_dir) {
        Ok(e) => e,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(TransportError::RemoteError(format!(
                "list_refs I/O error: {e}"
            )));
        }
    };

    for entry in entries {
        let entry = entry
            .map_err(|e| TransportError::RemoteError(format!("list_refs dir entry error: {e}")))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|e| TransportError::RemoteError(format!("list_refs file_type error: {e}")))?;

        if file_type.is_dir() {
            collect_refs(root_dir, &path, out)?;
        } else if file_type.is_file() {
            // Build the name relative to root_dir.
            let rel = path
                .strip_prefix(root_dir)
                .expect("path is under root_dir")
                .to_string_lossy()
                .replace('\\', "/"); // normalise Windows separators

            // Only include entries that are valid ref name segments.
            if !validate_ref_name(&rel) {
                continue;
            }

            if let Ok(bytes) = fs::read(&path)
                && let Some(hash) = decode_ref_wire(&bytes)
            {
                out.push(Ref {
                    name: rel,
                    hash: Some(hash),
                });
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use mkit_core::hash::hash as blake3_hash;
    use mkit_core::protocol::RefWriteCondition;
    use tempfile::TempDir;

    fn tmp() -> TempDir {
        tempfile::tempdir().expect("create tempdir")
    }

    fn pack_key_for(data: &[u8]) -> PackKey {
        PackKey::from(blake3_hash(data))
    }

    // ------------------------------------------------------------------
    // Pack verb tests (6 tests)
    // ------------------------------------------------------------------

    #[test]
    fn upload_and_download_pack() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        let data = b"hello packfile content";
        let key = pack_key_for(data);
        t.upload_pack(data, &key).unwrap();
        let got = t.download_pack(&key).unwrap();
        assert_eq!(got, data);
    }

    #[test]
    fn download_missing_pack_returns_not_found() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        let key = pack_key_for(b"nonexistent pack");
        let err = t.download_pack(&key).unwrap_err();
        assert!(matches!(err, TransportError::PackNotFound));
    }

    #[test]
    fn upload_pack_creates_packs_directory() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        assert!(!dir.path().join("packs").exists());
        let data = b"first pack";
        let key = pack_key_for(data);
        t.upload_pack(data, &key).unwrap();
        assert!(dir.path().join("packs").is_dir());
    }

    #[test]
    fn pack_exists_before_and_after_upload() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        let data = b"exists test";
        let key = pack_key_for(data);
        assert!(!t.pack_exists(&key).unwrap());
        t.upload_pack(data, &key).unwrap();
        assert!(t.pack_exists(&key).unwrap());
    }

    #[test]
    fn upload_pack_overwrites_idempotently() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        let key = PackKey::new([0x77u8; 32]);
        t.upload_pack(b"first", &key).unwrap();
        t.upload_pack(b"second", &key).unwrap();
        assert_eq!(t.download_pack(&key).unwrap(), b"second");
    }

    #[test]
    fn pack_filename_is_64_hex_chars() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        let data = b"hex filename test";
        let key = pack_key_for(data);
        t.upload_pack(data, &key).unwrap();
        let expected_name = key.to_hex();
        assert!(dir.path().join("packs").join(&expected_name).exists());
        assert_eq!(expected_name.len(), 64);
    }

    // ------------------------------------------------------------------
    // Ref verb tests (10 tests)
    // ------------------------------------------------------------------

    #[test]
    fn write_and_read_ref() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        let h = blake3_hash(b"commit-data");
        t.write_ref("refs/heads/main", &h).unwrap();
        let read = t.read_ref("refs/heads/main").unwrap();
        assert_eq!(read, Some(h));
    }

    #[test]
    fn write_ref_creates_parent_dirs() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        let h = blake3_hash(b"deep-ref");
        t.write_ref("refs/heads/feature/deep/branch", &h).unwrap();
        // Intermediate dirs were created.
        assert!(dir.path().join("refs/heads/feature/deep").is_dir());
        assert_eq!(
            t.read_ref("refs/heads/feature/deep/branch").unwrap(),
            Some(h)
        );
    }

    #[test]
    fn read_missing_ref_returns_none() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        assert_eq!(t.read_ref("refs/heads/nonexistent").unwrap(), None);
    }

    #[test]
    fn write_ref_overwrites_previous() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        let h1 = blake3_hash(b"commit-v1");
        let h2 = blake3_hash(b"commit-v2");
        t.write_ref("refs/heads/main", &h1).unwrap();
        t.write_ref("refs/heads/main", &h2).unwrap();
        assert_eq!(t.read_ref("refs/heads/main").unwrap(), Some(h2));
    }

    #[test]
    fn update_ref_match_success_writes_new_hash() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        let h_old = blake3_hash(b"cas-old");
        let h_new = blake3_hash(b"cas-new");
        t.write_ref("refs/heads/main", &h_old).unwrap();
        t.update_ref("refs/heads/main", RefWriteCondition::Match(h_old), &h_new)
            .unwrap();
        assert_eq!(t.read_ref("refs/heads/main").unwrap(), Some(h_new));
    }

    #[test]
    fn update_ref_match_stale_returns_conflict() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        let h_current = blake3_hash(b"current");
        let h_stale = blake3_hash(b"stale");
        let h_next = blake3_hash(b"next");
        t.write_ref("refs/heads/main", &h_current).unwrap();
        let err = t
            .update_ref(
                "refs/heads/main",
                RefWriteCondition::Match(h_stale),
                &h_next,
            )
            .unwrap_err();
        assert!(matches!(err, TransportError::RefConflict));
        // Ref unchanged.
        assert_eq!(t.read_ref("refs/heads/main").unwrap(), Some(h_current));
    }

    #[test]
    fn update_ref_missing_creates_when_absent() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        let h = blake3_hash(b"initial");
        t.update_ref("refs/heads/main", RefWriteCondition::Missing, &h)
            .unwrap();
        assert_eq!(t.read_ref("refs/heads/main").unwrap(), Some(h));
    }

    #[test]
    fn update_ref_missing_fails_when_present() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        let h = blake3_hash(b"initial");
        t.update_ref("refs/heads/main", RefWriteCondition::Missing, &h)
            .unwrap();
        let err = t
            .update_ref("refs/heads/main", RefWriteCondition::Missing, &h)
            .unwrap_err();
        assert!(matches!(err, TransportError::RefConflict));
    }

    #[test]
    fn update_ref_invalid_name_returns_error() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        let h = blake3_hash(b"h");
        let err = t.update_ref("", RefWriteCondition::Any, &h).unwrap_err();
        assert!(matches!(err, TransportError::InvalidRef(_)));
    }

    #[test]
    fn read_ref_invalid_name_returns_error() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        let err = t.read_ref("/bad").unwrap_err();
        assert!(matches!(err, TransportError::InvalidRef(_)));
    }

    // ------------------------------------------------------------------
    // list_refs tests (8 tests)
    // ------------------------------------------------------------------

    #[test]
    fn list_refs_returns_suffix_only() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        t.write_ref("refs/heads/main", &blake3_hash(b"c1")).unwrap();
        t.write_ref("refs/heads/develop", &blake3_hash(b"c2"))
            .unwrap();
        t.write_ref("refs/tags/v1.0", &blake3_hash(b"c3")).unwrap();

        let heads = t.list_refs("refs/heads").unwrap();
        assert_eq!(heads.len(), 2);
        let names: Vec<&str> = heads.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, ["develop", "main"]);
    }

    #[test]
    fn list_refs_all_with_empty_prefix() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        t.write_ref("refs/heads/main", &blake3_hash(b"m")).unwrap();
        t.write_ref("refs/tags/v1", &blake3_hash(b"t")).unwrap();
        let all = t.list_refs("").unwrap();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn list_refs_returns_empty_when_dir_missing() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        let refs = t.list_refs("refs/heads").unwrap();
        assert!(refs.is_empty());
    }

    #[test]
    fn list_refs_sorted_alphabetically() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        let h = blake3_hash(b"h");
        t.write_ref("refs/heads/zebra", &h).unwrap();
        t.write_ref("refs/heads/alpha", &h).unwrap();
        t.write_ref("refs/heads/middle", &h).unwrap();
        let refs = t.list_refs("refs/heads").unwrap();
        assert_eq!(refs.len(), 3);
        assert_eq!(refs[0].name, "alpha");
        assert_eq!(refs[1].name, "middle");
        assert_eq!(refs[2].name, "zebra");
    }

    #[test]
    fn list_refs_invalid_prefix_returns_error() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        let err = t.list_refs("/").unwrap_err();
        assert!(matches!(err, TransportError::InvalidRef(_)));
    }

    #[test]
    fn list_refs_with_trailing_slash_prefix() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        t.write_ref("refs/heads/main", &blake3_hash(b"m")).unwrap();
        let refs = t.list_refs("refs/heads/").unwrap();
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].name, "main");
    }

    #[test]
    fn list_refs_does_not_include_pack_dir() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        // Upload a pack (creates packs/ directory).
        let data = b"some pack";
        let key = pack_key_for(data);
        t.upload_pack(data, &key).unwrap();
        // list_refs("") should not return the pack hex file as a ref.
        t.write_ref("refs/heads/main", &blake3_hash(b"m")).unwrap();
        let all = t.list_refs("").unwrap();
        // Should only include refs/heads/main, not the pack key.
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].name, "refs/heads/main");
    }

    #[test]
    fn list_refs_no_tmp_files_leaked() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        t.write_ref("refs/heads/main", &blake3_hash(b"m")).unwrap();
        // Overwrite a few times.
        for i in 0..5u8 {
            t.write_ref("refs/heads/main", &blake3_hash(&[i])).unwrap();
        }
        // No .tmp. files should remain.
        let count = fs::read_dir(dir.path().join("refs/heads"))
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .count();
        assert_eq!(count, 0);
    }

    // ------------------------------------------------------------------
    // Full-interface integration test
    // ------------------------------------------------------------------

    // ------------------------------------------------------------------
    // Concurrent write test (write_ref Any never exposes truncated file)
    // ------------------------------------------------------------------

    #[test]
    fn concurrent_any_writes_never_expose_empty_file() {
        use std::sync::Arc;
        use std::thread;

        let dir = tmp();
        let t = Arc::new(FileTransport::new(dir.path()));

        let h_old = blake3_hash(b"concurrent-old");
        let h_new = blake3_hash(b"concurrent-new");
        t.write_ref("refs/heads/main", &h_old).unwrap();

        let t2 = Arc::clone(&t);
        let writer = thread::spawn(move || {
            for _ in 0..50 {
                let _ = t2.write_ref("refs/heads/main", &h_new);
            }
        });

        // Meanwhile, read and assert the ref is always one of the two valid hashes.
        for _ in 0..50 {
            if let Ok(Some(v)) = t.read_ref("refs/heads/main") {
                assert!(v == h_old || v == h_new, "unexpected hash value");
            }
        }

        writer.join().expect("writer thread panicked");

        // Final state must be one of the two valid hashes.
        let final_h = t.read_ref("refs/heads/main").unwrap();
        assert!(
            final_h == Some(h_old) || final_h == Some(h_new),
            "unexpected final state"
        );
    }

    // ------------------------------------------------------------------
    // Missing-race: two threads competing for Missing → only one wins
    // ------------------------------------------------------------------

    #[test]
    fn concurrent_missing_only_one_writer_wins() {
        use std::sync::Arc;
        use std::thread;

        let dir = tmp();
        let t = Arc::new(FileTransport::new(dir.path()));
        let h = blake3_hash(b"race-missing");

        let results: Vec<_> = (0..4)
            .map(|_| {
                let t2 = Arc::clone(&t);
                let h2 = h;
                thread::spawn(move || {
                    t2.update_ref("refs/heads/race", RefWriteCondition::Missing, &h2)
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|jh| jh.join().expect("thread panicked"))
            .collect();

        let successes = results.iter().filter(|r| r.is_ok()).count();
        let conflicts = results
            .iter()
            .filter(|r| matches!(r, Err(TransportError::RefConflict)))
            .count();
        assert_eq!(successes, 1, "exactly one Missing writer should succeed");
        assert_eq!(conflicts, 3, "the other three should get RefConflict");
    }

    // ------------------------------------------------------------------
    // E7: path-escape guard — symlink inside refs/ cannot escape root
    // ------------------------------------------------------------------

    /// A pre-existing symlink in `<root>/refs/...` that points outside
    /// `<root>/` MUST NOT allow read/write to escape the transport root.
    /// The transport must refuse the operation with a `RemoteError`
    /// mentioning the path-escape guard.
    #[cfg(unix)]
    #[test]
    fn read_ref_rejects_symlink_escaping_root() {
        use std::os::unix::fs::symlink;

        let dir = tmp();
        let outside = tmp();
        let outside_file = outside.path().join("secret");
        fs::write(&outside_file, b"outside content").unwrap();

        // Create refs/heads/, then a symlink evil -> outside_file.
        let refs_heads = dir.path().join("refs").join("heads");
        fs::create_dir_all(&refs_heads).unwrap();
        symlink(&outside_file, refs_heads.join("evil")).unwrap();

        let t = FileTransport::new(dir.path());
        let err = t
            .read_ref("refs/heads/evil")
            .expect_err("read_ref on path-escape symlink must return an error");
        match err {
            TransportError::RemoteError(msg) => {
                assert!(
                    msg.to_lowercase().contains("escape"),
                    "error should mention path escape: {msg}"
                );
            }
            other => panic!("expected RemoteError with path-escape, got {other:?}"),
        }
    }

    /// Regression: a root that lives under a symlinked parent and does
    /// NOT exist at construction time must NOT spuriously trip the
    /// path-escape guard. Previously `new()` cached
    /// `canonicalize(root).unwrap_or(root)`; when `root` was absent it
    /// stored the non-canonical literal path, so a later legitimate ref
    /// that canonicalised to the resolved `/private/...` form failed the
    /// `starts_with` prefix check and a valid write was rejected with a
    /// spurious "path escape" error. The guard now canonicalises the root
    /// lazily, so this round-trips cleanly.
    #[cfg(unix)]
    #[test]
    fn legit_write_under_symlinked_root_not_yet_existing_is_allowed() {
        use std::os::unix::fs::symlink;

        // `real` is the actual backing directory; `link` is a symlink that
        // points at it. We root the transport at `<link>/repo`, which does
        // NOT exist yet at construction time. Writing a ref under it must
        // succeed even though `<link>/repo` canonicalises to
        // `<real>/repo`.
        let real = tmp();
        let link_parent = tmp();
        let link = link_parent.path().join("link");
        symlink(real.path(), &link).unwrap();

        let root = link.join("repo");
        assert!(!root.exists(), "root must be absent at construction");

        let t = FileTransport::new(&root);
        let h = blake3_hash(b"legit-under-symlink");

        // This must NOT be rejected by the path-escape guard.
        t.write_ref("refs/heads/main", &h)
            .expect("legitimate write under a symlinked, not-yet-existing root must succeed");
        assert_eq!(t.read_ref("refs/heads/main").unwrap(), Some(h));

        // And the bytes really landed under the real backing directory.
        assert!(real.path().join("repo/refs/heads/main").exists());
    }

    // ------------------------------------------------------------------
    // Cross-process CAS race (file-lock guarantee)
    // ------------------------------------------------------------------

    /// Single-process round-trip: `Match` CAS succeeds for the right
    /// hash and fails (with the ref unchanged) for the wrong hash —
    /// exercised after the file-lock wiring is in place to confirm
    /// existing behaviour is preserved.
    #[test]
    fn match_cas_single_process_roundtrip_with_file_lock() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        let h0 = blake3_hash(b"genesis");
        let h1 = blake3_hash(b"first");
        let h2 = blake3_hash(b"second");

        t.write_ref("refs/heads/main", &h0).unwrap();

        // Wrong expected hash: ref unchanged, RefConflict.
        let err = t
            .update_ref("refs/heads/main", RefWriteCondition::Match(h1), &h2)
            .unwrap_err();
        assert!(matches!(err, TransportError::RefConflict));
        assert_eq!(t.read_ref("refs/heads/main").unwrap(), Some(h0));

        // Right expected hash: ref advances.
        t.update_ref("refs/heads/main", RefWriteCondition::Match(h0), &h1)
            .unwrap();
        assert_eq!(t.read_ref("refs/heads/main").unwrap(), Some(h1));

        // Lock sentinel file must exist after a Match CAS.
        assert!(
            dir.path().join(".mkit").join("refs").join(".lock").exists(),
            "RefLock sentinel file should be created on first Match CAS"
        );
    }

    #[test]
    fn every_write_condition_waits_for_the_file_cas_guard() {
        use std::sync::mpsc;
        use std::time::Duration;
        for condition in [RefWriteCondition::Any, RefWriteCondition::Missing] {
            let dir = tmp();
            let lock = RefLock::acquire(dir.path()).unwrap();
            let root = dir.path().to_path_buf();
            let (tx, rx) = mpsc::channel();
            let worker = std::thread::spawn(move || {
                let t = FileTransport::new(root);
                tx.send(t.update_ref("refs/heads/main", condition, &blake3_hash(b"next")))
                    .unwrap();
            });
            let premature = rx.recv_timeout(Duration::from_millis(100));
            let observed = FileTransport::new(dir.path())
                .read_ref("refs/heads/main")
                .unwrap();
            drop(lock);
            worker.join().unwrap();
            assert!(
                matches!(premature, Err(mpsc::RecvTimeoutError::Timeout)),
                "unconditional/create mutation bypassed a held CAS guard: {premature:?}"
            );
            assert_eq!(
                observed, None,
                "publication must wait for guard acquisition"
            );
            rx.recv_timeout(Duration::from_secs(2)).unwrap().unwrap();
        }
    }

    /// Cross-process race simulation.
    ///
    /// We simulate two processes by spawning two threads that each
    /// construct their own [`FileTransport`] over the **same on-disk
    /// root**. Each [`FileTransport`] owns its own `RefLock` handle
    /// (a fresh `File` opened at lock-acquire time). Because the OS
    /// `flock(2)` / `LockFileEx` mutual exclusion is enforced between
    /// distinct open file descriptions — not between threads — two
    /// threads holding two separate `File` handles to the same path
    /// reproduce the same exclusion semantics as two OS processes.
    ///
    /// This is the simplification called out in the task spec; a true
    /// `fork()` / `Command::spawn` test would add the same coverage at
    /// higher cost.
    #[test]
    fn cross_process_match_cas_only_one_winner() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering as AOrdering};
        use std::thread;

        let dir = tmp();
        // Two transports → two independent in-process Mutexes →
        // two independent file-lock acquisitions. This is the only way
        // to exercise the OS lock from inside a single test process.
        let t_a = Arc::new(FileTransport::new(dir.path()));
        let t_b = Arc::new(FileTransport::new(dir.path()));

        let h_old = blake3_hash(b"xproc-old");
        let h_a = blake3_hash(b"xproc-a-wins");
        let h_b = blake3_hash(b"xproc-b-wins");

        t_a.write_ref("refs/heads/main", &h_old).unwrap();

        // Run many rounds: each round, both writers race from the
        // same starting hash. After each round we reset to h_old.
        // Across rounds, the file lock must guarantee exactly one
        // success per round.
        let rounds = 50;
        let a_wins = Arc::new(AtomicUsize::new(0));
        let b_wins = Arc::new(AtomicUsize::new(0));

        for _ in 0..rounds {
            // Reset starting state.
            t_a.write_ref("refs/heads/main", &h_old).unwrap();

            let ta = Arc::clone(&t_a);
            let tb = Arc::clone(&t_b);
            let aw = Arc::clone(&a_wins);
            let bw = Arc::clone(&b_wins);

            let ja = thread::spawn(move || {
                ta.update_ref("refs/heads/main", RefWriteCondition::Match(h_old), &h_a)
            });
            let jb = thread::spawn(move || {
                tb.update_ref("refs/heads/main", RefWriteCondition::Match(h_old), &h_b)
            });

            let result_a = ja.join().expect("thread a panicked");
            let result_b = jb.join().expect("thread b panicked");

            let won_a = result_a.is_ok();
            let won_b = result_b.is_ok();

            // Exactly one must succeed and the other must observe
            // RefConflict — never RemoteError, never both-success.
            assert!(
                won_a ^ won_b,
                "exactly one writer must win; got a={result_a:?}, b={result_b:?}"
            );
            let loser = if won_a { &result_b } else { &result_a };
            assert!(
                matches!(loser, Err(TransportError::RefConflict)),
                "loser must report RefConflict, got {loser:?}"
            );

            if won_a {
                aw.fetch_add(1, AOrdering::Relaxed);
                assert_eq!(t_a.read_ref("refs/heads/main").unwrap(), Some(h_a));
            } else {
                bw.fetch_add(1, AOrdering::Relaxed);
                assert_eq!(t_a.read_ref("refs/heads/main").unwrap(), Some(h_b));
            }
        }

        // Sanity: across many rounds, both writers should have won at
        // least once. (Probabilistically; if this is flaky, scheduling
        // pinned everything to one thread — still correct, just
        // unfortunate. Loosen by reducing the floor to 0 if needed.)
        let aw = a_wins.load(AOrdering::Relaxed);
        let bw = b_wins.load(AOrdering::Relaxed);
        assert_eq!(aw + bw, rounds, "every round must have exactly one winner");
    }

    /// Stress: many threads on the same root contend for `Match` CAS
    /// in a CAS-loop until they have each advanced the ref once. With
    /// the file lock + process mutex in place, no `RemoteError` may
    /// surface and the ref must end at the last writer's hash with
    /// no torn state visible to readers.
    #[test]
    fn cross_process_match_cas_no_torn_state() {
        use std::sync::Arc;
        use std::thread;

        let dir = tmp();
        // 8 distinct transports → 8 distinct file-lock handles, as
        // close as we can get to 8 processes inside one test binary.
        let transports: Vec<Arc<FileTransport>> = (0..8)
            .map(|_| Arc::new(FileTransport::new(dir.path())))
            .collect();

        let initial = blake3_hash(b"contended-initial");
        transports[0]
            .write_ref("refs/heads/main", &initial)
            .unwrap();

        // Each thread advances the ref to its own hash by retrying
        // CAS until it wins from the latest observed value.
        let handles: Vec<_> = transports
            .iter()
            .enumerate()
            .map(|(i, t)| {
                let t = Arc::clone(t);
                thread::spawn(move || {
                    let target = blake3_hash(format!("writer-{i}").as_bytes());
                    loop {
                        let current = t.read_ref("refs/heads/main").expect("read must not error");
                        let Some(current) = current else {
                            panic!("ref must always be present mid-flight");
                        };
                        match t.update_ref(
                            "refs/heads/main",
                            RefWriteCondition::Match(current),
                            &target,
                        ) {
                            Ok(()) => return target,
                            Err(TransportError::RefConflict) => {}
                            Err(e) => panic!("unexpected transport error: {e:?}"),
                        }
                    }
                })
            })
            .collect();

        let final_hashes: Vec<_> = handles
            .into_iter()
            .map(|h| h.join().expect("writer thread panicked"))
            .collect();

        // The final on-disk hash must be one of the writers' targets
        // (the last to commit). Reads must always have decoded to a
        // valid hash — verified by the assertion inside the loop.
        let final_h = transports[0]
            .read_ref("refs/heads/main")
            .unwrap()
            .expect("final ref must exist");
        assert!(
            final_hashes.contains(&final_h),
            "final ref must equal one of the writers' targets: got {final_h:?}, writers={final_hashes:?}"
        );
    }

    // ------------------------------------------------------------------
    // Durability: parent-dir fsync is propagated, not swallowed (C1)
    // ------------------------------------------------------------------

    /// Regression for C1: the parent-directory fsync that makes a
    /// rename's / hard-link's dirent durable is now propagated via `?`
    /// instead of being discarded as best-effort. This exercises the
    /// now-propagating path end-to-end across all three write conditions
    /// (`Any` and the `Missing` create path go through `write_atomic` /
    /// `write_create_new`, both of which `sync_parent(parent)?`). A true
    /// power-loss / fsync-fault injection is impractical in a unit test;
    /// this asserts the synced write path still succeeds for every verb.
    #[test]
    fn synced_write_path_succeeds_for_all_conditions() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());

        // pack upload → write_atomic → sync_parent(parent)?
        let data = b"durable pack payload";
        let key = pack_key_for(data);
        t.upload_pack(data, &key)
            .expect("upload_pack must succeed through the propagated parent fsync");
        assert_eq!(t.download_pack(&key).unwrap(), data);

        // Missing → write_create_new → sync_parent(parent)? on the link arm
        let h0 = blake3_hash(b"durable-missing");
        t.update_ref("refs/heads/main", RefWriteCondition::Missing, &h0)
            .expect("update_ref(Missing) must succeed through the propagated parent fsync");
        assert_eq!(t.read_ref("refs/heads/main").unwrap(), Some(h0));

        // Any → write_atomic → sync_parent(parent)?
        let h1 = blake3_hash(b"durable-any");
        t.update_ref("refs/heads/main", RefWriteCondition::Any, &h1)
            .expect("update_ref(Any) must succeed through the propagated parent fsync");
        assert_eq!(t.read_ref("refs/heads/main").unwrap(), Some(h1));

        // Match → read-check-write → write_atomic → sync_parent(parent)?
        let h2 = blake3_hash(b"durable-match");
        t.update_ref("refs/heads/main", RefWriteCondition::Match(h1), &h2)
            .expect("update_ref(Match) must succeed through the propagated parent fsync");
        assert_eq!(t.read_ref("refs/heads/main").unwrap(), Some(h2));
    }

    /// `sync_parent` tolerates a vanished directory as success (mirrors
    /// `atomic::sync_parent_dir`): if the parent was removed concurrently
    /// there is nothing left to make durable, so a `NotFound` must not be
    /// surfaced as an error.
    #[test]
    fn sync_parent_tolerates_missing_dir() {
        let dir = tmp();
        let gone = dir.path().join("does-not-exist");
        sync_parent(&gone).expect("sync_parent must treat a missing dir as success");
    }

    /// Write side: a symlink that already exists inside `<root>/` but
    /// points outside it MUST NOT be followed by an unconditional write.
    #[cfg(unix)]
    #[test]
    fn write_ref_rejects_symlink_escaping_root() {
        use mkit_core::hash::hash as blake3_hash;
        use std::os::unix::fs::symlink;

        let dir = tmp();
        let outside = tmp();
        let outside_file = outside.path().join("target");
        fs::write(&outside_file, b"old").unwrap();

        let refs_heads = dir.path().join("refs").join("heads");
        fs::create_dir_all(&refs_heads).unwrap();
        symlink(&outside_file, refs_heads.join("evil")).unwrap();

        let t = FileTransport::new(dir.path());
        let h = blake3_hash(b"should-not-write");
        let err = t
            .update_ref("refs/heads/evil", RefWriteCondition::Any, &h)
            .expect_err("update_ref on path-escape symlink must return an error");
        assert!(matches!(err, TransportError::RemoteError(_)));

        // The outside file must NOT have been overwritten with the new
        // ref wire.
        let after = fs::read(&outside_file).unwrap();
        assert_eq!(after, b"old", "outside file was clobbered despite guard");
    }

    // ------------------------------------------------------------------
    // with_ref_lock / LockedRefs
    // ------------------------------------------------------------------

    #[test]
    fn with_ref_lock_holds_the_lock_file_and_writes_through_it() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        let h = blake3_hash(b"locked");
        let held = t
            .with_ref_lock(|refs| {
                refs.update_ref("refs/heads/a", RefWriteCondition::Missing, &h)
                    .unwrap();
                assert_eq!(refs.read_ref("refs/heads/a").unwrap(), Some(h));
                // Another open file description cannot take the lock.
                let lock = dir.path().join(".mkit").join("refs").join(".lock");
                let other = fs::File::open(lock).unwrap();
                other.try_lock().is_err()
            })
            .unwrap();
        assert!(held, "the ref lock is held inside with_ref_lock");
        assert_eq!(t.read_ref("refs/heads/a").unwrap(), Some(h));
    }

    #[test]
    fn with_ref_lock_recovers_after_a_panic() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            t.with_ref_lock(|_| panic!("panic under the ref lock"))
        }));
        assert!(panicked.is_err() && t.cas_lock.is_poisoned());
        let h = blake3_hash(b"after");
        t.update_ref("refs/heads/a", RefWriteCondition::Any, &h)
            .unwrap();
        assert_eq!(t.read_ref("refs/heads/a").unwrap(), Some(h));
    }

    #[test]
    fn ref_writes_refuse_a_root_marked_for_server_sqlite_meta() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        let h = blake3_hash(b"before");
        t.write_ref("refs/heads/main", &h).unwrap();
        fs::create_dir_all(dir.path().join(".mkit")).unwrap();
        fs::write(dir.path().join(SERVER_META_MARKER), b"marked").unwrap();

        // Every write path refuses, naming the marker; nothing changes.
        let err = t.write_ref("refs/heads/main", &blake3_hash(b"after"));
        match err {
            Err(TransportError::RemoteError(msg)) => {
                assert!(
                    msg.contains("SQLite") && msg.contains("server-meta"),
                    "{msg}"
                );
            }
            other => panic!("{other:?}"),
        }
        let refused = t
            .with_ref_lock(|refs| {
                let update = refs.update_ref("refs/heads/x", RefWriteCondition::Missing, &h);
                let delete = refs.delete_ref("refs/heads/main");
                let file = refs.write_file(Path::new(".mkit/server/rows/a"), b"x");
                let remove = refs.remove_file(Path::new(".mkit/server/rows/a"));
                [update.err(), delete.err(), file.err(), remove.err()]
            })
            .unwrap();
        for err in refused {
            assert!(
                matches!(err, Some(RefFileError::MetaElsewhere(_))),
                "{err:?}"
            );
        }
        // Reads still work.
        assert_eq!(t.read_ref("refs/heads/main").unwrap(), Some(h));
        assert_eq!(t.list_refs("").unwrap().len(), 1);
        // Packs are shared with the server and still upload.
        let key = PackKey(blake3_hash(b"pack"));
        t.upload_pack(b"pack", &key).unwrap();
    }

    #[test]
    fn delete_ref_removes_the_file_once_and_prunes_empty_dirs() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        let h = blake3_hash(b"gone");
        t.update_ref("refs/heads/team/a", RefWriteCondition::Any, &h)
            .unwrap();
        t.update_ref("refs/tags/v1", RefWriteCondition::Any, &h)
            .unwrap();
        let removed = t
            .with_ref_lock(|refs| {
                (
                    refs.delete_ref("refs/heads/team/a").unwrap(),
                    refs.delete_ref("refs/heads/team/a").unwrap(),
                )
            })
            .unwrap();
        assert_eq!(removed, (true, false));
        assert_eq!(t.read_ref("refs/heads/team/a").unwrap(), None);
        // The emptied `refs/heads/team` and `refs/heads` are gone; `refs`
        // and the non-empty `refs/tags` stay.
        assert!(!dir.path().join("refs/heads").exists());
        assert!(dir.path().join("refs/tags/v1").is_file());
        // So the name is free for a ref file again.
        t.update_ref("refs/heads/team", RefWriteCondition::Missing, &h)
            .unwrap();
        let invalid = t.with_ref_lock(|refs| refs.delete_ref("../x")).unwrap();
        assert!(matches!(invalid, Err(RefFileError::InvalidName(_))));
        // A directory where the ref file would be is no ref.
        let dir_ref = t.with_ref_lock(|refs| refs.delete_ref("refs")).unwrap();
        assert!(!dir_ref.unwrap());
    }

    #[test]
    fn ref_directory_file_clashes_are_invalid_names() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        let h = blake3_hash(b"clash");
        t.update_ref("refs/heads/a/b", RefWriteCondition::Any, &h)
            .unwrap();
        t.update_ref("refs/heads/c", RefWriteCondition::Any, &h)
            .unwrap();
        for name in ["refs/heads/a", "refs/heads/c/d"] {
            for condition in [RefWriteCondition::Any, RefWriteCondition::Missing] {
                let err = t.update_ref(name, condition, &h).unwrap_err();
                assert!(
                    matches!(err, TransportError::InvalidRef(_)),
                    "{name}: {err:?}"
                );
            }
        }
        assert_eq!(t.read_ref_strict("refs/heads/a").unwrap(), None);
        assert_eq!(t.read_ref_strict("refs/heads/c").unwrap(), Some(h));
    }

    #[test]
    fn strict_reads_report_corrupt_ref_files() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        let h = blake3_hash(b"ok");
        t.update_ref("refs/heads/ok", RefWriteCondition::Any, &h)
            .unwrap();
        fs::write(dir.path().join("refs/heads/bad"), b"not a ref\n").unwrap();
        // The lenient verbs treat it as absent and skip it...
        assert_eq!(t.read_ref("refs/heads/bad").unwrap(), None);
        assert_eq!(t.list_refs("refs/").unwrap().len(), 1);
        // ...the strict ones report it.
        assert!(matches!(
            t.read_ref_strict("refs/heads/bad"),
            Err(RefFileError::Corrupt(_))
        ));
        assert_eq!(
            t.list_ref_files("refs/").unwrap(),
            vec![
                ("refs/heads/bad".to_owned(), None),
                ("refs/heads/ok".to_owned(), Some(h)),
            ]
        );
        fs::remove_file(dir.path().join("refs/heads/bad")).unwrap();
        // Temp and lock files are not refs.
        fs::write(dir.path().join("refs/heads/.ok.tmp.1.2"), b"junk").unwrap();
        assert_eq!(
            t.list_ref_files("refs").unwrap(),
            vec![("refs/heads/ok".to_owned(), Some(h))]
        );
        assert_eq!(t.list_ref_files("refs/tags/").unwrap(), vec![]);
        assert!(t.list_ref_files("").is_err());
    }

    #[test]
    fn locked_file_writes_stay_under_the_server_dir() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        let rel = Path::new(".mkit/server/row");
        t.with_ref_lock(|refs| {
            refs.write_file(rel, b"v1").unwrap();
            refs.write_file(rel, b"v2").unwrap();
            for bad in [
                "",
                "/abs",
                "../up",
                "a/../b",
                "./a",
                ".mkit/server",
                ".mkit/server/../refs/.lock",
                ".mkit/refs/.lock",
                "refs/x",
                "packs/x",
            ] {
                let write = refs.write_file(Path::new(bad), b"x");
                assert!(matches!(write, Err(RefFileError::Escape(_))), "{bad}");
                let remove = refs.remove_file(Path::new(bad));
                assert!(matches!(remove, Err(RefFileError::Escape(_))), "{bad}");
            }
        })
        .unwrap();
        assert_eq!(fs::read(dir.path().join(rel)).unwrap(), b"v2");
        assert!(!dir.path().join("refs/x").exists() && !dir.path().join("packs").exists());
        let removed = t
            .with_ref_lock(|refs| {
                (
                    refs.remove_file(rel).unwrap(),
                    refs.remove_file(rel).unwrap(),
                )
            })
            .unwrap();
        assert_eq!(removed, (true, false));
    }

    #[cfg(unix)]
    #[test]
    fn locked_file_writes_reject_a_symlinked_server_dir() {
        use std::os::unix::fs::symlink;

        let dir = tmp();
        let outside = tmp();
        fs::create_dir_all(dir.path().join(".mkit")).unwrap();
        symlink(outside.path(), dir.path().join(".mkit/server")).unwrap();
        let t = FileTransport::new(dir.path());
        let result = t
            .with_ref_lock(|refs| refs.write_file(Path::new(".mkit/server/row"), b"x"))
            .unwrap();
        assert!(matches!(result, Err(RefFileError::Escape(_))));
        assert!(!outside.path().join("row").exists());
        // A symlink to a directory inside the root is refused too.
        fs::remove_file(dir.path().join(".mkit/server")).unwrap();
        fs::create_dir_all(dir.path().join("refs")).unwrap();
        symlink(dir.path().join("refs"), dir.path().join(".mkit/server")).unwrap();
        assert!(matches!(
            t.server_path(Path::new(".mkit/server/row")),
            Err(RefFileError::Escape(_))
        ));
    }

    #[test]
    fn create_dir_all_durably_creates_nested_dirs() {
        let dir = tmp();
        let nested = dir.path().join("a/b/c");
        create_dir_all_durably(&nested).unwrap();
        assert!(nested.is_dir());
        create_dir_all_durably(&nested).unwrap();
        fs::write(dir.path().join("file"), b"x").unwrap();
        assert!(create_dir_all_durably(&dir.path().join("file/sub")).is_err());
    }

    #[test]
    fn temp_paths_are_unique_hidden_siblings() {
        let dest = Path::new("/r/packs/abc");
        let (a, b) = (temp_path(dest).unwrap(), temp_path(dest).unwrap());
        assert_ne!(a, b);
        assert_eq!(a.parent(), dest.parent());
        let name = a.file_name().unwrap().to_string_lossy().into_owned();
        assert!(name.starts_with(".abc.tmp."), "{name}");
        assert!(temp_path(Path::new("/")).is_err());
    }
}
