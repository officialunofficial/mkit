//! POSIX primitives shared by the scoped-workspace modules.
//!
//! Every scoped-workspace lookup is descriptor-anchored (`openat`/`mkdirat`
//! against an `O_NOFOLLOW` directory descriptor) so no ancestor component can
//! be swapped out from under an in-progress create, open, or transition.
//! Linux and macOS only.

use std::ffi::CString;
use std::io;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::path::Path;

/// Errors from the descriptor-anchored primitives. `AlreadyExists` and
/// `Unsupported` are lifted out of [`io::Error`] so callers can map them to
/// the typed scoped-state errors without scraping raw errno values.
#[derive(Debug)]
pub(crate) enum SysError {
    Io(io::Error),
    AlreadyExists,
    Unsupported,
}

impl From<io::Error> for SysError {
    fn from(error: io::Error) -> Self {
        match error.raw_os_error() {
            Some(code) if code == libc::EEXIST => Self::AlreadyExists,
            Some(code)
                if code == libc::ENOSYS
                    || code == libc::ENOTSUP
                    || error.kind() == io::ErrorKind::Unsupported =>
            {
                Self::Unsupported
            }
            _ => Self::Io(error),
        }
    }
}

impl SysError {
    pub(crate) fn is_not_found(&self) -> bool {
        matches!(self, Self::Io(e) if e.kind() == io::ErrorKind::NotFound)
    }

    /// `ELOOP` (and friends) means a no-follow open met a symlink — an
    /// unsafe filesystem entry, not plain I/O.
    pub(crate) fn is_symlink(&self) -> bool {
        matches!(self, Self::Io(e) if e.raw_os_error() == Some(libc::ELOOP))
    }

    /// `ENOTDIR`: a component opened as a directory is a different entry
    /// type. Note `open_dir` maps symlink components to `ELOOP` first, so
    /// this is only reachable for genuinely non-directory entries.
    pub(crate) fn is_not_dir(&self) -> bool {
        matches!(self, Self::Io(e) if e.raw_os_error() == Some(libc::ENOTDIR))
    }
}

fn c_name(name: &[u8]) -> Result<CString, SysError> {
    CString::new(name).map_err(|_| {
        SysError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "filesystem name contains NUL",
        ))
    })
}

fn c_path(path: &Path) -> Result<CString, SysError> {
    use std::os::unix::ffi::OsStrExt;
    c_name(path.as_os_str().as_bytes())
}

const DIR_FLAGS: i32 = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;

/// How [`open_file`] opens a leaf beneath a directory descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OpenMode {
    /// `O_RDONLY` — fails on symlinks.
    Read,
    /// `O_RDWR` — fails on symlinks.
    ReadWrite,
    /// `O_WRONLY | O_CREAT | O_EXCL` — create-new; `EEXIST` propagates.
    CreateExclusive,
}

impl OpenMode {
    fn flags(self) -> i32 {
        // O_NONBLOCK on read opens: a FIFO/device substituted for a state
        // file cannot stall the open before descriptor metadata rejects
        // it. Harmless on regular files.
        match self {
            Self::Read => libc::O_RDONLY | libc::O_NONBLOCK,
            Self::ReadWrite => libc::O_RDWR | libc::O_NONBLOCK,
            Self::CreateExclusive => libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        }
    }
}

/// An owned `std::fs::File` opened through a scoped directory descriptor
/// with `O_NOFOLLOW`.
#[derive(Debug)]
pub(crate) struct File(std::fs::File);

impl File {
    fn from_fd(fd: RawFd) -> Self {
        // SAFETY: `fd` is a fresh descriptor we own outright.
        #[allow(unsafe_code)]
        Self(unsafe { std::fs::File::from_raw_fd(fd) })
    }

    pub(crate) fn metadata(&self) -> Result<std::fs::Metadata, SysError> {
        Ok(self.0.metadata()?)
    }

    /// Read the whole file, bounded: more than `cap` bytes is an error so
    /// a hostile file cannot balloon allocation.
    pub(crate) fn read_all(&self, cap: usize) -> Result<Vec<u8>, SysError> {
        use std::io::Read;
        let mut buf = Vec::new();
        let mut take = (&self.0).take(cap as u64 + 1);
        take.read_to_end(&mut buf)?;
        if buf.len() > cap {
            return Err(SysError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "file exceeds bounded size",
            )));
        }
        Ok(buf)
    }

    /// Read up to `buf.len()` bytes at the current offset — callers loop
    /// so one short read cannot underfill a requested prefix.
    pub(crate) fn read(&self, buf: &mut [u8]) -> Result<usize, SysError> {
        use std::io::Read;
        Ok((&self.0).read(buf)?)
    }

    pub(crate) fn write_all(&self, bytes: &[u8]) -> Result<(), SysError> {
        use std::io::Write;
        (&self.0).write_all(bytes)?;
        Ok(())
    }

    /// `fchmod(2)` to an exact mode, ignoring umask.
    pub(crate) fn fchmod(&self, mode: u32) -> Result<(), SysError> {
        let mode = libc::mode_t::try_from(mode).map_err(|_| {
            SysError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "mode out of range",
            ))
        })?;
        // SAFETY: `fchmod(2)` on a valid borrowed fd; touches no memory.
        #[allow(unsafe_code)]
        let rc = unsafe { libc::fchmod(self.0.as_raw_fd(), mode) };
        if rc < 0 {
            return Err(io::Error::last_os_error().into());
        }
        Ok(())
    }

    pub(crate) fn fsync(&self) -> Result<(), SysError> {
        Ok(self.0.sync_all()?)
    }

    /// Exclusive `flock(2)` — the scoped `workspace.lock` domain, never
    /// composed with the ordinary repository lock order. The lock is
    /// released by closing this descriptor, including under panic unwind;
    /// there is deliberately no `unlock` — an explicit release on a
    /// shared descriptor could free the lock while another operation is
    /// still inside the critical section.
    pub(crate) fn lock_exclusive(&self) -> Result<(), SysError> {
        // SAFETY: `flock(2)` on a valid borrowed fd; advisory lock on this
        // descriptor only.
        #[allow(unsafe_code)]
        let rc = unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_EX) };
        if rc < 0 {
            return Err(io::Error::last_os_error().into());
        }
        Ok(())
    }

    /// Test-only nonblocking acquisition probe on THIS descriptor:
    /// `Ok(true)` acquired, `Ok(false)` would block (`EWOULDBLOCK`) —
    /// proof a foreign open-file description holds the lock. A
    /// `true` result on an operation's own descriptor while another
    /// operation believes it holds the lock exposes the shared
    /// open-file-description defect: a redundant `LOCK_EX` on an
    /// already-locked description is a no-op success, so it must never
    /// be unlocked from the probe side.
    #[cfg(test)]
    pub(crate) fn try_lock_exclusive(&self) -> Result<bool, SysError> {
        // SAFETY: `flock(2)` on a valid borrowed fd; LOCK_NB avoids
        // blocking. Success acquires the lock (or confirms ownership on
        // this open-file description); descriptor close releases it.
        #[allow(unsafe_code)]
        let rc = unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc == 0 {
            return Ok(true);
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EWOULDBLOCK) {
            return Ok(false);
        }
        Err(error.into())
    }
}

/// An open `O_RDONLY | O_DIRECTORY | O_NOFOLLOW` directory descriptor.
#[derive(Debug)]
pub(crate) struct DirFd(std::fs::File);

impl DirFd {
    fn from_fd(fd: RawFd) -> Self {
        // SAFETY: `fd` is a fresh descriptor we own outright.
        #[allow(unsafe_code)]
        Self(unsafe { std::fs::File::from_raw_fd(fd) })
    }

    pub(crate) fn try_clone(&self) -> Result<Self, SysError> {
        Ok(Self(self.0.try_clone()?))
    }

    pub(crate) fn metadata(&self) -> Result<std::fs::Metadata, SysError> {
        Ok(self.0.metadata()?)
    }

    pub(crate) fn fsync(&self) -> Result<(), SysError> {
        Ok(self.0.sync_all()?)
    }

    pub(crate) fn raw(&self) -> RawFd {
        self.0.as_raw_fd()
    }

    /// Iterate entries as `(raw name, is_dir)` pairs. Re-opened on every
    /// call; used only on the scratch-cleanup path, never for state reads.
    pub(crate) fn read_dir(&self) -> Result<ReadDir, SysError> {
        // SAFETY: `fdopendir` duplicates our directory descriptor into a
        // DIR* we then own; `dirfd` borrows it only for the dup.
        #[allow(unsafe_code)]
        let dup = unsafe { libc::fcntl(self.raw(), libc::F_DUPFD_CLOEXEC, 0) };
        if dup < 0 {
            return Err(io::Error::last_os_error().into());
        }
        // SAFETY: `dup` is a fresh descriptor we own.
        #[allow(unsafe_code)]
        let dir = unsafe { libc::fdopendir(dup) };
        if dir.is_null() {
            // SAFETY: `dup` is still ours to close on this error path.
            #[allow(unsafe_code)]
            unsafe {
                libc::close(dup)
            };
            return Err(io::Error::last_os_error().into());
        }
        Ok(ReadDir(dir))
    }

    /// `unlinkat(2)` a non-directory child of this directory.
    pub(crate) fn unlink(&self, name: &[u8]) -> Result<(), SysError> {
        let c = c_name(name)?;
        // SAFETY: `unlinkat(2)` against our own directory fd.
        #[allow(unsafe_code)]
        let rc = unsafe { libc::unlinkat(self.raw(), c.as_ptr(), 0) };
        if rc < 0 {
            return Err(io::Error::last_os_error().into());
        }
        Ok(())
    }

    /// `unlinkat(2, AT_REMOVEDIR)` a directory child.
    pub(crate) fn rmdir(&self, name: &[u8]) -> Result<(), SysError> {
        let c = c_name(name)?;
        // SAFETY: `unlinkat(2)` against our own directory fd.
        #[allow(unsafe_code)]
        let rc = unsafe { libc::unlinkat(self.raw(), c.as_ptr(), libc::AT_REMOVEDIR) };
        if rc < 0 {
            return Err(io::Error::last_os_error().into());
        }
        Ok(())
    }
}

/// Directory-entry iterator over a [`DirFd`]; yields `(raw name, is_dir)`.
pub(crate) struct ReadDir(*mut libc::DIR);

/// Address of the thread-local `errno` — `__error` on macOS,
/// `__errno_location` on Linux.
#[cfg(target_os = "macos")]
fn errno_location() -> *mut libc::c_int {
    // SAFETY: `__error` always returns a valid per-thread pointer.
    #[allow(unsafe_code)]
    unsafe {
        libc::__error()
    }
}

/// Address of the thread-local `errno`.
#[cfg(not(target_os = "macos"))]
fn errno_location() -> *mut libc::c_int {
    // SAFETY: `__errno_location` always returns a valid per-thread pointer.
    #[allow(unsafe_code)]
    unsafe {
        libc::__errno_location()
    }
}

impl ReadDir {
    /// Next entry: `Ok(Some((name, is_dir)))`, `Ok(None)` at end.
    #[allow(clippy::should_implement_trait)]
    pub(crate) fn next_entry(&mut self) -> Result<Option<(Vec<u8>, bool)>, SysError> {
        // SAFETY: `self.0` is a live DIR* from fdopendir; readdir returns a
        // pointer owned by the DIR* valid until the next call; errno is
        // cleared and read via the per-thread pointer.
        #[allow(unsafe_code)]
        unsafe {
            *errno_location() = 0;
            let entry = libc::readdir(self.0);
            if entry.is_null() {
                let errno = *errno_location();
                if errno != 0 {
                    return Err(io::Error::from_raw_os_error(errno).into());
                }
                return Ok(None);
            }
            let name = std::ffi::CStr::from_ptr((*entry).d_name.as_ptr())
                .to_bytes()
                .to_vec();
            let is_dir = (*entry).d_type == libc::DT_DIR;
            Ok(Some((name, is_dir)))
        }
    }
}

impl Iterator for ReadDir {
    type Item = Result<(Vec<u8>, bool), SysError>;
    fn next(&mut self) -> Option<Self::Item> {
        self.next_entry().transpose()
    }
}

impl Drop for ReadDir {
    fn drop(&mut self) {
        // SAFETY: `self.0` is a live DIR* we own; closed exactly once.
        #[allow(unsafe_code)]
        unsafe {
            libc::closedir(self.0)
        };
    }
}

/// Open an absolute or relative `path` as a directory descriptor.
/// Interior symlink components resolve normally (the path may name a
/// directory through an alias); `O_NOFOLLOW` still refuses a symlink at
/// the LEAF — macOS reports that refusal as `ENOTDIR` rather than
/// `ELOOP`, so a leaf that `lstat` proves is a symlink is normalized to
/// `ELOOP` the same way [`open_dir`] does. A genuine non-directory
/// component keeps its `ENOTDIR`.
pub(crate) fn open_dir_path(path: &Path) -> Result<DirFd, SysError> {
    let c = c_path(path)?;
    // SAFETY: `open(2)` on a CString we built; returns a fresh fd or -1.
    #[allow(unsafe_code)]
    let fd = unsafe { libc::open(c.as_ptr(), DIR_FLAGS) };
    if fd < 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOTDIR) {
            // SAFETY: `lstat(2)` on a CString we built; inspects the leaf
            // itself without following it.
            #[allow(unsafe_code)]
            let is_link = unsafe {
                let mut stat: libc::stat = std::mem::zeroed();
                libc::lstat(c.as_ptr(), &raw mut stat) == 0
                    && (stat.st_mode & libc::S_IFMT) == libc::S_IFLNK
            };
            if is_link {
                return Err(io::Error::from_raw_os_error(libc::ELOOP).into());
            }
        }
        return Err(error.into());
    }
    Ok(DirFd::from_fd(fd))
}

/// Open `name` beneath `dir` as a no-follow directory descriptor.
pub(crate) fn open_dir(dir: &DirFd, name: &[u8]) -> Result<DirFd, SysError> {
    let c = c_name(name)?;
    // SAFETY: `openat(2)` against our own directory fd; fresh fd or -1.
    #[allow(unsafe_code)]
    let fd = unsafe { libc::openat(dir.raw(), c.as_ptr(), DIR_FLAGS) };
    if fd < 0 {
        let error = io::Error::last_os_error();
        // macOS reports a symlinked directory under
        // O_DIRECTORY|O_NOFOLLOW as ENOTDIR rather than Linux's ELOOP —
        // normalize so callers classify the refusal as a symlink on
        // both platforms.
        if error.raw_os_error() == Some(libc::ENOTDIR) {
            // SAFETY: `fstatat(2)` on a CString we built;
            // AT_SYMLINK_NOFOLLOW inspects the link itself.
            #[allow(unsafe_code)]
            let is_link = unsafe {
                let mut stat: libc::stat = std::mem::zeroed();
                libc::fstatat(
                    dir.raw(),
                    c.as_ptr(),
                    &raw mut stat,
                    libc::AT_SYMLINK_NOFOLLOW,
                ) == 0
                    && (stat.st_mode & libc::S_IFMT) == libc::S_IFLNK
            };
            if is_link {
                return Err(io::Error::from_raw_os_error(libc::ELOOP).into());
            }
        }
        return Err(error.into());
    }
    Ok(DirFd::from_fd(fd))
}

/// `mkdirat(2)` beneath `dir`; `EEXIST` propagates as
/// [`SysError::AlreadyExists`].
pub(crate) fn mkdir(dir: &DirFd, name: &[u8], mode: u32) -> Result<(), SysError> {
    let c = c_name(name)?;
    let mode = libc::mode_t::try_from(mode).map_err(|_| {
        SysError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "mode out of range",
        ))
    })?;
    // SAFETY: `mkdirat(2)` against our own directory fd; creates or fails.
    #[allow(unsafe_code)]
    let rc = unsafe { libc::mkdirat(dir.raw(), c.as_ptr(), mode) };
    if rc < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

/// Open `name` beneath `dir` per `mode`, always with
/// `O_NOFOLLOW | O_CLOEXEC` so a symlink leaf is refused.
pub(crate) fn open_file(dir: &DirFd, name: &[u8], mode: OpenMode) -> Result<File, SysError> {
    let c = c_name(name)?;
    let create_mode: libc::mode_t = match mode {
        OpenMode::CreateExclusive => 0o600,
        _ => 0,
    };
    // SAFETY: `openat(2)` against our own directory fd; fresh fd or -1.
    #[allow(unsafe_code)]
    let fd = unsafe {
        libc::openat(
            dir.raw(),
            c.as_ptr(),
            mode.flags() | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            libc::c_uint::from(create_mode),
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(File::from_fd(fd))
}

/// Atomic `renameat(2)` replace of `old` to `new` inside `dir` — the
/// linearization point that publishes a new `CURRENT`.
pub(crate) fn rename_replace(dir: &DirFd, old: &[u8], new: &[u8]) -> Result<(), SysError> {
    let old = c_name(old)?;
    let new = c_name(new)?;
    // SAFETY: `renameat(2)` between our own directory fd; atomically
    // replaces `new` when present.
    #[allow(unsafe_code)]
    let rc = unsafe { libc::renameat(dir.raw(), old.as_ptr(), dir.raw(), new.as_ptr()) };
    if rc < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

/// Install `old` beneath `old_dir` at `new` beneath `new_dir` as one
/// atomic NO-REPLACE rename: Linux `renameat2(RENAME_NOREPLACE)`, macOS
/// `renameatx_np(RENAME_EXCL)`. `EEXIST` maps to
/// [`SysError::AlreadyExists`]; a missing primitive maps to
/// [`SysError::Unsupported`] — never a fallback to exists-check +
/// overwrite rename.
#[cfg(target_os = "linux")]
pub(crate) fn rename_no_replace(
    old_dir: &DirFd,
    old: &[u8],
    new_dir: &DirFd,
    new: &[u8],
) -> Result<(), SysError> {
    let old = c_name(old)?;
    let new = c_name(new)?;
    // SAFETY: `renameat2(2)` on CStrings we built; RENAME_NOREPLACE makes
    // the kernel fail EEXIST rather than replace a live destination.
    #[allow(unsafe_code)]
    let rc = unsafe {
        libc::renameat2(
            old_dir.raw(),
            old.as_ptr(),
            new_dir.raw(),
            new.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if rc < 0 {
        let error = io::Error::last_os_error();
        // Some kernels/filesystems report unsupported renameat2 flags as
        // EINVAL; that is "primitive unavailable", not a generic I/O
        // error — callers must never fall back to a replacing rename.
        if error.raw_os_error() == Some(libc::EINVAL) {
            return Err(SysError::Unsupported);
        }
        return Err(error.into());
    }
    Ok(())
}

/// macOS no-replace install via `renameatx_np(RENAME_EXCL)` — the
/// descriptor-relative form of `renamex_np`.
#[cfg(target_os = "macos")]
pub(crate) fn rename_no_replace(
    old_dir: &DirFd,
    old: &[u8],
    new_dir: &DirFd,
    new: &[u8],
) -> Result<(), SysError> {
    let old = c_name(old)?;
    let new = c_name(new)?;
    // SAFETY: `renameatx_np(2)` on CStrings we built; RENAME_EXCL fails
    // EEXIST rather than replacing a live destination.
    #[allow(unsafe_code)]
    let rc = unsafe {
        libc::renameatx_np(
            old_dir.raw(),
            old.as_ptr(),
            new_dir.raw(),
            new.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn rename_no_replace(
    _old_dir: &DirFd,
    _old: &[u8],
    _new_dir: &DirFd,
    _new: &[u8],
) -> Result<(), SysError> {
    Err(SysError::Unsupported)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The install primitive is a real no-replace rename: an existing
    /// destination is never overwritten and the scratch source survives
    /// the refusal.
    #[test]
    fn rename_no_replace_never_overwrites_destination() {
        let dir = tempfile::tempdir().unwrap();
        let fd = open_dir_path(dir.path()).unwrap();
        mkdir(&fd, b"scratch", 0o700).unwrap();
        let scratch = open_dir(&fd, b"scratch").unwrap();
        open_file(&scratch, b"payload", OpenMode::CreateExclusive)
            .unwrap()
            .write_all(b"new")
            .unwrap();
        mkdir(&fd, b"dest", 0o700).unwrap();
        let dest = open_dir(&fd, b"dest").unwrap();
        open_file(&dest, b"keep", OpenMode::CreateExclusive)
            .unwrap()
            .write_all(b"old")
            .unwrap();
        match rename_no_replace(&fd, b"scratch", &fd, b"dest") {
            Err(SysError::AlreadyExists) => {}
            Err(SysError::Unsupported) => return, // platform lacks the primitive
            other => panic!("no-replace install must refuse: {other:?}"),
        }
        // Destination contents were not overwritten.
        let keep = open_file(&dest, b"keep", OpenMode::Read).unwrap();
        assert_eq!(keep.read_all(16).unwrap(), b"old");
        assert!(open_file(&dest, b"payload", OpenMode::Read).is_err());
        // The scratch directory still exists.
        open_dir(&fd, b"scratch").unwrap();
    }
}
