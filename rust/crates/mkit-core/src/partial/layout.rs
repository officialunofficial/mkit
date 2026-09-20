//! Scoped-workspace root layout: `create`/`open` plus the
//! descriptor-anchored filesystem access every state transition shares.
//!
//! A scoped workspace is a directory whose `.mkit` is a REGULAR FILE
//! carrying the exact marker bytes `mkit-scoped: 1\n` and whose
//! `.mkit-scoped/` subtree holds the durable local state
//! (SPEC-PARTIAL-WORKSPACES local-state section). It is NOT an ordinary
//! repository: `crate::layout::check_scoped_boundary` makes ordinary
//! discovery, store open/init, and CLI commands refuse it.
//!
//! All lookups under the root are descriptor-anchored (`openat` with
//! `O_NOFOLLOW`) so no ancestor or leaf can be swapped out from under an
//! in-progress create, open, or transition.

use std::collections::HashSet;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::hash::{self, Hash};
use crate::layout::{
    SCOPED_MARKER, SCOPED_MARKER_PREFIX, ScopedAuthority, classify_scoped_root,
    has_ordinary_authority,
};
use crate::object::EntryMode;
use crate::partial::state::{
    self, PartialStateError, ScopedWorkspaceState, StageEntryV1, StageStateV1, StatePlan,
    WorkspaceSelectionV1, WorkspaceStateV1, sys_err, unsafe_entry,
};
use crate::partial::sys::{self, DirFd, OpenMode, SysError};
use crate::partial::{
    PartialLimits, PartialPath, RemotePublicationTargetV1, VerifiedPartialSnapshot,
    verify_partial_snapshot,
};

/// Metadata directory name inside a scoped-workspace root.
pub(crate) const STATE_DIR: &str = ".mkit-scoped";
/// File and directory names fixed by code inside `.mkit-scoped` — never
/// decoded from on-disk names.
pub(crate) const LOCK_FILE: &str = "workspace.lock";
pub(crate) const CURRENT_FILE: &str = "CURRENT";
pub(crate) const GENERATIONS_DIR: &str = "generations";
pub(crate) const BUNDLES_DIR: &str = "bundles";
pub(crate) const OBJECTS_DIR: &str = "objects";
pub(crate) const UPDATES_DIR: &str = "updates";
pub(crate) const MANIFEST_FILE: &str = "manifest.bin";
pub(crate) const WORKSPACE_FILE: &str = "workspace.bin";
pub(crate) const STAGE_FILE: &str = "stage.bin";
pub(crate) const PENDING_FILE: &str = "pending.bin";
pub(crate) const ACCEPTED_FILE: &str = "accepted.bin";

/// The pending-update artifact name is canonically derived from its
/// digest — callers never name update files.
pub(crate) fn update_file_name(update_digest: &Hash) -> String {
    format!("{}.mkwu", hash::to_hex(update_digest))
}

/// The base-bundle artifact name, likewise digest-derived.
pub(crate) fn bundle_file_name(bundle_digest: &Hash) -> String {
    format!("{}.mkwb", hash::to_hex(bundle_digest))
}

static SCRATCH_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Deterministic fault-injection seam for the durability tests. Each
/// [`Fault`] names a point in the commit sequence; arming a seam makes the
/// next `hit` at that point fail once. One relaxed atomic load per seam on
/// the normal path; only tests ever arm it.
#[derive(Debug)]
pub(crate) struct Faults {
    armed: AtomicU64,
}

/// Commit-sequence seams at which a deterministic fault can be injected,
/// in real write order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub(crate) enum Fault {
    /// Before any immutable artifact bytes are written.
    BeforeData = 1,
    /// After artifacts, before generation member files are written.
    BeforeMembers = 2,
    /// After members, before the manifest is written.
    BeforeManifest = 3,
    /// After the manifest, before the new CURRENT is published.
    BeforeCurrentSwitch = 4,
    /// After CURRENT is replaced, before the state dir is fsynced.
    AfterCurrentSwitch = 5,
    /// After all fsyncs (transition otherwise succeeded).
    AfterSync = 6,
    /// Mid-write inside an immutable-file temporary: only a prefix is
    /// written before the abort — the canonical name is never touched.
    ImmutablePartialWrite = 7,
    /// Immutable temporary fully written, before its file fsync.
    ImmutableBeforeFileSync = 8,
    /// Immutable name installed by the no-replace rename, before the
    /// containing directory is fsynced.
    ImmutableBeforeDirSync = 9,
}

impl Faults {
    pub(crate) fn new() -> Self {
        Self {
            armed: AtomicU64::new(0),
        }
    }

    /// Arm `seam` so the next [`hit`](Self::hit) at it returns true once.
    #[cfg(test)]
    pub(crate) fn arm(&self, seam: Fault) {
        self.armed.store(seam as u64, Ordering::Relaxed);
    }

    /// True (once) when `seam` was armed; clears the arm.
    pub(crate) fn hit(&self, seam: Fault) -> bool {
        self.armed
            .compare_exchange(seam as u64, 0, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    }
}

/// A scoped workspace opened (or just installed) at `root`. The layout
/// owns the canonicalized root path, the `.mkit-scoped` directory
/// descriptor, and the recorded `workspace.lock` inode — every state read
/// and transition is descriptor-anchored through them, and every
/// transition opens a fresh inode-verified lock descriptor of its own.
#[derive(Debug)]
pub struct ScopedWorkspaceLayout {
    root: PathBuf,
    state_dir: DirFd,
    /// `(dev, ino)` of `workspace.lock` at open: a transition that sees a
    /// different inode under the lock path fails closed.
    lock_identity: (u64, u64),
    pub(crate) faults: Faults,
}

fn io_err(path: PathBuf, source: std::io::Error) -> PartialStateError {
    PartialStateError::Io { path, source }
}

/// `true` when `bytes` is a safe single working-file path component.
/// Bundle paths are already validated by [`verify_partial_snapshot`]; this
/// is defense in depth at materialization time.
fn safe_component(bytes: &[u8]) -> bool {
    !bytes.is_empty()
        && bytes != b"."
        && bytes != b".."
        && !bytes.contains(&b'/')
        && !bytes.contains(&0)
}

/// Open each component of an absolute canonicalized `path` with
/// `O_DIRECTORY | O_NOFOLLOW`, so every ancestor is verified a real
/// directory at open time rather than only at `canonicalize` time.
fn open_dir_chain(path: &Path) -> Result<DirFd, PartialStateError> {
    debug_assert!(path.is_absolute());
    let mut fd = sys::open_dir_path(Path::new("/")).map_err(|e| sys_err(PathBuf::from("/"), e))?;
    for comp in path.components().skip(1) {
        fd = sys::open_dir(&fd, comp.as_os_str().as_bytes())
            .map_err(|e| sys_err(path.to_path_buf(), e))?;
    }
    Ok(fd)
}

/// Materialize one verified selected file inside `root_fd`,
/// `mkdirat`-ing intermediate components and writing the leaf with its
/// exact mode. `created_dirs` records every directory this creation made
/// so an `EEXIST` on a path we did NOT create is an alias collision
/// (e.g. `A/x` vs `a/y` on a case-folding filesystem), not a reuse.
fn materialize_file(
    root_fd: &DirFd,
    components: &[Vec<u8>],
    bytes: &[u8],
    mode: EntryMode,
    created_dirs: &mut HashSet<Vec<u8>>,
) -> Result<(), PartialStateError> {
    let mut dir = root_fd
        .try_clone()
        .map_err(|e| sys_err(PathBuf::from("<root>"), e))?;
    let mut prefix: Vec<u8> = Vec::new();
    for comp in &components[..components.len() - 1] {
        if !safe_component(comp) {
            return Err(unsafe_entry(
                PathBuf::from(String::from_utf8_lossy(comp).into_owned()),
                "unsafe working-file path component",
            ));
        }
        if !prefix.is_empty() {
            prefix.push(b'/');
        }
        prefix.extend_from_slice(comp);
        if !created_dirs.contains(&prefix) {
            match sys::mkdir(&dir, comp, 0o755) {
                Ok(()) => {
                    created_dirs.insert(prefix.clone());
                    // Persist the new directory entry before descending.
                    dir.fsync().map_err(|e| {
                        sys_err(
                            PathBuf::from(String::from_utf8_lossy(&prefix).into_owned()),
                            e,
                        )
                    })?;
                }
                Err(SysError::AlreadyExists) => {
                    return Err(unsafe_entry(
                        PathBuf::from(String::from_utf8_lossy(&prefix).into_owned()),
                        "path-prefix alias collision",
                    ));
                }
                Err(error) => {
                    return Err(sys_err(
                        PathBuf::from(String::from_utf8_lossy(&prefix).into_owned()),
                        error,
                    ));
                }
            }
        }
        dir = sys::open_dir(&dir, comp).map_err(|e| {
            sys_err(
                PathBuf::from(String::from_utf8_lossy(&prefix).into_owned()),
                e,
            )
        })?;
    }
    let leaf = &components[components.len() - 1];
    let leaf_path = PathBuf::from(String::from_utf8_lossy(leaf).into_owned());
    if !safe_component(leaf) {
        return Err(unsafe_entry(leaf_path, "unsafe working-file name"));
    }
    let file = sys::open_file(&dir, leaf, OpenMode::CreateExclusive)
        .map_err(|e| sys_err(leaf_path.clone(), e))?;
    let meta = file.metadata().map_err(|e| sys_err(leaf_path.clone(), e))?;
    if !meta.is_file() || meta.nlink() != 1 {
        return Err(unsafe_entry(
            leaf_path,
            "working file must be a regular file with one link",
        ));
    }
    file.write_all(bytes)
        .map_err(|e| sys_err(leaf_path.clone(), e))?;
    let perm = if mode == EntryMode::Executable {
        0o755
    } else {
        0o644
    };
    file.fchmod(perm)
        .map_err(|e| sys_err(leaf_path.clone(), e))?;
    file.fsync().map_err(|e| sys_err(leaf_path.clone(), e))?;
    // Persist the leaf's directory entry in its parent.
    dir.fsync().map_err(|e| sys_err(leaf_path, e))?;
    Ok(())
}

/// Best-effort recursive delete of a scratch directory's contents — the
/// install-failure path only, never applied to a real workspace. Each
/// entry is probed with a real no-follow `openat` rather than trusting
/// `dirent.d_type`, which may be `DT_UNKNOWN`.
fn remove_tree(dir: &DirFd) -> Result<(), SysError> {
    for entry in dir.read_dir()? {
        let (name, _is_dir) = entry?;
        if name == b"." || name == b".." {
            continue;
        }
        match sys::open_dir(dir, &name) {
            Ok(child) => {
                let _ = remove_tree(&child);
                let _ = dir.rmdir(&name);
            }
            // Not a directory (or a symlink, which O_NOFOLLOW refuses):
            // unlink removes the entry itself.
            Err(_) => {
                let _ = dir.unlink(&name);
            }
        }
    }
    Ok(())
}

impl ScopedWorkspaceLayout {
    /// Create a new scoped workspace at `destination` (which must not
    /// exist), verifying `bundle_bytes` against the independently pinned
    /// `expected_base`, `expected_paths`, and `limits` FIRST, then
    /// installing a complete `.mkit-scoped` state plus materialized
    /// selected files in one atomic no-replace directory rename.
    ///
    /// The destination must not nest inside any ordinary, linked, or
    /// scoped repository. Failure leaves no destination behind.
    pub fn create(
        destination: &Path,
        expected_base: Hash,
        expected_paths: &[PartialPath],
        bundle_bytes: &[u8],
        limits: PartialLimits,
        target: Option<RemotePublicationTargetV1>,
    ) -> Result<Self, PartialStateError> {
        let snapshot =
            verify_partial_snapshot(expected_base, expected_paths, bundle_bytes, &limits)
                .map_err(PartialStateError::Partial)?;

        match std::fs::symlink_metadata(destination) {
            Ok(_) => {
                return Err(PartialStateError::DestinationExists(
                    destination.to_path_buf(),
                ));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(io_err(destination.to_path_buf(), e)),
        }
        let name = destination
            .file_name()
            .ok_or_else(|| {
                io_err(
                    destination.to_path_buf(),
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "destination must name a directory",
                    ),
                )
            })?
            .to_os_string();
        let raw_parent = destination
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
        let parent_path = raw_parent
            .canonicalize()
            .map_err(|e| io_err(raw_parent.clone(), e))?;
        // Reject nesting inside any existing repository or scoped
        // authority — walk the real ancestors of the canonical parent.
        for dir in parent_path.ancestors() {
            if classify_scoped_root(dir).map_err(|e| io_err(dir.to_path_buf(), e))?
                != ScopedAuthority::None
                || has_ordinary_authority(dir).map_err(|e| io_err(dir.to_path_buf(), e))?
            {
                return Err(PartialStateError::NestedLayout(dir.to_path_buf()));
            }
        }

        // Descriptor-anchored private scratch sibling (0700).
        let parent_fd = open_dir_chain(&parent_path)?;
        let mut scratch_name = None;
        for _ in 0..16 {
            let candidate = format!(
                ".mkit-scoped-new-{}-{}",
                std::process::id(),
                SCRATCH_COUNTER.fetch_add(1, Ordering::Relaxed)
            );
            match sys::mkdir(&parent_fd, candidate.as_bytes(), 0o700) {
                Ok(()) => {
                    scratch_name = Some(candidate);
                    break;
                }
                Err(SysError::AlreadyExists) => {}
                Err(error) => return Err(sys_err(parent_path.clone(), error)),
            }
        }
        let scratch_name = scratch_name.ok_or_else(|| {
            io_err(
                parent_path.clone(),
                std::io::Error::new(std::io::ErrorKind::AlreadyExists, "scratch name exhausted"),
            )
        })?;
        let scratch_fd = sys::open_dir(&parent_fd, scratch_name.as_bytes())
            .map_err(|e| sys_err(parent_path.clone(), e))?;

        // Build the complete workspace inside the scratch directory; the
        // marker is written last, and the no-replace rename is the single
        // linearization point so the destination never exists incomplete.
        if let Err(error) =
            Self::build_workspace(&scratch_fd, &snapshot, bundle_bytes, limits, target)
        {
            let _ = remove_tree(&scratch_fd);
            let _ = parent_fd.rmdir(scratch_name.as_bytes());
            return Err(error);
        }
        match sys::rename_no_replace(
            &parent_fd,
            scratch_name.as_bytes(),
            &parent_fd,
            name.as_os_str().as_encoded_bytes(),
        ) {
            Ok(()) => {}
            Err(SysError::AlreadyExists) => {
                let _ = remove_tree(&scratch_fd);
                let _ = parent_fd.rmdir(scratch_name.as_bytes());
                return Err(PartialStateError::DestinationExists(
                    destination.to_path_buf(),
                ));
            }
            Err(error) => {
                let _ = remove_tree(&scratch_fd);
                let _ = parent_fd.rmdir(scratch_name.as_bytes());
                return Err(sys_err(parent_path.clone(), error));
            }
        }
        // The no-replace rename already succeeded: the destination
        // exists and is complete. A failed parent fsync is durability
        // uncertainty, never a "did not install" error and never a
        // rollback.
        parent_fd.fsync().map_err(|e| {
            PartialStateError::DurabilityUncertain(match e {
                SysError::Io(source) => source,
                _ => std::io::Error::other("parent fsync"),
            })
        })?;
        Self::open(&parent_path.join(&name))
    }

    /// Populate `scratch_fd` with `.mkit-scoped` state, the initial
    /// bundle, the materialized selected files, and — LAST — the `.mkit`
    /// marker.
    fn build_workspace(
        scratch_fd: &DirFd,
        snapshot: &VerifiedPartialSnapshot,
        bundle_bytes: &[u8],
        limits: PartialLimits,
        target: Option<RemotePublicationTargetV1>,
    ) -> Result<(), PartialStateError> {
        sys::mkdir(scratch_fd, STATE_DIR.as_bytes(), 0o700)
            .map_err(|e| sys_err(PathBuf::from(STATE_DIR), e))?;
        let state_fd = sys::open_dir(scratch_fd, STATE_DIR.as_bytes())
            .map_err(|e| sys_err(PathBuf::from(STATE_DIR), e))?;
        for dir in [GENERATIONS_DIR, BUNDLES_DIR, OBJECTS_DIR, UPDATES_DIR] {
            sys::mkdir(&state_fd, dir.as_bytes(), 0o700)
                .map_err(|e| sys_err(PathBuf::from(dir), e))?;
        }
        // workspace.lock: stable inode, created once, never unlinked.
        let lock = sys::open_file(&state_fd, LOCK_FILE.as_bytes(), OpenMode::CreateExclusive)
            .map_err(|e| sys_err(PathBuf::from(LOCK_FILE), e))?;
        lock.fchmod(0o600)
            .map_err(|e| sys_err(PathBuf::from(LOCK_FILE), e))?;
        lock.fsync()
            .map_err(|e| sys_err(PathBuf::from(LOCK_FILE), e))?;

        let mut workspace_id = [0u8; 32];
        getrandom::fill(&mut workspace_id).map_err(|_| PartialStateError::RngFailure)?;

        // Persist the verified base bundle under its digest-derived name.
        let bundle_digest = hash::hash(bundle_bytes);
        state::write_artifact(
            &state_fd,
            BUNDLES_DIR,
            &bundle_file_name(&bundle_digest),
            bundle_bytes,
            &Faults::new(),
        )?;

        // Initial transaction generation 0 / base revision 0: clean stage
        // (every entry staged at its base id, no required objects), no
        // pending, no accepted.
        let selection: Vec<WorkspaceSelectionV1> = snapshot
            .files()
            .iter()
            .map(|file| WorkspaceSelectionV1 {
                path: file.path().clone(),
                mode: file.mode(),
                base_file_id: *file.object_id(),
            })
            .collect();
        let workspace = WorkspaceStateV1 {
            workspace_id,
            transaction_generation: 0,
            base_revision: 0,
            base_id: *snapshot.base_id(),
            base_bundle_digest: bundle_digest,
            selection,
            limits,
            target,
        };
        let stage = StageStateV1 {
            workspace_id,
            base_id: *snapshot.base_id(),
            base_revision: 0,
            entries: workspace
                .selection
                .iter()
                .map(|entry| StageEntryV1 {
                    path: entry.path.clone(),
                    mode: entry.mode,
                    staged_id: entry.base_file_id,
                })
                .collect(),
            required_object_ids: Vec::new(),
        };
        // The initial state is clean by construction, but it goes through
        // the same pre-publication validation every transition shares —
        // CURRENT never selects a state the reopen validator rejects.
        let plan = StatePlan {
            workspace,
            stage,
            pending: None,
            accepted: None,
            objects: std::collections::BTreeMap::new(),
            bundles: Vec::new(),
            updates: Vec::new(),
        };
        state::preflight_next(&plan, snapshot, &std::collections::BTreeMap::new())?;
        state::commit(&state_fd, &Faults::new(), &plan)?;

        // Materialize only verified selected files, preserving modes and
        // zero-byte files.
        let mut created_dirs = HashSet::new();
        for file in snapshot.files() {
            let bytes = state::snapshot_file_bytes(snapshot, file.object_id())?;
            materialize_file(
                scratch_fd,
                file.path(),
                &bytes,
                file.mode(),
                &mut created_dirs,
            )?;
        }

        // Marker LAST: any observer that can see `.mkit` sees a complete
        // install.
        let marker_path = PathBuf::from(crate::store::MKIT_DIR);
        let marker = sys::open_file(
            scratch_fd,
            crate::store::MKIT_DIR.as_bytes(),
            OpenMode::CreateExclusive,
        )
        .map_err(|e| sys_err(marker_path.clone(), e))?;
        marker
            .write_all(SCOPED_MARKER)
            .map_err(|e| sys_err(marker_path.clone(), e))?;
        marker
            .fchmod(0o644)
            .map_err(|e| sys_err(marker_path.clone(), e))?;
        marker.fsync().map_err(|e| sys_err(marker_path, e))?;
        scratch_fd
            .fsync()
            .map_err(|e| sys_err(PathBuf::from(STATE_DIR), e))?;
        Ok(())
    }

    /// Open an existing scoped workspace rooted at `root`. Requires the
    /// exact regular marker file and a safe `.mkit-scoped`; reads and
    /// fully verifies the `CURRENT`-selected generation before returning.
    pub fn open(root: &Path) -> Result<Self, PartialStateError> {
        // The supplied root itself must be a real directory — canonicalize
        // would silently resolve a symlink into acceptance.
        let supplied =
            std::fs::symlink_metadata(root).map_err(|e| io_err(root.to_path_buf(), e))?;
        if supplied.file_type().is_symlink() || !supplied.is_dir() {
            return Err(unsafe_entry(
                root.to_path_buf(),
                "workspace root must be a real directory, not a symlink",
            ));
        }
        let canonical = root
            .canonicalize()
            .map_err(|e| io_err(root.to_path_buf(), e))?;
        let root_fd = open_dir_chain(&canonical)?;
        let marker_path = canonical.join(crate::store::MKIT_DIR);
        let marker = sys::open_file(&root_fd, crate::store::MKIT_DIR.as_bytes(), OpenMode::Read)
            .map_err(|error| {
                if error.is_not_found() {
                    PartialStateError::NotScopedWorkspace(canonical.clone())
                } else {
                    sys_err(marker_path.clone(), error)
                }
            })?;
        let marker_meta = marker
            .metadata()
            .map_err(|e| sys_err(marker_path.clone(), e))?;
        if !marker_meta.is_file() || marker_meta.nlink() != 1 {
            return Err(unsafe_entry(
                marker_path,
                "scoped marker must be a regular file with one link",
            ));
        }
        let marker_bytes = marker
            .read_all(SCOPED_MARKER.len() + 1)
            .map_err(|e| sys_err(marker_path.clone(), e))?;
        if marker_bytes != SCOPED_MARKER {
            if marker_bytes.starts_with(SCOPED_MARKER_PREFIX) {
                return Err(PartialStateError::MarkerCorrupt(marker_path));
            }
            return Err(PartialStateError::NotScopedWorkspace(canonical));
        }
        let state_path = canonical.join(STATE_DIR);
        let state_dir = sys::open_dir(&root_fd, STATE_DIR.as_bytes()).map_err(|error| {
            if error.is_not_found() {
                PartialStateError::IncompleteInstall(state_path.clone())
            } else {
                sys_err(state_path.clone(), error)
            }
        })?;
        let lock_path = state_path.join(LOCK_FILE);
        let lock_file = sys::open_file(&state_dir, LOCK_FILE.as_bytes(), OpenMode::ReadWrite)
            .map_err(|error| {
                if error.is_not_found() {
                    PartialStateError::IncompleteInstall(lock_path.clone())
                } else {
                    sys_err(lock_path.clone(), error)
                }
            })?;
        let lock_meta = lock_file
            .metadata()
            .map_err(|e| sys_err(lock_path.clone(), e))?;
        if !lock_meta.is_file() || lock_meta.nlink() != 1 {
            return Err(unsafe_entry(
                lock_path,
                "workspace.lock must be a regular file with one link",
            ));
        }
        let lock_identity = (lock_meta.dev(), lock_meta.ino());
        let layout = Self {
            root: canonical,
            state_dir,
            lock_identity,
            faults: Faults::new(),
        };
        // Fail closed on a torn or corrupt install: the CURRENT-selected
        // generation, members, and every referenced artifact must verify
        // before the workspace is handed out.
        state::load_full(&layout)?;
        Ok(layout)
    }

    /// The scoped-workspace root directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Read and fully verify the `CURRENT`-selected state.
    pub fn read_state(&self) -> Result<ScopedWorkspaceState, PartialStateError> {
        state::load_full(self)
    }

    pub(crate) fn state_dir(&self) -> &DirFd {
        &self.state_dir
    }

    /// The `(dev, ino)` pair this handle pinned for `workspace.lock` at
    /// open — the key `lock_gate::arm` scopes a test gate to.
    #[cfg(test)]
    pub(crate) fn lock_identity(&self) -> (u64, u64) {
        self.lock_identity
    }

    /// Run `f` under the exclusive workspace lock.
    ///
    /// Every operation opens a FRESH descriptor of `workspace.lock`:
    /// flock ownership belongs to the open-file description, so a second
    /// flock arriving on a descriptor that already holds the lock would
    /// be a no-op — two threads sharing this handle must never proceed
    /// through the same already-locked descriptor. The descriptor is the
    /// guard: closing it, including during panic unwind, releases this
    /// operation's kernel lock, so a panic inside `f` cannot strand the
    /// lock or let a later invocation skip synchronization. A panic is
    /// NOT a rollback — if it lands after `CURRENT` switched, the
    /// complete new generation stays published; the guarantee is a
    /// coherent readable state plus a released lock.
    pub(crate) fn with_lock<T>(
        &self,
        f: impl FnOnce(&DirFd) -> Result<T, PartialStateError>,
    ) -> Result<T, PartialStateError> {
        let lock_path = self.root.join(STATE_DIR).join(LOCK_FILE);
        // Open fresh and verify the inode BEFORE flocking — never take a
        // kernel lock on an inode this handle did not pin at open.
        let operation_lock =
            sys::open_file(&self.state_dir, LOCK_FILE.as_bytes(), OpenMode::ReadWrite).map_err(
                |e| PartialStateError::LockFailed {
                    path: lock_path.clone(),
                    source: match e {
                        SysError::Io(source) => source,
                        _ => std::io::Error::other("workspace lock"),
                    },
                },
            )?;
        let meta = operation_lock
            .metadata()
            .map_err(|e| sys_err(lock_path.clone(), e))?;
        if !meta.is_file() || meta.nlink() != 1 {
            return Err(unsafe_entry(
                lock_path,
                "workspace.lock must be a regular file with one link",
            ));
        }
        if (meta.dev(), meta.ino()) != self.lock_identity {
            return Err(unsafe_entry(lock_path, "workspace.lock inode was replaced"));
        }
        #[cfg(test)]
        lock_gate::signal(lock_gate::Phase::BeforeFlock, self.lock_identity);
        operation_lock
            .lock_exclusive()
            .map_err(|e| PartialStateError::LockFailed {
                path: lock_path.clone(),
                source: match e {
                    SysError::Io(source) => source,
                    _ => std::io::Error::other("workspace lock"),
                },
            })?;
        // The flock can park this operation while the named sentinel is
        // atomically replaced — the descriptor it acquired then belongs
        // to a detached inode while new opens land on the replacement.
        // Re-resolve the name and re-verify identity AFTER acquisition;
        // on mismatch the acquired descriptor drops here, releasing the
        // stale inode's lock without ever entering `f`.
        let recheck = sys::open_file(&self.state_dir, LOCK_FILE.as_bytes(), OpenMode::ReadWrite)
            .map_err(|e| PartialStateError::LockFailed {
                path: lock_path.clone(),
                source: match e {
                    SysError::Io(source) => source,
                    _ => std::io::Error::other("workspace lock"),
                },
            })?;
        let meta = recheck
            .metadata()
            .map_err(|e| sys_err(lock_path.clone(), e))?;
        if !meta.is_file() || meta.nlink() != 1 {
            return Err(unsafe_entry(
                lock_path,
                "workspace.lock must be a regular file with one link",
            ));
        }
        if (meta.dev(), meta.ino()) != self.lock_identity {
            return Err(unsafe_entry(lock_path, "workspace.lock inode was replaced"));
        }
        drop(recheck);
        #[cfg(test)]
        lock_gate::signal(lock_gate::Phase::Acquired, self.lock_identity);
        let result = f(&self.state_dir);
        drop(operation_lock);
        result
    }
}

/// Deterministic lock-observation seam for tests: `arm` parks the next
/// `with_lock` reaching `phase` until released, proving a writer is
/// inside the critical section (`Acquired`) or parked at the flock
/// boundary with the sentinel already opened and verified
/// (`BeforeFlock`). Compiled out of non-test builds.
#[cfg(test)]
pub(crate) mod lock_gate {
    use std::sync::Mutex;
    use std::sync::mpsc::{Receiver, Sender};

    /// The `with_lock` position a gate may fire at.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Phase {
        /// Sentinel opened and identity-verified, immediately before the
        /// blocking flock — a writer proven to be waiting on the lock.
        BeforeFlock,
        /// Lock acquired and the sentinel re-verified — the operation is
        /// provably inside the critical section.
        Acquired,
    }

    struct Gate {
        phase: Phase,
        /// The `with_lock` handle's pinned sentinel `(dev, ino)` — gates
        /// are scoped to one workspace so a parallel test's `with_lock`
        /// can never consume this gate.
        identity: (u64, u64),
        signal: Sender<()>,
        release: Receiver<()>,
    }

    static GATE: Mutex<Option<Gate>> = Mutex::new(None);

    /// Arm a one-shot gate: the next `with_lock` on a handle pinned to
    /// `identity` reaching `phase` sends on `signal` then blocks on
    /// `release`, still holding whatever lock state it has at that
    /// point. Fires exactly once.
    pub(crate) fn arm(
        phase: Phase,
        identity: (u64, u64),
        signal: Sender<()>,
        release: Receiver<()>,
    ) {
        *GATE.lock().unwrap() = Some(Gate {
            phase,
            identity,
            signal,
            release,
        });
    }

    pub(super) fn signal(phase: Phase, identity: (u64, u64)) {
        let gate = {
            let mut slot = GATE.lock().unwrap();
            match slot.as_ref() {
                Some(gate) if gate.phase == phase && gate.identity == identity => slot.take(),
                _ => None,
            }
        };
        if let Some(gate) = gate {
            let _ = gate.signal.send(());
            let _ = gate.release.recv();
        }
    }
}
