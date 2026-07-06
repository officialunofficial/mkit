//! Local record of pack digests already applied to this repo's object
//! store, keyed by remote — the fetch-side redownload-avoidance cache for
//! issue #409.
//!
//! `fetch_pack_chain` ([`super::packmap::fetch_pack_chain`]) always walks a
//! branch's *whole* packmap chain to discover its shape (chain-node
//! downloads are small blobs and stay unconditional — see that function's
//! docs), but without this record it re-downloads and re-unpacks every pack
//! in the chain on every fetch, even packs the local object store already
//! has applied. [`AppliedPacks`] lets the loop skip download + unpack for
//! any pack digest already recorded, so a steady-state fetch costs
//! `O(new packs)` instead of `O(chain length)`.
//!
//! # Format
//!
//! One file per remote: `.mkit/applied-packs/<record>` (the `applied-packs/`
//! directory is created on first write). Contents are a lowercase 64-hex
//! BLAKE3 pack digest per line, LF-terminated, with no header. Unknown or
//! malformed lines are ignored on load, for forward compatibility. Writes
//! are atomic: a sibling `.tmp` file is written, fsynced, and renamed over
//! the destination — the same temp+fsync+rename pattern
//! `mkit_core::refs`/`mkit_core::atomic` use for ref files.
//!
//! `<record>` is the remote *name* with any `/` percent-encoded to `%2F`
//! (see [`record_file_name`]) so a legal multi-segment remote like
//! `team/upstream` maps to one flat file rather than a nested subdirectory.
//! [`AppliedPacks::load`] validates the name with
//! [`mkit_core::refs::validate_ref_name`] — the same check `mkit remote add`
//! applies, so any remote that can be configured can also be recorded. That
//! grammar admits `A-Za-z0-9._-` plus `/` as the segment separator, which
//! guarantees the name never contains `%` (keeping the `%2F` encoding
//! unambiguous and reversible) and rejects the control-char / `.lock` / `.`
//! / `..` cases a bespoke blacklist would miss.
//!
//! # Correctness posture
//!
//! [`mkit_core::pack::PackReader::read`] is idempotent (content-addressed
//! writes, full digest re-verification), so skipping a recorded pack is
//! purely a performance win, never a correctness risk *on its own*. The one
//! hazard this record introduces is staleness relative to the object store
//! (e.g. `.mkit/objects` wiped out-of-band while `applied-packs/` survives);
//! the fetch-side self-heal path in `fetch_pack_chain` handles that by
//! clearing the record and retrying once with a full re-download whenever a
//! run that skipped at least one pack also hits an error.
//!
//! # Repo-layout classification (cross-link: #493 Phase 0)
//!
//! #493's `RepoLayout` migration will eventually own every ad-hoc
//! `mkit_dir.join(...)` call site, including this one. When it lands, this
//! path MUST be classified as **common-dir (shared) state**: the record
//! describes what is already in the shared object store, so every worktree
//! of a repo shares one record per remote — it is NOT per-worktree state.
//!
//! It is also a pure **cache**, never a root: `mkit gc`'s
//! `ops::gc::collect_roots` must never treat any digest listed here as
//! pinning an object, and the file (and its containing directory) is always
//! safe to delete — a missing record just means the next fetch re-downloads
//! the whole chain once, per the self-heal behaviour above.

use std::collections::HashSet;
use std::fs;
#[cfg(unix)]
use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use mkit_core::hash::{HEX_LEN, Hash, to_hex};
use mkit_core::protocol::PackKey;
use tempfile::NamedTempFile;

use super::DispatchError;

/// Subdirectory (under `.mkit/`) holding one applied-pack record file per
/// remote.
const APPLIED_PACKS_DIR: &str = "applied-packs";

/// A local record of pack digests already unpacked into this repo's object
/// store for one remote. See the module docs for the on-disk format and the
/// self-heal contract.
#[derive(Debug)]
pub(crate) struct AppliedPacks {
    set: HashSet<Hash>,
    path: PathBuf,
    dirty: bool,
}

impl AppliedPacks {
    /// Load the record for `remote` under `mkit_dir` (the `.mkit/`
    /// directory). A missing file yields an empty set — this is the normal
    /// state for a fresh clone, not an error.
    ///
    /// # Errors
    ///
    /// [`DispatchError::InvalidRemoteName`] if `remote` is not a legal ref
    /// name (per [`mkit_core::refs::validate_ref_name`]). Any other I/O
    /// failure reading the file propagates as [`DispatchError::Io`]. Callers
    /// treat both as non-fatal — the record is a pure cache — see
    /// [`super::packmap::fetch_pack_chain`].
    pub(crate) fn load(mkit_dir: &Path, remote: &str) -> Result<Self, DispatchError> {
        validate_remote_name(remote)?;
        let path = record_path(mkit_dir, remote);
        let set = match fs::read(&path) {
            Ok(bytes) => parse(&bytes),
            Err(e) if e.kind() == io::ErrorKind::NotFound => HashSet::new(),
            Err(e) => return Err(DispatchError::Io(e)),
        };
        Ok(Self {
            set,
            path,
            dirty: false,
        })
    }

    /// An empty, in-memory record for `remote`, used as the non-fatal
    /// fallback when [`Self::load`] fails: the applied-pack record is purely
    /// a performance cache (#409), so a fetch whose objects durably land must
    /// never fail because the cache couldn't be read. Persisting is still
    /// attempted best-effort through the normal path.
    pub(crate) fn empty(mkit_dir: &Path, remote: &str) -> Self {
        Self {
            set: HashSet::new(),
            path: record_path(mkit_dir, remote),
            dirty: false,
        }
    }

    /// True iff `key`'s digest is already recorded as applied.
    pub(crate) fn contains(&self, key: &PackKey) -> bool {
        self.set.contains(&key.into_hash())
    }

    /// Record `key`'s digest as applied. Marks the record dirty so the next
    /// [`Self::persist`] call rewrites the file.
    pub(crate) fn insert(&mut self, key: &PackKey) {
        self.set.insert(key.into_hash());
        self.dirty = true;
    }

    /// Atomically rewrite the on-disk record with the full current set
    /// (sorted, for a deterministic file), but only if [`Self::insert`] has
    /// been called since the last successful persist. A no-op call is free.
    /// Clears the dirty flag on a successful write so a subsequent no-op
    /// call really is free.
    pub(crate) fn persist(&mut self) -> Result<(), DispatchError> {
        if !self.dirty {
            return Ok(());
        }
        write(&self.path, &self.set)?;
        self.dirty = false;
        Ok(())
    }

    /// Discard every recorded digest and persist the now-empty set
    /// unconditionally. Used by the fetch-side self-heal path when the
    /// local record is suspected stale relative to the object store (e.g.
    /// the store was wiped but `applied-packs/` survived).
    pub(crate) fn clear_and_persist(&mut self) -> Result<(), DispatchError> {
        self.set.clear();
        write(&self.path, &self.set)?;
        self.dirty = false;
        Ok(())
    }
}

/// Reject any remote name that isn't a legal ref name. A remote name *is* a
/// ref name — `mkit remote add` runs it through
/// [`mkit_core::refs::validate_ref_name`] — so reusing that check keeps the
/// two in lockstep and rejects the control-char / `.lock` / `.` / `..` /
/// backslash cases a bespoke blacklist misses. A legal name may still contain
/// `/` (a multi-segment remote like `team/upstream`); [`record_file_name`]
/// flattens that into the on-disk filename, so `/` is no longer rejected.
fn validate_remote_name(remote: &str) -> Result<(), DispatchError> {
    if mkit_core::refs::validate_ref_name(remote) {
        Ok(())
    } else {
        Err(DispatchError::InvalidRemoteName(remote.to_string()))
    }
}

/// Map a validated remote name to its flat record filename under
/// `applied-packs/`. A legal remote may contain `/` (a multi-segment name
/// like `team/upstream`), which would otherwise be read as a subdirectory
/// separator; percent-encode it to `%2F` so every remote gets exactly one
/// flat file and the atomic sibling-tmp+rename write stays within
/// `applied-packs/`. [`validate_remote_name`] guarantees the name never
/// contains `%`, so this mapping is unambiguous and reversible.
fn record_file_name(remote: &str) -> String {
    remote.replace('/', "%2F")
}

/// The full record path for `remote` under `mkit_dir` (the `.mkit/`
/// directory): `applied-packs/<record_file_name(remote)>`.
fn record_path(mkit_dir: &Path, remote: &str) -> PathBuf {
    mkit_dir
        .join(APPLIED_PACKS_DIR)
        .join(record_file_name(remote))
}

/// Parse the on-disk record format: one lowercase 64-hex digest per LF
/// line. Malformed lines (wrong length, non-hex, uppercase hex) are
/// silently ignored, per the module's forward-compatibility contract.
fn parse(bytes: &[u8]) -> HashSet<Hash> {
    let mut set = HashSet::new();
    let Ok(s) = core::str::from_utf8(bytes) else {
        return set;
    };
    for line in s.split('\n') {
        let trimmed = line.trim_end_matches('\r');
        // Strict lowercase-hex parse in a single pass — reuses the same
        // wire parser refs files use, rather than the more permissive
        // `hash::from_hex` (which tolerates uppercase). On-disk records must
        // be strict so a hand-edited or foreign-cased line is treated as
        // malformed and ignored rather than silently accepted.
        if let Some(h) = mkit_core::refs::parse_lowercase_hash(trimmed.as_bytes()) {
            set.insert(h);
        }
    }
    set
}

/// Atomically rewrite `path` with the sorted, LF-terminated hex encoding of
/// `set`. Creates the parent directory (`applied-packs/`) on first write.
fn write(path: &Path, set: &HashSet<Hash>) -> Result<(), DispatchError> {
    let mut hexes: Vec<String> = set.iter().map(to_hex).collect();
    hexes.sort_unstable();
    let mut body = String::with_capacity(hexes.len() * (HEX_LEN + 1));
    for hex in &hexes {
        body.push_str(hex);
        body.push('\n');
    }
    write_atomic(path, body.as_bytes())?;
    Ok(())
}

/// Atomic temp+fsync+rename write, matching `mkit_core::atomic::write_atomic`
/// (kept as a local copy here rather than reaching into mkit-core's
/// crate-private helper — see that module's docs for why each durable
/// subsystem owns its own copy of this primitive).
fn write_atomic(final_path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = final_path
        .parent()
        .expect("applied_packs::write_atomic: path has parent");
    fs::create_dir_all(parent)?;
    let file_name = final_path
        .file_name()
        .expect("applied_packs::write_atomic: path has file name")
        .to_string_lossy();
    // `with_prefix_in` already appends a random unique suffix, so this
    // prefix only needs to be stable and recognisable — no pid/sequence
    // needed for uniqueness.
    let tmp_prefix = format!(".{file_name}.tmp");

    let mut tmp = NamedTempFile::with_prefix_in(tmp_prefix, parent)?;
    tmp.as_file_mut().write_all(bytes)?;
    tmp.as_file_mut().sync_all()?;
    tmp.persist(final_path).map_err(|e| e.error)?;

    sync_parent_dir(parent)?;
    Ok(())
}

#[cfg(unix)]
fn sync_parent_dir(parent: &Path) -> io::Result<()> {
    match File::open(parent) {
        Ok(dir) => dir.sync_all(),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
fn sync_parent_dir(_parent: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mkit_core::hash;
    use tempfile::TempDir;

    fn h(seed: &str) -> Hash {
        hash::hash(seed.as_bytes())
    }

    fn pk(seed: &str) -> PackKey {
        PackKey::from_hash(h(seed))
    }

    fn fresh_mkit_dir() -> (TempDir, PathBuf) {
        let dir = TempDir::new().unwrap();
        let mkit_dir = dir.path().join(".mkit");
        fs::create_dir_all(&mkit_dir).unwrap();
        (dir, mkit_dir)
    }

    #[test]
    fn load_missing_yields_empty_set() {
        let (_dir, mkit_dir) = fresh_mkit_dir();
        let applied = AppliedPacks::load(&mkit_dir, "origin").unwrap();
        assert!(!applied.contains(&pk("a")));
    }

    #[test]
    fn insert_persist_reload_round_trip() {
        let (_dir, mkit_dir) = fresh_mkit_dir();
        let k1 = pk("pack-1");
        let k2 = pk("pack-2");
        {
            let mut applied = AppliedPacks::load(&mkit_dir, "origin").unwrap();
            applied.insert(&k1);
            applied.insert(&k2);
            applied.persist().unwrap();
        }
        let reloaded = AppliedPacks::load(&mkit_dir, "origin").unwrap();
        assert!(reloaded.contains(&k1));
        assert!(reloaded.contains(&k2));
        assert!(!reloaded.contains(&pk("pack-3")));
    }

    #[test]
    fn separate_remotes_get_separate_files() {
        let (_dir, mkit_dir) = fresh_mkit_dir();
        let k1 = pk("pack-1");
        let mut origin = AppliedPacks::load(&mkit_dir, "origin").unwrap();
        origin.insert(&k1);
        origin.persist().unwrap();

        let upstream = AppliedPacks::load(&mkit_dir, "upstream").unwrap();
        assert!(
            !upstream.contains(&k1),
            "records must not leak across remotes"
        );
    }

    #[test]
    fn malformed_lines_are_ignored_on_load() {
        let (_dir, mkit_dir) = fresh_mkit_dir();
        let path = mkit_dir.join(APPLIED_PACKS_DIR).join("origin");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let valid = h("valid");
        let mut content = String::new();
        content.push_str("short\n");
        content.push_str(&to_hex(&valid));
        content.push('\n');
        // Uppercase hex is malformed per this record's strict format.
        content.push_str(&"F".repeat(64));
        content.push('\n');
        content.push_str(&"z".repeat(64));
        content.push('\n');
        fs::write(&path, content).unwrap();

        let applied = AppliedPacks::load(&mkit_dir, "origin").unwrap();
        assert!(applied.contains(&PackKey::from_hash(valid)));
    }

    #[test]
    fn atomic_rewrite_leaves_no_tmp_file_on_success() {
        let (_dir, mkit_dir) = fresh_mkit_dir();
        let mut applied = AppliedPacks::load(&mkit_dir, "origin").unwrap();
        applied.insert(&pk("pack-1"));
        applied.persist().unwrap();

        let dir = mkit_dir.join(APPLIED_PACKS_DIR);
        let leftover: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp"))
            .collect();
        assert!(
            leftover.is_empty(),
            "no .tmp file should survive a successful persist"
        );
    }

    #[test]
    fn persist_is_noop_when_not_dirty() {
        let (_dir, mkit_dir) = fresh_mkit_dir();
        let mut applied = AppliedPacks::load(&mkit_dir, "origin").unwrap();
        // Never inserted anything, so persist() must not create the file
        // (or the applied-packs/ directory) at all.
        applied.persist().unwrap();
        assert!(!mkit_dir.join(APPLIED_PACKS_DIR).exists());
    }

    #[test]
    fn clear_and_persist_empties_the_record() {
        let (_dir, mkit_dir) = fresh_mkit_dir();
        let k1 = pk("pack-1");
        let mut applied = AppliedPacks::load(&mkit_dir, "origin").unwrap();
        applied.insert(&k1);
        applied.persist().unwrap();
        assert!(applied.contains(&k1));

        applied.clear_and_persist().unwrap();
        assert!(!applied.contains(&k1));

        let reloaded = AppliedPacks::load(&mkit_dir, "origin").unwrap();
        assert!(!reloaded.contains(&k1));
    }

    #[test]
    fn multi_segment_remote_round_trips() {
        // A legal multi-segment remote (`mkit remote add team/upstream`
        // passes `validate_ref_name`) must record without error, as one flat
        // file — the `/` is encoded, not turned into a subdirectory.
        let (_dir, mkit_dir) = fresh_mkit_dir();
        let k1 = pk("pack-1");
        {
            let mut applied = AppliedPacks::load(&mkit_dir, "team/upstream").unwrap();
            applied.insert(&k1);
            applied.persist().unwrap();
        }

        let dir = mkit_dir.join(APPLIED_PACKS_DIR);
        let entries: Vec<_> = fs::read_dir(&dir).unwrap().filter_map(Result::ok).collect();
        assert_eq!(entries.len(), 1, "exactly one flat record file per remote");
        assert!(
            entries[0].file_type().unwrap().is_file(),
            "the `/` must not create a subdirectory"
        );
        assert_eq!(
            entries[0].file_name().to_string_lossy(),
            "team%2Fupstream",
            "the `/` is percent-encoded in the on-disk filename"
        );

        let reloaded = AppliedPacks::load(&mkit_dir, "team/upstream").unwrap();
        assert!(reloaded.contains(&k1));
        // A different remote whose encoded name could otherwise collide stays
        // separate.
        let other = AppliedPacks::load(&mkit_dir, "teamupstream").unwrap();
        assert!(!other.contains(&k1), "encoded names must not collide");
    }

    #[test]
    fn remote_name_rejects_backslash() {
        let (_dir, mkit_dir) = fresh_mkit_dir();
        let err = AppliedPacks::load(&mkit_dir, "evil\\remote").unwrap_err();
        assert!(matches!(err, DispatchError::InvalidRemoteName(_)));
    }

    #[test]
    fn remote_name_rejects_dotdot_and_empty() {
        let (_dir, mkit_dir) = fresh_mkit_dir();
        // A `.` / `..` path segment (validate_ref_name rejects both).
        let err = AppliedPacks::load(&mkit_dir, "..").unwrap_err();
        assert!(matches!(err, DispatchError::InvalidRemoteName(_)));
        let err = AppliedPacks::load(&mkit_dir, "../escape").unwrap_err();
        assert!(matches!(err, DispatchError::InvalidRemoteName(_)));
        let err = AppliedPacks::load(&mkit_dir, "").unwrap_err();
        assert!(matches!(err, DispatchError::InvalidRemoteName(_)));
    }
}
