//! Conflict / operation state sidecar.
//!
//! mkit's `.mkit/index` stays a single-stage **resolved** staging area
//! (see SPEC-INDEX — no unmerged stages 1/2/3). When a merge,
//! cherry-pick, or rebase pauses on a conflict we instead persist the
//! state needed to resume or abort in a small set of files under
//! `.mkit/`, using Git-compatible names where they exist plus one
//! documented mkit sidecar:
//!
//! - `MERGE_HEAD`        — 64-hex of the other parent (merge: theirs).
//!   Presence ⇒ a merge is in progress.
//! - `CHERRY_PICK_HEAD`  — 64-hex of the commit being picked.
//!   Presence ⇒ a cherry-pick is in progress.
//! - `ORIG_HEAD`         — 64-hex of HEAD before the op (for `--abort`).
//! - `MERGE_MSG` / `CHERRY_PICK_MSG` — pending commit message bytes.
//! - `mkit-conflicts`    — the sidecar: one line per conflicting path,
//!   recording the conflict kind and the base/ours/theirs blob hashes.
//!   Used by `--abort` cleanup and by the "unresolved conflicts remain"
//!   gate on `--continue`.
//!
//! Rebase reuses the existing `.mkit/rebase-apply/` directory and writes
//! the same `mkit-conflicts` sidecar **inside** that directory when it
//! pauses.
//!
//! `mkit-conflicts` line format (tab-separated, one per path):
//!
//! ```text
//! <kind>\t<base_hex|->\t<ours_hex|->\t<theirs_hex|->\t<path>
//! ```
//!
//! where `<kind>` is one of `modify`, `addadd`, `deletemodify` and a
//! missing side is encoded as a single `-`. The `<path>` is the final
//! field so it may itself contain no `\t` (validated via
//! [`crate::index::validate_index_path`] on read) and runs to end of
//! line.

use std::fs;
use std::io;
use std::path::Path;

use crate::hash::{self, HEX_LEN, Hash};
use crate::index::validate_index_path;
use crate::ops::merge::{Conflict, ConflictKind};

/// File name: other parent of an in-progress merge.
pub const MERGE_HEAD: &str = "MERGE_HEAD";
/// File name: commit being applied by an in-progress cherry-pick.
pub const CHERRY_PICK_HEAD: &str = "CHERRY_PICK_HEAD";
/// File name: HEAD before the in-progress operation started.
pub const ORIG_HEAD: &str = "ORIG_HEAD";
/// File name: pending merge commit message.
pub const MERGE_MSG: &str = "MERGE_MSG";
/// File name: pending cherry-pick commit message.
pub const CHERRY_PICK_MSG: &str = "CHERRY_PICK_MSG";
/// File name: the conflict sidecar (also used inside `rebase-apply/`).
pub const CONFLICTS_FILE: &str = "mkit-conflicts";

/// Hard cap on any single state file we read back (1 MiB). Conflict
/// sidecars list at most one line per repo path; 1 MiB is generous.
const MAX_STATE_BYTES: u64 = 1024 * 1024;

/// Errors raised by the conflict-state subsystem.
#[derive(Debug, thiserror::Error)]
pub enum ConflictStateError {
    /// On-disk state was malformed (bad hex, bad kind, bad path, …).
    #[error("conflict state on disk is malformed")]
    Invalid,
    /// Underlying I/O failure.
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Result alias.
pub type ConflictStateResult<T> = Result<T, ConflictStateError>;

/// One recorded conflicting path: the conflict kind plus the three blob
/// hashes carried by [`Conflict`]. A missing side is `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConflictRecord {
    /// Repo-relative path.
    pub path: String,
    /// Conflict kind.
    pub kind: ConflictKind,
    /// Base-side blob hash (`None` for add/add).
    pub base_hash: Option<Hash>,
    /// Ours-side blob hash (`None` when ours deleted).
    pub ours_hash: Option<Hash>,
    /// Theirs-side blob hash (`None` when theirs deleted).
    pub theirs_hash: Option<Hash>,
}

impl From<&Conflict> for ConflictRecord {
    fn from(c: &Conflict) -> Self {
        Self {
            path: c.path.clone(),
            kind: c.kind,
            base_hash: c.base_hash,
            ours_hash: c.ours_hash,
            theirs_hash: c.theirs_hash,
        }
    }
}

fn kind_tag(kind: ConflictKind) -> &'static str {
    match kind {
        ConflictKind::ModifyModify => "modify",
        ConflictKind::AddAdd => "addadd",
        ConflictKind::DeleteModify => "deletemodify",
    }
}

fn kind_from_tag(tag: &str) -> Option<ConflictKind> {
    match tag {
        "modify" => Some(ConflictKind::ModifyModify),
        "addadd" => Some(ConflictKind::AddAdd),
        "deletemodify" => Some(ConflictKind::DeleteModify),
        _ => None,
    }
}

fn hex_or_dash(h: Option<Hash>) -> String {
    match h {
        Some(h) => hash::to_hex(&h),
        None => "-".to_string(),
    }
}

fn parse_hex_or_dash(field: &str) -> Result<Option<Hash>, ConflictStateError> {
    if field == "-" {
        return Ok(None);
    }
    if field.len() != HEX_LEN {
        return Err(ConflictStateError::Invalid);
    }
    hash::from_hex(field)
        .map(Some)
        .map_err(|_| ConflictStateError::Invalid)
}

/// Serialise conflict records to the `mkit-conflicts` line format.
#[must_use]
pub fn serialize_conflicts(records: &[ConflictRecord]) -> Vec<u8> {
    let mut out = String::new();
    for r in records {
        out.push_str(kind_tag(r.kind));
        out.push('\t');
        out.push_str(&hex_or_dash(r.base_hash));
        out.push('\t');
        out.push_str(&hex_or_dash(r.ours_hash));
        out.push('\t');
        out.push_str(&hex_or_dash(r.theirs_hash));
        out.push('\t');
        out.push_str(&r.path);
        out.push('\n');
    }
    out.into_bytes()
}

/// Parse the `mkit-conflicts` line format. Rejects malformed lines.
///
/// # Errors
/// [`ConflictStateError::Invalid`] on any malformed line (bad field
/// count, unknown kind, bad hex, or a path failing
/// [`validate_index_path`]).
pub fn deserialize_conflicts(data: &[u8]) -> ConflictStateResult<Vec<ConflictRecord>> {
    let text = core::str::from_utf8(data).map_err(|_| ConflictStateError::Invalid)?;
    let mut out = Vec::new();
    for line in text.split('\n') {
        if line.is_empty() {
            continue;
        }
        // kind, base, ours, theirs, path — exactly 5 fields; the path is
        // last and may not contain a tab.
        let mut fields = line.splitn(5, '\t');
        let kind = fields.next().ok_or(ConflictStateError::Invalid)?;
        let base = fields.next().ok_or(ConflictStateError::Invalid)?;
        let ours = fields.next().ok_or(ConflictStateError::Invalid)?;
        let theirs = fields.next().ok_or(ConflictStateError::Invalid)?;
        let path = fields.next().ok_or(ConflictStateError::Invalid)?;
        let kind = kind_from_tag(kind).ok_or(ConflictStateError::Invalid)?;
        if !validate_index_path(path) {
            return Err(ConflictStateError::Invalid);
        }
        out.push(ConflictRecord {
            path: path.to_string(),
            kind,
            base_hash: parse_hex_or_dash(base)?,
            ours_hash: parse_hex_or_dash(ours)?,
            theirs_hash: parse_hex_or_dash(theirs)?,
        });
    }
    Ok(out)
}

fn write_hex_file(mkit_dir: &Path, name: &str, h: &Hash) -> ConflictStateResult<()> {
    let mut buf = hash::to_hex(h);
    buf.push('\n');
    fs::write(mkit_dir.join(name), buf.as_bytes())?;
    Ok(())
}

fn read_hex_file(path: &Path) -> ConflictStateResult<Option<Hash>> {
    let raw = match read_capped(path) {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(ConflictStateError::Io(e)),
    };
    let trimmed = raw.trim_end_matches(['\n', '\r', ' ', '\t']);
    if trimmed.len() != HEX_LEN {
        return Err(ConflictStateError::Invalid);
    }
    hash::from_hex(trimmed)
        .map(Some)
        .map_err(|_| ConflictStateError::Invalid)
}

fn read_capped(path: &Path) -> io::Result<String> {
    let meta = fs::metadata(path)?;
    if meta.len() > MAX_STATE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "state too large",
        ));
    }
    let raw = fs::read(path)?;
    String::from_utf8(raw).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-utf8"))
}

/// Persisted state for an in-progress merge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergeState {
    /// The other (theirs) parent of the merge.
    pub merge_head: Hash,
    /// HEAD before the merge started.
    pub orig_head: Hash,
    /// Pending merge commit message.
    pub message: Vec<u8>,
}

/// Persisted state for an in-progress cherry-pick.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CherryPickState {
    /// The commit being picked.
    pub cherry_pick_head: Hash,
    /// HEAD before the cherry-pick started.
    pub orig_head: Hash,
    /// Pending commit message (the picked commit's message).
    pub message: Vec<u8>,
}

/// Write merge state + the conflict sidecar.
///
/// # Errors
/// [`ConflictStateError::Io`] on filesystem failures.
pub fn write_merge_state(
    mkit_dir: &Path,
    state: &MergeState,
    conflicts: &[ConflictRecord],
) -> ConflictStateResult<()> {
    fs::create_dir_all(mkit_dir)?;
    write_hex_file(mkit_dir, MERGE_HEAD, &state.merge_head)?;
    write_hex_file(mkit_dir, ORIG_HEAD, &state.orig_head)?;
    fs::write(mkit_dir.join(MERGE_MSG), &state.message)?;
    fs::write(
        mkit_dir.join(CONFLICTS_FILE),
        serialize_conflicts(conflicts),
    )?;
    Ok(())
}

/// Read merge state. Returns `Ok(None)` when no merge is in progress.
///
/// # Errors
/// [`ConflictStateError::Invalid`] on malformed state.
pub fn read_merge_state(mkit_dir: &Path) -> ConflictStateResult<Option<MergeState>> {
    let Some(merge_head) = read_hex_file(&mkit_dir.join(MERGE_HEAD))? else {
        return Ok(None);
    };
    let orig_head = read_hex_file(&mkit_dir.join(ORIG_HEAD))?.ok_or(ConflictStateError::Invalid)?;
    let message = match fs::read(mkit_dir.join(MERGE_MSG)) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(ConflictStateError::Io(e)),
    };
    Ok(Some(MergeState {
        merge_head,
        orig_head,
        message,
    }))
}

/// Write cherry-pick state + the conflict sidecar.
///
/// # Errors
/// [`ConflictStateError::Io`] on filesystem failures.
pub fn write_cherry_pick_state(
    mkit_dir: &Path,
    state: &CherryPickState,
    conflicts: &[ConflictRecord],
) -> ConflictStateResult<()> {
    fs::create_dir_all(mkit_dir)?;
    write_hex_file(mkit_dir, CHERRY_PICK_HEAD, &state.cherry_pick_head)?;
    write_hex_file(mkit_dir, ORIG_HEAD, &state.orig_head)?;
    fs::write(mkit_dir.join(CHERRY_PICK_MSG), &state.message)?;
    fs::write(
        mkit_dir.join(CONFLICTS_FILE),
        serialize_conflicts(conflicts),
    )?;
    Ok(())
}

/// Read cherry-pick state. Returns `Ok(None)` when none is in progress.
///
/// # Errors
/// [`ConflictStateError::Invalid`] on malformed state.
pub fn read_cherry_pick_state(mkit_dir: &Path) -> ConflictStateResult<Option<CherryPickState>> {
    let Some(cherry_pick_head) = read_hex_file(&mkit_dir.join(CHERRY_PICK_HEAD))? else {
        return Ok(None);
    };
    let orig_head = read_hex_file(&mkit_dir.join(ORIG_HEAD))?.ok_or(ConflictStateError::Invalid)?;
    let message = match fs::read(mkit_dir.join(CHERRY_PICK_MSG)) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(ConflictStateError::Io(e)),
    };
    Ok(Some(CherryPickState {
        cherry_pick_head,
        orig_head,
        message,
    }))
}

/// Read the conflict sidecar from `dir` (either `.mkit/` for merge /
/// cherry-pick or `.mkit/rebase-apply/` for rebase). Returns an empty
/// vector when the file is absent.
///
/// # Errors
/// [`ConflictStateError::Invalid`] on malformed lines.
pub fn read_conflicts(dir: &Path) -> ConflictStateResult<Vec<ConflictRecord>> {
    let path = dir.join(CONFLICTS_FILE);
    let raw = match read_capped(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(ConflictStateError::Io(e)),
    };
    deserialize_conflicts(raw.as_bytes())
}

/// Write the conflict sidecar into `dir`.
///
/// # Errors
/// [`ConflictStateError::Io`] on filesystem failures.
pub fn write_conflicts(dir: &Path, conflicts: &[ConflictRecord]) -> ConflictStateResult<()> {
    fs::create_dir_all(dir)?;
    fs::write(dir.join(CONFLICTS_FILE), serialize_conflicts(conflicts))?;
    Ok(())
}

fn remove_if_present(path: &Path) -> ConflictStateResult<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(ConflictStateError::Io(e)),
    }
}

/// Remove all merge state files (idempotent).
///
/// # Errors
/// [`ConflictStateError::Io`] on filesystem failures other than absence.
pub fn clear_merge_state(mkit_dir: &Path) -> ConflictStateResult<()> {
    remove_if_present(&mkit_dir.join(MERGE_HEAD))?;
    remove_if_present(&mkit_dir.join(MERGE_MSG))?;
    remove_if_present(&mkit_dir.join(ORIG_HEAD))?;
    remove_if_present(&mkit_dir.join(CONFLICTS_FILE))?;
    Ok(())
}

/// Remove all cherry-pick state files (idempotent).
///
/// # Errors
/// [`ConflictStateError::Io`] on filesystem failures other than absence.
pub fn clear_cherry_pick_state(mkit_dir: &Path) -> ConflictStateResult<()> {
    remove_if_present(&mkit_dir.join(CHERRY_PICK_HEAD))?;
    remove_if_present(&mkit_dir.join(CHERRY_PICK_MSG))?;
    remove_if_present(&mkit_dir.join(ORIG_HEAD))?;
    remove_if_present(&mkit_dir.join(CONFLICTS_FILE))?;
    Ok(())
}

/// `true` when a merge is in progress (`MERGE_HEAD` present).
#[must_use]
pub fn is_merge_in_progress(mkit_dir: &Path) -> bool {
    mkit_dir.join(MERGE_HEAD).exists()
}

/// `true` when a cherry-pick is in progress (`CHERRY_PICK_HEAD` present).
#[must_use]
pub fn is_cherry_pick_in_progress(mkit_dir: &Path) -> bool {
    mkit_dir.join(CHERRY_PICK_HEAD).exists()
}

/// `true` when any merge / cherry-pick / rebase is in progress. Used to
/// refuse starting a second such operation while one is unfinished.
#[must_use]
pub fn any_op_in_progress(mkit_dir: &Path) -> bool {
    is_merge_in_progress(mkit_dir)
        || is_cherry_pick_in_progress(mkit_dir)
        || crate::ops::rebase::is_rebase_in_progress(mkit_dir)
}

/// Human-readable name of whichever op is in progress, for error text.
#[must_use]
pub fn in_progress_op_name(mkit_dir: &Path) -> Option<&'static str> {
    if is_merge_in_progress(mkit_dir) {
        Some("merge")
    } else if is_cherry_pick_in_progress(mkit_dir) {
        Some("cherry-pick")
    } else if crate::ops::rebase::is_rebase_in_progress(mkit_dir) {
        Some("rebase")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn h(seed: &str) -> Hash {
        hash::hash(seed.as_bytes())
    }

    #[test]
    fn conflict_records_round_trip() {
        let records = vec![
            ConflictRecord {
                path: "src/main.rs".into(),
                kind: ConflictKind::ModifyModify,
                base_hash: Some(h("b")),
                ours_hash: Some(h("o")),
                theirs_hash: Some(h("t")),
            },
            ConflictRecord {
                path: "new.txt".into(),
                kind: ConflictKind::AddAdd,
                base_hash: None,
                ours_hash: Some(h("o2")),
                theirs_hash: Some(h("t2")),
            },
            ConflictRecord {
                path: "gone.txt".into(),
                kind: ConflictKind::DeleteModify,
                base_hash: Some(h("b3")),
                ours_hash: None,
                theirs_hash: Some(h("t3")),
            },
        ];
        let bytes = serialize_conflicts(&records);
        let parsed = deserialize_conflicts(&bytes).unwrap();
        assert_eq!(parsed, records);
    }

    #[test]
    fn rejects_bad_kind() {
        let line = format!("bogus\t-\t{}\t-\tpath.txt\n", hash::to_hex(&h("o")));
        assert!(deserialize_conflicts(line.as_bytes()).is_err());
    }

    #[test]
    fn rejects_bad_path() {
        let line = format!("modify\t-\t{}\t-\t../escape\n", hash::to_hex(&h("o")));
        assert!(deserialize_conflicts(line.as_bytes()).is_err());
    }

    #[test]
    fn rejects_short_hex() {
        let line = "modify\tdeadbeef\t-\t-\tpath.txt\n";
        assert!(deserialize_conflicts(line.as_bytes()).is_err());
    }

    #[test]
    fn rejects_truncated_line() {
        let line = "modify\t-\t-\n";
        assert!(deserialize_conflicts(line.as_bytes()).is_err());
    }

    #[test]
    fn merge_state_round_trip() {
        let tmp = TempDir::new().unwrap();
        let mkit = tmp.path().join(".mkit");
        fs::create_dir_all(&mkit).unwrap();
        let state = MergeState {
            merge_head: h("theirs"),
            orig_head: h("orig"),
            message: b"Merge branch 'x'".to_vec(),
        };
        let conflicts = vec![ConflictRecord {
            path: "a.txt".into(),
            kind: ConflictKind::ModifyModify,
            base_hash: Some(h("b")),
            ours_hash: Some(h("o")),
            theirs_hash: Some(h("t")),
        }];
        write_merge_state(&mkit, &state, &conflicts).unwrap();
        assert!(is_merge_in_progress(&mkit));
        assert!(any_op_in_progress(&mkit));
        let read = read_merge_state(&mkit).unwrap().unwrap();
        assert_eq!(read, state);
        assert_eq!(read_conflicts(&mkit).unwrap(), conflicts);
        clear_merge_state(&mkit).unwrap();
        assert!(!is_merge_in_progress(&mkit));
        assert!(read_merge_state(&mkit).unwrap().is_none());
    }

    #[test]
    fn cherry_pick_state_round_trip() {
        let tmp = TempDir::new().unwrap();
        let mkit = tmp.path().join(".mkit");
        fs::create_dir_all(&mkit).unwrap();
        let state = CherryPickState {
            cherry_pick_head: h("pick"),
            orig_head: h("orig"),
            message: b"original message".to_vec(),
        };
        write_cherry_pick_state(&mkit, &state, &[]).unwrap();
        assert!(is_cherry_pick_in_progress(&mkit));
        let read = read_cherry_pick_state(&mkit).unwrap().unwrap();
        assert_eq!(read, state);
        clear_cherry_pick_state(&mkit).unwrap();
        assert!(!is_cherry_pick_in_progress(&mkit));
    }

    #[test]
    fn clear_is_idempotent() {
        let tmp = TempDir::new().unwrap();
        let mkit = tmp.path().join(".mkit");
        fs::create_dir_all(&mkit).unwrap();
        clear_merge_state(&mkit).unwrap();
        clear_cherry_pick_state(&mkit).unwrap();
    }
}
