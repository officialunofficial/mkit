//! blake3↔sha1 mapping cache and per-remote export state
//! (SPEC-GIT-BRIDGE §12.3).
//!
//! Everything here is a **disposable cache**: translation is
//! deterministic, so a missing or corrupt file means "rebuild", never
//! an error. The map file is append-only text (`<64hex> <40hex>\n`);
//! a torn final line (crash mid-append) is detected and ignored on
//! load. Ref state is rewritten whole via temp-file + rename.

use crate::error::BridgeError;
use crate::gitobj::{Sha1Id, sha1_from_hex, sha1_hex};
use mkit_core::Hash;
use mkit_core::hash::{from_hex, to_hex};
use std::collections::HashMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};

/// `.mkit/git/<remote>/` — the per-remote bridge state directory.
/// Remote names are restricted to the mkit ref-segment charset so the
/// directory name is always safe.
pub fn state_dir(mkit_dir: &Path, remote: &str) -> Result<PathBuf, BridgeError> {
    if remote.is_empty()
        || !remote
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
        || remote == "."
        || remote == ".."
    {
        return Err(BridgeError::Source(format!(
            "remote name {remote:?} is not a valid bridge state name"
        )));
    }
    Ok(mkit_dir.join("git").join(remote))
}

const MAP_FILE: &str = "map";
const REFS_FILE: &str = "refs";
const IMPORT_REFS_FILE: &str = "refs-import";

/// Recorded direction of a state dir (SPEC-GIT-IMPORT §6): one dir
/// serves one direction; `fork` couples an import source with
/// passthrough export. Immutable once stamped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Import,
    Export,
    Fork,
}

impl Direction {
    fn as_str(self) -> &'static str {
        match self {
            Self::Import => "import",
            Self::Export => "export",
            Self::Fork => "fork",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "import" => Self::Import,
            "export" => Self::Export,
            "fork" => Self::Fork,
            _ => return None,
        })
    }
}

fn read_stamp(dir: &Path, name: &str) -> Result<Option<String>, BridgeError> {
    match std::fs::read_to_string(dir.join(name)) {
        Ok(v) => Ok(Some(v.trim().to_owned())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

fn write_stamp(dir: &Path, name: &str, value: &str) -> Result<(), BridgeError> {
    std::fs::create_dir_all(dir)?;
    std::fs::write(dir.join(name), format!("{value}\n"))?;
    Ok(())
}

/// Read the recorded direction, if stamped.
pub fn read_direction(dir: &Path) -> Result<Option<Direction>, BridgeError> {
    Ok(read_stamp(dir, "direction")?
        .as_deref()
        .and_then(Direction::parse))
}

/// Stamp the direction, or verify it matches an existing stamp.
/// `Export → Fork` upgrades are refused like any other mismatch (the
/// map semantics differ); `Import → Fork` is the supported upgrade
/// (fork = import + passthrough export over the same source).
pub fn bind_direction(dir: &Path, want: Direction) -> Result<(), BridgeError> {
    match read_direction(dir)? {
        None => write_stamp(dir, "direction", want.as_str()),
        Some(have) if have == want => Ok(()),
        Some(Direction::Import) if want == Direction::Fork => {
            write_stamp(dir, "direction", want.as_str())
        }
        Some(have) => Err(BridgeError::Source(format!(
            "state dir is bound to direction '{}'; '{}' is not allowed here \
             (one direction per state dir — use a different --remote-name)",
            have.as_str(),
            want.as_str()
        ))),
    }
}

/// Read the pinned importer pubkey (64 lowercase hex), if stamped.
pub fn read_signer(dir: &Path) -> Result<Option<[u8; 32]>, BridgeError> {
    Ok(read_stamp(dir, "signer")?
        .as_deref()
        .and_then(|s| crate::gitobj::bytes_from_hex(s, 32))
        .map(|v| {
            let mut k = [0u8; 32];
            k.copy_from_slice(&v);
            k
        }))
}

/// Pin the importer key, or refuse a mismatch (SPEC-GIT-IMPORT §4).
pub fn bind_signer(dir: &Path, key: &[u8; 32]) -> Result<(), BridgeError> {
    match read_signer(dir)? {
        None => write_stamp(dir, "signer", &crate::gitobj::bytes_hex(key)),
        Some(have) if have == *key => Ok(()),
        Some(have) => Err(BridgeError::Source(format!(
            "this import is pinned to importer key {}…; the available key is {}…. \
             Designated-importer model: pull this history over mkit transport from \
             the importer, or install the pinned key (SPEC-GIT-IMPORT §4)",
            &crate::gitobj::bytes_hex(&have)[..16],
            &crate::gitobj::bytes_hex(key)[..16]
        ))),
    }
}

/// Read / pin the import-spec version (SPEC-GIT-IMPORT §1.2).
pub fn bind_import_spec(dir: &Path, version: u32) -> Result<(), BridgeError> {
    match read_stamp(dir, "import-spec")? {
        None => write_stamp(dir, "import-spec", &version.to_string()),
        Some(v) if v == version.to_string() => Ok(()),
        Some(v) => Err(BridgeError::Source(format!(
            "state recorded import-spec {v}, this build implements {version}; \
             incremental pulls across mapping versions are refused — re-import \
             under a new --remote-name (SPEC-GIT-IMPORT §1.2)"
        ))),
    }
}

/// Load the map inverted (sha1 → blake3) for the import direction.
pub fn load_map_inverse(dir: &Path) -> Result<HashMap<Sha1Id, Hash>, BridgeError> {
    Ok(load_map(dir)?
        .into_iter()
        .map(|(blake3, sha1)| (sha1, blake3))
        .collect())
}

/// Append pairs given in import orientation (sha1, blake3) — the file
/// format stays blake3-first either way.
pub fn append_map_import(dir: &Path, pairs: &[(Sha1Id, Hash)]) -> Result<(), BridgeError> {
    let flipped: Vec<(Hash, Sha1Id)> = pairs.iter().map(|(s, b)| (*b, *s)).collect();
    append_map(dir, &flipped)
}

/// Load the blake3→sha1 map. Missing file = empty map. Lines that do
/// not parse (torn tail from a crash) are ignored.
pub fn load_map(dir: &Path) -> Result<HashMap<Hash, Sha1Id>, BridgeError> {
    let path = dir.join(MAP_FILE);
    // §12.3: corruption (including undecodable bytes) means "rebuild",
    // never an error — lossy decoding turns garbage into skipped lines.
    let data = match std::fs::read(&path) {
        Ok(d) => String::from_utf8_lossy(&d).into_owned(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(e) => return Err(e.into()),
    };
    let mut map = HashMap::new();
    for line in data.lines() {
        let Some((b3, s1)) = line.split_once(' ') else {
            continue;
        };
        let (Ok(h), Some(id)) = (from_hex(b3), sha1_from_hex(s1)) else {
            continue;
        };
        map.insert(h, id);
    }
    Ok(map)
}

/// Append newly translated pairs. Append-only by design: entries for
/// rewritten-away commits stay valid forever (determinism), so no
/// compaction or invalidation exists (§12.2).
pub fn append_map(dir: &Path, pairs: &[(Hash, Sha1Id)]) -> Result<(), BridgeError> {
    if pairs.is_empty() {
        return Ok(());
    }
    std::fs::create_dir_all(dir)?;
    let mut out = String::new();
    for (h, id) in pairs {
        out.push_str(&to_hex(h));
        out.push(' ');
        out.push_str(&sha1_hex(id));
        out.push('\n');
    }
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join(MAP_FILE))?;
    f.write_all(out.as_bytes())?;
    f.sync_all()?;
    Ok(())
}

/// Last-exported state for one ref: what the bridge last pushed.
/// Used as the `--force-with-lease` expectation (§12.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefState {
    pub ref_name: String,
    pub mkit_hash: Hash,
    pub git_id: Sha1Id,
}

/// Load per-ref EXPORT state (push leases). Missing file = empty.
pub fn load_ref_state(dir: &Path) -> Result<Vec<RefState>, BridgeError> {
    load_ref_state_file(dir, REFS_FILE)
}

/// Load per-ref IMPORT state (last-seen upstream tips). Kept separate
/// from the export leases: in a fork-mode state dir both directions
/// track the same ref names against different remotes.
pub fn load_import_ref_state(dir: &Path) -> Result<Vec<RefState>, BridgeError> {
    load_ref_state_file(dir, IMPORT_REFS_FILE)
}

fn load_ref_state_file(dir: &Path, file: &str) -> Result<Vec<RefState>, BridgeError> {
    let path = dir.join(file);
    let data = match std::fs::read(&path) {
        Ok(d) => String::from_utf8_lossy(&d).into_owned(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    let mut out = Vec::new();
    for line in data.lines() {
        let mut parts = line.splitn(3, ' ');
        let (Some(name), Some(b3), Some(s1)) = (parts.next(), parts.next(), parts.next()) else {
            continue;
        };
        let (Ok(h), Some(id)) = (from_hex(b3), sha1_from_hex(s1)) else {
            continue;
        };
        out.push(RefState {
            ref_name: name.to_owned(),
            mkit_hash: h,
            git_id: id,
        });
    }
    Ok(out)
}

/// Rewrite the whole export ref-state file atomically (temp + rename).
pub fn store_ref_state(dir: &Path, states: &[RefState]) -> Result<(), BridgeError> {
    store_ref_state_file(dir, REFS_FILE, states)
}

/// Rewrite the import ref-state file (see [`load_import_ref_state`]).
pub fn store_import_ref_state(dir: &Path, states: &[RefState]) -> Result<(), BridgeError> {
    store_ref_state_file(dir, IMPORT_REFS_FILE, states)
}

fn store_ref_state_file(dir: &Path, file: &str, states: &[RefState]) -> Result<(), BridgeError> {
    std::fs::create_dir_all(dir)?;
    let mut out = String::new();
    for s in states {
        out.push_str(&s.ref_name);
        out.push(' ');
        out.push_str(&to_hex(&s.mkit_hash));
        out.push(' ');
        out.push_str(&sha1_hex(&s.git_id));
        out.push('\n');
    }
    let tmp = dir.join(".refs.tmp");
    std::fs::write(&tmp, out.as_bytes())?;
    std::fs::rename(&tmp, dir.join(file))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_round_trips_and_tolerates_torn_tail() {
        let dir = tempfile::tempdir().unwrap();
        let pairs = vec![([1u8; 32], [2u8; 20]), ([3u8; 32], [4u8; 20])];
        append_map(dir.path(), &pairs).unwrap();
        // Simulate a torn append.
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(dir.path().join(MAP_FILE))
            .unwrap();
        f.write_all(b"deadbeef").unwrap();
        drop(f);
        let map = load_map(dir.path()).unwrap();
        assert_eq!(map.len(), 2);
        assert_eq!(map[&[1u8; 32]], [2u8; 20]);
    }

    #[test]
    fn ref_state_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let states = vec![RefState {
            ref_name: "refs/heads/main".into(),
            mkit_hash: [7; 32],
            git_id: [9; 20],
        }];
        store_ref_state(dir.path(), &states).unwrap();
        assert_eq!(load_ref_state(dir.path()).unwrap(), states);
    }

    #[test]
    fn state_dir_rejects_traversal() {
        let mkit = Path::new("/tmp/.mkit");
        assert!(state_dir(mkit, "origin").is_ok());
        assert!(state_dir(mkit, "..").is_err());
        assert!(state_dir(mkit, "a/b").is_err());
        assert!(state_dir(mkit, "").is_err());
    }
}
