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

/// Load the blake3→sha1 map. Missing file = empty map. Lines that do
/// not parse (torn tail from a crash) are ignored.
pub fn load_map(dir: &Path) -> Result<HashMap<Hash, Sha1Id>, BridgeError> {
    let path = dir.join(MAP_FILE);
    let data = match std::fs::read_to_string(&path) {
        Ok(d) => d,
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

/// Load per-ref state. Missing file = empty.
pub fn load_ref_state(dir: &Path) -> Result<Vec<RefState>, BridgeError> {
    let path = dir.join(REFS_FILE);
    let data = match std::fs::read_to_string(&path) {
        Ok(d) => d,
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

/// Rewrite the whole ref-state file atomically (temp + rename).
pub fn store_ref_state(dir: &Path, states: &[RefState]) -> Result<(), BridgeError> {
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
    std::fs::rename(&tmp, dir.join(REFS_FILE))?;
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
