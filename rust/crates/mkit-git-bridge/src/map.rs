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
    /// Stable on-disk / display token for this direction.
    #[must_use]
    pub fn as_str(self) -> &'static str {
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
    // Temp + content-fsync + rename + dir-fsync: stamps are bindings
    // (direction, signer, source, …) — a torn or vanished stamp after
    // power loss either wedges the state dir or silently unbinds it.
    let tmp = dir.join(format!(".{name}.tmp"));
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(format!("{value}\n").as_bytes())?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, dir.join(name))?;
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

/// Durable write of a named binding file (`source`, `dest`) — same
/// guarantees as the internal stamps.
pub fn write_binding(dir: &Path, name: &str, value: &str) -> Result<(), BridgeError> {
    write_stamp(dir, name, value)
}

/// Read the recorded direction, if stamped.
pub fn read_direction(dir: &Path) -> Result<Option<Direction>, BridgeError> {
    match read_stamp(dir, "direction")? {
        None => Ok(None),
        Some(v) => Direction::parse(&v).map(Some).ok_or_else(|| {
            // A present-but-unparsable stamp must NOT read as absent:
            // bind_direction would silently rebind a state dir whose
            // direction the spec pins as immutable (§6).
            BridgeError::Source(format!(
                "direction stamp is corrupt ({v:?}); refusing to guess — \
                 restore or remove the state dir"
            ))
        }),
    }
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
    match read_stamp(dir, "signer")? {
        None => Ok(None),
        Some(v) => crate::gitobj::bytes_from_hex(&v, 32)
            .map(|b| {
                let mut k = [0u8; 32];
                k.copy_from_slice(&b);
                Some(k)
            })
            .ok_or_else(|| {
                // Same rule as the direction stamp: corruption must
                // not silently unpin the importer key (§4).
                BridgeError::Source(
                    "signer stamp is corrupt; refusing to re-pin — restore or \
                     remove the state dir"
                        .into(),
                )
            }),
    }
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

/// Record that this state dir's imported history contains
/// historic-mode-normalized trees (SPEC-GIT-IMPORT §3.3). Sticky: a
/// normalized tree cannot reproduce its original sha1, so a later
/// import→fork upgrade must refuse (SPEC-GIT-BRIDGE §14.3 fork audit
/// would otherwise report false tampering forever).
pub fn mark_normalized(dir: &Path) -> Result<(), BridgeError> {
    write_stamp(dir, "normalized", "1")
}

/// Whether [`mark_normalized`] was ever stamped.
pub fn read_normalized(dir: &Path) -> Result<bool, BridgeError> {
    Ok(read_stamp(dir, "normalized")?.is_some())
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

/// Whether every non-empty line of the map file parses. A missing
/// file is intact (nothing to distrust). Any malformed line —
/// torn tail or mid-file corruption — means the cache may be
/// MISSING entries that recorded refs rely on, so callers must
/// rebuild rather than trust the surviving lines alone (§12.3).
pub fn map_is_intact(dir: &Path) -> Result<bool, BridgeError> {
    let path = dir.join(MAP_FILE);
    let data = match std::fs::read(&path) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(true),
        Err(e) => return Err(e.into()),
    };
    if std::str::from_utf8(&data).is_err() {
        return Ok(false);
    }
    let text = String::from_utf8_lossy(&data);
    for line in text.lines() {
        if line.is_empty() {
            // The format has no blank-line record: an internal blank
            // is a dropped mapping, not noise.
            return Ok(false);
        }
        let Some((b3, s1)) = line.split_once(' ') else {
            return Ok(false);
        };
        if from_hex(b3).is_err() || sha1_from_hex(s1).is_none() {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Load the map inverted (sha1 → blake3) for the import direction.
/// Parsed directly from the file lines: translation is many-to-one
/// (two historic-mode spellings of a tree normalize to ONE mkit
/// tree), so inverting the blake3-keyed [`load_map`] would drop a
/// sha1 and force a pointless re-translation every fetch.
pub fn load_map_inverse(dir: &Path) -> Result<HashMap<Sha1Id, Hash>, BridgeError> {
    let path = dir.join(MAP_FILE);
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
        map.insert(id, h);
    }
    Ok(map)
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
    // Per-target temp name: `refs` and `refs-import` rewrites must
    // not race each other onto one temp path (fetch + export can run
    // concurrently against a fork state dir).
    let tmp = dir.join(format!(".{file}.tmp"));
    {
        use std::io::Write as _;
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(out.as_bytes())?;
        // Content fsync before rename: this file is the lease /
        // tracking source of truth, and a durable name over torn
        // pages would be worse than the old file.
        f.sync_all()?;
    }
    std::fs::rename(&tmp, dir.join(file))?;
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
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
    fn map_intact_detection() {
        let dir = tempfile::tempdir().unwrap();
        // Missing file: intact (nothing to distrust).
        assert!(map_is_intact(dir.path()).unwrap());
        let pairs = vec![([1u8; 32], [2u8; 20]), ([3u8; 32], [4u8; 20])];
        append_map(dir.path(), &pairs).unwrap();
        assert!(map_is_intact(dir.path()).unwrap());
        // Malformed line.
        let good = std::fs::read_to_string(dir.path().join("map")).unwrap();
        std::fs::write(dir.path().join("map"), format!("{good}GARBAGE\n")).unwrap();
        assert!(!map_is_intact(dir.path()).unwrap());
        // Internal blank line (a dropped record, not noise).
        let lines: Vec<&str> = good.lines().collect();
        std::fs::write(
            dir.path().join("map"),
            format!("{}\n\n{}\n", lines[0], lines[1]),
        )
        .unwrap();
        assert!(!map_is_intact(dir.path()).unwrap());
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
