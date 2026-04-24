//! On-disk store for DSSE attestation envelopes.
//!
//! See `docs/SPEC-ATTESTATIONS.md` §3. Layout (rooted at `<root>` —
//! typically `.mkit/`, NOT the `attestations/` subdir):
//!
//! ```text
//! <root>/
//!   attestations/
//!     <64-hex-commit>/
//!       <64-hex-att-id>.dsse
//! ```
//!
//! Envelope bytes are written exactly as supplied (no trailing newline
//! is appended). The att-id is `BLAKE3(envelope_bytes)`, which makes
//! the filename a stable, content-addressed function of the envelope —
//! re-writing identical bytes is a no-op (idempotent via stat).
//!
//! Durability mirrors `mkit-core::store`:
//! `tempfile::NamedTempFile::persist` (atomic rename) plus an
//! Unix-only `fsync` of the containing commit directory afterwards so
//! the dirent update survives a power loss.

use std::fs;
#[cfg(unix)]
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicU64, Ordering};

use tempfile::NamedTempFile;

use crate::Error;
use crate::envelope as env_mod;
use mkit_core::Hash;
use mkit_core::hash::{self as hash_mod, HEX_LEN};

/// Directory under `<root>` that owns every envelope on disk.
pub const SUBDIR: &str = "attestations";

/// Envelope file extension. Keep in sync with SPEC-ATTESTATIONS §3.
pub const FILE_EXT: &str = ".dsse";

/// Safety cap on a single envelope read. A well-formed envelope with a
/// few signatures is well under a kilobyte; even an absurd multi-sig
/// case stays in the low tens of kilobytes. 1 MiB is a generous ceiling.
pub const MAX_ENVELOPE_SIZE: usize = 1024 * 1024;

/// Build the path for a given commit + att-id under `root`.
///
/// `root` is the `.mkit/` directory (the `attestations/` subdir is
/// appended internally).
#[must_use]
pub fn envelope_path(root: &Path, commit: &Hash, att_id: &Hash) -> PathBuf {
    root.join(SUBDIR)
        .join(hash_mod::to_hex(commit))
        .join(format!("{}{}", hash_mod::to_hex(att_id), FILE_EXT))
}

/// Save a DSSE envelope under `root` for `commit`.
///
/// Returns the `(att_id, full_path)` pair. Idempotent via content-
/// addressing: identical bytes for the same commit produce the same
/// path and skip the write.
///
/// # Errors
/// * [`Error::EnvelopeTooLarge`] if `bytes.len() > MAX_ENVELOPE_SIZE`.
/// * [`Error::Io`] on filesystem failures.
///
/// # Panics
/// Panics if `envelope_path` (an internal helper) returns a path with
/// no parent or no file name. Both invariants are upheld by the path
/// builder, so this only fires on programmer error.
pub fn save(root: &Path, commit: &Hash, bytes: &[u8]) -> Result<(Hash, PathBuf), Error> {
    if bytes.len() > MAX_ENVELOPE_SIZE {
        return Err(Error::EnvelopeTooLarge {
            len: bytes.len(),
            max: MAX_ENVELOPE_SIZE,
        });
    }
    let att_id = env_mod::attestation_id(bytes);
    let final_path = envelope_path(root, commit, &att_id);

    // Idempotency: filename IS the BLAKE3 of the bytes, so presence
    // implies equality. One stat beats a full read+compare.
    if final_path.exists() {
        return Ok((att_id, final_path));
    }

    let parent = final_path.parent().expect("envelope_path has parent");
    fs::create_dir_all(parent).map_err(|e| Error::Io(format!("mkdir: {e}")))?;

    write_atomic(&final_path, bytes)?;
    Ok((att_id, final_path))
}

/// Load an envelope by absolute path (typically returned by [`list`] or
/// [`save`]).
///
/// # Errors
/// * [`Error::EnvelopeTooLarge`] if the file exceeds `MAX_ENVELOPE_SIZE`.
/// * [`Error::Io`] on read failure (incl. not-found).
pub fn load(path: &Path) -> Result<env_mod::Envelope, Error> {
    let meta =
        fs::metadata(path).map_err(|e| Error::Io(format!("stat {}: {e}", path.display())))?;
    // Cast via try_from so 32-bit targets can't truncate the size check.
    let size_usize = usize::try_from(meta.len()).unwrap_or(usize::MAX);
    if size_usize > MAX_ENVELOPE_SIZE {
        return Err(Error::EnvelopeTooLarge {
            len: size_usize,
            max: MAX_ENVELOPE_SIZE,
        });
    }
    let bytes = fs::read(path).map_err(|e| Error::Io(format!("read {}: {e}", path.display())))?;
    env_mod::decode(&bytes)
}

/// List every envelope path attached to `commit`, sorted ascending by
/// att-id (byte-wise on the raw 32-byte hash).
///
/// An unattested commit returns an empty `Vec` — NOT an error, per
/// SPEC-ATTESTATIONS §7.1.
///
/// # Errors
/// * [`Error::Io`] on directory read failure other than not-found.
pub fn list(root: &Path, commit: &Hash) -> Result<Vec<PathBuf>, Error> {
    let commit_dir = root.join(SUBDIR).join(hash_mod::to_hex(commit));
    let read_dir = match fs::read_dir(&commit_dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(Error::Io(format!("readdir {}: {e}", commit_dir.display()))),
    };

    // Collect (att_id, path) so we can sort by hash.
    let mut entries: Vec<(Hash, PathBuf)> = Vec::new();
    for entry in read_dir {
        let entry = entry.map_err(|e| Error::Io(format!("readdir entry: {e}")))?;
        if !entry.file_type().is_ok_and(|t| t.is_file()) {
            continue;
        }
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        let Some(id) = parse_att_filename(name_str) else {
            continue;
        };
        entries.push((id, entry.path()));
    }
    entries.sort_by_key(|e| e.0);
    Ok(entries.into_iter().map(|(_, p)| p).collect())
}

/// Remove a single attestation. Idempotent: removing a non-existent
/// att-id (or a commit that has no attestations at all) returns
/// successfully. When the commit directory becomes empty, it is
/// removed as well — tolerating `DirNotEmpty` if a concurrent writer
/// landed a new envelope in the interim.
///
/// # Errors
/// * [`Error::Io`] on filesystem failures other than not-found / dir-
///   not-empty during cleanup.
pub fn remove(root: &Path, commit: &Hash, att_id: &Hash) -> Result<(), Error> {
    let final_path = envelope_path(root, commit, att_id);
    match fs::remove_file(&final_path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(Error::Io(format!("rm {}: {e}", final_path.display()))),
    }
    // Try to GC the now-possibly-empty commit dir.
    let commit_dir = root.join(SUBDIR).join(hash_mod::to_hex(commit));
    match fs::remove_dir(&commit_dir) {
        Ok(()) => {}
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::DirectoryNotEmpty
            ) => {}
        Err(e) => return Err(Error::Io(format!("rmdir {}: {e}", commit_dir.display()))),
    }
    Ok(())
}

// -- internals --

/// Parse `<64-hex-of-att-id>.dsse` → att-id, or return `None`.
fn parse_att_filename(name: &str) -> Option<Hash> {
    let stem = name.strip_suffix(FILE_EXT)?;
    if stem.len() != HEX_LEN {
        return None;
    }
    hash_mod::from_hex(stem).ok()
}

static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

fn write_atomic(final_path: &Path, bytes: &[u8]) -> Result<(), Error> {
    let parent = final_path.parent().expect("final_path has parent");
    let file_name = final_path
        .file_name()
        .expect("final_path has file name")
        .to_string_lossy();
    let pid = process::id();
    let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp_prefix = format!(".{file_name}.tmp.{pid}.{seq}");

    let mut tmp = NamedTempFile::with_prefix_in(tmp_prefix, parent)
        .map_err(|e| Error::Io(format!("tmpfile: {e}")))?;
    tmp.as_file_mut()
        .write_all(bytes)
        .map_err(|e| Error::Io(format!("write tmp: {e}")))?;
    tmp.as_file_mut()
        .sync_all()
        .map_err(|e| Error::Io(format!("fsync tmp: {e}")))?;
    tmp.persist(final_path)
        .map_err(|e| Error::Io(format!("persist: {}", e.error)))?;
    sync_parent_dir(parent)?;
    Ok(())
}

#[cfg(unix)]
fn sync_parent_dir(parent: &Path) -> Result<(), Error> {
    match File::open(parent) {
        Ok(dir) => dir
            .sync_all()
            .map_err(|e| Error::Io(format!("fsync dir: {e}"))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Error::Io(format!("open dir: {e}"))),
    }
}

#[cfg(not(unix))]
fn sync_parent_dir(_parent: &Path) -> Result<(), Error> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{Envelope, Sig};

    fn fake_hash(seed: u8) -> Hash {
        let mut h = [0u8; 32];
        for (i, b) in h.iter_mut().enumerate() {
            *b = seed.wrapping_add(u8::try_from(i).unwrap_or(0));
        }
        h
    }

    fn small_envelope(tag: &[u8]) -> (Vec<u8>, Hash) {
        let env = Envelope {
            payload_type: env_mod::PAYLOAD_TYPE_IN_TOTO.into(),
            payload: tag.to_vec(),
            signatures: vec![Sig {
                keyid: "blake3:aa".into(),
                sig: vec![1, 2, 3],
            }],
        };
        let bytes = env.encode().unwrap();
        let id = env_mod::attestation_id(bytes.as_bytes());
        (bytes.into_bytes(), id)
    }

    #[test]
    fn write_read_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let commit = fake_hash(0x11);
        let (bytes, expected_id) = small_envelope(b"{\"k\":1}");

        let (att_id, path) = save(dir.path(), &commit, &bytes).unwrap();
        assert_eq!(att_id, expected_id);
        assert!(path.exists());

        let env = load(&path).unwrap();
        assert_eq!(env.payload, b"{\"k\":1}");
    }

    #[test]
    fn write_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let commit = fake_hash(0x22);
        let (bytes, _) = small_envelope(b"hello");

        let (a, _) = save(dir.path(), &commit, &bytes).unwrap();
        let (b, _) = save(dir.path(), &commit, &bytes).unwrap();
        assert_eq!(a, b);

        let listed = list(dir.path(), &commit).unwrap();
        assert_eq!(listed.len(), 1);
    }

    #[test]
    fn list_returns_sorted_ids() {
        let dir = tempfile::tempdir().unwrap();
        let commit = fake_hash(0x33);

        let mut written: Vec<Hash> = Vec::new();
        for i in 0..5 {
            let (bytes, id) = small_envelope(format!("env-{i}").as_bytes());
            let (got, _) = save(dir.path(), &commit, &bytes).unwrap();
            assert_eq!(got, id);
            written.push(id);
        }

        let listed = list(dir.path(), &commit).unwrap();
        assert_eq!(listed.len(), 5);

        // Sorted ascending byte-wise on filename stem.
        let mut last: Option<String> = None;
        for p in &listed {
            let name = p.file_name().unwrap().to_string_lossy().to_string();
            if let Some(prev) = last {
                assert!(prev < name, "{prev} < {name}");
            }
            last = Some(name);
        }
        for w in written {
            let stem = format!("{}{}", hash_mod::to_hex(&w), FILE_EXT);
            assert!(listed.iter().any(|p| p.file_name().unwrap() == &*stem));
        }
    }

    #[test]
    fn list_on_unattested_commit_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let commit = fake_hash(0x44);
        let listed = list(dir.path(), &commit).unwrap();
        assert!(listed.is_empty());
    }

    #[test]
    fn remove_is_idempotent_on_missing() {
        let dir = tempfile::tempdir().unwrap();
        let commit = fake_hash(0x66);
        let missing = fake_hash(0x77);
        // No attestations dir at all.
        remove(dir.path(), &commit, &missing).unwrap();

        // Commit dir exists but specific id doesn't.
        let (bytes, _) = small_envelope(b"present");
        let _ = save(dir.path(), &commit, &bytes).unwrap();
        remove(dir.path(), &commit, &missing).unwrap();

        let listed = list(dir.path(), &commit).unwrap();
        assert_eq!(listed.len(), 1);
    }

    #[test]
    fn remove_cleans_up_empty_commit_dir() {
        let dir = tempfile::tempdir().unwrap();
        let commit = fake_hash(0x99);
        let (bytes, _) = small_envelope(b"only one");
        let (att_id, _) = save(dir.path(), &commit, &bytes).unwrap();
        remove(dir.path(), &commit, &att_id).unwrap();

        let listed = list(dir.path(), &commit).unwrap();
        assert!(listed.is_empty());

        let commit_dir = dir.path().join(SUBDIR).join(hash_mod::to_hex(&commit));
        assert!(!commit_dir.exists());
    }

    #[test]
    fn list_ignores_non_dsse_and_non_hex_stems() {
        let dir = tempfile::tempdir().unwrap();
        let commit = fake_hash(0xAA);
        let (bytes, good_id) = small_envelope(b"legit");
        let _ = save(dir.path(), &commit, &bytes).unwrap();

        let commit_dir = dir.path().join(SUBDIR).join(hash_mod::to_hex(&commit));
        // Wrong extension.
        fs::write(commit_dir.join("notes.txt"), b"x").unwrap();
        // Right extension, wrong-shaped stem.
        fs::write(commit_dir.join("zzz.dsse"), b"x").unwrap();
        // Right length, non-hex stem.
        let bad = format!("{}{FILE_EXT}", "g".to_string() + &"0".repeat(63));
        fs::write(commit_dir.join(bad), b"x").unwrap();

        let listed = list(dir.path(), &commit).unwrap();
        assert_eq!(listed.len(), 1);
        let want = format!("{}{FILE_EXT}", hash_mod::to_hex(&good_id));
        assert_eq!(listed[0].file_name().unwrap(), want.as_str());
    }
}
