//! Refs subsystem.
//!
//! Implements the local-disk side of `docs/SPEC-REFS.md`: ref names,
//! the 65-byte wire encoding, the symbolic-or-detached `HEAD` file, and
//! shallow-boundary persistence at `.mkit/shallow`.
//!
//! Wire format (per SPEC-REFS §1): exactly 64 lowercase-hex characters
//! plus a trailing `0x0A` newline = 65 bytes. Uppercase hex is rejected
//! on read. Trailing `\r` and ASCII whitespace are tolerated when
//! parsing local files (so a Windows-edited HEAD does not brick a
//! repo), but fresh writes always emit the strict 65-byte form.
//!
//! Ref name grammar (SPEC-REFS §3): `[A-Za-z0-9._-]+` segments joined
//! by `/`, with no leading/trailing `/`, no `.`/`..` segments, no
//! backslashes, no NULs. We share the validator with the future
//! transport layer via [`validate_ref_name`] / [`validate_ref_prefix`].
//!
//! CAS variants for [`update_ref`] follow SPEC-REFS §5: `Any` (clobber),
//! `Missing` (fail if it exists), `Match(H)` (fail if current value !=
//! H). The local-filesystem `Match` is **not atomic** across processes
//! — that is the documented v1 gap; transports that need true atomicity
//! must use s3/http/ssh.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::atomic::{write_atomic, write_create_new};
use crate::hash::{HASH_LEN, HEX_LEN, Hash, to_hex};

/// Subdirectory holding all refs (`.mkit/refs`).
pub const REFS_DIR: &str = "refs";
/// Subdirectory holding branch refs (`.mkit/refs/heads`).
pub const HEADS_DIR: &str = "refs/heads";
/// Subdirectory holding tag refs (`.mkit/refs/tags`).
pub const TAGS_DIR: &str = "refs/tags";
/// HEAD file relative to the `.mkit` root.
pub const HEAD_FILE: &str = "HEAD";
/// Shallow-boundary file relative to the `.mkit` root.
pub const SHALLOW_FILE: &str = "shallow";

/// Symbolic-ref prefix written to `HEAD` when pointing at a branch.
const HEAD_REF_PREFIX: &str = "ref: refs/heads/";

/// Hard cap on how many bytes we are willing to read from `HEAD`.
const HEAD_MAX_BYTES: u64 = 4 * 1024;
/// Hard cap on how many bytes we are willing to read from a single ref
/// file. The wire form is always 65 bytes; a few more is fine if the
/// file picked up extra whitespace, but anything pathological is
/// rejected.
const REF_FILE_MAX_BYTES: u64 = 128;
/// Hard cap on `.mkit/shallow` (1 MiB).
const SHALLOW_MAX_BYTES: u64 = 1024 * 1024;

/// Errors raised by this module.
#[derive(Debug, thiserror::Error)]
pub enum RefError {
    /// `name` failed [`validate_ref_name`].
    #[error("invalid ref name '{0}'")]
    InvalidRefName(String),
    /// On-disk bytes were not a valid 65-byte ref wire (length wrong,
    /// uppercase hex, non-hex byte, etc.).
    #[error("invalid ref content for '{0}'")]
    InvalidRef(String),
    /// `HEAD` content was neither a valid symbolic ref nor a valid
    /// detached hash.
    #[error("HEAD is not a valid symbolic-ref or detached-hash file")]
    InvalidHead,
    /// `HEAD` is missing.
    #[error("HEAD is not present")]
    NoHead,
    /// CAS condition failed: ref does not match expected state.
    #[error("ref '{0}' did not satisfy CAS condition")]
    Conflict(String),
    /// Tried to delete a ref that does not exist.
    #[error("ref '{0}' not found")]
    NotFound(String),
    /// Tried to delete the branch HEAD currently points to.
    #[error("cannot delete the current branch '{0}'")]
    CurrentBranch(String),
    /// Underlying I/O failure.
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Result alias used throughout this module.
pub type RefResult<T> = Result<T, RefError>;

/// CAS condition for [`update_ref`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefWriteCondition {
    /// Unconditional write — clobbers any existing value.
    Any,
    /// Write only if the ref does not currently exist.
    Missing,
    /// Write only if the ref currently contains this exact hash.
    Match(Hash),
}

/// HEAD pointer: either a symbolic reference to a branch name, or a
/// detached hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Head {
    /// Symbolic — `HEAD` was `ref: refs/heads/<branch>\n`.
    Branch(String),
    /// Detached — `HEAD` was a bare 64-char hex hash.
    Detached(Hash),
}

/// A listed ref entry: name (with `refs/heads/` or similar prefix
/// stripped) plus the resolved hash, when readable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ref {
    /// Ref name relative to the namespace (e.g. `"main"`, `"v1.0"`).
    pub name: String,
    /// Resolved 32-byte hash, or `None` if the on-disk bytes were
    /// malformed (the entry is then silently skipped by callers that
    /// only care about valid refs).
    pub hash: Option<Hash>,
}

/// Validate a ref name per SPEC-REFS §3. Used at every transport
/// boundary; transports MUST NOT silently lower-case or canonicalise.
///
/// Grammar:
/// - Non-empty.
/// - Segments split on `/`, each segment matches `[A-Za-z0-9._-]+`.
/// - No `.` or `..` segments. No empty segments (no `//`, no leading
///   `/`, no trailing `/`).
/// - No `\\` or NUL bytes.
#[must_use]
pub fn validate_ref_name(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    if name.starts_with('/') {
        return false;
    }
    for part in name.split('/') {
        if part.is_empty() {
            return false;
        }
        if part == "." || part == ".." {
            return false;
        }
        for &c in part.as_bytes() {
            if c == 0 || c == b'\\' {
                return false;
            }
            let allowed = c.is_ascii_alphanumeric() || c == b'.' || c == b'_' || c == b'-';
            if !allowed {
                return false;
            }
        }
    }
    true
}

/// Validate a prefix passed to `list_refs`. An empty prefix is allowed.
/// A single trailing `/` is allowed; otherwise the prefix must satisfy
/// [`validate_ref_name`].
#[must_use]
pub fn validate_ref_prefix(prefix: &str) -> bool {
    if prefix.is_empty() {
        return true;
    }
    let trimmed = prefix.trim_end_matches('/');
    if trimmed.is_empty() {
        return false;
    }
    validate_ref_name(trimmed)
}

/// Encode `h` to its 65-byte wire form (lowercase hex + `\n`).
#[must_use]
pub fn encode_ref_wire(h: &Hash) -> [u8; 65] {
    let hex = to_hex(h);
    let bytes = hex.as_bytes();
    let mut out = [0u8; 65];
    out[..HEX_LEN].copy_from_slice(bytes);
    out[HEX_LEN] = b'\n';
    out
}

/// Decode a ref wire blob into a [`Hash`]. Tolerates a trailing
/// newline / `\r` / ASCII whitespace (so files round-tripped through a
/// Windows editor still parse), but rejects uppercase hex per
/// SPEC-REFS §1.
///
/// Returns `None` for any malformed input; callers wrap the absent
/// case into a domain-specific [`RefError::InvalidRef`].
#[must_use]
pub fn decode_ref_wire(data: &[u8]) -> Option<Hash> {
    let s = core::str::from_utf8(data).ok()?;
    let trimmed = s.trim_end_matches(['\n', '\r', ' ', '\t']);
    if trimmed.len() != HEX_LEN {
        return None;
    }
    parse_lowercase_hash(trimmed.as_bytes())
}

/// Strict lowercase-only hex parser. SPEC-REFS §1 forbids uppercase on
/// read; the general [`hash::from_hex`] tolerates both cases for
/// programmatic callers, so we hand-roll a stricter variant here.
fn parse_lowercase_hash(bytes: &[u8]) -> Option<Hash> {
    if bytes.len() != HEX_LEN {
        return None;
    }
    let mut out = [0u8; HASH_LEN];
    for i in 0..HASH_LEN {
        let hi = lowercase_nibble(bytes[i * 2])?;
        let lo = lowercase_nibble(bytes[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn lowercase_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(10 + (b - b'a')),
        _ => None,
    }
}

/// Initialise the ref directory layout under `mkit_dir` (the
/// `.mkit/` directory). Creates the `refs/`, `refs/heads/`,
/// `refs/tags/` subdirectories and writes a default
/// `HEAD = ref: refs/heads/main\n` if `HEAD` does not already exist.
pub fn init(mkit_dir: &Path) -> RefResult<()> {
    fs::create_dir_all(mkit_dir.join(REFS_DIR))?;
    fs::create_dir_all(mkit_dir.join(HEADS_DIR))?;
    fs::create_dir_all(mkit_dir.join(TAGS_DIR))?;
    let head_path = mkit_dir.join(HEAD_FILE);
    if !head_path.exists() {
        let body = format!("{HEAD_REF_PREFIX}main\n");
        write_atomic(&head_path, body.as_bytes(), false)?;
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// HEAD
// -----------------------------------------------------------------------------

/// Read `HEAD` from `<mkit_dir>/HEAD`.
///
/// # Errors
/// - [`RefError::NoHead`] if the file is missing.
/// - [`RefError::InvalidHead`] for malformed content.
pub fn read_head(mkit_dir: &Path) -> RefResult<Head> {
    let path = mkit_dir.join(HEAD_FILE);
    let meta = match fs::metadata(&path) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(RefError::NoHead),
        Err(e) => return Err(RefError::Io(e)),
    };
    if meta.len() > HEAD_MAX_BYTES {
        return Err(RefError::InvalidHead);
    }
    let raw = fs::read(&path)?;
    let s = core::str::from_utf8(&raw).map_err(|_| RefError::InvalidHead)?;
    let trimmed = s.trim_end_matches(['\n', '\r', ' ', '\t']);
    if let Some(branch) = trimmed.strip_prefix(HEAD_REF_PREFIX) {
        if !validate_ref_name(branch) {
            return Err(RefError::InvalidHead);
        }
        return Ok(Head::Branch(branch.to_string()));
    }
    if trimmed.len() == HEX_LEN {
        let h = parse_lowercase_hash(trimmed.as_bytes()).ok_or(RefError::InvalidHead)?;
        return Ok(Head::Detached(h));
    }
    Err(RefError::InvalidHead)
}

/// Write `HEAD` as a symbolic ref pointing at `branch`.
///
/// # Errors
/// - [`RefError::InvalidRefName`] if `branch` does not satisfy
///   [`validate_ref_name`].
/// - [`RefError::Io`] for filesystem failures.
pub fn write_head_branch(mkit_dir: &Path, branch: &str) -> RefResult<()> {
    if !validate_ref_name(branch) {
        return Err(RefError::InvalidRefName(branch.to_string()));
    }
    let body = format!("{HEAD_REF_PREFIX}{branch}\n");
    write_atomic(&mkit_dir.join(HEAD_FILE), body.as_bytes(), false)?;
    Ok(())
}

/// Write `HEAD` as a detached hash.
///
/// # Errors
/// - [`RefError::Io`] for filesystem failures.
pub fn write_head_detached(mkit_dir: &Path, h: &Hash) -> RefResult<()> {
    let wire = encode_ref_wire(h);
    write_atomic(&mkit_dir.join(HEAD_FILE), &wire, false)?;
    Ok(())
}

/// Resolve `HEAD` to a commit hash. Returns `Ok(None)` when HEAD points
/// at a branch that has no commit yet.
pub fn resolve_head(mkit_dir: &Path) -> RefResult<Option<Hash>> {
    let head = match read_head(mkit_dir) {
        Ok(h) => h,
        Err(RefError::NoHead) => return Ok(None),
        Err(e) => return Err(e),
    };
    match head {
        Head::Branch(name) => read_ref(mkit_dir, &name),
        Head::Detached(h) => Ok(Some(h)),
    }
}

/// Update the ref HEAD currently points at (or HEAD itself, if
/// detached) to `commit_hash`.
pub fn update_head(mkit_dir: &Path, commit_hash: &Hash) -> RefResult<()> {
    let head = read_head(mkit_dir)?;
    match head {
        Head::Branch(name) => write_ref(mkit_dir, &name, commit_hash),
        Head::Detached(_) => write_head_detached(mkit_dir, commit_hash),
    }
}

// -----------------------------------------------------------------------------
// Branch refs (refs/heads/<name>)
// -----------------------------------------------------------------------------

/// Read the hash a branch ref points to. Returns `Ok(None)` if the ref
/// file does not exist.
///
/// # Errors
/// - [`RefError::InvalidRefName`] if `branch` does not validate.
/// - [`RefError::InvalidRef`] if the on-disk bytes are not a valid wire.
pub fn read_ref(mkit_dir: &Path, branch: &str) -> RefResult<Option<Hash>> {
    if !validate_ref_name(branch) {
        return Err(RefError::InvalidRefName(branch.to_string()));
    }
    read_ref_under(mkit_dir, HEADS_DIR, branch)
}

/// Write a branch ref (unconditional — equivalent to
/// `update_ref(branch, RefWriteCondition::Any, h)`).
pub fn write_ref(mkit_dir: &Path, branch: &str, h: &Hash) -> RefResult<()> {
    update_ref(mkit_dir, branch, RefWriteCondition::Any, h)
}

/// CAS-aware ref write per SPEC-REFS §5.
///
/// # Errors
/// - [`RefError::InvalidRefName`] if `branch` is not a valid name.
/// - [`RefError::Conflict`] if `condition` is not satisfied.
/// - [`RefError::Io`] for filesystem failures.
pub fn update_ref(
    mkit_dir: &Path,
    branch: &str,
    condition: RefWriteCondition,
    h: &Hash,
) -> RefResult<()> {
    if !validate_ref_name(branch) {
        return Err(RefError::InvalidRefName(branch.to_string()));
    }
    let path = ref_path(mkit_dir, HEADS_DIR, branch);
    let wire = encode_ref_wire(h);
    cas_write(&path, &wire, branch, condition)
}

/// Delete a branch ref. Errors with [`RefError::NotFound`] if absent.
pub fn delete_ref(mkit_dir: &Path, branch: &str) -> RefResult<()> {
    if !validate_ref_name(branch) {
        return Err(RefError::InvalidRefName(branch.to_string()));
    }
    let path = ref_path(mkit_dir, HEADS_DIR, branch);
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            Err(RefError::NotFound(branch.to_string()))
        }
        Err(e) => Err(RefError::Io(e)),
    }
}

/// Delete a branch ref unless it is the currently checked-out branch.
pub fn delete_ref_safe(mkit_dir: &Path, branch: &str) -> RefResult<()> {
    match read_head(mkit_dir) {
        Ok(Head::Branch(current)) if current == branch => {
            Err(RefError::CurrentBranch(branch.to_string()))
        }
        _ => delete_ref(mkit_dir, branch),
    }
}

/// List all branch refs, sorted lexicographically by name.
pub fn list_refs(mkit_dir: &Path) -> RefResult<Vec<Ref>> {
    list_refs_under(mkit_dir, HEADS_DIR)
}

// -----------------------------------------------------------------------------
// Tags (refs/tags/<name>)
// -----------------------------------------------------------------------------

/// Read the hash a tag points to.
pub fn read_tag(mkit_dir: &Path, name: &str) -> RefResult<Option<Hash>> {
    if !validate_ref_name(name) {
        return Err(RefError::InvalidRefName(name.to_string()));
    }
    read_ref_under(mkit_dir, TAGS_DIR, name)
}

/// Write a tag ref (unconditional).
pub fn write_tag(mkit_dir: &Path, name: &str, h: &Hash) -> RefResult<()> {
    update_tag(mkit_dir, name, RefWriteCondition::Any, h)
}

/// CAS-aware tag write — same semantics as [`update_ref`] but for
/// `refs/tags/`.
pub fn update_tag(
    mkit_dir: &Path,
    name: &str,
    condition: RefWriteCondition,
    h: &Hash,
) -> RefResult<()> {
    if !validate_ref_name(name) {
        return Err(RefError::InvalidRefName(name.to_string()));
    }
    let path = ref_path(mkit_dir, TAGS_DIR, name);
    let wire = encode_ref_wire(h);
    cas_write(&path, &wire, name, condition)
}

/// Delete a tag ref.
pub fn delete_tag(mkit_dir: &Path, name: &str) -> RefResult<()> {
    if !validate_ref_name(name) {
        return Err(RefError::InvalidRefName(name.to_string()));
    }
    let path = ref_path(mkit_dir, TAGS_DIR, name);
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Err(RefError::NotFound(name.to_string())),
        Err(e) => Err(RefError::Io(e)),
    }
}

/// List all tag refs, sorted lexicographically by name.
pub fn list_tags(mkit_dir: &Path) -> RefResult<Vec<Ref>> {
    list_refs_under(mkit_dir, TAGS_DIR)
}

// -----------------------------------------------------------------------------
// Shallow boundaries (.mkit/shallow)
// -----------------------------------------------------------------------------

/// Load shallow-boundary hashes from `.mkit/shallow`. Returns `Ok(None)`
/// if the file does not exist or is empty.
pub fn load_shallow_boundaries(mkit_dir: &Path) -> RefResult<Option<Vec<Hash>>> {
    let path = mkit_dir.join(SHALLOW_FILE);
    let meta = match fs::metadata(&path) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(RefError::Io(e)),
    };
    if meta.len() == 0 {
        return Ok(None);
    }
    if meta.len() > SHALLOW_MAX_BYTES {
        return Err(RefError::InvalidRef("shallow file too large".to_string()));
    }
    let bytes = fs::read(&path)?;
    let s = core::str::from_utf8(&bytes).map_err(|_| RefError::InvalidHead)?;
    let mut out = Vec::new();
    for line in s.split('\n') {
        let trimmed = line.trim_end_matches(['\r', ' ', '\t']);
        if trimmed.len() != HEX_LEN {
            continue;
        }
        if let Some(h) = parse_lowercase_hash(trimmed.as_bytes()) {
            out.push(h);
        }
    }
    if out.is_empty() {
        return Ok(None);
    }
    Ok(Some(out))
}

/// Write shallow-boundary hashes to `.mkit/shallow`. Passing an empty
/// slice removes the file.
pub fn write_shallow_boundaries(mkit_dir: &Path, boundaries: &[Hash]) -> RefResult<()> {
    let path = mkit_dir.join(SHALLOW_FILE);
    if boundaries.is_empty() {
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(RefError::Io(e)),
        }
    } else {
        let mut out = Vec::with_capacity(boundaries.len() * 65);
        for h in boundaries {
            out.extend_from_slice(&encode_ref_wire(h));
        }
        write_atomic(&path, &out, true)?;
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Internals
// -----------------------------------------------------------------------------

fn ref_path(mkit_dir: &Path, sub_dir: &str, name: &str) -> PathBuf {
    let mut path = mkit_dir.join(sub_dir);
    for segment in name.split('/') {
        path.push(segment);
    }
    path
}

fn read_ref_under(mkit_dir: &Path, sub_dir: &str, name: &str) -> RefResult<Option<Hash>> {
    let path = ref_path(mkit_dir, sub_dir, name);
    let meta = match fs::metadata(&path) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(RefError::Io(e)),
    };
    if meta.len() > REF_FILE_MAX_BYTES {
        return Err(RefError::InvalidRef(name.to_string()));
    }
    let bytes = fs::read(&path)?;
    let h = decode_ref_wire(&bytes).ok_or_else(|| RefError::InvalidRef(name.to_string()))?;
    Ok(Some(h))
}

fn cas_write(
    path: &Path,
    wire: &[u8; 65],
    name_for_err: &str,
    condition: RefWriteCondition,
) -> RefResult<()> {
    match condition {
        RefWriteCondition::Any => {
            write_atomic(path, wire, true)?;
            Ok(())
        }
        RefWriteCondition::Missing => {
            // O_EXCL — fail if anything is at `path` already.
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            let created = write_create_new(path, wire, true)?;
            if !created {
                return Err(RefError::Conflict(name_for_err.to_string()));
            }
            Ok(())
        }
        RefWriteCondition::Match(expected) => {
            // Read-then-write — non-atomic per SPEC-REFS §5.1 (file
            // transport row). The spec explicitly documents this gap.
            let current = match fs::read(path) {
                Ok(b) => Some(
                    decode_ref_wire(&b)
                        .ok_or_else(|| RefError::InvalidRef(name_for_err.to_string()))?,
                ),
                Err(e) if e.kind() == io::ErrorKind::NotFound => None,
                Err(e) => return Err(RefError::Io(e)),
            };
            if current != Some(expected) {
                return Err(RefError::Conflict(name_for_err.to_string()));
            }
            write_atomic(path, wire, true)?;
            Ok(())
        }
    }
}

fn list_refs_under(mkit_dir: &Path, sub_dir: &str) -> RefResult<Vec<Ref>> {
    let root = mkit_dir.join(sub_dir);
    let mut out = Vec::new();
    if !root.is_dir() {
        return Ok(out);
    }
    collect_refs(&root, "", &mut out, 0)?;
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

/// Cap on ref-tree recursion depth. A malicious or corrupt `.mkit/refs/`
/// directory with deeply nested empty dirs should not stack-overflow
/// the walker. 32 is far beyond anything a valid ref name (which cannot
/// contain more than a few `/` separators given the 1–255 path-segment
/// grammar) could ever require.
const MAX_REF_DEPTH: usize = 32;

fn collect_refs(root: &Path, prefix: &str, out: &mut Vec<Ref>, depth: usize) -> RefResult<()> {
    if depth > MAX_REF_DEPTH {
        // Silently stop — same "skip malformed" posture as below for
        // individual files. Callers get a partial result rather than a
        // stack overflow on adversarial input.
        return Ok(());
    }
    let dir_path = if prefix.is_empty() {
        root.to_path_buf()
    } else {
        root.join(prefix)
    };
    let iter = match fs::read_dir(&dir_path) {
        Ok(i) => i,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(RefError::Io(e)),
    };
    for entry in iter {
        let entry = entry?;
        let file_name = match entry.file_name().to_str() {
            Some(s) => s.to_string(),
            None => continue, // Non-UTF-8 names cannot be valid ref names.
        };
        let child_name = if prefix.is_empty() {
            file_name.clone()
        } else {
            format!("{prefix}/{file_name}")
        };
        let ft = entry.file_type()?;
        if ft.is_dir() {
            collect_refs(root, &child_name, out, depth + 1)?;
            continue;
        }
        if !ft.is_file() {
            continue;
        }
        if !validate_ref_name(&child_name) {
            continue;
        }
        // Read & decode; silently skip malformed files.
        let Ok(bytes) = fs::read(entry.path()) else {
            continue;
        };
        let hash = decode_ref_wire(&bytes);
        out.push(Ref {
            name: child_name,
            hash,
        });
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// Internal hash helper re-exports for goldens
// -----------------------------------------------------------------------------

/// Internal re-export used by the integration tests to hand-roll wire
/// bytes without round-tripping through `hash::from_hex`.
#[doc(hidden)]
#[must_use]
pub fn _hash_from_lowercase_hex_for_tests(s: &str) -> Option<Hash> {
    parse_lowercase_hash(s.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash;
    use tempfile::TempDir;

    fn fresh_repo() -> (TempDir, PathBuf) {
        let dir = TempDir::new().unwrap();
        let mkit_dir = dir.path().join(".mkit");
        fs::create_dir_all(&mkit_dir).unwrap();
        init(&mkit_dir).unwrap();
        (dir, mkit_dir)
    }

    fn h(seed: &str) -> Hash {
        hash::hash(seed.as_bytes())
    }

    // --- name grammar ---------------------------------------------------

    #[test]
    fn validate_accepts_simple_names() {
        assert!(validate_ref_name("main"));
        assert!(validate_ref_name("feat/v1.0-beta"));
        assert!(validate_ref_name("release/2024_09"));
    }

    #[test]
    fn validate_rejects_empty() {
        assert!(!validate_ref_name(""));
    }

    #[test]
    fn validate_rejects_leading_slash() {
        assert!(!validate_ref_name("/main"));
    }

    #[test]
    fn validate_rejects_dotdot_segment() {
        assert!(!validate_ref_name("feat/.."));
        assert!(!validate_ref_name("../escape"));
        assert!(!validate_ref_name("feat/./topic"));
    }

    #[test]
    fn validate_rejects_double_slash() {
        assert!(!validate_ref_name("refs//heads/main"));
        assert!(!validate_ref_name("main/"));
    }

    #[test]
    fn validate_rejects_disallowed_bytes() {
        assert!(!validate_ref_name("main@v1"));
        assert!(!validate_ref_name("feat\\branch"));
        assert!(!validate_ref_name("with space"));
    }

    #[test]
    fn validate_prefix() {
        assert!(validate_ref_prefix(""));
        assert!(validate_ref_prefix("refs/heads/"));
        assert!(validate_ref_prefix("refs/heads"));
        assert!(!validate_ref_prefix("refs//heads/"));
        assert!(!validate_ref_prefix("/"));
    }

    // --- wire encoding --------------------------------------------------

    #[test]
    fn wire_round_trip() {
        let original = h("test-ref");
        let wire = encode_ref_wire(&original);
        assert_eq!(wire.len(), 65);
        assert_eq!(wire[64], b'\n');
        let parsed = decode_ref_wire(&wire).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn wire_rejects_uppercase() {
        let original = h("test-ref");
        let mut wire = encode_ref_wire(&original);
        // Upper-case the first letter we find; SPEC-REFS §1 forbids
        // uppercase hex on read.
        let mut flipped = false;
        for b in &mut wire[..HEX_LEN] {
            if (b'a'..=b'f').contains(b) {
                *b -= b'a' - b'A';
                flipped = true;
                break;
            }
        }
        assert!(flipped, "test fixture should contain at least one a-f");
        assert!(decode_ref_wire(&wire).is_none());
    }

    #[test]
    fn wire_rejects_short_input() {
        let bad = b"deadbeef\n";
        assert!(decode_ref_wire(bad).is_none());
    }

    #[test]
    fn wire_rejects_non_hex() {
        let mut wire = encode_ref_wire(&h("x"));
        wire[1] = b'g';
        assert!(decode_ref_wire(&wire).is_none());
    }

    #[test]
    fn wire_tolerates_trailing_cr() {
        // Files round-tripped through Windows editors may pick up CRs.
        let original = h("eol");
        let mut buf = encode_ref_wire(&original).to_vec();
        buf.insert(64, b'\r');
        let parsed = decode_ref_wire(&buf).unwrap();
        assert_eq!(parsed, original);
    }

    // --- HEAD ----------------------------------------------------------

    #[test]
    fn init_writes_default_head() {
        let (_dir, mkit) = fresh_repo();
        let head = read_head(&mkit).unwrap();
        assert_eq!(head, Head::Branch("main".to_string()));
    }

    #[test]
    fn write_and_read_branch_ref() {
        let (_dir, mkit) = fresh_repo();
        let commit = h("commit1");
        write_ref(&mkit, "main", &commit).unwrap();
        let read = read_ref(&mkit, "main").unwrap();
        assert_eq!(read, Some(commit));
    }

    #[test]
    fn resolve_head_with_no_commits_returns_none() {
        let (_dir, mkit) = fresh_repo();
        assert_eq!(resolve_head(&mkit).unwrap(), None);
    }

    #[test]
    fn resolve_head_after_commit() {
        let (_dir, mkit) = fresh_repo();
        let commit = h("commit1");
        write_ref(&mkit, "main", &commit).unwrap();
        assert_eq!(resolve_head(&mkit).unwrap(), Some(commit));
    }

    #[test]
    fn update_head_updates_current_branch() {
        let (_dir, mkit) = fresh_repo();
        let h1 = h("c1");
        update_head(&mkit, &h1).unwrap();
        assert_eq!(resolve_head(&mkit).unwrap(), Some(h1));
        let h2 = h("c2");
        update_head(&mkit, &h2).unwrap();
        assert_eq!(resolve_head(&mkit).unwrap(), Some(h2));
    }

    #[test]
    fn detached_head_round_trip() {
        let dir = TempDir::new().unwrap();
        let mkit = dir.path().join(".mkit");
        fs::create_dir_all(&mkit).unwrap();
        let commit = h("detached");
        write_head_detached(&mkit, &commit).unwrap();
        match read_head(&mkit).unwrap() {
            Head::Detached(got) => assert_eq!(got, commit),
            other @ Head::Branch(_) => panic!("expected detached, got {other:?}"),
        }
        assert_eq!(resolve_head(&mkit).unwrap(), Some(commit));
    }

    #[test]
    fn nonexistent_branch_returns_none() {
        let (_dir, mkit) = fresh_repo();
        assert_eq!(read_ref(&mkit, "nonexistent").unwrap(), None);
    }

    #[test]
    fn list_refs_empty() {
        let (_dir, mkit) = fresh_repo();
        let refs = list_refs(&mkit).unwrap();
        assert!(refs.is_empty());
    }

    #[test]
    fn list_refs_sorted() {
        let (_dir, mkit) = fresh_repo();
        write_ref(&mkit, "main", &h("m")).unwrap();
        write_ref(&mkit, "dev", &h("d")).unwrap();
        let refs = list_refs(&mkit).unwrap();
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0].name, "dev");
        assert_eq!(refs[1].name, "main");
    }

    #[test]
    fn nested_refs_listed_recursively() {
        let (_dir, mkit) = fresh_repo();
        write_ref(&mkit, "feature/deep/topic", &h("nested")).unwrap();
        let refs = list_refs(&mkit).unwrap();
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].name, "feature/deep/topic");
    }

    #[test]
    fn delete_ref_basic() {
        let (_dir, mkit) = fresh_repo();
        write_ref(&mkit, "feature", &h("f")).unwrap();
        delete_ref(&mkit, "feature").unwrap();
        assert_eq!(read_ref(&mkit, "feature").unwrap(), None);
    }

    #[test]
    fn delete_nonexistent_ref_errors() {
        let (_dir, mkit) = fresh_repo();
        let err = delete_ref(&mkit, "nope").unwrap_err();
        assert!(matches!(err, RefError::NotFound(_)));
    }

    #[test]
    fn refuse_delete_current_branch() {
        let (_dir, mkit) = fresh_repo();
        write_ref(&mkit, "main", &h("m")).unwrap();
        let err = delete_ref_safe(&mkit, "main").unwrap_err();
        assert!(matches!(err, RefError::CurrentBranch(_)));
    }

    // --- CAS variants ---------------------------------------------------

    #[test]
    fn cas_any_clobbers() {
        let (_dir, mkit) = fresh_repo();
        update_ref(&mkit, "main", RefWriteCondition::Any, &h("a")).unwrap();
        update_ref(&mkit, "main", RefWriteCondition::Any, &h("b")).unwrap();
        assert_eq!(read_ref(&mkit, "main").unwrap(), Some(h("b")));
    }

    #[test]
    fn cas_missing_succeeds_when_absent() {
        let (_dir, mkit) = fresh_repo();
        update_ref(&mkit, "main", RefWriteCondition::Missing, &h("a")).unwrap();
        assert_eq!(read_ref(&mkit, "main").unwrap(), Some(h("a")));
    }

    #[test]
    fn cas_missing_fails_when_present() {
        let (_dir, mkit) = fresh_repo();
        write_ref(&mkit, "main", &h("a")).unwrap();
        let err = update_ref(&mkit, "main", RefWriteCondition::Missing, &h("b")).unwrap_err();
        assert!(matches!(err, RefError::Conflict(_)));
    }

    #[test]
    fn cas_match_succeeds_on_correct_hash() {
        let (_dir, mkit) = fresh_repo();
        write_ref(&mkit, "main", &h("a")).unwrap();
        update_ref(&mkit, "main", RefWriteCondition::Match(h("a")), &h("b")).unwrap();
        assert_eq!(read_ref(&mkit, "main").unwrap(), Some(h("b")));
    }

    #[test]
    fn cas_match_fails_on_wrong_hash() {
        let (_dir, mkit) = fresh_repo();
        write_ref(&mkit, "main", &h("a")).unwrap();
        let err = update_ref(&mkit, "main", RefWriteCondition::Match(h("z")), &h("b")).unwrap_err();
        assert!(matches!(err, RefError::Conflict(_)));
    }

    #[test]
    fn cas_match_fails_on_missing_ref() {
        let (_dir, mkit) = fresh_repo();
        let err = update_ref(&mkit, "main", RefWriteCondition::Match(h("a")), &h("b")).unwrap_err();
        assert!(matches!(err, RefError::Conflict(_)));
    }

    // --- name-validation enforcement -----------------------------------

    #[test]
    fn write_rejects_invalid_branch_name() {
        let (_dir, mkit) = fresh_repo();
        let err = write_ref(&mkit, "../escape", &h("x")).unwrap_err();
        assert!(matches!(err, RefError::InvalidRefName(_)));
        let err = write_head_branch(&mkit, "bad//branch").unwrap_err();
        assert!(matches!(err, RefError::InvalidRefName(_)));
    }

    // --- tags ----------------------------------------------------------

    #[test]
    fn write_and_read_tag() {
        let (_dir, mkit) = fresh_repo();
        let commit = h("v1.0");
        write_tag(&mkit, "v1.0", &commit).unwrap();
        assert_eq!(read_tag(&mkit, "v1.0").unwrap(), Some(commit));
    }

    #[test]
    fn list_tags_sorted() {
        let (_dir, mkit) = fresh_repo();
        write_tag(&mkit, "v2.0", &h("v2")).unwrap();
        write_tag(&mkit, "v1.0", &h("v1")).unwrap();
        write_tag(&mkit, "alpha", &h("a")).unwrap();
        let tags = list_tags(&mkit).unwrap();
        assert_eq!(
            tags.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(),
            vec!["alpha", "v1.0", "v2.0"]
        );
    }

    #[test]
    fn tag_and_branch_same_name_independent() {
        let (_dir, mkit) = fresh_repo();
        let tag = h("tag");
        let branch = h("branch");
        write_tag(&mkit, "main", &tag).unwrap();
        write_ref(&mkit, "main", &branch).unwrap();
        assert_eq!(read_tag(&mkit, "main").unwrap(), Some(tag));
        assert_eq!(read_ref(&mkit, "main").unwrap(), Some(branch));
    }

    #[test]
    fn delete_tag_basic() {
        let (_dir, mkit) = fresh_repo();
        write_tag(&mkit, "release", &h("r")).unwrap();
        delete_tag(&mkit, "release").unwrap();
        assert_eq!(read_tag(&mkit, "release").unwrap(), None);
    }

    #[test]
    fn delete_nonexistent_tag_errors() {
        let (_dir, mkit) = fresh_repo();
        let err = delete_tag(&mkit, "missing").unwrap_err();
        assert!(matches!(err, RefError::NotFound(_)));
    }

    // --- shallow boundaries --------------------------------------------

    #[test]
    fn load_shallow_returns_none_when_missing() {
        let (_dir, mkit) = fresh_repo();
        assert_eq!(load_shallow_boundaries(&mkit).unwrap(), None);
    }

    #[test]
    fn write_and_load_shallow_round_trip() {
        let (_dir, mkit) = fresh_repo();
        let bs = vec![h("b1"), h("b2"), h("b3")];
        write_shallow_boundaries(&mkit, &bs).unwrap();
        let loaded = load_shallow_boundaries(&mkit).unwrap().unwrap();
        assert_eq!(loaded.len(), 3);
        for b in &bs {
            assert!(loaded.contains(b));
        }
    }

    #[test]
    fn write_empty_shallow_removes_file() {
        let (_dir, mkit) = fresh_repo();
        write_shallow_boundaries(&mkit, &[h("x")]).unwrap();
        assert!(load_shallow_boundaries(&mkit).unwrap().is_some());
        write_shallow_boundaries(&mkit, &[]).unwrap();
        assert_eq!(load_shallow_boundaries(&mkit).unwrap(), None);
    }

    #[test]
    fn load_shallow_skips_invalid_lines() {
        let (_dir, mkit) = fresh_repo();
        let path = mkit.join(SHALLOW_FILE);
        let valid = h("ok");
        let valid_hex = to_hex(&valid);
        let mut content = String::new();
        content.push_str("short\n");
        content.push_str(&valid_hex);
        content.push('\n');
        content.push_str(&"z".repeat(64));
        content.push('\n');
        std::fs::write(&path, content).unwrap();
        let loaded = load_shallow_boundaries(&mkit).unwrap().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0], valid);
    }
}
