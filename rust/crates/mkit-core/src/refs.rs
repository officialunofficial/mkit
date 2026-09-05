//! Refs subsystem.
//!
//! Implements the local-disk side of `docs/specs/SPEC-REFS.md`: ref names,
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
//! backslashes, no NULs. In addition, no segment may end in `.lock`
//! (the canonical lock-file suffix) and the final segment may not be
//! the literal `HEAD` (which would shadow the repo-level HEAD
//! pointer). We share the validator with the future transport layer
//! via [`validate_ref_name`] / [`validate_ref_prefix`].
//!
//! CAS variants for [`update_ref`] follow SPEC-REFS §5: `Any` (clobber),
//! `Missing` (fail if it exists), `Match(H)` (fail if current value !=
//! H). As of #637, the local-filesystem `Match` read-compare-write is
//! serialized under a shared `refs.lock` in the common dir (the same
//! blocking kernel-lock primitive `repo_lock` uses elsewhere), so it is
//! atomic across processes regardless of what other locks each caller
//! holds — this closes the v1 gap previously documented here.

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::atomic::{write_atomic, write_create_new};
use crate::hash::{HASH_LEN, HEX_LEN, Hash, to_hex};
use crate::layout::RepoLayout;

/// Subdirectory holding all refs (`.mkit/refs`).
pub const REFS_DIR: &str = "refs";
/// Subdirectory holding branch refs (`.mkit/refs/heads`).
pub const HEADS_DIR: &str = "refs/heads";
/// Subdirectory holding tag refs (`.mkit/refs/tags`).
pub const TAGS_DIR: &str = "refs/tags";
/// Subdirectory holding remote-tracking refs (`.mkit/refs/remotes`).
pub const REMOTES_DIR: &str = "refs/remotes";
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
/// - No segment may start with `.` (this also rejects the exact `.`
///   and `..` segments) — git's `check-ref-format` rule, kept for
///   parity: a dot-leading component is invalid in both grammars, so
///   nothing on-disk under a dot-leading directory (e.g. crash debris
///   from a temp-directory rename, or an in-flight `atomic::write_atomic`
///   temp file) can ever surface as a ref in `collect_refs` / listings.
///   No empty segments (no `//`, no leading `/`, no trailing `/`).
/// - No `\\` or NUL bytes.
/// - No segment may end in `.lock` (the canonical lock-file suffix).
/// - The final segment may not be the literal `HEAD`, since that
///   would shadow the repo-level `HEAD` pointer.
#[must_use]
pub fn validate_ref_name(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    if name.starts_with('/') {
        return false;
    }
    let mut last_part: &str = "";
    for part in name.split('/') {
        if part.is_empty() {
            return false;
        }
        if part.starts_with('.') {
            return false;
        }
        // Reject the canonical lock-file suffix. Byte-level check so
        // clippy's case-sensitive file-extension lint (which assumes a
        // path extension) does not fire — ref segments are not paths
        // and `.lock` is a spec-mandated exact-match suffix.
        let bytes = part.as_bytes();
        if bytes.len() >= 5 && &bytes[bytes.len() - 5..] == b".lock" {
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
        last_part = part;
    }
    if last_part == "HEAD" {
        return false;
    }
    true
}

/// Hex-escape an arbitrary ref-like name (branch, tag, remote ref, or
/// a `refs.rs`-relative path) into a filename-safe token:
/// `[A-Za-z0-9-_]`-only input, injective, self-delimiting.
///
/// Every non-`[A-Za-z0-9-]` byte is encoded as `_xx` where `xx` is the
/// lowercase-hex byte value; `_` itself encodes as `_5f`, so every `_`
/// in the output is unambiguously the lead-in of a two-hex-digit
/// escape, never a literal.
///
/// Examples:
///   `main`        → `main`
///   `feat/v1.0`   → `feat_2fv1_2e0`
///   `feat_v1_0`   → `feat_5fv1_5f0`
///
/// Per-ref lock naming uses this encoding in every build.
pub(crate) fn sanitize_ref_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for &b in name.as_bytes() {
        let allowed = b.is_ascii_alphanumeric() || b == b'-';
        if allowed {
            out.push(b as char);
        } else {
            use core::fmt::Write as _;
            let _ = write!(&mut out, "_{b:02x}");
        }
    }
    out
}

/// Canonical per-branch lock name for ancestry publication and recovery.
#[cfg(feature = "history-mmr")]
pub(crate) fn history_lock_name(branch: &str) -> String {
    format!("refs-history-{}.lock", sanitize_ref_name(branch))
}

pub(crate) mod ancestry_state;

/// Retention roots of unfinished history publications, including when the
/// history-mmr feature is disabled. Corruption must abort GC.
pub fn pending_history_roots(layout: &RepoLayout) -> RefResult<BTreeSet<Hash>> {
    ancestry_state::pending_roots(layout.common_dir())
}

/// The `refs-<ref>.lock` filename every ref mutation
/// acquires, keyed off `path` relative to `common_dir` (not just a
/// bare name) so a branch and a tag/remote-ref sharing the same bare
/// name get distinct locks. Named for the same reason as
/// [`history_lock_name`]: a test that independently recomputes this
/// formula would stop catching a regression the moment production's
/// formula changed without the test's copy changing too.
pub(crate) fn cas_lock_name(common_dir: &Path, path: &Path) -> String {
    let ref_key = path
        .strip_prefix(common_dir)
        .map_or_else(|_| path.to_string_lossy(), |p| p.to_string_lossy());
    format!("refs-{}.lock", sanitize_ref_name(&ref_key))
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

/// Decode a ref wire blob into a [`Hash`](tyalias@Hash). Tolerates a trailing
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

/// Strict lowercase-only hex parser: exactly [`HEX_LEN`] lowercase-hex
/// bytes, decoded in a single pass. SPEC-REFS §1 forbids uppercase on read;
/// the general `hash::from_hex` tolerates both cases for programmatic
/// callers, so this is the stricter variant every on-the-wire / on-disk
/// reader (ref wire blobs, the applied-packs record) shares to keep a
/// hand-edited or foreign-cased line malformed rather than silently accepted.
#[must_use]
pub fn parse_lowercase_hash(bytes: &[u8]) -> Option<Hash> {
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

/// Initialise the ref layout: creates `refs/`, `refs/heads/`,
/// `refs/tags/`, `refs/remotes/` under the common dir and writes a
/// default `HEAD = ref: refs/heads/main\n` into the worktree state
/// dir if `HEAD` does not already exist.
pub fn init(layout: &RepoLayout) -> RefResult<()> {
    fs::create_dir_all(layout.refs_dir())?;
    fs::create_dir_all(layout.heads_dir())?;
    fs::create_dir_all(layout.tags_dir())?;
    fs::create_dir_all(layout.remotes_dir())?;
    let head_path = layout.head_file();
    if !head_path.exists() {
        let body = format!("{HEAD_REF_PREFIX}main\n");
        write_atomic(&head_path, body.as_bytes(), false)?;
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// HEAD
// -----------------------------------------------------------------------------

/// Read this worktree's `HEAD`.
///
/// # Errors
/// - [`RefError::NoHead`] if the file is missing.
/// - [`RefError::InvalidHead`] for malformed content.
pub fn read_head(layout: &RepoLayout) -> RefResult<Head> {
    let path = layout.head_file();
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
pub fn write_head_branch(layout: &RepoLayout, branch: &str) -> RefResult<()> {
    if !validate_ref_name(branch) {
        return Err(RefError::InvalidRefName(branch.to_string()));
    }
    let body = format!("{HEAD_REF_PREFIX}{branch}\n");
    write_atomic(&layout.head_file(), body.as_bytes(), false)?;
    Ok(())
}

/// Write `HEAD` as a detached hash.
///
/// # Errors
/// - [`RefError::Io`] for filesystem failures.
pub fn write_head_detached(layout: &RepoLayout, h: &Hash) -> RefResult<()> {
    let wire = encode_ref_wire(h);
    write_atomic(&layout.head_file(), &wire, false)?;
    Ok(())
}

/// Resolve `HEAD` to a commit hash. Returns `Ok(None)` when HEAD points
/// at a branch that has no commit yet.
pub fn resolve_head(layout: &RepoLayout) -> RefResult<Option<Hash>> {
    let head = match read_head(layout) {
        Ok(h) => h,
        Err(RefError::NoHead) => return Ok(None),
        Err(e) => return Err(e),
    };
    match head {
        Head::Branch(name) => read_ref(layout, &name),
        Head::Detached(h) => Ok(Some(h)),
    }
}

/// Update the ref HEAD currently points at (or HEAD itself, if
/// detached) to `commit_hash`.
pub fn update_head(layout: &RepoLayout, commit_hash: &Hash) -> RefResult<()> {
    let head = read_head(layout)?;
    match head {
        Head::Branch(name) => write_ref(layout, &name, commit_hash),
        Head::Detached(_) => write_head_detached(layout, commit_hash),
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
pub fn read_ref(layout: &RepoLayout, branch: &str) -> RefResult<Option<Hash>> {
    if !validate_ref_name(branch) {
        return Err(RefError::InvalidRefName(branch.to_string()));
    }
    read_ref_under(layout.common_dir(), HEADS_DIR, branch)
}

/// Write a branch ref (unconditional — equivalent to
/// `update_ref(branch, RefWriteCondition::Any, h)`).
pub fn write_ref(layout: &RepoLayout, branch: &str, h: &Hash) -> RefResult<()> {
    update_ref(layout, branch, RefWriteCondition::Any, h)
}

/// CAS-aware ref write per SPEC-REFS §5.
///
/// # Errors
/// - [`RefError::InvalidRefName`] if `branch` is not a valid name.
/// - [`RefError::Conflict`] if `condition` is not satisfied.
/// - [`RefError::Io`] for filesystem failures.
pub fn update_ref(
    layout: &RepoLayout,
    branch: &str,
    condition: RefWriteCondition,
    h: &Hash,
) -> RefResult<()> {
    if !validate_ref_name(branch) {
        return Err(RefError::InvalidRefName(branch.to_string()));
    }
    let path = ref_path(layout.common_dir(), HEADS_DIR, branch);
    let wire = encode_ref_wire(h);
    cas_write(layout.common_dir(), &path, &wire, branch, condition)
}

// -----------------------------------------------------------------------------
// History-coupled ref writes (feature: history-mmr)
// -----------------------------------------------------------------------------

/// Acquire the complete nested guard for a history transaction or snapshot.
#[cfg(feature = "history-mmr")]
pub(crate) fn acquire_history_mutation(
    layout: &RepoLayout,
    branch: &str,
) -> RefResult<(crate::repo_lock::RepoLock, RefMutation)> {
    if !validate_ref_name(branch) {
        return Err(RefError::InvalidRefName(branch.to_string()));
    }
    let history =
        crate::repo_lock::acquire_default(layout.common_dir(), &history_lock_name(branch))
            .map_err(|e| RefError::InvalidRef(format!("{branch}: history lock: {e}")))?;
    let path = ref_path(layout.common_dir(), HEADS_DIR, branch);
    let mutation = RefMutation::acquire(layout.common_dir(), &path, branch)?;
    Ok((history, mutation))
}

/// Publish a branch's canonical first-parent ancestry, with an explicit
/// generation and crash-recoverable descriptor.
#[cfg(feature = "history-mmr")]
pub fn update_ref_with_ancestry(
    layout: &RepoLayout,
    branch: &str,
    condition: RefWriteCondition,
    target: &Hash,
    store: &crate::store::ObjectStore,
) -> RefResult<()> {
    let (_history, mutation) = acquire_history_mutation(layout, branch)?;
    crate::history::ancestry::advance(layout, branch, &mutation, condition, *target, store).map_err(
        |e| match e {
            crate::history::HistoryError::Ref(e) => e,
            other => RefError::InvalidRef(format!("{branch}: ancestry publication: {other}")),
        },
    )
}

/// Delete a branch after recovering any pending ancestry publication. Archived
/// generation snapshots remain evidence; the current
/// descriptor is invalidated before the ref disappears.
#[cfg(feature = "history-mmr")]
pub fn delete_ref_with_ancestry(
    layout: &RepoLayout,
    branch: &str,
    expected: Option<Hash>,
    store: &crate::store::ObjectStore,
) -> RefResult<()> {
    let (_history, mutation) = acquire_history_mutation(layout, branch)?;
    crate::history::ancestry::recover(layout, branch, &mutation, store)
        .map_err(|e| RefError::InvalidRef(format!("{branch}: history recovery: {e}")))?;
    mutation.delete(expected)
}

/// Delete a branch ref. Errors with [`RefError::NotFound`] if absent.
pub fn delete_ref(layout: &RepoLayout, branch: &str) -> RefResult<()> {
    if !validate_ref_name(branch) {
        return Err(RefError::InvalidRefName(branch.to_string()));
    }
    let path = ref_path(layout.common_dir(), HEADS_DIR, branch);
    RefMutation::acquire(layout.common_dir(), &path, branch)?.delete(None)
}

/// Delete a branch ref unless it is the currently checked-out branch.
pub fn delete_ref_safe(layout: &RepoLayout, branch: &str) -> RefResult<()> {
    match read_head(layout) {
        Ok(Head::Branch(current)) if current == branch => {
            Err(RefError::CurrentBranch(branch.to_string()))
        }
        _ => delete_ref(layout, branch),
    }
}

/// CAS-guarded delete: removes a branch ref only if its current on-disk
/// value is exactly `expected`. Issue #658.
///
/// [`delete_ref`] is unconditional — it removes whatever is at `path`
/// regardless of what a caller last read. That is fine for the
/// user-initiated `branch -d`/`-D` path (deleting a specific named
/// branch is meaningful even if its tip moved since the user last
/// looked), but it is NOT fine for `branch -m`'s rename: a rename reads
/// the source branch's tip, publishes it under the new name, and then
/// drops the source ref. If a concurrent `commit` (via
/// [`RefWriteCondition::Match`], see `mkit-cli`'s `advance_head`)
/// advances the source branch in the window between the rename's read
/// and its delete, an unconditional delete destroys that freshly-landed
/// commit's only ref with no error to either caller — commit reports
/// success, rename reports success, and the commit becomes unreachable.
///
/// This closes that gap by making the delete itself compare-and-swap:
/// it acquires the SAME per-ref lock `cas_write`'s `Match` arm takes
/// (via `cas_lock_name`, keyed off the ref's path so it can never
/// collide with an unrelated ref of the same bare name), reads the
/// current value under that lock, and only removes the file if it is
/// still exactly `expected`. Because a concurrent `Match`-conditioned
/// advance on the SAME ref takes the identical lock, the two can never
/// interleave: either the advance's CAS write lands first (this call
/// then sees the new value, doesn't match, and errors `Conflict`
/// without touching the file) or this delete lands first (the advance's
/// subsequent `Match(expected)` then sees the ref gone and itself fails
/// `Conflict`) — never both "succeeding" against the same prior state.
///
/// All writers, including `Any`, and both delete forms take the same
/// per-ref guard. Callers do not need to establish a separate exclusion rule.
///
/// # Errors
/// - [`RefError::InvalidRefName`] if `branch` is not a valid name.
/// - [`RefError::Conflict`] if the ref's current value is not exactly
///   `expected` — this includes the ref not existing at all. The ref
///   file is left completely untouched in this case.
/// - [`RefError::Io`] for filesystem or lock-acquisition failures.
pub fn delete_ref_if_matches(layout: &RepoLayout, branch: &str, expected: Hash) -> RefResult<()> {
    if !validate_ref_name(branch) {
        return Err(RefError::InvalidRefName(branch.to_string()));
    }
    let path = ref_path(layout.common_dir(), HEADS_DIR, branch);
    RefMutation::acquire(layout.common_dir(), &path, branch)?.delete(Some(expected))
}

/// List all branch refs, sorted lexicographically by name.
pub fn list_refs(layout: &RepoLayout) -> RefResult<Vec<Ref>> {
    list_refs_under(layout.common_dir(), HEADS_DIR)
}

// -----------------------------------------------------------------------------
// Remote-tracking refs (refs/remotes/<remote>/<branch>)
// -----------------------------------------------------------------------------

/// Read a remote-tracking branch ref.
pub fn read_remote_ref(layout: &RepoLayout, remote: &str, branch: &str) -> RefResult<Option<Hash>> {
    validate_remote_and_branch(remote, branch)?;
    read_ref_under(layout.common_dir(), &remote_ref_dir(remote), branch)
}

/// Write a remote-tracking branch ref unconditionally.
pub fn write_remote_ref(
    layout: &RepoLayout,
    remote: &str,
    branch: &str,
    h: &Hash,
) -> RefResult<()> {
    validate_remote_and_branch(remote, branch)?;
    let path = ref_path(layout.common_dir(), &remote_ref_dir(remote), branch);
    let wire = encode_ref_wire(h);
    cas_write(
        layout.common_dir(),
        &path,
        &wire,
        branch,
        RefWriteCondition::Any,
    )
}

/// Batched writer for remote-tracking refs (#645): amortises the
/// parent-directory fsync across every ref written into it, instead of
/// paying one per ref like [`write_remote_ref`] in a loop.
///
/// `push`/`fetch` publish one tracking ref per branch
/// (`refs/remotes/<remote>/<branch>`) in a loop; each individual
/// [`write_remote_ref`] call goes through `write_atomic`'s
/// temp+fsync+rename+**dirsync** pattern, so N branches cost N serial
/// directory fsyncs even though every write lands under the same
/// `refs/remotes/<remote>/` tree. `RemoteRefBatch` instead:
///
/// 1. [`Self::write`]s each ref durable-content-before-visible (fsyncs
///    the wire bytes, then renames — same invariant
///    `crate::atomic::write_content_synced` gives object writes: a
///    reader can never observe a torn file), immediately, one call at a
///    time, deferring only the directory fsync that makes the RENAME
///    itself crash-durable;
/// 2. [`Self::commit`] fsyncs every distinct directory touched, once
///    each, deduplicated — O(distinct directories) instead of O(refs).
///    For the common case (one remote, flat branch names) that is
///    exactly one fsync for the whole batch.
///
/// This is deliberately scoped to `refs/remotes/*` ONLY — see
/// `atomic.rs`'s module docs for why branch heads (`refs/heads/*`,
/// [`write_ref`]/[`update_ref`]) keep the unbatched per-write contract:
/// tracking refs are a locally-cached, recomputable-from-a-re-fetch
/// view of another repository, not a pointer anything else orders
/// against.
///
/// # Partial-failure semantics
///
/// Best-effort, fail-fast — the same contract
/// [`crate::batch::WriteBatch::commit`] documents for the object store's
/// batched writes. [`Self::write`] renames each ref as soon as it
/// validates and its content is durable, so a ref that made it through
/// `write` is visible to readers immediately, exactly as it would have
/// been under the old per-ref loop. If a later `write` in the same
/// batch fails (bad name or I/O error), earlier successful writes are
/// **not** rolled back — content-addressed dedup isn't in play here,
/// but the same reasoning applies: remote-tracking refs are
/// recomputable, so a partially-applied batch is exactly as safe to
/// retry as the old loop was after failing at the same point. Callers
/// that want the successful prefix to be durable even when the batch as
/// a whole errors out should call [`Self::commit`] regardless of
/// whether the write loop returned early (see
/// `remote_dispatch::push_all_with` / `fetch_objects_inner` for the
/// pattern).
#[derive(Debug)]
pub struct RemoteRefBatch<'a> {
    layout: &'a RepoLayout,
    sub_dir: String,
    touched_dirs: BTreeSet<PathBuf>,
}

impl<'a> RemoteRefBatch<'a> {
    /// Start a batch for `remote`.
    ///
    /// # Errors
    /// [`RefError::InvalidRefName`] if `remote` fails [`validate_ref_name`].
    pub fn new(layout: &'a RepoLayout, remote: &str) -> RefResult<Self> {
        if !validate_ref_name(remote) {
            return Err(RefError::InvalidRefName(remote.to_string()));
        }
        Ok(Self {
            layout,
            sub_dir: remote_ref_dir(remote),
            touched_dirs: BTreeSet::new(),
        })
    }

    /// Write one remote-tracking ref: validates `branch`, fsyncs its
    /// wire-encoded content, then renames it into place — visible
    /// immediately, same as [`write_remote_ref`]. Only the directory
    /// fsync (rename durability) is deferred to [`Self::commit`].
    ///
    /// # Errors
    /// - [`RefError::InvalidRefName`] if `branch` fails
    ///   [`validate_ref_name`] — no I/O is attempted for an invalid name.
    /// - [`RefError::Io`] for filesystem failures.
    ///
    /// # Panics
    /// Never in practice: `ref_path` always produces a path with a
    /// parent (it is `self.layout.common_dir()` joined with at least the
    /// remote's subdirectory and the branch name).
    pub fn write(&mut self, branch: &str, h: &Hash) -> RefResult<()> {
        if !validate_ref_name(branch) {
            return Err(RefError::InvalidRefName(branch.to_string()));
        }
        let path = ref_path(self.layout.common_dir(), &self.sub_dir, branch);
        let guard = RefMutation::acquire(self.layout.common_dir(), &path, branch)?;
        guard.invalidate_history()?;
        let parent = path
            .parent()
            .expect("remote-tracking ref path always has a parent")
            .to_path_buf();
        fs::create_dir_all(&parent)?;
        let wire = encode_ref_wire(h);
        crate::atomic::write_content_synced(&path, &wire)?;
        self.touched_dirs.insert(parent);
        Ok(())
    }

    /// Fsync every directory touched by a completed [`Self::write`],
    /// once each. Idempotent to call on a batch with nothing staged (a
    /// no-op). MUST be called after the last `write` a caller intends to
    /// make durable — refs written but never committed are visible but
    /// not crash-durable (the rename may not have reached stable
    /// storage), the same window [`crate::store::BulkWriter::commit`]
    /// documents for bulk object writes.
    ///
    /// # Errors
    /// [`RefError::Io`] on the first directory fsync failure. Directories
    /// are synced in sorted order for determinism; a failure partway
    /// through leaves the remaining directories un-synced (best-effort,
    /// matching [`Self::write`]'s partial-failure contract).
    pub fn commit(self) -> RefResult<()> {
        for dir in &self.touched_dirs {
            crate::atomic::sync_dir(dir)?;
        }
        Ok(())
    }
}

/// Delete a remote-tracking branch ref (e.g. after the upstream
/// deleted the branch). Errors with [`RefError::NotFound`] if absent.
pub fn delete_remote_ref(layout: &RepoLayout, remote: &str, branch: &str) -> RefResult<()> {
    validate_remote_and_branch(remote, branch)?;
    let path = ref_path(layout.common_dir(), &remote_ref_dir(remote), branch);
    RefMutation::acquire(layout.common_dir(), &path, &format!("{remote}/{branch}"))?.delete(None)
}

/// List all remote-tracking refs for one remote.
pub fn list_remote_refs(layout: &RepoLayout, remote: &str) -> RefResult<Vec<Ref>> {
    if !validate_ref_name(remote) {
        return Err(RefError::InvalidRefName(remote.to_string()));
    }
    list_refs_under(layout.common_dir(), &remote_ref_dir(remote))
}

/// List the remote names that have at least one tracking ref on disk
/// (the immediate subdirectories of `refs/remotes/`), sorted. A
/// missing `refs/remotes/` yields an empty list. Entries whose names
/// fail the ref grammar are skipped (consistent with how malformed
/// ref files are skipped by [`list_refs`]).
pub fn list_remote_names(layout: &RepoLayout) -> RefResult<Vec<String>> {
    let dir = layout.remotes_dir();
    let entries = match fs::read_dir(&dir) {
        Ok(e) => e,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(RefError::Io(e)),
    };
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry.map_err(RefError::Io)?;
        if !entry.file_type().map_err(RefError::Io)?.is_dir() {
            continue;
        }
        if let Some(name) = entry.file_name().to_str()
            && validate_ref_name(name)
        {
            names.push(name.to_owned());
        }
    }
    names.sort();
    Ok(names)
}

// -----------------------------------------------------------------------------
// Tags (refs/tags/<name>)
// -----------------------------------------------------------------------------

/// Read the hash a tag points to.
pub fn read_tag(layout: &RepoLayout, name: &str) -> RefResult<Option<Hash>> {
    if !validate_ref_name(name) {
        return Err(RefError::InvalidRefName(name.to_string()));
    }
    read_ref_under(layout.common_dir(), TAGS_DIR, name)
}

/// Write a tag ref (unconditional).
pub fn write_tag(layout: &RepoLayout, name: &str, h: &Hash) -> RefResult<()> {
    update_tag(layout, name, RefWriteCondition::Any, h)
}

/// CAS-aware tag write — same semantics as [`update_ref`] but for
/// `refs/tags/`.
pub fn update_tag(
    layout: &RepoLayout,
    name: &str,
    condition: RefWriteCondition,
    h: &Hash,
) -> RefResult<()> {
    if !validate_ref_name(name) {
        return Err(RefError::InvalidRefName(name.to_string()));
    }
    let path = ref_path(layout.common_dir(), TAGS_DIR, name);
    let wire = encode_ref_wire(h);
    cas_write(layout.common_dir(), &path, &wire, name, condition)
}

/// Delete a tag ref.
pub fn delete_tag(layout: &RepoLayout, name: &str) -> RefResult<()> {
    if !validate_ref_name(name) {
        return Err(RefError::InvalidRefName(name.to_string()));
    }
    let path = ref_path(layout.common_dir(), TAGS_DIR, name);
    RefMutation::acquire(layout.common_dir(), &path, name)?.delete(None)
}

/// List all tag refs, sorted lexicographically by name.
pub fn list_tags(layout: &RepoLayout) -> RefResult<Vec<Ref>> {
    list_refs_under(layout.common_dir(), TAGS_DIR)
}

// -----------------------------------------------------------------------------
// Shallow boundaries (.mkit/shallow)
// -----------------------------------------------------------------------------

/// Load shallow-boundary hashes from `.mkit/shallow`. Returns `Ok(None)`
/// if the file does not exist or is empty.
pub fn load_shallow_boundaries(layout: &RepoLayout) -> RefResult<Option<Vec<Hash>>> {
    let path = layout.shallow_file();
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
pub fn write_shallow_boundaries(layout: &RepoLayout, boundaries: &[Hash]) -> RefResult<()> {
    let path = layout.shallow_file();
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

fn ref_path(common_dir: &Path, sub_dir: &str, name: &str) -> PathBuf {
    let mut path = common_dir.join(sub_dir);
    for segment in name.split('/') {
        path.push(segment);
    }
    path
}

fn remote_ref_dir(remote: &str) -> String {
    format!("{REMOTES_DIR}/{remote}")
}

fn validate_remote_and_branch(remote: &str, branch: &str) -> RefResult<()> {
    if !validate_ref_name(remote) {
        return Err(RefError::InvalidRefName(remote.to_string()));
    }
    if !validate_ref_name(branch) {
        return Err(RefError::InvalidRefName(branch.to_string()));
    }
    Ok(())
}

fn read_ref_under(common_dir: &Path, sub_dir: &str, name: &str) -> RefResult<Option<Hash>> {
    let path = ref_path(common_dir, sub_dir, name);
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

/// A held mutation transaction for exactly one full ref identity. Every
/// write condition and delete uses this guard; history callers acquire their
/// history lock first and may call the guarded primitives without relocking.
pub(crate) struct RefMutation {
    path: PathBuf,
    common_dir: PathBuf,
    name: String,
    _lock: crate::repo_lock::RepoLock,
}

impl RefMutation {
    fn acquire(common_dir: &Path, path: &Path, name: &str) -> RefResult<Self> {
        let lock = crate::repo_lock::acquire_default(common_dir, &cas_lock_name(common_dir, path))
            .map_err(|e| match e {
                crate::repo_lock::LockError::Io(io) => RefError::Io(io),
                other => RefError::InvalidRef(format!("{name}: ref mutation lock: {other}")),
            })?;
        Ok(Self {
            path: path.to_path_buf(),
            common_dir: common_dir.to_path_buf(),
            name: name.to_string(),
            _lock: lock,
        })
    }

    pub(crate) fn current(&self) -> RefResult<Option<Hash>> {
        match fs::read(&self.path) {
            Ok(bytes) => decode_ref_wire(&bytes)
                .map(Some)
                .ok_or_else(|| RefError::InvalidRef(self.name.clone())),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(RefError::Io(e)),
        }
    }

    pub(crate) fn check(&self, condition: RefWriteCondition) -> RefResult<()> {
        let matches = match condition {
            RefWriteCondition::Any => true,
            RefWriteCondition::Missing => !self.path.try_exists()?,
            RefWriteCondition::Match(expected) => self.current()? == Some(expected),
        };
        if matches {
            Ok(())
        } else {
            Err(RefError::Conflict(self.name.clone()))
        }
    }

    fn invalidate_history(&self) -> RefResult<()> {
        if let Ok(full_ref) = self.path.strip_prefix(&self.common_dir) {
            ancestry_state::invalidate(&self.common_dir, &full_ref.to_string_lossy())?;
        }
        Ok(())
    }

    fn write(&self, wire: &[u8; 65], condition: RefWriteCondition) -> RefResult<()> {
        self.check(condition)?;
        // Even a same-tip raw write refuses to bypass an outstanding intent.
        // Ordinary writes preserve a matching snapshot only for a true no-op.
        if self.current().ok().flatten() != decode_ref_wire(wire) {
            self.invalidate_history()?;
        } else if ancestry_state::Transaction::read(&ancestry_state::branch_dir(
            &self.common_dir,
            &self
                .path
                .strip_prefix(&self.common_dir)
                .unwrap_or(&self.path)
                .to_string_lossy(),
        ))?
        .is_some()
        {
            return Err(RefError::InvalidRef("pending history publication".into()));
        }
        self.write_preserving_history(wire, condition)
    }

    pub(crate) fn write_preserving_history(
        &self,
        wire: &[u8; 65],
        condition: RefWriteCondition,
    ) -> RefResult<()> {
        self.check(condition)?;
        if matches!(condition, RefWriteCondition::Missing) {
            if !write_create_new(&self.path, wire, true)? {
                return Err(RefError::Conflict(self.name.clone()));
            }
        } else {
            write_atomic(&self.path, wire, true)?;
        }
        Ok(())
    }

    fn delete(&self, expected: Option<Hash>) -> RefResult<()> {
        if let Some(expected) = expected {
            self.check(RefWriteCondition::Match(expected))?;
        }
        self.invalidate_history()?;
        match fs::remove_file(&self.path) {
            Ok(()) => {
                crate::atomic::sync_dir(self.path.parent().expect("ref path has parent"))?;
                Ok(())
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                if expected.is_some() {
                    Err(RefError::Conflict(self.name.clone()))
                } else {
                    Err(RefError::NotFound(self.name.clone()))
                }
            }
            Err(e) => Err(RefError::Io(e)),
        }
    }
}

fn cas_write(
    common_dir: &Path,
    path: &Path,
    wire: &[u8; 65],
    name_for_err: &str,
    condition: RefWriteCondition,
) -> RefResult<()> {
    RefMutation::acquire(common_dir, path, name_for_err)?.write(wire, condition)
}

fn list_refs_under(common_dir: &Path, sub_dir: &str) -> RefResult<Vec<Ref>> {
    let root = common_dir.join(sub_dir);
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
    use std::sync::Barrier;
    use tempfile::TempDir;

    fn fresh_repo() -> (TempDir, RepoLayout) {
        let dir = TempDir::new().unwrap();
        let layout = RepoLayout::single(dir.path());
        fs::create_dir_all(layout.common_dir()).unwrap();
        init(&layout).unwrap();
        (dir, layout)
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
    fn validate_rejects_dot_leading_segment() {
        // git's check-ref-format rule: no slash-separated component may
        // begin with '.'. This also inertifies crash debris parked at a
        // dot-leading directory (e.g. a `.rename.tmp.<pid>.<seq>` orphan)
        // as a ref name, not just the exact `.`/`..` shapes above.
        assert!(!validate_ref_name(".hidden"));
        assert!(!validate_ref_name("refs/.hidden/main"));
        assert!(!validate_ref_name(".rename.tmp.12345.0"));
        assert!(!validate_ref_name("refs/remotes/.rename.tmp.12345.0/main"));
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
    fn validate_rejects_lock_suffix() {
        assert!(!validate_ref_name("refs/heads/main.lock"));
    }

    #[test]
    fn validate_rejects_head_final_segment() {
        assert!(!validate_ref_name("refs/heads/HEAD"));
        assert!(!validate_ref_name("HEAD"));
    }

    #[test]
    fn validate_accepts_main_regression() {
        assert!(validate_ref_name("refs/heads/main"));
    }

    #[test]
    fn validate_accepts_non_lock_suffix_regression() {
        // Only trailing ".lock" should reject; "lockfile" is fine.
        assert!(validate_ref_name("refs/heads/lockfile"));
    }

    #[test]
    fn validate_accepts_headless_regression() {
        // Only the exact final segment "HEAD" is rejected.
        assert!(validate_ref_name("refs/heads/HEADless"));
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
        let mkit = RepoLayout::single(dir.path());
        fs::create_dir_all(mkit.common_dir()).unwrap();
        let commit = h("detached");
        write_head_detached(&mkit, &commit).unwrap();
        match read_head(&mkit).unwrap() {
            Head::Detached(got) => assert_eq!(got, commit),
            other @ Head::Branch(_) => panic!("expected detached, got {other:?}"),
        }
        assert_eq!(resolve_head(&mkit).unwrap(), Some(commit));
    }

    #[test]
    fn read_head_rejects_oversize_file() {
        // SPEC-REFS §6: HEAD content is capped at 4 KiB.
        let dir = TempDir::new().unwrap();
        let mkit = RepoLayout::single(dir.path());
        fs::create_dir_all(mkit.common_dir()).unwrap();
        fs::write(
            mkit.head_file(),
            vec![b'a'; usize::try_from(HEAD_MAX_BYTES).unwrap() + 1],
        )
        .unwrap();
        let err = read_head(&mkit).unwrap_err();
        assert!(matches!(err, RefError::InvalidHead));
    }

    #[test]
    fn nonexistent_branch_returns_none() {
        let (_dir, mkit) = fresh_repo();
        assert_eq!(read_ref(&mkit, "nonexistent").unwrap(), None);
    }

    #[test]
    fn read_ref_rejects_oversize_file() {
        // SPEC-REFS §6: a single ref file is capped at 128 bytes.
        let (_dir, mkit) = fresh_repo();
        let path = ref_path(mkit.common_dir(), HEADS_DIR, "main");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(
            &path,
            vec![b'0'; usize::try_from(REF_FILE_MAX_BYTES).unwrap() + 1],
        )
        .unwrap();
        let err = read_ref(&mkit, "main").unwrap_err();
        assert!(matches!(err, RefError::InvalidRef(_)));
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
    fn list_refs_silently_skips_entries_beyond_max_depth() {
        // SPEC-REFS §6: listing recurses with a hard depth cap of 32
        // levels to defeat adversarial nesting; anything deeper is
        // silently skipped (not an error, not a stack overflow).
        let (_dir, mkit) = fresh_repo();
        let deep_name = (0..40)
            .map(|i| format!("d{i}"))
            .collect::<Vec<_>>()
            .join("/");
        write_ref(&mkit, &deep_name, &h("deep")).unwrap();
        write_ref(&mkit, "main", &h("shallow")).unwrap();

        let refs = list_refs(&mkit).unwrap();
        let names: Vec<&str> = refs.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"main"), "shallow ref must still be listed");
        assert!(
            !names.contains(&deep_name.as_str()),
            "a ref nested beyond MAX_REF_DEPTH must be silently skipped, got {names:?}"
        );
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

    // --- INV-15 / #637: Match CAS must be atomic across uncoordinated
    // callers -------------------------------------------------------------

    /// Reproduces the lost-update race described in INV-15: two callers
    /// that do NOT share any lock (mimicking `branch -m` under
    /// `worktrees.lock` racing `commit` under `worktree.lock`, or two
    /// linked worktrees each holding their own `worktree.lock`) both
    /// read the ref's current value, both see it matches their
    /// expectation, and both `cas_write`. Without cross-process
    /// atomicity on the read-compare-write, both calls can report
    /// success even though only one write actually survives — silently
    /// losing the other caller's update.
    ///
    /// `layout_a`/`layout_b` are two distinct [`RepoLayout`]s (a
    /// "single" layout and a "linked" layout with a different
    /// `worktree_root`/`worktree_state_dir`) that share only
    /// `common_dir` — exactly the shape of two linked worktrees, each
    /// of which would hold its own separate `worktree.lock` and thus
    /// share no lock with the other over this CAS. A `Barrier` forces
    /// both threads to enter `update_ref` at (as close to) the same
    /// instant as the scheduler allows, and the loop repeats many
    /// iterations because the race window is a handful of syscalls wide
    /// and is not guaranteed to be hit on any single attempt.
    ///
    /// Before the #637 fix (no shared `refs.lock` around the `Match`
    /// arm) this reliably reproduces a "both succeeded" iteration within
    /// a few hundred attempts. After the fix, the shared lock makes the
    /// read-compare-write atomic across both callers, so this must
    /// never happen — exactly one of the two racing writers may
    /// succeed.
    #[test]
    fn cas_match_race_never_loses_an_update_across_uncoordinated_callers() {
        let (_dir, layout_a) = fresh_repo();
        let layout_b = RepoLayout::linked(
            layout_a.worktree_root().join("other-worktree"),
            layout_a.common_dir().join("worktrees").join("other"),
            layout_a.common_dir(),
        );

        let base = h("base");
        write_ref(&layout_a, "main", &base).unwrap();

        let iterations: usize = 500;
        let mut double_success_iteration = None;

        for i in 0..iterations {
            // Reset to a known base before each round. `Any` bypasses
            // CAS entirely, so this is not itself part of what's under
            // test.
            update_ref(&layout_a, "main", RefWriteCondition::Any, &base).unwrap();

            let val_a = h(&format!("race-a-{i}"));
            let val_b = h(&format!("race-b-{i}"));
            let barrier = Barrier::new(2);

            let (result_a, result_b) = std::thread::scope(|scope| {
                let handle_a = scope.spawn(|| {
                    barrier.wait();
                    update_ref(&layout_a, "main", RefWriteCondition::Match(base), &val_a)
                });
                let handle_b = scope.spawn(|| {
                    barrier.wait();
                    update_ref(&layout_b, "main", RefWriteCondition::Match(base), &val_b)
                });
                (handle_a.join().unwrap(), handle_b.join().unwrap())
            });

            if result_a.is_ok() && result_b.is_ok() {
                double_success_iteration = Some(i);
                break;
            }
        }

        assert!(
            double_success_iteration.is_none(),
            "both uncoordinated Match CAS callers reported success on iteration \
             {double_success_iteration:?} — an update was silently lost \
             (INV-15/INV-6 violation)"
        );
    }

    /// All mutations must join the CAS critical section, including calls
    /// from a linked tree with its own unrelated worktree lock.
    #[test]
    fn every_ref_mutation_waits_for_the_cas_guard() {
        use std::sync::mpsc;
        use std::time::Duration;
        for operation in 0..10 {
            let (_dir, layout) = fresh_repo();
            let branch = "mutation-guard";
            let sub_dir = match operation {
                5 | 6 => TAGS_DIR.to_string(),
                7..=9 => remote_ref_dir("default"),
                _ => HEADS_DIR.to_string(),
            };
            let path = ref_path(layout.common_dir(), &sub_dir, branch);
            cas_write(
                layout.common_dir(),
                &path,
                &encode_ref_wire(&h("base")),
                branch,
                RefWriteCondition::Any,
            )
            .unwrap();
            let lock = crate::repo_lock::acquire_default(
                layout.common_dir(),
                &cas_lock_name(layout.common_dir(), &path),
            )
            .unwrap();
            let linked = RepoLayout::linked(
                layout.worktree_root().join("linked"),
                layout.common_dir().join("worktrees/linked"),
                layout.common_dir(),
            );
            let (done_tx, done_rx) = mpsc::channel();
            let worker = std::thread::spawn(move || {
                let result = match operation {
                    0 => update_ref(&linked, branch, RefWriteCondition::Any, &h("next")),
                    1 => update_ref(&linked, branch, RefWriteCondition::Missing, &h("next")),
                    2 => delete_ref(&linked, branch),
                    3 => delete_ref_if_matches(&linked, branch, h("base")),
                    4 => update_ref(
                        &linked,
                        branch,
                        RefWriteCondition::Match(h("base")),
                        &h("next"),
                    ),
                    5 => write_tag(&linked, branch, &h("next")),
                    6 => delete_tag(&linked, branch),
                    7 => write_remote_ref(&linked, "default", branch, &h("next")),
                    8 => delete_remote_ref(&linked, "default", branch),
                    _ => {
                        let mut batch = RemoteRefBatch::new(&linked, "default").unwrap();
                        batch
                            .write(branch, &h("next"))
                            .and_then(|()| batch.commit())
                    }
                };
                done_tx.send(result).unwrap();
            });
            let premature = done_rx.recv_timeout(Duration::from_millis(100));
            let observed = fs::read(&path).ok().and_then(|b| decode_ref_wire(&b));
            drop(lock);
            worker.join().unwrap();
            assert!(
                matches!(premature, Err(mpsc::RecvTimeoutError::Timeout)),
                "operation {operation} bypassed the held CAS guard: {premature:?}"
            );
            assert_eq!(
                observed,
                Some(h("base")),
                "mutation must not precede guard acquisition"
            );
            let result = done_rx.recv_timeout(Duration::from_secs(2)).unwrap();
            assert_eq!(result.is_ok(), operation != 1);
        }
    }

    #[test]
    fn remote_batches_with_reversed_ref_order_finish_without_nested_ref_locks() {
        let (_dir, layout) = fresh_repo();
        let barrier = Barrier::new(2);
        std::thread::scope(|scope| {
            let a = scope.spawn(|| {
                barrier.wait();
                let mut batch = RemoteRefBatch::new(&layout, "default").unwrap();
                for branch in ["z", "a"] {
                    batch.write(branch, &h("a")).unwrap();
                }
                batch.commit().unwrap();
            });
            let b = scope.spawn(|| {
                barrier.wait();
                let mut batch = RemoteRefBatch::new(&layout, "default").unwrap();
                for branch in ["a", "z"] {
                    batch.write(branch, &h("b")).unwrap();
                }
                batch.commit().unwrap();
            });
            a.join().unwrap();
            b.join().unwrap();
        });
        for branch in ["a", "z"] {
            let value = read_remote_ref(&layout, "default", branch)
                .unwrap()
                .unwrap();
            assert!(value == h("a") || value == h("b"));
        }
    }

    /// Normal-case companion to the race test above: with no
    /// contention, a sequence of `Match` CAS writes on the same ref must
    /// still succeed every time and never wedge (guards against the
    /// `refs.lock` acquire/release added for #637 leaking or
    /// deadlocking across repeated calls from the same layout).
    #[test]
    fn cas_match_succeeds_repeatedly_when_uncontended() {
        let (_dir, mkit) = fresh_repo();
        let mut current = h("seed");
        write_ref(&mkit, "main", &current).unwrap();

        for i in 0..20 {
            let next = h(&format!("v{i}"));
            update_ref(&mkit, "main", RefWriteCondition::Match(current), &next).unwrap();
            assert_eq!(read_ref(&mkit, "main").unwrap(), Some(next));
            current = next;
        }
    }

    // --- INV-15 / #658: CAS-guarded delete must not lose a concurrent
    // Match-conditioned advance ---------------------------------------

    /// Primitive-level reproduction of #658's "Race 1": a caller (e.g.
    /// `branch -m`) reads a branch's tip `T`, then — before it gets
    /// around to deleting the ref — a concurrent `Match(T)` CAS (e.g.
    /// `commit`'s fixed advance) lands, moving the ref to `C`. The
    /// caller's delete must detect that the ref no longer matches what
    /// it read and refuse, leaving `C` on disk untouched.
    ///
    /// Confirmed against the pre-fix shape of this codebase: pointing
    /// this same sequence at plain, unconditional [`delete_ref`] instead
    /// of [`delete_ref_if_matches`] removes the ref regardless of `T` vs
    /// `C`, silently destroying the concurrently-landed `C` — exactly
    /// the bug #658 reports. [`delete_ref_if_matches`] must refuse
    /// instead.
    #[test]
    fn cas_delete_refuses_when_ref_moved_after_read() {
        let (_dir, mkit) = fresh_repo();
        let t = h("t");
        let c = h("c");
        write_ref(&mkit, "main", &t).unwrap();

        // Caller reads the tip...
        let read_t = read_ref(&mkit, "main").unwrap().unwrap();
        assert_eq!(read_t, t);

        // ...then a concurrent Match(T) CAS (a fixed `commit`) lands
        // before the caller's delete runs.
        update_ref(&mkit, "main", RefWriteCondition::Match(t), &c).unwrap();

        let err = delete_ref_if_matches(&mkit, "main", read_t).unwrap_err();
        assert!(
            matches!(err, RefError::Conflict(_)),
            "expected Conflict, got {err:?}"
        );
        assert_eq!(
            read_ref(&mkit, "main").unwrap(),
            Some(c),
            "the concurrently-landed commit must survive the refused delete untouched"
        );
    }

    /// `delete_ref_if_matches` refusing to delete must not remove the
    /// file at all — a second, correctly-conditioned delete against the
    /// NEW value must still succeed.
    #[test]
    fn cas_delete_refusal_leaves_ref_deletable_against_its_new_value() {
        let (_dir, mkit) = fresh_repo();
        let t = h("t");
        let c = h("c");
        write_ref(&mkit, "main", &t).unwrap();
        update_ref(&mkit, "main", RefWriteCondition::Match(t), &c).unwrap();

        assert!(matches!(
            delete_ref_if_matches(&mkit, "main", t).unwrap_err(),
            RefError::Conflict(_)
        ));
        delete_ref_if_matches(&mkit, "main", c).unwrap();
        assert_eq!(read_ref(&mkit, "main").unwrap(), None);
    }

    #[test]
    fn cas_delete_fails_on_missing_ref() {
        let (_dir, mkit) = fresh_repo();
        let err = delete_ref_if_matches(&mkit, "main", h("anything")).unwrap_err();
        assert!(matches!(err, RefError::Conflict(_)));
    }

    /// Racing-loop version of the reproduction above, mirroring
    /// [`cas_match_race_never_loses_an_update_across_uncoordinated_callers`]'s
    /// pattern: on each iteration, one thread performs a `Match`-guarded
    /// advance (mirroring a fixed `commit`) and the other performs a
    /// `delete_ref_if_matches` against the pre-advance value (mirroring
    /// `branch -m`'s rename), both released by the same `Barrier` so the
    /// scheduler is given its best shot at interleaving them. Because
    /// both operations serialize under the same per-ref lock
    /// ([`cas_lock_name`]), exactly one of the two may ever report
    /// success against a given prior value — never both, and the loser
    /// must never observe (or cause) a torn/lost state.
    #[test]
    fn cas_delete_vs_match_advance_race_never_lets_both_win_or_loses_the_advance() {
        let (_dir, mkit) = fresh_repo();
        let iterations: usize = 500;
        let mut bad_iteration: Option<(usize, &'static str)> = None;

        for i in 0..iterations {
            let base = h(&format!("base-{i}"));
            write_ref(&mkit, "main", &base).unwrap();
            let new_tip = h(&format!("advanced-{i}"));
            let barrier = Barrier::new(2);

            let (advance_result, delete_result) = std::thread::scope(|scope| {
                let advance_handle = scope.spawn(|| {
                    barrier.wait();
                    update_ref(&mkit, "main", RefWriteCondition::Match(base), &new_tip)
                });
                let delete_handle = scope.spawn(|| {
                    barrier.wait();
                    delete_ref_if_matches(&mkit, "main", base)
                });
                (
                    advance_handle.join().unwrap(),
                    delete_handle.join().unwrap(),
                )
            });

            match (&advance_result, &delete_result) {
                (Ok(()), Ok(())) => {
                    bad_iteration = Some((
                        i,
                        "both the concurrent advance and the concurrent delete reported success",
                    ));
                }
                (Ok(()), Err(RefError::Conflict(_))) => {
                    // The advance won the race; its value must survive.
                    if read_ref(&mkit, "main").unwrap() != Some(new_tip) {
                        bad_iteration = Some((
                            i,
                            "advance reported success but its value is not on disk — lost update",
                        ));
                    }
                }
                (Err(RefError::Conflict(_)), Ok(())) => {
                    // The delete won the race before the advance landed;
                    // the ref must be gone (the advance must have then
                    // failed its own CAS, which the match arm above
                    // already confirms).
                    if read_ref(&mkit, "main").unwrap().is_some() {
                        bad_iteration = Some((
                            i,
                            "delete reported success but the ref is still present on disk",
                        ));
                    }
                }
                (Err(RefError::Conflict(_)), Err(RefError::Conflict(_))) => {
                    // Both lost — impossible on a fresh `base` write each
                    // round with only these two writers, but not itself a
                    // safety violation; leave unhandled rather than
                    // silently accepting on a bug that could produce it.
                    bad_iteration = Some((
                        i,
                        "both the advance and the delete reported Conflict against a freshly-written base",
                    ));
                }
                _ => {
                    bad_iteration = Some((i, "unexpected error variant"));
                }
            }

            if bad_iteration.is_some() {
                break;
            }
        }

        assert!(
            bad_iteration.is_none(),
            "iteration {bad_iteration:?}: a concurrent Match-conditioned advance and a \
             CAS-guarded delete on the same ref did not serialize correctly (issue #658)"
        );
    }

    /// Cross-ref counterpart to the race test above: `refs.lock` used
    /// to be one repo-wide lock, so a `Match` CAS on branch "other"
    /// would block one on unrelated branch "main" for no reason —
    /// nothing about this CAS invariant spans refs. Now keyed per ref
    /// via [`cas_lock_name`]; proves an externally-held lock on
    /// "other"'s ref path does NOT block a `Match` CAS on "main"'s.
    #[test]
    fn cas_match_does_not_contend_across_different_refs() {
        let (_dir, mkit) = fresh_repo();
        write_ref(&mkit, "main", &h("m0")).unwrap();
        write_ref(&mkit, "other", &h("o0")).unwrap();

        let other_path = ref_path(mkit.common_dir(), HEADS_DIR, "other");
        let other_lock_name = cas_lock_name(mkit.common_dir(), &other_path);
        let common_dir = mkit.common_dir().to_path_buf();
        let (holding_tx, holding_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let holder = std::thread::spawn(move || {
            let _lock = crate::repo_lock::acquire_default(&common_dir, &other_lock_name).unwrap();
            holding_tx.send(()).unwrap();
            release_rx.recv().unwrap();
        });
        holding_rx.recv().unwrap();

        let start = std::time::Instant::now();
        update_ref(&mkit, "main", RefWriteCondition::Match(h("m0")), &h("m1")).unwrap();
        let elapsed = start.elapsed();

        release_tx.send(()).unwrap();
        holder.join().unwrap();

        assert!(
            elapsed < std::time::Duration::from_secs(1),
            "Match CAS on \"main\" took {elapsed:?} while \"other\"'s ref lock was held \
             elsewhere — refs are contending when they shouldn't be"
        );
        assert_eq!(read_ref(&mkit, "main").unwrap(), Some(h("m1")));
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
    fn load_shallow_rejects_oversize_file() {
        // SPEC-REFS §6: the shallow file is capped at 1 MiB.
        let (_dir, mkit) = fresh_repo();
        let path = mkit.shallow_file();
        fs::write(
            &path,
            vec![b'a'; usize::try_from(SHALLOW_MAX_BYTES).unwrap() + 1],
        )
        .unwrap();
        let err = load_shallow_boundaries(&mkit).unwrap_err();
        assert!(matches!(err, RefError::InvalidRef(_)));
    }

    #[test]
    fn load_shallow_skips_invalid_lines() {
        let (_dir, mkit) = fresh_repo();
        let path = mkit.shallow_file();
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

    // --- remote-ref batching (#645) --------------------------------------
    //
    // `push`/`fetch` publish one remote-tracking ref per branch in a loop
    // (`mkit-cli`'s `remote_dispatch::push_all_with` /
    // `fetch_objects_inner`). Each `write_remote_ref` call goes through
    // `cas_write` → `write_atomic`, which pays a parent-directory fsync
    // EVERY call (`atomic.rs`'s `sync_parent_dir`) — so N branches cost N
    // directory fsyncs, serially, even though they all land in the same
    // `refs/remotes/<remote>/` directory. `RemoteRefBatch` amortises that
    // into one fsync per distinct directory touched, however many refs
    // were written into it.

    /// Baseline (pre-#645): today's per-ref loop — exactly what
    /// `push_all_with`/`fetch_objects_inner` do today — pays one
    /// directory fsync per ref, even though every ref lands in the same
    /// `refs/remotes/origin/` directory. This is the O(N) cost #645
    /// exists to amortise; it must keep holding after the fix, since
    /// `write_remote_ref` itself (used elsewhere for single-ref writes)
    /// is intentionally left on the unbatched path.
    #[test]
    fn write_remote_ref_loop_pays_one_dir_sync_per_ref_today() {
        let (_dir, mkit) = fresh_repo();
        let n: u64 = 25;
        crate::atomic::testing::reset_dir_sync_calls();
        for i in 0..n {
            write_remote_ref(
                &mkit,
                "origin",
                &format!("branch-{i}"),
                &h(&format!("c{i}")),
            )
            .unwrap();
        }
        let calls = crate::atomic::testing::dir_sync_calls();
        assert_eq!(
            calls, n,
            "the current per-ref write path must cost exactly one directory \
             fsync per ref (O(N)); got {calls} for {n} refs"
        );
    }

    /// The #645 fix: staging N remote-tracking-ref writes into one
    /// `RemoteRefBatch` and committing once must cost O(1) directory
    /// fsyncs (one per distinct directory touched — here a single flat
    /// `refs/remotes/origin/` namespace, so exactly one), not O(N).
    #[test]
    fn remote_ref_batch_pays_one_dir_sync_for_many_refs() {
        let (_dir, mkit) = fresh_repo();
        let n = 25;
        let entries: Vec<(String, Hash)> = (0..n)
            .map(|i| (format!("branch-{i}"), h(&format!("c{i}"))))
            .collect();

        crate::atomic::testing::reset_dir_sync_calls();
        let mut batch = RemoteRefBatch::new(&mkit, "origin").unwrap();
        for (branch, hash) in &entries {
            batch.write(branch, hash).unwrap();
        }
        batch.commit().unwrap();

        let calls = crate::atomic::testing::dir_sync_calls();
        assert_eq!(
            calls, 1,
            "batching {n} tracking-ref writes into one flat remote \
             namespace must cost exactly one directory fsync (O(1)), got {calls}"
        );
    }

    /// Correctness: batched writes must produce the exact same final ref
    /// states as the old per-ref `write_remote_ref` loop — same hashes,
    /// same readability, for every branch.
    #[test]
    fn remote_ref_batch_matches_per_ref_loop_final_state() {
        let (_dir, old_path) = fresh_repo();
        let (_dir2, new_path) = fresh_repo();
        let n = 12;
        let entries: Vec<(String, Hash)> = (0..n)
            .map(|i| (format!("team/branch-{i}"), h(&format!("state{i}"))))
            .collect();

        for (branch, hash) in &entries {
            write_remote_ref(&old_path, "origin", branch, hash).unwrap();
        }

        let mut batch = RemoteRefBatch::new(&new_path, "origin").unwrap();
        for (branch, hash) in &entries {
            batch.write(branch, hash).unwrap();
        }
        batch.commit().unwrap();

        for (branch, hash) in &entries {
            let old_val = read_remote_ref(&old_path, "origin", branch).unwrap();
            let new_val = read_remote_ref(&new_path, "origin", branch).unwrap();
            assert_eq!(old_val, Some(*hash));
            assert_eq!(new_val, Some(*hash));
            assert_eq!(old_val, new_val, "branch {branch} diverged");
        }
    }

    /// Partial-failure semantics: best-effort / fail-fast, matching
    /// `WriteBatch::commit`'s documented contract (already-renamed
    /// entries stay visible; no rollback). An invalid branch name in the
    /// middle of a batch aborts every write from that point on — the
    /// refs staged before it stay visible and readable, exactly as they
    /// would have under the old per-ref loop had it hit the same
    /// mid-loop error (each earlier ref was already independently
    /// visible before the loop reached the bad one).
    #[test]
    fn remote_ref_batch_partial_failure_keeps_already_written_refs_visible() {
        let (_dir, mkit) = fresh_repo();
        let mut batch = RemoteRefBatch::new(&mkit, "origin").unwrap();
        batch.write("good-1", &h("g1")).unwrap();
        batch.write("good-2", &h("g2")).unwrap();
        let err = batch.write("bad//name", &h("x")).unwrap_err();
        assert!(matches!(err, RefError::InvalidRefName(_)));

        // Committing what was staged before the bad write must still
        // durably publish the good entries.
        batch.commit().unwrap();
        assert_eq!(
            read_remote_ref(&mkit, "origin", "good-1").unwrap(),
            Some(h("g1"))
        );
        assert_eq!(
            read_remote_ref(&mkit, "origin", "good-2").unwrap(),
            Some(h("g2"))
        );
        // "bad//name" was never a valid ref name in the first place —
        // nothing was ever staged for it, on either the old or new path.
        let never_written = read_remote_ref(&mkit, "origin", "bad//name").unwrap_err();
        assert!(matches!(never_written, RefError::InvalidRefName(_)));
    }

    #[test]
    fn remote_ref_batch_rejects_invalid_remote_name() {
        let (_dir, mkit) = fresh_repo();
        let err = RemoteRefBatch::new(&mkit, "../escape").unwrap_err();
        assert!(matches!(err, RefError::InvalidRefName(_)));
    }

    #[test]
    fn remote_ref_batch_of_zero_entries_is_a_noop_commit() {
        let (_dir, mkit) = fresh_repo();
        crate::atomic::testing::reset_dir_sync_calls();
        let batch = RemoteRefBatch::new(&mkit, "origin").unwrap();
        batch.commit().unwrap();
        assert_eq!(
            crate::atomic::testing::dir_sync_calls(),
            0,
            "an empty batch must not touch any directory"
        );
    }
}
