//! Versioned snapshots over verified first-parent ancestry.

use std::collections::BTreeSet;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use super::{CommitHistory, HistoryError, InclusionProof, Position, verify_inclusion};
use crate::hash::{self, Hash};
use crate::layout::RepoLayout;
use crate::object::Object;
use crate::refs::ancestry_state::{self, Transaction};
use crate::refs::{self, RefMutation, RefWriteCondition};
use crate::store::ObjectStore;

const MAGIC: &[u8; 5] = b"MKHA\x01";
/// Bound both graph walking and persisted allocation (32 MiB of leaf hashes).
pub(crate) const MAX_ANCESTRY_LEAVES: usize = 1_000_000;
const MAX_SNAPSHOT_BYTES: u64 = (MAX_ANCESTRY_LEAVES as u64) * 32 + 8192;

/// Context bound by a v1 ancestry descriptor. The MMB digest excludes context:
/// identical first-parent chains have identical roots across update schedules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AncestryDescriptor {
    pub repository: Hash,
    pub full_ref: String,
    pub generation: Hash,
    pub tip: Hash,
    pub leaf_count: u64,
    pub root: Hash,
}

/// A descriptor loaded from a local snapshot and checked against the locally
/// authoritative ref and verified object chain. Network input cannot construct
/// this type; a remote descriptor on its own is not an authentication source.
#[derive(Debug, Clone)]
pub struct TrustedAncestryDescriptor(AncestryDescriptor);

impl TrustedAncestryDescriptor {
    #[must_use]
    pub fn descriptor(&self) -> &AncestryDescriptor {
        &self.0
    }
}

/// Reconstructible ancestry state and proof primitive for one exact tip.
#[derive(Debug)]
pub struct AncestrySnapshot {
    descriptor: AncestryDescriptor,
    chain: Vec<Hash>,
    mmb: CommitHistory,
}

impl AncestrySnapshot {
    /// Load a trusted local snapshot without creating, upgrading or recovering
    /// files. Pending publication, stale context and missing ancestors fail.
    pub fn load(layout: &RepoLayout, branch: &str) -> Result<Self, HistoryError> {
        let (_history_lock, mutation) = refs::acquire_history_mutation(layout, branch)?;
        let dir = ancestry_state::branch_dir(layout.common_dir(), &format!("refs/heads/{branch}"));
        if Transaction::read(&dir)?.is_some() {
            return Err(HistoryError::Corrupted(
                "history publication pending; retry the write to recover".into(),
            ));
        }
        let repository = read_repository_id(layout.common_dir())?.ok_or_else(|| {
            HistoryError::Corrupted("no trusted local ancestry descriptor".into())
        })?;
        let snapshot = read_current(&dir)?
            .ok_or_else(|| HistoryError::Corrupted("no trusted local ancestry snapshot".into()))?;
        let current = mutation.current()?;
        if snapshot.descriptor.repository != repository
            || snapshot.descriptor.full_ref != format!("refs/heads/{branch}")
            || Some(snapshot.descriptor.tip) != current
        {
            return Err(HistoryError::Corrupted(
                "ancestry descriptor does not match the authoritative ref".into(),
            ));
        }
        let store = ObjectStore::open(layout)?;
        if snapshot.chain != first_parent_chain(&store, snapshot.descriptor.tip)? {
            return Err(HistoryError::Corrupted(
                "snapshot is not the current first-parent chain".into(),
            ));
        }
        Ok(snapshot)
    }

    #[must_use]
    pub fn descriptor(&self) -> &AncestryDescriptor {
        &self.descriptor
    }
    #[must_use]
    pub fn trusted_descriptor(&self) -> TrustedAncestryDescriptor {
        TrustedAncestryDescriptor(self.descriptor.clone())
    }
    #[must_use]
    pub fn len(&self) -> u64 {
        self.descriptor.leaf_count
    }
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.chain.is_empty()
    }
    #[must_use]
    pub fn root(&self) -> Hash {
        self.descriptor.root
    }
    pub fn prove(&self, position: Position) -> Result<InclusionProof, HistoryError> {
        self.mmb.prove(position)
    }
    #[must_use]
    pub fn position_of(&self, commit: &Hash) -> Option<Position> {
        self.chain
            .iter()
            .position(|h| h == commit)
            .map(|n| Position(n as u64))
    }

    fn build(
        repository: Hash,
        full_ref: String,
        generation: Hash,
        chain: Vec<Hash>,
    ) -> Result<Self, HistoryError> {
        if chain.is_empty() || chain.len() > MAX_ANCESTRY_LEAVES {
            return Err(HistoryError::Corrupted(
                "invalid ancestry leaf count".into(),
            ));
        }
        let mut mmb = CommitHistory::open();
        mmb.extend(&chain)?;
        let descriptor = AncestryDescriptor {
            repository,
            full_ref,
            generation,
            tip: *chain.last().expect("nonempty chain"),
            leaf_count: chain.len() as u64,
            root: mmb.root(),
        };
        Ok(Self {
            descriptor,
            chain,
            mmb,
        })
    }

    fn encode(&self) -> Result<Vec<u8>, HistoryError> {
        let d = &self.descriptor;
        let name_len = u16::try_from(d.full_ref.len())
            .map_err(|_| HistoryError::InvalidBranch(d.full_ref.clone()))?;
        let mut bytes = Vec::with_capacity(self.chain.len() * 32 + 192 + d.full_ref.len());
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&d.repository);
        bytes.extend_from_slice(&d.generation);
        bytes.extend_from_slice(&d.tip);
        bytes.extend_from_slice(&d.leaf_count.to_le_bytes());
        bytes.extend_from_slice(&d.root);
        bytes.extend_from_slice(&name_len.to_le_bytes());
        bytes.extend_from_slice(d.full_ref.as_bytes());
        for h in &self.chain {
            bytes.extend_from_slice(h);
        }
        bytes.extend_from_slice(&hash::hash(&bytes));
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self, HistoryError> {
        let (claimed, chain) = decode_descriptor_and_chain(bytes)?;
        let invalid = || HistoryError::Corrupted("malformed ancestry snapshot".into());
        let snapshot = Self::build(
            claimed.repository,
            claimed.full_ref.clone(),
            claimed.generation,
            chain,
        )?;
        if snapshot.descriptor.tip != claimed.tip || snapshot.descriptor.root != claimed.root {
            return Err(invalid());
        }
        Ok(snapshot)
    }
}

fn take<'a>(input: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
    if input.len() < n {
        return None;
    }
    let (head, tail) = input.split_at(n);
    *input = tail;
    Some(head)
}

fn descriptor_header_invalid() -> HistoryError {
    HistoryError::Corrupted("malformed ancestry snapshot".into())
}

/// Parse the fixed-size descriptor header and ref name from the front of
/// a snapshot's payload — everything up to, but not including, the
/// leaf-hash chain. Consumes `input` through the ref name; whatever
/// remains (the chain, for a full payload, or nothing, for a header-only
/// prefix read) is left for the caller. Shared by [`decode_descriptor_and_chain`]
/// (which continues on to parse and checksum-verify the chain) and
/// [`read_current_descriptor`] (which reads only this prefix from disk).
fn parse_descriptor_header(input: &mut &[u8]) -> Result<AncestryDescriptor, HistoryError> {
    fn digest(input: &mut &[u8]) -> Option<Hash> {
        take(input, 32)?.try_into().ok()
    }
    let invalid = descriptor_header_invalid;
    if take(input, 5) != Some(MAGIC.as_slice()) {
        return Err(invalid());
    }
    let repository = digest(input).ok_or_else(invalid)?;
    let generation = digest(input).ok_or_else(invalid)?;
    let tip = digest(input).ok_or_else(invalid)?;
    let count = u64::from_le_bytes(
        take(input, 8)
            .ok_or_else(invalid)?
            .try_into()
            .map_err(|_| invalid())?,
    );
    let root = digest(input).ok_or_else(invalid)?;
    let name_len = u16::from_le_bytes(
        take(input, 2)
            .ok_or_else(invalid)?
            .try_into()
            .map_err(|_| invalid())?,
    ) as usize;
    let full_ref = std::str::from_utf8(take(input, name_len).ok_or_else(invalid)?)
        .map_err(|_| invalid())?
        .to_owned();
    if !full_ref.starts_with("refs/heads/")
        || !refs::validate_ref_name(&full_ref)
        || count == 0
        || count > MAX_ANCESTRY_LEAVES as u64
    {
        return Err(invalid());
    }
    Ok(AncestryDescriptor {
        repository,
        full_ref,
        generation,
        tip,
        leaf_count: count,
        root,
    })
}

/// Parse a snapshot's wire bytes into its claimed descriptor and full
/// chain. The payload checksum (covering the encoded `root` along with
/// everything else) is verified against the whole payload before any
/// field is trusted, so accidental corruption or a torn/partial write is
/// caught here. Used by [`AncestrySnapshot::decode`] (via
/// [`AncestrySnapshot::load`] and `finish`'s from-scratch rebuild, both of
/// which need the actual chain and a working MMB for
/// [`AncestrySnapshot::prove`]) — [`read_current_descriptor`] is the
/// lighter, checksum-free sibling for `advance`'s comparison-only need,
/// which never touches `chain` or the MMB at all; see its own docs for
/// why skipping the checksum is safe there.
fn decode_descriptor_and_chain(
    bytes: &[u8],
) -> Result<(AncestryDescriptor, Vec<Hash>), HistoryError> {
    let invalid = descriptor_header_invalid;
    if bytes.len() < 175 || bytes.len() as u64 > MAX_SNAPSHOT_BYTES {
        return Err(invalid());
    }
    let (payload, checksum) = bytes.split_at(bytes.len() - 32);
    if hash::hash(payload).as_slice() != checksum {
        return Err(invalid());
    }
    let mut input = payload;
    let descriptor = parse_descriptor_header(&mut input)?;
    if input.len() as u64 != descriptor.leaf_count * 32 {
        return Err(invalid());
    }
    let chain: Vec<Hash> = input
        .chunks_exact(32)
        .map(|c| c.try_into().expect("32-byte chunk"))
        .collect();
    Ok((descriptor, chain))
}

/// Prefix length generous enough for any ref name a snapshot could
/// actually contain: the fixed header (5+32+32+32+8+32+2 = 143 bytes)
/// plus the largest possible `name_len` (a `u16`). Reading this many
/// bytes up front — one bounded read via [`read_prefix`] — means
/// [`read_current_descriptor`] never needs a second read regardless of
/// ref name length, while still stopping far short of the up-to-32 MiB
/// leaf-hash chain that follows for any history of meaningful size.
const DESCRIPTOR_HEADER_MAX_LEN: u64 = 143 + u16::MAX as u64;

/// Read up to `max_bytes` from `path`, without erroring if the file is
/// larger — the caller wants only a prefix, not an exact-length read.
/// `Ok(None)` if the file does not exist, matching
/// [`ancestry_state::read_bounded`]'s convention.
fn read_prefix(path: &Path, max_bytes: u64) -> Result<Option<Vec<u8>>, HistoryError> {
    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(HistoryError::Io(e)),
    };
    let mut bytes = Vec::new();
    file.take(max_bytes)
        .read_to_end(&mut bytes)
        .map_err(HistoryError::Io)?;
    Ok(Some(bytes))
}

/// Verify first-parent inclusion against an independently trusted local
/// descriptor AND the caller's exact expected context. A supplied root cannot
/// authenticate itself. A valid snapshot is evidence at that tip, not freshness
/// after the snapshot was obtained.
#[must_use]
pub fn verify_ancestry(
    commit: &Hash,
    position: Position,
    proof: &InclusionProof,
    claimed: &AncestryDescriptor,
    trusted: &TrustedAncestryDescriptor,
    expected: &AncestryDescriptor,
) -> bool {
    claimed == trusted.descriptor()
        && claimed == expected
        && position.0 < claimed.leaf_count
        && verify_inclusion(commit, position, proof, &claimed.root)
}

fn ancestry_cycle_or_limit() -> HistoryError {
    HistoryError::Corrupted("ancestry cycle or traversal limit".into())
}

fn ancestry_not_commit_or_remix() -> HistoryError {
    HistoryError::Corrupted("ancestry node is not a commit/remix".into())
}

fn first_parent_chain(store: &ObjectStore, tip: Hash) -> Result<Vec<Hash>, HistoryError> {
    let mut chain = Vec::new();
    let mut seen = BTreeSet::new();
    let mut next = Some(tip);
    while let Some(h) = next {
        if chain.len() >= MAX_ANCESTRY_LEAVES || !seen.insert(h) {
            return Err(ancestry_cycle_or_limit());
        }
        chain.push(h);
        next = match store.read_object(&h)? {
            Object::Commit(c) => c.parents.first().copied(),
            Object::Remix(r) => r.parents.first().copied(),
            _ => return Err(ancestry_not_commit_or_remix()),
        };
    }
    chain.reverse();
    Ok(chain)
}

/// Outcome of [`first_parent_suffix_to`]: whether `target`'s first-parent
/// ancestry passes through a previously-published tip before exhausting
/// itself at genesis.
enum SuffixWalk {
    /// It does: the hashes strictly after `stop_at`, oldest first, ending
    /// at `target` (empty when `target == stop_at`).
    Reached(Vec<Hash>),
    /// It doesn't: walked all the way to a commit with no first parent
    /// without ever finding `stop_at` — `target` does not build on it (a
    /// rewrite, reset, or unrelated branch). The caller must fall back to
    /// a full [`first_parent_chain`].
    NotFound,
}

/// Walk backward from `target` only as far as `stop_at`, instead of all
/// the way to genesis like [`first_parent_chain`] — the read-and-decode
/// step for `advance`'s fast-forward scrub-splice path (see
/// [`decide_chain`]'s docs for the full design and its rationale):
/// finding `target`'s new commits costs O(new), not O(total depth).
///
/// `prefix_len` is the already-published prefix's length, so the same
/// `MAX_ANCESTRY_LEAVES` bound `first_parent_chain` enforces on a
/// from-scratch walk applies to `prefix_len + this walk's length`, not
/// just this walk's own length — a splice can never end up longer than a
/// full walk would have allowed.
fn first_parent_suffix_to(
    store: &ObjectStore,
    target: Hash,
    stop_at: Hash,
    prefix_len: usize,
) -> Result<SuffixWalk, HistoryError> {
    let mut suffix = Vec::new();
    let mut seen = BTreeSet::new();
    let mut next = Some(target);
    while let Some(h) = next {
        if h == stop_at {
            suffix.reverse();
            return Ok(SuffixWalk::Reached(suffix));
        }
        if suffix.len() + prefix_len >= MAX_ANCESTRY_LEAVES || !seen.insert(h) {
            return Err(ancestry_cycle_or_limit());
        }
        suffix.push(h);
        next = match store.read_object(&h)? {
            Object::Commit(c) => c.parents.first().copied(),
            Object::Remix(r) => r.parents.first().copied(),
            _ => return Err(ancestry_not_commit_or_remix()),
        };
    }
    Ok(SuffixWalk::NotFound)
}

fn fresh_id() -> Result<Hash, HistoryError> {
    let mut id = [0; 32];
    getrandom::fill(&mut id).map_err(|e| std::io::Error::other(e.to_string()))?;
    Ok(id)
}

fn read_repository_id(common: &Path) -> Result<Option<Hash>, HistoryError> {
    let Some(bytes) = ancestry_state::read_bounded(
        &common.join(ancestry_state::DIRECTORY).join("repository-id"),
        65,
    )?
    else {
        return Ok(None);
    };
    refs::decode_ref_wire(&bytes)
        .map(Some)
        .ok_or_else(|| HistoryError::Corrupted("malformed history repository identity".into()))
}

fn repository_id(common: &Path) -> Result<Hash, HistoryError> {
    if let Some(id) = read_repository_id(common)? {
        return Ok(id);
    }
    let path = common.join(ancestry_state::DIRECTORY).join("repository-id");
    let id = fresh_id()?;
    crate::atomic::write_create_new(&path, &refs::encode_ref_wire(&id), true)?;
    crate::atomic::sync_dir(common)?;
    read_repository_id(common)?
        .ok_or_else(|| HistoryError::Corrupted("history repository identity disappeared".into()))
}

fn snapshot_path(dir: &Path, generation: Hash) -> PathBuf {
    dir.join("generations")
        .join(format!("{}.snapshot", hash::to_hex(&generation)))
}

fn read_current(dir: &Path) -> Result<Option<AncestrySnapshot>, HistoryError> {
    let Some(bytes) = ancestry_state::read_bounded(&dir.join("current"), 65)? else {
        return Ok(None);
    };
    let generation = refs::decode_ref_wire(&bytes)
        .ok_or_else(|| HistoryError::Corrupted("malformed history generation pointer".into()))?;
    let raw = ancestry_state::read_bounded(&snapshot_path(dir, generation), MAX_SNAPSHOT_BYTES)?
        .ok_or_else(|| HistoryError::Corrupted("missing ancestry generation snapshot".into()))?;
    let snapshot = AncestrySnapshot::decode(&raw)?;
    if snapshot.descriptor.generation != generation {
        return Err(HistoryError::Corrupted(
            "ancestry generation mismatch".into(),
        ));
    }
    Ok(Some(snapshot))
}

/// The previous publish's descriptor, without its chain or MMB — the only
/// thing `advance`'s compatibility/no-op/generation-reuse checks actually
/// need. `advance` never uses `old.chain` bytes directly: every check
/// compares against `chain = first_parent_chain(store, target)`, a fresh,
/// store-verified walk it computes unconditionally anyway. Content
/// addressing makes that walk deterministic in the hash it produces at
/// each position for a given tip and store contents, so:
///
/// - `target == old.tip` implies `chain` is byte-for-byte `old.chain`
///   (both are `first_parent_chain(store, old.tip)`, computed at
///   different times against the same immutable objects) — the no-op
///   check needs no more than that one hash comparison.
/// - `chain[old.leaf_count - 1] == old.tip` implies
///   `chain[..old.leaf_count] == old.chain`, by the same argument applied
///   to the sub-walk ending at that position — the fast-forward/
///   generation-reuse check needs the same single comparison, using
///   `chain[old.leaf_count - 1]`, which is already in memory (no extra
///   cost: `chain` is fully materialized either way).
///
/// So loading `old.chain` at all — up to 32 MiB of leaf hashes, and the
/// linear checksum hash over the full payload that validates it — was
/// pure waste on this path. [`read_current_descriptor`] reads only the
/// small fixed-size header (via [`read_prefix`], not the whole file) and
/// skips checksum verification entirely, which is a real, if narrow,
/// difference, a layer past the one [`decode_descriptor_and_chain`]'s docs
/// already accept for `advance`'s comparison-only use of `old`: there, a
/// corrupted-but-self-consistent payload could still fail via the root
/// rebuild-and-compare; here, there is no rebuild to catch it, so a
/// corrupted header field that still parses structurally (a bit-flipped
/// byte inside `tip`/`generation`/`root`, as opposed to e.g. invalid UTF-8
/// or a bad magic, both still caught) goes undetected by this function.
/// That stays safe for the same reason as before — `advance` never
/// *persists* `old`'s fields, it only compares them — traced field by
/// field: a corrupted `tip` fails the `compatible` filter against the
/// independently-read live ref value (`mutation.current()`) or the
/// fast-forward comparison against `chain`, either way just missing a
/// legitimate fast-forward and falling back to a fresh generation and full
/// rebuild, never accepting a wrong one (the astronomically unlikely case
/// of a corrupted `tip` coincidentally colliding with a real hash is the
/// same order of risk this whole checksum design already accepts
/// elsewhere). A corrupted `generation` is independently caught by the
/// `descriptor.generation != generation` check below, against the
/// separately-read `current` pointer file. A corrupted `leaf_count`'s only
/// remaining use (`decide_chain`'s `prefix_len`) is as the starting count
/// [`first_parent_suffix_to`] adds its own freshly-walked suffix onto for
/// the shared `MAX_ANCESTRY_LEAVES` traversal cap — a value corrupted
/// *upward* only makes that walk reject sooner (fails closed, same as
/// every other field here); corrupted *downward*, it lets that walk go
/// further than it would have against the true prefix length before
/// hitting the cap, so the total chain a fast-forward can reach in one
/// publish is bounded a bit more loosely than `MAX_ANCESTRY_LEAVES`
/// intends — never unboundedly, and never by more than the size of the
/// corruption itself, but not a hard guarantee either. No field's
/// corruption can cause a bad chain to reach the new, freshly-persisted
/// snapshot, since
/// that snapshot is always built from `chain` itself, never from `old`.
fn read_current_descriptor(dir: &Path) -> Result<Option<AncestryDescriptor>, HistoryError> {
    let Some(bytes) = ancestry_state::read_bounded(&dir.join("current"), 65)? else {
        return Ok(None);
    };
    let generation = refs::decode_ref_wire(&bytes)
        .ok_or_else(|| HistoryError::Corrupted("malformed history generation pointer".into()))?;
    let Some(prefix) = read_prefix(&snapshot_path(dir, generation), DESCRIPTOR_HEADER_MAX_LEN)?
    else {
        return Err(HistoryError::Corrupted(
            "missing ancestry generation snapshot".into(),
        ));
    };
    let mut input = prefix.as_slice();
    let descriptor = parse_descriptor_header(&mut input)?;
    if descriptor.generation != generation {
        return Err(HistoryError::Corrupted(
            "ancestry generation mismatch".into(),
        ));
    }
    Ok(Some(descriptor))
}

/// Read a specific generation's full snapshot chain — checksum-verified,
/// but without rebuilding the MMB — for [`decide_chain`]'s fast-forward
/// splice, which only needs the leaf hashes themselves (to splice onto
/// and to scrub a window of), not a working [`CommitHistory`] to prove
/// against.
fn read_snapshot_chain(dir: &Path, generation: Hash) -> Result<Vec<Hash>, HistoryError> {
    let raw = ancestry_state::read_bounded(&snapshot_path(dir, generation), MAX_SNAPSHOT_BYTES)?
        .ok_or_else(|| HistoryError::Corrupted("missing ancestry generation snapshot".into()))?;
    let (descriptor, chain) = decode_descriptor_and_chain(&raw)?;
    if descriptor.generation != generation {
        return Err(HistoryError::Corrupted(
            "ancestry generation mismatch".into(),
        ));
    }
    Ok(chain)
}

/// Re-read and re-hash (via [`ObjectStore::read_object`]'s integrity
/// check) every leaf in `prefix[start..end]` — the bounded portion of an
/// already-published, reused chain a fast-forward splice re-verifies on a
/// given publish. See [`decide_chain`]'s docs for the schedule this
/// implements and what it does and doesn't guarantee.
fn verify_scrub_window(
    store: &ObjectStore,
    prefix: &[Hash],
    start: u64,
    end: u64,
) -> Result<(), HistoryError> {
    let start = usize::try_from(start).expect("bounded by MAX_ANCESTRY_LEAVES");
    let end = usize::try_from(end).expect("bounded by MAX_ANCESTRY_LEAVES");
    for h in &prefix[start..end] {
        match store.read_object(h)? {
            Object::Commit(_) | Object::Remix(_) => {}
            _ => return Err(ancestry_not_commit_or_remix()),
        }
    }
    Ok(())
}

/// Minimum scrub window, in leaves, regardless of prefix size — keeps a
/// full lap bounded even for small-to-medium histories instead of
/// shrinking to a handful of leaves per publish.
const SCRUB_MIN_WINDOW: u64 = 512;
/// A full scrub lap takes roughly this many fast-forward publishes once
/// the prefix is large enough for `SCRUB_MIN_WINDOW` to no longer
/// dominate — the window is `verified_through / SCRUB_LAP_FRACTION` once
/// that exceeds `SCRUB_MIN_WINDOW`.
const SCRUB_LAP_FRACTION: u64 = 64;
/// Upper bound on how long a leaf can go without being re-verified from
/// the store, by wall clock, independent of publish frequency — matches
/// ZFS's default weekly `zpool scrub` cadence (more conservative than
/// btrfs's monthly default), so a repository idle for a while still gets
/// a full re-verify shortly after publishing resumes.
const SCRUB_MAX_AGE_SECS: u64 = 7 * 24 * 60 * 60;

fn scrub_window(verified_through: u64) -> u64 {
    (verified_through / SCRUB_LAP_FRACTION).max(SCRUB_MIN_WINDOW)
}

#[cfg(test)]
thread_local! { static NOW_OVERRIDE: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) }; }

/// Unix seconds, or a test-injected value — see [`SCRUB_MAX_AGE_SECS`]'s
/// use in [`decide_chain`], which needs to be exercised without an actual
/// multi-day wait.
fn now_unix() -> u64 {
    #[cfg(test)]
    if let Some(t) = NOW_OVERRIDE.with(std::cell::Cell::get) {
        return t;
    }
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Rolling re-verification progress for the fast-forward splice path in
/// [`decide_chain`]. Persisted alongside a branch's ancestry snapshot, in
/// the same directory, but entirely advisory: it only controls how much
/// of an already-published prefix gets re-read and re-hashed from the
/// object store on a *given* fast-forward publish, never what gets
/// persisted — the published chain is always byte-identical to what a
/// full [`first_parent_chain`] walk would have produced, whichever path
/// computed it. Missing or corrupt state always fails safe toward *more*
/// verification, never less: [`decide_chain`] treats it exactly like "no
/// prior full verification on record" and falls back to a full
/// from-scratch walk, [`first_parent_chain`]'s pre-existing behavior.
///
/// `generation` binds this state to the specific generation it was
/// computed against, and [`decide_chain`] discards a mismatch exactly
/// like a missing file (see its read-side check). Without this, a
/// generation change (a rewrite/reset — [`ChainDecision::NewGeneration`])
/// that crashes *after* [`finish`] durably commits the new, possibly much
/// shorter, chain but *before* [`advance`]'s own advisory
/// [`write_scrub_state`] call runs leaves this file holding the old
/// generation's `verified_through`/`cursor`, now paired on disk with a
/// shorter chain it was never computed against. The next fast-forward
/// would otherwise trust that stale window against the new chain and
/// slice past its end — `generation` turns that mismatch into "no prior
/// scrub state" instead of an out-of-bounds read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ScrubState {
    /// The generation this state was computed against — see the
    /// struct-level doc for why this binding exists.
    generation: Hash,
    /// Index into the prefix where the next scrub window starts.
    cursor: u64,
    /// The prefix length as of the last full verification — the range
    /// `cursor` rotates through. Leaves published after that (at indices
    /// `>= verified_through`) were each freshly read and verified by the
    /// publish that first added them (every leaf a splice ever appends
    /// comes from [`first_parent_suffix_to`]'s own `store.read_object`
    /// calls) and don't need scrubbing again until the next full verify
    /// folds them into the rotation.
    verified_through: u64,
    /// Unix seconds of the last full verification.
    last_full_verify_unix: u64,
}

/// `\x02`: the wire format grew a `generation` field (see [`ScrubState`]'s
/// docs) — bumped so a pre-upgrade `\x01` file, which is also the wrong
/// length now, can never be misread as the new layout; either mismatch
/// alone already makes [`ScrubState::decode`] return `None`, the same
/// safe "no prior scrub state" fallback either way.
const SCRUB_MAGIC: &[u8; 5] = b"MKSC\x02";

impl ScrubState {
    /// Builds a fresh state for a just-completed full verification.
    /// `generation` is a placeholder here — [`decide_chain`]'s two
    /// [`ChainDecision::NewGeneration`] call sites don't yet know the
    /// real one (only [`advance`] mints it, after `decide_chain`
    /// returns) — [`advance`] always overwrites this field with the
    /// actual published generation immediately before
    /// [`write_scrub_state`], so the placeholder here is never what
    /// reaches disk.
    fn fresh(chain_len: u64, now: u64) -> Self {
        Self {
            generation: [0; 32],
            cursor: 0,
            verified_through: chain_len,
            last_full_verify_unix: now,
        }
    }

    fn encode(self) -> [u8; 93] {
        let mut bytes = [0u8; 93];
        bytes[..5].copy_from_slice(SCRUB_MAGIC);
        bytes[5..37].copy_from_slice(&self.generation);
        bytes[37..45].copy_from_slice(&self.cursor.to_le_bytes());
        bytes[45..53].copy_from_slice(&self.verified_through.to_le_bytes());
        bytes[53..61].copy_from_slice(&self.last_full_verify_unix.to_le_bytes());
        let checksum = hash::hash(&bytes[..61]);
        bytes[61..93].copy_from_slice(&checksum);
        bytes
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 93 || bytes[..5] != *SCRUB_MAGIC {
            return None;
        }
        let (payload, checksum) = bytes.split_at(61);
        if hash::hash(payload).as_slice() != checksum {
            return None;
        }
        let field = |r: std::ops::Range<usize>| -> Option<u64> {
            Some(u64::from_le_bytes(payload[r].try_into().ok()?))
        };
        Some(Self {
            generation: payload[5..37].try_into().ok()?,
            cursor: field(37..45)?,
            verified_through: field(45..53)?,
            last_full_verify_unix: field(53..61)?,
        })
    }
}

fn scrub_path(dir: &Path) -> PathBuf {
    dir.join("scrub")
}

/// Missing or corrupt scrub state is not an error — see [`ScrubState`]'s
/// docs on why the caller treats `None` as "no prior full verification on
/// record" and falls back to a full walk.
fn read_scrub_state(dir: &Path) -> Result<Option<ScrubState>, HistoryError> {
    let Some(bytes) = ancestry_state::read_bounded(&scrub_path(dir), 93)? else {
        return Ok(None);
    };
    Ok(ScrubState::decode(&bytes))
}

fn write_scrub_state(dir: &Path, state: ScrubState) -> Result<(), HistoryError> {
    crate::atomic::write_atomic(&scrub_path(dir), &state.encode(), false)?;
    Ok(())
}

/// Decide the chain to publish for `target`, and the scrub bookkeeping
/// that publish earns, given `compatible` — the previous publish's
/// descriptor, already filtered down to "matches the live ref and this
/// repository" by the caller (`advance`).
///
/// This is the fix for the O(N) `first_parent_chain(store, target)` walk
/// `advance` used to run unconditionally on *every* publish, making N
/// sequential single-commit publishes cost O(N) store reads each — see
/// the CHANGELOG entry for this commit for the full design writeup and
/// the prior-art research behind it. In short: a from-scratch
/// verification of the *entire* first-parent chain on every single
/// publish is stronger than any other content-addressed/checksummed
/// system checks for by default (git never re-verifies past HEAD on
/// commit; ZFS/btrfs verify a block only on read of that block, with
/// *periodic scrub* — not per-write — for the rest); it defends against
/// *accidental* local corruption (bit rot, a bad GC, a torn write) between
/// two publishes, since content addressing means corruption can never
/// silently produce a *wrong* answer, only a *detectably missing* one.
/// Weakening that check to "verify only the new leaves, trust the rest
/// forever" (attempted once, reverted — see `git log` for
/// `first_parent_chain_from`) loses detection entirely for the reused
/// prefix. This lands between those two: every leaf still gets re-read
/// from the store on a bounded schedule — at least once every
/// [`SCRUB_LAP_FRACTION`] fast-forward publishes (via
/// [`scrub_window`]'s rotating window) *and* at least once every
/// [`SCRUB_MAX_AGE_SECS`] of wall-clock time, whichever comes first —
/// instead of either "every publish" or "never again".
///
/// A fast-forward's suffix (the actually-new commits) is always verified
/// in full, every time, via [`first_parent_suffix_to`] — only the reused
/// *prefix* gets the bounded/scheduled treatment. A non-fast-forward
/// (new branch, rewrite, reset, or unrelated history) always gets a full
/// [`first_parent_chain`] walk, exactly as before — there is no prefix to
/// reuse safely in that case.
fn decide_chain(
    store: &ObjectStore,
    dir: &Path,
    compatible: Option<&AncestryDescriptor>,
    target: Hash,
    now: u64,
) -> Result<ChainDecision, HistoryError> {
    let Some(d) = compatible else {
        let chain = first_parent_chain(store, target)?;
        let scrub = ScrubState::fresh(chain.len() as u64, now);
        return Ok(ChainDecision::NewGeneration { chain, scrub });
    };
    let prefix_len = usize::try_from(d.leaf_count).expect("bounded by MAX_ANCESTRY_LEAVES");
    let suffix = match first_parent_suffix_to(store, target, d.tip, prefix_len)? {
        SuffixWalk::Reached(suffix) => suffix,
        SuffixWalk::NotFound => {
            let chain = first_parent_chain(store, target)?;
            let scrub = ScrubState::fresh(chain.len() as u64, now);
            return Ok(ChainDecision::NewGeneration { chain, scrub });
        }
    };
    // A genuine fast-forward from here on — the generation is reused no
    // matter which branch below actually verifies the reused prefix.
    //
    // A scrub state left over from a *different* generation (see
    // `ScrubState`'s docs) is discarded here exactly like a missing
    // file — `d.generation` is the generation being fast-forwarded from,
    // so anything else on disk was computed against a chain this
    // publish isn't extending.
    let scrub = read_scrub_state(dir)?.filter(|s| s.generation == d.generation);
    let stale =
        scrub.is_none_or(|s| now.saturating_sub(s.last_full_verify_unix) > SCRUB_MAX_AGE_SECS);
    if !stale {
        let scrub = scrub.expect("`stale` is false only when `scrub` is Some");
        let window = scrub_window(scrub.verified_through);
        let end = scrub
            .cursor
            .saturating_add(window)
            .min(scrub.verified_through);
        if end < scrub.verified_through {
            let prefix = read_snapshot_chain(dir, d.generation)?;
            verify_scrub_window(store, &prefix, scrub.cursor, end)?;
            let mut chain = prefix;
            chain.extend(suffix);
            return Ok(ChainDecision::SameGeneration {
                chain,
                scrub: ScrubState {
                    cursor: end,
                    ..scrub
                },
            });
        }
        // Lap complete: fall through to the full walk below, which
        // re-verifies everything, including the window this lap didn't
        // reach yet.
    }
    // A full walk of the *prefix* (up through `d.tip`) is exactly what's
    // needed to freshly re-verify everything a completed lap or a stale
    // schedule requires — but `suffix` (verified moments ago, above) is
    // already the freshly-read continuation from `d.tip` to `target`, so
    // re-deriving it again via a full `first_parent_chain(store, target)`
    // walk would re-read and re-verify those same new leaves a second
    // time. `first_parent_chain(store, target) ==
    // first_parent_chain(store, d.tip) ++ suffix` always holds here: both
    // sides are deterministic functions of the same immutable,
    // content-addressed store, and `d.tip` is `suffix`'s own starting
    // point by construction (`first_parent_suffix_to` only returns
    // `Reached` when it walked backward from `target` to exactly
    // `d.tip`). Splicing is therefore not an approximation of the full
    // walk's result, just a cheaper way to compute the identical chain.
    let mut chain = first_parent_chain(store, d.tip)?;
    chain.extend(suffix);
    let scrub = ScrubState::fresh(chain.len() as u64, now);
    Ok(ChainDecision::SameGeneration { chain, scrub })
}

/// [`decide_chain`]'s result: the chain to publish, the scrub state to
/// persist once that publish durably succeeds, and — via which variant —
/// whether the target's generation should be reused (a fast-forward on
/// `compatible`, verified either by a bounded window or a full walk this
/// time) or freshly minted (a new branch, rewrite, reset, or unrelated
/// history).
enum ChainDecision {
    SameGeneration { chain: Vec<Hash>, scrub: ScrubState },
    NewGeneration { chain: Vec<Hash>, scrub: ScrubState },
}

/// Finish a durable intent under BOTH history and ref mutation guards. The
/// target is rebuilt from verified objects, not guessed from a single old leaf
/// — unless `prebuilt` already is that exact rebuild.
///
/// `prebuilt` lets a caller that just built (and validated) the matching
/// snapshot in memory — `advance`'s own non-crash path — hand it over
/// instead of paying a second full `first_parent_chain` walk and MMB
/// build for the identical chain here. It is only trusted when its
/// descriptor's `repository`/`full_ref`/`generation`/`tip` exactly match `tx`;
/// any mismatch (or `None`, as `recover` always passes — it only has a
/// `Transaction` read back from disk, never a live snapshot) falls back
/// to the original from-scratch rebuild.
fn finish(
    layout: &RepoLayout,
    dir: &Path,
    tx: &Transaction,
    mutation: &RefMutation,
    store: &ObjectStore,
    prebuilt: Option<AncestrySnapshot>,
) -> Result<AncestrySnapshot, HistoryError> {
    if tx.repository != repository_id(layout.common_dir())?
        || ancestry_state::branch_dir(layout.common_dir(), &tx.full_ref) != dir
    {
        return Err(HistoryError::Corrupted(
            "history transaction context mismatch".into(),
        ));
    }
    let current = mutation.current()?;
    if current != tx.previous && current != Some(tx.target) {
        return Err(HistoryError::Corrupted(
            "ref diverged from pending history transaction".into(),
        ));
    }
    let snapshot = match prebuilt {
        Some(snapshot)
            if snapshot.descriptor.repository == tx.repository
                && snapshot.descriptor.full_ref == tx.full_ref
                && snapshot.descriptor.generation == tx.generation
                && snapshot.descriptor.tip == tx.target =>
        {
            snapshot
        }
        _ => AncestrySnapshot::build(
            tx.repository,
            tx.full_ref.clone(),
            tx.generation,
            first_parent_chain(store, tx.target)?,
        )?,
    };
    let encoded = snapshot.encode()?;
    crate::atomic::write_atomic(&dir.join("pending-snapshot"), &encoded, true)?;
    checkpoint(2)?;
    mutation
        .write_preserving_history(&refs::encode_ref_wire(&tx.target), RefWriteCondition::Any)?;
    checkpoint(3)?;
    let dest = snapshot_path(dir, tx.generation);
    fs::create_dir_all(dest.parent().expect("snapshot parent"))?;
    fs::rename(dir.join("pending-snapshot"), &dest)?;
    crate::atomic::sync_dir(dest.parent().expect("snapshot parent"))?;
    crate::atomic::sync_dir(dir)?;
    checkpoint(4)?;
    crate::atomic::write_atomic(
        &dir.join("current"),
        &refs::encode_ref_wire(&tx.generation),
        true,
    )?;
    checkpoint(5)?;
    ancestry_state::remove_synced(&dir.join("transaction"))?;
    checkpoint(6)?;
    Ok(snapshot)
}

pub(crate) fn recover(
    layout: &RepoLayout,
    branch: &str,
    mutation: &RefMutation,
    store: &ObjectStore,
) -> Result<(), HistoryError> {
    let dir = ancestry_state::branch_dir(layout.common_dir(), &format!("refs/heads/{branch}"));
    if let Some(tx) = Transaction::read(&dir)? {
        finish(layout, &dir, &tx, mutation, store, None)?;
    }
    Ok(())
}

/// Lock-held update, called exclusively through `refs::update_ref_with_ancestry`.
pub(crate) fn advance(
    layout: &RepoLayout,
    branch: &str,
    mutation: &RefMutation,
    condition: RefWriteCondition,
    target: Hash,
    store: &ObjectStore,
) -> Result<(), HistoryError> {
    let full_ref = format!("refs/heads/{branch}");
    let dir = ancestry_state::branch_dir(layout.common_dir(), &full_ref);
    if let Some(tx) = Transaction::read(&dir)? {
        finish(layout, &dir, &tx, mutation, store, None)?;
        let retry_of_intent = target == tx.target
            && match condition {
                RefWriteCondition::Any => true,
                RefWriteCondition::Missing => tx.previous.is_none(),
                RefWriteCondition::Match(expected) => tx.previous == Some(expected),
            };
        if retry_of_intent {
            return Ok(());
        }
    }
    mutation.check(condition)?;
    let previous = mutation.current()?;
    let repository = repository_id(layout.common_dir())?;
    let old = read_current_descriptor(&dir)?;
    let compatible = old.as_ref().filter(|d| {
        d.repository == repository && d.full_ref == full_ref && Some(d.tip) == previous
    });
    // A no-op publish (target already the current, already-verified tip)
    // needs no walk at all: nothing new is being published, so there is
    // nothing new to verify. Checked before any store read, unlike the
    // walk-then-check order this replaced.
    if compatible.is_some_and(|d| d.tip == target) {
        return Ok(());
    }
    let now = now_unix();
    let decision = decide_chain(store, &dir, compatible, target, now)?;
    let (chain, generation, scrub) = match decision {
        ChainDecision::SameGeneration { chain, scrub } => (
            chain,
            compatible
                .expect("SameGeneration is only returned when `compatible` is Some")
                .generation,
            scrub,
        ),
        ChainDecision::NewGeneration { chain, scrub } => (chain, fresh_id()?, scrub),
    };
    let tx = Transaction {
        repository,
        full_ref,
        previous,
        target,
        generation,
        previous_generation: compatible.map(|d| d.generation),
    };
    // Validate the target before persisting intent, and keep the built
    // snapshot: `finish` below (the common, non-crash-recovery path) reuses
    // it instead of re-walking `store` and rebuilding the MMB a second time
    // for the exact same chain. Readers withhold proofs for the entire
    // intent window. GC pins previous+target from the metadata.
    let snapshot = AncestrySnapshot::build(repository, tx.full_ref.clone(), generation, chain)?;
    crate::atomic::write_atomic(&dir.join("transaction"), &tx.encode(), true)?;
    // Newly created directory entries must themselves be durable.
    for parent in [
        dir.parent(),
        dir.parent().and_then(Path::parent),
        Some(layout.common_dir()),
    ]
    .into_iter()
    .flatten()
    {
        crate::atomic::sync_dir(parent)?;
    }
    checkpoint(1)?;
    finish(layout, &dir, &tx, mutation, store, Some(snapshot))?;
    // Only recorded once the publish above durably succeeded; advisory,
    // so a failure here or a crash before it runs just costs the next
    // publish a bit more re-verification than strictly necessary, never
    // less (see `ScrubState`'s docs) — `generation` is the just-published
    // one (`decide_chain`'s own `scrub.generation` is a placeholder for
    // the `NewGeneration` case, since it doesn't know this value; always
    // overwriting it here, unconditionally, is what makes `decide_chain`'s
    // generation-binding check on the next publish actually correct).
    //
    // Deliberately not `?`: `finish` above already durably committed this
    // publish (the ref moved, the snapshot is on disk) — a caller must
    // never see that succeeded operation reported as a failure just
    // because this purely advisory bookkeeping write didn't land. The
    // generation-binding check in `decide_chain` already treats a
    // missing/mismatched file exactly like "no prior scrub state", so
    // losing this write costs only extra re-verification next publish,
    // never correctness.
    let _ = write_scrub_state(
        &dir,
        ScrubState {
            generation,
            ..scrub
        },
    );
    Ok(())
}

#[cfg(test)]
thread_local! { static FAIL_AFTER: std::cell::Cell<u8> = const { std::cell::Cell::new(0) }; }
// The production no-op keeps the same fallible call sites as fault-injection tests.
#[cfg_attr(not(test), allow(clippy::unnecessary_wraps))]
fn checkpoint(stage: u8) -> Result<(), HistoryError> {
    #[cfg(not(test))]
    let _ = stage;
    #[cfg(test)]
    if FAIL_AFTER.with(|s| s.get() == stage) {
        return Err(
            std::io::Error::other(format!("injected history publication failure {stage}")).into(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::{Commit, Identity, Tree};

    fn repo() -> (tempfile::TempDir, RepoLayout, ObjectStore) {
        let dir = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(dir.path());
        let store = ObjectStore::init(&layout).unwrap();
        refs::init(&layout).unwrap();
        (dir, layout, store)
    }

    fn commit(store: &ObjectStore, parents: Vec<Hash>, message: &[u8]) -> Hash {
        let tree = store
            .write(&crate::serialize::serialize(&Object::Tree(Tree { entries: vec![] })).unwrap())
            .unwrap();
        let c = Commit::new_unannotated(
            tree,
            parents,
            Identity::opaque(b"test".to_vec()),
            [0; 32],
            message.to_vec(),
            0,
            [0; 64],
        );
        store
            .write(&crate::serialize::serialize(&Object::Commit(c)).unwrap())
            .unwrap()
    }

    fn update(layout: &RepoLayout, store: &ObjectStore, branch: &str, target: Hash) {
        refs::update_ref_with_ancestry(layout, branch, RefWriteCondition::Any, &target, store)
            .unwrap();
    }

    #[test]
    fn sequential_fast_forward_and_backfill_have_identical_roots_and_positions() {
        let (_dir, layout, store) = repo();
        let a = commit(&store, vec![], b"a");
        let b = commit(&store, vec![a], b"b");
        let c = commit(&store, vec![b], b"c");
        for h in [a, b, c] {
            update(&layout, &store, "sequential", h);
        }
        update(&layout, &store, "fast-forward", a);
        update(&layout, &store, "fast-forward", c);
        refs::write_ref(&layout, "backfill", &c).unwrap();
        update(&layout, &store, "backfill", c);
        let seq = AncestrySnapshot::load(&layout, "sequential").unwrap();
        for branch in ["fast-forward", "backfill"] {
            let snapshot = AncestrySnapshot::load(&layout, branch).unwrap();
            assert_eq!(snapshot.root(), seq.root());
            assert_eq!(snapshot.len(), 3);
            for (i, h) in [a, b, c].iter().enumerate() {
                assert_eq!(snapshot.position_of(h), Some(Position(i as u64)));
                let proof = snapshot.prove(Position(i as u64)).unwrap();
                assert!(verify_ancestry(
                    h,
                    Position(i as u64),
                    &proof,
                    snapshot.descriptor(),
                    &snapshot.trusted_descriptor(),
                    snapshot.descriptor()
                ));
            }
        }
    }

    #[test]
    fn generation_changes_on_reset_and_recreation_but_not_noop_or_fast_forward() {
        let (_dir, layout, store) = repo();
        let a = commit(&store, vec![], b"a");
        let b = commit(&store, vec![a], b"b");
        update(&layout, &store, "main", a);
        let original = AncestrySnapshot::load(&layout, "main").unwrap();
        update(&layout, &store, "main", a);
        assert_eq!(
            AncestrySnapshot::load(&layout, "main")
                .unwrap()
                .descriptor(),
            original.descriptor()
        );
        update(&layout, &store, "main", b);
        assert_eq!(
            AncestrySnapshot::load(&layout, "main")
                .unwrap()
                .descriptor()
                .generation,
            original.descriptor().generation
        );
        update(&layout, &store, "main", a);
        let reset = AncestrySnapshot::load(&layout, "main").unwrap();
        assert_ne!(
            reset.descriptor().generation,
            original.descriptor().generation
        );
        assert_eq!(reset.root(), original.root());
        refs::delete_ref_with_ancestry(&layout, "main", Some(a), &store).unwrap();
        assert!(AncestrySnapshot::load(&layout, "main").is_err());
        update(&layout, &store, "main", a);
        let recreated = AncestrySnapshot::load(&layout, "main").unwrap();
        assert_eq!(recreated.root(), original.root());
        assert_ne!(
            recreated.descriptor().generation,
            reset.descriptor().generation
        );
    }

    #[test]
    fn merge_ancestry_uses_only_first_parent() {
        let (_dir, layout, store) = repo();
        let a = commit(&store, vec![], b"a");
        let b = commit(&store, vec![a], b"b");
        let side = commit(&store, vec![a], b"side");
        let merge = commit(&store, vec![b, side], b"merge");
        update(&layout, &store, "main", merge);
        let snapshot = AncestrySnapshot::load(&layout, "main").unwrap();
        assert_eq!(snapshot.chain, vec![a, b, merge]);
        assert_eq!(snapshot.position_of(&side), None);
    }

    #[test]
    fn proof_cannot_substitute_repository_ref_generation_tip_count_or_root() {
        let (_dir, layout, store) = repo();
        let a = commit(&store, vec![], b"a");
        update(&layout, &store, "main", a);
        let snapshot = AncestrySnapshot::load(&layout, "main").unwrap();
        let proof = snapshot.prove(Position(0)).unwrap();
        let trusted = snapshot.trusted_descriptor();
        for field in 0..6 {
            let mut wrong = snapshot.descriptor().clone();
            match field {
                0 => wrong.repository[0] ^= 1,
                1 => wrong.full_ref = "refs/heads/other".into(),
                2 => wrong.generation[0] ^= 1,
                3 => wrong.tip[0] ^= 1,
                4 => wrong.leaf_count += 1,
                _ => wrong.root[0] ^= 1,
            }
            assert!(!verify_ancestry(
                &a,
                Position(0),
                &proof,
                &wrong,
                &trusted,
                &wrong
            ));
            assert!(!verify_ancestry(
                &a,
                Position(0),
                &proof,
                snapshot.descriptor(),
                &trusted,
                &wrong
            ));
        }
        let (_foreign_dir, foreign, _) = repo();
        // Unauthenticated network-style descriptor bytes cannot be promoted:
        // even the correct root supplied without a local trust anchor fails load.
        assert!(AncestrySnapshot::load(&foreign, "main").is_err());
    }

    #[test]
    fn every_publication_boundary_recovers_the_whole_fast_forward() {
        for stage in 1..=6 {
            let (_dir, layout, store) = repo();
            let a = commit(&store, vec![], b"a");
            let b = commit(&store, vec![a], b"b");
            let c = commit(&store, vec![b], b"c");
            update(&layout, &store, "main", a);
            FAIL_AFTER.with(|s| s.set(stage));
            let failed = refs::update_ref_with_ancestry(
                &layout,
                "main",
                RefWriteCondition::Match(a),
                &c,
                &store,
            );
            FAIL_AFTER.with(|s| s.set(0));
            assert!(failed.is_err(), "stage {stage} must inject a failure");
            if stage < 6 {
                assert!(
                    AncestrySnapshot::load(&layout, "main").is_err(),
                    "pending proofs must be withheld"
                );
                let roots = refs::pending_history_roots(&layout).unwrap();
                assert!(roots.contains(&a) && roots.contains(&c));
                let live = crate::ops::gc::live_objects(&store, &layout).unwrap();
                assert!(live.contains(&b) && live.contains(&c));
                assert!(
                    refs::write_ref(&layout, "main", &a).is_err(),
                    "raw writer must not bypass recovery"
                );
            }
            if stage < 6 {
                refs::update_ref_with_ancestry(
                    &layout,
                    "main",
                    RefWriteCondition::Match(a),
                    &c,
                    &store,
                )
                .expect("retry of the interrupted CAS must finish its original intent");
            } else {
                update(&layout, &store, "main", c);
            }
            let snapshot = AncestrySnapshot::load(&layout, "main").unwrap();
            assert_eq!(snapshot.chain, vec![a, b, c], "stage {stage}");
            assert!(refs::pending_history_roots(&layout).unwrap().is_empty());
        }
    }

    #[test]
    fn missing_ancestor_fails_before_publication() {
        let (_dir, layout, store) = repo();
        let a = commit(&store, vec![], b"a");
        update(&layout, &store, "main", a);
        let invalid = commit(&store, vec![[91; 32]], b"missing parent");
        assert!(
            refs::update_ref_with_ancestry(
                &layout,
                "main",
                RefWriteCondition::Any,
                &invalid,
                &store
            )
            .is_err()
        );
        assert_eq!(refs::read_ref(&layout, "main").unwrap(), Some(a));
        refs::delete_ref_with_ancestry(&layout, "main", None, &store).unwrap();
    }

    #[test]
    fn raw_aba_mutation_invalidates_the_old_generation() {
        let (_dir, layout, store) = repo();
        let a = commit(&store, vec![], b"a");
        let b = commit(&store, vec![a], b"b");
        update(&layout, &store, "main", a);
        let old = AncestrySnapshot::load(&layout, "main")
            .unwrap()
            .descriptor()
            .generation;
        refs::write_ref(&layout, "main", &b).unwrap();
        refs::write_ref(&layout, "main", &a).unwrap();
        assert!(AncestrySnapshot::load(&layout, "main").is_err());
        update(&layout, &store, "main", a);
        assert_ne!(
            AncestrySnapshot::load(&layout, "main")
                .unwrap()
                .descriptor()
                .generation,
            old
        );
    }

    #[test]
    fn tampered_snapshot_and_transaction_fail_closed() {
        let (_dir, layout, store) = repo();
        let a = commit(&store, vec![], b"a");
        update(&layout, &store, "main", a);
        let snapshot = AncestrySnapshot::load(&layout, "main").unwrap();
        let dir = ancestry_state::branch_dir(layout.common_dir(), "refs/heads/main");
        let path = snapshot_path(&dir, snapshot.descriptor().generation);
        let mut bytes = fs::read(&path).unwrap();
        bytes[7] ^= 1;
        fs::write(&path, bytes).unwrap();
        assert!(AncestrySnapshot::load(&layout, "main").is_err());
        fs::write(dir.join("transaction"), b"broken").unwrap();
        assert!(refs::pending_history_roots(&layout).is_err());
        assert!(crate::ops::gc::live_objects(&store, &layout).is_err());
    }

    /// `advance`'s `write_scrub_state` call is documented as purely
    /// advisory: `finish` (called just before it) has already durably
    /// committed the publish, so a failure writing the scrub bookkeeping
    /// afterward must not be reported as a failure of that publish.
    #[test]
    fn a_write_scrub_state_failure_does_not_fail_the_publish() {
        let (_dir, layout, store) = repo();
        let dir = ancestry_state::branch_dir(layout.common_dir(), "refs/heads/main");
        // Force `write_atomic`'s rename onto "scrub" to fail: a directory
        // occupies the path the scrub *file* needs to land on.
        fs::create_dir_all(dir.join("scrub")).unwrap();

        let a = commit(&store, vec![], b"a");
        refs::update_ref_with_ancestry(&layout, "main", RefWriteCondition::Any, &a, &store)
            .expect("the publish itself must still succeed despite the scrub-state write failing");

        // The publish's own durable effects (ref move, snapshot) landed.
        let snapshot = AncestrySnapshot::load(&layout, "main").unwrap();
        assert_eq!(snapshot.descriptor().tip, a);
        // The scrub write really did fail (still a directory, not a
        // file), confirming this test exercises the failure path it
        // claims to rather than accidentally passing as a no-op.
        assert!(dir.join("scrub").is_dir());
    }

    /// `read_current_descriptor` is a new, narrower read path introduced
    /// specifically so `advance` doesn't have to load `old.chain` — pin
    /// that its fields agree exactly with the full `read_current`/`decode`
    /// path for the same on-disk snapshot, across a few chain lengths
    /// (including a single-leaf history, where `leaf_count - 1 == 0`).
    #[test]
    fn read_current_descriptor_matches_full_snapshot_fields() {
        for count in [1u64, 2, 50] {
            let (_dir, layout, store) = repo();
            let mut parents = vec![];
            let mut tip = [0; 32];
            for i in 0..count {
                tip = commit(&store, parents, i.to_be_bytes().as_slice());
                parents = vec![tip];
            }
            update(&layout, &store, "main", tip);

            let branch_dir = ancestry_state::branch_dir(layout.common_dir(), "refs/heads/main");
            let full = read_current(&branch_dir).unwrap().unwrap();
            let lite = read_current_descriptor(&branch_dir).unwrap().unwrap();

            assert_eq!(lite, full.descriptor, "count={count}");
            assert_eq!(lite.leaf_count, count);
            assert_eq!(lite.tip, tip);
        }
    }

    /// The new header-only read path (`read_prefix` bounded by
    /// `DESCRIPTOR_HEADER_MAX_LEN`) must still correctly parse a ref name
    /// long enough to stress the "read enough of the file up front"
    /// assumption, not just the short names every other test uses.
    #[test]
    fn read_current_descriptor_handles_a_long_branch_name() {
        let (_dir, layout, store) = repo();
        // A single path component near ext4's 255-byte NAME_MAX, not
        // `u16::MAX` — the ref name becomes a real filename on disk.
        let long_branch = "b".repeat(200);
        let a = commit(&store, vec![], b"a");
        update(&layout, &store, &long_branch, a);

        let branch_dir =
            ancestry_state::branch_dir(layout.common_dir(), &format!("refs/heads/{long_branch}"));
        let lite = read_current_descriptor(&branch_dir).unwrap().unwrap();
        assert_eq!(lite.full_ref, format!("refs/heads/{long_branch}"));
        assert_eq!(lite.tip, a);
        assert_eq!(lite.leaf_count, 1);
    }

    /// Sequential single-commit publishes never load `old.chain` anymore
    /// (see `read_current_descriptor`'s docs for the equivalence argument):
    /// pin that the generation is still correctly carried forward across
    /// many such publishes at every index — not just checked once at the
    /// end — and still correctly resets on a rewrite, at a chain length
    /// long enough that a bug indexing `chain` at the wrong position
    /// (off-by-one on `leaf_count - 1`, say) would show up as a spurious
    /// fresh generation somewhere in the middle of the run. A weaker
    /// version of this test that only compared the generation after all 40
    /// publishes against the generation after the rewrite would NOT catch
    /// that class of bug: two independently-minted random generations are
    /// virtually certain to differ regardless of whether the 40
    /// fast-forwards in between were each handled correctly, so the
    /// meaningful assertion is same-generation-every-step, not
    /// different-generation-at-the-end.
    #[test]
    fn many_sequential_publishes_keep_one_generation_until_a_real_rewrite() {
        let (_dir, layout, store) = repo();
        let mut parents = vec![];
        let mut tips = Vec::new();
        for i in 0..40u64 {
            let h = commit(&store, parents, i.to_be_bytes().as_slice());
            parents = vec![h];
            tips.push(h);
        }

        update(&layout, &store, "main", tips[0]);
        let first_generation = AncestrySnapshot::load(&layout, "main")
            .unwrap()
            .descriptor()
            .generation;
        for (i, &h) in tips.iter().enumerate().skip(1) {
            update(&layout, &store, "main", h);
            let generation = AncestrySnapshot::load(&layout, "main")
                .unwrap()
                .descriptor()
                .generation;
            assert_eq!(
                generation, first_generation,
                "fast-forward to tips[{i}] must keep the same generation as the first publish"
            );
        }
        let final_generation = first_generation;

        // A rewrite back to an earlier tip must start a new generation,
        // proving the run above wasn't just accepting every publish as
        // compatible regardless of the leaf-count/tip check.
        update(&layout, &store, "main", tips[10]);
        let reset_generation = AncestrySnapshot::load(&layout, "main")
            .unwrap()
            .descriptor()
            .generation;
        assert_ne!(reset_generation, final_generation);
    }

    /// Not a correctness test — a manual profiling comparison, isolating
    /// exactly the mechanism `read_current_descriptor` optimizes, free of
    /// the fsync noise that swamps it in the full publish pipeline (see
    /// CHANGELOG for why `cargo bench`'s `sequential_publish` couldn't show
    /// this at reasonable N: fsync dominates every publish, and reaching an
    /// N where the O(N) old-chain read would compete with that fixed cost
    /// takes far too long to benchmark end-to-end). Builds one large
    /// snapshot on disk (a single write, fsync'd once — not per iteration),
    /// then times many repeated *reads* of it — reads need no fsync, so
    /// this can iterate enough to average out scheduler/allocator noise —
    /// comparing `read_current_descriptor` (prefix read, header-only parse)
    /// against the pre-optimization equivalent reconstructed inline from
    /// still-present pieces (`read_bounded` the whole file, then
    /// `decode_descriptor_and_chain`, exactly what the removed
    /// `read_current_chain` did). Run with:
    /// `cargo test -p mkit-core --features history-mmr --lib \
    ///   history::ancestry::tests::profile_read_current_descriptor_vs_full_chain_read \
    ///   -- --ignored --nocapture`
    #[test]
    #[ignore = "manual profiling tool, not a correctness assertion"]
    fn profile_read_current_descriptor_vs_full_chain_read() {
        const LEAVES: u64 = 50_000;
        const ITERS: u32 = 200;

        let (_dir, layout, store) = repo();
        let tree = store
            .write(&crate::serialize::serialize(&Object::Tree(Tree { entries: vec![] })).unwrap())
            .unwrap();
        let mut parents = vec![];
        let mut tip = [0; 32];
        for i in 0..LEAVES {
            let c = Commit::new_unannotated(
                tree,
                parents,
                Identity::opaque(b"profile".to_vec()),
                [0; 32],
                i.to_be_bytes().to_vec(),
                0,
                [0; 64],
            );
            tip = store
                .write(&crate::serialize::serialize(&Object::Commit(c)).unwrap())
                .unwrap();
            parents = vec![tip];
        }
        update(&layout, &store, "main", tip);
        let branch_dir = ancestry_state::branch_dir(layout.common_dir(), "refs/heads/main");

        // Warm the OS page cache for both paths equally before timing.
        for _ in 0..5 {
            std::hint::black_box(read_current_descriptor(&branch_dir).unwrap());
            std::hint::black_box(read_current(&branch_dir).unwrap());
        }

        let old_style_read = || {
            let bytes = ancestry_state::read_bounded(&branch_dir.join("current"), 65)
                .unwrap()
                .unwrap();
            let generation = refs::decode_ref_wire(&bytes).unwrap();
            let raw = ancestry_state::read_bounded(
                &snapshot_path(&branch_dir, generation),
                MAX_SNAPSHOT_BYTES,
            )
            .unwrap()
            .unwrap();
            decode_descriptor_and_chain(&raw).unwrap()
        };

        let start = std::time::Instant::now();
        for _ in 0..ITERS {
            std::hint::black_box(old_style_read());
        }
        let old_elapsed = start.elapsed();

        let start = std::time::Instant::now();
        for _ in 0..ITERS {
            std::hint::black_box(read_current_descriptor(&branch_dir).unwrap());
        }
        let new_elapsed = start.elapsed();

        eprintln!(
            "read_current (old, full chain + checksum): {:?}/iter over {ITERS} iters, {LEAVES} leaves",
            old_elapsed / ITERS
        );
        eprintln!(
            "read_current_descriptor (new, header only): {:?}/iter over {ITERS} iters, {LEAVES} leaves",
            new_elapsed / ITERS
        );
        eprintln!(
            "speedup: {:.1}x",
            old_elapsed.as_secs_f64() / new_elapsed.as_secs_f64()
        );
    }

    fn set_now(t: u64) {
        NOW_OVERRIDE.with(|c| c.set(Some(t)));
    }

    fn clear_now() {
        NOW_OVERRIDE.with(|c| c.set(None));
    }

    /// Flip a byte in `h`'s on-disk object so it no longer hashes to `h` —
    /// the "silent local corruption between two publishes" scenario
    /// `decide_chain`'s scrub window exists to catch, eventually.
    fn corrupt_object(store: &ObjectStore, h: &Hash) {
        let path = store.path_for(h);
        let mut bytes = fs::read(&path).unwrap();
        bytes[6] ^= 0xFF;
        fs::write(&path, bytes).unwrap();
    }

    /// Build `count` commits directly against the store (no publish per
    /// commit — publishing is what's expensive; building the fixture
    /// shouldn't be) and return their hashes oldest first.
    fn build_chain(store: &ObjectStore, count: usize) -> Vec<Hash> {
        let mut parents = vec![];
        let mut tips = Vec::with_capacity(count);
        for i in 0..count {
            let h = commit(store, parents, i.to_be_bytes().as_slice());
            parents = vec![h];
            tips.push(h);
        }
        tips
    }

    /// A fast-forward publish reuses the prefix and only scrubs a bounded
    /// window of it — not the whole thing — while still publishing the
    /// exact chain a full walk would. `SCRUB_MIN_WINDOW` (512) leaves
    /// headroom below `SCRUB_LAP_FRACTION`'s threshold, so a 600-leaf base
    /// (just over the minimum window) proves the window is genuinely
    /// smaller than the prefix, not coincidentally covering all of it.
    #[test]
    fn fast_forward_scrubs_a_bounded_window_not_the_whole_prefix() {
        let (_dir, layout, store) = repo();
        let mut tips = build_chain(&store, 600);
        update(&layout, &store, "main", tips[599]);

        let dir = ancestry_state::branch_dir(layout.common_dir(), "refs/heads/main");
        let generation = AncestrySnapshot::load(&layout, "main")
            .unwrap()
            .descriptor()
            .generation;
        let scrub = read_scrub_state(&dir).unwrap().unwrap();
        assert_eq!(
            scrub,
            ScrubState {
                generation,
                cursor: 0,
                verified_through: 600,
                last_full_verify_unix: scrub.last_full_verify_unix,
            }
        );

        let next = commit(&store, vec![tips[599]], b"600");
        tips.push(next);
        update(&layout, &store, "main", next);

        let scrub = read_scrub_state(&dir).unwrap().unwrap();
        assert_eq!(
            scrub.cursor, SCRUB_MIN_WINDOW,
            "window must be bounded, not full-prefix"
        );
        assert_eq!(scrub.verified_through, 600);

        let snapshot = AncestrySnapshot::load(&layout, "main").unwrap();
        assert_eq!(snapshot.chain, tips);
    }

    /// Once the rotating cursor would complete a lap over `verified_through`,
    /// `decide_chain` does a full walk instead of a final short window —
    /// and correctly keeps the same generation, since this is still a
    /// fast-forward, just one that happens to be fully re-verified this
    /// time. Continues the 600-leaf fixture from the test above: after one
    /// fast-forward (cursor at 512), a second fast-forward's window would
    /// reach the end (512+512 >= 601), so it must trigger the full-walk
    /// branch and reset scrub state to reflect a fresh full verification.
    #[test]
    fn scrub_lap_completion_forces_a_full_walk_but_keeps_the_generation() {
        let (_dir, layout, store) = repo();
        let mut tips = build_chain(&store, 600);
        update(&layout, &store, "main", tips[599]);
        let dir = ancestry_state::branch_dir(layout.common_dir(), "refs/heads/main");
        let first_generation = AncestrySnapshot::load(&layout, "main")
            .unwrap()
            .descriptor()
            .generation;

        let step1 = commit(&store, vec![tips[599]], b"600");
        tips.push(step1);
        update(&layout, &store, "main", step1);
        assert_eq!(read_scrub_state(&dir).unwrap().unwrap().cursor, 512);

        let before = now_unix();
        let step2 = commit(&store, vec![step1], b"601");
        tips.push(step2);
        update(&layout, &store, "main", step2);

        let scrub = read_scrub_state(&dir).unwrap().unwrap();
        assert_eq!(
            scrub.cursor, 0,
            "a completed lap resets to a fresh full verify"
        );
        assert_eq!(scrub.verified_through, 602);
        assert!(scrub.last_full_verify_unix >= before);

        let snapshot = AncestrySnapshot::load(&layout, "main").unwrap();
        assert_eq!(snapshot.chain, tips);
        assert_eq!(
            snapshot.descriptor().generation,
            first_generation,
            "still a fast-forward on the same branch history — generation must not change"
        );
    }

    /// `decide_chain`'s full-walk fallback splices a freshly-walked
    /// prefix (`first_parent_chain(store, d.tip)`) onto the suffix
    /// already verified above it, instead of re-walking `target` from
    /// scratch — see that function's doc comment on why the two chains
    /// are provably identical. This proves the optimization didn't
    /// quietly drop real verification along with the redundant re-read:
    /// corruption planted deep in the prefix, at an index the bounded
    /// window from a single prior fast-forward would not have reached,
    /// must still be caught once a forced full walk (here, via
    /// `SCRUB_MAX_AGE_SECS`) runs.
    #[test]
    fn full_walk_fallback_still_verifies_the_spliced_prefix() {
        let (_dir, layout, store) = repo();
        let tips = build_chain(&store, 1500);
        set_now(1_000_000);
        update(&layout, &store, "main", tips[1499]);

        // Deep in the prefix — well past the single bounded window
        // (512 of 1500) a first ordinary fast-forward would scrub.
        corrupt_object(&store, &tips[900]);

        set_now(1_000_000 + SCRUB_MAX_AGE_SECS + 1);
        let step = commit(&store, vec![tips[1499]], b"1500");
        let result =
            refs::update_ref_with_ancestry(&layout, "main", RefWriteCondition::Any, &step, &store);
        assert!(
            result.is_err(),
            "the spliced full-walk fallback must still verify the whole prefix, not just the suffix"
        );
        clear_now();
    }

    /// The whole point of a bounded window: corruption planted inside a
    /// not-yet-scrubbed region does not fail the very next fast-forward,
    /// but is still caught within a bounded number of publishes once the
    /// rotating cursor reaches it — never "eventually, maybe" or "silently
    /// forever". A 1500-leaf prefix keeps both windows (0 and 1) strictly
    /// inside `SCRUB_MIN_WINDOW`-sized boundaries: [0,512) then [512,1024).
    #[test]
    fn corruption_outside_the_current_window_is_caught_within_a_bounded_number_of_publishes() {
        let (_dir, layout, store) = repo();
        let tips = build_chain(&store, 1500);
        update(&layout, &store, "main", tips[1499]);

        // Inside the second window ([512, 1024)), not the first.
        corrupt_object(&store, &tips[600]);

        let step1 = commit(&store, vec![tips[1499]], b"1500");
        refs::update_ref_with_ancestry(&layout, "main", RefWriteCondition::Any, &step1, &store)
            .expect("window [0, 512) does not include index 600: must still succeed");

        let step2 = commit(&store, vec![step1], b"1501");
        let result =
            refs::update_ref_with_ancestry(&layout, "main", RefWriteCondition::Any, &step2, &store);
        assert!(
            result.is_err(),
            "window [512, 1024) includes index 600: corruption must now be caught"
        );
    }

    /// `decide_chain` forces a full walk once `SCRUB_MAX_AGE_SECS` has
    /// elapsed since the last full verification, even when the rotating
    /// cursor is nowhere near completing a lap — bounding staleness by
    /// wall clock, independent of how many fast-forwards happened.
    #[test]
    fn stale_scrub_state_forces_a_full_walk_regardless_of_cursor_position() {
        let (_dir, layout, store) = repo();
        let tips = build_chain(&store, 1500);
        set_now(1_000_000);
        update(&layout, &store, "main", tips[1499]);
        let dir = ancestry_state::branch_dir(layout.common_dir(), "refs/heads/main");
        assert_eq!(read_scrub_state(&dir).unwrap().unwrap().cursor, 0);

        // Far short of a lap (window is 512 of 1500), but past the age bound.
        set_now(1_000_000 + SCRUB_MAX_AGE_SECS + 1);
        let step = commit(&store, vec![tips[1499]], b"1500");
        update(&layout, &store, "main", step);

        let scrub = read_scrub_state(&dir).unwrap().unwrap();
        assert_eq!(scrub.cursor, 0, "a forced full walk resets the cursor");
        assert_eq!(scrub.verified_through, 1501);
        assert_eq!(
            scrub.last_full_verify_unix,
            1_000_000 + SCRUB_MAX_AGE_SECS + 1
        );
        clear_now();
    }

    /// Missing or corrupt scrub state must never be treated as "fully
    /// verified, skip everything" — it has to fail safe toward a full walk,
    /// exactly like a `stale` schedule does.
    #[test]
    fn missing_scrub_state_forces_a_full_walk_instead_of_trusting_nothing() {
        let (_dir, layout, store) = repo();
        let tips = build_chain(&store, 1500);
        update(&layout, &store, "main", tips[1499]);
        let dir = ancestry_state::branch_dir(layout.common_dir(), "refs/heads/main");

        fs::remove_file(dir.join("scrub")).unwrap();
        // A leaf that a bounded window would not have reached on a first
        // pass; only a full walk (the missing-state fallback) finds it.
        corrupt_object(&store, &tips[1000]);

        let step = commit(&store, vec![tips[1499]], b"1500");
        let result =
            refs::update_ref_with_ancestry(&layout, "main", RefWriteCondition::Any, &step, &store);
        assert!(
            result.is_err(),
            "missing scrub state must force a full walk, not skip verification"
        );
    }

    /// A scrub file left over from a *different, since-superseded*
    /// generation must never be trusted against the current one — see
    /// `ScrubState`'s doc comment on why `advance`'s advisory
    /// `write_scrub_state` call can, on a crash, leave this file holding
    /// an old generation's `verified_through` paired with a new, shorter
    /// chain on disk.
    ///
    /// Reproduces that exact state without needing to inject a crash mid
    /// `advance`: publish a long chain (`verified_through=600`, window
    /// `end=512` on the very next fast-forward), capture that scrub file's
    /// bytes, reset to an unrelated 5-leaf chain (a real generation
    /// change, correctly re-verified and re-scrubbed on its own), then
    /// restore the captured *old* bytes over the new generation's own
    /// scrub file — reproducing "the crash happened before this
    /// generation's own `write_scrub_state` call ever ran" byte-for-byte,
    /// regardless of which write ordering or fault-injection point
    /// produces it. Before the generation-binding fix, the next
    /// fast-forward's `verify_scrub_window(store, &prefix, 0, 512)` would
    /// slice `prefix[0..512]` on a 5-leaf `prefix` and panic; the fix
    /// discards the mismatched-generation state and falls back to a full
    /// walk instead, exactly like a missing file.
    #[test]
    fn scrub_state_from_a_superseded_generation_is_discarded_not_misapplied() {
        let (_dir, layout, store) = repo();
        let dir = ancestry_state::branch_dir(layout.common_dir(), "refs/heads/main");

        let long_tips = build_chain(&store, 600);
        update(&layout, &store, "main", long_tips[599]);
        let stale_scrub_bytes = fs::read(scrub_path(&dir)).unwrap();
        assert_eq!(
            ScrubState::decode(&stale_scrub_bytes)
                .unwrap()
                .verified_through,
            600
        );

        // A real generation change to a short, unrelated 5-leaf chain —
        // this legitimately re-verifies and writes its own correct
        // (short) scrub state.
        let short_tips = build_chain(&store, 5);
        update(&layout, &store, "main", short_tips[4]);
        let new_generation = AncestrySnapshot::load(&layout, "main")
            .unwrap()
            .descriptor()
            .generation;
        assert_ne!(
            ScrubState::decode(&stale_scrub_bytes).unwrap().generation,
            new_generation,
            "sanity: the two generations must actually differ"
        );

        // Simulate the crash window: the new generation's own
        // write_scrub_state call never ran, so the file on disk is still
        // the long generation's stale bytes.
        fs::write(scrub_path(&dir), &stale_scrub_bytes).unwrap();

        // An ordinary fast-forward on the new (short) generation must
        // still succeed — not panic — and must end up with its own,
        // correctly-bound scrub state afterward.
        let next = commit(&store, vec![short_tips[4]], b"5");
        update(&layout, &store, "main", next);

        let scrub = read_scrub_state(&dir).unwrap().unwrap();
        assert_eq!(
            scrub.generation, new_generation,
            "the discarded stale state must be replaced with one bound to the current generation"
        );
        assert_eq!(scrub.verified_through, 6);
    }

    /// Not a correctness test — a manual profiling comparison, in the
    /// spirit of `profile_read_current_descriptor_vs_full_chain_read`
    /// above and for the same reason: `cargo bench`'s `sequential_publish`
    /// only goes up to 300 commits (fsync-dominated well below where the
    /// scrub window's O(N)-vs-bounded read-count difference would show up
    /// over that noise), and reaching an N where it would is impractical
    /// to benchmark end-to-end. Both variants go through the identical
    /// durable-publish pipeline (same fsync/`sync_dir` calls either way),
    /// so the fsync cost is a roughly constant additive term common to
    /// both — the wall-clock delta between them isolates
    /// `decide_chain`'s store-read savings even without eliminating fsync
    /// noise. Run with:
    /// `cargo test -p mkit-core --features history-mmr --lib \
    ///   history::ancestry::tests::profile_scrub_window_vs_full_walk_every_publish \
    ///   -- --ignored --nocapture`
    #[test]
    #[ignore = "manual profiling tool, not a correctness assertion"]
    fn profile_scrub_window_vs_full_walk_every_publish() {
        const LEAVES: usize = 20_000;
        const PUBLISHES: u32 = 20;

        fn fixture() -> (
            tempfile::TempDir,
            RepoLayout,
            ObjectStore,
            PathBuf,
            Vec<Hash>,
        ) {
            let (dir, layout, store) = repo();
            let base = build_chain(&store, LEAVES);
            update(&layout, &store, "main", base[LEAVES - 1]);
            let branch_dir = ancestry_state::branch_dir(layout.common_dir(), "refs/heads/main");
            (dir, layout, store, branch_dir, base)
        }

        // Warm the OS page cache equally before timing either variant.
        {
            let (_dir, layout, store, _branch_dir, base) = fixture();
            let extra = commit(&store, vec![base[LEAVES - 1]], b"warm");
            update(&layout, &store, "main", extra);
        }

        let (_dir, layout, store, _branch_dir, base) = fixture();
        let mut tip = base[LEAVES - 1];
        let start = std::time::Instant::now();
        for i in 0..PUBLISHES {
            let next = commit(&store, vec![tip], i.to_be_bytes().as_slice());
            update(&layout, &store, "main", next);
            tip = next;
        }
        let scrubbed_elapsed = start.elapsed();

        let (_dir, layout, store, branch_dir, base) = fixture();
        let mut tip = base[LEAVES - 1];
        let start = std::time::Instant::now();
        for i in 0..PUBLISHES {
            // Deleting the scrub state before every publish forces the
            // `decide_chain` fallback that treats it as "no prior full
            // verification on record" — a full `first_parent_chain` walk
            // every time, matching this file's pre-scrub-window behavior.
            fs::remove_file(branch_dir.join("scrub")).unwrap();
            let next = commit(&store, vec![tip], i.to_be_bytes().as_slice());
            update(&layout, &store, "main", next);
            tip = next;
        }
        let full_walk_elapsed = start.elapsed();

        eprintln!(
            "scrub window (new):  {:?}/publish over {PUBLISHES} publishes, {LEAVES} leaves",
            scrubbed_elapsed / PUBLISHES
        );
        eprintln!(
            "full walk (old, forced every publish): {:?}/publish over {PUBLISHES} publishes, {LEAVES} leaves",
            full_walk_elapsed / PUBLISHES
        );
        eprintln!(
            "speedup: {:.1}x",
            full_walk_elapsed.as_secs_f64() / scrubbed_elapsed.as_secs_f64()
        );
    }
}
