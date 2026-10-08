//! Bounded timestamp-priority history traversal shared by the server and
//! embedders.
//!
//! [`TimestampDiscovery`] is a pure, I/O-free state machine that emits an
//! all-parent commit/remix history in decreasing canonical timestamp order,
//! breaking ties by discovery order. The caller performs every object decode
//! (canonical reads, metadata lookups, descent-stop checks) through its own
//! I/O loop and feeds the results back in; the reducer owns only the
//! ordering, deduplication and bound accounting. The normative order,
//! timestamp and cap semantics are frozen in `docs/specs/SPEC-HISTORY-ORDER.md`;
//! this module is its reference implementation.
//!
//! The order is named [`HistoryOrder::TimestampDiscovery`] so it can never be
//! confused with the server's breadth-first `HistoryMode::AllParents` or the
//! CLI's hash-tiebreak date order, neither of which this module replaces.
//!
//! Driving the walk:
//!
//! 1. Seed the frontier with [`TimestampDiscovery::push`]. A selected-ref
//!    page seeds the tip peeled through any tags to its commit/remix; a
//!    continuation page reconstructs the walk with
//!    [`TimestampDiscovery::decode`] instead.
//! 2. Call [`TimestampDiscovery::step`]. [`WalkStep::NeedTimestamp`] asks
//!    the caller to decode that candidate's canonical timestamp and report
//!    it with [`TimestampDiscovery::provide_timestamp`];
//!    [`WalkStep::Emit`] hands out the next output id.
//! 3. Decode the emitted commit/remix, then call [`TimestampDiscovery::emit`]
//!    with all of its local parents in canonical decoded order, each marked
//!    for enqueue or held back by a live descent stop. The call completes
//!    parent discovery even for the last output of a page, after which
//!    [`TimestampDiscovery::encode`] captures the resumable state.
//!
//! Boundedness is a hard contract: the frontier never exceeds
//! [`FRONTIER_MAX`] pending slots and the emitted set never exceeds
//! [`EMITTED_MAX`] ids. Exceeding either bound fails with an explicit
//! [`HistoryOrderError`] and publishes no partial state; the walk never
//! truncates, evicts, or repeats an id.

use crate::hash::{HASH_LEN, Hash};
use std::collections::BTreeSet;

/// Maximum pending frontier slots, counting every retained slot including
/// duplicate ids. Spec: SPEC-HISTORY-ORDER §4.
pub const FRONTIER_MAX: usize = 256;
/// Maximum remembered emitted ids. Spec: SPEC-HISTORY-ORDER §4.
pub const EMITTED_MAX: usize = 192;

/// Snapshot encoding version accepted by [`TimestampDiscovery::decode`].
const SNAPSHOT_VERSION: u8 = 0x01;
/// Snapshot order discriminator for [`HistoryOrder::TimestampDiscovery`].
const ORDER_ID_TIMESTAMP_DISCOVERY: u8 = 0x01;

const FLAG_DEDUP_ACTIVE: u8 = 0x01;
const FLAG_SELECTED: u8 = 0x02;
const FLAG_SEALED: u8 = 0x04;
const KNOWN_FLAGS: u8 = FLAG_DEDUP_ACTIVE | FLAG_SELECTED | FLAG_SEALED;

/// The explicit all-parent ordering produced by [`TimestampDiscovery`].
///
/// `#[non_exhaustive]` so a second order (a differently-keyed priority, a
/// topological variant) can join this enum without breaking the public API;
/// each variant's snapshot encoding carries its own order discriminator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HistoryOrder {
    /// Decreasing canonical `Commit.timestamp` / `Remix.timestamp` (`u64`),
    /// ties broken by retained discovery order. Never a hash tiebreak, never
    /// a topological gate.
    TimestampDiscovery,
}

/// One frontier slot: a decoded-or-undecoded candidate awaiting emission.
///
/// `timestamp` is the candidate's canonical `Commit.timestamp` /
/// `Remix.timestamp` once the host has decoded it, and `None` while its
/// priority key is still unknown. An unknown-key slot wins by default only
/// when it is the last pending candidate; with competitors it must be keyed
/// before the walk selects output (see [`TimestampDiscovery::step`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingCandidate {
    /// Candidate object id.
    pub id: Hash,
    /// Canonical timestamp priority key, when known.
    pub timestamp: Option<u64>,
}

/// One local parent edge of the emitted node, in canonical decoded order.
///
/// The slice handed to [`TimestampDiscovery::emit`] lists every local
/// commit/remix parent of the decoded node — including edges the caller
/// refuses to traverse — so the reducer can detect merges from the true
/// parent count. Foreign remix sources, trees, blobs and delta bases are
/// never listed: they are not history lineage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParentEdge {
    /// Parent object id.
    pub id: Hash,
    /// Parent's canonical timestamp when the caller already decoded it for
    /// priority lookahead; `None` defers the key (the walk requests it only
    /// if the candidate later competes).
    pub timestamp: Option<u64>,
    /// `false` when a live descent stop or edge-role check holds this parent
    /// out of the frontier; the edge still counts toward merge detection.
    pub enqueue: bool,
}

/// What the walk needs from its caller next, from
/// [`TimestampDiscovery::step`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WalkStep {
    /// Emit this id: decode it, serve it, then register it with
    /// [`TimestampDiscovery::emit`].
    Emit(Hash),
    /// The walk cannot choose among multiple pending candidates while this
    /// id's priority key is unknown. Decode its canonical timestamp and
    /// report it with [`TimestampDiscovery::provide_timestamp`], then call
    /// `step` again. A lookahead decode stays pending; it is never a reason
    /// to expand or emit the candidate early.
    NeedTimestamp(Hash),
    /// No pending candidate remains that could emit. A continuation token is
    /// absent exactly in this state.
    Done,
}

/// Errors raised by [`TimestampDiscovery`]. Cap errors publish no partial
/// state: the failed call leaves the walk untouched.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum HistoryOrderError {
    /// A push or parent enqueue would exceed [`FRONTIER_MAX`]. Duplicate
    /// slots count.
    #[error("pending frontier exceeds 256 slots")]
    FrontierFull,
    /// Recording another emitted id would exceed [`EMITTED_MAX`].
    #[error("emitted set exceeds 192 ids")]
    EmittedFull,
    /// [`TimestampDiscovery::emit`] without a preceding [`WalkStep::Emit`].
    #[error("no selected candidate awaits emit")]
    NoSelectedCandidate,
    /// A [`WalkStep::Emit`] candidate is still outstanding: the previous
    /// candidate's parents were not registered yet.
    #[error("selected candidate still awaits emit")]
    CandidateOutstanding,
    /// [`TimestampDiscovery::push`] named the outstanding selected id.
    #[error("id is the outstanding selected candidate")]
    SelectedCandidate,
    /// [`TimestampDiscovery::push`] after the first completed emission.
    /// The seed window is closed: a late seed could descend into the
    /// unrecorded linear prefix and re-emit it.
    #[error("push after the first completed emission")]
    WalkStarted,
    /// [`TimestampDiscovery::provide_timestamp`] named an id that is not a
    /// pending slot.
    #[error("id is not pending")]
    NotPending(Hash),
    /// A supplied timestamp disagrees with an already-keyed slot for the
    /// same id.
    #[error("timestamp {supplied} conflicts with recorded key {recorded}")]
    ConflictingTimestamp {
        /// Candidate id whose slots disagree.
        id: Hash,
        /// Key already recorded on a slot.
        recorded: u64,
        /// Key supplied by the caller.
        supplied: u64,
    },
    /// Snapshot input ended before a complete field could be read.
    #[error("snapshot ended before a complete field could be read")]
    Truncated,
    /// Bytes remain after a complete snapshot.
    #[error("non-empty trailing bytes after a complete snapshot")]
    TrailingData,
    /// Snapshot `version` byte is not `SNAPSHOT_VERSION` (0x01).
    #[error("snapshot version byte {0:#04x} is not 0x01")]
    UnsupportedVersion(u8),
    /// Snapshot `order` byte is not `ORDER_ID_TIMESTAMP_DISCOVERY` (0x01).
    #[error("snapshot order byte {0:#04x} is not 0x01")]
    UnsupportedOrder(u8),
    /// Snapshot `flags` byte has reserved bits set.
    #[error("snapshot flags byte {0:#04x} has reserved bits set")]
    InvalidFlags(u8),
    /// Snapshot `pending_len` or `emitted_len` exceeds its cap.
    #[error("snapshot {field} count {count} exceeds cap {cap}")]
    LimitExceeded {
        /// Which count field overflowed.
        field: &'static str,
        /// Declared count.
        count: usize,
        /// The cap it exceeded.
        cap: usize,
    },
    /// Snapshot emitted ids are not strictly ascending (canonical form).
    #[error("snapshot emitted ids are not strictly ascending")]
    UnsortedEmitted,
    /// A pending entry's timestamp marker byte is not 0x00/0x01.
    #[error("snapshot timestamp marker byte {0:#04x} is not 0x00 or 0x01")]
    InvalidTimestampMarker(u8),
    /// `dedup_active` disagrees with the emitted set: dedup activates only
    /// by recording a merge, so the flag is set exactly when the set is
    /// non-empty.
    #[error("snapshot dedup flag disagrees with the emitted set")]
    InconsistentDedupState,
}

/// Pure bounded timestamp/discovery-order history reducer.
///
/// See the module docs for the driving contract. Invariants the type
/// maintains between calls (all enforced, none assumed):
///
/// - `pending` retains slots in insertion order, including duplicate ids;
///   position is the tiebreak among equal timestamps.
/// - `emitted` records ids only once dedup is live: the first emitted
///   node with more than one local parent activates dedup and enters the
///   set itself. So does any emission while other candidates still pend —
///   independently seeded histories can reconverge without a merge.
///   Earlier linear-prefix emissions are never seeded.
/// - `selected` is the popped candidate awaiting [`Self::emit`]; `step`
///   refuses to advance while it is set so a page cannot skip the
///   complete-parent-enqueue step.
/// - `sealed` latches at the first completed `emit`: seeding is open only
///   before the first emission, because pre-activation emissions are not
///   recorded and a later seed could descend into them unseen.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TimestampDiscovery {
    pending: Vec<PendingCandidate>,
    emitted: BTreeSet<Hash>,
    dedup_active: bool,
    sealed: bool,
    selected: Option<Hash>,
}

impl TimestampDiscovery {
    /// An empty walk. Seed with [`Self::push`] or restore with
    /// [`Self::decode`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The ordering this reducer produces.
    #[must_use]
    pub fn order(&self) -> HistoryOrder {
        HistoryOrder::TimestampDiscovery
    }

    /// Append a frontier candidate (a page-1 root, or a host-side
    /// discovery made before the walk started). Slots are retained
    /// verbatim — duplicate ids stay duplicate and count toward
    /// [`FRONTIER_MAX`]; emission suppression handles them at pop.
    /// Pushing the outstanding selected id is refused because the queue
    /// cannot legitimately rediscover an id its owner has not finished
    /// expanding, and every push after the first completed emission is
    /// refused: the seed window must close before output begins so a late
    /// seed cannot descend into the unrecorded linear prefix.
    pub fn push(&mut self, candidate: PendingCandidate) -> Result<(), HistoryOrderError> {
        if self.sealed {
            return Err(HistoryOrderError::WalkStarted);
        }
        if self.selected == Some(candidate.id) {
            return Err(HistoryOrderError::SelectedCandidate);
        }
        if self.pending.len() >= FRONTIER_MAX {
            return Err(HistoryOrderError::FrontierFull);
        }
        self.pending.push(candidate);
        Ok(())
    }

    /// Select the next step. Pure ordering work only; the caller owns all
    /// object I/O.
    ///
    /// Dead slots — pending ids already in the emitted set — are dropped
    /// whenever dedup is active; that cleanup cannot remove a future unique
    /// emission. A sole remaining candidate emits without needing a
    /// priority key (there is no competitor), which is what lets a linear
    /// page-1 loop skip lookahead decodes entirely. With multiple
    /// candidates every unknown key is requested in pending order before
    /// output is selected.
    pub fn step(&mut self) -> Result<WalkStep, HistoryOrderError> {
        if self.selected.is_some() {
            return Err(HistoryOrderError::CandidateOutstanding);
        }
        if self.dedup_active {
            self.pending.retain(|e| !self.emitted.contains(&e.id));
        }
        match self.pending.len() {
            0 => Ok(WalkStep::Done),
            1 => Ok(self.select(0)),
            _ => {
                if let Some(e) = self.pending.iter().find(|e| e.timestamp.is_none()) {
                    return Ok(WalkStep::NeedTimestamp(e.id));
                }
                // Greatest timestamp wins; retained pending position breaks
                // ties (`Reverse` timestamp, then lowest index).
                match self
                    .pending
                    .iter()
                    .enumerate()
                    .min_by_key(|(idx, e)| (std::cmp::Reverse(e.timestamp), *idx))
                {
                    Some((idx, _)) => Ok(self.select(idx)),
                    None => Ok(WalkStep::Done),
                }
            }
        }
    }

    /// Report a pending candidate's canonical timestamp, filling every
    /// unknown-key slot for that id (duplicate slots share one canonical
    /// key). The slot keeps its pending position for ties. Refuses ids that
    /// are not pending and keys that disagree with an already-keyed slot.
    pub fn provide_timestamp(&mut self, id: Hash, timestamp: u64) -> Result<(), HistoryOrderError> {
        let mut any = false;
        for e in &self.pending {
            if e.id != id {
                continue;
            }
            any = true;
            if let Some(recorded) = e.timestamp
                && recorded != timestamp
            {
                return Err(HistoryOrderError::ConflictingTimestamp {
                    id,
                    recorded,
                    supplied: timestamp,
                });
            }
        }
        if !any {
            return Err(HistoryOrderError::NotPending(id));
        }
        for e in &mut self.pending {
            if e.id == id {
                e.timestamp = Some(timestamp);
            }
        }
        Ok(())
    }

    /// Record the outstanding [`WalkStep::Emit`] candidate as emitted and
    /// queue its eligible parents.
    ///
    /// `parents` MUST list every local commit/remix parent of the decoded
    /// node in canonical order (see [`ParentEdge`]). Dedup goes live with
    /// the first emission that a later discovery could revisit — a node
    /// with more than one local parent (its branches may reconverge), or
    /// any emission while other candidates still pend (independently
    /// seeded histories can reconverge without a merge) — *before* the
    /// triggering node itself is recorded. From then on every emitted id
    /// enters the emitted set. Parents already emitted are omitted; the
    /// rest append after all existing pending slots, so earlier
    /// equal-timestamp candidates always outrank new discoveries.
    ///
    /// Both caps are enforced before any state changes: a failure records
    /// nothing, keeping the selected candidate outstanding.
    pub fn emit(&mut self, parents: &[ParentEdge]) -> Result<(), HistoryOrderError> {
        let id = self
            .selected
            .ok_or(HistoryOrderError::NoSelectedCandidate)?;
        let dedup_after = self.dedup_active || parents.len() > 1 || !self.pending.is_empty();
        let accepted = parents
            .iter()
            .filter(|e| e.enqueue)
            // A node is never its own ancestor; a self edge is malformed
            // input and must not be queued regardless of dedup state.
            .filter(|e| e.id != id && !(dedup_after && self.emitted.contains(&e.id)))
            .map(|e| PendingCandidate {
                id: e.id,
                timestamp: e.timestamp,
            })
            .collect::<Vec<_>>();
        if self.pending.len() + accepted.len() > FRONTIER_MAX {
            return Err(HistoryOrderError::FrontierFull);
        }
        if dedup_after && !self.emitted.contains(&id) && self.emitted.len() >= EMITTED_MAX {
            return Err(HistoryOrderError::EmittedFull);
        }
        self.dedup_active = dedup_after;
        if dedup_after {
            self.emitted.insert(id);
        }
        self.sealed = true;
        self.pending.extend(accepted);
        self.selected = None;
        Ok(())
    }

    fn select(&mut self, idx: usize) -> WalkStep {
        let e = self.pending.remove(idx);
        self.selected = Some(e.id);
        WalkStep::Emit(e.id)
    }

    /// Pending slots in retained order, including duplicate ids. While
    /// dedup is live the slice may contain already-emitted ids; they are
    /// dead slots that the next [`Self::step`] drops and that can never
    /// emit.
    #[must_use]
    pub fn pending(&self) -> &[PendingCandidate] {
        &self.pending
    }

    /// Remembered emitted ids in ascending (canonical encoded) order.
    #[must_use]
    pub fn emitted(&self) -> impl ExactSizeIterator<Item = &Hash> {
        self.emitted.iter()
    }

    /// Whether dedup is active: a multi-local-parent node was emitted, or
    /// an emission completed while other candidates still pend.
    #[must_use]
    pub fn dedup_active(&self) -> bool {
        self.dedup_active
    }

    /// Whether the seed window is closed (the first emission completed;
    /// [`Self::push`] now refuses).
    #[must_use]
    pub fn sealed(&self) -> bool {
        self.sealed
    }

    /// The outstanding selected id awaiting [`Self::emit`], if any.
    #[must_use]
    pub fn selected(&self) -> Option<Hash> {
        self.selected
    }

    /// Whether no pending or outstanding candidate could still emit; the
    /// walk is finished and yields no continuation token. A pending slot
    /// whose id is already emitted does not count — it can never emit.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.selected.is_none()
            && !self
                .pending
                .iter()
                .any(|e| !(self.dedup_active && self.emitted.contains(&e.id)))
    }

    /// Serialize the full walk state (frontier, emitted set, dedup flag and
    /// any outstanding selected candidate) as the canonical byte snapshot
    /// of SPEC-HISTORY-ORDER §5. This is the seam a continuation issuer
    /// embeds in its token claims; the reducer itself does no I/O.
    ///
    /// # Panics
    ///
    /// Never through the public API: the caps keep both counts inside
    /// `u16`; a panic means internal state was corrupted.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            7 + self.pending.len() * (HASH_LEN + 9)
                + usize::from(self.selected.is_some()) * HASH_LEN
                + self.emitted.len() * HASH_LEN,
        );
        let mut flags = 0u8;
        if self.dedup_active {
            flags |= FLAG_DEDUP_ACTIVE;
        }
        if self.selected.is_some() {
            flags |= FLAG_SELECTED;
        }
        if self.sealed {
            flags |= FLAG_SEALED;
        }
        out.push(SNAPSHOT_VERSION);
        out.push(ORDER_ID_TIMESTAMP_DISCOVERY);
        out.push(flags);
        let pending_len = u16::try_from(self.pending.len()).expect("frontier cap fits u16");
        let emitted_len = u16::try_from(self.emitted.len()).expect("emitted cap fits u16");
        out.extend_from_slice(&pending_len.to_le_bytes());
        out.extend_from_slice(&emitted_len.to_le_bytes());
        for e in &self.pending {
            out.extend_from_slice(&e.id);
            match e.timestamp {
                Some(ts) => {
                    out.push(0x01);
                    out.extend_from_slice(&ts.to_le_bytes());
                }
                None => out.push(0x00),
            }
        }
        if let Some(id) = self.selected {
            out.extend_from_slice(&id);
        }
        for id in &self.emitted {
            out.extend_from_slice(id);
        }
        out
    }

    /// Restore a walk from [`Self::encode`] bytes. Every field is
    /// range-checked: version, order, reserved flag bits, both caps,
    /// strictly-ascending emitted ids and exact input consumption. The
    /// result is bit-for-bit the encoded state, dead slots included —
    /// suppression runs at the next [`Self::step`], not at decode.
    pub fn decode(input: &[u8]) -> Result<Self, HistoryOrderError> {
        fn take<'a, const N: usize>(cur: &mut &'a [u8]) -> Result<&'a [u8; N], HistoryOrderError> {
            let (head, tail) = cur
                .split_first_chunk::<N>()
                .ok_or(HistoryOrderError::Truncated)?;
            *cur = tail;
            Ok(head)
        }
        let mut cur = input;
        let version = take::<1>(&mut cur)?[0];
        if version != SNAPSHOT_VERSION {
            return Err(HistoryOrderError::UnsupportedVersion(version));
        }
        let order = take::<1>(&mut cur)?[0];
        if order != ORDER_ID_TIMESTAMP_DISCOVERY {
            return Err(HistoryOrderError::UnsupportedOrder(order));
        }
        let flags = take::<1>(&mut cur)?[0];
        if flags & !KNOWN_FLAGS != 0 {
            return Err(HistoryOrderError::InvalidFlags(flags));
        }
        let pending_len = usize::from(u16::from_le_bytes(*take::<2>(&mut cur)?));
        let emitted_len = usize::from(u16::from_le_bytes(*take::<2>(&mut cur)?));
        if pending_len > FRONTIER_MAX {
            return Err(HistoryOrderError::LimitExceeded {
                field: "pending_len",
                count: pending_len,
                cap: FRONTIER_MAX,
            });
        }
        if emitted_len > EMITTED_MAX {
            return Err(HistoryOrderError::LimitExceeded {
                field: "emitted_len",
                count: emitted_len,
                cap: EMITTED_MAX,
            });
        }
        let mut pending = Vec::with_capacity(pending_len);
        for _ in 0..pending_len {
            let id: Hash = *take::<HASH_LEN>(&mut cur)?;
            let marker = take::<1>(&mut cur)?[0];
            let timestamp = match marker {
                0x00 => None,
                0x01 => Some(u64::from_le_bytes(*take::<8>(&mut cur)?)),
                other => return Err(HistoryOrderError::InvalidTimestampMarker(other)),
            };
            pending.push(PendingCandidate { id, timestamp });
        }
        let selected = if flags & FLAG_SELECTED != 0 {
            Some(*take::<HASH_LEN>(&mut cur)?)
        } else {
            None
        };
        let mut emitted = BTreeSet::new();
        let mut prev = None;
        for _ in 0..emitted_len {
            let id: Hash = *take::<HASH_LEN>(&mut cur)?;
            if prev.is_some_and(|p| id <= p) {
                return Err(HistoryOrderError::UnsortedEmitted);
            }
            prev = Some(id);
            emitted.insert(id);
        }
        if !cur.is_empty() {
            return Err(HistoryOrderError::TrailingData);
        }
        let dedup_active = flags & FLAG_DEDUP_ACTIVE != 0;
        if dedup_active == emitted.is_empty() {
            return Err(HistoryOrderError::InconsistentDedupState);
        }
        Ok(Self {
            pending,
            emitted,
            dedup_active,
            sealed: flags & FLAG_SEALED != 0,
            selected,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn id(byte: u8) -> Hash {
        [byte; HASH_LEN]
    }

    /// A distinct id space for numeric fixtures (LE u64 in the first bytes,
    /// zero padding) that can never collide with `id(b'X')` letter ids.
    fn nid(i: u64) -> Hash {
        let mut h = [0u8; HASH_LEN];
        h[..8].copy_from_slice(&i.to_le_bytes());
        h
    }

    /// In-memory commit/remix graph: canonical timestamp plus ordered local
    /// parents per id. Stands in for the caller's canonical-decode loop.
    #[derive(Debug, Default)]
    struct Graph {
        nodes: BTreeMap<Hash, (u64, Vec<Hash>)>,
    }

    impl Graph {
        fn node(&mut self, id: Hash, timestamp: u64, parents: &[Hash]) -> &mut Self {
            self.nodes.insert(id, (timestamp, parents.to_vec()));
            self
        }
        fn get(&self, id: &Hash) -> &(u64, Vec<Hash>) {
            self.nodes.get(id).expect("walk only asks for known ids")
        }
        fn descendants(&self, root: Hash) -> BTreeSet<Hash> {
            let mut seen = BTreeSet::from([root]);
            let mut stack = vec![root];
            while let Some(id) = stack.pop() {
                for p in &self.get(&id).1 {
                    if seen.insert(*p) {
                        stack.push(*p);
                    }
                }
            }
            seen
        }
    }

    #[derive(Default)]
    struct Stats {
        /// `NeedTimestamp` round-trips served to the walk.
        hydrations: usize,
    }

    /// One walk page, exactly as a host drives it: `step` -> decode -> `emit`
    /// -> repeat until `limit` outputs or `Done`. `keyed` parents carry their
    /// canonical timestamps (the caller lookahead-decoded them); unkeyed
    /// parents go in unknown and the walk requests keys only under
    /// competition. Emission stops after `emit` completes the last output's
    /// parent enqueue.
    fn page(
        walk: &mut TimestampDiscovery,
        graph: &Graph,
        limit: usize,
        keyed: bool,
        stats: &mut Stats,
    ) -> Result<Vec<Hash>, HistoryOrderError> {
        let mut out = Vec::new();
        while out.len() < limit {
            match walk.step()? {
                WalkStep::Done => break,
                WalkStep::NeedTimestamp(candidate) => {
                    stats.hydrations += 1;
                    walk.provide_timestamp(candidate, graph.get(&candidate).0)?;
                }
                WalkStep::Emit(candidate) => {
                    out.push(candidate);
                    let (_, parents) = graph.get(&candidate);
                    let edges = parents
                        .iter()
                        .map(|p| ParentEdge {
                            id: *p,
                            timestamp: keyed.then_some(graph.get(p).0),
                            enqueue: true,
                        })
                        .collect::<Vec<_>>();
                    walk.emit(&edges)?;
                }
            }
        }
        Ok(out)
    }

    /// Drive a full walk in one page.
    fn run_full(graph: &Graph, seeds: &[Hash], keyed: bool) -> Vec<Hash> {
        let mut walk = TimestampDiscovery::new();
        for &seed in seeds {
            walk.push(PendingCandidate {
                id: seed,
                timestamp: keyed.then_some(graph.get(&seed).0),
            })
            .unwrap();
        }
        let mut stats = Stats::default();
        page(&mut walk, graph, usize::MAX, keyed, &mut stats).unwrap()
    }

    /// Drive a walk in pages of `limit`, encode->decode resuming between
    /// pages exactly as a stateless continuation would.
    fn run_paged(graph: &Graph, seeds: &[Hash], limit: usize, keyed: bool) -> Vec<Hash> {
        let mut walk = TimestampDiscovery::new();
        for &seed in seeds {
            walk.push(PendingCandidate {
                id: seed,
                timestamp: keyed.then_some(graph.get(&seed).0),
            })
            .unwrap();
        }
        let mut stats = Stats::default();
        let mut out = Vec::new();
        loop {
            out.extend(page(&mut walk, graph, limit, keyed, &mut stats).unwrap());
            if walk.is_complete() {
                return out;
            }
            walk = TimestampDiscovery::decode(&walk.encode()).unwrap();
        }
    }

    /// The design's equal-time asymmetric merge: every timestamp is 100.
    /// `M -> [A, B]`, `A -> X`, `B -> C`, `C -> X`, `X -> []`. X is an
    /// ancestor of C yet emits before it — timestamp priority with
    /// discovery ties, not a topological order.
    fn asymmetric_merge_graph() -> Graph {
        let mut g = Graph::default();
        g.node(id(b'M'), 100, &[id(b'A'), id(b'B')])
            .node(id(b'A'), 100, &[id(b'X')])
            .node(id(b'B'), 100, &[id(b'C')])
            .node(id(b'C'), 100, &[id(b'X')])
            .node(id(b'X'), 100, &[]);
        g
    }

    #[test]
    fn equal_time_asymmetric_merge_matches_design() {
        let g = asymmetric_merge_graph();
        for keyed in [true, false] {
            assert_eq!(
                run_full(&g, &[id(b'M')], keyed),
                vec![id(b'M'), id(b'A'), id(b'B'), id(b'X'), id(b'C')],
                "keyed={keyed}"
            );
            assert_eq!(
                run_paged(&g, &[id(b'M')], 2, keyed),
                vec![id(b'M'), id(b'A'), id(b'B'), id(b'X'), id(b'C')],
                "keyed={keyed}"
            );
        }
    }

    #[test]
    fn equal_time_merge_page_state_matches_design() {
        let g = asymmetric_merge_graph();
        let mut walk = TimestampDiscovery::new();
        walk.push(PendingCandidate {
            id: id(b'M'),
            timestamp: Some(100),
        })
        .unwrap();
        let mut stats = Stats::default();
        assert_eq!(
            page(&mut walk, &g, 2, true, &mut stats).unwrap(),
            vec![id(b'M'), id(b'A')]
        );
        // After page 1 the frontier is [B, X] in that order; X was decoded
        // and queued but NOT emitted. The emitted set is exactly {M, A}
        // because dedup activated on the merge M.
        assert_eq!(
            walk.pending(),
            &[
                PendingCandidate {
                    id: id(b'B'),
                    timestamp: Some(100)
                },
                PendingCandidate {
                    id: id(b'X'),
                    timestamp: Some(100)
                },
            ]
        );
        assert_eq!(
            walk.emitted().copied().collect::<Vec<_>>(),
            vec![id(b'A'), id(b'M')]
        );
        assert!(walk.dedup_active());
        assert!(!walk.is_complete());
        // The rest of the walk emits X (before its descendant C) and never
        // emits X again when C's parent edge points back at it.
        assert_eq!(
            page(&mut walk, &g, usize::MAX, true, &mut stats).unwrap(),
            vec![id(b'B'), id(b'X'), id(b'C')]
        );
        assert!(walk.is_complete());
        assert_eq!(walk.step().unwrap(), WalkStep::Done);
    }

    #[test]
    fn clock_skew_shared_ancestor_suppressed() {
        // M100 -> [A90, B80], A90 -> X85, B80 -> X85.
        let mut g = Graph::default();
        g.node(id(b'M'), 100, &[id(b'A'), id(b'B')])
            .node(id(b'A'), 90, &[id(b'X')])
            .node(id(b'B'), 80, &[id(b'X')])
            .node(id(b'X'), 85, &[]);
        for keyed in [true, false] {
            assert_eq!(
                run_full(&g, &[id(b'M')], keyed),
                vec![id(b'M'), id(b'A'), id(b'X'), id(b'B')],
                "keyed={keyed}"
            );
            // The skewed ancestor X leaves and re-enters the frontier via B;
            // suppression keeps it to one emission.
            assert_eq!(
                run_paged(&g, &[id(b'M')], 2, keyed),
                vec![id(b'M'), id(b'A'), id(b'X'), id(b'B')],
                "keyed={keyed}"
            );
        }
    }

    #[test]
    fn linear_chain_needs_no_lookahead() {
        let mut g = Graph::default();
        g.node(id(b'A'), 40, &[id(b'B')])
            .node(id(b'B'), 30, &[id(b'C')])
            .node(id(b'C'), 20, &[id(b'D')])
            .node(id(b'D'), 10, &[]);
        for keyed in [true, false] {
            let mut walk = TimestampDiscovery::new();
            walk.push(PendingCandidate {
                id: id(b'A'),
                timestamp: keyed.then_some(40),
            })
            .unwrap();
            let mut stats = Stats::default();
            let out = page(&mut walk, &g, usize::MAX, keyed, &mut stats).unwrap();
            assert_eq!(out, vec![id(b'A'), id(b'B'), id(b'C'), id(b'D')]);
            // A lone pending candidate has no competitor: a linear walk
            // never needs a priority key it does not already have.
            assert_eq!(stats.hydrations, 0, "keyed={keyed}");
            assert!(!walk.dedup_active());
            assert_eq!(walk.emitted().len(), 0);
        }
    }

    #[test]
    fn equal_time_tie_is_discovery_not_hash() {
        // Discovery order Z then A; byte order A < Z. A hash tiebreak would
        // invert the required output.
        let mut g = Graph::default();
        g.node(id(b'M'), 100, &[id(b'Z'), id(b'A')])
            .node(id(b'Z'), 100, &[])
            .node(id(b'A'), 100, &[]);
        assert!(id(b'A') < id(b'Z'));
        assert_eq!(
            run_full(&g, &[id(b'M')], true),
            vec![id(b'M'), id(b'Z'), id(b'A')]
        );
    }

    #[test]
    fn parent_newer_than_child_wins() {
        // No topological gate: the newer parent emits before the older
        // sibling that discovered it.
        let mut g = Graph::default();
        g.node(id(b'M'), 50, &[id(b'A'), id(b'B')])
            .node(id(b'A'), 10, &[])
            .node(id(b'B'), 60, &[]);
        assert_eq!(
            run_full(&g, &[id(b'M')], true),
            vec![id(b'M'), id(b'B'), id(b'A')]
        );
    }

    #[test]
    fn octopus_merge_orders_all_branches() {
        let mut g = Graph::default();
        g.node(id(b'M'), 10, &[id(b'A'), id(b'B'), id(b'C')])
            .node(id(b'A'), 30, &[])
            .node(id(b'B'), 20, &[])
            .node(id(b'C'), 40, &[]);
        assert_eq!(
            run_full(&g, &[id(b'M')], true),
            vec![id(b'M'), id(b'C'), id(b'A'), id(b'B')]
        );
    }

    #[test]
    fn duplicate_parent_ids_emit_once() {
        // A commit listing the same parent twice still queues two slots;
        // suppression emits it once.
        let mut g = Graph::default();
        g.node(id(b'M'), 10, &[id(b'P'), id(b'P')])
            .node(id(b'P'), 5, &[]);
        let mut walk = TimestampDiscovery::new();
        walk.push(PendingCandidate {
            id: id(b'M'),
            timestamp: Some(10),
        })
        .unwrap();
        let mut stats = Stats::default();
        assert_eq!(
            page(&mut walk, &g, 1, true, &mut stats).unwrap(),
            vec![id(b'M')]
        );
        // Both verbatim slots were retained (the v2 slot policy).
        assert_eq!(walk.pending().len(), 2);
        assert!(walk.dedup_active());
        assert_eq!(
            page(&mut walk, &g, usize::MAX, true, &mut stats).unwrap(),
            vec![id(b'P')]
        );
        assert!(walk.is_complete());
    }

    #[test]
    fn independent_seeds_converging_without_merge_dedup() {
        // Two seed tips whose chains converge on S without any merge
        // commit: U -> A -> S and V -> B -> S (a fork, not a merge). A
        // merge-only dedup rule would emit S twice; recording every
        // emission made while other candidates still pend covers it.
        let mut g = Graph::default();
        g.node(id(b'U'), 100, &[id(b'A')])
            .node(id(b'V'), 90, &[id(b'B')])
            .node(id(b'A'), 80, &[id(b'S')])
            .node(id(b'B'), 70, &[id(b'S')])
            .node(id(b'S'), 60, &[]);
        assert_eq!(
            run_full(&g, &[id(b'U'), id(b'V')], true),
            vec![id(b'U'), id(b'V'), id(b'A'), id(b'B'), id(b'S')]
        );
    }

    #[test]
    fn shared_ancestor_queued_twice_emits_once() {
        // Diamond: A and B both parent S under equal timestamps.
        let mut g = Graph::default();
        g.node(id(b'M'), 100, &[id(b'A'), id(b'B')])
            .node(id(b'A'), 100, &[id(b'S')])
            .node(id(b'B'), 100, &[id(b'S')])
            .node(id(b'S'), 100, &[]);
        assert_eq!(
            run_full(&g, &[id(b'M')], true),
            vec![id(b'M'), id(b'A'), id(b'B'), id(b'S')]
        );
    }

    #[test]
    fn held_back_parent_still_counts_for_merge() {
        // A descent stop keeps B out of the frontier, but the decoded node's
        // two local parents still activate dedup.
        let mut g = Graph::default();
        g.node(id(b'M'), 10, &[id(b'A'), id(b'B')])
            .node(id(b'A'), 5, &[])
            .node(id(b'B'), 5, &[]);
        let mut walk = TimestampDiscovery::new();
        walk.push(PendingCandidate {
            id: id(b'M'),
            timestamp: Some(10),
        })
        .unwrap();
        assert_eq!(walk.step().unwrap(), WalkStep::Emit(id(b'M')));
        walk.emit(&[
            ParentEdge {
                id: id(b'A'),
                timestamp: Some(5),
                enqueue: true,
            },
            ParentEdge {
                id: id(b'B'),
                timestamp: Some(5),
                enqueue: false, // live descent stop
            },
        ])
        .unwrap();
        assert!(walk.dedup_active());
        assert_eq!(walk.emitted().copied().collect::<Vec<_>>(), vec![id(b'M')]);
        assert_eq!(walk.pending().len(), 1);
        let mut stats = Stats::default();
        assert_eq!(
            page(&mut walk, &g, usize::MAX, true, &mut stats).unwrap(),
            vec![id(b'A')]
        );
    }

    #[test]
    fn unknown_keys_hydrate_in_pending_order() {
        let g = asymmetric_merge_graph();
        let mut walk = TimestampDiscovery::new();
        walk.push(PendingCandidate {
            id: id(b'M'),
            timestamp: Some(100),
        })
        .unwrap();
        let mut stats = Stats::default();
        assert_eq!(
            page(&mut walk, &g, 1, false, &mut stats).unwrap(),
            vec![id(b'M')]
        );
        // M queued A and B unkeyed; the first hydration request must be the
        // earlier pending slot (A), preserving positions for ties.
        assert_eq!(walk.step().unwrap(), WalkStep::NeedTimestamp(id(b'A')));
        walk.provide_timestamp(id(b'A'), 100).unwrap();
        assert_eq!(walk.step().unwrap(), WalkStep::NeedTimestamp(id(b'B')));
        walk.provide_timestamp(id(b'B'), 100).unwrap();
        assert_eq!(walk.step().unwrap(), WalkStep::Emit(id(b'A')));
    }

    #[test]
    fn provide_timestamp_fills_duplicate_slots() {
        let mut g = Graph::default();
        g.node(id(b'M'), 10, &[id(b'P'), id(b'P')])
            .node(id(b'P'), 5, &[]);
        let mut walk = TimestampDiscovery::new();
        walk.push(PendingCandidate {
            id: id(b'M'),
            timestamp: Some(10),
        })
        .unwrap();
        assert_eq!(walk.step().unwrap(), WalkStep::Emit(id(b'M')));
        walk.emit(&[
            ParentEdge {
                id: id(b'P'),
                timestamp: None,
                enqueue: true,
            },
            ParentEdge {
                id: id(b'P'),
                timestamp: None,
                enqueue: true,
            },
        ])
        .unwrap();
        // Two unkeyed slots for one id share the single canonical key.
        assert_eq!(walk.step().unwrap(), WalkStep::NeedTimestamp(id(b'P')));
        walk.provide_timestamp(id(b'P'), 5).unwrap();
        assert!(walk.pending().iter().all(|e| e.timestamp == Some(5)));
    }

    #[test]
    fn push_after_first_emission_refused() {
        // The hole the sealed latch closes: a linear emission while
        // pending is empty leaves dedup off and E unrecorded; a late seed
        // could descend into E and force a second emission.
        let mut g = Graph::default();
        g.node(id(b'E'), 50, &[id(b'F')])
            .node(id(b'F'), 40, &[])
            .node(id(b'S'), 60, &[id(b'E')]);
        let mut walk = TimestampDiscovery::new();
        walk.push(PendingCandidate {
            id: id(b'E'),
            timestamp: Some(50),
        })
        .unwrap();
        assert_eq!(walk.step().unwrap(), WalkStep::Emit(id(b'E')));
        walk.emit(&[ParentEdge {
            id: id(b'F'),
            timestamp: Some(40),
            enqueue: true,
        }])
        .unwrap();
        // E was never recorded (dedup stayed off) and the seed window is
        // now closed.
        assert!(!walk.dedup_active());
        assert!(walk.sealed());
        assert_eq!(
            walk.push(PendingCandidate {
                id: id(b'S'),
                timestamp: Some(60)
            }),
            Err(HistoryOrderError::WalkStarted)
        );
        // The seal survives a snapshot round-trip.
        let mut resumed = TimestampDiscovery::decode(&walk.encode()).unwrap();
        assert!(resumed.sealed());
        assert_eq!(
            resumed.push(PendingCandidate {
                id: id(b'S'),
                timestamp: Some(60)
            }),
            Err(HistoryOrderError::WalkStarted)
        );
        let mut stats = Stats::default();
        assert_eq!(
            page(&mut resumed, &g, usize::MAX, true, &mut stats).unwrap(),
            vec![id(b'F')]
        );
        assert!(resumed.is_complete());
    }

    #[test]
    fn push_between_select_and_emit_still_allowed() {
        // Sealing latches at emit, not at select: a discovery made mid-step
        // is still inside the seed window, and the pending-nonempty dedup
        // trigger covers its convergence on the selected node.
        let mut g = Graph::default();
        g.node(id(b'E'), 50, &[id(b'F')])
            .node(id(b'F'), 40, &[])
            .node(id(b'S'), 60, &[id(b'E')]);
        let mut walk = TimestampDiscovery::new();
        walk.push(PendingCandidate {
            id: id(b'E'),
            timestamp: Some(50),
        })
        .unwrap();
        assert_eq!(walk.step().unwrap(), WalkStep::Emit(id(b'E')));
        walk.push(PendingCandidate {
            id: id(b'S'),
            timestamp: Some(60),
        })
        .unwrap();
        walk.emit(&[ParentEdge {
            id: id(b'F'),
            timestamp: Some(40),
            enqueue: true,
        }])
        .unwrap();
        assert!(walk.dedup_active());
        // S emits next; its edge back to the already-emitted E is omitted,
        // so E never re-emits.
        let mut stats = Stats::default();
        assert_eq!(
            page(&mut walk, &g, usize::MAX, true, &mut stats).unwrap(),
            vec![id(b'S'), id(b'F')]
        );
    }

    #[test]
    fn misuse_errors_are_explicit() {
        let mut walk = TimestampDiscovery::new();
        assert_eq!(walk.emit(&[]), Err(HistoryOrderError::NoSelectedCandidate));
        walk.push(PendingCandidate {
            id: id(b'A'),
            timestamp: None,
        })
        .unwrap();
        assert_eq!(walk.step().unwrap(), WalkStep::Emit(id(b'A')));
        // A second step() before emit() would skip the outstanding
        // candidate's parent enqueue.
        assert_eq!(walk.step(), Err(HistoryOrderError::CandidateOutstanding));
        assert_eq!(
            walk.push(PendingCandidate {
                id: id(b'A'),
                timestamp: None
            }),
            Err(HistoryOrderError::SelectedCandidate)
        );
        assert_eq!(
            walk.provide_timestamp(id(b'Z'), 1),
            Err(HistoryOrderError::NotPending(id(b'Z')))
        );
    }

    #[test]
    fn conflicting_timestamp_refused() {
        let mut g = Graph::default();
        g.node(id(b'M'), 10, &[id(b'A'), id(b'B')])
            .node(id(b'A'), 5, &[])
            .node(id(b'B'), 5, &[]);
        let mut walk = TimestampDiscovery::new();
        walk.push(PendingCandidate {
            id: id(b'M'),
            timestamp: Some(10),
        })
        .unwrap();
        assert_eq!(walk.step().unwrap(), WalkStep::Emit(id(b'M')));
        walk.emit(&[
            ParentEdge {
                id: id(b'A'),
                timestamp: Some(5),
                enqueue: true,
            },
            ParentEdge {
                id: id(b'B'),
                timestamp: None,
                enqueue: true,
            },
        ])
        .unwrap();
        assert_eq!(
            walk.provide_timestamp(id(b'A'), 9),
            Err(HistoryOrderError::ConflictingTimestamp {
                id: id(b'A'),
                recorded: 5,
                supplied: 9,
            })
        );
        // Same key again is a no-op, not an error.
        walk.provide_timestamp(id(b'A'), 5).unwrap();
    }

    #[test]
    fn frontier_cap_counts_duplicate_slots() {
        let mut walk = TimestampDiscovery::new();
        for _ in 0..FRONTIER_MAX {
            walk.push(PendingCandidate {
                id: id(b'Q'),
                timestamp: None,
            })
            .unwrap();
        }
        assert_eq!(
            walk.push(PendingCandidate {
                id: id(b'R'),
                timestamp: None
            }),
            Err(HistoryOrderError::FrontierFull)
        );
        assert_eq!(walk.pending().len(), FRONTIER_MAX);
    }

    #[test]
    fn emit_frontier_overflow_publishes_nothing() {
        let mut g = Graph::default();
        // One merge whose enqueue would take the frontier past 256.
        g.node(id(b'M'), 10, &[id(b'A'), id(b'B')])
            .node(id(b'A'), 5, &[])
            .node(id(b'B'), 5, &[]);
        let mut walk = TimestampDiscovery::new();
        for _ in 0..FRONTIER_MAX - 1 {
            walk.push(PendingCandidate {
                id: id(0xF0),
                timestamp: Some(1),
            })
            .unwrap();
        }
        walk.push(PendingCandidate {
            id: id(b'M'),
            timestamp: Some(10),
        })
        .unwrap();
        assert_eq!(walk.step().unwrap(), WalkStep::Emit(id(b'M')));
        assert_eq!(
            walk.emit(&[
                ParentEdge {
                    id: id(b'A'),
                    timestamp: Some(5),
                    enqueue: true,
                },
                ParentEdge {
                    id: id(b'B'),
                    timestamp: Some(5),
                    enqueue: true,
                },
            ]),
            Err(HistoryOrderError::FrontierFull)
        );
        // Nothing recorded: the selected candidate stays outstanding and
        // the frontier is untouched.
        assert_eq!(walk.selected(), Some(id(b'M')));
        // M was popped by step(); the frontier still holds the 255 seeds.
        assert_eq!(walk.pending().len(), FRONTIER_MAX - 1);
        assert!(!walk.dedup_active());
    }

    #[test]
    fn emitted_cap_at_192() {
        // Merge then a long linear tail: dedup on from the merge, so every
        // emission past it is remembered. M + P + 190 tail = 192 exactly;
        // the next unique emission fails.
        let mut g = Graph::default();
        let tail = 192u64;
        g.node(id(b'M'), 100, &[id(b'P'), nid(1)])
            .node(id(b'P'), 90, &[]);
        for i in 0..tail {
            let next = if i + 1 == tail {
                &[][..]
            } else {
                &[nid(i + 2)][..]
            };
            g.node(nid(i + 1), 50, next);
        }
        let mut walk = TimestampDiscovery::new();
        walk.push(PendingCandidate {
            id: id(b'M'),
            timestamp: Some(100),
        })
        .unwrap();
        let mut stats = Stats::default();
        // M (merge -> dedup on, recorded), P, then 190 tail emissions: 192.
        assert_eq!(
            page(&mut walk, &g, 192, true, &mut stats).unwrap().len(),
            192
        );
        assert_eq!(walk.emitted().len(), EMITTED_MAX);
        assert_eq!(walk.step().unwrap(), WalkStep::Emit(nid(191)));
        assert_eq!(
            walk.emit(&[ParentEdge {
                id: nid(192),
                timestamp: Some(50),
                enqueue: true,
            }]),
            Err(HistoryOrderError::EmittedFull)
        );
        assert_eq!(walk.emitted().len(), EMITTED_MAX);
        assert_eq!(walk.selected(), Some(nid(191)));
    }

    #[test]
    fn encode_decode_round_trip_everywhere() {
        fn state(
            walk: &TimestampDiscovery,
        ) -> (
            Vec<u8>,
            Vec<PendingCandidate>,
            Vec<Hash>,
            bool,
            bool,
            Option<Hash>,
        ) {
            (
                walk.encode(),
                walk.pending().to_vec(),
                walk.emitted().copied().collect(),
                walk.dedup_active(),
                walk.sealed(),
                walk.selected(),
            )
        }
        let g = asymmetric_merge_graph();
        let mut walk = TimestampDiscovery::new();
        walk.push(PendingCandidate {
            id: id(b'M'),
            timestamp: Some(100),
        })
        .unwrap();
        // Capture every reachable state boundary, including mid-step.
        let mut seen_states = vec![state(&walk)];
        loop {
            match walk.step().unwrap() {
                WalkStep::Done => break,
                WalkStep::NeedTimestamp(candidate) => {
                    walk.provide_timestamp(candidate, g.get(&candidate).0)
                        .unwrap();
                }
                WalkStep::Emit(candidate) => {
                    seen_states.push(state(&walk)); // mid-step: selected set
                    let (_, parents) = g.get(&candidate);
                    walk.emit(
                        &parents
                            .iter()
                            .map(|p| ParentEdge {
                                id: *p,
                                timestamp: Some(100),
                                enqueue: true,
                            })
                            .collect::<Vec<_>>(),
                    )
                    .unwrap();
                    seen_states.push(state(&walk)); // quiescent
                }
            }
        }
        for (bytes, pending, emitted, dedup, sealed, selected) in seen_states {
            let restored = TimestampDiscovery::decode(&bytes).unwrap();
            // Canonical form: re-encoding restores the identical bytes.
            assert_eq!(restored.encode(), bytes);
            // And every accessor reports the encoded state.
            assert_eq!(restored.pending(), pending.as_slice());
            assert_eq!(restored.emitted().copied().collect::<Vec<_>>(), emitted);
            assert_eq!(restored.dedup_active(), dedup);
            assert_eq!(restored.sealed(), sealed);
            assert_eq!(restored.selected(), selected);
        }
        // A mid-step snapshot resumes exactly where it paused.
        let g2 = asymmetric_merge_graph();
        let mut w2 = TimestampDiscovery::new();
        w2.push(PendingCandidate {
            id: id(b'M'),
            timestamp: Some(100),
        })
        .unwrap();
        assert_eq!(w2.step().unwrap(), WalkStep::Emit(id(b'M')));
        let snap = w2.encode();
        let mut resumed = TimestampDiscovery::decode(&snap).unwrap();
        assert_eq!(resumed.selected(), Some(id(b'M')));
        assert_eq!(resumed.step(), Err(HistoryOrderError::CandidateOutstanding));
        let (_, parents) = g2.get(&id(b'M'));
        resumed
            .emit(
                &parents
                    .iter()
                    .map(|p| ParentEdge {
                        id: *p,
                        timestamp: Some(100),
                        enqueue: true,
                    })
                    .collect::<Vec<_>>(),
            )
            .unwrap();
        let mut stats = Stats::default();
        assert_eq!(
            page(&mut resumed, &g2, usize::MAX, true, &mut stats).unwrap(),
            vec![id(b'A'), id(b'B'), id(b'X'), id(b'C')]
        );
    }

    #[test]
    fn decode_rejects_malformed_snapshots() {
        let good = {
            let mut walk = TimestampDiscovery::new();
            walk.push(PendingCandidate {
                id: id(b'A'),
                timestamp: Some(7),
            })
            .unwrap();
            walk.encode()
        };
        // Every strict prefix fails explicitly.
        for cut in 0..good.len() {
            assert!(matches!(
                TimestampDiscovery::decode(&good[..cut]),
                Err(HistoryOrderError::Truncated)
            ));
        }
        let mut bad = good.clone();
        bad.push(0);
        assert_eq!(
            TimestampDiscovery::decode(&bad),
            Err(HistoryOrderError::TrailingData)
        );
        let mut bad = good.clone();
        bad[0] = 0x02;
        assert_eq!(
            TimestampDiscovery::decode(&bad),
            Err(HistoryOrderError::UnsupportedVersion(0x02))
        );
        let mut bad = good.clone();
        bad[1] = 0x7f;
        assert_eq!(
            TimestampDiscovery::decode(&bad),
            Err(HistoryOrderError::UnsupportedOrder(0x7f))
        );
        let mut bad = good.clone();
        bad[2] = 0x08;
        assert_eq!(
            TimestampDiscovery::decode(&bad),
            Err(HistoryOrderError::InvalidFlags(0x08))
        );
        let mut bad = good.clone();
        bad[3..5].copy_from_slice(&u16::try_from(FRONTIER_MAX + 1).unwrap().to_le_bytes());
        assert!(matches!(
            TimestampDiscovery::decode(&bad),
            Err(HistoryOrderError::LimitExceeded {
                field: "pending_len",
                ..
            })
        ));
        let mut bad = good.clone();
        bad[5..7].copy_from_slice(&u16::try_from(EMITTED_MAX + 1).unwrap().to_le_bytes());
        assert!(matches!(
            TimestampDiscovery::decode(&bad),
            Err(HistoryOrderError::LimitExceeded {
                field: "emitted_len",
                ..
            })
        ));
        // Timestamp marker byte outside 0x00/0x01.
        let mut bad = good.clone();
        bad[7 + HASH_LEN] = 0x02;
        assert_eq!(
            TimestampDiscovery::decode(&bad),
            Err(HistoryOrderError::InvalidTimestampMarker(0x02))
        );
        // Emitted ids must be strictly ascending.
        let dup = {
            let mut bytes = vec![0x01, 0x01, FLAG_DEDUP_ACTIVE];
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(&2u16.to_le_bytes());
            bytes.extend_from_slice(&id(b'A'));
            bytes.extend_from_slice(&id(b'A'));
            bytes
        };
        assert_eq!(
            TimestampDiscovery::decode(&dup),
            Err(HistoryOrderError::UnsortedEmitted)
        );
        // dedup flag set but the emitted set is empty (or clear with a
        // non-empty set): not a canonical state.
        let inconsistent = vec![0x01, 0x01, FLAG_DEDUP_ACTIVE, 0, 0, 0, 0];
        assert_eq!(
            TimestampDiscovery::decode(&inconsistent),
            Err(HistoryOrderError::InconsistentDedupState)
        );
        let mut inconsistent = vec![0x01, 0x01, 0x00, 0, 0, 1, 0];
        inconsistent.extend_from_slice(&id(b'A'));
        assert_eq!(
            TimestampDiscovery::decode(&inconsistent),
            Err(HistoryOrderError::InconsistentDedupState)
        );
    }

    #[test]
    fn page_boundary_equivalence_every_size() {
        // Split at every page size; concatenated pages must equal the single
        // run with no skips and no duplicates, snapshots included.
        let mut graphs = vec![asymmetric_merge_graph()];
        let mut skew = Graph::default();
        skew.node(id(b'M'), 100, &[id(b'A'), id(b'B')])
            .node(id(b'A'), 90, &[id(b'X')])
            .node(id(b'B'), 80, &[id(b'X')])
            .node(id(b'X'), 85, &[]);
        graphs.push(skew);
        let mut deep = Graph::default();
        // Nested merges: M->[A,B], A->[C,X], B->[C,D], C->X, D->X.
        deep.node(id(b'M'), 100, &[id(b'A'), id(b'B')])
            .node(id(b'A'), 90, &[id(b'C'), id(b'X')])
            .node(id(b'B'), 90, &[id(b'C'), id(b'D')])
            .node(id(b'C'), 80, &[id(b'X')])
            .node(id(b'D'), 70, &[id(b'X')])
            .node(id(b'X'), 60, &[]);
        graphs.push(deep);
        for g in &graphs {
            for keyed in [true, false] {
                let expect = run_full(g, &[id(b'M')], keyed);
                for size in 1..=expect.len() {
                    let got = run_paged(g, &[id(b'M')], size, keyed);
                    assert_eq!(got, expect, "size={size} keyed={keyed}");
                    let unique: BTreeSet<_> = got.iter().collect();
                    assert_eq!(unique.len(), got.len(), "duplicate emission");
                }
            }
        }
    }

    use proptest::prelude::*;

    /// Random acyclic ancestor graphs: node `i` may only parent nodes with
    /// index `< i`, so cycles are impossible. Timestamps are drawn from a
    /// small range to force ties and skew; duplicate parent ids survive.
    fn dag_strategy() -> impl Strategy<Value = (Graph, Hash)> {
        (1usize..=20).prop_flat_map(|n| {
            (
                proptest::collection::vec(0u64..8, n..=n),
                proptest::collection::vec(proptest::collection::vec(0usize..20, 0..=3), n..=n),
            )
                .prop_map(move |(timestamps, parents)| {
                    let mut g = Graph::default();
                    for (i, (ts, ps)) in timestamps.iter().zip(parents).enumerate() {
                        let ps = ps
                            .iter()
                            .filter(|p| **p < i)
                            .map(|p| id(u8::try_from(*p).unwrap()))
                            .collect::<Vec<_>>();
                        g.node(id(u8::try_from(i).unwrap()), *ts, &ps);
                    }
                    (g, id(u8::try_from(n - 1).unwrap()))
                })
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn paged_equals_single_run((g, seed) in dag_strategy()) {
            for keyed in [true, false] {
                let expect = run_full(&g, &[seed], keyed);
                // Every reachable node emits exactly once, in both modes.
                let reachable = g.descendants(seed);
                let unique: BTreeSet<_> = expect.iter().copied().collect();
                prop_assert_eq!(unique.len(), expect.len());
                prop_assert_eq!(unique, reachable);
                for size in 1..=expect.len() {
                    let got = run_paged(&g, &[seed], size, keyed);
                    prop_assert_eq!(&got, &expect, "size={} keyed={}", size, keyed);
                }
            }
        }

        #[test]
        fn snapshot_round_trip_is_lossless((g, seed) in dag_strategy()) {
            // Encode/decode mid-walk at every quiescent boundary; the
            // resumed walk continues to the identical output.
            let mut walk = TimestampDiscovery::new();
            walk.push(PendingCandidate {
                id: seed,
                timestamp: Some(g.get(&seed).0),
            })
            .unwrap();
            let mut out = Vec::new();
            let mut steps = 0usize;
            loop {
                match walk.step().unwrap() {
                    WalkStep::Done => break,
                    WalkStep::NeedTimestamp(candidate) => {
                        walk.provide_timestamp(candidate, g.get(&candidate).0).unwrap();
                    }
                    WalkStep::Emit(candidate) => {
                        let (_, parents) = g.get(&candidate);
                        walk.emit(
                            &parents
                                .iter()
                                .map(|p| ParentEdge {
                                    id: *p,
                                    timestamp: None,
                                    enqueue: true,
                                })
                                .collect::<Vec<_>>(),
                        )
                        .unwrap();
                        out.push(candidate);
                        steps += 1;
                        if steps.is_multiple_of(3) && !walk.is_complete() {
                            walk = TimestampDiscovery::decode(&walk.encode()).unwrap();
                        }
                    }
                }
            }
            let reachable = g.descendants(seed);
            prop_assert_eq!(out.iter().copied().collect::<BTreeSet<_>>(), reachable);
        }
    }
}
