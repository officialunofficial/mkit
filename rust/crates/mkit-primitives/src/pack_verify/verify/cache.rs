//! Run-scoped write-back cache and live-page ledger for evidence pages.
//!
//! Pages are immutable and content-addressed, so every update to an index
//! produces new pages and supersedes old ones. The cache keeps recently used
//! pages in memory, hands a page to the host only when it must (eviction, a
//! checkpoint, or sealing), and tells the host when a page it holds has become
//! unreachable. A page that is superseded before it was ever handed out is
//! dropped without the host seeing it.
//!
//! Pages belong to one run. A host that never checkpoints can discard all of
//! them at completion; a checkpointing host must keep every page reachable
//! from its latest checkpoint, which is why pages that checkpoint reaches are
//! released only after the next checkpoint exists.
use super::super::resources::Resources;
use crate::{
    codec::failure,
    error::{Failure, FailureCode},
    evidence::PageCommitment,
};
use mkit_core::hash::Hash;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// Bookkeeping charged per tracked page in addition to its resident bytes.
pub(super) const ENTRY_OVERHEAD: u64 = 192;

fn invalid() -> Failure {
    failure(FailureCode::InvalidResponse)
}

/// Whether the host holds a page yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Produced locally and never handed out; the value orders emission.
    Dirty(u64),
    /// The host holds the page and has acknowledged or supplied it.
    Held,
    /// No tree position references the page any more. The entry stays, with
    /// its bookkeeping charge, until the host has been told to drop it.
    Gone,
}

#[derive(Debug)]
struct Entry {
    commitment: PageCommitment,
    /// Resident bytes, absent once evicted or while a feed borrows them.
    bytes: Option<Vec<u8>>,
    /// Tree positions that currently reference the page.
    refs: u32,
    /// Checkpoints that existed when the page was created.
    born: u32,
    state: State,
    /// Recency key while resident.
    tick: u64,
}

/// A page on its way to the host; its byte charge is already reserved.
#[derive(Debug)]
pub(super) struct Retained {
    pub(super) commitment: PageCommitment,
    pub(super) bytes: Vec<u8>,
}

/// Pages released by a checkpoint, as a count and byte total.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct Releasable {
    pub(super) pages: u64,
    pub(super) bytes: u64,
}

#[derive(Debug)]
pub(super) struct PageCache {
    entries: BTreeMap<Hash, Entry>,
    /// Resident pages by recency, oldest first.
    recency: BTreeMap<u64, Hash>,
    /// Dirty pages in creation order.
    dirty: BTreeMap<u64, Hash>,
    clock: u64,
    resident: u64,
    capacity: u64,
    /// Checkpoints that exist for this run (a resumed run starts with one).
    checkpoints: u32,
    /// Gone pages the latest checkpoint still reaches but the roots do not.
    deferred: BTreeSet<Hash>,
    /// Gone pages the host must still be told to drop, oldest first.
    releases: VecDeque<Hash>,
}

impl PageCache {
    pub(super) fn new(capacity: u64, checkpoints: u32) -> Self {
        Self {
            entries: BTreeMap::new(),
            recency: BTreeMap::new(),
            dirty: BTreeMap::new(),
            clock: 0,
            resident: 0,
            capacity,
            checkpoints,
            deferred: BTreeSet::new(),
            releases: VecDeque::new(),
        }
    }

    fn tick(&mut self) -> Result<u64, Failure> {
        self.clock = self
            .clock
            .checked_add(1)
            .ok_or_else(|| failure(FailureCode::ResourceLimit))?;
        Ok(self.clock)
    }

    fn resident_len(bytes: &[u8]) -> Result<u64, Failure> {
        u64::try_from(bytes.len()).map_err(|_| failure(FailureCode::ResourceLimit))
    }

    /// A locally produced page, referenced by one more tree position.
    pub(super) fn insert(
        &mut self,
        resources: &mut Resources,
        commitment: PageCommitment,
        bytes: Vec<u8>,
    ) -> Result<(), Failure> {
        if let Some(entry) = self.entries.get_mut(&commitment.digest) {
            // A superseded page never comes back: the trees only grow.
            if entry.commitment != commitment || entry.state == State::Gone {
                return Err(invalid());
            }
            entry.refs = entry
                .refs
                .checked_add(1)
                .ok_or_else(|| failure(FailureCode::ResourceLimit))?;
            return Ok(());
        }
        let len = Self::resident_len(&bytes)?;
        let charge = len.checked_add(ENTRY_OVERHEAD).ok_or_else(invalid)?;
        self.make_room(resources, charge)?;
        resources.reserve(charge)?;
        let tick = self.tick()?;
        self.recency.insert(tick, commitment.digest);
        self.dirty.insert(tick, commitment.digest);
        self.resident += len;
        self.entries.insert(
            commitment.digest,
            Entry {
                commitment,
                bytes: Some(bytes),
                refs: 1,
                born: self.checkpoints,
                state: State::Dirty(tick),
                tick,
            },
        );
        Ok(())
    }

    /// A page the host supplied and the caller authenticated against its
    /// commitment. It enters (or refills) the cache as a clean page.
    pub(super) fn fill(
        &mut self,
        resources: &mut Resources,
        commitment: PageCommitment,
        bytes: &[u8],
    ) -> Result<(), Failure> {
        let len = Self::resident_len(bytes)?;
        let known = match self.entries.get(&commitment.digest) {
            Some(entry) if entry.commitment != commitment || entry.state == State::Gone => {
                return Err(invalid());
            }
            Some(entry) if entry.bytes.is_some() => return Ok(()),
            Some(_) => true,
            None => false,
        };
        let charge = if known {
            len
        } else {
            len.checked_add(ENTRY_OVERHEAD).ok_or_else(invalid)?
        };
        // Charge before allocating, and give the charge back if allocation fails.
        self.make_room(resources, charge)?;
        resources.reserve(charge)?;
        let mut owned = Vec::new();
        if owned.try_reserve_exact(bytes.len()).is_err() {
            resources.release(charge)?;
            return Err(failure(FailureCode::ResourceLimit));
        }
        owned.extend_from_slice(bytes);
        let tick = self.tick()?;
        self.recency.insert(tick, commitment.digest);
        self.resident += len;
        if let Some(entry) = self.entries.get_mut(&commitment.digest) {
            entry.bytes = Some(owned);
            entry.tick = tick;
            return Ok(());
        }
        self.entries.insert(
            commitment.digest,
            Entry {
                commitment,
                bytes: Some(owned),
                refs: 0,
                // Supplied pages predate this run's newest checkpoint.
                born: 0,
                state: State::Held,
                tick,
            },
        );
        Ok(())
    }

    /// Drops clean pages, least recently used first, until `need` more bytes
    /// fit under the resident ceiling. The cache therefore shrinks before it
    /// ever starves the rest of the run; dirty pages stay, since handing one to
    /// the host frees nothing until the host acknowledges it.
    fn make_room(&mut self, resources: &mut Resources, need: u64) -> Result<(), Failure> {
        while resources.available() < need {
            let victim = self
                .recency
                .iter()
                .find(|(_, digest)| {
                    self.entries
                        .get(*digest)
                        .is_some_and(|entry| entry.state == State::Held)
                })
                .map(|(tick, digest)| (*tick, *digest));
            let Some((tick, digest)) = victim else {
                break;
            };
            self.recency.remove(&tick);
            let entry = self.entries.get_mut(&digest).ok_or_else(invalid)?;
            let bytes = entry.bytes.take().ok_or_else(invalid)?;
            let len = Self::resident_len(&bytes)?;
            self.resident -= len;
            resources.release(len)?;
        }
        Ok(())
    }

    /// Counts one more tree position for a page found by a full-tree walk.
    pub(super) fn reference(&mut self, commitment: PageCommitment) -> Result<(), Failure> {
        let entry = self
            .entries
            .get_mut(&commitment.digest)
            .filter(|entry| entry.commitment == commitment && entry.state != State::Gone)
            .ok_or_else(invalid)?;
        entry.refs = entry
            .refs
            .checked_add(1)
            .ok_or_else(|| failure(FailureCode::ResourceLimit))?;
        Ok(())
    }

    /// Lends the resident bytes of a page; pair with [`Self::restore`].
    pub(super) fn take(&mut self, commitment: PageCommitment) -> Option<Vec<u8>> {
        self.entries
            .get_mut(&commitment.digest)
            .filter(|entry| entry.commitment == commitment)
            .and_then(|entry| entry.bytes.take())
    }

    /// Returns bytes lent by [`Self::take`] and marks the page recently used.
    pub(super) fn restore(&mut self, commitment: PageCommitment, bytes: Vec<u8>) {
        let Ok(tick) = self.tick() else {
            return;
        };
        if let Some(entry) = self.entries.get_mut(&commitment.digest) {
            self.recency.remove(&entry.tick);
            entry.tick = tick;
            entry.bytes = Some(bytes);
            self.recency.insert(tick, commitment.digest);
        }
    }

    /// Evicts least recently used pages until the resident bytes fit. A dirty
    /// victim is queued for the host, which must retain it before any later
    /// lookup could need it.
    pub(super) fn evict(
        &mut self,
        resources: &mut Resources,
        out: &mut VecDeque<Retained>,
    ) -> Result<(), Failure> {
        while self.resident > self.capacity {
            let Some((&tick, &digest)) = self.recency.iter().next() else {
                break;
            };
            self.recency.remove(&tick);
            let entry = self.entries.get_mut(&digest).ok_or_else(invalid)?;
            let bytes = entry.bytes.take().ok_or_else(invalid)?;
            let len = Self::resident_len(&bytes)?;
            self.resident -= len;
            match entry.state {
                State::Held | State::Gone => resources.release(len)?,
                State::Dirty(order) => {
                    resources.evidence(len)?;
                    entry.state = State::Held;
                    self.dirty.remove(&order);
                    // The page's byte charge moves to the retention queue.
                    out.push_back(Retained {
                        commitment: entry.commitment,
                        bytes,
                    });
                }
            }
        }
        Ok(())
    }

    /// Hands out the oldest dirty page, keeping a clean copy cached.
    pub(super) fn take_dirty(
        &mut self,
        resources: &mut Resources,
    ) -> Result<Option<Retained>, Failure> {
        let Some((&order, &digest)) = self.dirty.iter().next() else {
            return Ok(None);
        };
        let len = {
            let entry = self.entries.get(&digest).ok_or_else(invalid)?;
            Self::resident_len(entry.bytes.as_ref().ok_or_else(invalid)?)?
        };
        // Charge the copy before allocating it.
        self.make_room(resources, len)?;
        resources.evidence(len)?;
        resources.reserve(len)?;
        let entry = self.entries.get_mut(&digest).ok_or_else(invalid)?;
        let bytes = entry.bytes.as_ref().ok_or_else(invalid)?;
        let mut copy = Vec::new();
        if copy.try_reserve_exact(bytes.len()).is_err() {
            resources.release(len)?;
            resources.release_evidence(len)?;
            return Err(failure(FailureCode::ResourceLimit));
        }
        copy.extend_from_slice(bytes);
        entry.state = State::Held;
        self.dirty.remove(&order);
        Ok(Some(Retained {
            commitment: entry.commitment,
            bytes: copy,
        }))
    }

    /// A committed tree no longer references this page from one position.
    pub(super) fn supersede(
        &mut self,
        resources: &mut Resources,
        commitment: PageCommitment,
    ) -> Result<(), Failure> {
        let entry = self
            .entries
            .get_mut(&commitment.digest)
            .filter(|entry| entry.commitment == commitment && entry.state != State::Gone)
            .ok_or_else(invalid)?;
        entry.refs = entry.refs.saturating_sub(1);
        if entry.refs > 0 {
            return Ok(());
        }
        let bytes = entry.bytes.take();
        let tick = entry.tick;
        let born = entry.born;
        let state = entry.state;
        if let Some(bytes) = &bytes {
            let len = Self::resident_len(bytes)?;
            self.resident -= len;
            resources.release(len)?;
            self.recency.remove(&tick);
        }
        match state {
            State::Dirty(order) => {
                // The host never saw it: forget it entirely.
                self.dirty.remove(&order);
                self.entries.remove(&commitment.digest);
                resources.release(ENTRY_OVERHEAD)?;
            }
            State::Held if born >= self.checkpoints => {
                // No checkpoint reaches a page created after the last one.
                self.entry_gone(&commitment.digest)?;
                self.queue_release(resources, commitment)?;
            }
            State::Held => {
                self.entry_gone(&commitment.digest)?;
                self.deferred.insert(commitment.digest);
            }
            State::Gone => return Err(invalid()),
        }
        Ok(())
    }

    fn entry_gone(&mut self, digest: &Hash) -> Result<(), Failure> {
        self.entries.get_mut(digest).ok_or_else(invalid)?.state = State::Gone;
        Ok(())
    }

    /// Uncounts a page the host is about to be told to drop.
    fn queue_release(
        &mut self,
        resources: &mut Resources,
        commitment: PageCommitment,
    ) -> Result<(), Failure> {
        resources.release_evidence(commitment.len)?;
        self.releases.push_back(commitment.digest);
        Ok(())
    }

    /// Pages the next checkpoint releases, for its usage snapshot.
    pub(super) fn releasable(&self) -> Releasable {
        Releasable {
            pages: self.deferred.len() as u64,
            bytes: self
                .deferred
                .iter()
                .filter_map(|digest| self.entries.get(digest))
                .map(|entry| entry.commitment.len)
                .sum(),
        }
    }

    /// A checkpoint now exists: the previous one is obsolete, so the pages only
    /// it reached can go. The host sees the releases on its next step, after it
    /// persisted the new checkpoint.
    pub(super) fn commit_checkpoint(&mut self, resources: &mut Resources) -> Result<(), Failure> {
        self.checkpoints = self
            .checkpoints
            .checked_add(1)
            .ok_or_else(|| failure(FailureCode::ResourceLimit))?;
        for digest in std::mem::take(&mut self.deferred) {
            let commitment = self.entries.get(&digest).ok_or_else(invalid)?.commitment;
            self.queue_release(resources, commitment)?;
        }
        Ok(())
    }

    /// Next page the host has not been told to drop.
    pub(super) fn pop_release(
        &mut self,
        resources: &mut Resources,
    ) -> Result<Option<PageCommitment>, Failure> {
        let Some(digest) = self.releases.pop_front() else {
            return Ok(None);
        };
        let entry = self.entries.remove(&digest).ok_or_else(invalid)?;
        resources.release(ENTRY_OVERHEAD)?;
        Ok(Some(entry.commitment))
    }

    /// Drops every cached page after completion. Pages already queued for the
    /// host keep their entries until delivered; the run owns nothing else.
    pub(super) fn clear(&mut self, resources: &mut Resources) -> Result<(), Failure> {
        let queued: BTreeSet<Hash> = self.releases.iter().copied().collect();
        for (digest, entry) in std::mem::take(&mut self.entries) {
            if queued.contains(&digest) {
                self.entries.insert(digest, entry);
                continue;
            }
            resources.release(ENTRY_OVERHEAD)?;
            if let Some(bytes) = &entry.bytes {
                resources.release(Self::resident_len(bytes)?)?;
            }
        }
        self.recency.clear();
        self.dirty.clear();
        self.deferred.clear();
        self.resident = 0;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{evidence::PageKind, limits::VerifyLimits};

    fn page(tag: u8, len: u64) -> PageCommitment {
        PageCommitment {
            digest: [tag; 32],
            kind: PageKind::Objects,
            len,
            items: 1,
        }
    }

    fn bytes(commitment: PageCommitment) -> Vec<u8> {
        vec![commitment.digest[0]; usize::try_from(commitment.len).unwrap()]
    }

    fn resources() -> Resources {
        Resources::new(VerifyLimits::indexed()).unwrap()
    }

    fn insert(cache: &mut PageCache, res: &mut Resources, commitment: PageCommitment) {
        cache.insert(res, commitment, bytes(commitment)).unwrap();
    }

    fn drain(cache: &mut PageCache, res: &mut Resources) -> Vec<PageCommitment> {
        std::iter::from_fn(|| cache.pop_release(res).unwrap()).collect()
    }

    #[test]
    fn a_page_superseded_before_the_host_saw_it_is_dropped_unseen() {
        let (mut cache, mut res) = (PageCache::new(1 << 20, 0), resources());
        let a = page(1, 100);
        insert(&mut cache, &mut res, a);
        cache.supersede(&mut res, a).unwrap();
        assert!(drain(&mut cache, &mut res).is_empty());
        assert_eq!(res.usage().evidence_pages, 0);
        assert_eq!(res.usage().resident_bytes, 0);
        assert!(cache.take_dirty(&mut res).unwrap().is_none());
    }

    #[test]
    fn a_held_page_born_after_the_last_checkpoint_is_released_at_once() {
        let (mut cache, mut res) = (PageCache::new(1 << 20, 0), resources());
        let a = page(1, 100);
        insert(&mut cache, &mut res, a);
        let handed = cache.take_dirty(&mut res).unwrap().unwrap();
        assert_eq!(handed.commitment, a);
        assert_eq!(res.usage().evidence_pages, 1);
        cache.supersede(&mut res, a).unwrap();
        assert_eq!(drain(&mut cache, &mut res), vec![a]);
        assert_eq!(res.usage().evidence_pages, 0);
        assert_eq!(res.usage().evidence_bytes, 0);
    }

    #[test]
    fn a_page_the_latest_checkpoint_reaches_is_released_by_the_next_one() {
        let (mut cache, mut res) = (PageCache::new(1 << 20, 0), resources());
        let (a, b) = (page(1, 100), page(2, 200));
        insert(&mut cache, &mut res, a);
        insert(&mut cache, &mut res, b);
        while cache.take_dirty(&mut res).unwrap().is_some() {}
        // The first checkpoint exists and reaches both pages.
        assert_eq!(cache.releasable(), Releasable::default());
        cache.commit_checkpoint(&mut res).unwrap();
        cache.supersede(&mut res, a).unwrap();
        assert!(
            drain(&mut cache, &mut res).is_empty(),
            "checkpoint 1 still reaches a"
        );
        assert_eq!(
            cache.releasable(),
            Releasable {
                pages: 1,
                bytes: 100
            }
        );
        // A page created after the checkpoint dies at once.
        let c = page(3, 50);
        insert(&mut cache, &mut res, c);
        cache.take_dirty(&mut res).unwrap().unwrap();
        cache.supersede(&mut res, c).unwrap();
        assert_eq!(drain(&mut cache, &mut res), vec![c]);
        // The second checkpoint obsoletes the first and frees a.
        cache.commit_checkpoint(&mut res).unwrap();
        assert_eq!(drain(&mut cache, &mut res), vec![a]);
        assert_eq!(res.usage().evidence_pages, 1);
        assert_eq!(res.usage().evidence_bytes, 200);
    }

    #[test]
    fn a_digest_shared_by_two_positions_lives_until_both_let_go() {
        let (mut cache, mut res) = (PageCache::new(1 << 20, 0), resources());
        let a = page(1, 100);
        insert(&mut cache, &mut res, a);
        insert(&mut cache, &mut res, a);
        cache.take_dirty(&mut res).unwrap().unwrap();
        cache.supersede(&mut res, a).unwrap();
        assert!(drain(&mut cache, &mut res).is_empty());
        cache.supersede(&mut res, a).unwrap();
        assert_eq!(drain(&mut cache, &mut res), vec![a]);
    }

    #[test]
    fn eviction_drops_clean_pages_and_queues_dirty_ones_oldest_first() {
        let (mut cache, mut res) = (PageCache::new(250, 0), resources());
        let (a, b, c) = (page(1, 100), page(2, 100), page(3, 100));
        insert(&mut cache, &mut res, a);
        insert(&mut cache, &mut res, b);
        // Touch a so b is the older of the two.
        let lent = cache.take(a).unwrap();
        cache.restore(a, lent);
        insert(&mut cache, &mut res, c);
        let mut queue = VecDeque::new();
        cache.evict(&mut res, &mut queue).unwrap();
        let handed: Vec<_> = queue.iter().map(|page| page.commitment).collect();
        assert_eq!(handed, vec![b]);
        assert!(cache.take(b).is_none(), "b left the cache");
        assert_eq!(res.usage().evidence_pages, 1);
        // The evicted dirty page is now Held, so a later refill is clean.
        cache.fill(&mut res, b, &bytes(b)).unwrap();
        assert!(cache.take(b).is_some());
    }

    #[test]
    fn a_clean_page_evicts_without_a_host_round_trip() {
        let (mut cache, mut res) = (PageCache::new(150, 0), resources());
        let (a, b) = (page(1, 100), page(2, 100));
        insert(&mut cache, &mut res, a);
        cache.take_dirty(&mut res).unwrap().unwrap();
        insert(&mut cache, &mut res, b);
        let mut queue = VecDeque::new();
        cache.evict(&mut res, &mut queue).unwrap();
        assert!(queue.is_empty(), "a was already held and drops silently");
        assert!(cache.take(a).is_none());
        assert!(cache.take(b).is_some());
    }

    #[test]
    fn clearing_returns_every_charge_and_keeps_queued_releases() {
        let (mut cache, mut res) = (PageCache::new(1 << 20, 0), resources());
        let baseline = res.usage().resident_bytes;
        for tag in 1..=5 {
            insert(&mut cache, &mut res, page(tag, 100));
        }
        // One page is handed out, then superseded: its release is queued.
        let handed = cache.take_dirty(&mut res).unwrap().unwrap();
        res.release(handed.bytes.len() as u64).unwrap();
        cache.supersede(&mut res, handed.commitment).unwrap();
        cache.clear(&mut res).unwrap();
        assert_eq!(res.usage().resident_bytes, baseline + ENTRY_OVERHEAD);
        assert_eq!(drain(&mut cache, &mut res), vec![handed.commitment]);
        assert_eq!(res.usage().resident_bytes, baseline);
    }

    #[test]
    fn bookkeeping_stays_charged_until_the_host_is_told() {
        let (mut cache, mut res) = (PageCache::new(1 << 20, 0), resources());
        let baseline = res.usage().resident_bytes;
        let a = page(1, 100);
        insert(&mut cache, &mut res, a);
        let handed = cache.take_dirty(&mut res).unwrap().unwrap();
        res.release(handed.bytes.len() as u64).unwrap();
        cache.supersede(&mut res, a).unwrap();
        assert_eq!(res.usage().resident_bytes, baseline + ENTRY_OVERHEAD);
        assert_eq!(res.usage().evidence_pages, 0, "uncounted when queued");
        assert_eq!(drain(&mut cache, &mut res), vec![a]);
        assert_eq!(res.usage().resident_bytes, baseline);
    }

    #[test]
    fn a_superseded_page_never_returns() {
        let (mut cache, mut res) = (PageCache::new(1 << 20, 0), resources());
        let a = page(1, 100);
        insert(&mut cache, &mut res, a);
        cache.take_dirty(&mut res).unwrap().unwrap();
        cache.commit_checkpoint(&mut res).unwrap();
        cache.supersede(&mut res, a).unwrap();
        // Deferred behind the checkpoint, still gone to the trees.
        assert!(cache.insert(&mut res, a, bytes(a)).is_err());
        assert!(cache.fill(&mut res, a, &bytes(a)).is_err());
        assert!(cache.reference(a).is_err());
        assert!(cache.supersede(&mut res, a).is_err());
        assert!(cache.take(a).is_none());
    }

    #[test]
    fn a_short_budget_drops_clean_pages_before_refusing_a_new_one() {
        let mut res = Resources::new(VerifyLimits {
            resident_bytes: 4 << 20,
            ..VerifyLimits::indexed()
        })
        .unwrap();
        let mut cache = PageCache::new(1 << 20, 0);
        let (a, b) = (page(1, 100), page(2, 100));
        insert(&mut cache, &mut res, a);
        let handed = cache.take_dirty(&mut res).unwrap().unwrap();
        res.release(handed.bytes.len() as u64).unwrap();
        // Short by 50 bytes for the next page until the clean one goes.
        let spare = 100 + ENTRY_OVERHEAD - 50;
        res.reserve(res.available() - spare).unwrap();
        insert(&mut cache, &mut res, b);
        assert!(cache.take(a).is_none(), "the clean page made room");
        assert!(cache.take(b).is_some());
        // Dirty pages are never dropped to make room: the next one is refused.
        let c = page(3, 100);
        assert_eq!(
            cache.insert(&mut res, c, bytes(c)).unwrap_err().code,
            FailureCode::ResourceLimit
        );
    }

    #[test]
    fn a_mismatched_commitment_is_never_served() {
        let (mut cache, mut res) = (PageCache::new(1 << 20, 0), resources());
        let a = page(1, 100);
        insert(&mut cache, &mut res, a);
        let mut other = a;
        other.len = 101;
        assert!(cache.take(other).is_none());
        assert!(cache.supersede(&mut res, other).is_err());
        assert!(cache.insert(&mut res, other, bytes(other)).is_err());
    }
}
