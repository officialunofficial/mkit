//! Versioned snapshots over verified first-parent ancestry.

use std::collections::BTreeSet;
use std::fs;
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

/// Context bound by a v1 ancestry descriptor. The MMR digest excludes context:
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
    mmr: CommitHistory,
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
        self.mmr.prove(position)
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
        let mut mmr = CommitHistory::open();
        for h in &chain {
            mmr.append(h)?;
        }
        let descriptor = AncestryDescriptor {
            repository,
            full_ref,
            generation,
            tip: *chain.last().expect("nonempty chain"),
            leaf_count: chain.len() as u64,
            root: mmr.root(),
        };
        Ok(Self {
            descriptor,
            chain,
            mmr,
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
        fn take<'a>(input: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
            if input.len() < n {
                return None;
            }
            let (head, tail) = input.split_at(n);
            *input = tail;
            Some(head)
        }
        fn digest(input: &mut &[u8]) -> Option<Hash> {
            take(input, 32)?.try_into().ok()
        }
        let invalid = || HistoryError::Corrupted("malformed ancestry snapshot".into());
        if bytes.len() < 175 || bytes.len() as u64 > MAX_SNAPSHOT_BYTES {
            return Err(invalid());
        }
        let (payload, checksum) = bytes.split_at(bytes.len() - 32);
        if hash::hash(payload).as_slice() != checksum {
            return Err(invalid());
        }
        let mut input = payload;
        if take(&mut input, 5) != Some(MAGIC.as_slice()) {
            return Err(invalid());
        }
        let repository = digest(&mut input).ok_or_else(invalid)?;
        let generation = digest(&mut input).ok_or_else(invalid)?;
        let tip = digest(&mut input).ok_or_else(invalid)?;
        let count = u64::from_le_bytes(
            take(&mut input, 8)
                .ok_or_else(invalid)?
                .try_into()
                .map_err(|_| invalid())?,
        );
        let root = digest(&mut input).ok_or_else(invalid)?;
        let name_len = u16::from_le_bytes(
            take(&mut input, 2)
                .ok_or_else(invalid)?
                .try_into()
                .map_err(|_| invalid())?,
        ) as usize;
        let full_ref = std::str::from_utf8(take(&mut input, name_len).ok_or_else(invalid)?)
            .map_err(|_| invalid())?
            .to_owned();
        if !full_ref.starts_with("refs/heads/")
            || !refs::validate_ref_name(&full_ref)
            || count == 0
            || count > MAX_ANCESTRY_LEAVES as u64
            || input.len() as u64 != count * 32
        {
            return Err(invalid());
        }
        let chain: Vec<Hash> = input
            .chunks_exact(32)
            .map(|c| c.try_into().expect("32-byte chunk"))
            .collect();
        let snapshot = Self::build(repository, full_ref, generation, chain)?;
        if snapshot.descriptor.tip != tip || snapshot.descriptor.root != root {
            return Err(invalid());
        }
        Ok(snapshot)
    }
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

fn first_parent_chain(store: &ObjectStore, tip: Hash) -> Result<Vec<Hash>, HistoryError> {
    let mut chain = Vec::new();
    let mut seen = BTreeSet::new();
    let mut next = Some(tip);
    while let Some(h) = next {
        if chain.len() >= MAX_ANCESTRY_LEAVES || !seen.insert(h) {
            return Err(HistoryError::Corrupted(
                "ancestry cycle or traversal limit".into(),
            ));
        }
        chain.push(h);
        next = match store.read_object(&h)? {
            Object::Commit(c) => c.parents.first().copied(),
            Object::Remix(r) => r.parents.first().copied(),
            _ => {
                return Err(HistoryError::Corrupted(
                    "ancestry node is not a commit/remix".into(),
                ));
            }
        };
    }
    chain.reverse();
    Ok(chain)
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

/// Finish a durable intent under BOTH history and ref mutation guards. The
/// target is rebuilt from verified objects, not guessed from a single old leaf.
fn finish(
    layout: &RepoLayout,
    dir: &Path,
    tx: &Transaction,
    mutation: &RefMutation,
    store: &ObjectStore,
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
    let snapshot = AncestrySnapshot::build(
        tx.repository,
        tx.full_ref.clone(),
        tx.generation,
        first_parent_chain(store, tx.target)?,
    )?;
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
        finish(layout, &dir, &tx, mutation, store)?;
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
        finish(layout, &dir, &tx, mutation, store)?;
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
    let old = read_current(&dir)?;
    let chain = first_parent_chain(store, target)?;
    let compatible = old.as_ref().filter(|s| {
        s.descriptor.repository == repository
            && s.descriptor.full_ref == full_ref
            && Some(s.descriptor.tip) == previous
    });
    if let Some(old) = compatible
        && old.chain == chain
    {
        return Ok(());
    }
    let generation = match compatible {
        Some(old) if chain.starts_with(&old.chain) => old.descriptor.generation,
        _ => fresh_id()?,
    };
    let tx = Transaction {
        repository,
        full_ref,
        previous,
        target,
        generation,
        previous_generation: compatible.map(|s| s.descriptor.generation),
    };
    // Validate the target before persisting intent. Readers withhold proofs for
    // the entire intent window. GC pins previous+target from the metadata.
    let _ = AncestrySnapshot::build(repository, tx.full_ref.clone(), generation, chain)?;
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
    finish(layout, &dir, &tx, mutation, store)?;
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
}
