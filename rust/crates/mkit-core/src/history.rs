//! In-memory Merkle Mountain Range for canonical first-parent ancestry.
//! Durable snapshots and their trusted context live in [`AncestrySnapshot`].
use crate::hash::{HASH_LEN, Hash};
use commonware_cryptography::{Blake3, Hasher as CHasher};
use commonware_storage::merkle::Bagging;
use commonware_storage::merkle::mmr::{
    Location as MmrLocation, Proof as MmrProof, StandardHasher, mem::Mmr as MemMmr,
};
pub(crate) mod ancestry;
pub use ancestry::{
    AncestryDescriptor, AncestrySnapshot, TrustedAncestryDescriptor, verify_ancestry,
};

// A cryptographic format parameter shared by producers and verifiers.
const HISTORY_BAGGING: Bagging = Bagging::ForwardFold;
fn history_hasher() -> StandardHasher<Blake3> {
    StandardHasher::new(HISTORY_BAGGING)
}

/// Zero-based leaf index within one ancestry generation.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Position(pub u64);
impl Position {
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}
/// Inclusion proof with the wire shape specified by SPEC-HISTORY-PROOF.
pub type InclusionProof = MmrProof<<Blake3 as CHasher>::Digest>;

#[derive(Debug, thiserror::Error)]
pub enum HistoryError {
    #[error("history ref: {0}")]
    Ref(#[from] crate::refs::RefError),
    #[error("history object: {0}")]
    Store(#[from] crate::store::StoreError),
    #[error("mmr error: {0}")]
    Mmr(String),
    #[error("invalid branch name for ancestry: {0:?}")]
    InvalidBranch(String),
    #[error("history snapshot is corrupt: {0}")]
    Corrupted(String),
    #[error("history directory I/O: {0}")]
    Io(#[from] std::io::Error),
}

/// In-memory accumulator over a verified first-parent chain.
pub struct CommitHistory {
    mmr: MemMmr<<Blake3 as CHasher>::Digest>,
    hasher: StandardHasher<Blake3>,
}
impl std::fmt::Debug for CommitHistory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommitHistory")
            .field("leaves", &self.len())
            .finish_non_exhaustive()
    }
}
impl Default for CommitHistory {
    fn default() -> Self {
        Self::open()
    }
}
impl CommitHistory {
    #[must_use]
    pub fn open() -> Self {
        Self {
            mmr: MemMmr::new(),
            hasher: history_hasher(),
        }
    }
    /// Append one hash and return its leaf position.
    pub fn append(&mut self, commit_hash: &Hash) -> Result<Position, HistoryError> {
        let leaf = digest_from_hash(commit_hash);
        let leaf_loc = self.mmr.leaves();
        let batch = self
            .mmr
            .new_batch()
            .add(&self.hasher, &leaf)
            .merkleize(&self.mmr, &self.hasher);
        self.mmr
            .apply_batch(&batch)
            .map_err(|e| HistoryError::Mmr(e.to_string()))?;
        Ok(Position(u64::from(leaf_loc)))
    }
    /// Return the root over every current leaf.
    ///
    /// # Panics
    /// Panics only if commonware rejects zero inactive peaks, which its contract permits.
    #[must_use]
    pub fn root(&self) -> Hash {
        let digest = self
            .mmr
            .root(&self.hasher, 0)
            .expect("zero inactive peaks is valid");
        let mut out = [0; HASH_LEN];
        out.copy_from_slice(digest.as_ref());
        out
    }
    #[must_use]
    pub fn len(&self) -> u64 {
        u64::from(self.mmr.leaves())
    }
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn prove(&self, position: Position) -> Result<InclusionProof, HistoryError> {
        self.mmr
            .proof(&self.hasher, MmrLocation::new(position.0), 0)
            .map_err(|e| HistoryError::Mmr(e.to_string()))
    }
}
/// Verify raw MMR inclusion. Use [`verify_ancestry`] for branch-context trust.
#[must_use]
pub fn verify_inclusion(
    commit_hash: &Hash,
    position: Position,
    proof: &InclusionProof,
    root: &Hash,
) -> bool {
    let leaf = digest_from_hash(commit_hash);
    let root_digest = digest_from_hash(root);
    let loc = MmrLocation::new(position.0);

    // Same bagging policy as the producer — see [`HISTORY_BAGGING`].
    let hasher = history_hasher();
    proof.verify_element_inclusion(&hasher, leaf.as_ref(), loc, &root_digest)
}

fn digest_from_hash(h: &Hash) -> <Blake3 as CHasher>::Digest {
    <<Blake3 as CHasher>::Digest as From<[u8; HASH_LEN]>>::from(*h)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn synth(i: u64) -> Hash {
        crate::hash::hash(&i.to_be_bytes())
    }
    #[test]
    fn mem_empty_history_root_is_well_defined() {
        let h1 = CommitHistory::open();
        let h2 = CommitHistory::open();
        assert_eq!(h1.root(), h2.root(), "empty root must be deterministic");
        assert!(h1.is_empty());
        assert_eq!(h1.len(), 0);
    }

    #[test]
    fn mem_append_returns_dense_positions() {
        let mut h = CommitHistory::open();
        for i in 0..16u64 {
            let pos = h.append(&synth(i)).unwrap();
            assert_eq!(pos, Position(i), "positions must be dense and 0-based");
        }
        assert_eq!(h.len(), 16);
    }

    #[test]
    fn mem_prove_and_verify_position_712_of_1000() {
        let mut h = CommitHistory::open();
        let commits: Vec<Hash> = (0..1000u64).map(synth).collect();
        for c in &commits {
            h.append(c).unwrap();
        }
        assert_eq!(h.len(), 1000);

        let target = Position(712);
        let proof = h.prove(target).unwrap();
        let root = h.root();

        assert!(
            verify_inclusion(&commits[712], target, &proof, &root),
            "honest proof must verify"
        );
    }

    #[test]
    fn mem_tampered_proof_fails_verification() {
        let mut h = CommitHistory::open();
        for i in 0..256u64 {
            h.append(&synth(i)).unwrap();
        }
        let target = Position(42);
        let mut proof = h.prove(target).unwrap();
        let root = h.root();
        let commit = synth(42);

        assert!(verify_inclusion(&commit, target, &proof, &root));

        assert!(
            !proof.digests.is_empty(),
            "non-trivial proof must carry at least one sibling"
        );
        let mut bytes: [u8; HASH_LEN] = [0u8; HASH_LEN];
        bytes.copy_from_slice(proof.digests[0].as_ref());
        bytes[0] ^= 0x01;
        proof.digests[0] = <<Blake3 as CHasher>::Digest as From<[u8; HASH_LEN]>>::from(bytes);

        assert!(
            !verify_inclusion(&commit, target, &proof, &root),
            "tampered proof must fail"
        );
    }

    /// SPEC-HISTORY-PROOF §3 enumerates six failure modes
    /// `verify_inclusion` MUST reject without panicking. Three are
    /// already covered above (tampered digest, wrong commit, wrong
    /// root); the remaining three — wrong position, mismatched leaf
    /// count, and a truncated/over-long `digests` vector — were only
    /// exercised indirectly, by trusting commonware's own test suite at
    /// the pinned version. Pin them directly here.
    #[test]
    fn verify_inclusion_rejects_wrong_position() {
        let mut h = CommitHistory::open();
        let commits: Vec<Hash> = (0..64u64).map(synth).collect();
        for c in &commits {
            h.append(c).unwrap();
        }
        let target = Position(42);
        let proof = h.prove(target).unwrap();
        let root = h.root();

        assert!(verify_inclusion(&commits[42], target, &proof, &root));
        // Same commit_hash, proof, and root — only the claimed position
        // differs. The proof was built for position 42; claiming it
        // proves position 41 (or any other) instead must fail.
        assert!(!verify_inclusion(&commits[42], Position(41), &proof, &root));
        assert!(!verify_inclusion(&commits[42], Position(0), &proof, &root));
    }

    #[test]
    fn verify_inclusion_rejects_mismatched_leaf_count() {
        let mut h = CommitHistory::open();
        let commits: Vec<Hash> = (0..64u64).map(synth).collect();
        for c in &commits {
            h.append(c).unwrap();
        }
        let target = Position(42);
        let mut proof = h.prove(target).unwrap();
        let root = h.root();
        assert!(verify_inclusion(&commits[42], target, &proof, &root));

        // `proof.leaves` claims how many leaves the MMR had when the
        // proof was built. Disagreeing with the actual count (64) must
        // fail — this is the prover asserting a different-length
        // history than the root it's paired with actually commits to.
        proof.leaves = MmrLocation::new(63);
        assert!(!verify_inclusion(&commits[42], target, &proof, &root));
    }

    #[test]
    fn verify_inclusion_rejects_truncated_or_over_long_digests() {
        let mut h = CommitHistory::open();
        let commits: Vec<Hash> = (0..64u64).map(synth).collect();
        for c in &commits {
            h.append(c).unwrap();
        }
        let target = Position(42);
        let proof = h.prove(target).unwrap();
        let root = h.root();
        assert!(verify_inclusion(&commits[42], target, &proof, &root));
        assert!(
            !proof.digests.is_empty(),
            "non-trivial proof must carry at least one digest"
        );

        // Truncated: drop the last digest the fold-consumer expects.
        let mut truncated = proof.clone();
        truncated.digests.pop();
        assert!(!verify_inclusion(&commits[42], target, &truncated, &root));

        // Over-long: append a bogus extra digest past what the
        // consumer-pointer walk expects to find.
        let mut over_long = proof;
        over_long.digests.push(over_long.digests[0]);
        assert!(!verify_inclusion(&commits[42], target, &over_long, &root));
    }
}
