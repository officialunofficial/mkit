//! Append-only commit-history Merkle Mountain Range (MMR).
//!
//! Phase 1 of issue #157. Light-client inclusion proofs for the commit
//! chain: a verifier with the MMR root for a branch tip can check
//! "commit X was leaf N on this branch" with `O(log n)` hash work,
//! without downloading the parent chain or any pack.
//!
//! # Status
//!
//! This module is **Phase 1**: the MMR is `mem`-backed (in-memory only,
//! lost on process exit). The persisted (journaled-on-disk) variant
//! lands in Phase 2; integration with `object::Commit` lands in
//! Phase 3. See `docs/SPEC-HISTORY-PROOF.md` for the normative wire
//! format and the rollout plan.
//!
//! Underlying primitive: [`commonware_storage::merkle::mmr::mem::Mmr`]
//! pinned to `2026.4.0` (ALPHA stability). The wire format of
//! [`InclusionProof`] is a thin re-export of `commonware-storage`'s
//! native [`Proof`] type — see SPEC-HISTORY-PROOF §2.
//!
//! # Hashing
//!
//! Internally the MMR is parameterised over `Blake3` (from
//! `commonware-cryptography`) so node digests are 32-byte BLAKE3
//! values — same primitive mkit already uses elsewhere
//! (`hash::Hash`). This is **not** the same hashing schedule as
//! `hash::hash()`: the MMR injects node-position bytes into each
//! parent/leaf digest (see commonware's `Hasher` trait). The two
//! schedules are deliberately separate; the MMR's domain-separation
//! is what makes inclusion proofs meaningful.

use commonware_cryptography::{Blake3, Hasher as CHasher};
use commonware_storage::merkle::mmr::{
    Location as MmrLocation, Proof as MmrProof, StandardHasher, mem::Mmr as MemMmr,
};

use crate::hash::{HASH_LEN, Hash};

/// 0-based index of a commit within its branch's MMR.
///
/// In commonware's vocabulary this is a `Location` — the leaf index in
/// insertion order, not the MMR's internal node position. The first
/// commit appended is `Position(0)`, the second is `Position(1)`, etc.
/// Stable for the lifetime of the branch: positions never shift
/// because the MMR is append-only.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Position(pub u64);

impl Position {
    /// Raw `u64`.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

/// Inclusion proof — re-export of commonware's MMR proof type bound to
/// our BLAKE3 digest. Wire shape is normatively defined in
/// `SPEC-HISTORY-PROOF.md` §2.
pub type InclusionProof = MmrProof<<Blake3 as CHasher>::Digest>;

/// Errors returned by [`CommitHistory`] and [`verify_inclusion`].
#[derive(Debug, thiserror::Error)]
pub enum HistoryError {
    /// The underlying MMR rejected the operation (out-of-bounds proof,
    /// invalid size, etc.). The wrapped string is commonware's own
    /// `Display` impl — stable enough for logs, not parsed.
    #[error("mmr error: {0}")]
    Mmr(String),
}

/// Append-only Merkle history of commit hashes for one branch.
///
/// Phase 1: `mem`-backed. Persistence and `open(mkit_dir, branch)` land
/// in Phase 2 — see SPEC-HISTORY-PROOF §4.
pub struct CommitHistory {
    mmr: MemMmr<<Blake3 as CHasher>::Digest>,
    hasher: StandardHasher<Blake3>,
}

impl core::fmt::Debug for CommitHistory {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CommitHistory")
            .field("leaves", &u64::from(self.mmr.leaves()))
            .field("size", &u64::from(self.mmr.size()))
            .finish_non_exhaustive()
    }
}

impl CommitHistory {
    /// Open a fresh empty history.
    ///
    /// Phase 1 stub: the MMR is in-memory only, so there is no path /
    /// branch to wire up yet. Phase 2 will introduce a path-bound
    /// `open(mkit_dir, branch)` against the on-disk journal.
    #[must_use]
    pub fn open() -> Self {
        let hasher: StandardHasher<Blake3> = StandardHasher::new();
        let mmr = MemMmr::new(&hasher);
        Self { mmr, hasher }
    }

    /// Append a commit hash. Returns its leaf [`Position`].
    ///
    /// Positions are dense: the *n*-th append returns `Position(n)`.
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

    /// Current MMR root digest. 32-byte BLAKE3 (mkit `Hash` shape).
    ///
    /// Defined for an empty history — commonware returns
    /// `Blake3(leaf_count = 0_u64_be)` in that case, which is
    /// deterministic and well-defined. See SPEC-HISTORY-PROOF §2.
    #[must_use]
    pub fn root(&self) -> Hash {
        let d = self.mmr.root();
        let mut out = [0u8; HASH_LEN];
        out.copy_from_slice(d.as_ref());
        out
    }

    /// Number of leaves (commits) appended so far.
    #[must_use]
    pub fn len(&self) -> u64 {
        u64::from(self.mmr.leaves())
    }

    /// `true` if no commits have been appended.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Build an inclusion proof for the commit at `position`.
    pub fn prove(&self, position: Position) -> Result<InclusionProof, HistoryError> {
        let loc = MmrLocation::new(position.0);
        self.mmr
            .proof(&self.hasher, loc)
            .map_err(|e| HistoryError::Mmr(e.to_string()))
    }
}

impl Default for CommitHistory {
    fn default() -> Self {
        Self::open()
    }
}

/// Verify that `commit_hash` was appended at `position` to a history
/// whose current root is `root`. Returns `true` on a passing proof,
/// `false` on any tamper / wrong-position / wrong-root case.
///
/// Pure function: no allocation beyond what commonware's verifier does
/// internally; safe to call from a light-client without any of the
/// preceding chain bytes.
#[must_use]
pub fn verify_inclusion(
    commit_hash: &Hash,
    position: Position,
    proof: &InclusionProof,
    root: &Hash,
) -> bool {
    // Reconstruct the typed digests commonware expects. Reject any
    // hash whose byte layout doesn't fit the BLAKE3 digest size — in
    // practice impossible (`Hash` is `[u8; 32]`) but the cast is
    // checked anyway.
    let leaf = digest_from_hash(commit_hash);
    let root_digest = digest_from_hash(root);
    let loc = MmrLocation::new(position.0);

    let hasher: StandardHasher<Blake3> = StandardHasher::new();
    proof.verify_element_inclusion(&hasher, leaf.as_ref(), loc, &root_digest)
}

/// Convert an mkit `Hash` (`[u8; 32]`) into commonware's `Blake3::Digest`.
///
/// Both are 32 bytes of BLAKE3 output, so this is a typed re-wrap with
/// zero copy beyond the `[u8; 32]` move.
fn digest_from_hash(h: &Hash) -> <Blake3 as CHasher>::Digest {
    <<Blake3 as CHasher>::Digest as From<[u8; HASH_LEN]>>::from(*h)
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic distinct commit hash generator.
    fn synth(i: u64) -> Hash {
        crate::hash::hash(&i.to_be_bytes())
    }

    #[test]
    fn empty_history_root_is_well_defined() {
        let h1 = CommitHistory::open();
        let h2 = CommitHistory::open();
        assert_eq!(h1.root(), h2.root(), "empty root must be deterministic");
        assert!(h1.is_empty());
        assert_eq!(h1.len(), 0);
    }

    #[test]
    fn append_returns_dense_positions() {
        let mut h = CommitHistory::open();
        for i in 0..16u64 {
            let pos = h.append(&synth(i)).unwrap();
            assert_eq!(pos, Position(i), "positions must be dense and 0-based");
        }
        assert_eq!(h.len(), 16);
    }

    #[test]
    fn root_changes_on_append() {
        let mut h = CommitHistory::open();
        let r0 = h.root();
        h.append(&synth(0)).unwrap();
        let r1 = h.root();
        assert_ne!(r0, r1, "root must change after appending a leaf");
    }

    /// Issue #157 acceptance: 1000 commits, prove a random one, verify.
    #[test]
    fn prove_and_verify_position_712_of_1000() {
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
    fn tampered_proof_fails_verification() {
        let mut h = CommitHistory::open();
        for i in 0..256u64 {
            h.append(&synth(i)).unwrap();
        }
        let target = Position(42);
        let mut proof = h.prove(target).unwrap();
        let root = h.root();
        let commit = synth(42);

        // Sanity: untampered passes.
        assert!(verify_inclusion(&commit, target, &proof, &root));

        // Flip one bit in the first sibling digest. This is the
        // canonical "tampered proof" case from issue #157.
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

    #[test]
    fn wrong_commit_fails_verification() {
        let mut h = CommitHistory::open();
        for i in 0..64u64 {
            h.append(&synth(i)).unwrap();
        }
        let target = Position(7);
        let proof = h.prove(target).unwrap();
        let root = h.root();

        // Honest hash at this position would be synth(7); we offer synth(8).
        assert!(
            !verify_inclusion(&synth(8), target, &proof, &root),
            "proof must not verify against the wrong commit"
        );
    }

    #[test]
    fn wrong_root_fails_verification() {
        let mut h = CommitHistory::open();
        for i in 0..64u64 {
            h.append(&synth(i)).unwrap();
        }
        let target = Position(7);
        let proof = h.prove(target).unwrap();
        let commit = synth(7);

        // A root from a completely different history.
        let mut other = CommitHistory::open();
        for i in 100..164u64 {
            other.append(&synth(i)).unwrap();
        }
        let wrong_root = other.root();
        assert_ne!(h.root(), wrong_root);

        assert!(
            !verify_inclusion(&commit, target, &proof, &wrong_root),
            "proof must not verify against a different root"
        );
    }

    #[test]
    fn two_open_calls_return_independent_histories() {
        // Phase 1: every `open()` is a fresh in-memory MMR. Phase 2
        // will replace this with a path-bound constructor; the test
        // is intentionally written so the *result* still holds (two
        // distinct paths = two distinct histories) — the API name is
        // what changes.
        let mut a = CommitHistory::open();
        let b = CommitHistory::open();
        a.append(&synth(0)).unwrap();
        assert_ne!(a.len(), b.len());
    }
}
