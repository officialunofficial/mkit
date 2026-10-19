//! Bounded, complete inventory plans. Inventories are authenticated host facts.
use super::{ForkBinding, ForkResult, invalid, resource};
use crate::error::Failure;
use mkit_core::hash::{Hash, Hasher};

/// Finite plan and decision work bounds, independent of deployment limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ForkLimits {
    /// Maximum inherited packs.
    pub packs: u32,
    /// Maximum dependency occurrences across all inventories.
    pub edges: u32,
    /// Maximum bytes in the supplied branch name.
    pub branch_bytes: u32,
    /// Maximum copied index entries.
    pub index_entries: u64,
    /// Maximum inherited bytes.
    pub inherited_bytes: u64,
    /// Maximum validation work (packs, edges, and binary-search comparisons).
    pub work: u64,
}

impl ForkLimits {
    /// Build from every field. The struct is `#[non_exhaustive]`: hosts
    /// construct it here and may assign any public field afterwards.
    #[must_use]
    pub const fn new(
        packs: u32,
        edges: u32,
        branch_bytes: u32,
        index_entries: u64,
        inherited_bytes: u64,
        work: u64,
    ) -> Self {
        Self {
            packs,
            edges,
            branch_bytes,
            index_entries,
            inherited_bytes,
            work,
        }
    }
}

/// Complete immutable inventory of an inherited pack, supplied by a trusted host.
///
/// The host authenticates the descriptor and resolves every external base to its
/// source supplier. `dependencies` contains the predecessor, listed packs, and
/// external suppliers, including entries outside the requested head's closure.
/// This fact is not a verifier artifact or a remote attestation.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct ForkInventory {
    /// Whole-pack content identity.
    pub pack: Hash,
    /// Exact immutable descriptor commitment.
    pub descriptor: Hash,
    /// Whole-pack byte length.
    pub bytes: u64,
    /// Exact copied index-entry count, including surplus entries.
    pub index_entries: u64,
    /// Sorted, distinct direct pack dependencies from the complete inventory.
    pub dependencies: Vec<Hash>,
}

impl ForkInventory {
    /// Build from every field. The struct is `#[non_exhaustive]`: hosts
    /// construct it here and may assign any public field afterwards.
    #[must_use]
    pub const fn new(
        pack: Hash,
        descriptor: Hash,
        bytes: u64,
        index_entries: u64,
        dependencies: Vec<Hash>,
    ) -> Self {
        Self {
            pack,
            descriptor,
            bytes,
            index_entries,
            dependencies,
        }
    }
}

/// A validated complete pack graph. Construction grants no membership or access.
///
/// Plan sealing validates supplied facts; it does not authenticate their origin.
/// The host must supply authenticated immutable inventories, not head-only views.
/// Only the final source fence establishes current source eligibility.
///
/// ```compile_fail
/// use mkit_primitives::fork::ForkPlan;
/// let forged = ForkPlan { binding: (), packs: vec![], bytes: 0,
///     index_entries: 0, pack_digest: [0; 32], edges: 0 };
/// ```
#[derive(Debug, PartialEq, Eq)]
#[must_use]
pub struct ForkPlan {
    pub(super) binding: ForkBinding,
    pub(super) packs: Vec<ForkInventory>,
    pub(super) result: ForkResult,
    pub(super) edges: u64,
    pub(super) commitment: Hash,
}

impl ForkPlan {
    /// Seal a canonical, complete graph rooted at the admitted packmap pack.
    ///
    /// Inputs are moved, not copied. Host-owned input memory is outside this
    /// operation's allocation accounting. Scratch is at most one `usize` and
    /// one byte per pack plus one result branch string; allocations are fallible
    /// and follow count and branch checks.
    /// Validation uses bounded graph traversal and metered binary searches.
    ///
    /// # Errors
    /// `InvalidResponse` for malformed, disconnected, duplicate, or incomplete
    /// inventory facts. `ResourceLimit` for finite-limit or allocation refusal.
    pub fn seal(
        binding: ForkBinding,
        packs: Vec<ForkInventory>,
        limits: ForkLimits,
    ) -> Result<Self, Failure> {
        if packs.len() as u64 > u64::from(limits.packs)
            || binding.branch.0.len() as u64 > u64::from(limits.branch_bytes)
        {
            return Err(resource());
        }
        let mut work = Work(limits.work);
        work.charge(binding.branch.0.len() as u64)?;
        if packs.is_empty()
            || binding.source == binding.destination
            || !binding.branch.0.starts_with("refs/heads/")
            || !crate::fork::valid_branch(&binding.branch.0)
            || binding.publication.head.is_none()
            || binding.publication.packmap.is_none()
            || binding.publication.published_prefix > binding.publication.sequence
            || binding.publication.deletion_boundary > binding.publication.published_prefix
            || binding.publication.sequence == 0
        {
            return Err(invalid());
        }

        let (mut bytes, mut index_entries, mut edges) = (0_u64, 0_u64, 0_u64);
        let mut digest = Hasher::new();
        for (i, pack) in packs.iter().enumerate() {
            work.charge(1)?;
            if pack.bytes == 0 || (i > 0 && packs[i - 1].pack >= pack.pack) {
                return Err(invalid());
            }
            edges = edges
                .checked_add(pack.dependencies.len() as u64)
                .ok_or_else(resource)?;
            if edges > u64::from(limits.edges) {
                return Err(resource());
            }
            work.charge(pack.dependencies.len() as u64)?;
            if pack.dependencies.windows(2).any(|ids| ids[0] >= ids[1]) {
                return Err(invalid());
            }
            bytes = bytes.checked_add(pack.bytes).ok_or_else(resource)?;
            index_entries = index_entries
                .checked_add(pack.index_entries)
                .ok_or_else(resource)?;
            if bytes > limits.inherited_bytes || index_entries > limits.index_entries {
                return Err(resource());
            }
            digest.update(&pack.pack);
        }
        let mut visited = Vec::new();
        visited
            .try_reserve_exact(packs.len())
            .map_err(|_| resource())?;
        visited.resize(packs.len(), false);
        let mut queue = Vec::new();
        queue
            .try_reserve_exact(packs.len())
            .map_err(|_| resource())?;
        let root = binding.publication.packmap.ok_or_else(invalid)?;
        let root_index = find(&packs, &root, &mut work)?;
        visited[root_index] = true;
        queue.push(root_index);
        let mut cursor = 0;
        while cursor < queue.len() {
            work.charge(1)?;
            let pack = &packs[queue[cursor]];
            for dependency in &pack.dependencies {
                let index = find(&packs, dependency, &mut work)?;
                if !visited[index] {
                    visited[index] = true;
                    queue.push(index);
                }
            }
            cursor += 1;
        }
        if queue.len() != packs.len() {
            return Err(invalid());
        }
        work.charge(binding.branch.0.len() as u64)?;
        let mut branch = String::new();
        branch
            .try_reserve_exact(binding.branch.0.len())
            .map_err(|_| resource())?;
        branch.push_str(&binding.branch.0);
        let result = ForkResult {
            branch: crate::decision::RefName(branch),
            source: binding.source,
            source_sequence: binding.publication.sequence,
            tip: binding.publication.head.ok_or_else(invalid)?,
            packmap: binding.publication.packmap.ok_or_else(invalid)?,
            packs: packs.len() as u64,
            bytes,
            index_entries,
            pack_digest: digest.finalize(),
            destination_generation: binding.destination_generation,
        };
        let commitment = Self::compute_commitment(&binding, &packs, &result);
        Ok(Self {
            binding,
            packs,
            result,
            edges,
            commitment,
        })
    }

    /// Exact admitted source, destination, and publication binding.
    #[must_use]
    pub const fn binding(&self) -> &ForkBinding {
        &self.binding
    }

    /// Canonically ordered full inherited pack inventories.
    #[must_use]
    pub fn packs(&self) -> &[ForkInventory] {
        &self.packs
    }

    /// Exact admission byte charge.
    #[must_use]
    pub const fn bytes(&self) -> u64 {
        self.result.bytes
    }

    /// Copied index-entry count.
    #[must_use]
    pub const fn index_entries(&self) -> u64 {
        self.result.index_entries
    }

    /// Existing fork result digest: BLAKE3 over concatenated sorted pack IDs.
    #[must_use]
    pub const fn pack_digest(&self) -> Hash {
        self.result.pack_digest
    }

    /// Complete response bound to this sealed plan.
    #[must_use]
    pub const fn result(&self) -> &ForkResult {
        &self.result
    }

    pub(super) fn within(&self, limits: ForkLimits) -> bool {
        self.packs.len() as u64 <= u64::from(limits.packs)
            && self.edges <= u64::from(limits.edges)
            && self.binding.branch.0.len() as u64 <= u64::from(limits.branch_bytes)
            && self.result.bytes <= limits.inherited_bytes
            && self.result.index_entries <= limits.index_entries
    }
}

struct Work(u64);
impl Work {
    fn charge(&mut self, amount: u64) -> Result<(), Failure> {
        self.0 = self.0.checked_sub(amount).ok_or_else(resource)?;
        Ok(())
    }
}
fn find(packs: &[ForkInventory], id: &Hash, work: &mut Work) -> Result<usize, Failure> {
    // Charge the worst-case comparisons before the search.
    work.charge(u64::from(usize::BITS - packs.len().leading_zeros()) + 1)?;
    packs
        .binary_search_by_key(id, |pack| pack.pack)
        .map_err(|_| invalid())
}
