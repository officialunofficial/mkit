//! Privileged canonical acquisition with explicit runtime admission geometry.
use crate::indexed::resolve::{self, MemberCache, MemberSourceLimits};
use crate::pipeline::ShardMap;
use crate::{BlobStore, Metrics, NamespaceStore, RepoId, ServerError};
use mkit_core::hash::Hash;
use std::{collections::BTreeSet, sync::Arc};

/// Validated limits; the caller budgets the actual namespace and blob boundaries.
#[derive(Debug, Clone, Copy)]
pub struct Profile {
    limits: MemberSourceLimits,
    chain_depth: u32,
    retained: u64,
    resident: u64,
}
impl Profile {
    /// Inline verification's configured retained budget and checked resident bound.
    ///
    /// # Errors
    /// Invalid chain geometry or overflow of the conservative resident allowance.
    pub fn inline(decode_budget: u64, chain_depth: u32) -> Result<Self, ServerError> {
        if decode_budget < 8 || chain_depth == 0 || chain_depth > u32::from(u16::MAX) {
            return Err(ServerError::invalid_argument("invalid acquisition limits"));
        }
        let resident = decode_budget
            .checked_mul(8)
            .and_then(|n| n.checked_add(128 << 20))
            .ok_or_else(|| ServerError::invalid_argument("acquisition resident bound overflow"))?;
        Ok(Self {
            limits: MemberSourceLimits {
                max_frame_bytes: decode_budget,
                max_decoded_bytes: decode_budget.min(mkit_core::store::MAX_RAW_OBJECT_SIZE as u64),
            },
            chain_depth,
            retained: decode_budget,
            resident,
        })
    }
    /// Current Worker admission: 1 MiB entries, 16 MiB windows, 50 delta hops.
    /// The 51 MiB retained chain, one exact 16 MiB frame, bounded scratch and
    /// transport pieces fit the conservative 96 MiB acquisition allowance.
    #[must_use]
    pub const fn scheduled() -> Self {
        Self {
            limits: MemberSourceLimits {
                max_frame_bytes: (16 << 20) + 5,
                max_decoded_bytes: 1 << 20,
            },
            chain_depth: 50,
            retained: 51 << 20,
            resident: 96 << 20,
        }
    }
    /// Conservative per-acquisition resident allowance for startup reporting.
    #[must_use]
    pub const fn resident_upper_bound(&self) -> u64 {
        self.resident
    }
}

/// Canonical storable bytes and their exact kind, verified against membership.
#[derive(Debug)]
pub struct Verified {
    pub id: Hash,
    pub kind: u8,
    pub canonical: Arc<[u8]>,
}

/// Resolve using the internal privilege that preserves already denied content.
/// All I/O must receive the caller's shared budget wrappers; retries do not reset it.
///
/// # Errors
/// Unknown membership, non-storable kinds, corrupt sources or exhausted bounds fail closed.
#[allow(clippy::too_many_arguments)]
pub async fn resolve<B: BlobStore, S: NamespaceStore>(
    blobs: &B,
    store: &S,
    shards: &dyn ShardMap,
    repo: &RepoId,
    id: Hash,
    profile: &Profile,
    metrics: &dyn Metrics,
) -> Result<Verified, ServerError> {
    let located = resolve::locate_split(store, shards, repo, &[id], metrics)
        .await?
        .remove(&id)
        .and_then(Result::ok)
        .flatten()
        .ok_or_else(|| ServerError::unavailable("canonical member source unavailable"))?;
    let mut memo = MemberCache::with_work_budget(profile.chain_depth + 1);
    let (canonical, _) = resolve::member_object_for_preservation_bounded(
        blobs,
        store,
        shards,
        repo,
        id,
        located,
        profile.chain_depth,
        profile.retained,
        &mut memo,
        &mut BTreeSet::new(),
        metrics,
        profile.limits,
    )
    .await
    .map_err(|_| ServerError::unavailable("canonical member source unavailable"))?;
    let kind = canonical.first().copied().unwrap_or(0);
    if !matches!(kind, 1 | 2 | 3 | 4 | 5 | 7) {
        return Err(ServerError::invalid_argument(
            "preservation target must be a canonical storable object",
        ));
    }
    Ok(Verified {
        id,
        kind,
        canonical,
    })
}

#[cfg(test)]
#[path = "acquisition_tests.rs"]
mod tests;
