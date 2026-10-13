//! Walking a branch's packmap chain.
//!
//! A branch's transfer history is a content-addressed singly-linked list of
//! packlist nodes, advertised through the `refs/mkit/packmap/<branch>`
//! metadata ref. Each push appends one node (a `prev` pointer plus the packs
//! it added); a fetch walks the chain oldest-first so every delta's base is
//! already in the store when its pack is unpacked.

use mkit_core::hash::Hash;
use mkit_core::protocol::PackKey;
use mkit_core::transfer;

use crate::error::SyncError;
use crate::observer::SyncObserver;
use crate::source::RemoteSource;

/// Ref under which a branch's transfer packlist key is advertised. The value
/// is the BLAKE3 of the packlist chain head, an auxiliary content-addressed
/// blob (not a packfile). It lives in the `refs/mkit/` metadata namespace so
/// it never collides with real heads or tags. See [`mkit_core::transfer`].
#[must_use]
pub fn packmap_ref(branch: &str) -> String {
    format!("refs/mkit/packmap/{branch}")
}

/// Push and fetch callers may carry a short branch name or its full ref name.
pub(crate) fn branch_ref_hint(branch: &str) -> String {
    format!(
        "refs/heads/{}",
        branch.strip_prefix("refs/heads/").unwrap_or(branch)
    )
}

/// Hard cap on packmap **chain length** (number of linked nodes), distinct
/// from [`transfer::PACKLIST_MAX_ENTRIES`], which caps the packs recorded in
/// a single node.
///
/// A `prev`-linked chain is attacker-influenced: a malicious or corrupt
/// remote can advertise an arbitrarily long (or cyclic) chain to make the
/// fetcher walk forever issuing one blob download per node. The walk is
/// bounded so such a remote surfaces as [`SyncError::PackChainInvalid`]
/// instead of hanging. (A cycle is already caught by the `seen` set; this
/// bound additionally caps an acyclic but pathologically long chain.)
const MAX_PACK_CHAIN_DEPTH: usize = 100_000;

/// Bounds retained chain and stage metadata across all nodes, not only
/// within one packlist. At most one million pack keys plus one hundred
/// thousand nodes.
pub(crate) const MAX_FETCH_PACKS: usize = 1_000_000;
/// Private download staging has a separate disk ceiling from one-pack memory.
/// A larger history must be fetched incrementally or re-baselined by its owner.
pub(crate) const MAX_FETCH_STAGED_BYTES: u64 = 64 * 1024 * 1024 * 1024;

/// Download and decode one packlist node by key. Packlist nodes are
/// auxiliary transfer metadata, not packfiles, so they travel over the
/// blob verb, with the branch hint.
pub(crate) fn download_packlist_node(
    source: &dyn RemoteSource,
    key: Hash,
    ref_name: &str,
) -> Result<transfer::PackListNode, SyncError> {
    let requested = PackKey::from_hash(key);
    let bytes = source.download_blob_via_ref(&requested, ref_name)?;
    requested
        .verify_bytes(&bytes)
        .map_err(crate::SourceError::from)?;
    Ok(transfer::decode_packlist(&bytes)?)
}

/// Walk a branch's packlist chain from `head_key` (newest node) following
/// `prev` pointers, applying the shared cycle and runaway-depth guard, and
/// return every node visited in newest-to-oldest order.
///
/// This is the one place the chain walk is written. It walks the WHOLE chain,
/// so it doubles as the push-side integrity check: a node the chain
/// references but the remote cannot deliver or decode, a cycle, or an
/// over-deep chain all surface as [`SyncError::PackChainInvalid`]. A
/// transient transport error propagates unchanged so it is never mistaken for
/// corruption.
pub fn walk_pack_chain(
    source: &dyn RemoteSource,
    observer: &dyn SyncObserver,
    branch: &str,
    head_key: Hash,
) -> Result<Vec<transfer::PackListNode>, SyncError> {
    let invalid = || SyncError::PackChainInvalid {
        branch: branch.to_owned(),
        source: None,
    };
    let mut nodes = Vec::new();
    let mut pack_count = 0usize;
    let mut seen = std::collections::HashSet::new();
    let mut cursor = Some(head_key);
    let ref_name = branch_ref_hint(branch);
    while let Some(key) = cursor {
        if observer.cancelled() {
            return Err(SyncError::Interrupted);
        }
        // Cycle / runaway-depth guard.
        if !seen.insert(key) || seen.len() > MAX_PACK_CHAIN_DEPTH {
            return Err(invalid());
        }
        let node = match download_packlist_node(source, key, &ref_name) {
            Ok(n) => n,
            // A referenced-but-undeliverable / undecodable node = broken
            // chain (distinct from a transient transport error).
            Err(SyncError::Source(error))
                if error.is_not_found() || error.is_invalid_response() =>
            {
                return Err(SyncError::PackChainInvalid {
                    branch: branch.to_owned(),
                    source: Some(error),
                });
            }
            Err(SyncError::PackList(_)) => return Err(invalid()),
            Err(e) => return Err(e),
        };
        pack_count = pack_count
            .checked_add(node.packs.len())
            .ok_or_else(invalid)?;
        if pack_count > MAX_FETCH_PACKS {
            return Err(invalid());
        }
        cursor = node.prev;
        nodes.push(node);
    }
    Ok(nodes)
}

/// Flatten nodes returned by [`walk_pack_chain`] into the pack keys in
/// **oldest-first** order, the order a fetcher must unpack so each delta's
/// base is already present.
#[must_use]
pub fn flatten_oldest_first(mut nodes: Vec<transfer::PackListNode>) -> Vec<Hash> {
    nodes.reverse();
    nodes.into_iter().flat_map(|n| n.packs).collect()
}

/// Walk a branch's packlist chain from `head_key` and return the flat
/// oldest-first list of pack keys it references.
pub fn resolve_pack_chain(
    source: &dyn RemoteSource,
    observer: &dyn SyncObserver,
    branch: &str,
    head_key: Hash,
) -> Result<Vec<Hash>, SyncError> {
    Ok(flatten_oldest_first(walk_pack_chain(
        source, observer, branch, head_key,
    )?))
}
