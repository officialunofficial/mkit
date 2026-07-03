//! The packmap-chain transfer layer for `mkit push` / `mkit fetch`.
//!
//! A branch's transfer history is a content-addressed singly-linked list
//! of packlist nodes — the *packmap* — advertised through the
//! `refs/mkit/packmap/<branch>` metadata ref. Each push appends one node
//! (a `prev` pointer plus the pack(s) it added); the fetch side walks the
//! chain oldest-first so every delta's base is already in the store when
//! its pack is unpacked.
//!
//! This module co-locates both ends of that machinery so the push-side
//! *advance* and the fetch-side *resolve / fetch* logic — which share the
//! same chain-walk integrity rules — sit next to each other:
//!
//! * push side: [`advance_packmap`] (chains a new pack on, gated by a CAS
//!   on the packmap ref).
//! * fetch side: [`resolve_pack_chain`] (walk + integrity check) and
//!   [`fetch_pack_chain`] (download + unpack each pack in order).
//!
//! All entry points keep `pub(crate)` visibility so the orchestration in
//! the parent [`super`] module (`push_branch`, `fetch_objects`) can call
//! them.

use std::path::Path;

use mkit_core::hash::Hash;
use mkit_core::pack::{self, PackReader};
use mkit_core::protocol::{AdvanceOutcome, PackKey, Transport, TransportError};
use mkit_core::refs;
use mkit_core::store::ObjectStore;
use mkit_core::transfer;

use super::DispatchError;
use super::applied_packs::AppliedPacks;

/// Ref under which a branch's transfer packlist key is advertised. The
/// value is the BLAKE3 of the packlist chain head — an auxiliary
/// content-addressed blob (moved via [`Transport::upload_blob`] /
/// [`Transport::download_blob`], not a packfile); the fetch side reads it to
/// discover every pack needed to reconstruct the branch. Lives in the
/// `refs/mkit/` metadata namespace so it never collides with real
/// heads/tags. See [`mkit_core::transfer`].
pub(crate) fn packmap_ref(branch: &str) -> String {
    format!("refs/mkit/packmap/{branch}")
}

/// Number of read-modify-write attempts when chaining a new pack onto the
/// packmap. Each conflict means another pusher advanced the packmap; we
/// re-read and retry. Exhaustion (sustained contention) aborts the push
/// *before* the branch ref moves — see [`advance_packmap`].
const PACKMAP_CAS_ATTEMPTS: u32 = 8;

/// Hard cap on packmap **chain length** (number of linked nodes), i.e.
/// chain DEPTH — distinct from [`transfer::PACKLIST_MAX_ENTRIES`], which
/// caps the packs recorded in a single node.
///
/// A `prev`-linked chain is attacker-influenced: a malicious or corrupt
/// remote can advertise an arbitrarily long (or cyclic) chain to make the
/// fetcher walk forever issuing one blob download per node. We bound the
/// walk so such a remote surfaces as [`DispatchError::PackChainInvalid`]
/// instead of hanging. (A cycle is already caught by the `seen` set; this
/// bound additionally caps an *acyclic* but pathologically long chain.)
///
/// `100_000` nodes is well beyond any honest history — one node is appended
/// per push, and periodic re-baselining (#406, see [`rebaseline_depth`])
/// now collapses a healthy chain back to a single node long before it gets
/// anywhere near this cap — while still being cheap to reject. It is
/// deliberately NOT tied to the per-node entry cap: conflating "packs in one
/// node" with "nodes in the chain" overloads one number for two unrelated
/// bounds. This constant remains the runaway/cycle guard for a chain that
/// re-baselining never got a chance to bound (e.g. a hostile or corrupt
/// remote advertising an ever-growing or cyclic chain).
const MAX_PACK_CHAIN_DEPTH: usize = 100_000;

/// Default chain depth at which a push re-baselines: resets the packlist
/// chain to a single fresh self-contained node instead of appending to it
/// (#406). Bounds clone cost, which otherwise grows with the chain length
/// (one node walked/downloaded per push since the last re-baseline).
/// Overridable via `MKIT_PACK_REBASELINE_DEPTH` for tests; `0` disables
/// re-baselining entirely.
const DEFAULT_REBASELINE_DEPTH: usize = 64;

/// Resolve the configured re-baseline threshold: the `MKIT_PACK_REBASELINE_DEPTH`
/// environment variable if present and parsable, else [`DEFAULT_REBASELINE_DEPTH`].
/// A value of `0` disables re-baselining (the push path never forces a
/// full-closure reset on depth alone).
pub(crate) fn rebaseline_depth() -> usize {
    std::env::var("MKIT_PACK_REBASELINE_DEPTH")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(DEFAULT_REBASELINE_DEPTH)
}

/// Download and decode one packlist node by key. Packlist nodes are
/// auxiliary transfer metadata, not packfiles, so they travel over the
/// dedicated [`Transport::download_blob`] verb.
fn download_packlist_node(
    tx: &dyn Transport,
    key: Hash,
) -> Result<transfer::PackListNode, DispatchError> {
    let bytes = tx.download_blob(&PackKey::from_hash(key))?;
    Ok(transfer::decode_packlist(&bytes)?)
}

/// Walk a branch's packlist chain from `head_key` (newest node) following
/// `prev` pointers, applying the shared cycle / runaway-depth guard, and
/// return every node visited in newest-to-oldest walk order.
///
/// This is the ONE place the chain walk is written: [`resolve_pack_chain`]
/// (which flattens the visited nodes' packs into the oldest-first fetch
/// order) and [`chain_depth`] (which only needs the visited-node count) both
/// call through here rather than re-implementing the walk.
///
/// This walks the WHOLE chain, so it doubles as the push-side integrity
/// check: a node the chain references but the remote can't deliver/decode,
/// a cycle, or an over-deep chain all surface as
/// [`DispatchError::PackChainInvalid`]. A transient transport error (network
/// blip) propagates unchanged so it is never mistaken for corruption. The
/// walk is `O(chain length)` node downloads; chain depth is bounded by
/// periodic re-baselining (#406, see [`rebaseline_depth`]), and a
/// server-side atomic advance (#408) could move this check off the hot path.
fn walk_pack_chain(
    tx: &dyn Transport,
    branch: &str,
    head_key: Hash,
) -> Result<Vec<transfer::PackListNode>, DispatchError> {
    let invalid = || DispatchError::PackChainInvalid {
        branch: branch.to_owned(),
    };
    let mut nodes = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut cursor = Some(head_key);
    while let Some(key) = cursor {
        if crate::signal::is_shutdown() {
            return Err(DispatchError::Interrupted);
        }
        // Cycle / runaway-depth guard.
        if !seen.insert(key) || seen.len() > MAX_PACK_CHAIN_DEPTH {
            return Err(invalid());
        }
        let node = match download_packlist_node(tx, key) {
            Ok(n) => n,
            // A referenced-but-undeliverable / undecodable node = broken
            // chain (distinct from a transient transport error).
            Err(
                DispatchError::Transport(TransportError::PackNotFound) | DispatchError::PackList(_),
            ) => return Err(invalid()),
            Err(e) => return Err(e),
        };
        cursor = node.prev;
        nodes.push(node);
    }
    Ok(nodes)
}

/// Walk a branch's packlist chain from `head_key` and return the flat
/// **oldest-first** list of pack keys it references — the order a fetcher
/// must unpack so each delta's base is already present. See
/// [`walk_pack_chain`] for the walk / integrity-check semantics.
pub(crate) fn resolve_pack_chain(
    tx: &dyn Transport,
    branch: &str,
    head_key: Hash,
) -> Result<Vec<Hash>, DispatchError> {
    let mut nodes = walk_pack_chain(tx, branch, head_key)?;
    nodes.reverse(); // oldest node first
    Ok(nodes.into_iter().flat_map(|n| n.packs).collect())
}

/// Resolve a branch's current packlist chain **depth** (number of linked
/// nodes) from `head_key`, without collecting any pack keys. Used by the
/// push side (#406) to decide, before planning a pack, whether this push
/// would grow the chain past the re-baseline threshold. Shares
/// [`walk_pack_chain`] with [`resolve_pack_chain`], so a corrupt/hostile
/// remote (cycle, over-deep chain, undeliverable node) surfaces identically
/// as [`DispatchError::PackChainInvalid`].
pub(crate) fn chain_depth(
    tx: &dyn Transport,
    branch: &str,
    head_key: Hash,
) -> Result<usize, DispatchError> {
    Ok(walk_pack_chain(tx, branch, head_key)?.len())
}

/// Chain `pack_key` onto the branch's packmap and CAS-advance the
/// `refs/mkit/packmap/<branch>` pointer to the new node.
///
/// This MUST succeed before the branch ref is moved: the invariant is
/// "if `refs/heads/<branch>` resolves to T, the packmap reconstructs
/// closure(T)". We can't update both refs in one transaction against the
/// CAS-only ref API, so we order them — packmap first, gated — and on a
/// concurrent conflict we re-read the (only-growing) packmap and retry.
/// If we can't land it within [`PACKMAP_CAS_ATTEMPTS`], the caller aborts
/// the push without moving the head, so the head never advances past a
/// packmap that fails to reconstruct it.
///
/// The **entire** prior chain is validated (not just its head node) before
/// we build on it, so a deeper missing/corrupt node can't slip a head onto a
/// chain that fetch cannot walk:
///
/// * No prior packmap → start a fresh chain (`prev = None`).
/// * Prior chain fully walks → append (`prev = prior`). If our pack is
///   already anywhere in the chain the push is idempotent and we stop.
/// * Prior chain broken at any depth → we must not append a chain whose tail
///   can't be resolved. If `self_contained` (this pack reconstructs the whole
///   closure with no external base) we **reset** to a fresh chain — the only
///   safe way to escape a broken chain. Otherwise we **block** the push
///   ([`DispatchError::PackChainInvalid`]) before the head moves, because the
///   deltas' bases live in the unreachable prior chain.
///
/// `rebaseline` (#406) is the *proactive* counterpart to the broken-chain
/// reset above: the caller (`push_branch`) sets it when the prior chain is
/// perfectly healthy but has simply grown past the re-baseline threshold
/// (see [`rebaseline_depth`]). When `true`, prior-chain validation is
/// skipped entirely and `prev` is unconditionally `None` — a re-baseline
/// always resets, whether or not the prior chain would otherwise resolve.
/// This requires `self_contained == true` (checked via `debug_assert` and,
/// defensively, a runtime error): a delta pack chained onto a reset point
/// would have its external bases go missing.
pub(crate) fn advance_packmap(
    tx: &dyn Transport,
    branch: &str,
    pack_key: Hash,
    self_contained: bool,
    rebaseline: bool,
    head_condition: refs::RefWriteCondition,
    tip: Hash,
) -> Result<(), DispatchError> {
    debug_assert!(
        !rebaseline || self_contained,
        "a re-baseline push must always be self-contained"
    );
    if rebaseline && !self_contained {
        return Err(DispatchError::RebaselineNotSelfContained {
            branch: branch.to_owned(),
        });
    }
    let packmap_name = packmap_ref(branch);
    let head_name = format!("refs/heads/{branch}");
    for _ in 0..PACKMAP_CAS_ATTEMPTS {
        if crate::signal::is_shutdown() {
            return Err(DispatchError::Interrupted);
        }
        let prior = tx.read_ref(&packmap_name)?;
        // Decide the new node's `prev`. A re-baseline always resets
        // (skipping prior-chain validation); otherwise validate the WHOLE
        // prior chain before deciding to append vs. reset.
        let prev = if rebaseline {
            None
        } else {
            match prior {
                None => None,
                Some(p) => match resolve_pack_chain(tx, branch, p) {
                    // Idempotency: a previous attempt already advertised this pack.
                    // The packmap is already correct, so only the head still needs
                    // to move — commit it alone.
                    Ok(packs) if packs.contains(&pack_key) => {
                        return commit_head(tx, &head_name, head_condition, &tip, branch);
                    }
                    Ok(_) => Some(p), // healthy chain — append onto it
                    // Broken chain: a self-contained pack can reset to escape it;
                    // a delta push must block (its bases live in the broken tail).
                    // Transient transport errors propagate (don't reset on a blip).
                    Err(DispatchError::PackChainInvalid { .. }) if self_contained => None,
                    Err(e) => return Err(e),
                },
            }
        };
        let node = transfer::encode_packlist(prev, &[pack_key])?;
        let node_key = pack::pack_key(&node);
        tx.upload_blob(&node, &PackKey::from_hash(node_key))?;
        // CAS off the packmap's CURRENT value (`prior`), independent of the
        // node's `prev` — a reset still has to win the race for the ref.
        let packmap_condition = match prior {
            Some(k) => refs::RefWriteCondition::Match(k),
            None => refs::RefWriteCondition::Missing,
        };
        // Commit the packmap AND the head together (#408). A transactional
        // transport applies both atomically; the default does packmap-then-
        // head — still safe, the head never lands past an unadvanced packmap.
        match tx.advance_refs(
            &head_name,
            head_condition,
            &tip,
            &packmap_name,
            packmap_condition,
            &node_key,
        )? {
            AdvanceOutcome::Committed => return Ok(()),
            // Another pusher advanced the packmap under us — re-read and retry.
            AdvanceOutcome::PackmapConflict => {}
            // The branch moved under us — the push is stale.
            AdvanceOutcome::HeadConflict => {
                return Err(DispatchError::NonFastForwardPush {
                    branch: branch.to_owned(),
                });
            }
        }
    }
    Err(DispatchError::PackmapContended {
        branch: branch.to_owned(),
    })
}

/// Move just the branch head under its CAS condition, mapping a conflict to
/// the actionable non-fast-forward error. Used when the packmap already
/// advertises the pack (idempotent retry) or a push has nothing to send.
pub(crate) fn commit_head(
    tx: &dyn Transport,
    head_name: &str,
    condition: refs::RefWriteCondition,
    tip: &Hash,
    branch: &str,
) -> Result<(), DispatchError> {
    match tx.update_ref(head_name, condition, tip) {
        Ok(()) => Ok(()),
        Err(TransportError::RefConflict) => Err(DispatchError::NonFastForwardPush {
            branch: branch.to_owned(),
        }),
        Err(e) => Err(e.into()),
    }
}

/// Walk a branch's packlist chain from `head_key` and unpack every pack in
/// dependency order (oldest node first), so each delta's base is already in
/// the store when its pack is unpacked. Chain resolution + integrity is
/// shared with the push side via [`resolve_pack_chain`].
///
/// Within a single packmap chain a delta's base always arrives in an
/// earlier pack (the push planner only deltas against bases the remote — and
/// therefore the chain — already holds), so unpacking oldest-first is
/// sufficient: there is no per-object base prefetch.
///
/// Packs already recorded in the local applied-pack record for `remote`
/// (`.mkit/applied-packs/<remote>`, see [`applied_packs`]) are skipped —
/// neither downloaded nor unpacked — so a steady-state fetch only pays for
/// packs new since the last fetch (#409). The chain itself is still
/// resolved in full every time: node downloads are small blobs and remain
/// the source of truth for chain shape, independent of what's locally
/// applied.
///
/// # Self-heal
///
/// A run's result is "downloading/unpacking every non-skipped pack, then
/// asserting `tip`'s closure is fully present" (the latter via
/// [`super::verify_closure_present`], folded in here rather than sequenced
/// by the caller — see that function's doc comment for why). If that
/// closure check fails with [`DispatchError::RemoteMissingObject`], or a
/// skipped pack turns out to be unreadable ([`DispatchError::Pack`] from
/// [`PackReader::read`]), in a run that skipped at least one recorded
/// pack, the local applied-pack record is treated as possibly stale
/// relative to the object store (e.g. `.mkit/objects` was wiped
/// out-of-band while `applied-packs/` survived) rather than a hard
/// failure: the record is cleared and the whole chain is retried once with
/// no skips. Only if that retry also fails is the error propagated. Every
/// other error kind (e.g. a transient [`DispatchError::Transport`] error,
/// or [`DispatchError::AdvertisedPackMissing`] for a genuinely
/// corrupt/incomplete remote) is NOT a staleness signal and propagates
/// immediately without touching the record — a network blip or a corrupt
/// remote is not evidence the local object store is stale. A
/// [`DispatchError::Interrupted`] (user-requested shutdown) is likewise
/// never treated as a self-heal trigger.
pub(crate) fn fetch_pack_chain(
    store: &ObjectStore,
    tx: &dyn Transport,
    mkit_dir: &Path,
    remote: &str,
    branch: &str,
    head_key: Hash,
    tip: Hash,
) -> Result<(), DispatchError> {
    // Chain shape is always resolved fresh and in full — see the doc
    // comment above. Only the per-pack download+unpack loop below
    // consults / mutates the applied-pack record.
    let chain = resolve_pack_chain(tx, branch, head_key)?;
    let mut applied = AppliedPacks::load(mkit_dir, remote)?;

    let (skipped, result) = attempt_pack_chain(store, tx, branch, &chain, tip, &mut applied);
    match result {
        Ok(()) => {
            applied.persist()?;
            Ok(())
        }
        Err(DispatchError::Interrupted) => Err(DispatchError::Interrupted),
        Err(e @ (DispatchError::RemoteMissingObject(_) | DispatchError::Pack(_)))
            if skipped > 0 =>
        {
            eprintln!(
                "note: applied-packs record for remote '{remote}' branch '{branch}' looks stale ({e}); clearing it and re-fetching the full pack chain"
            );
            applied.clear_and_persist()?;
            let (_, retry_result) =
                attempt_pack_chain(store, tx, branch, &chain, tip, &mut applied);
            retry_result?;
            applied.persist()?;
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// Run [`apply_pack_chain`] and, if it succeeds, follow up with
/// [`super::verify_closure_present`] on `tip`. Returns the number of packs
/// [`apply_pack_chain`] skipped alongside the combined result — the caller
/// uses the skip count to decide whether a failure (from either half) is
/// eligible for the self-heal retry in [`fetch_pack_chain`].
fn attempt_pack_chain(
    store: &ObjectStore,
    tx: &dyn Transport,
    branch: &str,
    chain: &[Hash],
    tip: Hash,
    applied: &mut AppliedPacks,
) -> (usize, Result<(), DispatchError>) {
    let (skipped, result) = apply_pack_chain(store, tx, branch, chain, applied);
    let result = result.and_then(|()| super::verify_closure_present(store, &tip));
    (skipped, result)
}

/// Download + unpack every key in `chain` not already recorded in
/// `applied`, inserting each newly-applied digest into `applied` as soon as
/// its pack is successfully read. Returns the number of packs skipped
/// (already recorded as applied) alongside the loop's result.
fn apply_pack_chain(
    store: &ObjectStore,
    tx: &dyn Transport,
    branch: &str,
    chain: &[Hash],
    applied: &mut AppliedPacks,
) -> (usize, Result<(), DispatchError>) {
    let mut skipped = 0usize;
    for &pk in chain {
        if crate::signal::is_shutdown() {
            return (skipped, Err(DispatchError::Interrupted));
        }
        let key = PackKey::from_hash(pk);
        if applied.contains(&key) {
            skipped += 1;
            continue;
        }
        let pack = match tx.download_pack(&key) {
            Ok(b) => b,
            // The packmap PROMISED this pack. Its objects are delta/raw
            // entries inside the pack, not stored under their own digests, so
            // they cannot be recovered any other way. A missing advertised
            // pack means a corrupt/incomplete remote — fail loudly rather
            // than publish a ref to a history we can't reconstruct.
            Err(TransportError::PackNotFound) => {
                return (
                    skipped,
                    Err(DispatchError::AdvertisedPackMissing {
                        branch: branch.to_owned(),
                        pack: mkit_core::hash::to_hex(&pk),
                    }),
                );
            }
            Err(e) => return (skipped, Err(e.into())),
        };
        if let Err(e) = PackReader::read(&pack, store) {
            return (skipped, Err(e.into()));
        }
        applied.insert(&key);
    }
    (skipped, Ok(()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mkit_core::hash;
    use mkit_transport_memory::MemoryTransport;

    fn h(seed: &str) -> Hash {
        hash::hash(seed.as_bytes())
    }

    /// Upload a hand-built packlist node under an explicit key — not
    /// necessarily the content hash of `bytes` — so a chain's shape
    /// (including a cycle, impossible to build under real content
    /// addressing) can be constructed directly for the walk/guard tests
    /// below.
    fn put_node(tx: &MemoryTransport, key: Hash, prev: Option<Hash>, packs: &[Hash]) {
        let bytes = transfer::encode_packlist(prev, packs).unwrap();
        tx.upload_blob(&bytes, &PackKey::from_hash(key)).unwrap();
    }

    #[test]
    fn chain_depth_counts_nodes_and_matches_resolve_pack_chain() {
        let tx = MemoryTransport::new();
        let n1 = h("n1");
        let n2 = h("n2");
        let n3 = h("n3");
        put_node(&tx, n1, None, &[h("pack1")]);
        put_node(&tx, n2, Some(n1), &[h("pack2")]);
        put_node(&tx, n3, Some(n2), &[h("pack3")]);

        assert_eq!(chain_depth(&tx, "main", n3).unwrap(), 3);

        // Same node count as the packs resolve_pack_chain flattens, and the
        // packs themselves come back oldest-first.
        let packs = resolve_pack_chain(&tx, "main", n3).unwrap();
        assert_eq!(packs, vec![h("pack1"), h("pack2"), h("pack3")]);
        assert_eq!(chain_depth(&tx, "main", n3).unwrap(), packs.len());
    }

    #[test]
    fn chain_depth_of_a_single_node_chain_is_one() {
        let tx = MemoryTransport::new();
        let solo = h("solo");
        put_node(&tx, solo, None, &[h("pack-solo")]);
        assert_eq!(chain_depth(&tx, "main", solo).unwrap(), 1);
    }

    #[test]
    fn chain_depth_errors_on_a_cycle_exactly_like_resolve_pack_chain() {
        let tx = MemoryTransport::new();
        let a = h("cycle-a");
        let b = h("cycle-b");
        // a -> b -> a: only reachable via hand-built (non-content-addressed)
        // nodes, exercising the shared cycle guard in `walk_pack_chain`.
        put_node(&tx, a, Some(b), &[h("pack-a")]);
        put_node(&tx, b, Some(a), &[h("pack-b")]);

        assert!(matches!(
            chain_depth(&tx, "main", a).unwrap_err(),
            DispatchError::PackChainInvalid { .. }
        ));
        assert!(matches!(
            resolve_pack_chain(&tx, "main", a).unwrap_err(),
            DispatchError::PackChainInvalid { .. }
        ));
    }

    #[test]
    fn chain_depth_errors_on_an_undownloadable_node_like_resolve_pack_chain() {
        let tx = MemoryTransport::new();
        let ghost = h("never-uploaded");
        assert!(matches!(
            chain_depth(&tx, "main", ghost).unwrap_err(),
            DispatchError::PackChainInvalid { .. }
        ));
        assert!(matches!(
            resolve_pack_chain(&tx, "main", ghost).unwrap_err(),
            DispatchError::PackChainInvalid { .. }
        ));
    }
}
