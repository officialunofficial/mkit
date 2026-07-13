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
//! * fetch side: [`resolve_pack_chain`] (walk + integrity check),
//!   [`resolve_and_download_chain`] (network-only: walk + download, no
//!   local writes), and [`apply_fetched_chain`] (unpack + verify + publish
//!   pre-check — must run under the repo lock).
//!
//! The fetch side is deliberately split into a network phase and a
//! local-write phase (#642): a branch's packs are fully downloaded before
//! the repo lock is taken, and the lock is held only from the first local
//! write through the branch's ref publish (in
//! [`super::fetch_objects_inner`]) — narrow enough that a slow transfer no
//! longer serializes out unrelated commands for its whole duration, while
//! still closing the #267 GC-prune race (a concurrent `gc` needs the same
//! lock, so it can never observe a downloaded-but-unpublished object).
//!
//! All entry points keep `pub(crate)` visibility so the orchestration in
//! the parent [`super`] module (`push_branch`, `fetch_objects`) can call
//! them.

use mkit_core::hash::{self, Hash};
use mkit_core::object::Object;
use mkit_core::pack::{self, PackReader};
use mkit_core::protocol::{AdvanceOutcome, PackKey, Transport, TransportError};
use mkit_core::refs;
use mkit_core::sign::{verify_commit, verify_remix, verify_tag};
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
/// remote advertising an ever-growing or cyclic chain) — AND, since mkit
/// #521, the *only* bound on a healthy chain's growth on a transport whose
/// `advance_refs` is not transactional (see
/// [`Transport::supports_atomic_advance`]): such a transport never
/// re-baselines (a reset is unsafe there), so it keeps appending past
/// [`rebaseline_depth`] until this cap.
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
    // Unset (or non-UTF-8) → the default. A present-but-unparsable value is
    // an operator mistake (`-1`, `off`, `""` — none of which disable; only
    // `0` does), so warn loudly instead of silently re-enabling the default.
    match std::env::var("MKIT_PACK_REBASELINE_DEPTH") {
        Err(_) => DEFAULT_REBASELINE_DEPTH,
        Ok(s) => s.parse::<usize>().unwrap_or_else(|_| {
            eprintln!(
                "warning: MKIT_PACK_REBASELINE_DEPTH='{s}' is not a valid non-negative \
                 integer; using the default {DEFAULT_REBASELINE_DEPTH} (set it to 0 to \
                 disable re-baselining)"
            );
            DEFAULT_REBASELINE_DEPTH
        }),
    }
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
/// order) and [`probe_chain`] (which needs both the visited-node count and
/// the flattened packs, for the push-side pre-plan re-baseline probe) both
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
    // Defined in terms of `probe_chain` so the flattened pack list is
    // identical BY CONSTRUCTION to `probe_chain(..).packs` (the equivalence
    // the `probe_chain_*_matches_resolve_pack_chain` test asserts) — the two
    // can't drift. `probe_chain` can't delegate the other way: it also needs
    // the node count for `depth`.
    Ok(probe_chain(tx, branch, head_key)?.packs)
}

/// A branch's packmap chain, walked exactly once, paired with the packmap
/// value it was walked from.
///
/// Produced by [`probe_chain`] (the push-side pre-plan re-baseline probe in
/// `push_branch`) and consumed by [`advance_packmap`]'s first CAS attempt —
/// so a healthy chain is walked once per push, not twice (mkit #521 perf
/// fix; previously the pre-plan depth probe and `advance_packmap`'s own
/// [`resolve_pack_chain`] call each walked the whole chain independently).
/// `advance_packmap` only reuses this when the packmap's live value still
/// equals `head`; a mismatch (the packmap moved between the probe and the
/// CAS attempt, or a prior CAS attempt already lost the race) falls back to
/// a fresh [`resolve_pack_chain`] call, preserving the existing retry
/// semantics.
#[derive(Debug)]
pub(crate) struct ResolvedChain {
    /// The packmap value this chain was walked from.
    pub(crate) head: Hash,
    /// Chain depth (node count) at `head`.
    pub(crate) depth: usize,
    /// Flattened oldest-first pack keys — identical to what
    /// [`resolve_pack_chain`] would return for `head`.
    pub(crate) packs: Vec<Hash>,
}

/// Walk a branch's packlist chain from `head_key` ONCE, returning both its
/// depth and its flattened oldest-first pack keys as a single
/// [`ResolvedChain`]. Sole caller is `push_branch`'s pre-plan re-baseline
/// probe (#406); see [`ResolvedChain`] for why threading its result into
/// [`advance_packmap`] matters.
pub(crate) fn probe_chain(
    tx: &dyn Transport,
    branch: &str,
    head_key: Hash,
) -> Result<ResolvedChain, DispatchError> {
    let mut nodes = walk_pack_chain(tx, branch, head_key)?;
    let depth = nodes.len();
    nodes.reverse(); // oldest node first
    let packs = nodes.into_iter().flat_map(|n| n.packs).collect();
    Ok(ResolvedChain {
        head: head_key,
        depth,
        packs,
    })
}

/// The push-side decision for how a new pack extends (or resets) the
/// packmap chain, computed once in `push_branch` and threaded into
/// [`advance_packmap`].
///
/// Replaces a former `self_contained: bool, rebaseline: bool` parameter
/// pair, which let "`rebaseline` == true but `self_contained` == false" —
/// an invariant violation `advance_packmap` had to police with a
/// `debug_assert` PLUS a defensive runtime error
/// (`DispatchError::RebaselineNotSelfContained`) — be constructed at all.
/// [`Self::ResetSelfContained`] carries no `self_contained` field, so that
/// illegal combination now has no representation (mkit #521).
#[derive(Debug, Clone, Copy)]
pub(crate) enum ChainAction {
    /// Validate the prior chain (if any) and append onto it. If the prior
    /// chain is broken, a self-contained pack (`self_contained == true`)
    /// resets to escape it; otherwise the push blocks
    /// ([`DispatchError::PackChainInvalid`]).
    Append {
        /// Whether the pack being chained on reconstructs the whole
        /// closure with no external base — the precondition for the
        /// broken-chain escape-hatch reset described above.
        self_contained: bool,
    },
    /// Proactive re-baseline (#406): unconditionally reset the chain to a
    /// single fresh self-contained node, skipping prior-chain validation
    /// entirely. `push_branch` only ever picks this alongside a
    /// full-closure pack plan (always self-contained), and only when the
    /// transport reports [`Transport::supports_atomic_advance`] AND the head
    /// write is CAS-conditioned (mkit #521) — see [`advance_packmap`]'s doc
    /// comment for why that gate matters.
    ///
    /// # Fetch-side cost (mkit #521)
    ///
    /// A reset replaces the whole chain with one new full-closure pack whose
    /// digest no existing fetcher has in its applied-pack record. So every
    /// incremental fetcher must re-download AND re-unpack the ENTIRE branch
    /// closure once per re-baseline cycle (~every [`DEFAULT_REBASELINE_DEPTH`]
    /// pushes), silently defeating #520's applied-packs skip optimization for
    /// that fetch. Worse, the applied-packs record then accumulates the
    /// orphaned pre-reset digests (one full cycle's worth per reset) with no
    /// pruning — an unbounded, full-file-rewrite-per-fetch growth. (The
    /// remote-side orphaning is documented in `transfer.rs` / makechain#849;
    /// this note covers the fetcher impact, which nothing else did.)
    ResetSelfContained,
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
/// `ChainAction::ResetSelfContained` (#406) is the *proactive* counterpart
/// to the broken-chain reset above: the caller (`push_branch`) picks it
/// when the prior chain is perfectly healthy but has simply grown past the
/// re-baseline threshold (see [`rebaseline_depth`]) — AND, since mkit
/// #521, only when the transport's [`Transport::advance_refs`] is
/// transactional (see [`Transport::supports_atomic_advance`]); a reset is
/// not a superset of the prior chain, so committing one while losing the
/// paired head CAS is safe only when both writes land as one transaction.
/// When picked, prior-chain validation is skipped entirely and `prev` is
/// unconditionally `None` — a re-baseline always resets, whether or not
/// the prior chain would otherwise resolve. `push_branch` only ever picks
/// this action alongside a pack planned with an empty `have_old` set
/// (always self-contained), so — unlike the old `self_contained: bool,
/// rebaseline: bool` pair this enum replaces — "a reset of a
/// non-self-contained pack" has no representation to defensively guard
/// against: [`ChainAction::ResetSelfContained`] carries no
/// `self_contained` field at all.
///
/// `resolved` (#521 perf fix) is an optional chain walk the caller already
/// performed (`push_branch`'s pre-plan re-baseline probe, see
/// [`probe_chain`]) for the SAME packmap value this loop's first iteration
/// will read. When it's still fresh (the packmap hasn't moved since), the
/// first iteration reuses it instead of re-walking the chain via
/// [`resolve_pack_chain`]; a lost CAS race (or a stale/absent `resolved`)
/// falls back to a fresh walk on retry, exactly as before this
/// optimization.
pub(crate) fn advance_packmap(
    tx: &dyn Transport,
    branch: &str,
    pack_key: Hash,
    action: ChainAction,
    resolved: Option<ResolvedChain>,
    head_condition: refs::RefWriteCondition,
    tip: Hash,
) -> Result<(), DispatchError> {
    let packmap_name = packmap_ref(branch);
    let head_name = format!("refs/heads/{branch}");
    // Consumed by (at most) the first iteration that reaches the "resolve
    // the prior chain" branch below; a retry (another loop pass) always
    // finds this already `None` and re-walks fresh, per the doc comment.
    let mut cached = resolved;
    // `action` (Append vs. Reset) is FROZEN by `push_branch` before this CAS
    // loop and never re-evaluated across retries — the depth probe ran once,
    // pre-plan. So under contention just below the re-baseline threshold, N
    // racers can each independently decide to Append (none saw the others'
    // node yet) and the chain overshoots the bound by ~N nodes. That is
    // bounded (by the number of concurrent pushers) and self-correcting (the
    // next push over the now-higher depth re-baselines), so we accept it
    // rather than re-probe depth inside the loop.
    for _ in 0..PACKMAP_CAS_ATTEMPTS {
        if crate::signal::is_shutdown() {
            return Err(DispatchError::Interrupted);
        }
        let prior = tx.read_ref(&packmap_name)?;
        // Decide the new node's `prev`. A re-baseline always resets
        // (skipping prior-chain validation); otherwise validate the WHOLE
        // prior chain before deciding to append vs. reset.
        let prev = match action {
            ChainAction::ResetSelfContained => {
                // Invariant guard (mkit #521): `push_branch` only ever picks a
                // reset on a transport whose `advance_refs` is transactional
                // AND whose head write is CAS-conditioned (not `Any`). A reset
                // is not a superset of the prior chain, so committing the
                // packmap while a paired ORDERED head PUT is lost/crashes
                // would strand the head at a closure the reset can't rebuild.
                // Assert both here so a FUTURE direct caller fails loudly
                // instead of silently reintroducing that stranded-head bug.
                debug_assert!(
                    tx.supports_atomic_advance(),
                    "re-baseline reset requires a transactional advance_refs (mkit #521)"
                );
                debug_assert!(
                    !matches!(head_condition, refs::RefWriteCondition::Any),
                    "re-baseline reset must not run with an `Any` head condition — the \
                     ordered advance_refs fallback would strand the head (mkit #521)"
                );
                None
            }
            ChainAction::Append { self_contained } => match prior {
                None => None,
                Some(p) => {
                    // Reuse the pre-plan walk if it's still for the packmap
                    // value we just read; otherwise walk it fresh. Either
                    // way this converges on the same `Result` shape
                    // `resolve_pack_chain` alone used to produce here.
                    let packs = match cached.take() {
                        Some(c) if c.head == p => Ok(c.packs),
                        _ => resolve_pack_chain(tx, branch, p),
                    };
                    match packs {
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
                    }
                }
            },
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
/// Packs already recorded in `applied` (the caller-owned, in-memory
/// applied-pack record for `remote`; see [`applied_packs`]) are skipped —
/// neither downloaded nor unpacked — so a steady-state fetch only pays for
/// packs new since the last fetch (#409). The chain itself is still
/// resolved in full every time: node downloads are small blobs and remain
/// the source of truth for chain shape, independent of what's locally
/// applied.
///
/// This function never loads or persists `applied` itself — it only mutates
/// the in-memory set; see [`super::fetch_objects`] for the load-once /
/// persist-once contract it runs under.
///
/// # Self-heal
///
/// A run first downloads/unpacks every non-skipped pack, then asserts
/// `tip`'s closure is fully present via [`super::verify_closure_present`]
/// (folded in here rather than sequenced by the caller — see that function's
/// doc comment for why). Exactly ONE failure mode is treated as local
/// staleness: the closure check reporting [`DispatchError::RemoteMissingObject`]
/// on a run that skipped at least one recorded pack. That means the record
/// claimed packs were applied but their objects aren't in the store (e.g.
/// `.mkit/objects` was wiped out-of-band while `applied-packs/` survived), so
/// `applied` is cleared in memory ([`AppliedPacks::clear`]) and the whole
/// chain is retried once with no skips; the caller's single end-of-fetch
/// persist durably reflects this post-heal state.
///
/// Every other failure propagates without triggering self-heal, because none
/// is evidence the local object store is stale:
///
/// * A download/unpack failure — a freshly-downloaded corrupt pack
///   ([`DispatchError::Pack`] from [`PackReader::read`]), a genuinely
///   incomplete remote ([`DispatchError::AdvertisedPackMissing`]), or a
///   transient [`DispatchError::Transport`] error — is a remote-side or
///   network problem. Wiping the cache would destroy a valid record on a
///   corrupt-remote's behalf, so these propagate as-is (a corrupt pack must
///   surface, not be papered over by a full re-download).
/// * A [`DispatchError::ClosureTooLarge`] means the closure exceeded the
///   verification cap — a scale limit, not staleness.
/// * A [`DispatchError::Interrupted`] (user-requested shutdown) is never a
///   self-heal trigger.
/// One branch's pack chain, resolved and downloaded over the network with
/// **no repo lock held** — see [`resolve_and_download_chain`]. Consumed by
/// [`apply_fetched_chain`], which the caller must run under the repo lock.
pub(crate) struct FetchedChain {
    /// Oldest-first flattened chain, as returned by [`resolve_pack_chain`].
    /// Retained (not just `downloaded`) so a self-heal retry inside
    /// [`apply_fetched_chain`] can re-download without re-walking the
    /// packlist chain.
    chain: Vec<Hash>,
    /// Raw bytes of every chain pack NOT already recorded in the
    /// `applied` snapshot passed to [`resolve_and_download_chain`], in
    /// chain order.
    downloaded: Vec<(PackKey, Vec<u8>)>,
}

/// Phase 1 of a branch fetch (#642): walk `branch`'s packmap chain from
/// `head_key` and download every pack in it not already recorded in
/// `applied`. Pure network I/O — resolving the chain shape reads small
/// auxiliary blobs and downloading packs never touches the local object
/// store — so the caller does **not** need the repo lock for this call.
/// The repo lock is only required for [`apply_fetched_chain`], which
/// unpacks the result.
///
/// # Errors
/// Propagates chain-walk failures ([`DispatchError::PackChainInvalid`],
/// [`DispatchError::Interrupted`]) and download failures
/// ([`DispatchError::AdvertisedPackMissing`], transport errors) unchanged.
pub(crate) fn resolve_and_download_chain(
    tx: &dyn Transport,
    branch: &str,
    head_key: Hash,
    applied: &AppliedPacks,
) -> Result<FetchedChain, DispatchError> {
    // Chain shape is always resolved fresh and in full — see the doc
    // comment on `fetch_pack_chain`'s prior single-function form. Only the
    // per-pack download loop below consults the applied-pack record (it
    // does not mutate it; mutation happens once the pack is actually
    // unpacked, in `unpack_downloaded_packs`).
    let chain = resolve_pack_chain(tx, branch, head_key)?;
    let downloaded = download_pack_chain(tx, branch, &chain, applied)?;
    Ok(FetchedChain { chain, downloaded })
}

/// Phase 2 of a branch fetch (#642): unpack `fetched`'s downloaded packs
/// into `store` and verify the closure at `tip` is complete, running the
/// applied-pack self-heal retry on a stale-record failure.
///
/// **The caller MUST hold the repo lock across this call, through the
/// branch's subsequent ref publish** — see [`super::fetch_objects_inner`]
/// and the module docs on `#642`. Unpacking writes objects to the local
/// store before this branch's ref makes them reachable; a concurrent `gc`
/// must not be able to observe that store state, so the lock has to stay
/// held continuously from the first write here through the ref write in
/// the caller. Self-heal (rare: only on a stale `applied` record) is the
/// one path that still does network I/O under that lock — an accepted
/// trade, since it is a recovery path, not the routine one.
///
/// # Signature verification (issue #692)
///
/// Once the closure is confirmed complete, every commit/remix/tag
/// [`unpack_downloaded_packs`] just wrote — the newly-fetched delta, NOT
/// the whole closure — is run through [`verify_new_object_signatures`]
/// when `require_signed` is `true` (the CLI's default; `false` is the
/// explicit `--no-verify-signatures` / `pull.require_signed = false`
/// opt-out). A failure is [`DispatchError::UnsignedOrInvalidObject`],
/// which — like [`DispatchError::ClosureTooLarge`] — is deliberately NOT
/// a self-heal trigger: an invalid signature is not evidence of local
/// staleness. On the self-heal path every re-downloaded object (the whole
/// chain, not just the delta) is re-verified, since self-heal only runs
/// when the local store's contents are already suspect.
///
/// # Errors
/// [`DispatchError::RemoteMissingObject`] if the closure is still
/// incomplete after self-heal (or immediately, when self-heal doesn't
/// apply); pack-decode / store errors from the unpack; download errors
/// from the self-heal retry; [`DispatchError::UnsignedOrInvalidObject`]
/// if `require_signed` is `true` and a newly-fetched object's signature
/// does not verify.
pub(crate) fn apply_fetched_chain(
    store: &ObjectStore,
    tx: &dyn Transport,
    remote: &str,
    branch: &str,
    fetched: FetchedChain,
    tip: Hash,
    applied: &mut AppliedPacks,
    require_signed: bool,
) -> Result<(), DispatchError> {
    let FetchedChain { chain, downloaded } = fetched;
    let skipped = chain.len() - downloaded.len();
    let stored = unpack_downloaded_packs(store, downloaded, applied)?;

    // Closure completeness. With skips this is the sole guarantee the
    // store is whole, and a `RemoteMissingObject` here is the ONLY
    // self-heal trigger.
    match super::verify_closure_present(store, &tip) {
        Ok(()) => verify_new_object_signatures(store, &stored, require_signed),
        Err(e @ DispatchError::RemoteMissingObject(_)) if skipped > 0 => {
            eprintln!(
                "note: applied-packs record for remote '{remote}' branch '{branch}' looks stale ({e}); clearing it and re-fetching the full pack chain"
            );
            // Clear the suspected-stale record in memory and retry the whole
            // chain with no skips. This is infallible — the caller's single
            // end-of-fetch persist durably reflects the post-heal state.
            // Clearing intentionally discards digests inserted by other
            // branches earlier in this same fetch: the store wipe that trips
            // self-heal makes those entries just as stale.
            applied.clear();
            let downloaded = download_pack_chain(tx, branch, &chain, applied)?;
            let stored = unpack_downloaded_packs(store, downloaded, applied)?;
            super::verify_closure_present(store, &tip)?;
            verify_new_object_signatures(store, &stored, require_signed)
        }
        Err(e) => Err(e),
    }
}

/// Verify the Ed25519 signature on every commit/remix/tag in `stored` —
/// the digests [`unpack_downloaded_packs`] just wrote, i.e. the objects
/// this fetch actually introduced (issue #692). Uses the exact same check
/// `mkit verify <rev>` runs manually
/// ([`mkit_core::sign::verify_commit`]/`verify_remix`/`verify_tag`), so
/// clone/pull/fetch cannot publish a remote-tracking ref to a hostile
/// remote's unsigned or forged history (THREAT-MODEL §3.1) without the
/// caller explicitly opting out. Blob/Tree/ChunkedBlob/Delta objects carry
/// no signature and are skipped.
///
/// `require_signed = false` (the explicit opt-out) short-circuits to
/// `Ok(())` without reading any object — a no-op, not a "verify but
/// ignore the result".
fn verify_new_object_signatures(
    store: &ObjectStore,
    stored: &[Hash],
    require_signed: bool,
) -> Result<(), DispatchError> {
    if !require_signed {
        return Ok(());
    }
    for h in stored {
        let obj = store.read_object(h)?;
        let result = match &obj {
            Object::Commit(c) => verify_commit(c),
            Object::Remix(r) => verify_remix(r),
            Object::Tag(t) => verify_tag(t),
            Object::Blob(_) | Object::Tree(_) | Object::ChunkedBlob(_) | Object::Delta(_) => {
                continue;
            }
        };
        if let Err(e) = result {
            return Err(DispatchError::UnsignedOrInvalidObject {
                hash: hash::to_hex(h),
                reason: e.to_string(),
            });
        }
    }
    Ok(())
}

/// Download every key in `chain` not already recorded in `applied`,
/// returning each pack's key paired with its raw bytes, in chain order.
/// Pure network I/O — never touches the local object store or `applied`
/// (skipping is a read-only check; recording a pack as applied happens
/// only once it is actually unpacked, in [`unpack_downloaded_packs`]).
fn download_pack_chain(
    tx: &dyn Transport,
    branch: &str,
    chain: &[Hash],
    applied: &AppliedPacks,
) -> Result<Vec<(PackKey, Vec<u8>)>, DispatchError> {
    let mut out = Vec::new();
    for &pk in chain {
        if crate::signal::is_shutdown() {
            return Err(DispatchError::Interrupted);
        }
        let key = PackKey::from_hash(pk);
        if applied.contains(&key) {
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
                return Err(DispatchError::AdvertisedPackMissing {
                    branch: branch.to_owned(),
                    pack: mkit_core::hash::to_hex(&pk),
                });
            }
            Err(e) => return Err(e.into()),
        };
        out.push((key, pack));
    }
    Ok(out)
}

/// Unpack previously-downloaded packs (see [`download_pack_chain`]) into
/// `store`, in order, inserting each newly-applied digest into `applied`
/// as soon as its pack is successfully read. Pure local disk I/O — see
/// [`apply_fetched_chain`] for the repo-lock contract this must run under.
///
/// Returns every hash newly written to `store` across all unpacked packs,
/// in pack order — the exact set [`apply_fetched_chain`] hands to
/// [`verify_new_object_signatures`] (issue #692) so the post-fetch
/// signature check costs proportional to what THIS call fetched, not the
/// tip's whole reachable closure.
fn unpack_downloaded_packs(
    store: &ObjectStore,
    downloaded: Vec<(PackKey, Vec<u8>)>,
    applied: &mut AppliedPacks,
) -> Result<Vec<Hash>, DispatchError> {
    let mut stored = Vec::new();
    for (key, pack) in downloaded {
        if crate::signal::is_shutdown() {
            return Err(DispatchError::Interrupted);
        }
        let report = PackReader::read(&pack, store)?;
        // Honest progress (#711): real objects just landed in the local
        // store, counted straight from the pack's own `UnpackReport` —
        // never an estimate. See `crate::progress`.
        let unpacked = (report.raw_count + report.delta_count) as usize;
        if unpacked > 0 {
            crate::progress::report(crate::progress::Event::ObjectsUnpacked(unpacked));
        }
        stored.extend(report.stored);
        applied.insert(&key);
    }
    Ok(stored)
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
    fn probe_chain_depth_counts_nodes_and_matches_resolve_pack_chain() {
        let tx = MemoryTransport::new();
        let n1 = h("n1");
        let n2 = h("n2");
        let n3 = h("n3");
        put_node(&tx, n1, None, &[h("pack1")]);
        put_node(&tx, n2, Some(n1), &[h("pack2")]);
        put_node(&tx, n3, Some(n2), &[h("pack3")]);

        let probed = probe_chain(&tx, "main", n3).unwrap();
        assert_eq!(probed.depth, 3);

        // Same node count as the packs resolve_pack_chain flattens, and the
        // packs themselves come back oldest-first — matching `probe_chain`'s
        // own `packs` field too.
        let packs = resolve_pack_chain(&tx, "main", n3).unwrap();
        assert_eq!(packs, vec![h("pack1"), h("pack2"), h("pack3")]);
        assert_eq!(probed.depth, packs.len());
        assert_eq!(probed.packs, packs);
        assert_eq!(probed.head, n3);
    }

    #[test]
    fn probe_chain_depth_of_a_single_node_chain_is_one() {
        let tx = MemoryTransport::new();
        let solo = h("solo");
        put_node(&tx, solo, None, &[h("pack-solo")]);
        assert_eq!(probe_chain(&tx, "main", solo).unwrap().depth, 1);
    }

    #[test]
    fn probe_chain_errors_on_a_cycle_exactly_like_resolve_pack_chain() {
        let tx = MemoryTransport::new();
        let a = h("cycle-a");
        let b = h("cycle-b");
        // a -> b -> a: only reachable via hand-built (non-content-addressed)
        // nodes, exercising the shared cycle guard in `walk_pack_chain`.
        put_node(&tx, a, Some(b), &[h("pack-a")]);
        put_node(&tx, b, Some(a), &[h("pack-b")]);

        assert!(matches!(
            probe_chain(&tx, "main", a).unwrap_err(),
            DispatchError::PackChainInvalid { .. }
        ));
        assert!(matches!(
            resolve_pack_chain(&tx, "main", a).unwrap_err(),
            DispatchError::PackChainInvalid { .. }
        ));
    }

    #[test]
    fn probe_chain_errors_on_an_undownloadable_node_like_resolve_pack_chain() {
        let tx = MemoryTransport::new();
        let ghost = h("never-uploaded");
        assert!(matches!(
            probe_chain(&tx, "main", ghost).unwrap_err(),
            DispatchError::PackChainInvalid { .. }
        ));
        assert!(matches!(
            resolve_pack_chain(&tx, "main", ghost).unwrap_err(),
            DispatchError::PackChainInvalid { .. }
        ));
    }
}
