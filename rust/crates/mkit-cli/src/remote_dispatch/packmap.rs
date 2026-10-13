//! The push side of the packmap-chain transfer layer.
//!
//! A branch's transfer history is a content-addressed singly-linked list of
//! packlist nodes, advertised through the `refs/mkit/packmap/<branch>`
//! metadata ref. Each push appends one node (a `prev` pointer plus the
//! pack(s) it added). The fetch side (chain walk, download, unpack, signature
//! verification) lives in `mkit-sync`; this module keeps [`advance_packmap`],
//! which chains new packs on, gated by a CAS on the packmap ref, and shares
//! the chain walk through `mkit_sync::packmap`.

use mkit_core::hash::Hash;
use mkit_core::protocol::{AdvanceOutcome, CommitOutcome, PackKey, Transport, TransportError};
use mkit_core::refs;
#[cfg(test)]
use mkit_core::transfer;
use mkit_core::transfer::packmap::{ChainState, PlanError, plan_advance};
use mkit_sync::TransportSource;
use mkit_sync::packmap::{flatten_oldest_first, packmap_ref, walk_pack_chain};

use super::{CliObserver, DispatchError};

/// Number of read-modify-write attempts when chaining a new pack onto the
/// packmap. Each conflict means another pusher advanced the packmap; we
/// re-read and retry. Exhaustion (sustained contention) aborts the push
/// *before* the branch ref moves — see [`advance_packmap`].
const PACKMAP_CAS_ATTEMPTS: u32 = 8;

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
/// Walk a branch's packlist chain from `head_key` and return the flat
/// **oldest-first** list of pack keys it references. See
/// [`mkit_sync::packmap::walk_pack_chain`] for the walk / integrity-check
/// semantics.
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
    let nodes = walk_pack_chain(&TransportSource::new(tx), &CliObserver, branch, head_key)?;
    let depth = nodes.len();
    let packs = flatten_oldest_first(nodes);
    Ok(ResolvedChain {
        head: head_key,
        depth,
        packs,
    })
}

/// The push-side action, frozen before pack construction and CAS retries.
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
    /// Reset to a full-closure node. Requires atomic advance and a conditioned
    /// head lease. Existing fetchers download the full closure again, and old
    /// pack digests remain in their applied-pack records until pruned.
    ResetSelfContained,
}

/// Advertise new packs in apply order and then move the branch head.
///
/// The shared planner validates idempotency, encodes the node, and supplies its
/// CAS condition. This driver owns chain reads, uploads and eight CAS attempts.
/// A transactional transport commits both refs together; the ordered default
/// commits packmap first, so the head never precedes its reconstructing packs.
///
/// Append validates the entire prior chain. A broken chain permits a reset only
/// for self-contained packs; deltas need its bases and fail with the original
/// error. Transient failures propagate. Proactive resets skip validation and
/// require atomic advance plus a conditioned head lease because a reset is not
/// a superset of the old chain. The caller chooses rollover before pack planning
/// and freezes that choice across retries; concurrent appends can temporarily
/// exceed the depth threshold until the next push resets it.
///
/// `resolved` reuses the pre-plan walk only while its head matches the live ref.
/// A stale probe or lost CAS race requires a fresh walk. An idempotent retry only
/// writes the head. Lost-response conflicts are disambiguated by reading it.
pub(crate) fn advance_packmap(
    tx: &dyn Transport,
    branch: &str,
    pack_keys: &[Hash],
    action: ChainAction,
    resolved: Option<ResolvedChain>,
    head_condition: refs::RefWriteCondition,
    tip: Hash,
) -> Result<(), DispatchError> {
    debug_assert!(
        !pack_keys.is_empty(),
        "advance_packmap requires at least one pack key — callers only reach this with a \
         non-empty plan"
    );
    let packmap_name = packmap_ref(branch);
    let head_name = format!("refs/heads/{branch}");
    // A cached walk is consumed once; retries resolve the live chain again.
    // The caller's append/reset decision stays frozen across attempts.
    let mut cached = resolved;
    for _ in 0..PACKMAP_CAS_ATTEMPTS {
        if crate::signal::is_shutdown() {
            return Err(DispatchError::Interrupted);
        }
        let prior = tx.read_ref(&packmap_name)?;
        // Decide the new node's `prev`. A re-baseline always resets
        // (skipping prior-chain validation); otherwise validate the WHOLE
        // prior chain before deciding to append vs. reset.
        let state = match action {
            ChainAction::ResetSelfContained => {
                // A reset can discard old closure: both conditioned refs must
                // commit atomically. Keep these guards for direct callers.
                debug_assert!(
                    tx.supports_atomic_advance(),
                    "re-baseline reset requires a transactional advance_refs (mkit #521)"
                );
                debug_assert!(
                    !matches!(head_condition, refs::RefWriteCondition::Any),
                    "re-baseline reset must not run with an `Any` head condition — the \
                     ordered advance_refs fallback would strand the head (mkit #521)"
                );
                ChainState::Reset { prior }
            }
            ChainAction::Append { self_contained } => match prior {
                None => ChainState::Missing,
                Some(p) => {
                    // Reuse only a walk matching the ref read by this attempt.
                    let packs = match cached.take() {
                        Some(c) if c.head == p => Ok(c.packs),
                        _ => resolve_pack_chain(tx, branch, p),
                    };
                    match packs {
                        Ok(packs) => ChainState::Append {
                            head: p,
                            packs: packs.into_iter().collect(),
                        },
                        // Broken chain: a self-contained pack can reset to escape it;
                        // a delta push must block (its bases live in the broken tail).
                        // Transient transport errors propagate (don't reset on a blip).
                        Err(DispatchError::PackChainInvalid { .. }) if self_contained => {
                            ChainState::Reset { prior }
                        }
                        Err(e) => return Err(e),
                    }
                }
            },
        };
        let node = plan_advance(state, pack_keys, None).map_err(|error| match error {
            PlanError::Packlist(error) => DispatchError::from(error),
            PlanError::NodeTooLarge => unreachable!("no node-size limit configured"),
        })?;
        let Some(node) = node else {
            return commit_head(tx, &head_name, head_condition, &tip, branch);
        };
        tx.upload_blob_via_ref(&node.bytes, &PackKey::from_hash(node.key), &head_name)
            .map_err(|error| super::repository_operation_error(tx, error))?;
        let commit_keys: Vec<PackKey> = pack_keys
            .iter()
            .copied()
            .map(PackKey::from_hash)
            .chain(std::iter::once(PackKey::from_hash(node.key)))
            .collect();
        // Commit the packmap AND the head together (#408). A transactional
        // transport applies both atomically; the default does packmap-then-
        // head — still safe, the head never lands past an unadvanced packmap.
        match tx
            .advance_refs_committing(
                &head_name,
                head_condition,
                &tip,
                &packmap_name,
                node.condition,
                &node.key,
                &commit_keys,
            )
            .map_err(|error| super::repository_operation_error(tx, error))?
        {
            CommitOutcome::Advanced(AdvanceOutcome::Committed) => return Ok(()),
            // Another pusher advanced the packmap under us — re-read and retry.
            CommitOutcome::Advanced(AdvanceOutcome::PackmapConflict) => {}
            // The head precondition failed. Either the branch moved under
            // us (the push is stale) or the retry ladder re-issued a write
            // that had already landed (SPEC-TRANSPORT §7) — disambiguate.
            CommitOutcome::Advanced(AdvanceOutcome::HeadConflict) => {
                return head_conflict(tx, &head_name, &tip, branch);
            }
            CommitOutcome::TicketRejected => {
                if tx.read_ref(&head_name)? == Some(tip) {
                    return Ok(());
                }
                return Err(DispatchError::TicketRejected);
            }
            CommitOutcome::PacklistNotInRepository => {
                if tx.read_ref(&head_name)? == Some(tip) {
                    return Ok(());
                }
                return Err(DispatchError::PacklistNotInRepository);
            }
            CommitOutcome::DeltaBaseUnavailable => return Err(DispatchError::DeltaBaseUnavailable),
            _ => return Err(DispatchError::Transport(TransportError::InvalidResponse)),
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
        Err(TransportError::RefConflict) => head_conflict(tx, head_name, tip, branch),
        Err(e) => Err(super::repository_operation_error(tx, e)),
    }
}

/// Resolve a failed head precondition (`RefConflict` from `update_ref`,
/// `HeadConflict` from `advance_refs`) per SPEC-TRANSPORT §7: the retry
/// ladder may have re-issued a write whose first attempt landed, so the
/// conflict can be our own write. Re-read the head; if it already holds
/// `tip` the push landed, otherwise it is a genuine non-fast-forward.
///
/// Only the head is checked. Whoever moved the head to `tip` also advanced
/// the packmap to reconstruct it first (packmap-then-head, or both at once),
/// so a head at `tip` already satisfies the push's invariant even if a later
/// pusher has since moved the packmap past our node.
fn head_conflict(
    tx: &dyn Transport,
    head_name: &str,
    tip: &Hash,
    branch: &str,
) -> Result<(), DispatchError> {
    let current = tx
        .read_ref(head_name)
        .map_err(|error| super::repository_operation_error(tx, error))?;
    if current == Some(*tip) {
        return Ok(());
    }
    Err(DispatchError::NonFastForwardPush {
        branch: branch.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mkit_core::hash;
    use mkit_transport_memory::MemoryTransport;

    fn h(seed: &str) -> Hash {
        hash::hash(seed.as_bytes())
    }

    /// Publish a real content-addressed node. Corruption tests insert
    /// forged bytes explicitly instead of teaching valid fixtures wrong IDs.
    fn put_node(tx: &MemoryTransport, prev: Option<Hash>, packs: &[Hash]) -> Hash {
        let bytes = transfer::encode_packlist(prev, packs).unwrap();
        let key = hash::hash(&bytes);
        tx.upload_blob(&bytes, &PackKey::from_hash(key)).unwrap();
        key
    }

    #[test]
    fn probe_chain_depth_counts_nodes_and_matches_resolve_pack_chain() {
        let tx = MemoryTransport::new();
        let n1 = put_node(&tx, None, &[h("pack1")]);
        let n2 = put_node(&tx, Some(n1), &[h("pack2")]);
        let n3 = put_node(&tx, Some(n2), &[h("pack3")]);

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
        let solo = put_node(&tx, None, &[h("pack-solo")]);
        assert_eq!(probe_chain(&tx, "main", solo).unwrap().depth, 1);
    }

    #[test]
    fn probe_chain_errors_on_a_cycle_exactly_like_resolve_pack_chain() {
        let tx = MemoryTransport::new();
        let a = h("cycle-a");
        let b = h("cycle-b");
        // a -> b -> a: only reachable via hand-built (non-content-addressed)
        // nodes, exercising the shared cycle guard in `walk_pack_chain`.
        let a_bytes = transfer::encode_packlist(Some(b), &[h("pack-a")]).unwrap();
        let b_bytes = transfer::encode_packlist(Some(a), &[h("pack-b")]).unwrap();
        tx.upload_blob(&a_bytes, &PackKey::from_hash(a)).unwrap();
        tx.upload_blob(&b_bytes, &PackKey::from_hash(b)).unwrap();

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

    // ---- advance_packmap — multi-key (issue #831) -------------------

    fn decode_node_at(tx: &MemoryTransport, key: Hash) -> transfer::PackListNode {
        let bytes = tx.download_blob(&PackKey::from_hash(key)).unwrap();
        transfer::decode_packlist(&bytes).unwrap()
    }

    #[test]
    fn advance_packmap_multi_key_first_push_writes_one_node_in_order() {
        let tx = MemoryTransport::new();
        let (k1, k2, k3) = (h("k1"), h("k2"), h("k3"));
        let tip = h("tip");

        advance_packmap(
            &tx,
            "main",
            &[k1, k2, k3],
            ChainAction::Append {
                self_contained: true,
            },
            None,
            refs::RefWriteCondition::Missing,
            tip,
        )
        .unwrap();

        let pm_head = tx.read_ref(&packmap_ref("main")).unwrap().unwrap();
        let node = decode_node_at(&tx, pm_head);
        assert_eq!(node.prev, None, "first push has no prior chain");
        assert_eq!(
            node.packs,
            vec![k1, k2, k3],
            "all keys land on ONE node, in build/apply order"
        );
        assert_eq!(tx.read_ref("refs/heads/main").unwrap(), Some(tip));
    }

    #[test]
    fn advance_packmap_single_key_matches_pre_831_shape() {
        // Regression: the common case (a push that fits one pack) must
        // still produce exactly the one-pack node it always did.
        let tx = MemoryTransport::new();
        let k1 = h("only-key");
        let tip = h("tip");

        advance_packmap(
            &tx,
            "main",
            &[k1],
            ChainAction::Append {
                self_contained: true,
            },
            None,
            refs::RefWriteCondition::Missing,
            tip,
        )
        .unwrap();

        let pm_head = tx.read_ref(&packmap_ref("main")).unwrap().unwrap();
        assert_eq!(decode_node_at(&tx, pm_head).packs, vec![k1]);
    }

    #[test]
    fn advance_packmap_is_idempotent_when_every_key_already_chained() {
        // A retried push (e.g. a lost head-CAS race after the packmap
        // already landed) must not append a redundant node when the
        // prior chain already carries every key this attempt would add
        // — only the head still needs to move.
        let tx = MemoryTransport::new();
        let (k1, k2, k3) = (h("k1"), h("k2"), h("k3"));
        let prior_head = put_node(&tx, None, &[k1, k2, k3]);
        tx.update_ref(
            &packmap_ref("main"),
            refs::RefWriteCondition::Missing,
            &prior_head,
        )
        .unwrap();
        let tip = h("tip");

        advance_packmap(
            &tx,
            "main",
            &[k1, k2, k3],
            ChainAction::Append {
                self_contained: true,
            },
            None,
            refs::RefWriteCondition::Missing,
            tip,
        )
        .unwrap();

        assert_eq!(
            tx.read_ref(&packmap_ref("main")).unwrap(),
            Some(prior_head),
            "idempotent retry must not write a new node"
        );
        assert_eq!(tx.read_ref("refs/heads/main").unwrap(), Some(tip));
    }

    #[test]
    fn advance_packmap_appends_when_only_some_keys_already_chained() {
        // Partial overlap is NOT idempotency — a different push that
        // happened to produce one identical pack is not the same push
        // retried. A fresh node carrying the full new set is appended.
        let tx = MemoryTransport::new();
        let (k1, k2, k3) = (h("k1"), h("k2"), h("k3"));
        let prior_head = put_node(&tx, None, &[k1]);
        tx.update_ref(
            &packmap_ref("main"),
            refs::RefWriteCondition::Missing,
            &prior_head,
        )
        .unwrap();
        let tip = h("tip");

        advance_packmap(
            &tx,
            "main",
            &[k1, k2, k3],
            ChainAction::Append {
                self_contained: true,
            },
            None,
            refs::RefWriteCondition::Missing,
            tip,
        )
        .unwrap();

        let new_head = tx.read_ref(&packmap_ref("main")).unwrap().unwrap();
        assert_ne!(new_head, prior_head, "a new node must be appended");
        let node = decode_node_at(&tx, new_head);
        assert_eq!(node.prev, Some(prior_head));
        assert_eq!(node.packs, vec![k1, k2, k3]);

        // The chain still resolves and flattens both nodes' packs.
        assert_eq!(
            resolve_pack_chain(&tx, "main", new_head).unwrap(),
            vec![k1, k1, k2, k3],
        );
    }

    // ---- lost-response retries — SPEC-TRANSPORT §7 (MKIT-58) --------

    /// How [`LostResponseTransport`] models the retry ladder re-issuing a
    /// CAS write whose first attempt landed but whose response was lost.
    #[derive(Clone, Copy)]
    enum Reissue {
        /// `update_ref` on a `refs/heads/` name is applied twice and the
        /// caller sees only the second result. `advance_refs` keeps the
        /// ordered packmap-then-head default, so the re-issued head write
        /// surfaces as `AdvanceOutcome::HeadConflict` after the packmap
        /// write landed.
        HeadUpdate,
        /// `advance_refs` is transactional and applied twice; the caller
        /// sees only the second outcome (`PackmapConflict`: both refs
        /// already moved).
        Advance,
        /// Nothing is re-issued: a plain transport, for the genuine
        /// non-fast-forward cases.
        None,
    }

    struct LostResponseTransport {
        inner: MemoryTransport,
        reissue: Reissue,
    }

    impl LostResponseTransport {
        fn new(reissue: Reissue) -> Self {
            Self {
                inner: MemoryTransport::new(),
                reissue,
            }
        }

        fn atomic_advance_once(
            &self,
            head: (&str, refs::RefWriteCondition, &Hash),
            packmap: (&str, refs::RefWriteCondition, &Hash),
        ) -> Result<AdvanceOutcome, TransportError> {
            fn holds(c: refs::RefWriteCondition, cur: Option<Hash>) -> bool {
                match c {
                    refs::RefWriteCondition::Any => true,
                    refs::RefWriteCondition::Missing => cur.is_none(),
                    refs::RefWriteCondition::Match(h) => cur == Some(h),
                }
            }
            if !holds(packmap.1, self.inner.read_ref(packmap.0)?) {
                return Ok(AdvanceOutcome::PackmapConflict);
            }
            if !holds(head.1, self.inner.read_ref(head.0)?) {
                return Ok(AdvanceOutcome::HeadConflict);
            }
            self.inner.update_ref(packmap.0, packmap.1, packmap.2)?;
            self.inner.update_ref(head.0, head.1, head.2)?;
            Ok(AdvanceOutcome::Committed)
        }
    }

    impl Transport for LostResponseTransport {
        fn upload_pack(&self, bytes: &[u8], key: &PackKey) -> Result<(), TransportError> {
            self.inner.upload_pack(bytes, key)
        }
        fn download_pack(&self, key: &PackKey) -> Result<Vec<u8>, TransportError> {
            self.inner.download_pack(key)
        }
        fn pack_exists(&self, key: &PackKey) -> Result<bool, TransportError> {
            self.inner.pack_exists(key)
        }
        fn upload_blob(&self, bytes: &[u8], key: &PackKey) -> Result<(), TransportError> {
            self.inner.upload_blob(bytes, key)
        }
        fn download_blob(&self, key: &PackKey) -> Result<Vec<u8>, TransportError> {
            self.inner.download_blob(key)
        }
        fn update_ref(
            &self,
            name: &str,
            condition: refs::RefWriteCondition,
            hash: &Hash,
        ) -> Result<(), TransportError> {
            if matches!(self.reissue, Reissue::HeadUpdate) && name.starts_with("refs/heads/") {
                // First attempt lands; its response is lost.
                let _ = self.inner.update_ref(name, condition, hash);
            }
            self.inner.update_ref(name, condition, hash)
        }
        fn read_ref(&self, name: &str) -> Result<Option<Hash>, TransportError> {
            self.inner.read_ref(name)
        }
        fn list_refs(&self, prefix: &str) -> Result<Vec<refs::Ref>, TransportError> {
            self.inner.list_refs(prefix)
        }
        fn advance_refs(
            &self,
            head_ref: &str,
            head_condition: refs::RefWriteCondition,
            head_value: &Hash,
            packmap_ref: &str,
            packmap_condition: refs::RefWriteCondition,
            packmap_value: &Hash,
        ) -> Result<AdvanceOutcome, TransportError> {
            let head = (head_ref, head_condition, head_value);
            let packmap = (packmap_ref, packmap_condition, packmap_value);
            match self.reissue {
                Reissue::Advance => {
                    // First attempt lands; its response is lost.
                    let _ = self.atomic_advance_once(head, packmap)?;
                    self.atomic_advance_once(head, packmap)
                }
                Reissue::HeadUpdate | Reissue::None => {
                    // The trait's ordered default: packmap, then head.
                    match self.update_ref(packmap_ref, packmap_condition, packmap_value) {
                        Ok(()) => {}
                        Err(TransportError::RefConflict) => {
                            return Ok(AdvanceOutcome::PackmapConflict);
                        }
                        Err(e) => return Err(e),
                    }
                    match self.update_ref(head_ref, head_condition, head_value) {
                        Ok(()) => Ok(AdvanceOutcome::Committed),
                        Err(TransportError::RefConflict) => Ok(AdvanceOutcome::HeadConflict),
                        Err(e) => Err(e),
                    }
                }
            }
        }
        fn supports_atomic_advance(&self) -> bool {
            matches!(self.reissue, Reissue::Advance)
        }
    }

    fn advance_first_push(
        tx: &dyn Transport,
        keys: &[Hash],
        tip: Hash,
    ) -> Result<(), DispatchError> {
        advance_packmap(
            tx,
            "main",
            keys,
            ChainAction::Append {
                self_contained: true,
            },
            None,
            refs::RefWriteCondition::Missing,
            tip,
        )
    }

    #[test]
    fn advance_packmap_head_conflict_from_reissued_head_write_is_success() {
        // Ordered advance: the packmap write lands, the head write lands
        // but its response is lost, and the ladder's re-issue reports
        // `HeadConflict` for our own write. SPEC-TRANSPORT §7: read the
        // head; it holds our tip, so the push landed.
        let tx = LostResponseTransport::new(Reissue::HeadUpdate);
        let tip = h("tip");
        advance_first_push(&tx, &[h("k1")], tip).unwrap();
        assert_eq!(tx.read_ref("refs/heads/main").unwrap(), Some(tip));
        let pm = tx.read_ref(&packmap_ref("main")).unwrap().unwrap();
        assert_eq!(decode_node_at(&tx.inner, pm).packs, vec![h("k1")]);
    }

    #[test]
    fn advance_packmap_reissued_atomic_advance_is_success() {
        // Transactional advance: the first attempt commits both refs and
        // its response is lost. The re-issue reports `PackmapConflict`; the
        // re-read finds our node already chained, so only the head write
        // remains, and that write's `RefConflict` is our own landed head.
        let tx = LostResponseTransport::new(Reissue::Advance);
        let tip = h("tip");
        advance_first_push(&tx, &[h("k1"), h("k2")], tip).unwrap();
        assert_eq!(tx.read_ref("refs/heads/main").unwrap(), Some(tip));
        let pm = tx.read_ref(&packmap_ref("main")).unwrap().unwrap();
        let node = decode_node_at(&tx.inner, pm);
        assert_eq!(node.prev, None, "no redundant node was appended");
        assert_eq!(node.packs, vec![h("k1"), h("k2")]);
    }

    #[test]
    fn advance_packmap_reissued_rebaseline_reset_is_success() {
        // A re-baseline reset re-issued after it landed: the retry loop
        // re-reads the packmap (now our node) and CASes off it, and the
        // head precondition then fails against our own landed tip.
        let tx = LostResponseTransport::new(Reissue::Advance);
        let old = h("old-tip");
        let prior = put_node(&tx.inner, None, &[h("old-pack")]);
        tx.inner
            .update_ref(
                &packmap_ref("main"),
                refs::RefWriteCondition::Missing,
                &prior,
            )
            .unwrap();
        tx.inner
            .update_ref("refs/heads/main", refs::RefWriteCondition::Missing, &old)
            .unwrap();
        let tip = h("tip");
        advance_packmap(
            &tx,
            "main",
            &[h("full")],
            ChainAction::ResetSelfContained,
            None,
            refs::RefWriteCondition::Match(old),
            tip,
        )
        .unwrap();
        assert_eq!(tx.read_ref("refs/heads/main").unwrap(), Some(tip));
    }

    #[test]
    fn advance_packmap_genuine_head_conflict_stays_non_fast_forward() {
        // Another writer moved the head to a different commit: the re-read
        // does not find our tip, so the push is still rejected.
        for reissue in [Reissue::None, Reissue::Advance] {
            let tx = LostResponseTransport::new(reissue);
            let theirs = h("their-tip");
            tx.inner
                .update_ref("refs/heads/main", refs::RefWriteCondition::Missing, &theirs)
                .unwrap();
            let err = advance_first_push(&tx, &[h("k1")], h("tip")).unwrap_err();
            assert!(
                matches!(err, DispatchError::NonFastForwardPush { ref branch } if branch == "main"),
                "{err:?}"
            );
            assert_eq!(tx.read_ref("refs/heads/main").unwrap(), Some(theirs));
        }
    }

    #[test]
    fn commit_head_reissued_write_is_success() {
        let tx = LostResponseTransport::new(Reissue::HeadUpdate);
        let tip = h("tip");
        commit_head(
            &tx,
            "refs/heads/main",
            refs::RefWriteCondition::Missing,
            &tip,
            "main",
        )
        .unwrap();
        assert_eq!(tx.read_ref("refs/heads/main").unwrap(), Some(tip));
    }

    #[test]
    fn commit_head_genuine_conflict_stays_non_fast_forward() {
        let tx = LostResponseTransport::new(Reissue::None);
        let theirs = h("their-tip");
        tx.inner
            .update_ref("refs/heads/main", refs::RefWriteCondition::Missing, &theirs)
            .unwrap();
        let err = commit_head(
            &tx,
            "refs/heads/main",
            refs::RefWriteCondition::Match(h("stale-lease")),
            &h("tip"),
            "main",
        )
        .unwrap_err();
        assert!(
            matches!(err, DispatchError::NonFastForwardPush { ref branch } if branch == "main"),
            "{err:?}"
        );
        assert_eq!(tx.read_ref("refs/heads/main").unwrap(), Some(theirs));
    }
}
