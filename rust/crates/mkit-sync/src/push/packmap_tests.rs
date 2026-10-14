//! Existing push packmap regression fixtures, run through the source boundary.

use super::packmap::{self, ChainAction, ResolvedChain};
use super::{PushContext, PushError};
use crate::packmap::packmap_ref;
use crate::{NoopObserver, SyncError, TransportSource};
use mkit_core::hash::Hash;
use mkit_core::protocol::{AdvanceOutcome, PackKey, Transport, TransportError};
use mkit_core::{refs, transfer};

fn probe_chain(tx: &dyn Transport, branch: &str, head: Hash) -> Result<ResolvedChain, PushError> {
    let source = TransportSource::new(tx);
    let context = PushContext {
        source: &source,
        observer: &NoopObserver,
    };
    packmap::probe_chain(&context, branch, head)
}

fn resolve_pack_chain(
    tx: &dyn Transport,
    branch: &str,
    head: Hash,
) -> Result<Vec<Hash>, PushError> {
    let source = TransportSource::new(tx);
    let context = PushContext {
        source: &source,
        observer: &NoopObserver,
    };
    packmap::resolve_pack_chain(&context, branch, head)
}

#[allow(clippy::too_many_arguments)]
fn advance_packmap(
    tx: &dyn Transport,
    branch: &str,
    keys: &[Hash],
    action: ChainAction,
    resolved: Option<ResolvedChain>,
    condition: refs::RefWriteCondition,
    tip: Hash,
) -> Result<(), PushError> {
    let source = TransportSource::new(tx);
    let context = PushContext {
        source: &source,
        observer: &NoopObserver,
    };
    packmap::advance_packmap(&context, branch, keys, action, resolved, condition, tip)
}

fn commit_head(
    tx: &dyn Transport,
    name: &str,
    condition: refs::RefWriteCondition,
    tip: &Hash,
    branch: &str,
) -> Result<(), PushError> {
    let source = TransportSource::new(tx);
    let context = PushContext {
        source: &source,
        observer: &NoopObserver,
    };
    packmap::commit_head(&context, name, condition, tip, branch)
}

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
        PushError::Sync(SyncError::PackChainInvalid { .. })
    ));
    assert!(matches!(
        resolve_pack_chain(&tx, "main", a).unwrap_err(),
        PushError::Sync(SyncError::PackChainInvalid { .. })
    ));
}

#[test]
fn probe_chain_errors_on_an_undownloadable_node_like_resolve_pack_chain() {
    let tx = MemoryTransport::new();
    let ghost = h("never-uploaded");
    assert!(matches!(
        probe_chain(&tx, "main", ghost).unwrap_err(),
        PushError::Sync(SyncError::PackChainInvalid { .. })
    ));
    assert!(matches!(
        resolve_pack_chain(&tx, "main", ghost).unwrap_err(),
        PushError::Sync(SyncError::PackChainInvalid { .. })
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

// ---- lost-response retries — SPEC-TRANSPORT §7 -----------------

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
    /// Atomic advance without a lost response, for recorded planner fixtures.
    Atomic,
    /// Nothing is re-issued: a plain transport, for the genuine
    /// non-fast-forward cases.
    None,
}

struct LostResponseTransport {
    inner: MemoryTransport,
    reissue: Reissue,
    capture: std::sync::Mutex<Vec<(refs::RefWriteCondition, Hash, refs::RefWriteCondition, Hash)>>,
    race: Option<Hash>,
}

impl LostResponseTransport {
    fn new(reissue: Reissue) -> Self {
        Self {
            inner: MemoryTransport::new(),
            reissue,
            capture: std::sync::Mutex::new(Vec::new()),
            race: None,
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
        let first = {
            let mut capture = self.capture.lock().unwrap();
            capture.push((
                head_condition,
                *head_value,
                packmap_condition,
                *packmap_value,
            ));
            capture.len() == 1
        };
        if first && let Some(race) = self.race {
            self.inner
                .update_ref(packmap_ref, refs::RefWriteCondition::Any, &race)?;
            return Ok(AdvanceOutcome::PackmapConflict);
        }
        let head = (head_ref, head_condition, head_value);
        let packmap = (packmap_ref, packmap_condition, packmap_value);
        match self.reissue {
            Reissue::Atomic => self.atomic_advance_once(head, packmap),
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
        matches!(self.reissue, Reissue::Advance | Reissue::Atomic)
    }
}

/// Recorded against the former driver as well as the shared planner.
#[test]
#[allow(clippy::too_many_lines)] // Keep the capture cases and assertions together.
fn packmap_driver_capture_matrix() {
    let keys: Vec<Hash> = (1..=2)
        .map(|salt| {
            let bytes = mkit_core::serialize::serialize(&mkit_core::object::Object::Blob(
                mkit_core::object::Blob {
                    data: vec![salt; 10],
                },
            ))
            .unwrap();
            let mut writer = mkit_core::pack::PackWriter::new();
            writer.push_raw(hash::hash(&bytes), &bytes).unwrap();
            mkit_core::pack::pack_key(&writer.finish().unwrap())
        })
        .collect();
    for (label, held, reset, conflict) in [
        ("first", None, false, false),
        ("append", Some(vec![[9; 32]]), false, false),
        ("partial", Some(vec![keys[0]]), false, false),
        ("full", Some(keys.clone()), false, false),
        ("rollover", Some(keys.clone()), true, false),
        ("changed-prior", Some(vec![[9; 32]]), false, true),
    ] {
        let mut tx = LostResponseTransport::new(Reissue::Atomic);
        let prior = held.as_ref().map(|packs| put_node(&tx.inner, None, packs));
        if let Some(prior) = prior {
            tx.inner
                .update_ref(
                    &packmap_ref("main"),
                    refs::RefWriteCondition::Missing,
                    &prior,
                )
                .unwrap();
        }
        let retry = prior.map(|head| put_node(&tx.inner, Some(head), &[[8; 32]]));
        if conflict {
            tx.race = retry;
        }
        tx.inner
            .update_ref(
                "refs/heads/main",
                refs::RefWriteCondition::Missing,
                &[6; 32],
            )
            .unwrap();
        advance_packmap(
            &tx,
            "main",
            &keys,
            if reset {
                ChainAction::ResetSelfContained
            } else {
                ChainAction::Append {
                    self_contained: true,
                }
            },
            None,
            refs::RefWriteCondition::Match([6; 32]),
            [4; 32],
        )
        .unwrap();
        assert_eq!(tx.read_ref("refs/heads/main").unwrap(), Some([4; 32]));
        let moves = tx.capture.lock().unwrap();
        if label == "full" {
            assert!(moves.is_empty());
            assert_eq!(tx.read_ref(&packmap_ref("main")).unwrap(), prior);
            continue;
        }
        assert_eq!(moves.len(), if conflict { 2 } else { 1 });
        for (attempt, (head_condition, head, condition, key)) in moves.iter().enumerate() {
            let current = if attempt == 0 { prior } else { retry };
            let bytes = tx.download_blob(&PackKey::from_hash(*key)).unwrap();
            let expected =
                transfer::encode_packlist(if reset { None } else { current }, &keys).unwrap();
            assert_eq!(bytes, expected, "{label}: bytes");
            assert_eq!(*key, mkit_core::pack::pack_key(&expected));
            assert_eq!(*head_condition, refs::RefWriteCondition::Match([6; 32]));
            assert_eq!(*head, [4; 32]);
            assert_eq!(
                *condition,
                current.map_or(
                    refs::RefWriteCondition::Missing,
                    refs::RefWriteCondition::Match
                )
            );
        }
    }
}

fn advance_first_push(tx: &dyn Transport, keys: &[Hash], tip: Hash) -> Result<(), PushError> {
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
            matches!(err, PushError::NonFastForwardPush { ref branch } if branch == "main"),
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
        matches!(err, PushError::NonFastForwardPush { ref branch } if branch == "main"),
        "{err:?}"
    );
    assert_eq!(tx.read_ref("refs/heads/main").unwrap(), Some(theirs));
}
