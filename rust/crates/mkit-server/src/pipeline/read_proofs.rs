//! Request-local structural evidence. Nothing here is an access decision.
use super::Authenticated;
use crate::http_objects::{HttpObjectsConfig, TakedownGate};
use crate::store::NamespaceStore;
use crate::store::publication::Publication;
use crate::{RepoId, ServerError, Value};
use mkit_core::{
    hash::Hash,
    object::{Object, ObjectType},
    ops::graph,
};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

// Independent hard ceilings even if an embedder configures a larger walk.
const MAX_PROOFS: usize = 50_000;
const MAX_EXPANSION_BYTES: usize = 1 << 20;

#[derive(Debug)]
struct Proof {
    parent: Option<Hash>,
    // Manifest ancestry needs live denial even when its chunk is the target.
    manifest_pack: Option<Hash>,
}

/// One selected-ref capture retained by a session. Identity is the `Arc`
/// pointer; every proofs reset drops it.
#[derive(Debug)]
pub(crate) struct Checkpoint {
    /// The ref name the capture is bound to.
    pub(crate) reference: String,
    /// Unpeeled anchor id (a tag ref keeps its tag id).
    pub(crate) tip: Hash,
    /// Full publication row read by the authoritative anchor.
    pub(crate) publication: Publication,
    /// Raw `[publication, ref]` values the anchor read.
    pub(crate) raw: Vec<Option<Value>>,
    /// `history_security` digest, captured after revision activation.
    pub(crate) security: Hash,
    /// Memo expiry at install.
    pub(crate) expires: u64,
}

/// Opaque handle to one selected-ref capture; identity is the generation.
/// The handle is not authority: it is valid only with the same session and
/// reader, the same credential scope, unchanged ref/publication/security
/// state and before its expiry.
#[derive(Debug, Clone)]
pub struct CaptureCheckpoint(pub(crate) Arc<Checkpoint>);

impl CaptureCheckpoint {
    /// The ref the capture is bound to.
    #[must_use]
    pub fn reference(&self) -> &str {
        &self.0.reference
    }
    /// The unpeeled anchor id captured.
    #[must_use]
    pub fn tip(&self) -> Hash {
        self.0.tip
    }
    /// Absolute Unix-ms expiry inherited from the session's memo: expiry at
    /// capture; the session's proofs may expire earlier (a later deadline
    /// only shrinks it), so validity is always rechecked.
    #[must_use]
    pub fn expires_at_ms(&self) -> u64 {
        self.0.expires
    }
}

/// How a decoded object reached a child row: its history role, or none for
/// content edges (trees, chunks, identity objects).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HistoryEdge {
    /// The captured selected-ref tip.
    Root,
    /// A commit/remix parent.
    Parent,
    /// A tag's target.
    TagTarget,
}

/// A decoded commit-like object's kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HistoryKind {
    Commit,
    Remix,
}

/// Per-row lineage: structural evidence only, never a permission.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Lineage {
    edge: Option<HistoryEdge>,
    decoded: Option<(HistoryKind, u64)>,
}

/// One row's recorded history link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HistoryLink {
    /// The object that introduced this row (`None` for a root).
    pub(crate) predecessor: Option<Hash>,
    /// The role that linked it.
    pub(crate) edge: HistoryEdge,
    /// Decoded commit/remix kind and timestamp, when recorded.
    pub(crate) decoded: Option<(HistoryKind, u64)>,
}

/// The history role `child` plays in `object`'s decoded edges, if any. A
/// tree entry that names a commit is a content edge: it records no role.
fn history_edge(object: &Object, child: Hash) -> Option<HistoryEdge> {
    match object {
        Object::Commit(c) if c.parents.contains(&child) => Some(HistoryEdge::Parent),
        Object::Remix(r) if r.parents.contains(&child) => Some(HistoryEdge::Parent),
        Object::Tag(t) if t.target == child => Some(HistoryEdge::TagTarget),
        _ => None,
    }
}

#[derive(Debug, Default)]
pub(crate) struct ReadProofs {
    identity: Option<Arc<()>>,
    authority: Option<Authenticated>,
    deadline: Option<u64>,
    expires: u64,
    pub(crate) tips: Option<Vec<Hash>>,
    cap: usize,
    proofs: BTreeMap<Hash, Proof>,
    checkpoint: Option<Arc<Checkpoint>>,
    lineage: BTreeMap<Hash, Lineage>,
}

impl ReadProofs {
    pub(crate) fn with_deadline(deadline: u64) -> Self {
        Self {
            deadline: Some(deadline),
            ..Self::default()
        }
    }

    /// Keep the original request deadline while isolating temporary evidence.
    pub(crate) fn isolated(&self) -> Self {
        Self {
            deadline: self.deadline,
            ..Self::default()
        }
    }

    pub(crate) fn inherit_deadline(&mut self, other: &Self) {
        if let Some(deadline) = other.deadline {
            let deadline = self.deadline.map_or(deadline, |old| old.min(deadline));
            self.deadline = Some(deadline);
            self.expires = self.expires.min(deadline);
        }
    }

    /// Identity is a fresh allocation owned by the immutable reader. Keeping it
    /// alive prevents pointer reuse across backends, repositories and views.
    /// Compare the *verified* authority too: header callbacks can change.
    pub(crate) fn bind(
        &mut self,
        identity: &Arc<()>,
        mut authority: Option<Authenticated>,
        now: u64,
        cfg: &HttpObjectsConfig,
    ) -> Result<(), ServerError> {
        if let Some(auth) = &mut authority {
            auth.business_now_ms = 0; // verification time is not credential scope
        }
        let configured_deadline =
            now.saturating_add(u64::try_from(cfg.read_deadline.as_millis()).unwrap_or(u64::MAX));
        let deadline = self
            .deadline
            .unwrap_or(configured_deadline)
            .min(configured_deadline);
        self.deadline = Some(deadline);
        if now >= deadline {
            self.clear();
            return Err(super::repo_storage::exhausted());
        }
        if self
            .identity
            .as_ref()
            .is_none_or(|old| !Arc::ptr_eq(old, identity))
            || self.authority != authority
            || now >= self.expires
        {
            self.clear();
            self.identity = Some(identity.clone());
            self.authority = authority;
            self.expires = deadline.min(now.saturating_add(cfg.reachability_lag_ms));
            self.cap = cfg.max_walk_objects.min(MAX_PROOFS);
        }
        Ok(())
    }

    /// Every reset of structural evidence drops a selected checkpoint and
    /// its recorded lineage: lineage never survives into another root set.
    fn drop_checkpoint(&mut self) {
        self.checkpoint = None;
        self.lineage.clear();
    }

    fn clear(&mut self) {
        self.tips = None;
        self.proofs.clear();
        self.drop_checkpoint();
    }

    pub(crate) fn capture(&mut self, tips: Vec<Hash>) {
        self.proofs.clear();
        self.drop_checkpoint();
        // Root enumeration already reserves its bounded rows before dispatch.
        // Oversized root sets are usable by the ordinary walk, without a memo.
        if tips.len() <= self.cap {
            for id in &tips {
                self.proofs.insert(
                    *id,
                    Proof {
                        parent: None,
                        manifest_pack: None,
                    },
                );
            }
        }
        self.tips = Some(tips);
    }

    /// Selected-ref operations prove only their local anchor. Do not make that
    /// single ref the root set of a later general-ID fallback in this session.
    pub(crate) fn capture_selected(&mut self, tip: Option<Hash>) {
        self.capture(tip.into_iter().collect());
        self.tips = None;
    }

    /// Install a selected-ref capture as this session's only root set. The
    /// checkpoint is immutable evidence; it dies with every proofs reset.
    /// `false` installs nothing: the tip could not be memoized (cap 0).
    pub(crate) fn capture_checkpoint(&mut self, mut checkpoint: Checkpoint) -> bool {
        let tip = checkpoint.tip;
        checkpoint.expires = self.expires;
        self.capture(vec![tip]);
        if !self.proofs.contains_key(&tip) {
            self.tips = None;
            return false;
        }
        self.lineage.insert(
            tip,
            Lineage {
                edge: Some(HistoryEdge::Root),
                ..Lineage::default()
            },
        );
        self.checkpoint = Some(Arc::new(checkpoint));
        true
    }

    /// The live selected-ref capture, if this session holds one.
    pub(crate) fn checkpoint(&self) -> Option<&Arc<Checkpoint>> {
        self.checkpoint.as_ref()
    }

    /// The recorded history link for a proved object, or `None` when this
    /// session holds no selected checkpoint or the row has no history edge.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "consumed by history continuation issuance")
    )]
    pub(crate) fn history_link(&self, id: &Hash) -> Option<HistoryLink> {
        self.checkpoint.as_ref()?;
        let proof = self.proofs.get(id)?;
        let lineage = self.lineage.get(id)?;
        Some(HistoryLink {
            predecessor: proof.parent,
            edge: lineage.edge?,
            decoded: lineage.decoded,
        })
    }

    pub(crate) fn current(&self, now: u64) -> bool {
        now < self.expires
    }

    pub(crate) fn expiry(&self) -> u64 {
        self.expires
    }

    /// Export only a bounded commit/tag path, including the proved cursor.
    pub(crate) fn history_ancestry(&self, cursor: Hash) -> Option<Vec<Hash>> {
        let mut ancestry = Vec::new();
        let mut next = Some(cursor);
        let mut seen = BTreeSet::new();
        while let Some(id) = next {
            if ancestry.len() >= crate::history_token::MAX_ANCESTORS || !seen.insert(id) {
                return None;
            }
            let proof = self.proofs.get(&id)?;
            if proof.manifest_pack.is_some() {
                return None;
            }
            ancestry.push(id);
            next = proof.parent;
        }
        ancestry.reverse();
        Some(ancestry)
    }

    /// Only the authenticated history-token path may call this. MAC validation,
    /// current authority, strict anchor/fence and ancestry stops precede import.
    pub(crate) fn restore_history(
        &mut self,
        ancestry: &[Hash],
        expiry: u64,
    ) -> Result<(), ServerError> {
        if ancestry.is_empty()
            || ancestry.len() > self.cap
            || ancestry.len() > crate::history_token::MAX_ANCESTORS
            || ancestry.iter().collect::<BTreeSet<_>>().len() != ancestry.len()
        {
            return Err(super::repo_storage::exhausted());
        }
        self.clear();
        self.expires = self.expires.min(expiry);
        let mut parent = None;
        for id in ancestry {
            self.proofs.insert(
                *id,
                Proof {
                    parent,
                    manifest_pack: None,
                },
            );
            parent = Some(*id);
        }
        Ok(())
    }

    pub(crate) fn contains(&self, id: &Hash) -> bool {
        self.proofs.contains_key(id)
    }

    /// Admit only the selected, decoded local edge. Wide trees and merge
    /// siblings need not fill the memo to prove one path or first-parent log.
    pub(crate) fn link(&mut self, id: Hash, object: &Object, child: Hash) -> bool {
        let real = match object {
            Object::Commit(c) => c.tree_hash == child || c.parents.contains(&child),
            Object::Remix(r) => r.tree_hash == child || r.parents.contains(&child),
            Object::Tree(t) => t.entries.iter().any(|entry| entry.object_hash == child),
            Object::Tag(t) => t.target == child,
            Object::Blob(_) | Object::ChunkedBlob(_) | Object::Delta(_) => false,
        };
        if !real || !self.contains(&id) {
            return false;
        }
        if self.contains(&child) {
            return true;
        }
        if self.proofs.len() >= self.cap {
            return false;
        }
        self.proofs.insert(
            child,
            Proof {
                parent: Some(id),
                manifest_pack: None,
            },
        );
        if self.checkpoint.is_some()
            && let Some(edge) = history_edge(object, child)
        {
            self.lineage.entry(child).or_default().edge = Some(edge);
        }
        true
    }

    /// Decline optional decoding before allocation. In particular, never clone
    /// a million-chunk manifest merely to populate an optimization.
    pub(crate) fn can_decode(&self, id: &Hash, bytes: &[u8]) -> bool {
        self.contains(id)
            && matches!(
                crate::http_objects::resolve::type_of(bytes),
                Some(
                    ObjectType::Commit
                        | ObjectType::Remix
                        | ObjectType::Tree
                        | ObjectType::Tag
                        | ObjectType::ChunkedBlob
                )
            )
            && bytes.len()
                <= MAX_EXPANSION_BYTES.min(
                    self.cap
                        .saturating_sub(self.proofs.len())
                        .saturating_mul(32),
                )
    }

    pub(crate) fn expand(&mut self, id: Hash, pack: Hash, object: &Object) {
        if !self.contains(&id) {
            return;
        }
        if self.checkpoint.is_some()
            && let Some(decoded) = match object {
                Object::Commit(c) => Some((HistoryKind::Commit, c.timestamp)),
                Object::Remix(r) => Some((HistoryKind::Remix, r.timestamp)),
                _ => None,
            }
        {
            self.lineage.entry(id).or_default().decoded = Some(decoded);
        }
        let count = match object {
            Object::Commit(c) => 1 + c.parents.len(),
            Object::Remix(r) => 1 + r.parents.len(),
            Object::Tree(t) => t.entries.len(),
            Object::ChunkedBlob(c) => c.chunks.len(),
            Object::Tag(_) => 1,
            Object::Blob(_) | Object::Delta(_) => 0,
        };
        // Reserve the complete edge vector and every possible new row before
        // graph::children allocates. No partial expansion on exhaustion.
        if count == 0 || count > self.cap.saturating_sub(self.proofs.len()) {
            return;
        }
        let children = graph::children(object, graph::ClosureMode::History);
        if let Some(proof) = self.proofs.get_mut(&id) {
            proof.manifest_pack = matches!(object, Object::ChunkedBlob(_)).then_some(pack);
        }
        for child in children {
            if let std::collections::btree_map::Entry::Vacant(slot) = self.proofs.entry(child) {
                slot.insert(Proof {
                    parent: Some(id),
                    manifest_pack: None,
                });
                if self.checkpoint.is_some()
                    && let Some(edge) = history_edge(object, child)
                {
                    self.lineage.entry(child).or_default().edge = Some(edge);
                }
            }
        }
    }

    /// Recheck stop-sensitive ancestry used by this batch. Ordinary immutable
    /// edges survive changes to ancestor storage, as in Reachability's contract;
    /// they do not waive the target's live membership or reconstruction checks.
    /// Custom stops and manifest denial are live. An invalid path discards the graph and lets
    /// the ordinary walk find another path from the captured roots.
    pub(crate) async fn revalidate(
        &mut self,
        store: &impl NamespaceStore,
        repo: &RepoId,
        gate: &dyn TakedownGate,
        targets: &BTreeSet<Hash>,
    ) -> Result<(), ServerError> {
        let mut ancestors = BTreeSet::new();
        for target in targets {
            let mut node = self.proofs.get(target).and_then(|p| p.parent);
            while let Some(id) = node {
                if !ancestors.insert(id) {
                    break;
                }
                node = self.proofs.get(&id).and_then(|p| p.parent);
            }
        }
        let mut stopped = false;
        let mut checks = BTreeSet::new();
        for id in ancestors {
            stopped |= gate.stops_descent(repo, &id);
            if let Some(pack) = self.proofs.get(&id).and_then(|p| p.manifest_pack) {
                checks.insert(id);
                checks.insert(pack);
            }
        }
        for id in checks {
            if stopped {
                break;
            }
            stopped = crate::takedown::denial::denied(store, &id).await?;
        }
        if stopped {
            self.proofs.clear();
            self.drop_checkpoint();
            if let Some(tips) = &self.tips
                && tips.len() <= self.cap
            {
                for id in tips {
                    self.proofs.insert(
                        *id,
                        Proof {
                            parent: None,
                            manifest_pack: None,
                        },
                    );
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repo::{NamespaceKey, RepoName};
    use futures_executor::block_on;
    use mkit_core::object::{ChunkedBlob, Commit, EntryMode, Identity, Tree, TreeEntry};

    fn repo() -> RepoId {
        RepoId {
            namespace: NamespaceKey::deployment_default(),
            name: RepoName::new("room").unwrap(),
        }
    }

    fn checkpoint(tip: Hash) -> Checkpoint {
        Checkpoint {
            reference: "refs/heads/main".into(),
            tip,
            publication: Publication::default(),
            raw: Vec::new(),
            security: [7; 32],
            expires: 0,
        }
    }

    fn commit(tree: Hash, parents: &[Hash]) -> Object {
        Object::Commit(Commit::new_unannotated(
            tree,
            parents.to_vec(),
            Identity::ed25519([0; 32]),
            [0; 32],
            Vec::new(),
            7,
            [0; 64],
        ))
    }

    fn tree(children: &[Hash]) -> Object {
        Object::Tree(Tree {
            entries: children
                .iter()
                .enumerate()
                .map(|(index, child)| TreeEntry {
                    name: vec![u8::try_from(index).unwrap()],
                    mode: EntryMode::Blob,
                    object_hash: *child,
                })
                .collect(),
        })
    }

    struct StopAt(Hash);
    impl TakedownGate for StopAt {
        fn stops_descent(&self, _: &RepoId, id: &Hash) -> bool {
            *id == self.0
        }
        fn check<'a>(
            &'a self,
            _: &'a RepoId,
            _: &'a Hash,
        ) -> crate::BoxFuture<'a, Result<crate::http_objects::TakedownVerdict, ServerError>>
        {
            Box::pin(async { Ok(crate::http_objects::TakedownVerdict::Clear) })
        }
    }

    fn bound_memo(cap: usize) -> ReadProofs {
        let cfg = HttpObjectsConfig {
            max_walk_objects: cap,
            ..HttpObjectsConfig::default()
        };
        let mut memo = ReadProofs::default();
        memo.bind(&Arc::new(()), None, 0, &cfg).unwrap();
        memo
    }

    #[test]
    fn a_checkpoint_records_roles_and_decoded_facts_on_new_rows_only() {
        let mut memo = bound_memo(16);
        assert!(memo.capture_checkpoint(checkpoint([1; 32])));
        let link = memo.history_link(&[1; 32]).unwrap();
        assert_eq!(link.edge, HistoryEdge::Root);
        assert_eq!(link.predecessor, None);
        assert_eq!(link.decoded, None);
        let head = commit([9; 32], &[[2; 32], [3; 32]]);
        memo.expand([1; 32], [0; 32], &head);
        for parent in [[2; 32], [3; 32]] {
            let link = memo.history_link(&parent).unwrap();
            assert_eq!(link.edge, HistoryEdge::Parent);
            assert_eq!(link.predecessor, Some([1; 32]));
            assert_eq!(link.decoded, None);
        }
        // A tree child is a content edge: a row, but no history link.
        assert!(memo.contains(&[9; 32]));
        assert!(memo.history_link(&[9; 32]).is_none());
        // A tree entry naming a commit records no edge for it either.
        memo.expand([9; 32], [0; 32], &tree(&[[4; 32], [5; 32]]));
        assert!(memo.contains(&[4; 32]));
        assert!(memo.history_link(&[4; 32]).is_none());
        // Decoding the expanded object fills in its fact, not a new edge.
        let parent = commit([9; 32], &[[3; 32], [6; 32]]);
        memo.expand([2; 32], [0; 32], &parent);
        let link = memo.history_link(&[2; 32]).unwrap();
        assert_eq!(link.edge, HistoryEdge::Parent);
        assert_eq!(link.decoded, Some((HistoryKind::Commit, 7)));
        // A second path to an existing row keeps its first recorded role.
        assert!(memo.link([2; 32], &parent, [3; 32]));
        let link = memo.history_link(&[3; 32]).unwrap();
        assert_eq!(link.edge, HistoryEdge::Parent);
        assert_eq!(link.predecessor, Some([1; 32]));
        let link = memo.history_link(&[6; 32]).unwrap();
        assert_eq!(link.edge, HistoryEdge::Parent);
        assert_eq!(link.predecessor, Some([2; 32]));
    }

    #[test]
    fn no_checkpoint_means_no_lineage() {
        let mut memo = bound_memo(16);
        memo.capture(vec![[1; 32]]);
        let head = commit([9; 32], &[[2; 32]]);
        memo.expand([1; 32], [0; 32], &head);
        assert!(memo.history_link(&[1; 32]).is_none());
        assert!(memo.history_link(&[2; 32]).is_none());
        assert!(memo.lineage.is_empty());
    }

    #[test]
    fn a_tip_that_cannot_be_memoized_installs_no_checkpoint() {
        let mut memo = bound_memo(0);
        assert!(!memo.capture_checkpoint(checkpoint([1; 32])));
        assert!(memo.checkpoint().is_none());
        assert!(memo.tips.is_none());
        assert!(memo.lineage.is_empty());
        assert!(!memo.contains(&[1; 32]));
    }

    #[test]
    fn every_reset_path_drops_the_checkpoint() {
        let resets: [fn(&mut ReadProofs); 3] = [
            |memo| {
                memo.capture(vec![[8; 32]]);
            },
            |memo| {
                memo.capture_selected(Some([8; 32]));
            },
            |memo| {
                memo.restore_history(&[[9; 32]], u64::MAX).unwrap();
            },
        ];
        for reset in resets {
            let mut memo = bound_memo(16);
            assert!(memo.capture_checkpoint(checkpoint([1; 32])));
            memo.expand([1; 32], [0; 32], &commit([9; 32], &[[2; 32]]));
            reset(&mut memo);
            assert!(memo.checkpoint().is_none());
            assert!(memo.lineage.is_empty());
            assert!(memo.history_link(&[2; 32]).is_none());
        }
        // Rebinding to another identity resets proofs like any other capture.
        let mut memo = bound_memo(16);
        assert!(memo.capture_checkpoint(checkpoint([1; 32])));
        let cfg = HttpObjectsConfig::default();
        memo.bind(&Arc::new(()), None, 1, &cfg).unwrap();
        assert!(memo.checkpoint().is_none());
        assert!(memo.lineage.is_empty());
        // Expiry is a reset too: the same identity re-binds empty.
        let mut memo = ReadProofs::default();
        let identity = Arc::new(());
        let cfg = HttpObjectsConfig {
            reachability_lag_ms: 5,
            ..HttpObjectsConfig::default()
        };
        memo.bind(&identity, None, 0, &cfg).unwrap();
        assert!(memo.capture_checkpoint(checkpoint([1; 32])));
        memo.bind(&identity, None, 5, &cfg).unwrap();
        assert!(memo.checkpoint().is_none());
        assert!(memo.lineage.is_empty());
        // A stopped revalidation reseeds the tips without the checkpoint.
        let mut memo = bound_memo(16);
        assert!(memo.capture_checkpoint(checkpoint([1; 32])));
        memo.expand([1; 32], [0; 32], &commit([9; 32], &[[2; 32]]));
        let store = crate::memory::MemoryKv::default();
        block_on(memo.revalidate(
            &store,
            &repo(),
            &StopAt([1; 32]),
            &BTreeSet::from([[2; 32]]),
        ))
        .unwrap();
        assert!(memo.checkpoint().is_none());
        assert!(memo.lineage.is_empty());
        assert!(memo.contains(&[1; 32]));
    }

    #[test]
    fn expansion_reserves_all_edges_before_publishing_and_declines_huge_manifests() {
        let cfg = HttpObjectsConfig {
            max_walk_objects: 4,
            ..HttpObjectsConfig::default()
        };
        let mut memo = ReadProofs::default();
        memo.bind(&Arc::new(()), None, 0, &cfg).unwrap();
        memo.capture(vec![[1; 32]]);
        let object = Object::ChunkedBlob(ChunkedBlob {
            total_size: 4,
            chunk_size: 1,
            chunks: vec![[2; 32]; 4],
        });
        memo.expand([1; 32], [9; 32], &object);
        assert_eq!(memo.proofs.len(), 1);
        assert!(memo.proofs[&[1; 32]].manifest_pack.is_none());
        assert!(!memo.can_decode(
            &[1; 32],
            &vec![ObjectType::ChunkedBlob as u8; MAX_EXPANSION_BYTES + 1]
        ));
        let object = Object::ChunkedBlob(ChunkedBlob {
            total_size: 3,
            chunk_size: 1,
            chunks: vec![[2; 32], [3; 32], [4; 32]],
        });
        memo.expand([1; 32], [9; 32], &object);
        assert_eq!(memo.proofs.len(), 4);
        assert!(!memo.can_decode(&[1; 32], &[ObjectType::ChunkedBlob as u8; 1]));
    }

    #[test]
    fn rebinding_changes_only_proofs_and_never_slides_deadline() {
        let cfg = HttpObjectsConfig {
            read_deadline: std::time::Duration::from_millis(10),
            reachability_lag_ms: 5,
            ..HttpObjectsConfig::default()
        };
        let mut memo = ReadProofs::default();
        let first = Arc::new(());
        memo.bind(&first, None, 0, &cfg).unwrap();
        memo.capture(vec![[1; 32]]);
        memo.bind(&first, None, 4, &cfg).unwrap();
        assert_eq!(memo.expires, 5);
        assert!(memo.contains(&[1; 32]));
        memo.bind(&first, None, 5, &cfg).unwrap();
        assert!(memo.tips.is_none());
        assert_eq!(memo.expires, 10);
        memo.capture(vec![[1; 32]]);
        memo.bind(&Arc::new(()), None, 9, &cfg).unwrap();
        assert!(memo.tips.is_none());
        assert_eq!(memo.expires, 10);
        assert!(memo.bind(&first, None, 10, &cfg).is_err());
    }
}
