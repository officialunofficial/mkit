//! Request-local structural evidence. Nothing here is an access decision.
use super::Authenticated;
use crate::http_objects::{HttpObjectsConfig, TakedownGate};
use crate::store::NamespaceStore;
use crate::{RepoId, ServerError};
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

#[derive(Debug, Default)]
pub(crate) struct ReadProofs {
    identity: Option<Arc<()>>,
    authority: Option<Authenticated>,
    deadline: Option<u64>,
    expires: u64,
    pub(crate) tips: Option<Vec<Hash>>,
    cap: usize,
    proofs: BTreeMap<Hash, Proof>,
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

    fn clear(&mut self) {
        self.tips = None;
        self.proofs.clear();
    }

    pub(crate) fn capture(&mut self, tips: Vec<Hash>) {
        self.proofs.clear();
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
            self.proofs.entry(child).or_insert(Proof {
                parent: Some(id),
                manifest_pack: None,
            });
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
    use mkit_core::object::ChunkedBlob;

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
