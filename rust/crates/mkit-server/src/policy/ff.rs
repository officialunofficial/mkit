//! The fast-forward ancestry engine (SPEC-SERVER §9.7, SPEC-WRITE-GRANTS
//! §8.2). It answers whether `to` descends from `from` along Commit and
//! Remix `parents` (never a Remix's `sources`), reading only this
//! repository's member index (§9.4): never the global object namespace.

use std::collections::BTreeSet;

use crate::indexed::{
    IndexedConfig, resolve,
    verify::{StagedCommits, history_parents},
};
use crate::pipeline::ShardMap;
use crate::repo::RepoId;
use crate::store::index::ObjectLookup;
use crate::telemetry::{METRIC_REF_POLICY_ANCESTRY_UNCHECKED, Metrics};
use crate::{BlobStore, Clock, NamespaceStore, ServerError};
use mkit_core::hash::Hash;

/// A `u`-only `MATCH` write that is allowed only as a proven fast-forward
/// (SPEC-WRITE-GRANTS §8.2), carried from stage 2 to stage 5, where it must
/// still describe the change being written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FastForward {
    pub name: String,
    pub from: Hash,
    pub to: Hash,
}

/// The walk's answer. Anything but `Descendant` denies the write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    Descendant,
    /// `from` is not an ancestor of `to`, or history is missing.
    NotDescendant,
    /// A cap, the decode budget or a corrupt member stopped the walk.
    Unchecked,
}

/// What the walk reads.
pub(crate) struct Walk<'a, B, S> {
    pub blobs: &'a B,
    pub store: &'a S,
    pub shards: &'a dyn ShardMap,
    pub repo: &'a RepoId,
    pub cfg: IndexedConfig,
    pub clock: &'a dyn Clock,
    pub metrics: &'a dyn Metrics,
}

/// What reading one member commit yielded.
enum Step {
    Parents(Vec<Hash>),
    /// Not (yet) visible in this repository.
    Missed,
    Stop(Verdict),
}

impl<B: BlobStore, S: NamespaceStore> Walk<'_, B, S> {
    fn unchecked(&self, reason: &'static str) -> Verdict {
        tracing::warn!(reason, "fast-forward ancestry unchecked");
        self.metrics.incr(
            METRIC_REF_POLICY_ANCESTRY_UNCHECKED,
            &[("reason", reason)],
            1,
        );
        Verdict::Unchecked
    }

    /// The parents of member commit `id` as located, or why there are none.
    async fn member_parents(
        &self,
        id: Hash,
        located: Option<&ObjectLookup>,
        budget: u64,
        memo: &mut resolve::MemberCache,
    ) -> Result<Step, ServerError> {
        let located = match located {
            Some(Ok(Some(located))) => *located,
            Some(Err(_)) => return Ok(Step::Stop(self.unchecked("lookup"))),
            _ => return Ok(Step::Missed),
        };
        let resolved = resolve::member_object(
            self.blobs,
            self.store,
            self.shards,
            self.repo,
            id,
            located,
            self.cfg.max_delta_chain_depth,
            budget,
            memo,
            &mut BTreeSet::new(),
            self.metrics,
        )
        .await;
        let bytes = match resolved {
            Ok((bytes, _)) => bytes,
            Err(resolve::ResolveFailure::Missing) => return Ok(Step::Missed),
            Err(resolve::ResolveFailure::Capped) => {
                return Ok(Step::Stop(self.unchecked("base")));
            }
            Err(resolve::ResolveFailure::Other(error))
                if error.code() == crate::Code::Unavailable =>
            {
                return Err(error);
            }
            Err(resolve::ResolveFailure::Other(error)) => {
                let budget = error.public_message() == "pack exceeds indexed decode budget";
                return Ok(Step::Stop(self.unchecked(if budget {
                    "budget"
                } else {
                    "member"
                })));
            }
        };
        Ok(
            match mkit_core::serialize::deserialize(&bytes)
                .ok()
                .and_then(|object| history_parents(&object))
            {
                Some(parents) => Step::Parents(parents),
                None => Step::Stop(self.unchecked("corrupt")),
            },
        )
    }

    /// Whether `to` is `from` or descends from it. Staged commits cost
    /// nothing; member commits are read breadth-first, one batched lookup
    /// per round, at most `max_ancestry_commits` of them. A miss while the
    /// window from `created_ms` is open answers a retryable `unavailable`
    /// unless another path proves the ancestry.
    ///
    /// # Errors
    /// `unavailable` for a storage failure or an open-window membership miss.
    pub(crate) async fn is_descendant(
        &self,
        to: Hash,
        from: Hash,
        staged: &StagedCommits,
        created_ms: u64,
    ) -> Result<Verdict, ServerError> {
        if to == from {
            return Ok(Verdict::Descendant);
        }
        let budget = self.cfg.decode_budget.saturating_sub(staged.bytes);
        let mut memo = resolve::MemberCache::default();
        let mut visited = BTreeSet::from([to]);
        let mut frontier = vec![to];
        let (mut reads, mut missed) = (0u32, false);
        while !frontier.is_empty() {
            let mut next = Vec::new();
            let mut member = Vec::new();
            let mut edges = Vec::new();
            for id in frontier {
                match staged.parents.get(&id) {
                    Some(parents) => edges.extend(parents.iter().copied()),
                    None => member.push(id),
                }
            }
            if edges.contains(&from) {
                return Ok(Verdict::Descendant);
            }
            reads = reads.saturating_add(u32::try_from(member.len()).unwrap_or(u32::MAX));
            if reads > self.cfg.max_ancestry_commits {
                return Ok(self.unchecked("commits"));
            }
            if !member.is_empty() {
                let found = resolve::locate_split(
                    self.store,
                    self.shards,
                    self.repo,
                    &member,
                    self.metrics,
                )
                .await?;
                for id in member {
                    match self
                        .member_parents(id, found.get(&id), budget, &mut memo)
                        .await?
                    {
                        Step::Parents(parents) => edges.extend(parents),
                        Step::Missed => missed = true,
                        Step::Stop(verdict) => return Ok(verdict),
                    }
                }
            }
            for parent in edges {
                if parent == from {
                    return Ok(Verdict::Descendant);
                }
                if visited.insert(parent) {
                    next.push(parent);
                }
            }
            frontier = next;
        }
        let now = u64::try_from(self.clock.now_ms()).unwrap_or(0);
        if missed && resolve::lagged(now, created_ms, self.cfg.relay_lag_bound_ms) {
            return Err(ServerError::unavailable(
                "repository membership not yet visible",
            ));
        }
        Ok(Verdict::NotDescendant)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mkit_core::object::{Blob, Identity, Object, ObjectType, Remix, RemixSource, Tag};

    #[test]
    fn only_commit_and_remix_parents_are_history_edges() {
        let author = Identity::ed25519([1; 32]);
        let remix = Object::Remix(Remix {
            tree_hash: [2; 32],
            parents: vec![[3; 32]],
            sources: vec![RemixSource {
                upstream_id: [4; 32],
                commit_hash: [5; 32],
            }],
            author: author.clone(),
            signer: [1; 32],
            message: Vec::new(),
            timestamp: 0,
            signature: [0; 64],
        });
        assert_eq!(history_parents(&remix), Some(vec![[3; 32]]));
        let tag = Object::Tag(Tag {
            target: [6; 32],
            target_type: ObjectType::Commit,
            name: b"v1".to_vec(),
            tagger: author,
            signer: [1; 32],
            message: Vec::new(),
            timestamp: 0,
            signature: [0; 64],
        });
        // A tag is a descendant only of itself: its target is no edge.
        assert_eq!(history_parents(&tag), Some(Vec::new()));
        assert_eq!(
            history_parents(&Object::Blob(Blob { data: Vec::new() })),
            None
        );
    }
}
