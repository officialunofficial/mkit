//! Incremental push verification: check the history a push introduces
//! before any ref moves (PRD §6.5, indexed mode).
//!
//! [`verify_push`] walks each new tip's closure through the same BFS as
//! the closure verifiers (`closure::walk`, edges from
//! [`crate::ops::graph::children`]), re-derives every object id, checks
//! commit, remix and tag signatures with
//! [`crate::sign::verify_object_signature`], and stops at a
//! caller-supplied frontier of objects this repository already verified.

use crate::hash::Hash;
use crate::object::ObjectType;
use crate::ops::graph::ClosureMode;
use crate::verify::VerifyError;

use super::closure::{ObjectSource, RootRule, walk};

/// What [`verify_push`] found. The push is acceptable only when
/// [`Self::is_accepted`] holds.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct PushReport {
    /// Objects fetched whose id re-derived correctly (their signatures,
    /// if any, were checked; failures are in [`Self::bad_signatures`]).
    pub verified: usize,
    /// Frontier stops: ids the caller's `known` accepted. Never fetched,
    /// never descended.
    pub skipped_known: usize,
    /// Referenced by a new object (or a tip) but not in the source:
    /// the closure is not closed. Sorted.
    pub missing: Vec<Hash>,
    /// Bytes that do not deserialize, or whose derived id is not the
    /// requested id, reported under the requested id. Sorted by id.
    pub corrupt: Vec<(Hash, String)>,
    /// Commits, remixes and tags whose signature does not verify under
    /// their embedded signer. Sorted by id.
    pub bad_signatures: Vec<(Hash, String)>,
    /// Tips that are not a commit, remix or tag. Sorted by id.
    pub bad_tips: Vec<(Hash, ObjectType)>,
}

impl PushReport {
    /// True iff nothing is missing, corrupt, badly signed, or a bad tip.
    #[must_use]
    pub fn is_accepted(&self) -> bool {
        self.missing.is_empty()
            && self.corrupt.is_empty()
            && self.bad_signatures.is_empty()
            && self.bad_tips.is_empty()
    }
}

/// Verify the history a push introduces, before refs move.
///
/// Breadth-first from every id in `new_tips` over
/// [`crate::ops::graph::children`]`(obj, mode)`, fetching each id at
/// most once from `source`. Every fetched object is deserialized and its
/// id re-derived; each commit, remix and tag has its signature checked.
/// Remix `sources` and `Delta.base_hash` are never followed. Everything
/// wrong is collected into the [`PushReport`] rather than stopping at the
/// first problem, so a server can reject with a complete reason.
///
/// # Repository isolation (PRD §6.5)
///
/// - `source` MUST serve only this repository's members plus the objects
///   of the push being verified. A source backed by a global content
///   store, or by another repository, turns this check into a cross-repo
///   existence oracle and lets a push "close" over objects its
///   repository never held.
/// - `known(id)` is a frontier: ids for which it returns `true` are
///   neither fetched nor descended. It MUST return `true` only for
///   objects whose **whole closure in this `mode` was already verified
///   in this repository** — never for "exists somewhere", and never for
///   an object merely present in the pushed pack. A `known` tip is
///   skipped entirely, including its commit/remix/tag type check; the
///   caller's index already knows that object's type.
///
/// # Errors
///
/// Only a `source` error, or [`VerifyError::TooManyClosureObjects`] once
/// the walk reaches more than [`crate::pack::MAX_ENTRIES`] ids (frontier
/// stops included). Verification failures are report entries, not errors.
pub fn verify_push(
    new_tips: &[Hash],
    mode: ClosureMode,
    source: &mut impl ObjectSource,
    known: impl FnMut(&Hash) -> bool,
) -> Result<PushReport, VerifyError> {
    let mut bad_signatures = Vec::new();
    let walked = walk(
        new_tips,
        mode,
        source,
        known,
        RootRule::Record,
        |id, obj| {
            if let Err(error) = crate::sign::verify_object_signature(obj) {
                bad_signatures.push((*id, error.to_string()));
            }
            Ok(())
        },
    )?;
    bad_signatures.sort_by_key(|(id, _)| *id);
    Ok(PushReport {
        verified: walked.verified,
        skipped_known: walked.skipped_known,
        missing: walked.missing,
        corrupt: walked.corrupt,
        bad_signatures,
        bad_tips: walked.bad_roots,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::borrow::Cow;
    use std::collections::{BTreeMap, BTreeSet};

    use crate::hash::ZERO;
    use crate::object::{
        Blob, ChunkedBlob, Commit, EntryMode, Identity, Object, Remix, RemixSource, Tag, Tree,
        TreeEntry,
    };
    use crate::sign::{KeyPair, sign_commit, sign_remix, sign_tag};

    /// In-memory source that counts fetches and panics on ids listed in
    /// `forbidden` or absent from both `objects` and `missing`.
    #[derive(Default)]
    struct Source {
        objects: BTreeMap<Hash, Vec<u8>>,
        forbidden: BTreeSet<Hash>,
        fetches: BTreeMap<Hash, usize>,
    }

    impl Source {
        fn put(&mut self, obj: &Object) -> Hash {
            let bytes = crate::serialize::serialize(obj).unwrap();
            let id = crate::object::id_from_object(obj, &bytes);
            self.objects.insert(id, bytes);
            id
        }

        fn blob(&mut self, data: &[u8]) -> Hash {
            self.put(&Object::Blob(Blob {
                data: data.to_vec(),
            }))
        }

        fn tree(&mut self, entries: &[(&[u8], Hash)]) -> Hash {
            self.put(&Object::Tree(Tree {
                entries: entries
                    .iter()
                    .map(|(name, id)| TreeEntry {
                        name: name.to_vec(),
                        mode: EntryMode::Blob,
                        object_hash: *id,
                    })
                    .collect(),
            }))
        }

        fn commit(&mut self, tree_hash: Hash, parents: Vec<Hash>, msg: &[u8]) -> Hash {
            let commit = signed_commit(tree_hash, parents, msg);
            self.put(&Object::Commit(commit))
        }

        fn assert_each_fetched_at_most_once(&self) {
            assert!(
                self.fetches.values().all(|n| *n == 1),
                "an id was fetched twice: {:?}",
                self.fetches
            );
        }
    }

    impl ObjectSource for Source {
        fn fetch(&mut self, id: &Hash) -> Result<Option<Cow<'_, [u8]>>, VerifyError> {
            assert!(
                !self.forbidden.contains(id),
                "forbidden fetch: {}",
                crate::hash::to_hex(id)
            );
            *self.fetches.entry(*id).or_default() += 1;
            Ok(self.objects.get(id).map(|b| Cow::Borrowed(b.as_slice())))
        }
    }

    fn kp() -> KeyPair {
        KeyPair::from_seed([0x24; 32])
    }

    fn signed_commit(tree_hash: Hash, parents: Vec<Hash>, msg: &[u8]) -> Commit {
        let kp = kp();
        let mut commit = Commit {
            tree_hash,
            parents,
            author: Identity::ed25519(kp.public.0),
            signer: kp.public.0,
            message: msg.to_vec(),
            timestamp: 7,
            message_hash: ZERO,
            content_digest: ZERO,
            signature: [0u8; 64],
        };
        commit.signature = sign_commit(&commit, &kp).unwrap().0;
        commit
    }

    fn signed_tag(target: Hash, target_type: ObjectType, name: &[u8]) -> Tag {
        let kp = kp();
        let mut tag = Tag {
            target,
            target_type,
            name: name.to_vec(),
            tagger: Identity::ed25519(kp.public.0),
            signer: kp.public.0,
            message: b"tag".to_vec(),
            timestamp: 9,
            signature: [0u8; 64],
        };
        tag.signature = sign_tag(&tag, &kp).unwrap().0;
        tag
    }

    /// `c2 -> c1`, each with its own one-file tree.
    fn two_commits(src: &mut Source) -> (Hash, Hash) {
        let b1 = src.blob(b"one");
        let t1 = src.tree(&[(b"a", b1)]);
        let c1 = src.commit(t1, vec![], b"first");
        let b2 = src.blob(b"two");
        let t2 = src.tree(&[(b"a", b2)]);
        let c2 = src.commit(t2, vec![c1], b"second");
        (c1, c2)
    }

    #[test]
    fn good_push_verifies_all_new_objects() {
        let mut src = Source::default();
        let (_c1, c2) = two_commits(&mut src);
        let report = verify_push(&[c2], ClosureMode::History, &mut src, |_| false).unwrap();
        assert!(report.is_accepted(), "{report:?}");
        assert_eq!(report.verified, 6);
        assert_eq!(report.skipped_known, 0);
        let all: BTreeSet<Hash> = src.objects.keys().copied().collect();
        assert_eq!(src.fetches.keys().copied().collect::<BTreeSet<_>>(), all);
        src.assert_each_fetched_at_most_once();
    }

    #[test]
    fn frontier_stop() {
        let mut src = Source::default();
        let (c1, c2) = two_commits(&mut src);
        // c1 and everything only it reaches must never be fetched.
        let before: BTreeSet<Hash> = src.objects.keys().copied().collect();
        let mut only_c1 = BTreeSet::from([c1]);
        let Object::Commit(commit) = crate::serialize::deserialize(&src.objects[&c1]).unwrap()
        else {
            panic!("c1 is a commit");
        };
        only_c1.insert(commit.tree_hash);
        let Object::Tree(tree) =
            crate::serialize::deserialize(&src.objects[&commit.tree_hash]).unwrap()
        else {
            panic!("tree");
        };
        only_c1.insert(tree.entries[0].object_hash);
        src.forbidden = only_c1.clone();

        let report = verify_push(&[c2], ClosureMode::History, &mut src, |id| *id == c1).unwrap();
        assert!(report.is_accepted(), "{report:?}");
        assert_eq!(report.skipped_known, 1);
        assert_eq!(report.verified, 3);
        let fetched: BTreeSet<Hash> = src.fetches.keys().copied().collect();
        assert_eq!(
            fetched,
            before
                .difference(&only_c1)
                .copied()
                .collect::<BTreeSet<_>>()
        );
    }

    #[test]
    fn known_tip_is_noop() {
        let mut src = Source::default();
        let (_c1, c2) = two_commits(&mut src);
        src.forbidden = src.objects.keys().copied().collect();
        let report = verify_push(&[c2], ClosureMode::History, &mut src, |_| true).unwrap();
        assert!(report.is_accepted());
        assert_eq!(report.skipped_known, 1);
        assert_eq!(report.verified, 0);
        assert!(src.fetches.is_empty());
    }

    #[test]
    fn unsigned_commit_rejected() {
        let mut src = Source::default();
        let blob = src.blob(b"x");
        let tree = src.tree(&[(b"x", blob)]);
        let mut commit = signed_commit(tree, vec![], b"unsigned");
        commit.signature = [0u8; 64];
        let c = src.put(&Object::Commit(commit));
        let report = verify_push(&[c], ClosureMode::History, &mut src, |_| false).unwrap();
        assert!(!report.is_accepted());
        assert_eq!(report.bad_signatures.len(), 1);
        assert_eq!(report.bad_signatures[0].0, c);
        assert_eq!(
            report.verified, 3,
            "a bad signature still walks the closure"
        );
        assert!(report.missing.is_empty() && report.corrupt.is_empty());
    }

    #[test]
    fn forged_tag_rejected() {
        let mut src = Source::default();
        let (_c1, c2) = two_commits(&mut src);
        let mut tag = signed_tag(c2, ObjectType::Commit, b"v1");
        tag.signer = KeyPair::from_seed([0x99; 32]).public.0;
        let t = src.put(&Object::Tag(tag));
        let report = verify_push(&[t], ClosureMode::History, &mut src, |_| false).unwrap();
        assert_eq!(
            report
                .bad_signatures
                .iter()
                .map(|b| b.0)
                .collect::<Vec<_>>(),
            vec![t]
        );
        assert!(report.bad_tips.is_empty());
    }

    #[test]
    fn remix_signature_checked() {
        let mut src = Source::default();
        let blob = src.blob(b"r");
        let tree = src.tree(&[(b"r", blob)]);
        let kp = kp();
        let mut remix = Remix {
            tree_hash: tree,
            parents: vec![],
            sources: vec![],
            author: Identity::ed25519(kp.public.0),
            signer: kp.public.0,
            message: b"remix".to_vec(),
            timestamp: 3,
            signature: [0u8; 64],
        };
        remix.signature = sign_remix(&remix, &kp).unwrap().0;
        let good = src.put(&Object::Remix(remix.clone()));
        let report = verify_push(&[good], ClosureMode::History, &mut src, |_| false).unwrap();
        assert!(report.is_accepted(), "{report:?}");

        remix.message = b"tampered".to_vec();
        let bad = src.put(&Object::Remix(remix));
        let report = verify_push(&[bad], ClosureMode::History, &mut src, |_| false).unwrap();
        assert_eq!(report.bad_signatures.len(), 1);
        assert_eq!(report.bad_signatures[0].0, bad);
    }

    #[test]
    fn tree_referencing_absent_blob_is_missing() {
        let mut src = Source::default();
        let absent = crate::hash::hash(b"never supplied");
        let tree = src.tree(&[(b"gone", absent)]);
        let c = src.commit(tree, vec![], b"dangling");
        let report = verify_push(&[c], ClosureMode::History, &mut src, |_| false).unwrap();
        assert_eq!(report.missing, vec![absent]);
        assert!(!report.is_accepted());
    }

    #[test]
    fn wrong_bytes_for_id_is_corrupt() {
        let mut src = Source::default();
        let blob = src.blob(b"genuine");
        let tree = src.tree(&[(b"f", blob)]);
        let c = src.commit(tree, vec![], b"c");
        let other = crate::serialize::serialize(&Object::Blob(Blob {
            data: b"impostor".to_vec(),
        }))
        .unwrap();
        src.objects.insert(blob, other);
        let report = verify_push(&[c], ClosureMode::History, &mut src, |_| false).unwrap();
        assert_eq!(
            report.corrupt.iter().map(|c| c.0).collect::<Vec<_>>(),
            vec![blob]
        );

        src.objects.insert(blob, b"not an object".to_vec());
        let report = verify_push(&[c], ClosureMode::History, &mut src, |_| false).unwrap();
        assert_eq!(
            report.corrupt.iter().map(|c| c.0).collect::<Vec<_>>(),
            vec![blob]
        );
        assert!(!report.is_accepted());
    }

    #[test]
    fn tip_is_tree_is_bad_tip() {
        let mut src = Source::default();
        let blob = src.blob(b"t");
        let tree = src.tree(&[(b"t", blob)]);
        let report = verify_push(&[tree], ClosureMode::History, &mut src, |_| false).unwrap();
        assert_eq!(report.bad_tips, vec![(tree, ObjectType::Tree)]);
        assert!(!report.is_accepted());
    }

    #[test]
    fn tag_of_tag_of_commit_walks_through() {
        let mut src = Source::default();
        let (_c1, c2) = two_commits(&mut src);
        let inner = src.put(&Object::Tag(signed_tag(c2, ObjectType::Commit, b"inner")));
        let outer = src.put(&Object::Tag(signed_tag(inner, ObjectType::Tag, b"outer")));
        let report = verify_push(&[outer], ClosureMode::History, &mut src, |_| false).unwrap();
        assert!(report.is_accepted(), "{report:?}");
        assert_eq!(report.verified, 8);
        assert_eq!(src.fetches.len(), src.objects.len());
    }

    #[test]
    fn chunked_blob_children_walked() {
        let mut src = Source::default();
        let chunk_a = src.blob(b"chunk-a");
        let chunk_b = crate::hash::hash(b"chunk-b never supplied");
        let manifest = src.put(&Object::ChunkedBlob(ChunkedBlob {
            total_size: 14,
            chunk_size: 7,
            chunks: vec![chunk_a, chunk_b],
        }));
        let tree = src.tree(&[(b"big", manifest)]);
        let c = src.commit(tree, vec![], b"chunked");
        let report = verify_push(&[c], ClosureMode::History, &mut src, |_| false).unwrap();
        assert_eq!(report.missing, vec![chunk_b]);
        assert!(src.fetches.contains_key(&chunk_a));
        assert_eq!(report.verified, 4);
    }

    #[test]
    fn history_vs_snapshot() {
        let mut src = Source::default();
        let absent_parent = crate::hash::hash(b"parent not pushed");
        let blob = src.blob(b"h");
        let tree = src.tree(&[(b"h", blob)]);
        let c = src.commit(tree, vec![absent_parent], b"child");

        let history = verify_push(&[c], ClosureMode::History, &mut src, |_| false).unwrap();
        assert_eq!(history.missing, vec![absent_parent]);

        let snapshot = verify_push(&[c], ClosureMode::Snapshot, &mut src, |_| false).unwrap();
        assert!(snapshot.is_accepted(), "{snapshot:?}");
    }

    #[test]
    fn each_object_fetched_once_across_multiple_tips() {
        let mut src = Source::default();
        let (c1, c2) = two_commits(&mut src);
        let shared_blob = src.blob(b"shared");
        let t3 = src.tree(&[(b"s", shared_blob)]);
        let c3 = src.commit(t3, vec![c1], b"branch-b");
        let t4 = src.tree(&[(b"s", shared_blob), (b"t", shared_blob)]);
        let c4 = src.commit(t4, vec![c2, c3], b"merge");
        // Tips listed redundantly, including an ancestor of another tip.
        let report = verify_push(
            &[c4, c2, c3, c4, c1],
            ClosureMode::History,
            &mut src,
            |_| false,
        )
        .unwrap();
        assert!(report.is_accepted(), "{report:?}");
        assert_eq!(report.verified, src.objects.len());
        assert_eq!(src.fetches.len(), src.objects.len());
        src.assert_each_fetched_at_most_once();
    }

    #[test]
    fn remix_sources_never_followed() {
        let mut src = Source::default();
        let blob = src.blob(b"m");
        let tree = src.tree(&[(b"m", blob)]);
        let foreign = crate::hash::hash(b"foreign upstream commit");
        src.forbidden.insert(foreign);
        let kp = kp();
        let mut remix = Remix {
            tree_hash: tree,
            parents: vec![],
            sources: vec![RemixSource {
                upstream_id: crate::hash::hash(b"upstream"),
                commit_hash: foreign,
            }],
            author: Identity::ed25519(kp.public.0),
            signer: kp.public.0,
            message: b"remix with source".to_vec(),
            timestamp: 4,
            signature: [0u8; 64],
        };
        remix.signature = sign_remix(&remix, &kp).unwrap().0;
        let r = src.put(&Object::Remix(remix));
        for mode in [ClosureMode::History, ClosureMode::Snapshot] {
            let report = verify_push(&[r], mode, &mut src, |_| false).unwrap();
            assert!(report.is_accepted(), "{mode:?}: {report:?}");
            assert!(report.missing.is_empty());
        }
    }

    #[test]
    fn missing_tip_is_missing() {
        let mut src = Source::default();
        let absent = crate::hash::hash(b"tip not pushed");
        let report = verify_push(&[absent], ClosureMode::History, &mut src, |_| false).unwrap();
        assert_eq!(report.missing, vec![absent]);
        assert!(report.bad_tips.is_empty());
        assert!(!report.is_accepted());
    }

    #[test]
    fn empty_tips_is_accepted_noop() {
        let mut src = Source::default();
        let report = verify_push(&[], ClosureMode::History, &mut src, |_| false).unwrap();
        assert_eq!(report, PushReport::default());
        assert!(report.is_accepted());
    }
}
