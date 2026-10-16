//! Allocation-free direct references under the baseline History profile.
//!
//! Extraction records obligations; it neither authenticates the source object
//! nor refuses tree-mode or tag-target kind mismatches. Chunk integrity needs
//! canonical Blob bytes and checked ordered accumulation against the manifest's
//! `total_size`. Individual lengths are not inferred from `chunk_size`.

use mkit_core::object::{EntryMode, Object, ObjectType};

use super::{EdgeKind, ObjectEdge};

/// Number of direct reference occurrences, including repeated chunk IDs.
///
/// This inspects the supplied object in constant time and allocates nothing.
/// Remix source claims and pack-only delta bases are not closure edges.
#[must_use]
pub fn edge_count(object: &Object) -> u64 {
    match object {
        Object::Commit(commit) => commit.parents.len() as u64 + 1,
        Object::Remix(remix) => remix.parents.len() as u64 + 1,
        Object::Tree(tree) => tree.entries.len() as u64,
        Object::ChunkedBlob(manifest) => manifest.chunks.len() as u64,
        Object::Tag(_) => 1,
        Object::Blob(_) | Object::Delta(_) => 0,
    }
}

/// Direct reference at `ordinal`, or `None` beyond the complete sequence.
///
/// Each call takes constant time and allocates nothing. Commit and remix trees
/// precede their parents; other edges retain their canonical occurrence order.
/// Kind hints for tree entries and tags are diagnostic under the baseline
/// profile. File entry modes admit Blob or ChunkedBlob, so they have no single
/// expected kind. No edge has an individual expected length: manifest totals
/// must be checked separately, counting every chunk occurrence.
#[must_use]
pub fn edge_at(object: &Object, ordinal: u64) -> Option<ObjectEdge> {
    let index = usize::try_from(ordinal).ok()?;
    let (target, kind, expected_kind) = match object {
        Object::Commit(commit) => {
            if index == 0 {
                (commit.tree_hash, EdgeKind::Tree, Some(ObjectType::Tree))
            } else {
                (*commit.parents.get(index - 1)?, EdgeKind::Parent, None)
            }
        }
        Object::Remix(remix) => {
            if index == 0 {
                (remix.tree_hash, EdgeKind::Tree, Some(ObjectType::Tree))
            } else {
                (*remix.parents.get(index - 1)?, EdgeKind::Parent, None)
            }
        }
        Object::Tree(tree) => {
            let entry = tree.entries.get(index)?;
            let expected = match entry.mode {
                EntryMode::Tree => Some(ObjectType::Tree),
                EntryMode::Symlink => Some(ObjectType::Blob),
                EntryMode::Blob | EntryMode::Executable => None,
            };
            (entry.object_hash, EdgeKind::TreeEntry, expected)
        }
        Object::ChunkedBlob(manifest) => (
            *manifest.chunks.get(index)?,
            EdgeKind::Chunk,
            Some(ObjectType::Blob),
        ),
        Object::Tag(tag) if index == 0 => (tag.target, EdgeKind::TagTarget, Some(tag.target_type)),
        Object::Tag(_) | Object::Blob(_) | Object::Delta(_) => return None,
    };
    Some(ObjectEdge {
        target,
        kind,
        ordinal,
        expected_kind,
        expected_len: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mkit_core::object::{
        Blob, ChunkedBlob, Commit, Delta, Identity, Remix, RemixSource, Tag, Tree, TreeEntry,
    };
    use mkit_core::ops::graph::{ClosureMode, children};

    fn assert_edges(object: Object, expected: &[(u8, EdgeKind, Option<ObjectType>)]) {
        assert_eq!(edge_count(&object), expected.len() as u64);
        let mut targets = Vec::new();
        for (ordinal, (target, kind, expected_kind)) in expected.iter().enumerate() {
            let edge = edge_at(&object, ordinal as u64);
            assert_eq!(
                edge,
                Some(ObjectEdge {
                    target: [*target; 32],
                    kind: *kind,
                    ordinal: ordinal as u64,
                    expected_kind: *expected_kind,
                    expected_len: None,
                })
            );
            targets.push([*target; 32]);
        }
        assert_eq!(targets, children(&object, ClosureMode::History));
        assert_eq!(edge_at(&object, expected.len() as u64), None);
        assert_eq!(edge_at(&object, u64::MAX), None);
    }

    #[test]
    fn commit_and_remix_include_parents_but_exclude_foreign_sources() {
        assert_edges(
            Object::Commit(Commit::new_unannotated(
                [1; 32],
                vec![[2; 32], [2; 32]],
                Identity::ed25519([0; 32]),
                [0; 32],
                Vec::new(),
                0,
                [0; 64],
            )),
            &[
                (1, EdgeKind::Tree, Some(ObjectType::Tree)),
                (2, EdgeKind::Parent, None),
                (2, EdgeKind::Parent, None),
            ],
        );
        assert_edges(
            Object::Remix(Remix {
                tree_hash: [1; 32],
                parents: vec![[2; 32]],
                sources: vec![RemixSource {
                    upstream_id: [3; 32],
                    commit_hash: [4; 32],
                }],
                author: Identity::ed25519([0; 32]),
                signer: [0; 32],
                message: Vec::new(),
                timestamp: 0,
                signature: [0; 64],
            }),
            &[
                (1, EdgeKind::Tree, Some(ObjectType::Tree)),
                (2, EdgeKind::Parent, None),
            ],
        );
    }

    #[test]
    fn tree_modes_only_record_kind_hints() {
        let entries = [
            EntryMode::Blob,
            EntryMode::Tree,
            EntryMode::Symlink,
            EntryMode::Executable,
        ]
        .into_iter()
        .enumerate()
        .map(|(index, mode)| TreeEntry {
            name: vec![b'a' + index as u8],
            mode,
            object_hash: [1; 32],
        })
        .collect();
        assert_edges(
            Object::Tree(Tree { entries }),
            &[
                (1, EdgeKind::TreeEntry, None),
                (1, EdgeKind::TreeEntry, Some(ObjectType::Tree)),
                (1, EdgeKind::TreeEntry, Some(ObjectType::Blob)),
                (1, EdgeKind::TreeEntry, None),
            ],
        );
        assert_edges(
            Object::Tree(Tree {
                entries: Vec::new(),
            }),
            &[],
        );
    }

    #[test]
    fn chunk_occurrences_have_no_inferred_individual_length() {
        for chunk_size in [0, 7] {
            assert_edges(
                Object::ChunkedBlob(ChunkedBlob {
                    total_size: 9,
                    chunk_size,
                    chunks: vec![[1; 32], [1; 32], [2; 32]],
                }),
                &[
                    (1, EdgeKind::Chunk, Some(ObjectType::Blob)),
                    (1, EdgeKind::Chunk, Some(ObjectType::Blob)),
                    (2, EdgeKind::Chunk, Some(ObjectType::Blob)),
                ],
            );
        }
    }

    #[test]
    fn tag_declared_kind_is_diagnostic_and_leaves_have_no_edges() {
        assert_edges(
            Object::Tag(Tag {
                target: [1; 32],
                target_type: ObjectType::Tree,
                name: b"tag".to_vec(),
                tagger: Identity::ed25519([0; 32]),
                signer: [0; 32],
                message: Vec::new(),
                timestamp: 0,
                signature: [0; 64],
            }),
            &[(1, EdgeKind::TagTarget, Some(ObjectType::Tree))],
        );
        assert_edges(Object::Blob(Blob { data: vec![1] }), &[]);
        assert_edges(
            Object::Delta(Delta {
                base_hash: [1; 32],
                result_size: 0,
                instructions: Vec::new(),
            }),
            &[],
        );
    }
}
