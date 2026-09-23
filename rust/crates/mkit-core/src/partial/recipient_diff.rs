//! Compare actual path occurrences, including modes and old object ids.

#[cfg(test)]
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};

use crate::hash::Hash;
use crate::object::{EntryMode, Object};
use crate::verify::ObjectSource;

use super::PartialPath;
use super::recipient::RecipientError;
use super::recipient_graph::RecipientGraph;
use super::update::UpdateChange;

#[cfg(test)]
thread_local! {
    static QUEUED_TREE_PATHS: Cell<usize> = const { Cell::new(0) };
}

pub(super) fn verify_diff<S: ObjectSource + ?Sized>(
    graph: &mut RecipientGraph<'_, S>,
    base: Hash,
    candidate: Hash,
    declared: &[UpdateChange],
) -> Result<(), RecipientError> {
    let expected: BTreeMap<_, _> = declared
        .iter()
        .map(|change| (change.path.clone(), change))
        .collect();
    let mut found = 0usize;
    let mut stack = vec![(
        graph.root_tree(&base)?,
        graph.root_tree(&candidate)?,
        PartialPath::new(),
    )];
    while let Some((old_id, new_id, path)) = stack.pop() {
        graph.charge(1)?;
        if old_id == new_id {
            continue;
        }
        let (Object::Tree(old), Object::Tree(new)) =
            (graph.object(&old_id)?, graph.object(&new_id)?)
        else {
            return Err(RecipientError::WrongObjectType(old_id));
        };
        let old_len = old.entries.len();
        if old_len != new.entries.len() {
            return Err(RecipientError::InvalidChange);
        }
        graph.charge(old_len)?;
        let (Object::Tree(old), Object::Tree(new)) =
            (graph.object(&old_id)?, graph.object(&new_id)?)
        else {
            unreachable!()
        };
        // Build the direct declared frontier once for this changed Tree.
        // BTreeMap's range starts at the path prefix; only its contiguous
        // descendants are examined (at most the portable path count).
        let declared_children: BTreeSet<&[u8]> = expected
            .range(path.clone()..)
            .take_while(|(declared_path, _)| declared_path.starts_with(&path))
            .filter_map(|(declared_path, _)| declared_path.get(path.len()).map(Vec::as_slice))
            .collect();
        let mut next = Vec::new();
        for (before, after) in old.entries.iter().zip(&new.entries) {
            if before.name != after.name || before.mode != after.mode {
                return Err(RecipientError::InvalidChange);
            }
            if before.object_hash == after.object_hash {
                continue;
            }
            if before.mode == EntryMode::Tree && !declared_children.contains(before.name.as_slice())
            {
                return Err(RecipientError::InvalidChange);
            }
            let mut child_path = path.clone();
            child_path.push(before.name.clone());
            if before.mode == EntryMode::Tree {
                #[cfg(test)]
                QUEUED_TREE_PATHS.with(|count| count.set(count.get() + 1));
                next.push((before.object_hash, after.object_hash, child_path));
            } else {
                if !matches!(before.mode, EntryMode::Blob | EntryMode::Executable) {
                    return Err(RecipientError::InvalidChange);
                }
                let Some(change) = expected.get(&child_path) else {
                    return Err(RecipientError::InvalidChange);
                };
                if change.old_mode != before.mode
                    || change.old_id != before.object_hash
                    || change.new_id != after.object_hash
                {
                    return Err(RecipientError::InvalidChange);
                }
                found += 1;
            }
        }
        stack.extend(next);
    }
    if found != declared.len() {
        return Err(RecipientError::InvalidChange);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use crate::object::{Blob, Commit, Identity, Tree, TreeEntry, id_from_object};
    use crate::serialize::serialize;
    use crate::sign::{KeyPair, sign_commit};
    use crate::verify::VerifyError;

    use super::super::recipient::RecipientLimits;
    use super::*;

    struct MapSource(BTreeMap<Hash, Vec<u8>>);

    impl ObjectSource for MapSource {
        fn fetch(&mut self, id: &Hash) -> Result<Option<Cow<'_, [u8]>>, VerifyError> {
            Ok(self.0.get(id).map(|bytes| Cow::Borrowed(bytes.as_slice())))
        }
    }

    fn put(source: &mut MapSource, object: Object) -> Hash {
        let bytes = serialize(&object).unwrap();
        let id = id_from_object(&object, &bytes);
        source.0.insert(id, bytes);
        id
    }

    fn signed(source: &mut MapSource, root: Hash, parents: Vec<Hash>) -> Hash {
        let signer = KeyPair::from_seed([42; 32]);
        let mut commit = Commit::new_unannotated(
            root,
            parents,
            Identity::ed25519(signer.public.0),
            signer.public.0,
            b"frontier test".to_vec(),
            1_700_000_000,
            [0; 64],
        );
        commit.signature = sign_commit(&commit, &signer).unwrap().0;
        put(source, Object::Commit(commit))
    }

    #[test]
    fn undeclared_tree_fanout_is_rejected_before_queue_growth() {
        let mut source = MapSource(BTreeMap::new());
        let old_file = put(
            &mut source,
            Object::Blob(Blob {
                data: b"old".to_vec(),
            }),
        );
        let new_file = put(
            &mut source,
            Object::Blob(Blob {
                data: b"new".to_vec(),
            }),
        );
        let subtree = |file| {
            Object::Tree(Tree {
                entries: vec![TreeEntry {
                    name: b"leaf.txt".to_vec(),
                    mode: EntryMode::Blob,
                    object_hash: file,
                }],
            })
        };
        let old_tree = put(&mut source, subtree(old_file));
        let new_tree = put(&mut source, subtree(new_file));
        let root = |child| {
            let mut entries = vec![TreeEntry {
                name: b"a".to_vec(),
                mode: EntryMode::Tree,
                object_hash: child,
            }];
            for index in 0..32 {
                entries.push(TreeEntry {
                    name: format!("h{index:02}").into_bytes(),
                    mode: EntryMode::Tree,
                    object_hash: child,
                });
            }
            Object::Tree(Tree { entries })
        };
        let old_root = put(&mut source, root(old_tree));
        let new_root = put(&mut source, root(new_tree));
        let base = signed(&mut source, old_root, Vec::new());
        let candidate = signed(&mut source, new_root, vec![base]);
        let change = UpdateChange {
            path: vec![b"a".to_vec(), b"leaf.txt".to_vec()],
            old_mode: EntryMode::Blob,
            old_id: old_file,
            new_id: new_file,
        };
        let mut graph = RecipientGraph::new(&mut source, RecipientLimits::DEFAULT);
        graph.validate_base(base).unwrap();
        graph
            .validate_candidate(candidate, &BTreeMap::new())
            .unwrap();
        QUEUED_TREE_PATHS.with(|count| count.set(0));
        assert!(matches!(
            verify_diff(&mut graph, base, candidate, &[change]),
            Err(RecipientError::InvalidChange)
        ));
        QUEUED_TREE_PATHS.with(|count| assert_eq!(count.get(), 1));
    }
}
