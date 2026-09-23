//! Compare actual path occurrences, including modes and old object ids.

use std::collections::BTreeMap;

use crate::hash::Hash;
use crate::object::{EntryMode, Object};
use crate::verify::ObjectSource;

use super::PartialPath;
use super::recipient::RecipientError;
use super::recipient_graph::RecipientGraph;
use super::update::UpdateChange;

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
        let mut next = Vec::new();
        for (before, after) in old.entries.iter().zip(&new.entries) {
            if before.name != after.name || before.mode != after.mode {
                return Err(RecipientError::InvalidChange);
            }
            if before.object_hash == after.object_hash {
                continue;
            }
            let mut child_path = path.clone();
            child_path.push(before.name.clone());
            if before.mode == EntryMode::Tree {
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
