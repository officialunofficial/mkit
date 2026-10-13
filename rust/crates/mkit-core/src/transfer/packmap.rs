//! Pure packmap planning shared by native and runtime-independent push drivers.
//! Callers validate/walk chains, classify failures, authorize resets, and do I/O.

use std::collections::HashSet;

use super::{PackListError, encode_packlist};
use crate::{hash::Hash, pack::pack_key, refs::RefWriteCondition};

/// Resolved state for one CAS attempt. Re-read and resolve after a conflict.
#[derive(Debug)]
pub enum ChainState {
    /// No packmap ref exists.
    Missing,
    /// A validated chain; `packs` contains every pack in it.
    /// Consumed so the set is dropped before encoding or uploading the node.
    Append { head: Hash, packs: HashSet<Hash> },
    /// An authorized self-contained reset, including a broken-chain escape.
    /// `prior` is the live ref value, even though the new node has no predecessor.
    Reset { prior: Option<Hash> },
}

/// A packmap ref move and the content-addressed node it advertises.
#[derive(Debug, PartialEq, Eq)]
pub struct Node {
    pub bytes: Vec<u8>,
    pub key: Hash,
    pub condition: RefWriteCondition,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PlanError {
    #[error(transparent)]
    Packlist(#[from] PackListError),
    #[error("packmap node exceeds byte limit")]
    NodeTooLarge,
}

/// Plan one attempt without I/O. `None` means only the head needs to move:
/// every new pack is already advertised by the validated chain. Otherwise,
/// upload the returned node before advancing its ref and the caller's head.
/// New packs retain their exact apply order, including partial overlaps.
///
/// Resets always produce a node and CAS against `prior`. The host decides
/// rollover depth before building a self-contained pack; this function never
/// changes that decision on retry. `max_node_bytes = None` preserves drivers
/// without a separate node-size limit. The codec entry cap applies when encoding a node.
///
/// # Errors
/// Returns a codec error or [`PlanError::NodeTooLarge`].
pub fn plan_advance(
    state: ChainState,
    packs: &[Hash],
    max_node_bytes: Option<u64>,
) -> Result<Option<Node>, PlanError> {
    let (prior, prev) = match state {
        ChainState::Missing => (None, None),
        ChainState::Append { head, packs: held } => {
            if packs.iter().all(|key| held.contains(key)) {
                return Ok(None);
            }
            drop(held);
            (Some(head), Some(head))
        }
        ChainState::Reset { prior } => (prior, None),
    };
    let bytes = encode_packlist(prev, packs)?;
    if max_node_bytes.is_some_and(|limit| bytes.len() as u64 > limit) {
        return Err(PlanError::NodeTooLarge);
    }
    Ok(Some(Node {
        key: pack_key(&bytes),
        bytes,
        condition: prior.map_or(RefWriteCondition::Missing, RefWriteCondition::Match),
    }))
}
