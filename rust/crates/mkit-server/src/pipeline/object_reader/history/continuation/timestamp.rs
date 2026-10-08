//! Timestamp-discovery redemption: resume a sealed reducer snapshot.
//!
//! The decoded walk is sealed, so seeding is impossible; every emission and
//! hydration follows [`TimestampDiscovery::step`]. Unknown priority keys are
//! hydrated in one batched `proved_nodes` pass per step; a known key is
//! rechecked against the decoded node at emission. A supplied key, decoded
//! timestamp or parent edge that disagrees with live state refuses the page —
//! the walk is never reordered to fit.
use super::super::{
    BTreeMap, BTreeSet, Budget, Hash, HookSet, MultipartBlobStore, NamespaceStore, Node,
    ObjectReader, ReaderSession, Role, ServerError, SliceBudget,
};
use super::absent;
use crate::HistoryStateLimit;
use crate::history_token::{ClaimState, WitnessNode};
use crate::pipeline::read_proofs::WitnessError;
use mkit_core::history_order::{HistoryOrderError, ParentEdge, TimestampDiscovery, WalkStep};

/// Map a reducer error: the state caps are explicit in either view, anything
/// else means the authenticated snapshot disagreed with live state.
fn order_error(error: &HistoryOrderError) -> ServerError {
    match error {
        HistoryOrderError::FrontierFull => {
            ServerError::history_state_limit_exceeded(HistoryStateLimit::Frontier)
        }
        HistoryOrderError::EmittedFull => {
            ServerError::history_state_limit_exceeded(HistoryStateLimit::Emitted)
        }
        _ => absent(),
    }
}

impl<B: MultipartBlobStore, N: NamespaceStore + Clone + 'static, H: HookSet>
    ObjectReader<'_, B, N, H>
{
    /// Serve up to `limit` commits from `walk`, then mint its successor.
    /// Hydrated-but-unemitted nodes live in `cache`; priority keys travel in
    /// the reducer's pending slots and are checked against the decoded node
    /// at emission.
    pub(super) async fn resume_timestamp(
        &self,
        session: &mut ReaderSession,
        mut walk: TimestampDiscovery,
        limit: usize,
        calls: &SliceBudget,
        admission: &crate::store::read_io::ReadIo,
        decode: &mut Budget,
    ) -> Result<(Vec<Node>, Option<(ClaimState, Vec<WitnessNode>)>), ServerError> {
        let mut output = Vec::new();
        let mut cache: BTreeMap<Hash, Node> = BTreeMap::new();
        while output.len() < limit {
            let known: BTreeMap<Hash, u64> = walk
                .pending()
                .iter()
                .filter_map(|candidate| candidate.timestamp.map(|t| (candidate.id, t)))
                .collect();
            match walk.step().map_err(|e| order_error(&e))? {
                WalkStep::Done => break,
                WalkStep::NeedTimestamp(_) => {
                    // Decode every unknown-key candidate in one pass: the
                    // batch keeps hydration inside the reader's bounded
                    // phases, and pending order keeps the carry deterministic.
                    let mut ids = Vec::new();
                    let mut seen = BTreeSet::new();
                    for candidate in walk.pending() {
                        if candidate.timestamp.is_none() && seen.insert(candidate.id) {
                            ids.push(candidate.id);
                        }
                    }
                    let nodes = self
                        .proved_nodes(session, &ids, Role::Commit, calls, admission, decode)
                        .await?;
                    for (id, node) in ids.iter().zip(nodes) {
                        let node = node.ok_or_else(absent)?;
                        let timestamp = node.timestamp().ok_or_else(absent)?;
                        walk.provide_timestamp(*id, timestamp)
                            .map_err(|_| absent())?;
                        cache.insert(*id, node);
                    }
                }
                WalkStep::Emit(id) => {
                    let node = match cache.remove(&id) {
                        Some(node) => node,
                        None => self
                            .proved_node(session, id, Role::Commit, calls, admission, decode)
                            .await?
                            .ok_or_else(absent)?,
                    };
                    if let Some(key) = known.get(&id)
                        && node.timestamp() != Some(*key)
                    {
                        return Err(absent());
                    }
                    let stop = self.seams.takedown.stops_descent(&self.repo, &node.id);
                    let parents: Vec<ParentEdge> = node
                        .parents()
                        .unwrap_or(&[])
                        .iter()
                        .map(|parent| ParentEdge {
                            id: *parent,
                            // A parent already pending with a server-checked
                            // key carries it forward without another load.
                            timestamp: cache
                                .get(parent)
                                .and_then(Node::timestamp)
                                .or_else(|| known.get(parent).copied()),
                            enqueue: !stop,
                        })
                        .collect();
                    for edge in &parents {
                        if edge.enqueue && !self.link_node(session, &node, edge.id)? {
                            return Err(absent());
                        }
                    }
                    walk.emit(&parents).map_err(|e| order_error(&e))?;
                    output.push(node);
                }
                _ => return Err(absent()),
            }
        }
        let successor = if walk.is_complete() {
            None
        } else {
            let mut targets = Vec::new();
            let mut seen = BTreeSet::new();
            for candidate in walk.pending() {
                if seen.insert(candidate.id) {
                    targets.push(candidate.id);
                }
            }
            match session.proofs.history_witness(&targets, false) {
                Ok(witness) => Some((ClaimState::TimestampDiscovery(walk), witness)),
                Err(WitnessError::Limit) => {
                    return Err(ServerError::history_state_limit_exceeded(
                        HistoryStateLimit::Provenance,
                    ));
                }
                Err(WitnessError::Unproven) => return Err(absent()),
            }
        };
        Ok((output, successor))
    }
}
