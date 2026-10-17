//! Deterministic adversarial pair-transition replay over twelve synthetic IDs.
//!
//! The input is a structured plan: packmap nodes, object facts, base facts,
//! cleared sets, absence/unavailability sets, response tampering, and a
//! checkpoint/resume cadence. No panic, unbounded work, or `Covered` after an
//! invalid fact is allowed.

use std::collections::{BTreeMap, BTreeSet};

use mkit_core::{hash::Hash, object::ObjectType};
use mkit_primitives::{
    closure::pair::{
        BaseFact, ClearedSet, ObjectFact, PackmapNode, PairCheckpointCfg, PairLimits, PairRequest,
        PairResponse, PairResume, PairStep, PairWalker, ResultingPair,
    },
    evidence::{ProfileId, RepositoryId, Revision, RulesetBinding, RulesetId},
    pack_verify::Acquisition,
};

const REPOSITORY: RepositoryId = RepositoryId([5; 32]);
const REVISION: Revision = Revision([6; 32]);
const RULESET: RulesetBinding = RulesetBinding {
    ruleset: RulesetId(1),
    profile: ProfileId::Indexed,
};
const MAX_TRANSITIONS: u64 = 8_000;
const CFG: PairCheckpointCfg = PairCheckpointCfg { max_bytes: 1 << 16 };

fn id(index: u8) -> Hash {
    let mut result = [0; 32];
    result[0] = 9;
    result[1] = index;
    result
}
fn byte(data: &[u8], index: usize) -> u8 {
    if data.is_empty() {
        0
    } else {
        data[index % data.len()]
    }
}
fn ids(data: &[u8], from: usize, count: usize) -> Vec<Hash> {
    (0..count).map(|n| id(byte(data, from + n) % 12)).collect()
}
fn sorted(data: &[u8], from: usize, count: usize) -> Vec<Hash> {
    let out: BTreeSet<Hash> = ids(data, from, count).into_iter().collect();
    if byte(data, from + count).is_multiple_of(4) {
        // Occasionally corrupt the required ordering.
        let mut scrambled: Vec<Hash> = out.iter().copied().collect();
        scrambled.reverse();
        return scrambled;
    }
    out.into_iter().collect()
}

type NodeRow = (Option<Hash>, Vec<Hash>, bool);
type FactRow = (Hash, ObjectType, Vec<Hash>, Vec<Hash>, Option<Hash>);
struct Tables {
    nodes: BTreeMap<Hash, NodeRow>,
    objects: BTreeMap<Hash, FactRow>,
    cleared: (Vec<Hash>, Vec<Hash>),
    cleared_known: bool,
    bases: BTreeMap<Hash, BaseFact>,
    absent: BTreeSet<Hash>,
    unavailable: BTreeSet<Hash>,
}
impl Tables {
    fn acquire<T>(&self, object: Hash, present: impl FnOnce(&Self) -> T) -> Acquisition<T> {
        if self.unavailable.contains(&object) {
            return Acquisition::Unavailable;
        }
        if self.absent.contains(&object) {
            return Acquisition::Absent;
        }
        Acquisition::Present(present(self))
    }
    fn request_id(request: &PairRequest) -> Option<mkit_primitives::pack_verify::RequestId> {
        Some(match *request {
            PairRequest::PackmapNode { request, .. }
            | PairRequest::Boundary { request }
            | PairRequest::Object { request, .. }
            | PairRequest::Base { request, .. } => request,
            _ => return None,
        })
    }
    fn answer(&self, request: &PairRequest) -> Option<PairResponse<'static>> {
        Some(match *request {
            PairRequest::PackmapNode { request, pack, .. } => PairResponse::PackmapNode {
                request,
                pack,
                value: self.acquire(pack, |tables| {
                    let (prev, packs, boundary) =
                        tables.nodes.get(&pack).cloned().unwrap_or_default();
                    PackmapNode {
                        prev,
                        packs: Box::leak(packs.into_boxed_slice()),
                        boundary,
                    }
                }),
            },
            PairRequest::Boundary { request } => PairResponse::Boundary {
                request,
                value: if self.cleared_known {
                    let (objects, suppliers) = self.cleared.clone();
                    Acquisition::Present(ClearedSet {
                        objects: Box::leak(objects.into_boxed_slice()),
                        suppliers: Box::leak(suppliers.into_boxed_slice()),
                    })
                } else {
                    Acquisition::Absent
                },
            },
            PairRequest::Object {
                request, object, ..
            } => PairResponse::Object {
                request,
                object,
                value: self.acquire(object, |tables| {
                    let fact = tables.objects.get(&object).cloned().unwrap_or((
                        object,
                        ObjectType::Blob,
                        Vec::new(),
                        Vec::new(),
                        None,
                    ));
                    ObjectFact {
                        pack: fact.0,
                        kind: fact.1,
                        children: Box::leak(fact.2.into_boxed_slice()),
                        suppliers: Box::leak(fact.3.into_boxed_slice()),
                        base: fact.4,
                    }
                }),
            },
            PairRequest::Base {
                request, object, ..
            } => PairResponse::Base {
                request,
                object,
                value: self.acquire(object, |tables| {
                    tables.bases.get(&object).copied().unwrap_or(BaseFact {
                        pack: object,
                        base: None,
                    })
                }),
            },
            _ => return None,
        })
    }
}

fn tables(data: &[u8]) -> Tables {
    let mut nodes = BTreeMap::new();
    for n in 0usize..4 {
        let node = id(u8::try_from(n).expect("few nodes"));
        let prev = match byte(data, 4 + n) % 6 {
            0 | 1 => None,
            tail => Some(id(tail % 5)),
        };
        let packs = ids(data, 8 + n * 4, (byte(data, 20 + n) % 3) as usize);
        nodes.insert(node, (prev, packs, byte(data, 24 + n) & 1 != 0));
    }
    let kinds = [
        ObjectType::Blob,
        ObjectType::Tree,
        ObjectType::Commit,
        ObjectType::Remix,
        ObjectType::Tag,
        ObjectType::Delta,
    ];
    let mut objects = BTreeMap::new();
    for n in 0usize..12 {
        let object = id(u8::try_from(n).expect("few objects"));
        let children = ids(data, 32 + n * 2, (byte(data, 60 + n) % 3) as usize);
        let suppliers = ids(data, 88 + n, (byte(data, 100 + n) % 2) as usize);
        let base = byte(data, 116 + n)
            .is_multiple_of(5)
            .then(|| id(byte(data, 132 + n) % 12));
        objects.insert(
            object,
            (
                id(byte(data, 44 + n) % 5),
                kinds[(byte(data, 148 + n) % 6) as usize],
                children,
                suppliers,
                base,
            ),
        );
    }
    let mut bases = BTreeMap::new();
    for n in 0usize..12 {
        let object = id(u8::try_from(n).expect("few objects"));
        bases.insert(
            object,
            BaseFact {
                pack: id(byte(data, 160 + n) % 5),
                base: byte(data, 176 + n)
                    .is_multiple_of(4)
                    .then(|| id(byte(data, 192 + n) % 12)),
            },
        );
    }
    Tables {
        nodes,
        objects,
        cleared: (sorted(data, 208, 4), sorted(data, 216, 4)),
        cleared_known: byte(data, 225) & 1 != 0,
        bases,
        absent: ids(data, 226, 4).into_iter().collect(),
        unavailable: ids(data, 240, 4).into_iter().collect(),
    }
}

fn limits(data: &[u8]) -> PairLimits {
    PairLimits {
        chain: 6 + u32::from(byte(data, 250)) % 6,
        packs: 6 + u32::from(byte(data, 251)) % 6,
        discovered: 6 + u32::from(byte(data, 252)) % 8,
        dependencies: 6 + u32::from(byte(data, 253)) % 8,
        suppliers: 6 + u32::from(byte(data, 254)) % 4,
        cleared: 2 + u32::from(byte(data, 255)) % 4,
        max_delta_depth: 1 + u32::from(byte(data, 256)) % 4,
        work: 200 + u64::from(byte(data, 257)) * 100,
    }
}

/// Replay one pair-coverage run against hostile but structured tables.
///
/// # Panics
/// Panics when the finite transition bound is exceeded; that is the oracle
/// for a runaway machine.
pub fn replay(data: &[u8]) {
    let pair = ResultingPair {
        head: (byte(data, 0) & 1 != 0).then(|| id(10)),
        packmap: (byte(data, 0) & 2 != 0).then(|| id(byte(data, 1) % 5)),
        branch: byte(data, 0) & 4 != 0,
    };
    let additions = ids(data, 2, 2);
    let honor_cleared = byte(data, 3) & 1 != 0;
    let limits = limits(data);
    let tables = tables(data);
    let cadence = 1 + usize::from(byte(data, 260)) % 4;
    let mut generation = 1u64;
    let Ok(mut walker) = PairWalker::new(
        pair,
        &additions,
        REPOSITORY,
        REVISION,
        RULESET,
        limits,
        honor_cleared,
        generation,
    ) else {
        return;
    };
    let mut steps = 0u64;
    let mut since_resume = 0usize;
    loop {
        steps += 1;
        assert!(
            steps <= MAX_TRANSITIONS,
            "pair replay exceeded its transition bound"
        );
        match walker.step() {
            Ok(PairStep::Progress) => {}
            Ok(PairStep::Request(request)) => {
                let request = request.clone();
                let Some(mut response) = tables.answer(&request) else {
                    break;
                };
                if byte(data, 270 + usize::try_from(steps).expect("bounded")).is_multiple_of(17) {
                    // Tamper: stale generation or a mismatched echo must refuse.
                    let Some(request_id) = Tables::request_id(&request) else {
                        break;
                    };
                    let stale = mkit_primitives::pack_verify::RequestId {
                        generation: request_id.generation + 1,
                        sequence: request_id.sequence,
                    };
                    response = PairResponse::Boundary {
                        request: stale,
                        value: Acquisition::Absent,
                    };
                }
                if walker.answer(response).is_err() {
                    break;
                }
                since_resume += 1;
                if since_resume.is_multiple_of(cadence)
                    && let Ok(bytes) = walker.checkpoint()
                {
                    PairWalker::validate_checkpoint(&bytes, CFG).expect("checkpoint decodes");
                    generation += 1;
                    let expected = PairResume {
                        pair,
                        additions: &additions,
                        repository: REPOSITORY,
                        view: REVISION,
                        ruleset: RULESET,
                        limits,
                        honor_cleared,
                    };
                    walker = PairWalker::resume(&bytes, CFG, &expected, generation)
                        .expect("checkpoint resumes");
                }
            }
            _ => break,
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn seeds_replay_without_panic() {
        crate::replay_seeds(super::replay);
    }
}
