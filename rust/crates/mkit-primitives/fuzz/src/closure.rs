//! Deterministic adversarial closure-transition replay over eight synthetic IDs.

use std::collections::{BTreeMap, BTreeSet};

use mkit_core::{
    hash::{Hash, hash},
    object::ObjectType,
};
use mkit_primitives::{
    closure::{
        ClosureRequest, ClosureResponse, ClosureStep, ClosureWalker, EdgeKind, InPackObject,
        InPackObjectView, MembershipAnswer, MembershipResponse, ObjectEdge, limits::ClosureLimits,
    },
    error::{Failure, FailureCode},
    evidence::{
        MemberFact, PackSource, ProfileId, RepositoryId, Revision, RulesetBinding, RulesetId,
        SourceBinding,
    },
    pack_verify::{Acquisition, VerifiedPack},
};

const REPOSITORY: RepositoryId = RepositoryId([1; 32]);
const REVISION: Revision = Revision([2; 32]);
const MAX_TRANSITIONS: u64 = 12_000;

fn id(index: u8) -> Hash {
    // All IDs share a bucket, exercising immutable-chain traversal and updates.
    let mut result = [0; 32];
    result[0] = 17;
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

#[derive(Clone)]
struct Graph {
    targets: [[u8; 2]; 4],
    absent: u8,
}
impl Graph {
    fn new(data: &[u8]) -> Self {
        let mut targets = [[0; 2]; 4];
        for (source, edges) in targets.iter_mut().enumerate() {
            edges[0] = byte(data, source * 2 + 2) % 8;
            edges[1] = byte(data, source * 2 + 3) % 8;
        }
        // Every replay has an external frontier, including the empty seed.
        targets[0][0] = 4;
        Self {
            targets,
            absent: byte(data, 1),
        }
    }
    fn missing(&self) -> u64 {
        self.targets
            .iter()
            .flatten()
            .copied()
            .filter(|index| *index >= 4 && self.absent & (1 << (*index - 4)) != 0)
            .collect::<BTreeSet<_>>()
            .len() as u64
    }
}
impl InPackObjectView for Graph {
    fn object_set_root(&self) -> Hash {
        let mut bytes = [0; 8];
        for (out, source) in bytes.as_chunks_mut::<2>().0.iter_mut().zip(self.targets) {
            out.copy_from_slice(&source);
        }
        hash(&bytes)
    }
    fn retained_bytes(&self) -> u64 {
        std::mem::size_of_val(self) as u64
    }
    fn object_count(&self) -> u64 {
        4
    }
    fn object(&self, object: &Hash) -> Result<Option<InPackObject>, Failure> {
        Ok((0..4)
            .find(|index| id(*index) == *object)
            .map(|_| InPackObject {
                object: *object,
                kind: ObjectType::Tag,
                canonical_len: 10,
            }))
    }
    fn edge(&self, object: &Hash, ordinal: u64) -> Result<Option<ObjectEdge>, Failure> {
        let source = (0..4).find(|index| id(*index) == *object);
        Ok(source.and_then(|source| {
            usize::try_from(ordinal)
                .ok()
                .and_then(|ordinal| self.targets[usize::from(source)].get(ordinal))
                .map(|target| ObjectEdge {
                    target: id(*target),
                    kind: EdgeKind::TagTarget,
                    ordinal,
                    expected_kind: Some(ObjectType::Tag),
                    expected_len: None,
                })
        }))
    }
    fn object_at(&self, ordinal: u64) -> Result<Option<InPackObject>, Failure> {
        if ordinal >= 4 {
            return Ok(None);
        }
        self.object(&id(u8::try_from(ordinal).expect("ordinal is below four")))
    }
}

fn member(object: Hash) -> MemberFact {
    MemberFact {
        repository: REPOSITORY,
        incarnation: REVISION,
        object,
        kind: ObjectType::Tag,
        canonical_len: 10,
        supplier: PackSource {
            id: [3; 32],
            len: 128,
            binding: SourceBinding([4; 32]),
        },
        canonical_binding: SourceBinding([5; 32]),
        revision: REVISION,
        delta_depth: 0,
        published: true,
        held: false,
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Closed(Hash, u64),
    Missing(Hash, u64),
    Refused(FailureCode),
}
#[derive(Debug, Default, PartialEq, Eq)]
struct Counts {
    transitions: u64,
    membership_requests: u64,
    member_ids: u64,
    page_requests: u64,
    retained_pages: u64,
    retained_bytes: u64,
    supplied_bytes: u64,
}

fn refused(walker: &mut ClosureWalker<Graph>, failure: &Failure) -> Outcome {
    // A refusal poisons the run; polling cannot resurrect a proof.
    assert!(matches!(walker.step(), Err(error) if error.code == FailureCode::InvalidResponse));
    Outcome::Refused(failure.code)
}

#[allow(clippy::too_many_lines)]
fn run(data: &[u8]) -> (Outcome, Counts) {
    let graph = Graph::new(data);
    let expected_missing = graph.missing();
    let limits = ClosureLimits {
        items: 32,
        edges: 128,
        depth: 16,
        decoded_bytes: 1024,
        object_bytes: 1024,
        resident_bytes: 1 << 20,
        evidence_bytes: 128 << 10,
        evidence_pages: 128,
        missing_items: 8,
        membership_batch: 4,
        work: 10_000,
    };
    let rules = RulesetBinding {
        ruleset: RulesetId(1),
        profile: ProfileId::Indexed,
    };
    let verified = VerifiedPack::synthetic_for_tests(graph.object_set_root(), rules);
    let mut walker = ClosureWalker::new(
        graph.clone(),
        &verified,
        &[id(0)],
        REPOSITORY,
        REVISION,
        rules,
        limits,
        1,
    )
    .expect("finite synthetic graph fits construction allowances");
    let mut pages = BTreeMap::<Hash, Vec<u8>>::new();
    let mut counts = Counts::default();
    let mut event = 0usize;
    let mut unsafe_completion = false;
    for _ in 0..MAX_TRANSITIONS {
        counts.transitions += 1;
        let step = match walker.step() {
            Ok(step) => step,
            Err(error) => return (refused(&mut walker, &error), counts),
        };
        match step {
            ClosureStep::Progress => {}
            ClosureStep::Closed(proof) => {
                assert!(
                    !unsafe_completion,
                    "incomplete or invalid acquisition produced closure"
                );
                assert_eq!(
                    expected_missing, 0,
                    "closure omitted an absent direct child"
                );
                assert_eq!(proof.repository(), REPOSITORY);
                assert_eq!(proof.view(), REVISION);
                assert_eq!(proof.object_set_root(), graph.object_set_root());
                return (
                    Outcome::Closed(
                        proof.external_witnesses().root,
                        proof.external_witnesses().count,
                    ),
                    counts,
                );
            }
            ClosureStep::Missing(missing) => {
                assert!(
                    !unsafe_completion,
                    "invalid acquisition produced a complete missing set"
                );
                assert_eq!(missing.count(), expected_missing);
                return (
                    Outcome::Missing(missing.sequence().root, missing.count()),
                    counts,
                );
            }
            ClosureStep::Retain(retention) => {
                let request = retention.request;
                let mut page = retention.page;
                let bytes = retention.bytes.to_vec();
                assert_eq!(page.len, bytes.len() as u64);
                assert!(bytes.len() <= 4096);
                counts.retained_pages += 1;
                counts.retained_bytes += page.len;
                let mode = byte(data, event + 10) % 16;
                event += 1;
                if mode == 15 {
                    page.digest[0] ^= 1;
                    unsafe_completion = true;
                } else {
                    pages.insert(page.digest, bytes);
                }
                if let Err(error) = walker.acknowledge(request, page) {
                    return (refused(&mut walker, &error), counts);
                }
                assert!(
                    !unsafe_completion,
                    "incorrect retention acknowledgement accepted"
                );
            }
            ClosureStep::Request(request) => {
                let request = request.clone();
                let mode = byte(data, event + 10) % 16;
                event += 1;
                let result = match request {
                    ClosureRequest::Membership(request) => {
                        counts.membership_requests += 1;
                        counts.member_ids += request.objects.len() as u64;
                        assert_ne!(request.objects, [] as [[u8; 32]; 0]);
                        assert!(request.objects.len() <= 4);
                        let mut answers = Vec::with_capacity(request.objects.len());
                        for object in &request.objects {
                            let index = object[1];
                            assert!((4..8).contains(&index));
                            let value = if graph.absent & (1 << (index - 4)) != 0 {
                                Acquisition::Absent
                            } else {
                                Acquisition::Present(member(*object))
                            };
                            answers.push(MembershipAnswer {
                                object: *object,
                                value,
                            });
                        }
                        let mut response = MembershipResponse {
                            request: request.request,
                            repository: request.repository,
                            view: request.view,
                            answers,
                        };
                        match mode {
                            1 => {
                                response.answers.pop();
                            }
                            2 => {
                                if response.answers.len() > 1 {
                                    response.answers[1] = response.answers[0].clone();
                                } else {
                                    response.answers.push(response.answers[0].clone());
                                }
                            }
                            3 => {
                                response.request.generation ^= 1;
                            }
                            4 => {
                                response.repository = RepositoryId([9; 32]);
                            }
                            5 => {
                                response.answers[0].value = Acquisition::Present({
                                    let mut fact = member(response.answers[0].object);
                                    fact.repository = RepositoryId([9; 32]);
                                    fact
                                });
                            }
                            6 => {
                                response.answers[0].value = Acquisition::Unavailable;
                            }
                            7 => {
                                response.answers.reverse();
                                if response.answers.len() == 1 {
                                    response.answers[0].object[2] ^= 1;
                                }
                            }
                            _ => {}
                        }
                        if (1..=7).contains(&mode) {
                            unsafe_completion = true;
                        }
                        walker.answer(ClosureResponse::Membership(response))
                    }
                    ClosureRequest::Page {
                        mut request,
                        mut page,
                    } => {
                        counts.page_requests += 1;
                        let mut bytes = pages
                            .get(&page.digest)
                            .cloned()
                            .expect("requested acknowledged page");
                        let value = match mode {
                            8 => {
                                unsafe_completion = true;
                                Acquisition::Absent
                            }
                            9 => {
                                unsafe_completion = true;
                                Acquisition::Unavailable
                            }
                            10 => {
                                unsafe_completion = true;
                                bytes[0] ^= 1;
                                Acquisition::Present(bytes.as_slice())
                            }
                            11 => {
                                unsafe_completion = true;
                                request.sequence ^= 1;
                                Acquisition::Present(bytes.as_slice())
                            }
                            12 => {
                                unsafe_completion = true;
                                page.digest[0] ^= 1;
                                Acquisition::Present(bytes.as_slice())
                            }
                            13 => {
                                unsafe_completion = true;
                                if let Some(other) =
                                    pages.iter().find(|(key, _)| **key != page.digest)
                                {
                                    bytes.clone_from(other.1);
                                } else {
                                    bytes.clear();
                                }
                                Acquisition::Present(bytes.as_slice())
                            }
                            _ => Acquisition::Present(bytes.as_slice()),
                        };
                        if let Acquisition::Present(supplied) = &value {
                            counts.supplied_bytes += supplied.len() as u64;
                        }
                        walker.answer(ClosureResponse::Page {
                            request,
                            page,
                            value,
                        })
                    }
                    ClosureRequest::Canonical { request, source } => {
                        // No synthetic edge is a chunk; unexpected byte acquisition fails closed.
                        unsafe_completion = true;
                        walker.answer(ClosureResponse::Canonical {
                            request,
                            source,
                            value: Acquisition::Unavailable,
                        })
                    }
                    other => panic!("unmodelled closure request: {other:?}"),
                };
                if let Err(error) = result {
                    return (refused(&mut walker, &error), counts);
                }
                assert!(
                    !unsafe_completion,
                    "malformed or unavailable response accepted"
                );
            }
            other => panic!("unmodelled closure step: {other:?}"),
        }
    }
    panic!("finite work ceiling did not bound closure transitions");
}

/// Replay a bounded input twice and compare normalized outcomes and host work.
///
/// # Panics
///
/// Panics if a malformed response, lost page, missing child, nondeterministic
/// transition, or ignored finite execution ceiling produces invalid completion.
pub fn replay(data: &[u8]) {
    let data = &data[..data.len().min(256)];
    assert_eq!(run(data), run(data));
}

#[cfg(test)]
mod tests {
    #[test]
    fn stable_closure_transition_seeds() {
        crate::replay_seeds(super::replay);
        for mode in 0..16u8 {
            super::replay(&[mode; 32]);
        }
        super::replay(&[0, 15, 4, 5, 6, 7, 0, 1, 2, 3]);
        let mut absent = [0; 256];
        absent[1] = 15;
        super::replay(&absent);
    }
}
