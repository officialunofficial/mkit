//! Frozen semantic facts exercise the pull machine without defining a wire format.

use super::{
    ClosureRequest, ClosureResponse, ClosureStep, ClosureWalker, EdgeKind, InPackObject,
    InPackObjectView, MembershipAnswer, MembershipResponse, ObjectEdge,
    limits::ClosureLimits,
    output::{PageDecodeCfg, decode_missing},
};
use crate::{
    error::Failure,
    evidence::{
        MemberFact, PackSource, PageCommitment, ProfileId, RepositoryId, Revision, RulesetBinding,
        RulesetId, SourceBinding,
    },
    pack_verify::{Acquisition, VerifiedPack},
};
use mkit_core::{
    hash::{Hash, hash},
    object::ObjectType,
};
use std::collections::BTreeMap;

const CASE: &str = include_str!("../../fixtures/closure/direct-children.case");
const REPOSITORY: RepositoryId = RepositoryId([61; 32]);
const VIEW: Revision = Revision([62; 32]);

fn id(text: &str) -> Hash {
    [text.parse::<u8>().unwrap(); 32]
}
fn kind(text: &str) -> ObjectType {
    match text {
        "Commit" => ObjectType::Commit,
        "Tree" => ObjectType::Tree,
        "Blob" => ObjectType::Blob,
        _ => panic!("unknown trusted fixture kind"),
    }
}
fn role(text: &str) -> EdgeKind {
    match text {
        "Tree" => EdgeKind::Tree,
        "TreeEntry" => EdgeKind::TreeEntry,
        _ => panic!("unknown trusted fixture edge role"),
    }
}
fn fact(object: Hash, kind: ObjectType, canonical_len: u64) -> MemberFact {
    MemberFact {
        repository: REPOSITORY,
        incarnation: VIEW,
        object,
        kind,
        canonical_len,
        supplier: PackSource {
            id: [63; 32],
            len: 256,
            binding: SourceBinding([64; 32]),
        },
        canonical_binding: SourceBinding([65; 32]),
        revision: Revision([66; 32]),
        delta_depth: 0,
        published: true,
        held: false,
    }
}

#[derive(Default)]
struct ViewFacts {
    objects: Vec<InPackObject>,
    edges: BTreeMap<Hash, Vec<ObjectEdge>>,
}
impl InPackObjectView for ViewFacts {
    fn object_set_root(&self) -> Hash {
        hash(CASE.as_bytes())
    }
    fn retained_bytes(&self) -> u64 {
        // Conservative bound for this tiny frozen table, including map nodes.
        4096
    }
    fn object_count(&self) -> u64 {
        self.objects.len() as u64
    }
    fn object(&self, id: &Hash) -> Result<Option<InPackObject>, Failure> {
        Ok(self
            .objects
            .iter()
            .find(|object| object.object == *id)
            .copied())
    }
    fn edge(&self, id: &Hash, ordinal: u64) -> Result<Option<ObjectEdge>, Failure> {
        Ok(self.edges.get(id).and_then(|edges| {
            usize::try_from(ordinal)
                .ok()
                .and_then(|ordinal| edges.get(ordinal))
                .copied()
        }))
    }
    fn object_at(&self, ordinal: u64) -> Result<Option<InPackObject>, Failure> {
        Ok(usize::try_from(ordinal)
            .ok()
            .and_then(|ordinal| self.objects.get(ordinal))
            .copied())
    }
}

#[derive(Default)]
struct Case {
    view: ViewFacts,
    heads: Vec<Hash>,
    members: BTreeMap<Hash, Option<MemberFact>>,
    expected_missing: Vec<Hash>,
}
fn parse_trusted_case() -> Case {
    let mut case = Case::default();
    for line in CASE
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        let fields: Vec<_> = line.split_whitespace().collect();
        match fields.as_slice() {
            ["object", object, object_kind, len] => case.view.objects.push(InPackObject {
                object: id(object),
                kind: kind(object_kind),
                canonical_len: len.parse().unwrap(),
            }),
            ["edge", source, target, edge_role, ordinal, hint] => {
                let edges = case.view.edges.entry(id(source)).or_default();
                assert_eq!(ordinal.parse::<u64>().unwrap(), edges.len() as u64);
                edges.push(ObjectEdge {
                    target: id(target),
                    kind: role(edge_role),
                    ordinal: ordinal.parse().unwrap(),
                    expected_kind: Some(kind(hint)),
                    expected_len: None,
                });
            }
            ["head", object] => case.heads.push(id(object)),
            ["member", object, "absent"] => {
                case.members.insert(id(object), None);
            }
            ["member", object, object_kind, len] => {
                case.members.insert(
                    id(object),
                    Some(fact(id(object), kind(object_kind), len.parse().unwrap())),
                );
            }
            ["missing", object] => case.expected_missing.push(id(object)),
            _ => panic!("unknown trusted fixture record"),
        }
    }
    assert_eq!(case.view.objects.len(), 3);
    assert_eq!(case.members.len(), 2);
    case
}

fn missing_ids(mut cursor: Option<PageCommitment>, pages: &BTreeMap<Hash, Vec<u8>>) -> Vec<Hash> {
    let mut actual = Vec::new();
    for _ in 0..16 {
        let Some(page) = cursor else {
            break;
        };
        let decoded = decode_missing(
            page,
            &pages[&page.digest],
            PageDecodeCfg {
                max_bytes: 4096,
                max_reasons: 16,
                max_work: 8192,
            },
        )
        .unwrap();
        actual.push(decoded.missing.object);
        cursor = decoded.previous;
    }
    assert!(cursor.is_none(), "missing pages exceed fixture bound");
    actual
}

#[test]
fn frozen_direct_children_case_checks_surplus_and_repository_frontier() {
    let case = parse_trusted_case();
    let limits = ClosureLimits {
        items: 16,
        edges: 16,
        depth: 8,
        decoded_bytes: 1024,
        object_bytes: 1024,
        resident_bytes: 1 << 20,
        evidence_bytes: 64 << 10,
        evidence_pages: 20,
        missing_items: 16,
        membership_batch: 4,
        work: 100_000,
    };
    let verified = VerifiedPack::synthetic_for_tests(
        case.view.object_set_root(),
        RulesetBinding {
            ruleset: RulesetId(1),
            profile: ProfileId::Indexed,
        },
    );
    let mut walker = ClosureWalker::new(
        case.view,
        &verified,
        &case.heads,
        REPOSITORY,
        VIEW,
        RulesetBinding {
            ruleset: RulesetId(1),
            profile: ProfileId::Indexed,
        },
        limits,
        1,
    )
    .unwrap();
    let mut pages = BTreeMap::new();
    let mut retained = 0;
    for _ in 0..1000 {
        match walker.step().unwrap() {
            ClosureStep::Progress => {}
            ClosureStep::Closed(_) => panic!("absent surplus-tree child must prevent closure"),
            ClosureStep::Retain(event) => {
                let request = event.request;
                let page = event.page;
                pages.insert(page.digest, event.bytes.to_vec());
                retained += 1;
                assert!(retained < 20);
                walker.acknowledge(request, page).unwrap();
            }
            ClosureStep::Request(request) => match request.clone() {
                ClosureRequest::Membership(request) => {
                    assert_eq!(request.repository, REPOSITORY);
                    assert_eq!(request.view, VIEW);
                    assert!(request.objects.len() <= 4);
                    let answers = request
                        .objects
                        .iter()
                        .map(|object| MembershipAnswer {
                            object: *object,
                            value: match &case.members[object] {
                                Some(fact) => Acquisition::Present(fact.clone()),
                                None => Acquisition::Absent,
                            },
                        })
                        .collect();
                    walker
                        .answer(ClosureResponse::Membership(MembershipResponse {
                            request: request.request,
                            repository: request.repository,
                            view: request.view,
                            answers,
                        }))
                        .unwrap();
                }
                ClosureRequest::Page { request, page } => {
                    walker
                        .answer(ClosureResponse::Page {
                            request,
                            page,
                            value: Acquisition::Present(&pages[&page.digest]),
                        })
                        .unwrap();
                }
                ClosureRequest::Canonical { .. } => {
                    panic!("existence-only children need no canonical bytes")
                }
            },
            ClosureStep::Missing(set) => {
                let actual = missing_ids(set.root(), &pages);
                assert_eq!(set.count(), actual.len() as u64);
                assert_eq!(actual, case.expected_missing);
                return;
            }
        }
    }
    panic!("frozen closure case exceeded its finite transition bound");
}
