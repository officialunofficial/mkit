use super::{
    edges::{edge_at, edge_count},
    limits::ClosureLimits,
    output::{PageDecodeCfg, decode_missing},
    walker::{
        CanonicalSource, ClosureDiagnostics, ClosureRequest, ClosureResponse, ClosureStep,
        ClosureWalker,
    },
    *,
};
use crate::{
    error::{Failure, FailureCode},
    evidence::{
        MemberFact, PackSource, PageCommitment, ProfileId, RepositoryId, Revision, RulesetBinding,
        RulesetId, SourceBinding,
    },
    pack_verify::Acquisition,
};
use mkit_core::{
    hash::Hash,
    object::{Blob, ChunkedBlob, EntryMode, Identity, Object, ObjectType, Tag, Tree, TreeEntry},
};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

const REPO: RepositoryId = RepositoryId([41; 32]);
const VIEW: Revision = Revision([42; 32]);
fn rules() -> RulesetBinding {
    RulesetBinding {
        ruleset: RulesetId(1),
        profile: ProfileId::Indexed,
    }
}
fn id(n: u8) -> Hash {
    [n; 32]
}
#[derive(Clone)]
struct Node {
    meta: InPackObject,
    edges: Vec<ObjectEdge>,
    bytes: Vec<u8>,
    manifest: Option<ChunkedBlobSummary>,
}
#[derive(Clone, Default)]
struct View(BTreeMap<Hash, Node>);
impl View {
    fn real(&mut self, object: Object) -> Hash {
        let manifest = match &object {
            Object::ChunkedBlob(value) => Some(ChunkedBlobSummary {
                total_size: value.total_size,
                chunks: value.chunks.len() as u64,
            }),
            _ => None,
        };
        let bytes = mkit_core::serialize::serialize(&object).unwrap();
        let object_id = mkit_core::object::id_from_object(&object, &bytes);
        let edges = (0..edge_count(&object))
            .map(|i| edge_at(&object, i).unwrap())
            .collect();
        self.0.insert(
            object_id,
            Node {
                meta: InPackObject {
                    object: object_id,
                    kind: object.object_type(),
                    canonical_len: bytes.len() as u64,
                },
                edges,
                bytes,
                manifest,
            },
        );
        object_id
    }
    fn graph(&mut self, key: Hash, targets: &[Hash]) {
        let edges = targets
            .iter()
            .enumerate()
            .map(|(ordinal, target)| ObjectEdge {
                target: *target,
                kind: EdgeKind::TreeEntry,
                ordinal: ordinal as u64,
                expected_kind: None,
                expected_len: None,
            })
            .collect();
        self.0.insert(
            key,
            Node {
                meta: InPackObject {
                    object: key,
                    kind: ObjectType::Tree,
                    canonical_len: 6,
                },
                edges,
                bytes: Vec::new(),
                manifest: None,
            },
        );
    }
}
impl InPackObjectView for View {
    fn object_set_root(&self) -> Hash {
        id(200)
    }
    fn object_count(&self) -> u64 {
        self.0.len() as u64
    }
    fn object(&self, key: &Hash) -> Result<Option<InPackObject>, Failure> {
        Ok(self.0.get(key).map(|n| n.meta.clone()))
    }
    fn object_at(&self, ordinal: u64) -> Result<Option<InPackObject>, Failure> {
        Ok(usize::try_from(ordinal)
            .ok()
            .and_then(|i| self.0.values().nth(i))
            .map(|n| n.meta.clone()))
    }
    fn chunked_blob(&self, key: &Hash) -> Result<Option<ChunkedBlobSummary>, Failure> {
        Ok(self.0.get(key).and_then(|node| node.manifest))
    }
    fn edge(&self, key: &Hash, ordinal: u64) -> Result<Option<ObjectEdge>, Failure> {
        Ok(self
            .0
            .get(key)
            .and_then(|n| usize::try_from(ordinal).ok().and_then(|i| n.edges.get(i)))
            .copied())
    }
}
fn member(object: Hash, kind: ObjectType, len: u64) -> MemberFact {
    MemberFact {
        repository: REPO,
        incarnation: VIEW,
        object,
        kind,
        canonical_len: len,
        supplier: PackSource {
            id: id(210),
            len: 99,
            binding: SourceBinding(id(211)),
        },
        canonical_binding: SourceBinding(id(212)),
        revision: Revision(id(213)),
        delta_depth: 0,
        published: true,
        held: false,
    }
}
#[derive(Default)]
struct Host {
    pages: BTreeMap<Hash, Vec<u8>>,
    external: BTreeMap<Hash, MemberFact>,
    canonical: BTreeMap<Hash, Vec<u8>>,
    batches: Vec<Vec<Hash>>,
}
impl Host {
    fn with_view(view: &View) -> Self {
        Self {
            canonical: view
                .0
                .iter()
                .map(|(key, n)| (*key, n.bytes.clone()))
                .collect(),
            ..Self::default()
        }
    }
    fn response(&mut self, request: &MembershipRequest) -> MembershipResponse {
        self.batches.push(request.objects.clone());
        MembershipResponse {
            request: request.request,
            repository: request.repository,
            view: request.view,
            answers: request
                .objects
                .iter()
                .map(|key| MembershipAnswer {
                    object: *key,
                    value: self
                        .external
                        .get(key)
                        .cloned()
                        .map_or(Acquisition::Absent, Acquisition::Present),
                })
                .collect(),
        }
    }
    fn supply(
        &mut self,
        walker: &mut ClosureWalker<View>,
        request: ClosureRequest,
    ) -> Result<(), Failure> {
        match request {
            ClosureRequest::Membership(request) => {
                let response = self.response(&request);
                walker.answer(ClosureResponse::Membership(response))
            }
            ClosureRequest::Page { request, page } => walker.answer(ClosureResponse::Page {
                request,
                page,
                value: Acquisition::Present(&self.pages[&page.digest]),
            }),
            ClosureRequest::Canonical { request, source } => {
                let key = match &source {
                    CanonicalSource::Member(fact) => fact.object,
                };
                walker.answer(ClosureResponse::Canonical {
                    request,
                    source,
                    value: Acquisition::Present(&self.canonical[&key]),
                })
            }
        }
    }
    fn missing(&self, mut page: Option<PageCommitment>) -> Vec<Hash> {
        let mut ids = Vec::new();
        while let Some(commitment) = page {
            let value = decode_missing(
                commitment,
                &self.pages[&commitment.digest],
                PageDecodeCfg {
                    max_bytes: 65536,
                    max_reasons: 1000,
                    max_work: 100000,
                },
            )
            .unwrap();
            ids.push(value.missing.object);
            page = value.previous;
        }
        ids
    }
    fn finish(&mut self, walker: &mut ClosureWalker<View>) -> Result<ResultSummary, Failure> {
        for _ in 0..200_000 {
            match walker.step()? {
                ClosureStep::Progress => {}
                ClosureStep::Retain(event) => {
                    let request = event.request;
                    let page = event.page;
                    self.pages.insert(page.digest, event.bytes.to_vec());
                    walker.acknowledge(request, page)?;
                }
                ClosureStep::Request(request) => {
                    let request = request.clone();
                    self.supply(walker, request)?;
                }
                ClosureStep::Closed(proof) => {
                    return Ok(ResultSummary {
                        missing: Vec::new(),
                        diagnostics: walker.diagnostics(),
                        witnesses: proof.external_witnesses().count,
                    });
                }
                ClosureStep::Missing(set) => {
                    return Ok(ResultSummary {
                        missing: self.missing(set.root()),
                        diagnostics: walker.diagnostics(),
                        witnesses: 0,
                    });
                }
            }
        }
        panic!("bounded test driver failed to terminate")
    }
    fn next_request(&mut self, walker: &mut ClosureWalker<View>) -> ClosureRequest {
        for _ in 0..10000 {
            match walker.step().unwrap() {
                ClosureStep::Progress => {}
                ClosureStep::Retain(event) => {
                    let request = event.request;
                    let page = event.page;
                    self.pages.insert(page.digest, event.bytes.to_vec());
                    walker.acknowledge(request, page).unwrap();
                }
                ClosureStep::Request(request) => return request.clone(),
                _ => panic!("expected request"),
            }
        }
        panic!("request not reached")
    }
}
#[derive(Debug)]
struct ResultSummary {
    missing: Vec<Hash>,
    diagnostics: ClosureDiagnostics,
    witnesses: u64,
}
fn walker(
    view: View,
    heads: &[Hash],
    limits: ClosureLimits,
    generation: u64,
) -> Result<ClosureWalker<View>, Failure> {
    ClosureWalker::new(view, heads, REPO, VIEW, rules(), limits, generation)
}
fn run(view: View, heads: &[Hash], limits: ClosureLimits) -> Result<ResultSummary, Failure> {
    let mut host = Host::with_view(&view);
    let mut machine = walker(view, heads, limits, 1)?;
    host.finish(&mut machine)
}
fn blob(view: &mut View, data: &[u8]) -> Hash {
    view.real(Object::Blob(Blob {
        data: data.to_vec(),
    }))
}
fn tree(view: &mut View, child: Hash, mode: EntryMode) -> Hash {
    view.real(Object::Tree(Tree {
        entries: vec![TreeEntry {
            name: b"child".to_vec(),
            mode,
            object_hash: child,
        }],
    }))
}

#[test]
fn all_surplus_objects_contribute_missing_edges() {
    let mut view = View::default();
    view.graph(id(1), &[id(99)]);
    view.graph(id(2), &[id(98), id(99)]);
    let result = run(view, &[], ClosureLimits::indexed()).unwrap();
    assert_eq!(result.missing, vec![id(98), id(99)]);
}

#[test]
fn independent_seeded_bfs_oracle_matches_complete_missing_sets() {
    let mut random = 71u64;
    for _ in 0..20 {
        let mut view = View::default();
        let mut adjacency = BTreeMap::new();
        for n in 1..=12u8 {
            let mut targets = Vec::new();
            for _ in 0..3 {
                random = random.wrapping_mul(6364136223846793005).wrapping_add(1);
                targets.push(id(1 + ((random >> 32) % 18) as u8));
            }
            view.graph(id(n), &targets);
            adjacency.insert(id(n), targets);
        }
        // Independent breadth-first reachability starts with every supplied entry.
        let mut queue: VecDeque<_> = adjacency.keys().copied().collect();
        let mut seen = BTreeSet::new();
        let mut absent = BTreeSet::new();
        while let Some(key) = queue.pop_front() {
            if seen.insert(key) {
                if let Some(targets) = adjacency.get(&key) {
                    queue.extend(targets);
                } else {
                    absent.insert(key);
                }
            }
        }
        assert_eq!(
            run(view, &[], ClosureLimits::indexed()).unwrap().missing,
            absent.into_iter().collect::<Vec<_>>()
        );
    }
}

#[test]
fn external_heads_require_tip_kind_and_members_stop_descending() {
    for kind in [
        ObjectType::Blob,
        ObjectType::Tree,
        ObjectType::Commit,
        ObjectType::Remix,
        ObjectType::Tag,
    ] {
        let mut host = Host::default();
        host.external.insert(id(91), member(id(91), kind, 20));
        let mut machine = walker(View::default(), &[id(91)], ClosureLimits::indexed(), 1).unwrap();
        let result = host.finish(&mut machine);
        if matches!(kind, ObjectType::Blob | ObjectType::Tree) {
            assert_eq!(result.unwrap_err().code, FailureCode::WrongKind);
        } else {
            let result = result.unwrap();
            assert!(result.missing.is_empty());
            assert_eq!(result.witnesses, 1);
            assert_eq!(host.batches, vec![vec![id(91)]]);
        }
    }
}

#[test]
fn tree_and_tag_kind_mismatches_are_only_diagnostics() {
    let mut view = View::default();
    let child = blob(&mut view, b"data");
    tree(&mut view, child, EntryMode::Tree);
    let head = view.real(Object::Tag(Tag {
        target: child,
        target_type: ObjectType::Tree,
        name: b"test".to_vec(),
        tagger: Identity::ed25519(id(0)),
        signer: id(0),
        message: Vec::new(),
        timestamp: 0,
        signature: [0; 64],
    }));
    let result = run(view, &[head], ClosureLimits::indexed()).unwrap();
    assert!(result.missing.is_empty());
    assert_eq!(result.diagnostics.kind_mismatches, 2);
}

#[test]
fn surplus_manifest_checks_each_repeated_chunk_occurrence_and_only_total_length() {
    for chunk_size in [0, 7] {
        let mut view = View::default();
        let chunk = blob(&mut view, b"abc");
        view.real(Object::ChunkedBlob(ChunkedBlob {
            total_size: 6,
            chunk_size,
            chunks: vec![chunk, chunk],
        }));
        assert!(
            run(view, &[], ClosureLimits::indexed())
                .unwrap()
                .missing
                .is_empty()
        );
    }
    for total_size in [2, 7] {
        let mut view = View::default();
        let chunk = blob(&mut view, b"abc");
        view.real(Object::ChunkedBlob(ChunkedBlob {
            total_size,
            chunk_size: 3,
            chunks: vec![chunk, chunk],
        }));
        assert_eq!(
            run(view, &[], ClosureLimits::indexed()).unwrap_err().code,
            FailureCode::NonCanonicalObject
        );
    }
    let mut view = View::default();
    let child = view.real(Object::Tree(Tree {
        entries: Vec::new(),
    }));
    view.real(Object::ChunkedBlob(ChunkedBlob {
        total_size: 0,
        chunk_size: 0,
        chunks: vec![child],
    }));
    assert_eq!(
        run(view, &[], ClosureLimits::indexed()).unwrap_err().code,
        FailureCode::WrongKind
    );
}

#[test]
fn external_chunk_bytes_and_duplicate_lengths_are_checked() {
    let mut external = View::default();
    let chunk = blob(&mut external, b"abc");
    let mut view = View::default();
    view.real(Object::ChunkedBlob(ChunkedBlob {
        total_size: 6,
        chunk_size: 3,
        chunks: vec![chunk, chunk],
    }));
    let mut host = Host::with_view(&view);
    let node = &external.0[&chunk];
    host.canonical.insert(chunk, node.bytes.clone());
    host.external.insert(
        chunk,
        member(chunk, ObjectType::Blob, node.meta.canonical_len),
    );
    let mut machine = walker(view, &[], ClosureLimits::indexed(), 1).unwrap();
    assert!(host.finish(&mut machine).unwrap().missing.is_empty());
    assert_eq!(
        host.batches
            .iter()
            .flatten()
            .filter(|key| **key == chunk)
            .count(),
        1
    );
}

#[test]
fn batches_use_frontier_cap_and_cap_plus_one() {
    for count in [4, 5] {
        let mut view = View::default();
        let targets: Vec<_> = (80..80 + count).map(id).collect();
        view.graph(id(1), &targets);
        let mut limits = ClosureLimits::indexed();
        limits.membership_batch = 4;
        let mut host = Host::with_view(&view);
        let mut machine = walker(view, &[], limits, 1).unwrap();
        assert_eq!(host.finish(&mut machine).unwrap().missing, targets);
        assert_eq!(
            host.batches.iter().map(Vec::len).collect::<Vec<_>>(),
            if count == 4 { vec![4] } else { vec![4, 1] }
        );
    }
}

#[test]
fn malformed_membership_answers_never_advance() {
    for mutation in 0..8 {
        let mut view = View::default();
        view.graph(id(1), &[id(80), id(81)]);
        let mut host = Host::with_view(&view);
        let mut machine = walker(view, &[], ClosureLimits::indexed(), 1).unwrap();
        let ClosureRequest::Membership(request) = host.next_request(&mut machine) else {
            panic!("membership expected")
        };
        let mut response = host.response(&request);
        match mutation {
            0 => {
                response.answers.pop();
            }
            1 => {
                response.answers[1].object = response.answers[0].object;
            }
            2 => response.request.generation += 1,
            3 => response.answers.swap(0, 1),
            4 => response.repository = RepositoryId(id(50)),
            5 => response.view = Revision(id(50)),
            6 => response.answers[0].value = Acquisition::Unavailable,
            _ => {
                let mut fact = member(response.answers[0].object, ObjectType::Blob, 10);
                fact.repository = RepositoryId(id(50));
                response.answers[0].value = Acquisition::Present(fact);
            }
        }
        let expected = if mutation == 6 {
            FailureCode::UnavailableInput
        } else {
            FailureCode::InvalidResponse
        };
        assert_eq!(
            machine
                .answer(ClosureResponse::Membership(response))
                .unwrap_err()
                .code,
            expected
        );
        assert_eq!(
            machine.step().unwrap_err().code,
            FailureCode::InvalidResponse
        );
    }
}

#[test]
fn resource_caps_never_report_a_truncated_complete_set() {
    let mut graph = View::default();
    graph.graph(id(1), &[id(2), id(80), id(81)]);
    graph.graph(id(2), &[id(3)]);
    graph.graph(id(3), &[]);
    for which in 0..9 {
        let mut limits = ClosureLimits::indexed();
        match which {
            0 => limits.items = 3,
            1 => limits.edges = 2,
            2 => limits.depth = 0,
            3 => limits.work = 10,
            4 => limits.resident_bytes = 1,
            5 => limits.evidence_bytes = 1,
            6 => limits.evidence_pages = 1,
            7 => limits.missing_items = 1,
            _ => limits.items = 10_000_001,
        }
        assert_eq!(
            run(graph.clone(), &[], limits).unwrap_err().code,
            FailureCode::ResourceLimit,
            "cap {which}"
        );
    }
    let mut external = View::default();
    let chunk = blob(&mut external, b"abc");
    let mut view = View::default();
    view.real(Object::ChunkedBlob(ChunkedBlob {
        total_size: 3,
        chunk_size: 0,
        chunks: vec![chunk],
    }));
    for object_cap in [false, true] {
        let mut limits = ClosureLimits::indexed();
        if object_cap {
            limits.object_bytes = 1;
        } else {
            limits.decoded_bytes = 1;
        }
        let mut host = Host::with_view(&view);
        let node = &external.0[&chunk];
        host.canonical.insert(chunk, node.bytes.clone());
        host.external.insert(
            chunk,
            member(chunk, ObjectType::Blob, node.meta.canonical_len),
        );
        let mut machine = walker(view.clone(), &[], limits, 1).unwrap();
        assert_eq!(
            host.finish(&mut machine).unwrap_err().code,
            FailureCode::ResourceLimit
        );
    }
}

#[test]
fn root_depth_is_zero_and_cycles_differ_from_shared_structure() {
    let mut leaf = View::default();
    leaf.graph(id(1), &[]);
    let mut limits = ClosureLimits::indexed();
    limits.depth = 0;
    assert!(run(leaf, &[], limits).is_ok());
    let mut cycle = View::default();
    cycle.graph(id(1), &[id(2)]);
    cycle.graph(id(2), &[id(1)]);
    assert_eq!(
        run(cycle, &[], ClosureLimits::indexed())
            .unwrap()
            .diagnostics
            .cycles,
        1
    );
    let mut shared = View::default();
    shared.graph(id(1), &[id(3)]);
    shared.graph(id(2), &[id(3)]);
    shared.graph(id(3), &[]);
    assert_eq!(
        run(shared, &[], ClosureLimits::indexed())
            .unwrap()
            .diagnostics
            .cycles,
        0
    );
}

#[test]
fn lost_pages_cannot_establish_absence_and_fresh_generation_replays() {
    let mut view = View::default();
    view.graph(id(1), &[id(2)]);
    view.graph(id(2), &[]);
    let mut host = Host::with_view(&view);
    let mut machine = walker(view.clone(), &[], ClosureLimits::indexed(), 1).unwrap();
    loop {
        let request = host.next_request(&mut machine);
        if let ClosureRequest::Page { request, page } = request {
            assert_eq!(
                machine
                    .answer(ClosureResponse::Page {
                        request,
                        page,
                        value: Acquisition::Unavailable
                    })
                    .unwrap_err()
                    .code,
                FailureCode::UnavailableInput
            );
            break;
        }
        host.supply(&mut machine, request).unwrap();
    }
    assert_eq!(
        machine.step().unwrap_err().code,
        FailureCode::InvalidResponse
    );
    let mut fresh = walker(view, &[], ClosureLimits::indexed(), 2).unwrap();
    assert!(host.finish(&mut fresh).unwrap().missing.is_empty());
}

#[test]
fn requests_and_retention_are_stable_until_acknowledged() {
    let mut view = View::default();
    view.graph(id(1), &[id(80)]);
    let mut machine = walker(view.clone(), &[], ClosureLimits::indexed(), 1).unwrap();
    loop {
        match machine.step().unwrap() {
            ClosureStep::Progress => {}
            ClosureStep::Retain(event) => {
                let request = event.request;
                let page = event.page;
                let bytes = event.bytes.to_vec();
                for _ in 0..3 {
                    let ClosureStep::Retain(repeated) = machine.step().unwrap() else {
                        panic!("retention must block")
                    };
                    assert_eq!(repeated.request, request);
                    assert_eq!(repeated.page, page);
                    assert_eq!(repeated.bytes, bytes);
                }
                machine.acknowledge(request, page).unwrap();
                break;
            }
            _ => panic!("first object must be retained"),
        }
    }
    let mut host = Host::with_view(&view);
    // Save the first acknowledged journal page for later acquisition.
    // Restart gives the driver ownership of all retained state for this check.
    let mut machine = walker(view, &[], ClosureLimits::indexed(), 2).unwrap();
    let request = host.next_request(&mut machine);
    for _ in 0..3 {
        let ClosureStep::Request(repeated) = machine.step().unwrap() else {
            panic!("request must block")
        };
        assert_eq!(*repeated, request);
    }
    host.supply(&mut machine, request).unwrap();
    assert_eq!(host.finish(&mut machine).unwrap().missing, vec![id(80)]);
}

#[test]
fn configured_large_frontier_is_batched_at_4096_and_4097() {
    for count in [4096u64, 4097] {
        let targets: Vec<_> = (0..count)
            .map(|n| mkit_core::hash::hash(&n.to_le_bytes()))
            .collect();
        let mut view = View::default();
        view.graph(id(1), &targets);
        let mut host = Host::with_view(&view);
        let mut machine = walker(view, &[], ClosureLimits::indexed(), 1).unwrap();
        let result = host.finish(&mut machine).unwrap();
        let mut expected = targets;
        expected.sort();
        assert_eq!(result.missing, expected);
        assert_eq!(
            host.batches.iter().map(Vec::len).collect::<Vec<_>>(),
            if count == 4096 {
                vec![4096]
            } else {
                vec![4096, 1]
            }
        );
    }
}
