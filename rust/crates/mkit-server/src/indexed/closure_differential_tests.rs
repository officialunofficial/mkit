//! Direct-child parity against the public cooperative walker.

use super::*;
use mkit_primitives::closure::{
    CanonicalSource, ChunkedBlobSummary, ClosureCheck, ClosureRequest, ClosureResponse,
    ClosureStep, ClosureWalker, InPackObject, InPackObjectView, MembershipAnswer,
    MembershipResponse, ObjectEdge,
    edges::{edge_at, edge_count},
    limits::ClosureLimits,
};
use mkit_primitives::error::{Failure, FailureCode};
use mkit_primitives::evidence::{
    MemberFact, PackSource, ProfileId, RepositoryId, Revision, RulesetBinding, RulesetId,
    SourceBinding,
};
use mkit_primitives::pack_verify::Acquisition;

const REPOSITORY: RepositoryId = RepositoryId([41; 32]);
const REVISION: Revision = Revision([42; 32]);

struct View(BTreeMap<Hash, Object>);
impl View {
    fn metadata(id: Hash, object: &Object) -> InPackObject {
        InPackObject {
            object: id,
            kind: object.object_type(),
            canonical_len: serialize(object).unwrap().len() as u64,
        }
    }
}
impl InPackObjectView for View {
    fn object_set_root(&self) -> Hash {
        hash(&self.0.keys().flatten().copied().collect::<Vec<_>>())
    }
    fn retained_bytes(&self) -> u64 {
        self.0
            .values()
            .map(|object| serialize(object).unwrap().len() as u64 + 256)
            .sum()
    }
    fn object_count(&self) -> u64 {
        self.0.len() as u64
    }
    fn object(&self, id: &Hash) -> Result<Option<InPackObject>, Failure> {
        Ok(self.0.get(id).map(|object| Self::metadata(*id, object)))
    }
    fn object_at(&self, ordinal: u64) -> Result<Option<InPackObject>, Failure> {
        Ok(self
            .0
            .iter()
            .nth(usize::try_from(ordinal).unwrap())
            .map(|(id, object)| Self::metadata(*id, object)))
    }
    fn edge(&self, id: &Hash, ordinal: u64) -> Result<Option<ObjectEdge>, Failure> {
        Ok(self.0.get(id).and_then(|object| edge_at(object, ordinal)))
    }
    fn chunked_blob(&self, id: &Hash) -> Result<Option<ChunkedBlobSummary>, Failure> {
        Ok(match self.0.get(id) {
            Some(Object::ChunkedBlob(manifest)) => Some(ChunkedBlobSummary {
                total_size: manifest.total_size,
                chunks: manifest.chunks.len() as u64,
            }),
            _ => None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Closed,
    Missing,
    MalformedFile,
}

struct Fixture {
    objects: Vec<Object>,
    members: Vec<Object>,
    bytes: Vec<u8>,
    head: Hash,
}
impl Fixture {
    fn view(&self) -> View {
        View(
            self.objects
                .iter()
                .map(|object| (object.id().unwrap(), object.clone()))
                .collect(),
        )
    }
    fn seed(&self, rig: &Rig) {
        for object in &self.members {
            seed_member(rig, object.id().unwrap(), &serialize(object).unwrap());
        }
    }
    fn walker(&self) -> Verdict {
        let mut walker = ClosureWalker::new(
            self.view(),
            &[self.head],
            REPOSITORY,
            REVISION,
            RulesetBinding {
                ruleset: RulesetId(1),
                profile: ProfileId::Indexed,
            },
            ClosureLimits::indexed(),
            1,
        )
        .unwrap();
        let mut pages = BTreeMap::new();
        let members: BTreeMap<_, _> = self
            .members
            .iter()
            .map(|object| (object.id().unwrap(), object))
            .collect();
        for _ in 0..200_000 {
            let request = match walker.step() {
                Ok(ClosureStep::Progress) => continue,
                Ok(ClosureStep::Closed(proof)) => {
                    assert_eq!(
                        proof.coverage(),
                        mkit_primitives::closure::Coverage::DirectChildren
                    );
                    return Verdict::Closed;
                }
                Ok(ClosureStep::Missing(_)) => return Verdict::Missing,
                Ok(ClosureStep::Retain(event)) => {
                    let (request, page) = (event.request, event.page);
                    pages.insert(page.digest, event.bytes.to_vec());
                    walker.acknowledge(request, page).unwrap();
                    continue;
                }
                Ok(ClosureStep::Request(request)) => request.clone(),
                Err(failure) => return file_failure(&walker, &failure),
            };
            let answered = match request {
                ClosureRequest::Membership(request) => {
                    let answers = request
                        .objects
                        .iter()
                        .map(|id| MembershipAnswer {
                            object: *id,
                            value: members.get(id).map_or(Acquisition::Absent, |object| {
                                Acquisition::Present(member_fact(*id, object))
                            }),
                        })
                        .collect();
                    walker.answer(ClosureResponse::Membership(MembershipResponse {
                        request: request.request,
                        repository: request.repository,
                        view: request.view,
                        answers,
                    }))
                }
                ClosureRequest::Canonical { request, source } => {
                    let CanonicalSource::Member(fact) = &source;
                    let bytes = serialize(members[&fact.object]).unwrap();
                    walker.answer(ClosureResponse::Canonical {
                        request,
                        source,
                        value: Acquisition::Present(&bytes),
                    })
                }
                ClosureRequest::Page { request, page } => walker.answer(ClosureResponse::Page {
                    request,
                    page,
                    value: Acquisition::Present(&pages[&page.digest]),
                }),
            };
            if let Err(failure) = answered {
                return file_failure(&walker, &failure);
            }
        }
        panic!("closure fixture did not terminate");
    }
    fn inline(&self) -> Verdict {
        let rig = Rig::new();
        self.seed(&rig);
        let (ticket, id) = rig.add(&self.bytes);
        rig.clock
            .advance(i64::try_from(rig.cfg.relay_lag_bound_ms + 1).unwrap());
        server_verdict(block_on(crate::indexed::verify::verify_ticketed(
            rig.blobs.as_ref(),
            rig.store.as_ref(),
            rig.shards.as_ref(),
            &rig.repo,
            &rig.source(),
            &[ticket],
            &[id],
            self.head,
            rig.cfg,
            true,
            rig.clock.as_ref(),
            rig.recorder.as_ref(),
        )))
    }
    fn scheduled(&self) -> Verdict {
        let rig = Rig::new();
        self.seed(&rig);
        let (ticket, id) = rig.add(&self.bytes);
        let pending = rig.check(&[(&ticket, id)], self.head).unwrap_err();
        assert_eq!(pending.public_message(), "pack verification pending");
        let extension = TestExtraction::new(&rig);
        for _ in 0..3_000 {
            tick(&rig, &extension, rig.store.as_ref(), true);
            rig.clock.advance(1_000);
            if rig.finished(&ticket.pack_id) {
                let result = rig.check(&[(&ticket, id)], self.head);
                match &result {
                    // A retryable closure job may still need its final recheck.
                    // A transient advance response is not a terminal verdict.
                    Err(error)
                        if matches!(
                            error.public_message(),
                            "pack verification pending" | "repository membership not yet visible"
                        ) => {}
                    Ok(_) if rig.job(&ticket.pack_id).unwrap().closure_retry() => {}
                    _ => return server_verdict(result),
                }
            }
        }
        panic!("scheduled closure fixture did not terminate");
    }
    fn assert_parity(&self, expected: Verdict) {
        assert_eq!(self.walker(), expected, "public walker");
        assert_eq!(self.inline(), expected, "inline server");
        assert_eq!(self.scheduled(), expected, "scheduled server");
    }
}

fn member_fact(id: Hash, object: &Object) -> MemberFact {
    // The same raw supplier pack that seed_member installs in each server rig.
    let supplier = pack(std::slice::from_ref(object));
    let supplier_id = hash(&supplier);
    MemberFact {
        repository: REPOSITORY,
        incarnation: REVISION,
        object: id,
        kind: object.object_type(),
        canonical_len: serialize(object).unwrap().len() as u64,
        supplier: PackSource {
            id: supplier_id,
            len: supplier.len() as u64,
            binding: SourceBinding(supplier_id),
        },
        canonical_binding: SourceBinding(hash(&serialize(object).unwrap())),
        revision: REVISION,
        delta_depth: 0,
        published: true,
        held: false,
    }
}
fn file_failure(walker: &ClosureWalker<View>, failure: &Failure) -> Verdict {
    // A head that cannot be a history tip is an open closure on the servers.
    if walker.failure_context().map(|context| context.check) == Some(ClosureCheck::Head) {
        assert_eq!(failure.code, FailureCode::WrongKind);
        return Verdict::Missing;
    }
    assert!(matches!(
        walker.failure_context().unwrap().check,
        ClosureCheck::Chunk { .. } | ClosureCheck::Manifest
    ));
    assert!(matches!(
        failure.code,
        FailureCode::WrongKind | FailureCode::NonCanonicalObject | FailureCode::ObjectHashMismatch
    ));
    Verdict::MalformedFile
}
fn server_verdict<T>(result: Result<T, crate::ServerError>) -> Verdict {
    match result {
        Ok(_) => Verdict::Closed,
        Err(error) => {
            assert_eq!(error.code(), crate::Code::InvalidArgument);
            match error.public_message() {
                "open closure" => Verdict::Missing,
                crate::indexed::extract::MALFORMED_MESSAGE => Verdict::MalformedFile,
                other => panic!("unexpected server refusal: {other}"),
            }
        }
    }
}
fn manifest_fixture(member_indices: &[usize], missing: bool, total_delta: i64) -> Fixture {
    let chunks = [
        Object::Blob(Blob {
            data: vec![3; 4_000],
        }),
        Object::Blob(Blob {
            data: vec![5; 9_000],
        }),
    ];
    let manifest = Object::ChunkedBlob(ChunkedBlob {
        total_size: u64::try_from(13_000 + total_delta).unwrap(),
        chunk_size: 0,
        chunks: chunks.iter().map(|object| object.id().unwrap()).collect(),
    });
    let (tree, commit, head) = tree_head(&[manifest.id().unwrap()]);
    let mut objects = vec![manifest, tree, commit];
    let mut members = Vec::new();
    for (index, chunk) in chunks.into_iter().enumerate() {
        if missing && index == 1 {
            continue;
        }
        if member_indices.contains(&index) {
            members.push(chunk);
        } else {
            objects.push(chunk);
        }
    }
    Fixture {
        bytes: pack(&objects),
        objects,
        members,
        head,
    }
}

#[test]
fn public_walker_and_servers_agree_on_external_manifest_chunks_and_missing_members() {
    for members in [vec![], vec![0, 1], vec![1]] {
        manifest_fixture(&members, false, 0).assert_parity(Verdict::Closed);
    }
    manifest_fixture(&[], true, 0).assert_parity(Verdict::Missing);
}

#[test]
fn public_walker_and_servers_agree_on_manifest_total_integrity() {
    for delta in [-1, 1] {
        manifest_fixture(&[1], false, delta).assert_parity(Verdict::MalformedFile);
    }
}

#[test]
fn public_walker_and_servers_agree_after_an_in_pack_delta_chain() {
    let chunks = (0..4)
        .map(|n| {
            Object::Blob(Blob {
                data: vec![n; 2_000],
            })
        })
        .collect::<Vec<_>>();
    let (tree, commit, head) = tree_head(&[chunks.last().unwrap().id().unwrap()]);
    let mut writer = PackWriter::new();
    let mut prior = serialize(&chunks[0]).unwrap();
    writer.push_raw(chunks[0].id().unwrap(), &prior).unwrap();
    for chunk in &chunks[1..] {
        let raw = serialize(chunk).unwrap();
        writer
            .push_delta(
                &hash(&prior),
                &mkit_core::delta::encode(&prior, &raw).unwrap(),
            )
            .unwrap();
        prior = raw;
    }
    for object in [&tree, &commit] {
        writer
            .push_raw(object.id().unwrap(), &serialize(object).unwrap())
            .unwrap();
    }
    let mut objects = chunks;
    objects.extend([tree, commit]);
    Fixture {
        objects,
        members: vec![],
        bytes: writer.finish().unwrap(),
        head,
    }
    .assert_parity(Verdict::Closed);
}

#[test]
fn public_walker_and_servers_agree_when_a_manifest_chunk_is_a_thin_delta_result() {
    let mut fixture = manifest_fixture(&[0], false, 0);
    let base = Object::Blob(Blob {
        data: vec![4; 9_000],
    });
    let base_raw = serialize(&base).unwrap();
    let mut writer = PackWriter::new();
    for object in &fixture.objects {
        let raw = serialize(object).unwrap();
        if matches!(object, Object::Blob(_)) {
            writer
                .push_delta(
                    &base.id().unwrap(),
                    &mkit_core::delta::encode(&base_raw, &raw).unwrap(),
                )
                .unwrap();
        } else {
            writer.push_raw(object.id().unwrap(), &raw).unwrap();
        }
    }
    fixture.members.push(base);
    fixture.bytes = writer.finish().unwrap();
    fixture.assert_parity(Verdict::Closed);
}

#[test]
fn a_packmap_cycle_is_separate_from_direct_child_closure() {
    use mkit_primitives::closure::pair::{
        PackmapNode, PairCheck, PairLimits, PairRequest, PairResponse, PairStep, PairWalker,
        ResultingPair,
    };

    let node = [73; 32];
    // A packmap's previous pointer belongs to pair coverage. A canonical Blob
    // containing such bytes remains a leaf under direct-child coverage.
    let payload = mkit_core::transfer::encode_packlist(Some(node), &[[74; 32]]).unwrap();
    let blob = Object::Blob(Blob { data: payload });
    assert_eq!(edge_count(&blob), 0);
    let (tree, commit, head) = tree_head(&[blob.id().unwrap()]);
    let objects = vec![blob, tree, commit];
    Fixture {
        bytes: pack(&objects),
        objects,
        members: vec![],
        head,
    }
    .assert_parity(Verdict::Closed);

    // Independently exercise a host-supplied packmap node whose previous
    // pointer is itself. These pair facts are not direct-child object edges.
    // This checks the public pair primitive, not server pair integration.
    let mut pair = PairWalker::new(
        ResultingPair {
            head: Some(head),
            packmap: Some(node),
            branch: true,
        },
        &[],
        REPOSITORY,
        REVISION,
        RulesetBinding {
            ruleset: RulesetId(1),
            profile: ProfileId::Indexed,
        },
        PairLimits {
            chain: 16,
            packs: 16,
            discovered: 32,
            dependencies: 32,
            suppliers: 16,
            cleared: 16,
            max_delta_depth: 4,
            work: 1_000_000,
        },
        true,
        1,
    )
    .unwrap();
    let request = match pair.step().unwrap() {
        PairStep::Request(request) => request.clone(),
        other => panic!("expected a chain request: {other:?}"),
    };
    let PairRequest::PackmapNode { request, pack, .. } = request else {
        panic!("expected the packmap node");
    };
    assert_eq!(pack, node);
    pair.answer(PairResponse::PackmapNode {
        request,
        pack,
        value: Acquisition::Present(PackmapNode {
            prev: Some(node),
            packs: &[[74; 32]],
            boundary: false,
        }),
    })
    .unwrap();
    assert_eq!(pair.step().unwrap_err().code, FailureCode::PackmapCycle);
    assert_eq!(
        pair.failure_context(),
        Some(PairCheck::ChainRepeat { pack: node })
    );
}

#[test]
fn public_walker_and_servers_agree_on_a_missing_tree_member() {
    let (commit, head) = signed_commit([91; 32], Vec::new(), 7, b"missing tree");
    let objects = vec![commit];
    Fixture {
        bytes: pack(&objects),
        objects,
        members: vec![],
        head,
    }
    .assert_parity(Verdict::Missing);
}

#[test]
fn public_walker_and_servers_agree_on_a_wrong_kind_chunk() {
    let chunk = Object::Tree(Tree { entries: vec![] });
    let manifest = Object::ChunkedBlob(ChunkedBlob {
        total_size: 0,
        chunk_size: 0,
        chunks: vec![chunk.id().unwrap()],
    });
    let (tree, commit, head) = tree_head(&[manifest.id().unwrap()]);
    let objects = vec![chunk, manifest, tree, commit];
    Fixture {
        bytes: pack(&objects),
        objects,
        members: vec![],
        head,
    }
    .assert_parity(Verdict::MalformedFile);
}

#[test]
fn public_walker_and_servers_report_a_missing_object_before_a_file_fault() {
    // A wrong-kind chunk and an absent tree member in the same tree: both
    // servers answer the open closure, so the walker must as well.
    let chunk = Object::Tree(Tree { entries: vec![] });
    let manifest = Object::ChunkedBlob(ChunkedBlob {
        total_size: 0,
        chunk_size: 0,
        chunks: vec![chunk.id().unwrap()],
    });
    let (tree, commit, head) = tree_head(&[manifest.id().unwrap(), [93; 32]]);
    let objects = vec![chunk, manifest, tree, commit];
    Fixture {
        bytes: pack(&objects),
        objects,
        members: vec![],
        head,
    }
    .assert_parity(Verdict::Missing);

    // The same shape with a bad manifest total instead of a wrong-kind chunk.
    let mut fixture = manifest_fixture(&[], false, 1);
    let (tree, commit, head) = tree_head(&[fixture.objects[0].id().unwrap(), [94; 32]]);
    fixture.objects.extend([tree, commit]);
    fixture.bytes = pack(&fixture.objects);
    fixture.head = head;
    fixture.assert_parity(Verdict::Missing);
}

#[test]
fn public_walker_and_servers_agree_on_head_kinds() {
    for object in [
        Object::Blob(Blob {
            data: vec![1; 100],
        }),
        Object::Tree(Tree { entries: vec![] }),
    ] {
        let head = object.id().unwrap();
        let objects = vec![object];
        Fixture {
            bytes: pack(&objects),
            objects,
            members: vec![],
            head,
        }
        .assert_parity(Verdict::Missing);
    }
}
