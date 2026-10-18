use super::{super::SignatureResult, *};
use crate::{
    closure::{
        ClosureRequest, ClosureResponse, ClosureStep, ClosureWalker, InPackObject,
        InPackObjectView, MembershipAnswer, MembershipResponse, ObjectEdge, limits::ClosureLimits,
    },
    error::Failure,
    evidence::{MemberFact, PackSource, ProfileId, Revision, RulesetId, SourceBinding},
    limits::{IndexedProfile, VerifyLimits},
    pack_verify::{Acquisition, ByteSource, Request, Response, Step, verify::VerifyDriver},
};
use mkit_core::{
    delta,
    hash::{self, Hash},
    object::{
        Blob, Commit, EntryMode, Identity, Object, ObjectType, Tag, Tree, TreeEntry, id_from_object,
    },
    pack::PackWriter,
    serialize::{deserialize, serialize},
    sign,
};
use std::collections::BTreeMap;

const REPOSITORY: RepositoryId = RepositoryId([0x22; 32]);
const VIEW: Revision = Revision([0x55; 32]);

fn config() -> AcceptanceEvidenceBuildCfg {
    AcceptanceEvidenceBuildCfg {
        envelope: AcceptanceEvidenceDecodeCfg {
            max_envelope_bytes: 4096,
            max_operation_bytes: 32,
            max_heads: 4,
            max_head_bytes: 1024,
            max_total_head_bytes: 3072,
            max_external_dependencies: 4,
            ruleset_id: RulesetId(1),
            profile_limits_digest: [0x11; 32],
        },
        max_head_occurrences: 8,
        max_witness_pages: 8,
        max_total_witness_bytes: 65536,
        witness_page: PageDecodeCfg {
            max_bytes: 4096,
            max_reasons: 0,
            max_work: 4096,
        },
    }
}
fn rules() -> RulesetBinding {
    RulesetBinding {
        ruleset: RulesetId(1),
        profile: ProfileId::Indexed,
    }
}
fn binding() -> AcceptanceEvidenceBinding<'static> {
    AcceptanceEvidenceBinding {
        repository: REPOSITORY,
        operation: b"job",
        epoch: 8,
    }
}
fn representative() -> AcceptanceEvidence {
    AcceptanceEvidence::decode(
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/fixtures/acceptance/representative.bin"
        )),
        &config().envelope,
    )
    .expect("frozen signed fixture")
}

// An empty, immutable in-pack set leaves requested external heads to the
// public closure membership protocol. No private proof fields are constructed.
struct EmptyView;
impl InPackObjectView for EmptyView {
    fn object_set_root(&self) -> Hash {
        [0x44; 32]
    }
    fn retained_bytes(&self) -> u64 {
        0
    }
    fn object_count(&self) -> u64 {
        0
    }
    fn object(&self, _: &Hash) -> std::result::Result<Option<InPackObject>, Failure> {
        Ok(None)
    }
    fn object_at(&self, _: u64) -> std::result::Result<Option<InPackObject>, Failure> {
        Ok(None)
    }
    fn edge(&self, _: &Hash, _: u64) -> std::result::Result<Option<ObjectEdge>, Failure> {
        Ok(None)
    }
}
fn closed(heads: &[(Hash, ObjectType, Hash)]) -> (ClosureProof, Vec<Vec<u8>>) {
    let ids: Vec<_> = heads.iter().map(|h| h.0).collect();
    let mut walker = ClosureWalker::new(
        EmptyView,
        &ids,
        REPOSITORY,
        VIEW,
        rules(),
        ClosureLimits::indexed(),
        1,
    )
    .expect("bounded closure fixture");
    let mut pages = BTreeMap::<Hash, Vec<u8>>::new();
    for _ in 0..10000 {
        match walker.step().expect("valid closure protocol") {
            ClosureStep::Progress => {}
            ClosureStep::Retain(event) => {
                let request = event.request;
                let page = event.page;
                pages.insert(page.digest, event.bytes.to_vec());
                walker
                    .acknowledge(request, page)
                    .expect("retained page acknowledgement");
            }
            ClosureStep::Request(request) => {
                let response = match request.clone() {
                    ClosureRequest::Membership(request) => {
                        let answers = request
                            .objects
                            .iter()
                            .map(|object| {
                                let (_, kind, supplier) = heads
                                    .iter()
                                    .find(|h| h.0 == *object)
                                    .expect("requested fixture member");
                                MembershipAnswer {
                                    object: *object,
                                    value: Acquisition::Present(MemberFact {
                                        repository: REPOSITORY,
                                        incarnation: VIEW,
                                        object: *object,
                                        kind: *kind,
                                        canonical_len: 128,
                                        supplier: PackSource {
                                            id: *supplier,
                                            len: 4096,
                                            binding: SourceBinding([6; 32]),
                                        },
                                        canonical_binding: SourceBinding([7; 32]),
                                        revision: Revision([8; 32]),
                                        delta_depth: 0,
                                        published: true,
                                        held: false,
                                    }),
                                }
                            })
                            .collect();
                        ClosureResponse::Membership(MembershipResponse {
                            request: request.request,
                            repository: request.repository,
                            view: request.view,
                            answers,
                        })
                    }
                    ClosureRequest::Page { request, page } => ClosureResponse::Page {
                        request,
                        page,
                        value: Acquisition::Present(
                            pages.get(&page.digest).expect("retained page"),
                        ),
                    },
                    ClosureRequest::Canonical { .. } => {
                        panic!("member heads need no canonical acquisition")
                    }
                };
                walker.answer(response).expect("valid membership response");
            }
            ClosureStep::Closed(proof) => {
                let mut ordered = Vec::new();
                let mut next = proof.relied_on_members();
                while let Some(page) = next {
                    let bytes = pages.get(&page.digest).expect("retained witness page");
                    next = decode_witness(page, bytes, config().witness_page)
                        .expect("authenticated fixture witness")
                        .previous;
                    ordered.push(bytes.clone());
                }
                return (proof, ordered);
            }
            ClosureStep::Missing(_) => panic!("all fixture members are present"),
        }
    }
    panic!("bounded closure driver must terminate")
}
fn proof_with_three_members() -> (ClosureProof, Vec<Vec<u8>>) {
    closed(&[
        ([1; 32], ObjectType::Commit, [0x77; 32]),
        ([2; 32], ObjectType::Remix, [0x66; 32]),
        ([3; 32], ObjectType::Tag, [0x77; 32]),
    ])
}
fn suppliers(
    proof: &ClosureProof,
    pages: &[Vec<u8>],
    cfg: &AcceptanceEvidenceBuildCfg,
) -> Result<Vec<Hash>> {
    supplier_ids(proof, pages.iter().map(Vec::as_slice), cfg)
}

#[test]
fn encoder_preserves_frozen_minimal_and_representative_contracts() {
    let cfg = config();
    for fixture in [
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/fixtures/acceptance/minimal.bin"
        ))
        .as_slice(),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/fixtures/acceptance/representative.bin"
        ))
        .as_slice(),
    ] {
        let original = AcceptanceEvidence::decode(fixture, &cfg.envelope).unwrap();
        let heads: Vec<_> = original.heads().collect();
        let dependencies: Vec<_> = original.external_dependencies().collect();
        let encoded = encode(
            AcceptanceEvidenceBinding {
                repository: original.repository(),
                operation: original.operation(),
                epoch: original.epoch(),
            },
            original.witness(),
            original.denial_version(),
            original.pack(),
            &heads,
            &dependencies,
            &cfg.envelope,
        )
        .unwrap();
        assert_eq!(encoded.encode(), fixture);
        assert_eq!(encoded.digest(), original.digest());
        encoded.recheck_heads().unwrap();
    }
}

#[test]
fn requested_head_order_and_repetitions_bind_before_output_deduplication() {
    let fixture = representative();
    let heads: Vec<_> = fixture.heads().collect();
    let requested = [
        heads[2].canonical_bytes,
        heads[0].canonical_bytes,
        heads[2].canonical_bytes,
    ];
    let (proof, _) = closed(&[
        (heads[2].object_id, heads[2].kind, [0x66; 32]),
        (heads[0].object_id, heads[0].kind, [0x77; 32]),
        (heads[2].object_id, heads[2].kind, [0x66; 32]),
    ]);
    let result = prepare_heads(&requested, proof.heads_root(), &config()).unwrap();
    assert_eq!(
        result.iter().map(|h| h.object_id).collect::<Vec<_>>(),
        [heads[0].object_id, heads[2].object_id]
    );
    for changed in [
        vec![requested[1], requested[0], requested[2]],
        vec![requested[0], requested[1]],
    ] {
        assert_eq!(
            prepare_heads(&changed, proof.heads_root(), &config())
                .unwrap_err()
                .code,
            FailureCode::EvidenceBindingMismatch
        );
    }
}

#[test]
fn supplied_heads_verify_signatures_and_canonical_kind() {
    let fixture = representative();
    for head in fixture.heads() {
        let root = closure::heads_root(std::iter::once(head.object_id)).unwrap();
        prepare_heads(&[head.canonical_bytes], root, &config()).unwrap();
        let mut object = mkit_core::serialize::deserialize(head.canonical_bytes).unwrap();
        match &mut object {
            Object::Commit(c) => c.signature = [0; 64],
            Object::Remix(r) => r.signature = [0; 64],
            Object::Tag(t) => t.signature = [0; 64],
            _ => unreachable!(),
        }
        let unsigned = mkit_core::serialize::serialize(&object).unwrap();
        assert_eq!(
            prepare_heads(&[&unsigned], root, &config())
                .unwrap_err()
                .code,
            FailureCode::BadSignature
        );
        assert_eq!(
            prepare_heads(&[&head.canonical_bytes[..1]], root, &config())
                .unwrap_err()
                .code,
            FailureCode::NonCanonicalObject
        );
    }
    let blob = mkit_core::serialize::serialize(&Object::Blob(Blob { data: vec![1] })).unwrap();
    assert_eq!(
        prepare_heads(&[&blob], [0; 32], &config())
            .unwrap_err()
            .code,
        FailureCode::EvidenceHeadMismatch
    );
}

#[test]
fn head_occurrence_bytes_and_unique_head_caps_are_independent() {
    let fixture = representative();
    let heads: Vec<_> = fixture.heads().collect();
    let requested = [heads[0].canonical_bytes, heads[0].canonical_bytes];
    let root = closure::heads_root([heads[0].object_id; 2].into_iter()).unwrap();
    let mut cfg = config();
    cfg.max_head_occurrences = 2;
    cfg.envelope.max_heads = 1;
    cfg.envelope.max_head_bytes = u32::try_from(requested[0].len()).unwrap();
    cfg.envelope.max_total_head_bytes = cfg.envelope.max_head_bytes * 2;
    assert_eq!(prepare_heads(&requested, root, &cfg).unwrap().len(), 1);
    for which in 0..4 {
        let mut limited = cfg.clone();
        match which {
            0 => limited.max_head_occurrences -= 1,
            1 => limited.envelope.max_head_bytes -= 1,
            2 => limited.envelope.max_total_head_bytes -= 1,
            _ => limited.envelope.max_heads = 0,
        }
        assert_eq!(
            prepare_heads(&requested, root, &limited).unwrap_err().code,
            FailureCode::ResourceLimit
        );
    }
}

#[test]
fn complete_witness_chain_yields_sorted_unique_supplier_ids() {
    let (proof, pages) = proof_with_three_members();
    assert_eq!(proof.external_witnesses().count, 3);
    assert_eq!(
        suppliers(&proof, &pages, &config()).unwrap(),
        [[0x66; 32], [0x77; 32]]
    );
    let mut cfg = config();
    cfg.envelope.max_external_dependencies = 2;
    cfg.max_witness_pages = 3;
    cfg.max_total_witness_bytes = pages.iter().map(|b| b.len() as u64).sum();
    cfg.witness_page.max_bytes = pages.iter().map(|b| b.len() as u64).max().unwrap();
    cfg.witness_page.max_work = cfg.witness_page.max_bytes;
    assert_eq!(suppliers(&proof, &pages, &cfg).unwrap().len(), 2);
    for which in 0..5 {
        let mut limited = cfg.clone();
        match which {
            0 => limited.envelope.max_external_dependencies -= 1,
            1 => limited.max_witness_pages -= 1,
            2 => limited.max_total_witness_bytes -= 1,
            3 => limited.witness_page.max_bytes -= 1,
            _ => limited.witness_page.max_work -= 1,
        }
        assert_eq!(
            suppliers(&proof, &pages, &limited).unwrap_err().code,
            FailureCode::ResourceLimit
        );
    }
}

#[test]
fn witness_chain_rejects_missing_extra_reordered_and_tampered_pages() {
    let (proof, pages) = proof_with_three_members();
    for mutation in 0..6 {
        let mut changed = pages.clone();
        match mutation {
            0 => {
                changed.remove(0);
            }
            1 => {
                changed.pop();
            }
            2 => changed.push(pages[0].clone()),
            3 => changed.swap(0, 1),
            4 => changed[0][10] ^= 1,
            _ => changed[1] = pages[0].clone(),
        }
        assert_eq!(
            suppliers(&proof, &changed, &config()).unwrap_err().code,
            FailureCode::InvalidResponse,
            "mutation {mutation}"
        );
    }
}

#[test]
fn empty_proof_requires_empty_witness_stream_and_no_allowance() {
    let (proof, pages) = closed(&[]);
    assert!(pages.is_empty());
    let mut cfg = config();
    cfg.max_witness_pages = 0;
    cfg.max_total_witness_bytes = 0;
    cfg.envelope.max_external_dependencies = 0;
    assert!(suppliers(&proof, &pages, &cfg).unwrap().is_empty());
    assert_eq!(
        supplier_ids(&proof, std::iter::once(b"extra".as_slice()), &cfg)
            .unwrap_err()
            .code,
        FailureCode::InvalidResponse
    );
}

#[test]
fn real_closure_proof_binds_repository_object_root_and_ruleset() {
    let (proof, _) = closed(&[]);
    let cfg = config();
    check_artifact_binding([0x44; 32], rules(), &proof, binding(), &cfg).unwrap();
    assert_eq!(
        check_artifact_binding([0x45; 32], rules(), &proof, binding(), &cfg)
            .unwrap_err()
            .code,
        FailureCode::EvidenceBindingMismatch
    );
    let wrong_binding = AcceptanceEvidenceBinding {
        repository: RepositoryId([9; 32]),
        ..binding()
    };
    assert_eq!(
        check_artifact_binding([0x44; 32], rules(), &proof, wrong_binding, &cfg)
            .unwrap_err()
            .code,
        FailureCode::EvidenceBindingMismatch
    );
    let wrong_rules = RulesetBinding {
        ruleset: RulesetId(2),
        ..rules()
    };
    assert_eq!(
        check_artifact_binding([0x44; 32], wrong_rules, &proof, binding(), &cfg)
            .unwrap_err()
            .code,
        FailureCode::EvidenceProfileMismatch
    );
    let mut wrong_cfg = cfg;
    wrong_cfg.envelope.ruleset_id = RulesetId(2);
    assert_eq!(
        check_artifact_binding([0x44; 32], rules(), &proof, binding(), &wrong_cfg)
            .unwrap_err()
            .code,
        FailureCode::EvidenceProfileMismatch
    );
}

#[test]
fn shared_heads_root_matches_frozen_sequence_vectors() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fixtures/acceptance-export/heads-root.json"
    )))
    .unwrap();
    let parse_hash = |value: &serde_json::Value| -> Hash {
        let text = value.as_str().expect("hexadecimal fixture hash");
        assert_eq!(text.len(), 64);
        std::array::from_fn(|n| {
            u8::from_str_radix(&text[n * 2..n * 2 + 2], 16).expect("hexadecimal fixture byte")
        })
    };
    let mut roots = std::collections::BTreeSet::new();
    for vector in fixture["vectors"].as_array().unwrap() {
        let ids: Vec<_> = vector["ids"]
            .as_array()
            .unwrap()
            .iter()
            .map(parse_hash)
            .collect();
        let expected = parse_hash(&vector["root"]);
        assert_eq!(
            closure::heads_root(ids.into_iter()).unwrap(),
            expected,
            "vector {}",
            vector["name"]
        );
        assert!(
            roots.insert(expected),
            "each order or repetition has a distinct root"
        );
    }
    assert_eq!(roots.len(), 5);
}

#[test]
fn debug_output_is_bounded_and_omits_caller_bytes() {
    struct WitnessesWithoutDebug;
    impl Iterator for WitnessesWithoutDebug {
        type Item = Vec<u8>;
        fn next(&mut self) -> Option<Self::Item> {
            panic!("Debug must not poll witness input")
        }
    }
    let operation = vec![0xab; 65536];
    let bind = AcceptanceEvidenceBinding {
        operation: &operation,
        ..binding()
    };
    let bytes = vec![0xcd; 65536];
    let heads = [&bytes[..]];
    let input = AcceptanceEvidenceInput {
        heads: &heads,
        witness_pages: WitnessesWithoutDebug,
    };
    let binding_debug = format!("{bind:?}");
    let input_debug = format!("{input:?}");
    assert!(binding_debug.contains("65536"));
    assert!(input_debug.contains("head_occurrences: 1"));
    for diagnostic in [&binding_debug, &input_debug] {
        assert!(diagnostic.len() < 128);
        assert!(!diagnostic.contains("171, 171"));
        assert!(!diagnostic.contains("205, 205"));
    }
}

// Real sealed artifacts end to end: a written pack is verified by the sans-IO
// driver, the closure walker runs over the decoded object set, and export emits
// an envelope that decodes, binds, and rechecks independently.
const SUPPLIER: PackSource = PackSource {
    id: [0x77; 32],
    len: 4096,
    binding: SourceBinding([6; 32]),
};

fn object_pair(object: &Object) -> (Hash, Vec<u8>) {
    let bytes = serialize(object).unwrap();
    (id_from_object(object, &bytes), bytes)
}

fn signed_commit(tree_id: Hash) -> (Hash, Vec<u8>) {
    let key = sign::KeyPair::from_seed([0x42; 32]);
    let mut commit = Commit::new_unannotated(
        tree_id,
        vec![],
        Identity::ed25519(key.public.0),
        key.public.0,
        b"commit".to_vec(),
        100,
        [0; 64],
    );
    commit.signature = sign::sign_commit(&commit, &key).unwrap().0;
    object_pair(&Object::Commit(commit))
}

fn signed_tag(target: Hash) -> (Hash, Vec<u8>) {
    let key = sign::KeyPair::from_seed([0x33; 32]);
    let mut tag = Tag {
        target,
        target_type: ObjectType::Commit,
        name: b"v9".to_vec(),
        tagger: Identity::ed25519(key.public.0),
        signer: key.public.0,
        message: b"tag".to_vec(),
        timestamp: 101,
        signature: [0; 64],
    };
    tag.signature = sign::sign_tag(&tag, &key).unwrap().0;
    object_pair(&Object::Tag(tag))
}

// Pure in-memory view over the decoded object set; the sealed root is the
// trusted host commitment the trait contract requires.
struct PackView {
    root: Hash,
    objects: BTreeMap<Hash, (ObjectType, Vec<u8>)>,
    order: Vec<Hash>,
}
impl InPackObjectView for PackView {
    fn object_set_root(&self) -> Hash {
        self.root
    }
    fn retained_bytes(&self) -> u64 {
        self.objects.values().map(|(_, b)| b.len() as u64).sum()
    }
    fn object_count(&self) -> u64 {
        self.order.len() as u64
    }
    fn object(&self, id: &Hash) -> std::result::Result<Option<InPackObject>, Failure> {
        Ok(self.objects.get(id).map(|(kind, bytes)| InPackObject {
            object: *id,
            kind: *kind,
            canonical_len: bytes.len() as u64,
        }))
    }
    fn object_at(&self, ordinal: u64) -> std::result::Result<Option<InPackObject>, Failure> {
        let Ok(index) = usize::try_from(ordinal) else {
            return Ok(None);
        };
        Ok(self.order.get(index).and_then(|id| {
            self.objects.get(id).map(|(kind, bytes)| InPackObject {
                object: *id,
                kind: *kind,
                canonical_len: bytes.len() as u64,
            })
        }))
    }
    fn edge(&self, id: &Hash, ordinal: u64) -> std::result::Result<Option<ObjectEdge>, Failure> {
        Ok(self
            .objects
            .get(id)
            .map(|(_, bytes)| deserialize(bytes).expect("view holds canonical objects"))
            .and_then(|object| closure::edges::edge_at(&object, ordinal)))
    }
}

fn verify_pack(pack: &[u8], canonical: &BTreeMap<Hash, Vec<u8>>) -> VerifiedPack {
    let source = PackSource {
        id: hash::hash(pack),
        len: pack.len() as u64,
        binding: SourceBinding([0x7b; 32]),
    };
    let mut machine = VerifyDriver::new(
        source,
        REPOSITORY,
        IndexedProfile {
            pack_bytes: 1 << 30,
            decoded_bytes: 4 << 30,
            delta_depth: 50,
        },
        VerifyLimits::indexed(),
        17,
    )
    .expect("finite verify driver");
    let mut fragments: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
    let mut pages: Vec<(crate::evidence::PageCommitment, Vec<u8>)> = Vec::new();
    for _ in 0..100_000 {
        match machine.step().expect("valid verify protocol") {
            Step::Request(request) => match request {
                Request::Bytes {
                    request,
                    source,
                    range,
                } => {
                    let owned;
                    let value = match source {
                        ByteSource::Pack(_) => pack.get(
                            usize::try_from(range.offset).unwrap()
                                ..usize::try_from(range.offset + range.len).unwrap(),
                        ),
                        ByteSource::Canonical { object, len, .. } => {
                            owned = canonical.get(&object).cloned().or_else(|| {
                                fragments.values().find_map(|bytes| {
                                    (bytes.len() as u64 == len
                                        && deserialize(bytes).is_ok_and(|parsed| {
                                            id_from_object(&parsed, bytes) == object
                                        }))
                                    .then(|| bytes.clone())
                                })
                            });
                            owned.as_deref().and_then(|bytes| {
                                bytes.get(
                                    usize::try_from(range.offset).unwrap()
                                        ..usize::try_from(range.offset + range.len).unwrap(),
                                )
                            })
                        }
                    };
                    machine
                        .supply(Response::Bytes {
                            request,
                            source,
                            range,
                            value: value.map_or(Acquisition::Unavailable, Acquisition::Present),
                        })
                        .expect("exact byte response");
                }
                Request::ExternalObject { request, .. } => machine
                    .supply(Response::ExternalObject {
                        request,
                        value: Acquisition::Absent,
                    })
                    .expect("authoritative absence is answerable"),
                Request::EvidencePage { request, page } => {
                    let value = pages
                        .iter()
                        .find(|(commitment, _)| *commitment == page)
                        .map(|(_, bytes)| bytes.clone());
                    machine
                        .supply(Response::EvidencePage {
                            request,
                            page,
                            value: value
                                .as_deref()
                                .map_or(Acquisition::Unavailable, Acquisition::Present),
                        })
                        .expect("retained page response");
                }
            },
            Step::ProvisionalObject(fragment) => fragments
                .entry(fragment.ordinal)
                .or_default()
                .extend_from_slice(fragment.bytes),
            Step::RetainEvidence(page) => {
                let commitment = page.commitment;
                pages.push((commitment, page.bytes.to_vec()));
                machine
                    .acknowledge_retention(commitment)
                    .expect("acknowledged retention");
            }
            Step::Progress => {}
            Step::Complete(verified) => return verified,
        }
    }
    panic!("bounded verify driver must terminate")
}

fn closure_over(
    view: PackView,
    heads: &[Hash],
    ruleset: RulesetBinding,
    members: &BTreeMap<Hash, MemberFact>,
) -> (ClosureProof, Vec<Vec<u8>>) {
    let mut walker = ClosureWalker::new(
        view,
        heads,
        REPOSITORY,
        VIEW,
        ruleset,
        ClosureLimits::indexed(),
        1,
    )
    .expect("bounded closure fixture");
    let mut pages = BTreeMap::<Hash, Vec<u8>>::new();
    for _ in 0..10000 {
        match walker.step().expect("valid closure protocol") {
            ClosureStep::Progress => {}
            ClosureStep::Retain(event) => {
                let request = event.request;
                let page = event.page;
                pages.insert(page.digest, event.bytes.to_vec());
                walker
                    .acknowledge(request, page)
                    .expect("retained page acknowledgement");
            }
            ClosureStep::Request(request) => {
                let response = match request.clone() {
                    ClosureRequest::Membership(request) => {
                        let answers = request
                            .objects
                            .iter()
                            .map(|object| MembershipAnswer {
                                object: *object,
                                value: members.get(object).map_or(Acquisition::Absent, |fact| {
                                    Acquisition::Present(fact.clone())
                                }),
                            })
                            .collect();
                        ClosureResponse::Membership(MembershipResponse {
                            request: request.request,
                            repository: request.repository,
                            view: request.view,
                            answers,
                        })
                    }
                    ClosureRequest::Page { request, page } => ClosureResponse::Page {
                        request,
                        page,
                        value: Acquisition::Present(
                            pages.get(&page.digest).expect("retained page"),
                        ),
                    },
                    ClosureRequest::Canonical { request, source } => ClosureResponse::Canonical {
                        request,
                        source,
                        value: Acquisition::Absent,
                    },
                };
                walker.answer(response).expect("valid closure response");
            }
            ClosureStep::Closed(proof) => {
                let mut ordered = Vec::new();
                let mut next = proof.relied_on_members();
                while let Some(page) = next {
                    let bytes = pages.get(&page.digest).expect("retained witness page");
                    next = decode_witness(page, bytes, config().witness_page)
                        .expect("authenticated fixture witness")
                        .previous;
                    ordered.push(bytes.clone());
                }
                return (proof, ordered);
            }
            ClosureStep::Missing(_) => panic!("unexpected missing members"),
        }
    }
    panic!("bounded closure driver must terminate")
}

// One written pack: blobs a and delta-derived b, tree t over both, signed
// commit head.
struct WrittenPack {
    pack: Vec<u8>,
    canonical: BTreeMap<Hash, Vec<u8>>,
    rows: Vec<(Hash, ObjectType, Vec<u8>)>,
    head_id: Hash,
    head: Vec<u8>,
}
fn written_pack() -> WrittenPack {
    let (a_id, a) = object_pair(&Object::Blob(Blob {
        data: b"alpha".to_vec(),
    }));
    let (b_id, b) = object_pair(&Object::Blob(Blob {
        data: b"beta".to_vec(),
    }));
    let (t_id, t) = object_pair(&Object::Tree(Tree {
        entries: vec![
            TreeEntry {
                name: b"alpha".to_vec(),
                mode: EntryMode::Blob,
                object_hash: a_id,
            },
            TreeEntry {
                name: b"beta".to_vec(),
                mode: EntryMode::Blob,
                object_hash: b_id,
            },
        ],
    }));
    let (head_id, head) = signed_commit(t_id);
    let mut writer = PackWriter::new();
    writer.push_raw(a_id, &a).unwrap();
    writer
        .push_delta(&a_id, &delta::encode(&a, &b).unwrap())
        .unwrap();
    writer.push_raw(t_id, &t).unwrap();
    writer.push_raw(head_id, &head).unwrap();
    let pack = writer.finish().unwrap();
    let rows = [
        (a_id, ObjectType::Blob, a),
        (b_id, ObjectType::Blob, b),
        (t_id, ObjectType::Tree, t),
        (head_id, ObjectType::Commit, head.clone()),
    ];
    let canonical = rows
        .iter()
        .map(|(id, _, bytes)| (*id, bytes.clone()))
        .collect();
    WrittenPack {
        pack,
        canonical,
        rows: rows.into_iter().collect(),
        head_id,
        head,
    }
}

#[test]
fn sealed_artifacts_export_decodable_bound_evidence() {
    let written = written_pack();
    let verified = verify_pack(&written.pack, &written.canonical);
    assert_eq!(verified.counts().entries, 4);
    assert_eq!(verified.counts().objects, 4);
    assert_eq!(verified.counts().delta_entries, 1);

    let view = PackView {
        root: verified.object_set_root(),
        objects: written
            .rows
            .iter()
            .map(|(id, kind, bytes)| (*id, (*kind, bytes.clone())))
            .collect(),
        order: written.rows.iter().map(|(id, ..)| *id).collect(),
    };
    let (tag_id, tag) = signed_tag(written.head_id);
    let mut members = BTreeMap::new();
    members.insert(
        tag_id,
        MemberFact {
            repository: REPOSITORY,
            incarnation: VIEW,
            object: tag_id,
            kind: ObjectType::Tag,
            canonical_len: tag.len() as u64,
            supplier: SUPPLIER,
            canonical_binding: SourceBinding([0x66; 32]),
            revision: Revision([0x88; 32]),
            delta_depth: 0,
            published: true,
            held: false,
        },
    );
    let (proof, witness_pages) = closure_over(
        view,
        &[written.head_id, tag_id],
        verified.ruleset(),
        &members,
    );
    assert_eq!(proof.external_witnesses().count, 1);

    let mut cfg = config();
    cfg.envelope.ruleset_id = verified.ruleset().ruleset;
    let witness = MembershipWitness {
        generation: 5,
        removal_version: 9,
    };
    let evidence = AcceptanceEvidence::from_verified(
        &verified,
        &proof,
        AcceptanceEvidenceBinding {
            repository: REPOSITORY,
            operation: b"accept-7",
            epoch: 3,
        },
        witness,
        12,
        AcceptanceEvidenceInput {
            heads: &[written.head.as_slice(), tag.as_slice()],
            witness_pages: witness_pages.iter(),
        },
        &cfg,
    )
    .expect("sealed artifacts export");

    assert_exported(
        &evidence,
        &verified,
        &cfg,
        witness,
        [written.head_id, tag_id],
        SUPPLIER.id,
    );
}

fn assert_exported(
    evidence: &AcceptanceEvidence,
    verified: &VerifiedPack,
    cfg: &AcceptanceEvidenceBuildCfg,
    witness: MembershipWitness,
    heads: [Hash; 2],
    supplier: Hash,
) {
    let decoded = AcceptanceEvidence::decode(evidence.encode(), &cfg.envelope)
        .expect("export round-trips through strict decode");
    assert_eq!(&decoded, evidence);
    decoded
        .check_binding(
            &verified.pack_id(),
            verified.len(),
            &REPOSITORY,
            b"accept-7",
            3,
        )
        .expect("frozen binding rechecks");
    decoded.recheck_heads().expect("heads reverify");
    assert_eq!(decoded.digest(), evidence.digest());

    let facts = decoded.pack();
    assert_eq!(facts.id, verified.pack_id());
    assert_eq!(facts.len, verified.len());
    assert_eq!(facts.object_count, 4);
    assert_eq!(facts.delta_count, 1);
    assert_eq!(facts.object_set_root, verified.object_set_root());
    assert_eq!(decoded.witness(), witness);
    assert_eq!(decoded.denial_version(), 12);
    assert_eq!(
        decoded.external_dependencies().collect::<Vec<_>>(),
        vec![supplier]
    );
    let mut ids: Vec<Hash> = decoded.heads().map(|head| head.object_id).collect();
    ids.sort_unstable();
    let mut expected = heads;
    expected.sort_unstable();
    assert_eq!(ids, expected);
    for head_fact in decoded.heads() {
        assert_eq!(head_fact.signature_result, SignatureResult::Valid);
    }
}

#[test]
fn envelope_cap_refuses_before_encode() {
    let fixture = representative();
    let heads: Vec<_> = fixture.heads().collect();
    let dependencies: Vec<_> = fixture.external_dependencies().collect();
    let mut cfg = config();
    cfg.envelope.max_envelope_bytes = u32::try_from(fixture.encode().len() - 1).unwrap();
    assert_eq!(
        encode(
            AcceptanceEvidenceBinding {
                repository: fixture.repository(),
                operation: fixture.operation(),
                epoch: fixture.epoch(),
            },
            fixture.witness(),
            fixture.denial_version(),
            fixture.pack(),
            &heads,
            &dependencies,
            &cfg.envelope,
        )
        .unwrap_err()
        .code,
        FailureCode::ResourceLimit
    );
}
