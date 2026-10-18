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
    let verified = VerifiedPack::synthetic_for_tests(EmptyView.object_set_root(), rules());
    let mut walker = ClosureWalker::new(
        EmptyView,
        &verified,
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

/// Bytes for one requested range of the pack or a canonical object.
fn byte_range<'a>(
    pack: &'a [u8],
    canonical: &BTreeMap<Hash, Vec<u8>>,
    fragments: &BTreeMap<u64, Vec<u8>>,
    source: ByteSource,
    range: crate::pack_verify::ByteRange,
    owned: &'a mut Option<Vec<u8>>,
) -> Option<&'a [u8]> {
    let start = usize::try_from(range.offset).unwrap();
    let end = usize::try_from(range.offset + range.len).unwrap();
    match source {
        ByteSource::Pack(_) => pack.get(start..end),
        ByteSource::Canonical { object, len, .. } => {
            *owned = canonical.get(&object).cloned().or_else(|| {
                fragments.values().find_map(|bytes| {
                    (bytes.len() as u64 == len
                        && deserialize(bytes)
                            .is_ok_and(|parsed| id_from_object(&parsed, bytes) == object))
                    .then(|| bytes.clone())
                })
            });
            owned.as_deref().and_then(|bytes| bytes.get(start..end))
        }
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
                    let mut owned = None;
                    let value = byte_range(pack, canonical, &fragments, source, range, &mut owned);
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
                Request::Compute { .. } => {
                    panic!("acceptance verification issues no compute jobs")
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
            Step::Progress | Step::ReleasePage(_) => {}
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
    let verified = VerifiedPack::synthetic_for_tests(view.object_set_root(), ruleset);
    let mut walker = ClosureWalker::new(
        view,
        &verified,
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

mod basis {
    use super::*;
    use crate::decision::ref_write::guard_kind;
    use crate::decision::{AcceptanceBasis, BasisCfg, GuardKind, RequiredGuard};

    fn cfg() -> BasisCfg {
        let build = config();
        BasisCfg {
            max_witness_pages: build.max_witness_pages,
            max_total_witness_bytes: build.max_total_witness_bytes,
            max_dependencies: 8,
            witness_page: build.witness_page,
        }
    }
    fn verified() -> VerifiedPack {
        VerifiedPack::synthetic_for_tests([0x44; 32], rules())
    }
    fn kinds(basis: &AcceptanceBasis) -> Vec<GuardKind> {
        let mut kinds = Vec::new();
        for guard in basis.guards() {
            let kind = guard_kind(guard);
            if !kinds.contains(&kind) {
                kinds.push(kind);
            }
        }
        kinds
    }
    fn external_base(object: u8) -> MemberFact {
        MemberFact {
            repository: REPOSITORY,
            incarnation: VIEW,
            object: [object; 32],
            kind: ObjectType::Blob,
            canonical_len: 64,
            supplier: PackSource {
                id: [0x99; 32],
                len: 512,
                binding: SourceBinding([0x98; 32]),
            },
            canonical_binding: SourceBinding([0x97; 32]),
            revision: Revision([0x96; 32]),
            delta_depth: 0,
            published: true,
            held: false,
        }
    }
    fn derive(
        verified: &VerifiedPack,
        proof: &ClosureProof,
        pages: &[&[u8]],
        bases: &[MemberFact],
        cfg: &BasisCfg,
    ) -> Result<AcceptanceBasis> {
        AcceptanceBasis::from_verified(verified, proof, None, 9, pages.iter().copied(), bases, cfg)
    }
    fn all(pages: &[Vec<u8>]) -> Vec<&[u8]> {
        pages.iter().map(Vec::as_slice).collect()
    }

    #[test]
    fn from_verified_guards_every_relied_on_dependency_the_denial_and_the_roots() {
        let (proof, pages) = proof_with_three_members();
        let basis = derive(
            &verified(),
            &proof,
            &all(&pages),
            &[external_base(0x10)],
            &cfg(),
        )
        .unwrap();
        assert_eq!(basis.repository(), REPOSITORY);
        let count = |f: fn(&RequiredGuard) -> bool| basis.guards().iter().filter(|g| f(g)).count();
        // Three closure witnesses plus one external delta base.
        assert_eq!(count(|g| matches!(g, RequiredGuard::Membership { .. })), 4);
        assert_eq!(
            count(|g| matches!(g, RequiredGuard::DependencyPublication { .. })),
            4
        );
        assert_eq!(
            count(|g| matches!(g, RequiredGuard::DenialVersion { version: 9 })),
            1
        );
        assert_eq!(count(|g| matches!(g, RequiredGuard::Binding { .. })), 1);
        assert_eq!(basis.guards().len(), 10);
        // The evidence-backed basis draws on a subset of the same guard kinds.
        let evidence = AcceptanceBasis::from_evidence(&representative());
        for kind in kinds(&evidence) {
            assert!(kinds(&basis).contains(&kind), "{kind:?}");
        }
        // The pack the basis covers is the sealed pack, by identity and length.
        let sealed = verified();
        assert!(basis.covers(&sealed.pack_id(), sealed.len()));
        assert!(!basis.covers(&sealed.pack_id(), sealed.len() + 1));
        assert!(!basis.covers(&[0x42; 32], sealed.len()));
    }

    #[test]
    fn from_verified_roots_bind_the_pack_and_the_closure() {
        let (proof, pages) = proof_with_three_members();
        let digest = |basis: &AcceptanceBasis| {
            basis.guards().iter().find_map(|g| match g {
                RequiredGuard::Binding { digest } => Some(*digest),
                _ => None,
            })
        };
        let base = derive(&verified(), &proof, &all(&pages), &[], &cfg()).unwrap();
        // A different closure (other heads and witnesses) binds a different root.
        let (other, other_pages) = closed(&[([1; 32], ObjectType::Commit, [0x77; 32])]);
        let other_basis = derive(&verified(), &other, &all(&other_pages), &[], &cfg()).unwrap();
        assert_ne!(digest(&base), digest(&other_basis));
        // A pack whose object-set root differs from the proof's is refused.
        let foreign = VerifiedPack::synthetic_for_tests([0x45; 32], rules());
        assert_eq!(
            derive(&foreign, &proof, &all(&pages), &[], &cfg())
                .unwrap_err()
                .code,
            FailureCode::EvidenceBindingMismatch
        );
        // So is a pack verified under another ruleset.
        let other_rules = RulesetBinding {
            ruleset: RulesetId(2),
            ..rules()
        };
        let reruled = VerifiedPack::synthetic_for_tests([0x44; 32], other_rules);
        assert_eq!(
            derive(&reruled, &proof, &all(&pages), &[], &cfg())
                .unwrap_err()
                .code,
            FailureCode::EvidenceBindingMismatch
        );
    }

    #[test]
    fn from_verified_refuses_bad_witness_streams_and_never_truncates() {
        let (proof, pages) = proof_with_three_members();
        let pages = all(&pages);
        let go = |pages: &[&[u8]], cfg: &BasisCfg| derive(&verified(), &proof, pages, &[], cfg);
        assert!(go(&pages, &cfg()).is_ok());
        // Missing, extra and reordered pages fail closed.
        assert_eq!(
            go(&pages[..2], &cfg()).unwrap_err().code,
            FailureCode::InvalidResponse
        );
        let mut extra = pages.clone();
        extra.push(pages[0]);
        assert_eq!(
            go(&extra, &cfg()).unwrap_err().code,
            FailureCode::InvalidResponse
        );
        let mut reordered = pages.clone();
        reordered.swap(0, 1);
        assert!(go(&reordered, &cfg()).is_err());
        // Every allowance refuses rather than truncating.
        let total: u64 = pages.iter().map(|b| b.len() as u64).sum();
        let mut tight = cfg();
        tight.max_total_witness_bytes = total;
        tight.witness_page.max_bytes = pages.iter().map(|b| b.len() as u64).max().unwrap();
        tight.witness_page.max_work = tight.witness_page.max_bytes;
        tight.max_dependencies = 3;
        assert!(go(&pages, &tight).is_ok());
        for which in 0..5 {
            let mut limited = tight;
            match which {
                0 => limited.max_dependencies = 2,
                1 => limited.max_witness_pages = 2,
                2 => limited.max_total_witness_bytes = total - 1,
                3 => limited.witness_page.max_bytes -= 1,
                _ => limited.witness_page.max_work -= 1,
            }
            assert_eq!(
                go(&pages, &limited).unwrap_err().code,
                FailureCode::ResourceLimit,
                "allowance {which}"
            );
        }
    }

    #[test]
    fn external_bases_are_scoped_deduplicated_and_never_contradictory() {
        let (proof, pages) = proof_with_three_members();
        let pages = all(&pages);
        let go = |bases: &[MemberFact]| derive(&verified(), &proof, &pages, bases, &cfg());
        // A base from another repository is refused.
        let mut foreign = external_base(0x10);
        foreign.repository = RepositoryId([0x23; 32]);
        assert_eq!(
            go(&[foreign]).unwrap_err().code,
            FailureCode::EvidenceBindingMismatch
        );
        // The same base twice guards once; the same object seen both as a
        // closure witness and as a base must agree exactly.
        let once = go(&[external_base(0x10)]).unwrap();
        assert_eq!(
            go(&[external_base(0x10), external_base(0x10)])
                .unwrap()
                .guards(),
            once.guards()
        );
        let mut conflicting = external_base(0x10);
        conflicting.held = true;
        assert_eq!(
            go(&[external_base(0x10), conflicting]).unwrap_err().code,
            FailureCode::InvalidResponse
        );
        let mut as_witness = external_base(1);
        as_witness.revision = Revision([0x11; 32]);
        assert_eq!(
            go(&[as_witness]).unwrap_err().code,
            FailureCode::InvalidResponse
        );
    }

    #[test]
    fn from_evidence_yields_exactly_three_guards_and_each_field_moves_one() {
        let evidence = representative();
        let basis = AcceptanceBasis::from_evidence(&evidence);
        assert_eq!(basis.repository(), evidence.repository());
        let pack = evidence.pack();
        assert!(basis.covers(&pack.id, pack.len));
        assert!(!basis.covers(&pack.id, pack.len + 1));
        let witness = evidence.witness();
        assert_eq!(
            basis.guards(),
            [
                RequiredGuard::MembershipWitness {
                    repository: evidence.repository(),
                    generation: witness.generation,
                    removal_version: witness.removal_version,
                },
                RequiredGuard::DenialVersion {
                    version: evidence.denial_version(),
                },
                RequiredGuard::Binding {
                    digest: evidence.digest(),
                },
            ]
        );
        // The last 24 bytes are generation, removal version and denial version.
        let bytes = evidence.encode().to_vec();
        for offset in [24, 16, 8] {
            let mut moved = bytes.clone();
            let at = moved.len() - offset;
            moved[at] ^= 1;
            let decoded = AcceptanceEvidence::decode(&moved, &config().envelope).unwrap();
            let next = AcceptanceBasis::from_evidence(&decoded);
            assert_ne!(next.guards(), basis.guards(), "offset {offset}");
        }
        // Any other byte, here the replay epoch, changes the root binding.
        let mut moved = bytes;
        let epoch_at = 4 + 2 + 4 + 32 + 32 + 4 + evidence.operation().len();
        moved[epoch_at] ^= 1;
        let decoded = AcceptanceEvidence::decode(&moved, &config().envelope).unwrap();
        assert_eq!(decoded.epoch() ^ evidence.epoch(), 1);
        assert_ne!(
            AcceptanceBasis::from_evidence(&decoded).guards(),
            basis.guards()
        );
    }
}
