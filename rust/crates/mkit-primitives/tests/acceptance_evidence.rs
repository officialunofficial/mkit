use mkit_core::{
    object::{self, Commit, Identity, Object, ObjectType, Remix, RemixSource, Tag},
    serialize, sign,
};
use mkit_primitives::{
    error::FailureCode,
    evidence::{
        RepositoryId, RulesetId, acceptance::AcceptanceEvidence,
        acceptance::AcceptanceEvidenceDecodeCfg,
    },
};

#[derive(Clone)]
struct Head {
    id: [u8; 32],
    kind: u8,
    signer: [u8; 32],
    signature_tag: u8,
    bytes: Vec<u8>,
}

#[derive(Clone)]
struct Envelope {
    operation: Vec<u8>,
    heads: Vec<Head>,
    dependencies: Vec<[u8; 32]>,
    object_count: u64,
    delta_count: u64,
}

impl Envelope {
    fn empty() -> Self {
        Self {
            operation: Vec::new(),
            heads: Vec::new(),
            dependencies: Vec::new(),
            object_count: 0,
            delta_count: 0,
        }
    }

    // Independent wire builder: field order and widths are the format contract.
    fn encode(&self) -> Vec<u8> {
        let mut b = b"MKAE".to_vec();
        b.extend(1_u16.to_le_bytes());
        b.extend(1_u32.to_le_bytes());
        b.extend([0x11; 32]);
        b.extend([0x22; 32]);
        b.extend(
            u32::try_from(self.operation.len())
                .expect("valid deterministic fixture")
                .to_le_bytes(),
        );
        b.extend(&self.operation);
        b.extend(0_u64.to_le_bytes());
        b.extend([0x33; 32]);
        b.extend(0_u64.to_le_bytes());
        b.extend(self.object_count.to_le_bytes());
        b.extend(self.delta_count.to_le_bytes());
        b.extend([0x44; 32]);
        b.extend(
            u32::try_from(self.heads.len())
                .expect("valid deterministic fixture")
                .to_le_bytes(),
        );
        for h in &self.heads {
            b.extend(h.id);
            b.push(h.kind);
            b.extend(h.signer);
            b.push(h.signature_tag);
            b.extend(
                u32::try_from(h.bytes.len())
                    .expect("valid deterministic fixture")
                    .to_le_bytes(),
            );
            b.extend(&h.bytes);
        }
        b.extend(
            u32::try_from(self.dependencies.len())
                .expect("valid deterministic fixture")
                .to_le_bytes(),
        );
        for d in &self.dependencies {
            b.extend(d);
        }
        b.extend(0_u64.to_le_bytes());
        b.extend(0_u64.to_le_bytes());
        b.extend(0_u64.to_le_bytes());
        b
    }
}

fn cfg() -> AcceptanceEvidenceDecodeCfg {
    AcceptanceEvidenceDecodeCfg {
        max_envelope_bytes: 4096,
        max_operation_bytes: 32,
        max_heads: 4,
        max_head_bytes: 1024,
        max_total_head_bytes: 3072,
        max_external_dependencies: 4,
        ruleset_id: RulesetId(1),
        profile_limits_digest: [0x11; 32],
    }
}

fn reject(bytes: &[u8], config: &AcceptanceEvidenceDecodeCfg, code: FailureCode) {
    assert_eq!(
        AcceptanceEvidence::decode(bytes, config)
            .expect_err("malformed evidence is rejected")
            .code,
        code
    );
}

fn signed_heads() -> Vec<Head> {
    let kp = sign::KeyPair::from_seed([0x42; 32]);
    let mut commit = Commit::new_unannotated(
        [1; 32],
        vec![],
        Identity::ed25519(kp.public.0),
        kp.public.0,
        b"commit".to_vec(),
        100,
        [0; 64],
    );
    commit.signature = sign::sign_commit(&commit, &kp)
        .expect("valid deterministic fixture")
        .0;
    let mut remix = Remix {
        tree_hash: [1; 32],
        parents: vec![],
        sources: vec![RemixSource {
            upstream_id: [2; 32],
            commit_hash: [3; 32],
        }],
        author: Identity::ed25519(kp.public.0),
        signer: kp.public.0,
        message: b"remix".to_vec(),
        timestamp: 101,
        signature: [0; 64],
    };
    remix.signature = sign::sign_remix(&remix, &kp)
        .expect("valid deterministic fixture")
        .0;
    let mut tag = Tag {
        target: [3; 32],
        target_type: ObjectType::Commit,
        name: b"v1.0.0".to_vec(),
        tagger: Identity::ed25519(kp.public.0),
        signer: kp.public.0,
        message: b"tag".to_vec(),
        timestamp: 102,
        signature: [0; 64],
    };
    tag.signature = sign::sign_tag(&tag, &kp)
        .expect("valid deterministic fixture")
        .0;
    let mut heads: Vec<_> = [
        Object::Commit(commit),
        Object::Remix(remix),
        Object::Tag(tag),
    ]
    .into_iter()
    .map(|obj| {
        let bytes = serialize::serialize(&obj).expect("valid deterministic fixture");
        Head {
            id: object::id_from_object(&obj, &bytes),
            kind: bytes[0],
            signer: kp.public.0,
            signature_tag: 1,
            bytes,
        }
    })
    .collect();
    heads.sort_by_key(|h| h.id);
    heads
}

#[test]
fn minimal_encoding_and_digest_are_pinned() {
    let bytes = Envelope::empty().encode();
    assert_eq!(bytes.len(), 206);
    assert_eq!(
        bytes.as_slice(),
        include_bytes!("../fixtures/acceptance/minimal.bin")
    );
    let e = AcceptanceEvidence::decode(&bytes, &cfg()).unwrap();
    let hex = mkit_core::hash::to_hex(&e.digest());
    // Independently generated BLAKE3 vector, committed with the format fixture.
    assert_eq!(
        hex,
        "b35231ce8e02236728253f931e9635195ecf56223526f634b292d432ca2cb6da"
    );
    assert_eq!(e.encode(), bytes);
    assert_eq!(e.encoded_len(), bytes.len());
    assert_eq!(e.repository(), RepositoryId([0x22; 32]));
    assert_eq!(e.profile_limits_digest(), [0x11; 32]);
    assert_eq!(e.ruleset_id(), RulesetId(1));
    assert_eq!(e.pack().object_set_root, [0x44; 32]);
    assert_eq!(e.pack().object_count, 0);
    assert_eq!(e.pack().delta_count, 0);
    assert_eq!(e.witness().generation, 0);
    assert_eq!(e.witness().removal_version, 0);
    assert_eq!(e.denial_version(), 0);
    e.recheck_heads().unwrap();
}

#[test]
fn signed_commit_remix_and_tag_roundtrip_and_recheck() {
    let mut input = Envelope::empty();
    input.operation = b"operation\0opaque\xff".to_vec();
    input.heads = signed_heads();
    input.dependencies = vec![[1; 32], [2; 32]];
    input.object_count = u64::MAX;
    input.delta_count = u64::MAX;
    let bytes = input.encode();
    let e = AcceptanceEvidence::decode(&bytes, &cfg()).unwrap();
    e.recheck_heads().unwrap();
    assert_eq!(e.encode(), bytes);
    assert_eq!(e.operation(), input.operation);
    assert_eq!(
        e.external_dependencies().collect::<Vec<_>>(),
        input.dependencies
    );
    let heads: Vec<_> = e.heads().collect();
    assert_eq!(heads.len(), 3);
    for (decoded, expected) in heads.iter().zip(&input.heads) {
        assert_eq!(decoded.object_id, expected.id);
        assert_eq!(decoded.kind as u8, expected.kind);
        assert_eq!(decoded.signer, expected.signer);
        assert_eq!(decoded.canonical_bytes, expected.bytes);
    }
    let mut kinds: Vec<_> = heads.iter().map(|h| h.kind as u8).collect();
    kinds.sort_unstable();
    assert_eq!(kinds, [3, 4, 7]);
    assert_eq!(AcceptanceEvidence::decode(e.encode(), &cfg()).unwrap(), e);
    for prefix in 0..bytes.len() {
        reject(&bytes[..prefix], &cfg(), FailureCode::UnexpectedEof);
    }
}

#[test]
fn every_frozen_and_replay_binding_is_checked() {
    let e = AcceptanceEvidence::decode(&Envelope::empty().encode(), &cfg()).unwrap();
    let repo = RepositoryId([0x22; 32]);
    e.check_binding(&[0x33; 32], 0, &repo, b"", 0).unwrap();
    for (pack, len, repository, operation, epoch) in [
        ([0x34; 32], 0, repo, b"".as_slice(), 0),
        ([0x33; 32], 1, repo, b"".as_slice(), 0),
        ([0x33; 32], 0, RepositoryId([0x23; 32]), b"".as_slice(), 0),
        ([0x33; 32], 0, repo, b"changed".as_slice(), 0),
        ([0x33; 32], 0, repo, b"".as_slice(), 1),
    ] {
        assert_eq!(
            e.check_binding(&pack, len, &repository, operation, epoch)
                .unwrap_err()
                .code,
            FailureCode::EvidenceBindingMismatch
        );
    }
}

#[test]
fn recheck_refuses_each_head_metadata_and_signature_attack() {
    for original in signed_heads() {
        let mut bad_signature = original.clone();
        let mut obj = serialize::deserialize(&bad_signature.bytes).unwrap();
        match &mut obj {
            Object::Commit(c) => c.signature[0] ^= 1,
            Object::Remix(r) => r.signature[0] ^= 1,
            Object::Tag(t) => t.signature[0] ^= 1,
            _ => unreachable!(),
        }
        bad_signature.bytes = serialize::serialize(&obj).unwrap();
        bad_signature.id = object::id_from_object(&obj, &bad_signature.bytes);
        let mut wrong_id = original.clone();
        wrong_id.id[0] ^= 1;
        let mut wrong_signer = original.clone();
        wrong_signer.signer[0] ^= 1;
        let mut malformed = original.clone();
        malformed.bytes.truncate(1);
        for (head, code) in [
            (bad_signature, FailureCode::BadSignature),
            (wrong_id, FailureCode::ObjectHashMismatch),
            (wrong_signer, FailureCode::EvidenceHeadMismatch),
            (malformed, FailureCode::NonCanonicalObject),
        ] {
            let mut input = Envelope::empty();
            input.heads.push(head);
            let e = AcceptanceEvidence::decode(&input.encode(), &cfg()).unwrap();
            assert_eq!(e.recheck_heads().unwrap_err().code, code);
        }
    }
}

#[test]
fn rejects_unknown_versions_profiles_tags_and_trailing_bytes() {
    let minimal = Envelope::empty().encode();
    for version in [0_u16, 2, u16::MAX] {
        let mut b = minimal.clone();
        b[4..6].copy_from_slice(&version.to_le_bytes());
        reject(&b, &cfg(), FailureCode::UnsupportedEvidenceVersion);
    }
    for offset in [0, 6, 10] {
        let mut b = minimal.clone();
        b[offset] ^= 1;
        reject(
            &b,
            &cfg(),
            if offset == 0 {
                FailureCode::NonCanonicalEvidence
            } else {
                FailureCode::EvidenceProfileMismatch
            },
        );
    }
    let mut b = minimal;
    b.push(0);
    reject(&b, &cfg(), FailureCode::NonCanonicalEvidence);
    for (kind, tag, bytes) in [
        (0, 1, vec![0]),
        (255, 1, vec![255]),
        (3, 0, vec![3]),
        (3, 2, vec![3]),
        (3, 1, vec![]),
        (3, 1, vec![4]),
    ] {
        let mut input = Envelope::empty();
        input.heads.push(Head {
            id: [0; 32],
            kind,
            signer: [0; 32],
            signature_tag: tag,
            bytes,
        });
        reject(&input.encode(), &cfg(), FailureCode::NonCanonicalEvidence);
    }
    let mut input = Envelope::empty();
    input.delta_count = 1;
    reject(&input.encode(), &cfg(), FailureCode::NonCanonicalEvidence);
}

#[test]
fn rejects_duplicates_and_noncanonical_order() {
    let heads = signed_heads();
    for pair in [
        vec![heads[0].clone(), heads[0].clone()],
        vec![heads[1].clone(), heads[0].clone()],
    ] {
        let mut input = Envelope::empty();
        input.heads = pair;
        reject(&input.encode(), &cfg(), FailureCode::NonCanonicalEvidence);
    }
    for dependencies in [vec![[1; 32], [1; 32]], vec![[2; 32], [1; 32]]] {
        let mut input = Envelope::empty();
        input.dependencies = dependencies;
        reject(&input.encode(), &cfg(), FailureCode::NonCanonicalEvidence);
    }
}

#[test]
fn exact_caps_succeed_and_one_extra_unit_fails() {
    let mut input = Envelope::empty();
    input.operation = vec![0; 4];
    input.heads = signed_heads();
    input.dependencies = vec![[1; 32], [2; 32]];
    let bytes = input.encode();
    let mut exact = cfg();
    exact.max_envelope_bytes = u32::try_from(bytes.len()).unwrap();
    exact.max_operation_bytes = u32::try_from(input.operation.len()).unwrap();
    exact.max_heads = u32::try_from(input.heads.len()).unwrap();
    exact.max_head_bytes =
        u32::try_from(input.heads.iter().map(|h| h.bytes.len()).max().unwrap()).unwrap();
    exact.max_total_head_bytes =
        u32::try_from(input.heads.iter().map(|h| h.bytes.len()).sum::<usize>()).unwrap();
    exact.max_external_dependencies = u32::try_from(input.dependencies.len()).unwrap();
    AcceptanceEvidence::decode(&bytes, &exact)
        .unwrap()
        .recheck_heads()
        .unwrap();
    for field in 0..6 {
        let mut reduced = exact.clone();
        match field {
            0 => reduced.max_envelope_bytes -= 1,
            1 => reduced.max_operation_bytes -= 1,
            2 => reduced.max_heads -= 1,
            3 => reduced.max_head_bytes -= 1,
            4 => reduced.max_total_head_bytes -= 1,
            5 => reduced.max_external_dependencies -= 1,
            _ => unreachable!(),
        }
        reject(&bytes, &reduced, FailureCode::ResourceLimit);
    }
    let mut zero = cfg();
    zero.max_operation_bytes = 0;
    zero.max_heads = 0;
    zero.max_head_bytes = 0;
    zero.max_total_head_bytes = 0;
    zero.max_external_dependencies = 0;
    assert!(AcceptanceEvidence::decode(&Envelope::empty().encode(), &zero).is_ok());
}

#[test]
fn diagnostics_do_not_dump_head_or_operation_bytes() {
    let mut input = Envelope::empty();
    input.operation = b"private-operation".to_vec();
    input.heads = signed_heads();
    let evidence = AcceptanceEvidence::decode(&input.encode(), &cfg()).unwrap();
    // Diagnostics remain bounded independently of canonical object/identifier bytes.
    assert!(format!("{evidence:?}").len() < 128);
    for head in evidence.heads() {
        assert!(format!("{head:?}").len() < 128);
    }
}
