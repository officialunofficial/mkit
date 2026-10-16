//! Frozen bytes authored independently of the Rust encoders. Never regenerated.

use super::{
    EdgeKind,
    journal::{Journal, Lookup, Record, State, validate_bytes},
    output::{
        MissingObject, MissingReason, PageDecodeCfg, decode_missing, decode_witness,
        encode_missing, encode_witness,
    },
};
use crate::{
    error::FailureCode,
    evidence::{
        MemberFact, PackSource, PageCommitment, PageKind, RepositoryId, Revision, SourceBinding,
    },
};
use mkit_core::{hash::domain_digest, object::ObjectType};

const GRAY: &[u8] = include_bytes!("../../fixtures/closure/state-gray.bin");
const BLACK: &[u8] = include_bytes!("../../fixtures/closure/state-black.bin");
const ABSENT: &[u8] = include_bytes!("../../fixtures/closure/state-absent.bin");
const MEMBER: &[u8] = include_bytes!("../../fixtures/closure/state-member.bin");
const WITNESS: &[u8] = include_bytes!("../../fixtures/closure/witness-member.bin");
const MISSING: &[u8] = include_bytes!("../../fixtures/closure/missing-all-reasons.bin");
const CFG: PageDecodeCfg = PageDecodeCfg {
    max_bytes: 4096,
    max_reasons: 6,
    max_work: 8192,
};

fn fact() -> MemberFact {
    MemberFact {
        repository: RepositoryId([1; 32]),
        incarnation: Revision([2; 32]),
        object: [17; 32],
        kind: ObjectType::Blob,
        canonical_len: 19,
        supplier: PackSource {
            id: [3; 32],
            len: 100,
            binding: SourceBinding([4; 32]),
        },
        canonical_binding: SourceBinding([5; 32]),
        revision: Revision([6; 32]),
        delta_depth: 7,
        published: true,
        held: false,
    }
}
fn previous() -> PageCommitment {
    PageCommitment {
        digest: [0x90; 32],
        kind: PageKind::Closure,
        len: 64,
        items: 1,
    }
}
fn commitment(domain: &[u8], bytes: &[u8]) -> PageCommitment {
    PageCommitment {
        digest: domain_digest(domain, bytes),
        kind: PageKind::Closure,
        len: bytes.len() as u64,
        items: 1,
    }
}
fn gray() -> Record {
    Record {
        kind: ObjectType::Blob,
        canonical_len: 19,
        state: State::Gray,
        blob_payload_len: None,
    }
}
fn missing() -> MissingObject {
    let mut reasons = vec![MissingReason {
        source: None,
        kind: None,
        ordinal: 0,
    }];
    for (ordinal, kind) in [
        EdgeKind::TreeEntry,
        EdgeKind::Tree,
        EdgeKind::Parent,
        EdgeKind::Chunk,
        EdgeKind::TagTarget,
    ]
    .into_iter()
    .enumerate()
    {
        reasons.push(MissingReason {
            source: Some([0x21; 32]),
            kind: Some(kind),
            ordinal: ordinal as u64 + 1,
        });
    }
    MissingObject {
        object: [0x31; 32],
        reasons,
    }
}

#[test]
fn frozen_state_bytes_match_all_states_and_optional_fields() {
    for (record, bytes, prepend) in [
        (gray(), GRAY, false),
        (
            Record {
                state: State::Black,
                blob_payload_len: Some(9),
                ..gray()
            },
            BLACK,
            true,
        ),
        (
            Record {
                canonical_len: 0,
                state: State::Absent,
                ..gray()
            },
            ABSENT,
            false,
        ),
        (
            Record {
                state: State::Member(fact()),
                blob_payload_len: Some(9),
                ..gray()
            },
            MEMBER,
            true,
        ),
    ] {
        let mut journal = Journal::new();
        if prepend {
            let (page, encoded) = journal.put([17; 32], gray()).unwrap();
            assert_eq!(encoded, GRAY);
            journal.acknowledge(page).unwrap();
        }
        let (page, encoded) = journal.put([17; 32], record.clone()).unwrap();
        assert_eq!(encoded, bytes);
        assert_eq!(page, commitment(b"mkit-closure-state:v1", bytes));
        journal.acknowledge(page).unwrap();
        assert_eq!(journal.lookup(&[17; 32]).unwrap(), Lookup::NeedPage(page));
        journal.supply(bytes).unwrap();
        assert_eq!(
            journal.lookup(&[17; 32]).unwrap(),
            Lookup::Found(Some(record))
        );
    }
}

#[test]
fn frozen_witness_and_missing_bytes_preserve_all_fields() {
    let (page, encoded) = encode_witness(Some(previous()), &fact()).unwrap();
    assert_eq!(encoded, WITNESS);
    assert_eq!(page, commitment(b"mkit-closure-witness:v1", WITNESS));
    let decoded = decode_witness(page, WITNESS, CFG).unwrap();
    assert_eq!(decoded.previous, Some(previous()));
    assert_eq!(decoded.fact, fact());

    let (page, encoded) = encode_missing(Some(previous()), &missing()).unwrap();
    assert_eq!(encoded, MISSING);
    assert_eq!(page, commitment(b"mkit-closure-missing:v1", MISSING));
    let decoded = decode_missing(page, MISSING, CFG).unwrap();
    assert_eq!(decoded.previous, Some(previous()));
    assert_eq!(decoded.missing, missing());
}

#[test]
fn frozen_bad_state_grammar_is_rejected() {
    for bytes in [
        include_bytes!("../../fixtures/closure/state-bad-version.bin").as_slice(),
        include_bytes!("../../fixtures/closure/state-trailing.bin").as_slice(),
        include_bytes!("../../fixtures/closure/state-bad-kind.bin").as_slice(),
        include_bytes!("../../fixtures/closure/state-bad-payload.bin").as_slice(),
    ] {
        // Parser-level test: these bytes have their own valid commitment, so
        // refusal must come from grammar rather than an incorrect digest.
        assert_ne!(commitment(b"mkit-closure-state:v1", bytes).digest, [0; 32]);
        assert_eq!(
            validate_bytes(bytes).unwrap_err().code,
            FailureCode::InvalidResponse
        );
    }
}

#[test]
fn frozen_bad_output_pages_refuse_even_with_matching_commitments() {
    for bytes in [
        include_bytes!("../../fixtures/closure/witness-bad-version.bin").as_slice(),
        include_bytes!("../../fixtures/closure/witness-trailing.bin").as_slice(),
        include_bytes!("../../fixtures/closure/witness-bad-boolean.bin").as_slice(),
    ] {
        let page = commitment(b"mkit-closure-witness:v1", bytes);
        assert_eq!(
            decode_witness(page, bytes, CFG).unwrap_err().code,
            FailureCode::InvalidResponse
        );
    }
    for bytes in [
        include_bytes!("../../fixtures/closure/missing-bad-version.bin").as_slice(),
        include_bytes!("../../fixtures/closure/missing-trailing.bin").as_slice(),
        include_bytes!("../../fixtures/closure/missing-bad-edge.bin").as_slice(),
    ] {
        let page = commitment(b"mkit-closure-missing:v1", bytes);
        assert_eq!(
            decode_missing(page, bytes, CFG).unwrap_err().code,
            FailureCode::InvalidResponse
        );
    }
}

#[test]
fn frozen_output_decoder_caps_are_exact() {
    let page = commitment(b"mkit-closure-witness:v1", WITNESS);
    let exact = PageDecodeCfg {
        max_bytes: page.len,
        max_reasons: 0,
        max_work: page.len,
    };
    assert!(decode_witness(page, WITNESS, exact).is_ok());
    assert_eq!(
        decode_witness(
            page,
            WITNESS,
            PageDecodeCfg {
                max_bytes: page.len - 1,
                ..exact
            }
        )
        .unwrap_err()
        .code,
        FailureCode::ResourceLimit,
    );
    let page = commitment(b"mkit-closure-missing:v1", MISSING);
    let exact = PageDecodeCfg {
        max_bytes: page.len,
        max_reasons: 6,
        max_work: page.len + 6,
    };
    assert!(decode_missing(page, MISSING, exact).is_ok());
    for cfg in [
        PageDecodeCfg {
            max_bytes: page.len - 1,
            ..exact
        },
        PageDecodeCfg {
            max_reasons: 5,
            ..exact
        },
        PageDecodeCfg {
            max_work: page.len + 5,
            ..exact
        },
    ] {
        assert_eq!(
            decode_missing(page, MISSING, cfg).unwrap_err().code,
            FailureCode::ResourceLimit
        );
    }
}
