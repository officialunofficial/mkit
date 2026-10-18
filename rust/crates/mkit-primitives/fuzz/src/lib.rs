//! Stable seed replay shared by decoder and transition harnesses.
#![forbid(unsafe_code)]

#[path = "../../tests/support/fork.rs"]
pub mod fork;

mod framing_model;
mod proof_model;
mod verify_model;

/// Largest input admitted by a fuzz body before applying its own tighter limits.
pub const MAX_INPUT_BYTES: usize = 64 * 1024;

/// Exercises bounded framing and hostile reply identities through the public driver.
///
/// # Panics
/// Panics when a production decoder violates the fuzz target's invariant.
pub fn framing(data: &[u8]) {
    if data.len() <= MAX_INPUT_BYTES {
        framing_model::exercise(data);
    }
}

/// Exercises all-entry verification, hostile replies, and cold resume schedules.
///
/// Also replays the input through the fixed-size verify record decoders; a
/// successful parse must re-encode byte-for-byte.
///
/// # Panics
/// Panics when a production decoder violates the fuzz target's invariant.
pub fn verify(data: &[u8]) {
    use mkit_primitives::pack_verify::verify::records::{
        DependencyRecord, HeadRecord, ObjectRecord, OccurrenceRecord, OrdinalRecord,
    };
    if data.len() > MAX_INPUT_BYTES {
        return;
    }
    for decoded in [
        ObjectRecord::from_bytes(data).map(|record| record.to_bytes()),
        OccurrenceRecord::from_bytes(data).map(|record| record.to_bytes()),
        OrdinalRecord::from_bytes(data).map(|record| record.to_bytes()),
        HeadRecord::from_bytes(data).map(|record| record.to_bytes()),
        DependencyRecord::from_bytes(data).map(|record| record.to_bytes()),
    ]
    .into_iter()
    .flatten()
    {
        assert_eq!(decoded, data);
    }
    verify_model::exercise(data);
}

/// Exercises caller-driven compute schedules against the serial verification oracle.
///
/// # Panics
/// Panics if scheduling changes evidence, refusals, or ordered output events.
pub fn compute_schedule(data: &[u8]) {
    if data.len() <= MAX_INPUT_BYTES {
        verify_model::exercise_compute(data);
    }
}

/// Exercises the strict page decoder with finite shared operation limits.
///
/// # Panics
/// Panics when a production decoder violates the fuzz target's invariant.
pub fn page(data: &[u8]) {
    use mkit_primitives::{
        evidence::{
            PackSource, ProfileId, RepositoryId, RulesetBinding, SourceBinding,
            pages::{EvidenceBinding, INDEXED_RULESET, PageView},
        },
        limits::EvidenceLimits,
        pack_verify::framing::FrameRecord,
    };
    if data.len() > MAX_INPUT_BYTES {
        return;
    }
    // The occurrence value is an independently versioned page subdecoder.
    if let Ok(record) = FrameRecord::from_bytes(data) {
        assert!(record.offset().checked_add(record.length()).is_some());
    }
    let mut empty_pack = b"MKIT\x01\0\0\0\0\0\0\0".to_vec();
    empty_pack.extend_from_slice(&mkit_core::hash::hash(&empty_pack));
    let binding = EvidenceBinding {
        source: PackSource {
            id: mkit_core::hash::hash(&empty_pack),
            len: 44,
            binding: SourceBinding([7; 32]),
        },
        repository: RepositoryId([9; 32]),
        ruleset: RulesetBinding {
            ruleset: INDEXED_RULESET,
            profile: ProfileId::Indexed,
        },
    };
    let limits = EvidenceLimits {
        page_bytes: MAX_INPUT_BYTES as u64,
        value_bytes: 4096,
        proof_bytes: MAX_INPUT_BYTES as u64,
        proof_pages: 4,
        work: 2 << 20,
        allocated_bytes: MAX_INPUT_BYTES as u64,
    };
    if let Ok(page) = PageView::from_bytes(data, binding, limits) {
        assert_eq!(page.encoded(), data);
        assert!(page.items() <= 16);
        if let Ok(records) = page.records() {
            let mut count = 0;
            for record in records {
                let _ = FrameRecord::from_bytes(record.value);
                count += 1;
            }
            assert_eq!(count, usize::from(page.items()));
        }
    }
}

/// Authenticates arbitrary bounded paths against the pinned empty-tree root.
///
/// # Panics
/// Panics when a production decoder violates the fuzz target's invariant.
pub fn proof(data: &[u8]) {
    use mkit_primitives::{
        evidence::{pages::PageView, proof::verify_path},
        limits::EvidenceLimits,
    };
    if data.len() > MAX_INPUT_BYTES {
        return;
    }
    proof_model::exercise(data);
    let limits = EvidenceLimits {
        page_bytes: MAX_INPUT_BYTES as u64,
        value_bytes: 4096,
        proof_bytes: MAX_INPUT_BYTES as u64,
        proof_pages: 4,
        work: 2 << 20,
        allocated_bytes: 0,
    };
    let binding = seed_binding();
    let Ok(root) = PageView::from_bytes(
        include_bytes!("../../fixtures/evidence/page-empty.bin"),
        binding,
        limits,
    ) else {
        panic!("invalid pinned page");
    };
    if let Ok(answer) = verify_path(data, binding, root.commitment(), [5; 32], limits) {
        assert_eq!(answer.root(), root.commitment());
        assert_eq!(answer.binding(), binding);
        assert_eq!(answer.key(), [5; 32]);
        assert_eq!(answer.value(), None);
    }
}

/// Exercises checkpoint syntax and geometry with bounded input and work.
///
/// Both original checksums and recomputed checksums are tried so mutations can
/// reach field validation. No successful parse is treated as valid resumption.
///
/// # Panics
/// Panics when a production decoder violates the fuzz target's invariant.
pub fn checkpoint(data: &[u8]) {
    use mkit_primitives::{evidence::checkpoint::Checkpoint, limits::VerifyLimits};
    if data.len() > MAX_INPUT_BYTES {
        return;
    }
    let limits = VerifyLimits {
        checkpoint_bytes: MAX_INPUT_BYTES as u64,
        work: 2 << 20,
        ..VerifyLimits::indexed()
    };
    if let Ok(parsed) = Checkpoint::from_bytes(data, limits) {
        assert_eq!(parsed.bytes(), data);
    }
    if let Some(split) = data.len().checked_sub(32) {
        let mut resealed = data.to_vec();
        let checksum =
            mkit_core::hash::domain_digest(b"mkit-checkpoint-checksum:v1", &resealed[..split]);
        resealed[split..].copy_from_slice(&checksum);
        if let Ok(parsed) = Checkpoint::from_bytes(&resealed, limits) {
            assert_eq!(parsed.bytes(), resealed);
        }
    }
}

fn seed_binding() -> mkit_primitives::evidence::pages::EvidenceBinding {
    use mkit_primitives::evidence::{
        PackSource, ProfileId, RepositoryId, RulesetBinding, SourceBinding,
        pages::{EvidenceBinding, INDEXED_RULESET},
    };
    let mut empty = b"MKIT\x01\0\0\0\0\0\0\0".to_vec();
    empty.extend_from_slice(&mkit_core::hash::hash(&empty));
    EvidenceBinding {
        source: PackSource {
            id: mkit_core::hash::hash(&empty),
            len: 44,
            binding: SourceBinding([7; 32]),
        },
        repository: RepositoryId([9; 32]),
        ruleset: RulesetBinding {
            ruleset: INDEXED_RULESET,
            profile: ProfileId::Indexed,
        },
    }
}

/// Replay deterministic boundary seeds through the same body used by a fuzz target.
/// Bodies and their target registrations land alongside each owning decoder.
pub fn replay_seeds(mut body: impl FnMut(&[u8])) {
    body(&[]);
    let zeros = [0; 64];
    let high = [255; 64];
    for len in [1, 3, 4, 7, 8, 31, 32, 63, 64] {
        body(&zeros[..len]);
        body(&high[..len]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_decoder_bodies_replay_stable_seeds() {
        replay_seeds(framing);
        replay_seeds(verify);
        replay_seeds(page);
        replay_seeds(proof);
        replay_seeds(checkpoint);
        for bytes in [
            include_bytes!("../../fixtures/framing/earlier-delta-base.bin").as_slice(),
            include_bytes!("../../fixtures/framing/payload-u32-max.bin").as_slice(),
        ] {
            framing(bytes);
            verify(bytes);
        }
        page(include_bytes!("../../fixtures/evidence/page-empty.bin"));
        for bytes in [
            include_bytes!("../../fixtures/evidence/page-version.bin").as_slice(),
            include_bytes!("../../fixtures/evidence/page-wrong-source.bin").as_slice(),
            include_bytes!("../../fixtures/evidence/page-single-child.bin").as_slice(),
        ] {
            page(bytes);
        }
        page(include_bytes!(
            "../../fixtures/evidence/framing-record-empty.bin"
        ));
        page(include_bytes!(
            "../../fixtures/evidence/framing-record-invalid-type.bin"
        ));
        proof(include_bytes!("../../fixtures/evidence/proof-empty.bin"));
        for bytes in [
            include_bytes!("../../fixtures/evidence/proof-version.bin").as_slice(),
            include_bytes!("../../fixtures/evidence/proof-wrong-query.bin").as_slice(),
            include_bytes!("../../fixtures/evidence/proof-missing-page.bin").as_slice(),
            include_bytes!("../../fixtures/evidence/proof-multilevel-inclusion.bin").as_slice(),
            include_bytes!("../../fixtures/evidence/proof-multilevel-absence.bin").as_slice(),
        ] {
            proof(bytes);
        }
        for bytes in [
            include_bytes!("../../fixtures/evidence/checkpoint-header.bin").as_slice(),
            include_bytes!("../../fixtures/evidence/checkpoint-integrity-finished.bin").as_slice(),
            include_bytes!("../../fixtures/evidence/checkpoint-integrity-partial-trailer.bin")
                .as_slice(),
            include_bytes!("../../fixtures/evidence/checkpoint-decode.bin").as_slice(),
            include_bytes!("../../fixtures/evidence/checkpoint-complete.bin").as_slice(),
            include_bytes!("../../fixtures/evidence/checkpoint-version.bin").as_slice(),
            include_bytes!("../../fixtures/evidence/checkpoint-verify.bin").as_slice(),
            include_bytes!("../../fixtures/evidence/checkpoint-corrupt.bin").as_slice(),
        ] {
            checkpoint(bytes);
        }
    }

    #[test]
    fn checkpoint_vectors_preserve_bytes_and_refuse_version_and_corruption() {
        use mkit_primitives::{
            error::FailureCode, evidence::checkpoint::Checkpoint, limits::VerifyLimits,
        };
        let bytes = include_bytes!("../../fixtures/evidence/checkpoint-header.bin");
        assert_eq!(
            Checkpoint::from_bytes(bytes, VerifyLimits::indexed())
                .unwrap()
                .bytes(),
            bytes
        );
        for bytes in [
            include_bytes!("../../fixtures/evidence/checkpoint-version.bin").as_slice(),
            include_bytes!("../../fixtures/evidence/checkpoint-corrupt.bin").as_slice(),
        ] {
            assert_eq!(
                Checkpoint::from_bytes(bytes, VerifyLimits::indexed())
                    .unwrap_err()
                    .code,
                FailureCode::InvalidCheckpoint
            );
        }
    }

    #[test]
    fn frame_record_vectors_preserve_placement_and_refuse_reserved_type() {
        use mkit_primitives::{error::FailureCode, pack_verify::framing::FrameRecord};
        let record = FrameRecord::from_bytes(include_bytes!(
            "../../fixtures/evidence/framing-record-empty.bin"
        ))
        .unwrap();
        assert_eq!(record.offset(), 12);
        assert_eq!(record.length(), 5);
        assert_eq!(record.wire_type(), 0);
        assert_eq!(record.decoded_bytes(), 0);
        assert_eq!(record.previous(), [0; 32]);
        assert_eq!(
            FrameRecord::from_bytes(include_bytes!(
                "../../fixtures/evidence/framing-record-invalid-type.bin"
            ))
            .unwrap_err()
            .code,
            FailureCode::InvalidEvidence
        );
    }

    #[test]
    fn portable_page_vectors_pin_version_and_source_refusals() {
        use mkit_primitives::{
            error::FailureCode, evidence::pages::PageView, limits::EvidenceLimits,
        };
        let binding = seed_binding();
        let limits = EvidenceLimits::indexed();
        for (bytes, expected) in [
            (
                include_bytes!("../../fixtures/evidence/page-version.bin").as_slice(),
                FailureCode::UnsupportedEvidenceVersion,
            ),
            (
                include_bytes!("../../fixtures/evidence/page-wrong-source.bin").as_slice(),
                FailureCode::SourceChanged,
            ),
        ] {
            assert_eq!(
                PageView::from_bytes(bytes, binding, limits)
                    .unwrap_err()
                    .code,
                expected
            );
        }
        let branch = PageView::from_bytes(
            include_bytes!("../../fixtures/evidence/page-single-child.bin"),
            binding,
            limits,
        )
        .unwrap();
        assert_eq!(branch.height(), 1);
        assert_eq!(branch.items(), 1);
    }

    #[test]
    fn portable_proof_vectors_pin_failures_without_manufacturing_absence() {
        use mkit_primitives::{
            error::FailureCode,
            evidence::{pages::PageView, proof::verify_path},
            limits::EvidenceLimits,
        };
        let binding = seed_binding();
        let limits = EvidenceLimits::indexed();
        let root = PageView::from_bytes(
            include_bytes!("../../fixtures/evidence/page-empty.bin"),
            binding,
            limits,
        )
        .unwrap()
        .commitment();
        for (bytes, expected) in [
            (
                include_bytes!("../../fixtures/evidence/proof-version.bin").as_slice(),
                FailureCode::UnsupportedEvidenceVersion,
            ),
            (
                include_bytes!("../../fixtures/evidence/proof-wrong-query.bin").as_slice(),
                FailureCode::EvidenceMismatch,
            ),
        ] {
            assert_eq!(
                verify_path(bytes, binding, root, [5; 32], limits)
                    .unwrap_err()
                    .code,
                expected
            );
        }
        let branch = PageView::from_bytes(
            include_bytes!("../../fixtures/evidence/page-single-child.bin"),
            binding,
            limits,
        )
        .unwrap()
        .commitment();
        assert_eq!(
            verify_path(
                include_bytes!("../../fixtures/evidence/proof-missing-page.bin"),
                binding,
                branch,
                [5; 32],
                limits
            )
            .unwrap_err()
            .code,
            FailureCode::UnavailableInput
        );
    }

    #[test]
    fn stable_seed_replay_is_bounded_and_repeatable() {
        let mut first = Vec::new();
        replay_seeds(|seed| {
            assert!(seed.len() <= MAX_INPUT_BYTES);
            first.push(seed.to_vec());
        });
        let mut second = Vec::new();
        replay_seeds(|seed| second.push(seed.to_vec()));
        assert_eq!(first, second);
        assert!(first.iter().any(Vec::is_empty));
        assert!(first.iter().any(|seed| seed.len() == 32));
    }
}

/// Adversarial closure-machine transitions with an independent missing-ID oracle.
pub mod closure;
/// Authenticated closure page grammars and canonical reencoding.
pub mod closure_pages;
/// Adversarial pair-machine transitions with hostile answers and resume.
pub mod pair;
/// Local pair-checkpoint decoding under corrupted input.
pub mod pair_checkpoint;
// auth
pub mod auth_claims;
// acceptance evidence
pub mod acceptance;
#[cfg(test)]
mod acceptance_seed_tests;

/// Bounded fork progress and accepted-clearance transitions.
#[path = "../../tests/support/fork_advance.rs"]
pub mod fork_advance;
// decision
/// Bounded ref transitions checked against an independent CAS oracle.
pub mod ref_decisions;

/// Bounded ticketed advance, cleanup, and reservation settlement replay.
pub mod ticketed;
