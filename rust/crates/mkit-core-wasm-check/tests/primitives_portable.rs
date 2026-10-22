//! Execute portable primitives fixtures on wasm32, including 32-bit conversions.
#![allow(clippy::unwrap_used)]
use mkit_core::hash;
use mkit_primitives::{
    error::FailureCode,
    evidence::{PackSource, SourceBinding},
    limits::{IndexedProfile, VerifyLimits},
    pack_verify::{
        Acquisition, Request, Response,
        framing::{FramingDriver, FramingStep},
    },
};

#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::wasm_bindgen_test;

fn verify(bytes: &[u8]) -> Result<u32, FailureCode> {
    verify_run(bytes, false)
}

/// Limits matching what the frozen checkpoint fixtures were encoded under;
/// keep the original `work` ceiling so a default-profile change cannot
/// churn them.
fn frozen_limits() -> VerifyLimits {
    VerifyLimits {
        work: 1_000_000_000,
        ..VerifyLimits::indexed()
    }
}

fn verify_run(bytes: &[u8], restart: bool) -> Result<u32, FailureCode> {
    let pack_source = PackSource {
        id: hash::hash(bytes),
        len: u64::try_from(bytes.len()).unwrap(),
        binding: SourceBinding([1; 32]),
    };
    let repository = mkit_primitives::evidence::RepositoryId([9; 32]);
    let profile = IndexedProfile {
        pack_bytes: 5 << 30,
        decoded_bytes: 4 << 30,
        delta_depth: 50,
    };
    let limits = VerifyLimits::indexed();
    let mut driver = FramingDriver::new(pack_source, repository, profile, limits, 23)
        .map_err(|error| error.code)?;
    let mut saved_page = None;
    for _ in 0..100 {
        match driver.step().map_err(|error| error.code)? {
            FramingStep::Request(Request::Bytes {
                request,
                source,
                range,
            }) => {
                let begin = usize::try_from(range.offset).unwrap();
                let end = begin
                    .checked_add(usize::try_from(range.len).unwrap())
                    .unwrap();
                driver
                    .supply(Response::Bytes {
                        request,
                        source,
                        range,
                        value: Acquisition::Present(&bytes[begin..end]),
                    })
                    .map_err(|error| error.code)?;
            }
            FramingStep::Request(Request::EvidencePage { request, page }) => {
                let (commitment, bytes): &(mkit_primitives::evidence::PageCommitment, Vec<u8>) =
                    saved_page.as_ref().unwrap();
                assert_eq!(*commitment, page);
                driver
                    .supply(Response::EvidencePage {
                        request,
                        page,
                        value: Acquisition::Present(bytes),
                    })
                    .map_err(|error| error.code)?;
            }
            FramingStep::RetainEvidence(page) => {
                let saved = (restart && saved_page.is_none())
                    .then(|| (page.commitment, page.bytes.to_vec()));
                let commitment = page.commitment;
                driver
                    .acknowledge_retention(commitment)
                    .map_err(|error| error.code)?;
                if let Some(page) = saved {
                    saved_page = Some(page);
                    let snapshot = driver.checkpoint().map_err(|error| error.code)?;
                    let checkpoint = mkit_primitives::evidence::checkpoint::Checkpoint::from_bytes(
                        snapshot.bytes(),
                        limits,
                    )
                    .map_err(|error| error.code)?;
                    driver = FramingDriver::resume(
                        pack_source,
                        repository,
                        profile,
                        limits,
                        24,
                        &checkpoint,
                    )
                    .map_err(|error| error.code)?;
                }
            }
            FramingStep::Frame(_) | FramingStep::Progress => {}
            FramingStep::Complete(summary) => {
                assert!(
                    driver.usage().peak_resident_bytes <= VerifyLimits::indexed().resident_bytes
                );
                return Ok(summary.entries());
            }
            _ => panic!("unexpected portable transition"),
        }
    }
    panic!("bounded fixture exceeded transition ceiling")
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn raw_compressed_and_unsigned_length_fixtures_execute() {
    assert_eq!(
        verify(include_bytes!(
            "../../mkit-primitives/fixtures/framing/earlier-delta-base.bin"
        )),
        Ok(3)
    );
    assert_eq!(
        verify(include_bytes!(
            "../../../tests/golden/pack-v2/raw_4k_repeat.bin"
        )),
        Ok(1)
    );
    for bytes in [
        include_bytes!("../../mkit-primitives/fixtures/framing/earlier-delta-base.bin").as_slice(),
        include_bytes!("../../../tests/golden/pack-v2/raw_4k_repeat.bin").as_slice(),
    ] {
        assert_eq!(verify_run(bytes, true), verify(bytes));
    }
    for bytes in [
        include_bytes!("../../mkit-primitives/fixtures/framing/payload-high-bit.bin").as_slice(),
        include_bytes!("../../mkit-primitives/fixtures/framing/payload-u32-max.bin").as_slice(),
    ] {
        assert_eq!(verify(bytes), Err(FailureCode::PackfileTooLarge));
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn portable_checkpoint_resume_and_authenticated_absence_execute() {
    use mkit_primitives::{
        evidence::{
            ProfileId, RepositoryId, RulesetBinding,
            checkpoint::Checkpoint,
            pages::{EvidenceBinding, INDEXED_RULESET, PageView},
            proof::verify_path,
        },
        limits::EvidenceLimits,
    };
    let mut empty = b"MKIT\x01\0\0\0\0\0\0\0".to_vec();
    empty.extend_from_slice(&hash::hash(&empty));
    let source = PackSource {
        id: hash::hash(&empty),
        len: 44,
        binding: SourceBinding([7; 32]),
    };
    let repository = RepositoryId([9; 32]);
    let limits = frozen_limits();
    let snapshot = Checkpoint::from_bytes(
        include_bytes!("../../mkit-primitives/fixtures/evidence/checkpoint-header.bin"),
        limits,
    )
    .unwrap();
    let mut resumed = FramingDriver::resume(
        source,
        repository,
        IndexedProfile {
            pack_bytes: mkit_core::pack::MAX_TOTAL_PAYLOAD + 50_000_044,
            decoded_bytes: 4 << 30,
            delta_depth: 50,
        },
        limits,
        18,
        &snapshot,
    )
    .unwrap();
    for _ in 0..20 {
        match resumed.step().unwrap() {
            FramingStep::Request(Request::Bytes {
                request,
                source,
                range,
            }) => {
                let start = usize::try_from(range.offset).unwrap();
                let end = start + usize::try_from(range.len).unwrap();
                resumed
                    .supply(Response::Bytes {
                        request,
                        source,
                        range,
                        value: Acquisition::Present(&empty[start..end]),
                    })
                    .unwrap();
            }
            FramingStep::Progress => (),
            FramingStep::Complete(pack) => {
                assert_eq!(pack.entries(), 0);
                break;
            }
            _ => panic!("empty checkpoint resumed to unexpected transition"),
        }
    }
    assert!(matches!(resumed.step().unwrap(), FramingStep::Complete(_)));
    let binding = EvidenceBinding {
        source,
        repository,
        ruleset: RulesetBinding {
            ruleset: INDEXED_RULESET,
            profile: ProfileId::Indexed,
        },
    };
    let page = PageView::from_bytes(
        include_bytes!("../../mkit-primitives/fixtures/evidence/page-empty.bin"),
        binding,
        EvidenceLimits::indexed(),
    )
    .unwrap();
    let proof = include_bytes!("../../mkit-primitives/fixtures/evidence/proof-empty.bin");
    assert_eq!(
        verify_path(
            proof,
            binding,
            page.commitment(),
            [5; 32],
            EvidenceLimits::indexed()
        )
        .unwrap()
        .value(),
        None
    );
    assert!(
        verify_path(
            &proof[..proof.len() - 1],
            binding,
            page.commitment(),
            [5; 32],
            EvidenceLimits::indexed()
        )
        .is_err()
    );
}

// Execute the same frozen nonempty proof vectors as the native package.
#[path = "../../mkit-primitives/tests/evidence_portable.rs"]
mod evidence_portable;

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn portable_checkpoint_optional_states_preserve_bytes() {
    use mkit_primitives::evidence::checkpoint::Checkpoint;
    for bytes in [
        include_bytes!("../../mkit-primitives/fixtures/evidence/checkpoint-integrity-finished.bin")
            .as_slice(),
        include_bytes!(
            "../../mkit-primitives/fixtures/evidence/checkpoint-integrity-partial-trailer.bin"
        )
        .as_slice(),
        include_bytes!("../../mkit-primitives/fixtures/evidence/checkpoint-decode.bin").as_slice(),
        include_bytes!("../../mkit-primitives/fixtures/evidence/checkpoint-complete.bin")
            .as_slice(),
    ] {
        let checkpoint = Checkpoint::from_bytes(bytes, VerifyLimits::indexed()).unwrap();
        assert_eq!(checkpoint.bytes(), bytes);
    }
}
