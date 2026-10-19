//! Targeted capability and backend vectors, also run in raw/both configurations.
#![allow(clippy::unwrap_used)]
use mkit_core::{hash, pack::MAX_TOTAL_PAYLOAD};
use mkit_primitives::{
    error::FailureCode,
    evidence::{PackSource, SourceBinding},
    limits::{IndexedProfile, VerifyLimits},
    pack_verify::{
        Acquisition, Request, Response,
        framing::{FramedEntry, FramingDriver, FramingStep},
    },
};

fn run(bytes: &[u8]) -> Result<Vec<Vec<u8>>, FailureCode> {
    let mut driver = FramingDriver::new(
        PackSource {
            id: hash::hash(bytes),
            len: u64::try_from(bytes.len()).unwrap(),
            binding: SourceBinding([1; 32]),
        },
        mkit_primitives::evidence::RepositoryId([9; 32]),
        IndexedProfile {
            pack_bytes: MAX_TOTAL_PAYLOAD + 50_000_044,
            decoded_bytes: 4 << 30,
            delta_depth: 50,
        },
        VerifyLimits::indexed(),
        1,
    )
    .map_err(|error| error.code)?;
    let mut output = Vec::new();
    loop {
        match driver.step().map_err(|error| error.code)? {
            FramingStep::Request(Request::Bytes {
                request,
                source,
                range,
            }) => {
                let begin = usize::try_from(range.offset).unwrap();
                let end = begin + usize::try_from(range.len).unwrap();
                driver
                    .supply(Response::Bytes {
                        request,
                        source,
                        range,
                        value: Acquisition::Present(&bytes[begin..end]),
                    })
                    .map_err(|error| error.code)?;
            }
            FramingStep::Frame(frame) => output.push(match frame.entry {
                FramedEntry::Raw(bytes) => bytes.to_vec(),
                FramedEntry::Delta { stream, .. } => stream.to_vec(),
                other => panic!("unmodelled framed entry: {other:?}"),
            }),
            FramingStep::RetainEvidence(page) => {
                let commitment = page.commitment;
                driver
                    .acknowledge_retention(commitment)
                    .map_err(|error| error.code)?;
            }
            FramingStep::Progress => {}
            FramingStep::Complete(summary) => {
                assert_eq!(summary.entries() as usize, output.len());
                assert!(
                    driver.usage().peak_resident_bytes <= VerifyLimits::indexed().resident_bytes
                );
                return Ok(output);
            }
            _ => panic!("unexpected framing acquisition"),
        }
    }
}

#[test]
fn raw_capability_and_unsigned_lengths_are_feature_independent() {
    assert_eq!(
        run(include_bytes!("../fixtures/framing/earlier-delta-base.bin"))
            .unwrap()
            .len(),
        3
    );
    for bytes in [
        include_bytes!("../fixtures/framing/payload-high-bit.bin").as_slice(),
        include_bytes!("../fixtures/framing/payload-u32-max.bin").as_slice(),
    ] {
        assert_eq!(run(bytes), Err(FailureCode::PackfileTooLarge));
    }
}

#[test]
fn compressed_fixture_matches_the_selected_decoder_capability() {
    let bytes = include_bytes!("../../../tests/golden/pack-v2/raw_4k_repeat.bin");
    let decoded = run(bytes);
    if cfg!(any(feature = "pack-ruzstd", feature = "pack-zstd")) {
        assert_eq!(decoded.unwrap().len(), 1);
    } else {
        assert_eq!(decoded, Err(FailureCode::UnsupportedCapability));
    }
}
