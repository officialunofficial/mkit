//! Bounded schedule oracle with integrity-repaired entry-decoder inputs.
use mkit_core::hash::{self, Hash, Hasher};
use mkit_primitives::{
    error::FailureCode,
    evidence::{PackSource, PageCommitment, RepositoryId, SourceBinding},
    limits::{IndexedProfile, VerifyLimits},
    pack_verify::{
        Acquisition, ByteRange, ByteSource, Request, RequestId, Response,
        framing::{FramedEntry, FramedPack, FramingDriver, FramingStep},
    },
};

#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Complete(FramedPack, Hash),
    Refused(FailureCode, Hash),
}

pub(super) fn exercise(data: &[u8]) {
    compare_schedules(data);
    if let Some(split) = data.len().checked_sub(32) {
        let mut repaired = data.to_vec();
        let trailer = hash::hash(&repaired[..split]);
        repaired[split..].copy_from_slice(&trailer);
        compare_schedules(&repaired);
    }
    // Fixed outer geometry also reaches entry decoding from random input,
    // while the original and repaired inputs preserve hostile header paths.
    let payload = &data[..data.len().min(super::MAX_INPUT_BYTES - 49)];
    let mut generated = b"MKIT\x01\0\0\0\x01\0\0\0".to_vec();
    generated.push(data.first().copied().unwrap_or(0) & 3);
    generated.extend_from_slice(
        &u32::try_from(payload.len())
            .expect("bounded model invariant")
            .to_le_bytes(),
    );
    generated.extend_from_slice(payload);
    generated.extend_from_slice(&hash::hash(&generated));
    compare_schedules(&generated);
}

fn compare_schedules(bytes: &[u8]) {
    let baseline = run(bytes, 0);
    assert_eq!(run(bytes, 1), baseline);
    assert_eq!(run(bytes, 2), baseline);
    assert_eq!(run(bytes, 3), baseline);
}

fn run(bytes: &[u8], schedule: u8) -> Outcome {
    let limits = VerifyLimits {
        work: 64 << 20,
        ..VerifyLimits::indexed()
    };
    let source = PackSource {
        id: hash::hash(bytes),
        len: bytes.len() as u64,
        binding: SourceBinding([4; 32]),
    };
    let profile = IndexedProfile {
        pack_bytes: super::MAX_INPUT_BYTES as u64,
        decoded_bytes: 4 << 20,
        delta_depth: 50,
    };
    let mut frames = Hasher::new();
    let mut recovered_page = None;
    let mut driver = match FramingDriver::new(source, RepositoryId([9; 32]), profile, limits, 17) {
        Ok(driver) => driver,
        Err(error) => return Outcome::Refused(error.code, frames.finalize()),
    };
    // At most floor(64 KiB / 5) frames, each requiring a frame and retention
    // transition, plus bounded acquisitions and completion transitions.
    for _ in 0..super::MAX_INPUT_BYTES {
        let step = match driver.step() {
            Ok(step) => step,
            Err(error) => return Outcome::Refused(error.code, frames.finalize()),
        };
        match step {
            FramingStep::Request(Request::Bytes {
                request,
                source,
                range,
            }) => {
                let begin = usize::try_from(range.offset).expect("bounded model invariant");
                let end = begin
                    .checked_add(usize::try_from(range.len).expect("bounded model invariant"))
                    .expect("bounded model invariant");
                let input = bytes.get(begin..end).expect("request escaped bound source");
                if schedule != 0 {
                    exercise_retries(&mut driver, request, source, range, input, schedule);
                }
                if let Err(error) = driver.supply(Response::Bytes {
                    request,
                    source,
                    range,
                    value: Acquisition::Present(input),
                }) {
                    return Outcome::Refused(error.code, frames.finalize());
                }
            }
            FramingStep::Frame(frame) => record_frame(&mut frames, &frame),
            FramingStep::Request(Request::EvidencePage { request, page }) => {
                let (saved, bytes): &(PageCommitment, Vec<u8>) = recovered_page
                    .as_ref()
                    .expect("resume requests only the acknowledged first page");
                assert_eq!(*saved, page);
                driver
                    .supply(Response::EvidencePage {
                        request,
                        page,
                        value: Acquisition::Present(bytes),
                    })
                    .expect("authenticated resume page");
            }
            FramingStep::RetainEvidence(page) => {
                let should_restart = schedule == 3 && recovered_page.is_none();
                let saved = should_restart.then(|| page.bytes.to_vec());
                let commitment = page.commitment;
                let digest = hash::hash(page.bytes);
                if schedule != 0 {
                    exercise_retention(&mut driver, commitment, digest);
                }
                driver
                    .acknowledge_retention(commitment)
                    .expect("bounded model invariant");
                if let Some(bytes) = saved {
                    recovered_page = Some((commitment, bytes));
                    driver = restart(&mut driver, source, profile, limits);
                }
            }
            FramingStep::Complete(pack) => {
                assert_eq!(pack.source(), source);
                assert!(driver.usage().peak_resident_bytes <= limits.resident_bytes);
                return Outcome::Complete(pack, frames.finalize());
            }
            FramingStep::Progress => {}
            _ => panic!("unexpected framing request or transition"),
        }
    }
    panic!("bounded framing did not terminate");
}

fn restart(
    driver: &mut FramingDriver,
    source: PackSource,
    profile: IndexedProfile,
    limits: VerifyLimits,
) -> FramingDriver {
    let snapshot = driver.checkpoint().expect("safe acknowledged entry");
    let checkpoint =
        mkit_primitives::evidence::checkpoint::Checkpoint::from_bytes(snapshot.bytes(), limits)
            .expect("canonical checkpoint");
    FramingDriver::resume(
        source,
        RepositoryId([9; 32]),
        profile,
        limits,
        18,
        &checkpoint,
    )
    .expect("bound cold resume")
}

fn record_frame(frames: &mut Hasher, frame: &mkit_primitives::pack_verify::framing::Frame<'_>) {
    frames.update(&frame.ordinal.to_le_bytes());
    match frame.entry {
        FramedEntry::Raw(raw) => {
            frames.update(&[0]);
            frames.update(raw);
        }
        FramedEntry::Delta { base, stream } => {
            frames.update(&[1]);
            frames.update(&base);
            frames.update(stream);
        }
        ref other => panic!("unmodelled framed entry: {other:?}"),
    }
}

fn exercise_retention(driver: &mut FramingDriver, commitment: PageCommitment, digest: Hash) {
    let FramingStep::RetainEvidence(repeated) = driver.step().expect("bounded model invariant")
    else {
        panic!("unacknowledged evidence advanced");
    };
    assert_eq!(repeated.commitment, commitment);
    assert_eq!(hash::hash(repeated.bytes), digest);
    let mut wrong = commitment;
    wrong.digest[0] ^= 1;
    assert_eq!(
        driver
            .acknowledge_retention(wrong)
            .expect_err("invalid reply must refuse")
            .code,
        FailureCode::InvalidResponse
    );
}

fn exercise_retries(
    driver: &mut FramingDriver,
    request: RequestId,
    source: ByteSource,
    range: ByteRange,
    input: &[u8],
    schedule: u8,
) {
    let expected = Request::Bytes {
        request,
        source,
        range,
    };
    let FramingStep::Request(repeated) = driver.step().expect("bounded model invariant") else {
        panic!("outstanding request advanced");
    };
    assert_eq!(repeated, expected);
    let stale = RequestId {
        generation: request.generation.wrapping_sub(1),
        ..request
    };
    let wrong_sequence = RequestId {
        sequence: request.sequence.wrapping_add(1),
        ..request
    };
    let wrong_range = ByteRange {
        offset: range.offset.wrapping_add(1),
        ..range
    };
    for (request, range) in [
        (stale, range),
        (wrong_sequence, range),
        (request, wrong_range),
    ] {
        assert_eq!(
            driver
                .supply(Response::Bytes {
                    request,
                    source,
                    range,
                    value: Acquisition::Present(input),
                })
                .expect_err("invalid reply must refuse")
                .code,
            FailureCode::InvalidResponse
        );
    }
    let value = if schedule == 1 {
        Acquisition::Absent
    } else {
        Acquisition::Unavailable
    };
    assert_eq!(
        driver
            .supply(Response::Bytes {
                request,
                source,
                range,
                value
            })
            .expect_err("invalid reply must refuse")
            .code,
        FailureCode::UnavailableInput
    );
    let FramingStep::Request(repeated) = driver.step().expect("bounded model invariant") else {
        panic!("retryable acquisition advanced");
    };
    assert_eq!(repeated, expected);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repaired_mutations_reach_entry_decoder_and_schedules_preserve_outcome() {
        let mut bytes = include_bytes!("../../fixtures/framing/earlier-delta-base.bin").to_vec();
        bytes[12] = 255;
        assert!(matches!(
            run(&bytes, 0),
            Outcome::Refused(FailureCode::PackfileCorrupted, _)
        ));
        let split = bytes.len() - 32;
        let trailer = hash::hash(&bytes[..split]);
        bytes[split..].copy_from_slice(&trailer);
        assert!(matches!(
            run(&bytes, 0),
            Outcome::Refused(FailureCode::InvalidEntryType, _)
        ));
        compare_schedules(&bytes);
        let valid = include_bytes!("../../fixtures/framing/earlier-delta-base.bin");
        assert!(matches!(run(valid, 0), Outcome::Complete(_, _)));
        compare_schedules(valid);
    }
}
