//! Bounded schedule oracle for the all-entry verify driver.
use mkit_core::hash::{self, Hash, Hasher};
use mkit_core::object::id_from_object;
use mkit_core::serialize::deserialize;
use mkit_primitives::{
    error::FailureCode,
    evidence::{PackSource, PageCommitment, RepositoryId, SourceBinding},
    limits::{IndexedProfile, VerifyLimits},
    pack_verify::{
        Acquisition, ByteRange, ByteSource, Request, RequestId, Response, Step,
        verify::VerifyDriver,
    },
};
use std::collections::BTreeMap;

#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Complete(Hash),
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

#[derive(Default)]
struct Host {
    fragments: BTreeMap<u64, Vec<u8>>,
    pages: Vec<(PageCommitment, Vec<u8>)>,
}

impl Host {
    fn canonical(&self, object: Hash) -> Option<Vec<u8>> {
        self.fragments
            .values()
            .find(|bytes| {
                deserialize(bytes).is_ok_and(|parsed| id_from_object(&parsed, bytes) == object)
            })
            .cloned()
    }
}

#[allow(clippy::too_many_lines)]
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
    let mut trace = Hasher::new();
    let mut host = Host::default();
    let mut restarted = false;
    let mut driver = match VerifyDriver::new(source, RepositoryId([9; 32]), profile, limits, 17) {
        Ok(driver) => driver,
        Err(error) => return Outcome::Refused(error.code, trace.finalize()),
    };
    for _ in 0..8 * super::MAX_INPUT_BYTES {
        let step = match driver.step() {
            Ok(step) => step,
            Err(error) => return Outcome::Refused(error.code, trace.finalize()),
        };
        match step {
            Step::Request(Request::Bytes {
                request,
                source,
                range,
            }) => {
                let owned;
                let input = match source {
                    ByteSource::Pack(_) => bytes
                        .get(
                            usize::try_from(range.offset).expect("bounded model invariant")
                                ..usize::try_from(range.offset + range.len)
                                    .expect("bounded model invariant"),
                        )
                        .expect("request escaped bound source"),
                    ByteSource::Canonical { object, len, .. } => {
                        owned = host.canonical(object);
                        match owned.as_deref() {
                            Some(found)
                                if found.len() as u64 == len && range.offset + range.len <= len =>
                            {
                                &found[usize::try_from(range.offset)
                                    .expect("bounded model invariant")
                                    ..usize::try_from(range.offset + range.len)
                                        .expect("bounded model invariant")]
                            }
                            _ => {
                                trace.update(&[0xa1]);
                                if driver
                                    .supply(Response::Bytes {
                                        request,
                                        source,
                                        range,
                                        value: Acquisition::Unavailable,
                                    })
                                    .is_err()
                                {
                                    // Unavailable canonical input is retryable;
                                    // keep the schedule stable by refusing here.
                                    return Outcome::Refused(
                                        FailureCode::UnavailableInput,
                                        trace.finalize(),
                                    );
                                }
                                continue;
                            }
                        }
                    }
                    _ => {
                        // Non-exhaustive source kinds must never hang the model.
                        if let Err(error) = driver.supply(Response::Bytes {
                            request,
                            source,
                            range,
                            value: Acquisition::Unavailable,
                        }) {
                            return Outcome::Refused(error.code, trace.finalize());
                        }
                        continue;
                    }
                };
                if schedule != 0 {
                    exercise_retries(&mut driver, request, source, range, input, schedule);
                }
                if let Err(error) = driver.supply(Response::Bytes {
                    request,
                    source,
                    range,
                    value: Acquisition::Present(input),
                }) {
                    return Outcome::Refused(error.code, trace.finalize());
                }
            }
            Step::Request(Request::ExternalObject { request, .. }) => {
                // Deterministic absence: never a member.
                if let Err(error) = driver.supply(Response::ExternalObject {
                    request,
                    value: Acquisition::Absent,
                }) {
                    return Outcome::Refused(error.code, trace.finalize());
                }
            }
            Step::Request(Request::EvidencePage { request, page }) => {
                let value = host
                    .pages
                    .iter()
                    .find(|(commitment, _)| *commitment == page)
                    .map_or(Acquisition::Unavailable, |(_, bytes)| {
                        Acquisition::Present(bytes.as_slice())
                    });
                if schedule != 0 {
                    let Step::Request(Request::EvidencePage {
                        request: repeated,
                        page: repeated_page,
                    }) = driver.step().expect("bounded model invariant")
                    else {
                        panic!("outstanding evidence page request advanced");
                    };
                    assert_eq!(repeated, request);
                    assert_eq!(repeated_page, page);
                    let mut wrong = page;
                    wrong.digest[0] ^= 1;
                    assert_eq!(
                        driver
                            .supply(Response::EvidencePage {
                                request,
                                page: wrong,
                                value: value.clone(),
                            })
                            .expect_err("wrong page commitment must refuse")
                            .code,
                        FailureCode::InvalidResponse
                    );
                }
                if let Err(error) = driver.supply(Response::EvidencePage {
                    request,
                    page,
                    value,
                }) {
                    return Outcome::Refused(error.code, trace.finalize());
                }
            }
            Step::ProvisionalObject(fragment) => {
                trace.update(&fragment.ordinal.to_le_bytes());
                trace.update(&fragment.offset.to_le_bytes());
                trace.update(fragment.bytes);
                host.fragments
                    .entry(fragment.ordinal)
                    .or_default()
                    .extend_from_slice(fragment.bytes);
            }
            Step::RetainEvidence(page) => {
                let commitment = page.commitment;
                let bytes = page.bytes.to_vec();
                if schedule != 0 {
                    exercise_retention(&mut driver, commitment);
                }
                host.pages.push((commitment, bytes));
                driver
                    .acknowledge_retention(commitment)
                    .expect("bounded model invariant");
            }
            Step::Progress => {
                if schedule == 3 && !restarted && driver.checkpoint().is_ok() {
                    restarted = true;
                    driver = restart(&mut driver, source, profile, limits);
                }
            }
            Step::Complete(pack) => {
                assert_eq!(pack.source(), source);
                assert!(driver.usage().peak_resident_bytes <= limits.resident_bytes);
                assert!(
                    schedule != 3 || restarted || pack.counts().entries == 0,
                    "cold-resume schedule never restarted"
                );
                trace.update(&pack.object_set_root());
                trace.update(&pack.counts().entries.to_le_bytes());
                trace.update(&pack.counts().delta_entries.to_le_bytes());
                return Outcome::Complete(trace.finalize());
            }
            _ => panic!("unexpected verify transition"),
        }
    }
    panic!("bounded verify did not terminate");
}

fn restart(
    driver: &mut VerifyDriver,
    source: PackSource,
    profile: IndexedProfile,
    limits: VerifyLimits,
) -> VerifyDriver {
    let snapshot = driver.checkpoint().expect("safe acknowledged boundary");
    let checkpoint =
        mkit_primitives::evidence::checkpoint::Checkpoint::from_bytes(snapshot.bytes(), limits)
            .expect("canonical checkpoint");
    VerifyDriver::resume(
        source,
        RepositoryId([9; 32]),
        profile,
        limits,
        18,
        &checkpoint,
    )
    .expect("bound cold resume")
}

fn exercise_retention(driver: &mut VerifyDriver, commitment: PageCommitment) {
    let Step::RetainEvidence(repeated) = driver.step().expect("bounded model invariant") else {
        panic!("unacknowledged evidence advanced");
    };
    assert_eq!(repeated.commitment, commitment);
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
    driver: &mut VerifyDriver,
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
    let Step::Request(repeated) = driver.step().expect("bounded model invariant") else {
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
                value,
            })
            .expect_err("invalid reply must refuse")
            .code,
        FailureCode::UnavailableInput
    );
    let Step::Request(repeated) = driver.step().expect("bounded model invariant") else {
        panic!("retryable acquisition advanced");
    };
    assert_eq!(repeated, expected);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_pack_completes_across_schedules() {
        let valid = include_bytes!("../../fixtures/framing/earlier-delta-base.bin");
        assert!(matches!(run(valid, 0), Outcome::Complete(_)));
        compare_schedules(valid);
    }
}
