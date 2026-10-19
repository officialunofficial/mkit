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
        verify::{ComputeConfig, ComputeDisposition, ComputeOutput, VerifyDriver},
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

/// Replays arbitrary packs and generated valid packs under caller compute schedules.
pub(super) fn exercise_compute(data: &[u8]) {
    let seed = data
        .iter()
        .take(8)
        .enumerate()
        .fold(0x9e37_79b9_u64, |seed, (index, byte)| {
            seed ^ (u64::from(*byte) << (index * 8))
        });
    compare_compute(data, seed);
    if let Some(split) = data.len().checked_sub(32) {
        let mut repaired = data.to_vec();
        let digest = hash::hash(&repaired[..split]);
        repaired[split..].copy_from_slice(&digest);
        compare_compute(&repaired, seed);
    }
    compare_compute(&small_blobs(data), seed);
}

fn compare_compute(bytes: &[u8], seed: u64) {
    let baseline = run(bytes, 0);
    for order in [0, 1, seed.max(2)] {
        assert_eq!(run_compute(bytes, 2, Some(order), &mut 0), baseline);
    }
}

fn small_blobs(seed: &[u8]) -> Vec<u8> {
    use mkit_core::{
        object::{Blob, Object},
        serialize::serialize,
    };
    let count = 8 + u32::from(seed.first().copied().unwrap_or(0)) % 8;
    let mut pack = b"MKIT\x01\0\0\0".to_vec();
    pack.extend_from_slice(&count.to_le_bytes());
    for ordinal in 0..count {
        let mut data = ordinal.to_le_bytes().to_vec();
        let start = (ordinal as usize * 7).min(seed.len());
        data.extend_from_slice(&seed[start..(start + 32).min(seed.len())]);
        let bytes = serialize(&Object::Blob(Blob { data })).expect("bounded blob");
        pack.push(0);
        pack.extend_from_slice(
            &u32::try_from(bytes.len())
                .expect("bounded generated blob")
                .to_le_bytes(),
        );
        pack.extend_from_slice(&bytes);
    }
    pack.extend_from_slice(&hash::hash(&pack));
    pack
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
    run_compute(bytes, schedule, None, &mut 0)
}

#[allow(clippy::too_many_lines)]
fn run_compute(
    bytes: &[u8],
    schedule: u8,
    mut compute_seed: Option<u64>,
    peak: &mut usize,
) -> Outcome {
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
    if compute_seed.is_some() {
        driver = driver
            .with_compute(ComputeConfig::new(3).with_min_job_bytes(0))
            .expect("finite configuration");
    }
    if compute_seed.is_some() {
        assert_eq!(
            driver
                .supply_compute(stale_output())
                .expect("stale run output"),
            ComputeDisposition::Stale
        );
    }
    let mut outputs: Vec<ComputeOutput> = Vec::new();
    for _ in 0..8 * super::MAX_INPUT_BYTES {
        let step = match driver.step() {
            Ok(step) => step,
            Err(error) => return Outcome::Refused(error.code, trace.finalize()),
        };
        match step {
            Step::Request(Request::Compute { job }) => {
                let Step::Request(Request::Compute { job: repeated }) =
                    driver.step().expect("stable compute request")
                else {
                    panic!("untaken compute request advanced")
                };
                assert_eq!(repeated, job);
                let owned = driver.take_compute(job).expect("issued compute descriptor");
                assert_eq!(owned.request(), job);
                assert_eq!(
                    driver
                        .take_compute(job)
                        .expect_err("job can be taken only once")
                        .code,
                    FailureCode::InvalidResponse
                );
                outputs.push(owned.run());
                *peak = (*peak).max(outputs.len());
                assert!(
                    outputs.len() <= 3,
                    "compute queue exceeded configured width"
                );
            }
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
                // Which pages the host holds, and when, depends on the
                // checkpoint cadence, so retention stays out of the trace.
                // A page released too early surfaces as an unavailable fetch.
                host.pages.push((commitment, bytes));
                driver
                    .acknowledge_retention(commitment)
                    .expect("bounded model invariant");
            }
            Step::ReleasePage(page) => {
                let position = host
                    .pages
                    .iter()
                    .position(|(commitment, _)| *commitment == page)
                    .expect("released a page the host never held");
                host.pages.swap_remove(position);
            }
            Step::Progress => {
                if !outputs.is_empty() {
                    let seed = compute_seed.as_mut().expect("compute mode issued a job");
                    let index = match *seed {
                        0 => 0,
                        1 => outputs.len() - 1,
                        _ => {
                            *seed ^= *seed << 13;
                            *seed ^= *seed >> 7;
                            *seed ^= *seed << 17;
                            usize::try_from(*seed % outputs.len() as u64)
                                .expect("bounded queue index")
                        }
                    };
                    assert_eq!(
                        driver
                            .supply_compute(outputs.remove(index))
                            .expect("bound output"),
                        ComputeDisposition::Accepted
                    );
                    continue;
                }
                if schedule == 3
                    && !restarted
                    && let Ok(snapshot) = driver.checkpoint()
                {
                    let checkpoint = mkit_primitives::evidence::checkpoint::Checkpoint::from_bytes(
                        snapshot.bytes(),
                        limits,
                    )
                    .expect("canonical checkpoint");
                    restarted = true;
                    driver = restart(source, profile, limits, &checkpoint);
                }
            }
            Step::Complete(pack) => {
                assert_eq!(pack.source(), source);
                assert!(driver.usage().peak_resident_bytes <= limits.resident_bytes);
                assert!(
                    schedule != 3 || restarted || pack.counts().entries == 0,
                    "cold-resume schedule never restarted"
                );
                assert_eq!(pack.pack_id(), source.id);
                assert_eq!(pack.len(), source.len);
                assert_eq!(pack.profile(), profile);
                assert_eq!(pack.limits(), limits);
                trace.update(
                    format!(
                        "{:?}",
                        (
                            pack.source(),
                            pack.counts(),
                            pack.version(),
                            pack.trailer(),
                            pack.ruleset(),
                            pack.profile(),
                            pack.limits(),
                            pack.object_set_root(),
                            pack.occurrences(),
                            pack.dependencies(),
                            pack.ordinals(),
                            pack.head_facts()
                        )
                    )
                    .as_bytes(),
                );
                return Outcome::Complete(trace.finalize());
            }
            _ => panic!("unexpected verify transition"),
        }
    }
    panic!("bounded verify did not terminate");
}

// A real library output from another generation must never satisfy this run.
fn stale_output() -> ComputeOutput {
    let bytes = small_blobs(b"retired generation");
    let source = PackSource {
        id: hash::hash(&bytes),
        len: bytes.len() as u64,
        binding: SourceBinding([4; 32]),
    };
    let mut driver = VerifyDriver::new(
        source,
        RepositoryId([9; 32]),
        IndexedProfile {
            pack_bytes: super::MAX_INPUT_BYTES as u64,
            decoded_bytes: 4 << 20,
            delta_depth: 50,
        },
        VerifyLimits::indexed(),
        16,
    )
    .expect("valid source")
    .with_compute(ComputeConfig::new(3).with_min_job_bytes(0))
    .expect("finite configuration");
    for _ in 0..4096 {
        match driver.step().expect("valid generation probe") {
            Step::Request(Request::Compute { job }) => {
                return driver.take_compute(job).expect("owned probe job").run();
            }
            Step::Request(Request::Bytes {
                request,
                source,
                range,
            }) => {
                driver
                    .supply(Response::Bytes {
                        request,
                        source,
                        range,
                        value: Acquisition::Present(
                            &bytes[usize::try_from(range.offset).expect("bounded probe offset")
                                ..usize::try_from(range.offset + range.len)
                                    .expect("bounded probe end")],
                        ),
                    })
                    .expect("bound probe bytes");
            }
            Step::RetainEvidence(page) => {
                let commitment = page.commitment;
                driver
                    .acknowledge_retention(commitment)
                    .expect("probe retention");
            }
            Step::Progress => {}
            _ => panic!("probe failed before compute"),
        }
    }
    panic!("probe did not issue compute");
}

fn restart(
    source: PackSource,
    profile: IndexedProfile,
    limits: VerifyLimits,
    checkpoint: &mkit_primitives::evidence::checkpoint::Checkpoint,
) -> VerifyDriver {
    VerifyDriver::resume(
        source,
        RepositoryId([9; 32]),
        profile,
        limits,
        18,
        checkpoint,
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
    fn caller_compute_replays_seeds_and_reorders_multiple_outputs() {
        super::super::replay_seeds(exercise_compute);
        let bytes = small_blobs(b"fixed caller scheduling seed");
        let baseline = run(&bytes, 0);
        assert!(matches!(baseline, Outcome::Complete(_)));
        for order in [0, 1, 0x51a7_f00d] {
            let mut peak = 0;
            assert_eq!(run_compute(&bytes, 2, Some(order), &mut peak), baseline);
            assert!(peak >= 2, "schedule did not exercise actual fan-out");
        }
        exercise_compute(include_bytes!(
            "../../fixtures/framing/earlier-delta-base.bin"
        ));
    }

    #[test]
    fn fixture_pack_completes_across_schedules() {
        let valid = include_bytes!("../../fixtures/framing/earlier-delta-base.bin");
        assert!(matches!(run(valid, 0), Outcome::Complete(_)));
        compare_schedules(valid);
    }
}
