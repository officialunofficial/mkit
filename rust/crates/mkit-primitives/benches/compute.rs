//! Caller-owned scoped-thread comparison over many small canonical blobs.
//! A standard-library timer keeps this illustrative host benchmark dependency-free;
//! elapsed time includes thread creation, evidence storage, and oracle checking.
use mkit_core::{
    hash,
    object::{Blob, Object},
    serialize::serialize,
};
use mkit_primitives::{
    evidence::{PackSource, RepositoryId, SourceBinding},
    limits::{IndexedProfile, VerifyLimits},
    pack_verify::{
        Acquisition, Request, Response, Step,
        verify::{ComputeConfig, ComputeDisposition, ComputeJob, VerifyDriver},
    },
};
use std::{collections::BTreeMap, hint::black_box, time::Instant};

fn pack(count: u32) -> Vec<u8> {
    let mut bytes = b"MKIT\x01\0\0\0".to_vec();
    bytes.extend_from_slice(&count.to_le_bytes());
    for ordinal in 0..count {
        let mut data = vec![0x41; 128];
        data[..4].copy_from_slice(&ordinal.to_le_bytes());
        let canonical = serialize(&Object::Blob(Blob { data })).expect("canonical blob");
        bytes.push(0);
        bytes.extend_from_slice(
            &u32::try_from(canonical.len())
                .expect("bounded canonical blob")
                .to_le_bytes(),
        );
        bytes.extend_from_slice(&canonical);
    }
    bytes.extend_from_slice(&hash::hash(&bytes));
    bytes
}

fn verify(bytes: &[u8], width: u8) -> (String, usize, u64, u64) {
    let source = PackSource {
        id: hash::hash(bytes),
        len: bytes.len() as u64,
        binding: SourceBinding([4; 32]),
    };
    let limits = VerifyLimits::indexed();
    let mut driver = VerifyDriver::new(
        source,
        RepositoryId([9; 32]),
        IndexedProfile {
            pack_bytes: 64 << 20,
            decoded_bytes: 64 << 20,
            delta_depth: 50,
        },
        limits,
        1,
    )
    .expect("bounded benchmark pack");
    if width != 0 {
        driver = driver
            .with_compute(ComputeConfig::new(width).with_min_job_bytes(0))
            .expect("finite width");
    }
    let mut pages: BTreeMap<hash::Hash, Vec<u8>> = BTreeMap::new();
    let mut jobs: Vec<ComputeJob> = Vec::new();
    let mut peak = 0;
    let mut trace = hash::Hasher::new();
    let mut steps = 0;
    loop {
        steps += 1;
        match driver.step().expect("benchmark verification") {
            Step::Request(Request::Compute { job }) => {
                jobs.push(driver.take_compute(job).expect("issued job"));
                peak = peak.max(jobs.len());
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
                            &bytes[usize::try_from(range.offset).expect("bounded pack offset")
                                ..usize::try_from(range.offset + range.len)
                                    .expect("bounded pack end")],
                        ),
                    })
                    .expect("bound pack range");
            }
            Step::Request(Request::EvidencePage { request, page }) => {
                driver
                    .supply(Response::EvidencePage {
                        request,
                        page,
                        value: Acquisition::Present(
                            pages.get(&page.digest).expect("retained page"),
                        ),
                    })
                    .expect("authenticated page");
            }
            Step::RetainEvidence(page) => {
                let commitment = page.commitment;
                trace.update(&commitment.digest);
                trace.update(page.bytes);
                pages.insert(commitment.digest, page.bytes.to_vec());
                driver
                    .acknowledge_retention(commitment)
                    .expect("retention acknowledged");
            }
            Step::ReleasePage(page) => {
                pages.remove(&page.digest);
            }
            Step::ProvisionalObject(fragment) => {
                trace.update(&fragment.ordinal.to_le_bytes());
                trace.update(&fragment.offset.to_le_bytes());
                trace.update(fragment.bytes);
            }
            Step::Progress => {
                if !jobs.is_empty() {
                    finish_jobs(&mut driver, &mut jobs);
                }
            }
            Step::Complete(pack) => {
                assert!(driver.usage().peak_resident_bytes <= limits.resident_bytes);
                return (
                    format!("{pack:?}:{:?}", trace.finalize()),
                    peak,
                    driver.usage().peak_resident_bytes,
                    steps,
                );
            }
            _ => panic!("unexpected benchmark acquisition"),
        }
    }
}

fn finish_jobs(driver: &mut VerifyDriver, jobs: &mut Vec<ComputeJob>) {
    let outputs = std::thread::scope(|scope| {
        let workers: Vec<_> = jobs
            .drain(..)
            .map(|job| scope.spawn(move || job.run()))
            .collect();
        workers
            .into_iter()
            .map(|worker| worker.join().expect("pure worker"))
            .collect::<Vec<_>>()
    });
    for output in outputs.into_iter().rev() {
        assert_eq!(
            driver.supply_compute(output).expect("worker output"),
            ComputeDisposition::Accepted
        );
    }
}

fn main() {
    let count = std::env::args()
        .nth(1)
        .and_then(|value| value.parse().ok())
        .unwrap_or(1024);
    assert!((2..=65_536).contains(&count));
    let bytes = pack(count);
    let mut baseline = None;
    for width in [0, 2, 3] {
        let start = Instant::now();
        let (artifact, peak, resident_bytes, steps) = black_box(verify(black_box(&bytes), width));
        let elapsed = start.elapsed();
        if let Some(expected) = &baseline {
            assert_eq!(
                &artifact, expected,
                "scheduling changed the artifact or event trace"
            );
            assert!(peak >= 2, "benchmark did not exercise concurrent jobs");
        } else {
            baseline = Some(artifact);
        }
        println!(
            "{}::verify/objects={count} caller_width={width} peak_jobs={peak} peak_resident_bytes={resident_bytes} steps={steps} elapsed_ns={}",
            module_path!(),
            elapsed.as_nanos()
        );
    }
}
