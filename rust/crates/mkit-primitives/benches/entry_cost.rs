//! Per-entry cost of `VerifyDriver` against the core window reader.
//!
//! Prints microseconds per entry (median of several runs, single thread). The
//! fan-out rows run every issued compute job inline on the calling thread, so
//! they measure the CPU cost of the job machinery rather than thread wakeups.
//! The host retains every encoded page in a `HashMap` keyed by digest, answers
//! page requests from it, and reads the occurrence pages back after completion.
use mkit_core::{
    hash::{self, Hash},
    object::{Blob, Object},
    pack::{DecodeLimits, window},
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
use std::{collections::HashMap, hint::black_box, time::Instant};

fn pack(count: u32, size: impl Fn(u32) -> usize) -> Vec<u8> {
    let mut bytes = b"MKIT\x01\0\0\0".to_vec();
    bytes.extend_from_slice(&count.to_le_bytes());
    let mut state = 0x9E37_79B9_7F4A_7C15_u64;
    for ordinal in 0..count {
        let mut data = vec![0; size(ordinal).max(4)];
        for chunk in data.chunks_mut(8) {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let word = state.to_le_bytes();
            chunk.copy_from_slice(&word[..chunk.len()]);
        }
        data[..4].copy_from_slice(&ordinal.to_le_bytes());
        let canonical = serialize(&Object::Blob(Blob { data })).expect("canonical blob");
        bytes.push(0);
        bytes.extend_from_slice(
            &u32::try_from(canonical.len())
                .expect("bounded")
                .to_le_bytes(),
        );
        bytes.extend_from_slice(&canonical);
    }
    bytes.extend_from_slice(&hash::hash(&bytes));
    bytes
}

fn verify(bytes: &[u8], width: u8) -> u64 {
    let source = PackSource {
        id: hash::hash(bytes),
        len: bytes.len() as u64,
        binding: SourceBinding([4; 32]),
    };
    let mut driver = VerifyDriver::new(
        source,
        RepositoryId([9; 32]),
        IndexedProfile {
            pack_bytes: 2 << 30,
            decoded_bytes: 2 << 30,
            delta_depth: 50,
        },
        VerifyLimits::indexed(),
        1,
    )
    .expect("bounded pack");
    if width != 0 {
        driver = driver
            .with_compute(ComputeConfig { max_jobs: width })
            .expect("finite width");
    }
    let mut pages: HashMap<Hash, Vec<u8>> = HashMap::new();
    let mut jobs: Vec<ComputeJob> = Vec::new();
    loop {
        match driver.step().expect("verification") {
            Step::Request(Request::Compute { job }) => {
                jobs.push(driver.take_compute(job).expect("issued job"));
            }
            Step::Request(Request::Bytes {
                request,
                source,
                range,
            }) => {
                let start = usize::try_from(range.offset).expect("offset");
                let end = start + usize::try_from(range.len).expect("len");
                driver
                    .supply(Response::Bytes {
                        request,
                        source,
                        range,
                        value: Acquisition::Present(&bytes[start..end]),
                    })
                    .expect("range");
            }
            Step::Request(Request::EvidencePage { request, page }) => {
                driver
                    .supply(Response::EvidencePage {
                        request,
                        page,
                        value: Acquisition::Present(pages.get(&page.digest).expect("page")),
                    })
                    .expect("page");
            }
            Step::RetainEvidence(page) => {
                let commitment = page.commitment;
                pages.insert(commitment.digest, page.bytes.to_vec());
                driver.acknowledge_retention(commitment).expect("retained");
            }
            Step::ReleasePage(_) | Step::ProvisionalObject(_) => {}
            Step::Progress => {
                for job in std::mem::take(&mut jobs).into_iter().rev() {
                    let output = job.run();
                    assert_eq!(
                        driver.supply_compute(output).expect("output"),
                        ComputeDisposition::Accepted
                    );
                }
            }
            Step::Complete(done) => {
                let mut readback = 0;
                for page in pages.values() {
                    readback += page.len() as u64;
                }
                return black_box(done.counts().entries + readback);
            }
            _ => panic!("unexpected acquisition"),
        }
    }
}

fn reader(bytes: &[u8]) -> u32 {
    let mut reader = window::WindowReader::new_one_pass(
        bytes.len() as u64,
        1 << 20,
        DecodeLimits::default(),
        Some(hash::hash(bytes)),
    )
    .expect("geometry");
    let mut entries = 0;
    loop {
        match reader.step().expect("read") {
            window::Step::NeedWindow(request) => {
                let start = usize::try_from(request.offset).expect("offset");
                let end = start + usize::try_from(request.len).expect("len");
                reader
                    .feed(request.offset, &bytes[start..end])
                    .expect("feed");
            }
            window::Step::Entry(entry) => {
                // Per-entry work any all-entry verifier owes: canonical decode
                // and the type-dependent object id.
                if let mkit_core::pack::PackEntry::Raw { bytes } = &entry {
                    let object = mkit_core::serialize::deserialize(bytes).expect("canonical");
                    black_box(mkit_core::object::id_from_object(&object, bytes));
                }
                entries += 1;
            }
            window::Step::Done(_) => return entries,
            _ => panic!("unexpected step"),
        }
    }
}

fn median<T>(runs: u32, mut f: impl FnMut() -> T) -> f64 {
    let mut times: Vec<f64> = (0..runs)
        .map(|_| {
            let start = Instant::now();
            black_box(f());
            start.elapsed().as_secs_f64()
        })
        .collect();
    times.sort_by(f64::total_cmp);
    times[times.len() / 2]
}

fn main() {
    let filter = std::env::args()
        .skip(1)
        .find(|arg| !arg.starts_with('-'))
        .unwrap_or_default();
    if let Some(secs) = std::env::var("ENTRY_COST_LOOP")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
    {
        let bytes = pack(3000, |i| 32 + (i as usize % 5) * 150);
        let until = Instant::now() + std::time::Duration::from_secs(secs);
        while Instant::now() < until {
            black_box(verify(&bytes, 0));
        }
        return;
    }
    let packs: Vec<(&str, u32, Vec<u8>, u32)> = vec![
        ("1-entry", 1, pack(1, |_| 128), 200),
        ("24-entry", 24, pack(24, |_| 128), 100),
        ("96-blob", 96, pack(96, |i| 64 + (i as usize % 7) * 200), 50),
        (
            "3000-small",
            3000,
            pack(3000, |i| 32 + (i as usize % 5) * 150),
            15,
        ),
        ("150MiB", 150, pack(150, |_| 1 << 20), 5),
    ];
    println!(
        "{:<12} {:>9} {:>9} {:>9} {:>9}",
        "pack", "reader", "serial", "fanout4", "ratio"
    );
    for (name, count, bytes, runs) in &packs {
        if !filter.is_empty() && !name.contains(&filter) {
            continue;
        }
        let per = f64::from(*count) / 1e6;
        let core = median(*runs, || reader(bytes)) / per;
        let serial = median(*runs, || verify(bytes, 0)) / per;
        let fan = median(*runs, || verify(bytes, 4)) / per;
        println!(
            "{name:<12} {core:>9.2} {serial:>9.2} {fan:>9.2} {:>8.2}x",
            serial / core
        );
    }
}
