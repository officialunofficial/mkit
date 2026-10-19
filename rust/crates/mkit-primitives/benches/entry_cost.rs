//! Batched host cost with a reused worker set and occurrence-page read-back.
//!
//! CSV rows report median wall/process CPU microseconds per entry and the
//! maximum outstanding batch and active workers in each measured run. Process
//! CPU includes user and system time in every thread. Pack generation, worker
//! startup, and optional host replay profiling sit outside measured samples.
use mkit_core::{
    hash::{self, Hash},
    object::{Blob, Commit, EntryMode, Identity, Object, Tree, TreeEntry},
    pack::{DecodeLimits, window},
    serialize::serialize,
    sign,
};
use mkit_primitives::{
    evidence::{
        PackSource, PageKind, ProfileId, RepositoryId, RulesetBinding, SourceBinding,
        pages::{EvidenceBinding, INDEXED_RULESET, PageView},
    },
    limits::{EvidenceLimits, IndexedProfile, VerifyLimits},
    pack_verify::{
        Acquisition, Request, Response, Step,
        verify::{
            ComputeConfig, ComputeDisposition, ComputeJob, ComputeOutput, VerifyDriver,
            records::OccurrenceRecord,
        },
    },
};
use std::{
    collections::HashMap,
    hint::black_box,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

// A window holds more than eight maximum-size raw entries. The same envelope
// applies to serial and every job count; it admits all eight jobs plus reader,
// decoder and evidence reservations without limiting the measured concurrency.
const WINDOW_BYTES: u64 = 16 << 20;
const RESIDENT_BYTES: u64 = 256 << 20;

#[derive(Default)]
struct Activity {
    running: AtomicUsize,
    peak: AtomicUsize,
}

struct Workers {
    inputs: Vec<mpsc::Sender<ComputeJob>>,
    outputs: mpsc::Receiver<ComputeOutput>,
    threads: Vec<thread::JoinHandle<()>>,
    activity: Arc<Activity>,
}

impl Workers {
    fn new(width: u8) -> Self {
        let (output, outputs) = mpsc::channel();
        let activity = Arc::new(Activity::default());
        let mut inputs = Vec::new();
        let mut threads = Vec::new();
        for _ in 0..width {
            let (input, jobs) = mpsc::channel::<ComputeJob>();
            let output = output.clone();
            let activity = Arc::clone(&activity);
            threads.push(thread::spawn(move || {
                while let Ok(job) = jobs.recv() {
                    let running = activity.running.fetch_add(1, Ordering::Relaxed) + 1;
                    activity.peak.fetch_max(running, Ordering::Relaxed);
                    let result = job.run();
                    activity.running.fetch_sub(1, Ordering::Relaxed);
                    output.send(result).expect("driver alive");
                }
            }));
            inputs.push(input);
        }
        Self {
            inputs,
            outputs,
            threads,
            activity,
        }
    }

    fn run(&self, jobs: &mut Vec<ComputeJob>) -> Vec<ComputeOutput> {
        let count = jobs.len();
        for (index, job) in jobs.drain(..).enumerate() {
            self.inputs[index].send(job).expect("worker alive");
        }
        // Match a collect-then-supply host: no output enters the driver until
        // every job in this batch has returned. Arrival order is immaterial.
        (0..count)
            .map(|_| self.outputs.recv().expect("output"))
            .collect()
    }
}

impl Drop for Workers {
    fn drop(&mut self) {
        self.inputs.clear();
        for worker in self.threads.drain(..) {
            worker.join().expect("worker");
        }
    }
}

#[cfg(unix)]
fn cpu() -> Duration {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    // SAFETY: getrusage initializes this valid output pointer on success.
    assert_eq!(
        unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) },
        0
    );
    // SAFETY: the successful call initialized the entire rusage value.
    let usage = unsafe { usage.assume_init() };
    let seconds = usage.ru_utime.tv_sec + usage.ru_stime.tv_sec;
    let micros = usage.ru_utime.tv_usec + usage.ru_stime.tv_usec;
    Duration::from_secs(u64::try_from(seconds).expect("cpu seconds"))
        + Duration::from_micros(u64::try_from(micros).expect("cpu micros"))
}
#[cfg(not(unix))]
fn cpu() -> Duration {
    panic!("process CPU measurement requires getrusage")
}

fn append(bytes: &mut Vec<u8>, canonical: &[u8]) {
    bytes.push(0);
    bytes.extend_from_slice(
        &u32::try_from(canonical.len())
            .expect("bounded")
            .to_le_bytes(),
    );
    bytes.extend_from_slice(canonical);
}

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
        append(&mut bytes, &canonical);
    }
    bytes.extend_from_slice(&hash::hash(&bytes));
    bytes
}

fn realistic_pack() -> Vec<u8> {
    let mut bytes = pack(3000, |_| 4096);
    bytes.truncate(bytes.len() - 32);
    bytes[8..12].copy_from_slice(&3004_u32.to_le_bytes());
    let mut entries = Vec::new();
    let mut offset = 12;
    for ordinal in 0..3000 {
        let len = u32::from_le_bytes(
            bytes[offset + 1..offset + 5]
                .try_into()
                .expect("raw frame length"),
        ) as usize;
        let canonical = &bytes[offset + 5..offset + 5 + len];
        entries.push(TreeEntry {
            name: format!("file-{ordinal:04}").into_bytes(),
            mode: EntryMode::Blob,
            object_hash: hash::hash(canonical),
        });
        offset += 5 + len;
    }
    let tree = Object::Tree(Tree { entries });
    let canonical = serialize(&tree).expect("tree");
    let tree_hash = mkit_core::object::id_from_object(&tree, &canonical);
    append(&mut bytes, &canonical);
    let key = sign::KeyPair::from_seed([42; 32]);
    let mut parents = Vec::new();
    for timestamp in 1..=3 {
        let mut commit = Commit::new_unannotated(
            tree_hash,
            parents,
            Identity::ed25519(key.public.0),
            key.public.0,
            b"bench".to_vec(),
            timestamp,
            [0; 64],
        );
        commit.signature = sign::sign_commit(&commit, &key).expect("signed commit").0;
        let object = Object::Commit(commit);
        let canonical = serialize(&object).expect("commit");
        parents = vec![mkit_core::object::id_from_object(&object, &canonical)];
        append(&mut bytes, &canonical);
    }
    bytes.extend_from_slice(&hash::hash(&bytes));
    bytes
}

fn compute_config(width: u8) -> ComputeConfig {
    let minimum = std::env::var("ENTRY_COST_MIN_BYTES")
        .ok()
        .map_or(64 << 10, |value| value.parse().expect("minimum job bytes"));
    ComputeConfig::new(width).with_min_job_bytes(minimum)
}

#[derive(Default)]
struct Report {
    batch: usize,
    active: usize,
}

fn new_driver(bytes: &[u8], width: u8) -> (VerifyDriver, EvidenceBinding) {
    let source = PackSource {
        id: hash::hash(bytes),
        len: bytes.len() as u64,
        binding: SourceBinding([4; 32]),
    };
    let limits = VerifyLimits {
        resident_bytes: RESIDENT_BYTES,
        acquisition_bytes: WINDOW_BYTES,
        ..VerifyLimits::indexed()
    };
    let mut driver = VerifyDriver::new(
        source,
        RepositoryId([9; 32]),
        IndexedProfile {
            pack_bytes: 2 << 30,
            decoded_bytes: 2 << 30,
            delta_depth: 50,
        },
        limits,
        1,
    )
    .expect("bounded pack");
    if width != 0 {
        driver = driver
            .with_compute(compute_config(width))
            .expect("finite width");
    }
    let binding = EvidenceBinding {
        source,
        repository: RepositoryId([9; 32]),
        ruleset: RulesetBinding {
            ruleset: INDEXED_RULESET,
            profile: ProfileId::Indexed,
        },
    };
    (driver, binding)
}

fn read_occurrences(
    pages: &HashMap<Hash, Vec<u8>>,
    occurrences: &[Hash],
    binding: EvidenceBinding,
) -> u64 {
    let mut records = 0;
    for digest in occurrences {
        let page = PageView::from_bytes(&pages[digest], binding, EvidenceLimits::indexed())
            .expect("occurrence page");
        if page.height() == 0 {
            for leaf in page.records().expect("leaf") {
                black_box(OccurrenceRecord::from_bytes(leaf.value).expect("occurrence"));
                records += 1;
            }
        }
    }
    records
}

fn host_replay(
    pages: &HashMap<Hash, Vec<u8>>,
    dispatched: u64,
    requested_pages: u64,
    report: &Report,
) {
    let copy = measure(31, 1, || {
        black_box(pages.values().cloned().collect::<Vec<_>>());
        Report::default()
    });
    let store = measure(31, 1, || {
        black_box(
            pages
                .iter()
                .map(|(id, bytes)| (*id, bytes.clone()))
                .collect::<HashMap<_, _>>(),
        );
        Report::default()
    });
    eprintln!(
        "host replay: jobs={dispatched}, batch={}, active={}, page_requests={requested_pages}, pages={}, copy_cpu_us={:.1}, copy_and_store_cpu_us={:.1}",
        report.batch,
        report.active,
        pages.len(),
        copy.cpu * 1e6,
        store.cpu * 1e6
    );
}

fn verify(bytes: &[u8], width: u8, workers: &Workers, profile: bool) -> Report {
    workers.activity.peak.store(0, Ordering::Relaxed);
    let (mut driver, binding) = new_driver(bytes, width);
    let mut pages: HashMap<Hash, Vec<u8>> = HashMap::new();
    let mut occurrences = Vec::new();
    let mut jobs = Vec::new();
    let mut report = Report::default();
    let mut dispatched = 0;
    let mut requested_pages = 0;
    loop {
        match driver.step().expect("verification") {
            Step::Request(Request::Compute { job }) => {
                dispatched += 1;
                jobs.push(driver.take_compute(job).expect("issued job"));
                report.batch = report.batch.max(jobs.len());
            }
            Step::Request(Request::Bytes {
                request,
                source,
                range,
            }) => {
                assert!(jobs.is_empty());
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
                assert!(jobs.is_empty());
                requested_pages += 1;
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
                if let std::collections::hash_map::Entry::Vacant(slot) =
                    pages.entry(commitment.digest)
                {
                    slot.insert(page.bytes.to_vec());
                    if commitment.kind == PageKind::Occurrences {
                        occurrences.push(commitment.digest);
                    }
                }
                driver.acknowledge_retention(commitment).expect("retained");
            }
            Step::ReleasePage(_) | Step::ProvisionalObject(_) => {}
            Step::Progress => {
                if !jobs.is_empty() {
                    for output in workers.run(&mut jobs) {
                        assert_eq!(
                            driver.supply_compute(output).expect("output"),
                            ComputeDisposition::Accepted
                        );
                    }
                }
            }
            Step::Complete(done) => {
                let records = read_occurrences(&pages, &occurrences, binding);
                assert_eq!(records, done.counts().entries);
                assert!(driver.usage().peak_resident_bytes <= RESIDENT_BYTES);
                let _ = black_box(done);
                report.active = workers.activity.peak.load(Ordering::Relaxed);
                if profile {
                    host_replay(&pages, dispatched, requested_pages, &report);
                }
                return report;
            }
            _ => panic!("unexpected acquisition"),
        }
    }
}

fn reader(bytes: &[u8]) -> Report {
    let mut reader = window::WindowReader::new_one_pass(
        bytes.len() as u64,
        WINDOW_BYTES,
        DecodeLimits::default(),
        Some(hash::hash(bytes)),
    )
    .expect("geometry");
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
                if let mkit_core::pack::PackEntry::Raw { bytes } = &entry {
                    let object = mkit_core::serialize::deserialize(bytes).expect("canonical");
                    black_box(mkit_core::object::id_from_object(&object, bytes));
                }
            }
            window::Step::Done(_) => return Report::default(),
            _ => panic!("unexpected step"),
        }
    }
}

struct Measurement {
    wall: f64,
    cpu: f64,
    batches: Vec<usize>,
    active: Vec<usize>,
}

fn measure(runs: u32, batch: u32, mut f: impl FnMut() -> Report) -> Measurement {
    black_box(f());
    let mut wall = Vec::new();
    let mut process = Vec::new();
    let mut batches = Vec::new();
    let mut active = Vec::new();
    for _ in 0..runs {
        let before = cpu();
        let start = Instant::now();
        let mut peak = Report::default();
        for _ in 0..batch {
            let report = black_box(f());
            peak.batch = peak.batch.max(report.batch);
            peak.active = peak.active.max(report.active);
        }
        wall.push(start.elapsed().as_secs_f64() / f64::from(batch));
        process.push(
            cpu()
                .checked_sub(before)
                .expect("monotonic process CPU")
                .as_secs_f64()
                / f64::from(batch),
        );
        batches.push(peak.batch);
        active.push(peak.active);
    }
    wall.sort_by(f64::total_cmp);
    process.sort_by(f64::total_cmp);
    Measurement {
        wall: wall[wall.len() / 2],
        cpu: process[process.len() / 2],
        batches,
        active,
    }
}

fn peaks(values: &[usize]) -> String {
    values
        .iter()
        .map(usize::to_string)
        .collect::<Vec<_>>()
        .join("|")
}

fn main() {
    let filter = std::env::args()
        .skip(1)
        .find(|arg| !arg.starts_with('-'))
        .unwrap_or_default();
    let workers = Workers::new(8);
    let names = [
        "1-entry",
        "24-entry",
        "96-blob",
        "3000-small",
        "3000-files",
        "150MiB",
    ];
    println!("pack,mode,wall_us/entry,cpu_us/entry,batch_peaks,worker_peaks");
    for name in names {
        if !filter.is_empty() && !name.contains(&filter) {
            continue;
        }
        let (count, bytes) = match name {
            "1-entry" => (1, pack(1, |_| 128)),
            "24-entry" => (24, pack(24, |_| 128)),
            "96-blob" => (96, pack(96, |i| 64 + (i as usize % 7) * 200)),
            "3000-small" => (3000, pack(3000, |i| 32 + (i as usize % 5) * 150)),
            "3000-files" => (3004, realistic_pack()),
            "150MiB" => (150, pack(150, |_| 1 << 20)),
            _ => unreachable!(),
        };
        let runs = std::env::var("ENTRY_COST_RUNS")
            .ok()
            .map_or(7, |value| value.parse().expect("runs"));
        assert!(runs > 0);
        let batch = (256_u32 / count).max(1);
        let per = f64::from(count) / 1e6;
        for width in [None, Some(0), Some(2), Some(4), Some(8)] {
            if let (Some(width), Ok(value)) = (width, std::env::var("ENTRY_COST_JOBS"))
                && width != value.parse::<u8>().expect("jobs")
            {
                continue;
            }
            let result = measure(runs, batch, || {
                width.map_or_else(
                    || reader(&bytes),
                    |width| verify(&bytes, width, &workers, false),
                )
            });
            let mode = width.map_or_else(|| "core".to_owned(), |width| width.to_string());
            println!(
                "{name},{mode},{:.3},{:.3},{},{}",
                result.wall / per,
                result.cpu / per,
                peaks(&result.batches),
                peaks(&result.active)
            );
            if let Some(width) = width
                && std::env::var_os("ENTRY_COST_HOST_PROFILE").is_some()
            {
                black_box(verify(&bytes, width, &workers, true));
            }
        }
    }
}
