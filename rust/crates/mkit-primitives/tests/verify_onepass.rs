//! Public-host regressions for single-pass integrity and durable entry boundaries.
#![allow(clippy::unwrap_used)]
use mkit_core::{
    delta, hash,
    object::{Blob, Commit, Identity, Object, id_from_object},
    pack::PackWriter,
    serialize::serialize,
    sign,
};
use mkit_primitives::{
    error::{Failure, FailureCode},
    evidence::{PackSource, PageCommitment, RepositoryId, SourceBinding, checkpoint::Checkpoint},
    limits::{IndexedProfile, VerifyLimits},
    pack_verify::{
        Acquisition, ByteSource, Request, Response, Step,
        verify::{ComputeConfig, ComputeDisposition, ComputeJob, VerifyDriver},
    },
};
use std::collections::BTreeMap;

const REPOSITORY: RepositoryId = RepositoryId([9; 32]);
fn profile() -> IndexedProfile {
    IndexedProfile {
        pack_bytes: 2 << 30,
        decoded_bytes: 2 << 30,
        delta_depth: 50,
    }
}
fn limits(window: u64) -> VerifyLimits {
    VerifyLimits {
        acquisition_bytes: window,
        resident_bytes: 48 << 20,
        ..VerifyLimits::indexed()
    }
}
fn source(pack: &[u8]) -> PackSource {
    PackSource {
        id: hash::hash(pack),
        len: u64::try_from(pack.len()).unwrap(),
        binding: SourceBinding([7; 32]),
    }
}
fn blob(data: Vec<u8>) -> ([u8; 32], Vec<u8>) {
    let object = Object::Blob(Blob { data });
    let bytes = serialize(&object).unwrap();
    (id_from_object(&object, &bytes), bytes)
}
fn raw_pack(count: usize, size: usize) -> Vec<u8> {
    let mut writer = PackWriter::new_raw_only();
    for index in 0..count {
        let (id, bytes) = blob(vec![u8::try_from(index).unwrap(); size]);
        writer.push_raw(id, &bytes).unwrap();
    }
    writer.finish().unwrap()
}
#[derive(Clone, Copy, Debug)]
enum Schedule {
    Serial,
    Fifo,
    Lifo,
    Seeded(u64),
}
const SCHEDULES: [Schedule; 5] = [
    Schedule::Serial,
    Schedule::Fifo,
    Schedule::Lifo,
    Schedule::Seeded(7),
    Schedule::Seeded(31),
];
impl Schedule {
    fn completion_index(self, len: usize, random: &mut u64) -> usize {
        match self {
            Self::Lifo => len - 1,
            Self::Seeded(_) => {
                *random = random
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1);
                usize::try_from(*random % u64::try_from(len).unwrap()).unwrap()
            }
            _ => 0,
        }
    }
}
fn configured(
    pack: &[u8],
    budget: VerifyLimits,
    schedule: Schedule,
    checkpoint: Option<&Checkpoint>,
) -> VerifyDriver {
    let driver = match checkpoint {
        Some(cp) => VerifyDriver::resume(source(pack), REPOSITORY, profile(), budget, 18, cp),
        None => VerifyDriver::new(source(pack), REPOSITORY, profile(), budget, 17),
    }
    .unwrap();
    match schedule {
        Schedule::Serial => driver,
        _ => driver
            .with_compute(ComputeConfig::new(3).with_min_job_bytes(0))
            .unwrap(),
    }
}
#[derive(Default, Clone)]
struct Host {
    pages: Vec<(PageCommitment, Vec<u8>)>,
    fragments: BTreeMap<u64, Vec<u8>>,
    ranges: Vec<(u64, u64)>,
    fragment_count: u64,
}
impl Host {
    fn serve(
        &mut self,
        driver: &mut VerifyDriver,
        request: &Request,
        pack: &[u8],
    ) -> Result<(), Failure> {
        match *request {
            Request::Bytes {
                request,
                source,
                range,
            } => {
                let owned;
                let bytes = match source {
                    ByteSource::Pack(_) => {
                        self.ranges.push((range.offset, range.len));
                        &pack[usize::try_from(range.offset).unwrap()
                            ..usize::try_from(range.offset + range.len).unwrap()]
                    }
                    ByteSource::Canonical { object, .. } => {
                        owned = self
                            .fragments
                            .values()
                            .find(|bytes| {
                                mkit_core::serialize::deserialize(bytes)
                                    .is_ok_and(|parsed| id_from_object(&parsed, bytes) == object)
                            })
                            .cloned();
                        let Some(owned) = owned.as_ref() else {
                            return driver.supply(Response::Bytes {
                                request,
                                source,
                                range,
                                value: Acquisition::Unavailable,
                            });
                        };
                        &owned[usize::try_from(range.offset).unwrap()
                            ..usize::try_from(range.offset + range.len).unwrap()]
                    }
                    _ => panic!("unexpected byte source"),
                };
                driver.supply(Response::Bytes {
                    request,
                    source,
                    range,
                    value: Acquisition::Present(bytes),
                })
            }
            Request::ExternalObject { request, .. } => driver.supply(Response::ExternalObject {
                request,
                value: Acquisition::Absent,
            }),
            Request::EvidencePage { request, page } => {
                let bytes = &self
                    .pages
                    .iter()
                    .find(|(known, _)| *known == page)
                    .unwrap()
                    .1;
                driver.supply(Response::EvidencePage {
                    request,
                    page,
                    value: Acquisition::Present(bytes),
                })
            }
            Request::Compute { .. } => panic!("compute jobs are handled by the scheduler"),
            _ => panic!("unexpected request"),
        }
    }
}
#[derive(Clone)]
struct Snapshot {
    checkpoint: Vec<u8>,
    host: Host,
    entries: u64,
    prefix: u64,
}
fn run(
    pack: &[u8],
    budget: VerifyLimits,
    schedule: Schedule,
    snapshot: Option<&Snapshot>,
    retain_fragments: bool,
    checkpoints: bool,
) -> (Result<u64, Failure>, Host, Vec<Snapshot>, u64) {
    let cp = snapshot.map(|snapshot| Checkpoint::from_bytes(&snapshot.checkpoint, budget).unwrap());
    let mut driver = configured(pack, budget, schedule, cp.as_ref());
    let mut host = snapshot.map_or_else(Host::default, |snapshot| snapshot.host.clone());
    host.ranges.clear();
    let mut jobs = Vec::<ComputeJob>::new();
    let mut random = if let Schedule::Seeded(seed) = schedule {
        seed
    } else {
        0
    };
    let mut snapshots = Vec::new();
    let mut last_boundary = snapshot.map_or(0, |snapshot| snapshot.entries);
    let mut peak = 0;
    for _ in 0..1_000_000 {
        let outcome = match driver.step() {
            Err(error) => return (Err(error), host, snapshots, peak),
            Ok(step) => step,
        };
        let supplied = match outcome {
            Step::Request(Request::Compute { job }) => {
                jobs.push(driver.take_compute(job).unwrap());
                Ok(())
            }
            Step::Request(request) => {
                assert!(jobs.is_empty());
                host.serve(&mut driver, &request, pack)
            }
            Step::Progress => {
                while !jobs.is_empty() {
                    let index = schedule.completion_index(jobs.len(), &mut random);
                    assert_eq!(
                        driver.supply_compute(jobs.remove(index).run()).unwrap(),
                        ComputeDisposition::Accepted
                    );
                }
                Ok(())
            }
            Step::ProvisionalObject(fragment) => {
                host.fragment_count = host.fragment_count.max(fragment.ordinal + 1);
                if retain_fragments {
                    host.fragments
                        .entry(fragment.ordinal)
                        .or_default()
                        .extend_from_slice(fragment.bytes);
                }
                Ok(())
            }
            Step::RetainEvidence(page) => {
                let commitment = page.commitment;
                host.pages.push((commitment, page.bytes.to_vec()));
                driver.acknowledge_retention(commitment)
            }
            Step::ReleasePage(_) => Ok(()),
            Step::Complete(verified) => {
                return (Ok(verified.counts().entries), host, snapshots, peak);
            }
            _ => panic!("unexpected step"),
        };
        if let Err(error) = supplied {
            return (Err(error), host, snapshots, peak);
        }
        peak = peak.max(driver.usage().peak_resident_bytes);
        assert!(peak <= budget.resident_bytes);
        if checkpoints
            && host.fragment_count > last_boundary
            && let Ok(checkpoint) = driver.checkpoint()
        {
            last_boundary = host.fragment_count;
            let mut prefix = 12_usize;
            for _ in 0..last_boundary {
                let len = u32::from_le_bytes(pack[prefix + 1..prefix + 5].try_into().unwrap());
                prefix += 5 + usize::try_from(len).unwrap();
            }
            let prefix = u64::try_from(prefix).unwrap();
            snapshots.push(Snapshot {
                checkpoint: checkpoint.bytes().to_vec(),
                host: host.clone(),
                entries: last_boundary,
                prefix,
            });
        }
    }
    panic!("driver did not terminate")
}
fn acquisition_case(count: usize, window: u64) {
    let pack = raw_pack(count, 768 << 10);
    if count == 96 {
        assert_eq!(pack.len(), 75_498_956);
    }
    let (outcome, host, _, peak) = run(&pack, limits(window), Schedule::Serial, None, false, false);
    assert_eq!(outcome.unwrap(), u64::try_from(count).unwrap());
    let bytes: u64 = host.ranges.iter().map(|(_, len)| len).sum();
    assert_eq!(bytes, u64::try_from(pack.len()).unwrap());
    println!(
        "entries={count} acquisition={window} pack_bytes={} requests={} acquired_bytes={bytes} peak_resident={peak}",
        pack.len(),
        host.ranges.len()
    );
}
#[test]
fn acquisition_table_75mb_64k() {
    acquisition_case(96, 64 << 10);
}
#[test]
fn acquisition_table_75mb_1m() {
    acquisition_case(96, 1 << 20);
}
#[test]
fn acquisition_table_75mb_16m() {
    acquisition_case(96, 16 << 20);
}
#[test]
fn acquisition_table_150mb_16m() {
    acquisition_case(192, 16 << 20);
}
#[test]
fn every_raw_entry_boundary_resumes_without_prefix_acquisition() {
    let pack = raw_pack(24, 8192);
    let budget = limits(64 << 10);
    let (outcome, _, snapshots, _) = run(&pack, budget, Schedule::Serial, None, false, true);
    assert_eq!(outcome.unwrap(), 24);
    assert_eq!(snapshots.len(), 24);
    for snapshot in &snapshots {
        for schedule in SCHEDULES {
            let (outcome, host, _, _) = run(&pack, budget, schedule, Some(snapshot), false, false);
            assert_eq!(outcome.unwrap(), 24);
            let resumed_bytes: u64 = host.ranges.iter().map(|(_, len)| len).sum();
            assert_eq!(
                resumed_bytes,
                u64::try_from(pack.len()).unwrap() - snapshot.prefix
            );
            assert!(
                host.ranges
                    .iter()
                    .all(|(offset, _)| *offset >= snapshot.prefix),
                "entry {} reread prefix {}: {:?}",
                snapshot.entries,
                snapshot.prefix,
                host.ranges
            );
        }
    }
}
fn fault_pack(kind: usize) -> Vec<u8> {
    let mut writer = if kind < 2 {
        PackWriter::new()
    } else {
        PackWriter::new_raw_only()
    };
    for index in 0..3 {
        let (id, bytes) = blob(vec![index; 64]);
        writer.push_raw(id, &bytes).unwrap();
    }
    match kind {
        0 | 1 => {
            let (base_id, base) = blob(b"absent base".to_vec());
            let (_, target) = blob(b"target".to_vec());
            writer
                .push_delta(&base_id, &delta::encode(&base, &target).unwrap())
                .unwrap();
            if kind == 1 {
                writer.push_raw(base_id, &base).unwrap();
            }
        }
        2 => {
            let kp = sign::KeyPair::from_seed([42; 32]);
            let mut commit = Commit::new_unannotated(
                [1; 32],
                vec![],
                Identity::ed25519(kp.public.0),
                kp.public.0,
                b"commit".to_vec(),
                100,
                [0; 64],
            );
            commit.signature = sign::sign_commit(&commit, &kp).unwrap().0;
            commit.signature[0] ^= 1;
            let object = Object::Commit(commit);
            let bytes = serialize(&object).unwrap();
            writer
                .push_raw(id_from_object(&object, &bytes), &bytes)
                .unwrap();
        }
        3 | 4 => {
            let size = if kind == 4 { (1 << 20) + 1 } else { 64 };
            let (id, bytes) = blob(vec![99; size]);
            writer.push_raw(id, &bytes).unwrap();
        }
        _ => unreachable!(),
    }
    let mut pack = writer.finish().unwrap();
    if kind == 3 {
        let offset = 12 + 3 * (5 + 74);
        pack[offset] = 255;
        let end = pack.len() - 32;
        let trailer = hash::hash(&pack[..end]);
        pack[end..].copy_from_slice(&trailer);
    }
    pack
}
#[test]
fn integrity_precedence_is_identical_across_schedules_and_durable_boundaries() {
    for (kind, expected) in [
        (0, FailureCode::ExternalBaseAbsent),
        (1, FailureCode::ExternalBaseAbsent),
        (2, FailureCode::BadSignature),
        (3, FailureCode::InvalidEntryType),
        (4, FailureCode::PackfileTooLarge),
    ] {
        for corrupt in [false, true] {
            let mut pack = fault_pack(kind);
            if corrupt {
                let last = pack.len() - 1;
                pack[last] ^= 1;
            }
            let expected = if corrupt {
                FailureCode::PackfileCorrupted
            } else {
                expected
            };
            let budget = limits(64 << 10);
            let mut reference = None;
            for schedule in SCHEDULES {
                let (outcome, _, snapshots, _) = run(&pack, budget, schedule, None, true, true);
                let failure = outcome.unwrap_err();
                assert_eq!(
                    failure.code, expected,
                    "kind={kind}, corrupt={corrupt}, schedule={schedule:?}"
                );
                let reference = reference.get_or_insert_with(|| failure.clone());
                assert_eq!(&failure, reference);
                assert!(!snapshots.is_empty());
                if matches!(schedule, Schedule::Serial) {
                    for entry in 1..=3 {
                        assert!(snapshots.iter().any(|snapshot| snapshot.entries == entry));
                    }
                }
                for snapshot in snapshots {
                    for resumed_schedule in SCHEDULES {
                        let (outcome, _, _, _) = run(
                            &pack,
                            budget,
                            resumed_schedule,
                            Some(&snapshot),
                            true,
                            false,
                        );
                        assert_eq!(
                            &outcome.unwrap_err(),
                            reference,
                            "resume kind={kind}, corrupt={corrupt}, schedule={resumed_schedule:?}, entry={}",
                            snapshot.entries
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn unavailable_earlier_base_remains_retryable_before_integrity_verdict() {
    let (base_id, base) = blob(b"earlier base".to_vec());
    let (_, target) = blob(b"target".to_vec());
    let mut writer = PackWriter::new();
    writer.push_raw(base_id, &base).unwrap();
    writer
        .push_delta(&base_id, &delta::encode(&base, &target).unwrap())
        .unwrap();
    let valid = writer.finish().unwrap();
    for corrupt in [false, true] {
        let mut pack = valid.clone();
        if corrupt {
            let last = pack.len() - 1;
            pack[last] ^= 1;
        }
        for schedule in SCHEDULES {
            let (outcome, _, _, _) = run(&pack, limits(64 << 10), schedule, None, false, false);
            assert_eq!(outcome.unwrap_err().code, FailureCode::UnavailableInput);
        }
    }
}
