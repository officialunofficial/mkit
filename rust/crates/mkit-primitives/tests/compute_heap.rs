//! Single-test Rust allocation epoch including caller-held jobs and outputs.
#![allow(clippy::unwrap_used)]
#[path = "../../../tests/support/primitives_heap.rs"]
mod heap;

use mkit_core::{
    hash,
    object::{Blob, Object, id_from_object},
    pack::PackWriter,
    serialize::serialize,
};
use mkit_primitives::{
    evidence::{PackSource, PageCommitment, RepositoryId, SourceBinding},
    limits::{IndexedProfile, VerifyLimits},
    pack_verify::{
        Acquisition, ByteSource, Request, Response, Step,
        verify::{ComputeConfig, ComputeDisposition, ComputeJob, ComputeOutput, VerifyDriver},
    },
};

fn assert_accounted(machine: &VerifyDriver, epoch: &heap::Epoch, ceiling: u64) {
    let usage = machine.usage();
    assert!(epoch.live() <= usage.resident_bytes);
    assert!(epoch.peak() <= usage.peak_resident_bytes);
    assert!(usage.peak_resident_bytes <= ceiling);
}

fn fixture_pack() -> Vec<u8> {
    let mut writer = PackWriter::new_raw_only();
    for index in 0_u8..96 {
        let object = Object::Blob(Blob {
            data: vec![index; 96],
        });
        let bytes = serialize(&object).unwrap();
        writer
            .push_raw(id_from_object(&object, &bytes), &bytes)
            .unwrap();
    }
    let long = Object::Blob(Blob {
        data: vec![0xa5; 192 << 10],
    });
    let bytes = serialize(&long).unwrap();
    let id = id_from_object(&long, &bytes);
    writer.push_raw(id, &bytes).unwrap();
    writer.push_raw(id, &bytes).unwrap();
    writer.finish().unwrap()
}

fn complete_batch(
    machine: &mut VerifyDriver,
    jobs: &mut Vec<ComputeJob>,
    outputs: &mut Vec<ComputeOutput>,
    epoch: &heap::Epoch,
    ceiling: u64,
) -> usize {
    // Run last-issued first and retain every opaque output together before
    // delivering any result. Both ownership phases count in the epoch.
    while let Some(job) = jobs.pop() {
        assert!(outputs.len() < outputs.capacity());
        outputs.push(job.run());
        assert_accounted(machine, epoch, ceiling);
    }
    let held_outputs = outputs.len();
    while !outputs.is_empty() {
        let output = outputs.remove(0);
        assert_eq!(
            machine.supply_compute(output).unwrap(),
            ComputeDisposition::Accepted
        );
        assert_accounted(machine, epoch, ceiling);
    }
    held_outputs
}

fn serve_input(
    machine: &mut VerifyDriver,
    request: &Request,
    pack: &[u8],
    pages: &[(PageCommitment, usize, usize)],
    arena: &[u8],
) -> bool {
    match request {
        Request::Bytes {
            request,
            source,
            range,
        } => {
            assert!(matches!(source, ByteSource::Pack(_)));
            let start = usize::try_from(range.offset).unwrap();
            let end = start + usize::try_from(range.len).unwrap();
            machine
                .supply(Response::Bytes {
                    request: *request,
                    source: *source,
                    range: *range,
                    value: Acquisition::Present(&pack[start..end]),
                })
                .unwrap();
            true
        }
        Request::EvidencePage { request, page } => {
            let (_, offset, len) = pages.iter().find(|(known, _, _)| known == page).unwrap();
            machine
                .supply(Response::EvidencePage {
                    request: *request,
                    page: *page,
                    value: Acquisition::Present(&arena[*offset..*offset + *len]),
                })
                .unwrap();
            false
        }
        _ => panic!("unexpected input request in raw Blob allocation probe"),
    }
}

#[test]
fn shared_ceiling_covers_queued_jobs_completed_outputs_and_window_crossings() {
    // All source and host-retention storage exists before the allocation epoch.
    // Provisional raw Blob bytes need no canonical lookup and are discarded.
    let pack = fixture_pack();
    let source = PackSource {
        id: hash::hash(&pack),
        len: pack.len() as u64,
        binding: SourceBinding([3; 32]),
    };
    let budget = VerifyLimits {
        acquisition_bytes: 64 << 10,
        page_bytes: 4096,
        resident_pages: 4,
        ..VerifyLimits::indexed()
    };
    let profile = IndexedProfile {
        pack_bytes: 16 << 20,
        decoded_bytes: 16 << 20,
        delta_depth: 50,
    };
    let mut arena = vec![0_u8; 32 << 20];
    let mut pages = Vec::<(PageCommitment, usize, usize)>::with_capacity(16_384);
    let mut jobs = Vec::<ComputeJob>::with_capacity(3);
    let mut outputs = Vec::<ComputeOutput>::with_capacity(3);
    let mut arena_used = 0;
    let mut max_jobs = 0;
    let mut max_outputs = 0;
    let mut pack_requests = 0;
    let epoch = heap::Epoch::begin();
    let mut machine = VerifyDriver::new(source, RepositoryId([7; 32]), profile, budget, 5)
        .unwrap()
        .with_compute(ComputeConfig { max_jobs: 3 })
        .unwrap();
    assert_accounted(&machine, &epoch, budget.resident_bytes);
    let mut finished = false;
    for _ in 0..100_000 {
        match machine.step().unwrap() {
            Step::Request(Request::Compute { job }) => {
                assert!(jobs.len() < jobs.capacity());
                jobs.push(machine.take_compute(job).unwrap());
                max_jobs = max_jobs.max(jobs.len());
            }
            Step::Request(request) => {
                assert!(jobs.is_empty() && outputs.is_empty());
                pack_requests +=
                    usize::from(serve_input(&mut machine, &request, &pack, &pages, &arena));
            }
            Step::Progress => {
                max_outputs = max_outputs.max(complete_batch(
                    &mut machine,
                    &mut jobs,
                    &mut outputs,
                    &epoch,
                    budget.resident_bytes,
                ));
            }
            Step::ProvisionalObject(_) => (),
            Step::RetainEvidence(page) => {
                let commitment = page.commitment;
                let len = page.bytes.len();
                let end = arena_used + len;
                assert!(end <= arena.len());
                arena[arena_used..end].copy_from_slice(page.bytes);
                assert!(pages.len() < pages.capacity());
                pages.push((commitment, arena_used, len));
                arena_used = end;
                machine.acknowledge_retention(commitment).unwrap();
            }
            Step::Complete(pack) => {
                assert_eq!(pack.counts().entries, 98);
                assert_eq!(pack.counts().objects, 97);
                finished = true;
                break;
            }
            _ => panic!("unexpected request in raw Blob allocation probe"),
        }
        assert_accounted(&machine, &epoch, budget.resident_bytes);
    }
    assert!(finished);
    assert!(max_jobs >= 2 && max_outputs >= 2);
    // Both large frames exceed a window, so this also exercises carried input.
    assert!(192 << 10 > budget.acquisition_bytes);
    let expected_requests = source.len.div_ceil(budget.acquisition_bytes);
    assert_eq!(u64::try_from(pack_requests).unwrap(), expected_requests);
    assert!(jobs.is_empty() && outputs.is_empty());
    assert_accounted(&machine, &epoch, budget.resident_bytes);
    drop(machine);
    assert_eq!(epoch.live(), 0);
}
