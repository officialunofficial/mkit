//! Allocation epoch over a large raw source and server-sized acquisitions.
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
    pack_verify::{Acquisition, ByteSource, Request, Response, Step, verify::VerifyDriver},
};
fn fixture_pack() -> Vec<u8> {
    let mut writer = PackWriter::new_raw_only();
    for index in 0..96_u8 {
        let object = Object::Blob(Blob {
            data: vec![index; 768 << 10],
        });
        let bytes = serialize(&object).unwrap();
        writer
            .push_raw(id_from_object(&object, &bytes), &bytes)
            .unwrap();
    }
    writer.finish().unwrap()
}

fn assert_accounted(driver: &VerifyDriver, epoch: &heap::Epoch, ceiling: u64) {
    assert!(
        epoch.live() <= driver.usage().resident_bytes,
        "live {} ledger {}",
        epoch.live(),
        driver.usage().resident_bytes
    );
    assert!(
        epoch.peak() <= driver.usage().peak_resident_bytes,
        "heap peak {} ledger peak {}",
        epoch.peak(),
        driver.usage().peak_resident_bytes
    );
    assert!(driver.usage().peak_resident_bytes <= ceiling);
}

#[test]
fn server_sized_acquisitions_fit_the_measured_allocation_ceiling() {
    let pack = fixture_pack();
    let source = PackSource {
        id: hash::hash(&pack),
        len: u64::try_from(pack.len()).unwrap(),
        binding: SourceBinding([7; 32]),
    };
    let limits = VerifyLimits {
        acquisition_bytes: 16 << 20,
        resident_bytes: 48 << 20,
        ..VerifyLimits::indexed()
    };
    let profile = IndexedProfile {
        pack_bytes: 2 << 30,
        decoded_bytes: 2 << 30,
        delta_depth: 50,
    };
    // Source backing and durable evidence storage exist before the epoch. Each
    // acquisition allocates a fresh physical host buffer inside the epoch, so
    // both that buffer and the driver copy count toward the ceiling.
    let mut arena = vec![0_u8; 16 << 20];
    let mut pages = Vec::<(PageCommitment, usize, usize)>::with_capacity(16384);
    let mut used = 0;
    let mut bytes = 0;
    let epoch = heap::Epoch::begin();
    let mut driver = VerifyDriver::new(source, RepositoryId([9; 32]), profile, limits, 17).unwrap();
    let mut complete = false;
    for _ in 0..100_000 {
        match driver.step().unwrap() {
            Step::Request(Request::Bytes {
                request,
                source,
                range,
            }) => {
                assert!(matches!(source, ByteSource::Pack(_)));
                bytes += range.len;
                let physical = pack[usize::try_from(range.offset).unwrap()
                    ..usize::try_from(range.offset + range.len).unwrap()]
                    .to_vec();
                driver
                    .supply(Response::Bytes {
                        request,
                        source,
                        range,
                        value: Acquisition::Present(&physical),
                    })
                    .unwrap();
            }
            Step::Request(Request::EvidencePage { request, page }) => {
                let (_, offset, len) = pages.iter().find(|(known, _, _)| *known == page).unwrap();
                driver
                    .supply(Response::EvidencePage {
                        request,
                        page,
                        value: Acquisition::Present(&arena[*offset..*offset + *len]),
                    })
                    .unwrap();
            }
            Step::ProvisionalObject(_) | Step::Progress | Step::ReleasePage(_) => (),
            Step::RetainEvidence(page) => {
                let commitment = page.commitment;
                let len = page.bytes.len();
                assert!(used + len <= arena.len());
                assert!(pages.len() < pages.capacity());
                arena[used..used + len].copy_from_slice(page.bytes);
                pages.push((commitment, used, len));
                used += len;
                driver.acknowledge_retention(commitment).unwrap();
            }
            Step::Complete(verified) => {
                assert_eq!(verified.counts().entries, 96);
                complete = true;
                break;
            }
            _ => panic!("unexpected raw-pack request"),
        }
        assert_accounted(&driver, &epoch, limits.resident_bytes);
    }
    assert!(complete);
    assert_eq!(bytes, u64::try_from(pack.len()).unwrap());
    let measured_peak = epoch.peak();
    let charged_peak = driver.usage().peak_resident_bytes;
    drop(driver);
    assert_eq!(epoch.live(), 0);
    println!(
        "pack_bytes={} acquisition={} measured_heap_peak={measured_peak} charged_peak={charged_peak} ceiling={}",
        pack.len(),
        limits.acquisition_bytes,
        limits.resident_bytes
    );
}
