//! A carried frame must account for both host and copied input during supply.
#![allow(clippy::unwrap_used)]
#[path = "../../../tests/support/primitives_heap.rs"]
mod heap;
use mkit_core::hash;
use mkit_primitives::{
    evidence::{PackSource, RepositoryId, SourceBinding},
    limits::{IndexedProfile, VerifyLimits},
    pack_verify::{Acquisition, ByteSource, Request, Response, Step, verify::VerifyDriver},
};

fn hostile_compressed_pack() -> Vec<u8> {
    let payload = 15_usize << 20;
    let mut pack = Vec::with_capacity(12 + 5 + payload + 32);
    pack.extend_from_slice(b"MKIT");
    pack.extend_from_slice(&2_u32.to_le_bytes());
    pack.extend_from_slice(&1_u32.to_le_bytes());
    pack.push(3);
    pack.extend_from_slice(&u32::try_from(payload).unwrap().to_le_bytes());
    // The frame must be carried across many windows before its deliberately
    // invalid compressed stream can reach decoding. Its decoded claim is small.
    pack.extend_from_slice(&10_u32.to_le_bytes());
    pack.resize(12 + 5 + payload, 0);
    let trailer = hash::hash(&pack);
    pack.extend_from_slice(&trailer);
    pack
}

#[test]
fn carried_frame_feed_accounts_for_a_live_physical_buffer_and_the_driver_copy() {
    let pack = hostile_compressed_pack();
    let source = PackSource {
        id: hash::hash(&pack),
        len: u64::try_from(pack.len()).unwrap(),
        binding: SourceBinding([7; 32]),
    };
    let limits = VerifyLimits::indexed();
    let profile = IndexedProfile {
        pack_bytes: 2 << 30,
        decoded_bytes: 2 << 30,
        delta_depth: 50,
    };
    // Initial empty-index pages are persisted outside the measured epoch. The
    // test stops before an entry is decoded or an evidence lookup is needed.
    let mut durable = vec![0_u8; 64 << 10];
    let mut retained = 0;
    let epoch = heap::Epoch::begin();
    let mut driver = VerifyDriver::new(source, RepositoryId([9; 32]), profile, limits, 17).unwrap();
    let mut supplied = 0;
    let (mut measured, mut charged) = (0, 0);
    for _ in 0..1_000 {
        match driver.step().unwrap() {
            Step::RetainEvidence(page) => {
                let commitment = page.commitment;
                let end = retained + page.bytes.len();
                durable[retained..end].copy_from_slice(page.bytes);
                retained = end;
                driver.acknowledge_retention(commitment).unwrap();
            }
            Step::Request(Request::Bytes {
                request,
                source,
                range,
            }) => {
                assert!(matches!(source, ByteSource::Pack(_)));
                assert_eq!(range.len, 1 << 20);
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
                supplied += 1;
                // Keep `physical` live here: supply borrows it and creates an
                // independently owned window while the large carry remains.
                measured = epoch.live();
                charged = driver.usage().resident_bytes;
                assert!(
                    measured <= charged,
                    "supply {supplied}: live={measured}, charged={charged}"
                );
                assert!(charged <= limits.resident_bytes);
                assert!(epoch.peak() <= driver.usage().peak_resident_bytes);
                if supplied == 2 {
                    assert!(measured > 16 << 20, "a large frame must already be carried");
                    break;
                }
            }
            Step::Progress => (),
            _ => panic!("the test must stop before entry decode"),
        }
    }
    assert_eq!(supplied, 2);
    drop(driver);
    assert_eq!(epoch.live(), 0);
    println!("second_feed_heap={measured} charged_resident={charged}");
}
