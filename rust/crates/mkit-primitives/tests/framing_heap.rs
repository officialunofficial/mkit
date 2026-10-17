//! Whole-driver Rust allocation probe; native C workspace is outside this meter.
#![allow(clippy::unwrap_used)]
#[path = "../../../tests/support/primitives_heap.rs"]
mod heap;

use mkit_core::hash;
use mkit_primitives::{
    error::FailureCode,
    evidence::{PackSource, RepositoryId, SourceBinding},
    limits::{IndexedProfile, VerifyLimits},
    pack_verify::{
        Acquisition, Request, Response,
        framing::{FramingDriver, FramingStep},
    },
};

fn pack(version: u32, kind: u8, payloads: &[&[u8]]) -> Vec<u8> {
    let mut bytes = b"MKIT".to_vec();
    bytes.extend_from_slice(&version.to_le_bytes());
    bytes.extend_from_slice(&u32::try_from(payloads.len()).unwrap().to_le_bytes());
    for payload in payloads {
        bytes.push(kind);
        bytes.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_le_bytes());
        bytes.extend_from_slice(payload);
    }
    bytes.extend_from_slice(&hash::hash(&bytes));
    bytes
}

fn snapshot(driver: &mut FramingDriver, epoch: &heap::Epoch) {
    let len = match driver.checkpoint() {
        Ok(checkpoint) => checkpoint.bytes().len() as u64,
        Err(error) if error.code == FailureCode::CheckpointNotReady => return,
        Err(error) => panic!("checkpoint failed: {error}"),
    };
    // The driver still owns the borrowed output after the borrow ends.
    assert!(driver.usage().resident_bytes >= len);
    assert!(epoch.live() <= driver.usage().resident_bytes);
    assert!(epoch.peak() <= driver.usage().peak_resident_bytes);
}

fn measured(bytes: &[u8], expected: Option<FailureCode>, expected_frames: u32) {
    // Source hashing and fixture construction are host work before the epoch.
    let source = PackSource {
        id: hash::hash(bytes),
        len: bytes.len() as u64,
        binding: SourceBinding([3; 32]),
    };
    let limits = VerifyLimits {
        acquisition_bytes: 64 << 10,
        page_bytes: 256,
        resident_pages: 1,
        ..VerifyLimits::indexed()
    };
    let profile = IndexedProfile {
        pack_bytes: 4 << 20,
        decoded_bytes: 4 << 20,
        delta_depth: 50,
    };
    let epoch = heap::Epoch::begin();
    let mut driver = FramingDriver::new(source, RepositoryId([7; 32]), profile, limits, 5).unwrap();
    snapshot(&mut driver, &epoch);
    let mut finished = false;
    let mut frames = 0;
    for _ in 0..1000 {
        let result = driver.step();
        match result {
            Ok(FramingStep::Request(Request::Bytes {
                request,
                source,
                range,
            })) => {
                let begin = usize::try_from(range.offset).unwrap();
                let end = begin + usize::try_from(range.len).unwrap();
                driver
                    .supply(Response::Bytes {
                        request,
                        source,
                        range,
                        value: Acquisition::Present(&bytes[begin..end]),
                    })
                    .unwrap();
            }
            Ok(FramingStep::Frame(frame)) => {
                assert!(!matches!(
                    frame.entry,
                    mkit_primitives::pack_verify::framing::FramedEntry::Delta { .. }
                ));
                frames += 1;
            }
            Ok(FramingStep::RetainEvidence(page)) => {
                // Retention uses the borrowed page, without copying host storage.
                let commitment = page.commitment;
                driver.acknowledge_retention(commitment).unwrap();
                snapshot(&mut driver, &epoch);
            }
            Ok(FramingStep::Progress) => {}
            Ok(FramingStep::Complete(_)) => {
                assert_eq!(expected, None);
                assert_eq!(frames, expected_frames);
                snapshot(&mut driver, &epoch);
                finished = true;
                break;
            }
            Err(error) => {
                assert_eq!(Some(error.code), expected);
                finished = true;
                break;
            }
            Ok(_) => panic!("unexpected fresh-run request"),
        }
        assert!(epoch.live() <= driver.usage().resident_bytes);
        assert!(epoch.peak() <= driver.usage().peak_resident_bytes);
    }
    assert!(finished, "bounded probe did not terminate");
    let usage = driver.usage();
    assert!(epoch.peak() <= usage.peak_resident_bytes);
    assert!(epoch.peak() <= limits.resident_bytes);
    // Verify that the positive path actually allocated carried entry bytes.
    if expected.is_none() && bytes.len() >= 300_000 {
        assert!(epoch.peak() >= 300_000);
    }
    let measured_peak = epoch.peak();
    drop(driver);
    assert_eq!(epoch.live(), 0);
    println!(
        "framing Rust heap: input={} measured_peak={measured_peak} reserved_peak={} outcome={expected:?}",
        bytes.len(),
        usage.peak_resident_bytes
    );
}

fn measured_decode_resume(bytes: &[u8]) {
    use mkit_primitives::evidence::checkpoint::Checkpoint;
    let source = PackSource {
        id: hash::hash(bytes),
        len: bytes.len() as u64,
        binding: SourceBinding([3; 32]),
    };
    let repository = RepositoryId([7; 32]);
    let profile = IndexedProfile {
        pack_bytes: 4 << 20,
        decoded_bytes: 4 << 20,
        delta_depth: 50,
    };
    let limits = VerifyLimits::indexed();
    let mut original = FramingDriver::new(source, repository, profile, limits, 5).unwrap();
    let (checkpoint, retained) = loop {
        match original.step().unwrap() {
            FramingStep::Request(Request::Bytes {
                request,
                source,
                range,
            }) => {
                let start = usize::try_from(range.offset).unwrap();
                original
                    .supply(Response::Bytes {
                        request,
                        source,
                        range,
                        value: Acquisition::Present(
                            &bytes[start..start + usize::try_from(range.len).unwrap()],
                        ),
                    })
                    .unwrap();
            }
            FramingStep::RetainEvidence(page) => {
                let retained = (page.commitment, page.bytes.to_vec());
                original.acknowledge_retention(retained.0).unwrap();
                let snapshot = original.checkpoint().unwrap();
                break (
                    Checkpoint::from_bytes(snapshot.bytes(), limits).unwrap(),
                    retained,
                );
            }
            FramingStep::Frame(_) | FramingStep::Progress => (),
            _ => panic!("expected a resumable first entry"),
        }
    };
    // Host-owned source, checkpoint and page are acquired before this epoch.
    // Drop the original reader first so its frees cannot reduce the measurement.
    drop(original);
    let epoch = heap::Epoch::begin();
    let mut restored =
        FramingDriver::resume(source, repository, profile, limits, 6, &checkpoint).unwrap();
    assert!(epoch.live() <= restored.usage().resident_bytes);
    let mut recovered = false;
    loop {
        match restored.step().unwrap() {
            FramingStep::Request(Request::EvidencePage { request, page }) => {
                assert_eq!(page, retained.0);
                restored
                    .supply(Response::EvidencePage {
                        request,
                        page,
                        value: Acquisition::Present(&retained.1),
                    })
                    .unwrap();
                recovered = true;
            }
            FramingStep::Request(Request::Bytes {
                request,
                source,
                range,
            }) => {
                assert!(recovered);
                let start = usize::try_from(range.offset).unwrap();
                restored
                    .supply(Response::Bytes {
                        request,
                        source,
                        range,
                        value: Acquisition::Present(
                            &bytes[start..start + usize::try_from(range.len).unwrap()],
                        ),
                    })
                    .unwrap();
            }
            FramingStep::RetainEvidence(page) => {
                let commitment = page.commitment;
                restored.acknowledge_retention(commitment).unwrap();
                snapshot(&mut restored, &epoch);
            }
            FramingStep::Frame(_) | FramingStep::Progress => (),
            FramingStep::Complete(_) => break,
            _ => panic!("unexpected resumed request"),
        }
        assert!(epoch.live() <= restored.usage().resident_bytes);
        assert!(epoch.peak() <= restored.usage().peak_resident_bytes);
    }
    assert!(epoch.peak() <= restored.usage().peak_resident_bytes);
    assert!(epoch.peak() <= limits.resident_bytes);
    drop(restored);
    assert_eq!(epoch.live(), 0);
}

#[cfg(all(feature = "pack-ruzstd", not(feature = "pack-zstd")))]
fn corrupt_compression() -> Vec<u8> {
    // RFC frame with a sequence flood rejected by the vendored block preflight.
    // The 8 MiB window descriptor exercises the real pure-Rust decoder path.
    let mut frame = vec![0x28, 0xb5, 0x2f, 0xfd, 0, 0x68];
    frame.extend_from_slice(&(4_u32 << 3).to_le_bytes()[..3]);
    frame.extend_from_slice(b"AAAA");
    let n = 2000_u16;
    let [high, low] = n.to_be_bytes();
    let mut body = vec![0, 0x80 + high, low, 0x54, 0, 2, 52];
    body.resize(body.len() + usize::from(n) * 18 / 8, 0);
    body.push(1);
    let header = (u32::try_from(body.len()).unwrap() << 3) | (2 << 1) | 1;
    frame.extend_from_slice(&header.to_le_bytes()[..3]);
    frame.extend_from_slice(&body);
    let mut payload = (64_u32 << 10).to_le_bytes().to_vec();
    payload.extend_from_slice(&frame);
    pack(2, 3, &[&payload])
}

// One test keeps allocator epochs isolated from other test cases in this binary.
#[test]
fn framing_allocations_fit_live_reservations_and_peak_ceiling() {
    let payload = vec![0x41; 300_000];
    let bytes = pack(1, 0, &[&payload, &payload, &payload]);
    measured(&bytes, None, 3);
    measured_decode_resume(&bytes);
    #[cfg(any(feature = "pack-ruzstd", feature = "pack-zstd"))]
    measured(
        include_bytes!("../../../tests/golden/pack-v2/raw_4k_repeat.bin"),
        None,
        1,
    );
    #[cfg(any(feature = "pack-ruzstd", feature = "pack-zstd"))]
    measured_decode_resume(include_bytes!("../../../tests/golden/pack-v2/mixed.bin"));
    #[cfg(all(feature = "pack-ruzstd", not(feature = "pack-zstd")))]
    measured(
        &corrupt_compression(),
        Some(FailureCode::DecompressionFailed),
        0,
    );
}
