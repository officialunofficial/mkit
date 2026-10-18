//! Portable framing parity, malformed inputs, and bounded resource accounting.
#![allow(clippy::unwrap_used)]
use mkit_core::{
    hash::{self, Hash},
    pack::{
        DecodeLimits, PackEntries, PackEntry,
        window::{FrameInfo, Step, WindowReader},
    },
};
use mkit_primitives::{
    error::FailureCode,
    evidence::{PackSource, RepositoryId, SourceBinding},
    limits::{IndexedProfile, VerifyLimits},
    pack_verify::{
        Acquisition, Request, ResourceUsage, Response,
        framing::{FramedEntry, FramingDriver, FramingStep},
    },
};

#[derive(Debug, PartialEq, Eq)]
struct Entry {
    base: Option<Hash>,
    bytes: Vec<u8>,
}

#[derive(Debug)]
struct Outcome {
    entries: Vec<Entry>,
    frames: Vec<FrameInfo>,
    usage: ResourceUsage,
    max_request: u64,
}

fn limits() -> VerifyLimits {
    VerifyLimits {
        acquisition_bytes: 64 << 10,
        page_bytes: 256,
        resident_pages: 1,
        ..VerifyLimits::indexed()
    }
}

fn profile() -> IndexedProfile {
    IndexedProfile {
        pack_bytes: 64 << 20,
        decoded_bytes: 64 << 20,
        delta_depth: 50,
    }
}

fn streamed(bytes: &[u8], limits: VerifyLimits) -> Result<Outcome, FailureCode> {
    let source = PackSource {
        id: hash::hash(bytes),
        len: bytes.len().try_into().unwrap(),
        binding: SourceBinding([3; 32]),
    };
    let mut driver = FramingDriver::new(source, RepositoryId([7; 32]), profile(), limits, 5)
        .map_err(|error| error.code)?;
    let mut entries = Vec::new();
    let mut frames = Vec::new();
    let mut max_request = 0;
    for _ in 0..10_000 {
        match driver.step().map_err(|error| error.code)? {
            FramingStep::Request(Request::Bytes {
                request,
                source,
                range,
            }) => {
                assert!(range.len <= limits.acquisition_bytes);
                max_request = max_request.max(range.len);
                let begin = usize::try_from(range.offset).unwrap();
                let end = begin
                    .checked_add(usize::try_from(range.len).unwrap())
                    .unwrap();
                let value = bytes
                    .get(begin..end)
                    .expect("request remains within bound source");
                driver
                    .supply(Response::Bytes {
                        request,
                        source,
                        range,
                        value: Acquisition::Present(value),
                    })
                    .map_err(|error| error.code)?;
            }
            FramingStep::Frame(frame) => {
                assert_eq!(frame.ordinal, u64::try_from(entries.len()).unwrap());
                frames.push(frame.info);
                entries.push(match frame.entry {
                    FramedEntry::Raw(bytes) => Entry {
                        base: None,
                        bytes: bytes.to_vec(),
                    },
                    FramedEntry::Delta { base, stream } => Entry {
                        base: Some(base),
                        bytes: stream.to_vec(),
                    },
                    other => panic!("unmodelled framed entry: {other:?}"),
                });
            }
            FramingStep::RetainEvidence(page) => {
                let commitment = page.commitment;
                assert!(u64::try_from(page.bytes.len()).unwrap() <= limits.page_bytes);
                driver
                    .acknowledge_retention(commitment)
                    .map_err(|error| error.code)?;
            }
            FramingStep::Progress => {}
            FramingStep::Complete(pack) => {
                assert_eq!(pack.source(), source);
                assert_eq!(usize::try_from(pack.entries()).unwrap(), entries.len());
                assert_eq!(pack.trailer(), bytes[bytes.len() - 32..]);
                let usage = driver.usage();
                assert!(usage.peak_resident_bytes <= limits.resident_bytes);
                assert!(usage.evidence_bytes <= limits.evidence_bytes);
                assert!(usage.evidence_pages <= limits.evidence_pages);
                assert!(usage.work <= limits.work);
                return Ok(Outcome {
                    entries,
                    frames,
                    usage,
                    max_request,
                });
            }
            _ => panic!("unexpected acquisition in a fresh run"),
        }
    }
    panic!("bounded test driver did not terminate")
}

fn buffered(bytes: &[u8]) -> Vec<Entry> {
    PackEntries::new(bytes)
        .unwrap()
        .map(|entry| match entry.unwrap() {
            PackEntry::Raw { bytes } => Entry {
                base: None,
                bytes: bytes.into_owned(),
            },
            PackEntry::Delta { base, stream } => Entry {
                base: Some(base),
                bytes: stream.into_owned(),
            },
        })
        .collect()
}

fn core_frames(bytes: &[u8]) -> Vec<FrameInfo> {
    let mut reader = WindowReader::new(
        u64::try_from(bytes.len()).unwrap(),
        64 << 10,
        DecodeLimits::default(),
        Some(hash::hash(bytes)),
    )
    .unwrap();
    let mut frames = Vec::new();
    loop {
        match reader.step().unwrap() {
            Step::NeedWindow(range) => {
                let begin = usize::try_from(range.offset).unwrap();
                reader
                    .feed(
                        range.offset,
                        &bytes[begin..begin + usize::try_from(range.len).unwrap()],
                    )
                    .unwrap();
            }
            Step::Entry(_) => frames.push(reader.last_frame().unwrap()),
            Step::Done(_) => return frames,
            _ => panic!("unexpected core transition"),
        }
    }
}

fn parity(bytes: &[u8]) -> Outcome {
    let actual = streamed(bytes, limits()).unwrap();
    assert_eq!(actual.entries, buffered(bytes));
    assert_eq!(actual.frames, core_frames(bytes));
    assert_eq!(
        actual.usage.evidence_pages,
        u64::try_from(actual.entries.len()).unwrap()
    );
    actual
}

#[test]
fn every_committed_pack_v2_vector_matches_buffered_and_window_readers() {
    // Pins copied from each pack-v2 JSON sidecar's decoded_blake3 field.
    // Delta pins commit the decoded instruction stream before base resolution.
    let fixtures: [(&[u8], &[Option<&str>]); 5] = [
        (
            include_bytes!("../../../tests/golden/pack-v2/raw_4k_repeat.bin"),
            &[Some(
                "8aef4d27f20ef2cfd6a693197fe790b618f6b1fc524164caaea24dfcb8ba6a87",
            )],
        ),
        (
            include_bytes!("../../../tests/golden/pack-v2/delta_repeat.bin"),
            &[
                None,
                Some("73f1a378cebf1a519197de17137c1e820111fb202ffd0e0f3759a421f6ce0199"),
            ],
        ),
        (
            include_bytes!("../../../tests/golden/pack-v2/mixed.bin"),
            &[
                None,
                Some("cca51ff50cfa41e6be29f2d8324ab16d241ff107f3b2ce936d58f358a08a6f75"),
                None,
                Some("95343a32ae90008f76c471581100015272509a15574b7be89354349af45107a4"),
            ],
        ),
        (
            include_bytes!("../../../tests/golden/pack-v2/tree_and_commit.bin"),
            &[
                None,
                Some("beab0ce685da535843e5387d1325b61070e4413e145052c152b884159fe05e2b"),
                Some("0a4c86b2295f3d8a71885807416381ea3dbebeefada361df8fbbf85915c5f959"),
            ],
        ),
        (
            include_bytes!("../../../tests/golden/pack-v2/large_literals.bin"),
            &[
                Some("f3b38880d58138bfef17e0c7db979eb04f9ce2aff3259966e43b29396b869057"),
                Some("1f79b26275a9a50d4dc59eec0ac92d8c10ccb162f38e17245fd7f7417858c64d"),
                Some("597c74e3b236fe45de51a24ed94f127b222f377e2d677b2b281f195040608928"),
            ],
        ),
    ];
    for (bytes, expected) in fixtures {
        if cfg!(any(feature = "pack-ruzstd", feature = "pack-zstd")) {
            let actual = parity(bytes);
            assert_eq!(actual.entries.len(), expected.len());
            for ((entry, frame), expected) in
                actual.entries.iter().zip(&actual.frames).zip(expected)
            {
                assert_eq!(
                    matches!(frame.wire_type, 3 | 4),
                    expected.is_some(),
                    "every compressed frame has an independent decoded-byte pin"
                );
                if let Some(expected) = expected {
                    assert_eq!(
                        hash::to_hex(&hash::hash(&entry.bytes)),
                        *expected,
                        "decoded frame payload at offset {}",
                        frame.offset
                    );
                }
            }
        } else {
            assert_eq!(
                streamed(bytes, limits()).unwrap_err(),
                FailureCode::UnsupportedCapability
            );
        }
    }
}

#[test]
fn delta_order_is_framed_without_claiming_base_eligibility() {
    // Resolving base eligibility belongs to all-entry verification.
    for bytes in [
        include_bytes!("../fixtures/framing/earlier-delta-base.bin").as_slice(),
        include_bytes!("../fixtures/framing/later-delta-base.bin").as_slice(),
    ] {
        parity(bytes);
    }
}

fn finish(mut body: Vec<u8>) -> Vec<u8> {
    let trailer = hash::hash(&body);
    body.extend_from_slice(&trailer);
    body
}

fn raw_pack(count: u32, payload_len: usize) -> Vec<u8> {
    let mut body = b"MKIT".to_vec();
    body.extend_from_slice(&1_u32.to_le_bytes());
    body.extend_from_slice(&count.to_le_bytes());
    for ordinal in 0..count {
        body.push(0);
        body.extend_from_slice(&u32::try_from(payload_len).unwrap().to_le_bytes());
        body.extend((0..payload_len).map(|offset| {
            u8::try_from(offset % 256)
                .unwrap()
                .wrapping_add(u8::try_from(ordinal % 256).unwrap())
        }));
    }
    finish(body)
}

fn refusal(bytes: &[u8], code: FailureCode) {
    assert_eq!(streamed(bytes, limits()).unwrap_err(), code);
}

#[test]
fn malformed_header_frame_and_integrity_vectors_fail_closed() {
    let original = raw_pack(1, 8);
    let body = &original[..original.len() - 32];
    for (offset, value, expected) in [
        (0, 0, FailureCode::InvalidMagic),
        (4, 3, FailureCode::UnsupportedPackVersion),
        (12, 1, FailureCode::InvalidEntryType),
    ] {
        let mut changed = body.to_vec();
        changed[offset] = value;
        refusal(&finish(changed), expected);
    }
    let mut changed = body.to_vec();
    changed[8..12].copy_from_slice(&10_000_001_u32.to_le_bytes());
    refusal(&finish(changed), FailureCode::TooManyObjects);
    let mut changed = body.to_vec();
    changed[8..12].copy_from_slice(&2_u32.to_le_bytes());
    refusal(&finish(changed), FailureCode::UnexpectedEof);
    let mut changed = body.to_vec();
    changed[8..12].copy_from_slice(&0_u32.to_le_bytes());
    refusal(&finish(changed), FailureCode::TrailingData);
    let mut changed = body.to_vec();
    changed[13..17].copy_from_slice(&9_u32.to_le_bytes());
    refusal(&finish(changed), FailureCode::UnexpectedEof);
    let mut changed = original.clone();
    *changed.last_mut().unwrap() ^= 1;
    refusal(&changed, FailureCode::PackfileCorrupted);
    let mut changed = body.to_vec();
    changed.push(0);
    refusal(&finish(changed), FailureCode::TrailingData);
    for end in 0..original.len() {
        assert!(
            streamed(&original[..end], limits()).is_err(),
            "prefix {end}"
        );
    }
}

#[test]
fn cross_window_frames_have_source_size_independent_resident_reservations() {
    let small = raw_pack(2, 300_000);
    let large = raw_pack(6, 300_000);
    parity(&small);
    parity(&large);
    let small = streamed(&small, limits()).unwrap();
    let large = streamed(&large, limits()).unwrap();
    assert_eq!(small.max_request, 64 << 10);
    assert_eq!(large.max_request, small.max_request);
    assert_eq!(
        large.usage.peak_resident_bytes,
        small.usage.peak_resident_bytes
    );
    assert!(large.usage.evidence_bytes > small.usage.evidence_bytes);
    assert!(large.usage.work > small.usage.work);
}

#[test]
fn execution_caps_refuse_instead_of_truncating_or_finishing() {
    let bytes = raw_pack(2, 80_000);
    let baseline = streamed(&bytes, limits()).unwrap();
    let base = limits();
    for restricted in [
        VerifyLimits {
            acquisition_bytes: 32 << 10,
            ..base
        },
        VerifyLimits {
            resident_bytes: baseline.usage.peak_resident_bytes - 1,
            ..base
        },
        VerifyLimits {
            page_bytes: 216,
            ..base
        },
        VerifyLimits {
            resident_pages: 0,
            ..base
        },
        VerifyLimits {
            evidence_bytes: 433,
            ..base
        },
        VerifyLimits {
            evidence_pages: 1,
            ..base
        },
        VerifyLimits { work: 1, ..base },
        VerifyLimits {
            checkpoint_bytes: 0,
            ..base
        },
    ] {
        assert_eq!(
            streamed(&bytes, restricted).unwrap_err(),
            FailureCode::ResourceLimit
        );
    }
}
