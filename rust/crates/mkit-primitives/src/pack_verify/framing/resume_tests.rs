//! Cold Decode restart, binding and admission regressions through public cursors.
use super::*;
use crate::pack_verify::{Acquisition, Request, Response, framing::FramingStep};
use mkit_core::{
    hash,
    pack::{DecodeLimits, PackWriter},
};

fn profile() -> IndexedProfile {
    IndexedProfile {
        pack_bytes: super::super::MAX_PACK_BYTES,
        decoded_bytes: 4 << 30,
        delta_depth: 50,
    }
}
fn limits() -> VerifyLimits {
    VerifyLimits {
        acquisition_bytes: 64 << 10,
        ..VerifyLimits::indexed()
    }
}
fn source(bytes: &[u8]) -> PackSource {
    PackSource {
        id: hash::hash(bytes),
        len: bytes.len() as u64,
        binding: crate::evidence::SourceBinding([7; 32]),
    }
}
fn repository() -> RepositoryId {
    RepositoryId([9; 32])
}
fn machine(bytes: &[u8]) -> FramingDriver {
    FramingDriver::new(source(bytes), repository(), profile(), limits(), 17).unwrap()
}
fn raw_pack() -> Vec<u8> {
    let mut writer = PackWriter::new_raw_only();
    for bytes in [vec![3; 70 << 10], vec![4; 11], vec![5; 19]] {
        writer.push_raw(hash::hash(&bytes), &bytes).unwrap();
    }
    writer.finish().unwrap()
}
fn supply_bytes(
    machine: &mut FramingDriver,
    bytes: &[u8],
    request: crate::pack_verify::RequestId,
    source: crate::pack_verify::ByteSource,
    range: crate::pack_verify::ByteRange,
) {
    let begin = usize::try_from(range.offset).unwrap();
    machine
        .supply(Response::Bytes {
            request,
            source,
            range,
            value: Acquisition::Present(&bytes[begin..begin + usize::try_from(range.len).unwrap()]),
        })
        .unwrap();
}
fn snapshot(machine: &mut FramingDriver) -> Checkpoint {
    Checkpoint::from_bytes(machine.checkpoint().unwrap().bytes(), limits()).unwrap()
}
fn first_snapshot(bytes: &[u8]) -> (Checkpoint, Vec<(crate::evidence::PageCommitment, Vec<u8>)>) {
    let mut machine = machine(bytes);
    loop {
        match machine.step().unwrap() {
            FramingStep::Request(Request::Bytes {
                request,
                source,
                range,
            }) => supply_bytes(&mut machine, bytes, request, source, range),
            FramingStep::RetainEvidence(page) => {
                let saved = (page.commitment, page.bytes.to_vec());
                machine.acknowledge_retention(saved.0).unwrap();
                return (snapshot(&mut machine), vec![saved]);
            }
            FramingStep::Frame(_) | FramingStep::Progress => (),
            _ => panic!("expected a retained entry"),
        }
    }
}
fn restore(cp: &Checkpoint, generation: u64) -> FramingDriver {
    let m = cp.meta();
    FramingDriver::resume(m.source, m.repository, m.profile, m.limits, generation, cp).unwrap()
}
fn complete(
    machine: &mut FramingDriver,
    bytes: &[u8],
    pages: &mut Vec<(crate::evidence::PageCommitment, Vec<u8>)>,
) -> (Vec<u64>, FramedPack) {
    let mut frames = Vec::new();
    let mut recovery_left = machine.ordinal;
    loop {
        match machine.step().unwrap() {
            FramingStep::Request(Request::EvidencePage { request, page }) => {
                let data = &pages.iter().find(|(key, _)| *key == page).unwrap().1;
                machine
                    .supply(Response::EvidencePage {
                        request,
                        page,
                        value: Acquisition::Present(data),
                    })
                    .unwrap();
                recovery_left -= 1;
            }
            FramingStep::Request(Request::Bytes {
                request,
                source,
                range,
            }) => {
                assert_eq!(
                    recovery_left, 0,
                    "all predecessors must recover before decoding"
                );
                supply_bytes(machine, bytes, request, source, range);
            }
            FramingStep::Frame(frame) => {
                assert_eq!(recovery_left, 0);
                frames.push(frame.ordinal);
            }
            FramingStep::RetainEvidence(page) => {
                let saved = (page.commitment, page.bytes.to_vec());
                machine.acknowledge_retention(saved.0).unwrap();
                pages.push(saved);
            }
            FramingStep::Complete(pack) => {
                assert_eq!(recovery_left, 0);
                return (frames, pack);
            }
            FramingStep::Progress => (),
            _ => panic!("unexpected request"),
        }
    }
}

#[test]
fn decode_resume_at_every_acknowledged_entry_matches_uninterrupted_framing() {
    let raw = raw_pack();
    let mut cases = vec![
        raw.as_slice(),
        include_bytes!("../../../fixtures/framing/earlier-delta-base.bin").as_slice(),
    ];
    if cfg!(any(feature = "pack-ruzstd", feature = "pack-zstd")) {
        cases.push(include_bytes!(
            "../../../../../tests/golden/pack-v2/mixed.bin"
        ));
        cases.push(include_bytes!(
            "../../../../../tests/golden/pack-v2/large_literals.bin"
        ));
    }
    for bytes in cases {
        let entries = u64::from(u32::from_le_bytes(bytes[8..12].try_into().unwrap()));
        let mut original = machine(bytes);
        let mut pages = Vec::new();
        let mut results = Vec::new();
        let mut count = 0;
        let final_pack = loop {
            match original.step().unwrap() {
                FramingStep::Request(Request::Bytes {
                    request,
                    source,
                    range,
                }) => supply_bytes(&mut original, bytes, request, source, range),
                FramingStep::Frame(frame) => {
                    assert_eq!(frame.ordinal, count);
                    count += 1;
                }
                FramingStep::RetainEvidence(page) => {
                    let saved = (page.commitment, page.bytes.to_vec());
                    original.acknowledge_retention(saved.0).unwrap();
                    pages.push(saved);
                    let cp = snapshot(&mut original);
                    assert_eq!(cp.meta().phase, CheckpointPhase::Decode);
                    let mut resumed = restore(&cp, 18);
                    assert!(resumed.usage().work > cp.meta().usage.work);
                    assert_eq!(
                        resumed.usage().resident_bytes,
                        std::mem::size_of::<FramingDriver>() as u64 + resumed.decoder_reservation
                    );
                    assert!(
                        resumed.usage().peak_resident_bytes >= cp.meta().usage.peak_resident_bytes
                    );
                    let (remaining, pack) = complete(&mut resumed, bytes, &mut pages.clone());
                    assert_eq!(remaining, (count..entries).collect::<Vec<_>>());
                    assert!(resumed.usage().peak_resident_bytes <= limits().resident_bytes);
                    results.push(pack);
                }
                FramingStep::Complete(pack) => break pack,
                FramingStep::Progress => (),
                _ => panic!(),
            }
        };
        assert_eq!(count, entries);
        assert_eq!(results.len() as u64, entries);
        for result in results {
            assert_eq!(result, final_pack);
        }
    }
}

fn altered(cp: &Checkpoint, change: impl FnOnce(&mut CheckpointMeta)) -> Checkpoint {
    let state = cp.decode(cp.meta().limits).unwrap();
    let mut meta = state.meta;
    change(&mut meta);
    checkpoint::encode(
        &CheckpointView {
            meta,
            integrity: None,
            cursor: &state.cursor,
        },
        meta.limits,
    )
    .unwrap()
}
#[test]
fn decode_resume_refuses_every_mismatched_cursor_binding() {
    let bytes = raw_pack();
    let (cp, _) = first_snapshot(&bytes);
    let changes: [fn(&mut CheckpointMeta); 8] = [
        |m| m.source.len += 1,
        |m| m.limits.acquisition_bytes *= 2,
        |m| m.payload += 1,
        |m| m.payload -= 1,
        |m| m.header.as_mut().unwrap().0 = 2,
        |m| m.header.as_mut().unwrap().1 += 1,
        |m| {
            m.ordinal += 1;
            m.retention_count += 1;
            m.usage.evidence_pages += 1;
        },
        |m| m.source.id[0] ^= 1,
    ];
    for (index, change) in changes.into_iter().enumerate() {
        let bad = altered(&cp, change);
        let m = bad.meta();
        let err = FramingDriver::resume(m.source, m.repository, m.profile, m.limits, 18, &bad)
            .unwrap_err();
        assert_eq!(
            err.code,
            FailureCode::InvalidCheckpoint,
            "binding case {index}"
        );
    }
}

#[test]
fn decode_resume_missing_pages_and_changed_consumed_prefix_never_advance() {
    let bytes = raw_pack();
    let (cp, pages) = first_snapshot(&bytes);
    let mut resumed = restore(&cp, 18);
    let FramingStep::Request(Request::EvidencePage { request, page }) = resumed.step().unwrap()
    else {
        panic!()
    };
    let stale = crate::pack_verify::RequestId {
        generation: 17,
        ..request
    };
    assert_eq!(
        resumed
            .supply(Response::EvidencePage {
                request: stale,
                page,
                value: Acquisition::Present(&pages[0].1)
            })
            .unwrap_err()
            .code,
        FailureCode::InvalidResponse
    );
    for missing in [Acquisition::Absent, Acquisition::Unavailable] {
        assert_eq!(
            resumed
                .supply(Response::EvidencePage {
                    request,
                    page,
                    value: missing
                })
                .unwrap_err()
                .code,
            FailureCode::UnavailableInput
        );
        assert!(
            matches!(resumed.step().unwrap(), FramingStep::Request(Request::EvidencePage { request: again, .. }) if again == request)
        );
    }
    resumed
        .supply(Response::EvidencePage {
            request,
            page,
            value: Acquisition::Present(&pages[0].1),
        })
        .unwrap();
    let FramingStep::Request(Request::Bytes {
        request,
        source,
        range,
    }) = resumed.step().unwrap()
    else {
        panic!()
    };
    let mut changed = bytes[usize::try_from(range.offset).unwrap()
        ..usize::try_from(range.offset + range.len).unwrap()]
        .to_vec();
    changed[0] ^= 1;
    assert_eq!(
        resumed
            .supply(Response::Bytes {
                request,
                source,
                range,
                value: Acquisition::Present(&changed)
            })
            .unwrap_err()
            .code,
        FailureCode::PackfileCorrupted
    );
    assert!(resumed.step().is_err());
}

#[test]
fn warm_checkpoints_and_cold_window_admission_keep_cumulative_work() {
    let bytes = raw_pack();
    let (cp, pages) = first_snapshot(&bytes);
    let mut resumed = restore(&cp, 18);
    let FramingStep::Request(Request::EvidencePage { request, page }) = resumed.step().unwrap()
    else {
        panic!()
    };
    resumed
        .supply(Response::EvidencePage {
            request,
            page,
            value: Acquisition::Present(&pages[0].1),
        })
        .unwrap();
    let FramingStep::Request(Request::Bytes {
        request,
        source,
        range,
    }) = resumed.step().unwrap()
    else {
        panic!()
    };
    let before = resumed.usage().work;
    supply_bytes(&mut resumed, &bytes, request, source, range);
    assert_eq!(resumed.usage().work - before, 4 * range.len);
    let before = resumed.usage().work;
    let next = snapshot(&mut resumed);
    let first = resumed.usage().work - before;
    let before = resumed.usage().work;
    let _ = snapshot(&mut resumed);
    assert_eq!(resumed.usage().work - before, first);
    assert!(
        first < 2 * limits().acquisition_bytes,
        "fixed checkpoint work, no window surcharge"
    );
    let again = restore(&next, 19);
    assert!(again.usage().work > next.meta().usage.work);

    let tight = altered(&cp, |m| m.usage.work = m.limits.work - 1);
    let m = tight.meta();
    assert_eq!(
        FramingDriver::resume(m.source, m.repository, m.profile, m.limits, 18, &tight)
            .unwrap_err()
            .code,
        FailureCode::ResourceLimit
    );
    let tight = altered(&cp, |m| {
        m.limits.resident_bytes = m.usage.peak_resident_bytes;
        m.limits.checkpoint_bytes = m.limits.resident_bytes;
    });
    let m = tight.meta();
    assert_eq!(
        FramingDriver::resume(m.source, m.repository, m.profile, m.limits, 18, &tight)
            .unwrap_err()
            .code,
        FailureCode::ResourceLimit
    );
}

#[test]
fn decode_resume_requires_the_cursors_expected_whole_pack_identity() {
    let bytes = raw_pack();
    let (cp, _) = first_snapshot(&bytes);
    let mut reader = WindowReader::new(
        bytes.len() as u64,
        limits().acquisition_bytes,
        DecodeLimits::default(),
        None,
    )
    .unwrap();
    let cursor = loop {
        match reader.step().unwrap() {
            mkit_core::pack::window::Step::NeedWindow(range) => {
                let start = usize::try_from(range.offset).unwrap();
                reader
                    .feed(
                        range.offset,
                        &bytes[start..start + usize::try_from(range.len).unwrap()],
                    )
                    .unwrap();
            }
            mkit_core::pack::window::Step::Entry(_) => break reader.checkpoint().unwrap(),
            _ => panic!(),
        }
    };
    assert_eq!(cursor.metadata().unwrap().expected_pack_id(), None);
    let cursor_bytes = cursor.to_bytes();
    let changed = checkpoint::encode(
        &CheckpointView {
            meta: cp.meta(),
            integrity: None,
            cursor: &cursor_bytes,
        },
        limits(),
    )
    .unwrap();
    let m = changed.meta();
    assert_eq!(
        FramingDriver::resume(m.source, m.repository, m.profile, m.limits, 18, &changed)
            .unwrap_err()
            .code,
        FailureCode::InvalidCheckpoint
    );
}

#[test]
fn cold_window_admission_refuses_before_decoder_progress() {
    let bytes = raw_pack();
    let (cp, pages) = first_snapshot(&bytes);
    let mut resumed = restore(&cp, 18);
    let FramingStep::Request(Request::EvidencePage { request, page }) = resumed.step().unwrap()
    else {
        panic!()
    };
    resumed
        .supply(Response::EvidencePage {
            request,
            page,
            value: Acquisition::Present(&pages[0].1),
        })
        .unwrap();
    let FramingStep::Request(Request::Bytes {
        request,
        source,
        range,
    }) = resumed.step().unwrap()
    else {
        panic!()
    };
    let remaining = limits().work - resumed.usage().work;
    resumed
        .resources
        .work(remaining - 4 * range.len + 1)
        .unwrap();
    let before = resumed.usage();
    let begin = usize::try_from(range.offset).unwrap();
    assert_eq!(
        resumed
            .supply(Response::Bytes {
                request,
                source,
                range,
                value: Acquisition::Present(
                    &bytes[begin..begin + usize::try_from(range.len).unwrap()]
                )
            })
            .unwrap_err()
            .code,
        FailureCode::ResourceLimit
    );
    assert_eq!(resumed.usage(), before);
    assert!(resumed.step().is_err());
}
