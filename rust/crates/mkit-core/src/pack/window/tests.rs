use super::*;
use crate::hash;
use crate::pack::{PackEntries, PackWriter};
use proptest::prelude::*;
use std::path::{Path, PathBuf};

const WINDOW: u64 = 64 * 1024;

#[derive(Debug, PartialEq, Eq)]
enum Value {
    Raw(Vec<u8>),
    Delta(Hash, Vec<u8>),
}

fn value(entry: PackEntry<'_>) -> Value {
    match entry {
        PackEntry::Raw { bytes } => Value::Raw(bytes.into_owned()),
        PackEntry::Delta { base, stream } => Value::Delta(base, stream.into_owned()),
    }
}

fn buffered(pack: &[u8]) -> Result<(Vec<Value>, WindowSummary), PackError> {
    let entries = PackEntries::new(pack)?;
    let summary = WindowSummary {
        version: u32::from_le_bytes(pack[4..8].try_into().unwrap()),
        entry_count: u32::try_from(entries.entry_count()).unwrap(),
        raw_only: entries.is_raw_only(),
        first_non_raw: entries.first_non_raw_index(),
    };
    let values = entries
        .map(|entry| entry.map(value))
        .collect::<Result<_, _>>()?;
    Ok((values, summary))
}

fn windowed(
    pack: &[u8],
    window: u64,
    limits: DecodeLimits,
    expected: Option<Hash>,
) -> Result<(Vec<Value>, WindowSummary), PackError> {
    let mut values = Vec::new();
    let mut source = pack;
    let summary = read_all(
        &mut source,
        u64::try_from(pack.len()).unwrap(),
        window,
        limits,
        expected,
        |entry| {
            values.push(value(entry));
            Ok(())
        },
    )?;
    Ok((values, summary))
}

fn differential(pack: &[u8], window: u64) {
    differential_with_id(pack, window, None);
}

fn differential_with_id(pack: &[u8], window: u64, expected: Option<Hash>) {
    let reference = buffered(pack);
    let actual = windowed(pack, window, DecodeLimits::default(), expected);
    match (reference, actual) {
        (Ok(reference), Ok(actual)) => assert_eq!(reference, actual),
        (Err(_), Err(_)) => {}
        (reference, actual) => {
            panic!("buffered/window disagreement at window {window}: {reference:?} / {actual:?}")
        }
    }
}

fn finish_bytes(mut bytes: Vec<u8>) -> Vec<u8> {
    bytes.extend_from_slice(&hash::hash(&bytes));
    bytes
}

fn synthetic(version: u32, entries: &[(u8, Vec<u8>)]) -> Vec<u8> {
    let mut bytes = MAGIC.to_vec();
    bytes.extend_from_slice(&version.to_le_bytes());
    bytes.extend_from_slice(&u32::try_from(entries.len()).unwrap().to_le_bytes());
    for (kind, payload) in entries {
        bytes.push(*kind);
        bytes.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_le_bytes());
        bytes.extend_from_slice(payload);
    }
    finish_bytes(bytes)
}

fn raw_pack(payloads: &[Vec<u8>]) -> Vec<u8> {
    let mut writer = PackWriter::new_raw_only();
    for bytes in payloads {
        writer.push_raw(hash::hash(bytes), bytes).unwrap();
    }
    writer.finish().unwrap()
}

fn assert_request_geometry(reader: &WindowReader, request: WindowRequest) {
    assert_eq!(request.offset % reader.state.window_size, 0);
    assert_eq!(
        request.len,
        reader
            .state
            .window_size
            .min(reader.state.pack_len - request.offset)
    );
}

fn feed_from(reader: &mut WindowReader, pack: &[u8], request: WindowRequest) {
    assert_request_geometry(reader, request);
    let from = usize::try_from(request.offset).unwrap();
    let to = usize::try_from(request.offset + request.len).unwrap();
    reader.feed(request.offset, &pack[from..to]).unwrap();
}

fn drive(reader: &mut WindowReader, pack: &[u8]) -> Result<(Vec<Value>, WindowSummary), PackError> {
    drive_from(reader, pack, 0)
}

fn drive_from(
    reader: &mut WindowReader,
    pack: &[u8],
    minimum_offset: u64,
) -> Result<(Vec<Value>, WindowSummary), PackError> {
    let mut values = Vec::new();
    loop {
        match reader.step()? {
            Step::NeedWindow(request) => {
                assert_request_geometry(reader, request);
                assert!(
                    request.offset >= minimum_offset,
                    "a resume must not re-read completed windows"
                );
                let mut source = pack;
                let bytes = source.read_window(request.offset, request.len)?;
                reader.feed(request.offset, &bytes)?;
            }
            Step::Entry(entry) => values.push(value(entry)),
            Step::Done(summary) => return Ok((values, summary)),
        }
    }
}

fn golden_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/golden")
}

fn pack_fixtures(directory: &Path, out: &mut Vec<PathBuf>) {
    let mut children = std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    children.sort();
    for path in children {
        if path.is_dir() {
            pack_fixtures(&path, out);
        } else if path.extension().is_some_and(|extension| extension == "bin") {
            let bytes = std::fs::read(&path).unwrap();
            if bytes.starts_with(MAGIC) {
                out.push(path);
            }
        }
    }
}

#[test]
fn every_pack_golden_agrees_at_both_window_sizes() {
    let mut paths = Vec::new();
    pack_fixtures(&golden_root(), &mut paths);
    assert!(
        paths
            .iter()
            .any(|path| path.ends_with("pack-v2/large_literals.bin"))
    );
    assert!(
        paths
            .iter()
            .any(|path| path.parent().unwrap() != golden_root().join("pack-v2"))
    );
    for path in paths {
        let bytes = std::fs::read(&path).unwrap();
        for window in [WINDOW, 1024 * 1024] {
            differential(&bytes, window);
        }
    }
}

fn generated_pack(entries: &[(bool, bool, Vec<u8>)]) -> Vec<u8> {
    let mut writer = PackWriter::new();
    writer
        .push_raw(hash::hash(b"raw seed"), b"raw seed")
        .unwrap();
    writer
        .push_delta(&hash::hash(b"raw seed"), b"tiny delta")
        .unwrap();
    // Native writers emit 0x03 and 0x04 here. Ruzstd-only writers emit the
    // equivalent v1 entries; golden tests supply compressed inputs there.
    writer.push_raw(hash::hash(&[7; 2048]), &[7; 2048]).unwrap();
    writer
        .push_delta(&hash::hash(b"raw seed"), &[9; 2048])
        .unwrap();
    for (delta, repeated, bytes) in entries {
        let bytes = if *repeated {
            vec![bytes.first().copied().unwrap_or(0); 2048 + bytes.len()]
        } else {
            bytes.clone()
        };
        if *delta {
            writer.push_delta(&hash::hash(b"raw seed"), &bytes).unwrap();
        } else {
            writer.push_raw(hash::hash(&bytes), &bytes).unwrap();
        }
    }
    writer.finish().unwrap()
}

fn prepend_padding(pack: &[u8], window: u64) -> Vec<u8> {
    let padding = raw_pack(&[vec![0xa5; usize::try_from(window).unwrap()]]);
    let mut bytes = pack[..12].to_vec();
    let count = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    bytes[8..12].copy_from_slice(&(count + 1).to_le_bytes());
    bytes.extend_from_slice(&padding[12..padding.len() - 32]);
    bytes.extend_from_slice(&pack[12..pack.len() - 32]);
    finish_bytes(bytes)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(40))]

    #[test]
    fn generated_valid_and_mutated_packs_agree(
        entries in prop::collection::vec((any::<bool>(), any::<bool>(), prop::collection::vec(any::<u8>(), 0..384)), 0..12),
        mutation in any::<usize>(),
        bit in 0u8..8,
    ) {
        let generated = generated_pack(&entries);
        for window in [WINDOW, 1024 * 1024] {
            let pack = prepend_padding(&generated, window);
            assert!(buffered(&pack).is_ok());
            let after_padding = 17 + usize::try_from(window).unwrap();
            assert!(after_padding > usize::try_from(window).unwrap());
            let mut flipped = pack.clone();
            let at = after_padding + mutation % (flipped.len() - after_padding);
            flipped[at] ^= 1 << bit;
            let mut framing_mutation = flipped.clone();
            let split = framing_mutation.len() - 32;
            let checksum = hash::hash(&framing_mutation[..split]);
            framing_mutation[split..].copy_from_slice(&checksum);
            let truncated = &pack[..after_padding + mutation % (pack.len() - after_padding)];
            let mut extra = pack.clone();
            extra.extend_from_slice(&[bit, 0xa5]);
            let mut trailing = pack[..pack.len() - 32].to_vec();
            trailing.push(bit);
            let trailing = finish_bytes(trailing);
            for input in [pack.as_slice(), flipped.as_slice(), framing_mutation.as_slice(), truncated, extra.as_slice(), trailing.as_slice()] {
                for expected in [None, Some(hash::hash(input))] {
                    differential_with_id(input, window, expected);
                }
            }
        }
    }

    #[test]
    fn generated_header_and_payload_straddles_agree(
        header_bytes_before_boundary in 0usize..5,
        payload in prop::collection::vec(any::<u8>(), 0..2048),
    ) {
        // The padding frame positions the next frame at W - 0..4.
        let padding_len = usize::try_from(WINDOW).unwrap() - 17 - header_bytes_before_boundary;
        let pack = synthetic(1, &[(0, vec![0x33; padding_len]), (0, payload), (0, vec![0x44; 2 * usize::try_from(WINDOW).unwrap() + 7])]);
        differential(&pack, WINDOW);
        differential(&pack, 1024 * 1024);
    }
}

#[test]
fn compressed_frames_and_claim_prefixes_straddle_boundaries() {
    for name in [
        "raw_4k_repeat.bin",
        "delta_repeat.bin",
        "large_literals.bin",
    ] {
        let golden = std::fs::read(golden_root().join("pack-v2").join(name)).unwrap();
        let count = u32::from_le_bytes(golden[8..12].try_into().unwrap());
        let mut frames = Vec::new();
        let mut pos = 12;
        for _ in 0..count {
            let kind = golden[pos];
            let len = usize::try_from(u32::from_le_bytes(
                golden[pos + 1..pos + 5].try_into().unwrap(),
            ))
            .unwrap();
            pos += 5;
            frames.push((kind, golden[pos..pos + len].to_vec()));
            pos += len;
        }
        let first_compressed = frames
            .iter()
            .find(|(kind, _)| matches!(kind, 3 | 4))
            .unwrap();
        for window in [WINDOW, 1024 * 1024] {
            // Split each frame-header byte, the base hash, and the claim prefix.
            for cut in [1, 2, 3, 4, 5, 31, 32, 33, 34, 35, 36] {
                let padding = usize::try_from(window).unwrap() - 22 - cut;
                let pack = synthetic(2, &[(0, vec![0x65; padding]), first_compressed.clone()]);
                differential(&pack, window);
                if buffered(&pack).is_ok() {
                    resume_each_entry(&pack, window, Some(hash::hash(&pack)));
                }
            }
            for before in 0..5 {
                let padding = usize::try_from(window).unwrap() - 17 - before;
                let pack = synthetic(2, &[(0, vec![0x65; padding]), first_compressed.clone()]);
                differential(&pack, window);
            }
        }
    }
}

#[test]
fn malformed_zstd_claims_and_frames_agree_with_buffered_errors() {
    let golden = std::fs::read(golden_root().join("pack-v2/raw_4k_repeat.bin")).unwrap();
    let mut payload = golden[17..golden.len() - 32].to_vec();
    for short in 0..4 {
        differential(&synthetic(2, &[(3, payload[..short].to_vec())]), WINDOW);
    }
    for claim in [0u32, 4095, 4097, 1024 * 1024 * 1024 + 1, u32::MAX] {
        payload[..4].copy_from_slice(&claim.to_le_bytes());
        differential(&synthetic(2, &[(3, payload.clone())]), WINDOW);
    }
    payload[..4].copy_from_slice(&4096u32.to_le_bytes());
    payload[4] ^= 1;
    differential(&synthetic(2, &[(3, payload)]), WINDOW);
}

#[test]
fn frame_headers_split_at_every_byte_and_empty_entries_at_boundaries() {
    for window in [WINDOW, 1024 * 1024] {
        for before in 0..5 {
            let padding = usize::try_from(window).unwrap() - 17 - before;
            let pack = synthetic(
                1,
                &[
                    (0, vec![0x61; padding]),
                    (0, Vec::new()),
                    (2, vec![0x72; 39]),
                    (0, vec![0x83; usize::try_from(window * 2 + 3).unwrap()]),
                ],
            );
            differential(&pack, window);
            resume_each_entry(&pack, window, None);
        }
    }
}

fn resume_each_entry(pack: &[u8], window: u64, expected: Option<Hash>) {
    let reference = buffered(pack).unwrap();
    let mut reader = WindowReader::new(
        u64::try_from(pack.len()).unwrap(),
        window,
        DecodeLimits::default(),
        expected,
    )
    .unwrap();
    assert!(reader.checkpoint().is_none());
    let mut values = Vec::new();
    loop {
        match reader.step().unwrap() {
            Step::NeedWindow(request) => feed_from(&mut reader, pack, request),
            Step::Entry(entry) => {
                values.push(value(entry));
                let cursor = reader.checkpoint().unwrap();
                let bytes = cursor.to_bytes();
                assert!(bytes.len() <= 4096);
                let cursor = WindowCursor::from_bytes(&bytes).unwrap();
                assert_eq!(cursor.to_bytes(), bytes);
                reader = WindowReader::resume(&cursor, DecodeLimits::default()).unwrap();
                assert_eq!(
                    reader.checkpoint().is_some(),
                    cursor.pos.is_multiple_of(window)
                );
                let Step::NeedWindow(request) = reader.step().unwrap() else {
                    panic!("resume must request a window")
                };
                assert_eq!(
                    reader.checkpoint().is_some(),
                    cursor.pos.is_multiple_of(window)
                );
                assert_eq!(request.offset, cursor.pos / window * window);
                feed_from(&mut reader, pack, request);
            }
            Step::Done(summary) => {
                assert_eq!((values, summary), reference);
                return;
            }
        }
    }
}

#[test]
fn checkpoint_after_every_entry_matches_all_valid_pack_v2_goldens() {
    let mut paths = Vec::new();
    pack_fixtures(&golden_root().join("pack-v2"), &mut paths);
    for path in paths {
        let pack = std::fs::read(path).unwrap();
        if buffered(&pack).is_ok() {
            for window in [WINDOW, 1024 * 1024] {
                resume_each_entry(&pack, window, None);
                resume_each_entry(&pack, window, Some(hash::hash(&pack)));
            }
        }
    }
}

fn first_cursor(pack: &[u8], expected: Option<Hash>) -> WindowCursor {
    let mut reader = WindowReader::new(
        u64::try_from(pack.len()).unwrap(),
        WINDOW,
        DecodeLimits::default(),
        expected,
    )
    .unwrap();
    loop {
        match reader.step().unwrap() {
            Step::NeedWindow(request) => feed_from(&mut reader, pack, request),
            Step::Entry(_) => return reader.checkpoint().unwrap(),
            Step::Done(_) => panic!("fixture needs an entry"),
        }
    }
}

fn resign_cursor(bytes: &mut [u8]) {
    let split = bytes.len() - 32;
    let checksum = hash::hash(&bytes[..split]);
    bytes[split..].copy_from_slice(&checksum);
}

#[test]
fn cursors_reject_corruption_truncation_version_and_inconsistent_fields() {
    let pack = raw_pack(&[
        vec![0x11; 2 * usize::try_from(WINDOW).unwrap()],
        vec![0x22; 33],
    ]);
    let cursor = first_cursor(&pack, Some(hash::hash(&pack)));
    let bytes = cursor.to_bytes();
    for length in 0..bytes.len() {
        assert!(matches!(
            WindowCursor::from_bytes(&bytes[..length]),
            Err(PackError::PackfileCorrupted)
        ));
    }
    for at in 0..bytes.len() {
        let mut corrupt = bytes.clone();
        corrupt[at] ^= 1;
        assert!(matches!(
            WindowCursor::from_bytes(&corrupt),
            Err(PackError::PackfileCorrupted)
        ));
    }
    let mut wrong_version = bytes.clone();
    wrong_version[0] = 2;
    resign_cursor(&mut wrong_version);
    assert!(matches!(
        WindowCursor::from_bytes(&wrong_version),
        Err(PackError::PackfileCorrupted)
    ));
    for (offset, value) in [(17, 11u64), (17, cursor.pack_len), (25, u64::MAX)] {
        let mut bad = bytes.clone();
        bad[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        resign_cursor(&mut bad);
        assert!(matches!(
            WindowCursor::from_bytes(&bad),
            Err(PackError::PackfileCorrupted)
        ));
    }
    let mut bad_index = bytes.clone();
    bad_index[41..45].copy_from_slice(&(cursor.count + 1).to_le_bytes());
    resign_cursor(&mut bad_index);
    assert!(matches!(
        WindowCursor::from_bytes(&bad_index),
        Err(PackError::PackfileCorrupted)
    ));
    let mut bad_stack = cursor.clone();
    bad_stack.trailer_tree.stack.clear();
    assert!(matches!(
        WindowCursor::from_bytes(&bad_stack.to_bytes()),
        Err(PackError::PackfileCorrupted)
    ));
    assert!(matches!(
        WindowReader::resume(&bad_stack, DecodeLimits::default()),
        Err(PackError::PackfileCorrupted)
    ));
    let mut oversized = bytes;
    oversized.resize(4097, 0);
    assert!(matches!(
        WindowCursor::from_bytes(&oversized),
        Err(PackError::PackfileCorrupted)
    ));
}

#[test]
fn changed_verified_prefix_preserves_entries_of_the_original_verified_pack() {
    let pack = raw_pack(&[
        vec![0x11; usize::try_from(WINDOW * 2 + 23).unwrap()],
        vec![0x22; 77],
    ]);
    for expected in [None, Some(hash::hash(&pack))] {
        let cursor = first_cursor(&pack, expected);
        assert!(cursor.completed > 0);
        for update_trailer in [false, true] {
            // Mutation is entirely in a completed window: the suffix and all
            // resumed entry bytes stay identical. Stored CVs and previously
            // yielded entries still belong to the original verified pack.
            let mut other = pack.clone();
            other[19] ^= 1;
            if update_trailer {
                let split = other.len() - 32;
                let checksum = hash::hash(&other[..split]);
                other[split..].copy_from_slice(&checksum);
            }
            let mut resumed = WindowReader::resume(
                &WindowCursor::from_bytes(&cursor.to_bytes()).unwrap(),
                DecodeLimits::default(),
            )
            .unwrap();
            let result = drive_from(&mut resumed, &other, cursor.completed * WINDOW);
            if update_trailer {
                assert!(matches!(result, Err(PackError::PackfileCorrupted)));
            } else {
                let (remaining, summary) = result.unwrap();
                let mut yielded = vec![Value::Raw(vec![
                    0x11;
                    usize::try_from(WINDOW * 2 + 23).unwrap()
                ])];
                yielded.extend(remaining);
                assert_eq!((yielded, summary), buffered(&pack).unwrap());
            }
        }
        let mut wrong_length = cursor.clone();
        wrong_length.pack_len = 43;
        assert!(matches!(
            WindowReader::resume(&wrong_length, DecodeLimits::default()),
            Err(PackError::PackfileCorrupted)
        ));
    }
}

#[test]
fn fix_round_one_resuming_genuine_pack_rejects_a_tampered_yielded_prefix_on_feed() {
    let genuine = raw_pack(&[vec![0x11; 21], vec![0x22; 77]]);
    let mut tampered = genuine.clone();
    tampered[19] ^= 1;
    for expected in [None, Some(hash::hash(&genuine))] {
        let cursor = first_cursor(&tampered, expected);
        assert_eq!(cursor.completed, 0);
        let cursor = WindowCursor::from_bytes(&cursor.to_bytes()).unwrap();
        let mut resumed = WindowReader::resume(&cursor, DecodeLimits::default()).unwrap();
        let Step::NeedWindow(request) = resumed.step().unwrap() else {
            panic!()
        };
        let from = usize::try_from(request.offset).unwrap();
        let to = usize::try_from(request.offset + request.len).unwrap();
        assert!(
            matches!(
                resumed.feed(request.offset, &genuine[from..to]),
                Err(PackError::PackfileCorrupted)
            ),
            "a previously yielded tampered prefix must fail on the first resumed feed"
        );
    }
}

#[test]
fn probe_shaped_resume_rejects_tampered_entry_in_checkpoint_window() {
    let genuine = raw_pack(&[
        vec![0x61; usize::try_from(WINDOW).unwrap() - 14],
        vec![0x11; 100],
        vec![0x22; usize::try_from(WINDOW + 50).unwrap()],
    ]);
    let mut tampered = genuine.clone();
    tampered[usize::try_from(WINDOW).unwrap() + 8 + 10] ^= 1;
    for expected in [None, Some(hash::hash(&genuine))] {
        let mut original = WindowReader::new(
            u64::try_from(tampered.len()).unwrap(),
            WINDOW,
            DecodeLimits::default(),
            expected,
        )
        .unwrap();
        let mut yielded = Vec::new();
        let cursor = loop {
            match original.step().unwrap() {
                Step::NeedWindow(request) => feed_from(&mut original, &tampered, request),
                Step::Entry(entry) => {
                    yielded.push(value(entry));
                    if yielded.len() == 2 {
                        break original.checkpoint().unwrap();
                    }
                    assert_eq!(original.state.pos, WINDOW + 3);
                }
                Step::Done(_) => panic!("the probe needs a cursor after entry A"),
            }
        };
        assert_ne!(yielded[1], Value::Raw(vec![0x11; 100]));
        assert_eq!(cursor.index, 2);
        assert_eq!(cursor.completed, 1);
        assert_eq!(cursor.pos, WINDOW + 108);
        let mut resumed = WindowReader::resume(
            &WindowCursor::from_bytes(&cursor.to_bytes()).unwrap(),
            DecodeLimits::default(),
        )
        .unwrap();
        let Step::NeedWindow(request) = resumed.step().unwrap() else {
            panic!()
        };
        assert_eq!(request.offset, WINDOW);
        let start = usize::try_from(request.offset).unwrap();
        let end = usize::try_from(request.offset + request.len).unwrap();
        assert!(matches!(
            resumed.feed(request.offset, &genuine[start..end]),
            Err(PackError::PackfileCorrupted)
        ));
    }
}

#[test]
fn fix_round_one_checkpoint_is_absent_when_its_boundary_window_was_released() {
    let pack = raw_pack(&[vec![0x53; 65_537 - 49]]);
    assert_eq!(pack.len(), 65_537);
    let mut reader = WindowReader::new(
        65_537,
        WINDOW,
        DecodeLimits::default(),
        Some(hash::hash(&pack)),
    )
    .unwrap();
    let Step::NeedWindow(request) = reader.step().unwrap() else {
        panic!()
    };
    feed_from(&mut reader, &pack, request);
    let Step::Entry(entry) = reader.step().unwrap() else {
        panic!()
    };
    let yielded = value(entry);
    let retained = reader.checkpoint().unwrap();
    assert_eq!(retained.pos, 65_505);
    let Step::NeedWindow(request) = reader.step().unwrap() else {
        panic!()
    };
    assert_eq!(request.offset, WINDOW);
    assert!(reader.window.is_empty());
    assert!(
        reader.checkpoint().is_none(),
        "the partial boundary window is no longer resident"
    );
    feed_from(&mut reader, &pack, request);
    let Step::Done(summary) = reader.step().unwrap() else {
        panic!()
    };
    assert!(reader.checkpoint().is_none());
    let mut resumed = WindowReader::resume(
        &WindowCursor::from_bytes(&retained.to_bytes()).unwrap(),
        DecodeLimits::default(),
    )
    .unwrap();
    let (remaining, resumed_summary) = drive(&mut resumed, &pack).unwrap();
    assert!(remaining.is_empty());
    assert_eq!(resumed_summary, summary);
    assert_eq!((vec![yielded], summary), buffered(&pack).unwrap());
}

#[test]
fn cursors_bind_same_window_prefix_and_unseen_future_entries() {
    let pack = raw_pack(&[
        vec![0x11; 21],
        vec![0x22; usize::try_from(WINDOW + 73).unwrap()],
    ]);
    for expected in [None, Some(hash::hash(&pack))] {
        let cursor = first_cursor(&pack, expected);
        assert_eq!(cursor.completed, 0);
        for changed_offset in [19, usize::try_from(WINDOW).unwrap() + 1] {
            let mut other = pack.clone();
            other[changed_offset] ^= 1;
            let split = other.len() - 32;
            let checksum = hash::hash(&other[..split]);
            other[split..].copy_from_slice(&checksum);
            assert!(buffered(&other).is_ok());
            let cursor = WindowCursor::from_bytes(&cursor.to_bytes()).unwrap();
            let mut resumed = WindowReader::resume(&cursor, DecodeLimits::default()).unwrap();
            assert!(matches!(
                drive(&mut resumed, &other),
                Err(PackError::PackfileCorrupted)
            ));
        }
    }
}

#[test]
fn a_same_window_mutation_after_the_cursor_is_rejected_at_done() {
    let genuine = raw_pack(&[vec![0x11; 21], vec![0x22; 77]]);
    for expected in [None, Some(hash::hash(&genuine))] {
        let cursor = first_cursor(&genuine, expected);
        let mut tampered = genuine.clone();
        let at = usize::try_from(cursor.pos).unwrap() + 5;
        assert!(at < usize::try_from(WINDOW).unwrap());
        tampered[at] ^= 1;
        let mut resumed = WindowReader::resume(
            &WindowCursor::from_bytes(&cursor.to_bytes()).unwrap(),
            DecodeLimits::default(),
        )
        .unwrap();
        assert!(resumed.checkpoint().is_none());
        let Step::NeedWindow(request) = resumed.step().unwrap() else {
            panic!()
        };
        assert!(resumed.checkpoint().is_none());
        feed_from(&mut resumed, &tampered, request);
        let Step::Entry(entry) = resumed.step().unwrap() else {
            panic!()
        };
        assert_ne!(value(entry), Value::Raw(vec![0x22; 77]));
        assert!(matches!(resumed.step(), Err(PackError::PackfileCorrupted)));
        assert!(resumed.checkpoint().is_none());
    }
}

#[test]
fn exact_window_boundary_checkpoint_needs_no_resident_window() {
    let pack = raw_pack(&[vec![0x61; usize::try_from(WINDOW).unwrap() - 17]]);
    let mut reader = WindowReader::new(
        u64::try_from(pack.len()).unwrap(),
        WINDOW,
        DecodeLimits::default(),
        Some(hash::hash(&pack)),
    )
    .unwrap();
    assert!(reader.checkpoint().is_none());
    let Step::NeedWindow(request) = reader.step().unwrap() else {
        panic!()
    };
    assert!(reader.checkpoint().is_none());
    feed_from(&mut reader, &pack, request);
    assert!(matches!(reader.step().unwrap(), Step::Entry(_)));
    let retained = reader.checkpoint().unwrap();
    assert_eq!(retained.pos, WINDOW);
    assert!(retained.window_prefix.is_none());
    let Step::NeedWindow(request) = reader.step().unwrap() else {
        panic!()
    };
    assert!(reader.window.is_empty());
    assert!(reader.checkpoint().is_some());
    feed_from(&mut reader, &pack, request);
    assert!(matches!(reader.step().unwrap(), Step::Done(_)));
    assert!(reader.checkpoint().is_some());
    let mut resumed = WindowReader::resume(
        &WindowCursor::from_bytes(&retained.to_bytes()).unwrap(),
        DecodeLimits::default(),
    )
    .unwrap();
    assert!(resumed.window.is_empty());
    assert!(resumed.checkpoint().is_some());
    assert!(drive(&mut resumed, &pack).unwrap().0.is_empty());
}

#[test]
fn cursor_prefix_presence_must_match_its_partial_window_geometry() {
    let partial_pack = raw_pack(&[vec![0x11; 21], vec![0x22; 77]]);
    let mut partial = first_cursor(&partial_pack, Some(hash::hash(&partial_pack)));
    assert!(partial.window_prefix.is_some());
    partial.window_prefix = None;
    assert!(matches!(
        WindowCursor::from_bytes(&partial.to_bytes()),
        Err(PackError::PackfileCorrupted)
    ));
    assert!(matches!(
        WindowReader::resume(&partial, DecodeLimits::default()),
        Err(PackError::PackfileCorrupted)
    ));
    let boundary_pack = raw_pack(&[vec![0x33; usize::try_from(WINDOW).unwrap() - 17]]);
    let mut boundary = first_cursor(&boundary_pack, Some(hash::hash(&boundary_pack)));
    assert_eq!(boundary.pos, WINDOW);
    assert!(boundary.window_prefix.is_none());
    boundary.window_prefix = Some([0x44; 32]);
    assert!(matches!(
        WindowCursor::from_bytes(&boundary.to_bytes()),
        Err(PackError::PackfileCorrupted)
    ));
    assert!(matches!(
        WindowReader::resume(&boundary, DecodeLimits::default()),
        Err(PackError::PackfileCorrupted)
    ));
}

#[test]
fn checkpoint_is_absent_mid_header_and_mid_payload() {
    let pack = synthetic(
        1,
        &[
            (0, vec![1; usize::try_from(WINDOW).unwrap() - 19]),
            (0, vec![2; usize::try_from(WINDOW * 2).unwrap()]),
        ],
    );
    let mut reader = WindowReader::new(
        u64::try_from(pack.len()).unwrap(),
        WINDOW,
        DecodeLimits::default(),
        Some(hash::hash(&pack)),
    )
    .unwrap();
    let Step::NeedWindow(request) = reader.step().unwrap() else {
        panic!()
    };
    feed_from(&mut reader, &pack, request);
    assert!(matches!(reader.step().unwrap(), Step::Entry(_)));
    assert!(reader.checkpoint().is_some());
    let Step::NeedWindow(request) = reader.step().unwrap() else {
        panic!()
    };
    assert!(reader.checkpoint().is_none());
    feed_from(&mut reader, &pack, request);
    let Step::NeedWindow(request) = reader.step().unwrap() else {
        panic!()
    };
    assert!(!reader.carry.is_empty());
    assert!(reader.checkpoint().is_none());
    feed_from(&mut reader, &pack, request);
    assert!(!reader.window.is_empty());
    assert!(!reader.carry.is_empty());
    assert_eq!(reader.start, WINDOW * 2);
    assert!(reader.checkpoint().is_none());
    let Step::NeedWindow(request) = reader.step().unwrap() else {
        panic!()
    };
    assert!(reader.checkpoint().is_none());
    feed_from(&mut reader, &pack, request);
    assert!(matches!(reader.step().unwrap(), Step::Entry(_)));
    assert!(reader.checkpoint().is_some());
}

#[test]
fn giant_zstd_claim_and_carried_payload_are_rejected_before_allocation() {
    let mut bomb = (1024u32 * 1024 * 1024).to_le_bytes().to_vec();
    bomb.extend_from_slice(&[0x28, 0xb5, 0x2f, 0xfd]);
    for kind in [3, 4] {
        let payload = if kind == 4 {
            [vec![0x42; 32], bomb.clone()].concat()
        } else {
            bomb.clone()
        };
        let pack = synthetic(2, &[(kind, payload)]);
        let mut reader = WindowReader::new(
            u64::try_from(pack.len()).unwrap(),
            WINDOW,
            DecodeLimits::default().with_max_decoded_bytes(16 * 1024 * 1024),
            None,
        )
        .unwrap();
        assert!(matches!(
            drive(&mut reader, &pack),
            Err(PackError::PackfileTooLarge)
        ));
        assert_eq!(reader.carry.capacity(), 0);
        assert!(reader.peak <= usize::try_from(WINDOW).unwrap());
    }
    let pack = raw_pack(&[vec![0x51; usize::try_from(WINDOW).unwrap()]]);
    assert!(buffered(&pack).is_ok());
    assert!(windowed(&pack, WINDOW, DecodeLimits::default(), None).is_ok());
    let mut reader = WindowReader::new(
        u64::try_from(pack.len()).unwrap(),
        WINDOW,
        DecodeLimits::default().with_max_decoded_bytes(1),
        None,
    )
    .unwrap();
    assert!(matches!(
        drive(&mut reader, &pack),
        Err(PackError::PackfileTooLarge)
    ));
    assert_eq!(reader.carry.capacity(), 0);
}

#[test]
fn a_late_zstd_claim_exceeds_budget_before_a_decode_allocation() {
    let mut claim = (1024u32 * 1024 * 1024).to_le_bytes().to_vec();
    claim.extend_from_slice(&[0x28, 0xb5, 0x2f, 0xfd]);
    for kind in [3, 4] {
        let payload = if kind == 4 {
            [vec![0x42; 32], claim.clone()].concat()
        } else {
            claim.clone()
        };
        let padding = usize::try_from(WINDOW).unwrap() - 22;
        let pack = synthetic(2, &[(0, vec![0x61; padding]), (kind, payload.clone())]);
        let mut reader = WindowReader::new(
            u64::try_from(pack.len()).unwrap(),
            WINDOW,
            DecodeLimits::default(),
            Some(hash::hash(&pack)),
        )
        .unwrap();
        let Step::NeedWindow(request) = reader.step().unwrap() else {
            panic!()
        };
        feed_from(&mut reader, &pack, request);
        assert!(matches!(reader.step().unwrap(), Step::Entry(_)));
        let cursor = reader.checkpoint().unwrap();
        assert_eq!(cursor.pos, WINDOW - 5);
        let budget = u64::try_from(payload.len()).unwrap();
        reader = WindowReader::resume(
            &WindowCursor::from_bytes(&cursor.to_bytes()).unwrap(),
            DecodeLimits::default().with_max_decoded_bytes(budget),
        )
        .unwrap();
        let Step::NeedWindow(request) = reader.step().unwrap() else {
            panic!()
        };
        assert_eq!(request.offset, 0);
        feed_from(&mut reader, &pack, request);
        let Step::NeedWindow(request) = reader.step().unwrap() else {
            panic!()
        };
        assert_eq!(request.offset, WINDOW);
        assert_eq!(reader.header_used, 5);
        assert!(reader.carry.is_empty());
        assert!(reader.checkpoint().is_none());
        feed_from(&mut reader, &pack, request);
        assert!(matches!(reader.step(), Err(PackError::PackfileTooLarge)));
        assert_eq!(reader.carry.capacity(), 0);
        assert!(reader.peak <= usize::try_from(WINDOW).unwrap());
        assert!(reader.checkpoint().is_none());
    }
}

#[test]
fn charged_peak_stays_within_one_window_plus_budget() {
    let budget = WINDOW * 3;
    let pack = raw_pack(&[
        vec![1; usize::try_from(WINDOW * 2 + 1).unwrap()],
        vec![2; 29],
        vec![3; usize::try_from(WINDOW + 23).unwrap()],
    ]);
    let mut reader = WindowReader::new(
        u64::try_from(pack.len()).unwrap(),
        WINDOW,
        DecodeLimits::default().with_max_decoded_bytes(budget),
        None,
    )
    .unwrap();
    let result = drive(&mut reader, &pack).unwrap();
    assert_eq!(result, buffered(&pack).unwrap());
    assert!(reader.peak > usize::try_from(WINDOW).unwrap());
    assert!(reader.peak <= usize::try_from(WINDOW + budget).unwrap());
    for name in [
        "raw_4k_repeat.bin",
        "delta_repeat.bin",
        "large_literals.bin",
    ] {
        let pack = std::fs::read(golden_root().join("pack-v2").join(name)).unwrap();
        let mut reader = WindowReader::new(
            u64::try_from(pack.len()).unwrap(),
            WINDOW,
            DecodeLimits::default().with_max_decoded_bytes(16 * 1024 * 1024),
            None,
        )
        .unwrap();
        let result = drive(&mut reader, &pack);
        if buffered(&pack).is_ok() {
            assert!(result.is_ok());
        }
        assert!(reader.peak <= usize::try_from(WINDOW + 16 * 1024 * 1024).unwrap());
    }
}

#[test]
fn oversized_source_capacity_is_not_retained_as_a_window() {
    let pack = raw_pack(&[vec![0x37; 16]]);
    let budget = 16;
    let mut reader = WindowReader::new(
        u64::try_from(pack.len()).unwrap(),
        WINDOW,
        DecodeLimits::default().with_max_decoded_bytes(budget),
        Some(hash::hash(&pack)),
    )
    .unwrap();
    let Step::NeedWindow(request) = reader.step().unwrap() else {
        panic!()
    };
    let mut oversized = Vec::with_capacity(8 * 1024 * 1024);
    oversized.extend_from_slice(&pack);
    assert_eq!(u64::try_from(oversized.len()).unwrap(), request.len);
    reader.feed_owned(request.offset, oversized).unwrap();
    assert!(reader.window.capacity() <= usize::try_from(WINDOW).unwrap());
    assert_eq!(drive(&mut reader, &pack).unwrap(), buffered(&pack).unwrap());
    assert!(reader.peak <= usize::try_from(WINDOW + budget).unwrap());
}

#[test]
fn high_bit_payload_lengths_preserve_buffered_eof_errors() {
    for payload in [0x8000_0000u32, 0x8000_0001, 0xffff_fffe, u32::MAX] {
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.push(0);
        bytes.extend_from_slice(&payload.to_le_bytes());
        let pack = finish_bytes(bytes);
        assert!(matches!(
            PackEntries::new(&pack),
            Err(PackError::UnexpectedEof)
        ));
        assert!(matches!(
            windowed(&pack, WINDOW, DecodeLimits::default(), None),
            Err(PackError::UnexpectedEof)
        ));
    }
}

#[test]
fn enormous_pack_lengths_and_out_of_range_sources_return_errors() {
    let pack = raw_pack(&[b"small".to_vec()]);
    for length in [
        u64::from(u32::MAX) - 1,
        u64::from(u32::MAX),
        u64::from(u32::MAX) + 1,
        u64::MAX - 1,
        u64::MAX,
    ] {
        let mut reader =
            match WindowReader::new(length, WINDOW, DecodeLimits::default(), Some([0; 32])) {
                Ok(reader) => reader,
                Err(error) => {
                    assert!(matches!(error, PackError::PackfileTooLarge));
                    continue;
                }
            };
        let Step::NeedWindow(request) = reader.step().unwrap() else {
            panic!()
        };
        assert_eq!(
            request,
            WindowRequest {
                offset: 0,
                len: WINDOW
            }
        );
        assert!(matches!(
            (&*pack).read_window(request.offset, request.len),
            Err(PackError::UnexpectedEof)
        ));
        // Supplying a plausible first window proves later framing arithmetic
        // does not overflow even when the declared length is near u64::MAX.
        let mut first = vec![0; usize::try_from(WINDOW).unwrap()];
        first[..pack.len()].copy_from_slice(&pack);
        reader.feed(0, &first).unwrap();
        assert!(matches!(reader.step().unwrap(), Step::Entry(_)));
        assert!(matches!(reader.step(), Err(PackError::TrailingData)));
    }
    let mut source = &*pack;
    assert!(matches!(
        source.read_window(u64::MAX, 1),
        Err(PackError::UnexpectedEof)
    ));
    assert!(source.read_window(u64::MAX - 1, 1).is_err());
}

#[test]
fn invalid_geometry_and_wrong_feed_range_are_rejected() {
    for length in [0, 12, 43] {
        assert!(matches!(
            WindowReader::new(length, WINDOW, DecodeLimits::default(), None),
            Err(PackError::PackfileTooShort)
        ));
    }
    for window in [
        0,
        1,
        WINDOW - 1,
        WINDOW + 1,
        96 * 1024,
        128 * 1024 * 1024,
        u64::MAX,
    ] {
        assert!(matches!(
            WindowReader::new(44, window, DecodeLimits::default(), None),
            Err(PackError::PackfileCorrupted)
        ));
    }
    let pack = raw_pack(&[vec![1; 10]]);
    let mut reader = WindowReader::new(
        u64::try_from(pack.len()).unwrap(),
        WINDOW,
        DecodeLimits::default(),
        None,
    )
    .unwrap();
    assert!(matches!(
        reader.feed(0, &pack),
        Err(PackError::PackfileCorrupted)
    ));
    let Step::NeedWindow(request) = reader.step().unwrap() else {
        panic!()
    };
    assert!(matches!(
        reader.feed(1, &pack),
        Err(PackError::PackfileCorrupted)
    ));
    assert!(matches!(
        reader.feed(0, &pack[..pack.len() - 1]),
        Err(PackError::PackfileCorrupted)
    ));
    assert!(matches!(reader.step().unwrap(), Step::NeedWindow(actual) if actual == request));
    reader.feed(0, &pack).unwrap();
    assert!(matches!(
        reader.feed(0, &pack),
        Err(PackError::PackfileCorrupted)
    ));
    assert!(drive(&mut reader, &pack).is_ok());
}

#[test]
fn trailer_split_at_every_final_boundary_position() {
    for tail in 1..32 {
        let length = usize::try_from(WINDOW).unwrap() + tail;
        let pack = raw_pack(&[vec![0x53; length - 49]]);
        assert_eq!(pack.len(), length);
        if tail == 1 {
            assert_eq!(pack.len(), 65_537);
        }
        differential(&pack, WINDOW);
        assert!(
            windowed(
                &pack,
                WINDOW,
                DecodeLimits::default(),
                Some(hash::hash(&pack))
            )
            .is_ok()
        );
        resume_each_entry(&pack, WINDOW, Some(hash::hash(&pack)));
    }
}

#[test]
fn trailer_and_requested_pack_id_are_checked_after_provisional_entries() {
    for pack in [raw_pack(&[]), raw_pack(&[b"entry".to_vec()])] {
        assert!(
            windowed(
                &pack,
                WINDOW,
                DecodeLimits::default(),
                Some(hash::hash(&pack))
            )
            .is_ok()
        );
        let mut reader = WindowReader::new(
            u64::try_from(pack.len()).unwrap(),
            WINDOW,
            DecodeLimits::default(),
            Some([0xff; 32]),
        )
        .unwrap();
        let Step::NeedWindow(request) = reader.step().unwrap() else {
            panic!()
        };
        feed_from(&mut reader, &pack, request);
        if !buffered(&pack).unwrap().0.is_empty() {
            assert!(matches!(reader.step().unwrap(), Step::Entry(_)));
        }
        assert!(matches!(reader.step(), Err(PackError::PackfileCorrupted)));
    }
    let mut pack = raw_pack(&[b"provisional".to_vec()]);
    let last = pack.len() - 1;
    pack[last] ^= 1;
    let mut reader = WindowReader::new(
        u64::try_from(pack.len()).unwrap(),
        WINDOW,
        DecodeLimits::default(),
        None,
    )
    .unwrap();
    let Step::NeedWindow(request) = reader.step().unwrap() else {
        panic!()
    };
    feed_from(&mut reader, &pack, request);
    assert!(matches!(reader.step().unwrap(), Step::Entry(_)));
    assert!(matches!(reader.step(), Err(PackError::PackfileCorrupted)));
}

#[test]
fn hazmat_roots_match_plain_hash_across_length_classes() {
    for window in [WINDOW, 1024 * 1024] {
        let mut lengths = vec![1, 12, 1023, 1024, 1025];
        let counts: &[u64] = if window == WINDOW {
            &[1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33]
        } else {
            &[1, 2, 3, 4, 5]
        };
        for count in counts {
            let boundary = count * window;
            lengths.extend([
                boundary - 32,
                boundary - 1,
                boundary,
                boundary + 1,
                boundary + 31,
                boundary + 1024,
            ]);
        }
        for length in lengths {
            let bytes = vec![0xa5; usize::try_from(length).unwrap()];
            let mut tree = Tree::new();
            for (index, part) in bytes.chunks(usize::try_from(window).unwrap()).enumerate() {
                tree.absorb(u64::try_from(index).unwrap() * window, part, length, window)
                    .unwrap();
                assert!(tree.stack.len() <= 64);
            }
            assert_eq!(
                tree.root,
                Some(hash::hash(&bytes)),
                "length={length}, window={window}"
            );
        }
    }
}

#[test]
fn synchronous_driver_propagates_source_and_sink_errors() {
    struct Broken;
    impl WindowSource for Broken {
        fn read_window(&mut self, _: u64, _: u64) -> Result<Vec<u8>, PackError> {
            Err(PackError::UnexpectedEof)
        }
    }
    assert!(matches!(
        read_all(
            &mut Broken,
            44,
            WINDOW,
            DecodeLimits::default(),
            None,
            |_| Ok(())
        ),
        Err(PackError::UnexpectedEof)
    ));
    let pack = raw_pack(&[b"entry".to_vec()]);
    assert!(matches!(
        read_all(
            &mut &*pack,
            u64::try_from(pack.len()).unwrap(),
            WINDOW,
            DecodeLimits::default(),
            None,
            |_| Err(PackError::TrailingData)
        ),
        Err(PackError::TrailingData)
    ));
}
