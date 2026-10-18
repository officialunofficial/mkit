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
                assert_cursor_reference(&reader, &cursor);
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
                if let Some(cursor) = reader.checkpoint() {
                    assert_cursor_reference(&reader, &cursor);
                }
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
    for limits in [
        DecodeLimits::default(),
        DecodeLimits::default().with_entry_geometry(16 << 20, 1 << 20),
    ] {
        checkpoint_is_absent_when_boundary_released(limits);
    }
}

fn checkpoint_is_absent_when_boundary_released(limits: DecodeLimits) {
    let pack = raw_pack(&[vec![0x53; 65_537 - 49]]);
    assert_eq!(pack.len(), 65_537);
    let mut reader = WindowReader::new(65_537, WINDOW, limits, Some(hash::hash(&pack))).unwrap();
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
        limits,
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

struct Prior(std::collections::HashMap<Hash, Vec<u8>>);
impl crate::pack::DeltaBaseSource for Prior {
    fn base(&mut self, id: &Hash) -> Result<Option<Vec<u8>>, PackError> {
        Ok(self.0.get(id).cloned())
    }
}

/// `last_frame` and `decode_entry_with` reproduce what the buffered decoder
/// reports for every self-contained golden pack, at both window sizes.
#[test]
fn last_frame_and_decode_entry_agree_with_the_buffered_decoder() {
    let mut paths = Vec::new();
    pack_fixtures(&golden_root(), &mut paths);
    let mut compared = 0;
    for path in paths {
        let bytes = std::fs::read(&path).unwrap();
        let mut reference = Vec::new();
        if crate::pack::decode_entries_with(
            &bytes,
            &mut crate::pack::NoExternalBases,
            DecodeLimits::default(),
            |entry| {
                reference.push((
                    entry.id,
                    entry.bytes.to_vec(),
                    (entry.frame_offset, entry.frame_length, entry.wire_type),
                ));
                Ok(())
            },
        )
        .is_err()
        {
            continue;
        }
        for window in [WINDOW, 1024 * 1024] {
            let mut reader = WindowReader::new(
                u64::try_from(bytes.len()).unwrap(),
                window,
                DecodeLimits::default(),
                None,
            )
            .unwrap();
            assert_eq!(reader.last_frame(), None);
            let mut bases = Prior(std::collections::HashMap::new());
            let mut actual = Vec::new();
            loop {
                match reader.step().unwrap() {
                    Step::NeedWindow(request) => {
                        let mut source = bytes.as_slice();
                        let piece = source.read_window(request.offset, request.len).unwrap();
                        reader.feed(request.offset, &piece).unwrap();
                    }
                    Step::Entry(entry) => {
                        let frame = reader.last_frame().unwrap();
                        let (id, decoded) = crate::pack::decode_entry_with(
                            entry,
                            &mut bases,
                            DecodeLimits::default(),
                        )
                        .unwrap();
                        bases.0.insert(id, decoded.clone());
                        actual.push((id, decoded, (frame.offset, frame.length, frame.wire_type)));
                    }
                    Step::Done(_) => break,
                }
            }
            assert_eq!(actual, reference, "{}", path.display());
            compared += 1;
        }
    }
    assert!(compared > 4, "golden coverage: {compared}");
}

#[test]
fn a_resumed_reader_reports_frames_only_for_entries_it_yields() {
    let payloads: Vec<_> = (0..5_u8).map(|n| vec![n; 100]).collect();
    let pack = raw_pack(&payloads);
    let mut reader = WindowReader::new(
        u64::try_from(pack.len()).unwrap(),
        WINDOW,
        DecodeLimits::default(),
        None,
    )
    .unwrap();
    let mut source = pack.as_slice();
    let mut cursor = None;
    let mut seen = 0;
    while cursor.is_none() {
        match reader.step().unwrap() {
            Step::NeedWindow(request) => {
                let piece = source.read_window(request.offset, request.len).unwrap();
                reader.feed(request.offset, &piece).unwrap();
            }
            Step::Entry(_) => {
                seen += 1;
                if seen == 2 {
                    assert_eq!(reader.last_frame().unwrap().offset, 12 + 105);
                    cursor = reader.checkpoint();
                }
            }
            Step::Done(_) => unreachable!("cursor taken at the second entry"),
        }
    }
    let resumed = WindowReader::resume(&cursor.unwrap(), DecodeLimits::default()).unwrap();
    assert_eq!(resumed.last_frame(), None);
}

#[cfg(any(feature = "pack-zstd", feature = "pack-ruzstd"))]
#[test]
fn explicit_geometry_carried_compressed_frame_binds_the_released_prefix() {
    let raw = vec![0x42; 4096];
    let mut encoded = u32::try_from(raw.len()).unwrap().to_le_bytes().to_vec();
    encoded.extend_from_slice(&[0x28, 0xb5, 0x2f, 0xfd, 0, 0x68]);
    let block = (u32::try_from(raw.len()).unwrap() << 3) | 1;
    encoded.extend_from_slice(&block.to_le_bytes()[..3]);
    encoded.extend_from_slice(&raw);
    let pack = synthetic(
        2,
        &[
            (0, vec![0x31; usize::try_from(WINDOW).unwrap() - 100]),
            (3, encoded),
        ],
    );
    let limits = DecodeLimits::default().with_entry_geometry(16 << 20, 1 << 20);
    let mut reader = WindowReader::new(
        u64::try_from(pack.len()).unwrap(),
        WINDOW,
        limits,
        Some(hash::hash(&pack)),
    )
    .unwrap();
    let mut entries = 0;
    loop {
        match reader.step().unwrap() {
            Step::NeedWindow(request) => feed_from(&mut reader, &pack, request),
            Step::Entry(_) => {
                entries += 1;
                if entries == 2 {
                    break;
                }
            }
            Step::Done(_) => panic!("need the carried compressed entry"),
        }
    }
    assert!(reader.window.is_empty());
    let cursor = reader.checkpoint().unwrap();
    cursor.validate().unwrap();
    let Step::NeedWindow(request) = reader.step().unwrap() else {
        panic!()
    };
    let mut bytes = pack[usize::try_from(request.offset).unwrap()
        ..usize::try_from(request.offset + request.len).unwrap()]
        .to_vec();
    bytes[0] ^= 1;
    assert!(matches!(
        reader.feed_owned(request.offset, bytes),
        Err(PackError::PackfileCorrupted)
    ));
    let mut clean = WindowReader::resume(&cursor, limits).unwrap();
    assert!(drive(&mut clean, &pack).is_ok());
}

// Independent pre-optimization checkpoint algorithm: hash the complete prefix.
fn assert_cursor_reference(reader: &WindowReader, cursor: &WindowCursor) {
    let mut reference = reader.boundary.clone().unwrap();
    let start = reference.completed * reference.window_size;
    let len = usize::try_from(reference.pos - start).unwrap();
    reference.window_prefix = if len == 0 {
        None
    } else {
        assert_eq!(reader.start, start);
        Some(hash::hash(&reader.window[..len]))
    };
    assert_eq!(cursor.to_bytes(), reference.to_bytes());
}

#[test]
fn checkpoints_match_reference_on_every_valid_fixture() {
    let mut paths = Vec::new();
    pack_fixtures(&golden_root(), &mut paths);
    for path in paths {
        let pack = std::fs::read(path).unwrap();
        if buffered(&pack).is_ok() {
            for expected in [None, Some(hash::hash(&pack))] {
                resume_each_entry(&pack, WINDOW, expected);
            }
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 24,
        rng_seed: proptest::test_runner::RngSeed::Fixed(0x5052_4546),
        ..ProptestConfig::default()
    })]
    #[test]
    fn warm_cold_many_checkpoints_and_rollover(
        seed in any::<u8>(), size in 1usize..2048, interval in 1usize..17,
    ) {
        let payloads = (0u8..180).map(|i| vec![seed.wrapping_add(i); size]).collect::<Vec<_>>();
        let pack = raw_pack(&payloads);
        for expected in [None, Some(hash::hash(&pack))] {
            let mut warm = WindowReader::new(u64::try_from(pack.len()).unwrap(), WINDOW, DecodeLimits::default(), expected).unwrap();
            let mut seen = 0;
            loop {
                match warm.step().unwrap() {
                    Step::NeedWindow(r) => feed_from(&mut warm, &pack, r),
                    Step::Entry(entry) => {
                        assert_eq!(value(entry), Value::Raw(payloads[seen].clone()));
                        seen += 1;
                        let cursor = warm.checkpoint().unwrap();
                        assert_cursor_reference(&warm, &cursor);
                        assert!(warm.prefix.checkpoint.get().unwrap().len <= usize::try_from(WINDOW).unwrap());
                        assert_eq!(u64::try_from(warm.prefix.checkpoint.get().unwrap().len).unwrap(), warm.state.pos - warm.start);
                        assert!(std::mem::size_of_val(&warm.prefix) <= 4096);
                        assert_eq!(cursor.to_bytes(), warm.checkpoint().unwrap().to_bytes());
                        if seen % interval == 0 {
                            let mut cold = WindowReader::resume(&cursor, DecodeLimits::default()).unwrap();
                            let Step::NeedWindow(r) = cold.step().unwrap() else { panic!() };
                            feed_from(&mut cold, &pack, r);
                            assert_eq!(cursor.to_bytes(), cold.checkpoint().unwrap().to_bytes());
                            if cursor.pos > r.offset {
                                let mut changed = pack[usize::try_from(r.offset).unwrap()..usize::try_from(r.offset + r.len).unwrap()].to_vec();
                                changed[usize::try_from(cursor.pos - r.offset - 1).unwrap()] ^= 1;
                                let mut bad = WindowReader::resume(&cursor, DecodeLimits::default()).unwrap();
                                bad.step().unwrap();
                                assert!(matches!(bad.feed(r.offset, &changed), Err(PackError::PackfileCorrupted)));
                            }
                            warm = cold;
                        }
                    }
                    Step::Done(_) => break,
                }
            }
            assert_eq!(seen, 180);
        }
    }
}

#[test]
fn window_relative_offsets_fit_32_bits_even_past_4_gib() {
    let offset = u64::from(u32::MAX) + 1;
    let pos = offset + WINDOW - 1;
    assert_eq!(
        us(pos - offset).unwrap(),
        usize::try_from(WINDOW - 1).unwrap()
    );
    assert!(u32::try_from(pos).is_err());
    assert!(u32::try_from(pos - offset).is_ok());
    #[cfg(target_pointer_width = "32")]
    assert!(matches!(us(u64::MAX), Err(PackError::PackfileTooLarge)));
    let bytes = vec![0; 54];
    let mut cursor = WindowCursor::initial(offset + 54, WINDOW, Some([0; 32]));
    cursor.pos = offset + 17;
    cursor.payload_sum = offset;
    cursor.version = 1;
    cursor.count = 2;
    cursor.index = 1;
    cursor.completed = offset / WINDOW;
    cursor.window_prefix = Some(hash::hash(&bytes[..17]));
    cursor.trailer_tree.stack.push([1; 32]);
    cursor.id_tree.stack.push([1; 32]);
    let cursor = WindowCursor::from_bytes(&cursor.to_bytes()).unwrap();
    let mut reader = WindowReader::resume(&cursor, DecodeLimits::default()).unwrap();
    let Step::NeedWindow(r) = reader.step().unwrap() else {
        panic!()
    };
    assert_eq!(r.offset, offset);
    reader.feed_owned(offset, bytes).unwrap();
    assert_eq!(reader.checkpoint().unwrap().to_bytes(), cursor.to_bytes());
    assert!(matches!(reader.step().unwrap(), Step::Entry(_)));
    assert_cursor_reference(&reader, &reader.checkpoint().unwrap());
    // Trusted cursor construction above uses synthetic CVs. Reaching the
    // boundary does not grant a completion result with those commitments.
    assert!(matches!(reader.step(), Err(PackError::PackfileCorrupted)));
}

#[test]
fn uncheckpointed_entries_do_not_hash_the_live_prefix() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<WindowReader>();
    let pack = raw_pack(&[vec![0x63; 32], vec![0x75; 64]]);
    let mut reader = WindowReader::new(
        u64::try_from(pack.len()).unwrap(),
        WINDOW,
        DecodeLimits::default(),
        Some(hash::hash(&pack)),
    )
    .unwrap();
    let Step::NeedWindow(r) = reader.step().unwrap() else {
        panic!()
    };
    feed_from(&mut reader, &pack, r);
    assert!(matches!(reader.step().unwrap(), Step::Entry(_)));
    assert_eq!(reader.prefix.previous.len, 0);
    let cursor = reader.checkpoint().unwrap();
    assert_cursor_reference(&reader, &cursor);
    let hashed = reader.prefix.checkpoint.get().unwrap().len;
    assert!(matches!(reader.step().unwrap(), Step::Entry(_)));
    assert_eq!(reader.prefix.previous.len, hashed);
    assert_cursor_reference(&reader, &reader.checkpoint().unwrap());
}

#[test]
fn concurrent_checkpoints_and_interrupted_initialization_match_prefix_bytes() {
    let pack = raw_pack(&[vec![0x46; 12_345]]);
    let mut reader = WindowReader::new(
        u64::try_from(pack.len()).unwrap(),
        WINDOW,
        DecodeLimits::default(),
        Some(hash::hash(&pack)),
    )
    .unwrap();
    let Step::NeedWindow(r) = reader.step().unwrap() else {
        panic!()
    };
    feed_from(&mut reader, &pack, r);
    assert!(matches!(reader.step().unwrap(), Step::Entry(_)));
    let expected = reader.checkpoint().unwrap().to_bytes();
    reader.prefix.checkpoint.take();
    let barrier = std::sync::Barrier::new(4);
    std::thread::scope(|scope| {
        for _ in 0..4 {
            let reader = &reader;
            let expected = &expected;
            let barrier = &barrier;
            scope.spawn(move || {
                barrier.wait();
                for _ in 0..16 {
                    assert_eq!(&reader.checkpoint().unwrap().to_bytes(), expected);
                }
            });
        }
    });
    reader.prefix.checkpoint.take();
    assert!(
        std::panic::catch_unwind(|| {
            reader
                .prefix
                .checkpoint
                .get_or_init(|| panic!("interrupt private cache initialization"));
        })
        .is_err()
    );
    assert!(reader.prefix.checkpoint.get().is_none());
    assert_eq!(reader.checkpoint().unwrap().to_bytes(), expected);
    assert_cursor_reference(&reader, &reader.checkpoint().unwrap());
}

#[test]
fn cursor_metadata_matches_live_boundaries_and_roundtrips() {
    for version in [1, 2] {
        let pack = synthetic(
            version,
            &[
                (0, vec![0x11; usize::try_from(WINDOW).unwrap() + 7]),
                (0, vec![0x22; 9]),
            ],
        );
        for expected in [None, Some(hash::hash(&pack))] {
            let mut reader = WindowReader::new(
                u64::try_from(pack.len()).unwrap(),
                WINDOW,
                DecodeLimits::default(),
                expected,
            )
            .unwrap();
            let mut ordinal = 0;
            let mut payload = 0;
            loop {
                match reader.step().unwrap() {
                    Step::NeedWindow(request) => feed_from(&mut reader, &pack, request),
                    Step::Entry(entry) => {
                        let PackEntry::Raw { bytes } = entry else {
                            panic!("raw fixture")
                        };
                        ordinal += 1;
                        payload += u64::try_from(bytes.len()).unwrap();
                        let cursor = reader.checkpoint().unwrap();
                        let encoded = cursor.to_bytes();
                        let metadata = cursor.metadata().unwrap();
                        assert_eq!(metadata.pack_len(), u64::try_from(pack.len()).unwrap());
                        assert_eq!(metadata.window_size(), WINDOW);
                        assert_eq!(metadata.position(), 12 + u64::from(ordinal) * 5 + payload);
                        assert_eq!(metadata.payload_sum(), payload);
                        assert_eq!(metadata.pack_version(), version);
                        assert_eq!(metadata.entry_count(), 2);
                        assert_eq!(metadata.entry_index(), ordinal);
                        assert_eq!(metadata.expected_pack_id(), expected);
                        assert_eq!(cursor.to_bytes(), encoded);
                        let restored = WindowCursor::from_bytes(&encoded).unwrap();
                        assert_eq!(restored.metadata().unwrap(), metadata);
                        assert_eq!(restored.to_bytes(), encoded);
                    }
                    Step::Done(_) => {
                        assert_eq!(ordinal, 2);
                        break;
                    }
                }
            }
        }
    }
}

#[test]
fn cursor_metadata_reuses_geometry_and_frontier_validation() {
    let pack = raw_pack(&[vec![0x11; 2 * usize::try_from(WINDOW).unwrap()]]);
    let cursor = first_cursor(&pack, Some(hash::hash(&pack)));
    let mutations: [fn(&mut WindowCursor); 9] = [
        |state| state.pack_len = 0,
        |state| state.window_size = 0,
        |state| state.pos += 1,
        |state| state.payload_sum += 1,
        |state| state.version = 0,
        |state| state.count = 0,
        |state| state.index = state.count + 1,
        |state| {
            state.expected = None;
            state.anchor = None;
        },
        |state| state.trailer_tree.stack.clear(),
    ];
    for mutate in mutations {
        let mut inconsistent = cursor.clone();
        mutate(&mut inconsistent);
        assert!(matches!(
            inconsistent.validate(),
            Err(PackError::PackfileCorrupted)
        ));
        assert!(matches!(
            inconsistent.metadata(),
            Err(PackError::PackfileCorrupted)
        ));
    }
}

#[test]
fn cursor_metadata_preserves_frozen_encoding() {
    // Frozen from the existing public reader before metadata inspection existed.
    let bytes = [
        0x01, 0xbd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x1f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x0c, 0xf2, 0xd3, 0xbf, 0x99,
        0x8a, 0xa3, 0x7e, 0xd8, 0xc2, 0x48, 0x23, 0xff, 0xe7, 0x60, 0xae, 0x18, 0x42, 0xec, 0x66,
        0xd0, 0xe7, 0xe6, 0x80, 0xc4, 0xb3, 0x34, 0x14, 0xe7, 0xb4, 0x05, 0xbb, 0x00, 0x01, 0xca,
        0xb7, 0x45, 0x73, 0xaf, 0x17, 0x3b, 0x7c, 0x7c, 0x82, 0x30, 0x19, 0x87, 0x02, 0x6f, 0x1a,
        0xee, 0x1c, 0xf5, 0x5c, 0x74, 0x6b, 0xc2, 0xa1, 0xdc, 0x40, 0x0b, 0x6d, 0x04, 0x65, 0x6e,
        0x8e, 0x00, 0x00, 0x00, 0x00, 0xa8, 0x7a, 0x03, 0x51, 0x61, 0x00, 0x80, 0x3d, 0x46, 0x21,
        0xff, 0xf5, 0xf2, 0xaf, 0xf5, 0xcb, 0xf7, 0xb8, 0x38, 0xb2, 0xf0, 0x69, 0x03, 0x08, 0xcc,
        0xa7, 0xf1, 0xf5, 0x51, 0x38, 0xb5, 0x75,
    ];
    let cursor = WindowCursor::from_bytes(&bytes).unwrap();
    let metadata = cursor.metadata().unwrap();
    assert_eq!(metadata.pack_len(), 189);
    assert_eq!(metadata.acquired_end(), None);
    assert_eq!(metadata.window_size(), 1 << 20);
    assert_eq!(metadata.position(), 31);
    assert_eq!(metadata.payload_sum(), 14);
    assert_eq!(metadata.pack_version(), 1);
    assert_eq!(metadata.entry_count(), 3);
    assert_eq!(metadata.entry_index(), 1);
    assert_eq!(
        metadata.expected_pack_id(),
        Some(
            hash::from_hex("0cf2d3bf998aa37ed8c24823ffe760ae1842ec66d0e7e680c4b33414e7b405bb")
                .unwrap()
        )
    );
    assert_eq!(cursor.to_bytes(), bytes);
    assert_eq!(
        WindowCursor::from_bytes(&cursor.to_bytes())
            .unwrap()
            .metadata()
            .unwrap(),
        metadata
    );
}

#[test]
fn exact_checkpoints_resume_without_consumed_prefix_reads() {
    for tail in [1, 13, 32, 65_490, 65_500] {
        let pack = synthetic(
            1,
            &[(0, vec![7; 13]), (0, vec![8; 70_000]), (0, vec![9; tail])],
        );
        for expected in [None, Some(hash::hash(&pack))] {
            let mut reader =
                WindowReader::new(pack.len() as u64, WINDOW, DecodeLimits::default(), expected)
                    .unwrap();
            loop {
                match reader.step().unwrap() {
                    Step::NeedWindow(request) => feed_from(&mut reader, &pack, request),
                    Step::Entry(_) => {
                        let cursor = reader.checkpoint_exact().unwrap();
                        let position = cursor.metadata().unwrap().position();
                        let bytes = cursor.to_bytes();
                        assert_eq!(bytes[0], 2);
                        let cursor = WindowCursor::from_bytes(&bytes).unwrap();
                        assert_eq!(cursor.to_bytes(), bytes);
                        let mut resumed =
                            WindowReader::resume(&cursor, DecodeLimits::default()).unwrap();
                        let mut first = true;
                        loop {
                            match resumed.step().unwrap() {
                                Step::NeedWindow(request) => {
                                    assert!(request.offset >= position);
                                    if first {
                                        assert_eq!(request.offset, position);
                                        first = false;
                                    }
                                    feed_exact(&mut resumed, &pack, request);
                                }
                                Step::Entry(_) => {
                                    assert!(resumed.checkpoint_exact().is_some());
                                }
                                Step::Done(_) => {
                                    assert_eq!(
                                        resumed.trailer(),
                                        Some(hash::hash(&pack[..pack.len() - 32]))
                                    );
                                    break;
                                }
                            }
                        }
                    }
                    Step::Done(_) => break,
                }
            }
        }
    }
}

#[test]
fn exact_checkpoint_rejects_changed_unconsumed_suffix() {
    let pack = synthetic(1, &[(0, vec![1; 17]), (0, vec![2; 200])]);
    let mut reader = WindowReader::new(
        pack.len() as u64,
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
    let cursor = reader.checkpoint_exact().unwrap();
    let mut resumed = WindowReader::resume(&cursor, DecodeLimits::default()).unwrap();
    let Step::NeedWindow(request) = resumed.step().unwrap() else {
        panic!()
    };
    let mut suffix = pack[usize::try_from(request.offset).unwrap()
        ..usize::try_from(request.offset + request.len).unwrap()]
        .to_vec();
    suffix[0] ^= 1;
    assert!(matches!(
        resumed.feed_owned(request.offset, suffix),
        Err(PackError::PackfileCorrupted)
    ));
}

#[test]
fn integrity_drain_after_framing_error_reads_each_window_once() {
    let mut pack = synthetic(1, &[(0, vec![2; usize::try_from(WINDOW).unwrap() * 2])]);
    pack[12] = 0xff;
    let split = pack.len() - 32;
    let trailer = hash::hash(&pack[..split]);
    pack[split..].copy_from_slice(&trailer);
    for corrupt in [false, true] {
        let mut bytes = pack.clone();
        if corrupt {
            bytes[split] ^= 1;
        }
        let mut reader = WindowReader::new(
            bytes.len() as u64,
            WINDOW,
            DecodeLimits::default(),
            Some(hash::hash(&bytes)),
        )
        .unwrap();
        let Step::NeedWindow(request) = reader.step().unwrap() else {
            panic!()
        };
        feed_from(&mut reader, &bytes, request);
        assert!(matches!(
            reader.step(),
            Err(PackError::InvalidEntryType(0xff))
        ));
        assert_eq!(reader.trailer(), None);
        let mut offset = WINDOW;
        loop {
            match reader.integrity_step() {
                Ok(Step::NeedWindow(request)) => {
                    assert_eq!(request.offset, offset);
                    offset += request.len;
                    feed_from(&mut reader, &bytes, request);
                }
                Ok(Step::Done(_)) => {
                    assert!(!corrupt);
                    assert_eq!(reader.trailer(), Some(trailer));
                    break;
                }
                Err(PackError::PackfileCorrupted) => {
                    assert!(corrupt);
                    assert_eq!(reader.trailer(), None);
                    break;
                }
                other => panic!("unexpected integrity action: {other:?}"),
            }
        }
        assert_eq!(offset, bytes.len() as u64);
    }
}

fn feed_exact(reader: &mut WindowReader, pack: &[u8], request: WindowRequest) {
    let begin = usize::try_from(request.offset).unwrap();
    let end = usize::try_from(request.offset + request.len).unwrap();
    reader
        .feed_owned(request.offset, pack[begin..end].to_vec())
        .unwrap();
}

#[test]
fn exact_checkpoint_drain_resumes_at_acquired_frontier() {
    let mut pack = synthetic(
        1,
        &[(0, vec![5; usize::try_from(WINDOW).unwrap() * 3 - 30])],
    );
    pack[12] = 0xff;
    let split = pack.len() - 32;
    let digest = hash::hash(&pack[..split]);
    pack[split..].copy_from_slice(&digest);
    let mut reader = WindowReader::new_one_pass(
        pack.len() as u64,
        WINDOW,
        DecodeLimits::default(),
        Some(hash::hash(&pack)),
    )
    .unwrap();
    let Step::NeedWindow(request) = reader.step().unwrap() else {
        panic!()
    };
    feed_exact(&mut reader, &pack, request);
    assert!(reader.step().is_err());
    let mut acquired_end = WINDOW;
    loop {
        let action = reader.integrity_step().unwrap();
        let cursor = reader.checkpoint_exact().unwrap();
        assert!(cursor.metadata().unwrap().exact());
        assert!(cursor.metadata().unwrap().integrity_only());
        assert_eq!(
            cursor.metadata().unwrap().acquired_end(),
            Some(acquired_end)
        );
        assert_eq!(cursor.metadata().unwrap().position(), 12);
        let cursor = WindowCursor::from_bytes(&cursor.to_bytes()).unwrap();
        reader = WindowReader::resume(&cursor, DecodeLimits::default()).unwrap();
        match action {
            Step::NeedWindow(_) => {
                let Step::NeedWindow(request) = reader.integrity_step().unwrap() else {
                    panic!()
                };
                assert_eq!(request.offset, acquired_end);
                acquired_end += request.len;
                feed_exact(&mut reader, &pack, request);
            }
            Step::Done(_) => {
                assert!(matches!(reader.integrity_step().unwrap(), Step::Done(_)));
                assert_eq!(reader.trailer(), Some(digest));
                assert_eq!(acquired_end, pack.len() as u64);
                break;
            }
            Step::Entry(_) => panic!(),
        }
    }
}

#[test]
fn exact_cursor_geometry_is_strict() {
    let pack = synthetic(1, &[(0, vec![1; 17]), (0, vec![2; 70_000])]);
    let mut reader = WindowReader::new_one_pass(
        pack.len() as u64,
        WINDOW,
        DecodeLimits::default(),
        Some(hash::hash(&pack)),
    )
    .unwrap();
    let Step::NeedWindow(request) = reader.step().unwrap() else {
        panic!()
    };
    feed_exact(&mut reader, &pack, request);
    assert!(matches!(reader.step().unwrap(), Step::Entry(_)));
    let cursor = reader.checkpoint_exact().unwrap();
    let mutations: &[fn(&mut WindowCursor)] = &[
        |cursor| cursor.exact.as_mut().unwrap().end -= 1,
        |cursor| cursor.exact.as_mut().unwrap().end = 0,
        |cursor| cursor.exact.as_mut().unwrap().end = cursor.pack_len + 1,
        |cursor| cursor.exact.as_mut().unwrap().suffix = None,
        |cursor| cursor.window_prefix = Some([0; 32]),
        |cursor| cursor.exact.as_mut().unwrap().trailer[31] = 1,
        |cursor| cursor.trailer_tree.stack.clear(),
    ];
    for mutate in mutations {
        let mut invalid = cursor.clone();
        mutate(&mut invalid);
        assert!(invalid.metadata().is_err());
        assert!(WindowCursor::from_bytes(&invalid.to_bytes()).is_err());
    }
    let mut bytes = cursor.to_bytes();
    bytes[0] = 3;
    let checksum = hash::hash(&bytes[..bytes.len() - 32]);
    let end = bytes.len();
    bytes[end - 32..].copy_from_slice(&checksum);
    assert!(WindowCursor::from_bytes(&bytes).is_err());
}

#[test]
fn exact_checkpoint_at_window_edge_and_split_trailer() {
    for payload in [
        usize::try_from(WINDOW).unwrap() - 17,
        usize::try_from(WINDOW).unwrap() - 30,
        usize::try_from(WINDOW).unwrap() - 49,
    ] {
        let pack = synthetic(1, &[(0, vec![4; payload])]);
        let mut reader = WindowReader::new_one_pass(
            pack.len() as u64,
            WINDOW,
            DecodeLimits::default(),
            Some(hash::hash(&pack)),
        )
        .unwrap();
        loop {
            match reader.step().unwrap() {
                Step::NeedWindow(request) => feed_exact(&mut reader, &pack, request),
                Step::Entry(_) => {
                    let cursor = reader.checkpoint_exact().unwrap();
                    let position = cursor.metadata().unwrap().position();
                    reader = WindowReader::resume(
                        &WindowCursor::from_bytes(&cursor.to_bytes()).unwrap(),
                        DecodeLimits::default(),
                    )
                    .unwrap();
                    let Step::NeedWindow(request) = reader.step().unwrap() else {
                        panic!()
                    };
                    assert_eq!(request.offset, position);
                    feed_exact(&mut reader, &pack, request);
                }
                Step::Done(_) => {
                    let cursor = reader.checkpoint_exact().unwrap();
                    let position = cursor.metadata().unwrap().position();
                    let mut resumed =
                        WindowReader::resume(&cursor, DecodeLimits::default()).unwrap();
                    loop {
                        match resumed.step().unwrap() {
                            Step::NeedWindow(request) => {
                                assert!(request.offset >= position);
                                feed_exact(&mut resumed, &pack, request);
                            }
                            Step::Done(_) => break,
                            Step::Entry(_) => panic!(),
                        }
                    }
                    break;
                }
            }
        }
    }
}

#[cfg(any(feature = "pack-zstd", feature = "pack-ruzstd"))]
#[test]
fn one_pass_carried_compressed_entry_never_reacquires_a_window() {
    let raw = vec![0x42; 4096];
    let mut encoded = u32::try_from(raw.len()).unwrap().to_le_bytes().to_vec();
    encoded.extend_from_slice(&[0x28, 0xb5, 0x2f, 0xfd, 0, 0x68]);
    let block = (u32::try_from(raw.len()).unwrap() << 3) | 1;
    encoded.extend_from_slice(&block.to_le_bytes()[..3]);
    encoded.extend_from_slice(&raw);
    let pack = synthetic(
        2,
        &[
            (0, vec![0x31; usize::try_from(WINDOW).unwrap() - 100]),
            (3, encoded),
        ],
    );
    let limits = DecodeLimits::default().with_entry_geometry(16 << 20, 1 << 20);
    let mut reader =
        WindowReader::new_one_pass(pack.len() as u64, WINDOW, limits, Some(hash::hash(&pack)))
            .unwrap();
    let mut acquired = 0;
    let mut entries = 0;
    loop {
        match reader.step().unwrap() {
            Step::NeedWindow(request) => {
                assert_eq!(request.offset, acquired);
                acquired += request.len;
                feed_exact(&mut reader, &pack, request);
            }
            Step::Entry(_) => {
                entries += 1;
                let work = reader.exact_checkpoint_work();
                let cursor = reader.checkpoint_exact().unwrap();
                assert_eq!(work, reader.end - cursor.metadata().unwrap().position());
                if entries == 2 {
                    assert!(!reader.window.is_empty());
                    let mut resumed = WindowReader::resume(&cursor, limits).unwrap();
                    let position = cursor.metadata().unwrap().position();
                    loop {
                        match resumed.step().unwrap() {
                            Step::NeedWindow(request) => {
                                assert!(request.offset >= position);
                                feed_exact(&mut resumed, &pack, request);
                            }
                            Step::Done(_) => break,
                            Step::Entry(_) => panic!(),
                        }
                    }
                }
            }
            Step::Done(_) => break,
        }
    }
    assert_eq!(entries, 2);
    assert_eq!(acquired, pack.len() as u64);
}

#[test]
fn exact_cursor_encoding_is_digest_pinned() {
    let pack = synthetic(1, &[(0, vec![1; 17]), (0, vec![2; 200])]);
    let mut reader = WindowReader::new_one_pass(
        pack.len() as u64,
        WINDOW,
        DecodeLimits::default(),
        Some(hash::hash(&pack)),
    )
    .unwrap();
    let Step::NeedWindow(request) = reader.step().unwrap() else {
        panic!()
    };
    feed_exact(&mut reader, &pack, request);
    assert!(matches!(reader.step().unwrap(), Step::Entry(_)));
    let cursor = reader.checkpoint_exact().unwrap();
    assert_eq!(
        cursor.metadata().unwrap().acquired_end(),
        Some(pack.len() as u64)
    );
    assert!(
        cursor.metadata().unwrap().acquired_end().unwrap() > cursor.metadata().unwrap().position()
    );
    let encoded = cursor.to_bytes();
    assert_eq!(encoded.len(), 263);
    assert_eq!(
        hash::to_hex(&hash::hash(&encoded)),
        "379bc66d6ceba26c1199d3222fd05afff32adef2fb76b26cd0be31628d3a7c1b"
    );
    assert_eq!(
        WindowCursor::from_bytes(&encoded).unwrap().to_bytes(),
        encoded
    );
}

#[test]
fn batching_boundary_binds_only_its_retained_window() {
    let pack = synthetic(
        1,
        &[(0, vec![1; 17]), (0, vec![2; 23]), (0, vec![3; 70_000])],
    );
    let mut reader = WindowReader::new_one_pass(
        pack.len() as u64,
        WINDOW,
        DecodeLimits::default(),
        Some(hash::hash(&pack)),
    )
    .unwrap();
    let Step::NeedWindow(request) = reader.step().unwrap() else {
        panic!()
    };
    feed_exact(&mut reader, &pack, request);
    assert!(matches!(reader.step().unwrap(), Step::Entry(_)));
    let boundary = reader.checkpoint_boundary().unwrap();
    assert!(reader.next_entry_fits_window());
    assert!(matches!(reader.step().unwrap(), Step::Entry(_)));
    assert!(!reader.next_entry_fits_window());
    let cursor = reader.checkpoint_exact_at(&boundary).unwrap();
    assert_eq!(cursor.metadata().unwrap().position(), 34);
    assert_eq!(reader.exact_checkpoint_work_at(&boundary), WINDOW - 34);
    // Batches must settle before stepping into the next acquisition.
    let Step::NeedWindow(request) = reader.step().unwrap() else {
        panic!()
    };
    assert!(reader.checkpoint_exact_at(&boundary).is_none());
    feed_exact(&mut reader, &pack, request);
    assert!(reader.checkpoint_exact_at(&boundary).is_none());
    assert_eq!(reader.exact_checkpoint_work_at(&boundary), 0);
    let mut resumed = WindowReader::resume(&cursor, DecodeLimits::default()).unwrap();
    let mut entries = 0;
    loop {
        match resumed.step().unwrap() {
            Step::NeedWindow(request) => {
                assert!(request.offset >= 34);
                feed_exact(&mut resumed, &pack, request);
            }
            Step::Entry(_) => entries += 1,
            Step::Done(_) => break,
        }
    }
    assert_eq!(entries, 2);
}

#[test]
fn batching_boundary_rejects_another_unverified_prefix() {
    let pack = synthetic(1, &[(0, vec![1; 17]), (0, vec![2; 70_000])]);
    let mut changed = pack.clone();
    changed[20] ^= 1;
    let expected = Some(hash::hash(&pack));
    let readers = [&pack[..], &changed[..]].map(|bytes| {
        let mut reader = WindowReader::new_one_pass(
            bytes.len() as u64,
            WINDOW,
            DecodeLimits::default(),
            expected,
        )
        .unwrap();
        let Step::NeedWindow(request) = reader.step().unwrap() else {
            panic!()
        };
        feed_exact(&mut reader, bytes, request);
        assert!(matches!(reader.step().unwrap(), Step::Entry(_)));
        reader
    });
    let boundary = readers[0].checkpoint_boundary().unwrap();
    assert!(readers[0].checkpoint_exact_at(&boundary).is_some());
    assert!(readers[1].checkpoint_exact_at(&boundary).is_none());
}
