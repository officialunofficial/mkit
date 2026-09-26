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
    let reference = buffered(pack);
    let actual = windowed(pack, window, DecodeLimits::default(), None);
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

fn feed_from(reader: &mut WindowReader, pack: &[u8], request: WindowRequest) {
    assert_eq!(request.offset % reader.state.window_size, 0);
    assert_eq!(
        request.len,
        reader
            .state
            .window_size
            .min(reader.state.pack_len - request.offset)
    );
    let from = usize::try_from(request.offset).unwrap();
    let to = usize::try_from(request.offset + request.len).unwrap();
    reader.feed(request.offset, &pack[from..to]).unwrap();
}

fn drive(reader: &mut WindowReader, pack: &[u8]) -> Result<(Vec<Value>, WindowSummary), PackError> {
    let mut values = Vec::new();
    loop {
        match reader.step()? {
            Step::NeedWindow(request) => feed_from(reader, pack, request),
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

proptest! {
    #![proptest_config(ProptestConfig::with_cases(40))]

    #[test]
    fn generated_valid_and_mutated_packs_agree(
        entries in prop::collection::vec((any::<bool>(), any::<bool>(), prop::collection::vec(any::<u8>(), 0..384)), 0..12),
        mutation in any::<usize>(),
        bit in 0u8..8,
    ) {
        let pack = generated_pack(&entries);
        assert!(buffered(&pack).is_ok());
        for window in [WINDOW, 1024 * 1024] {
            differential(&pack, window);
            let mut flipped = pack.clone();
            let at = mutation % flipped.len();
            flipped[at] ^= 1 << bit;
            differential(&flipped, window);
            let mut framing_mutation = flipped.clone();
            let split = framing_mutation.len() - 32;
            let checksum = hash::hash(&framing_mutation[..split]);
            framing_mutation[split..].copy_from_slice(&checksum);
            differential(&framing_mutation, window);
            differential(&pack[..mutation % pack.len()], window);
            let mut extra = pack.clone();
            extra.extend_from_slice(&[bit, 0xa5]);
            differential(&extra, window);
            let mut trailing = pack[..pack.len() - 32].to_vec();
            trailing.push(bit);
            differential(&finish_bytes(trailing), window);
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
                let Step::NeedWindow(request) = reader.step().unwrap() else {
                    panic!("resume must request a window")
                };
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
fn a_cursor_never_completes_a_different_pack_even_with_a_stale_trailer() {
    let pack = raw_pack(&[
        vec![0x11; usize::try_from(WINDOW * 2 + 23).unwrap()],
        vec![0x22; 77],
    ]);
    for expected in [None, Some(hash::hash(&pack))] {
        let cursor = first_cursor(&pack, expected);
        assert!(cursor.completed > 0);
        for update_trailer in [false, true] {
            // Mutation is entirely in a completed window: the suffix and all
            // resumed entry bytes stay identical. The stale-trailer case must
            // revalidate the cursor's skipped prefix before allowing Done.
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
            assert!(matches!(
                drive(&mut resumed, &other),
                Err(PackError::PackfileCorrupted)
            ));
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
    assert!(reader.checkpoint().is_none());
    feed_from(&mut reader, &pack, request);
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
