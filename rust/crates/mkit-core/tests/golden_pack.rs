//! Phase 3 goldens.
//!
//! These tests assert that:
//!
//! 1. [`mkit_core::chunker`] produces the pinned chunk boundaries for
//!    the splitmix64-derived inputs stored at
//!    `rust/tests/golden/phase3/fastcdc_boundaries_*.bin`.
//! 2. [`mkit_core::delta`] encodes a SPEC-DELTA stream that round-trips
//!    through [`mkit_core::delta::decode`] and pins to a fixed byte
//!    prefix for a deterministic input.
//! 3. [`mkit_core::pack`] writes a SPEC-PACKFILE v1 pack that the
//!    reader resolves end-to-end and that pins to a fixed byte prefix
//!    for a deterministic input.
//!
//! Goldens for #2 / #3 do NOT live on disk — they're inline byte
//! arrays so the spec change → test failure feedback is immediate.

use std::fs;
use std::path::PathBuf;

use mkit_core::chunker::{ChunkIterator, FastCdc, chunk_boundaries};
use mkit_core::delta;
use mkit_core::hash;
use mkit_core::pack::{PackReader, PackWriter, pack_key};
use mkit_core::store::ObjectStore;

fn phase3_dir() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop(); // crates/
    d.pop(); // rust/
    d.push("tests");
    d.push("golden");
    d.push("phase3");
    d
}

/// Splitmix64 byte stream. Pinned — changing this invalidates the
/// checked-in boundary goldens.
fn splitmix_bytes(seed: u64, total: usize) -> Vec<u8> {
    let mut buf = vec![0u8; total];
    let mut state: u64 = seed;
    let mut i = 0usize;
    while i < total {
        state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^= z >> 31;
        let bytes = z.to_le_bytes();
        let end = (i + 8).min(total);
        buf[i..end].copy_from_slice(&bytes[..end - i]);
        i = end;
    }
    buf
}

fn parse_boundaries_json(s: &str) -> Vec<usize> {
    // Minimal one-line parser: trim brackets/whitespace, split on `,`.
    let trimmed = s.trim();
    let inner = trimmed
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(trimmed);
    inner
        .split(',')
        .map(|t| {
            t.trim()
                .parse::<usize>()
                .unwrap_or_else(|_| panic!("bad boundary token: {t:?}"))
        })
        .collect()
}

#[test]
fn fastcdc_boundaries_1mib_match_golden() {
    let raw = fs::read_to_string(phase3_dir().join("fastcdc_boundaries_1mib.bin"))
        .expect("missing fastcdc_boundaries_1mib.bin");
    let expected = parse_boundaries_json(&raw);
    let data = splitmix_bytes(0xA5A5_F00D_DEAD_BEEF, 1024 * 1024);
    let actual = chunk_boundaries(&data);
    assert_eq!(
        actual, expected,
        "1 MiB FastCDC boundaries diverged from pinned golden"
    );
}

#[test]
fn fastcdc_boundaries_256k_match_golden() {
    let raw = fs::read_to_string(phase3_dir().join("fastcdc_boundaries_256k.bin"))
        .expect("missing fastcdc_boundaries_256k.bin");
    let expected = parse_boundaries_json(&raw);
    let data = splitmix_bytes(0xCAFE_BABE_1234_5678, 256 * 1024);
    let actual = chunk_boundaries(&data);
    assert_eq!(
        actual, expected,
        "256 KiB FastCDC boundaries diverged from pinned golden"
    );
}

#[test]
fn fastcdc_iterator_total_equals_input_length() {
    // Sanity, plus exercises the Iterator API in tests/.
    let data = splitmix_bytes(0xDEAD_BEEF, 200 * 1024);
    let total: usize = ChunkIterator::new(FastCdc::v1(), &data)
        .map(|b| b.length)
        .sum();
    assert_eq!(total, data.len());
}

#[test]
fn delta_basic_pin_bytes_and_roundtrip() {
    // SPEC-DELTA pure-INSERT pin: base="aaa", target="zzz".
    // Stream MUST be: [0x01][3,0,0,0][3,0,0,0][3]['z','z','z'] = 13 bytes.
    let stream = delta::encode(b"aaa", b"zzz");
    let expected: [u8; 13] = [
        0x01, // version
        0x03, 0x00, 0x00, 0x00, // base_len = 3
        0x03, 0x00, 0x00, 0x00, // result_len = 3
        0x03, // INSERT length 3
        b'z', b'z', b'z',
    ];
    assert_eq!(
        stream,
        expected.to_vec(),
        "delta basic INSERT bytes drifted"
    );
    let restored = delta::decode(b"aaa", &stream).unwrap();
    assert_eq!(restored, b"zzz");
}

#[test]
fn delta_pure_copy_pin_bytes() {
    // Hand-build a one-COPY stream: base = 16 bytes; result = base[..16].
    // Expected pin = [ver=1][base_len=16 LE][result_len=16 LE][0x80][0,0,0,0][16,0]
    let base: Vec<u8> = (0..16u8).collect();
    let expected: [u8; 16] = [
        0x01, // version
        0x10, 0x00, 0x00, 0x00, // base_len = 16
        0x10, 0x00, 0x00, 0x00, // result_len = 16
        0x80, // COPY opcode
        0x00, 0x00, 0x00, 0x00, // offset = 0
        0x10, 0x00, // length = 16
    ];
    let restored = delta::decode(&base, &expected).unwrap();
    assert_eq!(restored, base);
}

#[test]
fn pack_basic_pin_bytes_roundtrip() {
    // A minimal one-raw-entry pack of an empty mkit blob.
    let blob = mkit_core::object::Object::Blob(mkit_core::object::Blob {
        data: b"hi".to_vec(),
    });
    let blob_bytes = mkit_core::serialize::serialize(&blob).unwrap();
    let blob_hash = hash::hash(&blob_bytes);

    let mut w = PackWriter::new();
    w.push_raw(blob_hash, blob_bytes.clone()).unwrap();
    let pack = w.finish().unwrap();

    // Pin the framing: header (12 bytes) + entry frame (5 bytes) +
    // blob payload + 32-byte trailer.
    let entry_payload_len = blob_bytes.len();
    let expected_pack_len = 12 + 5 + entry_payload_len + 32;
    assert_eq!(pack.len(), expected_pack_len);

    // Header.
    assert_eq!(&pack[0..4], b"MKIT");
    assert_eq!(u32::from_le_bytes(pack[4..8].try_into().unwrap()), 1);
    assert_eq!(u32::from_le_bytes(pack[8..12].try_into().unwrap()), 1);

    // First entry frame.
    assert_eq!(pack[12], 0x00);
    assert_eq!(
        u32::from_le_bytes(pack[13..17].try_into().unwrap()) as usize,
        entry_payload_len
    );
    assert_eq!(&pack[17..17 + entry_payload_len], blob_bytes.as_slice());

    // Trailer = BLAKE3 of everything before it.
    let split = pack.len() - 32;
    let trailer = hash::hash(&pack[..split]);
    assert_eq!(&pack[split..], trailer.as_slice());

    // Pack key matches.
    assert_eq!(pack_key(&pack), hash::hash(&pack));

    // Roundtrip through reader.
    let dir = tempfile::TempDir::new().unwrap();
    let store = ObjectStore::init(dir.path()).unwrap();
    let report = PackReader::read(&pack, &store).unwrap();
    assert_eq!(report.raw_count, 1);
    assert_eq!(report.delta_count, 0);
    assert_eq!(report.stored, vec![blob_hash]);
}

#[test]
fn empty_pack_pin_bytes() {
    // 12-byte header + 32-byte trailer = 44 bytes.
    let pack = PackWriter::new().finish().unwrap();
    assert_eq!(pack.len(), 44);
    assert_eq!(&pack[0..4], b"MKIT");
    assert_eq!(u32::from_le_bytes(pack[4..8].try_into().unwrap()), 1);
    assert_eq!(u32::from_le_bytes(pack[8..12].try_into().unwrap()), 0);
    let trailer = hash::hash(&pack[..12]);
    assert_eq!(&pack[12..], trailer.as_slice());
}
