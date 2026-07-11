//! Chunker / delta / packfile goldens.
//!
//! These tests assert that:
//!
//! 1. [`mkit_core::chunker`] produces the pinned chunk boundaries for
//!    the splitmix64-derived inputs stored at
//!    `rust/tests/golden/fastcdc/fastcdc_boundaries_*.bin`.
//! 2. [`mkit_core::delta`] encodes a SPEC-DELTA stream that round-trips
//!    through [`mkit_core::delta::decode`] and pins to a fixed byte
//!    prefix for a deterministic input.
//! 3. [`mkit_core::pack`] writes a SPEC-PACKFILE v1 pack that the
//!    reader resolves end-to-end and that pins to a fixed byte prefix
//!    for a deterministic input.
//!
//! Goldens for #2 / #3 do NOT live on disk — they're inline byte
//! arrays so the spec change → test failure feedback is immediate.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::fs;
use std::path::PathBuf;

use mkit_core::chunker::{ChunkIterator, FastCdc, chunk_boundaries};
use mkit_core::delta;
use mkit_core::hash;
use mkit_core::layout::RepoLayout;
use mkit_core::pack::{PackReader, PackWriter, pack_key};
use mkit_core::store::ObjectStore;

fn fastcdc_dir() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop(); // crates/
    d.pop(); // rust/
    d.push("tests");
    d.push("golden");
    d.push("fastcdc");
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
    let raw = fs::read_to_string(fastcdc_dir().join("fastcdc_boundaries_1mib.bin"))
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
    let raw = fs::read_to_string(fastcdc_dir().join("fastcdc_boundaries_256k.bin"))
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
    let stream = delta::encode(b"aaa", b"zzz").unwrap();
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
    // The encoder must actually emit this pinned COPY-only stream for a
    // pure-copy edit (base == result) — an INSERT-only encoder would
    // still round-trip via `decode` but would never produce this byte
    // shape, so pin `encode`'s output directly instead of only
    // exercising `decode` on a hand-built stream.
    let encoded = delta::encode(&base, &base).unwrap();
    assert_eq!(
        encoded, expected,
        "encode must emit the pinned COPY opcode stream"
    );

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
    w.push_raw(blob_hash, &blob_bytes).unwrap();
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
    let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
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

/// The exact 61 bytes `pack_basic_pin_bytes_roundtrip` builds via
/// `PackWriter` — captured as a literal byte-for-byte pin BEFORE
/// issue #646's v2/zstd changes landed. Unlike that test (which
/// re-derives the pack through the current `PackWriter` and would
/// silently drift if writer and reader changed in lockstep), this
/// array can never change: it is the one fixed point
/// `v1_pack_still_reads_bit_identical` decodes against, so any v1
/// framing regression shows up as a decode failure here even if
/// `PackWriter` itself is buggy in a way that's invisible to
/// self-roundtrip tests.
const PINNED_V1_SINGLE_RAW_PACK: [u8; 61] = [
    0x4d, 0x4b, 0x49, 0x54, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00,
    0x00, 0x01, 0x4d, 0x4b, 0x54, 0x31, 0x01, 0x02, 0x00, 0x00, 0x00, 0x68, 0x69, 0x8e, 0x3d, 0xbb,
    0x17, 0x27, 0x3f, 0xd9, 0xca, 0x89, 0x34, 0xc6, 0x4e, 0x78, 0xe4, 0xe7, 0x55, 0xc3, 0x76, 0x81,
    0x80, 0xf7, 0x8f, 0x08, 0x2c, 0xc1, 0xbf, 0x66, 0x95, 0xa8, 0xa6, 0x91, 0x34,
];

#[test]
fn v1_pack_still_reads_bit_identical() {
    // No-regression guardrail for issue #646 (SPEC-PACKFILE v2,
    // zstd-compressed entries): a pre-existing v1 pack, pinned as raw
    // bytes captured before the v2 changes, MUST decode to exactly the
    // same result after those changes as it did before. `PackWriter`
    // now sometimes emits `version = 2`, and `PackReader` now handles
    // `0x03`/`0x04` — none of that may perturb how a plain `version =
    // 1`, all-`0x00`/`0x02` pack like this one is read.
    let blob = mkit_core::object::Object::Blob(mkit_core::object::Blob {
        data: b"hi".to_vec(),
    });
    let blob_bytes = mkit_core::serialize::serialize(&blob).unwrap();
    let blob_hash = hash::hash(&blob_bytes);

    let pack = &PINNED_V1_SINGLE_RAW_PACK;
    assert_eq!(u32::from_le_bytes(pack[4..8].try_into().unwrap()), 1);
    assert_eq!(
        pack[12], 0x00,
        "sanity: pinned pack's only entry is 0x00 raw"
    );

    let dir = tempfile::TempDir::new().unwrap();
    let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
    let report = PackReader::read(pack.as_slice(), &store).unwrap();
    assert_eq!(report.raw_count, 1);
    assert_eq!(report.delta_count, 0);
    assert_eq!(report.stored, vec![blob_hash]);
    assert_eq!(store.read(&blob_hash).unwrap(), blob_bytes);
}

#[test]
#[cfg(feature = "pack-zstd")]
fn pack_v2_compressed_raw_pin_bytes_roundtrip() {
    // Minimal v2 pack: one highly-compressible raw entry, forced into
    // the 0x03 zstd-raw path by the §3.3 writer policy.
    let payload = vec![0x42u8; 4096];
    let blob = mkit_core::object::Object::Blob(mkit_core::object::Blob { data: payload });
    let blob_bytes = mkit_core::serialize::serialize(&blob).unwrap();
    let blob_hash = hash::hash(&blob_bytes);

    let mut w = PackWriter::new();
    w.push_raw(blob_hash, &blob_bytes).unwrap();
    let pack = w.finish().unwrap();

    // Header: version = 2.
    assert_eq!(&pack[0..4], b"MKIT");
    assert_eq!(u32::from_le_bytes(pack[4..8].try_into().unwrap()), 2);
    assert_eq!(u32::from_le_bytes(pack[8..12].try_into().unwrap()), 1);

    // Entry frame: type 0x03, payload = [4B uncompressed_len][zstd frame].
    assert_eq!(pack[12], 0x03);
    let entry_payload_len = u32::from_le_bytes(pack[13..17].try_into().unwrap()) as usize;
    let uncompressed_len = u32::from_le_bytes(pack[17..21].try_into().unwrap()) as usize;
    assert_eq!(uncompressed_len, blob_bytes.len());
    // The whole point of compression: on-wire payload is much smaller
    // than the 4096+ byte original for this maximally-repetitive input.
    assert!(
        entry_payload_len < blob_bytes.len() / 4,
        "expected substantial compression, on-wire={entry_payload_len} raw={}",
        blob_bytes.len()
    );

    // Trailer.
    let split = pack.len() - 32;
    let trailer = hash::hash(&pack[..split]);
    assert_eq!(&pack[split..], trailer.as_slice());
    assert_eq!(pack_key(&pack), hash::hash(&pack));

    // Roundtrip through reader: recovered bytes are byte-identical to
    // the pre-compression original.
    let dir = tempfile::TempDir::new().unwrap();
    let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
    let report = PackReader::read(&pack, &store).unwrap();
    assert_eq!(report.raw_count, 1);
    assert_eq!(report.delta_count, 0);
    assert_eq!(report.stored, vec![blob_hash]);
    assert_eq!(store.read(&blob_hash).unwrap(), blob_bytes);
}

#[test]
#[cfg(feature = "pack-zstd")]
fn pack_v2_compressed_delta_pin_bytes_roundtrip() {
    // Minimal v2 pack: a raw base plus one delta entry whose stream is
    // highly-compressible, forced into the 0x04 zstd-delta path.
    let base_blob = mkit_core::object::Object::Blob(mkit_core::object::Blob {
        data: b"delta base filler, deliberately unrelated to the target".to_vec(),
    });
    let base_bytes = mkit_core::serialize::serialize(&base_blob).unwrap();
    let base_hash = hash::hash(&base_bytes);

    let target_blob = mkit_core::object::Object::Blob(mkit_core::object::Blob {
        data: vec![0x42u8; 4096],
    });
    let target_bytes = mkit_core::serialize::serialize(&target_blob).unwrap();
    let target_hash = hash::hash(&target_bytes);

    let stream = delta::encode(&base_bytes, &target_bytes).unwrap();
    assert!(
        stream.len() >= 64,
        "sanity: stream must clear the compression-candidate floor"
    );

    let mut w = PackWriter::new();
    w.push_raw(base_hash, &base_bytes).unwrap();
    w.push_delta(&base_hash, &stream).unwrap();
    let pack = w.finish().unwrap();

    assert_eq!(u32::from_le_bytes(pack[4..8].try_into().unwrap()), 2);
    assert_eq!(u32::from_le_bytes(pack[8..12].try_into().unwrap()), 2);

    // First entry: raw base (0x00, base_bytes is short and not worth
    // compressing).
    assert_eq!(pack[12], 0x00);
    let base_payload_len = u32::from_le_bytes(pack[13..17].try_into().unwrap()) as usize;
    assert_eq!(&pack[17..17 + base_payload_len], base_bytes.as_slice());

    // Second entry: 0x04 zstd-delta, payload = [32B base_hash]
    // [4B uncompressed_len][zstd frame].
    let second_offset = 12 + 5 + base_payload_len;
    assert_eq!(pack[second_offset], 0x04);
    let second_payload_offset = second_offset + 5;
    assert_eq!(
        &pack[second_payload_offset..second_payload_offset + 32],
        base_hash.as_slice(),
        "0x04's base_hash must be uncompressed and in the same position as 0x02's"
    );
    let uncompressed_len_offset = second_payload_offset + 32;
    let uncompressed_len = u32::from_le_bytes(
        pack[uncompressed_len_offset..uncompressed_len_offset + 4]
            .try_into()
            .unwrap(),
    ) as usize;
    assert_eq!(uncompressed_len, stream.len());

    // Trailer.
    let split = pack.len() - 32;
    let trailer = hash::hash(&pack[..split]);
    assert_eq!(&pack[split..], trailer.as_slice());

    // Roundtrip through reader.
    let dir = tempfile::TempDir::new().unwrap();
    let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
    let report = PackReader::read(&pack, &store).unwrap();
    assert_eq!(report.raw_count, 1);
    assert_eq!(report.delta_count, 1);
    assert_eq!(report.stored, vec![base_hash, target_hash]);
    assert_eq!(store.read(&target_hash).unwrap(), target_bytes);
}
