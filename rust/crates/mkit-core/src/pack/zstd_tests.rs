//! SPEC-PACKFILE §3.3/§3.4 zstd entry decoding: the one-frame rule on
//! both backends, the pure-Rust (`pack-ruzstd`) decoder's bounds, and
//! the C-vs-Rust differential suite (runs under `--all-features`).
//!
//! Frames the tests need without an encoder are hand-built from raw
//! blocks (RFC 8878 §3.1.1.2), so the `pack-ruzstd`-only build exercises
//! real framing too.

use super::*;

/// The RFC 8878 frame magic, for hand-built frames.
#[cfg(feature = "pack-ruzstd")]
const MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];
/// A skippable frame (magic `0x184D2A50`) with an empty body.
#[cfg(any(feature = "pack-zstd", feature = "pack-ruzstd"))]
const SKIPPABLE: [u8; 8] = [0x50, 0x2A, 0x4D, 0x18, 0, 0, 0, 0];

/// A `0x03`-style entry payload: `[u32 LE claim][frame]`.
#[cfg(feature = "pack-ruzstd")]
fn entry(claim: usize, frame: &[u8]) -> Vec<u8> {
    let mut p = u32::try_from(claim).unwrap().to_le_bytes().to_vec();
    p.extend_from_slice(frame);
    p
}

#[cfg(any(feature = "pack-zstd", feature = "pack-ruzstd"))]
fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

/// A frame of raw (stored) blocks. `fcs` writes a 4-byte
/// `Frame_Content_Size`; `window_log: None` sets `Single_Segment`
/// (which requires `fcs`), `Some(log)` writes a window descriptor.
#[cfg(feature = "pack-ruzstd")]
fn raw_block_frame(content: &[u8], fcs: Option<u32>, window_log: Option<u8>) -> Vec<u8> {
    let mut f = MAGIC.to_vec();
    let fcs_flag = if fcs.is_some() { 0b10 << 6 } else { 0 };
    let single = if window_log.is_none() { 0x20 } else { 0 };
    f.push(fcs_flag | single);
    if let Some(log) = window_log {
        f.push((log - 10) << 3);
    }
    if let Some(n) = fcs {
        f.extend_from_slice(&n.to_le_bytes());
    }
    if content.is_empty() {
        f.extend_from_slice(&[1, 0, 0]); // last raw block, size 0
    }
    let mut blocks = content.chunks(128 * 1024).peekable();
    while let Some(block) = blocks.next() {
        let last = u32::from(blocks.peek().is_none());
        let header = (u32::try_from(block.len()).unwrap() << 3) | last;
        f.extend_from_slice(&header.to_le_bytes()[..3]);
        f.extend_from_slice(block);
    }
    f
}

/// The committed C-encoded v2 fixtures (`rust/tests/golden/pack-v2/`).
#[cfg(all(feature = "pack-zstd", feature = "pack-ruzstd"))]
const FIXTURES: [&str; 5] = [
    "raw_4k_repeat",
    "delta_repeat",
    "mixed",
    "tree_and_commit",
    "large_literals",
];

#[cfg(feature = "pack-ruzstd")]
fn fixture(name: &str) -> Vec<u8> {
    let mut dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    dir.pop();
    dir.pop();
    dir.extend(["tests", "golden", "pack-v2", &format!("{name}.bin")]);
    std::fs::read(dir).unwrap()
}

/// Every `0x03`/`0x04` entry's `[claim][frame]` payload, in pack order.
#[cfg(feature = "pack-ruzstd")]
fn zstd_payloads(pack: &[u8]) -> Vec<&[u8]> {
    let count = u32::from_le_bytes(pack[ENTRY_COUNT_OFFSET..HEADER_LEN].try_into().unwrap());
    let mut pos = HEADER_LEN;
    let mut out = Vec::new();
    for _ in 0..count {
        let etype = pack[pos];
        let len = u32::from_le_bytes(pack[pos + 1..pos + 5].try_into().unwrap()) as usize;
        let payload = &pack[pos + ENTRY_FRAME_LEN..pos + ENTRY_FRAME_LEN + len];
        pos += ENTRY_FRAME_LEN + len;
        match etype {
            0x03 => out.push(payload),
            0x04 => out.push(&payload[hash::HASH_LEN..]),
            _ => {}
        }
    }
    out
}

/// The variant class a decode ended in; the message inside
/// `ZstdDecompress` may legitimately differ between backends.
#[cfg(feature = "pack-ruzstd")]
fn class(r: &Result<Vec<u8>, PackError>) -> &'static str {
    match r {
        Ok(_) => "ok",
        Err(PackError::ZstdEntryTruncated) => "ZstdEntryTruncated",
        Err(PackError::DecompressedSizeOverCap(_)) => "DecompressedSizeOverCap",
        Err(PackError::DecompressedSizeMismatch(..)) => "DecompressedSizeMismatch",
        Err(PackError::ZstdDecompress(_)) => "ZstdDecompress",
        Err(e) => panic!("unexpected zstd entry error {e:?}"),
    }
}

/// The C backend (before this change) decoded concatenated frames and
/// skipped skippable ones; SPEC-PACKFILE §3.3 allows exactly one frame.
#[cfg(feature = "pack-zstd")]
#[test]
fn c_backend_enforces_one_frame() {
    let a = zstd::bulk::compress(&[1u8; 100], 3).unwrap();
    let b = zstd::bulk::compress(&[2u8; 100], 3).unwrap();
    assert_eq!(zstd_decompress_capped(&a, 100).unwrap(), vec![1u8; 100]);
    let mut legacy = a.clone();
    legacy[0] = 0x27; // v0.7 legacy frame magic 0xFD2FB527
    for (case, frame, cap) in [
        ("two frames", cat(&[&a, &b]), 200),
        ("frame + skippable", cat(&[&a, &SKIPPABLE]), 100),
        ("skippable + frame", cat(&[&SKIPPABLE, &a]), 100),
        ("lone skippable", SKIPPABLE.to_vec(), 0),
        ("trailing byte", cat(&[&a, &[0]]), 100),
        ("legacy magic", legacy, 100),
    ] {
        let r = zstd_decompress_capped(&frame, cap);
        assert!(
            matches!(r, Err(PackError::ZstdDecompress(_))),
            "{case}: {r:?}"
        );
    }
}

/// `PackWriter` only compresses with the C encoder: a decode-only
/// build (`pack-ruzstd` alone, or neither feature) writes v1 packs.
#[cfg(not(feature = "pack-zstd"))]
#[test]
fn raw_only_writer_when_no_c_zstd() {
    let blob = crate::serialize::serialize(&crate::object::Object::Blob(crate::object::Blob {
        data: vec![0x42; 4096],
    }))
    .unwrap();
    assert!(maybe_compress(&blob).is_none());
    let mut w = PackWriter::new();
    w.push_raw(hash::hash(&blob), &blob).unwrap();
    let pack = w.finish().unwrap();
    assert_eq!(
        u32::from_le_bytes(pack[VERSION_OFFSET..VERSION_OFFSET + 4].try_into().unwrap()),
        VERSION
    );
    assert_eq!(pack[HEADER_LEN], 0x00);
}

#[cfg(feature = "pack-ruzstd")]
mod ruzstd_backend {
    use super::*;

    fn decode(claim: usize, frame: &[u8]) -> Result<Vec<u8>, PackError> {
        decompress_zstd_entry_with(&entry(claim, frame), ruzstd_decompress_capped)
    }

    #[test]
    fn ruzstd_decodes_hand_built_frames() {
        let big: Vec<u8> = (0..300 * 1024u32)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect();
        for (case, content, frame) in [
            (
                "single segment",
                b"hi".to_vec(),
                raw_block_frame(b"hi", Some(2), None),
            ),
            ("empty", vec![], raw_block_frame(&[], Some(0), None)),
            (
                "windowed, no fcs",
                vec![7; 1000],
                raw_block_frame(&[7; 1000], None, Some(10)),
            ),
            (
                "multi-block",
                big.clone(),
                raw_block_frame(&big, None, Some(20)),
            ),
        ] {
            assert_eq!(decode(content.len(), &frame).unwrap(), content, "{case}");
        }
    }

    #[test]
    fn ruzstd_enforces_one_frame() {
        let a = raw_block_frame(b"abc", Some(3), None);
        for (case, frame, cap) in [
            ("two frames", cat(&[&a, &a]), 6),
            ("frame + skippable", cat(&[&a, &SKIPPABLE]), 3),
            ("skippable + frame", cat(&[&SKIPPABLE, &a]), 3),
            ("lone skippable", SKIPPABLE.to_vec(), 0),
            ("trailing byte", cat(&[&a, &[0]]), 3),
        ] {
            let r = decode(cap, &frame);
            assert_eq!(class(&r), "ZstdDecompress", "{case}: {r:?}");
        }
    }

    /// `Size_Format` of every compressed block's Huffman-coded literals
    /// section in a dictionary-less frame.
    fn literals_size_formats(frame: &[u8]) -> Vec<u8> {
        let d = frame[4];
        assert_eq!(d & 3, 0, "no dictionary id");
        let single = d & 0x20 != 0;
        let fcs_len = [usize::from(single), 2, 4, 8][usize::from(d >> 6)];
        let mut pos = 5 + usize::from(!single) + fcs_len;
        let mut formats = Vec::new();
        loop {
            let h = u32::from_le_bytes([frame[pos], frame[pos + 1], frame[pos + 2], 0]);
            let size = (h >> 3) as usize;
            let kind = (h >> 1) & 3;
            if kind == 2 && frame[pos + 3] & 3 >= 2 {
                formats.push((frame[pos + 3] >> 2) & 3);
            }
            pos += 3 + if kind == 1 { 1 } else { size };
            if h & 1 == 1 {
                return formats;
            }
        }
    }

    /// The 4-byte (14-bit) and 5-byte (18-bit) literals headers decode.
    /// On a 32-bit target the 5-byte header overflowed `usize` in the
    /// sequence-mode walker; the wasm32 harness
    /// (`scripts/wasm-ruzstd-check.sh`) runs this fixture there.
    #[test]
    fn ruzstd_decodes_4_and_5_byte_literals_headers() {
        let pack = fixture("large_literals");
        let mut formats = Vec::new();
        for payload in zstd_payloads(&pack) {
            formats.extend(literals_size_formats(&payload[ZSTD_LEN_PREFIX..]));
            decompress_zstd_entry_with(payload, ruzstd_decompress_capped).unwrap();
        }
        assert!(
            formats.contains(&2),
            "no 4-byte literals header in {formats:?}"
        );
        assert!(
            formats.contains(&3),
            "no 5-byte literals header in {formats:?}"
        );
    }

    /// Over-cap claims fail before any frame byte is read; declared sizes
    /// above the claim fail from the header; output past the claim stops
    /// at `claim + 1` bytes. (Allocation itself is not measured here.)
    #[test]
    fn ruzstd_rejects_claims_before_or_at_the_cap() {
        let r = decode(MAX_RAW_OBJECT_SIZE + 1, &[0u8; 8]);
        assert!(
            matches!(r, Err(PackError::DecompressedSizeOverCap(n)) if n == MAX_RAW_OBJECT_SIZE + 1),
            "{r:?}"
        );
        // A 1 GiB declared content size behind a 16-byte claim: rejected
        // from the header, before any block is decoded.
        let header_only = raw_block_frame(&[], Some(1 << 30), Some(20));
        assert_eq!(class(&decode(16, &header_only)), "ZstdDecompress");
        // No declared size: 1 MiB of output behind a 16-byte claim stops
        // at the claim instead of buffering the whole frame.
        let long = raw_block_frame(&vec![0u8; 1 << 20], None, Some(10));
        let r = ruzstd_decompress_capped(&long, 16);
        assert_eq!(class(&r), "ZstdDecompress", "{r:?}");
        // Short output is the caller's length mismatch, as on the C path.
        let r = decode(4, &raw_block_frame(b"abc", None, Some(10)));
        assert!(
            matches!(r, Err(PackError::DecompressedSizeMismatch(4, 3))),
            "{r:?}"
        );
    }

    #[test]
    fn ruzstd_rejects_lying_frame_content_size() {
        let content = [9u8; 1000];
        for fcs in [999, 1001] {
            let frame = raw_block_frame(&content, Some(fcs), Some(10));
            let r = decode(1001, &frame);
            assert_eq!(class(&r), "ZstdDecompress", "fcs {fcs}: {r:?}");
        }
    }

    /// A 2 GiB window over 1 KiB of content is rejected from the header
    /// (window limit `max(claim, 8 MiB)`), never allocated; an 8 MiB
    /// window still decodes.
    #[test]
    fn ruzstd_rejects_huge_window_frame() {
        let content = [5u8; 1024];
        let huge = raw_block_frame(&content, None, Some(31));
        let r = decode(1024, &huge);
        assert_eq!(class(&r), "ZstdDecompress", "{r:?}");
        let floor = raw_block_frame(&content, None, Some(23));
        assert_eq!(decode(1024, &floor).unwrap(), content);
    }

    /// RFC 8878 §3.1.1.2.4: a block may not decode past a sub-128 KiB
    /// window, and the descriptor's reserved bit must be clear. Bare
    /// ruzstd accepts both; the C decoder rejects the reserved bit and
    /// oversized compressed blocks.
    #[test]
    fn ruzstd_enforces_reserved_bits_and_block_size() {
        let r = decode(5000, &raw_block_frame(&[4; 5000], None, Some(10)));
        assert_eq!(class(&r), "ZstdDecompress", "{r:?}");
        let mut reserved = raw_block_frame(&[3; 100], Some(100), None);
        reserved[4] |= 0x08;
        assert_eq!(class(&decode(100, &reserved)), "ZstdDecompress");
    }
}

#[cfg(all(feature = "pack-zstd", feature = "pack-ruzstd"))]
mod differential {
    use super::*;
    use proptest::prelude::*;
    use zstd::zstd_safe::CParameter;

    /// Decode `payload` through the full entry checks with each backend;
    /// both must reach the same class and, on success, the same bytes.
    fn agree(case: &str, payload: &[u8]) -> Result<Vec<u8>, PackError> {
        let c = decompress_zstd_entry_with(payload, zstd_decompress_capped);
        let rs = decompress_zstd_entry_with(payload, ruzstd_decompress_capped);
        let brief = |r: &Result<Vec<u8>, PackError>| match r {
            Ok(v) => format!("Ok({} bytes)", v.len()),
            Err(e) => format!("{e:?}"),
        };
        assert_eq!(
            class(&c),
            class(&rs),
            "{case}: C {} vs ruzstd {}",
            brief(&c),
            brief(&rs)
        );
        if let (Ok(a), Ok(b)) = (&c, &rs) {
            assert_eq!(a, b, "{case}: decoded bytes differ");
        }
        c
    }

    fn compress_with(content: &[u8], params: &[CParameter]) -> Vec<u8> {
        let mut c = zstd::bulk::Compressor::new(ZSTD_LEVEL).unwrap();
        for p in params {
            c.set_parameter(*p).unwrap();
        }
        c.compress(content).unwrap()
    }

    #[test]
    #[allow(clippy::too_many_lines)] // one flat table
    fn backends_agree_on_adversarial_frames() {
        let content = b"adversarial frame content, repeated. ".repeat(40);
        let n = content.len();
        let frame = compress_with(&content, &[]);
        let no_fcs = compress_with(&content, &[CParameter::ContentSizeFlag(false)]);
        let checked = compress_with(&content, &[CParameter::ChecksumFlag(true)]);
        let mut bad_sum = checked.clone();
        *bad_sum.last_mut().unwrap() ^= 1;
        let mut dict = MAGIC.to_vec();
        dict.extend_from_slice(&[0x21, 7, 100]); // single segment, 1-byte dict id 7, fcs 100
        dict.extend_from_slice(&(100u32 << 3 | 1).to_le_bytes()[..3]);
        dict.extend_from_slice(&[3; 100]);
        let mut reserved = raw_block_frame(&[3; 100], Some(100), None);
        reserved[4] |= 0x08;

        let cases: Vec<(&str, Vec<u8>, &str)> = vec![
            ("valid", entry(n, &frame), "ok"),
            ("valid, checksummed", entry(n, &checked), "ok"),
            ("valid, no fcs", entry(n, &no_fcs), "ok"),
            (
                "valid, raw blocks",
                entry(3, &raw_block_frame(b"abc", Some(3), None)),
                "ok",
            ),
            (
                "payload shorter than prefix",
                vec![1, 2],
                "ZstdEntryTruncated",
            ),
            (
                "claim over MAX_RAW_OBJECT_SIZE",
                entry(MAX_RAW_OBJECT_SIZE + 1, &frame),
                "DecompressedSizeOverCap",
            ),
            ("empty frame", entry(n, &[]), "ZstdDecompress"),
            (
                "truncated frame",
                entry(n, &frame[..frame.len() - 3]),
                "ZstdDecompress",
            ),
            ("header only", entry(n, &frame[..6]), "ZstdDecompress"),
            (
                "two concatenated frames",
                entry(2 * n, &cat(&[&frame, &frame])),
                "ZstdDecompress",
            ),
            (
                "frame + 1 trailing byte",
                entry(n, &cat(&[&frame, &[0]])),
                "ZstdDecompress",
            ),
            (
                "lone skippable frame",
                entry(0, &SKIPPABLE),
                "ZstdDecompress",
            ),
            (
                "frame + skippable",
                entry(n, &cat(&[&frame, &SKIPPABLE])),
                "ZstdDecompress",
            ),
            (
                "skippable + frame",
                entry(n, &cat(&[&SKIPPABLE, &frame])),
                "ZstdDecompress",
            ),
            ("checksum mismatch", entry(n, &bad_sum), "ZstdDecompress"),
            (
                "claim > frame content size",
                entry(n + 1, &frame),
                "DecompressedSizeMismatch",
            ),
            (
                "claim < frame content size",
                entry(n - 1, &frame),
                "ZstdDecompress",
            ),
            (
                "no fcs, claim > actual",
                entry(n + 1, &no_fcs),
                "DecompressedSizeMismatch",
            ),
            (
                "no fcs, claim < actual",
                entry(n - 1, &no_fcs),
                "ZstdDecompress",
            ),
            (
                "fcs below content",
                entry(1001, &raw_block_frame(&[9; 1000], Some(999), Some(10))),
                "ZstdDecompress",
            ),
            (
                "fcs above content",
                entry(1001, &raw_block_frame(&[9; 1000], Some(1001), Some(10))),
                "ZstdDecompress",
            ),
            (
                "dictionary id, no dictionary",
                entry(100, &dict),
                "ZstdDecompress",
            ),
            (
                "reserved descriptor bit",
                entry(100, &reserved),
                "ZstdDecompress",
            ),
        ];
        for (case, payload, want) in cases {
            let got = agree(case, &payload);
            assert_eq!(class(&got), want, "{case}: {got:?}");
            if want == "ok" {
                let expect: &[u8] = if case.contains("raw blocks") {
                    b"abc"
                } else {
                    &content
                };
                assert_eq!(got.unwrap(), expect, "{case}");
            }
        }
    }

    /// A fixed corpus of single-bit corruptions of real frames (every
    /// byte, bits 0/3/7): the backends agree on accept/reject, variant
    /// class and bytes. It pins the reserved-field checks ruzstd lacks
    /// (descriptor bit 3, sequence-mode bits 1-0). Agreement on *arbitrary*
    /// malformed frames is not claimed: see the residual-divergence note
    /// in docs/INVARIANTS.md.
    #[test]
    fn backends_agree_on_bit_flipped_frames() {
        let mut content = b"literal-heavy header text; ".repeat(30);
        content.extend((0u32..2000).map(|i| i.wrapping_mul(2_654_435_761).to_le_bytes()[1]));
        let n = content.len();
        for params in [vec![], vec![CParameter::ChecksumFlag(true)]] {
            let frame = compress_with(&content, &params);
            for i in 0..frame.len() {
                for bit in [0, 3, 7] {
                    let mut f = frame.clone();
                    f[i] ^= 1 << bit;
                    let _ = agree(&format!("byte {i} bit {bit}"), &entry(n, &f));
                }
            }
        }
    }

    /// Setting a `Symbol_Compression_Modes` reserved bit leaves the decoded
    /// bytes unchanged, so bare ruzstd accepted it while the C decoder
    /// rejects it (a fail-open divergence the block walker now closes).
    #[test]
    fn backends_agree_on_reserved_sequence_mode_bits() {
        let content = b"sequence modes reserved bits. ".repeat(50);
        let frame = compress_with(&content, &[]);
        assert!(ruzstd_check_reserved_fields(&frame).is_ok());
        let mut hits = 0;
        for i in 0..frame.len() {
            let mut f = frame.clone();
            f[i] |= 1;
            if ruzstd_check_reserved_fields(&f)
                != Err("zstd sequences section has its reserved mode bits set")
            {
                continue;
            }
            hits += 1;
            let r = agree(&format!("mode byte {i}"), &entry(content.len(), &f));
            assert_eq!(class(&r), "ZstdDecompress", "{r:?}");
        }
        assert!(hits >= 1, "the frame's sequences section was never hit");
    }

    /// Known, documented fail-closed divergences on window size. The C
    /// one-shot decoder accepts both frames; the pure-Rust decoder refuses
    /// a declared window above `max(claim, 8 MiB)` rather than buffer it,
    /// and output past a sub-128 KiB window because it cannot see
    /// per-block sizes (the C decoder rejects such blocks when they are
    /// compressed, but not when they are raw).
    #[test]
    fn window_divergences_are_fail_closed() {
        for (content, window_log) in [(vec![5u8; 1024], 31), (vec![4u8; 5000], 10)] {
            let payload = entry(
                content.len(),
                &raw_block_frame(&content, None, Some(window_log)),
            );
            let c = decompress_zstd_entry_with(&payload, zstd_decompress_capped);
            assert_eq!(c.unwrap(), content);
            let rs = decompress_zstd_entry_with(&payload, ruzstd_decompress_capped);
            assert_eq!(class(&rs), "ZstdDecompress", "{rs:?}");
        }
    }

    /// Every `0x03`/`0x04` payload in `pack` decodes identically under both
    /// backends; returns the decoded payloads in entry order.
    fn assert_pack_agrees(case: &str, pack: &[u8]) -> Vec<Vec<u8>> {
        zstd_payloads(pack)
            .iter()
            .enumerate()
            .map(|(i, inner)| agree(&format!("{case} zstd entry {i}"), inner).unwrap())
            .collect()
    }

    #[test]
    fn backends_agree_on_committed_v2_fixtures() {
        let mut seen = 0;
        for name in FIXTURES {
            seen += assert_pack_agrees(name, &fixture(name)).len();
        }
        assert_eq!(seen, 9, "compressed entries across the fixtures");
    }

    /// Deterministic object content of a given shape.
    fn shaped(kind: u8, len: usize, seed: u64) -> Vec<u8> {
        let mut s = seed | 1;
        let mut noise = move || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s.to_le_bytes()[0]
        };
        match kind {
            0 => b"compressible line of text\n"
                .iter()
                .copied()
                .cycle()
                .take(len)
                .collect(),
            1 => (0..len).map(|_| noise()).collect(),
            _ => (0..len)
                .map(|i| if (i / 4096) % 2 == 0 { b'm' } else { noise() })
                .collect(),
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(24))]

        /// Whatever `PackWriter` (C level-3 compression) emits, both
        /// decoders recover byte-identical entries.
        #[test]
        fn ruzstd_matches_c_on_writer_output(
            kind in 0u8..3,
            len in 0usize..=256 * 1024,
            seed in any::<u64>(),
        ) {
            let content = shaped(kind, len, seed);
            let target = crate::serialize::serialize(&crate::object::Object::Blob(
                crate::object::Blob { data: content.clone() },
            ))
            .unwrap();
            let base = crate::serialize::serialize(&crate::object::Object::Blob(
                crate::object::Blob { data: content[..len / 2].to_vec() },
            ))
            .unwrap();
            let stream = delta::encode(&base, &target).unwrap();
            let mut w = PackWriter::new();
            w.push_raw(hash::hash(&target), &target).unwrap();
            w.push_raw(hash::hash(&base), &base).unwrap();
            w.push_delta(&hash::hash(&base), &stream).unwrap();
            let pack = w.finish().unwrap();

            let decoded = assert_pack_agrees("writer output", &pack);
            let mut wanted = vec![target, base, stream].into_iter();
            for (i, d) in decoded.iter().enumerate() {
                prop_assert!(wanted.any(|w| &w == d), "decoded payload {i} is not an input");
            }
        }
    }
}
