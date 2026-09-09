//! `ChunkReader` (streaming FastCDC over a `Read`) throughput vs. the
//! in-memory `ChunkIterator` floor.
//!
//! `ChunkReader` is the only chunker used for files above
//! `worktree::CHUNK_THRESHOLD` (1 MiB) — `mkit add`, and `status`/`diff`
//! for any stat-mismatched large file, stream through it. Its window
//! management used to allocate-and-copy on every chunk: `fill` read into
//! a separate 64 KiB scratch buffer and `extend_from_slice`d into the
//! growing window, and `next_chunk` cut the window with `Vec::split_off`
//! (a fresh allocation plus a memcpy of the remainder) followed by a
//! `mem::replace`. That is two extra full-window-sized copies of every
//! byte on top of the unavoidable cut scan. This suite isolates just the
//! streaming-reader cost (cut + window bookkeeping, no BLAKE3/store I/O)
//! against the `ChunkIterator` floor — the same cut over the same bytes
//! with no windowing at all — so a regression in the windowing overhead
//! shows up as the streaming series drifting away from the floor.
//!
//! Numbers are wallclock ms over one un-warmed pass (matches
//! `store_write.rs`'s convention: real memcpy/syscall cost, not a
//! cache-warmed loop); smaller is better and closer-to-floor is better.

use std::io::Cursor;

use criterion::{Criterion, criterion_group, criterion_main};
use mkit_benches::{Sample, Unit, time_one};
use mkit_core::chunker::{ChunkIterator, ChunkReader, FastCdc};

const SIZES: &[(usize, &str)] = &[(8 << 20, "8 MiB"), (32 << 20, "32 MiB")];

/// Deterministic xorshift-filled buffer — not compressible, not
/// all-zero, so `FastCdc::cut` takes its real scanning path rather than
/// hitting a degenerate all-same-byte / all-zero shortcut.
fn payload(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    let mut x = 0x2545_F491_4F6C_DD1Du64;
    for b in &mut buf {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *b = (x & 0xFF) as u8;
    }
    buf
}

fn iterate_in_memory(data: &[u8]) -> usize {
    ChunkIterator::new(FastCdc::v1(), data)
        .map(|b| b.length)
        .sum()
}

fn stream_owned(data: &[u8]) -> usize {
    let mut reader = ChunkReader::new(FastCdc::v1(), Cursor::new(data));
    let mut total = 0usize;
    while let Some(chunk) = reader.next_chunk().unwrap() {
        total += chunk.len();
    }
    total
}

fn time_ms(f: impl FnMut()) -> f64 {
    time_one(0, 1, f) * 1000.0
}

fn bench_chunker_streaming(c: &mut Criterion) {
    let mut samples: Vec<Sample> = Vec::new();

    for &(n, axis) in SIZES {
        let data = payload(n);

        c.bench_function(&format!("chunker_streaming/{axis}/in_memory_floor"), |b| {
            b.iter(|| std::hint::black_box(iterate_in_memory(&data)));
        });
        let ms = time_ms(|| {
            std::hint::black_box(iterate_in_memory(&data));
        });
        samples.push(Sample {
            category: "chunker_streaming".into(),
            axis: axis.into(),
            library: "in_memory_floor".into(),
            value: ms,
            unit: Unit::Millis,
        });

        c.bench_function(
            &format!("chunker_streaming/{axis}/chunk_reader_next_chunk"),
            |b| {
                b.iter(|| std::hint::black_box(stream_owned(&data)));
            },
        );
        let ms = time_ms(|| {
            std::hint::black_box(stream_owned(&data));
        });
        samples.push(Sample {
            category: "chunker_streaming".into(),
            axis: axis.into(),
            library: "chunk_reader_next_chunk".into(),
            value: ms,
            unit: Unit::Millis,
        });

        assert_eq!(iterate_in_memory(&data), n, "cut must partition the input");
        assert_eq!(
            stream_owned(&data),
            n,
            "streamed chunks must reconstitute the input length"
        );
    }

    mkit_benches::write_summary("chunker_streaming", &samples);
}

criterion_group!(name = benches; config = Criterion::default().sample_size(10); targets = bench_chunker_streaming);
criterion_main!(benches);
