//! Pack payload compression (SPEC-PACKFILE v2, zstd, issue #646) — the
//! Testing Decision the issue calls out explicitly: build a small
//! multi-commit corpus of realistic small text-file edits and report
//! resulting pack bytes for {v1 uncompressed, v2 compressed}.
//!
//! This is deliberately NOT primarily a speed benchmark — the number
//! this file exists to produce is a *size* comparison, which criterion
//! has no native concept of. It still registers one `bench_function`
//! (timing `PackWriter` construction of the v2 pack) so `cargo bench`
//! and `cargo bench -- --test` smoke-pass through the normal harness,
//! but the size numbers themselves are computed once and printed via
//! `eprintln!` — visible in any `cargo bench -p mkit-benches --bench
//! pack_compression` run. Not wired into `mkit_benches::write_summary`
//! (the shared `Sample`/`Unit` chart contract has no byte-count unit,
//! and MiB/s or ops/s would mislabel a static size comparison).

use criterion::{Criterion, criterion_group, criterion_main};
use mkit_core::hash;
use mkit_core::object::{Blob, Object};
use mkit_core::pack::{ENTRY_FRAME_LEN, HEADER_LEN, PackWriter, TRAILER_LEN};
use mkit_core::serialize;

/// A handful of commits, each editing a few files — the shape the
/// issue's Testing Decision asks for ("a sequence of commits each
/// touching a handful of source files under 100KB").
const COMMITS: usize = 6;
const FILES_PER_COMMIT: usize = 4;

/// Deterministic, source-code-shaped filler: a small keyword
/// vocabulary repeated with pseudo-random word choice. Meant to sit
/// between the two unrealistic extremes — pure random bytes (zstd
/// can't compress those at all) and a single repeated byte (zstd
/// compresses those far better than real text) — so the reported
/// ratio is a believable stand-in for "a real small source file" made
/// of English/code-shaped tokens, in the a-few-KiB-to-tens-of-KiB
/// range git's own object format handles well too.
fn synthetic_text(seed: u64, target_len: usize) -> Vec<u8> {
    const WORDS: &[&str] = &[
        "fn", "let", "mut", "struct", "impl", "return", "self", "pub", "match", "Some", "None",
        "Result", "Ok", "Err", "use", "crate", "for", "in", "if", "else", "while", "true", "false",
        "vec", "push", "unwrap", "String", "usize", "async", "await",
    ];
    let mut state = seed | 1;
    let mut out = String::with_capacity(target_len + 16);
    while out.len() < target_len {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let word = WORDS[(state >> 40) as usize % WORDS.len()];
        out.push_str(word);
        out.push(if (state >> 3) & 1 == 0 { ' ' } else { '\n' });
    }
    out.truncate(target_len);
    out.into_bytes()
}

/// Build the corpus as already-serialised `Blob` object bytes — one
/// per (commit, file) pair, each a distinct "edit" (different seed, so
/// no two files are byte-identical) but all drawn from the same
/// text-shaped generator. File sizes vary 8..48 KiB, comfortably under
/// the issue's "<100 KB" ask.
fn build_corpus_blobs() -> Vec<Vec<u8>> {
    let mut blobs = Vec::with_capacity(COMMITS * FILES_PER_COMMIT);
    for commit in 0..COMMITS {
        for file in 0..FILES_PER_COMMIT {
            let len = 8 * 1024 + ((commit * 7 + file * 13) % 40) * 1024;
            let seed = 0x1000_0000_u64
                .wrapping_add((commit as u64) << 8)
                .wrapping_add(file as u64);
            let content = synthetic_text(seed, len);
            let blob = Object::Blob(Blob { data: content });
            blobs.push(serialize::serialize(&blob).expect("serialize synthetic blob"));
        }
    }
    blobs
}

fn build_v2_pack(blobs: &[Vec<u8>]) -> Vec<u8> {
    let mut w = PackWriter::new();
    for blob in blobs {
        w.push_raw(hash::hash(blob), blob).expect("push_raw");
    }
    w.finish().expect("finish pack")
}

fn bench_pack_compression(c: &mut Criterion) {
    let blobs = build_corpus_blobs();

    // v1-equivalent size: header + sum(entry framing + raw payload) +
    // trailer. This is exactly the byte count `PackWriter` produced
    // before issue #646 — pre-#646 it never compressed anything, so
    // this is direct SPEC-PACKFILE §1/§2 arithmetic over the same
    // object bytes, not a second writer code path to keep in sync.
    let v1_equivalent_bytes: usize = HEADER_LEN
        + blobs
            .iter()
            .map(|b| ENTRY_FRAME_LEN + b.len())
            .sum::<usize>()
        + TRAILER_LEN;

    c.bench_function("pack_compression/small_text_corpus/build_v2_pack", |b| {
        b.iter(|| {
            std::hint::black_box(build_v2_pack(&blobs));
        });
    });

    let v2_pack = build_v2_pack(&blobs);
    let raw_object_bytes: usize = blobs.iter().map(Vec::len).sum();
    let ratio = v1_equivalent_bytes as f64 / v2_pack.len() as f64;
    let pct_saved = 100.0 * (1.0 - (v2_pack.len() as f64 / v1_equivalent_bytes as f64));

    eprintln!(
        "pack_compression/small_text_corpus: {COMMITS} commits x {FILES_PER_COMMIT} files \
         ({raw_object_bytes} bytes of raw object content) -> \
         v1(uncompressed)={v1_equivalent_bytes} bytes, v2(compressed)={} bytes, \
         ratio={ratio:.2}x, saved={pct_saved:.1}%",
        v2_pack.len(),
    );
}

criterion_group!(benches, bench_pack_compression);
criterion_main!(benches);
