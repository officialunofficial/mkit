//! Line-level diff (`ops::unified_hunks`, the Myers edit script behind
//! `diff`/`show`/`add -p`/3-way merge) at increasing file sizes.
//!
//! Regression guard for the common-**prefix** elision in
//! `ops::diff::myers_changed`: a real edit almost always leaves most of a
//! file as a shared, unchanged leading run (a single changed line, an
//! appended block), and Myers' `O((N+M)*D)` core pays for the *whole*
//! `old`/`new` line count on every call regardless of how small the actual
//! edit `D` is — the `v`/`trace` state it allocates and clones is sized off
//! `old.len() + new.len()` up front, not off the surrounding context.
//! Eliding the shared prefix before the core runs shrinks that `N+M` down
//! toward the size of the real edit. (A common *trailing* run is not
//! elided — an earlier version of this optimization also tried that, but
//! it's unsound for reasons `myers_changed`'s own doc comment covers; the
//! `single_line_edit` scenario below still benefits from prefix-only
//! elision, just less than it would from eliding both ends.)
//!
//! `no_common_affix` is the control: old/new share no prefix at all, so
//! elision finds nothing to trim and this bench's numbers should be
//! unaffected (same cost as before, not a regression) — the case where
//! trimming can't help, not the case it's for. It also has no line in
//! common at all between the two sides, which is Myers' own worst case
//! (edit distance `D` proportional to `n+m`, `O((n+m)*D)` degrading to
//! `O((n+m)^2)`) independent of this change, so it's kept at a much
//! smaller size than the other two scenarios — this bench isolates the
//! prefix elision, not that pre-existing, unrelated cost.
//!
//! Numbers are wallclock ms; smaller is better.

use criterion::{Criterion, criterion_group, criterion_main};
use mkit_benches::{Sample, Unit, time_one};
use mkit_core::ops::unified_hunks;

const LINE_COUNTS: &[(usize, &str)] = &[
    (1_000, "1k lines"),
    (10_000, "10k lines"),
    (100_000, "100k lines"),
];
/// `no_common_affix` only: `O((n+m)^2)` there makes 100k lines impractical
/// (unrelated to this change — see module doc).
const NO_AFFIX_LINE_COUNTS: &[(usize, &str)] = &[(1_000, "1k lines"), (2_000, "2k lines")];

fn lines(n: usize, make: impl Fn(usize) -> String) -> Vec<u8> {
    // ~8 bytes/line is a reasonable estimate for this file's fixtures
    // ("line 12345\n"); avoids repeated reallocation building 100k-line
    // fixtures, matching the preallocation convention `content_eq.rs`'s
    // `fixture()` already uses for its own large buffers.
    let mut out = String::with_capacity(n * 8);
    for i in 0..n {
        out.push_str(&make(i));
        out.push('\n');
    }
    out.into_bytes()
}

/// Single-line edit near the middle of an `n`-line file: shares a long
/// prefix (and, though `myers_changed` no longer elides it, a long
/// unchanged suffix the O(ND) core still has to walk), differing only at
/// one line.
fn single_line_edit(n: usize) -> (Vec<u8>, Vec<u8>) {
    let old = lines(n, |i| format!("line {i}"));
    let mid = n / 2;
    let new = lines(n, |i| {
        if i == mid {
            format!("line {i} EDITED")
        } else {
            format!("line {i}")
        }
    });
    (old, new)
}

/// Append 200 new lines to the end of an `n`-line file: shares the entire
/// original file as a common prefix, differing only in the appended tail.
fn append_tail(n: usize) -> (Vec<u8>, Vec<u8>) {
    let old = lines(n, |i| format!("line {i}"));
    let new = lines(n + 200, |i| format!("line {i}"));
    (old, new)
}

/// No shared prefix at all — every line differs. The control: elision has
/// nothing to trim here, so this measures the untrimmed cost (confirms no
/// regression).
fn no_common_affix(n: usize) -> (Vec<u8>, Vec<u8>) {
    let old = lines(n, |i| format!("old {i}"));
    let new = lines(n, |i| format!("new {i}"));
    (old, new)
}

type Scenario = (&'static str, fn(usize) -> (Vec<u8>, Vec<u8>));
const SCENARIOS: &[Scenario] = &[
    ("single_line_edit", single_line_edit),
    ("append_tail", append_tail),
];

fn run_one(
    c: &mut Criterion,
    samples: &mut Vec<Sample>,
    name: &str,
    label: &str,
    old: &[u8],
    new: &[u8],
) {
    let axis = format!("{label}/{name}");
    c.bench_function(&format!("diff_edit_script/{axis}"), |b| {
        b.iter(|| std::hint::black_box(unified_hunks(old, new)));
    });
    let ms = time_one(2, 10, || {
        std::hint::black_box(unified_hunks(old, new));
    }) * 1000.0;
    eprintln!("diff_edit_script/{axis}: {ms:.4} ms");
    samples.push(Sample {
        category: "diff_edit_script".into(),
        axis,
        library: "unified_hunks".into(),
        value: ms,
        unit: Unit::Millis,
    });
}

fn bench_diff_edit_script(c: &mut Criterion) {
    let mut samples: Vec<Sample> = Vec::new();

    for &(count, label) in LINE_COUNTS {
        for &(name, make) in SCENARIOS {
            let (old, new) = make(count);
            run_one(c, &mut samples, name, label, &old, &new);
        }
    }
    for &(count, label) in NO_AFFIX_LINE_COUNTS {
        let (old, new) = no_common_affix(count);
        run_one(c, &mut samples, "no_common_affix", label, &old, &new);
    }

    mkit_benches::write_summary("diff_edit_script", &samples);
}

criterion_group!(name = benches; config = Criterion::default().sample_size(10); targets = bench_diff_edit_script);
criterion_main!(benches);
