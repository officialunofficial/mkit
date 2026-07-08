//! Shared types between the bench harnesses and the SVG renderer.

use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::Instant;

/// Time a single invocation of `f` in seconds-per-call.
///
/// Runs `warmup` un-timed iterations to settle caches/branch
/// predictors, then `iters` timed iterations and returns the mean
/// wall-clock seconds per call. Used to populate the flat summary JSON
/// the renderer reads — criterion writes its own per-iteration
/// estimates, but those are buried in nested dirs and we want a flat
/// shape. Shared by every loop-based bench suite so the measurement
/// contract lives in one place.
///
/// # Panics
/// Panics if `iters` is zero.
pub fn time_one<F: FnMut()>(warmup: u32, iters: u32, mut f: F) -> f64 {
    assert!(iters > 0, "time_one requires at least one timed iteration");
    for _ in 0..warmup {
        f();
    }
    let t0 = Instant::now();
    for _ in 0..iters {
        f();
    }
    t0.elapsed().as_secs_f64() / f64::from(iters)
}

/// Cold, per-repetition timing with fresh fixture state each rep.
///
/// `time_one` calls its closure repeatedly against whatever state the
/// closure already captured. That is wrong for anything backed by a
/// content-addressed store, a git ODB, or any other fixture with a
/// dedup / "already exists" fast path: the first call does the real
/// work, every call after it is measuring a no-op. PR #604 found
/// exactly this — `object_commit` reported a 100-file commit as
/// *cheaper* than a 10-file commit, because both the criterion
/// `b.iter` loop and the hand-rolled `time_one` sample reused the same
/// `ObjectStore` across every iteration, so only the very first
/// iteration ever wrote real bytes.
///
/// `time_cold` runs `reps` independent repetitions. Each repetition
/// calls `setup` to build brand-new fixture state (a fresh tempdir +
/// store, typically), then times exactly one call to `routine` against
/// that fresh state — so every repetition measures the same cold-start
/// cost, and the average can't be short-circuited by a warm cache or a
/// dedup hit. Returns the mean wall-clock seconds per call.
///
/// # Panics
/// Panics if `reps` is zero.
pub fn time_cold<S, F: FnMut() -> S, R: FnMut(S)>(reps: u32, mut setup: F, mut routine: R) -> f64 {
    assert!(reps > 0, "time_cold requires at least one repetition");
    let mut total = 0.0f64;
    for _ in 0..reps {
        let state = setup();
        let t0 = Instant::now();
        routine(state);
        total += t0.elapsed().as_secs_f64();
    }
    total / f64::from(reps)
}

/// Assert that `later` (more/bigger real work) did not measure cheaper
/// than `earlier` (less/smaller real work). Panics loudly, naming both
/// samples, when the ordering is physically impossible — the class of
/// bug PR #604 found in `object_commit` (100 files reported cheaper
/// than 10). Call this from a bench's own summary-building code AND
/// from a `#[test]` so the regression is caught both by `cargo test`
/// and by a nightly `cargo bench` run.
///
/// # Panics
/// Panics when `later.1 < earlier.1`.
pub fn assert_monotonic(context: &str, earlier: (&str, f64), later: (&str, f64)) {
    assert!(
        later.1 >= earlier.1,
        "{context}: {} ({:.6}) measured CHEAPER than {} ({:.6}) — physically \
         impossible for strictly more work; the fixture is almost certainly \
         contaminated across iterations (dedup/stat-cache short-circuit)",
        later.0,
        later.1,
        earlier.0,
        earlier.1,
    );
}

/// One benchmark sample: which library / variant produced what
/// throughput on what input. The renderer groups these by `category`
/// + `axis` (x-axis label) and emits one SVG per (category, axis)
/// pair, with one bar per `library`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sample {
    /// e.g. "hashing", "sign", "verify", "object-commit", "pack-create".
    pub category: String,
    /// e.g. "1 KiB", "64 KiB", "Ed25519", "100 files".
    pub axis: String,
    /// e.g. "BLAKE3 (mkit)", "SHA-1", "git2", "git CLI".
    pub library: String,
    /// Throughput in MiB/s (for byte-stream benchmarks) or ops/s (for
    /// signature benchmarks). Renderer reads `unit` to label the axis.
    pub value: f64,
    pub unit: Unit,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Unit {
    MibPerSec,
    OpsPerSec,
    /// Wallclock milliseconds — bars sized by `1000 / value`, so
    /// faster wins.
    Millis,
}

impl Unit {
    #[must_use]
    pub fn axis_label(self) -> &'static str {
        match self {
            Self::MibPerSec => "MiB/s",
            Self::OpsPerSec => "ops/s",
            Self::Millis => "ms",
        }
    }
}

/// Write `samples` as pretty JSON to `target/bench-results/{category}.json`
/// (relative to the workspace root), the location `render-charts` reads.
/// Shared by every bench suite so the output contract lives in one place.
pub fn write_summary(category: &str, samples: &[Sample]) {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".into());
    let dir = Path::new(&manifest).parent().map_or_else(
        || Path::new("target/bench-results").to_path_buf(),
        |p| p.join("target/bench-results"),
    );
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join(format!("{category}.json"));
    let body = serde_json::to_string_pretty(samples).expect("serialize samples");
    if let Err(e) = std::fs::write(&path, body) {
        eprintln!("warning: could not write {}: {e}", path.display());
    } else {
        eprintln!("wrote {}", path.display());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_one_runs_warmup_then_timed_iters() {
        // Counts every call (warmup + timed) so we can confirm the
        // helper honours both parameters.
        let mut total_calls = 0u32;
        let _ = time_one(3, 5, || total_calls += 1);
        assert_eq!(total_calls, 3 + 5, "should run warmup + timed calls");
    }

    #[test]
    #[should_panic(expected = "at least one timed iteration")]
    fn time_one_rejects_zero_iters() {
        let _ = time_one(2, 0, || {});
    }

    #[test]
    fn time_cold_reruns_setup_every_repetition() {
        // Each repetition must get a fresh `setup()` call — that's the
        // whole point of the helper (no state leaks/accumulates
        // between reps the way a shared closure over `time_one` would).
        let mut setup_calls = 0u32;
        let mut routine_calls = 0u32;
        let _ = time_cold(
            4,
            || {
                setup_calls += 1;
                setup_calls
            },
            |state| {
                routine_calls += 1;
                assert_eq!(
                    state, routine_calls,
                    "setup must run before each routine call"
                );
            },
        );
        assert_eq!(setup_calls, 4);
        assert_eq!(routine_calls, 4);
    }

    #[test]
    #[should_panic(expected = "at least one repetition")]
    fn time_cold_rejects_zero_reps() {
        let _ = time_cold(0, || (), |()| {});
    }

    #[test]
    fn assert_monotonic_allows_nondecreasing() {
        assert_monotonic("test", ("10 files", 1.0), ("100 files", 5.0));
        assert_monotonic("test", ("10 files", 1.0), ("100 files", 1.0));
    }

    #[test]
    #[should_panic(expected = "physically impossible")]
    fn assert_monotonic_rejects_cheaper_later_sample() {
        // This is the exact shape of PR #604's bug: a 100-file commit
        // (`later`) reporting less wall-clock than a 10-file commit
        // (`earlier`).
        assert_monotonic("object-commit/mkit", ("10 files", 5.0), ("100 files", 1.0));
    }

    /// Cheap, real end-to-end regression guard (not a mock): writes N
    /// distinct blobs into a fresh on-disk [`mkit_core::store::ObjectStore`]
    /// for N = 10 and N = 100, using [`time_cold`] so each repetition
    /// gets its own tempdir/store and can't dedup-hit against a
    /// previous repetition's objects. If a future edit reintroduces
    /// PR #604's shared-fixture bug (e.g. someone "simplifies" a bench
    /// back to a single `ObjectStore` reused across iterations), this
    /// fails `cargo test -p mkit-benches` — not just the nightly bench
    /// job — so the lie can't come back silently.
    #[test]
    fn object_store_write_cost_is_monotonic_in_object_count() {
        use mkit_core::layout::RepoLayout;
        use mkit_core::store::ObjectStore;

        fn cold_write_cost(n: usize, reps: u32) -> f64 {
            time_cold(
                reps,
                || {
                    let dir = tempfile::tempdir().unwrap();
                    let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
                    let payloads: Vec<Vec<u8>> = (0..n)
                        .map(|i| format!("object-store-monotonic-test {i}\n").into_bytes())
                        .collect();
                    (dir, store, payloads)
                },
                |(_dir, store, payloads)| {
                    for p in &payloads {
                        store.write(p).unwrap();
                    }
                },
            )
        }

        // 2 reps keeps this test fast (real fsyncs: 2 * (10 + 100) =
        // 220 on-disk writes) while still averaging away one-off
        // scheduler noise.
        let ten = cold_write_cost(10, 2);
        let hundred = cold_write_cost(100, 2);
        assert_monotonic(
            "object_store_write_cost_is_monotonic_in_object_count",
            ("10 objects", ten),
            ("100 objects", hundred),
        );
    }
}
