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
}
