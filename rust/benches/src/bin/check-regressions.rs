//! Nightly regression gate for the criterion micro-benches.
//!
//! `cargo bench ... -- --baseline committed` (after
//! `scripts/bench-baseline.sh restore` seeds `target/criterion/` from
//! the tracked snapshot) makes criterion write one
//! `<bench-dir>/change/estimates.json` per benchmark, comparing the
//! just-run mean wall-clock time against the committed baseline as a
//! fractional change (e.g. `0.12` = 12% slower). This binary walks
//! every `change/estimates.json` under `target/criterion/`, and fails
//! (non-zero exit) if any benchmark's mean regressed beyond a
//! documented tolerance.
//!
//! Per #609's tiering, these are tier-3 absolute wall-clock timings:
//! nightly-with-tolerance, never PR-blocking. This binary is invoked
//! only from `.github/workflows/bench-nightly.yml`, on a schedule —
//! never from the per-PR gate. A failure here fails that scheduled
//! job (and, printed above the failure, a plain-text report), not any
//! PR check.
//!
//! Usage: `cargo run -p mkit-benches --bin check-regressions`
//!
//! Env:
//! - `MKIT_BENCH_TOLERANCE` — fractional regression tolerance to flag
//!   (default `0.25`, i.e. 25%). Deliberately generous: these numbers
//!   run on shared/variable CI hardware, and the goal is to catch
//!   real regressions like #606 (which moved the write path 55%), not
//!   to chase noise on a tier-3 absolute-timing bench.

use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct ConfidenceInterval {
    lower_bound: f64,
    upper_bound: f64,
}

#[derive(Debug, Deserialize)]
struct Estimate {
    confidence_interval: ConfidenceInterval,
    point_estimate: f64,
}

#[derive(Debug, Deserialize)]
struct ChangeEstimates {
    mean: Estimate,
}

fn tolerance() -> f64 {
    std::env::var("MKIT_BENCH_TOLERANCE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0.25)
}

fn workspace_root() -> PathBuf {
    // From rust/benches/, walk up to the repo root (same trick
    // render-charts.rs uses).
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".into());
    let p = PathBuf::from(manifest);
    p.parent()
        .and_then(Path::parent)
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
}

fn collect_change_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        if path.file_name().and_then(|n| n.to_str()) == Some("change") {
            let f = path.join("estimates.json");
            if f.is_file() {
                out.push(f);
            }
            // "change" is a leaf directory in criterion's layout — no
            // need to recurse further into it.
            continue;
        }
        collect_change_files(&path, out);
    }
}

/// `.../<bench-dir>/change/estimates.json` -> `<bench-dir>` relative
/// to `target/criterion`, for a human-readable report line.
fn bench_name_from_change_path(criterion_dir: &Path, change_estimates: &Path) -> String {
    change_estimates
        .parent()
        .and_then(Path::parent)
        .and_then(|p| p.strip_prefix(criterion_dir).ok())
        .map_or_else(
            || change_estimates.display().to_string(),
            |p| p.display().to_string(),
        )
}

fn main() {
    let tolerance = tolerance();
    let criterion_dir = workspace_root().join("rust/target/criterion");

    if !criterion_dir.is_dir() {
        eprintln!(
            "error: no {} — run the benches first (see scripts/bench-baseline.sh and \
             .github/workflows/bench-nightly.yml)",
            criterion_dir.display()
        );
        std::process::exit(1);
    }

    let mut change_files = Vec::new();
    collect_change_files(&criterion_dir, &mut change_files);
    change_files.sort();

    if change_files.is_empty() {
        eprintln!(
            "error: no change/estimates.json files found under {} — the bench run did not \
             compare against a baseline (expected `-- --baseline committed`). Treating this \
             as a hard failure rather than silently reporting green: a broken nightly wiring \
             must not look like a clean bench run.",
            criterion_dir.display()
        );
        std::process::exit(1);
    }

    println!(
        "Regression check — {} comparison(s), tolerance {:.0}% (MKIT_BENCH_TOLERANCE)\n",
        change_files.len(),
        tolerance * 100.0
    );
    println!(
        "{:<60} {:>9}  {:>18}  status",
        "benchmark", "mean Δ", "95% CI"
    );

    let mut regressed: Vec<(String, f64)> = Vec::new();
    for path in &change_files {
        let bench_name = bench_name_from_change_path(&criterion_dir, path);
        let body = match fs::read_to_string(path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("warning: could not read {}: {e}", path.display());
                continue;
            }
        };
        let estimates: ChangeEstimates = match serde_json::from_str(&body) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("warning: could not parse {}: {e}", path.display());
                continue;
            }
        };
        let delta = estimates.mean.point_estimate;
        let ci = &estimates.mean.confidence_interval;
        let status = if delta > tolerance {
            regressed.push((bench_name.clone(), delta * 100.0));
            "REGRESSED"
        } else if delta < -tolerance {
            "improved"
        } else {
            "ok"
        };
        println!(
            "{:<60} {:>+8.1}%  [{:>+7.1}%,{:>+6.1}%]  {}",
            bench_name,
            delta * 100.0,
            ci.lower_bound * 100.0,
            ci.upper_bound * 100.0,
            status
        );
    }

    if regressed.is_empty() {
        println!(
            "\nNo benchmark regressed beyond the {:.0}% tolerance.",
            tolerance * 100.0
        );
        return;
    }

    eprintln!(
        "\n{} benchmark(s) regressed beyond the {:.0}% tolerance:",
        regressed.len(),
        tolerance * 100.0
    );
    for (name, pct) in &regressed {
        eprintln!("  - {name}: {pct:+.1}%");
    }
    std::process::exit(1);
}
