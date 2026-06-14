//! Shared types between the bench harnesses and the SVG renderer.

use serde::{Deserialize, Serialize};
use std::path::Path;

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
