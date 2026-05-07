//! Shared types between the bench harnesses and the SVG renderer.

use serde::{Deserialize, Serialize};

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
