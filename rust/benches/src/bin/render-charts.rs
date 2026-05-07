//! Render buffa-style SVG charts from the bench summaries the
//! criterion harnesses write under `target/bench-results/`.
//!
//! For each (category, axis) pair, emits one SVG with horizontal
//! bars — one bar per `library`, ordered by sample order. mkit's
//! library entries get the primary blue (#4C78A8) so the eye lands
//! on them first; comparison libraries get distinct hues from the
//! same Tableau palette buffa uses.
//!
//! Output: `benchmarks/charts/<category>-<axis-slug>.svg`. The
//! filename mirrors buffa's pattern (`binary-decode-api_response.svg`).

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use mkit_benches::{Sample, Unit};

const PALETTE: &[(&str, &str)] = &[
    // (substring of library name, hex). Order matters — first match
    // wins. Keeps mkit/BLAKE3 in the canonical "primary" blue.
    ("BLAKE3", "#4C78A8"),
    ("Ed25519", "#4C78A8"),
    ("secp256k1", "#72B7B2"),
    ("P-256", "#F58518"),
    ("SHA-1", "#F58518"),
    ("SHA-256", "#EEAE62"),
    ("BLAKE2b", "#54A24B"),
    ("mkit", "#4C78A8"),
    ("git2", "#E45756"),
    ("git CLI", "#B279A2"),
    ("git pack-objects", "#9D7660"),
];

fn color_for(library: &str) -> &'static str {
    for (k, v) in PALETTE {
        if library.contains(k) {
            return v;
        }
    }
    "#999999"
}

fn slug(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' => c.to_ascii_lowercase(),
            _ => '_',
        })
        .collect::<String>()
        .trim_matches('_')
        .replace("__", "_")
}

fn fmt_value(v: f64, unit: Unit) -> String {
    match unit {
        Unit::MibPerSec => {
            if v >= 1000.0 {
                format!("{:.0}", v)
                    .bytes()
                    .rev()
                    .enumerate()
                    .map(|(i, b)| {
                        let ch = b as char;
                        if i > 0 && i % 3 == 0 {
                            format!("{ch},")
                        } else {
                            ch.to_string()
                        }
                    })
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect::<String>()
            } else {
                format!("{:.0}", v)
            }
        }
        Unit::OpsPerSec => {
            if v >= 1000.0 {
                format!("{:.0}", v)
                    .bytes()
                    .rev()
                    .enumerate()
                    .map(|(i, b)| {
                        let ch = b as char;
                        if i > 0 && i % 3 == 0 {
                            format!("{ch},")
                        } else {
                            ch.to_string()
                        }
                    })
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect::<String>()
            } else {
                format!("{:.0}", v)
            }
        }
        Unit::Millis => {
            // Show µs for sub-millisecond latencies — "0.00 ms" is
            // useless, "133 µs" carries information.
            if v < 1.0 {
                format!("{:.0} µs", v * 1000.0)
            } else if v < 100.0 {
                format!("{v:.2} ms")
            } else {
                format!("{v:.0} ms")
            }
        }
    }
}

fn fmt_axis(v: f64) -> String {
    if v >= 1000.0 {
        format!("{:.0}", v)
            .bytes()
            .rev()
            .enumerate()
            .map(|(i, b)| {
                let ch = b as char;
                if i > 0 && i % 3 == 0 {
                    format!("{ch},")
                } else {
                    ch.to_string()
                }
            })
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<String>()
    } else if v == v.floor() {
        format!("{v:.0}")
    } else {
        format!("{v:.1}")
    }
}

/// Bar length is throughput (longer = better) for MibPerSec /
/// OpsPerSec. For Millis (wallclock; smaller = better), we plot
/// `1000.0 / value` so the bar still grows with goodness, AND we
/// override the unit at chart time to OpsPerSec so the axis label
/// matches what the bar represents.
fn bar_metric(s: &Sample) -> f64 {
    match s.unit {
        Unit::MibPerSec | Unit::OpsPerSec => s.value,
        Unit::Millis => 1000.0 / s.value.max(0.0001),
    }
}

/// What the axis should label itself as. Millis → ops/s, since the
/// bar metric IS ops/s.
fn axis_unit(stored: Unit) -> Unit {
    match stored {
        Unit::Millis => Unit::OpsPerSec,
        other => other,
    }
}

fn render_chart(
    title: &str,
    axis_unit: Unit,
    display_unit: Unit,
    libraries: &[(String, f64, f64)], // (label, raw value, bar metric)
) -> String {
    let width = 800.0;
    let n = libraries.len();
    let row_h = 26.0;
    let top_pad = 60.0;
    let bottom_pad = 40.0;
    let height = top_pad + n as f64 * row_h + bottom_pad;
    let bar_x = 200.0;
    let bar_max = width - bar_x - 80.0;
    let max_metric = libraries
        .iter()
        .map(|(_, _, m)| *m)
        .fold(0.0f64, f64::max)
        .max(1.0);
    // Round axis up to a nice number.
    let ticks = nice_ticks(max_metric, 5);
    let axis_max = *ticks.last().unwrap();

    let mut svg = String::new();
    svg.push_str(&format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{width:.0}\" height=\"{height:.0}\" viewBox=\"0 0 {width:.0} {height:.0}\">\n"
    ));
    svg.push_str(
        "  <style>\n\
            text { font-family: -apple-system, BlinkMacSystemFont, \"Segoe UI\", Helvetica, Arial, sans-serif; }\n\
            .title { font-size: 16px; font-weight: 600; fill: #24292f; }\n\
            .label { font-size: 12px; fill: #24292f; }\n\
            .value { font-size: 11px; fill: #57606a; }\n\
            .axis-label { font-size: 11px; fill: #57606a; }\n\
            .grid { stroke: #d0d7de; stroke-width: 0.5; }\n\
          </style>\n"
    );
    svg.push_str("  <rect width=\"100%\" height=\"100%\" fill=\"white\"/>\n");
    svg.push_str(&format!(
        "  <text x=\"{:.1}\" y=\"30\" text-anchor=\"middle\" class=\"title\">{}</text>\n",
        width / 2.0,
        escape_xml(title)
    ));

    // Grid + axis ticks.
    let chart_top = top_pad - 8.0;
    let chart_bottom = top_pad + n as f64 * row_h;
    for t in &ticks {
        let x = bar_x + (*t / axis_max) * bar_max;
        svg.push_str(&format!(
            "  <line x1=\"{x:.1}\" y1=\"{chart_top:.1}\" x2=\"{x:.1}\" y2=\"{chart_bottom:.1}\" class=\"grid\"/>\n"
        ));
        svg.push_str(&format!(
            "  <text x=\"{x:.1}\" y=\"{:.1}\" text-anchor=\"middle\" class=\"axis-label\">{}</text>\n",
            chart_bottom + 14.0,
            fmt_axis(*t)
        ));
    }
    svg.push_str(&format!(
        "  <text x=\"{:.1}\" y=\"{:.1}\" text-anchor=\"middle\" class=\"axis-label\">{}</text>\n",
        bar_x + bar_max / 2.0,
        chart_bottom + 30.0,
        axis_unit.axis_label()
    ));

    // Rows.
    for (i, (label, raw, metric)) in libraries.iter().enumerate() {
        let y = top_pad + i as f64 * row_h;
        let bar_w = (metric / axis_max) * bar_max;
        // Library label, right-aligned.
        svg.push_str(&format!(
            "  <text x=\"{:.1}\" y=\"{:.1}\" text-anchor=\"end\" class=\"label\">{}</text>\n",
            bar_x - 10.0,
            y + row_h * 0.66,
            escape_xml(label)
        ));
        // Bar.
        svg.push_str(&format!(
            "  <rect x=\"{bar_x:.1}\" y=\"{y:.1}\" width=\"{bar_w:.1}\" height=\"{:.1}\" rx=\"2\" fill=\"{}\"/>\n",
            row_h * 0.7,
            color_for(label)
        ));
        // Value (printed in the unit the user wants to read, even
        // when the bar metric is something else — e.g. millis benches
        // plot ops/s but print "13.72 ms" for human latency feel).
        svg.push_str(&format!(
            "  <text x=\"{:.1}\" y=\"{:.1}\" class=\"value\">{}</text>\n",
            bar_x + bar_w + 8.0,
            y + row_h * 0.66,
            fmt_value(*raw, display_unit)
        ));
    }

    svg.push_str("</svg>\n");
    svg
}

fn nice_ticks(max: f64, n: usize) -> Vec<f64> {
    let step = nice_step(max / n as f64);
    let last_step_count = (max / step).ceil() as usize;
    (0..=last_step_count).map(|i| i as f64 * step).collect()
}

fn nice_step(rough: f64) -> f64 {
    if rough <= 0.0 {
        return 1.0;
    }
    let exp = rough.log10().floor();
    let frac = rough / 10f64.powf(exp);
    let nice = if frac < 1.5 {
        1.0
    } else if frac < 3.5 {
        2.0
    } else if frac < 7.5 {
        5.0
    } else {
        10.0
    };
    nice * 10f64.powf(exp)
}

fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn humanize_axis(axis: &str) -> String {
    axis.to_string()
}

fn category_title(category: &str) -> &'static str {
    match category {
        "hashing" => "Hash Throughput",
        "sign" => "Signature Throughput — Sign",
        "verify" => "Signature Throughput — Verify",
        "object-commit" => "Object Commit Wallclock",
        "pack-create" => "Pack Create Wallclock",
        _ => "Benchmark",
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let workspace_root = std::env::var("CARGO_MANIFEST_DIR")
        .map(|s| {
            // From `rust/benches/`, walk up to repo root.
            let p = PathBuf::from(s);
            p.parent()
                .and_then(Path::parent)
                .map_or(PathBuf::from("."), Path::to_path_buf)
        })
        .unwrap_or_else(|_| PathBuf::from("."));
    let results_dir = workspace_root.join("rust/target/bench-results");
    let charts_dir = workspace_root.join("benchmarks/charts");
    fs::create_dir_all(&charts_dir)?;

    if !results_dir.is_dir() {
        return Err(format!(
            "no bench results at {}; run `cargo bench --workspace` first",
            results_dir.display()
        )
        .into());
    }

    // Aggregate every bench-results/*.json into a single sample list.
    let mut all: Vec<Sample> = Vec::new();
    for entry in fs::read_dir(&results_dir)? {
        let entry = entry?;
        if entry.path().extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let body = fs::read_to_string(entry.path())?;
        let mut s: Vec<Sample> = serde_json::from_str(&body)?;
        all.append(&mut s);
    }

    // Group by (category, axis).
    let mut groups: BTreeMap<(String, String), Vec<Sample>> = BTreeMap::new();
    for s in all {
        groups
            .entry((s.category.clone(), s.axis.clone()))
            .or_default()
            .push(s);
    }

    let mut written = 0usize;
    for ((category, axis), samples) in &groups {
        let stored_unit = samples.first().map(|s| s.unit).unwrap_or(Unit::MibPerSec);
        let render_unit = axis_unit(stored_unit);
        let display_unit = stored_unit;
        let mut rows: Vec<(String, f64, f64)> = samples
            .iter()
            .map(|s| (s.library.clone(), s.value, bar_metric(s)))
            .collect();
        // Sort with mkit first, then descending by metric.
        rows.sort_by(|a, b| {
            let a_is_mkit = a.0.contains("mkit") || a.0.contains("BLAKE3");
            let b_is_mkit = b.0.contains("mkit") || b.0.contains("BLAKE3");
            match (a_is_mkit, b_is_mkit) {
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                _ => b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal),
            }
        });

        let suffix = if matches!(stored_unit, Unit::Millis) {
            " (ops/s — higher is better)"
        } else {
            ""
        };
        let title = format!("{} — {}{suffix}", category_title(category), humanize_axis(axis));
        let svg = render_chart(&title, render_unit, display_unit, &rows);
        let path = charts_dir.join(format!("{}-{}.svg", slug(category), slug(axis)));
        fs::write(&path, svg)?;
        written += 1;
    }

    println!("wrote {written} charts to {}", charts_dir.display());
    Ok(())
}
