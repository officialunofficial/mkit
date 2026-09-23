use clap::Args;
use mkit_core::hash::{hash, to_hex};
use mkit_core::ops::diff::{WhitespaceMode, unified_hunks_opts};
use serde_json::json;

use super::{
    OutputFormat, envelope, err, exact_paths, header, open_here, path_text, print_json, read_state,
};
use crate::exit;

#[derive(Debug, Args)]
pub(super) struct DiffArgs {
    #[arg(long)]
    cached: bool,
    #[arg(long, value_enum, default_value = "human")]
    format: OutputFormat,
    #[arg(last = true)]
    paths: Vec<String>,
}

#[allow(clippy::too_many_lines)] // one selected-only comparison and presentation pipeline
pub(super) fn run(args: &DiffArgs) -> u8 {
    let layout = match open_here() {
        Ok(v) => v,
        Err(c) => return c,
    };
    let state = match read_state(&layout) {
        Ok(v) => v,
        Err(c) => return c,
    };
    let paths = if args.paths.is_empty() {
        state
            .workspace()
            .selection()
            .iter()
            .map(|s| s.path().clone())
            .collect::<Vec<_>>()
    } else {
        match exact_paths(&args.paths, &state) {
            Ok(v) => v,
            Err(c) => return c,
        }
    };
    let mut changes = Vec::new();
    let mut working_total = 0usize;
    for path in &paths {
        let selected = state
            .workspace()
            .selection()
            .iter()
            .find(|s| s.path() == path)
            .expect("validated selection");
        let staged = state
            .stage()
            .entries()
            .iter()
            .find(|s| s.path() == path)
            .expect("verified stage");
        let before_id = if args.cached {
            selected.base_file_id()
        } else {
            staged.staged_id()
        };
        let before = match state.selected_file_bytes(before_id) {
            Ok(v) => v,
            Err(e) => return err(&format!("read selected file: {e}"), exit::DATAERR),
        };
        let after = if args.cached {
            match state.selected_file_bytes(staged.staged_id()) {
                Ok(v) => v,
                Err(e) => return err(&format!("read staged file: {e}"), exit::DATAERR),
            }
        } else {
            let remaining = state
                .workspace()
                .limits()
                .max_total_selected_bytes
                .saturating_sub(working_total);
            let cap = state
                .workspace()
                .limits()
                .max_selected_file_bytes
                .min(remaining);
            match layout.capture_selected_file(path, selected.mode(), cap) {
                Ok(v) => {
                    working_total += v.len();
                    v
                }
                Err(e) => {
                    return err(
                        &format!("unsupported selected file {}: {e}", path_text(path)),
                        exit::DATAERR,
                    );
                }
            }
        };
        if before != after {
            // The shared Myers renderer retains an edit trace proportional
            // to edit distance times line count. Cap both before invoking it.
            let patch = if before.len() <= 512 * 1024
                && after.len() <= 512 * 1024
                && within_line_budget(&before)
                && within_line_budget(&after)
                && safe_text(&before)
                && safe_text(&after)
            {
                unified_hunks_opts(&before, &after, 3, WhitespaceMode::Exact).and_then(|hunks| {
                    (hunks.len() <= 512 * 1024)
                        .then(|| String::from_utf8(hunks).ok())
                        .flatten()
                })
            } else {
                None
            };
            changes.push(json!({"path":path_text(path),"before_bytes":before.len(),"after_bytes":after.len(),"before_digest":to_hex(&hash(&before)),"after_digest":to_hex(&hash(&after)),"patch":patch}));
        }
    }
    match args.format {
        OutputFormat::Json => {
            let mut output = envelope(&state, "diff");
            output["comparison"] = if args.cached {
                "base-to-stage"
            } else {
                "stage-to-working"
            }
            .into();
            output["changes"] = changes.into();
            print_json(&output);
        }
        OutputFormat::Human => {
            header(&state);
            println!(
                "Comparison: {}",
                if args.cached {
                    "base to stage"
                } else {
                    "stage to working"
                }
            );
            for change in &changes {
                let selected_path = change["path"].as_str().unwrap_or("");
                let quoted = super::super::c_quote_path(selected_path)
                    .unwrap_or_else(|| selected_path.to_owned());
                println!("diff --selected {quoted}");
                match change["patch"].as_str() {
                    Some(hunks) => {
                        let minus = format!("a/{selected_path}");
                        let plus = format!("b/{selected_path}");
                        println!(
                            "--- {}",
                            super::super::c_quote_path(&minus).unwrap_or(minus)
                        );
                        println!("+++ {}", super::super::c_quote_path(&plus).unwrap_or(plus));
                        print!("{hunks}");
                    }
                    None => println!(
                        "binary or large content differs ({} -> {} bytes; {} -> {})",
                        change["before_bytes"],
                        change["after_bytes"],
                        change["before_digest"].as_str().unwrap_or(""),
                        change["after_digest"].as_str().unwrap_or("")
                    ),
                }
            }
        }
    }
    exit::OK
}

fn safe_text(bytes: &[u8]) -> bool {
    std::str::from_utf8(bytes).is_ok_and(|text| {
        text.chars()
            .all(|c| c == '\n' || c == '\t' || !c.is_control())
    })
}

fn within_line_budget(bytes: &[u8]) -> bool {
    let mut lines = 0usize;
    for byte in bytes {
        if *byte == b'\n' {
            lines += 1;
            if lines > 512 {
                return false;
            }
        }
    }
    true
}
