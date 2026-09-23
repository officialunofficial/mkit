use clap::Args;
use serde_json::json;

use super::{OutputFormat, envelope, err, header, open_here, path_text, print_json, read_state};
use crate::exit;

#[derive(Debug, Args)]
pub(super) struct StatusArgs {
    #[arg(long, value_enum, default_value = "human")]
    format: OutputFormat,
}

#[allow(clippy::too_many_lines)] // selected status and bounded extras share one coherent state view
pub(super) fn run(args: &StatusArgs) -> u8 {
    let layout = match open_here() {
        Ok(v) => v,
        Err(c) => return c,
    };
    let state = match read_state(&layout) {
        Ok(v) => v,
        Err(c) => return c,
    };
    let mut files = Vec::new();
    let mut working_total = 0usize;
    for (selected, staged) in state
        .workspace()
        .selection()
        .iter()
        .zip(state.stage().entries())
    {
        let stage_bytes = match state.selected_file_bytes(staged.staged_id()) {
            Ok(v) => v,
            Err(e) => return err(&format!("staged selected file: {e}"), exit::DATAERR),
        };
        let base_bytes = match state.selected_file_bytes(selected.base_file_id()) {
            Ok(v) => v,
            Err(e) => return err(&format!("base selected file: {e}"), exit::DATAERR),
        };
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
        let (working, reason) =
            match layout.capture_selected_file(selected.path(), selected.mode(), cap) {
                Ok(bytes) => {
                    working_total += bytes.len();
                    (Some(bytes), None)
                }
                Err(e) => (None, Some(e.to_string())),
            };
        files.push(json!({
            "path": path_text(selected.path()),
            "staged": stage_bytes != base_bytes,
            "working": working.as_ref().map(|b| b != &stage_bytes),
            "unsupported": reason,
        }));
    }
    let selected = state
        .workspace()
        .selection()
        .iter()
        .map(|s| s.path().clone())
        .collect::<Vec<_>>();
    let (extras, complete) = match layout.extra_paths(&selected, 4096) {
        Ok(v) => v,
        Err(e) => return err(&format!("scan extra paths: {e}"), exit::DATAERR),
    };
    match args.format {
        OutputFormat::Json => {
            let mut output = envelope(&state, "status");
            output["files"] = files.into();
            output["extra_paths"] = extras.into();
            output["extra_scan_complete"] = complete.into();
            print_json(&output);
        }
        OutputFormat::Human => {
            header(&state);
            super::pending_lines(&state);
            for file in &files {
                let raw = file["path"].as_str().unwrap_or("");
                let path = super::super::c_quote_path(raw).unwrap_or_else(|| raw.to_owned());
                if let Some(reason) = file["unsupported"].as_str() {
                    println!("unsupported {path}: {reason}");
                } else if file["staged"] == true || file["working"] == true {
                    println!(
                        "{}{} {path}",
                        if file["staged"] == true {
                            "staged"
                        } else {
                            "      "
                        },
                        if file["working"] == true {
                            "+working"
                        } else {
                            "        "
                        }
                    );
                }
            }
            for path in &extras {
                let shown = super::super::c_quote_path(path).unwrap_or_else(|| path.clone());
                println!("untracked {shown}");
            }
            if !complete {
                println!("Extra-path scan incomplete (4096-entry limit).");
            }
            if files.iter().all(|f| {
                f["staged"] == false && f["working"] == false && f["unsupported"].is_null()
            }) && extras.is_empty()
                && complete
            {
                println!("Selected files clean.");
            }
        }
    }
    exit::OK
}
