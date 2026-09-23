use clap::Args;
use mkit_core::partial::FileReplacement;
use serde_json::json;

use super::{
    OutputFormat, envelope, err, exact_paths, header, open_here, path_text, print_json, read_state,
};
use crate::exit;

#[derive(Debug, Args)]
pub(super) struct AddArgs {
    #[arg(long, conflicts_with = "paths")]
    all: bool,
    #[arg(long, value_enum, default_value = "human")]
    format: OutputFormat,
    #[arg(last = true)]
    paths: Vec<String>,
}

pub(super) fn run(args: &AddArgs) -> u8 {
    let layout = match open_here() {
        Ok(v) => v,
        Err(c) => return c,
    };
    let state = match read_state(&layout) {
        Ok(v) => v,
        Err(c) => return c,
    };
    if !args.all && args.paths.is_empty() {
        return err("workspace add requires --all or -- PATH...", exit::USAGE);
    }
    let paths = if args.all {
        state
            .workspace()
            .selection()
            .iter()
            .map(|s| s.path().clone())
            .collect::<Vec<_>>()
    } else {
        match exact_paths(&args.paths, &state) {
            Ok(p) => p,
            Err(c) => return c,
        }
    };
    let mut replacements = Vec::new();
    let mut total = 0usize;
    for path in &paths {
        let selected = state
            .workspace()
            .selection()
            .iter()
            .find(|s| s.path() == path)
            .expect("validated selection");
        let remaining = state
            .workspace()
            .limits()
            .max_total_selected_bytes
            .saturating_sub(total);
        let cap = state
            .workspace()
            .limits()
            .max_selected_file_bytes
            .min(remaining);
        let bytes = match layout.capture_selected_file(path, selected.mode(), cap) {
            Ok(v) => v,
            Err(e) => {
                return err(
                    &format!("cannot stage {}: {e}", path_text(path)),
                    exit::DATAERR,
                );
            }
        };
        total = match total.checked_add(bytes.len()) {
            Some(v) if v <= state.workspace().limits().max_total_selected_bytes => v,
            _ => return err("selected batch exceeds size limit", exit::DATAERR),
        };
        replacements.push(FileReplacement::bytes(path.clone(), bytes));
    }
    let next = match layout.replace_stage(state.workspace().transaction_generation(), &replacements)
    {
        Ok(v) => v,
        Err(e) => return err(&format!("stage selected batch: {e}"), exit::DATAERR),
    };
    match args.format {
        OutputFormat::Human => {
            header(&next);
            println!("Staged {} selected file(s).", paths.len());
        }
        OutputFormat::Json => {
            let mut output = envelope(&next, "add");
            output["staged_paths"] = json!(paths.iter().map(path_text).collect::<Vec<_>>());
            output["transaction_generation"] = next.workspace().transaction_generation().into();
            print_json(&output);
        }
    }
    exit::OK
}
