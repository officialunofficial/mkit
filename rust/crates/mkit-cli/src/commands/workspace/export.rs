use std::path::PathBuf;

use clap::Args;
use mkit_core::hash::to_hex;
use serde_json::json;

use super::{OutputFormat, envelope, err, header, open_here, print_json, read_state};
use crate::exit;

#[derive(Debug, Args)]
pub(super) struct ExportArgs {
    #[arg(long, value_name = "FILE")]
    output: PathBuf,
    #[arg(long, value_enum, default_value = "human")]
    format: OutputFormat,
}

pub(super) fn run(args: &ExportArgs) -> u8 {
    let layout = match open_here() {
        Ok(v) => v,
        Err(c) => return c,
    };
    let state = match read_state(&layout) {
        Ok(v) => v,
        Err(c) => return c,
    };
    let pending = match state.pending() {
        Some(v) => v,
        None => return err("no pending candidate to export", exit::USAGE),
    };
    let size = match layout.export_pending_to(
        state.workspace().transaction_generation(),
        &pending.identity(),
        &args.output,
    ) {
        Ok(v) => v,
        Err(e) => return err(&format!("export pending update: {e}"), exit::CANTCREAT),
    };
    match args.format {
        OutputFormat::Human => {
            header(&state);
            println!(
                "Exported exact pending update for {} to {} ({} bytes). Publication state is unchanged.",
                to_hex(pending.candidate_id()),
                args.output.display(),
                size
            );
        }
        OutputFormat::Json => {
            let mut output = envelope(&state, "export");
            output["candidate"] = json!(to_hex(pending.candidate_id()));
            output["output"] = json!(args.output);
            output["bytes"] = json!(size);
            output["pending_status"] = json!(format!("{:?}", pending.status()).to_lowercase());
            output["publication"] = json!("unchanged");
            print_json(&output);
        }
    }
    exit::OK
}
