use clap::Args;
use mkit_core::hash::to_hex;
use serde_json::json;

use super::{OutputFormat, envelope, header, open_here, print_json, read_state};
use crate::exit;

#[derive(Debug, Args)]
pub(super) struct LogArgs {
    #[arg(long, value_enum, default_value = "human")]
    format: OutputFormat,
}

pub(super) fn run(args: &LogArgs) -> u8 {
    let layout = match open_here() {
        Ok(v) => v,
        Err(c) => return c,
    };
    let state = match read_state(&layout) {
        Ok(v) => v,
        Err(c) => return c,
    };
    let mut entries = Vec::new();
    if let Some(pending) = state.pending() {
        entries.push(json!({"kind":"pending-candidate-id","id":to_hex(pending.candidate_id()),"status":format!("{:?}",pending.status())}));
    }
    if let Some(accepted) = state.accepted() {
        entries.push(
            json!({"kind":"locally-recorded-accepted-id","id":to_hex(accepted.candidate_id())}),
        );
    }
    entries.push(json!({"kind":"authenticated-base","id":to_hex(state.workspace().base_id())}));
    match args.format {
        OutputFormat::Json => {
            let mut output = envelope(&state, "log");
            output["local_entries"] = entries.into();
            output["history_boundary"] = "earlier history unavailable".into();
            print_json(&output);
        }
        OutputFormat::Human => {
            header(&state);
            for entry in &entries {
                println!(
                    "{} {}",
                    entry["kind"].as_str().unwrap_or(""),
                    entry["id"].as_str().unwrap_or("")
                );
            }
            println!("Earlier history unavailable.");
        }
    }
    exit::OK
}
