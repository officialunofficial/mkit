use clap::Args;
use mkit_core::hash::{from_hex, to_hex};
use serde_json::json;

use super::{OutputFormat, envelope, err, header, open_here, print_json, read_state};
use crate::exit;

#[derive(Debug, Args)]
pub(super) struct AbandonArgs {
    #[arg(long, value_name = "ID")]
    candidate: String,
    #[arg(long = "acknowledge-possible-publication")]
    acknowledge_possible_publication: bool,
    #[arg(long, value_enum, default_value = "human")]
    format: OutputFormat,
}

pub(super) fn run(args: &AbandonArgs) -> u8 {
    let candidate = match from_hex(&args.candidate) {
        Ok(v) => v,
        Err(_) => return err("candidate must be a 64-character object ID", exit::USAGE),
    };
    let layout = match open_here() {
        Ok(v) => v,
        Err(c) => return c,
    };
    let state = match read_state(&layout) {
        Ok(v) => v,
        Err(c) => return c,
    };
    let next = match layout.abandon_pending(
        state.workspace().transaction_generation(),
        &candidate,
        args.acknowledge_possible_publication,
    ) {
        Ok(v) => v,
        Err(e) => return err(&format!("abandon pending candidate: {e}"), exit::DATAERR),
    };
    match args.format {
        OutputFormat::Human => {
            header(&next);
            println!(
                "Released pending candidate {} locally. Any possible remote publication was not undone.",
                to_hex(&candidate)
            );
        }
        OutputFormat::Json => {
            let mut output = envelope(&next, "abandon");
            output["abandoned_candidate"] = json!(to_hex(&candidate));
            output["remote_undo"] = json!(false);
            print_json(&output);
        }
    }
    exit::OK
}
