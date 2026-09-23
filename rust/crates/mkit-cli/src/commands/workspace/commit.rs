use std::time::{SystemTime, UNIX_EPOCH};

use clap::Args;
use mkit_core::hash::to_hex;
use mkit_core::partial::{export_partial_update, prepare_partial_commit};
use serde_json::json;

use super::{OutputFormat, envelope, err, header, open_here, print_json, read_state};
use crate::{commands::commit::load_scoped_commit_signer, config, exit};

#[derive(Debug, Args)]
pub(super) struct CommitArgs {
    #[arg(short = 'm', long = "message", value_name = "MESSAGE")]
    message: String,
    #[arg(long = "author", value_name = "IDENTITY")]
    author: Option<String>,
    #[arg(long, value_enum, default_value = "human")]
    format: OutputFormat,
}

pub(super) fn run(args: &CommitArgs) -> u8 {
    let layout = match open_here() {
        Ok(v) => v,
        Err(c) => return c,
    };
    let state = match read_state(&layout) {
        Ok(v) => v,
        Err(c) => return c,
    };
    let prepared = match state.prepare_staged_edit() {
        Ok(v) => v,
        Err(e) => return err(&format!("prepare staged edit: {e}"), exit::DATAERR),
    };
    let cfg = match config::read_user_or_default() {
        Ok(v) => v,
        Err(e) => return err(&format!("user config: {e}"), exit::CONFIG_ERROR),
    };
    let mut signing_provider = match load_scoped_commit_signer(&cfg) {
        Ok(v) => v,
        Err((message, code)) => return err(&message, code),
    };
    let public = match signing_provider.public_key() {
        Ok(v) => v,
        Err((message, code)) => return err(&message, code),
    };
    let author = match crate::commands::commit::resolve_author(
        args.author.as_deref(),
        &cfg.user_identity,
        &public,
    ) {
        Ok(v) => v,
        Err(e) => return err(&format!("author: {e}"), exit::CONFIG_ERROR),
    };
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let unsigned = match prepare_partial_commit(
        state.verified(),
        &prepared,
        author,
        public,
        args.message.as_bytes().to_vec(),
        timestamp,
        state.workspace().limits(),
    ) {
        Ok(v) => v,
        Err(e) => return err(&format!("prepare commit: {e}"), exit::DATAERR),
    };
    let mut signed = unsigned.clone();
    signed.signature = match signing_provider.sign_commit(&unsigned) {
        Ok(v) => v,
        Err((message, code)) => return err(&message, code),
    };
    let update = match export_partial_update(
        state.verified(),
        &prepared,
        &unsigned,
        &signed,
        state.workspace().limits(),
    ) {
        Ok(v) => v,
        Err(e) => return err(&format!("prepare update: {e}"), exit::DATAERR),
    };
    let bytes = match update.encode(state.workspace().limits()) {
        Ok(v) => v,
        Err(e) => return err(&format!("encode update: {e}"), exit::DATAERR),
    };
    let next = match layout.save_pending(
        state.workspace().transaction_generation(),
        &unsigned,
        &signed,
        &bytes,
        None,
    ) {
        Ok(v) => v,
        Err(e) => return err(&format!("save pending commit: {e}"), exit::DATAERR),
    };
    match args.format {
        OutputFormat::Human => {
            header(&next);
            println!(
                "Candidate {} prepared locally; publication has not been attempted.",
                to_hex(update.candidate_id())
            );
        }
        OutputFormat::Json => {
            let mut output = envelope(&next, "commit");
            output["candidate"] = json!(to_hex(update.candidate_id()));
            output["pending_status"] = json!("prepared");
            output["publication"] = json!("not-attempted");
            print_json(&output);
        }
    }
    exit::OK
}
