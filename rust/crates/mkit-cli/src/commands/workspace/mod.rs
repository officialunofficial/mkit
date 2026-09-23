//! Offline commands for authenticated selected-file workspaces.

mod abandon;
mod add;
mod commit;
mod create;
mod diff;
mod export;
mod log;
mod push;
mod status;

use std::cell::Cell;
use std::path::Path;

use clap::{Parser, ValueEnum};
use mkit_core::hash::to_hex;
use mkit_core::layout::{DiscoverError, check_scoped_boundary};
use mkit_core::partial::{PartialPath, ScopedWorkspaceLayout, ScopedWorkspaceState};
use serde_json::{Value, json};

use crate::{clap_shim, exit};

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub(super) enum OutputFormat {
    #[default]
    Human,
    Json,
}

thread_local! { static JSON_ERRORS: Cell<bool> = const { Cell::new(false) }; }

#[derive(Debug, Parser)]
#[command(
    name = "mkit workspace",
    about = "Inspect and stage an offline scoped workspace"
)]
enum WorkspaceCommand {
    Create(create::CreateArgs),
    Status(status::StatusArgs),
    Diff(diff::DiffArgs),
    Add(add::AddArgs),
    Log(log::LogArgs),
    Commit(commit::CommitArgs),
    Export(export::ExportArgs),
    Push(push::PushArgs),
    Abandon(abandon::AbandonArgs),
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    JSON_ERRORS.with(|flag| {
        flag.set(requested_json(args));
    });
    if let Some(first) = args.first()
        && matches!(first.as_str(), "merge" | "rebase" | "checkout" | "gc")
    {
        return err(
            &format!("workspace {first} is unsupported in this version"),
            exit::UNAVAILABLE,
        );
    }
    let command = if JSON_ERRORS.with(Cell::get) {
        let parsed_args = std::iter::once("mkit workspace".to_owned()).chain(args.iter().cloned());
        match WorkspaceCommand::try_parse_from(parsed_args) {
            Ok(c) => c,
            Err(error)
                if matches!(
                    error.kind(),
                    clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
                ) =>
            {
                return clap_shim::report_clap_error(&error);
            }
            Err(error) => return err(&error.to_string(), exit::USAGE),
        }
    } else {
        match clap_shim::parse::<WorkspaceCommand>("mkit workspace", args) {
            Ok(c) => c,
            Err(code) => return code,
        }
    };
    match command {
        WorkspaceCommand::Create(args) => create::run(&args),
        WorkspaceCommand::Status(args) => status::run(&args),
        WorkspaceCommand::Diff(args) => diff::run(&args),
        WorkspaceCommand::Add(args) => add::run(&args),
        WorkspaceCommand::Log(args) => log::run(&args),
        WorkspaceCommand::Commit(args) => commit::run(&args),
        WorkspaceCommand::Export(args) => export::run(&args),
        WorkspaceCommand::Push(args) => push::run(&args),
        WorkspaceCommand::Abandon(args) => abandon::run(&args),
    }
}

fn requested_json(args: &[String]) -> bool {
    let option_args = args.split(|arg| arg == "--").next().unwrap_or(args);
    option_args
        .windows(2)
        .any(|pair| pair[0] == "--format" && pair[1] == "json")
        || option_args.iter().any(|arg| arg == "--format=json")
}

pub(super) fn err(message: &str, code: u8) -> u8 {
    if JSON_ERRORS.with(Cell::get) {
        print_json(&json!({"ok":false,"workspace_mode":"scoped","error":message}));
    } else {
        eprintln!("error: {message}");
    }
    code
}

pub(super) fn open_here() -> Result<ScopedWorkspaceLayout, u8> {
    let cwd = std::env::current_dir().map_err(|e| err(&format!("cwd: {e}"), exit::NOINPUT))?;
    let root = match check_scoped_boundary(&cwd) {
        Err(DiscoverError::ScopedWorkspace(root)) => root,
        Err(e) => return Err(err(&format!("workspace discovery: {e}"), exit::DATAERR)),
        Ok(()) => return Err(err("not inside a scoped workspace", exit::USAGE)),
    };
    ScopedWorkspaceLayout::open(&root)
        .map_err(|e| err(&format!("open scoped workspace: {e}"), exit::DATAERR))
}

pub(super) fn path_from_arg(value: &str) -> Result<PartialPath, u8> {
    if value.is_empty() || value.starts_with('/') || value.contains('\\') || value.contains('\0') {
        return Err(err(
            "selected path must be repository-relative UTF-8",
            exit::USAGE,
        ));
    }
    let components: Vec<_> = value
        .split('/')
        .map(|part| part.as_bytes().to_vec())
        .collect();
    if components
        .iter()
        .any(|c| c.is_empty() || c == b"." || c == b".." || c.iter().any(|b| *b < 0x20))
    {
        return Err(err("selected path has an unsafe component", exit::USAGE));
    }
    Ok(components)
}

pub(super) fn path_text(path: &PartialPath) -> String {
    path.iter()
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

pub(super) fn exact_paths(
    args: &[String],
    state: &ScopedWorkspaceState,
) -> Result<Vec<PartialPath>, u8> {
    let mut paths = Vec::new();
    for arg in args {
        let path = path_from_arg(arg)?;
        if !state
            .workspace()
            .selection()
            .iter()
            .any(|s| s.path() == &path)
        {
            return Err(err(
                &format!("path `{arg}` is outside the exact workspace selection"),
                exit::USAGE,
            ));
        }
        if paths.contains(&path) {
            return Err(err("duplicate selected path", exit::USAGE));
        }
        paths.push(path);
    }
    paths.sort_by_key(path_text);
    Ok(paths)
}

pub(super) fn envelope(state: &ScopedWorkspaceState, command: &str) -> Value {
    let pending = state.pending().map(|pending| {
        json!({
            "candidate": to_hex(pending.candidate_id()),
            "status": format!("{:?}", pending.status()).to_lowercase(),
            "operation_pinned": pending.operation().is_some(),
        })
    });
    let target = state.workspace().target().map(|target| json!({
        "endpoint": target.endpoint(), "repository": target.repository(), "ref": target.exact_ref(),
    }));
    json!({
        "command": command,
        "workspace_mode": "scoped",
        "base_commit": to_hex(state.workspace().base_id()),
        "selected_paths": state.workspace().selection().iter().map(|s| path_text(s.path())).collect::<Vec<_>>(),
        "coverage": {"content":"selected-files","history":"partial","verification":"selected-only"},
        "pending": pending,
        "target": target,
        "transport_guarantee": "single-attempt-file-no-durable-results",
    })
}

pub(super) fn header(state: &ScopedWorkspaceState) {
    println!(
        "Scoped workspace: {} selected files; repository content and history are partial.",
        state.workspace().selection().len()
    );
}

pub(super) fn pending_lines(state: &ScopedWorkspaceState) {
    if let Some(pending) = state.pending() {
        println!(
            "Pending candidate {}: {:?}.",
            to_hex(pending.candidate_id()),
            pending.status()
        );
    }
    if let Some(target) = state.workspace().target() {
        println!(
            "Pinned target: {} {} {}.",
            target.endpoint(),
            target.repository(),
            target.exact_ref()
        );
    }
    println!("File publication: single attempt, no durable result ledger.");
}

pub(super) fn print_json(value: &Value) {
    println!("{value}");
}

pub(super) fn read_state(layout: &ScopedWorkspaceLayout) -> Result<ScopedWorkspaceState, u8> {
    layout
        .read_state()
        .map_err(|e| err(&format!("read scoped workspace: {e}"), exit::DATAERR))
}

pub(super) fn display_path(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_format_probe_stops_at_path_separator() {
        assert!(!requested_json(&[
            "add".into(),
            "--".into(),
            "--format=json".into()
        ]));
        assert!(requested_json(&[
            "add".into(),
            "--format=json".into(),
            "--".into(),
            "file".into()
        ]));
        assert!(path_from_arg("--format=json").is_ok());
    }
}
