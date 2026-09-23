use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

use clap::Args;
use mkit_core::hash::from_hex;
use mkit_core::partial::{PartialLimits, PartialSnapshotBundle, ScopedWorkspaceLayout};

use super::{OutputFormat, err, header, path_from_arg, print_json, read_state};
use crate::exit;

#[derive(Debug, Args)]
pub(super) struct CreateArgs {
    #[arg(long, value_name = "FILE")]
    bundle: PathBuf,
    #[arg(long, value_name = "ID")]
    base: String,
    #[arg(
        long = "path",
        value_name = "PATH",
        conflicts_with = "accept_bundle_selection"
    )]
    paths: Vec<String>,
    #[arg(long, conflicts_with = "paths")]
    accept_bundle_selection: bool,
    #[arg(long, value_enum, default_value = "human")]
    format: OutputFormat,
    #[arg(value_name = "DIR")]
    destination: PathBuf,
}

pub(super) fn run(args: &CreateArgs) -> u8 {
    if !args.accept_bundle_selection && args.paths.is_empty() {
        return err(
            "specify --path at least once or --accept-bundle-selection",
            exit::USAGE,
        );
    }
    let base = match from_hex(&args.base) {
        Ok(hash) if args.base.len() == 64 => hash,
        _ => return err("--base requires an exact 64-hex object id", exit::USAGE),
    };
    let mut bytes = Vec::new();
    let mut file = match File::open(&args.bundle) {
        Ok(file) => file,
        Err(e) => return err(&format!("bundle: {e}"), exit::NOINPUT),
    };
    if let Err(e) = (&mut file)
        .take(PartialLimits::V1.max_bundle_bytes as u64 + 1)
        .read_to_end(&mut bytes)
    {
        return err(&format!("bundle: {e}"), exit::NOINPUT);
    }
    if bytes.len() > PartialLimits::V1.max_bundle_bytes {
        return err("bundle exceeds the v1 size limit", exit::DATAERR);
    }
    let paths = if args.accept_bundle_selection {
        match PartialSnapshotBundle::decode(&bytes, &PartialLimits::V1) {
            Ok(bundle) => bundle.paths().to_vec(),
            Err(e) => return err(&format!("bundle selection: {e}"), exit::DATAERR),
        }
    } else {
        let mut paths = Vec::new();
        for value in &args.paths {
            match path_from_arg(value) {
                Ok(path) => paths.push(path),
                Err(code) => return code,
            }
        }
        paths.sort_by_key(super::path_text);
        if paths.windows(2).any(|pair| pair[0] == pair[1]) {
            return err("duplicate --path", exit::USAGE);
        }
        paths
    };
    let layout = match ScopedWorkspaceLayout::create(
        &args.destination,
        base,
        &paths,
        &bytes,
        PartialLimits::V1,
        None,
    ) {
        Ok(layout) => layout,
        Err(e) => return err(&format!("workspace create: {e}"), exit::DATAERR),
    };
    let state = match read_state(&layout) {
        Ok(s) => s,
        Err(code) => return code,
    };
    match args.format {
        OutputFormat::Human => {
            header(&state);
            println!("Created {}", layout.root().display());
        }
        OutputFormat::Json => {
            let mut output = super::envelope(&state, "create");
            output["path"] = super::display_path(layout.root()).into();
            print_json(&output);
        }
    }
    exit::OK
}
