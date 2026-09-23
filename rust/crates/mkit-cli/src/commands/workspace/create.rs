use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

use clap::Args;
use mkit_core::hash::from_hex;
use mkit_core::layout::RepoLayout;
use mkit_core::partial::{PartialLimits, PartialSnapshotBundle, ScopedWorkspaceLayout};
use mkit_transport_connect::{
    ConnectTransport, HostedReadError, HostedWorkspaceRequest, hosted_partial_limits,
};

use super::{OutputFormat, err, header, path_from_arg, print_json, read_state};
use crate::exit;

#[derive(Debug, Args)]
pub(super) struct CreateArgs {
    #[arg(long, value_name = "FILE", conflicts_with = "hosted")]
    bundle: Option<PathBuf>,
    #[arg(long, value_name = "URL", conflicts_with = "bundle")]
    hosted: Option<String>,
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
    #[arg(long = "ref", value_name = "REF")]
    exact_ref: Option<String>,
    #[arg(long, value_name = "ID")]
    workspace_id: Option<String>,
    #[arg(long, value_name = "ID")]
    grant_id: Option<String>,
    #[arg(long, value_name = "DECIMAL")]
    grant_generation: Option<String>,
    #[arg(long, value_enum, default_value = "human")]
    format: OutputFormat,
    #[arg(value_name = "DIR")]
    destination: PathBuf,
}

pub(super) fn run(args: &CreateArgs) -> u8 {
    if args.bundle.is_none() == args.hosted.is_none() {
        return err("specify exactly one of --bundle or --hosted", exit::USAGE);
    }
    if args.hosted.is_some() && args.accept_bundle_selection {
        return err(
            "--hosted requires explicit --path, not --accept-bundle-selection",
            exit::USAGE,
        );
    }
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
    if let Some(bundle) = &args.bundle {
        let mut file = match File::open(bundle) {
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
    let limits = if let Some(url) = &args.hosted {
        let Some(exact_ref) = &args.exact_ref else {
            return err("--hosted requires --ref", exit::USAGE);
        };
        let Some(workspace_id) = &args.workspace_id else {
            return err("--hosted requires --workspace-id", exit::USAGE);
        };
        let Some(grant_id) = &args.grant_id else {
            return err("--hosted requires --grant-id", exit::USAGE);
        };
        let Some(grant_generation) = &args.grant_generation else {
            return err("--hosted requires --grant-generation", exit::USAGE);
        };
        let cfg = match crate::config::read_user_or_default() {
            Ok(cfg) => cfg,
            Err(e) => return err(&format!("hosted config: {e}"), exit::USAGE),
        };
        if cfg.transport_signed_reads() != Ok(true)
            || !cfg.transport_auth_envelope()
            || cfg.trusted_remote_endpoint.trim() != url
            || !(url.starts_with("mkit+https://") || url.starts_with("mkit+http://"))
        {
            return err(
                "hosted reads require user-configured signed reads, envelope auth, and this exact trusted_remote_endpoint",
                exit::NOPERM,
            );
        }
        if matches!(cfg.signer.as_str(), "" | "legacy")
            && !std::path::Path::new(&cfg.signing_key).is_absolute()
        {
            return err(
                "hosted create requires an explicit absolute user signing_key or configured keystore signer",
                exit::NOPERM,
            );
        }
        let signer = match crate::remote_dispatch::envelope_signer_from_config(
            &cfg,
            &RepoLayout::single(&args.destination),
        ) {
            Ok(Some(signer)) => signer,
            Ok(None) => return err("hosted signed identity unavailable", exit::NOPERM),
            Err(e) => return err(&format!("hosted signer: {e}"), exit::NOPERM),
        };
        let transport = match ConnectTransport::connect_with_signed_reads(url, signer) {
            Ok(transport) => transport,
            Err(e) => return err(&format!("hosted transport: {e}"), exit::UNAVAILABLE),
        };
        let request = HostedWorkspaceRequest {
            workspace_id: workspace_id.clone(),
            grant_id: grant_id.clone(),
            grant_generation: grant_generation.clone(),
            expected_ref: exact_ref.clone(),
            expected_base: base,
            paths: paths.clone(),
        };
        let limits = hosted_partial_limits();
        match transport.get_hosted_workspace(&request, base, &paths, &limits) {
            Ok(bundle) => bytes = bundle.bytes().to_vec(),
            Err(
                HostedReadError::AuthRequired
                | HostedReadError::AccessDenied
                | HostedReadError::UntrustedEndpoint,
            ) => return err("hosted read denied", exit::NOPERM),
            Err(
                HostedReadError::InvalidRequest
                | HostedReadError::InvalidResponse
                | HostedReadError::Verification(_),
            ) => return err("invalid hosted snapshot", exit::DATAERR),
            Err(HostedReadError::Conflict) => {
                return err("hosted snapshot is stale", exit::TEMPFAIL);
            }
            Err(HostedReadError::UnsupportedProfile | HostedReadError::ResourceExhausted) => {
                return err("hosted snapshot exceeds profile", exit::UNAVAILABLE);
            }
            Err(HostedReadError::Unavailable) => {
                return err("hosted service unavailable", exit::UNAVAILABLE);
            }
        }
        limits
    } else {
        PartialLimits::V1
    };
    let layout = match ScopedWorkspaceLayout::create(
        &args.destination,
        base,
        &paths,
        &bytes,
        limits,
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
