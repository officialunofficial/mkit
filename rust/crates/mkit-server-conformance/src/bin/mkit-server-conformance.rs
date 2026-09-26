//! `mkit-server-conformance wire`: run the black-box wire suite against a
//! server at a URL and print a TAP report. Exits 1 if any case fails, 2 on
//! a usage error.
//!
//! ```text
//! mkit-server-conformance wire --base-url http://localhost:8791 \
//!     --auth auth-v2 --audience http://localhost:8791 --repository default \
//!     --random-signer --atomic-advance --max-pack-bytes 67108864
//! ```

use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use mkit_server_conformance::wire::{CASES, ProfileSpec, WireTarget, run};

#[derive(Debug, Parser)]
#[command(
    name = "mkit-server-conformance",
    about = "Conformance suites for mkit servers"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the black-box wire suite against a `mkit.transport.v1` server.
    Wire(WireArgs),
}

#[derive(Debug, Args)]
#[allow(clippy::struct_excessive_bools)] // clap flags
struct WireArgs {
    /// The server's base URL (http or https).
    #[arg(long, value_name = "URL")]
    base_url: Option<url::Url>,
    /// A TOML profile; the flags below override it.
    #[arg(long, value_name = "FILE")]
    profile: Option<std::path::PathBuf>,
    /// How the server authenticates: none, bearer or auth-v2.
    #[arg(long, value_name = "MODE")]
    auth: Option<String>,
    /// The environment variable holding the bearer token.
    #[arg(long, value_name = "VAR")]
    bearer_token_env: Option<String>,
    /// Auth v2: the server's canonical origin, exactly as configured.
    #[arg(long, value_name = "ORIGIN")]
    audience: Option<String>,
    /// Auth v2: the server's repository identity.
    #[arg(long, value_name = "ID")]
    repository: Option<String>,
    /// Auth v2: the environment variable holding the seed every case
    /// signer derives from (64 hex). Keeps the seed out of `ps`.
    #[arg(long, value_name = "VAR", conflicts_with_all = ["signer_seed_hex", "random_signer"])]
    signer_seed_env: Option<String>,
    /// Auth v2: the seed itself (visible in process listings; prefer
    /// `--signer-seed-env`).
    #[arg(long, value_name = "HEX", conflicts_with = "random_signer")]
    signer_seed_hex: Option<String>,
    /// Auth v2: a random seed.
    #[arg(long)]
    random_signer: bool,
    /// Sign read RPCs too (M2 signed reads; off in M0).
    #[arg(long)]
    sign_reads: bool,
    /// The server commits `AdvanceRefs` atomically.
    #[arg(long)]
    atomic_advance: bool,
    /// The largest pack the server accepts.
    #[arg(long, value_name = "N")]
    max_pack_bytes: Option<u64>,
    /// A tiny per-signer write quota (disposable servers only): writes.
    #[arg(long, value_name = "N", requires = "quota_bytes")]
    quota_ops: Option<u32>,
    /// ... and bytes per window.
    #[arg(long, value_name = "N", requires = "quota_ops")]
    quota_bytes: Option<u64>,
    /// ... and the window, ms (default one hour).
    #[arg(long, value_name = "MS")]
    quota_window_ms: Option<i64>,
    /// Highest milestone to run (M0..M5).
    #[arg(long, value_name = "M")]
    milestone: Option<String>,
    /// Add features to the derived set, or remove one with a leading `-`
    /// (comma-separated, e.g. health,test-faults,-replay). With
    /// test-faults and a declared short quota window, the growth case runs:
    /// it needs a disposable server (fresh, no other writers).
    #[arg(
        long,
        value_name = "A,B",
        value_delimiter = ',',
        allow_hyphen_values = true
    )]
    features: Option<Vec<String>>,
    /// Run only cases whose name contains this.
    #[arg(long, value_name = "SUBSTR")]
    filter: Option<String>,
    /// A fixed run id (default random); refs go under
    /// refs/heads/conformance/<run-id>/.
    #[arg(long, value_name = "ID")]
    run_id: Option<String>,
    /// Refs the large-listing case creates (default 10000; 0 skips it).
    #[arg(long, value_name = "N")]
    list_refs: Option<u32>,
    /// The server's replay prune grace after expiry, ms (default 60000).
    #[arg(long, value_name = "MS")]
    replay_prune_grace_ms: Option<i64>,
    /// How long a concurrent duplicate retries `aborted`, ms (default 10000).
    #[arg(long, value_name = "MS")]
    duplicate_retry_ms: Option<u64>,
    /// Print the cases with their milestone and requirements, and exit.
    #[arg(long)]
    list_cases: bool,
}

impl WireArgs {
    fn spec(&self) -> ProfileSpec {
        ProfileSpec {
            auth: self.auth.clone(),
            bearer_token_env: self.bearer_token_env.clone(),
            audience: self.audience.clone(),
            repository: self.repository.clone(),
            signer_seed_hex: self.signer_seed_hex.clone(),
            signer_seed_env: self.signer_seed_env.clone(),
            random_signer: self.random_signer.then_some(true),
            atomic_advance: self.atomic_advance.then_some(true),
            max_pack_bytes: self.max_pack_bytes,
            quota_ops: self.quota_ops,
            quota_bytes: self.quota_bytes,
            quota_window_ms: self.quota_window_ms,
            milestone: self.milestone.clone(),
            features: self.features.clone(),
            run_id: self.run_id.clone(),
            list_refs: self.list_refs,
            replay_prune_grace_ms: self.replay_prune_grace_ms,
            duplicate_retry_ms: self.duplicate_retry_ms,
            sign_reads: self.sign_reads.then_some(true),
        }
    }
}

fn list_cases() {
    for case in CASES {
        let requires = case.requires.iter().map(|f| f.as_str().to_owned());
        let excludes = case.excludes.iter().map(|f| format!("!{}", f.as_str()));
        let needs: Vec<_> = requires.chain(excludes).collect();
        let needs = needs.join(",");
        println!("{:<56} {:?} {needs}", case.name, case.milestone);
    }
}

fn wire(args: &WireArgs) -> Result<bool, String> {
    if args.list_cases {
        list_cases();
        return Ok(true);
    }
    let base_url = args.base_url.clone().ok_or("--base-url is required")?;
    if !matches!(base_url.scheme(), "http" | "https") {
        return Err(format!(
            "--base-url: unsupported scheme `{}` (http, https)",
            base_url.scheme()
        ));
    }
    let file = match &args.profile {
        Some(path) => {
            let text = std::fs::read_to_string(path)
                .map_err(|e| format!("--profile {}: {e}", path.display()))?;
            ProfileSpec::from_toml(&text)?
        }
        None => ProfileSpec::default(),
    };
    let profile = file
        .merge(args.spec())
        .build(|var| std::env::var(var).ok())?;
    let target = WireTarget { base_url, profile };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime: {e}"))?;
    let report = runtime.block_on(run(&target, args.filter.as_deref()));
    print!("{}", report.tap());
    Ok(!report.failed())
}

fn main() -> ExitCode {
    let Command::Wire(args) = Cli::parse().command;
    match wire(&args) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("mkit-server-conformance: {e}");
            ExitCode::from(2)
        }
    }
}
