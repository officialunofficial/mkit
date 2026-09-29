//! `mkit visibility set` (WP-2.14, R-156): switch a repository between public
//! and private (SPEC-WRITE-GRANTS §9.1).
//!
//! Two modes, chosen by `--statement`:
//!
//! * **Envelope** (default): a signed auth v2 write of `SetRepoVisibility`
//!   with the repository signing key, so it needs `transport_auth = envelope`
//!   and a trusted remote, like `mkit push`. A grant never authorizes it.
//! * **Statement** (`--statement`): an owner-signed `mkit-repo-visibility:v1`
//!   statement, sent with no envelope and with `X-Repository`. It signs with
//!   any owner scheme, including a wallet or passkey by import.
//!
//! Either way the server may answer `unavailable` + `Retry-After` while a
//! change to private takes effect everywhere; the command waits.

use std::io::Write as _;

use clap::{Args, Parser, Subcommand, ValueEnum};
use mkit_attest::grant::{Visibility, VisibilityStatement};
use mkit_transport_connect::{VisibilityChoice, VisibilityRequest};

use crate::clap_shim;
use crate::commands::{error, usage_error};
use crate::exit;
use crate::grants::cli::{Ctx, finish_wait, parse_timeout, print_statement};
use crate::grants::now_ms;
use crate::grants::owner::{Kind, OwnerArgs, Produced, produce};
use crate::grants::remote::{Driven, check_audiences, drive, interruptible_sleep, resolve_target};
use crate::grants::spec::{build_visibility, canonical_audiences, statement_lifetime_ms};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum VisibilityArg {
    Public,
    Private,
}

#[derive(Debug, Parser)]
#[command(
    name = "mkit visibility",
    about = "Switch a repository between public and private."
)]
struct VisibilityOpts {
    #[command(subcommand)]
    command: VisibilityCommand,
}

#[derive(Debug, Subcommand)]
enum VisibilityCommand {
    /// Set a repository's visibility on a remote.
    Set(SetOpts),
}

#[derive(Debug, Args)]
struct SetOpts {
    /// Remote name, or an `mkit+https://` URL naming `<namespace>/<name>`.
    remote: String,
    /// The visibility to set.
    #[arg(value_enum)]
    visibility: VisibilityArg,
    /// Send an owner-signed statement instead of a signed request. Lets a
    /// wallet or passkey owner change visibility (see --print-statement).
    #[arg(long)]
    statement: bool,
    /// Audience of the statement (repeatable; default: the remote's origin).
    /// Only with --statement.
    #[arg(long, value_name = "ORIGIN", requires = "statement")]
    audience: Vec<String>,
    /// Longest to wait for the change to complete (for example 5m).
    #[arg(long, value_name = "DURATION", default_value = "5m")]
    timeout: String,
    #[command(flatten)]
    owner: OwnerArgs,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<VisibilityOpts>("mkit visibility", args) {
        Ok(opts) => opts,
        Err(code) => return code,
    };
    match opts.command {
        VisibilityCommand::Set(opts) => set(&opts),
    }
}

fn owner_flags_used(owner: &OwnerArgs) -> bool {
    owner.scheme.is_some()
        || owner.print_statement
        || owner.statement_file.is_some()
        || owner.signature.is_some()
        || owner.webauthn_assertion.is_some()
}

#[allow(clippy::too_many_lines)] // linear flow: resolve, sign once, send until done, report
fn set(opts: &SetOpts) -> u8 {
    let ctx = match Ctx::load() {
        Ok(ctx) => ctx,
        Err(code) => return code,
    };
    let timeout = match parse_timeout(&opts.timeout) {
        Ok(t) => t,
        Err(e) => return usage_error(&format!("--timeout: {e}")),
    };
    if !opts.statement && owner_flags_used(&opts.owner) {
        return usage_error(
            "--scheme, --print-statement, --statement-file, --signature and --webauthn-assertion sign a statement: add --statement",
        );
    }
    let target = match resolve_target(&ctx.layered, Some(&opts.remote)) {
        Ok(target) => target,
        Err(e) => return usage_error(&e),
    };
    let choice = match opts.visibility {
        VisibilityArg::Public => VisibilityChoice::Public,
        VisibilityArg::Private => VisibilityChoice::Private,
    };

    let outcome = if opts.statement {
        let tx = match ctx.open_unsigned(&target) {
            Ok(tx) => tx,
            Err(e) => return error(&e, exit::UNAVAILABLE),
        };
        let repository = tx.repository().clone();
        let Some(namespace) = repository.namespace().copied() else {
            return usage_error(
                "a visibility statement names a full <namespace>/<name> repository: use a remote URL that includes it",
            );
        };
        let audiences = if opts.audience.is_empty() {
            vec![tx.origin().to_owned()]
        } else {
            match canonical_audiences(&opts.audience) {
                Ok(a) => a,
                Err(e) => return usage_error(&e),
            }
        };
        if let Err(e) = check_audiences(&audiences, Some(&target)) {
            return error(&e, exit::USAGE);
        }
        let plan = match ctx.plan(&opts.owner, Some(namespace)) {
            Ok(plan) => plan,
            Err(e) => return error(&e, exit::USAGE),
        };
        let wanted = match opts.visibility {
            VisibilityArg::Public => Visibility::Public,
            VisibilityArg::Private => Visibility::Private,
        };
        let now = now_ms();
        let lifetime_ms = statement_lifetime_ms(timeout);
        let signed = match produce(
            plan,
            |_| {
                build_visibility(&repository, wanted, &audiences, now, lifetime_ms)?
                    .encode()
                    .map_err(crate::grants::spec::statement_error)
            },
            Kind::Visibility(&repository),
            &ctx.relying_parties,
            now,
        ) {
            Ok(Produced::Signed(signed)) => signed,
            Ok(Produced::Print {
                statement,
                namespace,
            }) => return print_statement(&statement, &namespace),
            Err(e) => return error(&e, exit::DATAERR),
        };
        match VisibilityStatement::parse(&signed.statement) {
            Ok(s) if s.repository == repository && s.visibility == wanted => {
                if let Err(e) = check_audiences(&s.audiences, Some(&target)) {
                    return error(&e, exit::USAGE);
                }
            }
            Ok(_) => {
                return error(
                    "the imported statement is for a different repository or visibility than the command asks for",
                    exit::DATAERR,
                );
            }
            Err(e) => return error(&format!("invalid statement: {e}"), exit::DATAERR),
        }
        drive(
            || tx.set_repo_visibility(VisibilityRequest::Statement(&signed.header)),
            timeout,
            interruptible_sleep,
        )
    } else {
        let tx = match ctx.open_signed(&target) {
            Ok(tx) => tx,
            Err(e) => return error(&e, exit::NOPERM),
        };
        drive(
            || tx.set_repo_visibility(VisibilityRequest::Envelope(choice)),
            timeout,
            interruptible_sleep,
        )
    };
    let outcome = match outcome {
        Ok(outcome) => outcome,
        Err(e) => {
            let hint = match e {
                mkit_core::protocol::TransportError::AccessDenied => {
                    " (only the repository owner can change visibility; a grant never can)"
                }
                _ => "",
            };
            return error(&format!("SetRepoVisibility: {e}{hint}"), exit::NOPERM);
        }
    };
    if let Some(code) = finish_wait(&outcome, "the visibility change") {
        return code;
    }
    if !matches!(outcome, Driven::Done(())) {
        return exit::GENERAL_ERROR;
    }
    let mut stdout = std::io::stdout().lock();
    let _ = writeln!(
        stdout,
        "{} is now {}",
        target
            .repository()
            .map_or_else(|| target.endpoint.clone(), |r| r.to_string()),
        match opts.visibility {
            VisibilityArg::Public => "public",
            VisibilityArg::Private => "private",
        }
    );
    exit::OK
}
