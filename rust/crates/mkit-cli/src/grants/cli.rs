//! What `mkit grant`, `mkit epoch` and `mkit visibility` share: loading the
//! layered config and relying-party pins, choosing an owner-signing plan,
//! opening the remote, and printing.

use std::io::Write as _;
use std::time::Duration;

use mkit_attest::grant::{Namespace, RelyingParty};
use mkit_core::layout::RepoLayout;
use mkit_transport_connect::ConnectTransport;

use super::owner::{self, NativeOwner, OwnerArgs, Plan, SignCtx};
use super::remote::{Driven, Target, drive, interruptible_sleep};
use super::spec::parse_ttl;
use crate::commands::{error, usage_error};
use crate::config::{self, LayeredConfig};
use crate::exit;
use crate::remote_dispatch;

/// Longest a command waits for one plain read (`GetGrantEpoch`).
const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Everything a command needs before it does anything.
#[derive(Debug)]
pub struct Ctx {
    pub layout: RepoLayout,
    pub layered: LayeredConfig,
    pub relying_parties: Vec<RelyingParty>,
}

impl Ctx {
    /// Load the config. Works outside a repository: the layout then names the
    /// current directory and there is simply no repository config.
    ///
    /// # Errors
    /// The exit code, after printing the reason.
    pub fn load() -> Result<Self, u8> {
        let cwd =
            std::env::current_dir().map_err(|e| error(&format!("cwd: {e}"), exit::NOINPUT))?;
        let layout = crate::commands::resolve_layout(&cwd)?;
        let layered = config::read_layered(&layout)
            .map_err(|e| error(&format!("config: {e}"), exit::CONFIG_ERROR))?;
        let relying_parties = super::parse_relying_parties(&layered.merged.grant_webauthn_rp)
            .map_err(|e| error(&format!("grant.webauthn_rp: {e}"), exit::CONFIG_ERROR))?;
        Ok(Self {
            layout,
            layered,
            relying_parties,
        })
    }

    /// Choose how to sign; see [`owner::resolve`].
    ///
    /// # Errors
    /// The message to print.
    pub fn plan(&self, args: &OwnerArgs, hint: Option<Namespace>) -> Result<Plan, String> {
        let cfg = &self.layered.merged;
        let ed25519 =
            || NativeOwner::ed25519(remote_dispatch::owner_ed25519_signer(cfg, &self.layout)?);
        owner::resolve(
            args,
            hint,
            &SignCtx {
                ed25519: &ed25519,
                cfg,
                relying_parties: &self.relying_parties,
            },
        )
    }

    /// Open `target` with no ambient signing identity, for the unsigned
    /// epoch RPCs. The credential-trust gate still applies.
    ///
    /// # Errors
    /// The message to print.
    pub fn open_unsigned(&self, target: &Target) -> Result<ConnectTransport, String> {
        self.open(target, false)
    }

    /// Open `target` with the ambient signing identity (needs
    /// `transport_auth = envelope` and a trusted remote, like `mkit push`).
    ///
    /// # Errors
    /// The message to print.
    pub fn open_signed(&self, target: &Target) -> Result<ConnectTransport, String> {
        if !self.layered.merged.transport_auth_envelope() {
            return Err(
                "envelope-mode visibility signs with your mkit key: run `mkit config transport_auth envelope` and trust the remote with `mkit config trusted_remote_endpoint <url>`, or use --statement to sign with an owner key instead"
                    .to_owned(),
            );
        }
        self.open(target, true)
    }

    fn open(&self, target: &Target, sign: bool) -> Result<ConnectTransport, String> {
        remote_dispatch::open_connect_trusted(
            &target.endpoint,
            &target.name,
            target.repo_chosen,
            &self.layered,
            &self.layout,
            sign,
        )
        .map_err(|e| e.to_string())
    }

    /// The stored epoch of `namespace` at `tx`'s deployment.
    ///
    /// # Errors
    /// The message to print.
    pub fn read_epoch(tx: &ConnectTransport, namespace: &Namespace) -> Result<u64, String> {
        let name = namespace.to_string();
        match drive(
            || tx.get_grant_epoch(&name),
            READ_TIMEOUT,
            interruptible_sleep,
        )
        .map_err(|e| format!("GetGrantEpoch for {name}: {e}"))?
        {
            Driven::Done(epoch) => Ok(epoch),
            Driven::TimedOut { .. } => Err(format!(
                "GetGrantEpoch for {name}: the server kept answering `unavailable`"
            )),
            Driven::Cancelled => Err("interrupted".to_owned()),
        }
    }
}

impl Ctx {
    /// One `GetGrantEpoch` attempt, with no retry ladder and no waiting out
    /// `Retry-After`: for advisory checks.
    ///
    /// # Errors
    /// The message to print.
    pub fn read_epoch_once(tx: &ConnectTransport, namespace: &Namespace) -> Result<u64, String> {
        let name = namespace.to_string();
        match tx
            .get_grant_epoch_once(&name)
            .map_err(|e| format!("GetGrantEpoch for {name}: {e}"))?
        {
            mkit_transport_connect::Completion::Done(epoch) => Ok(epoch),
            mkit_transport_connect::Completion::Pending { .. } => Err(format!(
                "GetGrantEpoch for {name}: the server answered `unavailable`"
            )),
        }
    }
}

/// `--timeout`, in the same spellings as `--ttl`.
///
/// # Errors
/// An unparsable duration.
pub fn parse_timeout(text: &str) -> Result<Duration, String> {
    let ms = parse_ttl(text)?;
    Ok(Duration::from_millis(u64::try_from(ms).unwrap_or(0)))
}

/// Write the statement bytes to stdout exactly (no added newline) and the
/// signing instructions to stderr: the `--print-statement` output.
#[must_use]
pub fn print_statement(statement: &[u8], namespace: &Namespace) -> u8 {
    let mut stdout = std::io::stdout().lock();
    if stdout
        .write_all(statement)
        .and_then(|()| stdout.flush())
        .is_err()
    {
        return error("write statement", exit::GENERAL_ERROR);
    }
    let mut stderr = std::io::stderr().lock();
    let _ = write!(
        stderr,
        "\n{}",
        owner::signing_instructions(statement, namespace)
    );
    exit::OK
}

/// Parse `--namespace`.
///
/// # Errors
/// The exit code after printing the reason.
pub fn parse_namespace(text: Option<&str>) -> Result<Option<Namespace>, u8> {
    text.map(|t| {
        Namespace::parse(t).map_err(|e| {
            usage_error(&format!(
                "--namespace `{t}`: {e} (expected ed25519-<64 hex> or 0x<40 hex>)"
            ))
        })
    })
    .transpose()
}

/// Turn a wait outcome into an exit code, printing the reason for anything but
/// success.
#[must_use]
pub fn finish_wait<T>(outcome: &Driven<T>, what: &str) -> Option<u8> {
    match outcome {
        Driven::Done(_) => None,
        Driven::TimedOut { waited } => Some(error(
            &format!(
                "{what} is still completing after {}s; it may yet finish on the server. Check before retrying (a new run signs a new statement)",
                waited.as_secs()
            ),
            exit::TEMPFAIL,
        )),
        Driven::Cancelled => Some(error(
            &format!("interrupted; {what} may still complete on the server. Check before retrying"),
            exit::TEMPFAIL,
        )),
    }
}
