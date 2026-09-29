//! `mkit epoch show|bump` (WP-2.14, R-156): read and advance a namespace's
//! grant epoch at a deployment (SPEC-WRITE-GRANTS §5).
//!
//! Both RPCs are unsigned transport: no auth v2 envelope and no
//! `X-Repository`. `bump` signs a `mkit-write-epoch:v1` statement with the
//! owner key and re-sends the identical bytes while the server answers
//! `unavailable` + `Retry-After`, so a retry never starts a second
//! revocation.

use clap::{Args, Parser, Subcommand};
use mkit_attest::grant::{
    EpochStatement, EpochTransition, MAX_EPOCH_STEP, Namespace, epoch_transition,
};
use std::io::Write as _;

use crate::clap_shim;
use crate::commands::{error, usage_error};
use crate::exit;
use crate::format::{JsonObject, json_string_array};
use crate::grants::cli::{Ctx, finish_wait, parse_namespace, parse_timeout, print_statement};
use crate::grants::owner::{Kind, OwnerArgs, Produced, produce};
use crate::grants::remote::{Driven, check_audiences, drive, interruptible_sleep, resolve_target};
use crate::grants::spec::{build_epoch, canonical_audiences, statement_lifetime_ms};
use crate::grants::store::{GrantStore, StoredGrant};
use crate::grants::{now_ms, scope_text};

#[derive(Debug, Parser)]
#[command(
    name = "mkit epoch",
    about = "Show or advance a namespace's grant epoch on a remote."
)]
struct EpochOpts {
    #[command(subcommand)]
    command: EpochCommand,
}

#[derive(Debug, Subcommand)]
enum EpochCommand {
    /// Show the epoch a remote stores for a namespace.
    Show(ShowOpts),
    /// Advance the epoch, revoking every grant issued at a lower one.
    Bump(BumpOpts),
}

#[derive(Debug, Args)]
struct ShowOpts {
    /// Remote name or mkit+https:// URL (default: the trusted remote).
    remote: Option<String>,
    /// Namespace to read (default: the remote URL's, else the signing key's).
    #[arg(long, value_name = "NS")]
    namespace: Option<String>,
    /// Emit a JSON object.
    #[arg(long)]
    json: bool,
}

/// Flags of `mkit epoch bump`, also driving `mkit grant revoke`.
#[derive(Debug, Clone, Args)]
pub(crate) struct BumpOpts {
    /// Remote name or mkit+https:// URL.
    pub remote: Option<String>,
    /// Namespace to advance (default: the remote URL's, else the signing key's).
    #[arg(long, value_name = "NS")]
    pub namespace: Option<String>,
    /// How far to advance (1 to 1024).
    #[arg(long, value_name = "N", default_value_t = 1)]
    pub by: u64,
    /// Audience the statement is valid for (repeatable; default: the remote's
    /// origin, the audience its requests are signed for).
    #[arg(long, value_name = "ORIGIN")]
    pub audience: Vec<String>,
    /// Longest to wait for revocation to complete (for example 5m).
    #[arg(long, value_name = "DURATION", default_value = "5m")]
    pub timeout: String,
    /// Emit a JSON object.
    #[arg(long)]
    pub json: bool,
    #[command(flatten)]
    pub owner: OwnerArgs,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<EpochOpts>("mkit epoch", args) {
        Ok(opts) => opts,
        Err(code) => return code,
    };
    match opts.command {
        EpochCommand::Show(opts) => show(&opts),
        EpochCommand::Bump(opts) => bump(&opts, None),
    }
}

/// `--namespace`, else the namespace of the repository the remote URL names.
fn hint_namespace(
    flag: Option<&str>,
    target: &crate::grants::remote::Target,
) -> Result<Option<Namespace>, u8> {
    Ok(parse_namespace(flag)?.or_else(|| target.namespace()))
}

fn show(opts: &ShowOpts) -> u8 {
    let ctx = match Ctx::load() {
        Ok(ctx) => ctx,
        Err(code) => return code,
    };
    let target = match resolve_target(&ctx.layered, opts.remote.as_deref()) {
        Ok(target) => target,
        Err(e) => return usage_error(&e),
    };
    let namespace = match hint_namespace(opts.namespace.as_deref(), &target) {
        Ok(Some(ns)) => ns,
        Ok(None) => {
            // Fall back to the configured signing key's namespace.
            let plan = ctx.plan(&OwnerArgs::default(), None);
            match plan {
                Ok(crate::grants::owner::Plan::Native(owner)) => *owner.namespace(),
                _ => {
                    return usage_error(
                        "no namespace: pass --namespace, or a remote URL that names <namespace>/<repo>",
                    );
                }
            }
        }
        Err(code) => return code,
    };
    let tx = match ctx.open_unsigned(&target) {
        Ok(tx) => tx,
        Err(e) => return error(&e, exit::UNAVAILABLE),
    };
    let epoch = match Ctx::read_epoch(&tx, &namespace) {
        Ok(epoch) => epoch,
        Err(e) => return error(&e, exit::UNAVAILABLE),
    };
    let mut stdout = std::io::stdout().lock();
    if opts.json {
        let mut object = JsonObject::new();
        object
            .field_str("namespace", &namespace.to_string())
            .field_str("audience", tx.origin())
            .field_u64("epoch", epoch);
        let _ = writeln!(stdout, "{}", object.finish());
    } else {
        let _ = writeln!(stdout, "namespace {namespace}");
        let _ = writeln!(stdout, "audience  {}", tx.origin());
        let _ = writeln!(stdout, "epoch     {epoch}");
    }
    exit::OK
}

/// What `mkit grant revoke` adds around a bump.
pub(crate) struct RevokeExtras {
    pub store: GrantStore,
    pub prune: bool,
}

/// Local grants a bump to `new_epoch` touches, split by whether every audience
/// of the grant is covered by the bump's `audiences`.
struct Invalidated<'a> {
    /// Every audience is covered: the grant stops working everywhere.
    dead: Vec<&'a StoredGrant>,
    /// Some audience is not covered: still valid there, and kept.
    partial: Vec<&'a StoredGrant>,
}

/// Grants in `stored` of `namespace` below `new_epoch` that list at least one
/// of the bump's `audiences`.
fn invalidated<'a>(
    stored: &'a [StoredGrant],
    namespace: &Namespace,
    audiences: &[String],
    new_epoch: u64,
) -> Invalidated<'a> {
    let mut out = Invalidated {
        dead: Vec::new(),
        partial: Vec::new(),
    };
    for g in stored.iter().filter(|g| {
        g.grant.namespace == *namespace
            && g.grant.epoch < new_epoch
            && g.grant.audiences.iter().any(|a| audiences.contains(a))
    }) {
        if g.grant.audiences.iter().all(|a| audiences.contains(a)) {
            out.dead.push(g);
        } else {
            out.partial.push(g);
        }
    }
    out
}

fn grant_line(g: &StoredGrant) -> String {
    format!(
        "{}  {}  epoch {}  {}",
        mkit_core::hash::to_hex_bytes(&g.id),
        g.grant.capabilities.token(),
        g.grant.epoch,
        scope_text(&g.grant)
    )
}

#[allow(clippy::too_many_lines)] // linear flow: resolve, sign once, send until done, report
pub(crate) fn bump(opts: &BumpOpts, revoke: Option<&RevokeExtras>) -> u8 {
    let ctx = match Ctx::load() {
        Ok(ctx) => ctx,
        Err(code) => return code,
    };
    let timeout = match parse_timeout(&opts.timeout) {
        Ok(t) => t,
        Err(e) => return usage_error(&format!("--timeout: {e}")),
    };
    if opts.by == 0 || opts.by > MAX_EPOCH_STEP {
        return usage_error(&format!(
            "--by {} is outside 1..={MAX_EPOCH_STEP}, the largest epoch step a server accepts (SPEC-WRITE-GRANTS §5.2); bump in several steps",
            opts.by
        ));
    }
    let Some(remote) = opts.remote.as_deref() else {
        return usage_error("mkit epoch bump needs a remote (name or mkit+https:// URL)");
    };
    let target = match resolve_target(&ctx.layered, Some(remote)) {
        Ok(target) => target,
        Err(e) => return usage_error(&e),
    };
    let tx = match ctx.open_unsigned(&target) {
        Ok(tx) => tx,
        Err(e) => return error(&e, exit::UNAVAILABLE),
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
    let hint = match hint_namespace(opts.namespace.as_deref(), &target) {
        Ok(hint) => hint,
        Err(code) => return code,
    };
    let plan = match ctx.plan(&opts.owner, hint) {
        Ok(plan) => plan,
        Err(e) => return error(&e, exit::USAGE),
    };

    // Native and print plans build the statement from the stored epoch.
    let mut read_current: Option<u64> = None;
    let now = now_ms();
    let lifetime_ms = statement_lifetime_ms(timeout);
    let produced = produce(
        plan,
        |ns| {
            let current = Ctx::read_epoch(&tx, ns)?;
            read_current = Some(current);
            let new = current
                .checked_add(opts.by)
                .ok_or("the epoch would overflow")?;
            build_epoch(ns, new, &audiences, now, lifetime_ms)?
                .encode()
                .map_err(|e| format!("invalid statement: {e}"))
        },
        Kind::Epoch,
        &ctx.relying_parties,
        now,
    );
    let signed = match produced {
        Ok(Produced::Signed(signed)) => signed,
        Ok(Produced::Print {
            statement,
            namespace,
        }) => return print_statement(&statement, &namespace),
        Err(e) => return error(&e, exit::DATAERR),
    };
    let statement = match EpochStatement::parse(&signed.statement) {
        Ok(s) => s,
        Err(e) => return error(&format!("invalid statement: {e}"), exit::DATAERR),
    };
    // An imported statement was made elsewhere: hold what it says, not the
    // flags, to the same audience and namespace rules.
    if let Err(e) = check_audiences(&statement.audiences, Some(&target)) {
        return error(&e, exit::USAGE);
    }
    if let Some(hint) = hint
        && hint != statement.namespace
    {
        return error(
            &format!(
                "the statement is for namespace {}, but the command asks for {hint}",
                statement.namespace
            ),
            exit::DATAERR,
        );
    }
    let current = match read_current {
        Some(c) => c,
        None => match Ctx::read_epoch(&tx, &statement.namespace) {
            Ok(c) => c,
            Err(e) => return error(&e, exit::UNAVAILABLE),
        },
    };
    match epoch_transition(current, statement.new_epoch) {
        EpochTransition::Advance | EpochTransition::Retry => {}
        EpochTransition::Reject if statement.new_epoch > current => {
            return error(
                &format!(
                    "the statement raises epoch {current} to {}: a step of {} is over the maximum of {MAX_EPOCH_STEP}",
                    statement.new_epoch,
                    statement.new_epoch - current
                ),
                exit::DATAERR,
            );
        }
        EpochTransition::Reject => {
            return error(
                &format!(
                    "the statement sets epoch {} but {} is already stored; an epoch never decreases",
                    statement.new_epoch, current
                ),
                exit::DATAERR,
            );
        }
    }

    let stored = revoke.map(|r| r.store.load(&ctx.relying_parties));
    if let Some(report) = &stored {
        for warning in &report.warnings {
            eprintln!("warning: {warning}");
        }
        let affected = invalidated(
            &report.grants,
            &statement.namespace,
            &statement.audiences,
            statement.new_epoch,
        );
        eprintln!(
            "revoking: {} local grant(s) stop working when {} reaches epoch {}",
            affected.dead.len() + affected.partial.len(),
            statement.namespace,
            statement.new_epoch
        );
        for g in &affected.dead {
            eprintln!("  {}", grant_line(g));
        }
        for g in &affected.partial {
            eprintln!(
                "  {}  (still valid at {})",
                grant_line(g),
                g.grant
                    .audiences
                    .iter()
                    .filter(|a| !statement.audiences.contains(a))
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }

    let outcome = drive(
        || tx.set_grant_epoch(&signed.header),
        timeout,
        interruptible_sleep,
    );
    let outcome = match outcome {
        Ok(outcome) => outcome,
        Err(e) => return set_epoch_error(&e),
    };
    if let Some(code) = finish_wait(&outcome, "the epoch bump") {
        return code;
    }
    let Driven::Done(stored_epoch) = outcome else {
        return exit::GENERAL_ERROR;
    };
    report_bump(
        opts,
        &statement,
        current,
        stored_epoch,
        revoke,
        stored.as_ref().map(|r| r.grants.as_slice()),
    )
}

#[allow(clippy::too_many_arguments)]
fn report_bump(
    opts: &BumpOpts,
    statement: &EpochStatement,
    previous: u64,
    stored_epoch: u64,
    revoke: Option<&RevokeExtras>,
    grants: Option<&[StoredGrant]>,
) -> u8 {
    let mut pruned = 0usize;
    if let (Some(extras), Some(grants)) = (revoke, grants)
        && extras.prune
    {
        for g in invalidated(
            grants,
            &statement.namespace,
            &statement.audiences,
            stored_epoch,
        )
        .dead
        {
            match extras.store.remove(&g.id) {
                Ok(true) => pruned += 1,
                Ok(false) => {}
                Err(e) => eprintln!("warning: could not remove grant: {e}"),
            }
        }
    }
    let mut stdout = std::io::stdout().lock();
    if opts.json {
        let mut object = JsonObject::new();
        object
            .field_str("namespace", &statement.namespace.to_string())
            .field_raw("audiences", &json_string_array(&statement.audiences))
            .field_u64("previous", previous)
            .field_u64("epoch", stored_epoch);
        if revoke.is_some() {
            object.field_u64("pruned", pruned as u64);
        }
        let _ = writeln!(stdout, "{}", object.finish());
    } else {
        let _ = writeln!(stdout, "namespace {}", statement.namespace);
        let _ = writeln!(stdout, "audience  {}", statement.audiences.join(", "));
        let _ = writeln!(stdout, "epoch     {stored_epoch} (was {previous})");
    }
    if revoke.is_some() {
        eprintln!(
            "grants issued at epoch {previous} or lower no longer work. Issue replacements with `mkit grant create --epoch {stored_epoch} ...`{}",
            if pruned > 0 {
                format!("; removed {pruned} local grant(s)")
            } else {
                String::new()
            }
        );
    }
    exit::OK
}

fn set_epoch_error(error_value: &mkit_core::protocol::TransportError) -> u8 {
    use mkit_core::protocol::TransportError;
    let hint = match error_value {
        TransportError::AccessDenied => {
            " (the server rejected the statement: a step over 1024, a decrease, a wrong audience, an expired statement, a bad signature, or a namespace this deployment doesn't serve)"
        }
        _ => "",
    };
    error(&format!("SetGrantEpoch: {error_value}{hint}"), exit::NOPERM)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grants::store::GrantStore;
    use crate::grants::testutil::signed_grant;

    fn stored(dir: &std::path::Path, nonce: u8, epoch: u64, audiences: &[&str]) -> StoredGrant {
        // `signed_grant` takes one audience; rebuild a multi-audience grant
        // by signing it with the first and re-reading its fields.
        let header = signed_grant(1, nonce, epoch, audiences[0]);
        let store = GrantStore::at(dir.to_path_buf());
        store.add(&header, &[]).unwrap();
        let mut g = store
            .load(&[])
            .grants
            .into_iter()
            .find(|g| g.grant.epoch == epoch && g.header == header)
            .unwrap();
        g.grant.audiences = audiences.iter().map(|a| (*a).to_owned()).collect();
        g
    }

    #[test]
    fn a_bump_only_kills_grants_it_covers_in_full() {
        let tmp = tempfile::tempdir().unwrap();
        let a = "https://a.example";
        let b = "https://b.example";
        let all = vec![
            stored(tmp.path(), 1, 0, &[a]),
            stored(tmp.path(), 2, 1, &[a, b]),
            stored(tmp.path(), 3, 2, &[b]),
            stored(tmp.path(), 4, 5, &[a]),
        ];
        let namespace = all[0].grant.namespace;
        let hit = invalidated(&all, &namespace, &[a.to_owned()], 3);
        assert_eq!(hit.dead.len(), 1);
        assert_eq!(hit.dead[0].grant.epoch, 0);
        // Epoch 1 also lists b, which the bump does not reach: kept.
        assert_eq!(hit.partial.len(), 1);
        assert_eq!(hit.partial[0].grant.epoch, 1);
        // Covering both audiences kills it.
        let hit = invalidated(&all, &namespace, &[a.to_owned(), b.to_owned()], 3);
        assert_eq!(hit.dead.len(), 3);
        assert!(hit.partial.is_empty());
    }
}
