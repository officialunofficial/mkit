//! `mkit grant create|add|list|revoke` (WP-2.13, WP-2.14; R-155, R-156):
//! issue, import, inspect and revoke SPEC-WRITE-GRANTS write and read grants.
//!
//! This is the *client* grant store, under the user config directory. It
//! does not register grants on a server: it holds grants a person was given
//! so `mkit push` and `mkit clone` present them.

use std::io::Write as _;

use clap::{Args, Parser, Subcommand};
use mkit_attest::grant::{Capabilities, Namespace};
use mkit_core::hash::{from_hex, hash, to_hex_bytes};

use crate::clap_shim;
use crate::commands::epoch::{BumpOpts, RevokeExtras, bump};
use crate::commands::{error, usage_error};
use crate::exit;
use crate::format::{JsonObject, human_date_utc, json_string_array};
use crate::grants::cli::{Ctx, parse_namespace, print_statement};
use crate::grants::owner::{Kind, OwnerArgs, Produced, produce};
use crate::grants::remote::{Target, check_audiences, resolve_target};
use crate::grants::spec::{
    DEFAULT_GRANT_TTL, GrantSpec, RepoSelector, build_grant, canonical_audiences,
    canonical_capabilities, canonical_ref_scopes, check_ref_scopes, parse_ttl,
};
use crate::grants::store::{AddOutcome, GrantStore, StoredGrant};
use crate::grants::{now_ms, scope_text};

/// The clock lead a server tolerates on a grant's `created` (§1.1).
const CLOCK_LEAD_MS: i64 = 30_000;

#[derive(Debug, Parser)]
#[command(
    name = "mkit grant",
    about = "Issue, import, list and revoke write and read grants."
)]
struct GrantOpts {
    #[command(subcommand)]
    command: GrantCommand,
}

#[derive(Debug, Subcommand)]
enum GrantCommand {
    /// Create an owner-signed grant for a grantee's key.
    Create(Box<CreateOpts>),
    /// Verify a grant header and add it to your grant store.
    Add(AddOpts),
    /// List the grants in your grant store.
    List(ListOpts),
    /// Revoke grants by advancing the namespace's epoch on a remote.
    Revoke(Box<RevokeOpts>),
}

#[derive(Debug, Args)]
#[allow(clippy::struct_excessive_bools)]
struct CreateOpts {
    /// Namespace that owns the repositories (default: the signing key's).
    #[arg(long, value_name = "NS")]
    namespace: Option<String>,
    /// One repository in the namespace.
    #[arg(long, value_name = "NAME", conflicts_with = "all")]
    repo: Option<String>,
    /// Every repository in the namespace, including ones not created yet.
    #[arg(long)]
    all: bool,
    /// Audience the grant is valid for (repeatable, 1 to 8; default: the
    /// trusted remote's origin).
    #[arg(long, value_name = "ORIGIN")]
    audience: Vec<String>,
    /// A ref scope `pattern=flags` from `cufd` (repeatable): for example
    /// `refs/heads/*=cuf`. Required with write, not allowed with read.
    #[arg(long, value_name = "PATTERN=FLAGS")]
    refs: Vec<String>,
    /// `read`, `read,write` or `write` (`write,read` is accepted and
    /// spelled canonically).
    #[arg(long, value_name = "CAP")]
    cap: Option<String>,
    /// The grantee's Ed25519 public key, 64 hex digits.
    #[arg(long, value_name = "HEX")]
    grantee: Option<String>,
    /// Lifetime, at most 30d (for example 12h, 7d).
    #[arg(long, value_name = "DURATION", default_value = DEFAULT_GRANT_TTL)]
    ttl: String,
    /// The namespace epoch the grant is valid at (default: read from the
    /// remote).
    #[arg(long, value_name = "N", conflicts_with = "offline")]
    epoch: Option<u64>,
    /// Don't contact a remote; the epoch defaults to 0.
    #[arg(long)]
    offline: bool,
    /// Remote (name or mkit+https:// URL) supplying the default audience and
    /// epoch. Default: the trusted remote.
    #[arg(long, value_name = "REMOTE")]
    remote: Option<String>,
    /// Also add the grant to your own grant store.
    #[arg(long)]
    store: bool,
    #[command(flatten)]
    owner: OwnerArgs,
}

#[derive(Debug, Args)]
struct AddOpts {
    /// File holding a grant header, or `-` for stdin.
    file: String,
    /// Remote (name or mkit+https:// URL) to compare the grant's epoch with.
    /// Default: the trusted remote.
    #[arg(long, value_name = "REMOTE")]
    remote: Option<String>,
    /// Don't contact a remote.
    #[arg(long)]
    offline: bool,
}

#[derive(Debug, Args)]
struct ListOpts {
    /// Ask the trusted remote (or --remote) for each namespace's epoch and
    /// mark grants `stale epoch` or `future epoch`.
    #[arg(long)]
    check: bool,
    /// Remote (name or mkit+https:// URL) for --check. Default: the trusted
    /// remote.
    #[arg(long, value_name = "REMOTE")]
    remote: Option<String>,
    /// Emit a JSON array.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct RevokeOpts {
    /// Remote name or mkit+https:// URL.
    remote: Option<String>,
    /// Namespace to advance (default: the remote URL's, else the signing key's).
    #[arg(long, value_name = "NS")]
    namespace: Option<String>,
    /// Audience the statement is valid for (repeatable; default: the remote's
    /// origin).
    #[arg(long, value_name = "ORIGIN")]
    audience: Vec<String>,
    /// Longest to wait for revocation to complete (for example 5m).
    #[arg(long, value_name = "DURATION", default_value = "5m")]
    timeout: String,
    /// Delete the local grants this revocation invalidates, once it succeeds.
    #[arg(long)]
    prune: bool,
    /// Emit a JSON object.
    #[arg(long)]
    json: bool,
    #[command(flatten)]
    owner: OwnerArgs,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<GrantOpts>("mkit grant", args) {
        Ok(opts) => opts,
        Err(code) => return code,
    };
    match opts.command {
        GrantCommand::Create(opts) => create(&opts),
        GrantCommand::Add(opts) => add(&opts),
        GrantCommand::List(opts) => list(&opts),
        GrantCommand::Revoke(opts) => {
            let opts = *opts;
            let store = match GrantStore::open_default() {
                Ok(store) => store,
                Err(e) => return error(&e, exit::CONFIG_ERROR),
            };
            bump(
                &BumpOpts {
                    remote: opts.remote,
                    namespace: opts.namespace,
                    by: 1,
                    audience: opts.audience,
                    timeout: opts.timeout,
                    json: opts.json,
                    owner: opts.owner,
                },
                Some(&RevokeExtras {
                    store,
                    prune: opts.prune,
                }),
            )
        }
    }
}

fn optional_target(ctx: &Ctx, remote: Option<&str>) -> Result<Option<Target>, u8> {
    match resolve_target(&ctx.layered, remote) {
        Ok(target) => Ok(Some(target)),
        Err(e) if remote.is_some() => Err(usage_error(&e)),
        Err(_) => Ok(None),
    }
}

fn build_spec(o: &CreateOpts, audiences: Vec<String>) -> Result<GrantSpec, u8> {
    let repo = match (&o.repo, o.all) {
        (Some(name), false) => RepoSelector::Name(name.clone()),
        (None, true) => RepoSelector::All,
        _ => return Err(usage_error("give exactly one of --repo NAME or --all")),
    };
    let capabilities = canonical_capabilities(
        o.cap
            .as_deref()
            .ok_or_else(|| usage_error("--cap is required (read, read,write or write)"))?,
    )
    .map_err(|e| usage_error(&e))?;
    let grantee_text = o
        .grantee
        .as_deref()
        .ok_or_else(|| usage_error("--grantee <ed25519 public key hex> is required"))?;
    let grantee = from_hex(grantee_text).map_err(|e| {
        usage_error(&format!(
            "--grantee must be a 64-digit lowercase hex Ed25519 public key: {e}"
        ))
    })?;
    let ref_scopes = if o.refs.is_empty() {
        None
    } else {
        Some(canonical_ref_scopes(&o.refs).map_err(|e| usage_error(&e))?)
    };
    check_ref_scopes(capabilities, ref_scopes.as_ref()).map_err(|e| usage_error(&e))?;
    let ttl_ms = parse_ttl(&o.ttl).map_err(|e| usage_error(&format!("--ttl: {e}")))?;
    Ok(GrantSpec {
        repo,
        grantee,
        capabilities,
        audiences,
        ref_scopes,
        epoch: 0,
        ttl_ms,
    })
}

#[allow(clippy::too_many_lines)] // linear flow: plan, audiences, epoch, sign, store
fn create(o: &CreateOpts) -> u8 {
    let ctx = match Ctx::load() {
        Ok(ctx) => ctx,
        Err(code) => return code,
    };
    let importing = o.owner.statement_file.is_some();
    if importing
        && (o.repo.is_some()
            || o.all
            || !o.audience.is_empty()
            || !o.refs.is_empty()
            || o.cap.is_some()
            || o.grantee.is_some()
            || o.epoch.is_some())
    {
        return usage_error(
            "--statement-file already fixes the grant: don't combine it with --repo, --all, --audience, --refs, --cap, --grantee or --epoch",
        );
    }
    let hint = match parse_namespace(o.namespace.as_deref()) {
        Ok(hint) => hint,
        Err(code) => return code,
    };
    let target = match optional_target(&ctx, o.remote.as_deref()) {
        Ok(target) => target,
        Err(code) => return code,
    };
    let audiences = if importing {
        Vec::new()
    } else if o.audience.is_empty() {
        match target.as_ref().map(Target::audience) {
            Some(Ok(audience)) => vec![audience],
            Some(Err(e)) => return usage_error(&e),
            None => {
                return usage_error(
                    "no --audience and no trusted remote to default to (set one with `mkit config trusted_remote_endpoint <url>`)",
                );
            }
        }
    } else {
        match canonical_audiences(&o.audience) {
            Ok(a) => a,
            Err(e) => return usage_error(&e),
        }
    };
    if !importing && let Err(e) = check_audiences(&audiences, target.as_ref()) {
        return error(&e, exit::USAGE);
    }
    let spec = if importing {
        None
    } else {
        match build_spec(o, audiences.clone()) {
            Ok(spec) => Some(spec),
            Err(code) => return code,
        }
    };
    let plan = match ctx.plan(&o.owner, hint) {
        Ok(plan) => plan,
        Err(e) => return error(&e, exit::USAGE),
    };

    let now = now_ms();
    let epoch_for = |ns: &Namespace| -> Result<u64, String> {
        if let Some(epoch) = o.epoch {
            return Ok(epoch);
        }
        if o.offline {
            return Ok(0);
        }
        let target = target.as_ref().ok_or(
            "no remote to read the current epoch from: pass --epoch N, --offline, --remote, or set a trusted remote",
        )?;
        let audience = target.audience()?;
        if !audiences.contains(&audience) {
            return Err(format!(
                "the audiences don't include the remote's {audience}, so its epoch doesn't apply: pass --epoch N"
            ));
        }
        Ctx::read_epoch(&ctx.open_unsigned(target)?, ns)
    };
    let produced = produce(
        plan,
        |ns| {
            let mut spec = spec.clone().ok_or("no grant to build")?;
            spec.epoch = epoch_for(ns)?;
            build_grant(&spec, ns, now)?
                .encode()
                .map_err(crate::grants::spec::statement_error)
        },
        Kind::Grant,
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
    if o.store {
        let store = match GrantStore::open_default() {
            Ok(store) => store,
            Err(e) => return error(&e, exit::CONFIG_ERROR),
        };
        match store.add(&signed.header, &ctx.relying_parties) {
            Ok(AddOutcome::Added) => eprintln!("stored in {}", store.dir().display()),
            Ok(AddOutcome::AlreadyStored) => eprintln!("already in your grant store"),
            Err(e) => return error(&format!("store the grant: {e}"), exit::CANTCREAT),
        }
    }
    let mut stdout = std::io::stdout().lock();
    let _ = writeln!(stdout, "{}", signed.header);
    let _ = stdout.flush();
    eprintln!(
        "grant {} ({}): give the header above to the grantee, who runs `mkit grant add`",
        to_hex_bytes(&hash(&signed.statement)),
        signed.scheme.token()
    );
    exit::OK
}

fn read_header(source: &str) -> Result<String, String> {
    const LIMIT: u64 = 16 * 1024;
    let read = if source == "-" {
        crate::grants::read_bounded(std::io::stdin().lock(), LIMIT)
    } else {
        std::fs::File::open(source).and_then(|f| crate::grants::read_bounded(f, LIMIT))
    };
    let bytes = read.map_err(|e| format!("{source}: {e}"))?;
    let text = String::from_utf8(bytes).map_err(|_| format!("{source}: not UTF-8"))?;
    Ok(text.trim().to_owned())
}

fn add(o: &AddOpts) -> u8 {
    let ctx = match Ctx::load() {
        Ok(ctx) => ctx,
        Err(code) => return code,
    };
    let header = match read_header(&o.file) {
        Ok(header) => header,
        Err(e) => return error(&e, exit::NOINPUT),
    };
    let verified = match crate::grants::verify_grant_header(&header, &ctx.relying_parties) {
        Ok(verified) => verified,
        Err(e) => return error(&format!("rejected: {e}"), exit::DATAERR),
    };
    let store = match GrantStore::open_default() {
        Ok(store) => store,
        Err(e) => return error(&e, exit::CONFIG_ERROR),
    };
    let outcome = match store.add(&header, &ctx.relying_parties) {
        Ok(outcome) => outcome,
        Err(e) => return error(&format!("rejected: {e}"), exit::DATAERR),
    };
    let id = to_hex_bytes(&verified.id);
    match outcome {
        AddOutcome::Added => println!("added grant {id}"),
        AddOutcome::AlreadyStored => println!("grant {id} is already in your grant store"),
    }
    if !o.offline {
        warn_if_future_epoch(&ctx, o.remote.as_deref(), &verified.grant);
    }
    exit::OK
}

/// Longest `grant add` waits to compare epochs.
const ADD_EPOCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// B6 caveat: a grant for an epoch above the remote's outranks the live
/// grants until the owner bumps the epoch.
fn warn_if_future_epoch(ctx: &Ctx, remote: Option<&str>, grant: &mkit_attest::grant::Grant) {
    let Ok(target) = resolve_target(&ctx.layered, remote) else {
        return;
    };
    let Ok(audience) = target.audience() else {
        return;
    };
    if !grant.audiences.contains(&audience) {
        return;
    }
    // Advisory: one short attempt, and a failure only warns.
    let epoch = ctx.open_unsigned(&target).and_then(|tx| {
        Ctx::read_epoch_once(&tx.with_unary_timeout(ADD_EPOCH_TIMEOUT), &grant.namespace)
    });
    match epoch {
        Ok(current) if grant.epoch > current => eprintln!(
            "warning: this grant is for epoch {} but {audience} is at epoch {current}. Until the owner raises the epoch it is refused there, and it outranks your other grants for {} at that audience",
            grant.epoch, grant.namespace
        ),
        Ok(_) => {}
        Err(e) => eprintln!("warning: couldn't compare the grant's epoch with {audience}: {e}"),
    }
}

fn status_at(stored: &StoredGrant, now: i64) -> &'static str {
    if stored.grant.created_ms > now.saturating_add(CLOCK_LEAD_MS) {
        "not yet valid"
    } else if now >= stored.grant.expiry_ms {
        "expired"
    } else {
        "valid"
    }
}

fn epoch_status(grant_epoch: u64, remote_epoch: u64) -> &'static str {
    match grant_epoch.cmp(&remote_epoch) {
        std::cmp::Ordering::Less => "stale epoch",
        std::cmp::Ordering::Equal => "epoch current",
        std::cmp::Ordering::Greater => "future epoch",
    }
}

fn ref_scope_text(stored: &StoredGrant) -> String {
    stored.grant.ref_scopes.as_ref().map_or_else(
        || "-".to_owned(),
        |scopes| {
            scopes
                .entries()
                .iter()
                .map(|(pattern, flags)| format!("{pattern}={flags}"))
                .collect::<Vec<_>>()
                .join(";")
        },
    )
}

fn date(ms: i64) -> String {
    human_date_utc(u64::try_from(ms / 1000).unwrap_or(0))
}

#[allow(clippy::too_many_lines)] // load, optional epoch check, then JSON or text output
fn list(o: &ListOpts) -> u8 {
    let ctx = match Ctx::load() {
        Ok(ctx) => ctx,
        Err(code) => return code,
    };
    let store = match GrantStore::open_default() {
        Ok(store) => store,
        Err(e) => return error(&e, exit::CONFIG_ERROR),
    };
    let report = store.load(&ctx.relying_parties);
    for warning in &report.warnings {
        eprintln!("warning: {warning}");
    }
    let mut grants = report.grants;
    grants.sort_by_key(|g| (g.grant.namespace.to_string(), g.grant.epoch, g.id));
    let now = now_ms();

    // --check asks only the trusted (or named) remote: a grant file is data
    // from other people, and contacting an origin it names would send it your
    // ambient credentials.
    let mut checked: std::collections::BTreeMap<String, Result<u64, String>> =
        std::collections::BTreeMap::new();
    let mut check_audience = None;
    let mut check_error = None;
    if o.check {
        match resolve_target(&ctx.layered, o.remote.as_deref())
            .and_then(|t| ctx.open_unsigned(&t).map(|tx| (t, tx)))
        {
            Ok((target, tx)) => {
                check_audience = target.audience().ok();
                for g in &grants {
                    if check_audience
                        .as_ref()
                        .is_some_and(|a| g.grant.audiences.contains(a))
                    {
                        checked
                            .entry(g.grant.namespace.to_string())
                            .or_insert_with(|| Ctx::read_epoch(&tx, &g.grant.namespace));
                    }
                }
            }
            Err(e) => check_error = Some(e),
        }
    }
    let epoch_state = |g: &StoredGrant| -> Option<String> {
        if !o.check {
            return None;
        }
        if let Some(e) = &check_error {
            return Some(format!("unchecked ({e})"));
        }
        let covered = check_audience
            .as_ref()
            .is_some_and(|a| g.grant.audiences.contains(a));
        if !covered {
            return Some("unchecked (audience is not the checked remote)".to_owned());
        }
        match checked.get(&g.grant.namespace.to_string()) {
            Some(Ok(remote)) => Some(epoch_status(g.grant.epoch, *remote).to_owned()),
            Some(Err(e)) => Some(format!("unchecked ({e})")),
            None => Some("unchecked (audience is not the checked remote)".to_owned()),
        }
    };

    let mut stdout = std::io::stdout().lock();
    if o.json {
        let items: Vec<String> = grants
            .iter()
            .map(|g| {
                let mut object = JsonObject::new();
                object
                    .field_str("id", &to_hex_bytes(&g.id))
                    .field_str("namespace", &g.grant.namespace.to_string())
                    .field_str("scope", &scope_text(&g.grant))
                    .field_str("grantee", &to_hex_bytes(&g.grant.grantee))
                    .field_str("capabilities", g.grant.capabilities.token())
                    .field_str("ref_scopes", &ref_scope_text(g))
                    .field_raw("audiences", &json_string_array(&g.grant.audiences))
                    .field_u64("epoch", g.grant.epoch)
                    .field_u64("created_ms", u64::try_from(g.grant.created_ms).unwrap_or(0))
                    .field_u64("expiry_ms", u64::try_from(g.grant.expiry_ms).unwrap_or(0))
                    .field_str("scheme", g.scheme.token())
                    .field_str("status", status_at(g, now));
                if let Some(state) = epoch_state(g) {
                    object.field_str("epoch_status", &state);
                }
                object.finish()
            })
            .collect();
        let _ = writeln!(stdout, "[{}]", items.join(","));
        return exit::OK;
    }
    if grants.is_empty() {
        let _ = writeln!(stdout, "no grants in {}", store.dir().display());
        return exit::OK;
    }
    for g in &grants {
        let mut status = status_at(g, now).to_owned();
        if let Some(state) = epoch_state(g) {
            status = format!("{status}, {state}");
        }
        let _ = writeln!(
            stdout,
            "{}  {}  epoch {}  {}",
            to_hex_bytes(&g.id),
            g.grant.capabilities.token(),
            g.grant.epoch,
            status
        );
        let _ = writeln!(stdout, "  namespace  {}", g.grant.namespace);
        let _ = writeln!(stdout, "  scope      {}", scope_text(&g.grant));
        let _ = writeln!(stdout, "  grantee    {}", to_hex_bytes(&g.grant.grantee));
        let _ = writeln!(stdout, "  audiences  {}", g.grant.audiences.join(", "));
        if g.grant.capabilities != Capabilities::Read {
            let _ = writeln!(stdout, "  refs       {}", ref_scope_text(g));
        }
        let _ = writeln!(stdout, "  expires    {}", date(g.grant.expiry_ms));
    }
    if o.check && check_audience.is_none() && check_error.is_none() {
        eprintln!("note: --check needs a remote with an mkit+https:// URL");
    }
    exit::OK
}
