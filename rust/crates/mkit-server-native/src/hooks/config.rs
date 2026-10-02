//! The hook flags and their fail-closed resolution into [`HookSettings`]
//! (WP-3.8; SPEC-SERVER §§6-8).

use core::fmt;
use core::time::Duration;
use std::path::{Path, PathBuf};

use clap::{Args, ValueEnum};
use mkit_core::hash::{from_hex, to_hex};
use mkit_server::hooks::{HookSigner, MAX_VALIDITY};
use mkit_server::pipeline::{AuthMode, PipelineConfig};
use mkit_server::policy::AuthorizerRole;
use zeroize::Zeroizing;

use crate::config::{ConfigError, MetaChoice, PREFIX, read_secret_file};
use crate::exit;

/// The hook signing key's environment variable, the alternative to
/// `--hook-key-file` (one line: `<key-id> <64 hex>`).
pub const HOOK_KEY_ENV: &str = "MKIT_HOOK_KEY";

/// Default `--hook-timeout-secs` (SPEC-SERVER §8, informative).
pub const DEFAULT_TIMEOUT_SECS: u64 = 5;

/// Default maximum metadata objects in one Inspect call.
pub const DEFAULT_INSPECT_BATCH_MAX_OBJECTS: usize = 10_000;

/// Default `--hook-signature-validity-secs`.
pub const DEFAULT_VALIDITY_SECS: u64 = 60;

/// How a remote authorizer composes with the built-in policy
/// (`--authorizer-role`, SPEC-SERVER §6.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum AuthorizerRoleArg {
    /// An extra check that may deny an otherwise authorized write (default).
    Check,
    /// The rule-3 authority source: it may authorize non-owners.
    Authority,
}

/// The remote-hook flags of `mkit-server serve`. A URL enables its role; any
/// of them needs `--auth auth-v2` and a signing key.
#[derive(Debug, Clone, Args, Default)]
pub struct HookArgs {
    /// Base URL of the hook service's Authorize RPC (`https`, or `http` to
    /// loopback only; no credentials, query or fragment). The RPC is
    /// `POST <URL>/mkit.server.hooks.v1.HooksService/Authorize`.
    #[arg(long, value_name = "URL")]
    pub hook_authorize_url: Option<String>,
    /// Base URL of the hook service's Admit RPC. A remote admission replaces
    /// the built-in per-signer abuse quota: the hook owns abuse control.
    #[arg(long, value_name = "URL")]
    pub hook_admit_url: Option<String>,
    /// Base URL of the hook service's Outcome RPC, which receives every
    /// terminal outcome after commit, retried until a 2xx. Needs
    /// `--meta sqlite:<PATH>`.
    #[arg(long, value_name = "URL")]
    pub hook_outcome_url: Option<String>,
    /// Signed global `CachePurge` sink; acknowledges only after global invalidation.
    #[arg(long, value_name = "URL")]
    pub hook_cache_purge_url: Option<String>,
    /// Base URL of an Inspect RPC; repeat for independent inspectors.
    #[arg(long, value_name = "URL")]
    pub hook_inspect_url: Vec<String>,
    /// Launch profile: only synchronous inspection is supported.
    #[arg(long, value_name = "MODE")]
    pub inspect_mode: Option<String>,
    /// Launch profile: only `fail_closed` is supported.
    #[arg(long, value_name = "POLICY")]
    pub inspect_on_unavailable: Option<String>,
    /// Maximum objects per Inspect call (1..=10000).
    #[arg(long, default_value_t = DEFAULT_INSPECT_BATCH_MAX_OBJECTS)]
    pub inspect_batch_max_objects: usize,
    /// The hook signing key: one line `<key-id> <64 hex seed>`, owner-only.
    /// Without it, `MKIT_HOOK_KEY` is read. It must differ from every ticket,
    /// URL-token and enc key (SPEC-SERVER §7.1). Print the public key list
    /// with `mkit-server hook-key-list`.
    #[arg(long, value_name = "PATH")]
    pub hook_key_file: Option<PathBuf>,
    /// How long each signed request stays valid (1 to 300).
    #[arg(long, value_name = "SECS", default_value_t = DEFAULT_VALIDITY_SECS)]
    pub hook_signature_validity_secs: u64,
    /// Bound on one hook call (at least 1, and below `--unary-timeout-secs`).
    #[arg(long, value_name = "SECS", default_value_t = DEFAULT_TIMEOUT_SECS)]
    pub hook_timeout_secs: u64,
    /// With `--hook-authorize-url`: `check` (default) lets the hook only deny;
    /// `authority` makes it the authority source for non-owner writes.
    #[arg(long, value_enum)]
    pub authorizer_role: Option<AuthorizerRoleArg>,
}

/// A resolved hook configuration. `Debug` never prints a URL (a path may
/// carry a secret) or key material.
#[derive(Clone)]
pub struct HookSettings {
    /// Base URL of Authorize, if that role is remote.
    pub authorize: Option<String>,
    /// Base URL of Admit, if that role is remote.
    pub admit: Option<String>,
    /// Base URL of Outcome, if delivery is remote.
    pub outcome: Option<String>,
    /// Global cache purge sink.
    pub purge: Option<String>,
    /// Independent synchronous, fail-closed Inspect endpoints.
    pub inspect: Vec<String>,
    /// Bound on one Inspect metadata batch.
    pub inspect_batch_max_objects: usize,
    key_id: String,
    seed: Zeroizing<[u8; 32]>,
    /// The validity each signature carries.
    pub validity: Duration,
    /// The bound on one hook call, and on one kind-8 sink call.
    pub timeout: Duration,
}

impl fmt::Debug for HookSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HookSettings")
            .field("authorize", &self.authorize.is_some())
            .field("admit", &self.admit.is_some())
            .field("outcome", &self.outcome.is_some())
            .field("inspectors", &self.inspect.len())
            .field("key_id", &self.key_id)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl HookSettings {
    /// Settings for tests and embedders: `key_id` and `seed` sign, every role
    /// URL is set separately.
    ///
    /// # Errors
    /// A key id outside the spec's grammar.
    pub fn new(key_id: &str, seed: [u8; 32]) -> Result<Self, ConfigError> {
        let seed = Zeroizing::new(seed);
        let settings = Self {
            authorize: None,
            admit: None,
            outcome: None,
            purge: None,
            inspect: Vec::new(),
            inspect_batch_max_objects: DEFAULT_INSPECT_BATCH_MAX_OBJECTS,
            key_id: key_id.to_owned(),
            seed,
            validity: Duration::from_secs(DEFAULT_VALIDITY_SECS),
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
        };
        settings.signer()?;
        Ok(settings)
    }

    /// A fresh signer for one client (a signer is not `Clone`).
    ///
    /// # Errors
    /// `CONFIG_ERROR` for a key id or validity the spec refuses.
    pub fn signer(&self) -> Result<HookSigner, ConfigError> {
        HookSigner::new(self.key_id.clone(), self.seed.clone())
            .and_then(|signer| signer.with_validity(self.validity))
            .map_err(|e| ConfigError::new(exit::CONFIG_ERROR, format!("{PREFIX}: hook key: {e}")))
    }

    /// The Ed25519 public key of the signing key.
    ///
    /// # Errors
    /// As [`Self::signer`].
    pub fn public_key(&self) -> Result<[u8; 32], ConfigError> {
        Ok(self.signer()?.public_key())
    }

    /// Refuse role public keys that equal this signing seed or public key.
    pub(crate) fn check_role_keys(&self, public: &[[u8; 32]]) -> Result<(), ConfigError> {
        if public.contains(&*self.seed) || public.contains(&self.public_key()?) {
            return Err(ConfigError::new(
                exit::CONFIG_ERROR,
                "hook key must differ from other configured role keys",
            ));
        }
        Ok(())
    }

    /// Refuse scanner role reuse without exposing the hook seed.
    pub(crate) fn check_scanner_keys(
        &self,
        config: &mkit_server::scanner_retrieval::RetrievalConfig,
    ) -> Result<(), ConfigError> {
        config
            .check_role_keys(&[self.public_key()?], &[*self.seed])
            .map_err(|e| ConfigError::new(exit::CONFIG_ERROR, e.to_string()))
    }

    /// Whether any role is remote.
    #[must_use]
    pub fn any(&self) -> bool {
        self.authorize.is_some()
            || self.admit.is_some()
            || self.outcome.is_some()
            || self.purge.is_some()
            || !self.inspect.is_empty()
    }
}

/// Parse `<key-id> <64 hex>`: one non-comment line, nothing else.
fn parse_key(text: &str) -> Option<(String, Zeroizing<[u8; 32]>)> {
    let mut lines = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'));
    let line = lines.next()?;
    if lines.next().is_some() {
        return None;
    }
    let mut fields = line.split_whitespace();
    let (id, seed) = (fields.next()?, fields.next()?);
    if fields.next().is_some() {
        return None;
    }
    Some((id.to_owned(), Zeroizing::new(from_hex(seed).ok()?)))
}

fn key_error() -> ConfigError {
    ConfigError::new(
        exit::CONFIG_ERROR,
        format!("{PREFIX}: the hook key is invalid; expected one line `<key-id> <64 hex>`"),
    )
}

/// Read the hook key from `path`, or from `env`'s `MKIT_HOOK_KEY`. Errors
/// never quote the key.
///
/// # Errors
/// `CONFIG_ERROR` for a missing, unsafe or malformed key.
pub fn read_key(
    path: Option<&Path>,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<(String, Zeroizing<[u8; 32]>), ConfigError> {
    let text = match path {
        Some(path) => read_secret_file(path, "--hook-key-file", HOOK_KEY_ENV)?,
        None => env(HOOK_KEY_ENV).ok_or_else(|| {
            ConfigError::new(
                exit::CONFIG_ERROR,
                format!(
                    "{PREFIX}: hooks need a signing key: pass --hook-key-file or set {HOOK_KEY_ENV}"
                ),
            )
        })?,
    };
    let text = Zeroizing::new(text);
    let (id, seed) = parse_key(&text).ok_or_else(key_error)?;
    // Same grammar the signer enforces; fail here with a config message.
    HookSigner::new(id.clone(), seed.clone()).map_err(|_| key_error())?;
    Ok((id, seed))
}

/// The SPEC-SERVER §7.2 key list for one key, for the hook service's
/// configuration (`mkit-server hook-key-list`).
#[must_use]
pub fn key_list_json(key_id: &str, public_key: &[u8; 32]) -> String {
    // The key id grammar (`[A-Za-z0-9._-]`) needs no escaping.
    format!(
        "{{\n  \"version\": 1,\n  \"keys\": [\n    {{\n      \"keyId\": \"{key_id}\",\n      \
         \"alg\": \"ed25519\",\n      \"publicKey\": \"{}\"\n    }}\n  ]\n}}\n",
        to_hex(public_key)
    )
}

/// `mkit-server hook-key-list`: the public key list of the key `path` holds.
///
/// # Errors
/// As [`read_key`].
pub fn key_list_for(path: &Path) -> Result<String, ConfigError> {
    let (id, seed) = read_key(Some(path), &|_| None)?;
    let signer = HookSigner::new(id.clone(), seed).map_err(|_| key_error())?;
    Ok(key_list_json(&id, &signer.public_key()))
}

/// Refuse a hook key that is another key's (SPEC-SERVER §7.1: distinct roles
/// use distinct keys). `others` are `(what, public key)` pairs of the keys
/// this deployment already holds; seeds compare as their public keys.
///
/// # Errors
/// `CONFIG_ERROR` naming the key it repeats.
pub fn check_key_separation(
    hook_public: &[u8; 32],
    others: &[(&str, &[u8; 32])],
) -> Result<(), ConfigError> {
    for (what, public) in others {
        if hook_public == *public {
            return Err(ConfigError::new(
                exit::CONFIG_ERROR,
                format!(
                    "{PREFIX}: the hook key is also the {what}; SPEC-SERVER §7.1 requires a \
                     dedicated hook key"
                ),
            ));
        }
    }
    Ok(())
}

fn resolve_inspection(args: &HookArgs, pipeline: &mut PipelineConfig) -> Result<(), ConfigError> {
    let usage = |m: &str| ConfigError::new(exit::USAGE, format!("{PREFIX}: {m}"));
    let config = |m: &str| ConfigError::new(exit::CONFIG_ERROR, format!("{PREFIX}: {m}"));
    if args.hook_inspect_url.is_empty()
        && (args.inspect_mode.is_some() || args.inspect_on_unavailable.is_some())
    {
        return Err(usage("inspection options need --hook-inspect-url"));
    }
    if args.hook_inspect_url.len() > 4 {
        return Err(config("inspection supports at most four inspectors"));
    }
    if !args.hook_inspect_url.is_empty() {
        if args.inspect_mode.as_deref().is_some_and(|v| v != "sync")
            || args
                .inspect_on_unavailable
                .as_deref()
                .is_some_and(|v| v != "fail_closed")
        {
            return Err(config("launch inspection requires sync and fail_closed"));
        }
        if args.inspect_batch_max_objects == 0 || args.inspect_batch_max_objects > 10_000 {
            return Err(config("--inspect-batch-max-objects must be 1..=10000"));
        }
        if pipeline.indexed.is_none()
            || pipeline.write_policy == mkit_server::policy::WritePolicy::Open
            || pipeline.ticket_keys.is_none()
        {
            return Err(config(
                "inspection requires indexed mode, restricted writes and upload ticket keys",
            ));
        }
        pipeline.begin_upload_threshold_bytes = 0;
        let mut bases = Vec::new();
        for url in &args.hook_inspect_url {
            let base = super::http::canonical_base(url)
                .map_err(|e| config(&format!("--hook-inspect-url: {e}")))?;
            if bases.contains(&base) {
                return Err(config("--hook-inspect-url repeats an inspector endpoint"));
            }
            bases.push(base);
        }
    }
    Ok(())
}

fn check_role_material(
    key_id: &str,
    seed: &Zeroizing<[u8; 32]>,
    pipeline: &PipelineConfig,
) -> Result<(), ConfigError> {
    let config =
        |message: &str| ConfigError::new(exit::CONFIG_ERROR, format!("{PREFIX}: {message}"));
    if pipeline
        .ticket_keys
        .as_ref()
        .is_some_and(|keys| keys.contains_secret(seed))
    {
        return Err(config(
            "the hook key is also an upload ticket key; SPEC-SERVER §7.1 requires a dedicated \
             hook key",
        ));
    }
    let public = HookSigner::new(key_id, seed.clone())
        .map_err(|_| key_error())?
        .public_key();
    if pipeline
        .ticket_keys
        .as_ref()
        .is_some_and(|tickets| tickets.contains_ed25519_public(&public))
    {
        return Err(config(
            "hook public key must differ from ticket secret material",
        ));
    }
    #[cfg(feature = "http-objects")]
    {
        let material = Zeroizing::new([public, **seed]);
        crate::http_mount::check_other_keys(pipeline.url_tokens.as_ref(), &*material)?;
    }
    Ok(())
}

/// Resolve the hook flags. Sets `pipeline.authorizer_role` from
/// `--authorizer-role`.
///
/// # Errors
/// `USAGE` for flags that need an authorize URL or a URL; `CONFIG_ERROR` for
/// hooks without auth v2 (or an outcome URL without `SQLite` metadata), a
/// missing or unsafe key, a key that repeats a ticket key, and timeouts the
/// spec or the unary deadline refuses.
pub fn resolve(
    args: &HookArgs,
    pipeline: &mut PipelineConfig,
    meta: &MetaChoice,
    unary_timeout: Duration,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<Option<HookSettings>, ConfigError> {
    let usage = |m: &str| ConfigError::new(exit::USAGE, format!("{PREFIX}: {m}"));
    let config = |m: &str| ConfigError::new(exit::CONFIG_ERROR, format!("{PREFIX}: {m}"));
    let urls = [
        ("--hook-authorize-url", &args.hook_authorize_url),
        ("--hook-admit-url", &args.hook_admit_url),
        ("--hook-outcome-url", &args.hook_outcome_url),
        ("--hook-cache-purge-url", &args.hook_cache_purge_url),
    ];
    resolve_inspection(args, pipeline)?;
    if urls.iter().all(|(_, url)| url.is_none()) && args.hook_inspect_url.is_empty() {
        if args.authorizer_role.is_some() {
            return Err(usage("--authorizer-role needs --hook-authorize-url"));
        }
        if args.hook_key_file.is_some() {
            return Err(usage(
                "--hook-key-file needs a hook URL (--hook-authorize-url, --hook-admit-url or \
                 --hook-outcome-url)",
            ));
        }
        return Ok(None);
    }
    if args.authorizer_role.is_some() && args.hook_authorize_url.is_none() {
        return Err(usage("--authorizer-role needs --hook-authorize-url"));
    }
    for (flag, url) in urls {
        if let Some(url) = url {
            super::http::validate_base_url(url).map_err(|e| config(&format!("{flag}: {e}")))?;
        }
    }
    if !matches!(pipeline.auth, AuthMode::AuthV2(_)) {
        return Err(config(
            "remote hooks need --auth auth-v2: hook requests name the server's audience and \
             admission credentials travel only on signed writes",
        ));
    }
    if args.hook_admit_url.is_some() && pipeline.ticket_keys.is_none() {
        // A remote admission grants reservations that upload tickets consume
        // (`Pipeline::new` refuses it without ticket keys).
        return Err(config(
            "--hook-admit-url needs upload ticket keys (--ticket-key-file or MKIT_TICKET_KEYS)",
        ));
    }
    if (args.hook_outcome_url.is_some() || args.hook_cache_purge_url.is_some())
        && !matches!(meta, MetaChoice::Sqlite { .. })
    {
        return Err(config(
            "--hook-outcome-url needs --meta sqlite:<PATH>: outcome delivery runs from the \
             timer driver",
        ));
    }
    if args.hook_timeout_secs == 0 {
        return Err(usage("--hook-timeout-secs must be at least 1"));
    }
    let timeout = Duration::from_secs(args.hook_timeout_secs);
    if timeout >= unary_timeout {
        return Err(config(
            "--hook-timeout-secs must be below --unary-timeout-secs: Authorize and Admit run \
             one after the other inside one request",
        ));
    }
    let validity = Duration::from_secs(args.hook_signature_validity_secs);
    if validity.is_zero() || validity > MAX_VALIDITY {
        return Err(usage("--hook-signature-validity-secs must be 1 to 300"));
    }
    let (key_id, seed) = read_key(args.hook_key_file.as_deref(), env)?;
    check_role_material(&key_id, &seed, pipeline)?;
    if let Some(role) = args.authorizer_role {
        pipeline.authorizer_role = match role {
            AuthorizerRoleArg::Check => AuthorizerRole::Check,
            AuthorizerRoleArg::Authority => AuthorizerRole::Authority,
        };
    }
    Ok(Some(HookSettings {
        authorize: args.hook_authorize_url.clone(),
        admit: args.hook_admit_url.clone(),
        outcome: args.hook_outcome_url.clone(),
        purge: args.hook_cache_purge_url.clone(),
        inspect: args.hook_inspect_url.clone(),
        inspect_batch_max_objects: args.inspect_batch_max_objects,
        key_id,
        seed,
        validity,
        timeout,
    }))
}
