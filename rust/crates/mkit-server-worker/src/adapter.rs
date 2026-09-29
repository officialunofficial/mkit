//! The Workers fetch adapter (WP-M0-17): a `worker::Request` in, the
//! pipeline's Connect binding ([`mkit_server::connect::service`]) over
//! [`R2BlobStore`](crate::r2::R2BlobStore) and
//! [`DoNamespaceStore`](crate::ns_client::DoNamespaceStore), a
//! `worker::Response` out. A deployment's `#[event(fetch)]` calls `fetch`
//! (wasm32), and its `#[durable_object]` holds the `ns_object` (wasm32) of
//! its state.
//!
//! **Streaming.** Neither body is ever held whole (reconciliation R-25):
//!
//! - The request body is the Worker's `ReadableStream`, wrapped in
//!   [`LimitedBody`]: it counts bytes and fails the stream past
//!   `max_body_bytes`, and gives connectrpc the `Send + Sync` error type it
//!   needs. connectrpc collects unary bodies itself (at most 4 MiB) and
//!   reads client-streaming bodies message by message on a spawned reader
//!   (`spawn_local` on wasm32) through a depth-1 channel, so an upload
//!   holds about one `UploadPack` chunk. A body over the cap gets
//!   vcs-worker's 400 JSON `resource_exhausted`: before dispatch when its
//!   `Content-Length` says so, and in place of connectrpc's answer when a
//!   chunked body trips [`LimitedBody`] ([`over_cap_response`]).
//! - The response body streams frame by frame
//!   (`mkit_worker_common::adapter::respond_streamed`): a `DownloadPack`
//!   chunk is at most 800 KiB. A unary response is one frame, so a large
//!   `ListRefs` reply is held whole (about 45 bytes per ref: 1.2 MB for
//!   30,000 refs) until WP-1.27 pages it. A unary response connectrpc compressed
//!   itself (`Content-Encoding: gzip`, for a client that accepts it) is
//!   passed through with `encodeBody: "manual"`, so the runtime does not
//!   compress it a second time.
//!
//! **Deadline headers.** `connect-timeout-ms` and `grpc-timeout` are
//! dropped before dispatch (`is_deadline_header`): connectrpc turns them
//! into a deadline with `Instant::now()`, which panics on wasm32. A client's
//! deadline is therefore not enforced.
//!
//! **Pipeline.** Auth v2 with the default write quota, one repository
//! (`AUTH_REPOSITORY`) in the deployment-default namespace, a 64 MiB pack
//! cap (the M1 stopgap; resumable parts replace it) and the Worker clock.
//! It is built per request from the request's `Env`: building it costs no
//! I/O.
//!
//! **Test faults** (`test-faults` only): the pipeline gets
//! `WorkerFaults`, `GET /__mkit_test/stats` answers the default
//! partition's size, `TEST_QUOTA_*` vars replace the write quota, and each
//! request logs the most body bytes the adapter held at once, with its
//! path (`mkit-adapter peak-buffered-bytes <n> … path <path>`).
//! Under D34, `POST /__mkit_test/relay/<pack>` plants a membership relay;
//! `GET` on that path checks target membership and source queue drainage.

use core::pin::Pin;
use core::task::{Context, Poll};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
#[cfg(feature = "test-faults")]
use mkit_server::quota::QuotaLimits;
use mkit_server::sql::Capacity;

use crate::naming::Placement;
use mkit_server::pipeline::Sharding;
use mkit_server::upload::token::TicketKeys;

use crate::do_sql::{DO_CAPACITY, DO_FREE_MAX_BYTES};

/// The Worker var holding the canonical origin writes are signed for.
pub const AUDIENCE_VAR: &str = "AUTH_AUDIENCE";
/// The Worker var holding the repository identity writes are signed for.
pub const REPOSITORY_VAR: &str = "AUTH_REPOSITORY";
/// The Worker var naming the Cloudflare plan: `paid` or `free`.
pub const PLAN_VAR: &str = "WORKERS_PLAN";
/// The deployment secret containing upload MAC keys.
pub const TICKET_KEYS_VAR: &str = "TICKET_KEYS";
/// The Worker var selecting `single` (default) or `multi` addressing.
pub const ADDRESSING_VAR: &str = "ADDRESSING";
/// The Worker var for a multi deployment's namespace policy: `allowlist`
/// (default) or `any`.
pub const NAMESPACE_POLICY_VAR: &str = "NAMESPACE_POLICY";
/// The Worker var holding a multi deployment's namespace allowlist:
/// namespaces separated by newlines or commas, `#` comments allowed.
pub const NAMESPACE_ALLOWLIST_VAR: &str = "NAMESPACE_ALLOWLIST";
/// The Worker var opting `NAMESPACE_POLICY=any` in; must be exactly
/// `true` when set.
pub const UNSAFE_OPEN_NAMESPACES_VAR: &str = "UNSAFE_OPEN_NAMESPACES";
/// The Worker var listing the owner schemes write grants accept
/// (comma-separated tokens). Unset: write grants are off. Present but blank
/// is an error, never "off".
pub const GRANT_SCHEMES_VAR: &str = "GRANT_SCHEMES";
/// The Worker var listing `WebAuthn` relying parties for write grants:
/// `id=origin[,origin...]` entries separated by `;` or newlines.
pub const WEBAUTHN_RPS_VAR: &str = "WEBAUTHN_RPS";
/// Development only: accept a loopback `AUTH_AUDIENCE` or relying party for
/// write grants. Honoured only in `test-faults` builds; a release build that
/// sees it set refuses to start.
pub const UNSAFE_LOOPBACK_GRANTS_VAR: &str = "UNSAFE_LOOPBACK_GRANTS";
/// Maximum ticketed pack size (bytes), bounded by R2's single-object limit.
pub const MAX_PACK_BYTES_VAR: &str = "MAX_PACK_BYTES";

/// Default ticketed pack cap, one GiB until staging CPU measurements.
pub const MAX_PACK_BYTES: u64 = 1024 * 1024 * 1024;
/// R2's 4.995 GiB single-object ceiling, rounded down to whole bytes.
pub const MAX_PACK_BYTES_CEILING: u64 = 4_995 * 1024 * 1024 * 1024 / 1000;
/// Legacy single-part `UploadPack` cap.
pub const SINGLE_PUT_MAX_BYTES: u64 = 64 * 1024 * 1024;

/// Room for Connect framing on top of [`SINGLE_PUT_MAX_BYTES`]: a 5-byte
/// envelope and about 45 bytes of message fields around each chunk's data,
/// so any client whose chunks average 4 KiB or more fits (mkit sends
/// 800 KiB chunks).
const FRAMING_ALLOWANCE: usize = 1024 * 1024;

/// The default request body cap: a 64 MiB pack and its framing.
#[allow(clippy::cast_possible_truncation)] // 65 MiB fits every usize we build for
pub const DEFAULT_MAX_BODY_BYTES: usize = SINGLE_PUT_MAX_BYTES as usize + FRAMING_ALLOWANCE;

/// `Access-Control-Allow-Methods`.
pub const CORS_ALLOW_METHODS: &str = "POST, GET, OPTIONS";

/// Deployment settings read from the Worker's vars.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct WorkerConfig {
    /// `AUTH_AUDIENCE`: the canonical origin writes are signed for.
    pub audience: String,
    /// `AUTH_REPOSITORY`: the repository identity writes are signed for.
    /// `None` under `ADDRESSING=multi`, where it is neither required nor
    /// read: each request's `X-Repository` selects its repository.
    pub repository: Option<String>,
    /// `ADDRESSING` and the namespace-policy vars: one configured
    /// repository (default) or `X-Repository` routing across the
    /// policy's namespaces.
    pub addressing: mkit_server::Addressing,
    /// Upload MAC keys; missing keys disable `BeginUpload` (and refuse a
    /// multi deployment outright).
    pub ticket_keys: Option<TicketKeys>,
    /// Maximum ticketed pack size from `MAX_PACK_BYTES`.
    pub max_pack_bytes: u64,
    /// `GRANT_SCHEMES`, `WEBAUTHN_RPS` and `UNSAFE_LOOPBACK_GRANTS`: the
    /// validated write-grant inputs (`None`: grants off). The verifier is
    /// built from them, with `AUTH_AUDIENCE`, when the pipeline is.
    pub grants: Option<mkit_server::policy::GrantSettings>,
    /// `SHARDING`: d34 (default) or single; guarded against changing existing data.
    /// A deployment holding single-sharded data must pin `SHARDING=single`:
    /// the guard answers 503 until then (there is no migration, R-123).
    pub sharding: Sharding,
    /// Deployment-wide placement. Jurisdiction must remain fixed for its lifetime:
    /// changing it maps every name to new, empty objects.
    pub placement: Placement,
    /// The request body cap, [`DEFAULT_MAX_BODY_BYTES`].
    pub max_body_bytes: usize,
    /// The R2 bucket binding ([`crate::r2::STORAGE_BINDING`]). Durable
    /// Object bindings come from [`crate::naming`].
    pub blob_binding: &'static str,
    /// `TEST_QUOTA_OPS`, `TEST_QUOTA_BYTES` and `TEST_QUOTA_WINDOW_MS`,
    /// when all three are set: the write quota instead of the default
    /// (`test-faults` builds only, for the wire suite's quota and growth
    /// cases).
    #[cfg(feature = "test-faults")]
    pub test_quota: Option<QuotaLimits>,
}

/// A missing or malformed var. The adapter answers every RPC
/// `unavailable` with this message, as vcs-worker answered writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError(pub String);

impl core::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

impl WorkerConfig {
    /// The store Health probes for this deployment mode.
    #[must_use]
    pub fn probe_partition(&self) -> mkit_server::Partition {
        let root = mkit_server::NamespaceKey::deployment_default();
        if self.sharding == Sharding::D34 {
            mkit_server::Partition::Coordinator(root)
        } else {
            mkit_server::Partition::Namespace(root)
        }
    }

    /// Build the deployment pipeline configuration without store access.
    #[cfg(any(target_arch = "wasm32", test))]
    fn pipeline_config(&self) -> Result<mkit_server::pipeline::PipelineConfig, ConfigError> {
        use mkit_server::auth_v2::AuthV2Config;
        use mkit_server::pipeline::{AuthMode, PipelineConfig};
        use mkit_server::upload::UploadLimits;

        let bad = |e: &dyn core::fmt::Display| ConfigError(e.to_string());
        // Under multi addressing the signed repository is the request's,
        // not a configured one: the empty bound the conformance baseline
        // signs.
        let auth = AuthV2Config::new(&self.audience, self.repository.as_deref().unwrap_or(""))
            .map_err(|e| bad(&e))?;
        let limits = UploadLimits {
            max_total_bytes: self.max_pack_bytes,
            // vcs-worker had no chunk cap; the body cap bounds the count.
            max_chunks: u32::MAX,
        };
        let mut config =
            PipelineConfig::new(self.addressing.clone(), AuthMode::AuthV2(auth), limits);
        config.single_upload_max_bytes = Some(SINGLE_PUT_MAX_BYTES);
        config.sharding = self.sharding;
        config.ticket_keys.clone_from(&self.ticket_keys);
        config.grants = self
            .grants
            .as_ref()
            .map(|settings| settings.build(&self.audience))
            .transpose()
            .map_err(|e| ConfigError(e.public_message().to_owned()))?;
        #[cfg(feature = "test-faults")]
        if let Some(quota) = self.test_quota {
            config.write_quota = Some(quota);
        }
        Ok(config)
    }

    /// The settings from `var`, which looks a Worker var up by name.
    ///
    /// # Errors
    /// A missing `AUTH_AUDIENCE` or `AUTH_REPOSITORY` (vcs-worker parity:
    /// "`<VAR>` is not configured"; the latter is neither required nor
    /// read under `ADDRESSING=multi`), an invalid repository identity, a
    /// malformed `TEST_QUOTA_*` var, or an invalid multi-addressing
    /// combination: `NAMESPACE_POLICY`/`NAMESPACE_ALLOWLIST`/
    /// `UNSAFE_OPEN_NAMESPACES` and `TICKET_KEYS` rules.
    pub fn from_vars(var: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        if var("INDEXED_MODE").is_some_and(|value| {
            !value.is_empty() && value != "0" && !value.eq_ignore_ascii_case("false")
        }) {
            return Err(ConfigError(
                "indexed mode on Workers requires WP-4.8".into(),
            ));
        }
        let required =
            |name: &str| var(name).ok_or_else(|| ConfigError(format!("{name} is not configured")));
        let audience = required(AUDIENCE_VAR)?;
        let multi = match var(ADDRESSING_VAR).as_deref() {
            None | Some("single") => false,
            Some("multi") => true,
            Some(_) => return Err(ConfigError("ADDRESSING must be single or multi".into())),
        };
        let repository = if multi {
            // `wrangler.jsonc` ships a default; under multi it is ignored.
            None
        } else {
            let repository = required(REPOSITORY_VAR)?;
            mkit_core::repo_identity::RepositoryIdentity::parse_bare_allowed(&repository).map_err(
                |_| ConfigError("AUTH_REPOSITORY is invalid (SPEC-TRANSPORT-CONNECT §7.4)".into()),
            )?;
            Some(repository)
        };
        let ticket_keys = var(TICKET_KEYS_VAR)
            .map(|text| {
                TicketKeys::parse_secret(text)
                    .map_err(|_| ConfigError("TICKET_KEYS is invalid".into()))
            })
            .transpose()?;
        let max_pack_bytes = var(MAX_PACK_BYTES_VAR).map_or(Ok(MAX_PACK_BYTES), |value| {
            value
                .parse::<u64>()
                .ok()
                .filter(|n| *n > 0 && *n <= MAX_PACK_BYTES_CEILING)
                .ok_or_else(|| ConfigError("MAX_PACK_BYTES must be 1..=4.995 GiB".into()))
        })?;
        let sharding = match var("SHARDING").as_deref() {
            Some("single") => Sharding::Single,
            None | Some("d34") => Sharding::D34,
            Some(_) => return Err(ConfigError("SHARDING must be single or d34".into())),
        };
        let jurisdiction = var("NAMESPACE_JURISDICTION");
        if jurisdiction
            .as_deref()
            .is_some_and(|value| !matches!(value, "eu" | "us" | "fedramp"))
        {
            return Err(ConfigError(
                "NAMESPACE_JURISDICTION must be eu, us or fedramp".into(),
            ));
        }
        let placement = Placement {
            location_hint: var("NAMESPACE_LOCATION_HINT"),
            jurisdiction,
        };
        let addressing =
            resolve_addressing(&var, multi, repository.as_deref(), ticket_keys.is_some())?;
        let grants = resolve_grants(&var, multi, &audience)?;
        Ok(Self {
            sharding,
            placement,
            audience,
            repository,
            addressing,
            ticket_keys,
            max_pack_bytes,
            grants,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            blob_binding: crate::r2::STORAGE_BINDING,
            #[cfg(feature = "test-faults")]
            test_quota: test_quota(&var)?,
        })
    }

    /// The settings from `env`'s vars.
    ///
    /// # Errors
    /// As [`Self::from_vars`].
    #[cfg(target_arch = "wasm32")]
    pub fn from_env(env: &worker::Env) -> Result<Self, ConfigError> {
        Self::from_vars(|name| {
            if name == TICKET_KEYS_VAR {
                env.secret(name)
                    .ok()
                    .map(|secret| secret.to_string())
                    .or_else(|| env.var(name).ok().map(|value| value.to_string()))
            } else {
                env.var(name).ok().map(|value| value.to_string())
            }
        })
    }
}

/// The `Addressing` from the `ADDRESSING`/`NAMESPACE_*` vars: multi reads
/// its namespace policy and requires `TICKET_KEYS`; single parses the
/// repository name the caller already validated.
fn resolve_addressing(
    var: &impl Fn(&str) -> Option<String>,
    multi: bool,
    repository: Option<&str>,
    has_ticket_keys: bool,
) -> Result<mkit_server::Addressing, ConfigError> {
    use mkit_server::policy::{NamespacePolicy, parse_namespace_allowlist};
    use mkit_server::{MultiAddressing, NamespaceKey, RepoId, RepoName};

    let namespace_policy = var(NAMESPACE_POLICY_VAR);
    let allowlist = var(NAMESPACE_ALLOWLIST_VAR);
    let unsafe_open = match var(UNSAFE_OPEN_NAMESPACES_VAR).as_deref() {
        None => false,
        Some("true") => true,
        Some(_) => {
            return Err(ConfigError(
                "UNSAFE_OPEN_NAMESPACES must be `true` when set".into(),
            ));
        }
    };
    if !multi && (namespace_policy.is_some() || allowlist.is_some() || unsafe_open) {
        return Err(ConfigError(
            "NAMESPACE_POLICY, NAMESPACE_ALLOWLIST and UNSAFE_OPEN_NAMESPACES require \
             ADDRESSING=multi"
                .into(),
        ));
    }
    if unsafe_open && namespace_policy.as_deref() != Some("any") {
        return Err(ConfigError(
            "UNSAFE_OPEN_NAMESPACES requires NAMESPACE_POLICY=any".into(),
        ));
    }
    if !multi {
        let repository = repository.unwrap_or_default();
        return Ok(mkit_server::Addressing::Single {
            repo: RepoId {
                namespace: NamespaceKey::deployment_default(),
                name: RepoName::new(repository).map_err(|e| ConfigError(e.to_string()))?,
            },
        });
    }
    let policy = match namespace_policy.as_deref().unwrap_or("allowlist") {
        "allowlist" => {
            let Some(text) = allowlist else {
                return Err(ConfigError(
                    "ADDRESSING=multi requires NAMESPACE_ALLOWLIST (or NAMESPACE_POLICY=any \
                     with UNSAFE_OPEN_NAMESPACES=true)"
                        .into(),
                ));
            };
            NamespacePolicy::Allowlist(
                parse_namespace_allowlist(&text)
                    .map_err(|e| ConfigError(format!("NAMESPACE_ALLOWLIST is invalid: {e}")))?,
            )
        }
        "any" => {
            if allowlist.is_some() {
                return Err(ConfigError(
                    "NAMESPACE_ALLOWLIST and NAMESPACE_POLICY=any are mutually exclusive".into(),
                ));
            }
            if !unsafe_open {
                return Err(ConfigError(
                    "NAMESPACE_POLICY=any requires UNSAFE_OPEN_NAMESPACES=true: the default \
                     admission step cannot vet an open namespace set"
                        .into(),
                ));
            }
            NamespacePolicy::Any {
                unsafe_without_admission: true,
            }
        }
        _ => {
            return Err(ConfigError(
                "NAMESPACE_POLICY must be allowlist or any".into(),
            ));
        }
    };
    if !has_ticket_keys {
        return Err(ConfigError(
            "ADDRESSING=multi requires TICKET_KEYS: signed writes must mint upload tickets".into(),
        ));
    }
    Ok(mkit_server::Addressing::Multi(
        MultiAddressing::new().with_namespace_policy(policy),
    ))
}

/// The write-grant settings from `GRANT_SCHEMES`, `WEBAUTHN_RPS` and
/// `UNSAFE_LOOPBACK_GRANTS`. Any bad, partial or unsupported value is a
/// `ConfigError` (so every RPC answers `unavailable`), never "grants off";
/// the verifier rules are `mkit-attest`'s and are checked here by building
/// the verifier once for `audience`.
fn resolve_grants(
    var: &impl Fn(&str) -> Option<String>,
    multi: bool,
    audience: &str,
) -> Result<Option<mkit_server::policy::GrantSettings>, ConfigError> {
    use mkit_server::policy::{GrantSettings, parse_grant_schemes, parse_relying_parties};

    let schemes = var(GRANT_SCHEMES_VAR)
        .map(|text| parse_grant_schemes(&text))
        .transpose()
        .map_err(|e| ConfigError(format!("{GRANT_SCHEMES_VAR}: {e}")))?;
    let parties = var(WEBAUTHN_RPS_VAR)
        .map(|text| parse_relying_parties(&text))
        .transpose()
        .map_err(|e| ConfigError(format!("{WEBAUTHN_RPS_VAR}: {e}")))?
        .unwrap_or_default();
    let loopback = match var(UNSAFE_LOOPBACK_GRANTS_VAR).as_deref() {
        None => false,
        #[cfg(feature = "test-faults")]
        Some("true") => true,
        #[cfg(feature = "test-faults")]
        Some(_) => {
            return Err(ConfigError(format!(
                "{UNSAFE_LOOPBACK_GRANTS_VAR} must be `true` when set"
            )));
        }
        #[cfg(not(feature = "test-faults"))]
        Some(_) => {
            return Err(ConfigError(format!(
                "{UNSAFE_LOOPBACK_GRANTS_VAR} is honoured only in test-faults builds; a \
                 production deployment never accepts a loopback grant audience"
            )));
        }
    };
    let Some(settings) = GrantSettings::from_parts(schemes, parties, loopback)
        .map_err(|e| ConfigError(format!("{GRANT_SCHEMES_VAR}: {e}")))?
    else {
        return Ok(None);
    };
    if !multi {
        return Err(ConfigError(format!(
            "{GRANT_SCHEMES_VAR} requires ADDRESSING=multi"
        )));
    }
    settings
        .build(audience)
        .map_err(|e| ConfigError(e.public_message().to_owned()))?;
    Ok(Some(settings))
}

/// `TEST_QUOTA_*`: all three or none.
#[cfg(feature = "test-faults")]
fn test_quota(var: &impl Fn(&str) -> Option<String>) -> Result<Option<QuotaLimits>, ConfigError> {
    fn parse<T: core::str::FromStr>(name: &str, v: Option<&str>) -> Result<T, ConfigError> {
        v.and_then(|v| v.trim().parse().ok())
            .ok_or_else(|| ConfigError(format!("{name} is not a number")))
    }
    let names = ["TEST_QUOTA_OPS", "TEST_QUOTA_BYTES", "TEST_QUOTA_WINDOW_MS"];
    let [ops, bytes, window] = names.map(var);
    if ops.is_none() && bytes.is_none() && window.is_none() {
        return Ok(None);
    }
    Ok(Some(QuotaLimits {
        max_ops: parse(names[0], ops.as_deref())?,
        max_bytes: parse(names[1], bytes.as_deref())?,
        window_ms: parse(names[2], window.as_deref())?,
    }))
}

/// The Durable Object storage cap for the `WORKERS_PLAN` var: `paid` is
/// [`DO_CAPACITY`] (10 GB), `free` or unset is `Capacity::new(`
/// [`DO_FREE_MAX_BYTES`]`)` (1 GB). Free is the default because it is safe
/// on either plan: a Free cap on a Paid account only stops writes early,
/// while a Paid cap on a Free account runs into the 1 GB hard limit, where
/// `SQLITE_FULL` inside a transaction resets the object.
///
/// # Errors
/// Any other value, with the Free cap to fall back to.
pub fn plan_capacity(plan: Option<&str>) -> Result<Capacity, (ConfigError, Capacity)> {
    let free = Capacity::new(DO_FREE_MAX_BYTES);
    match plan.map(str::trim) {
        Some(p) if p.eq_ignore_ascii_case("paid") => Ok(DO_CAPACITY),
        None => Ok(free),
        Some(p) if p.eq_ignore_ascii_case("free") => Ok(free),
        Some(p) => Err((
            ConfigError(format!("{PLAN_VAR} `{p}` is neither `paid` nor `free`")),
            free,
        )),
    }
}

/// The handlers installed by a Durable Object's deployment adapter.
///
/// Relay delivery belongs only to [`crate::classes::ShardClass::RefShard`].
/// The kind-5 quota rollup is registered on the `RefShard`, `NsCoordinator`
/// and `RefStore` classes (the ones that hold `qs`/`qc` rows) and on no other.
/// A configuration failure retains its relay timers for retry, rather than
/// leaving them without a registered handler. `target` uses the deployment's
/// placement and `plan` is its `WORKERS_PLAN` value.
#[must_use]
pub fn timer_registry<S, T>(
    class: crate::classes::ShardClass,
    target: Result<T, ConfigError>,
    plan: Option<&str>,
) -> mkit_server::timers::TimerRegistry<'static, S>
where
    S: mkit_server::NamespaceStore,
    T: mkit_server::NamespaceStore + 'static,
{
    use crate::classes::ShardClass;
    use mkit_server::relay::{NoHook, RelayBudget, RelayHandler};
    use mkit_server::timers::{TimerRegistry, lease_sweep::LeaseSweep};

    // One target client serves the class's relay or lease sweep and its rollup.
    let target = target.map(|store| Arc::new(store));
    let registry = TimerRegistry::new();
    let registry = match class {
        ShardClass::NsCoordinator => {
            let source = match target.clone().map(SharedStore) {
                Ok(source) => Some(source),
                Err(error) => {
                    crate::log_failure(&format!(
                        "Worker lease sweep configuration unavailable: {error}"
                    ));
                    None
                }
            };
            let max_per_tick = if plan.is_some_and(|p| p.trim().eq_ignore_ascii_case("paid")) {
                32
            } else {
                16
            };
            registry.register(WorkerLeaseSweep {
                sweep: LeaseSweep::optional(source)
                    .with_metrics(Arc::new(crate::telemetry::ConsoleMetrics::default())),
                max_per_tick,
            })
        }
        ShardClass::RefShard => {
            let paid = plan.is_some_and(|p| p.trim().eq_ignore_ascii_case("paid"));
            let max_per_tick = if paid {
                mkit_server::relay::WORKER_PAID_RELAY_FIRES
            } else {
                mkit_server::relay::WORKER_FREE_RELAY_FIRES
            };
            // Paid: <= 8 fires x 32 targets x 2 calls = 512 per alarm.
            // Free:
            // <= 2 fires x 8 targets x 2 calls = 32, below its limit of 50.
            // The target-call cap also bounds chunking and contention retries.
            let mut budget = RelayBudget::default();
            budget.max_rows = 128;
            budget.max_targets = if paid {
                mkit_server::relay::WORKER_PAID_RELAY_TARGETS
            } else {
                mkit_server::relay::WORKER_FREE_RELAY_TARGETS
            };
            budget.max_target_calls = Some(mkit_server::relay::WORKER_RELAY_CALLS_PER_TARGET);
            let relay = match target.clone().map(SharedStore) {
                Ok(target) => Some(RelayHandler {
                    target,
                    hook: NoHook,
                    budget,
                }),
                Err(error) => {
                    crate::log_failure(&format!("Worker relay configuration unavailable: {error}"));
                    None
                }
            };
            registry.register(WorkerRelay {
                relay,
                max_per_tick,
                metrics: Arc::new(crate::telemetry::ConsoleMetrics::default()),
            })
        }
        _ => registry,
    };
    let registry = match class {
        ShardClass::NsCoordinator | ShardClass::RefShard | ShardClass::RefStore => {
            registry.register(WorkerQuotaRollup::new(target.map(SharedStore)))
        }
        _ => registry,
    };
    #[cfg(feature = "test-faults")]
    let registry = registry.register(mkit_server::timers::test_kind::TestTimer);
    registry
}

/// Register kind-2 expiry on the classes that own ticket rows.
#[must_use]
pub fn timer_registry_with_blobs<S, T, B>(
    class: crate::classes::ShardClass,
    target: Result<T, ConfigError>,
    plan: Option<&str>,
    blobs: B,
) -> mkit_server::timers::TimerRegistry<'static, S>
where
    S: mkit_server::NamespaceStore,
    T: mkit_server::NamespaceStore + 'static,
    B: mkit_server::MultipartBlobStore + 'static,
{
    let registry = timer_registry(class, target, plan);
    match class {
        crate::classes::ShardClass::RefStore | crate::classes::ShardClass::RefShard => {
            registry.register(mkit_server::timers::ticket_expiry::TicketExpiry { blobs })
        }
        _ => registry,
    }
}

/// Register the outcome kinds on every class that holds `o`/`oq` rows:
/// kind 8 (delivery, in-tree `NoOutcomes` sink that acknowledges locally)
/// and kind 9 (reconcile). Both make no subrequests, so the Free-plan alarm
/// budget below is unchanged. A missing audience retains kind-8 rows.
#[must_use]
pub fn with_outcome_timers<S>(
    registry: mkit_server::timers::TimerRegistry<'static, S>,
    class: crate::classes::ShardClass,
    audience: Result<String, ConfigError>,
) -> mkit_server::timers::TimerRegistry<'static, S>
where
    S: mkit_server::NamespaceStore,
{
    use crate::classes::ShardClass;
    if !matches!(
        class,
        ShardClass::RefStore | ShardClass::NsCoordinator | ShardClass::RefShard
    ) {
        return registry;
    }
    let delivery = match audience {
        Ok(audience) => Some(mkit_server::timers::outcome_delivery::OutcomeDelivery {
            sink: mkit_server::pipeline::NoOutcomes,
            audience,
            metrics: Arc::new(crate::telemetry::ConsoleMetrics::default()),
        }),
        Err(error) => {
            crate::log_failure(&format!(
                "Worker outcome delivery configuration unavailable: {error}"
            ));
            None
        }
    };
    registry
        .register(WorkerOutcomeDelivery { delivery })
        .register(mkit_server::timers::reservation_reconcile::ReservationReconcile)
}

struct WorkerOutcomeDelivery {
    delivery: Option<
        mkit_server::timers::outcome_delivery::OutcomeDelivery<mkit_server::pipeline::NoOutcomes>,
    >,
}

impl<S: mkit_server::NamespaceStore> mkit_server::timers::TimerHandler<S>
    for WorkerOutcomeDelivery
{
    fn kind(&self) -> mkit_server::timers::TimerKind {
        mkit_server::timers::registry::kinds::OUTCOME_DELIVERY
    }

    // Each fire delivers at most 16 rows locally; no subrequests.
    fn max_per_tick(&self) -> Option<u32> {
        Some(4)
    }

    fn fire<'a>(
        &'a self,
        ctx: &'a mkit_server::timers::TimerCtx<'a, S>,
        timer: &'a mkit_server::timers::DueTimer,
    ) -> mkit_server::BoxFuture<'a, Result<mkit_server::timers::Fired, mkit_server::StoreError>>
    {
        match &self.delivery {
            Some(delivery) => delivery.fire(ctx, timer),
            None => Box::pin(async { Ok(mkit_server::timers::Fired::Retry) }),
        }
    }
}

/// A shared handle on the deployment's target client, so one client serves
/// two handlers of a class without requiring `T: Clone`.
struct SharedStore<T>(Arc<T>);

impl<T> Clone for SharedStore<T> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<T: mkit_server::NamespaceStore> mkit_server::NamespaceStore for SharedStore<T> {
    fn capabilities(&self) -> mkit_server::StoreCapabilities {
        self.0.capabilities()
    }
    async fn get(
        &self,
        p: &mkit_server::Partition,
        k: &mkit_server::Key,
    ) -> Result<Option<mkit_server::Value>, mkit_server::StoreError> {
        self.0.get(p, k).await
    }
    async fn scan(
        &self,
        p: &mkit_server::Partition,
        start: &mkit_server::Key,
        end: &mkit_server::Key,
        after: Option<&mkit_server::Cursor>,
        limit: u32,
    ) -> Result<mkit_server::ScanPage, mkit_server::StoreError> {
        self.0.scan(p, start, end, after, limit).await
    }
    async fn apply(
        &self,
        p: &mkit_server::Partition,
        batch: mkit_server::Batch,
    ) -> Result<mkit_server::BatchOutcome, mkit_server::StoreError> {
        self.0.apply(p, batch).await
    }
    async fn stats(
        &self,
        p: &mkit_server::Partition,
    ) -> Result<mkit_server::PartitionStats, mkit_server::StoreError> {
        self.0.stats(p).await
    }
    async fn probe(&self) -> Result<(), mkit_server::StoreError> {
        self.0.probe().await
    }
}

/// Fires kind-5 rollups per alarm tick on a Durable Object.
///
/// Subrequests of one fire, from `quota_rollup.rs` (each store call on the
/// coordinator stub counts): a live-window fire is the aggregate read plus its
/// guarded write, 2; an expired-window fire adds the contribution prune (a
/// read, a scan, the last-source read, two older-window scans and the
/// guarded delete), 8 in all. Contention replans the aggregate at most
/// `MAX_AGGREGATE_REPLANS` (8) times, 2 calls each. Four fires are thus 8
/// calls typically and 32 when every fire is an expired window without
/// contention, which alone fits Free's 50; beside a saturated relay tick
/// (32) a Free alarm can meet the limit, and the failed call surfaces as a
/// retryable `StoreError` (`Fired` failure with backoff), never a lost timer.
const ROLLUP_FIRES_PER_TICK: u32 = 4;

/// A rollup handler whose coordinator client may be unavailable: a
/// configuration error retains the timers, as [`WorkerRelay`] does.
struct WorkerQuotaRollup<T> {
    rollup:
        Option<mkit_server::timers::quota_rollup::QuotaRollup<T, crate::telemetry::ConsoleMetrics>>,
    max_per_tick: u32,
}

impl<T> WorkerQuotaRollup<T> {
    fn new(target: Result<T, ConfigError>) -> Self {
        let rollup = match target {
            Ok(coordinator) => Some(mkit_server::timers::quota_rollup::QuotaRollup {
                coordinator,
                metrics: crate::telemetry::ConsoleMetrics::default(),
            }),
            Err(error) => {
                crate::log_failure(&format!(
                    "Worker quota rollup configuration unavailable: {error}"
                ));
                None
            }
        };
        Self {
            rollup,
            max_per_tick: ROLLUP_FIRES_PER_TICK,
        }
    }
}

impl<S: mkit_server::NamespaceStore, T: mkit_server::NamespaceStore>
    mkit_server::timers::TimerHandler<S> for WorkerQuotaRollup<T>
{
    fn kind(&self) -> mkit_server::timers::TimerKind {
        mkit_server::timers::registry::kinds::QUOTA_ROLLUP
    }

    fn max_per_tick(&self) -> Option<u32> {
        Some(self.max_per_tick)
    }

    fn fire<'a>(
        &'a self,
        ctx: &'a mkit_server::timers::TimerCtx<'a, S>,
        timer: &'a mkit_server::timers::DueTimer,
    ) -> mkit_server::BoxFuture<'a, Result<mkit_server::timers::Fired, mkit_server::StoreError>>
    {
        match &self.rollup {
            Some(rollup) => rollup.fire(ctx, timer),
            None => Box::pin(async { Ok(mkit_server::timers::Fired::Retry) }),
        }
    }
}

struct WorkerRelay<T> {
    relay: Option<mkit_server::relay::RelayHandler<T>>,
    max_per_tick: u32,
    metrics: Arc<dyn mkit_server::Metrics>,
}

struct WorkerLeaseSweep<T> {
    sweep: mkit_server::timers::lease_sweep::LeaseSweep<T>,
    max_per_tick: u32,
}

impl<S: mkit_server::NamespaceStore, T: mkit_server::NamespaceStore>
    mkit_server::timers::TimerHandler<S> for WorkerLeaseSweep<T>
{
    fn kind(&self) -> mkit_server::timers::TimerKind {
        mkit_server::timers::registry::kinds::LEASE_SWEEP
    }

    fn max_per_tick(&self) -> Option<u32> {
        Some(self.max_per_tick)
    }

    fn fire<'a>(
        &'a self,
        ctx: &'a mkit_server::timers::TimerCtx<'a, S>,
        timer: &'a mkit_server::timers::DueTimer,
    ) -> mkit_server::BoxFuture<'a, Result<mkit_server::timers::Fired, mkit_server::StoreError>>
    {
        self.sweep.fire(ctx, timer)
    }
}

impl<S: mkit_server::NamespaceStore, T: mkit_server::NamespaceStore>
    mkit_server::timers::TimerHandler<S> for WorkerRelay<T>
{
    fn kind(&self) -> mkit_server::timers::TimerKind {
        mkit_server::timers::registry::kinds::RELAY
    }

    fn max_per_tick(&self) -> Option<u32> {
        Some(self.max_per_tick)
    }

    fn fire<'a>(
        &'a self,
        ctx: &'a mkit_server::timers::TimerCtx<'a, S>,
        timer: &'a mkit_server::timers::DueTimer,
    ) -> mkit_server::BoxFuture<'a, Result<mkit_server::timers::Fired, mkit_server::StoreError>>
    {
        match &self.relay {
            Some(relay) => Box::pin(relay.deliver_with_metrics(ctx, timer, self.metrics.as_ref())),
            None => Box::pin(async { Ok(mkit_server::timers::Fired::Retry) }),
        }
    }
}

/// Why a request body stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BodyError {
    /// More than the cap arrived.
    TooLarge {
        /// The cap, bytes.
        limit: usize,
    },
    /// The runtime failed to read the body (its detail).
    Read(String),
}

impl core::fmt::Display for BodyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooLarge { limit } => write!(f, "request body exceeds {limit} bytes"),
            Self::Read(detail) => write!(f, "request body read failed: {detail}"),
        }
    }
}

impl std::error::Error for BodyError {}

/// What the adapter observed of one request's bodies, shared by both: the
/// largest frame (the most body bytes held at once) and whether the
/// request body ran past its cap.
#[derive(Debug, Clone, Default)]
pub struct BodyWatch(Arc<WatchState>);

#[derive(Debug, Default)]
struct WatchState {
    peak: AtomicUsize,
    too_large: AtomicBool,
}

impl BodyWatch {
    /// Record a frame of `len` bytes.
    pub fn record(&self, len: usize) {
        self.0.peak.fetch_max(len, Ordering::Relaxed);
    }

    /// The largest frame recorded.
    #[must_use]
    pub fn peak(&self) -> usize {
        self.0.peak.load(Ordering::Relaxed)
    }

    /// The request body ran past its cap ([`BodyError::TooLarge`]).
    #[must_use]
    pub fn too_large(&self) -> bool {
        self.0.too_large.load(Ordering::Relaxed)
    }

    fn set_too_large(&self) {
        self.0.too_large.store(true, Ordering::Relaxed);
    }
}

/// The response to a request whose body ran past `limit` bytes, whatever
/// connectrpc answered: vcs-worker's HTTP 400 with the Connect JSON
/// [`body_too_large_json`], as for a `Content-Length` over the cap. A
/// chunked body has no `Content-Length`, so only the stream finds out; the
/// error connectrpc builds from a failed body read is `internal`.
#[must_use]
pub fn over_cap_response(watch: &BodyWatch, limit: usize) -> Option<(u16, String)> {
    watch.too_large().then(|| (400, body_too_large_json(limit)))
}

/// A body that fails once more than `limit` bytes have passed, maps its
/// inner error to [`BodyError`] and records each frame in a [`BodyWatch`].
/// Nothing is buffered: each frame passes through as it arrives.
#[derive(Debug)]
pub struct LimitedBody<B> {
    inner: B,
    limit: usize,
    seen: usize,
    peak: BodyWatch,
    failed: bool,
}

impl<B> LimitedBody<B> {
    /// `inner`, capped at `limit` bytes.
    #[must_use]
    pub fn new(inner: B, limit: usize, peak: BodyWatch) -> Self {
        Self {
            inner,
            limit,
            seen: 0,
            peak,
            failed: false,
        }
    }
}

impl<B> Body for LimitedBody<B>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: core::fmt::Display,
{
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        let this = self.get_mut();
        if this.failed {
            return Poll::Ready(None);
        }
        let frame = match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(None) => return Poll::Ready(None),
            Poll::Ready(Some(Err(e))) => {
                this.failed = true;
                return Poll::Ready(Some(Err(BodyError::Read(e.to_string()))));
            }
            Poll::Ready(Some(Ok(frame))) => frame,
        };
        if let Some(data) = frame.data_ref() {
            this.peak.record(data.len());
            this.seen = this.seen.saturating_add(data.len());
            if this.seen > this.limit {
                this.failed = true;
                this.peak.set_too_large();
                return Poll::Ready(Some(Err(BodyError::TooLarge { limit: this.limit })));
            }
        }
        Poll::Ready(Some(Ok(frame)))
    }

    fn is_end_stream(&self) -> bool {
        self.failed || self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// Called with a request's peak frame when its response body is dropped.
pub type PeakReport = Box<dyn FnOnce(usize)>;

/// A response body that records each frame in a [`BodyWatch`] and, when
/// dropped (the request is over), hands the peak to `report`.
pub struct MeasuredBody<B> {
    inner: B,
    peak: BodyWatch,
    report: Option<PeakReport>,
}

impl<B: core::fmt::Debug> core::fmt::Debug for MeasuredBody<B> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MeasuredBody")
            .field("inner", &self.inner)
            .field("peak", &self.peak)
            .finish_non_exhaustive()
    }
}

impl<B> MeasuredBody<B> {
    /// `inner`, measured into `peak`.
    #[must_use]
    pub fn new(inner: B, peak: BodyWatch, report: Option<PeakReport>) -> Self {
        Self {
            inner,
            peak,
            report,
        }
    }
}

impl<B> Drop for MeasuredBody<B> {
    fn drop(&mut self) {
        if let Some(report) = self.report.take() {
            report(self.peak.peak());
        }
    }
}

impl<B: Body<Data = Bytes> + Unpin> Body for MeasuredBody<B> {
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, B::Error>>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut this.inner).poll_frame(cx);
        if let Poll::Ready(Some(Ok(frame))) = &polled
            && let Some(data) = frame.data_ref()
        {
            this.peak.record(data.len());
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// Drive `svc` once with a request of any body type: the streaming
/// counterpart of `mkit_worker_common::adapter::dispatch_oneshot`, which
/// takes only a whole `Full<Bytes>` body.
pub async fn dispatch_oneshot_body<S, B>(svc: S, req: http::Request<B>) -> S::Response
where
    S: tower::Service<http::Request<B>, Error = core::convert::Infallible>,
{
    use tower::ServiceExt as _;
    match svc.oneshot(req).await {
        Ok(response) => response,
        Err(never) => match never {},
    }
}

/// vcs-worker's answer to a body over the cap: HTTP 400, Connect JSON
/// `resource_exhausted`.
#[must_use]
pub fn body_too_large_json(limit: usize) -> String {
    format!(
        "{{\"code\":\"resource_exhausted\",\"message\":\"request body exceeds {limit} bytes\"}}"
    )
}

/// The Connect JSON of an `unavailable` error with `message`.
#[must_use]
pub fn unavailable_json(message: &str) -> String {
    let body = serde_json::json!({ "code": "unavailable", "message": message });
    body.to_string()
}

#[cfg(feature = "test-faults")]
pub use faults::{FINAL_CHUNK_FAULT, FaultState, WorkerFaults};

#[cfg(feature = "test-faults")]
mod faults {
    use std::collections::HashSet;
    use std::sync::{Arc, Mutex, PoisonError};

    use mkit_core::hash::Hash;
    use mkit_server::pipeline::{FailOnce, FaultHooks, FaultPoint, TestDirectives};
    use mkit_server::{MaybeSend, MaybeSync, Operation, ServerError};

    /// The `x-mkit-test-fault` token that fails an upload's final R2 chunk
    /// once per operation ([`crate::r2::R2BlobStore::fail_final_chunk_once`]).
    pub const FINAL_CHUNK_FAULT: &str = "final-chunk";

    /// The isolate's fault state: it outlives each request's pipeline, so
    /// a fault fires once per operation and its retry passes.
    #[derive(Debug, Default)]
    pub struct FaultState {
        once: FailOnce,
        final_chunk: Mutex<HashSet<Option<Hash>>>,
    }

    /// The Workers [`FaultHooks`]: vcs-worker's `after-reserve` and
    /// `after-put` ([`FailOnce`]), plus `final-chunk`, which arms the blob
    /// store's withheld-final-chunk fault at the reservation. The Durable
    /// Object's own fault (a batch writing a key containing
    /// `__test_fail_once-` fails once) needs no hook: `NsObject` wraps its
    /// connection in `FaultConn` under `test-faults`.
    pub struct WorkerFaults<A> {
        state: Arc<FaultState>,
        arm_final_chunk: A,
    }

    impl<A> core::fmt::Debug for WorkerFaults<A> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("WorkerFaults").finish_non_exhaustive()
        }
    }

    impl<A: Fn() + MaybeSend + MaybeSync> WorkerFaults<A> {
        /// Hooks over the isolate's `state`; `arm_final_chunk` arms the
        /// request's blob store.
        pub fn new(state: Arc<FaultState>, arm_final_chunk: A) -> Self {
            Self {
                state,
                arm_final_chunk,
            }
        }
    }

    impl<A: Fn() + MaybeSend + MaybeSync> FaultHooks for WorkerFaults<A> {
        async fn at(
            &self,
            point: FaultPoint,
            op: &Operation,
            directives: &TestDirectives,
        ) -> Result<(), ServerError> {
            if point == FaultPoint::AfterReserve
                && directives.fault.as_deref() == Some(FINAL_CHUNK_FAULT)
            {
                let scope = op.auth.as_ref().map(|a| a.replay_scope);
                let first = self
                    .state
                    .final_chunk
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .insert(scope);
                if first {
                    (self.arm_final_chunk)();
                }
            }
            self.state.once.at(point, op, directives).await
        }
    }
}

#[cfg(target_arch = "wasm32")]
pub use glue::{fetch, ns_object, serve};

#[cfg(target_arch = "wasm32")]
mod glue {
    use std::sync::Arc;
    use std::sync::Once;

    use crate::telemetry::{ConsoleMetrics, install};
    use mkit_server::auth_v2::CORS_ALLOW_HEADERS;
    use mkit_server::pipeline::{Hooks, Pipeline};
    use mkit_worker_common::adapter::{
        copy_headers_filtered, copy_response_headers, is_deadline_header, respond_streamed,
        to_http_method,
    };
    use mkit_worker_common::body_cap::content_length_exceeds;
    use mkit_worker_common::cors::{cors_preflight_response, is_options_preflight, with_cors};
    use worker::{Env, Request, Response, State};

    use super::{
        BodyWatch, CORS_ALLOW_METHODS, ConfigError, LimitedBody, MeasuredBody, PLAN_VAR,
        SINGLE_PUT_MAX_BYTES, WorkerConfig, body_too_large_json, dispatch_oneshot_body,
        over_cap_response, plan_capacity, unavailable_json,
    };
    use crate::backup::{BACKUPS_BINDING, BackupConfig, BackupDrain, BackupHandler};
    use crate::clock::WorkerClock;
    use crate::ns_client::{StubTransport, WorkerNamespaceStore};
    use crate::ns_object::NsObject;
    use crate::r2::{EnvBucket, PACKS_KEYSPACE, R2BlobStore, WorkerBlobStore};
    use crate::sharding_guard::{Outcome, Settled, check_addressing, check_mode};

    thread_local! {
        static SHARDING_GUARD: std::cell::RefCell<Option<Settled>> = const { std::cell::RefCell::new(None) };
    }

    static BACKUPS_MISSING_LOG: Once = Once::new();
    static BACKUPS_INVALID_LOG: Once = Once::new();

    /// The pipeline a request runs on.
    type WorkerPipeline = Pipeline<WorkerBlobStore, WorkerNamespaceStore, Hooks>;

    fn json_response(body: String, status: u16) -> worker::Result<Response> {
        let mut response = Response::error(body, status)?;
        response
            .headers_mut()
            .set("Content-Type", "application/json")?;
        Ok(response)
    }

    /// The pipeline for `cfg` over `env`'s bindings.
    fn pipeline(env: &Env, cfg: &WorkerConfig) -> Result<WorkerPipeline, ConfigError> {
        let bad = |e: &dyn core::fmt::Display| ConfigError(e.to_string());
        let config = cfg.pipeline_config()?;
        let blobs = R2BlobStore::new(
            EnvBucket::new(env.clone(), cfg.blob_binding),
            PACKS_KEYSPACE,
        )
        .with_max_bytes(SINGLE_PUT_MAX_BYTES);
        let meta = WorkerNamespaceStore::new(
            StubTransport::new(env.clone(), cfg.placement.clone()),
            cfg.probe_partition(),
        );
        #[cfg(feature = "test-faults")]
        let faulted = blobs.clone();
        let pipe = Pipeline::new(
            blobs,
            meta,
            Hooks::new(),
            config,
            Arc::new(WorkerClock),
            Arc::new(ConsoleMetrics::default()),
        )
        .map_err(|e| bad(&e))?;
        #[cfg(feature = "test-faults")]
        let pipe = pipe.with_faults(super::WorkerFaults::new(test::fault_state(), move || {
            faulted.fail_final_chunk_once();
        }));
        Ok(pipe)
    }

    /// The `http::Request` connectrpc dispatches: `req`'s method, URL and
    /// headers (without the deadline headers) over its streaming body.
    fn http_request(
        req: &Request,
        max_body_bytes: usize,
        watch: &BodyWatch,
    ) -> worker::Result<http::Request<LimitedBody<worker::Body>>> {
        let body = req
            .inner()
            .body()
            .map_or_else(worker::Body::empty, worker::Body::new);
        let mut http_req = http::Request::builder()
            .method(to_http_method(req.method()))
            .uri(req.url()?.to_string())
            .body(LimitedBody::new(body, max_body_bytes, watch.clone()))
            .map_err(|e| worker::Error::RustError(format!("build http request: {e}")))?;
        copy_headers_filtered(req.headers().entries(), http_req.headers_mut(), |k| {
            !is_deadline_header(k)
        });
        Ok(http_req)
    }

    /// A deployment's whole `#[event(fetch)]`: [`serve`] with the
    /// [`WorkerConfig`] of `env`'s vars. With a var missing or malformed,
    /// every request but a CORS preflight is answered `unavailable` (HTTP
    /// 503) naming it.
    ///
    /// # Errors
    /// Only when the runtime fails to build a response.
    pub async fn fetch(req: Request, env: Env) -> worker::Result<Response> {
        install();
        match WorkerConfig::from_env(&env) {
            Ok(cfg) => serve(req, env, &cfg).await,
            Err(_) if is_options_preflight(&req) => {
                cors_preflight_response(CORS_ALLOW_HEADERS, CORS_ALLOW_METHODS)
            }
            Err(e) => Ok(with_cors(json_response(unavailable_json(&e.0), 503)?)),
        }
    }

    /// Answer one request of a deployment (see the module docs).
    ///
    /// # Errors
    /// Only when the runtime fails to build a response.
    pub async fn serve(req: Request, env: Env, cfg: &WorkerConfig) -> worker::Result<Response> {
        #[cfg(feature = "test-faults")]
        let mut req = req;
        install();
        if is_options_preflight(&req) {
            return cors_preflight_response(CORS_ALLOW_HEADERS, CORS_ALLOW_METHODS);
        }
        let meta = WorkerNamespaceStore::new(
            StubTransport::new(env.clone(), cfg.placement.clone()),
            cfg.probe_partition(),
        );
        let jurisdiction = cfg.placement.jurisdiction.as_deref();
        let multi = matches!(cfg.addressing, mkit_server::Addressing::Multi(_));
        let cached =
            SHARDING_GUARD.with(|cache| Settled::cached(cache, cfg.sharding, multi, jurisdiction));
        let checked = if let Some(outcome) = cached {
            outcome.into_result()
        } else {
            // This request owns every await. Only settled data crosses requests.
            let result = match check_mode(&meta, cfg.sharding).await {
                Ok(Outcome::Ok) => check_addressing(&meta, multi).await,
                settled => settled,
            };
            SHARDING_GUARD
                .with(|cache| Settled::finish(cache, cfg.sharding, multi, jurisdiction, result))
        };
        if let Err(error) = checked {
            return Ok(with_cors(json_response(
                unavailable_json(error.public_message()),
                503,
            )?));
        }
        #[cfg(feature = "test-faults")]
        if let Some(response) = test::backup_round_trip(&mut req, &env, cfg).await? {
            return Ok(with_cors(response));
        }
        #[cfg(feature = "test-faults")]
        if req.method() == worker::Method::Get && req.path() == test::STATS_PATH {
            return Ok(with_cors(test::stats(&env, cfg).await?));
        }
        #[cfg(feature = "test-faults")]
        {
            let path = req.path();
            if let Some(pack) = path.strip_prefix(test::RELAY_PATH_PREFIX) {
                return Ok(with_cors(test::relay(req.method(), pack, &env, cfg).await?));
            }
        }
        let length = req.headers().get("content-length").ok().flatten();
        if content_length_exceeds(length.as_deref(), cfg.max_body_bytes) {
            let body = body_too_large_json(cfg.max_body_bytes);
            return Ok(with_cors(json_response(body, 400)?));
        }
        let pipe = match pipeline(&env, cfg) {
            Ok(pipe) => pipe,
            Err(e) => return Ok(with_cors(json_response(unavailable_json(&e.0), 503)?)),
        };
        let watch = BodyWatch::default();
        let http_req = http_request(&req, cfg.max_body_bytes, &watch)?;
        // The binding takes an `Arc` and holds it in a `SendWrapper` on
        // wasm32, where the pipeline's Workers handles are `!Send`.
        #[allow(clippy::arc_with_non_send_sync)]
        let pipe = Arc::new(pipe);
        let http_resp = dispatch_oneshot_body(mkit_server::connect::service(pipe), http_req).await;
        // A unary body is read whole, and a client-streaming handler has
        // answered, before connectrpc returns its response: a body that
        // ran past the cap has tripped the watch by now.
        if let Some((status, body)) = over_cap_response(&watch, cfg.max_body_bytes) {
            return Ok(with_cors(json_response(body, status)?));
        }
        let status = http_resp.status().as_u16();
        let headers = http_resp.headers().clone();
        #[cfg(feature = "test-faults")]
        let report: Option<super::PeakReport> = {
            let path = req.path();
            Some(Box::new(move |bytes| test::report_peak(&path, bytes)))
        };
        #[cfg(not(feature = "test-faults"))]
        let report = None;
        let body = MeasuredBody::new(http_resp.into_body(), watch, report);
        let mut out = respond_streamed(status, body)?;
        if headers.contains_key(http::header::CONTENT_ENCODING) {
            // connectrpc compressed the body itself (a unary response to
            // `Accept-Encoding: gzip`): the runtime must pass it through,
            // not encode it a second time.
            out = out.with_encode_body(worker::EncodeBody::Manual);
        }
        copy_response_headers(&headers, &mut out);
        Ok(with_cors(out))
    }

    /// The Durable Object of a partition for `state`: its store capped for
    /// the plan in `env`'s `WORKERS_PLAN` var (see [`plan_capacity`]).
    #[must_use]
    pub fn ns_object(state: State, env: &Env, class: crate::classes::ShardClass) -> NsObject {
        install();
        let plan = env.var(PLAN_VAR).ok().map(|v| v.to_string());
        let capacity = plan_capacity(plan.as_deref()).unwrap_or_else(|(e, free)| {
            worker::console_error!("{e}; using the Workers Free cap");
            free
        });
        let target = WorkerConfig::from_env(env).map(|cfg| {
            let probe = cfg.probe_partition();
            WorkerNamespaceStore::new(StubTransport::new(env.clone(), cfg.placement), probe)
        });
        let registry = super::timer_registry_with_blobs(
            class,
            target,
            plan.as_deref(),
            R2BlobStore::new(
                EnvBucket::new(env.clone(), crate::r2::STORAGE_BINDING),
                PACKS_KEYSPACE,
            ),
        );
        let registry = super::with_outcome_timers(
            registry,
            class,
            WorkerConfig::from_env(env).map(|cfg| cfg.audience),
        );
        let backup = BackupConfig::from_vars(|name| env.var(name).ok().map(|v| v.to_string()))
            .map_err(|error| {
                BACKUPS_INVALID_LOG
                    .call_once(|| crate::log_failure(&format!("backup config invalid: {error}")));
            })
            .ok()
            .filter(|config| config.interval_ms != 0);
        let backup = backup.and_then(|config| {
            if env.bucket(BACKUPS_BINDING).is_ok() {
                Some(config)
            } else {
                BACKUPS_MISSING_LOG.call_once(|| {
                    crate::log_failure("BACKUPS R2 binding absent; backups disabled");
                });
                None
            }
        });
        let registry = if let Some(config) = backup.clone() {
            // Free-plan alarm budget: at most 32 relay calls plus this
            // handler's single R2 put = 33 external subrequests, under 50.
            // Kinds 8 and 9 (NoOutcomes, reconcile) make no external calls.
            registry.register(BackupHandler::new(
                EnvBucket::new(env.clone(), BACKUPS_BINDING),
                config,
            ))
        } else {
            registry.register(BackupDrain)
        };
        let object = NsObject::new(state, class)
            .0
            .with_capacity(capacity)
            .with_registry(registry);
        if let Some(config) = backup {
            object.with_backup_interval(config.interval_ms)
        } else {
            object
        }
    }

    #[cfg(feature = "test-faults")]
    mod test {
        use std::sync::Arc;

        use mkit_server::pipeline::{D34Shards, ShardMap, Sharding};
        use mkit_server::store::{keys, outbox::OutboxBuilder};
        use mkit_server::{
            Batch, BatchOutcome, BlobKey, Clock, NamespaceKey, NamespaceStore, Partition, RepoId,
            RepoName, StoreError, Value,
        };
        use worker::{Env, Method, Request, Response};

        use super::super::faults::FaultState;
        use crate::naming::{DoTarget, REFSTORE, ROOT_INSTANCE};
        use crate::ns_client::{NsTransport, StubTransport, WorkerNamespaceStore};
        use crate::wire::{Blob, NsCall, NsReply, NsRequest};

        /// The wire suite's stats hook (M0-07).
        pub(super) const STATS_PATH: &str = "/__mkit_test/stats";
        const SNAPSHOT_PATH: &str = "/__mkit_test/snapshot";
        const RESTORE_PATH: &str = "/__mkit_test/restore";
        const RESTORED_SNAPSHOT_PATH: &str = "/__mkit_test/restored-snapshot";
        const RESTORED_INSTANCE: &str = "root-restore-test";

        /// A wrangler-dev-only round trip between two `RefStore` instances.
        pub(super) async fn backup_round_trip(
            req: &mut Request,
            env: &Env,
            cfg: &super::WorkerConfig,
        ) -> worker::Result<Option<Response>> {
            let path = req.path();
            if !matches!(
                path.as_str(),
                SNAPSHOT_PATH | RESTORE_PATH | RESTORED_SNAPSHOT_PATH
            ) {
                return Ok(None);
            }
            if cfg.sharding != mkit_server::pipeline::Sharding::Single {
                return Response::error("snapshot test route is single-sharding only", 409)
                    .map(Some);
            }
            let is_import = path == RESTORE_PATH;
            if req.method() != if is_import { Method::Post } else { Method::Get } {
                return Response::error("method not allowed", 405).map(Some);
            }
            let part = Partition::Namespace(NamespaceKey::deployment_default());
            let target = DoTarget {
                binding: REFSTORE,
                name: if path == SNAPSHOT_PATH {
                    ROOT_INSTANCE
                } else {
                    RESTORED_INSTANCE
                }
                .into(),
            };
            let call = if is_import {
                let bytes = req.bytes().await?;
                if bytes.len() > crate::backup::DEFAULT_MAX_BYTES {
                    return Response::error("snapshot exceeds backup cap", 413).map(Some);
                }
                NsCall::TestImport { bytes: Blob(bytes) }
            } else {
                NsCall::TestSnapshot
            };
            let body = serde_json::to_string(
                &NsRequest::new(&part, call)
                    .map_err(|e| worker::Error::RustError(e.to_string()))?,
            )
            .map_err(|e| worker::Error::RustError(e.to_string()))?;
            let transport = StubTransport::new(env.clone(), cfg.placement.clone());
            let raw = match transport.call(&target, "test_backup", body).await {
                Ok(raw) => raw,
                Err(e) => return Response::error(e.to_string(), 503).map(Some),
            };
            let reply: NsReply =
                serde_json::from_str(&raw).map_err(|e| worker::Error::RustError(e.to_string()))?;
            let response = match reply {
                NsReply::Snapshot { bytes } => {
                    let mut response = Response::from_bytes(bytes.0)?;
                    response
                        .headers_mut()
                        .set("Content-Type", "application/octet-stream")?;
                    response
                }
                NsReply::Imported { records } => {
                    Response::from_json(&serde_json::json!({ "records": records }))?
                }
                NsReply::Err { message, .. } => Response::error(message, 400)?,
                _ => Response::error("unexpected test backup reply", 500)?,
            };
            Ok(Some(response))
        }

        /// Local conformance planting/probing of real `RefShard` relay alarms.
        pub(super) const RELAY_PATH_PREFIX: &str = "/__mkit_test/relay/";

        thread_local! {
            static FAULTS: Arc<FaultState> = Arc::default();
        }

        /// The isolate's fault state.
        pub(super) fn fault_state() -> Arc<FaultState> {
            FAULTS.with(Arc::clone)
        }

        /// `{bytes, keys}` of the deployment-default partition, which holds
        /// the replay records and quota windows.
        pub(super) async fn stats(
            env: &Env,
            cfg: &super::WorkerConfig,
        ) -> worker::Result<Response> {
            if cfg.sharding == mkit_server::pipeline::Sharding::D34 {
                return Response::error("stats hook is single-sharding only", 409);
            }
            let store = WorkerNamespaceStore::new(
                StubTransport::new(env.clone(), cfg.placement.clone()),
                cfg.probe_partition(),
            );
            let p = Partition::Namespace(NamespaceKey::deployment_default());
            match store.stats(&p).await {
                Ok(s) => {
                    Response::from_json(&serde_json::json!({ "bytes": s.bytes, "keys": s.keys }))
                }
                Err(e) => Response::error(e.to_string(), 503),
            }
        }

        /// Plant a ref-local member and its relay, or inspect target membership
        /// and source queue drainage. The fixture id lives in the URL, so this
        /// hook never reads or buffers a request body.
        pub(super) async fn relay(
            method: Method,
            pack_hex: &str,
            env: &Env,
            cfg: &super::WorkerConfig,
        ) -> worker::Result<Response> {
            if cfg.sharding != Sharding::D34 {
                return Response::error("relay hook is D34-sharding only", 409);
            }
            if !matches!(method, Method::Get | Method::Post) {
                return Response::error("relay hook requires GET or POST", 405);
            }
            let Ok(pack) = mkit_core::hash::from_hex(pack_hex) else {
                return Response::error("relay fixture must be a 64-character hex pack id", 400);
            };
            let repo = RepoId {
                namespace: NamespaceKey::deployment_default(),
                name: RepoName::new(cfg.repository.as_deref().unwrap_or("default"))
                    .map_err(|e| worker::Error::RustError(e.to_string()))?,
            };
            let reference = format!(
                "refs/heads/mkit-test-relay-{}",
                mkit_core::hash::to_hex(&pack)
            );
            let source = D34Shards.ref_shard(&repo, &reference);
            let target = D34Shards.membership(&repo, &BlobKey::pack(pack));
            let key = keys::membership(&repo.name, &pack);
            let store = WorkerNamespaceStore::new(
                StubTransport::new(env.clone(), cfg.placement.clone()),
                cfg.probe_partition(),
            );
            let result: Result<serde_json::Value, StoreError> = async {
                if method == Method::Post {
                    let observed = store.get(&source, &keys::outbox_sequence()).await?;
                    let mut outbox = OutboxBuilder::new(observed.as_ref(), None)?;
                    let now = u64::try_from(super::WorkerClock.now_ms()).unwrap_or(0);
                    outbox.relay_at(now);
                    outbox.relay(&target, vec![(key.clone(), Value::default())]);
                    let mut batch = Batch::new().put(key, Value::default());
                    outbox.try_finish(&mut batch.preconditions, &mut batch.writes)?;
                    if store.apply(&source, batch).await? != BatchOutcome::Committed {
                        return Err(StoreError::Invalid("relay fixture planting raced".into()));
                    }
                    Ok(serde_json::json!({ "planted": true }))
                } else {
                    let member = store.get(&target, &key).await?.is_some();
                    let (start, end) = keys::class_range(keys::TAG_RELAY);
                    let queue = store.scan(&source, &start, &end, None, 1).await?;
                    let queued = !queue.entries.is_empty() || queue.next.is_some();
                    Ok(serde_json::json!({ "member": member, "queued": queued }))
                }
            }
            .await;
            match result {
                Ok(state) => Response::from_json(&state),
                Err(error) => Response::error(error.to_string(), 503),
            }
        }

        /// Log the most body bytes a request held at once
        /// (`scripts/vcs-worker-conformance.sh --test-faults` checks it).
        /// Also logs the isolate's wasm linear memory, which only grows: a
        /// leak across requests shows as a climb toward the 128 MB isolate
        /// limit.
        /// The script bounds the streaming RPCs' lines only: a unary body is
        /// one frame (a whole `ListRefs` reply until WP-1.27's paging).
        pub(super) fn report_peak(path: &str, bytes: usize) {
            let memory = core::arch::wasm32::memory_size::<0>() * 65_536;
            worker::console_log!(
                "mkit-adapter peak-buffered-bytes {bytes} wasm-memory-bytes {memory} path {path}"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use futures::executor::block_on;
    use http_body_util::{BodyExt as _, Full, StreamBody};

    use super::*;

    fn vars(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> + use<> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |k| map.get(k).cloned()
    }

    #[test]
    fn config_requires_audience_and_repository() {
        let cfg = WorkerConfig::from_vars(vars(&[
            (AUDIENCE_VAR, "https://vcs.example"),
            (REPOSITORY_VAR, "default"),
        ]))
        .unwrap();
        assert_eq!(cfg.audience, "https://vcs.example");
        assert_eq!(cfg.repository.as_deref(), Some("default"));
        assert_eq!(cfg.max_body_bytes, DEFAULT_MAX_BODY_BYTES);
        assert_eq!(cfg.blob_binding, "STORAGE");
        assert_eq!(
            WorkerConfig::from_vars(vars(&[(REPOSITORY_VAR, "default")])).unwrap_err(),
            ConfigError("AUTH_AUDIENCE is not configured".into())
        );
        assert_eq!(
            WorkerConfig::from_vars(vars(&[(AUDIENCE_VAR, "https://vcs.example")])).unwrap_err(),
            ConfigError("AUTH_REPOSITORY is not configured".into())
        );
    }

    #[test]
    fn ticket_keys_are_optional_validated_and_passed_to_the_pipeline() {
        let base = [
            (AUDIENCE_VAR, "https://vcs.example"),
            (REPOSITORY_VAR, "default"),
        ];
        let cfg = WorkerConfig::from_vars(vars(&base)).unwrap();
        assert!(cfg.ticket_keys.is_none());
        let mut pairs = base.to_vec();
        let secret = "dev 1111111111111111111111111111111111111111111111111111111111111111";
        pairs.push((TICKET_KEYS_VAR, secret));
        let cfg = WorkerConfig::from_vars(vars(&pairs)).unwrap();
        assert!(cfg.ticket_keys.is_some());
        assert_eq!(cfg.pipeline_config().unwrap().ticket_keys, cfg.ticket_keys);
        for invalid in ["", "dev secret-must-not-be-echoed", "bad/key 11"] {
            pairs.pop();
            pairs.push((TICKET_KEYS_VAR, invalid));
            assert_eq!(
                WorkerConfig::from_vars(vars(&pairs)).unwrap_err(),
                ConfigError("TICKET_KEYS is invalid".into())
            );
        }
    }

    #[test]
    fn sharding_parsing_and_pipeline_selection() {
        let base = [
            (AUDIENCE_VAR, "https://vcs.example"),
            (REPOSITORY_VAR, "default"),
        ];
        for (value, expected) in [
            (None, Sharding::D34),
            (Some("single"), Sharding::Single),
            (Some("d34"), Sharding::D34),
        ] {
            let mut pairs = base.to_vec();
            if let Some(value) = value {
                pairs.push(("SHARDING", value));
            }
            let cfg = WorkerConfig::from_vars(vars(&pairs)).unwrap();
            assert_eq!(cfg.sharding, expected);
            assert_eq!(cfg.pipeline_config().unwrap().sharding, expected);
        }
        let mut pairs = base.to_vec();
        pairs.push(("SHARDING", "other"));
        assert!(WorkerConfig::from_vars(vars(&pairs)).is_err());
    }

    #[test]
    fn placement_parsing_is_deployment_wide() {
        let base = [
            (AUDIENCE_VAR, "https://vcs.example"),
            (REPOSITORY_VAR, "default"),
        ];
        assert_eq!(
            WorkerConfig::from_vars(vars(&base)).unwrap().placement,
            Placement::default()
        );
        for jurisdiction in ["eu", "us", "fedramp"] {
            let mut pairs = base.to_vec();
            pairs.extend([
                ("NAMESPACE_JURISDICTION", jurisdiction),
                ("NAMESPACE_LOCATION_HINT", "weur"),
            ]);
            let placement = WorkerConfig::from_vars(vars(&pairs)).unwrap().placement;
            assert_eq!(placement.jurisdiction.as_deref(), Some(jurisdiction));
            assert_eq!(placement.location_hint.as_deref(), Some("weur"));
        }
        for value in ["", "EU", "weur", "invalid"] {
            let mut pairs = base.to_vec();
            pairs.push(("NAMESPACE_JURISDICTION", value));
            assert!(WorkerConfig::from_vars(vars(&pairs)).is_err());
        }
    }

    #[test]
    fn config_validates_repository_grammar() {
        for repository in ["Upper", ".name", "root/name", "a/b", &"a".repeat(101)] {
            let err = WorkerConfig::from_vars(vars(&[
                (AUDIENCE_VAR, "https://vcs.example"),
                (REPOSITORY_VAR, repository),
            ]))
            .unwrap_err();
            assert_eq!(
                err,
                ConfigError("AUTH_REPOSITORY is invalid (SPEC-TRANSPORT-CONNECT §7.4)".into())
            );
        }
        let identity = format!("ed25519-{}/name", "a".repeat(64));
        let cfg = WorkerConfig::from_vars(vars(&[
            (AUDIENCE_VAR, "https://vcs.example"),
            (REPOSITORY_VAR, &identity),
        ]))
        .unwrap();
        assert_eq!(cfg.repository.as_deref(), Some(identity.as_str()));
    }

    fn ns(byte: u8) -> String {
        format!("ed25519-{}{byte:02x}", "a".repeat(62))
    }

    /// `ADDRESSING=multi` with its allowlist: the pipeline addresses by
    /// `X-Repository`, the allowlist's namespaces may write, and
    /// `AUTH_REPOSITORY` is neither required nor read.
    #[test]
    fn multi_vars_build_a_multi_pipeline() {
        use mkit_server::policy::NamespacePolicy;

        let secret = "dev 1111111111111111111111111111111111111111111111111111111111111111";
        let allowlist = format!("{},{}", ns(1), ns(2));
        let pairs = [
            (AUDIENCE_VAR, "https://vcs.example"),
            (ADDRESSING_VAR, "multi"),
            (NAMESPACE_ALLOWLIST_VAR, allowlist.as_str()),
            (TICKET_KEYS_VAR, secret),
        ];
        let cfg = WorkerConfig::from_vars(vars(&pairs)).unwrap();
        assert_eq!(cfg.repository, None);
        let mkit_server::Addressing::Multi(multi) = &cfg.addressing else {
            panic!("ADDRESSING=multi must select multi addressing");
        };
        let NamespacePolicy::Allowlist(namespaces) = &multi.namespace_policy else {
            panic!("the default multi namespace policy is an allowlist");
        };
        assert_eq!(namespaces.len(), 2);
        assert!(namespaces.contains(&mkit_core::repo_identity::Namespace::parse(&ns(1)).unwrap()));
        let pipeline = cfg.pipeline_config().unwrap();
        assert_eq!(pipeline.addressing, cfg.addressing);
        assert_eq!(
            pipeline.write_policy,
            mkit_server::policy::WritePolicy::Owner
        );
    }

    /// Every multi var combination the config must refuse.
    #[test]
    fn multi_vars_fail_closed() {
        let secret = "dev 1111111111111111111111111111111111111111111111111111111111111111";
        let namespace = ns(1);
        let multi = [
            (AUDIENCE_VAR, "https://vcs.example"),
            (ADDRESSING_VAR, "multi"),
            (NAMESPACE_ALLOWLIST_VAR, namespace.as_str()),
            (TICKET_KEYS_VAR, secret),
        ];
        for (var, value, message) in [
            ("ADDRESSING", "many", "ADDRESSING must be single or multi"),
            (
                NAMESPACE_ALLOWLIST_VAR,
                "not a namespace",
                "NAMESPACE_ALLOWLIST is invalid: line 1:",
            ),
        ] {
            let mut pairs = multi.to_vec();
            pairs.retain(|(k, _)| *k != var);
            pairs.push((var, value));
            let err = WorkerConfig::from_vars(vars(&pairs)).unwrap_err();
            assert!(err.0.starts_with(message), "{var}={value}: {err}");
        }
        // Missing the allowlist or the ticket keys.
        for (drop, message) in [
            (
                NAMESPACE_ALLOWLIST_VAR,
                "ADDRESSING=multi requires NAMESPACE_ALLOWLIST",
            ),
            (TICKET_KEYS_VAR, "ADDRESSING=multi requires TICKET_KEYS"),
        ] {
            let mut pairs = multi.to_vec();
            pairs.retain(|(k, _)| *k != drop);
            let err = WorkerConfig::from_vars(vars(&pairs)).unwrap_err();
            assert!(err.0.starts_with(message), "without {drop}: {err}");
        }
        // Namespace vars are multi-only.
        for var in [
            NAMESPACE_POLICY_VAR,
            NAMESPACE_ALLOWLIST_VAR,
            UNSAFE_OPEN_NAMESPACES_VAR,
        ] {
            let err = WorkerConfig::from_vars(vars(&[
                (AUDIENCE_VAR, "https://vcs.example"),
                (REPOSITORY_VAR, "default"),
                (
                    var,
                    if var == UNSAFE_OPEN_NAMESPACES_VAR {
                        "true"
                    } else {
                        "any"
                    },
                ),
            ]))
            .unwrap_err();
            assert!(err.0.contains("ADDRESSING=multi"), "{var}: {err}");
        }
        // `any` needs the unsafe opt-in, and both options are exclusive.
        let mut pairs = multi.to_vec();
        pairs.retain(|(k, _)| *k != NAMESPACE_ALLOWLIST_VAR);
        pairs.push((NAMESPACE_POLICY_VAR, "any"));
        let err = WorkerConfig::from_vars(vars(&pairs)).unwrap_err();
        assert_eq!(
            err.0,
            "NAMESPACE_POLICY=any requires UNSAFE_OPEN_NAMESPACES=true: the default \
             admission step cannot vet an open namespace set"
        );
        pairs.push((UNSAFE_OPEN_NAMESPACES_VAR, "true"));
        let cfg = WorkerConfig::from_vars(vars(&pairs)).unwrap();
        assert!(matches!(cfg.addressing, mkit_server::Addressing::Multi(_)));
        pairs.push((NAMESPACE_ALLOWLIST_VAR, namespace.as_str()));
        assert!(WorkerConfig::from_vars(vars(&pairs)).is_err());
        pairs.pop();
        pairs.pop();
        pairs.push((UNSAFE_OPEN_NAMESPACES_VAR, "1"));
        assert_eq!(
            WorkerConfig::from_vars(vars(&pairs)).unwrap_err().0,
            "UNSAFE_OPEN_NAMESPACES must be `true` when set"
        );
        pairs.pop();
        pairs.push((NAMESPACE_POLICY_VAR, "garbage"));
        assert_eq!(
            WorkerConfig::from_vars(vars(&pairs)).unwrap_err().0,
            "NAMESPACE_POLICY must be allowlist or any"
        );
    }

    const RP: &str = "example.test=https://example.test";

    fn multi_pairs<'a>(namespace: &'a str, audience: &'a str) -> Vec<(&'a str, &'a str)> {
        vec![
            (AUDIENCE_VAR, audience),
            (ADDRESSING_VAR, "multi"),
            (NAMESPACE_ALLOWLIST_VAR, namespace),
            (
                TICKET_KEYS_VAR,
                "dev 1111111111111111111111111111111111111111111111111111111111111111",
            ),
        ]
    }

    /// Grants are off unless `GRANT_SCHEMES` is set, and the validated inputs
    /// (not a `GrantConfig`) are what the config holds and compares.
    #[test]
    fn grant_vars_configure_the_verifier_and_default_to_off() {
        let namespace = ns(1);
        let base = multi_pairs(&namespace, "https://vcs.example");
        let off = WorkerConfig::from_vars(vars(&base)).unwrap();
        assert_eq!(off.grants, None);
        assert!(off.pipeline_config().unwrap().grants.is_none());
        let mut pairs = base.clone();
        pairs.extend([
            (GRANT_SCHEMES_VAR, "ed25519, webauthn-p256"),
            (
                WEBAUTHN_RPS_VAR,
                "example.test=https://example.test;other.test=https://other.test,https://a.other.test\n",
            ),
        ]);
        let cfg = WorkerConfig::from_vars(vars(&pairs)).unwrap();
        assert_eq!(cfg, WorkerConfig::from_vars(vars(&pairs)).unwrap());
        assert_ne!(cfg, off);
        let settings = cfg.grants.as_ref().unwrap();
        assert_eq!(settings.relying_parties.len(), 2);
        assert!(!settings.allow_loopback);
        let grants = cfg.pipeline_config().unwrap().grants.unwrap();
        assert_eq!(grants.audience(), "https://vcs.example");
        assert_eq!(
            grants.schemes().tokens().collect::<Vec<_>>(),
            ["ed25519", "webauthn-p256"]
        );
    }

    /// Every grant var refusal is a `ConfigError`, never "grants off".
    #[test]
    fn grant_vars_fail_closed() {
        let namespace = ns(1);
        let base = multi_pairs(&namespace, "https://vcs.example");
        let all = "ed25519,secp256k1-eip191,webauthn-p256";
        for (extra, message) in [
            (
                vec![(GRANT_SCHEMES_VAR, "rsa")],
                "GRANT_SCHEMES: invalid grant schemes",
            ),
            (vec![(GRANT_SCHEMES_VAR, "")], "GRANT_SCHEMES:"),
            (vec![(GRANT_SCHEMES_VAR, "  ")], "GRANT_SCHEMES:"),
            (vec![(GRANT_SCHEMES_VAR, "ed25519,")], "GRANT_SCHEMES:"),
            (
                vec![(GRANT_SCHEMES_VAR, all), (WEBAUTHN_RPS_VAR, "example.test")],
                "WEBAUTHN_RPS:",
            ),
            (
                vec![(GRANT_SCHEMES_VAR, all), (WEBAUTHN_RPS_VAR, "")],
                "WEBAUTHN_RPS:",
            ),
            (
                vec![
                    (GRANT_SCHEMES_VAR, all),
                    (
                        WEBAUTHN_RPS_VAR,
                        "a.test=https://a.test;;b.test=https://b.test",
                    ),
                ],
                "WEBAUTHN_RPS: relying parties: blank entry",
            ),
            (
                vec![
                    (GRANT_SCHEMES_VAR, all),
                    (
                        WEBAUTHN_RPS_VAR,
                        "a.test=https://a.test\na.test=https://other.test",
                    ),
                ],
                "WEBAUTHN_RPS: relying parties: duplicate id",
            ),
            // webauthn-p256 without a relying party; a relying party
            // without any scheme.
            (
                vec![(GRANT_SCHEMES_VAR, "webauthn-p256")],
                "invalid grant configuration",
            ),
            (vec![(WEBAUTHN_RPS_VAR, RP)], "GRANT_SCHEMES:"),
        ] {
            let mut pairs = base.clone();
            pairs.extend(extra.clone());
            let err = WorkerConfig::from_vars(vars(&pairs)).unwrap_err();
            assert!(err.0.starts_with(message), "{extra:?}: {err}");
        }
        // Grants need multi addressing.
        let err = WorkerConfig::from_vars(vars(&[
            (AUDIENCE_VAR, "https://vcs.example"),
            (REPOSITORY_VAR, "default"),
            (GRANT_SCHEMES_VAR, "ed25519"),
        ]))
        .unwrap_err();
        assert!(err.0.contains("ADDRESSING=multi"), "{err}");
        // A loopback audience or relying party needs the loopback opt-in.
        let loopback = multi_pairs(&namespace, "http://localhost:8787");
        let mut pairs = loopback.clone();
        pairs.push((GRANT_SCHEMES_VAR, "ed25519"));
        assert!(
            WorkerConfig::from_vars(vars(&pairs))
                .unwrap_err()
                .0
                .starts_with("invalid grant configuration")
        );
        let mut pairs = base.clone();
        pairs.extend([
            (GRANT_SCHEMES_VAR, all),
            (WEBAUTHN_RPS_VAR, "localhost=http://localhost:8787"),
        ]);
        assert!(WorkerConfig::from_vars(vars(&pairs)).is_err());
    }

    /// `UNSAFE_LOOPBACK_GRANTS` opens loopback grants in `test-faults` builds.
    #[cfg(feature = "test-faults")]
    #[test]
    fn loopback_grants_are_honoured_in_test_faults_builds() {
        let namespace = ns(1);
        let mut pairs = multi_pairs(&namespace, "http://localhost:8787");
        pairs.extend([
            (GRANT_SCHEMES_VAR, "ed25519"),
            (UNSAFE_LOOPBACK_GRANTS_VAR, "true"),
        ]);
        let cfg = WorkerConfig::from_vars(vars(&pairs)).unwrap();
        assert!(cfg.grants.as_ref().unwrap().allow_loopback);
        assert!(cfg.pipeline_config().unwrap().grants.is_some());
        pairs.pop();
        pairs.push((UNSAFE_LOOPBACK_GRANTS_VAR, "1"));
        assert!(WorkerConfig::from_vars(vars(&pairs)).is_err());
    }

    /// A release build never honours it: setting it is an error, even with
    /// nothing else configured.
    #[cfg(not(feature = "test-faults"))]
    #[test]
    fn loopback_grants_var_is_refused_in_release_builds() {
        let namespace = ns(1);
        let mut pairs = multi_pairs(&namespace, "http://localhost:8787");
        pairs.extend([
            (GRANT_SCHEMES_VAR, "ed25519"),
            (UNSAFE_LOOPBACK_GRANTS_VAR, "true"),
        ]);
        let err = WorkerConfig::from_vars(vars(&pairs)).unwrap_err();
        assert!(err.0.contains("only in test-faults builds"), "{err}");
        let err = WorkerConfig::from_vars(vars(&[
            (AUDIENCE_VAR, "https://vcs.example"),
            (REPOSITORY_VAR, "default"),
            (UNSAFE_LOOPBACK_GRANTS_VAR, "true"),
        ]))
        .unwrap_err();
        assert!(err.0.contains("only in test-faults builds"), "{err}");
    }

    /// Single addressing is the default and unchanged.
    #[test]
    fn single_is_the_default_addressing() {
        let cfg = WorkerConfig::from_vars(vars(&[
            (AUDIENCE_VAR, "https://vcs.example"),
            (REPOSITORY_VAR, "default"),
        ]))
        .unwrap();
        assert!(matches!(
            cfg.addressing,
            mkit_server::Addressing::Single { .. }
        ));
        assert!(matches!(
            cfg.pipeline_config().unwrap().addressing,
            mkit_server::Addressing::Single { .. }
        ));
    }

    #[cfg(feature = "test-faults")]
    #[test]
    fn test_quota_is_all_or_nothing() {
        let base = [(AUDIENCE_VAR, "https://x.example"), (REPOSITORY_VAR, "r")];
        let cfg = WorkerConfig::from_vars(vars(&base)).unwrap();
        assert_eq!(cfg.test_quota, None);
        let mut all = base.to_vec();
        all.extend([
            ("TEST_QUOTA_OPS", "7"),
            ("TEST_QUOTA_BYTES", "1024"),
            ("TEST_QUOTA_WINDOW_MS", "5000"),
        ]);
        let cfg = WorkerConfig::from_vars(vars(&all)).unwrap();
        assert_eq!(
            cfg.test_quota,
            Some(QuotaLimits {
                window_ms: 5000,
                max_ops: 7,
                max_bytes: 1024
            })
        );
        let mut partial = base.to_vec();
        partial.push(("TEST_QUOTA_OPS", "7"));
        assert!(WorkerConfig::from_vars(vars(&partial)).is_err());
    }

    /// `final-chunk` arms the blob store once per operation; `after-reserve`
    /// and `after-put` fail once per operation through `FailOnce`.
    #[cfg(feature = "test-faults")]
    #[test]
    fn worker_faults_fire_once_per_operation() {
        use mkit_core::protocol::PackKey;
        use mkit_core::write_auth::Authorized;
        use mkit_server::pipeline::{FaultHooks, FaultPoint, TestDirectives};
        use mkit_server::{
            NamespaceKey, OpKind, Operation, Principal, RepoId, RepoName, VerifiedAuth,
        };

        let op = |scope: u8| {
            let hex = |b: u8| format!("{b:02x}").repeat(32);
            let authorized = Authorized {
                scope: hex(scope),
                public_key: hex(1),
                nonce: hex(0),
                fingerprint: hex(2),
                commitment: format!("pack:{}:1", hex(3)),
                expires_at: 1,
            };
            let auth = VerifiedAuth::try_from(&authorized).unwrap();
            let repo = RepoId {
                namespace: NamespaceKey::deployment_default(),
                name: RepoName::new("default").unwrap(),
            };
            let kind = OpKind::UploadPack {
                key: PackKey::new([3; 32]),
                declared_len: 1,
            };
            Operation::new(repo, Principal::Anonymous, Some(auth), kind)
        };
        let directives = |fault: &str| TestDirectives {
            fault: Some(fault.to_owned()),
            clock_skew_ms: 0,
            ..TestDirectives::default()
        };
        let armed = Arc::new(AtomicUsize::new(0));
        let counter = armed.clone();
        let faults = WorkerFaults::new(Arc::default(), move || {
            counter.fetch_add(1, Ordering::SeqCst);
        });
        let at = |point, op: &Operation, fault| block_on(faults.at(point, op, &directives(fault)));
        // `final-chunk` never fails the hook itself: it arms the store.
        for _ in 0..2 {
            at(FaultPoint::AfterReserve, &op(1), FINAL_CHUNK_FAULT).unwrap();
        }
        assert_eq!(armed.load(Ordering::SeqCst), 1, "once per operation");
        at(FaultPoint::AfterReserve, &op(2), FINAL_CHUNK_FAULT).unwrap();
        assert_eq!(armed.load(Ordering::SeqCst), 2, "again for another one");
        at(FaultPoint::AfterAuthorize, &op(3), FINAL_CHUNK_FAULT).unwrap();
        assert_eq!(armed.load(Ordering::SeqCst), 2, "only at the reservation");
        // vcs-worker's tokens: the first attempt fails, its retry passes.
        for (point, token) in [
            (FaultPoint::AfterReserve, "after-reserve"),
            (FaultPoint::AfterBlobCommit, "after-put"),
        ] {
            assert!(at(point, &op(4), token).is_err());
            at(point, &op(4), token).unwrap();
        }
    }

    #[test]
    fn plan_capacity_defaults_to_free() {
        let free = Capacity::new(DO_FREE_MAX_BYTES);
        assert_eq!(plan_capacity(None).unwrap(), free);
        assert_eq!(plan_capacity(Some("free")).unwrap(), free);
        assert_eq!(plan_capacity(Some(" Paid ")).unwrap(), DO_CAPACITY);
        let (err, fallback) = plan_capacity(Some("enterprise")).unwrap_err();
        assert!(err.0.contains("enterprise"), "{err}");
        assert_eq!(fallback, free);
    }

    type Chunks = Vec<Result<Frame<Bytes>, BodyError>>;
    type Frames =
        StreamBody<futures::stream::Iter<std::vec::IntoIter<Result<Frame<Bytes>, BodyError>>>>;

    fn frames(chunks: &[&[u8]]) -> Frames {
        let items: Chunks = chunks
            .iter()
            .map(|c| Ok(Frame::data(Bytes::copy_from_slice(c))))
            .collect();
        StreamBody::new(futures::stream::iter(items))
    }

    #[test]
    fn limited_body_passes_frames_through_and_records_the_peak() {
        let peak = BodyWatch::default();
        let body = LimitedBody::new(frames(&[b"abc", b"defgh", b"ij"]), 10, peak.clone());
        let out = block_on(body.collect()).unwrap().to_bytes();
        assert_eq!(&out[..], b"abcdefghij");
        assert_eq!(peak.peak(), 5, "the largest frame, never the total");
    }

    #[test]
    fn limited_body_fails_past_the_cap_and_then_ends() {
        let peak = BodyWatch::default();
        let mut body = LimitedBody::new(frames(&[b"abc", b"defgh", b"ij"]), 7, peak);
        let first = block_on(body.frame()).unwrap().unwrap();
        assert_eq!(first.into_data().unwrap(), Bytes::from_static(b"abc"));
        let err = block_on(body.frame()).unwrap().unwrap_err();
        assert_eq!(err, BodyError::TooLarge { limit: 7 });
        assert!(block_on(body.frame()).is_none());
        assert!(body.is_end_stream());
    }

    #[test]
    fn limited_body_maps_read_errors() {
        let items: Chunks = vec![Err(BodyError::Read("reset".into()))];
        let inner = StreamBody::new(futures::stream::iter(items));
        let mut body = LimitedBody::new(inner, 10, BodyWatch::default());
        let err = block_on(body.frame()).unwrap().unwrap_err();
        assert!(
            matches!(err, BodyError::Read(ref d) if d.contains("reset")),
            "{err}"
        );
    }

    #[test]
    fn measured_body_records_response_frames() {
        static REPORTED: AtomicUsize = AtomicUsize::new(0);
        fn report(n: usize) {
            REPORTED.store(n, Ordering::SeqCst);
        }
        let peak = BodyWatch::default();
        peak.record(3);
        let full = Full::new(Bytes::from_static(b"12345678"));
        let body = MeasuredBody::new(full, peak.clone(), Some(Box::new(report)));
        let out = block_on(body.collect()).unwrap().to_bytes();
        assert_eq!(out.len(), 8);
        assert_eq!(peak.peak(), 8);
        // Collecting consumed (dropped) the body: the peak was reported.
        assert_eq!(REPORTED.load(Ordering::SeqCst), 8);
    }

    #[test]
    fn default_body_cap_leaves_room_for_framing() {
        assert!(DEFAULT_MAX_BODY_BYTES as u64 > SINGLE_PUT_MAX_BYTES);
        assert!(body_too_large_json(5).contains("resource_exhausted"));
        let v: serde_json::Value = serde_json::from_str(&unavailable_json("a \"b\"")).unwrap();
        assert_eq!(v["code"], "unavailable");
        assert_eq!(v["message"], "a \"b\"");
    }

    #[test]
    fn worker_refuses_indexed_mode_until_async_driver() {
        for value in ["true", "1", "yes", "on"] {
            let err =
                WorkerConfig::from_vars(|name| (name == "INDEXED_MODE").then(|| value.to_owned()))
                    .unwrap_err();
            assert!(
                err.to_string()
                    .contains("indexed mode on Workers requires WP-4.8"),
                "{value}"
            );
        }
    }

    /// The Connect binding over memory stores, open auth, 1 MiB packs.
    fn open_service() -> connectrpc::ConnectRpcService {
        use mkit_server::pipeline::{AuthMode, Hooks, Pipeline, PipelineConfig};
        use mkit_server::upload::UploadLimits;
        use mkit_server::{
            Addressing, MemoryBlobStore, MemoryKv, NamespaceKey, NoopMetrics, RepoId, RepoName,
            SystemClock,
        };

        let repo = RepoId {
            namespace: NamespaceKey::deployment_default(),
            name: RepoName::new("default").unwrap(),
        };
        let limits = UploadLimits {
            max_total_bytes: 1 << 20,
            max_chunks: 64,
        };
        let cfg = PipelineConfig::new(Addressing::Single { repo }, AuthMode::Open, limits);
        let pipe = Pipeline::new(
            MemoryBlobStore::default(),
            MemoryKv::default(),
            Hooks::new(),
            cfg,
            Arc::new(SystemClock),
            Arc::new(NoopMetrics),
        )
        .unwrap();
        mkit_server::connect::service(Arc::new(pipe))
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    /// A streaming request body reaches the service unbuffered: the Connect
    /// binding answers a unary RPC read from a multi-frame body.
    #[test]
    fn dispatch_streams_a_request_body_into_the_connect_binding() {
        let svc = open_service();
        let peak = BodyWatch::default();
        let body = LimitedBody::new(
            frames(&[b"{\"name\":", b"\"refs/heads/main\"}"]),
            1024,
            peak.clone(),
        );
        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri("http://w.example/mkit.transport.v1.TransportService/ReadRef")
            .header("content-type", "application/json")
            .header("connect-protocol-version", "1")
            .body(body)
            .unwrap();
        let runtime = runtime();
        let resp = runtime.block_on(dispatch_oneshot_body(svc, req));
        assert_eq!(resp.status(), 200);
        let out = runtime
            .block_on(resp.into_body().collect())
            .unwrap()
            .to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_ne!(
            v.get("exists").and_then(serde_json::Value::as_bool),
            Some(true),
            "{v}"
        );
        assert_eq!(peak.peak(), b"\"refs/heads/main\"}".len());
    }

    /// One Connect streaming envelope around a JSON message.
    fn envelope(msg: &serde_json::Value) -> Vec<u8> {
        let json = msg.to_string().into_bytes();
        let mut out = vec![0];
        out.extend_from_slice(&u32::try_from(json.len()).unwrap().to_be_bytes());
        out.extend_from_slice(&json);
        out
    }

    /// A chunked (no `Content-Length`) `UploadPack` body that runs past the
    /// cap while its data stays within the declared size: connectrpc
    /// answers the failed read as an error of its own, and the adapter's
    /// watch has tripped by the time the response is back, so it answers
    /// 400 `resource_exhausted` as for a `Content-Length` over the cap.
    #[test]
    fn a_chunked_body_over_the_cap_is_resource_exhausted() {
        use base64::Engine as _;
        use base64::engine::general_purpose::STANDARD;

        const LIMIT: usize = 4096;
        let pack: Vec<u8> = (0..=255_u8).cycle().take(64 * 1024).collect();
        let id = STANDARD.encode(mkit_core::hash::hash(&pack));
        let mut messages: Vec<Vec<u8>> = vec![envelope(&serde_json::json!({
            "header": { "packId": id, "totalBytes": pack.len().to_string() }
        }))];
        for (i, data) in pack.chunks(1024).enumerate() {
            messages.push(envelope(&serde_json::json!({ "chunk": {
                "packId": id,
                "offset": (i * 1024).to_string(),
                "data": STANDARD.encode(data),
                "last": (i + 1) * 1024 == pack.len(),
            }})));
        }
        let parts: Vec<&[u8]> = messages.iter().map(Vec::as_slice).collect();
        let watch = BodyWatch::default();
        let body = LimitedBody::new(frames(&parts), LIMIT, watch.clone());
        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri("http://w.example/mkit.transport.v1.TransportService/UploadPack")
            .header("content-type", "application/connect+json")
            .header("connect-protocol-version", "1")
            .body(body)
            .unwrap();
        assert!(!req.headers().contains_key(http::header::CONTENT_LENGTH));
        let runtime = runtime();
        let resp = runtime.block_on(dispatch_oneshot_body(open_service(), req));
        assert!(watch.too_large(), "the cap tripped before the response");
        let connect = runtime
            .block_on(resp.into_body().collect())
            .unwrap()
            .to_bytes();
        let connect = String::from_utf8_lossy(&connect);
        assert!(!connect.contains("resource_exhausted"), "{connect}");
        let (status, json) = over_cap_response(&watch, LIMIT).unwrap();
        assert_eq!(status, 400);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["code"], "resource_exhausted");
        // Under the cap nothing is replaced.
        assert_eq!(over_cap_response(&BodyWatch::default(), LIMIT), None);
    }
}
