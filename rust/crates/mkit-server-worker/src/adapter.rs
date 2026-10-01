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
//!   `ListRefs` page is held whole (about 45 bytes per ref, with a
//!   128-ref page cap for the Uno launch). A unary response connectrpc compressed
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
//! (`AUTH_REPOSITORY`) in the deployment-default namespace and the Worker clock.
//! `MAX_PACK_BYTES` defaults to 1 GiB; resumable parts carry larger packs.
//! The Paid Uno launch selects Multi/D34 and scheduled indexed verification.
//! It is built per request from the request's `Env`: building it costs no
//! I/O.
//!
//! **Test faults** (`test-faults` only): the pipeline gets
//! `WorkerFaults`, `GET /__mkit_test/stats` answers the default
//! partition's size (under D34, that of the ref shard `?ref=<name>` names),
//! `TEST_QUOTA_*` vars replace the write quota, `TEST_TICKET_TTL_MS`
//! shortens the ticket lifetime, and each
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
/// Visibility when no explicit repository visibility is stored.
pub const DEFAULT_REPO_VISIBILITY_VAR: &str = "DEFAULT_REPO_VISIBILITY";
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
/// The Worker var that turns indexed mode on in the Paid launch profile.
pub const INDEXED_MODE_VAR: &str = "INDEXED_MODE";
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

/// Request headers a browser may send besides
/// [`mkit_server::auth_v2::CORS_ALLOW_HEADERS`]: a bearer or payment
/// credential and the payment preference (SPEC-TRANSPORT-CONNECT §5.1).
pub const CORS_PAYMENT_ALLOW_HEADERS: [&str; 4] = [
    "authorization",
    "payment-authorization",
    "payment-signature",
    "accept-payment",
];

/// `Access-Control-Allow-Headers` of a preflight: the auth v2 list plus
/// [`CORS_PAYMENT_ALLOW_HEADERS`], each name once.
#[must_use]
pub fn cors_allow_headers() -> String {
    let base = mkit_server::auth_v2::CORS_ALLOW_HEADERS;
    let extra = CORS_PAYMENT_ALLOW_HEADERS.iter().filter(|name| {
        !base
            .split(',')
            .any(|have| have.trim().eq_ignore_ascii_case(name))
    });
    core::iter::once(base)
        .chain(extra.copied())
        .collect::<Vec<_>>()
        .join(", ")
}

/// `Access-Control-Expose-Headers` of every response: the admission
/// challenge and receipt headers a browser client must read.
#[must_use]
pub fn cors_expose_headers() -> String {
    mkit_server::pipeline::ADMISSION_EXPOSE_HEADERS.join(", ")
}

/// How to copy `headers` onto a runtime response: `(name, value, append)`.
/// A name's first value is `set` (replacing anything the runtime added) and
/// each further value of the same name is appended, so repeated fields such
/// as several `WWW-Authenticate` challenges all reach the client. Values that
/// are not UTF-8 are skipped.
#[must_use]
pub fn response_header_plan(headers: &http::HeaderMap) -> Vec<(String, String, bool)> {
    let mut seen = std::collections::BTreeSet::new();
    headers
        .iter()
        .filter_map(|(name, value)| {
            let value = value.to_str().ok()?;
            let append = !seen.insert(name.as_str().to_owned());
            Some((name.as_str().to_owned(), value.to_owned(), append))
        })
        .collect()
}

/// Deployment settings read from the Worker's vars.
#[derive(Debug, Clone)]
#[cfg_attr(not(feature = "http-objects"), derive(PartialEq, Eq))]
#[non_exhaustive]
pub struct WorkerConfig {
    /// Explicit Paid indexed launch selection; absent retains the default adapter.
    pub launch: Option<crate::launch::LaunchConfig>,
    /// Default-off signed operator keys, independent of client credentials.
    pub admin: Option<mkit_server::admin::Config>,
    /// Mount `AdminService` on public fetch; false leaves only `serve_admin_with`.
    /// Programmatic only; operator authentication is unchanged in either mode.
    pub admin_on_public_path: bool,
    /// Programmatic ref signer and fast-forward rules; no environment grammar.
    pub ref_policy: Option<mkit_server::policy::RefPolicy>,
    /// Programmatic global takedown denial; requires complete preservation.
    pub takedown_denial: bool,
    /// An embedder's actual purge sink and local invalidation, instead of HTTPS.
    pub custom_purge: Option<crate::embedding::PurgeHooks>,
    /// Default-off restricted preservation configuration.
    pub takedown: Option<crate::admin::TakedownSettings>,
    /// Default-off private scanner retrieval, available only to Paid inspection.
    pub scanner_retrieval: Option<Arc<mkit_server::scanner_retrieval::RetrievalConfig>>,
    /// Optional dedicated deployment-authority keys (`AUTHORITY_FENCE`, `AUTHORITY_KEYS`).
    pub authority_fence: Option<mkit_server::authority::AuthorityFence>,
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
    /// `DEFAULT_REPO_VISIBILITY`: public (default) or private for missing visibility rows.
    /// Read gating applies to Multi deployments with Owner write policy.
    pub default_repo_visibility: mkit_server::pipeline::RepoVisibility,
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
    /// Indexed mode with scheduled verification and extraction, selected by
    /// the explicit Paid launch profile (or a local test-faults configuration).
    pub indexed: Option<mkit_server::indexed::IndexedConfig>,
    /// `HOOK_ROLES`, `HOOK_TIMEOUT_MS` and `AUTHORIZER_ROLE`: which stages
    /// call the hook Worker over the `ADMISSION_HOOK` service binding. `None`
    /// runs the built-in hooks (WP-3.9).
    pub hooks: Option<crate::hooks::config::HookVars>,
    /// Explicit indexed HTTP configuration and route opt-in.
    #[cfg(feature = "http-objects")]
    pub http_mount: Option<crate::http_mount::WorkerHttpMountConfig>,
    /// Feature-gated `URL_TOKEN_KEYS`/`URL_TOKEN_TTL`; no mount is enabled by these vars.
    #[cfg(feature = "http-objects")]
    pub url_tokens: Option<mkit_server::url_token::UrlTokenConfig>,
    /// Programmatic snapshot opt-in; environment parsing always leaves None.
    #[cfg(feature = "published-view")]
    pub published_view: Option<crate::published_view::PublishedViewConfig>,
    /// `TEST_QUOTA_OPS`, `TEST_QUOTA_BYTES` and `TEST_QUOTA_WINDOW_MS`,
    /// when all three are set: the write quota instead of the default
    /// (`test-faults` builds only, for the wire suite's quota and growth
    /// cases).
    #[cfg(feature = "test-faults")]
    pub test_quota: Option<QuotaLimits>,
    /// Test-only outbox row threshold; absent in release builds.
    #[cfg(feature = "test-faults")]
    pub test_outbox_rows: Option<u64>,
    /// `TEST_TICKET_TTL_MS`: the upload ticket lifetime instead of the
    /// default 24 hours (`test-faults` builds only, so the growth case can
    /// wait out real ticket expiry).
    #[cfg(feature = "test-faults")]
    pub test_ticket_ttl_ms: Option<u64>,
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
    pub(crate) fn pipeline_config(
        &self,
    ) -> Result<mkit_server::pipeline::PipelineConfig, ConfigError> {
        use mkit_server::auth_v2::AuthV2Config;
        use mkit_server::pipeline::{AuthMode, PipelineConfig};
        use mkit_server::upload::UploadLimits;

        crate::launch::validate_programmatic(self)?;
        #[cfg(feature = "published-view")]
        if let Some(config) = &self.published_view {
            crate::published_view::PublishedViewConfig::new(config.deployment.clone())
                .map_err(|e| ConfigError(e.to_string()))?;
            if self.sharding != Sharding::D34
                || !matches!(self.addressing, mkit_server::Addressing::Multi(_))
            {
                return Err(ConfigError("published-view requires Multi and D34".into()));
            }
        }
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
        #[cfg(feature = "published-view")]
        if self.published_view.is_some() {
            config.max_list_refs_page_size = config.max_list_refs_page_size.min(128);
        }
        config.single_upload_max_bytes = Some(SINGLE_PUT_MAX_BYTES);
        config.sharding = self.sharding;
        config.default_repo_visibility = self.default_repo_visibility;
        config.ticket_keys.clone_from(&self.ticket_keys);
        config.authority_fence.clone_from(&self.authority_fence);
        config.scanner_retrieval.clone_from(&self.scanner_retrieval);
        config.admin_keys = self
            .admin
            .as_ref()
            .map_or_else(Vec::new, mkit_server::admin::Config::public_keys);
        config.receipt_publication = self.takedown.as_ref().map(|s| s.publication.clone());
        if let Some(settings) = &self.takedown {
            config
                .admin_keys
                .extend_from_slice(settings.publication.public_keys());
        }
        config.indexed = self.indexed;
        config.ref_policy.clone_from(&self.ref_policy);
        config.takedown_denial = self.takedown_denial;
        if self.launch.is_some() {
            config.begin_upload_threshold_bytes = 0;
        }
        #[cfg(feature = "http-objects")]
        if let Some(mount) = &self.http_mount {
            config.indexed = Some(mount.indexed);
            config.http_objects = Some(mount.http_objects);
            config.url_tokens.clone_from(&self.url_tokens);
        }
        config.indexed = config.indexed.map(|mut indexed| {
            indexed.max_ancestry_commits = indexed.max_ancestry_commits.min(64);
            indexed
        });
        if let Some(policy) = &config.ref_policy {
            policy
                .validate_for_indexed(config.indexed.is_some())
                .map_err(|e| bad(&e))?;
        }
        self.configure_hooks_and_purge(&mut config)?;
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
        #[cfg(feature = "test-faults")]
        {
            if let Some(rows) = self.test_outbox_rows {
                config.outbox_backlog_cap = Some(mkit_server::pipeline::OutboxBacklogCap {
                    rows,
                    bytes: u64::MAX,
                });
            }
            if let Some(ttl) = self.test_ticket_ttl_ms {
                config.ticket_ttl_ms = ttl;
            }
        }
        mkit_server::scanner_retrieval::validate_config(&config).map_err(|error| bad(&error))?;
        Ok(config)
    }

    fn configure_hooks_and_purge(
        &self,
        config: &mut mkit_server::pipeline::PipelineConfig,
    ) -> Result<(), ConfigError> {
        if let Some(hooks) = &self.hooks {
            config.authorizer_role = hooks.authorizer_role;
            if hooks.roles.inspect {
                if config.indexed.is_none()
                    || config.ticket_keys.is_none()
                    || config.write_policy == mkit_server::policy::WritePolicy::Open
                {
                    return Err(ConfigError("inspection requires indexed mode, restricted writes and upload ticket keys".into()));
                }
                config.begin_upload_threshold_bytes = 0;
            }
            if hooks.roles.cache_purge {
                config.purge = Some(mkit_server::purge::PurgeConfig::new(
                    self.audience.clone(),
                    true,
                    true,
                ));
            }
        }
        if let Some(purge) = &self.custom_purge {
            config.purge = Some(
                mkit_server::purge::PurgeConfig::new(self.audience.clone(), true, true)
                    .with_local(purge.local.clone()),
            );
        }
        Ok(())
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
    #[allow(clippy::too_many_lines)] // Resolves the deployment fields together; authority statement grammar is factored separately.
    pub fn from_vars(var: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let cfg = Self::parse_vars(&var)?;
        Ok(cfg)
    }

    /// Parse with an actual custom purger as the alternative to signed HTTPS.
    /// # Errors
    /// Incomplete configuration, key role conflicts or unavailable prerequisites.
    pub fn from_vars_with_purge(
        var: impl Fn(&str) -> Option<String>,
        purge: crate::embedding::PurgeHooks,
    ) -> Result<Self, ConfigError> {
        let cfg = Self::parse_vars_with_purge(&var, Some(purge))?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Validate programmatic changes before accepting requests or constructing DOs.
    /// # Errors
    /// Invalid policy, incomplete opt-ins or unavailable prerequisites.
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.pipeline_config().map(|_| ())
    }

    #[cfg(target_arch = "wasm32")]
    fn validate_runtime(&self, env: &worker::Env) -> Result<(), ConfigError> {
        self.validate()?;
        crate::launch::validate_runtime_key_material(self, &|name| {
            env.secret(name).ok().map(|secret| secret.to_string())
        })?;
        self.validate_for_plan(env.var(PLAN_VAR).ok().map(|v| v.to_string()).as_deref())?;
        crate::hooks::build::hooks_from_env(env, self)?;
        if self.launch.is_some() {
            env.bucket(self.blob_binding)
                .map_err(|_| ConfigError("launch requires configured serving R2 binding".into()))?;
            for binding in [
                "REFSTORE",
                "NS_COORD",
                "REF_SHARD",
                "REPO_INDEX",
                "CONTENT_INDEX",
            ] {
                env.durable_object(binding).map_err(|_| {
                    ConfigError(format!("launch requires {binding} Durable Object binding"))
                })?;
            }
        }
        if let Some(settings) = &self.takedown {
            env.bucket(crate::admin::PRESERVATION_BINDING)
                .map_err(|_| ConfigError("PRESERVATION binding required".into()))?;
            if self.blob_binding == crate::admin::PRESERVATION_BINDING {
                return Err(ConfigError(
                    "preservation binding must differ from serving storage".into(),
                ));
            }
            if let Some(http) = self.hooks.as_ref().and_then(|hooks| hooks.http.as_ref()) {
                crate::hooks::config::http_signer(
                    env.secret("MKIT_HOOK_KEY").ok().map(|s| s.to_string()),
                    http,
                    self.ticket_keys.as_ref(),
                    settings.publication.public_keys(),
                )?;
            }
        }

        Ok(())
    }

    #[cfg(any(target_arch = "wasm32", test))]
    pub(crate) fn validate_for_plan(&self, plan: Option<&str>) -> Result<(), ConfigError> {
        if (self.launch.is_some()
            || self.indexed.is_some()
            || self.custom_purge.is_some()
            || self.takedown.is_some())
            && !plan.is_some_and(|plan| plan.trim().eq_ignore_ascii_case("paid"))
        {
            return Err(ConfigError(
                "configured indexed launch, takedown or custom purge requires WORKERS_PLAN=paid"
                    .into(),
            ));
        }
        Ok(())
    }

    // Parse deployment grammar before runtime binding checks.
    #[allow(clippy::too_many_lines)]
    pub(crate) fn parse_vars(var: &impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        Self::parse_vars_with_purge(var, None)
    }

    #[allow(clippy::too_many_lines)]
    fn parse_vars_with_purge(
        var: &impl Fn(&str) -> Option<String>,
        custom_purge: Option<crate::embedding::PurgeHooks>,
    ) -> Result<Self, ConfigError> {
        let indexed_requested = var(INDEXED_MODE_VAR).is_some_and(|value| {
            !value.is_empty() && value != "0" && !value.eq_ignore_ascii_case("false")
        });
        let launch = crate::launch::LaunchConfig::parse(&var)?;
        #[cfg(not(feature = "test-faults"))]
        if indexed_requested && launch.is_none() {
            return Err(ConfigError(
                "INDEXED_MODE requires LAUNCH_PROFILE=uno".into(),
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
        let default_repo_visibility = match var(DEFAULT_REPO_VISIBILITY_VAR).as_deref() {
            None | Some("public") => mkit_server::pipeline::RepoVisibility::Public,
            Some("private") => mkit_server::pipeline::RepoVisibility::Private,
            Some(_) => {
                return Err(ConfigError(
                    "DEFAULT_REPO_VISIBILITY must be public or private".into(),
                ));
            }
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
        let indexed = resolve_indexed(
            indexed_requested,
            var(PLAN_VAR).as_deref(),
            multi,
            sharding,
            ticket_keys.is_some(),
            max_pack_bytes,
        )?;
        #[cfg(feature = "http-objects")]
        let url_tokens = crate::http_mount::token_config_for_tickets(&var, ticket_keys.as_ref())?;
        let admin = crate::admin::parse(&var, &audience, ticket_keys.as_ref())?;
        let hooks = crate::hooks::config::HookVars::parse(&var)?;
        let takedown = crate::admin::takedown(
            &var,
            admin.as_ref(),
            indexed.is_some(),
            &addressing,
            var(PLAN_VAR).is_some_and(|p| p.trim().eq_ignore_ascii_case("paid")),
            ticket_keys.as_ref(),
        )?;
        if hooks.as_ref().is_some_and(|hooks| hooks.roles.cache_purge)
            && !var(PLAN_VAR).is_some_and(|plan| plan.trim().eq_ignore_ascii_case("paid"))
        {
            return Err(ConfigError("cache-purge requires WORKERS_PLAN=paid".into()));
        }
        if hooks.as_ref().is_some_and(|hooks| hooks.roles.inspect)
            && (indexed.is_none()
                || !multi
                || ticket_keys.is_none()
                || !var(PLAN_VAR).is_some_and(|plan| plan.trim().eq_ignore_ascii_case("paid")))
        {
            return Err(ConfigError(
                "inspection requires Paid indexed mode, restricted writes and upload ticket keys"
                    .into(),
            ));
        }
        let scanner_retrieval = crate::scanner_retrieval::parse(
            &var,
            indexed.is_some(),
            hooks.as_ref().is_some_and(|h| h.roles.inspect),
        )?;
        let authority_fence = resolve_authority_fence(&var, multi, hooks.as_ref())?;
        if let Some(fence) = &authority_fence
            && fence.public_keys().any(|key| {
                ticket_keys
                    .as_ref()
                    .is_some_and(|tickets| tickets.contains_ed25519_public(&key))
            })
        {
            return Err(ConfigError(
                "authority keys must differ from ticket keys".into(),
            ));
        }
        #[cfg(feature = "http-objects")]
        if let Some(fence) = &authority_fence
            && fence.public_keys().any(|key| {
                url_tokens
                    .as_ref()
                    .is_some_and(|tokens| tokens.keys().public_keys().any(|public| public == key))
            })
        {
            return Err(ConfigError(
                "authority keys must differ from URL-token keys".into(),
            ));
        }
        if let (Some(admin), Some(fence)) = (&admin, &authority_fence) {
            admin
                .check_separation(&fence.public_keys().collect::<Vec<_>>())
                .map_err(|_| ConfigError("ADMIN_KEYS must differ from authority keys".into()))?;
        }
        #[cfg(feature = "http-objects")]
        if let (Some(admin), Some(tokens)) = (&admin, &url_tokens) {
            admin
                .check_separation(&tokens.keys().public_keys().collect::<Vec<_>>())
                .map_err(|_| ConfigError("ADMIN_KEYS must differ from URL-token keys".into()))?;
        }
        if let Some(settings) = &takedown {
            let published = settings.publication.public_keys();
            if audience.len() > 2048
                || authority_fence
                    .as_ref()
                    .is_some_and(|f| f.public_keys().any(|key| published.contains(&key)))
            {
                return Err(ConfigError(
                    "invalid receipt origin or overlapping authority key".into(),
                ));
            }
            #[cfg(feature = "http-objects")]
            if url_tokens
                .as_ref()
                .is_some_and(|t| t.keys().public_keys().any(|key| published.contains(&key)))
            {
                return Err(ConfigError("receipt key repeats URL-token key".into()));
            }
        }
        let mut cfg = Self {
            admin_on_public_path: true,
            ref_policy: None,
            takedown_denial: launch.as_ref().is_some_and(|cfg| cfg.takedown),
            custom_purge,
            launch,
            takedown,
            admin,
            scanner_retrieval,
            authority_fence,
            indexed,
            sharding,
            placement,
            audience,
            repository,
            addressing,
            default_repo_visibility,
            ticket_keys,
            max_pack_bytes,
            grants,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            blob_binding: crate::r2::STORAGE_BINDING,
            hooks,
            #[cfg(feature = "http-objects")]
            http_mount: None,
            #[cfg(feature = "http-objects")]
            url_tokens,
            #[cfg(feature = "published-view")]
            published_view: None,
            #[cfg(feature = "test-faults")]
            test_quota: test_quota(&var)?,
            #[cfg(feature = "test-faults")]
            test_outbox_rows: test_number(&var, "TEST_OUTBOX_BACKLOG_ROWS", 16)?,
            #[cfg(feature = "test-faults")]
            test_ticket_ttl_ms: test_ticket_ttl(&var)?,
        };
        crate::launch::validate(&mut cfg, &var)?;
        if cfg.scanner_retrieval.is_some() {
            cfg.pipeline_config()?;
        }
        Ok(cfg)
    }

    /// The settings from `env`'s vars.
    ///
    /// # Errors
    /// As [`Self::from_vars`].
    #[cfg(target_arch = "wasm32")]
    pub fn from_env(env: &worker::Env) -> Result<Self, ConfigError> {
        Self::from_env_using_purge(env, None)
    }

    /// Parse bindings and opt-ins with a custom purger configured at startup.
    /// # Errors
    /// As `from_env`; admin catalog exposure still waits for its prerequisite.
    #[cfg(target_arch = "wasm32")]
    pub fn from_env_with_purge(
        env: &worker::Env,
        purge: crate::embedding::PurgeHooks,
    ) -> Result<Self, ConfigError> {
        Self::from_env_using_purge(env, Some(purge))
    }

    #[cfg(target_arch = "wasm32")]
    fn from_env_using_purge(
        env: &worker::Env,
        purge: Option<crate::embedding::PurgeHooks>,
    ) -> Result<Self, ConfigError> {
        let cfg = Self::parse_vars_with_purge(
            &|name| {
                if name == crate::admin::RECEIPT_SECRET {
                    return env.secret(name).ok().map(|secret| secret.to_string());
                }
                env.secret(name)
                    .ok()
                    .map(|secret| secret.to_string())
                    .or_else(|| env.var(name).ok().map(|value| value.to_string()))
            },
            purge,
        )?;
        crate::hooks::config::HookVars::check_binding(
            cfg.hooks.as_ref(),
            env.service(crate::hooks::config::BINDING).is_ok(),
        )?;
        if cfg.launch.is_some() {
            if env.bucket(cfg.blob_binding).is_err() {
                return Err(ConfigError("launch requires STORAGE R2 binding".into()));
            }
            for binding in [
                "REFSTORE",
                "NS_COORD",
                "REF_SHARD",
                "REPO_INDEX",
                "CONTENT_INDEX",
            ] {
                if env.durable_object(binding).is_err() {
                    return Err(ConfigError(format!(
                        "launch requires {binding} Durable Object binding"
                    )));
                }
            }
        }
        if let Some(settings) = &cfg.takedown {
            if let Some(http) = cfg.hooks.as_ref().and_then(|hooks| hooks.http.as_ref()) {
                crate::hooks::config::http_signer(
                    env.secret("MKIT_HOOK_KEY").ok().map(|s| s.to_string()),
                    http,
                    cfg.ticket_keys.as_ref(),
                    settings.publication.public_keys(),
                )?;
            }
            env.bucket(crate::admin::PRESERVATION_BINDING)
                .map_err(|_| ConfigError("PRESERVATION binding required".into()))?;
            if cfg.blob_binding == crate::admin::PRESERVATION_BINDING {
                return Err(ConfigError(
                    "preservation binding must differ from serving storage".into(),
                ));
            }
        }
        Ok(cfg)
    }
}

fn resolve_authority_fence(
    var: &impl Fn(&str) -> Option<String>,
    multi: bool,
    hooks: Option<&crate::hooks::config::HookVars>,
) -> Result<Option<mkit_server::authority::AuthorityFence>, ConfigError> {
    let enabled = match var("AUTHORITY_FENCE").as_deref() {
        None | Some("false") => false,
        Some("true") => true,
        _ => return Err(ConfigError("AUTHORITY_FENCE must be true or false".into())),
    };
    let keys = var("AUTHORITY_KEYS");
    if enabled != keys.is_some() {
        return Err(ConfigError(
            "AUTHORITY_FENCE and AUTHORITY_KEYS must be configured together".into(),
        ));
    }
    let authority_fence = keys
        .map(|keys| {
            mkit_server::authority::AuthorityFence::parse(&keys)
                .map_err(|_| ConfigError("AUTHORITY_KEYS is invalid".into()))
        })
        .transpose()?;
    if enabled
        && (!multi
            || hooks.is_none_or(|hooks| {
                !hooks.roles.authorize
                    || hooks.authorizer_role != mkit_server::policy::AuthorizerRole::Authority
            }))
    {
        return Err(ConfigError(
            "authority fencing requires Multi and an Authority hook".into(),
        ));
    }
    Ok(authority_fence)
}

/// The indexed configuration `INDEXED_MODE` asks for: scheduled verification
/// (WP-4.8), which needs a Paid plan (a slice spends about 256 of an alarm's
/// 1,000 subrequests; Free's 50 are all assigned, R-147), D34 (the slices run
/// on ref shards), Multi addressing and upload tickets. Release activation
/// additionally requires the explicit Uno launch selection in `from_vars`.
fn resolve_indexed(
    requested: bool,
    plan: Option<&str>,
    multi: bool,
    sharding: Sharding,
    has_ticket_keys: bool,
    max_pack_bytes: u64,
) -> Result<Option<mkit_server::indexed::IndexedConfig>, ConfigError> {
    if !requested {
        return Ok(None);
    }
    if !plan.is_some_and(|plan| plan.trim().eq_ignore_ascii_case("paid")) {
        return Err(ConfigError(
            "INDEXED_MODE requires WORKERS_PLAN=paid: scheduled verification does not fit a \
             Free alarm's 50 subrequests"
                .into(),
        ));
    }
    if !multi || sharding != Sharding::D34 || !has_ticket_keys {
        return Err(ConfigError(
            "INDEXED_MODE requires ADDRESSING=multi, SHARDING=d34 and TICKET_KEYS".into(),
        ));
    }
    Ok(Some(mkit_server::indexed::IndexedConfig::scheduled(
        max_pack_bytes,
    )))
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

#[cfg(feature = "test-faults")]
fn test_number(
    var: &impl Fn(&str) -> Option<String>,
    name: &str,
    max: u64,
) -> Result<Option<u64>, ConfigError> {
    var(name)
        .map(|value| {
            value
                .trim()
                .parse::<u64>()
                .ok()
                .filter(|n| *n > 0 && *n <= max)
                .ok_or_else(|| ConfigError(format!("{name} is outside its test range")))
        })
        .transpose()
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

/// `TEST_TICKET_TTL_MS`: a positive lifetime in milliseconds, or unset.
#[cfg(feature = "test-faults")]
fn test_ticket_ttl(var: &impl Fn(&str) -> Option<String>) -> Result<Option<u64>, ConfigError> {
    test_number(var, "TEST_TICKET_TTL_MS", 60_000)
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
    timer_registry_budgeted(class, target, plan, None, None, None, None)
}

#[allow(
    clippy::too_many_lines,
    reason = "Keep allocated timer ownership together"
)]
fn timer_registry_budgeted<
    S: mkit_server::NamespaceStore,
    T: mkit_server::NamespaceStore + 'static,
>(
    class: crate::classes::ShardClass,
    target: Result<T, ConfigError>,
    plan: Option<&str>,
    alarm_budget: Option<&mkit_server::purge::SliceBudget>,
    takedown_root: Option<&mkit_server::Partition>,
    relay_root: Option<&mkit_server::Partition>,
    purge: Option<&mkit_server::purge::PurgeConfig>,
) -> mkit_server::timers::TimerRegistry<'static, S> {
    use crate::classes::ShardClass;
    use mkit_server::relay::{RelayBudget, RelayHandler};
    use mkit_server::timers::{TimerRegistry, lease_sweep::LeaseSweep};

    // One target client serves the class's relay or lease sweep and its rollup.
    let target = target.map(|store| SharedStore(Arc::new(store), alarm_budget.cloned()));
    let registry = TimerRegistry::new();
    let registry = match class {
        ShardClass::NsCoordinator => {
            let source = match target.clone() {
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
        ShardClass::ContentIndexShard => match (takedown_root, target.clone()) {
            (Some(root), Ok(store)) => registry.register(crate::purge::Budgeted {
                handler: mkit_server::takedown::late::LateTimer {
                    acceptance: mkit_server::takedown::late_owner::LateOwner::new(
                        store,
                        root.clone(),
                    )
                    .with_purge(purge.cloned()),
                    max_subrequests: 700,
                },
                budget: alarm_budget.cloned(),
                calls: if purge.is_some() { 64 } else { 0 },
            }),
            _ => registry.register(mkit_server::relay::TakedownRequestTimer),
        },
        _ => registry,
    };
    let registry = if class == ShardClass::RefShard
        || alarm_budget.is_some()
            && matches!(
                class,
                ShardClass::NsCoordinator
                    | ShardClass::RefStore
                    | ShardClass::RepoIndexShard
                    | ShardClass::ContentIndexShard
            ) {
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
        let relay = match target.clone() {
            Ok(target) => Some(RelayHandler {
                target,
                hook: WorkerRelayHook::new(relay_root.cloned().unwrap_or_else(|| {
                    if class == ShardClass::RefStore {
                        mkit_server::Partition::Namespace(
                            mkit_server::NamespaceKey::deployment_default(),
                        )
                    } else {
                        mkit_server::Partition::Coordinator(
                            mkit_server::NamespaceKey::deployment_default(),
                        )
                    }
                })),
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
    } else {
        registry
    };
    // Inspection is Paid-only. Kind 12 retains blocked work and makes at most
    // one bounded dependency recheck per alarm; Free's reserved 49-call split
    // remains unchanged, and unknown timers are retained rather than cleared.
    let registry = if matches!(class, ShardClass::RefShard | ShardClass::RefStore)
        && plan.is_some_and(|p| p.trim().eq_ignore_ascii_case("paid"))
    {
        match target.clone() {
            Ok(mut target) => {
                // The recheck reserves shared calls before reading, so it can
                // checkpoint when none remain. Avoid charging them twice.
                target.1 = None;
                let recheck =
                    mkit_server::timers::publication_recheck::PublicationRecheck::new(target);
                if let Some(budget) = alarm_budget {
                    registry.register(recheck.with_alarm_budget(budget.clone()))
                } else {
                    registry.register(recheck)
                }
            }
            Err(_) => registry,
        }
    } else {
        registry
    };
    let registry = match class {
        ShardClass::NsCoordinator | ShardClass::RefShard | ShardClass::RefStore => {
            registry.register(WorkerQuotaRollup::new(target, plan))
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

/// What kind-8 may spend in one Durable Object alarm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutcomeBudget {
    /// Kind-8 fires per alarm.
    pub fires_per_alarm: u32,
    /// Rows (sink calls) per fire.
    pub rows_per_fire: usize,
}

impl OutcomeBudget {
    /// The most sink calls one alarm can make.
    #[must_use]
    pub fn sink_calls_per_alarm(self) -> u32 {
        self.fires_per_alarm
            .saturating_mul(u32::try_from(self.rows_per_fire).unwrap_or(u32::MAX))
    }
}

/// Bound on one kind-8 sink call on a Worker (the wall-clock bound on a whole
/// fire is twice this).
pub const OUTCOME_SINK_TIMEOUT: core::time::Duration = core::time::Duration::from_secs(5);
/// Kind-8 rows (sink calls) per fire on the Free plan.
pub const FREE_OUTCOME_ROWS_PER_FIRE: usize = 8;
/// Kind-8 fires per alarm on the Free plan.
pub const FREE_OUTCOME_FIRES_PER_ALARM: u32 = 1;
/// Kind-8 rows (sink calls) per fire on the Paid plan.
pub const PAID_OUTCOME_ROWS_PER_FIRE: usize = 16;
/// Kind-8 fires per alarm on the Paid plan.
pub const PAID_OUTCOME_FIRES_PER_ALARM: u32 = 4;

/// The audience stamped on delivered outcomes: the deployment's canonical
/// origin, as on native (`outcome_audience`). A hook client's
/// `server_audience` must be taken from this value (R-162).
#[must_use]
pub fn outcome_audience(cfg: &WorkerConfig) -> String {
    cfg.audience.clone()
}

/// The kind-8 budget for `plan` (`WORKERS_PLAN`), always applied: Free makes
/// at most 8 sink calls per alarm (one fire of 8 rows), Paid at most 64 (four
/// fires of 16). A sink call may be a subrequest, and a Free alarm allows 50.
///
/// Free per-alarm subrequest split (`RefShard`, the class with all of them):
/// relay 32 + backup 1 + outcome delivery <= 8 (1 fire x 8 rows; 0 calls
/// today with `NoOutcomes`, reserved for 3.9's binding sink) + quota rollup
/// <= 8 (`FREE_ROLLUP_CALLS`, one fire per tick) = at most 49 of 50.
#[must_use]
pub fn outcome_budget(plan: Option<&str>) -> OutcomeBudget {
    let paid = plan.is_some_and(|p| p.trim().eq_ignore_ascii_case("paid"));
    if paid {
        OutcomeBudget {
            fires_per_alarm: PAID_OUTCOME_FIRES_PER_ALARM,
            rows_per_fire: PAID_OUTCOME_ROWS_PER_FIRE,
        }
    } else {
        OutcomeBudget {
            fires_per_alarm: FREE_OUTCOME_FIRES_PER_ALARM,
            rows_per_fire: FREE_OUTCOME_ROWS_PER_FIRE,
        }
    }
}

/// Register the outcome kinds on every class that holds `o`/`oq` rows:
/// kind 8 (delivery to `sink`; `NoOutcomes` acknowledges locally) and kind 9
/// (reconcile). Each sink call is bounded by 5 s through `sleep`
/// (`WorkerSleep` on Workers; `clock` bounds a whole fire), a fire stops at
/// its first failure, and the fire budget follows `plan` ([`outcome_budget`]). A missing audience retains
/// kind-8 rows. A sink that names the server's audience (a hook client's
/// `server_audience`) must take it from the same `audience` value (R-162).
#[must_use]
pub fn with_outcome_timers<S, O>(
    registry: mkit_server::timers::TimerRegistry<'static, S>,
    class: crate::classes::ShardClass,
    audience: Result<String, ConfigError>,
    plan: Option<&str>,
    sink: O,
    sleep: Arc<dyn mkit_server::Sleep>,
    clock: Arc<dyn mkit_server::Clock>,
) -> mkit_server::timers::TimerRegistry<'static, S>
where
    S: mkit_server::NamespaceStore,
    O: mkit_server::pipeline::OutcomeSink + 'static,
{
    with_outcome_timers_budgeted(registry, class, audience, plan, sink, sleep, clock, None)
}

#[allow(clippy::too_many_arguments)]
fn with_outcome_timers_budgeted<
    S: mkit_server::NamespaceStore,
    O: mkit_server::pipeline::OutcomeSink + 'static,
>(
    registry: mkit_server::timers::TimerRegistry<'static, S>,
    class: crate::classes::ShardClass,
    audience: Result<String, ConfigError>,
    plan: Option<&str>,
    sink: O,
    sleep: Arc<dyn mkit_server::Sleep>,
    clock: Arc<dyn mkit_server::Clock>,
    alarm_budget: Option<mkit_server::purge::SliceBudget>,
) -> mkit_server::timers::TimerRegistry<'static, S> {
    use crate::classes::ShardClass;
    if !matches!(
        class,
        ShardClass::RefStore
            | ShardClass::NsCoordinator
            | ShardClass::RefShard
            | ShardClass::ContentIndexShard
    ) {
        return registry;
    }
    let budget = outcome_budget(plan);
    let delivery = match audience {
        Ok(audience) => Some(
            mkit_server::timers::outcome_delivery::OutcomeDelivery::new(
                sink,
                audience,
                Arc::new(crate::telemetry::ConsoleMetrics::default()),
                sleep,
            )
            .with_max_rows(budget.rows_per_fire)
            .with_sink_timeout(OUTCOME_SINK_TIMEOUT)
            .with_clock(clock),
        ),
        Err(error) => {
            crate::log_failure(&format!(
                "Worker outcome delivery configuration unavailable: {error}"
            ));
            None
        }
    };
    registry
        .register(crate::purge::Budgeted {
            handler: WorkerOutcomeDelivery {
                delivery,
                max_per_tick: budget.fires_per_alarm,
            },
            budget: alarm_budget,
            calls: u32::try_from(budget.rows_per_fire).unwrap_or(u32::MAX),
        })
        .register(mkit_server::timers::reservation_reconcile::ReservationReconcile)
}

struct WorkerOutcomeDelivery<O> {
    delivery: Option<mkit_server::timers::outcome_delivery::OutcomeDelivery<O>>,
    max_per_tick: u32,
}

impl<S, O> mkit_server::timers::TimerHandler<S> for WorkerOutcomeDelivery<O>
where
    S: mkit_server::NamespaceStore,
    O: mkit_server::pipeline::OutcomeSink,
{
    fn kind(&self) -> mkit_server::timers::TimerKind {
        mkit_server::timers::registry::kinds::OUTCOME_DELIVERY
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
        match &self.delivery {
            Some(delivery) => delivery.fire(ctx, timer),
            None => Box::pin(async { Ok(mkit_server::timers::Fired::Retry) }),
        }
    }
}

/// A shared handle on the deployment's target client, so one client serves
/// two handlers of a class without requiring `T: Clone`.
struct SharedStore<T>(Arc<T>, Option<mkit_server::purge::SliceBudget>);

impl<T> SharedStore<T> {
    fn charge(&self) -> Result<(), mkit_server::StoreError> {
        if self.1.as_ref().is_some_and(|budget| !budget.charge(1)) {
            Err(mkit_server::StoreError::unavailable(
                "alarm operation budget exhausted",
            ))
        } else {
            Ok(())
        }
    }
}

impl<T> Clone for SharedStore<T> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0), self.1.clone())
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
        self.charge()?;
        self.0.get(p, k).await
    }
    async fn has(
        &self,
        p: &mkit_server::Partition,
        k: &mkit_server::Key,
    ) -> Result<bool, mkit_server::StoreError> {
        self.charge()?;
        self.0.has(p, k).await
    }
    async fn get_many(
        &self,
        p: &mkit_server::Partition,
        keys: &[mkit_server::Key],
    ) -> Result<Vec<Option<mkit_server::Value>>, mkit_server::StoreError> {
        self.charge()?;
        self.0.get_many(p, keys).await
    }
    async fn scan_many(
        &self,
        p: &mkit_server::Partition,
        ranges: &[mkit_server::RangeScan],
    ) -> Result<Vec<mkit_server::ScanPage>, mkit_server::StoreError> {
        self.charge()?;
        self.0.scan_many(p, ranges).await
    }
    async fn scan(
        &self,
        p: &mkit_server::Partition,
        start: &mkit_server::Key,
        end: &mkit_server::Key,
        after: Option<&mkit_server::Cursor>,
        limit: u32,
    ) -> Result<mkit_server::ScanPage, mkit_server::StoreError> {
        self.charge()?;
        self.0.scan(p, start, end, after, limit).await
    }
    async fn apply(
        &self,
        p: &mkit_server::Partition,
        batch: mkit_server::Batch,
    ) -> Result<mkit_server::BatchOutcome, mkit_server::StoreError> {
        self.charge()?;
        self.0.apply(p, batch).await
    }
    async fn stats(
        &self,
        p: &mkit_server::Partition,
    ) -> Result<mkit_server::PartitionStats, mkit_server::StoreError> {
        self.charge()?;
        self.0.stats(p).await
    }
    async fn probe(&self) -> Result<(), mkit_server::StoreError> {
        self.charge()?;
        self.0.probe().await
    }
}

/// Kind-5 rollups per alarm tick, and the coordinator calls one fire may make.
///
/// Free-plan alarm budget: see [`outcome_budget`] (49 of 50 with the rollup's
/// 8), so Free runs one rollup fire per tick and caps that fire at [`FREE_ROLLUP_CALLS`] external
/// calls. From `quota_rollup.rs`: a live-window fire is the aggregate read
/// plus its guarded write (2 calls); an expired-window fire adds the
/// contribution prune (a read, a scan, the last-source read, two
/// older-window scans and the guarded delete), 8 in all; contention could
/// replan the aggregate up to 8 times, so the cap turns the excess into a
/// retryable `StoreError` (a failed fire, retried with backoff and resuming
/// its prune), never a lost timer. Paid runs four fires with the same
/// eight-call cap, reserving at most 32 coordinator calls per alarm.
const PAID_ROLLUP_FIRES_PER_TICK: u32 = 4;
const FREE_ROLLUP_FIRES_PER_TICK: u32 = 1;
const FREE_ROLLUP_CALLS: u32 = 8;

/// A store handle that fails the fire once `limit` calls were made since
/// [`Self::reset`], so one rollup fire stays within its subrequest budget.
struct BudgetedStore<T> {
    inner: SharedStore<T>,
    used: Arc<core::sync::atomic::AtomicU32>,
    limit: u32,
}

impl<T> BudgetedStore<T> {
    fn charge(&self) -> Result<(), mkit_server::StoreError> {
        use core::sync::atomic::Ordering;
        if self.used.fetch_add(1, Ordering::SeqCst) >= self.limit {
            // `Unavailable` (reason "storage"), not `Invalid` (which the rollup
            // labels "contention"): an exhausted budget is not a CAS race.
            return Err(mkit_server::StoreError::Unavailable(
                "quota rollup subrequest budget exhausted".into(),
            ));
        }
        Ok(())
    }
}

impl<T: mkit_server::NamespaceStore> mkit_server::NamespaceStore for BudgetedStore<T> {
    fn capabilities(&self) -> mkit_server::StoreCapabilities {
        self.inner.capabilities()
    }
    async fn get(
        &self,
        p: &mkit_server::Partition,
        k: &mkit_server::Key,
    ) -> Result<Option<mkit_server::Value>, mkit_server::StoreError> {
        self.charge()?;
        self.inner.get(p, k).await
    }
    async fn has(
        &self,
        p: &mkit_server::Partition,
        k: &mkit_server::Key,
    ) -> Result<bool, mkit_server::StoreError> {
        self.charge()?;
        self.inner.has(p, k).await
    }
    /// One round trip to the coordinator: charged once, however many keys.
    async fn get_many(
        &self,
        p: &mkit_server::Partition,
        keys: &[mkit_server::Key],
    ) -> Result<Vec<Option<mkit_server::Value>>, mkit_server::StoreError> {
        self.charge()?;
        self.inner.get_many(p, keys).await
    }
    /// One round trip to the coordinator: charged once, however many ranges.
    async fn scan_many(
        &self,
        p: &mkit_server::Partition,
        ranges: &[mkit_server::RangeScan],
    ) -> Result<Vec<mkit_server::ScanPage>, mkit_server::StoreError> {
        self.charge()?;
        self.inner.scan_many(p, ranges).await
    }
    async fn scan(
        &self,
        p: &mkit_server::Partition,
        start: &mkit_server::Key,
        end: &mkit_server::Key,
        after: Option<&mkit_server::Cursor>,
        limit: u32,
    ) -> Result<mkit_server::ScanPage, mkit_server::StoreError> {
        self.charge()?;
        self.inner.scan(p, start, end, after, limit).await
    }
    async fn apply(
        &self,
        p: &mkit_server::Partition,
        batch: mkit_server::Batch,
    ) -> Result<mkit_server::BatchOutcome, mkit_server::StoreError> {
        self.charge()?;
        self.inner.apply(p, batch).await
    }
    async fn stats(
        &self,
        p: &mkit_server::Partition,
    ) -> Result<mkit_server::PartitionStats, mkit_server::StoreError> {
        self.charge()?;
        self.inner.stats(p).await
    }
    async fn probe(&self) -> Result<(), mkit_server::StoreError> {
        self.charge()?;
        self.inner.probe().await
    }
}

/// A rollup handler whose coordinator client may be unavailable: a
/// configuration error retains the timers, as [`WorkerRelay`] does.
struct WorkerQuotaRollup<T> {
    rollup: Option<
        mkit_server::timers::quota_rollup::QuotaRollup<
            BudgetedStore<T>,
            crate::telemetry::ConsoleMetrics,
        >,
    >,
    used: Arc<core::sync::atomic::AtomicU32>,
    max_per_tick: u32,
}

impl<T> WorkerQuotaRollup<T> {
    fn new(target: Result<SharedStore<T>, ConfigError>, plan: Option<&str>) -> Self {
        let free = !plan.is_some_and(|p| p.trim().eq_ignore_ascii_case("paid"));
        let used = Arc::new(core::sync::atomic::AtomicU32::new(0));
        let rollup = match target {
            Ok(inner) => Some(mkit_server::timers::quota_rollup::QuotaRollup {
                coordinator: BudgetedStore {
                    inner,
                    used: Arc::clone(&used),
                    limit: FREE_ROLLUP_CALLS,
                },
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
            used,
            max_per_tick: if free {
                FREE_ROLLUP_FIRES_PER_TICK
            } else {
                PAID_ROLLUP_FIRES_PER_TICK
            },
        }
    }
}

impl<S: mkit_server::NamespaceStore, T: mkit_server::NamespaceStore + 'static>
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
        // Fires in one tick run one after another: each starts a fresh budget.
        self.used.store(0, core::sync::atomic::Ordering::SeqCst);
        match &self.rollup {
            Some(rollup) => rollup.fire(ctx, timer),
            None => Box::pin(async { Ok(mkit_server::timers::Fired::Retry) }),
        }
    }
}

/// Preserve content observations and the merged target-local audit reserve.
struct WorkerRelayHook {
    content: mkit_server::relay::HolderRelayHook,
    audit: mkit_server::admin::AuditReserveHook,
}

impl WorkerRelayHook {
    fn new(root: mkit_server::Partition) -> Self {
        Self {
            content: mkit_server::relay::HolderRelayHook {
                #[cfg(target_arch = "wasm32")]
                clock: Arc::new(crate::clock::WorkerClock),
                #[cfg(not(target_arch = "wasm32"))]
                clock: Arc::new(mkit_server::SystemClock),
            },
            audit: mkit_server::admin::AuditReserveHook::new(root),
        }
    }
}

impl mkit_server::relay::RelayHook for WorkerRelayHook {
    fn reserved_ops(
        &self,
        target: &mkit_server::Partition,
        rows: &[(u64, mkit_server::store::codec::RelayV1)],
    ) -> usize {
        self.audit.reserved_ops(target, rows)
    }

    fn read_keys(
        &self,
        target: &mkit_server::Partition,
        rows: &[(u64, mkit_server::store::codec::RelayV1)],
    ) -> Result<Vec<mkit_server::Key>, mkit_server::StoreError> {
        self.content.read_keys(target, rows)
    }

    fn before_apply<'a>(
        &'a self,
        target: &'a mkit_server::Partition,
        rows: &'a [(u64, mkit_server::store::codec::RelayV1)],
        pre: &'a mut Vec<mkit_server::Precondition>,
        writes: &'a mut Vec<mkit_server::Write>,
    ) -> mkit_server::BoxFuture<'a, Result<(), mkit_server::StoreError>> {
        Box::pin(async move {
            self.content.before_apply(target, rows, pre, writes).await?;
            self.audit.before_apply(target, rows, pre, writes).await
        })
    }

    fn before_apply_observed<'a>(
        &'a self,
        target: &'a mkit_server::Partition,
        rows: &'a [(u64, mkit_server::store::codec::RelayV1)],
        observed: &'a [(mkit_server::Key, Option<mkit_server::Value>)],
        pre: &'a mut Vec<mkit_server::Precondition>,
        writes: &'a mut Vec<mkit_server::Write>,
    ) -> mkit_server::BoxFuture<'a, Result<(), mkit_server::StoreError>> {
        Box::pin(async move {
            self.content
                .before_apply_observed(target, rows, observed, pre, writes)
                .await?;
            self.audit.before_apply(target, rows, pre, writes).await
        })
    }
}

struct WorkerRelay<T> {
    relay: Option<mkit_server::relay::RelayHandler<T, WorkerRelayHook>>,
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

#[cfg(feature = "http-objects")]
pub use mkit_server::pipeline::{IssuedUrl, ObjectReader, ReaderView};

#[cfg(target_arch = "wasm32")]
pub(crate) use glue::build_ns_object;
#[cfg(all(target_arch = "wasm32", feature = "http-objects"))]
pub use glue::fetch_with_context;
#[cfg(target_arch = "wasm32")]
pub use glue::{
    WorkerPipeline, fetch, fetch_with, ns_object, ns_object_with, pipeline as embedding_pipeline,
    serve, serve_admin_with, serve_with,
};
#[cfg(all(target_arch = "wasm32", feature = "published-view"))]
pub use glue::{fetch_configured, ns_object_configured};

#[cfg(target_arch = "wasm32")]
mod glue {
    use std::sync::Arc;
    use std::sync::Once;

    use crate::telemetry::{ConsoleMetrics, install};
    use mkit_server::pipeline::{DeliveryError, HookSet, OutcomeSink, Pipeline};
    use mkit_worker_common::adapter::{
        copy_headers_filtered, is_deadline_header, respond_streamed, to_http_method,
    };
    use mkit_worker_common::body_cap::content_length_exceeds;
    use mkit_worker_common::cors::{cors_preflight_response, is_options_preflight};
    use worker::{Env, Request, Response, State};

    use super::{
        BodyWatch, CORS_ALLOW_METHODS, ConfigError, LimitedBody, MeasuredBody, PLAN_VAR,
        SINGLE_PUT_MAX_BYTES, WorkerConfig, body_too_large_json, cors_allow_headers,
        cors_expose_headers, dispatch_oneshot_body, over_cap_response, plan_capacity,
        response_header_plan, unavailable_json,
    };
    use crate::backup::{BACKUPS_BINDING, BackupConfig, BackupDrain, BackupHandler};
    use crate::clock::WorkerClock;
    use crate::hooks::build::{hooks_from_env, sink_from_env};
    use crate::ns_client::{StubTransport, WorkerNamespaceStore};
    use crate::ns_object::NsObject;
    use crate::r2::{EnvBucket, PACKS_KEYSPACE, R2BlobStore, WorkerBlobStore};
    use crate::sharding_guard::{Outcome, Settled, check_addressing, check_mode};

    thread_local! {
        static SHARDING_GUARD: std::cell::RefCell<Option<Settled>> = const { std::cell::RefCell::new(None) };
    }

    static BACKUPS_MISSING_LOG: Once = Once::new();
    static BACKUPS_INVALID_LOG: Once = Once::new();

    /// The pipeline a request runs on, over the hooks `H`.
    pub type WorkerPipeline<H> = Pipeline<WorkerBlobStore, WorkerNamespaceStore, H>;

    /// `Access-Control-Allow-Origin` and the admission `Expose-Headers` on
    /// every response, so a browser reads a challenge or a receipt.
    fn cors(resp: Response) -> Response {
        let mut resp = mkit_worker_common::cors::with_cors(resp);
        let _ = resp
            .headers_mut()
            .set("Access-Control-Expose-Headers", &cors_expose_headers());
        resp
    }

    /// Copy `headers` onto `out`, appending repeated fields.
    fn copy_response_headers(headers: &http::HeaderMap, out: &mut Response) {
        let out_headers = out.headers_mut();
        for (name, value, append) in response_header_plan(headers) {
            let _ = if append {
                out_headers.append(&name, &value)
            } else {
                out_headers.set(&name, &value)
            };
        }
    }

    fn json_response(body: String, status: u16) -> worker::Result<Response> {
        let mut response = Response::error(body, status)?;
        response
            .headers_mut()
            .set("Content-Type", "application/json")?;
        Ok(response)
    }

    fn receipt_keys(req: &Request, cfg: &WorkerConfig) -> worker::Result<Option<Response>> {
        if req.path() == "/.well-known/mkit-receipt-keys.json"
            && req.method() == worker::Method::Get
            && let Some(settings) = &cfg.takedown
        {
            let mut response =
                Response::from_bytes(settings.publication.key_list.as_bytes().to_vec())?;
            response
                .headers_mut()
                .set("content-type", "application/json")?;
            response
                .headers_mut()
                .set("cache-control", "public, max-age=300")?;
            response
                .headers_mut()
                .set("access-control-allow-origin", "*")?;
            return Ok(Some(response));
        }
        Ok(None)
    }

    /// The request-budgeted embedding pipeline for configured bindings/hooks.
    /// # Errors
    /// Invalid configuration or unavailable bindings.
    pub fn pipeline<H: HookSet + 'static>(
        env: &Env,
        cfg: &WorkerConfig,
        hooks: H,
        request_budget: &mkit_server::indexed::budget::SliceBudget,
        #[cfg(feature = "published-view")] snapshot_warm: bool,
    ) -> Result<WorkerPipeline<H>, ConfigError> {
        cfg.validate_runtime(env)?;
        let bad = |e: &dyn core::fmt::Display| ConfigError(e.to_string());
        let mut config = cfg.pipeline_config()?;
        let blobs = R2BlobStore::new(
            EnvBucket::new(env.clone(), cfg.blob_binding).with_budget(request_budget.clone()),
            PACKS_KEYSPACE,
        )
        .with_max_bytes(SINGLE_PUT_MAX_BYTES);
        let meta = WorkerNamespaceStore::new(
            StubTransport::new(env.clone(), cfg.placement.clone()),
            cfg.probe_partition(),
        )
        .with_budget(request_budget.clone());
        #[cfg(feature = "published-view")]
        let meta = if cfg.published_view.is_some() {
            meta.with_apply_reserve(3)
        } else {
            meta
        };
        config.purge = crate::admin::purge_config(cfg, meta.clone(), Some(request_budget))?;
        #[cfg(feature = "published-view")]
        let snapshot_fence = config.purge.as_ref().map(|_| meta.clone());
        #[cfg(feature = "test-faults")]
        let faulted = blobs.clone();
        let pipe = Pipeline::new(
            blobs,
            meta,
            hooks,
            config,
            Arc::new(WorkerClock),
            Arc::new(ConsoleMetrics::default()),
        )
        .map_err(|e| bad(&e))?;
        let pipe = if let Some(vars) = cfg.hooks.as_ref().filter(|v| v.roles.inspect) {
            pipe.with_inspectors(
                crate::hooks::build::inspectors_from_env(env, cfg)?,
                vars.inspect_batch_max_objects,
            )
            .map_err(|e| bad(&e))?
        } else {
            pipe
        };
        #[cfg(feature = "http-objects")]
        let pipe = if let Some(mount) = &cfg.http_mount {
            pipe.with_http_seams(|mut seams| {
                seams.read_runtime.clone_from(&mount.read_runtime);
                seams
            })
        } else {
            pipe
        };
        #[cfg(feature = "published-view")]
        let pipe = if let Some(config) = cfg
            .published_view
            .clone()
            .map(|mut config| {
                config.inspection_configured |= cfg.hooks.as_ref().is_some_and(|v| v.roles.inspect);
                config
            })
            .filter(|c| snapshot_warm || c.inspection_configured)
        {
            let source = crate::published_view::shared_reader(
                crate::published_view::WorkerSnapshotBucket(
                    env.clone(),
                    Some(request_budget.clone()),
                ),
                crate::published_view::WorkerCache(Some(request_budget.clone())),
                config,
                Arc::new(WorkerClock),
            );
            // Paid purge deployments add two strong coordinator reads around
            // snapshot reads/fills; cached bytes never bypass the durable fence.
            let source = if let Some(store) = &snapshot_fence {
                crate::published_view::fenced_reader(source, store.clone(), cfg.sharding)
            } else {
                source
            };
            pipe.with_published_source(source)
        } else {
            pipe
        };
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
            .uri(req.inner().url())
            .body(LimitedBody::new(body, max_body_bytes, watch.clone()))
            .map_err(|_| worker::Error::RustError("invalid HTTP request URL".into()))?;
        copy_headers_filtered(req.headers().entries(), http_req.headers_mut(), |k| {
            !is_deadline_header(k)
        });
        Ok(http_req)
    }

    /// A deployment's whole `#[event(fetch)]`: [`serve`] with the
    /// [`WorkerConfig`] of `env`'s vars. With a var missing or malformed,
    /// every request but a CORS preflight is answered `unavailable` (HTTP
    /// 503) naming it. The hooks come from the hook vars and the
    /// `ADMISSION_HOOK` service binding (WP-3.9); [`fetch_with`] supplies
    /// others.
    ///
    /// # Errors
    /// Only when the runtime fails to build a response.
    pub async fn fetch(req: Request, env: Env) -> worker::Result<Response> {
        fetch_with(req, env, hooks_from_env).await
    }

    /// Serve the optional launch HTTP mount with settlement retained by the fetch event.
    ///
    /// # Errors
    /// Only when the runtime fails to build a response.
    #[cfg(feature = "http-objects")]
    pub async fn fetch_with_context(
        req: Request,
        env: Env,
        context: worker::Context,
    ) -> worker::Result<Response> {
        match WorkerConfig::from_env(&env) {
            Ok(mut cfg) => {
                cfg.http_mount = cfg
                    .http_mount
                    .take()
                    .map(|mount| mount.with_context(context));
                serve_with(req, env, &cfg, hooks_from_env).await
            }
            Err(error) => env_config_error(&req, &env, &error, true),
        }
    }

    /// Explicit published-view fetch entry point. Environment variables never enable snapshots.
    #[cfg(feature = "published-view")]
    pub async fn fetch_configured(
        req: Request,
        env: Env,
        config: crate::published_view::PublishedViewConfig,
    ) -> worker::Result<Response> {
        match WorkerConfig::from_env(&env) {
            Ok(mut cfg) => {
                cfg.published_view = Some(config);
                serve_with(req, env, &cfg, hooks_from_env).await
            }
            Err(error) => env_config_error(&req, &env, &error, false),
        }
    }

    /// [`fetch`] over hooks built by `make_hooks` from `env` and the parsed
    /// [`WorkerConfig`], for a deployment with its own authorizer or
    /// admission (the 3.14 reference Worker's business layer, for example).
    /// A build error answers every RPC `unavailable` (HTTP 503), like a bad
    /// var. The kind-8 outcome sink is the Durable Objects' to build:
    /// [`ns_object_with`].
    ///
    /// # Errors
    /// Only when the runtime fails to build a response.
    pub async fn fetch_with<H, F>(req: Request, env: Env, make_hooks: F) -> worker::Result<Response>
    where
        H: HookSet + 'static,
        F: FnOnce(&Env, &WorkerConfig) -> Result<H, ConfigError>,
    {
        install();
        match WorkerConfig::from_env(&env) {
            Ok(cfg) => serve_with(req, env, &cfg, make_hooks).await,
            Err(error) => env_config_error(&req, &env, &error, true),
        }
    }

    fn env_config_error(
        req: &Request,
        env: &Env,
        error: &ConfigError,
        connect_preflight: bool,
    ) -> worker::Result<Response> {
        #[cfg(not(feature = "http-objects"))]
        let _ = env;
        #[cfg(feature = "http-objects")]
        if crate::http_mount::glue::env_mounted_request(req, env) {
            let response = if req.method() == worker::Method::Options {
                let mut response = Response::empty()?.with_status(204);
                response.headers_mut().set("Allow", "GET, HEAD, OPTIONS")?;
                response
            } else {
                json_response(unavailable_json(&error.0), 503)?
            };
            return crate::http_mount::glue::finish(
                response,
                req.method().as_ref(),
                req.headers().get("Origin")?.as_deref(),
                &mkit_server::http_objects::mount::HttpMountOptions::default(),
            );
        }
        if connect_preflight && is_options_preflight(req) {
            return cors_preflight_response(&cors_allow_headers(), CORS_ALLOW_METHODS);
        }
        Ok(cors(json_response(unavailable_json(&error.0), 503)?))
    }

    /// Answer one request of a deployment (see the module docs), with the
    /// hooks the hook vars and the `ADMISSION_HOOK` binding name.
    ///
    /// # Errors
    /// Only when the runtime fails to build a response.
    pub async fn serve(req: Request, env: Env, cfg: &WorkerConfig) -> worker::Result<Response> {
        serve_with(req, env, cfg, hooks_from_env).await
    }

    /// Serve the authenticated operator mount on an embedder-selected path.
    /// Pass the `AdminService` path after host routing; operator signatures and
    /// `ADMIN_KEYS` are checked by the same mount as public fetch.
    /// # Errors
    /// Runtime response construction failures.
    pub async fn serve_admin_with(
        req: Request,
        env: Env,
        cfg: &WorkerConfig,
    ) -> worker::Result<Response> {
        if let Err(error) = cfg.validate_runtime(&env) {
            return crate::admin::no_store(json_response(unavailable_json(&error.0), 503));
        }
        let request_budget = mkit_server::indexed::budget::SliceBudget::new(9000);
        let meta = WorkerNamespaceStore::new(
            StubTransport::new(env.clone(), cfg.placement.clone()),
            cfg.probe_partition(),
        )
        .with_budget(request_budget.clone());
        let checked = match check_mode(&meta, cfg.sharding).await {
            Ok(Outcome::Ok) => {
                check_addressing(
                    &meta,
                    matches!(cfg.addressing, mkit_server::Addressing::Multi(_)),
                )
                .await
            }
            outcome => outcome,
        };
        if let Err(error) = checked
            .map_err(crate::sharding_guard::GuardError::Storage)
            .and_then(Outcome::into_result)
        {
            return crate::admin::no_store(json_response(
                unavailable_json(error.public_message()),
                503,
            ));
        }
        crate::admin::serve(req, env, cfg, &request_budget).await
    }

    /// [`serve`] over hooks built by `make_hooks`.
    ///
    /// # Errors
    /// Only when the runtime fails to build a response.
    pub async fn serve_with<H, F>(
        req: Request,
        env: Env,
        cfg: &WorkerConfig,
        make_hooks: F,
    ) -> worker::Result<Response>
    where
        H: HookSet + 'static,
        F: FnOnce(&Env, &WorkerConfig) -> Result<H, ConfigError>,
    {
        if let Err(error) = cfg.validate_runtime(&env) {
            let response = json_response(unavailable_json(&error.0), 503)?;
            #[cfg(feature = "http-objects")]
            if let Some(mount) = &cfg.http_mount
                && crate::http_mount::glue::mounted_request(&req, cfg)
            {
                return crate::http_mount::glue::finish(
                    response,
                    req.method().as_ref(),
                    req.headers().get("Origin")?.as_deref(),
                    &mount.options,
                );
            }
            return if req.path().starts_with(mkit_server::admin::PREFIX) {
                crate::admin::no_store(Ok(response))
            } else {
                Ok(response)
            };
        }
        #[cfg(feature = "http-objects")]
        if crate::http_mount::glue::mounted_request(&req, cfg) {
            let method = req.method();
            let origin = req.headers().get("Origin")?;
            let response = match crate::http_mount::glue::early(&req, cfg) {
                Ok(Some(response)) => response,
                Ok(None) => match serve_inner_with(req, env, cfg, make_hooks).await {
                    Ok(response) => response,
                    Err(_) => Response::error("HTTP object adapter failed", 503)?,
                },
                Err(_) => Response::error("HTTP object adapter failed", 503)?,
            };
            if let Some(mount) = &cfg.http_mount {
                return crate::http_mount::glue::finish(
                    response,
                    method.as_ref(),
                    origin.as_deref(),
                    &mount.options,
                );
            }
            return Ok(response);
        }
        serve_inner_with(req, env, cfg, make_hooks).await
    }

    async fn serve_inner_with<H, F>(
        req: Request,
        env: Env,
        cfg: &WorkerConfig,
        make_hooks: F,
    ) -> worker::Result<Response>
    where
        H: HookSet + 'static,
        F: FnOnce(&Env, &WorkerConfig) -> Result<H, ConfigError>,
    {
        #[cfg(feature = "test-faults")]
        let mut req = req;
        install();
        if let Some(response) = receipt_keys(&req, cfg)? {
            return Ok(response);
        }
        let scanner_request = crate::scanner_retrieval::mounted(&req.path(), cfg);
        if !scanner_request && is_options_preflight(&req) {
            return cors_preflight_response(&cors_allow_headers(), CORS_ALLOW_METHODS);
        }
        // One invocation owns all backend phases and lazy upload/proof clones.
        // Reserve 1000 calls for bounded remote hooks and response settlement.
        let request_budget = mkit_server::indexed::budget::SliceBudget::new(9000);
        let meta = WorkerNamespaceStore::new(
            StubTransport::new(env.clone(), cfg.placement.clone()),
            cfg.probe_partition(),
        )
        .with_budget(request_budget.clone());
        let jurisdiction = cfg.placement.jurisdiction.as_deref();
        let multi = matches!(cfg.addressing, mkit_server::Addressing::Multi(_));
        let cached =
            SHARDING_GUARD.with(|cache| Settled::cached(cache, cfg.sharding, multi, jurisdiction));
        #[cfg(feature = "published-view")]
        let snapshot_warm = cached.is_some();
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
            if scanner_request {
                return crate::scanner_retrieval::not_found();
            }
            return Ok(cors(json_response(
                unavailable_json(error.public_message()),
                503,
            )?));
        }
        if cfg.admin_on_public_path && req.path().starts_with(mkit_server::admin::PREFIX) {
            // Parse hook configuration/signing too: invalid role separation must
            // refuse the operator route before its authenticated effect.
            return serve_admin_with(req, env, cfg).await;
        }
        #[cfg(feature = "test-faults")]
        if let Some(response) = test::backup_round_trip(&mut req, &env, cfg).await? {
            return Ok(cors(response));
        }
        #[cfg(feature = "test-faults")]
        if req.method() == worker::Method::Get && req.path() == test::STATS_PATH {
            let scope = req
                .url()
                .map_err(|_| worker::Error::RustError("invalid request URL".into()))?
                .query_pairs()
                .find_map(|(k, v)| (k == "ref").then(|| v.into_owned()));
            return Ok(cors(test::stats(&env, cfg, scope.as_deref()).await?));
        }
        #[cfg(feature = "test-faults")]
        {
            let path = req.path();
            if let Some(pack) = path.strip_prefix(test::RELAY_PATH_PREFIX) {
                return Ok(cors(test::relay(req.method(), pack, &env, cfg).await?));
            }
        }
        if !scanner_request && exceeds_body_cap(&req, cfg) {
            let body = body_too_large_json(cfg.max_body_bytes);
            return Ok(cors(json_response(body, 400)?));
        }
        // Cold guard discovery spends additional DO calls: attach no snapshot
        // reader then, retaining the configured page cap and inspection refusal.
        let pipe = match make_hooks(&env, cfg).and_then(|hooks| {
            pipeline(
                &env,
                cfg,
                hooks,
                &request_budget,
                #[cfg(feature = "published-view")]
                snapshot_warm,
            )
        }) {
            Ok(pipe) => pipe,
            Err(_) if scanner_request => return crate::scanner_retrieval::not_found(),
            Err(e) => return Ok(cors(json_response(unavailable_json(&e.0), 503)?)),
        };
        #[cfg(feature = "http-objects")]
        if crate::http_mount::glue::mounted_request(&req, cfg) {
            return crate::http_mount::glue::serve(&pipe, &req).await;
        }
        if scanner_request {
            return crate::scanner_retrieval::serve(&pipe, req).await;
        }
        serve_connect(&req, cfg, pipe).await
    }

    fn exceeds_body_cap(req: &Request, cfg: &WorkerConfig) -> bool {
        #[cfg(feature = "http-objects")]
        if crate::http_mount::glue::mounted_request(req, cfg) {
            return false;
        }
        let length = req.headers().get("content-length").ok().flatten();
        content_length_exceeds(length.as_deref(), cfg.max_body_bytes)
    }

    /// Dispatch Connect and bridge its streaming response with request-cap accounting.
    async fn serve_connect<H: HookSet + 'static>(
        req: &Request,
        cfg: &WorkerConfig,
        pipe: WorkerPipeline<H>,
    ) -> worker::Result<Response> {
        let watch = BodyWatch::default();
        let http_req = http_request(req, cfg.max_body_bytes, &watch)?;
        // The binding takes an `Arc` and holds it in a `SendWrapper` on
        // wasm32, where the pipeline's Workers handles are `!Send`.
        #[allow(clippy::arc_with_non_send_sync)]
        let pipe = Arc::new(pipe);
        let http_resp = dispatch_oneshot_body(mkit_server::connect::service(pipe), http_req).await;
        // A unary body is read whole, and a client-streaming handler has
        // answered, before connectrpc returns its response: a body that
        // ran past the cap has tripped the watch by now.
        if let Some((status, body)) = over_cap_response(&watch, cfg.max_body_bytes) {
            return Ok(cors(json_response(body, status)?));
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
        Ok(cors(out))
    }

    /// The Durable Object of a partition for `state`: its store capped for
    /// the plan in `env`'s `WORKERS_PLAN` var (see [`plan_capacity`]), and its
    /// kind-8 outcome sink built from the hook vars and the `ADMISSION_HOOK`
    /// binding.
    #[must_use]
    pub fn ns_object(state: State, env: &Env, class: crate::classes::ShardClass) -> NsObject {
        ns_object_with(state, env, class, sink_from_env)
    }

    /// The kind-8 sink, or the reason there is none: delivery then waits
    /// (`Fired::Retry`) and the rows are kept.
    struct MaybeSink<O>(Option<O>);

    impl<O: OutcomeSink> OutcomeSink for MaybeSink<O> {
        async fn deliver(
            &self,
            outcome: &mkit_server::pipeline::Outcome,
        ) -> Result<(), DeliveryError> {
            match &self.0 {
                Some(sink) => sink.deliver(outcome).await,
                None => Err(DeliveryError::new(
                    "outcome hook configuration unavailable",
                    None,
                )),
            }
        }
    }

    /// [`ns_object`] with the outcome sink built by `make_sink` from `env`
    /// and the parsed [`WorkerConfig`]. Pair it with [`fetch_with`] when the
    /// deployment has its own stages. A sink or config error keeps every
    /// outcome row queued: delivery runs only with a valid sink and audience.
    #[must_use]
    pub fn ns_object_with<O, F>(
        state: State,
        env: &Env,
        class: crate::classes::ShardClass,
        make_sink: F,
    ) -> NsObject
    where
        O: OutcomeSink + 'static,
        F: FnOnce(&Env, &WorkerConfig) -> Result<O, ConfigError>,
    {
        crate::embedding::NsObjectBuilder::new(state, env, class, WorkerConfig::from_env(env))
            .build_with(make_sink)
    }

    /// Explicit published-view DO construction, paired with `fetch_configured`.
    #[cfg(feature = "published-view")]
    #[must_use]
    pub fn ns_object_configured(
        state: State,
        env: &Env,
        class: crate::classes::ShardClass,
        config: crate::published_view::PublishedViewConfig,
    ) -> NsObject {
        crate::embedding::NsObjectBuilder::new(state, env, class, WorkerConfig::from_env(env))
            .with_published_view(config)
            .build_with(crate::hooks::build::sink_from_env)
    }

    // Keep the one-time DO construction and typed handler wiring together.
    #[allow(clippy::too_many_lines, clippy::arc_with_non_send_sync)] // Worker futures are single-threaded; core shares Arc on both targets.
    pub(crate) fn build_ns_object<O, F>(
        state: State,
        env: &Env,
        class: crate::classes::ShardClass,
        cfg: Result<WorkerConfig, ConfigError>,
        make_sink: F,
    ) -> NsObject
    where
        O: OutcomeSink + 'static,
        F: FnOnce(&Env, &WorkerConfig) -> Result<O, ConfigError>,
    {
        install();
        let plan = env.var(PLAN_VAR).ok().map(|v| v.to_string());
        let capacity = plan_capacity(plan.as_deref()).unwrap_or_else(|(e, free)| {
            worker::console_error!("{e}; using the Workers Free cap");
            free
        });
        let cfg = cfg.and_then(|cfg| {
            cfg.validate_runtime(env)?;
            Ok(cfg)
        });
        let target = cfg.as_ref().map_err(Clone::clone).map(|cfg| {
            let probe = cfg.probe_partition();
            WorkerNamespaceStore::new(
                StubTransport::new(env.clone(), cfg.placement.clone()),
                probe,
            )
        });
        #[cfg(feature = "published-view")]
        let target = target.map(|store| {
            if cfg.as_ref().is_ok_and(|cfg| cfg.published_view.is_some()) {
                store.with_apply_reserve(3)
            } else {
                store
            }
        });
        #[cfg(feature = "published-view")]
        let snapshot_target = target.clone();
        // The audience the sink names (the hook client's `server_audience`)
        // is the one kind 8 stamps on outcomes: `outcome_audience`, once.
        let (audience, sink) = match &cfg {
            Ok(cfg) => match make_sink(env, cfg) {
                Ok(sink) => (Ok(super::outcome_audience(cfg)), Some(sink)),
                Err(error) => (Err(error), None),
            },
            Err(error) => (Err(error.clone()), None),
        };
        let alarm_budget = plan
            .as_deref()
            .filter(|plan| plan.trim().eq_ignore_ascii_case("paid"))
            .map(|_| {
                let allowance = if cfg.as_ref().is_ok_and(|cfg| cfg.launch.is_some()) {
                    crate::purge::LAUNCH_ALARM_OPERATIONS
                } else {
                    crate::purge::ALARM_OPERATIONS
                };
                mkit_server::purge::SliceBudget::new(allowance)
            });
        let takedown_root = cfg
            .as_ref()
            .ok()
            .filter(|cfg| cfg.takedown.is_some())
            .map(WorkerConfig::probe_partition);
        let (purge, takedown_root) = match (&cfg, &target) {
            (Ok(cfg), Ok(target)) => match crate::admin::purge_config(cfg, target.clone(), None) {
                Ok(purge) => (purge, takedown_root),
                Err(error) => {
                    crate::log_failure(&error.to_string());
                    (None, None)
                }
            },
            _ => (None, None),
        };
        let relay_root = cfg.as_ref().ok().map(WorkerConfig::probe_partition);
        let registry = super::timer_registry_budgeted(
            class,
            target,
            plan.as_deref(),
            alarm_budget.as_ref(),
            takedown_root.as_ref(),
            relay_root.as_ref(),
            purge.as_ref(),
        );
        let registry = if let (Ok(cfg), Some(budget)) = (&cfg, &alarm_budget)
            && cfg.takedown.is_some()
            && class
                == match cfg.sharding {
                    mkit_server::pipeline::Sharding::Single => crate::classes::ShardClass::RefStore,
                    _ => crate::classes::ShardClass::NsCoordinator,
                } {
            match crate::admin::work(env, cfg, budget) {
                Ok(work) => registry.register(crate::purge::Budgeted {
                    calls: if work.purge.is_some() { 64 } else { 0 },
                    handler: work,
                    budget: Some(budget.clone()),
                }),
                Err(error) => {
                    crate::log_failure(&error.to_string());
                    registry
                }
            }
        } else {
            registry
        };
        let registry = if matches!(
            class,
            crate::classes::ShardClass::RefStore | crate::classes::ShardClass::RefShard
        ) {
            registry.register(crate::purge::Budgeted {
                handler: mkit_server::timers::ticket_expiry::TicketExpiry {
                    blobs: R2BlobStore::new(
                        EnvBucket::new(
                            env.clone(),
                            cfg.as_ref()
                                .map_or(crate::r2::STORAGE_BINDING, |cfg| cfg.blob_binding),
                        ),
                        PACKS_KEYSPACE,
                    )
                    .with_deferred_abort(
                        !plan
                            .as_deref()
                            .is_some_and(|p| p.trim().eq_ignore_ascii_case("paid")),
                    ),
                },
                budget: alarm_budget.clone(),
                calls: 3,
            })
        } else {
            registry
        };
        let registry = super::with_outcome_timers_budgeted(
            registry,
            class,
            audience,
            plan.as_deref(),
            MaybeSink(sink),
            Arc::new(crate::sleep::WorkerSleep),
            Arc::new(WorkerClock),
            alarm_budget.clone(),
        );
        // Kind 7: registered for an indexed Paid deployment, with the merged
        // extraction driver required before Verified becomes visible.
        let registry = if let Ok(cfg) = &cfg {
            crate::verify::register_configured_budgeted(
                registry,
                env,
                class,
                plan.as_deref(),
                alarm_budget.clone(),
                cfg,
            )
        } else {
            registry
        };
        let registry = if let (Ok(cfg), Some(budget)) = (&cfg, &alarm_budget) {
            if let Some(custom) = &cfg.custom_purge {
                registry.register(custom.delivery(budget.clone()))
            } else {
                match crate::hooks::build::purge_from_env(env, cfg) {
                    Ok(Some(sink)) => registry.register(crate::purge::NamespaceDelivery {
                        delivery: mkit_server::purge::PurgeDelivery::new(
                            Arc::new(mkit_server::purge::NoLocalCache),
                            Some(Arc::new(sink)),
                            budget.clone(),
                        ),
                        local: crate::purge::local_cache(cfg),
                        remote: WorkerNamespaceStore::new(
                            StubTransport::new(env.clone(), cfg.placement.clone()),
                            cfg.probe_partition(),
                        ),
                        sharding: cfg.sharding,
                        single: match &cfg.addressing {
                            mkit_server::Addressing::Single { repo } => Some(repo.clone()),
                            _ => None,
                        },
                    }),
                    Ok(None) => registry,
                    Err(error) => {
                        crate::log_failure(&format!("purge sink unavailable: {error}"));
                        registry
                    }
                }
            }
        } else {
            registry
        };
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
        #[cfg(feature = "published-view")]
        let snapshot_alarm = cfg
            .as_ref()
            .ok()
            .and_then(|cfg| cfg.published_view.as_ref())
            .filter(|c| !c.inspection_configured)
            .filter(|_| {
                class == crate::classes::ShardClass::RepoIndexShard && snapshot_target.is_ok()
            })
            .map(|_| crate::published_view::SnapshotAlarm::default());
        let registry = if let Some(config) = backup.clone() {
            // Free-plan alarm budget: relay 32 + this handler's single R2 put
            // 1 + outcome delivery <= 8 + quota rollup <= 8 = 49 of 50 (see
            // `outcome_budget`; each remote hook call is one service-binding
            // subrequest). Kind 9 makes no external calls.
            let handler = crate::purge::Budgeted {
                handler: BackupHandler::new(EnvBucket::new(env.clone(), BACKUPS_BINDING), config),
                budget: alarm_budget.clone(),
                calls: 1,
            };
            #[cfg(feature = "published-view")]
            if let Some(alarm) = &snapshot_alarm {
                registry.register(crate::published_view::AlarmLimited {
                    handler,
                    alarm: alarm.clone(),
                })
            } else {
                registry.register(handler)
            }
            #[cfg(not(feature = "published-view"))]
            registry.register(handler)
        } else {
            registry.register(BackupDrain)
        };
        #[cfg(feature = "published-view")]
        let registry = if let (Some(alarm), Ok(coordinator), Ok(cfg)) =
            (&snapshot_alarm, snapshot_target, cfg.as_ref())
        {
            registry.register(crate::purge::Budgeted {
                handler: crate::published_view::SnapshotHandler {
                    default_repo_visibility: cfg.default_repo_visibility,
                    bucket: crate::published_view::WorkerSnapshotBucket(env.clone(), None),
                    coordinator,
                    clock: Arc::new(WorkerClock),
                    alarm: alarm.clone(),
                },
                budget: alarm_budget.clone(),
                calls: 3,
            })
        } else {
            registry
        };
        let object = NsObject::new(state, class)
            .0
            .with_capacity(capacity)
            .with_alarm_budget(alarm_budget)
            .with_registry(registry);
        #[cfg(feature = "published-view")]
        let object = if let Some(alarm) = snapshot_alarm {
            object.with_published_view(alarm)
        } else {
            object
        };
        if let Some(config) = backup {
            object.with_backup_interval(config.interval_ms)
        } else {
            object
        }
    }

    /// A deployment's own hooks and outcome sink type-check through the
    /// generic entry points (R-138, R-154). Never called: the wasm32 build is
    /// the check.
    #[allow(dead_code)]
    async fn own_hooks_and_sink_compile(req: Request, env: Env, state: State) {
        use mkit_server::pipeline::{Hooks, NoOutcomes};

        let _ = fetch_with(req, env.clone(), |_env, _cfg| Ok(Hooks::new())).await;
        let _ = ns_object_with(
            state,
            &env,
            crate::classes::ShardClass::RefStore,
            |_env, _cfg| Ok(NoOutcomes),
        );
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

        /// `{bytes, keys}` of the partition that holds the replay records and
        /// quota windows of writes to `scope` (a full ref name): the
        /// deployment-default partition under Single sharding, where `scope`
        /// is ignored, and that ref's shard under D34, where it is required.
        pub(super) async fn stats(
            env: &Env,
            cfg: &super::WorkerConfig,
            scope: Option<&str>,
        ) -> worker::Result<Response> {
            let p = if cfg.sharding == Sharding::D34 {
                let Some(reference) = scope.filter(|r| mkit_server::refs::validate_ref_name(r))
                else {
                    return Response::error("D34 stats need ?ref=<valid ref name>", 400);
                };
                let repo = RepoId {
                    namespace: NamespaceKey::deployment_default(),
                    name: RepoName::new(cfg.repository.as_deref().unwrap_or("default"))
                        .map_err(|e| worker::Error::RustError(e.to_string()))?,
                };
                D34Shards.ref_shard(&repo, reference)
            } else {
                Partition::Namespace(NamespaceKey::deployment_default())
            };
            let store = WorkerNamespaceStore::new(
                StubTransport::new(env.clone(), cfg.placement.clone()),
                cfg.probe_partition(),
            );
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
                    outbox.relay(
                        &target,
                        vec![
                            (key.clone(), Value::default()),
                            (keys::published_member(&repo.name, &pack), Value::default()),
                        ],
                    );
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
        /// one frame (a whole bounded `ListRefs` page).
        pub(super) fn report_peak(path: &str, bytes: usize) {
            let memory = core::arch::wasm32::memory_size::<0>() * 65_536;
            worker::console_log!(
                "mkit-adapter peak-buffered-bytes {bytes} wasm-memory-bytes {memory} path {path}"
            );
        }
    }
}

#[cfg(test)]
#[path = "adapter/activation_tests.rs"]
mod activation_tests;

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
    #[allow(
        clippy::too_many_lines,
        reason = "Keeps shared alarm reservation and adapter restart in one regression"
    )]
    fn publication_recheck_checkpoints_at_the_shared_alarm_limit() {
        use mkit_server::pipeline::{D34Shards, ShardMap};
        use mkit_server::store::publication::{Advance, Clearance, Pair, Publication, Witness};
        use mkit_server::timers::{TickBudget, run_due};
        use mkit_server::{
            Batch, BatchOutcome, NamespaceKey, NamespaceStore, RepoId, RepoName, Value,
        };
        block_on(async {
            let clock = Arc::new(mkit_server::ManualClock::new(0));
            let kv = Arc::new(mkit_server::MemoryKv::with_clock(clock.clone()));
            let repo = RepoId {
                namespace: NamespaceKey::deployment_default(),
                name: RepoName::new("budgeted").unwrap(),
            };
            let name = "refs/heads/main";
            let source = D34Shards.ref_shard(&repo, name);
            let key = mkit_server::store::keys::advance(&repo.name, name, 1);
            let state = Publication {
                sequence: 1,
                published: 0,
                boundary: 0,
                generation: 0,
                value: Pair::default(),
            };
            let advance = Advance {
                sequence: 1,
                generation: 0,
                value: Pair::default(),
                additions: vec![],
                dependencies: vec![[1; 32], [2; 32]],
                external_bases: vec![],
                obligations: vec![],
                state: Clearance::Pending,
                operation: [3; 32],
            };
            // Current fixed-width initial cursor: version 1, zero binding/position.
            let mut initial = vec![0; 37];
            initial[0] = 1;
            assert_eq!(
                kv.apply(
                    &source,
                    Batch::new()
                        .put(key.clone(), advance.encode().unwrap())
                        .put(
                            mkit_server::store::keys::publication(&repo.name, name),
                            state.encode().unwrap()
                        )
                        .put(
                            mkit_server::store::keys::timer(0, 12, key.as_bytes()),
                            Value::new(initial)
                        )
                )
                .await
                .unwrap(),
                BatchOutcome::Committed
            );
            for pack in &advance.dependencies {
                let target = D34Shards.membership(&repo, &mkit_server::BlobKey::pack(*pack));
                let witness = Witness {
                    generation: 0,
                    sequence: 1,
                    published: true,
                    held: false,
                };
                kv.apply(
                    &target,
                    Batch::new().put(
                        mkit_server::store::keys::published_member(&repo.name, pack),
                        witness.encode(),
                    ),
                )
                .await
                .unwrap();
            }
            let budget = mkit_server::purge::SliceBudget::new(crate::purge::ALARM_OPERATIONS);
            assert!(budget.charge(crate::purge::ALARM_OPERATIONS - 1));
            let registry = timer_registry_budgeted::<_, _>(
                crate::classes::ShardClass::RefShard,
                Ok(kv.clone()),
                Some("paid"),
                Some(&budget),
                None,
                None,
                None,
            );
            let report = run_due(
                &kv,
                &source,
                &registry,
                clock.as_ref(),
                0,
                &TickBudget::default(),
            )
            .await
            .unwrap();
            assert_eq!((report.fired, report.failed), (1, 0));
            assert_eq!(budget.used(), crate::purge::ALARM_OPERATIONS);
            assert_eq!(
                mkit_server::store::publication::read(&kv, &source, &repo.name, name)
                    .await
                    .unwrap()
                    .published,
                0
            );
            let continued = kv
                .get(
                    &source,
                    &mkit_server::store::keys::timer(5_000, 12, key.as_bytes()),
                )
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                &continued.as_bytes()[33..],
                &1u32.to_le_bytes(),
                "one charged call must checkpoint one witness"
            );
            budget.reset();
            let report = run_due(
                &kv,
                &source,
                &registry,
                clock.as_ref(),
                5_000,
                &TickBudget::default(),
            )
            .await
            .unwrap();
            assert_eq!((report.fired, report.failed), (1, 0));
            assert_eq!(
                budget.used(),
                1,
                "resume must neither reread nor double-charge"
            );
            assert_eq!(
                mkit_server::store::publication::read(&kv, &source, &repo.name, name)
                    .await
                    .unwrap()
                    .published,
                1
            );
        });
    }

    #[test]
    fn authority_fence_configuration_is_complete_permissioned_and_default_off() {
        let ns = "ed25519-0101010101010101010101010101010101010101010101010101010101010101";
        let public = mkit_core::hash::to_hex(
            &mkit_core::hash::from_hex(
                "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c",
            )
            .unwrap(),
        );
        let key = format!("deployment {public} {ns}");
        let base = [
            (AUDIENCE_VAR, "https://vcs.example"),
            (ADDRESSING_VAR, "multi"),
            (NAMESPACE_POLICY_VAR, "allowlist"),
            (NAMESPACE_ALLOWLIST_VAR, ns),
            (
                TICKET_KEYS_VAR,
                "ticket 0909090909090909090909090909090909090909090909090909090909090909",
            ),
            ("HOOK_ROLES", "authorize"),
            ("AUTHORIZER_ROLE", "authority"),
        ];
        assert!(
            WorkerConfig::from_vars(vars(&base))
                .unwrap()
                .authority_fence
                .is_none()
        );
        let mut pairs = base.to_vec();
        pairs.push(("AUTHORITY_FENCE", "true"));
        assert!(WorkerConfig::from_vars(vars(&pairs)).is_err());
        pairs.push(("AUTHORITY_KEYS", &key));
        let cfg = WorkerConfig::from_vars(vars(&pairs)).unwrap();
        assert!(cfg.pipeline_config().unwrap().authority_fence.is_some());
        pairs.push(("AUTHORIZER_ROLE", "check"));
        assert!(WorkerConfig::from_vars(vars(&pairs)).is_err());
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
    fn default_repo_visibility_is_public_configurable_and_propagated() {
        use mkit_server::pipeline::RepoVisibility;
        let base = [
            (AUDIENCE_VAR, "https://vcs.example"),
            (REPOSITORY_VAR, "default"),
        ];
        let mut cfg = WorkerConfig::from_vars(vars(&base)).unwrap();
        assert_eq!(cfg.default_repo_visibility, RepoVisibility::Public);
        assert_eq!(
            cfg.pipeline_config().unwrap().default_repo_visibility,
            RepoVisibility::Public
        );
        for (value, expected) in [
            ("public", RepoVisibility::Public),
            ("private", RepoVisibility::Private),
        ] {
            let mut pairs = base.to_vec();
            pairs.push((DEFAULT_REPO_VISIBILITY_VAR, value));
            let cfg = WorkerConfig::from_vars(vars(&pairs)).unwrap();
            assert_eq!(cfg.default_repo_visibility, expected);
            assert_eq!(
                cfg.pipeline_config().unwrap().default_repo_visibility,
                expected
            );
        }
        cfg.default_repo_visibility = RepoVisibility::Private;
        assert_eq!(
            cfg.pipeline_config().unwrap().default_repo_visibility,
            RepoVisibility::Private
        );
        for value in ["", "PRIVATE", "friends", " public"] {
            let mut pairs = base.to_vec();
            pairs.push((DEFAULT_REPO_VISIBILITY_VAR, value));
            assert_eq!(
                WorkerConfig::from_vars(vars(&pairs)).unwrap_err(),
                ConfigError("DEFAULT_REPO_VISIBILITY must be public or private".into())
            );
        }
    }

    /// The hook vars are part of the config: absent means the built-in hooks,
    /// present they reach the pipeline's authorizer role, and a malformed one
    /// is a config error like any other.
    #[test]
    fn hook_vars_are_parsed_with_the_config() {
        let base = [
            (AUDIENCE_VAR, "https://vcs.example"),
            (REPOSITORY_VAR, "default"),
        ];
        let plain = WorkerConfig::from_vars(vars(&base)).unwrap();
        assert!(plain.hooks.is_none());
        assert_eq!(
            plain.pipeline_config().unwrap().authorizer_role,
            mkit_server::policy::AuthorizerRole::Check
        );
        let mut pairs = base.to_vec();
        pairs.extend([
            ("HOOK_ROLES", "authorize,admit"),
            ("AUTHORIZER_ROLE", "authority"),
        ]);
        let cfg = WorkerConfig::from_vars(vars(&pairs)).unwrap();
        let hooks = cfg.hooks.as_ref().unwrap();
        assert!(hooks.roles.authorize && hooks.roles.admit && !hooks.roles.outcome);
        assert_eq!(
            cfg.pipeline_config().unwrap().authorizer_role,
            mkit_server::policy::AuthorizerRole::Authority
        );
        pairs.push(("HOOK_TIMEOUT_MS", "0"));
        assert!(WorkerConfig::from_vars(vars(&pairs)).is_err());
    }

    #[test]
    #[cfg(feature = "signed-http-hooks")]
    fn purge_configuration_is_default_off_paid_only_and_enables_only_the_sink() {
        let mut pairs = vec![
            (AUDIENCE_VAR, "https://vcs.example"),
            (REPOSITORY_VAR, "default"),
        ];
        assert!(
            WorkerConfig::from_vars(vars(&pairs))
                .unwrap()
                .pipeline_config()
                .unwrap()
                .purge
                .is_none()
        );
        pairs.extend([
            ("HOOK_ROLES", "cache-purge"),
            ("HOOK_URL", "https://hooks.example"),
        ]);
        assert!(WorkerConfig::from_vars(vars(&pairs)).is_err());
        pairs.push((PLAN_VAR, "paid"));
        assert!(
            WorkerConfig::from_vars(vars(&pairs))
                .unwrap_err()
                .0
                .contains("MKIT_HOOK_KEY")
        );
        pairs.push((
            "MKIT_HOOK_KEY",
            "purge 3333333333333333333333333333333333333333333333333333333333333333",
        ));
        let config = WorkerConfig::from_vars(vars(&pairs)).unwrap();
        let purge = config.pipeline_config().unwrap().purge.unwrap();
        assert!(purge.shared_caches && purge.remote_sink);
        assert_eq!(purge.audience, "https://vcs.example");
        let roles = config.hooks.unwrap().roles;
        assert!(roles.cache_purge && !roles.admit && !roles.authorize && !roles.outcome);
    }

    #[test]
    fn inspection_requires_restricted_indexed_tickets_and_forces_ticket_threshold() {
        let namespace = ns(1);
        let secret = "dev 1111111111111111111111111111111111111111111111111111111111111111";
        let pairs = [
            (AUDIENCE_VAR, "https://vcs.example"),
            (ADDRESSING_VAR, "multi"),
            (NAMESPACE_ALLOWLIST_VAR, namespace.as_str()),
            (TICKET_KEYS_VAR, secret),
        ];
        let mut config = WorkerConfig::from_vars(vars(&pairs)).unwrap();
        config.hooks = crate::hooks::config::HookVars::parse(&|name| {
            (name == "HOOK_ROLES").then(|| "inspect".into())
        })
        .unwrap();
        assert!(config.pipeline_config().is_err());
        config.indexed = Some(mkit_server::indexed::IndexedConfig::scheduled(
            config.max_pack_bytes,
        ));
        let scanner_public =
            mkit_server::hooks::HookSigner::new("scanner", zeroize::Zeroizing::new([0x33; 32]))
                .unwrap()
                .public_key();
        config.scanner_retrieval = Some(Arc::new(
            mkit_server::scanner_retrieval::RetrievalConfig::parse(
                &format!("active retrieval {}", "66".repeat(32)),
                &mkit_core::hash::to_hex(&scanner_public),
            )
            .unwrap(),
        ));
        assert_eq!(
            config
                .pipeline_config()
                .unwrap()
                .begin_upload_threshold_bytes,
            0
        );
        config.ticket_keys = None;
        assert!(config.pipeline_config().is_err());
        let invalid = [
            (AUDIENCE_VAR, "https://vcs.example"),
            (REPOSITORY_VAR, "default"),
            ("HOOK_ROLES", "inspect"),
            (PLAN_VAR, "paid"),
        ];
        assert!(WorkerConfig::from_vars(vars(&invalid)).is_err());
    }

    #[test]
    fn paid_relay_and_quota_clients_charge_the_same_alarm_budget_before_calls() {
        use futures::executor::block_on;
        use mkit_server::NamespaceStore;
        let budget = mkit_server::purge::SliceBudget::new(2);
        let store = SharedStore(
            Arc::new(mkit_server::MemoryKv::default()),
            Some(budget.clone()),
        );
        let partition =
            mkit_server::Partition::Namespace(mkit_server::NamespaceKey::deployment_default());
        let key = mkit_server::Key::new(b"test".to_vec());
        block_on(store.get(&partition, &key)).unwrap();
        block_on(store.clone().apply(&partition, mkit_server::Batch::new())).unwrap();
        assert!(block_on(store.get(&partition, &key)).is_err());
        assert_eq!(budget.used(), 2);
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

    #[cfg(feature = "published-view")]
    #[test]
    fn published_view_config_requires_valid_identity_multi_and_d34_and_caps_pages() {
        let secret = "dev 1111111111111111111111111111111111111111111111111111111111111111";
        let namespace = ns(1);
        let pairs = [
            (AUDIENCE_VAR, "https://vcs.example"),
            (ADDRESSING_VAR, "multi"),
            (NAMESPACE_ALLOWLIST_VAR, namespace.as_str()),
            (TICKET_KEYS_VAR, secret),
        ];
        let mut cfg = WorkerConfig::from_vars(vars(&pairs)).unwrap();
        assert!(cfg.published_view.is_none());
        assert_eq!(cfg.pipeline_config().unwrap().max_list_refs_page_size, 1000);
        cfg.published_view =
            Some(crate::published_view::PublishedViewConfig::new("stage").unwrap());
        assert_eq!(cfg.pipeline_config().unwrap().max_list_refs_page_size, 128);
        cfg.published_view.as_mut().unwrap().deployment = "bad/identity".into();
        assert!(cfg.pipeline_config().is_err());
        cfg.published_view.as_mut().unwrap().deployment = "stage".into();
        cfg.sharding = Sharding::Single;
        assert!(cfg.pipeline_config().is_err());
        cfg.sharding = Sharding::D34;
        cfg.addressing = mkit_server::Addressing::Single {
            repo: mkit_server::RepoId {
                namespace: mkit_server::NamespaceKey::deployment_default(),
                name: mkit_server::RepoName::new("default").unwrap(),
            },
        };
        assert!(cfg.pipeline_config().is_err());
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

    /// One Free-plan rollup fire may make `limit` coordinator calls; the next
    /// is a retryable `StoreError`, never a silent overrun.
    #[test]
    fn rollup_budget_fails_the_call_past_its_limit() {
        use mkit_server::{Key, MemoryKv, NamespaceKey, NamespaceStore, Partition, StoreError};
        let store = BudgetedStore {
            inner: SharedStore(Arc::new(MemoryKv::default()), None),
            used: Arc::new(core::sync::atomic::AtomicU32::new(0)),
            limit: 2,
        };
        let partition = Partition::Namespace(NamespaceKey::deployment_default());
        let key = Key::new(b"k".to_vec());
        for _ in 0..2 {
            assert_eq!(block_on(store.get(&partition, &key)).unwrap(), None);
        }
        assert!(matches!(
            block_on(store.get(&partition, &key)),
            Err(StoreError::Unavailable(_))
        ));
    }

    /// An expired-window fire with a pending shard delta stays within the
    /// Free cap of 8 coordinator calls, and `get_many`/`scan_many` charge 1.
    #[test]
    fn expired_window_rollup_fits_the_free_cap() {
        use mkit_server::timers::{TickBudget, TimerRegistry, run_due};
        use mkit_server::{
            Batch, Key, ManualClock, MemoryKv, NamespaceKey, NamespaceStore, Partition, RangeScan,
            RepoName,
        };
        let clock = Arc::new(ManualClock::new(700_000));
        let coordinator = Arc::new(MemoryKv::with_clock(clock.clone()));
        let used = Arc::new(core::sync::atomic::AtomicU32::new(0));
        let handler = mkit_server::timers::quota_rollup::QuotaRollup {
            coordinator: BudgetedStore {
                inner: SharedStore(coordinator, None),
                used: Arc::clone(&used),
                limit: FREE_ROLLUP_CALLS,
            },
            metrics: mkit_server::NoopMetrics,
        };
        let local = MemoryKv::with_clock(clock.clone());
        let shard = Partition::Ref {
            ns: NamespaceKey::deployment_default(),
            repo: RepoName::new("room").unwrap(),
            shard_ref: "refs/heads/b0".into(),
        };
        let reference = bytes::Bytes::copy_from_slice(&0u64.to_be_bytes());
        let timer_key = mkit_server::store::keys::timer(
            60_000,
            mkit_server::timers::registry::kinds::QUOTA_ROLLUP.get(),
            &reference,
        );
        block_on(
            local.apply(
                &shard,
                Batch::new()
                    .put(
                        mkit_server::store::keys::quota_shard(0),
                        mkit_server::store::codec::encode_namespace_usage(
                            mkit_server::quota::NamespaceUsage { ops: 3, bytes: 12 },
                        ),
                    )
                    .put(timer_key, mkit_server::store::codec::encode_u64(60_000)),
            ),
        )
        .unwrap();
        let registry = TimerRegistry::new().register(handler);
        let out = block_on(run_due(
            &local,
            &shard,
            &registry,
            clock.as_ref(),
            700_000,
            &TickBudget::default(),
        ))
        .unwrap();
        assert_eq!(out.fired, 1);
        assert!(used.load(core::sync::atomic::Ordering::SeqCst) <= FREE_ROLLUP_CALLS);
        // One charge per batched read, whatever its width.
        let store = BudgetedStore {
            inner: SharedStore(Arc::new(MemoryKv::default()), None),
            used: Arc::new(core::sync::atomic::AtomicU32::new(0)),
            limit: 100,
        };
        let p = Partition::Namespace(NamespaceKey::deployment_default());
        let keys = [Key::new(b"a".to_vec()), Key::new(b"b".to_vec())];
        block_on(store.get_many(&p, &keys)).unwrap();
        let range = RangeScan::new(Key::new(b"a".to_vec()), Key::new(b"z".to_vec()), None, 10);
        block_on(store.scan_many(&p, &[range.clone(), range])).unwrap();
        assert_eq!(store.used.load(core::sync::atomic::Ordering::SeqCst), 2);
    }

    #[test]
    #[allow(clippy::too_many_lines)] // End-to-end registration and cleanup fixture.
    fn worker_registry_delivers_a_current_96_effect_generic_relay_in_two_calls() {
        use mkit_server::store::{codec, keys, outbox::OutboxBuilder};
        use mkit_server::timers::{TickBudget, run_due};
        use mkit_server::{
            Batch, Key, ManualClock, MemoryKv, NamespaceKey, NamespaceStore, Partition, RepoName,
            Value,
        };
        let clock = Arc::new(ManualClock::new(100));
        let local = MemoryKv::with_clock(clock.clone());
        let remote = Arc::new(MemoryKv::with_clock(clock.clone()));
        let calls = Arc::new(core::sync::atomic::AtomicU32::new(0));
        let source = Partition::Ref {
            ns: NamespaceKey::deployment_default(),
            repo: RepoName::new("room").unwrap(),
            shard_ref: "refs/heads/main".into(),
        };
        let target = Partition::ContentShard(0);
        let mut builder = OutboxBuilder::new(None, None).unwrap();
        builder.relay_at(50);
        builder.relay(
            &target,
            (0..96_u8)
                .map(|n| (Key::new(vec![b'x', n]), Value::new(vec![n])))
                .collect(),
        );
        let mut batch = Batch::new();
        builder
            .try_finish(&mut batch.preconditions, &mut batch.writes)
            .unwrap();
        block_on(local.apply(&source, batch)).unwrap();
        let registry = timer_registry(
            crate::classes::ShardClass::RefShard,
            Ok(BudgetedStore {
                inner: SharedStore(remote.clone(), None),
                used: calls.clone(),
                limit: 2,
            }),
            Some("free"),
        );
        let report = block_on(run_due(
            &local,
            &source,
            &registry,
            clock.as_ref(),
            100,
            &TickBudget::default(),
        ))
        .unwrap();
        assert_eq!(report.fired, 1);
        assert_eq!(calls.load(core::sync::atomic::Ordering::SeqCst), 2);
        for n in 0..96_u8 {
            assert_eq!(
                block_on(remote.get(&target, &Key::new(vec![b'x', n]))).unwrap(),
                Some(Value::new(vec![n]))
            );
        }
        assert_eq!(
            block_on(remote.get(&target, &keys::relay_high_water(&source).unwrap())).unwrap(),
            Some(codec::encode_u64(1))
        );
        let object = [0x78; 32];
        let hold = [0x79; 32];
        let identity = mkit_server::store::PendingHolderV1::new(
            mkit_server::store::Holder::new(
                NamespaceKey::deployment_default(),
                RepoName::new("room").unwrap(),
            ),
            source.clone(),
            [0x7a; 32],
            object,
            hold,
            [0x7b; 32],
        )
        .unwrap();
        let idx = mkit_server::store::ContentIndex::new(SharedStore(remote.clone(), None));
        assert_eq!(
            block_on(idx.add_hold(&object, &hold, 20_000, 100)).unwrap(),
            mkit_server::store::HoldOutcome::Held
        );
        assert_eq!(
            block_on(idx.protect_pending_holder(&object, &hold, &identity, 100)).unwrap(),
            mkit_server::store::HoldOutcome::Held
        );
        let destination = mkit_server::store::content_shard(&object);
        let os = block_on(local.get(&source, &keys::outbox_sequence())).unwrap();
        let mut builder = OutboxBuilder::new(os.as_ref(), None).unwrap();
        builder.relay_at(50);
        builder.relay(
            &destination,
            vec![(
                keys::pending_holder(&object, &hold),
                identity.encode().unwrap(),
            )],
        );
        let mut batch = Batch::new();
        builder
            .try_finish(&mut batch.preconditions, &mut batch.writes)
            .unwrap();
        block_on(local.apply(&source, batch)).unwrap();
        calls.store(0, core::sync::atomic::Ordering::SeqCst);
        block_on(run_due(
            &local,
            &source,
            &registry,
            clock.as_ref(),
            100,
            &TickBudget::default(),
        ))
        .unwrap();
        assert_eq!(calls.load(core::sync::atomic::Ordering::SeqCst), 2);
        assert!(
            block_on(remote.get(
                &destination,
                &keys::holder(&object, &identity.holder.ns, &identity.holder.repo).unwrap()
            ))
            .unwrap()
            .is_some()
        );
        assert!(
            block_on(remote.get(&destination, &keys::pending_holder(&object, &hold)))
                .unwrap()
                .is_none()
        );
        assert!(
            block_on(remote.get(&destination, &keys::hold(&object, &hold)))
                .unwrap()
                .is_none()
        );
        let content = timer_registry::<MemoryKv, MemoryKv>(
            crate::classes::ShardClass::ContentIndexShard,
            Ok(MemoryKv::default()),
            Some("paid"),
        );
        assert!(format!("{content:?}").contains("TimerKind(13)"));
    }

    #[test]
    fn paid_rollup_backlog_is_bounded_and_resumes_until_drained() {
        use mkit_server::store::{codec, keys};
        use mkit_server::timers::{TickBudget, TimerRegistry, run_due};
        use mkit_server::{
            Batch, ManualClock, MemoryKv, NamespaceKey, NamespaceStore, Partition, RepoName,
        };
        let clock = Arc::new(ManualClock::new(700_000));
        let coordinator = Arc::new(MemoryKv::with_clock(clock.clone()));
        let namespace = NamespaceKey::deployment_default();
        let target = Partition::Coordinator(namespace.clone());
        let shard = Partition::Ref {
            ns: namespace.clone(),
            repo: RepoName::new("room").unwrap(),
            shard_ref: "refs/heads/main".into(),
        };
        for n in 0..65 {
            let source = Partition::Ref {
                ns: namespace.clone(),
                repo: RepoName::new("room").unwrap(),
                shard_ref: format!("refs/heads/{n}"),
            };
            block_on(coordinator.apply(
                &target,
                Batch::new().put(
                    keys::quota_contribution(0, &source).unwrap(),
                    codec::encode_namespace_usage(mkit_server::quota::NamespaceUsage {
                        ops: 1,
                        bytes: 1,
                    }),
                ),
            ))
            .unwrap();
        }
        let handler =
            WorkerQuotaRollup::new(Ok(SharedStore(coordinator.clone(), None)), Some("paid"));
        let used = handler.used.clone();
        let registry = TimerRegistry::new().register(handler);
        let local = MemoryKv::with_clock(clock.clone());
        let timer = keys::timer(
            60_000,
            mkit_server::timers::registry::kinds::QUOTA_ROLLUP.get(),
            &1_u64.to_be_bytes(),
        );
        block_on(local.apply(&shard, Batch::new().put(timer, codec::encode_u64(60_000)))).unwrap();
        let (start, end) = keys::quota_namespace_before(keys::TAG_QUOTA_CONTRIBUTION, 1);
        for attempt in 0..20 {
            let report = block_on(run_due(
                &local,
                &shard,
                &registry,
                clock.as_ref(),
                u64::try_from(mkit_server::Clock::now_ms(clock.as_ref())).unwrap(),
                &TickBudget::default(),
            ))
            .unwrap();
            assert_eq!(report.fired, 1);
            // The ninth attempted call fails before reaching the coordinator.
            assert!(used.load(core::sync::atomic::Ordering::SeqCst) <= 9);
            let remaining = block_on(coordinator.scan(&target, &start, &end, None, 100)).unwrap();
            if attempt == 0 {
                assert!(
                    !remaining.entries.is_empty(),
                    "bounded prune must retain its continuation"
                );
                assert!(
                    remaining.entries.len() < 65,
                    "committed prune pages survive retry"
                );
            }
            if report.next_wake_ms.is_none() {
                assert!(remaining.entries.is_empty());
                return;
            }
            clock.advance(60_000);
        }
        panic!("bounded Paid rollup failed to finish its backlog");
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
        assert_eq!(
            cfg.grants,
            WorkerConfig::from_vars(vars(&pairs)).unwrap().grants
        );
        assert_ne!(cfg.grants, off.grants);
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

    #[cfg(not(feature = "test-faults"))]
    #[test]
    fn release_never_reads_m3_test_vars() {
        let cfg = WorkerConfig::from_vars(|name| {
            assert!(
                !name.starts_with("TEST_"),
                "test var reached release configuration"
            );
            match name {
                "AUTH_AUDIENCE" => Some("https://vcs.test".into()),
                "AUTH_REPOSITORY" => Some("default".into()),
                _ => None,
            }
        })
        .unwrap();
        let pipe = cfg.pipeline_config().unwrap();
        assert_eq!(pipe.ticket_ttl_ms, 86_400_000);
        assert_eq!(pipe.outbox_backlog_cap.unwrap().rows, 100_000);
    }
    #[cfg(feature = "test-faults")]
    #[test]
    fn m3_test_vars_are_bounded_and_injected() {
        for bad in ["0", "17", "invalid"] {
            assert!(test_number(&|_| Some(bad.into()), "TEST_OUTBOX_BACKLOG_ROWS", 16).is_err());
        }
        let cfg = WorkerConfig::from_vars(|name| match name {
            "AUTH_AUDIENCE" => Some("https://vcs.test".into()),
            "AUTH_REPOSITORY" => Some("default".into()),
            "TEST_OUTBOX_BACKLOG_ROWS" => Some("16".into()),
            "TEST_TICKET_TTL_MS" => Some("3000".into()),
            _ => None,
        })
        .unwrap();
        let pipe = cfg.pipeline_config().unwrap();
        assert_eq!(pipe.ticket_ttl_ms, 3000);
        assert_eq!(pipe.outbox_backlog_cap.unwrap().rows, 16);
    }

    #[cfg(feature = "test-faults")]
    #[test]
    fn test_ticket_ttl_is_positive_or_unset() {
        let base = [(AUDIENCE_VAR, "https://x.example"), (REPOSITORY_VAR, "r")];
        let cfg = WorkerConfig::from_vars(vars(&base)).unwrap();
        assert_eq!(cfg.test_ticket_ttl_ms, None);
        let mut short = base.to_vec();
        short.push(("TEST_TICKET_TTL_MS", "20000"));
        let cfg = WorkerConfig::from_vars(vars(&short)).unwrap();
        assert_eq!(cfg.test_ticket_ttl_ms, Some(20_000));
        assert_eq!(cfg.pipeline_config().unwrap().ticket_ttl_ms, 20_000);
        for bad in ["0", "-1", "soon"] {
            let mut vars_bad = base.to_vec();
            vars_bad.push(("TEST_TICKET_TTL_MS", bad));
            assert!(WorkerConfig::from_vars(vars(&vars_bad)).is_err(), "{bad}");
        }
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

    /// A release build requires the explicit launch profile for indexed mode.
    #[cfg(not(feature = "test-faults"))]
    #[test]
    fn a_release_worker_requires_launch_selection_for_indexed_mode() {
        for value in ["true", "1", "yes", "on"] {
            let err =
                WorkerConfig::from_vars(|name| (name == "INDEXED_MODE").then(|| value.to_owned()))
                    .unwrap_err();
            assert!(
                err.to_string()
                    .contains("INDEXED_MODE requires LAUNCH_PROFILE=uno"),
                "{value}"
            );
        }
        for value in ["", "0", "false", "FALSE"] {
            let vars = |name: &str| match name {
                "INDEXED_MODE" => Some(value.to_owned()),
                AUDIENCE_VAR => Some("https://example.test".to_owned()),
                REPOSITORY_VAR => Some("repo".to_owned()),
                _ => None,
            };
            assert_eq!(
                WorkerConfig::from_vars(vars).unwrap().indexed,
                None,
                "{value:?}"
            );
        }
    }

    #[cfg(feature = "test-faults")]
    fn indexed_vars<'a>(extra: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |name| {
            if let Some((_, value)) = extra.iter().find(|(key, _)| *key == name) {
                return Some((*value).to_owned());
            }
            match name {
                "INDEXED_MODE" => Some("true".to_owned()),
                AUDIENCE_VAR => Some("https://example.test".to_owned()),
                "ADDRESSING" => Some("multi".to_owned()),
                NAMESPACE_ALLOWLIST_VAR => Some(ns(1)),
                TICKET_KEYS_VAR => Some(
                    "dev 1111111111111111111111111111111111111111111111111111111111111111"
                        .to_owned(),
                ),
                _ => None,
            }
        }
    }

    /// Under `test-faults` the var is accepted only on Paid, in Multi + D34.
    #[cfg(feature = "test-faults")]
    #[test]
    fn indexed_mode_is_scheduled_and_paid_only() {
        let config = WorkerConfig::from_vars(indexed_vars(&[(PLAN_VAR, "paid")])).unwrap();
        let indexed = config.indexed.expect("indexed on Paid");
        assert_eq!(
            indexed.verification,
            mkit_server::indexed::VerificationMode::Scheduled
        );
        assert!(indexed.max_pack_bytes <= indexed.decode_budget);
        assert_eq!(indexed.max_pack_bytes, config.max_pack_bytes);
        assert_eq!(config.pipeline_config().unwrap().indexed, Some(indexed));
        assert_eq!(indexed.max_ancestry_commits, 64);
        let mut enlarged = config.clone();
        enlarged.indexed.as_mut().unwrap().max_ancestry_commits = 256;
        assert_eq!(
            enlarged
                .pipeline_config()
                .unwrap()
                .indexed
                .unwrap()
                .max_ancestry_commits,
            64
        );
        // Free (or an unset plan) cannot run it: every subrequest is assigned.
        for plan in [Some("free"), None] {
            let extra: Vec<(&str, &str)> = plan.map(|plan| (PLAN_VAR, plan)).into_iter().collect();
            let err = WorkerConfig::from_vars(indexed_vars(&extra)).unwrap_err();
            assert!(err.to_string().contains("WORKERS_PLAN=paid"), "{plan:?}");
        }
        let err =
            WorkerConfig::from_vars(indexed_vars(&[(PLAN_VAR, "paid"), ("SHARDING", "single")]))
                .unwrap_err();
        assert!(err.to_string().contains("SHARDING=d34"));
    }

    /// A deployment that does not ask for indexed mode is unchanged: the
    /// pipeline carries no indexed config, so `GetServerInfo` reports
    /// `indexed_mode=false` and no kind-7 handler is ever built.
    #[test]
    fn a_deployment_without_indexed_mode_stays_unindexed() {
        let vars = |name: &str| match name {
            AUDIENCE_VAR => Some("https://example.test".to_owned()),
            REPOSITORY_VAR => Some("repo".to_owned()),
            _ => None,
        };
        let config = WorkerConfig::from_vars(vars).unwrap();
        assert_eq!(config.indexed, None);
        assert_eq!(config.pipeline_config().unwrap().indexed, None);
        for class in [
            crate::classes::ShardClass::RefStore,
            crate::classes::ShardClass::NsCoordinator,
            crate::classes::ShardClass::RefShard,
            crate::classes::ShardClass::RepoIndexShard,
            crate::classes::ShardClass::ContentIndexShard,
        ] {
            let registry = timer_registry::<mkit_server::MemoryKv, mkit_server::MemoryKv>(
                class,
                Ok(mkit_server::MemoryKv::default()),
                Some("paid"),
            );
            assert!(
                !format!("{registry:?}").contains("TimerKind(7)"),
                "{class:?}"
            );
        }
    }

    /// An admission that answers every write with a payment challenge, or
    /// (`deny`) a refusal.
    #[derive(Clone)]
    struct Gate {
        deny: bool,
    }

    impl mkit_server::pipeline::Admission for Gate {
        async fn admit(
            &self,
            _: &mkit_server::pipeline::AdmissionInput<'_>,
        ) -> Result<mkit_server::pipeline::AdmissionDecision, mkit_server::ServerError> {
            if self.deny {
                return Err(mkit_server::ServerError::permission_denied("no writes"));
            }
            Ok(mkit_server::pipeline::AdmissionDecision::challenge(
                vec![mkit_server::pipeline::Challenge {
                    scheme: "payment".to_owned(),
                    value: "id=\"c1\"".to_owned(),
                }],
                "pay",
            ))
        }
    }

    /// The Connect binding with `admission` in front of writes.
    fn gated_service(admission: Gate) -> connectrpc::ConnectRpcService {
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
        let mut cfg = PipelineConfig::new(
            Addressing::Single { repo },
            AuthMode::AuthV2(
                mkit_server::auth_v2::AuthV2Config::new("http://localhost", "default").unwrap(),
            ),
            UploadLimits {
                max_total_bytes: 1 << 20,
                max_chunks: 64,
            },
        );
        cfg.ticket_keys = Some(
            mkit_server::upload::token::TicketKeys::new(vec![("test".into(), [9; 32])]).unwrap(),
        );
        let hooks = Hooks {
            authorizer: mkit_server::pipeline::OpenAuthorizer,
            admission,
            pre_receive: mkit_server::pipeline::NoPreReceive,
            receipts: mkit_server::pipeline::NoReceipts,
            outcomes: mkit_server::pipeline::NoOutcomes,
        };
        let pipe = Pipeline::new(
            MemoryBlobStore::default(),
            MemoryKv::default(),
            hooks,
            cfg,
            Arc::new(SystemClock),
            Arc::new(NoopMetrics),
        )
        .unwrap();
        mkit_server::connect::service(Arc::new(pipe))
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

    /// Every event and span field value, `Debug`-printed, in one buffer.
    #[derive(Clone, Default)]
    struct Captured(Arc<std::sync::Mutex<String>>);

    impl tracing::field::Visit for Captured {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn core::fmt::Debug) {
            use core::fmt::Write as _;
            let _ = write!(self.0.lock().unwrap(), " {}={value:?}", field.name());
        }
    }

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Captured {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _: tracing_subscriber::layer::Context<'_, S>,
        ) {
            event.record(&mut self.clone());
        }

        fn on_new_span(
            &self,
            attrs: &tracing::span::Attributes<'_>,
            _: &tracing::span::Id,
            _: tracing_subscriber::layer::Context<'_, S>,
        ) {
            attrs.record(&mut self.clone());
        }
    }

    /// A write carrying payment credentials, answered by a challenging or a
    /// denying admission (402 / 403), leaves none of the credential values in
    /// any event or span field. Platform invocation logs are outside this test.
    #[test]
    fn credentials_never_reach_the_adapters_tracing() {
        use tracing_subscriber::layer::SubscriberExt as _;
        let captured = Captured::default();
        let subscriber = tracing_subscriber::registry().with(captured.clone());
        let _guard = tracing::subscriber::set_default(subscriber);
        // The capture works: an event of ours shows up in it.
        tracing::info!(marker = "capture-works");
        for (deny, expected) in [(false, 402u16), (true, 403)] {
            let procedure = "/mkit.transport.v1.TransportService/UpdateRef";
            let json = br#"{"name":"refs/heads/x","expectation":"REF_EXPECTATION_ANY","newId":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc="}"#;
            let signed = mkit_server_conformance::wire::sign::Signer::new(
                [5; 32],
                "http://localhost",
                "default",
            )
            .sign_body(procedure, json);
            let mut builder = http::Request::builder()
                .method(http::Method::POST)
                .uri(format!("http://w.example{procedure}"))
                .header("content-type", "application/json")
                .header("connect-protocol-version", "1")
                .header("payment-authorization", "pay-secret-0123")
                .header("payment-signature", "paysig-secret-0123")
                .header("authorization", "Payment scheme-secret-0123");
            for (name, value) in &signed.headers {
                builder = builder.header(name, value);
            }
            let req = builder
                .body(LimitedBody::new(
                    frames(&[json]),
                    1024,
                    BodyWatch::default(),
                ))
                .unwrap();
            let runtime = runtime();
            let resp = runtime.block_on(dispatch_oneshot_body(gated_service(Gate { deny }), req));
            assert_eq!(resp.status().as_u16(), expected);
            let _ = runtime.block_on(resp.into_body().collect());
        }
        let out = captured.0.lock().unwrap().clone();
        for secret in [
            "pay-secret-0123",
            "paysig-secret-0123",
            "scheme-secret-0123",
        ] {
            assert!(!out.contains(secret), "{secret} leaked: {out}");
        }
    }

    pub(super) async fn late_holder_fixture() -> (
        Arc<mkit_server::ManualClock>,
        Arc<mkit_server::MemoryKv>,
        mkit_server::Partition,
        mkit_server::Partition,
        mkit_server::Key,
    ) {
        use mkit_server::store::{BlockEntry, ContentIndex, Holder, PendingHolderV1, keys};
        use mkit_server::{
            Batch, ManualClock, MemoryKv, NamespaceKey, NamespaceStore, Partition, RepoName, Value,
        };
        let clock = Arc::new(ManualClock::new(1000));
        let store = Arc::new(MemoryKv::with_clock(clock.clone()));
        let root = Partition::Namespace(NamespaceKey::deployment_default());
        let request = mkit_server::relay::ContentTakedownV1 {
            identity: PendingHolderV1::new(
                Holder::new(
                    NamespaceKey::deployment_default(),
                    RepoName::new("late").unwrap(),
                ),
                root.clone(),
                [3; 32],
                [1; 32],
                [2; 32],
                [4; 32],
            )
            .unwrap(),
            blocked: BlockEntry::new("private reason", 998),
            queued_at_ms: 999,
            ready_at_ms: Some(1000),
        };
        let partition = mkit_server::store::content_shard(&request.identity.object);
        ContentIndex::new(store.clone())
            .block(&request.identity.object, &request.blocked, 1000)
            .await
            .unwrap();
        let row = keys::content_takedown(&request.identity.object, &request.identity.intent);
        let reference = [
            request.identity.object.as_slice(),
            request.identity.intent.as_slice(),
        ]
        .concat();
        store
            .apply(
                &partition,
                Batch::new()
                    .put(row.clone(), request.encode().unwrap())
                    .put(keys::timer(1000, 13, &reference), Value::default()),
            )
            .await
            .unwrap();
        (clock, store, root, partition, row)
    }

    #[test]
    fn real_late_holder_registration_takes_ownership_only_when_selected() {
        use mkit_server::store::keys;
        use mkit_server::timers::{TickBudget, run_due};
        use mkit_server::{MemoryKv, NamespaceStore};
        block_on(async {
            let (clock, store, root, partition, row) = late_holder_fixture().await;
            let off = timer_registry::<MemoryKv, _>(
                crate::classes::ShardClass::ContentIndexShard,
                Ok(store.clone()),
                Some("paid"),
            );
            run_due(
                store.as_ref(),
                &partition,
                &off,
                clock.as_ref(),
                1000,
                &TickBudget::default(),
            )
            .await
            .unwrap();
            assert!(store.get(&partition, &row).await.unwrap().is_some());
            assert!(
                store
                    .get(&root, &mkit_server::Key::new(b"ah\0".to_vec()))
                    .await
                    .unwrap()
                    .is_none()
            );
            clock.set(3_601_000);
            let budget = mkit_server::purge::SliceBudget::new(1000);
            let on = timer_registry_budgeted::<MemoryKv, _>(
                crate::classes::ShardClass::ContentIndexShard,
                Ok(store.clone()),
                Some("paid"),
                Some(&budget),
                Some(&root),
                Some(&root),
                None,
            );
            run_due(
                store.as_ref(),
                &partition,
                &on,
                clock.as_ref(),
                3_601_000,
                &TickBudget::default(),
            )
            .await
            .unwrap();
            assert!(store.get(&partition, &row).await.unwrap().is_none());
            assert!(
                store
                    .get(&root, &mkit_server::Key::new(b"ah\0".to_vec()))
                    .await
                    .unwrap()
                    .is_some()
            );
            let (start, end) = keys::class_range(keys::TAG_TIMER);
            let timers = store.scan(&root, &start, &end, None, 16).await.unwrap();
            assert!(timers.entries.iter().any(|(key, _)| matches!(
                keys::parse(key),
                Some(keys::ParsedKey::Timer { kind: 15, .. })
            )));
            assert!(budget.used() > 0 && budget.used() < 1000);
        });
    }
}
