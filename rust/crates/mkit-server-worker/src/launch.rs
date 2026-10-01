//! Paid indexed launch selection and fail-closed prerequisite checks (R-194).
//! No environment variable can override implementation readiness.
use crate::adapter::{ConfigError, WorkerConfig};

/// Explicit launch selection; optional features are validated independently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchConfig {
    /// Enable the completed lean takedown catalog, never the hold/reinstate ops.
    pub takedown: bool,
}

fn error(message: impl Into<String>) -> ConfigError {
    ConfigError(message.into())
}

/// Check supported programmatic changes against the parsed launch contract.
pub(crate) fn validate_programmatic(cfg: &WorkerConfig) -> Result<(), ConfigError> {
    #[cfg(not(feature = "test-faults"))]
    {
        let indexed = cfg.indexed.is_some();
        #[cfg(feature = "http-objects")]
        let indexed = indexed || cfg.http_mount.is_some();
        if indexed && cfg.launch.is_none() {
            return Err(error(
                "indexed Worker configuration requires LAUNCH_PROFILE=uno",
            ));
        }
    }
    if cfg.launch.is_some()
        && (cfg.indexed.is_none_or(|indexed| {
            indexed.verification != mkit_server::indexed::VerificationMode::Scheduled
        }) || cfg.ticket_keys.is_none()
            || !matches!(cfg.addressing, mkit_server::Addressing::Multi(_))
            || cfg.sharding != mkit_server::pipeline::Sharding::D34)
    {
        return Err(error(
            "launch requires scheduled indexed Multi, D34 and TICKET_KEYS",
        ));
    }
    validate_key_roles(cfg)?;
    if cfg.launch.is_some() && !cfg.audience.starts_with("https://") {
        return Err(error("launch requires a canonical HTTPS AUTH_AUDIENCE"));
    }
    if cfg
        .admin
        .as_ref()
        .is_some_and(|admin| admin.audience() != cfg.audience)
    {
        return Err(error("ADMIN_KEYS audience must match AUTH_AUDIENCE"));
    }
    if let Some(hooks) = &cfg.hooks {
        if hooks.roles.inspect && cfg.scanner_retrieval.is_none() {
            return Err(error(
                "inspection requires complete SCANNER_RETRIEVAL_KEYS and SCANNER_KEYS",
            ));
        }
        if hooks.roles.inspect && !(1..=10000).contains(&hooks.inspect_batch_max_objects) {
            return Err(error("INSPECT_BATCH_MAX_OBJECTS must be 1..=10000"));
        }
        if hooks.timeout.is_zero()
            || hooks.timeout.as_millis() > u128::from(crate::hooks::config::MAX_TIMEOUT_MS)
        {
            return Err(error("HOOK_TIMEOUT_MS must be 1..=30000"));
        }
    }
    if cfg.scanner_retrieval.is_some()
        && cfg.hooks.as_ref().is_none_or(|hooks| !hooks.roles.inspect)
    {
        return Err(error("scanner retrieval requires an inspector"));
    }
    if cfg.takedown_denial
        || cfg.takedown.is_some()
        || cfg.launch.as_ref().is_some_and(|v| v.takedown)
    {
        validate_preservation(cfg, &|_| None)?;
    }
    #[cfg(feature = "http-objects")]
    if let Some(mount) = &cfg.http_mount {
        mount
            .http_objects
            .validate(mount.indexed.extract_min_bytes)
            .map_err(|e| error(e.to_string()))?;
        if cfg.launch.is_some() {
            if cfg.url_tokens.is_none() {
                return Err(error("HTTP_OBJECTS requires dedicated URL_TOKEN_KEYS"));
            }
            if cfg.indexed != Some(mount.indexed) {
                return Err(error(
                    "launch HTTP and verification must use the same indexed configuration",
                ));
            }
            if mount.http_objects.admit_reads && cfg.hooks.as_ref().is_none_or(|v| !v.roles.admit) {
                return Err(error("HTTP_ADMIT_READS requires the admit hook role"));
            }
        }
    }
    Ok(())
}

#[allow(unused_mut)] // HTTP builds append the URL-token group.
fn role_groups(cfg: &WorkerConfig) -> Vec<Vec<[u8; 32]>> {
    let mut groups = vec![
        cfg.admin
            .as_ref()
            .map_or_else(Vec::new, mkit_server::admin::Config::public_keys),
        cfg.authority_fence
            .as_ref()
            .map_or_else(Vec::new, |f| f.public_keys().collect()),
        cfg.takedown
            .as_ref()
            .map_or_else(Vec::new, |s| s.publication.public_keys().to_vec()),
    ];
    #[cfg(feature = "http-objects")]
    groups.push(
        cfg.url_tokens
            .as_ref()
            .map_or_else(Vec::new, |t| t.keys().public_keys().collect()),
    );
    groups
}

fn validate_key_roles(cfg: &WorkerConfig) -> Result<(), ConfigError> {
    let mut public = Vec::new();
    for group in role_groups(cfg) {
        if group.iter().any(|key| {
            public.contains(key)
                || cfg
                    .ticket_keys
                    .as_ref()
                    .is_some_and(|tickets| tickets.contains_ed25519_public(key))
        }) {
            return Err(error(
                "ADMIN_KEYS, authority, receipt, URL_TOKEN_KEYS and TICKET_KEYS must use distinct key roles",
            ));
        }
        public.extend(group);
    }
    if let Some(retrieval) = &cfg.scanner_retrieval {
        retrieval.check_role_keys(&public, &[]).map_err(|_| {
            error("scanner retrieval keys must differ from every configured key role")
        })?;
        public.extend(retrieval.scanner_keys());
    }
    validate_signing_seeds(cfg, &public, &|_| None)
}

fn validate_signing_seeds(
    cfg: &WorkerConfig,
    public: &[[u8; 32]],
    var: &impl Fn(&str) -> Option<String>,
) -> Result<(), ConfigError> {
    #[cfg(feature = "http-objects")]
    if cfg
        .url_tokens
        .as_ref()
        .is_some_and(|tokens| public.iter().any(|key| tokens.keys().contains_secret(key)))
    {
        return Err(error(
            "URL token signing seed must differ from published role keys",
        ));
    }
    if let Some(text) = var(crate::admin::RECEIPT_SECRET) {
        let text = zeroize::Zeroizing::new(text);
        let seed = zeroize::Zeroizing::new(
            mkit_core::hash::from_hex(text.trim()).map_err(|_| error("invalid receipt key"))?,
        );
        if public.contains(&*seed)
            || cfg
                .ticket_keys
                .as_ref()
                .is_some_and(|tickets| tickets.contains_secret(&seed))
        {
            return Err(error(
                "receipt signing seed must differ from configured role keys",
            ));
        }
    }
    Ok(())
}

#[cfg(any(target_arch = "wasm32", test))]
pub(crate) fn validate_runtime_key_material(
    cfg: &WorkerConfig,
    var: &impl Fn(&str) -> Option<String>,
) -> Result<(), ConfigError> {
    let mut public = role_groups(cfg).concat();
    if let Some(retrieval) = &cfg.scanner_retrieval {
        public.extend(retrieval.scanner_keys());
    }
    if let Some(http) = cfg.hooks.as_ref().and_then(|hooks| hooks.http.as_ref()) {
        let signer = crate::hooks::config::http_signer(
            var("MKIT_HOOK_KEY"),
            http,
            cfg.ticket_keys.as_ref(),
            &public,
        )?;
        public.push(signer.public_key());
    }
    validate_signing_seeds(cfg, &public, var)
}

fn boolean(var: &impl Fn(&str) -> Option<String>, name: &str) -> Result<bool, ConfigError> {
    match var(name).as_deref() {
        None | Some("false") => Ok(false),
        Some("true") => Ok(true),
        _ => Err(error(format!("{name} must be true or false"))),
    }
}

impl LaunchConfig {
    /// Parse the fixed retention policy and optional launch selectors.
    /// # Errors
    /// Unknown profiles, unsupported lease/GC/retention, or orphaned opt-ins.
    pub fn parse(var: &impl Fn(&str) -> Option<String>) -> Result<Option<Self>, ConfigError> {
        let selected = match var("LAUNCH_PROFILE").as_deref() {
            None => false,
            Some("uno") => true,
            _ => return Err(error("LAUNCH_PROFILE must be uno when set")),
        };
        let http = boolean(var, "HTTP_OBJECTS")?;
        let reads = boolean(var, "HTTP_ADMIT_READS")?;
        let takedown = boolean(var, "TAKEDOWN_ENABLED")?;
        let leases = boolean(var, "STORAGE_LEASES")?;
        let gc = boolean(var, "GC_ENABLED")?;
        if leases || gc {
            return Err(error(
                "storage leases and GC are unsupported; launch requires both off",
            ));
        }
        if var("RETENTION").is_some_and(|v| v != "permanent") {
            return Err(error("RETENTION must be permanent"));
        }
        if !selected {
            if http || reads || takedown {
                return Err(error(
                    "HTTP_OBJECTS, HTTP_ADMIT_READS and TAKEDOWN_ENABLED require LAUNCH_PROFILE=uno",
                ));
            }
            return Ok(None);
        }
        if var("INDEXED_MODE").as_deref() != Some("true") {
            return Err(error("LAUNCH_PROFILE=uno requires INDEXED_MODE=true"));
        }
        if !var("WORKERS_PLAN").is_some_and(|v| v.trim().eq_ignore_ascii_case("paid")) {
            return Err(error("LAUNCH_PROFILE=uno requires WORKERS_PLAN=paid"));
        }
        Ok(Some(Self { takedown }))
    }
}

/// Validate every selected option, including signing keys, before readiness.
/// # Errors
/// Partial or contradictory configuration. Diagnostics contain names only.
pub(crate) fn validate(
    cfg: &mut WorkerConfig,
    var: &impl Fn(&str) -> Option<String>,
) -> Result<(), ConfigError> {
    // Signed hooks are complete at startup, not deferred until an operation.
    let mut public = Vec::new();
    if let Some(settings) = &cfg.takedown {
        public.extend_from_slice(settings.publication.public_keys());
    }
    if let Some(admin) = &cfg.admin {
        public.extend(admin.public_keys());
    }
    if let Some(fence) = &cfg.authority_fence {
        public.extend(fence.public_keys());
    }
    #[cfg(feature = "http-objects")]
    if let Some(tokens) = &cfg.url_tokens {
        public.extend(tokens.keys().public_keys());
    }
    if [
        "INSPECT_CLEAR_DEADLINE_MS",
        "INSPECT_CLEAR_DEADLINE",
        "INSPECT_DEADLINE_MS",
    ]
    .iter()
    .any(|name| var(name).is_some())
    {
        return Err(error("launch refuses inspection clear deadlines"));
    }
    let key = zeroize::Zeroizing::new(var("MKIT_HOOK_KEY"));
    if let Some(http) = cfg.hooks.as_ref().and_then(|v| v.http.as_ref()) {
        let signer = crate::hooks::config::http_signer(
            key.as_ref().cloned(),
            http,
            cfg.ticket_keys.as_ref(),
            &public,
        )?;
        public.push(signer.public_key());
    } else if key.is_some() {
        return Err(error("MKIT_HOOK_KEY requires signed HTTPS HOOK_URL"));
    }
    #[cfg(not(feature = "http-objects"))]
    if ["URL_TOKEN_KEYS", "URL_TOKEN_TTL"]
        .iter()
        .any(|name| var(name).is_some())
    {
        return Err(error(
            "URL_TOKEN_KEYS requires the http-objects build feature",
        ));
    }
    if let Some(config) = &cfg.scanner_retrieval {
        config.check_role_keys(&public, &[]).map_err(|_| {
            error("scanner retrieval keys must differ from every configured key role")
        })?;
        crate::scanner_retrieval::check_hook_seed(config, key.as_ref().map(String::as_str))?;
        public.extend(config.scanner_keys());
    }
    validate_signing_seeds(cfg, &public, var)?;
    if cfg.launch.is_none() {
        // Missing foundations must never silently turn these options off.
        if [
            "PRESERVATION_RETENTION_MS",
            crate::admin::RECEIPT_SECRET,
            "RECEIPT_KEYS",
        ]
        .iter()
        .any(|name| var(name).is_some())
        {
            return Err(error("preservation requires LAUNCH_PROFILE=uno"));
        }
        return Ok(());
    }
    if cfg.indexed.is_none()
        || cfg.ticket_keys.is_none()
        || !matches!(cfg.addressing, mkit_server::Addressing::Multi(_))
        || cfg.sharding != mkit_server::pipeline::Sharding::D34
    {
        return Err(error("launch requires indexed Multi, D34 and TICKET_KEYS"));
    }
    mkit_core::write_auth::validate_audience(&cfg.audience)
        .map_err(|_| error("AUTH_AUDIENCE must be a canonical launch origin"))?;
    if !cfg.audience.starts_with("https://") {
        return Err(error("launch AUTH_AUDIENCE must use HTTPS"));
    }
    validate_http(cfg, var)?;
    let inspecting = cfg.hooks.as_ref().is_some_and(|v| v.roles.inspect);
    let retrieval = boolean(var, "SCANNER_RETRIEVAL")?;
    if inspecting && !retrieval {
        return Err(error(
            "launch inspection requires SCANNER_RETRIEVAL=true and dedicated scanner keys (R-193)",
        ));
    }
    if retrieval != cfg.scanner_retrieval.is_some() || retrieval && !inspecting {
        return Err(error(
            "scanner retrieval requires its complete configuration and the inspect role",
        ));
    }
    validate_preservation(cfg, var)
}

fn validate_http(
    cfg: &mut WorkerConfig,
    var: &impl Fn(&str) -> Option<String>,
) -> Result<(), ConfigError> {
    let http = boolean(var, "HTTP_OBJECTS")?;
    let reads = boolean(var, "HTTP_ADMIT_READS")?;
    if reads && (!http || cfg.hooks.as_ref().is_none_or(|v| !v.roles.admit)) {
        return Err(error(
            "HTTP_ADMIT_READS requires HTTP_OBJECTS and the admit hook role",
        ));
    }
    #[cfg(not(feature = "http-objects"))]
    if http {
        return Err(error(
            "HTTP_OBJECTS requires the http-objects build feature",
        ));
    }
    #[cfg(feature = "http-objects")]
    if http {
        if cfg.url_tokens.is_none() {
            return Err(error("HTTP_OBJECTS requires dedicated URL_TOKEN_KEYS"));
        }
        let indexed = cfg
            .indexed
            .ok_or_else(|| error("HTTP_OBJECTS requires indexed mode"))?;
        let mut limits = mkit_server::http_objects::HttpObjectsConfig::default();
        limits.admit_reads = reads;
        cfg.http_mount = Some(crate::http_mount::WorkerHttpMountConfig {
            indexed,
            http_objects: limits,
            options: mkit_server::http_objects::mount::HttpMountOptions::default(),
            read_runtime: None, // The fetch event attaches its wait_until lifetime.
        });
    }
    Ok(())
}

fn validate_preservation(
    cfg: &WorkerConfig,
    var: &impl Fn(&str) -> Option<String>,
) -> Result<(), ConfigError> {
    let preservation = [
        "PRESERVATION_RETENTION_MS",
        crate::admin::RECEIPT_SECRET,
        "RECEIPT_KEYS",
    ];
    if cfg.takedown.is_some()
        || cfg.takedown_denial
        || cfg.launch.as_ref().is_some_and(|v| v.takedown)
    {
        if cfg.admin.as_ref().is_none_or(|admin| !admin.enabled())
            || cfg.takedown.is_none()
            || cfg.indexed.is_none()
        {
            return Err(error(
                "TAKEDOWN_ENABLED requires ADMIN_KEYS and complete preservation",
            ));
        }
        if !cfg.takedown_denial {
            return Err(error("configured takedown requires global denial"));
        }
        if cfg.custom_purge.is_none()
            && cfg
                .hooks
                .as_ref()
                .is_none_or(|v| !v.roles.cache_purge || v.http.is_none())
        {
            return Err(error("TAKEDOWN_ENABLED requires signed HTTPS cache-purge"));
        }
        if cfg.takedown.as_ref().is_some_and(|s| s.retention_ms == 0) {
            return Err(error("PRESERVATION_RETENTION_MS must be positive"));
        }
        // The merged preservation parser validates explicit retention and
        // signing/publication separation; from_env checks the dedicated bucket.
        return Ok(());
    }
    if preservation.iter().any(|name| var(name).is_some()) {
        return Err(error("preservation settings require TAKEDOWN_ENABLED=true"));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
