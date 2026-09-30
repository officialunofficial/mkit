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

    /// Refuse activation until the owning implementations have merged.
    /// # Errors
    /// Phase 1 has no extraction driver, preservation or private retrieval.
    pub fn check_prerequisites(&self) -> Result<(), ConfigError> {
        if self.takedown {
            return Err(error(
                "launch takedown requires WP-5.6a-2 verified preservation",
            ));
        }
        Err(error(
            "Paid indexed launch requires WP-4.10b-2 extraction driver; Verified must imply extracted",
        ))
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
            key.as_ref().clone(),
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
    if cfg.launch.is_none() {
        // Missing foundations must never silently turn these options off.
        if [
            "SCANNER_RETRIEVAL",
            "SCANNER_RETRIEVAL_KEYS",
            "SCANNER_KEYS",
            "PRESERVATION_BUCKET",
            "PRESERVATION_RETENTION_SECS",
            "PRESERVATION_KEY",
        ]
        .iter()
        .any(|name| var(name).is_some())
        {
            return Err(error(
                "scanner retrieval and preservation require LAUNCH_PROFILE=uno",
            ));
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
    let inspecting = cfg.hooks.as_ref().is_some_and(|v| v.roles.inspect);
    let retrieval = boolean(var, "SCANNER_RETRIEVAL")?;
    if inspecting && !retrieval {
        return Err(error(
            "launch inspection requires SCANNER_RETRIEVAL=true and dedicated scanner keys (R-193)",
        ));
    }
    if retrieval || var("SCANNER_KEYS").is_some() || var("SCANNER_RETRIEVAL_KEYS").is_some() {
        if !retrieval || !inspecting {
            return Err(error(
                "scanner keys require SCANNER_RETRIEVAL=true and the inspect role",
            ));
        }
        for name in ["SCANNER_KEYS", "SCANNER_RETRIEVAL_KEYS"] {
            if var(name).is_none_or(|s| s.trim().is_empty()) {
                return Err(error(format!("{name} is required for launch inspection")));
            }
        }
        // R-193 owns the exact key codec/separation and route. Until merged,
        // refuse even test-faults launch selection rather than parse a rival codec.
        return Err(error(
            "launch scanner retrieval requires R-193 private pack retrieval",
        ));
    }
    let preservation = [
        "PRESERVATION_BUCKET",
        "PRESERVATION_RETENTION_SECS",
        "PRESERVATION_KEY",
    ];
    if cfg.launch.as_ref().is_some_and(|v| v.takedown) {
        if cfg.admin.is_none() {
            return Err(error("TAKEDOWN_ENABLED requires nonempty ADMIN_KEYS"));
        }
        if cfg
            .hooks
            .as_ref()
            .is_none_or(|v| !v.roles.cache_purge || v.http.is_none())
        {
            return Err(error("TAKEDOWN_ENABLED requires signed HTTPS cache-purge"));
        }
        for name in preservation {
            if var(name).is_none_or(|s| s.trim().is_empty()) {
                return Err(error(format!("TAKEDOWN_ENABLED requires {name}")));
            }
        }
        let retention = var("PRESERVATION_RETENTION_SECS").unwrap_or_default();
        if !retention
            .parse::<u64>()
            .ok()
            .is_some_and(|n| n > 0 && n.to_string() == retention)
        {
            return Err(error(
                "PRESERVATION_RETENTION_SECS must be a positive canonical integer",
            ));
        }
        // The preservation implementation owns signing/key-list grammar and
        // actual bucket isolation. Phase 1 must refuse without that contract.
        return Err(error(
            "launch takedown requires WP-5.6a-2 verified preservation",
        ));
    }
    if preservation.iter().any(|name| var(name).is_some()) {
        return Err(error("preservation settings require TAKEDOWN_ENABLED=true"));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
