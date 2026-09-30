use crate::ServerError;
use crate::pipeline::PipelineConfig;
use bytes::Bytes;

/// A bounded pack segment, fully checked before the adapter returns its bytes.
#[derive(Debug)]
pub struct RetrievalResponse {
    /// Exact raw bytes, bounded by `MAX_RESPONSE_BYTES`.
    pub bytes: Bytes,
    /// First byte of the selected segment.
    pub start: u64,
    /// Exact bound raw pack length.
    pub total: u64,
    /// Whether the scanner explicitly requested a range.
    pub partial: bool,
}

pub(crate) fn missing() -> ServerError {
    ServerError::not_found("pack not found")
}

/// Validate scanner prerequisites and key separation before serving requests.
///
/// # Errors
/// Returns a configuration error when an enabled retrieval role is incomplete
/// or shares key material with another configured role.
pub fn validate_config(cfg: &PipelineConfig) -> Result<(), ServerError> {
    let Some(config) = &cfg.scanner_retrieval else {
        return Ok(());
    };
    if !cfg!(feature = "remote-hooks")
        || !matches!(cfg.auth, crate::pipeline::AuthMode::AuthV2(_))
        || cfg.indexed.is_none()
        || cfg.ticket_keys.is_none()
        || cfg.begin_upload_threshold_bytes != 0
        || cfg.write_policy == crate::policy::WritePolicy::Open
    {
        return Err(ServerError::invalid_argument(
            "scanner retrieval requires ticketed indexed inspection and auth v2",
        ));
    }
    let mut public = cfg.admin_keys.clone();
    if let Some(tokens) = &cfg.url_tokens {
        public.extend(tokens.keys().public_keys());
    }
    if let Some(fence) = &cfg.authority_fence {
        public.extend(fence.public_keys());
    }
    let namespaces: Vec<_> = match &cfg.addressing {
        crate::Addressing::Single { repo } => vec![repo.namespace.as_str().to_owned()],
        crate::Addressing::Multi(multi) => match &multi.namespace_policy {
            crate::policy::NamespacePolicy::Allowlist(list) => {
                list.iter().map(ToString::to_string).collect()
            }
            _ => Vec::new(),
        },
    };
    for namespace in namespaces {
        if let Ok(mkit_core::repo_identity::Namespace::Ed25519(key)) =
            mkit_core::repo_identity::Namespace::parse(&namespace)
        {
            public.push(key);
        }
    }
    config.check_role_keys(&public, &[]).map_err(|_| {
        ServerError::invalid_argument("scanner retrieval key roles must be distinct")
    })?;
    if let Some(tokens) = &cfg.url_tokens
        && (config.keys.iter().any(|key| {
            tokens.keys().contains_secret(&key.secret)
                || tokens.keys().contains_secret(
                    &ed25519_dalek::SigningKey::from_bytes(&key.secret)
                        .verifying_key()
                        .to_bytes(),
                )
        }) || config
            .scanner_keys()
            .any(|key| tokens.keys().contains_secret(&key)))
    {
        return Err(ServerError::invalid_argument(
            "scanner retrieval and URL token key roles must be distinct",
        ));
    }
    if let Some(tickets) = &cfg.ticket_keys
        && (config.keys.iter().any(|key| {
            tickets.contains_secret(&key.secret)
                || tickets.contains_ed25519_public(&key.secret)
                || tickets.contains_secret(
                    &ed25519_dalek::SigningKey::from_bytes(&key.secret)
                        .verifying_key()
                        .to_bytes(),
                )
                || tickets.contains_ed25519_public(
                    &ed25519_dalek::SigningKey::from_bytes(&key.secret)
                        .verifying_key()
                        .to_bytes(),
                )
        }) || config
            .scanner_keys()
            .any(|key| tickets.contains_secret(&key) || tickets.contains_ed25519_public(&key)))
    {
        return Err(ServerError::invalid_argument(
            "scanner retrieval and ticket key roles must be distinct",
        ));
    }
    Ok(())
}
