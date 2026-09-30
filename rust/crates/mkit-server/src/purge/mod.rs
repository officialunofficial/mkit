//! Durable cache purge work and deployment-independent selectors (§16.7).
mod delivery;
#[cfg(test)]
mod tests;
pub use delivery::{LocalInvalidation, NoLocalCache, PurgeDelivery, PurgeSink, SliceBudget};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use mkit_core::hash::{hash, to_hex};
use serde::{Deserialize, Serialize};
use crate::store::{Batch, Precondition, StoreError, Value, codec, keys};

/// Explicit activation. A shared-cache deployment always needs a global sink.
#[derive(Clone)]
pub struct PurgeConfig {
    /// This server's canonical origin.
    pub audience: String,
    /// Whether any serving cache is shared between instances.
    pub shared_caches: bool,
    /// A signed remote purger is configured.
    pub remote_sink: bool,
    /// Durable acceptance/audit seam for automatic triggers.
    pub audit: Option<std::sync::Arc<dyn AutomaticAudit>>,
}
impl core::fmt::Debug for PurgeConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result { f.debug_struct("PurgeConfig").field("audience", &self.audience).field("shared_caches", &self.shared_caches).field("remote_sink", &self.remote_sink).finish_non_exhaustive() }
}
/// Accept and audit automatic work before it changes serving state.
pub trait AutomaticAudit: crate::MaybeSend + crate::MaybeSync {
    /// Returned effects belong to `partition`; cross-partition acceptance must
    /// be durably completed before returning, and deduplicated by purge id.
    fn plan<'a>(&'a self, partition: &'a crate::Partition, request: &'a Request, now_ms: u64) -> crate::BoxFuture<'a, Result<Batch, StoreError>>;
}
impl PurgeConfig {
    /// Construct settings; storage-backed auditing is attached at startup.
    #[must_use]
    pub fn new(audience: String, shared_caches: bool, remote_sink: bool) -> Self { Self { audience, shared_caches, remote_sink, audit: None } }
    /// Attach the automatic action audit/acceptance implementation.
    #[must_use]
    pub fn with_audit(mut self, audit: std::sync::Arc<dyn AutomaticAudit>) -> Self { self.audit = Some(audit); self }
    /// Refuse invalid origins and shared caches without a global purger.
    pub fn validate(&self) -> Result<(), StoreError> {
        mkit_core::write_auth::validate_audience(&self.audience)
            .map_err(|_| invalid("invalid purge audience"))?;
        if self.shared_caches && !self.remote_sink {
            return Err(invalid("shared caches require a global purge sink"));
        }
        Ok(())
    }
}
/// Reasons defined by the cache-purge protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Trigger {
    /// An inspection hit or takedown.
    #[serde(rename = "CACHE_PURGE_TRIGGER_TAKEDOWN")]
    Takedown,
    /// Quarantine or administrative serving stop.
    #[serde(rename = "CACHE_PURGE_TRIGGER_SUSPENSION")]
    Suspension,
    /// Deferred lease-deletion consumer.
    #[serde(rename = "CACHE_PURGE_TRIGGER_LEASE_DELETION")]
    LeaseDeletion,
    /// Repository visibility changed.
    #[serde(rename = "CACHE_PURGE_TRIGGER_VISIBILITY_CHANGE")]
    VisibilityChange,
    /// Signed administrator request.
    #[serde(rename = "CACHE_PURGE_TRIGGER_MANUAL")]
    Manual,
}
/// The exact protobuf-JSON CachePurgeRequest stored for every retry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Request {
    /// Audience-unique operation identity, stable across attempts.
    pub purge_id: String,
    /// The server origin, distinct from the sink signing origin.
    pub audience: String,
    /// Full repository identity, empty for a namespace purge.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub repository: String,
    /// Reason for the purge.
    pub trigger: Trigger,
    /// Exact origin-relative paths, excluding query and fragment.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub url_paths: Vec<String>,
    /// Canonical base64 encodings of raw 32-byte ids.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub object_ids: Vec<String>,
    /// Full ref names.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub refs: Vec<String>,
    /// Full namespace identity, empty for a repository purge.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub namespace: String,
}
fn invalid(message: &str) -> StoreError { StoreError::Invalid(message.into()) }
impl Request {
    /// Validate bounded protocol selectors before acceptance or side effects.
    pub fn validate(&self) -> Result<(), StoreError> {
        if self.purge_id.is_empty() || self.purge_id.len() > 128
            || !self.purge_id.bytes().all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
            || self.repository.is_empty() == self.namespace.is_empty()
            || self.url_paths.len() + self.object_ids.len() + self.refs.len() > 64 {
            return Err(invalid("invalid purge identity or selectors"));
        }
        mkit_core::write_auth::validate_audience(&self.audience)
            .map_err(|_| invalid("invalid purge audience"))?;
        if !self.repository.is_empty() {
            let (ns, repo) = self.repository.rsplit_once('/').ok_or_else(|| invalid("invalid purge repository"))?;
            if ns != "root" { mkit_core::repo_identity::Namespace::parse(ns).map_err(|_| invalid("invalid purge namespace"))?; }
            mkit_core::repo_identity::validate_name(repo).map_err(|_| invalid("invalid purge repository"))?;
        } else if self.namespace != "root" { mkit_core::repo_identity::Namespace::parse(&self.namespace).map_err(|_| invalid("invalid purge namespace"))?; }
        for path in &self.url_paths {
            if !path.starts_with('/') || path.starts_with("//") || path.len() > 4096
                || path.bytes().any(|b| b.is_ascii_control() || matches!(b, b'?' | b'#' | b'\\' | b'@')) {
                return Err(invalid("invalid purge path"));
            }
        }
        for id in &self.object_ids {
            let bytes = STANDARD.decode(id).map_err(|_| invalid("invalid purge object id"))?;
            if bytes.len() != 32 || STANDARD.encode(bytes) != *id { return Err(invalid("invalid purge object id")); }
        }
        if self.refs.iter().any(|r| !crate::refs::validate_ref_name(r)) { return Err(invalid("invalid purge ref")); }
        Ok(())
    }
    /// Stable scope identity used for durable snapshot invalidation.
    #[must_use]
    pub fn scope(&self) -> &str {
        if self.repository.is_empty() { &self.namespace } else { &self.repository }
    }
    /// Deployment-independent Cache-Tag selectors understood by the remote purger.
    /// Empty selectors purge a complete scope, including proofs and snapshots.
    #[must_use]
    pub fn tags(&self) -> Vec<String> {
        let scope = if self.repository.is_empty() { "namespace" } else { "repository" };
        if self.url_paths.is_empty() && self.object_ids.is_empty() && self.refs.is_empty() {
            return vec![cache_tag(&self.audience, scope, self.scope())];
        }
        let mut tags = Vec::new();
        for (kind, selectors) in [("path", &self.url_paths), ("object", &self.object_ids), ("ref", &self.refs)] {
            for value in selectors {
                tags.push(cache_tag(&self.audience, kind, &format!("{}\0{value}", self.scope())));
            }
        }
        // Ref mutations can change reachability and published snapshots.
        tags.push(cache_tag(&self.audience, "proof", self.scope()));
        tags.push(cache_tag(&self.audience, "snapshot", self.scope()));
        tags
    }
}
/// Unambiguous, bounded Cache-Tag for a cache insertion and its purge selector.
#[must_use]
pub fn cache_tag(audience: &str, kind: &str, identity: &str) -> String {
    format!("mkit-{kind}-{}", to_hex(&hash(format!("mkit.cache.v1\0{audience}\0{kind}\0{identity}").as_bytes())))
}
/// Decode the durable invalidation time; absent means never invalidated.
pub fn generation(value: Option<&Value>) -> Result<u64, StoreError> {
    value.map_or(Ok(0), |v| {
        let bytes = v.as_bytes().try_into().map_err(|_| StoreError::Corrupt("invalid purge generation".into()))?;
        Ok(u64::from_be_bytes(bytes))
    })
}
/// Plan work, a durable refill fence, combined backlog and wake in one atomic unit.
/// The caller merges this batch into its authenticated intent/audit transaction.
pub fn plan_enqueue(request: &Request, now_ms: u64, backlog: Option<&Value>, prior_generation: Option<&Value>) -> Result<Batch, StoreError> {
    request.validate()?;
    let key = keys::cache_purge(&request.purge_id)?;
    let bytes = serde_json::to_vec(request).map_err(|_| invalid("cannot encode purge"))?;
    if bytes.len() > 65_536 { return Err(invalid("purge body too large")); }
    let size = u64::try_from(key.as_bytes().len() + bytes.len()).map_err(|_| invalid("purge body too large"))?;
    let mut count = backlog.map(codec::decode_backlog).transpose()?.unwrap_or_default();
    count.rows = count.rows.checked_add(1).ok_or_else(|| invalid("purge backlog overflow"))?;
    count.bytes = count.bytes.checked_add(size).ok_or_else(|| invalid("purge backlog overflow"))?;
    let fence_key = keys::cache_purge_generation(request.scope());
    let floor = generation(prior_generation)?.checked_add(1).ok_or_else(|| invalid("purge generation overflow"))?.max(now_ms);
    Ok(Batch::new().require(Precondition::Absent(key.clone()))
        .require(guard(keys::outcome_backlog(), backlog))
        .require(guard(fence_key.clone(), prior_generation))
        .put(key, Value::new(bytes))
        .put(fence_key, Value::new(floor.to_be_bytes().to_vec()))
        .put(keys::outcome_backlog(), codec::encode_backlog(&count))
        .put(keys::timer(now_ms, crate::timers::registry::kinds::CACHE_PURGE.get(), request.purge_id.as_bytes()), Value::default()))
}
/// Read accepted work for immediate request-side local invalidation.
pub async fn read_request<S: crate::NamespaceStore>(store: &S, partition: &crate::Partition, purge_id: &str) -> Result<Option<Request>, StoreError> {
    store.get(partition, &keys::cache_purge(purge_id)?).await?.map(|v| {
        let request: Request = serde_json::from_slice(v.as_bytes()).map_err(|_| StoreError::Corrupt("invalid purge work".into()))?;
        request.validate()?;
        Ok(request)
    }).transpose()
}
fn guard(key: crate::Key, value: Option<&Value>) -> Precondition {
    value.map_or_else(|| Precondition::Absent(key.clone()), |v| Precondition::Equals(key.clone(), v.clone()))
}
