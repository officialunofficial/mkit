//! Lean denial and durable takedown intents; adapters control activation.
pub mod acquisition;
mod admin;
mod closure;
mod copy;
pub mod denial;
pub(crate) mod directory;
pub mod discovery;
mod intent;
pub mod inventory;
pub mod late;
pub mod late_owner;
mod local;
pub mod work;
pub use local::LocalStore;
mod publication;
pub(crate) mod source;
#[cfg(test)]
mod tests;
pub use intent::{Record, Service};
pub use publication::PublicationConfig;

/// Configured namespace roots; an open policy has no exhaustive configured set.
#[must_use]
pub fn configured_namespaces(addressing: &crate::Addressing) -> Vec<crate::NamespaceKey> {
    match addressing {
        crate::Addressing::Single { repo } => vec![repo.namespace.clone()],
        crate::Addressing::Multi(multi) => match &multi.namespace_policy {
            crate::policy::NamespacePolicy::Allowlist(namespaces) => namespaces
                .iter()
                .map(crate::NamespaceKey::from_namespace)
                .collect(),
            crate::policy::NamespacePolicy::Any { .. } => Vec::new(),
        },
    }
}
