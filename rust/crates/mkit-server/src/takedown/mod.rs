//! Inert lean denial and durable, unresolved takedown intent foundation.
pub mod acquisition;
mod closure;
mod copy;
pub mod denial;
pub mod discovery;
mod intent;
pub mod inventory;
pub mod late;
pub mod late_owner;
mod local;
pub mod work;
pub use local::LocalStore;
mod publication;
#[cfg(test)]
mod tests;
pub use intent::{Record, Service};
pub use publication::PublicationConfig;

/// Launch stays disabled until the remaining signed admin catalog is delivered.
pub const ACTIVATED: bool = false;

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
