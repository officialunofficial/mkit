//! Deployment namespace and write policy (SPEC-TRANSPORT-CONNECT §7.5).

mod namespace;
mod write;

pub use namespace::{NamespacePolicy, parse_namespace_allowlist};
pub use write::{AuthorizerRole, WritePolicy};
