//! Deployment namespace and write policy (SPEC-TRANSPORT-CONNECT §7.5).

pub(crate) mod grants;
mod namespace;
pub(crate) mod ref_scopes;
mod write;

pub use grants::GrantConfig;
pub use namespace::{NamespacePolicy, parse_namespace_allowlist};
pub use write::{AuthorizerRole, WritePolicy};
