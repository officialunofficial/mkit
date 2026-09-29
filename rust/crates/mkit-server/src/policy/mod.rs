//! Deployment namespace and write policy (SPEC-TRANSPORT-CONNECT §7.5).

pub(crate) mod ff;
pub(crate) mod grants;
mod namespace;
pub(crate) mod read;
mod ref_policy;
pub(crate) mod ref_scopes;
mod write;

pub use grants::GrantConfig;
pub use namespace::{NamespacePolicy, parse_namespace_allowlist};
pub use ref_policy::{RefPolicy, RefRule};
pub use write::{AuthorizerRole, WritePolicy};
