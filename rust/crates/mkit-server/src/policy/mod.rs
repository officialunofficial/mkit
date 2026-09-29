//! Deployment namespace and write policy (SPEC-TRANSPORT-CONNECT §7.5).

pub(crate) mod grants;
mod namespace;
pub(crate) mod read;
mod write;

pub use grants::GrantConfig;
pub use namespace::NamespacePolicy;
pub use write::{AuthorizerRole, WritePolicy};
