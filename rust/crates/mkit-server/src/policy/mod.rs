//! Deployment namespace and write policy (SPEC-TRANSPORT-CONNECT §7.5).

mod namespace;
mod write;

pub use namespace::NamespacePolicy;
pub use write::{AuthorizerRole, WritePolicy};
