//! Deployment namespace and write policy (SPEC-TRANSPORT-CONNECT §7.5).

pub(crate) mod grants;
mod namespace;
pub(crate) mod read;
pub(crate) mod ref_scopes;
mod write;

pub use grants::{
    GrantConfig, GrantSettings, parse_grant_schemes, parse_relying_parties, parse_relying_party,
};
pub use mkit_attest::grant::{AcceptedSchemes, RelyingParty};
pub use namespace::{NamespacePolicy, parse_namespace_allowlist};
pub use write::{AuthorizerRole, WritePolicy};
