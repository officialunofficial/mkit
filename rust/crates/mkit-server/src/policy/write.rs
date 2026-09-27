/// Write authorization policy (SPEC-TRANSPORT-CONNECT §7.5).
/// Hooks compose with this policy under SPEC-SERVER §6.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WritePolicy {
    /// Authentication and the authorizer hook suffice; Single addressing only.
    Open,
    /// Require namespace ownership or an authority source; grants land in M2.
    Owner,
}

/// How the authorizer composes with built-in policy (SPEC-SERVER §6.2,
/// SPEC-TRANSPORT-CONNECT §7.5). Neither role overrides namespace denial.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthorizerRole {
    /// An additional check that may deny an otherwise authorized write.
    #[default]
    Check,
    /// The rule-3 authority source. It may authorize non-owners and deny owners.
    Authority,
}
