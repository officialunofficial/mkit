//! Dependency-free grant selection boundary for the Connect client.

/// The condition a write asks the server to apply to one ref.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantCondition {
    Missing,
    Match,
    Any,
    Delete,
}

/// One ref whose scope must be covered by a write grant.
#[derive(Clone, Copy, Debug)]
pub struct GrantRef<'a> {
    pub name: &'a str,
    pub condition: GrantCondition,
}

/// The operation for which a grant is requested.
#[derive(Clone, Copy, Debug)]
pub enum GrantOperation<'a> {
    Read,
    Write {
        refs: &'a [GrantRef<'a>],
    },
    /// Ticketed part path; it never carries a grant.
    Part,
}

/// Local context for choosing a grant. All strings are canonical values
/// already used by the Connect client for addressing and signing.
#[derive(Clone, Copy, Debug)]
pub struct GrantRequest<'a> {
    pub origin: &'a str,
    pub repository: &'a str,
    pub public_key_hex: &'a str,
    pub operation: GrantOperation<'a>,
}

/// Supplies one encoded `X-Write-Grant` value, if any. Implementations
/// decide selection locally; the transport never parses or verifies grants.
pub trait GrantSource: Send + Sync {
    fn select(&self, request: &GrantRequest<'_>) -> Option<String>;
}
