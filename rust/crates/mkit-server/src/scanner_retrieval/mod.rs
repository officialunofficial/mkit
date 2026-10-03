//! Private raw-pack retrieval for synchronous scanners (SPEC-SERVER §11.4).
//! Capabilities authorize only open ticket-bound bytes; public serving is unrelated.
mod config;
pub(crate) mod service;
#[cfg(all(test, feature = "remote-hooks"))]
mod tests;
#[cfg(feature = "remote-hooks")]
mod token;
#[cfg(feature = "remote-hooks")]
pub(crate) use token::Claims;

pub use config::{ConfigError, RetrievalConfig};
pub use service::{RetrievalResponse, validate_config};
#[cfg(feature = "remote-hooks")]
pub use token::{Assignment, PackGrant};

/// Exact private POST path; auth v2 signs this procedure and the request body.
pub const PATH: &str = "/_mkit/scanner/pack";
/// Bound the complete signed request, including its capability.
pub const MAX_REQUEST_BYTES: usize = 16_384;
/// Maximum returned range, or entire pack when no range is requested.
pub const MAX_RESPONSE_BYTES: usize = 1 << 20;
/// Shared bound for denial, ticket and blob operations; adapter work has headroom.
pub const MAX_CALLS: u32 = crate::limits::OBJECT_READER_CALLS;
/// Small retrieval margin after the hook timeout.
pub const MARGIN_MS: u64 = 1_000;
/// Longest capability validity; hook timeout is at most five minutes.
pub const MAX_LIFETIME_MS: u64 = 301_000;
