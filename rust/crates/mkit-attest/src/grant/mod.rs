//! Write grants (SPEC-WRITE-GRANTS): the grant, epoch and visibility
//! statement codecs, their `X-Write-Grant` header encoding, owner
//! signatures and the stateless verifier.
//!
//! * [`text`]: the §3.1 canonical text rules every statement shares.
//! * [`ref_scope`]: §3.3 ref-scope patterns and flags, §8.1 effective flags.
//! * [`statement`]: the §3.2 grant statement, its §3.5 rejections and the
//!   §3.4 grant id.
//! * [`header`]: the §4.2 `<statement>.<scheme>.<blob>` header value.
//! * [`epoch`]: the §5.1 epoch statement and the §5.2 check 7.
//! * [`visibility`]: the §9.1 visibility statement.
//! * [`config`]: the deployment's [`VerifierConfig`] (own audience,
//!   accepted schemes, `WebAuthn` relying parties).
//! * [`owner`]: §4 owner-signature dispatch (`ed25519`, `secp256k1-eip191`,
//!   `webauthn-p256`).
//! * [`webauthn`]: the `webauthn-p256` blob, relying parties and the §4.3
//!   assertion checks.
//! * [`verify`]: the stateless §7 verifier, the §5.2 and §9.1 statement
//!   checks and the §10 registration check.
//!
//! Every parser here is strict and canonical: it accepts exactly one
//! encoding per value and never repairs, and every encoder reproduces that
//! encoding (`encode(parse(b)) == b`).
//!
//! Repository identities and namespaces come from
//! [`mkit_core::repo_identity`] (SPEC-TRANSPORT-CONNECT §7.4).

pub mod config;
pub mod epoch;
pub mod error;
pub mod header;
pub mod owner;
pub mod ref_scope;
pub mod statement;
pub mod text;
pub mod verify;
pub mod visibility;
pub mod webauthn;

pub use config::{AcceptedSchemes, VerifierConfig, is_loopback_origin};
pub use epoch::{EpochStatement, EpochTransition, epoch_transition};
pub use error::GrantError;
pub use header::{OwnerScheme, SignedHeader};
pub use mkit_core::repo_identity::{Namespace, RepositoryIdentity};
pub use owner::verify_owner_signature;
pub use ref_scope::{RefFlags, RefPattern, RefScopes, head_packmap, packmap_head};
pub use statement::{Capabilities, Capability, Grant, RepoScope};
pub use verify::{
    GrantRequest, OwnerVerified, VerifiedEpoch, VerifiedGrant, VerifiedVisibility,
    verify_epoch_statement, verify_for_registration, verify_grant_owner,
    verify_visibility_statement,
};
pub use visibility::{Visibility, VisibilityStatement};
pub use webauthn::{MAX_CLIENT_DATA_DEPTH, RelyingParty, WebAuthnAssertion, webauthn_challenge};

/// Domain separator and first field of a grant statement (§12.1).
pub const DOMAIN_GRANT: &str = "mkit-write-grant:v1";
/// Domain separator and first field of an epoch statement (§12.1).
pub const DOMAIN_EPOCH: &str = "mkit-write-epoch:v1";
/// Domain separator and first field of a visibility statement (§12.1).
pub const DOMAIN_VISIBILITY: &str = "mkit-repo-visibility:v1";

/// Longest grant lifetime: 30 days (§1.1).
pub const GRANT_MAX_LIFETIME_MS: i64 = 2_592_000_000;
/// Longest epoch or visibility statement lifetime: 30 days (§1.1).
pub const EPOCH_STATEMENT_MAX_LIFETIME_MS: i64 = 2_592_000_000;
/// Largest accepted epoch increase in one epoch statement (§1.1, §5.2).
pub const MAX_EPOCH_STEP: u64 = 1024;
/// Largest accepted clock lead of a statement's `created` (§1.1): the auth
/// v2 clock lead.
pub const MAX_CLOCK_LEAD_MS: i64 = mkit_core::write_auth::MAX_CLOCK_LEAD_MS;
/// Most audiences in one statement (§1.1).
pub const MAX_AUDIENCES: usize = 8;
/// Most ref-scope entries in one grant (§1.1).
pub const MAX_REF_SCOPES: usize = 16;
/// Longest statement in bytes (§1.1, §3.1).
pub const MAX_STATEMENT_BYTES: usize = 4096;
/// Longest `X-Write-Grant` header value in bytes (§1.1, §4.2).
pub const MAX_GRANT_HEADER_BYTES: usize = 8192;

// §1.1 fixes the clock lead to the auth v2 value.
const _: () = assert!(MAX_CLOCK_LEAD_MS == 30_000);
