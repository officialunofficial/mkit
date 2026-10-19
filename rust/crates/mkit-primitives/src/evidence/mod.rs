//! Source and ruleset bindings and references to retained evidence.
//!
//! Caller-supplied facts are not remote attestations. Versioned pages, proofs,
//! and checkpoints have explicit bounded codecs; decoding seals no authority.

pub mod acceptance;
pub mod checkpoint;
pub mod pages;
pub mod proof;
use mkit_core::{hash::Hash, object::ObjectType};

/// Logical repository identity, independent of storage routing.
/// Host resolution and replay retention follow SPEC-PRIMITIVE-EVIDENCE §1.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RepositoryId(pub [u8; 32]);
/// Immutable source version supplied by the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceBinding(pub [u8; 32]);
/// Exact pack identity, byte length, and immutable version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackSource {
    /// Whole-pack content address.
    pub id: Hash,
    /// Exact length, including trailer.
    pub len: u64,
    /// Immutable source version; changes require restart.
    pub binding: SourceBinding,
}
/// Normative ruleset identity, independent of crate and envelope versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RulesetId(pub u32);
/// Semantic verification profile, independent of execution budgets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProfileId {
    /// Indexed repository admission under the server specification.
    Indexed,
}
/// Ruleset and profile that a result establishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RulesetBinding {
    /// Normative ruleset.
    pub ruleset: RulesetId,
    /// Semantic profile.
    pub profile: ProfileId,
}
/// Purpose of a committed evidence page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PageKind {
    /// Object-ID index with first-occurrence ownership.
    Objects,
    /// Ordered frame occurrences.
    Occurrences,
    /// External immutable and membership dependencies.
    Dependencies,
    /// Closure traversal frontier and obligations.
    Closure,
    /// Immutable head-candidate facts.
    Heads,
    /// Ordered distinct-object identities in first-occurrence order.
    Ordinals,
}
/// Expected identity and bounds of a retained page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageCommitment {
    /// Content commitment; the owning format defines hash framing.
    pub digest: Hash,
    /// Committed page role.
    pub kind: PageKind,
    /// Exact encoded length.
    pub len: u64,
    /// Exact record count.
    pub items: u64,
}
/// Location of a bounded inclusion or absence proof in retained evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofReference {
    /// Root under which the proof must authenticate.
    pub root: Hash,
    /// Page containing the proof.
    pub page: PageCommitment,
    /// Record ordinal within that page.
    pub ordinal: u64,
}
/// Logical revision from an authoritative host observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Revision(pub [u8; 32]);
/// Repository-scoped verified-member fact supplied by a trusted host.
///
/// It establishes neither current authorization nor a live acceptance guard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberFact {
    /// Exact repository; cross-repository substitution is invalid.
    pub repository: RepositoryId,
    /// Repository incarnation.
    pub incarnation: Revision,
    /// Canonical object identity.
    pub object: Hash,
    /// Canonical object kind.
    pub kind: ObjectType,
    /// Canonical byte length.
    pub canonical_len: u64,
    /// Verified supplier pack.
    pub supplier: PackSource,
    /// Immutable canonical-byte source version.
    pub canonical_binding: SourceBinding,
    /// Membership observation revision.
    pub revision: Revision,
    /// Effective encoded delta-chain depth, including reconstructed bases.
    pub delta_depth: u32,
    /// Whether publication currently permits using the supplier.
    pub published: bool,
    /// Whether inspection or another live hold prevents using it.
    pub held: bool,
}
