//! Version 1 test-control binding. These messages are test infrastructure,
//! never part of the public transport. See the crate README for semantics.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Test-only serving state for a pack-location conformance fixture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackLocationState {
    /// Published, public membership with correct location bytes.
    Available,
    /// An inspection serving stop that hides membership from every caller.
    Held,
    /// Accepted membership awaiting inspection and publication.
    Pending,
    /// Published membership in a private repository.
    Private,
    /// A deployment denial, including already issued location expiry.
    Denied,
    /// Correct streaming bytes and same-length corrupt location bytes.
    Corrupt,
}

/// Test-control protocol version.
pub const VERSION: u32 = 1;
/// Capability negotiation route (GET).
pub const CAPABILITIES_PATH: &str = "/__mkit_test/v1/capabilities";
/// Command route (POST JSON).
pub const CONTROL_PATH: &str = "/__mkit_test/v1/control";

/// Test controls supported by a disposable server under test.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capabilities {
    /// Exactly [`VERSION`]. Unknown versions fail negotiation.
    pub version: u32,
    /// Supported control names, including supported named barriers.
    pub controls: Vec<String>,
    /// Actual failure guarantees; volatile memory is not persistent durability.
    pub durability_profile: String,
    /// Unsupported controls and concrete reasons, used for declared skips.
    pub unsupported: BTreeMap<String, String>,
}

/// A wire identity, independent of a server's replay-record layout.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayIdentity {
    /// Signed audience.
    pub audience: String,
    /// Signed full repository identity.
    pub repository: String,
    /// Signed public key, in the envelope's spelling.
    pub signer: String,
    /// Original idempotency key.
    pub nonce: String,
}

/// A quota window selected by protocol identity and epoch time.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuotaQuery {
    /// Signed public key, in the envelope's spelling.
    pub signer: String,
    /// Beginning of the quota window, Unix milliseconds; absent selects the
    /// current authoritative window for the signer.
    pub window_start_ms: Option<i64>,
}

/// One atomic observation of the authoritative acceptance domain.
/// Collections preserve query order. No field accepts a raw storage key.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationQuery {
    /// Full repository identity.
    pub repository: String,
    /// Head ref; its paired packmap is implicit.
    pub head: String,
    /// Original signed operation, if asserted.
    pub replay: Option<ReplayIdentity>,
    /// Ticket IDs in lowercase hex.
    pub ticket_ids: Vec<String>,
    /// Explicit admission reservation IDs. If empty, observe ticket reservations
    /// in ticket query order, then the ref reservation bound to `replay`.
    pub reservation_ids: Vec<String>,
    /// Pack IDs whose local live membership is asserted, in lowercase hex.
    pub packs: Vec<String>,
    /// Signer quota window, if asserted.
    pub quota: Option<QuotaQuery>,
}

/// Replay state exposed without backend encoding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayView {
    /// `in_flight` or `committed`.
    pub state: String,
    /// Saved result class, when committed. Fork success is `fork_committed`;
    /// a saved refusal uses its protocol error code.
    pub result: Option<String>,
    /// Digest binding the saved result to the signed request.
    pub fingerprint: Option<String>,
}

/// Ticket state exposed without backend encoding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TicketView {
    /// `live`, `consumed`, or `expired`.
    pub state: String,
}

/// Reservation state and terminal-result multiplicity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReservationView {
    /// `pending`, `ticketed`, `committed`, `aborted`, or `expired`.
    pub state: String,
    /// Number of terminal results for this reservation, excluding deliveries.
    pub terminal_count: u32,
}

/// Applied quota counters, separate from delayed aggregate projections.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuotaView {
    /// Operations charged.
    pub ops: u64,
    /// Bytes charged.
    pub bytes: u64,
}

/// Typed values that all coexisted at one authoritative observation point.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    /// Live head object ID, lowercase hex, or absent.
    pub head: Option<String>,
    /// Paired live packmap ID, lowercase hex, or absent.
    pub packmap: Option<String>,
    /// Saved replay state, if present.
    pub replay: Option<ReplayView>,
    /// Ticket states in query order; absent is distinct from consumed.
    pub tickets: Vec<Option<TicketView>>,
    /// Reservation states in query order.
    pub reservations: Vec<Option<ReservationView>>,
    /// Local live memberships in query order.
    pub memberships: Vec<bool>,
    /// Applied quota state, if present.
    pub quota: Option<QuotaView>,
}

/// Parameters for a deterministic, valid fork source. The binding seeds a
/// public source readable by `signer`, including committed membership.
/// It MUST NOT create the destination or start its fork.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForkFixtureQuery {
    /// Fresh destination repository identity, owned by the fixture signer.
    pub destination: String,
    /// Ed25519 public key in signed-envelope spelling.
    pub signer: String,
    /// Source head ref to populate; no destination ref is created.
    pub source_head: String,
}

/// A valid source and the test metadata needed to exercise each guarded commit.
/// Repeating the query with fresh destinations yields the same source contents
/// and number of preparatory commits. These counts prescribe no orchestration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForkFixture {
    /// Full source repository identity.
    pub source_repository: String,
    /// Published source head ref.
    pub source_head: String,
    /// Expected source tip, lowercase hex.
    pub tip: String,
    /// Published source packmap, lowercase hex. A paired creation using `tip`
    /// and `packmap` MUST pass content validation once the destination activates.
    pub packmap: String,
    /// Packs imported by the fork, in deterministic order, lowercase hex.
    pub packs: Vec<String>,
    /// An object in each pack, in pack order, lowercase hex.
    pub objects: Vec<String>,
    /// Number of durable preparatory commits advancing this fixture's fork.
    /// The acceptance itself is excluded. Must be nonzero for progress tests.
    pub advancing_commits: u64,
}

/// A committed change to the source used by an existing fork fixture.
/// Visibility revocation makes the source unreadable to the forking principal;
/// a fixture may use a distinct source owner to exercise this change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForkSourceChange {
    /// Publish a different source head/packmap pair.
    Moved,
    /// Remove the admitted source publication.
    Unpublished,
    /// Commit a visibility change revoking the forking principal's read access.
    VisibilityRevoked,
    /// Deny every pack explicitly selected by the change query's nonempty
    /// `packs` list. Other source facts remain unchanged.
    Denied,
}

/// A semantic query of a fork's authoritative decision and destination gate.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForkQuery {
    /// Destination repository identity.
    pub destination: String,
    /// Original signed fork identity.
    pub replay: ReplayIdentity,
    /// Imported packs to observe, in fixture order, lowercase hex.
    pub packs: Vec<String>,
}

/// Saved fork result, independent of its stored representation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForkResultView {
    /// Full source repository identity.
    pub source_repository: String,
    /// Source branch.
    pub source_head: String,
    /// Accepted source tip, lowercase hex.
    pub tip: String,
    /// Source publication sequence at acceptance.
    pub source_sequence: u64,
    /// Accepted source packmap head, lowercase hex.
    pub packmap: String,
    /// Imported pack count.
    pub pack_count: u64,
    /// Imported bytes, counting each pack once.
    pub pack_bytes: u64,
    /// Copied index-entry count.
    pub object_count: u64,
    /// Digest of sorted imported pack IDs, lowercase hex.
    pub pack_set_digest: String,
    /// Accepted destination membership generation.
    pub membership_generation: u64,
}

/// Values that coexisted at one authoritative observation point. Internal
/// staging may exist while the destination remains unreadable and unwritable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForkObservation {
    /// Fork guarded acceptance is durable.
    pub accepted: bool,
    /// Fork has durably failed.
    pub failed: bool,
    /// Destination currently accepts ordinary signed writes.
    pub writable: bool,
    /// Destination head ref, absent throughout the fork itself.
    pub head: Option<String>,
    /// Destination paired packmap ref, absent throughout the fork itself.
    pub packmap: Option<String>,
    /// Constructed memberships in query order, including inert staging.
    pub staged_memberships: Vec<bool>,
    /// Reader-visible memberships in query order.
    pub visible_memberships: Vec<bool>,
    /// Monotonic number of durable preparatory commits for this fork, retained
    /// after failure; cleanup is excluded. The acceptance itself is excluded.
    pub progress_commits: u64,
    /// Saved result, absent until guarded acceptance.
    pub result: Option<ForkResultView>,
    /// Original signed operation's replay state.
    pub replay: Option<ReplayView>,
    /// Fork reservation and terminal responsibility.
    pub outcome: Option<ReservationView>,
}

/// Select a published-clearance observation using protocol identities.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationQuery {
    /// Acceptance state and packs whose reader-visible membership is asserted.
    pub acceptance: ObservationQuery,
}

/// Acceptance and publication values that coexisted at one observation point.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationObservation {
    /// Original acceptance evidence, unaffected by later clearance.
    pub acceptance: Observation,
    /// Reader-visible head object ID, or absent.
    pub published_head: Option<String>,
    /// Reader-visible paired packmap ID, or absent.
    pub published_packmap: Option<String>,
    /// Accepted branch sequence.
    pub live_sequence: u64,
    /// Largest eligible reader-visible prefix.
    pub published_sequence: u64,
    /// Latest accepted deletion boundary.
    pub deletion_boundary: u64,
    /// Published memberships in the acceptance query's pack order.
    pub published_memberships: Vec<bool>,
}

/// Reliance rule exercised by a disposable fixture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReliancePurpose {
    /// Existing unrooted members with completed GC mark/wait history.
    Gc,
    /// An external delta whose base can receive an inspection serving stop.
    Inspection,
}

/// Request an accepted base and a new, unpublished external-delta candidate.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelianceFixtureQuery {
    /// Select required setup without inferring it from a branch name.
    pub purpose: ReliancePurpose,
    /// Fresh repository identity owned by the fixture signer.
    pub repository: String,
    /// Candidate branch, initially absent.
    pub head: String,
    /// Candidate signing public key in envelope spelling.
    pub signer: String,
}

/// Canonical candidate bytes relying on exactly one accepted external base.
/// The binding establishes the base through a valid accepted operation; it
/// MUST NOT accept the candidate or create the candidate branch. The base
/// remains usable. For `gc` fixtures it has no independent root, pin, or hold
/// forbidding the prepared drop, with mark/wait history complete at the pinned
/// clock; a real deletion may remove its original seeding ref. Fixture setup
/// restores that clock and never fabricates an accepted candidate.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelianceFixture {
    /// Accepted, usable base pack, lowercase hex.
    pub base_pack: String,
    /// Accepted head object in the base pack, for a ticketless GC race.
    pub base_head: String,
    /// Accepted canonical packmap member naming the base, for that GC race.
    pub base_packmap: String,
    /// Candidate canonical pack bytes with an external delta base in `base_pack`.
    pub pack: Vec<u8>,
    /// Candidate head object ID, lowercase hex.
    pub head: String,
    /// Canonical candidate packmap bytes.
    pub packmap_pack: Vec<u8>,
    /// Candidate packmap ID, lowercase hex.
    pub packmap: String,
}

/// Acceptance and usable-membership evidence from one authoritative snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelianceObservation {
    /// Candidate acceptance evidence.
    pub acceptance: Observation,
    /// Usability for delta-base and closure reliance, in query pack order.
    pub usable_memberships: Vec<bool>,
}

/// Commands operate only on an isolated test fixture. Unsupported commands
/// return HTTP 501 and mutate nothing. Successful commands return HTTP 200.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    /// Seed or change a single-pack fixture, using protocol identity and bytes.
    /// Requires `pack-locations.fixture`. The content-addressed body is bounded
    /// to 64 KiB. Denials are irreversible; scenarios use fresh pack bodies.
    PackLocationFixture {
        repository: String,
        pack: Vec<u8>,
        state: PackLocationState,
    },
    /// Obtain a valid test-only wire setter statement without changing authority.
    /// Requires `authority.setter_fixture`; never returns signing key material.
    PrepareAuthoritySetter,
    /// Pin the test server's business clock (Unix milliseconds).
    PinClock { now_ms: i64 },
    /// Advance that clock by a nonnegative duration.
    AdvanceClock { delta_ms: u64 },
    /// Increment a namespace's authority and install its local final fence.
    BumpAuthority { namespace: String },
    /// Arm a one-shot protocol boundary for a particular decision.
    Pause {
        step: String,
        repository: String,
        head: String,
        /// Optional protocol decision class; absent selects ref acceptance.
        /// `fork_destination_claim` selects first atomic destination exclusion.
        /// `writer_authority_ready` selects ordinary write acceptance after
        /// reusable write authority is acquired; resume retains that authority.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        decision_class: Option<String>,
        /// One-based occurrence within this operation's decision class.
        /// Absent selects the first occurrence.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        occurrence: Option<u64>,
        /// Optional test-only result injection after releasing the barrier.
        /// `uncertain_storage_result` requires `fault.uncertain_result`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        on_resume: Option<String>,
    },
    /// Observe whether the armed operation has reached its barrier.
    BarrierStatus,
    /// Release the blocked operation. No acceptance is implied.
    Resume,
    /// Rebuild the server, retaining the stores promised by its profile.
    /// Modes: `graceful` or `kill`; the latter needs host support.
    Restart { mode: String },
    /// Read one atomic, typed authoritative snapshot.
    Observe { query: ObservationQuery },
    /// Observe acceptance and publication in one authoritative snapshot.
    /// Requires `observe.publication`.
    ObservePublication { query: PublicationQuery },
    /// Control publication eligibility for future decisions on this branch.
    /// This does not assert integration of asynchronous inspection holds.
    /// Requires `publication.eligibility`.
    SetPublicationEligibility {
        repository: String,
        head: String,
        eligible: bool,
    },
    /// Drive outstanding clearance for this branch without replaying acceptance.
    /// Requires `publication.drive`.
    DrivePublication { repository: String, head: String },
    /// Establish an accepted base and return an unpublished dependent candidate.
    /// Requires `reliance.fixture`.
    PrepareReliance { query: RelianceFixtureQuery },
    /// Capture the genuine GC recheck proof, without dropping the member.
    /// Requires `gc.prepare_drop`.
    PrepareGcDrop { repository: String, pack: String },
    /// Attempt that prepared GC drop with its original reliance fence.
    /// Requires `gc.commit_drop`; returns `committed` or `conflict`.
    CommitGcDrop { repository: String, pack: String },
    /// Commit a real inspection verdict or hold that prevents member reliance.
    /// Requires `inspection.hide_member`.
    HideMember { repository: String, pack: String },
    /// Observe acceptance and membership usability atomically.
    /// Requires `reliance.observe`.
    ObserveReliance { query: ObservationQuery },
    /// Seed a deterministic valid source without creating the destination.
    PrepareFork { query: ForkFixtureQuery },
    /// Read one atomic, layout-independent fork snapshot.
    ObserveFork { query: ForkQuery },
    /// Commit a source change before returning; never modify the destination.
    /// Requires the matching `fork.source_change.<change>` capability.
    ChangeForkSource {
        query: ForkQuery,
        change: ForkSourceChange,
    },
}

/// Command result. An absent optional field has no asserted meaning.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    /// Dedicated test namespace, only for `prepare_authority_setter`.
    pub authority_namespace: Option<String>,
    /// Valid signed setter statement for a strictly newer generation.
    pub authority_statement: Option<String>,
    /// Observation, only for `observe`.
    pub observation: Option<Observation>,
    /// Atomic publication snapshot, only for `observe_publication`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publication_observation: Option<PublicationObservation>,
    /// External-delta fixture, only for `prepare_reliance`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reliance_fixture: Option<RelianceFixture>,
    /// Actual prepared GC drop result: `committed` or `conflict`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gc_drop_result: Option<String>,
    /// Atomic reliance snapshot, only for `observe_reliance`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reliance_observation: Option<RelianceObservation>,
    /// True once an armed operation is held at the named step.
    pub paused: bool,
    /// Current clock, for clock commands.
    pub now_ms: Option<i64>,
    /// Installed authority generation, for authority commands.
    pub generation: Option<u64>,
    /// Valid source and commit-count metadata, only for `prepare_fork`.
    pub fork_fixture: Option<ForkFixture>,
    /// Atomic fork snapshot, only for `observe_fork`.
    pub fork_observation: Option<ForkObservation>,
}
