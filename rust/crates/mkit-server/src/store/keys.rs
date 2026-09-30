//! Key layouts: the registry of every row and index the server stores
//! (reconciliation R-17). Indexes are layouts, not queries.
//!
//! Every key is `<class tag> 0x00 …`: tags such as `p`/`px`/`pp` share
//! prefixes, and the terminator keeps a scan of one class from ever seeing
//! another. Integers are big-endian, so byte order is numeric order. The
//! partition identifies the namespace (and under D34 the shard), never the
//! key. `0x00` never occurs in a repo name, so the repo component can be
//! followed by more components; the last component of a key may hold any
//! bytes.
//!
//! | Class | Key | Value |
//! |---|---|---|
//! | deployment sharding marker (root `Namespace` only) | `sm 00` | UTF-8 `single` or `d34` |
//! | deployment addressing marker (root `Namespace` only) | `am 00` | UTF-8 `single` or `multi` |
//! | layout version | `v 00` | be32 [`LAYOUT_VERSION`]; never on `RefsOnly` stores |
//! | publication sequence and boundary | `pp 00 <repo> 00 <canonical ref>` | v1 `Publication` |
//! | retained advance | `av 00 <repo> 00 <canonical ref> 00 <seq:be64>` | v1 `Advance` |
//! | published ref | `pr 00 <repo> 00 <ref>` | 32-byte published id |
//! | published ref index | `py 00 <repo> 00 <ref>` | 32-byte published id |
//! | published membership index | `pm 00 <repo> 00 <pack:32>` | v1 clearance witness |
//! | ref | `r 00 <repo> 00 <refname>` | 32-byte id |
//! | ref-name index (`RefIndex`) | `x 00 <repo> 00 <refname>` | 32-byte id |
//! | replay record | `p 00 <scope:32>` | codec `ReplayRecord` |
//! | replay expiry index | `px 00 <expires_at:be64> <scope:32>` | empty |
//! | quota state | `q 00 <scope>` | codec `QuotaState` |
//! | quota window index | `qx 00 <window_start:be64> <scope>` | empty |
//! | ref-shard namespace usage | `qs 00 <window:be64>` | codec `NamespaceUsage` |
//! | local namespace view | `qv 00 <window:be64>` | codec `NamespaceView` |
//! | coordinator source cumulative | `qc 00 <window:be64> <Partition::encode(source)>` | codec `NamespaceUsage` |
//! | coordinator namespace total | `qt 00 <window:be64>` | codec `NamespaceUsage` |
//! | namespace record (`Coordinator`) | `nr 00` | codec `NamespaceRecord` |
//! | repo record (`Coordinator`) | `rr 00 <repo>` | codec `RepoRecord` |
//! | repository visibility (`Coordinator`) | `rv 00 <repo>` | codec `RepoVisibilityV1`; absent means public |
//! | repo-known marker (ref shard) | `rk 00 <repo>` | empty |
//! | grant epoch | `e 00` | be64; absent means 0, never written as 0 |
//! | epoch lease (ref shard) | `el 00` | codec `EpochLease` |
//! | leased shard (`Coordinator`) | `ls 00 <repo> 00 <shard_ref>` | codec `LeasedShard` |
//! | lease recovery/authority mode (`Coordinator`) | `lr 00` | codec `LeaseRecovery` |
//! | bounded fence checkpoint (`Coordinator`) | `fc 00 <kind:u8>`; 0 grant, 1 authority | v1 generation/recovery/cursor JSON |
//! | published snapshot state (configured Worker `RefIndex` only) | `ps 00` | v1: version:u8, dirty:u8, generation/due/last-success:be64 |
//! | backup state (Worker only; never pruned) | `bk 00` | codec `BackupStateV1` |
//! | ticket | `t 00 <ticket_id:32>` | codec `TicketV1` |
//! | ticket idempotency | `ti 00 <repo> 00 <ref> 00 <pack:32> <signer:32>` | raw ticket id |
//! | open tickets per ref | `tc 00 <repo> 00 <ref>` | be64; absent means 0, deleted at 0 |
//! | open tickets per signer | `tu 00 <repo> 00 <ref> 00 <signer:32>` | be64; same rules |
//! | ticket expiry timer | `w 00 <expires_at:be64> 02 <ticket_id:32>` | empty |
//! | local membership | `m 00 <repo> 00 <pack:32>` | empty (immediate upload) or v1 clearance witness |
//! | indexed verification state | `vs 00 <repo> 00 <pack:32>` | `VerificationV1` |
//! | scheduled-verification job (ref shard) | `vc 00 <repo> 00 <pack:32> <sub:u8> [<id:32>]` | sub 0 job `VerifyJobV1`; 1 frame; 2 closure child; 3 charged external base; 4 extraction candidate (WP-4.10b); 5 history edges (parents); 6 external source pack dependency |
//! | repository object index | `i 00 <repo> 00 <object:32> <pack:32>` | binary `IndexValue` |
//! | reservation and outcome | `o 00 <reservation_id>` | codec `ReservationV1` |
//! | outcome pending index | `oq 00 <seq:be64> <reservation_id>` | empty |
//! | relay high-water mark | `rh 00 <Partition::encode(source)>` | be64; never pruned, bounded by source shards |
//! | relay queue | `or 00 <seq:be64>` | codec `RelayV1` |
//! | relay scan progress (source shard) | `rs 00` | codec `RelayScanV1`; one per source, never pruned |
//! | outbox sequence | `os 00` | be64; last allocated, starts at 1, never deleted |
//! | outcome backlog | `oc 00` | codec `Backlog`; absent means zero |
//! | timer (owned by `timers`) | `w 00 <due_at:be64> <kind:u8> <ref>` | codec per kind |
//! | holder (`ContentShard`) | `h 00 <object:32> <ns> 00 <repo>` | codec `HolderRecord` (`HolderV1`: `seq`, `op_id`) |
//! | GC hold (`ContentShard`) | `g 00 <object:32> <hold_id:32>` | codec `hold` |
//! | blocklist (`ContentShard`) | `b 00 <object:32>` | codec `BlockEntry` |
//! | object state (`ContentShard`) | `c 00 <object:32>` | codec `ObjectState` |
//!
//! Reserved tags ([`RESERVED_TAGS`]), each laid out by the work package
//! that adds it: leases `l`, tombstones `tb`, and the
//! deployment's namespace list
//! [`TAG_NAMESPACE_LIST`] (WP-1.5; see `Partition` for enumeration). A
//! new row adds its layout here, with a golden test.
//!
//! The `ContentIndex` classes (`h`, `g`, `b`, `c`) live only in
//! `ContentShard` partitions. Each holder row carries the object's
//! post-bump change sequence and the recording operation's id (R-131); the
//! holder count lives in the object's `c` row.

use bytes::{BufMut, Bytes, BytesMut};
use mkit_core::hash::Hash;

use super::Partition;
use super::error::StoreError;
use super::kv::{Key, MAX_KEY_BYTES};
use crate::quota::QuotaScope;
use crate::refs::{MAX_REF_NAME_BYTES, is_served_ref_name};
use crate::repo::{MAX_REPO_NAME_BYTES, NamespaceKey, RepoName};

// The longest ticket index (`ti 00 <repo> 00 <ref> 00 <pack> <signer>`) fits.
const _: () = assert!(3 + MAX_REPO_NAME_BYTES + 1 + MAX_REF_NAME_BYTES + 1 + 64 <= MAX_KEY_BYTES);

// rh + Ref partition: tag, longest ed25519 namespace (72), repo, ref, terminators.
const _: () = assert!(3 + 1 + 72 + MAX_REPO_NAME_BYTES + MAX_REF_NAME_BYTES + 3 <= MAX_KEY_BYTES);

// The longest ref key (`r 00 <repo> 00 <refname>`) fits a key.
const _: () = assert!(2 + MAX_REPO_NAME_BYTES + 1 + MAX_REF_NAME_BYTES <= MAX_KEY_BYTES);

/// The key-layout version this binary writes. A binary that reads a newer
/// version refuses to serve the partition.
pub const LAYOUT_VERSION: u32 = 1;

/// Layout version tag.
pub const TAG_LAYOUT_VERSION: &str = "v";
/// Worker deployment sharding marker tag (root Namespace only).
pub const TAG_SHARDING_MARKER: &str = "sm";
/// Worker deployment addressing marker tag (root Namespace only).
pub const TAG_ADDRESSING_MARKER: &str = "am";
/// Ref tag.
pub const TAG_REF: &str = "r";
/// Ref-name index tag.
pub const TAG_REF_INDEX: &str = "x";
/// Replay record tag.
pub const TAG_REPLAY: &str = "p";
/// Replay expiry index tag.
pub const TAG_REPLAY_EXPIRY: &str = "px";
/// Quota state tag.
pub const TAG_QUOTA: &str = "q";
/// Quota window index tag.
pub const TAG_QUOTA_WINDOW: &str = "qx";
/// Ref-shard cumulative namespace usage.
pub const TAG_QUOTA_SHARD: &str = "qs";
/// Ref-shard local aggregate view.
pub const TAG_QUOTA_VIEW: &str = "qv";
/// Coordinator source contribution.
pub const TAG_QUOTA_CONTRIBUTION: &str = "qc";
/// Coordinator namespace total, also charged directly there.
pub const TAG_QUOTA_TOTAL: &str = "qt";
/// Grant epoch tag.
pub const TAG_GRANT_EPOCH: &str = "e";
/// Independent namespace authority generation.
pub const TAG_AUTHORITY_GENERATION: &str = "ag";
/// Durable generation/recovery-bound completion cursor; kind 0 grant, 1 authority.
pub const TAG_FENCE_CURSOR: &str = "fc";
/// Ref shard's epoch lease tag.
pub const TAG_EPOCH_LEASE: &str = "el";
/// Coordinator's leased shard table tag.
pub const TAG_LEASED_SHARD: &str = "ls";
/// Coordinator's declared lease-table recovery marker tag.
pub const TAG_LEASE_RECOVERY: &str = "lr";
/// Coordinator's completed lease-table reconciliation marker tag.
pub const TAG_LEASE_RECONCILE: &str = "lrc";
/// Per-partition Worker backup state. Never pruned.
pub const TAG_BACKUP_STATE: &str = "bk";
/// Timer tag (owned by `timers`).
pub const TAG_TIMER: &str = "w";
/// `ContentIndex` holder tag.
pub const TAG_HOLDER: &str = "h";
/// `ContentIndex` GC hold tag.
pub const TAG_HOLD: &str = "g";
/// `ContentIndex` blocklist tag.
pub const TAG_BLOCK: &str = "b";
/// `ContentIndex` object state (last change and holder count) tag.
pub const TAG_OBJECT_STATE: &str = "c";

/// Namespace record tag: the namespace's creation time and configuration
/// version, in its coordinator.
pub const TAG_NAMESPACE_RECORD: &str = "nr";
/// Repo-known marker tag: the repository is registered in its coordinator.
pub const TAG_REPO_KNOWN: &str = "rk";
/// Repo registry tag: one row per repo of the namespace, in its
/// coordinator partition. Bounded by repos, not refs.
pub const TAG_REPO_REGISTRY: &str = "rr";
/// Repository visibility tag (`Coordinator`): absent means public; the
/// row may exist without `rr` (SPEC-WRITE-GRANTS §9.1).
pub const TAG_REPO_VISIBILITY: &str = "rv";
/// Namespace list tag, reserved until namespace enumeration under
/// `namespace_policy = any` is needed (WP-1.29 backup). No M1 consumer
/// or deployment-wide partition exists. A backend may keep its own metadata.
pub const TAG_NAMESPACE_LIST: &str = "nl";

/// Ticket row tag.
pub const TAG_TICKET: &str = "t";
/// Ticket idempotency index tag.
pub const TAG_TICKET_INDEX: &str = "ti";
/// Open-ticket counter per ref tag.
pub const TAG_TICKETS_PER_REF: &str = "tc";
/// Open-ticket counter per signer tag.
pub const TAG_TICKETS_PER_SIGNER: &str = "tu";
/// Local repository membership tag.
pub const TAG_MEMBERSHIP: &str = "m";
/// Per-(repository, pack) verification state in the ref shard.
pub const TAG_VERIFICATION: &str = "vs";
/// Scheduled-verification job and checkpoint rows in the ref shard.
pub const TAG_VERIFY_CURSOR: &str = "vc";
/// Repository-scoped object index tag.
pub const TAG_OBJECT_INDEX: &str = "i";
/// Reservation and terminal outcome tag.
pub const TAG_RESERVATION: &str = "o";
/// Undelivered terminal outcome index tag.
pub const TAG_OUTCOME_PENDING: &str = "oq";
/// Membership relay queue tag.
pub const TAG_RELAY: &str = "or";
/// Per-source relay deduplication watermark in the target.
pub const TAG_RELAY_HIGH_WATER: &str = "rh";
/// Persistent source relay scan progress tag.
pub const TAG_RELAY_SCAN: &str = "rs";
/// Last allocated outbox sequence tag.
pub const TAG_OUTBOX_SEQUENCE: &str = "os";
/// Terminal outcome backlog tag.
pub const TAG_OUTCOME_BACKLOG: &str = "oc";

/// Persistent paired sequence, pointer and deletion boundary.
pub const TAG_PUBLICATION: &str = "pp";
/// Retained advance values and obligations.
pub const TAG_ADVANCE: &str = "av";
/// Authoritative published ref value.
pub const TAG_PUBLISHED_REF: &str = "pr";
/// Published `RefIndex` projection.
pub const TAG_PUBLISHED_INDEX: &str = "py";
/// Published `RepoIndex` membership projection.
pub const TAG_PUBLISHED_MEMBER: &str = "pm";

/// Tags whose layouts later work packages add. No M0 key uses them.
pub const RESERVED_TAGS: &[&str] = &["tb", "l", TAG_NAMESPACE_LIST];

/// [`TAG_VERIFY_CURSOR`] sub-classes: the job row.
pub const VC_JOB: u8 = 0;
/// A pack entry's frame, keyed by object id.
pub const VC_FRAME: u8 = 1;
/// A closure child still owed a member, keyed by object id.
pub const VC_CHILD: u8 = 2;
/// External-base charges keyed by a location digest, and object-keyed depth rows.
pub const VC_BASE: u8 = 3;
/// An extraction candidate, keyed by object id (WP-4.10b).
pub const VC_CANDIDATE: u8 = 4;
/// A commit's, remix's or tag's parents, keyed by object id: the history
/// edges the fast-forward check reads (WP-4.17).
pub const VC_HISTORY: u8 = 5;
/// External delta-base source pack, including chain intermediates.
pub const VC_DEPENDENCY: u8 = 6;

/// A key decoded by [`parse`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParsedKey {
    /// `bk 00`.
    BackupState,
    /// `sm 00`: the Worker deployment sharding mode.
    ShardingMarker,
    /// `am 00`: the Worker deployment addressing mode.
    AddressingMarker,
    /// `v 00`.
    LayoutVersion,
    /// `nr 00`.
    NamespaceRecord,
    /// `rr 00 <repo>`.
    RepoRecord(RepoName),
    /// `rv 00 <repo>`.
    RepoVisibility(RepoName),
    /// `rk 00 <repo>`.
    RepoKnown(RepoName),
    /// `rh 00 <Partition::encode(source)>`. Never pruned.
    RelayHighWater(Partition),
    /// `r 00 <repo> 00 <refname>`.
    Ref {
        /// Repository.
        repo: RepoName,
        /// Full ref name.
        name: String,
    },
    /// `x 00 <repo> 00 <refname>`.
    RefIndexEntry {
        /// Repository.
        repo: RepoName,
        /// Full ref name.
        name: String,
    },
    /// Publication key with a validated full sequence/ref name.
    Publication { repo: RepoName, name: String },
    /// Retained advance, with nonzero sequence.
    Advance {
        repo: RepoName,
        name: String,
        sequence: u64,
    },
    /// Authoritative published value.
    PublishedRef { repo: RepoName, name: String },
    /// Published ref projection.
    PublishedIndex { repo: RepoName, name: String },
    /// Versioned published membership witness.
    PublishedMember { repo: RepoName, pack_id: Hash },
    /// `p 00 <scope>`.
    Replay(Hash),
    /// `px 00 <expires_at> <scope>`.
    ReplayExpiry {
        /// Record expiry, Unix ms.
        expires_at_ms: u64,
        /// Record scope.
        scope: Hash,
    },
    /// `q 00 <scope>`.
    Quota(String),
    /// `qx 00 <window_start> <scope>`.
    QuotaWindow {
        /// Window start, Unix ms.
        window_start_ms: u64,
        /// Quota scope.
        scope: String,
    },
    /// `qs 00 <window>`.
    QuotaShard(u64),
    /// `qv 00 <window>`.
    QuotaView(u64),
    /// `qc 00 <window> <source>`.
    QuotaContribution { window: u64, source: Partition },
    /// `qt 00 <window>`.
    QuotaTotal(u64),
    /// `t 00 <ticket_id>`.
    Ticket(Hash),
    /// `ti 00 <repo> 00 <ref> 00 <pack> <signer>`.
    TicketIndex {
        /// Repository.
        repo: RepoName,
        /// Ref name.
        name: String,
        /// Pack id.
        pack_id: Hash,
        /// Signer id.
        signer: Hash,
    },
    /// `tc 00 <repo> 00 <ref>`.
    TicketsPerRef {
        /// Repository.
        repo: RepoName,
        /// Ref name.
        name: String,
    },
    /// `tu 00 <repo> 00 <ref> 00 <signer>`.
    TicketsPerSigner {
        /// Repository.
        repo: RepoName,
        /// Ref name.
        name: String,
        /// Signer id.
        signer: Hash,
    },
    /// `m 00 <repo> 00 <pack>`.
    Membership {
        /// Repository.
        repo: RepoName,
        /// Pack id.
        pack_id: Hash,
    },
    /// `vs 00 <repo> 00 <pack>`.
    Verification { repo: RepoName, pack_id: Hash },
    /// `vc 00 <repo> 00 <pack> <sub> [<id>]`.
    VerifyCursor {
        /// Repository.
        repo: RepoName,
        /// Pack id.
        pack_id: Hash,
        /// Sub-class, one of the `VC_*` constants.
        sub: u8,
        /// Object id, for every sub-class but the job row.
        id: Option<Hash>,
    },
    /// `i 00 <repo> 00 <object> <pack>`.
    ObjectIndex {
        /// Repository.
        repo: RepoName,
        /// Object id.
        object: Hash,
        /// Pack id.
        pack_id: Hash,
    },
    /// `o 00 <reservation_id>`.
    Reservation(String),
    /// `oq 00 <seq> <reservation_id>`.
    OutcomePending {
        /// Allocated sequence.
        seq: u64,
        /// Reservation id.
        reservation_id: String,
    },
    /// `or 00 <seq>`.
    Relay(u64),
    /// `rs 00`: persistent source relay scan progress.
    RelayScan,
    /// `os 00`.
    OutboxSequence,
    /// `oc 00`.
    OutcomeBacklog,
    /// `e 00`.
    GrantEpoch,
    /// Independent deployment-authority generation.
    AuthorityGeneration,
    /// `el 00`.
    EpochLease,
    /// `ls 00 <repo> 00 <shard_ref>`.
    LeasedShard {
        /// Repository whose ref shard holds the lease.
        repo: RepoName,
        /// The `Partition::Ref.shard_ref` identity.
        shard_ref: String,
    },
    /// `lr 00`.
    LeaseRecovery,
    /// `fc 00 <kind:u8>`: independent generation/recovery-bound cursor.
    FenceCursor(u8),
    /// `lrc 00`.
    LeaseReconcile,
    /// `w 00 <due_at> <kind> <ref>`.
    Timer {
        /// Due time, Unix ms.
        due_at_ms: u64,
        /// Timer kind.
        kind: u8,
        /// What the timer refers to.
        reference: Bytes,
    },
    /// `h 00 <object> <ns> 00 <repo>`.
    Holder {
        /// Object id.
        object: Hash,
        /// Holding namespace.
        ns: NamespaceKey,
        /// Holding repository.
        repo: RepoName,
    },
    /// `g 00 <object> <hold_id>`.
    Hold {
        /// Object id.
        object: Hash,
        /// Hold id.
        hold_id: Hash,
    },
    /// `b 00 <object>`.
    Block(Hash),
    /// `c 00 <object>`.
    ObjectState(Hash),
}

fn key(tag: &str, parts: &[&[u8]]) -> Key {
    let mut buf =
        BytesMut::with_capacity(tag.len() + 1 + parts.iter().map(|p| p.len()).sum::<usize>());
    buf.put_slice(tag.as_bytes());
    buf.put_u8(0);
    for part in parts {
        buf.put_slice(part);
    }
    Key::new(buf.freeze())
}

/// The smallest key greater than every key starting with `prefix`.
fn successor(prefix: &Key) -> Key {
    let mut bytes = prefix.as_bytes().to_vec();
    while bytes.last() == Some(&0xff) {
        bytes.pop();
    }
    if let Some(last) = bytes.last_mut() {
        *last += 1;
    }
    Key::new(bytes)
}

/// `[<tag> 00, <tag> 01)`: every key of one class and no other.
#[must_use]
pub fn class_range(tag: &str) -> (Key, Key) {
    let start = key(tag, &[]);
    let end = successor(&start);
    (start, end)
}

/// Whether `key` is in the ref class (what a `RefsOnly` store accepts).
#[must_use]
pub fn is_ref_key(key: &Key) -> bool {
    key.as_bytes().starts_with(b"r\0")
}

/// `v 00`.
#[must_use]
pub fn layout_version() -> Key {
    key(TAG_LAYOUT_VERSION, &[])
}

/// `sm 00`: UTF-8 `single` or `d34`, only in the root Namespace partition.
#[must_use]
pub fn sharding_marker() -> Key {
    key(TAG_SHARDING_MARKER, &[])
}

/// `am 00`: UTF-8 `single` or `multi`, only in the root Namespace partition.
#[must_use]
pub fn addressing_marker() -> Key {
    key(TAG_ADDRESSING_MARKER, &[])
}

/// `nr 00`: the namespace coordinator record.
#[must_use]
pub fn namespace_record() -> Key {
    key(TAG_NAMESPACE_RECORD, &[])
}

/// `rr 00 <repo>`: the repository coordinator record.
#[must_use]
pub fn repo_record(repo: &RepoName) -> Key {
    key(TAG_REPO_REGISTRY, &[repo.as_str().as_bytes()])
}

/// `rv 00 <repo>`: the repository's visibility row in its coordinator.
#[must_use]
pub fn repo_visibility(repo: &RepoName) -> Key {
    key(TAG_REPO_VISIBILITY, &[repo.as_str().as_bytes()])
}

/// `rk 00 <repo>`: the ref shard's repository registration marker.
#[must_use]
pub fn repo_known(repo: &RepoName) -> Key {
    key(TAG_REPO_KNOWN, &[repo.as_str().as_bytes()])
}

/// `r 00 <repo> 00 <name>`.
#[must_use]
pub fn ref_key(repo: &RepoName, name: &str) -> Key {
    key(TAG_REF, &[repo.as_str().as_bytes(), b"\0", name.as_bytes()])
}

/// The scan range of every ref of `repo` whose name starts with `prefix`.
#[must_use]
pub fn ref_prefix_range(repo: &RepoName, prefix: &str) -> (Key, Key) {
    let start = ref_key(repo, prefix);
    let end = successor(&start);
    (start, end)
}

/// `x 00 <repo> 00 <name>`.
#[must_use]
pub fn ref_index_key(repo: &RepoName, name: &str) -> Key {
    key(
        TAG_REF_INDEX,
        &[repo.as_str().as_bytes(), b"\0", name.as_bytes()],
    )
}

/// The scan range of every indexed ref of `repo` starting with `prefix`.
#[must_use]
pub fn ref_index_prefix_range(repo: &RepoName, prefix: &str) -> (Key, Key) {
    let start = ref_index_key(repo, prefix);
    let end = successor(&start);
    (start, end)
}

/// Publication key for the canonical sequence name (head for a branch pair).
#[must_use]
pub fn publication(repo: &RepoName, name: &str) -> Key {
    key(
        TAG_PUBLICATION,
        &[repo.as_str().as_bytes(), b"\0", name.as_bytes()],
    )
}
/// Retained value, ordered numerically within one ref sequence.
#[must_use]
pub fn advance(repo: &RepoName, name: &str, sequence: u64) -> Key {
    key(
        TAG_ADVANCE,
        &[
            repo.as_str().as_bytes(),
            b"\0",
            name.as_bytes(),
            b"\0",
            &sequence.to_be_bytes(),
        ],
    )
}
/// Authoritative published ref value.
#[must_use]
pub fn published_ref(repo: &RepoName, name: &str) -> Key {
    key(
        TAG_PUBLISHED_REF,
        &[repo.as_str().as_bytes(), b"\0", name.as_bytes()],
    )
}
/// Published ref projection in the same bucket as the live index.
#[must_use]
pub fn published_index(repo: &RepoName, name: &str) -> Key {
    key(
        TAG_PUBLISHED_INDEX,
        &[repo.as_str().as_bytes(), b"\0", name.as_bytes()],
    )
}
/// Published membership in the pack's repository index partition.
#[must_use]
pub fn published_member(repo: &RepoName, pack: &Hash) -> Key {
    key(
        TAG_PUBLISHED_MEMBER,
        &[repo.as_str().as_bytes(), b"\0", pack],
    )
}
/// A validated published-ref or published-index prefix range.
#[must_use]
pub fn published_range(repo: &RepoName, prefix: &str, index: bool) -> (Key, Key) {
    let start = if index {
        published_index(repo, prefix)
    } else {
        published_ref(repo, prefix)
    };
    let end = successor(&start);
    (start, end)
}

/// `p 00 <scope>`.
#[must_use]
pub fn replay(scope: &Hash) -> Key {
    key(TAG_REPLAY, &[scope])
}

/// `px 00 <expires_at> <scope>`.
#[must_use]
pub fn replay_expiry(expires_at_ms: u64, scope: &Hash) -> Key {
    key(TAG_REPLAY_EXPIRY, &[&expires_at_ms.to_be_bytes(), scope])
}

/// The expiry-index range of records expiring strictly before `before_ms`.
#[must_use]
pub fn replay_expiry_before(before_ms: u64) -> (Key, Key) {
    let (start, _) = class_range(TAG_REPLAY_EXPIRY);
    (start, key(TAG_REPLAY_EXPIRY, &[&before_ms.to_be_bytes()]))
}

/// `q 00 <scope>`.
#[must_use]
pub fn quota(scope: &QuotaScope) -> Key {
    key(TAG_QUOTA, &[scope.as_str().as_bytes()])
}

/// `qx 00 <window_start> <scope>`.
#[must_use]
pub fn quota_window(window_start_ms: u64, scope: &QuotaScope) -> Key {
    key(
        TAG_QUOTA_WINDOW,
        &[&window_start_ms.to_be_bytes(), scope.as_str().as_bytes()],
    )
}

/// The window-index range of windows starting strictly before `before_ms`.
#[must_use]
pub fn quota_window_before(before_ms: u64) -> (Key, Key) {
    let (start, _) = class_range(TAG_QUOTA_WINDOW);
    (start, key(TAG_QUOTA_WINDOW, &[&before_ms.to_be_bytes()]))
}

/// `qs 00 <window:be64>`.
#[must_use]
pub fn quota_shard(window: u64) -> Key {
    key(TAG_QUOTA_SHARD, &[&window.to_be_bytes()])
}

/// `qv 00 <window:be64>`.
#[must_use]
pub fn quota_view(window: u64) -> Key {
    key(TAG_QUOTA_VIEW, &[&window.to_be_bytes()])
}

/// `qc 00 <window:be64> <source>`.
pub fn quota_contribution(window: u64, source: &Partition) -> Result<Key, StoreError> {
    if !matches!(source, Partition::Ref { .. }) {
        return Err(StoreError::Invalid(
            "quota source is not a ref shard".into(),
        ));
    }
    checked_key(
        TAG_QUOTA_CONTRIBUTION,
        &[&window.to_be_bytes(), &source.encode()?],
    )
}

/// `qt 00 <window:be64>`.
#[must_use]
pub fn quota_total(window: u64) -> Key {
    key(TAG_QUOTA_TOTAL, &[&window.to_be_bytes()])
}

/// The ordered range of namespace rows strictly before `window`.
#[must_use]
pub fn quota_namespace_before(tag: &str, window: u64) -> (Key, Key) {
    (key(tag, &[]), key(tag, &[&window.to_be_bytes()]))
}

/// Every row of a fixed namespace window in one ordered class.
#[must_use]
pub fn quota_namespace_window(tag: &str, window: u64) -> (Key, Key) {
    (
        key(tag, &[&window.to_be_bytes()]),
        key(tag, &[&window.saturating_add(1).to_be_bytes()]),
    )
}

/// Whether an id satisfies SPEC-SERVER §6.6: 1–128 ASCII bytes.
#[must_use]
pub fn validate_reservation_id(rid: &str) -> bool {
    (1..=128).contains(&rid.len())
        && rid
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
}

fn checked_key(tag: &str, parts: &[&[u8]]) -> Result<Key, StoreError> {
    let result = key(tag, parts);
    if result.as_bytes().len() > MAX_KEY_BYTES {
        return Err(StoreError::Invalid("key exceeds MAX_KEY_BYTES".into()));
    }
    Ok(result)
}

fn check_ticket_ref(name: &str) -> Result<(), StoreError> {
    if !is_served_ref_name(name) {
        return Err(StoreError::Invalid("invalid ticket ref name".into()));
    }
    Ok(())
}

/// `t 00 <ticket_id>`; fixed length, always within the store limit.
#[must_use]
pub fn ticket(id: &Hash) -> Key {
    key(TAG_TICKET, &[id])
}

/// `ti 00 <repo> 00 <ref> 00 <pack> <signer>`.
pub fn ticket_index(
    repo: &RepoName,
    name: &str,
    pack: &Hash,
    signer: &Hash,
) -> Result<Key, StoreError> {
    check_ticket_ref(name)?;
    checked_key(
        TAG_TICKET_INDEX,
        &[
            repo.as_str().as_bytes(),
            b"\0",
            name.as_bytes(),
            b"\0",
            pack,
            signer,
        ],
    )
}

/// `tc 00 <repo> 00 <ref>`.
pub fn tickets_per_ref(repo: &RepoName, name: &str) -> Result<Key, StoreError> {
    check_ticket_ref(name)?;
    checked_key(
        TAG_TICKETS_PER_REF,
        &[repo.as_str().as_bytes(), b"\0", name.as_bytes()],
    )
}

/// `tu 00 <repo> 00 <ref> 00 <signer>`.
pub fn tickets_per_signer(repo: &RepoName, name: &str, signer: &Hash) -> Result<Key, StoreError> {
    check_ticket_ref(name)?;
    checked_key(
        TAG_TICKETS_PER_SIGNER,
        &[
            repo.as_str().as_bytes(),
            b"\0",
            name.as_bytes(),
            b"\0",
            signer,
        ],
    )
}

/// `m 00 <repo> 00 <pack>`; bounded by `RepoName` and the fixed hash size.
#[must_use]
pub fn membership(repo: &RepoName, pack: &Hash) -> Key {
    key(TAG_MEMBERSHIP, &[repo.as_str().as_bytes(), b"\0", pack])
}

/// `vs 00 <repo> 00 <pack>`; the ref shard holding the ticket owns it.
#[must_use]
pub fn verification(repo: &RepoName, pack: &Hash) -> Key {
    key(TAG_VERIFICATION, &[repo.as_str().as_bytes(), b"\0", pack])
}

/// `vc 00 <repo> 00 <pack> 00`: the job row of a scheduled verification.
#[must_use]
pub fn verify_job(repo: &RepoName, pack: &Hash) -> Key {
    verify_row(repo, pack, VC_JOB, None)
}

/// `vc 00 <repo> 00 <pack> <sub> [<id>]`; only the job row (`VC_JOB`) has no id.
#[must_use]
pub fn verify_row(repo: &RepoName, pack: &Hash, sub: u8, id: Option<&Hash>) -> Key {
    key(
        TAG_VERIFY_CURSOR,
        &[
            repo.as_str().as_bytes(),
            b"\0",
            pack,
            &[sub],
            id.map_or(&[][..], |id| &id[..]),
        ],
    )
}

/// Every row of one job (`sub` `None`), or of one sub-class.
#[must_use]
pub fn verify_range(repo: &RepoName, pack: &Hash, sub: Option<u8>) -> (Key, Key) {
    let mut parts: Vec<&[u8]> = vec![repo.as_str().as_bytes(), b"\0", pack];
    let sub = sub.map(|sub| [sub]);
    if let Some(sub) = &sub {
        parts.push(sub);
    }
    let start = key(TAG_VERIFY_CURSOR, &parts);
    let end = successor(&start);
    (start, end)
}

/// `i 00 <repo> 00 <object> <pack>`.
#[must_use]
pub fn object_index(repo: &RepoName, object: &Hash, pack: &Hash) -> Key {
    key(
        TAG_OBJECT_INDEX,
        &[repo.as_str().as_bytes(), b"\0", object, pack],
    )
}

/// The exact range of index rows for one repository and object.
#[must_use]
pub fn object_index_range(repo: &RepoName, object: &Hash) -> (Key, Key) {
    let start = key(TAG_OBJECT_INDEX, &[repo.as_str().as_bytes(), b"\0", object]);
    let end = successor(&start);
    (start, end)
}

/// `o 00 <reservation_id>`.
pub fn reservation(rid: &str) -> Result<Key, StoreError> {
    if !validate_reservation_id(rid) {
        return Err(StoreError::Invalid("invalid reservation id".into()));
    }
    checked_key(TAG_RESERVATION, &[rid.as_bytes()])
}

/// `oq 00 <seq> <reservation_id>`.
pub fn outcome_pending(seq: u64, rid: &str) -> Result<Key, StoreError> {
    if !validate_reservation_id(rid) || seq == 0 {
        return Err(StoreError::Invalid("invalid outcome pending key".into()));
    }
    checked_key(TAG_OUTCOME_PENDING, &[&seq.to_be_bytes(), rid.as_bytes()])
}

/// `or 00 <seq>`; fixed length, always within the store limit.
#[must_use]
pub fn relay(seq: u64) -> Key {
    key(TAG_RELAY, &[&seq.to_be_bytes()])
}

/// `rh 00 <Partition::encode(source)>`. Never pruned: bounded by source shards.
pub fn relay_high_water(source: &Partition) -> Result<Key, StoreError> {
    checked_key(TAG_RELAY_HIGH_WATER, &[&source.encode()?])
}

/// `rs 00`: one scan-progress row per source shard, never pruned.
#[must_use]
pub fn relay_scan() -> Key {
    key(TAG_RELAY_SCAN, &[])
}

/// `os 00`.
#[must_use]
pub fn outbox_sequence() -> Key {
    key(TAG_OUTBOX_SEQUENCE, &[])
}

/// `oc 00`.
#[must_use]
pub fn outcome_backlog() -> Key {
    key(TAG_OUTCOME_BACKLOG, &[])
}

/// Independent namespace authority generation; absent means generation zero.
#[must_use]
pub fn authority_generation() -> Key {
    key(TAG_AUTHORITY_GENERATION, &[])
}

/// Durable checkpoint for one independent generation's bounded scan.
#[must_use]
pub fn revoke_cursor(authority: bool) -> Key {
    key(TAG_FENCE_CURSOR, &[&[u8::from(authority)]])
}

/// `e 00`.
#[must_use]
pub fn grant_epoch() -> Key {
    key(TAG_GRANT_EPOCH, &[])
}

/// `el 00`: the ref shard's epoch lease.
#[must_use]
pub fn epoch_lease() -> Key {
    key(TAG_EPOCH_LEASE, &[])
}

/// `ls 00 <repo> 00 <shard_ref>`: a coordinator lease-table row.
#[must_use]
pub fn leased_shard(repo: &RepoName, shard_ref: &str) -> Key {
    key(
        TAG_LEASED_SHARD,
        &[repo.as_str().as_bytes(), b"\0", shard_ref.as_bytes()],
    )
}

/// `lr 00`: the coordinator's declared recovery time.
#[must_use]
pub fn lease_recovery() -> Key {
    key(TAG_LEASE_RECOVERY, &[])
}

/// `lrc 00`: reconciliation completed after the declared recovery time.
#[must_use]
pub fn lease_reconcile() -> Key {
    key(TAG_LEASE_RECONCILE, &[])
}

/// Per-partition Worker backup state.
#[must_use]
pub fn backup_state() -> Key {
    key(TAG_BACKUP_STATE, &[])
}

/// `w 00 <due_at> <kind> <reference>` (owned by `timers`).
#[must_use]
pub fn timer(due_at_ms: u64, kind: u8, reference: &[u8]) -> Key {
    key(TAG_TIMER, &[&due_at_ms.to_be_bytes(), &[kind], reference])
}

/// `h 00 <object> <ns> 00 <repo>`.
///
/// # Errors
/// [`StoreError::Invalid`] if `ns` contains `0x00` (no valid namespace
/// does).
pub fn holder(object: &Hash, ns: &NamespaceKey, repo: &RepoName) -> Result<Key, StoreError> {
    if ns.as_str().as_bytes().contains(&0) {
        return Err(StoreError::Invalid("namespace contains 0x00".into()));
    }
    Ok(key(
        TAG_HOLDER,
        &[
            object,
            ns.as_str().as_bytes(),
            b"\0",
            repo.as_str().as_bytes(),
        ],
    ))
}

/// The scan range of every holder row of `object`.
#[must_use]
pub fn holders_of(object: &Hash) -> (Key, Key) {
    let start = key(TAG_HOLDER, &[object]);
    let end = successor(&start);
    (start, end)
}

/// `g 00 <object> <hold_id>`.
#[must_use]
pub fn hold(object: &Hash, hold_id: &Hash) -> Key {
    key(TAG_HOLD, &[object, hold_id])
}

/// The scan range of every hold on `object`.
#[must_use]
pub fn holds_of(object: &Hash) -> (Key, Key) {
    let start = key(TAG_HOLD, &[object]);
    let end = successor(&start);
    (start, end)
}

/// `b 00 <object>`.
#[must_use]
pub fn block(object: &Hash) -> Key {
    key(TAG_BLOCK, &[object])
}

/// `c 00 <object>`.
#[must_use]
pub fn object_state(object: &Hash) -> Key {
    key(TAG_OBJECT_STATE, &[object])
}

fn be64(bytes: &[u8]) -> Option<(u64, &[u8])> {
    let (head, rest) = bytes.split_first_chunk::<8>()?;
    Some((u64::from_be_bytes(*head), rest))
}

fn hash(bytes: &[u8]) -> Option<Hash> {
    Hash::try_from(bytes).ok()
}

fn parse_ticket_binding(tag: &[u8], body: &[u8]) -> Option<ParsedKey> {
    let text = |b: &[u8]| String::from_utf8(b.to_vec()).ok();
    Some({
        let sep = body.iter().position(|&b| b == 0)?;
        let repo = RepoName::new(text(&body[..sep])?).ok()?;
        let rest = &body[sep + 1..];
        if tag == b"tc" {
            let name = text(rest)?;
            check_ticket_ref(&name).ok()?;
            ParsedKey::TicketsPerRef { repo, name }
        } else {
            let sep = rest.iter().position(|&b| b == 0)?;
            let name = text(&rest[..sep])?;
            check_ticket_ref(&name).ok()?;
            let tail = &rest[sep + 1..];
            if tag == b"ti" {
                let (pack_id, signer) = tail.split_first_chunk::<32>()?;
                ParsedKey::TicketIndex {
                    repo,
                    name,
                    pack_id: *pack_id,
                    signer: hash(signer)?,
                }
            } else {
                ParsedKey::TicketsPerSigner {
                    repo,
                    name,
                    signer: hash(tail)?,
                }
            }
        }
    })
}

fn parse_reservation_id(bytes: &[u8]) -> Option<String> {
    let rid = std::str::from_utf8(bytes).ok()?;
    validate_reservation_id(rid).then(|| rid.to_owned())
}

fn parse_outcome_pending(body: &[u8]) -> Option<ParsedKey> {
    let (seq, rest) = be64(body)?;
    let reservation_id = parse_reservation_id(rest)?;
    if seq == 0 {
        return None;
    }
    Some(ParsedKey::OutcomePending {
        seq,
        reservation_id,
    })
}

fn parse_leased_shard(body: &[u8]) -> Option<ParsedKey> {
    let sep = body.iter().position(|&b| b == 0)?;
    Some(ParsedKey::LeasedShard {
        repo: RepoName::new(core::str::from_utf8(&body[..sep]).ok()?).ok()?,
        shard_ref: core::str::from_utf8(&body[sep + 1..]).ok()?.to_owned(),
    })
}

fn parse_holder(body: &[u8]) -> Option<ParsedKey> {
    let (object, rest) = body.split_first_chunk::<32>()?;
    let sep = rest.iter().position(|&b| b == 0)?;
    Some(ParsedKey::Holder {
        object: *object,
        ns: NamespaceKey::from_stored(String::from_utf8(rest[..sep].to_vec()).ok()?),
        repo: RepoName::new(String::from_utf8(rest[sep + 1..].to_vec()).ok()?).ok()?,
    })
}

fn parse_namespace_quota(tag: &[u8], body: &[u8]) -> Option<ParsedKey> {
    let (window, rest) = be64(body)?;
    match tag {
        b"qs" if rest.is_empty() => Some(ParsedKey::QuotaShard(window)),
        b"qv" if rest.is_empty() => Some(ParsedKey::QuotaView(window)),
        b"qt" if rest.is_empty() => Some(ParsedKey::QuotaTotal(window)),
        b"qc" => {
            let source = Partition::decode(rest).ok()?;
            matches!(source, Partition::Ref { .. })
                .then_some(ParsedKey::QuotaContribution { window, source })
        }
        _ => None,
    }
}

fn parse_named_ref(body: &[u8]) -> Option<(RepoName, String)> {
    let sep = body.iter().position(|&b| b == 0)?;
    let repo = RepoName::new(String::from_utf8(body[..sep].to_vec()).ok()?).ok()?;
    let name = String::from_utf8(body[sep + 1..].to_vec()).ok()?;
    Some((repo, name))
}

/// Decode a key of any laid-out class; `None` for a malformed key or a
/// reserved class.
#[must_use]
#[allow(clippy::too_many_lines)] // The key-class dispatch remains in one parser.
pub fn parse(key: &Key) -> Option<ParsedKey> {
    let bytes = key.as_bytes();
    if bytes.len() > MAX_KEY_BYTES {
        return None;
    }
    let split = bytes.iter().position(|&b| b == 0)?;
    let (tag, body) = (&bytes[..split], &bytes[split + 1..]);
    let text = |b: &[u8]| String::from_utf8(b.to_vec()).ok();
    Some(match tag {
        b"sm" if body.is_empty() => ParsedKey::ShardingMarker,
        b"am" if body.is_empty() => ParsedKey::AddressingMarker,
        b"v" if body.is_empty() => ParsedKey::LayoutVersion,
        b"e" if body.is_empty() => ParsedKey::GrantEpoch,
        b"ag" if body.is_empty() => ParsedKey::AuthorityGeneration,
        b"el" if body.is_empty() => ParsedKey::EpochLease,
        b"lr" if body.is_empty() => ParsedKey::LeaseRecovery,
        b"fc" if body.len() == 1 && body[0] <= 1 => ParsedKey::FenceCursor(body[0]),
        b"lrc" if body.is_empty() => ParsedKey::LeaseReconcile,
        b"bk" if body.is_empty() => ParsedKey::BackupState,
        b"ls" => parse_leased_shard(body)?,
        b"nr" if body.is_empty() => ParsedKey::NamespaceRecord,
        b"rr" => ParsedKey::RepoRecord(RepoName::new(text(body)?).ok()?),
        b"rv" => ParsedKey::RepoVisibility(RepoName::new(text(body)?).ok()?),
        b"rh" => ParsedKey::RelayHighWater(Partition::decode(body).ok()?),
        b"rs" if body.is_empty() => ParsedKey::RelayScan,
        b"rk" => ParsedKey::RepoKnown(RepoName::new(text(body)?).ok()?),
        b"r" => {
            let (repo, name) = parse_named_ref(body)?;
            ParsedKey::Ref { repo, name }
        }
        b"x" => {
            let (repo, name) = parse_named_ref(body)?;
            ParsedKey::RefIndexEntry { repo, name }
        }
        b"pp" | b"pr" | b"py" => {
            let (repo, name) = parse_named_ref(body)?;
            check_ticket_ref(&name).ok()?;
            match tag {
                b"pp" => ParsedKey::Publication { repo, name },
                b"pr" => ParsedKey::PublishedRef { repo, name },
                _ => ParsedKey::PublishedIndex { repo, name },
            }
        }
        b"av" => {
            let cut = body.len().checked_sub(9)?;
            if body[cut] != 0 {
                return None;
            }
            let (repo, name) = parse_named_ref(&body[..cut])?;
            check_ticket_ref(&name).ok()?;
            let (sequence, rest) = be64(&body[cut + 1..])?;
            if sequence == 0 || !rest.is_empty() {
                return None;
            }
            ParsedKey::Advance {
                repo,
                name,
                sequence,
            }
        }
        b"pm" => {
            let sep = body.iter().position(|b| *b == 0)?;
            ParsedKey::PublishedMember {
                repo: RepoName::new(text(&body[..sep])?).ok()?,
                pack_id: hash(&body[sep + 1..])?,
            }
        }
        b"t" => ParsedKey::Ticket(hash(body)?),
        b"ti" | b"tc" | b"tu" => parse_ticket_binding(tag, body)?,
        b"m" => {
            let sep = body.iter().position(|&b| b == 0)?;
            ParsedKey::Membership {
                repo: RepoName::new(text(&body[..sep])?).ok()?,
                pack_id: hash(&body[sep + 1..])?,
            }
        }
        b"vs" => {
            let sep = body.iter().position(|&b| b == 0)?;
            ParsedKey::Verification {
                repo: RepoName::new(text(&body[..sep])?).ok()?,
                pack_id: hash(&body[sep + 1..])?,
            }
        }
        b"vc" => {
            let sep = body.iter().position(|&b| b == 0)?;
            let (pack, rest) = body[sep + 1..].split_first_chunk::<32>()?;
            let (sub, id) = rest.split_first()?;
            let id = match (*sub, id.len()) {
                (VC_JOB, 0) => None,
                (VC_FRAME..=VC_DEPENDENCY, 32) => Some(hash(id)?),
                _ => return None,
            };
            ParsedKey::VerifyCursor {
                repo: RepoName::new(text(&body[..sep])?).ok()?,
                pack_id: *pack,
                sub: *sub,
                id,
            }
        }
        b"i" => {
            let sep = body.iter().position(|&b| b == 0)?;
            let (object, pack_id) = body[sep + 1..].split_first_chunk::<32>()?;
            ParsedKey::ObjectIndex {
                repo: RepoName::new(text(&body[..sep])?).ok()?,
                object: *object,
                pack_id: hash(pack_id)?,
            }
        }
        b"o" => ParsedKey::Reservation(parse_reservation_id(body)?),
        b"oq" => parse_outcome_pending(body)?,
        b"or" => {
            let (seq, rest) = be64(body)?;
            if !rest.is_empty() {
                return None;
            }
            ParsedKey::Relay(seq)
        }
        b"os" if body.is_empty() => ParsedKey::OutboxSequence,
        b"oc" if body.is_empty() => ParsedKey::OutcomeBacklog,
        b"p" => ParsedKey::Replay(hash(body)?),
        b"px" => {
            let (expires_at_ms, rest) = be64(body)?;
            ParsedKey::ReplayExpiry {
                expires_at_ms,
                scope: hash(rest)?,
            }
        }
        b"q" => ParsedKey::Quota(text(body)?),
        b"qx" => {
            let (window_start_ms, rest) = be64(body)?;
            ParsedKey::QuotaWindow {
                window_start_ms,
                scope: text(rest)?,
            }
        }
        b"qs" | b"qv" | b"qt" | b"qc" => parse_namespace_quota(tag, body)?,
        b"w" => {
            let (due_at_ms, rest) = be64(body)?;
            let (&kind, reference) = rest.split_first()?;
            ParsedKey::Timer {
                due_at_ms,
                kind,
                reference: Bytes::copy_from_slice(reference),
            }
        }
        b"h" => parse_holder(body)?,
        b"g" => {
            let (object, hold_id) = body.split_first_chunk::<32>()?;
            ParsedKey::Hold {
                object: *object,
                hold_id: hash(hold_id)?,
            }
        }
        b"b" => ParsedKey::Block(hash(body)?),
        b"c" => ParsedKey::ObjectState(hash(body)?),
        _ => return None,
    })
}

/// The quota-state key a quota-window index key points at.
#[must_use]
pub fn quota_for_window(index: &Key) -> Option<Key> {
    match parse(index)? {
        ParsedKey::QuotaWindow { scope, .. } => Some(key(TAG_QUOTA, &[scope.as_bytes()])),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn repo(name: &str) -> RepoName {
        RepoName::new(name).unwrap()
    }

    fn scope() -> QuotaScope {
        QuotaScope::for_signer(&NamespaceKey::deployment_default(), &[0xab; 32])
    }

    fn all_tags() -> Vec<&'static str> {
        let mut tags = vec![
            TAG_SHARDING_MARKER,
            TAG_LAYOUT_VERSION,
            TAG_REF,
            TAG_REF_INDEX,
            TAG_REPLAY,
            TAG_REPLAY_EXPIRY,
            TAG_QUOTA,
            TAG_QUOTA_WINDOW,
            TAG_QUOTA_SHARD,
            TAG_QUOTA_VIEW,
            TAG_QUOTA_CONTRIBUTION,
            TAG_QUOTA_TOTAL,
            TAG_GRANT_EPOCH,
            TAG_EPOCH_LEASE,
            TAG_LEASED_SHARD,
            TAG_LEASE_RECOVERY,
            TAG_FENCE_CURSOR,
            TAG_BACKUP_STATE,
            TAG_TIMER,
            TAG_HOLDER,
            TAG_HOLD,
            TAG_BLOCK,
            TAG_OBJECT_STATE,
            TAG_NAMESPACE_RECORD,
            TAG_REPO_REGISTRY,
            TAG_REPO_VISIBILITY,
            TAG_REPO_KNOWN,
            TAG_RELAY_HIGH_WATER,
            TAG_RELAY_SCAN,
            TAG_TICKET,
            TAG_TICKET_INDEX,
            TAG_TICKETS_PER_REF,
            TAG_TICKETS_PER_SIGNER,
            TAG_MEMBERSHIP,
            TAG_VERIFICATION,
            TAG_VERIFY_CURSOR,
            TAG_OBJECT_INDEX,
            TAG_RESERVATION,
            TAG_OUTCOME_PENDING,
            TAG_RELAY,
            TAG_OUTBOX_SEQUENCE,
            TAG_OUTCOME_BACKLOG,
            TAG_PUBLICATION,
            TAG_ADVANCE,
            TAG_PUBLISHED_REF,
            TAG_PUBLISHED_INDEX,
            TAG_PUBLISHED_MEMBER,
        ];
        tags.extend_from_slice(RESERVED_TAGS);
        tags
    }

    #[test]
    fn publication_key_goldens_and_strict_parsing() {
        let repository = repo("a");
        let name = "refs/heads/main";
        let cases = [
            (
                publication(&repository, name),
                b"pp\0a\0refs/heads/main".to_vec(),
                ParsedKey::Publication {
                    repo: repository.clone(),
                    name: name.into(),
                },
            ),
            (
                advance(&repository, name, 0x0102_0304_0506_0708),
                [
                    b"av\0a\0refs/heads/main\0".as_slice(),
                    &[1, 2, 3, 4, 5, 6, 7, 8],
                ]
                .concat(),
                ParsedKey::Advance {
                    repo: repository.clone(),
                    name: name.into(),
                    sequence: 0x0102_0304_0506_0708,
                },
            ),
            (
                published_ref(&repository, name),
                b"pr\0a\0refs/heads/main".to_vec(),
                ParsedKey::PublishedRef {
                    repo: repository.clone(),
                    name: name.into(),
                },
            ),
            (
                published_index(&repository, name),
                b"py\0a\0refs/heads/main".to_vec(),
                ParsedKey::PublishedIndex {
                    repo: repository.clone(),
                    name: name.into(),
                },
            ),
            (
                published_member(&repository, &[0x11; 32]),
                [b"pm\0a\0".as_slice(), &[0x11; 32]].concat(),
                ParsedKey::PublishedMember {
                    repo: repository.clone(),
                    pack_id: [0x11; 32],
                },
            ),
        ];
        for (key, golden, parsed) in cases {
            assert_eq!(key.as_bytes(), golden);
            assert_eq!(parse(&key), Some(parsed));
        }
        for bad in [
            advance(&repository, name, 0).into_bytes().to_vec(),
            [b"av\0a\0refs/heads/main\0".as_slice(), &[1; 7]].concat(),
            [b"av\0a\0refs/heads/main\0".as_slice(), &[1; 9]].concat(),
            b"pr\0a\0not-a-ref".to_vec(),
            [b"pm\0a\0".as_slice(), &[1; 31]].concat(),
            [b"pm\0a\0".as_slice(), &[1; 33]].concat(),
        ] {
            assert_eq!(parse(&Key::new(bad)), None);
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)] // One golden per key family, merged from two WPs.
    fn layouts_golden_bytes() {
        let s = [0x11; 32];
        let q = format!("root\n{}", "ab".repeat(32));
        let cases: Vec<(Key, Vec<u8>)> = vec![
            (sharding_marker(), b"sm\0".to_vec()),
            (addressing_marker(), b"am\0".to_vec()),
            (layout_version(), b"v\0".to_vec()),
            (relay_scan(), b"rs\0".to_vec()),
            (
                relay_high_water(&Partition::ContentShard(7)).unwrap(),
                b"rh\0s7\0".to_vec(),
            ),
            (namespace_record(), b"nr\0".to_vec()),
            (repo_record(&repo("room-a")), b"rr\0room-a".to_vec()),
            (repo_visibility(&repo("room-a")), b"rv\0room-a".to_vec()),
            (repo_known(&repo("room-a")), b"rk\0room-a".to_vec()),
            (
                verification(&repo("room-a"), &s),
                [&b"vs\0room-a\0"[..], &[0x11; 32]].concat(),
            ),
            (
                ref_key(&repo("room-a"), "refs/heads/main"),
                b"r\0room-a\0refs/heads/main".to_vec(),
            ),
            (
                ref_index_key(&repo("room-a"), "refs/heads/main"),
                b"x\0room-a\0refs/heads/main".to_vec(),
            ),
            (replay(&s), [&b"p\0"[..], &[0x11; 32]].concat()),
            (
                replay_expiry(0x0102_0304_0506_0708, &s),
                [&b"px\0"[..], &[1, 2, 3, 4, 5, 6, 7, 8], &[0x11; 32]].concat(),
            ),
            (quota(&scope()), [b"q\0", q.as_bytes()].concat()),
            (
                quota_window(256, &scope()),
                [&b"qx\0"[..], &[0, 0, 0, 0, 0, 0, 1, 0], q.as_bytes()].concat(),
            ),
            (grant_epoch(), b"e\0".to_vec()),
            (epoch_lease(), b"el\0".to_vec()),
            (lease_recovery(), b"lr\0".to_vec()),
            (lease_reconcile(), b"lrc\0".to_vec()),
            (backup_state(), b"bk\0".to_vec()),
            (
                leased_shard(&repo("a"), "refs/heads/main"),
                b"ls\0a\0refs/heads/main".to_vec(),
            ),
            (
                timer(1, 7, b"refs/heads/x"),
                [&b"w\0"[..], &[0, 0, 0, 0, 0, 0, 0, 1, 7], b"refs/heads/x"].concat(),
            ),
            (
                holder(&s, &NamespaceKey::deployment_default(), &repo("a")).unwrap(),
                [&b"h\0"[..], &[0x11; 32], b"root\0a"].concat(),
            ),
            (
                hold(&s, &[0x22; 32]),
                [&b"g\0"[..], &[0x11; 32], &[0x22; 32]].concat(),
            ),
            (block(&s), [&b"b\0"[..], &[0x11; 32]].concat()),
            (object_state(&s), [&b"c\0"[..], &[0x11; 32]].concat()),
            (
                object_index(&repo("a"), &s, &[0x22; 32]),
                [&b"i\0a\0"[..], &[0x11; 32], &[0x22; 32]].concat(),
            ),
        ];
        for (key, golden) in cases {
            assert_eq!(key.as_bytes(), golden.as_slice());
        }
        let (a, s2) = (repo("a"), [0x22; 32]);
        for (key, golden, sub, id) in [
            (
                verify_job(&a, &s),
                [&b"vc\0a\0"[..], &s, &[0]].concat(),
                VC_JOB,
                None,
            ),
            (
                verify_row(&a, &s, VC_FRAME, Some(&s2)),
                [&b"vc\0a\0"[..], &s, &[1], &s2].concat(),
                VC_FRAME,
                Some(s2),
            ),
            (
                verify_row(&a, &s, VC_CANDIDATE, Some(&s2)),
                [&b"vc\0a\0"[..], &s, &[4], &s2].concat(),
                VC_CANDIDATE,
                Some(s2),
            ),
            (
                verify_row(&a, &s, VC_DEPENDENCY, Some(&s2)),
                [&b"vc\0a\0"[..], &s, &[6], &s2].concat(),
                VC_DEPENDENCY,
                Some(s2),
            ),
        ] {
            assert_eq!(key.as_bytes(), golden.as_slice());
            assert_eq!(
                parse(&key),
                Some(ParsedKey::VerifyCursor {
                    repo: a.clone(),
                    pack_id: s,
                    sub,
                    id,
                })
            );
        }
        let (start, end) = verify_range(&a, &s, None);
        for sub in [VC_JOB, VC_FRAME, VC_BASE, VC_DEPENDENCY] {
            let row = verify_row(&a, &s, sub, (sub != VC_JOB).then_some(&s2));
            assert!(start <= row && row < end);
        }
        let (start, end) = verify_range(&a, &s, Some(VC_CHILD));
        assert!(
            !(start <= verify_row(&a, &s, VC_FRAME, Some(&s2))
                && verify_row(&a, &s, VC_FRAME, Some(&s2)) < end)
        );
        assert!(start <= verify_row(&a, &s, VC_CHILD, Some(&s2)));
        let other = verify_job(&a, &s2);
        assert!(!(verify_range(&a, &s, None).0 <= other && other < verify_range(&a, &s, None).1));
        for bad in [
            [&b"vc\0a\0"[..], &s, &[0], &s2].concat(),
            [&b"vc\0a\0"[..], &s, &[1]].concat(),
            [&b"vc\0a\0"[..], &s, &[7], &s2].concat(),
        ] {
            assert_eq!(parse(&Key::new(bad)), None);
        }
        assert_eq!(LAYOUT_VERSION, 1);
        assert!(!RESERVED_TAGS.contains(&TAG_VERIFY_CURSOR));
        assert!(!RESERVED_TAGS.contains(&TAG_OBJECT_INDEX));
        assert!(!RESERVED_TAGS.contains(&TAG_VERIFICATION));
        let state = verification(&repo("a"), &s);
        assert_eq!(
            parse(&state),
            Some(ParsedKey::Verification {
                repo: repo("a"),
                pack_id: s,
            })
        );
        let index = object_index(&repo("a"), &s, &[0x22; 32]);
        assert_eq!(
            parse(&index),
            Some(ParsedKey::ObjectIndex {
                repo: repo("a"),
                object: s,
                pack_id: [0x22; 32],
            })
        );
        let (start, end) = object_index_range(&repo("a"), &s);
        assert!(start <= index && index < end);
        assert_eq!(
            parse(&Key::new([&b"i\0a\0"[..], &[0x11; 63]].concat())),
            None
        );
        // Enumeration classes: their scan ranges remain pinned.
        for (tag, start, end) in [
            (TAG_REPO_REGISTRY, &b"rr\0"[..], &b"rr\x01"[..]),
            (TAG_NAMESPACE_LIST, b"nl\0", b"nl\x01"),
        ] {
            let (s, e) = class_range(tag);
            assert_eq!((s.as_bytes(), e.as_bytes()), (start, end));
        }
    }

    #[test]
    fn ticket_outbox_layouts_golden_and_roundtrip() {
        let r = repo("a");
        let name = "refs/heads/main";
        let pack = [0x11; 32];
        let signer = [0x22; 32];
        let seq = 0x0102_0304_0506_0708;
        let cases = vec![
            (
                ticket(&pack),
                [&b"t\0"[..], &pack].concat(),
                ParsedKey::Ticket(pack),
            ),
            (
                ticket_index(&r, name, &pack, &signer).unwrap(),
                [&b"ti\0a\0refs/heads/main\0"[..], &pack, &signer].concat(),
                ParsedKey::TicketIndex {
                    repo: r.clone(),
                    name: name.into(),
                    pack_id: pack,
                    signer,
                },
            ),
            (
                tickets_per_ref(&r, name).unwrap(),
                b"tc\0a\0refs/heads/main".to_vec(),
                ParsedKey::TicketsPerRef {
                    repo: r.clone(),
                    name: name.into(),
                },
            ),
            (
                tickets_per_signer(&r, name, &signer).unwrap(),
                [&b"tu\0a\0refs/heads/main\0"[..], &signer].concat(),
                ParsedKey::TicketsPerSigner {
                    repo: r.clone(),
                    name: name.into(),
                    signer,
                },
            ),
            (
                membership(&r, &pack),
                [&b"m\0a\0"[..], &pack].concat(),
                ParsedKey::Membership {
                    repo: r,
                    pack_id: pack,
                },
            ),
            (
                reservation("R-1:ok").unwrap(),
                b"o\0R-1:ok".to_vec(),
                ParsedKey::Reservation("R-1:ok".into()),
            ),
            (
                outcome_pending(seq, "R-1:ok").unwrap(),
                [&b"oq\0"[..], &[1, 2, 3, 4, 5, 6, 7, 8], b"R-1:ok"].concat(),
                ParsedKey::OutcomePending {
                    seq,
                    reservation_id: "R-1:ok".into(),
                },
            ),
            (
                relay(seq),
                [&b"or\0"[..], &[1, 2, 3, 4, 5, 6, 7, 8]].concat(),
                ParsedKey::Relay(seq),
            ),
            (relay_scan(), b"rs\0".to_vec(), ParsedKey::RelayScan),
            (
                outbox_sequence(),
                b"os\0".to_vec(),
                ParsedKey::OutboxSequence,
            ),
            (
                outcome_backlog(),
                b"oc\0".to_vec(),
                ParsedKey::OutcomeBacklog,
            ),
            (
                timer(seq, 2, &pack),
                [&b"w\0"[..], &[1, 2, 3, 4, 5, 6, 7, 8, 2], &pack].concat(),
                ParsedKey::Timer {
                    due_at_ms: seq,
                    kind: 2,
                    reference: Bytes::copy_from_slice(&pack),
                },
            ),
        ];
        for (key, golden, parsed) in cases {
            assert_eq!(key.as_bytes(), golden);
            assert_eq!(parse(&key), Some(parsed));
        }
        assert_eq!(parse(&Key::new(b"rs\0extra".to_vec())), None);
        let (start, end) = class_range(TAG_RELAY_SCAN);
        assert_eq!(
            (start.as_bytes(), end.as_bytes()),
            (&b"rs\0"[..], &b"rs\x01"[..])
        );
    }

    #[test]
    fn ticket_outbox_key_validation_and_maximum() {
        let r = repo(&"a".repeat(MAX_REPO_NAME_BYTES));
        let name = format!(
            "refs/heads/{}",
            "b".repeat(MAX_REF_NAME_BYTES - "refs/heads/".len())
        );
        let longest = ticket_index(&r, &name, &[0; 32], &[0; 32]).unwrap();
        assert_eq!(
            longest.as_bytes().len(),
            3 + MAX_REPO_NAME_BYTES + 1 + MAX_REF_NAME_BYTES + 1 + 64
        );
        assert!(longest.as_bytes().len() <= MAX_KEY_BYTES);
        assert!(parse(&longest).is_some());
        for rid in ["", "bad/rid", "space id", "nonascii-é", &"a".repeat(129)] {
            assert!(!validate_reservation_id(rid));
            assert!(reservation(rid).is_err());
            assert!(outcome_pending(1, rid).is_err());
        }
        assert!(reservation(&"a".repeat(128)).is_ok());
        assert!(outcome_pending(0, "ok").is_err());
        for name in ["", "bad", "refs/heads/a\0b", &format!("{name}x")] {
            assert!(ticket_index(&r, name, &[0; 32], &[0; 32]).is_err());
            assert!(tickets_per_ref(&r, name).is_err());
            assert!(tickets_per_signer(&r, name, &[0; 32]).is_err());
        }
        for bad in [
            &b"t\0short"[..],
            b"ti\0a\0refs/heads/a\0short",
            b"tc\0a\0bad",
            b"tu\0a\0refs/heads/a\0short",
            b"m\0a\0short",
            b"o\0bad/id",
            b"oq\0short",
            b"or\0short",
            b"os\0extra",
            b"oc\0extra",
        ] {
            assert_eq!(parse(&Key::new(bad.to_vec())), None);
        }
        assert_eq!(parse(&Key::new(vec![b'x'; MAX_KEY_BYTES + 1])), None);
    }

    #[test]
    fn backup_state_parse_roundtrip_and_malformed_suffix() {
        assert_eq!(parse(&backup_state()), Some(ParsedKey::BackupState));
        assert_eq!(parse(&Key::new(b"bk\0x".to_vec())), None);
    }

    #[test]
    fn class_scans_never_overlap() {
        let tags = all_tags();
        for (i, a) in tags.iter().enumerate() {
            assert!(!tags[i + 1..].contains(a), "duplicate tag {a}");
            let (start, end) = class_range(a);
            for b in &tags {
                for tail in [&b""[..], b"\0", b"\xff\xff", b"x\0y"] {
                    let k = Key::new([b.as_bytes(), b"\0", tail].concat());
                    assert_eq!(start <= k && k < end, a == b, "{a} range vs {b} key");
                }
            }
        }
    }

    #[test]
    fn ref_index_prefix_is_exact() {
        let first = repo("one");
        let (start, end) = ref_index_prefix_range(&first, "refs/heads/feat/");
        assert!(
            start <= ref_index_key(&first, "refs/heads/feat/topic")
                && ref_index_key(&first, "refs/heads/feat/topic") < end
        );
        assert!(
            !(start <= ref_index_key(&first, "refs/heads/featx")
                && ref_index_key(&first, "refs/heads/featx") < end)
        );
        assert!(
            !(start <= ref_index_key(&repo("two"), "refs/heads/feat/topic")
                && ref_index_key(&repo("two"), "refs/heads/feat/topic") < end)
        );
    }

    proptest! {
        #[test]
        fn ref_index_prefix_bounds_and_repo_isolation(
            prefix in "[a-z/.-]{0,6}",
            name in "[a-z/.-]{0,10}",
        ) {
            let r = repo("repo");
            let (start, end) = ref_index_prefix_range(&r, &prefix);
            let key = ref_index_key(&r, &name);
            prop_assert_eq!(start <= key && key < end, name.starts_with(&prefix));
            let foreign = ref_index_key(&repo("repo2"), &name);
            prop_assert!(!(start <= foreign && foreign < end));
            prop_assert_eq!(parse(&key), Some(ParsedKey::RefIndexEntry { repo: r, name }));
        }

        #[test]
        fn ref_prefix_scan_bounds_cover_exactly_the_prefix(
            prefix in "[a-z/.-]{0,6}",
            name in "[a-z/.-]{0,10}",
            other in "[a-z]{1,3}",
        ) {
            let r = repo("repo");
            let (start, end) = ref_prefix_range(&r, &prefix);
            let k = ref_key(&r, &name);
            prop_assert_eq!(start <= k && k < end, name.starts_with(&prefix));
            // No other repo's refs, and no other class, fall in the range.
            let foreign = ref_key(&repo(&format!("repo{other}")), &name);
            prop_assert!(!(start <= foreign && foreign < end));
            prop_assert!(!(start <= replay(&[0; 32]) && replay(&[0; 32]) < end));
        }

        #[test]
        fn be64_orders_numerically(a: u64, b: u64) {
            let s = [0xff; 32];
            prop_assert_eq!(replay_expiry(a, &s).cmp(&replay_expiry(b, &s)), a.cmp(&b));
            let (start, end) = replay_expiry_before(b);
            let k = replay_expiry(a, &s);
            prop_assert_eq!(start <= k && k < end, a < b);
            let (start, end) = quota_window_before(b);
            let k = quota_window(a, &scope());
            prop_assert_eq!(start <= k && k < end, a < b);
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)] // Exhaustive fixture includes both fence checkpoint kinds.
    fn parse_roundtrip_every_class() {
        let s = [0x22; 32];
        let q = scope();
        let cases = vec![
            (layout_version(), ParsedKey::LayoutVersion),
            (
                ref_key(&repo("a"), "refs/tags/v1"),
                ParsedKey::Ref {
                    repo: repo("a"),
                    name: "refs/tags/v1".into(),
                },
            ),
            (replay(&s), ParsedKey::Replay(s)),
            (
                replay_expiry(9, &s),
                ParsedKey::ReplayExpiry {
                    expires_at_ms: 9,
                    scope: s,
                },
            ),
            (quota(&q), ParsedKey::Quota(q.as_str().into())),
            (
                quota_window(5, &q),
                ParsedKey::QuotaWindow {
                    window_start_ms: 5,
                    scope: q.as_str().into(),
                },
            ),
            (grant_epoch(), ParsedKey::GrantEpoch),
            (epoch_lease(), ParsedKey::EpochLease),
            (lease_recovery(), ParsedKey::LeaseRecovery),
            (revoke_cursor(false), ParsedKey::FenceCursor(0)),
            (revoke_cursor(true), ParsedKey::FenceCursor(1)),
            (lease_reconcile(), ParsedKey::LeaseReconcile),
            (
                leased_shard(&repo("a"), "refs/heads/main"),
                ParsedKey::LeasedShard {
                    repo: repo("a"),
                    shard_ref: "refs/heads/main".into(),
                },
            ),
            (sharding_marker(), ParsedKey::ShardingMarker),
            (addressing_marker(), ParsedKey::AddressingMarker),
            (namespace_record(), ParsedKey::NamespaceRecord),
            (repo_record(&repo("a")), ParsedKey::RepoRecord(repo("a"))),
            (repo_known(&repo("a")), ParsedKey::RepoKnown(repo("a"))),
            (
                timer(3, 2, b"r"),
                ParsedKey::Timer {
                    due_at_ms: 3,
                    kind: 2,
                    reference: Bytes::from_static(b"r"),
                },
            ),
            (
                holder(&s, &NamespaceKey::deployment_default(), &repo("a")).unwrap(),
                ParsedKey::Holder {
                    object: s,
                    ns: NamespaceKey::deployment_default(),
                    repo: repo("a"),
                },
            ),
            (
                hold(&s, &[3; 32]),
                ParsedKey::Hold {
                    object: s,
                    hold_id: [3; 32],
                },
            ),
            (block(&s), ParsedKey::Block(s)),
            (object_state(&s), ParsedKey::ObjectState(s)),
        ];
        for (key, parsed) in cases {
            assert_eq!(parse(&key), Some(parsed));
        }
        assert_eq!(quota_for_window(&quota_window(5, &q)), Some(quota(&q)));
        assert_eq!(quota_for_window(&quota(&q)), None);
        for bad in [
            &b"p\0short"[..],
            b"v\0x",
            b"px\0\0",
            b"no-terminator",
            b"c\0short",
            b"g\0short",
            b"nr\0extra",
            b"rr\0",
            b"rk\0bad name",
        ] {
            assert_eq!(parse(&Key::new(bad.to_vec())), None);
        }
        // An object's holder and hold ranges hold exactly its rows.
        let other = [0x23; 32];
        let (start, end) = holders_of(&s);
        let own = holder(&s, &NamespaceKey::deployment_default(), &repo("z")).unwrap();
        let foreign = holder(&other, &NamespaceKey::deployment_default(), &repo("a")).unwrap();
        assert!(start <= own && own < end && !(start <= foreign && foreign < end));
        let (start, end) = holds_of(&s);
        assert!(start <= hold(&s, &[0xff; 32]) && hold(&s, &[0xff; 32]) < end);
        assert!(!(start <= hold(&other, &[0; 32]) && hold(&other, &[0; 32]) < end));
        let nul = NamespaceKey::from_stored("a\0b".into());
        assert!(matches!(
            holder(&s, &nul, &repo("a")),
            Err(StoreError::Invalid(_))
        ));
    }

    #[test]
    fn object_index_parse_roundtrip() {
        let object = [0x22; 32];
        let pack_id = [3; 32];
        let key = object_index(&repo("a"), &object, &pack_id);
        assert_eq!(
            parse(&key),
            Some(ParsedKey::ObjectIndex {
                repo: repo("a"),
                object,
                pack_id,
            })
        );
    }
    #[test]
    fn repo_visibility_key_roundtrips() {
        let key = repo_visibility(&repo("room-a"));
        assert_eq!(key.as_bytes(), b"rv\0room-a");
        assert_eq!(parse(&key), Some(ParsedKey::RepoVisibility(repo("room-a"))));
        assert_eq!(parse(&Key::new(b"rv\0"[..].to_vec())), None);
    }

    #[test]
    fn lease_keys_reject_malformed_payloads() {
        for bad in [
            &b"el\0extra"[..],
            b"lr\0extra",
            b"ls\0no-separator",
            b"ls\0\0refs/heads/main",
        ] {
            assert_eq!(parse(&Key::new(bad.to_vec())), None);
        }
    }

    #[test]
    fn namespace_quota_key_goldens_and_ranges() {
        let window: u64 = 0x0102_0304_0506_0708;
        let suffix = window.to_be_bytes();
        assert_eq!(
            quota_shard(window).as_bytes(),
            [&b"qs\0"[..], &suffix].concat()
        );
        assert_eq!(
            quota_view(window).as_bytes(),
            [&b"qv\0"[..], &suffix].concat()
        );
        assert_eq!(
            quota_total(window).as_bytes(),
            [&b"qt\0"[..], &suffix].concat()
        );
        let source = Partition::Ref {
            ns: NamespaceKey::deployment_default(),
            repo: repo("room"),
            shard_ref: "refs/heads/main".into(),
        };
        let contribution = quota_contribution(window, &source).unwrap();
        let next = quota_contribution(window + 1, &source).unwrap();
        assert_eq!(
            contribution.as_bytes(),
            [&b"qc\0"[..], &suffix, &source.encode().unwrap()].concat()
        );
        assert_eq!(
            parse(&contribution),
            Some(ParsedKey::QuotaContribution { window, source })
        );
        assert_eq!(
            parse(&quota_shard(window)),
            Some(ParsedKey::QuotaShard(window))
        );
        assert_eq!(
            parse(&quota_view(window)),
            Some(ParsedKey::QuotaView(window))
        );
        assert_eq!(
            parse(&quota_total(window)),
            Some(ParsedKey::QuotaTotal(window))
        );
        let (start, end) = quota_namespace_window(TAG_QUOTA_CONTRIBUTION, window);
        assert!(start <= contribution && contribution < end);
        assert!(!(start <= next && next < end));
        assert!(matches!(
            quota_contribution(
                window,
                &Partition::Coordinator(NamespaceKey::deployment_default())
            ),
            Err(StoreError::Invalid(_))
        ));
    }
}
