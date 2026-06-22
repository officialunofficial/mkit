//! Append-only commit-history Merkle Mountain Range (MMR).
//!
//! Issue #157. Light-client inclusion proofs for the commit chain: a
//! verifier with the MMR root for a branch tip can check "commit X was
//! leaf N on this branch" with `O(log n)` hash work, without
//! downloading the parent chain or any pack.
//!
//! # Status
//!
//! - **In-memory** (shipped, [`CommitHistory::open`]): `mem`-backed
//!   MMR. Lost on process exit. Useful for tests and
//!   short-lived computations where the proof is the only output.
//! - **On-disk journaled** (this build, [`CommitHistory::open_at`]):
//!   journaled MMR backed by
//!   [`commonware_storage::merkle::mmr::full::Mmr`] pinned to
//!   `=2026.5.0`. The on-disk layout is commonware's native two-store
//!   shape — a fixed-item journal of node digests plus a metadata
//!   sidecar for pruned pinned nodes — laid out under
//!   `<mkit_dir>/history/<sanitized_branch>/`. See
//!   `docs/SPEC-HISTORY-PROOF.md` §4.
//! - **Commit-field integration** (planned, v0.2): `Commit.history_root`
//!   proto field, new signing-bytes layout. Out of scope here.
//!
//! # Hashing
//!
//! The underlying primitive is `commonware-storage`'s journaled MMR
//! parameterised over BLAKE3 (from `commonware-cryptography`). Node
//! digests are 32-byte BLAKE3 values — same primitive mkit already
//! uses elsewhere ([`crate::hash::Hash`]). The schedule is **not** the
//! same as [`crate::hash::hash`]: commonware injects each node's
//! position into the parent/leaf digest. Treat the digests as opaque
//! beyond comparison.
//!
//! # Sync / async bridge
//!
//! commonware's journaled MMR is async over a `commonware-runtime`
//! `Context`. The mkit-core public surface ([`CommitHistory::append`],
//! [`CommitHistory::root`], [`CommitHistory::prove`]) is synchronous
//! by design — it is called from the synchronous `refs::update_ref`
//! path and from CLI helpers that have no async-runtime context.
//!
//! The bridge is the [`crate::protocol::async_shim::Executor`] trait
//! hoisted in PR #167. [`CommitHistory`] is generic over an executor
//! `X: Executor`; every sync method drives its async counterpart via
//! `executor.block_on(...)`. The executor is held by [`Arc`] for the
//! lifetime of the [`CommitHistory`] value so multiple `append` /
//! `prove` calls share a single runtime.
//!
//! # Executor / Context ownership
//!
//! [`CommitHistory::open_at`] takes an [`Arc`]-shared executor from
//! the caller. The commonware `Context` needed to drive the
//! journaled MMR is bootstrapped *internally* via a one-shot
//! [`commonware_runtime::tokio::Runner::start`] on a fresh OS thread
//! (the standard workaround documented in transport-enc):
//! the runner returns a Context clone, the outer `Arc<Executor>` inside
//! the Context keeps tokio's runtime alive, and the bootstrap thread
//! joins immediately. Subsequent async ops are driven through the
//! caller-supplied executor.
//!
//! This means production callers only need to construct an executor
//! ([`crate::history::tokio_executor::TokioExecutor`] is provided when
//! the `history-mmr` feature is on); mkit-core handles the
//! commonware-side wiring. The trade-off: every [`CommitHistory`]
//! owns one tokio runtime (via its executor) AND one commonware
//! Context with its own inner tokio runtime. The two never need to
//! interact — `tokio::fs` and `tokio::sync::Mutex` are runtime-agnostic
//! and work whichever runtime is driving the poll.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use commonware_cryptography::{Blake3, Hasher as CHasher};
use commonware_parallel::Sequential;
use commonware_runtime::{Runner as _, Supervisor as _, buffer::paged::CacheRef};
use commonware_storage::merkle::Bagging;
use commonware_storage::merkle::mmr::{
    Location as MmrLocation, Proof as MmrProof, StandardHasher,
    full::{Config as JConfig, Mmr as JournaledMmr},
    mem::Mmr as MemMmr,
};
use commonware_utils::{NZU16, NZU64, NZUsize};

use crate::hash::{HASH_LEN, Hash};
use crate::protocol::async_shim::Executor;
use crate::refs::validate_ref_name;

pub mod tokio_executor;

/// Re-export of the bundled tokio-runtime executor.
pub use tokio_executor::TokioExecutor;

/// Peak-bagging policy for the commit-history MMR.
///
/// This is a **load-bearing cryptographic parameter**: the producer
/// ([`CommitHistory::root`] / [`CommitHistory::prove`]) and the verifier
/// ([`verify_inclusion`]) must fold MMR peaks into a root identically, or
/// every inclusion proof silently fails to verify. Pinning it here — and
/// consuming it only via [`history_hasher`] — makes that agreement
/// un-desyncable across all call sites and both code paths.
///
/// `ForwardFold` is also a **back-compat** choice: it reproduces the root
/// that the pre-2026.5 commonware default produced byte-for-byte, so MMR
/// journals written by an older mkit build and roots already stored in the
/// reflog stay valid across the commonware bump. Do **not** change this
/// without an on-disk format-version bump and a migration.
const HISTORY_BAGGING: Bagging = Bagging::ForwardFold;

/// The canonical hasher for the commit-history MMR — the single source of
/// truth for [`HISTORY_BAGGING`], so the producer and verifier sides can
/// never drift on the bagging policy.
fn history_hasher() -> StandardHasher<Blake3> {
    StandardHasher::new(HISTORY_BAGGING)
}

// ---------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------

/// 0-based index of a commit within its branch's MMR.
///
/// In commonware's vocabulary this is a `Location` — the leaf index in
/// insertion order, not the MMR's internal node position. The first
/// commit appended is `Position(0)`, the second is `Position(1)`, etc.
/// Stable for the lifetime of the branch: positions never shift
/// because the MMR is append-only.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Position(pub u64);

impl Position {
    /// Raw `u64`.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

/// Inclusion proof — re-export of commonware's MMR proof type bound to
/// our BLAKE3 digest. Wire shape is normatively defined in
/// `SPEC-HISTORY-PROOF.md` §2.
pub type InclusionProof = MmrProof<<Blake3 as CHasher>::Digest>;

/// Errors returned by [`CommitHistory`] and [`verify_inclusion`].
#[derive(Debug, thiserror::Error)]
pub enum HistoryError {
    /// The underlying MMR rejected the operation (out-of-bounds proof,
    /// invalid size, etc.). The wrapped string is commonware's own
    /// `Display` impl — stable enough for logs, not parsed.
    #[error("mmr error: {0}")]
    Mmr(String),
    /// The branch name failed [`crate::refs::validate_ref_name`].
    #[error("invalid branch name for history journal: {0:?}")]
    InvalidBranch(String),
    /// On-disk journal could not be opened or recovered. commonware's
    /// own `init` performs roll-forward recovery on a half-written
    /// trailing leaf (see `commonware_storage::merkle::mmr::full`
    /// docs); this variant surfaces failures it cannot recover from.
    #[error("history journal is corrupt: {0}")]
    Corrupted(String),
    /// Failed to bootstrap the commonware tokio Context.
    #[error("failed to bootstrap commonware runtime: {0}")]
    RuntimeBootstrap(String),
    /// Failed to set up the on-disk history directory.
    #[error("history directory I/O: {0}")]
    Io(#[from] std::io::Error),
}

// ---------------------------------------------------------------------
// On-disk layout
// ---------------------------------------------------------------------

/// Subdirectory of `<mkit_dir>` that holds per-branch MMR journals.
///
/// commonware lays its journaled-MMR partitions out as a pair of
/// suffix-discriminated directories below this root:
///
/// ```text
/// <mkit_dir>/history/<sanitized_branch>__journal-blobs/     # node-digest journal blobs
/// <mkit_dir>/history/<sanitized_branch>__journal-metadata/  # journal segment table
/// <mkit_dir>/history/<sanitized_branch>__metadata/          # pruned-pinned-node sidecar
/// ```
///
/// The `-blobs` / `-metadata` segment suffixes are appended by
/// commonware-storage; mkit names the leading partition tokens
/// (`<sanitized_branch>__journal` and `<sanitized_branch>__metadata`)
/// and hands them to `journaled::Mmr::init` via [`JConfig`].
///
/// commonware partition names are restricted to `[A-Za-z0-9_-]+`, so
/// branch names go through `sanitize_branch` — a `_xx`-hex encoding
/// of every byte outside `[A-Za-z0-9-]`. Empty branches and invalid
/// ref names are rejected up front by [`CommitHistory::open_at`].
pub const HISTORY_DIR: &str = "history";

/// Suffix appended to the branch's partition name for the node-digest
/// journal.
pub const JOURNAL_PARTITION_SUFFIX: &str = "__journal";

/// Suffix appended to the branch's partition name for the
/// pruned-pinned-node metadata sidecar.
pub const METADATA_PARTITION_SUFFIX: &str = "__metadata";

// ---------------------------------------------------------------------
// CommitHistory
// ---------------------------------------------------------------------

/// Append-only Merkle history of commit hashes for one branch.
///
/// Two construction modes:
///
/// 1. [`CommitHistory::open`] — purely in-memory. Useful for tests
///    and for callers that don't want any disk side-effects. Lost on
///    drop.
/// 2. [`CommitHistory::open_at`] — on-disk journaled MMR under
///    `<mkit_dir>/history/<branch>/`. Survives process exit.
///
/// Each call to a sync method (`append`, `root`, `prove`) on the
/// journaled flavour drives an async operation on the underlying
/// `commonware-storage::journaled::Mmr` via the caller-supplied
/// [`Executor`].
pub struct CommitHistory<X: Executor = TokioExecutor> {
    backend: Backend<X>,
    hasher: StandardHasher<Blake3>,
}

/// Internal backend selector. The mem variant is the in-memory shape;
/// the journaled variant is the on-disk one.
///
/// `Journaled` is boxed because its inner state (commonware's
/// `Journaled` plus a `Context` clone) is ~2.2 KiB and would otherwise
/// pad every mem-flavour `CommitHistory` by the same amount.
enum Backend<X: Executor> {
    Mem {
        mmr: MemMmr<<Blake3 as CHasher>::Digest>,
    },
    Journaled(Box<JournaledBackend<X>>),
}

struct JournaledBackend<X: Executor> {
    // Order matters for Drop: `mmr` must drop before `_ctx` so
    // any pending async-resource shutdowns can still poll on the
    // surviving tokio runtime. In practice commonware's
    // `Journaled` only flushes synchronously in `sync`, but the
    // ordering is cheap insurance.
    mmr: JournaledMmr<commonware_runtime::tokio::Context, <Blake3 as CHasher>::Digest, Sequential>,
    executor: Arc<X>,
    // Held to keep the bootstrap tokio runtime (inside the Context's
    // executor `Arc`) alive for the whole CommitHistory lifetime.
    _ctx: commonware_runtime::tokio::Context,
    // Held so update_ref_with_history can take a fresh RepoLock for
    // every append. None for the mem-only flavour.
    mkit_dir: PathBuf,
    branch: String,
}

impl<X: Executor> core::fmt::Debug for CommitHistory<X> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match &self.backend {
            Backend::Mem { mmr } => f
                .debug_struct("CommitHistory::Mem")
                .field("leaves", &u64::from(mmr.leaves()))
                .field("size", &u64::from(mmr.size()))
                .finish_non_exhaustive(),
            Backend::Journaled(b) => f
                .debug_struct("CommitHistory::Journaled")
                .field("branch", &b.branch)
                .field("leaves", &u64::from(b.mmr.leaves()))
                .field("size", &u64::from(b.mmr.size()))
                .finish_non_exhaustive(),
        }
    }
}

impl CommitHistory<TokioExecutor> {
    /// Open a fresh empty in-memory history (mem-backed shape).
    ///
    /// Lost on drop. Useful for unit tests and for callers that just
    /// need a proof bundle without committing any state to disk.
    #[must_use]
    pub fn open() -> Self {
        let hasher = history_hasher();
        let mmr = MemMmr::new();
        Self {
            backend: Backend::Mem { mmr },
            hasher,
        }
    }
}

impl<X: Executor + 'static> CommitHistory<X> {
    /// Open a persisted history under `<mkit_dir>/history/<branch>/`.
    ///
    /// The on-disk layout is commonware-storage's native journaled MMR
    /// shape — see [`HISTORY_DIR`] and SPEC-HISTORY-PROOF §4. If the
    /// underlying journal does not yet exist, it is created empty
    /// (subsequent [`CommitHistory::append`] calls populate it).
    ///
    /// Crash recovery is delegated to commonware: its `Journaled::init`
    /// detects a half-written trailing leaf, rewinds the journal to
    /// the last valid size, and re-derives the in-memory state. See
    /// SPEC-HISTORY-PROOF §4.4 for the contract surfaced to mkit
    /// callers.
    ///
    /// # Errors
    ///
    /// - [`HistoryError::InvalidBranch`] — `branch` failed
    ///   [`validate_ref_name`].
    /// - [`HistoryError::RuntimeBootstrap`] — could not start the
    ///   commonware tokio Runner used to construct the underlying
    ///   storage Context.
    /// - [`HistoryError::Corrupted`] — commonware refused to recover
    ///   the journal (a deeper-than-trailing-leaf corruption).
    /// - [`HistoryError::Io`] — failed to create the history dir.
    pub fn open_at(executor: Arc<X>, mkit_dir: &Path, branch: &str) -> Result<Self, HistoryError> {
        if !validate_ref_name(branch) {
            return Err(HistoryError::InvalidBranch(branch.to_string()));
        }

        let history_dir = mkit_dir.join(HISTORY_DIR);
        std::fs::create_dir_all(&history_dir)?;

        // Bootstrap a commonware tokio Context rooted at
        // `<mkit_dir>/history`. The Context survives the bootstrap
        // runner's drop because its inner `Arc<Executor>` (the
        // commonware Executor, not ours) holds the tokio runtime alive.
        let ctx = bootstrap_commonware_context(&history_dir)?;

        let sanitized = sanitize_branch(branch);
        let journal_partition = format!("{sanitized}{JOURNAL_PARTITION_SUFFIX}");
        let metadata_partition = format!("{sanitized}{METADATA_PARTITION_SUFFIX}");
        let cfg = JConfig {
            journal_partition,
            metadata_partition,
            // 4096 items/blob → 128 KiB blobs (32 B digest × 4096). Big
            // enough that small branches stay in one blob; small enough
            // that pruning later doesn't carry stale data around.
            items_per_blob: NZU64!(4096),
            write_buffer: NZUsize!(4096),
            strategy: Sequential,
            page_cache: CacheRef::from_pooler(&ctx, NZU16!(4096), NZUsize!(8)),
        };

        let hasher = history_hasher();
        let mmr = {
            let hasher_inner = history_hasher();
            // `child` returns an owned child Context, leaving `ctx` usable for
            // the surviving CommitHistory (which keeps the bootstrap runtime
            // alive via its inner executor Arc).
            let ctx_for_init = ctx.child("mmr_init");
            executor
                .block_on(async move {
                    JournaledMmr::<_, <Blake3 as CHasher>::Digest, Sequential>::init(
                        ctx_for_init,
                        &hasher_inner,
                        cfg,
                    )
                    .await
                })
                .map_err(|e| HistoryError::Corrupted(e.to_string()))?
        };

        Ok(Self {
            backend: Backend::Journaled(Box::new(JournaledBackend {
                mmr,
                executor,
                _ctx: ctx,
                mkit_dir: mkit_dir.to_path_buf(),
                branch: branch.to_string(),
            })),
            hasher,
        })
    }

    /// Borrow the `mkit_dir` this history was opened against. `None`
    /// for the mem-only flavour. Used by
    /// [`crate::refs::update_ref_with_history`] to take a `RepoLock`
    /// around the ref-write + MMR-append critical section.
    #[must_use]
    pub fn mkit_dir(&self) -> Option<&Path> {
        match &self.backend {
            Backend::Mem { .. } => None,
            Backend::Journaled(b) => Some(b.mkit_dir.as_path()),
        }
    }

    /// Borrow the branch name this history was opened against. `None`
    /// for the mem-only flavour.
    #[must_use]
    pub fn branch(&self) -> Option<&str> {
        match &self.backend {
            Backend::Mem { .. } => None,
            Backend::Journaled(b) => Some(b.branch.as_str()),
        }
    }

    /// Append a commit hash. Returns its leaf [`Position`].
    ///
    /// Positions are dense: the *n*-th append returns `Position(n)`.
    /// For the journaled flavour, the underlying MMR is `sync`'d to
    /// disk before returning — survives a `SIGKILL` immediately after.
    pub fn append(&mut self, commit_hash: &Hash) -> Result<Position, HistoryError> {
        let leaf = digest_from_hash(commit_hash);
        match &mut self.backend {
            Backend::Mem { mmr } => {
                let leaf_loc = mmr.leaves();
                let batch = mmr
                    .new_batch()
                    .add(&self.hasher, &leaf)
                    .merkleize(mmr, &self.hasher);
                mmr.apply_batch(&batch)
                    .map_err(|e| HistoryError::Mmr(e.to_string()))?;
                Ok(Position(u64::from(leaf_loc)))
            }
            Backend::Journaled(b) => {
                let leaf_loc = b.mmr.leaves();
                let batch = b.mmr.new_batch().add(&self.hasher, &leaf);
                let batch = b.mmr.with_mem(|mem| batch.merkleize(mem, &self.hasher));
                b.mmr
                    .apply_batch(&batch)
                    .map_err(|e| HistoryError::Mmr(e.to_string()))?;
                // Flush to disk synchronously so a SIGKILL between
                // append and the caller's next ref-write does not lose
                // the leaf we just promised to persist.
                let sync_fut = b.mmr.sync();
                b.executor
                    .block_on(sync_fut)
                    .map_err(|e| HistoryError::Mmr(e.to_string()))?;
                Ok(Position(u64::from(leaf_loc)))
            }
        }
    }

    /// Current MMR root digest. 32-byte BLAKE3 (mkit `Hash` shape).
    ///
    /// Defined for an empty history — commonware returns a
    /// deterministic empty-MMR root (see SPEC-HISTORY-PROOF §2.3).
    ///
    /// # Panics
    ///
    /// Never panics in practice. Internally calls commonware's
    /// `root(&hasher, 0)`, which only returns an error for a non-zero
    /// inactive-peak count; mkit always requests `0` inactive peaks
    /// (its proofs are self-contained over the full leaf set), so the
    /// `Result` is always `Ok`.
    #[must_use]
    pub fn root(&self) -> Hash {
        // `root` takes the hasher + an `inactive_peaks` count (0 for a
        // self-contained MMR over the full leaf set) and returns an owned
        // `Digest`. Both backends are sync here (Journaled reads its
        // in-memory cache); 0 inactive peaks is always a valid request,
        // so the `Result` is always `Ok` — see the `# Panics` note above.
        let digest = match &self.backend {
            Backend::Mem { mmr } => mmr.root(&self.hasher, 0),
            Backend::Journaled(b) => b.mmr.root(&self.hasher, 0),
        }
        .expect("0 inactive peaks is always a valid root request");
        let mut out = [0u8; HASH_LEN];
        out.copy_from_slice(digest.as_ref());
        out
    }

    /// Number of leaves (commits) appended so far.
    #[must_use]
    pub fn len(&self) -> u64 {
        match &self.backend {
            Backend::Mem { mmr } => u64::from(mmr.leaves()),
            Backend::Journaled(b) => u64::from(b.mmr.leaves()),
        }
    }

    /// `true` if no commits have been appended.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Build an inclusion proof for the commit at `position`.
    pub fn prove(&self, position: Position) -> Result<InclusionProof, HistoryError> {
        let loc = MmrLocation::new(position.0);
        match &self.backend {
            Backend::Mem { mmr } => mmr
                .proof(&self.hasher, loc, 0)
                .map_err(|e| HistoryError::Mmr(e.to_string())),
            Backend::Journaled(b) => {
                let hasher = self.hasher.clone();
                let proof_fut = b.mmr.proof(&hasher, loc, 0);
                // Drive the async proof builder via the executor. The
                // future borrows `mmr` immutably for the duration of
                // `block_on`; the borrow ends when `block_on` returns.
                b.executor
                    .block_on(proof_fut)
                    .map_err(|e| HistoryError::Mmr(e.to_string()))
            }
        }
    }
}

impl Default for CommitHistory<TokioExecutor> {
    fn default() -> Self {
        Self::open()
    }
}

/// Verify that `commit_hash` was appended at `position` to a history
/// whose current root is `root`. Returns `true` on a passing proof,
/// `false` on any tamper / wrong-position / wrong-root case.
///
/// Pure function: no allocation beyond what commonware's verifier does
/// internally; safe to call from a light-client without any of the
/// preceding chain bytes.
#[must_use]
pub fn verify_inclusion(
    commit_hash: &Hash,
    position: Position,
    proof: &InclusionProof,
    root: &Hash,
) -> bool {
    let leaf = digest_from_hash(commit_hash);
    let root_digest = digest_from_hash(root);
    let loc = MmrLocation::new(position.0);

    // Same bagging policy as the producer — see [`HISTORY_BAGGING`].
    let hasher = history_hasher();
    proof.verify_element_inclusion(&hasher, leaf.as_ref(), loc, &root_digest)
}

// ---------------------------------------------------------------------
// v0.1.x → v0.2.x rebuild shim
// ---------------------------------------------------------------------

/// Rebuild a branch's history MMR from its on-disk parent chain.
///
/// For repos created against an older mkit (v0.1.x, before this
/// module persisted anything to disk) the `<mkit_dir>/history/<branch>/`
/// directory is empty on first open, but the branch's commit chain is
/// already on disk in the object store. This helper walks the
/// first-parent chain from `tip` to root, then re-appends each commit
/// (in oldest-first order) into the supplied empty [`CommitHistory`].
///
/// The walker is supplied by the caller as `parent_of`: given a
/// commit hash, it returns `Ok(Some(parent_hash))` if there is a
/// parent, `Ok(None)` for the root commit, and `Err(_)` for any
/// lookup failure. This keeps `mkit-core::history` free of an
/// `ObjectStore` dependency — the rebuild shim is a tool the caller
/// (typically `mkit-cli`) drives.
///
/// # Errors
///
/// - Propagates any error from `parent_of`.
/// - Propagates any [`HistoryError`] from `history.append`.
pub fn rebuild_from_chain<X, F, E>(
    history: &mut CommitHistory<X>,
    tip: Hash,
    mut parent_of: F,
) -> Result<u64, RebuildError<E>>
where
    X: Executor + 'static,
    F: FnMut(&Hash) -> Result<Option<Hash>, E>,
    E: core::fmt::Display,
{
    let mut chain = Vec::new();
    let mut cursor = Some(tip);
    while let Some(h) = cursor {
        chain.push(h);
        cursor = parent_of(&h).map_err(RebuildError::Walker)?;
    }
    // Walker yielded tip..root; we need root..tip for the append order.
    chain.reverse();
    let count = chain.len() as u64;
    for h in &chain {
        history.append(h).map_err(RebuildError::History)?;
    }
    Ok(count)
}

/// Errors returned by [`rebuild_from_chain`].
#[derive(Debug, thiserror::Error)]
pub enum RebuildError<E: core::fmt::Display> {
    /// The caller-supplied parent-walker failed. The wrapped `E`
    /// carries the walker's error verbatim, so callers that pass a
    /// structured error type get it back unchanged.
    #[error("parent-chain walker failed: {0}")]
    Walker(E),
    /// The underlying [`CommitHistory::append`] failed.
    #[error(transparent)]
    History(HistoryError),
}

// ---------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------

/// Convert an mkit `Hash` (`[u8; 32]`) into commonware's `Blake3::Digest`.
fn digest_from_hash(h: &Hash) -> <Blake3 as CHasher>::Digest {
    <<Blake3 as CHasher>::Digest as From<[u8; HASH_LEN]>>::from(*h)
}

/// Hex-escape a mkit branch name into a commonware-partition-safe
/// token.
///
/// commonware partition names are restricted to `[A-Za-z0-9_-]+`. mkit
/// ref names can contain `.` and `/` (and `_`, which IS allowed
/// upstream but which we must escape too to keep this encoding
/// injective). Every non-`[A-Za-z0-9-]` byte is encoded as `_xx`
/// where `xx` is the lowercase-hex byte value; `_` itself encodes as
/// `_5f`. This makes the encoding self-delimiting — every `_` in the
/// output is the lead-in of a two-hex-digit escape, never a literal.
///
/// Examples:
///   `main`        → `main`
///   `feat/v1.0`   → `feat_2fv1_2e0`
///   `feat_v1_0`   → `feat_5fv1_5f0`
///
/// The encoding is injective: different valid branch names always
/// sanitize to different partition tokens, so the journaled MMRs of
/// two branches in the same repo never share commonware partitions.
fn sanitize_branch(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for &b in name.as_bytes() {
        let allowed = b.is_ascii_alphanumeric() || b == b'-';
        if allowed {
            out.push(b as char);
        } else {
            use core::fmt::Write as _;
            let _ = write!(&mut out, "_{b:02x}");
        }
    }
    out
}

/// Bootstrap a commonware tokio `Context` whose `storage_directory`
/// is the supplied path.
///
/// The bootstrap is done on a fresh OS thread because tokio refuses to
/// nest `runtime::Builder::build()` inside an already-active runtime
/// (the `TokioExecutor`'s runtime is already alive in the caller's
/// thread). The returned Context's inner `Arc<Executor>` keeps the
/// bootstrap runtime alive after the bootstrap thread joins.
///
/// See `docs/SPEC-HISTORY-PROOF.md` §4.1 for the design rationale and
/// the trade-off with the alternative "share the caller's tokio
/// runtime" approach.
fn bootstrap_commonware_context(
    storage_directory: &Path,
) -> Result<commonware_runtime::tokio::Context, HistoryError> {
    let dir = storage_directory.to_path_buf();
    std::thread::spawn(move || {
        let cfg = commonware_runtime::tokio::Config::new().with_storage_directory(dir);
        let runner = commonware_runtime::tokio::Runner::new(cfg);
        // Return an owned, labelled child Context. `Context::clone` and
        // `Metrics::with_label` were both removed in 2026.5.0;
        // `Supervisor::child` returns an owned Context that clones the
        // inner `executor: Arc<Executor>`, which keeps the tokio runtime
        // alive after the bootstrap Runner is dropped at the end of
        // `start`. The label is best-effort so any commonware metrics
        // surfaced through this Context are easy to spot in a debugger.
        runner
            .start(|ctx| async move { commonware_runtime::Supervisor::child(&ctx, "mkit_history") })
    })
    .join()
    .map_err(|_| HistoryError::RuntimeBootstrap("bootstrap thread panicked".to_string()))
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Deterministic distinct commit hash generator.
    fn synth(i: u64) -> Hash {
        crate::hash::hash(&i.to_be_bytes())
    }

    fn fresh_mkit_dir() -> (TempDir, PathBuf) {
        let tmp = TempDir::new().unwrap();
        let mkit_dir = tmp.path().join(".mkit");
        std::fs::create_dir_all(&mkit_dir).unwrap();
        (tmp, mkit_dir)
    }

    fn fresh_executor() -> Arc<TokioExecutor> {
        Arc::new(TokioExecutor::new().expect("tokio runtime"))
    }

    // ---- mem-only API (unchanged from issue #157) -----------------

    #[test]
    fn mem_empty_history_root_is_well_defined() {
        let h1 = CommitHistory::open();
        let h2 = CommitHistory::open();
        assert_eq!(h1.root(), h2.root(), "empty root must be deterministic");
        assert!(h1.is_empty());
        assert_eq!(h1.len(), 0);
    }

    #[test]
    fn mem_append_returns_dense_positions() {
        let mut h = CommitHistory::open();
        for i in 0..16u64 {
            let pos = h.append(&synth(i)).unwrap();
            assert_eq!(pos, Position(i), "positions must be dense and 0-based");
        }
        assert_eq!(h.len(), 16);
    }

    #[test]
    fn mem_prove_and_verify_position_712_of_1000() {
        let mut h = CommitHistory::open();
        let commits: Vec<Hash> = (0..1000u64).map(synth).collect();
        for c in &commits {
            h.append(c).unwrap();
        }
        assert_eq!(h.len(), 1000);

        let target = Position(712);
        let proof = h.prove(target).unwrap();
        let root = h.root();

        assert!(
            verify_inclusion(&commits[712], target, &proof, &root),
            "honest proof must verify"
        );
    }

    #[test]
    fn mem_tampered_proof_fails_verification() {
        let mut h = CommitHistory::open();
        for i in 0..256u64 {
            h.append(&synth(i)).unwrap();
        }
        let target = Position(42);
        let mut proof = h.prove(target).unwrap();
        let root = h.root();
        let commit = synth(42);

        assert!(verify_inclusion(&commit, target, &proof, &root));

        assert!(
            !proof.digests.is_empty(),
            "non-trivial proof must carry at least one sibling"
        );
        let mut bytes: [u8; HASH_LEN] = [0u8; HASH_LEN];
        bytes.copy_from_slice(proof.digests[0].as_ref());
        bytes[0] ^= 0x01;
        proof.digests[0] = <<Blake3 as CHasher>::Digest as From<[u8; HASH_LEN]>>::from(bytes);

        assert!(
            !verify_inclusion(&commit, target, &proof, &root),
            "tampered proof must fail"
        );
    }

    // ---- journaled API --------------------------------------------

    #[test]
    fn open_at_rejects_invalid_branch() {
        let (_tmp, mkit_dir) = fresh_mkit_dir();
        let exec = fresh_executor();
        let err = CommitHistory::open_at(exec, &mkit_dir, "../escape").expect_err("invalid branch");
        assert!(matches!(err, HistoryError::InvalidBranch(_)));
    }

    #[test]
    fn open_at_empty_root_matches_mem() {
        let (_tmp, mkit_dir) = fresh_mkit_dir();
        let exec = fresh_executor();
        let h_disk = CommitHistory::open_at(exec, &mkit_dir, "main").unwrap();
        let h_mem = CommitHistory::open();
        assert_eq!(
            h_disk.root(),
            h_mem.root(),
            "empty journaled root must match empty mem root"
        );
        assert!(h_disk.is_empty());
    }

    #[test]
    fn open_at_round_trip_100_commits() {
        let (_tmp, mkit_dir) = fresh_mkit_dir();
        let exec = fresh_executor();

        let commits: Vec<Hash> = (0..100u64).map(synth).collect();
        let (root_before, len_before) = {
            let mut h = CommitHistory::open_at(exec.clone(), &mkit_dir, "main").unwrap();
            for c in &commits {
                h.append(c).unwrap();
            }
            (h.root(), h.len())
        };
        // Re-open and verify the root survives.
        let h = CommitHistory::open_at(exec.clone(), &mkit_dir, "main").unwrap();
        assert_eq!(h.len(), len_before, "leaf count must survive reopen");
        assert_eq!(h.root(), root_before, "root must survive reopen");
    }

    #[test]
    fn open_at_prove_after_reopen() {
        let (_tmp, mkit_dir) = fresh_mkit_dir();
        let exec = fresh_executor();
        let commits: Vec<Hash> = (0..64u64).map(synth).collect();
        let root = {
            let mut h = CommitHistory::open_at(exec.clone(), &mkit_dir, "main").unwrap();
            for c in &commits {
                h.append(c).unwrap();
            }
            h.root()
        };
        let h = CommitHistory::open_at(exec.clone(), &mkit_dir, "main").unwrap();
        let target = Position(17);
        let proof = h.prove(target).unwrap();
        assert!(verify_inclusion(&commits[17], target, &proof, &root));
    }

    #[test]
    fn open_at_distinct_branches_have_distinct_roots() {
        let (_tmp, mkit_dir) = fresh_mkit_dir();
        let exec = fresh_executor();
        let mut main = CommitHistory::open_at(exec.clone(), &mkit_dir, "main").unwrap();
        let mut dev = CommitHistory::open_at(exec.clone(), &mkit_dir, "dev").unwrap();
        main.append(&synth(0)).unwrap();
        dev.append(&synth(1)).unwrap();
        assert_ne!(main.root(), dev.root());
    }

    #[test]
    fn open_at_branch_with_slash_is_isolated() {
        // Two branches that sanitize to different partition names
        // must not share state.
        let (_tmp, mkit_dir) = fresh_mkit_dir();
        let exec = fresh_executor();
        let mut a = CommitHistory::open_at(exec.clone(), &mkit_dir, "feat/v1").unwrap();
        let mut b = CommitHistory::open_at(exec.clone(), &mkit_dir, "feat/v2").unwrap();
        a.append(&synth(0)).unwrap();
        assert_eq!(a.len(), 1);
        assert_eq!(b.len(), 0, "sibling branch must not see appended leaf");
        b.append(&synth(1)).unwrap();
        assert_ne!(a.root(), b.root());
    }

    #[test]
    fn open_at_root_matches_live_mem_root() {
        // Executor swap test: a journaled MMR's root must equal the
        // pure-mem MMR's root computed over the same leaf sequence.
        // This proves the executor and the persistence layer are
        // opaque to MMR semantics.
        let (_tmp, mkit_dir) = fresh_mkit_dir();
        let exec = fresh_executor();
        let commits: Vec<Hash> = (0..50u64).map(synth).collect();

        let mut journaled = CommitHistory::open_at(exec, &mkit_dir, "main").unwrap();
        let mut mem = CommitHistory::open();
        for c in &commits {
            journaled.append(c).unwrap();
            mem.append(c).unwrap();
        }
        assert_eq!(
            journaled.root(),
            mem.root(),
            "journaled and mem MMRs must produce the same root for the same leaf sequence"
        );
    }

    // ---- Negative-path verification (journaled flow) -------------

    /// Mem-flavour-equivalent: appending must change the root. Same
    /// property as the deleted `root_changes_on_append` test, lifted
    /// onto the journaled flavour.
    #[test]
    fn journaled_root_changes_on_append() {
        let (_tmp, mkit_dir) = fresh_mkit_dir();
        let exec = fresh_executor();
        let mut h = CommitHistory::open_at(exec, &mkit_dir, "main").unwrap();
        let root_before = h.root();
        h.append(&synth(0)).unwrap();
        let root_after = h.root();
        assert_ne!(
            root_before, root_after,
            "appending a leaf must change the journaled MMR root"
        );
    }

    /// Mem-flavour-equivalent: an honest inclusion proof must not verify
    /// against a different commit hash than the one that was appended.
    #[test]
    fn journaled_wrong_commit_fails_verification() {
        let (_tmp, mkit_dir) = fresh_mkit_dir();
        let exec = fresh_executor();
        let mut h = CommitHistory::open_at(exec, &mkit_dir, "main").unwrap();
        let h_a = synth(0);
        let h_other = synth(99);
        h.append(&h_a).unwrap();
        let proof = h.prove(Position(0)).unwrap();
        let root = h.root();

        assert!(
            verify_inclusion(&h_a, Position(0), &proof, &root),
            "honest proof must verify with the appended commit"
        );
        assert!(
            !verify_inclusion(&h_other, Position(0), &proof, &root),
            "swapping in a different commit hash must fail verification"
        );
    }

    /// Mem-flavour-equivalent: an inclusion proof from one branch's MMR
    /// must not verify against another branch's root.
    #[test]
    fn journaled_wrong_root_fails_verification() {
        let (_tmp, mkit_dir) = fresh_mkit_dir();
        let exec = fresh_executor();

        let h_a = synth(0);
        let mut a = CommitHistory::open_at(exec.clone(), &mkit_dir, "main").unwrap();
        a.append(&h_a).unwrap();
        let proof = a.prove(Position(0)).unwrap();
        let root_a = a.root();
        assert!(
            verify_inclusion(&h_a, Position(0), &proof, &root_a),
            "sanity: honest proof verifies against its own root"
        );

        // Independent branch with different leaves — distinct root.
        let mut b = CommitHistory::open_at(exec, &mkit_dir, "dev").unwrap();
        b.append(&synth(1)).unwrap();
        b.append(&synth(2)).unwrap();
        let root_b = b.root();
        assert_ne!(root_a, root_b, "distinct branches must have distinct roots");

        assert!(
            !verify_inclusion(&h_a, Position(0), &proof, &root_b),
            "proof from one branch must not verify against another branch's root"
        );
    }

    // ---- Crash recovery (commonware-native semantics) ----------

    /// Simulate a torn write: truncate one journal blob mid-frame and
    /// verify that commonware's `Journaled::init` either rolls forward
    /// to the last valid size OR surfaces a recoverable error.
    ///
    /// SPEC-HISTORY-PROOF §4.4: mkit relies on commonware's native
    /// recovery; mkit's own contract is only that reopening a
    /// half-written journal does NOT panic and does NOT silently
    /// expose stale data.
    #[test]
    fn truncated_journal_rolls_forward_or_surfaces_corruption() {
        let (_tmp, mkit_dir) = fresh_mkit_dir();
        let exec = fresh_executor();
        let commits: Vec<Hash> = (0..32u64).map(synth).collect();

        let len_before = {
            let mut h = CommitHistory::open_at(exec.clone(), &mkit_dir, "main").unwrap();
            for c in &commits {
                h.append(c).unwrap();
            }
            h.len()
        };
        assert_eq!(len_before, 32);

        // Find the journal blob directory and chop a few bytes off
        // the tail of the largest file. The sanitized partition name
        // for branch "main" is "main" → "main__journal".
        // commonware lays out the journal partition's blobs in a
        // subdirectory named `<partition>-blobs`; the journal metadata
        // sidecar sits at `<partition>-metadata`. The truncation
        // target is whichever blob holds actual digest data.
        let journal_root = mkit_dir.join(HISTORY_DIR).join("main__journal-blobs");
        assert!(
            journal_root.exists(),
            "journal blob dir must exist after appends"
        );
        let mut largest: Option<(std::path::PathBuf, u64)> = None;
        for entry in std::fs::read_dir(&journal_root).unwrap() {
            let entry = entry.unwrap();
            let meta = entry.metadata().unwrap();
            if meta.is_file() {
                let path = entry.path();
                let len = meta.len();
                if largest.as_ref().is_none_or(|(_, l)| len > *l) {
                    largest = Some((path, len));
                }
            }
        }
        let (blob_path, blob_len) = largest.expect("at least one blob present after 32 appends");
        assert!(
            blob_len > 5,
            "blob must be large enough to truncate (got {blob_len} bytes)"
        );

        // Truncate 5 bytes off the end — fewer than a digest (32 B), so
        // commonware sees a torn frame at the tail.
        let truncated_len = blob_len - 5;
        let f = std::fs::OpenOptions::new()
            .write(true)
            .open(&blob_path)
            .unwrap();
        f.set_len(truncated_len).unwrap();
        drop(f);

        // Reopen. mkit's contract: either succeeds (rolled forward to
        // last valid size, possibly fewer leaves than before) OR
        // surfaces a `Corrupted` error. Crucially: no panic, no
        // silent-stale-root.
        let reopened = CommitHistory::open_at(exec, &mkit_dir, "main");
        match reopened {
            Ok(h) => {
                assert!(
                    h.len() <= len_before,
                    "rolled-forward leaf count must not exceed the pre-truncation count"
                );
                // The root of the rolled-forward state, if non-empty,
                // must equal the root of a freshly-built mem MMR over
                // the surviving leaves — proving roll-forward is
                // semantically consistent.
                if !h.is_empty() {
                    let n = usize::try_from(h.len()).expect("leaf count fits in usize");
                    let mut reference = CommitHistory::open();
                    for c in &commits[..n] {
                        reference.append(c).unwrap();
                    }
                    assert_eq!(
                        h.root(),
                        reference.root(),
                        "rolled-forward root must equal a clean replay of the surviving leaves"
                    );
                }
            }
            Err(HistoryError::Corrupted(_)) => {
                // Acceptable: commonware refused to recover. Surfaced
                // to the caller via the documented error variant.
            }
            Err(other) => panic!("unexpected error on truncated journal: {other:?}"),
        }
    }

    // ---- Rebuild shim --------------------------------------------

    #[test]
    fn rebuild_from_chain_matches_live_appends() {
        let (_tmp, mkit_dir_a) = fresh_mkit_dir();
        let (_tmp_b, mkit_dir_b) = fresh_mkit_dir();
        let exec = fresh_executor();

        // Build the "reference" history by live appends.
        let commits: Vec<Hash> = (0..10u64).map(synth).collect();
        let reference_root = {
            let mut h = CommitHistory::open_at(exec.clone(), &mkit_dir_a, "main").unwrap();
            for c in &commits {
                h.append(c).unwrap();
            }
            h.root()
        };

        // Simulate the v0.1.x situation: refs/heads/main has a tip
        // commit, but `<mkit_dir>/history/` is empty. The walker
        // returns each commit's parent until root.
        let mut h = CommitHistory::open_at(exec.clone(), &mkit_dir_b, "main").unwrap();
        let tip = commits[commits.len() - 1];
        let count = rebuild_from_chain::<TokioExecutor, _, std::io::Error>(&mut h, tip, |hash| {
            // Find this hash in `commits`, return the prior one or
            // None if at index 0.
            let idx = commits
                .iter()
                .position(|c| c == hash)
                .expect("walker called with unknown hash");
            if idx == 0 {
                Ok(None)
            } else {
                Ok(Some(commits[idx - 1]))
            }
        })
        .unwrap();
        assert_eq!(count, commits.len() as u64);
        assert_eq!(
            h.root(),
            reference_root,
            "rebuilt root must match live-append root"
        );
    }

    // ---- Sanitization --------------------------------------------

    #[test]
    fn sanitize_branch_round_trip_invariants() {
        // Different ref-name byte sequences must encode to different
        // partition tokens.
        assert_ne!(sanitize_branch("feat/v1.0"), sanitize_branch("feat_v1_0"));
        // Plain alpha-numeric / dash names pass through unchanged.
        assert_eq!(sanitize_branch("main"), "main");
        assert_eq!(sanitize_branch("release-2026"), "release-2026");
        // `/` escapes to `_2f`.
        assert_eq!(sanitize_branch("a/b"), "a_2fb");
        // `.` escapes to `_2e`.
        assert_eq!(sanitize_branch("v1.0"), "v1_2e0");
        // `_` itself escapes to `_5f` to keep the encoding injective.
        assert_eq!(sanitize_branch("a_b"), "a_5fb");
    }
}
