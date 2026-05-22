//! mkit-core — BLAKE3 hashing and canonical v1 object byte format.
//!
//! The byte layout implemented here is defined, normatively, in
//! `docs/SPEC-OBJECTS.md` (version `0x01`, magic `"MKT1"`). Any change
//! to this crate MUST update the spec in the same PR.
//!
//! The library depends on `std` to keep the code readable. No `serde`,
//! no `anyhow`, no panics on unchecked input.

// `deny(unsafe_code)` rather than `forbid` so a single, justified
// `#[allow(unsafe_code)]` callsite can use `libc::geteuid()` in
// `sign::load_key` for the POSIX uid check. Every other module
// remains under the same prohibition; a code-review gate (CONTRIBUTING)
// requires SAFETY notes on any new `unsafe` block.
#![deny(unsafe_code)]
// `ed25519-dalek` v2.2 still pulls in older sha2/cpufeatures (and
// rand_core 0.6 which transitively wants getrandom 0.2). These are
// transitive duplicates we cannot dedupe without forking dalek; allow
// them. cargo-deny still tracks them at warn level via deny.toml.
#![allow(clippy::multiple_crate_versions)]

pub mod chunker;
pub mod delta;
pub mod hash;
pub mod object;
pub mod ops;
pub mod pack;
// Erasure-coded pack delivery (Reed-Solomon). Feature-gated because
// the dep stack (`commonware-coding` + `commonware-cryptography` +
// `commonware-parallel` + `commonware-storage`) is large and only
// needed by the shard-aware transports — see
// `docs/SPEC-PACK-SHARDS.md`. Sibling of `pack`, not nested: the
// on-disk pack format stays untouched; shards are a wire-level
// encoding *of* a pack.
#[cfg(feature = "pack-shards")]
pub mod pack_shard;
pub mod serialize;
pub mod sign;
pub mod store;

// Phase 4 — refs + index + worktree + ignore + repo_lock.
pub(crate) mod atomic;
pub mod ignore;
pub mod index;
pub mod refs;
pub mod repo_lock;
pub mod worktree;

// Phase 7a — transport trait surface (vtable + SSH framing + retry policy).
pub mod protocol;

// Phase 1 of issue #157 — append-only MMR over the commit chain for
// O(log n) inclusion proofs. Feature-gated so the `commonware-storage`
// dep tree only materialises for downstream callers that opt in.
// Persisted (journaled) MMR + commit-field integration are Phase 2/3
// — see docs/SPEC-HISTORY-PROOF.md.
#[cfg(feature = "history-mmr")]
pub mod history;

// Verifiable sparse-checkout (issue #158, Phase 2). Feature-gated
// because the upstream `commonware-storage::AuthenticatedBitMap` is
// ALPHA-tier and pulls in `commonware-runtime` /
// `commonware-cryptography`. Off by default.
#[cfg(feature = "sparse-checkout")]
pub mod sparse;

#[cfg(feature = "sparse-checkout")]
pub use sparse::{
    MAX_FILTER_PATHS as SPARSE_MAX_FILTER_PATHS, MAX_LEAVES as SPARSE_MAX_LEAVES, SPARSE_CACHE_DIR,
    SPARSE_CACHE_MAGIC, SPARSE_CACHE_VERSION, SPARSE_WIRE_MAGIC, SPARSE_WIRE_MAX_BYTES,
    SPARSE_WIRE_VERSION, SparseError, SparseManifest, SparseProof, SparseResponse, SparseWireError,
    build_sparse, decode_sparse_cache, decode_sparse_response, encode_sparse_cache,
    encode_sparse_response, hash_filter, verify_sparse,
};

pub use hash::{HASH_LEN, HEX_LEN, Hash, Hasher, to_hex, to_hex_bytes};
pub use object::{
    Blob, ChunkedBlob, Commit, Delta, EntryMode, IDENTITY_MAX_LEN, Identity, IdentityKind, MAGIC,
    MkitError, Object, ObjectType, Remix, RemixSource, SCHEMA_VERSION, Tree, TreeEntry,
};
pub use serialize::{deserialize, serialize};
pub use sign::{
    COMMIT_DOMAIN, KeyPair, PublicKey, REMIX_DOMAIN, SecretSeed, Signature, commit_signing_bytes,
    commit_signing_hash, remix_signing_bytes, remix_signing_hash, sign_commit, sign_remix, verify,
    verify_commit, verify_remix,
};
pub use store::{MAX_RAW_OBJECT_SIZE, MKIT_DIR, OBJECTS_DIR, ObjectStore, StoreError, StoreResult};

// Phase 3 — content-defined chunker (FastCDC v1).
pub use chunker::{
    AVG_SIZE as CHUNK_AVG_SIZE, ChunkBoundary, ChunkIterator, FastCdc, MASK_L as CHUNK_MASK_L,
    MASK_S as CHUNK_MASK_S, MAX_SIZE as CHUNK_MAX_SIZE, MIN_SIZE as CHUNK_MIN_SIZE,
    SEED as CHUNK_SEED, chunk_boundaries, gear_table_digest,
};

// Phase 3 — delta instruction stream (SPEC-DELTA v1).
pub use delta::{HEADER_LEN as DELTA_HEADER_LEN, MAX_INSERT_LEN, OP_COPY, STREAM_VERSION};

// Phase 3 — packfile reader/writer (SPEC-PACKFILE v1).
pub use pack::{
    HEADER_LEN as PACK_HEADER_LEN, MAGIC as PACK_MAGIC, MAX_ENTRIES as PACK_MAX_ENTRIES,
    MAX_TOTAL_PAYLOAD as PACK_MAX_TOTAL_PAYLOAD, PackError, PackReader, PackWriter,
    TRAILER_LEN as PACK_TRAILER_LEN, UnpackReport, VERSION as PACK_VERSION, pack_key,
};

// Phase 4 — refs + index + worktree + ignore + repo_lock.
pub use ignore::{IgnoreError, IgnoreList, MAX_IGNORE_FILE_BYTES, Pattern, glob_match};
pub use index::{
    EntryStatus, INDEX_FILE, Index, IndexEntry, IndexError, IndexResult, MAGIC as INDEX_MAGIC,
    MAX_INDEX_BYTES, MAX_PATH_LEN, validate_index_path,
};
pub use refs::{
    HEAD_FILE, HEADS_DIR, Head, REFS_DIR, Ref, RefError, RefResult, RefWriteCondition,
    SHALLOW_FILE, TAGS_DIR, decode_ref_wire, encode_ref_wire, validate_ref_name,
    validate_ref_prefix,
};
pub use repo_lock::{DEFAULT_TIMEOUT as LOCK_DEFAULT_TIMEOUT, LockError, LockResult, RepoLock};
pub use worktree::{
    CHUNK_THRESHOLD, MAX_FILE_BYTES, WorktreeError, WorktreeResult, validate_symlink_target,
};

// Cross-transport types. The SSH-specific wire bytes live in
// mkit-rpc's ssh.proto and are consumed by mkit-transport-ssh
// directly.
pub use protocol::{
    BACKOFF_CAP, BACKOFF_INITIAL, BACKOFF_MAX_ATTEMPTS, BackoffIterator, PackKey, Transport,
    TransportError, TransportResult, is_retryable, pack_key_from_hex,
};

// Phase 5 — ops re-exports (OPS1: diff/graph/merge/cherry_pick).
// OPS2's rebase/bisect/blame/stash/restore are accessed via
// `mkit_core::ops::{rebase, bisect, ...}` directly rather than re-exported
// at the crate root — the submodule is typically the right import scope
// for state-machine APIs.
pub use ops::{
    CherryPickError, CherryPickResult, Conflict, ConflictKind, DiffEntry, DiffError, DiffKind,
    DiffResult, MergeResult, StatusEntry, StatusStaging, cherry_pick, collect_ancestor_set,
    diff_trees, find_merge_base, is_ancestor, merge_trees, status_diff,
};
