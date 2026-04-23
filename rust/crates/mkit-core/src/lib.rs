//! mkit-core — BLAKE3 hashing and canonical v1 object byte format.
//!
//! This crate is the Rust port of the Zig modules `src/hash.zig`,
//! `src/object.zig`, and `src/serialize.zig` on the `main` branch.
//!
//! The byte layout implemented here is defined, normatively, in
//! `docs/SPEC-OBJECTS.md` (version `0x01`, magic `"MKT1"`). Any change
//! to this crate MUST update the spec in the same PR.
//!
//! The library is `#![no_std]`-friendly only via `alloc`; for now we
//! depend on `std` (like the Zig original) to keep the port readable.
//! No `serde`, no `anyhow`, no panics on unchecked input.

#![forbid(unsafe_code)]

pub mod hash;
pub mod object;
pub mod serialize;
pub mod store;

pub use hash::{HASH_LEN, HEX_LEN, Hash, Hasher};
pub use object::{
    Blob, ChunkedBlob, Commit, Delta, EntryMode, IDENTITY_MAX_LEN, Identity, IdentityKind, MAGIC,
    MkitError, Object, ObjectType, Remix, RemixSource, SCHEMA_VERSION, Tree, TreeEntry,
};
pub use serialize::{deserialize, serialize};
pub use store::{MAX_RAW_OBJECT_SIZE, MKIT_DIR, OBJECTS_DIR, ObjectStore, StoreError, StoreResult};
