#![doc = include_str!("../README.md")]
//!
//! In-memory [`Transport`] implementation for tests and fuzz harnesses.
//!
//! A `HashMap`-backed store that holds pack bytes and refs entirely in
//! RAM. The 7-verb [`Transport`] trait does not include attestation
//! methods; those live in `mkit-attest`.
//!
//! ## CAS guarantees
//!
//! | Variant          | Guarantee                                             |
//! |------------------|-------------------------------------------------------|
//! | `Any`            | Unconditional clobber. Lock-free inside the Mutex.    |
//! | `Missing`        | Fails with [`TransportError::RefConflict`] if the ref |
//! |                  | already exists. Atomic w.r.t. concurrent callers      |
//! |                  | sharing the same [`MemoryTransport`] instance because  |
//! |                  | the whole `HashMap` is held under `Mutex` for the read- |
//! |                  | then-write. No TOCTOU for in-process users.           |
//! | `Match(H)`       | Fails with [`TransportError::RefConflict`] if the ref |
//! |                  | is absent or has a different value. Same Mutex-based  |
//! |                  | atomicity guarantee as `Missing`.                     |
//!
//! The `Mutex` makes all three variants safe for concurrent in-process
//! callers. Cross-process atomicity is not required (and not provided)
//! because `MemoryTransport` is test-only.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::Mutex;

use mkit_core::hash::Hash;
use mkit_core::protocol::{PackKey, RefWriteCondition, Transport, TransportError, TransportResult};
use mkit_core::refs::{
    Ref, decode_ref_wire, encode_ref_wire, validate_ref_name, validate_ref_prefix,
};

/// In-memory transport backed by two `HashMap`s guarded by a single
/// `Mutex`. Safe to share across threads; designed for tests.
///
/// Packs are keyed by [`PackKey`] (the BLAKE3 digest of the pack
/// bytes). Refs are keyed by their full ref name (e.g.
/// `"refs/heads/main"`) and stored in the 65-byte wire form.
#[derive(Debug, Default)]
pub struct MemoryTransport {
    inner: Mutex<Inner>,
}

#[derive(Debug, Default)]
struct Inner {
    /// Content-addressed pack store: digest → raw bytes.
    packs: HashMap<PackKey, Vec<u8>>,
    /// Ref store: full ref name → 65-byte wire (`[64-hex]\n`).
    refs: HashMap<String, [u8; 65]>,
}

impl MemoryTransport {
    /// Create a new, empty [`MemoryTransport`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of packs currently stored.
    ///
    /// # Panics
    ///
    /// Panics if the internal `Mutex` is poisoned (another thread
    /// panicked while holding the lock).
    #[must_use]
    pub fn pack_count(&self) -> usize {
        self.inner
            .lock()
            .expect("MemoryTransport mutex poisoned")
            .packs
            .len()
    }

    /// Number of refs currently stored.
    ///
    /// # Panics
    ///
    /// Panics if the internal `Mutex` is poisoned.
    #[must_use]
    pub fn ref_count(&self) -> usize {
        self.inner
            .lock()
            .expect("MemoryTransport mutex poisoned")
            .refs
            .len()
    }
}

impl Transport for MemoryTransport {
    // ------------------------------------------------------------------
    // Pack verbs
    // ------------------------------------------------------------------

    /// Insert or overwrite a pack. The caller is responsible for
    /// providing a [`PackKey`] that matches `BLAKE3(bytes)`; this
    /// implementation does **not** re-hash to verify, trusting the
    /// caller's digest for performance.
    fn upload_pack(&self, bytes: &[u8], key: &PackKey) -> TransportResult<()> {
        let mut g = self.inner.lock().expect("MemoryTransport mutex poisoned");
        g.packs.insert(*key, bytes.to_vec());
        Ok(())
    }

    fn download_pack(&self, key: &PackKey) -> TransportResult<Vec<u8>> {
        let g = self.inner.lock().expect("MemoryTransport mutex poisoned");
        g.packs
            .get(key)
            .cloned()
            .ok_or(TransportError::PackNotFound)
    }

    fn pack_exists(&self, key: &PackKey) -> TransportResult<bool> {
        let g = self.inner.lock().expect("MemoryTransport mutex poisoned");
        Ok(g.packs.contains_key(key))
    }

    // ------------------------------------------------------------------
    // Ref verbs
    // ------------------------------------------------------------------

    fn update_ref(
        &self,
        name: &str,
        condition: RefWriteCondition,
        hash: &Hash,
    ) -> TransportResult<()> {
        if !validate_ref_name(name) {
            return Err(TransportError::InvalidRef(name.to_owned()));
        }

        let mut g = self.inner.lock().expect("MemoryTransport mutex poisoned");

        // Read current value (under the lock — no TOCTOU).
        let current: Option<Hash> = g.refs.get(name).and_then(|wire| decode_ref_wire(wire));

        match condition {
            RefWriteCondition::Any => {}
            RefWriteCondition::Missing => {
                if current.is_some() {
                    return Err(TransportError::RefConflict);
                }
            }
            RefWriteCondition::Match(expected) => match current {
                Some(c) if c == expected => {}
                _ => return Err(TransportError::RefConflict),
            },
        }

        g.refs.insert(name.to_owned(), encode_ref_wire(hash));
        Ok(())
    }

    fn read_ref(&self, name: &str) -> TransportResult<Option<Hash>> {
        if !validate_ref_name(name) {
            return Err(TransportError::InvalidRef(name.to_owned()));
        }
        let g = self.inner.lock().expect("MemoryTransport mutex poisoned");
        Ok(g.refs.get(name).and_then(|wire| decode_ref_wire(wire)))
    }

    fn list_refs(&self, prefix: &str) -> TransportResult<Vec<Ref>> {
        if !validate_ref_prefix(prefix) {
            return Err(TransportError::InvalidRef(prefix.to_owned()));
        }

        // Normalise: strip trailing slash so we can do a clean prefix
        // match and suffix extraction.
        let prefix_trimmed = prefix.trim_end_matches('/');

        let g = self.inner.lock().expect("MemoryTransport mutex poisoned");

        let mut out: Vec<Ref> = g
            .refs
            .iter()
            .filter_map(|(full_name, wire)| {
                // The ref name must start with the (trimmed) prefix.
                let rest = if prefix_trimmed.is_empty() {
                    full_name.as_str()
                } else if let Some(after) = full_name.strip_prefix(prefix_trimmed) {
                    // Skip the separator slash between prefix and suffix.
                    after.strip_prefix('/').unwrap_or(after)
                } else {
                    return None;
                };

                // The remaining suffix must itself be a valid ref name
                // segment (guards against `refs/heads` matching
                // `refs/headsfoo`).
                if !validate_ref_name(rest) {
                    return None;
                }

                let hash = decode_ref_wire(wire)?;
                Some(Ref {
                    name: rest.to_owned(),
                    hash: Some(hash),
                })
            })
            .collect();

        // Sort deterministically by name.
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use mkit_core::hash::hash as blake3_hash;
    use mkit_core::protocol::RefWriteCondition;

    // Helper: build a PackKey from hashing a byte slice.
    fn pack_key(data: &[u8]) -> PackKey {
        PackKey::from(blake3_hash(data))
    }

    // ------------------------------------------------------------------
    // Pack verb tests (5 tests)
    // ------------------------------------------------------------------

    #[test]
    fn upload_and_download_pack() {
        let t = MemoryTransport::new();
        let data = b"pack file content here";
        let key = pack_key(data);
        t.upload_pack(data, &key).unwrap();
        let got = t.download_pack(&key).unwrap();
        assert_eq!(got, data);
    }

    #[test]
    fn download_missing_pack_returns_not_found() {
        let t = MemoryTransport::new();
        let key = pack_key(b"nonexistent");
        let err = t.download_pack(&key).unwrap_err();
        assert!(matches!(err, TransportError::PackNotFound));
    }

    #[test]
    fn pack_exists_true_after_upload() {
        let t = MemoryTransport::new();
        let data = b"some pack bytes";
        let key = pack_key(data);
        assert!(!t.pack_exists(&key).unwrap());
        t.upload_pack(data, &key).unwrap();
        assert!(t.pack_exists(&key).unwrap());
    }

    #[test]
    fn pack_exists_false_for_unknown_key() {
        let t = MemoryTransport::new();
        let key = PackKey::new([0u8; 32]);
        assert!(!t.pack_exists(&key).unwrap());
    }

    #[test]
    fn upload_pack_overwrites_existing_entry() {
        let t = MemoryTransport::new();
        let key = PackKey::new([0xABu8; 32]);
        t.upload_pack(b"first", &key).unwrap();
        t.upload_pack(b"second", &key).unwrap();
        assert_eq!(t.download_pack(&key).unwrap(), b"second");
    }

    // ------------------------------------------------------------------
    // Ref verb tests (10 tests)
    // ------------------------------------------------------------------

    #[test]
    fn write_and_read_ref() {
        let t = MemoryTransport::new();
        let h = blake3_hash(b"commit-abc");
        t.write_ref("refs/heads/main", &h).unwrap();
        let read = t.read_ref("refs/heads/main").unwrap();
        assert_eq!(read, Some(h));
    }

    #[test]
    fn read_missing_ref_returns_none() {
        let t = MemoryTransport::new();
        let result = t.read_ref("refs/heads/nonexistent").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn write_ref_overwrites_previous() {
        let t = MemoryTransport::new();
        let h1 = blake3_hash(b"commit-1");
        let h2 = blake3_hash(b"commit-2");
        t.write_ref("refs/heads/main", &h1).unwrap();
        t.write_ref("refs/heads/main", &h2).unwrap();
        assert_eq!(t.read_ref("refs/heads/main").unwrap(), Some(h2));
    }

    #[test]
    fn update_ref_match_success() {
        let t = MemoryTransport::new();
        let h_old = blake3_hash(b"old");
        let h_new = blake3_hash(b"new");
        t.write_ref("refs/heads/main", &h_old).unwrap();
        t.update_ref("refs/heads/main", RefWriteCondition::Match(h_old), &h_new)
            .unwrap();
        assert_eq!(t.read_ref("refs/heads/main").unwrap(), Some(h_new));
    }

    #[test]
    fn update_ref_match_stale_returns_conflict() {
        let t = MemoryTransport::new();
        let h_current = blake3_hash(b"current");
        let h_stale = blake3_hash(b"stale");
        let h_next = blake3_hash(b"next");
        t.write_ref("refs/heads/main", &h_current).unwrap();
        let err = t
            .update_ref(
                "refs/heads/main",
                RefWriteCondition::Match(h_stale),
                &h_next,
            )
            .unwrap_err();
        assert!(matches!(err, TransportError::RefConflict));
        // Ref unchanged.
        assert_eq!(t.read_ref("refs/heads/main").unwrap(), Some(h_current));
    }

    #[test]
    fn update_ref_match_missing_ref_returns_conflict() {
        let t = MemoryTransport::new();
        let h = blake3_hash(b"h");
        let err = t
            .update_ref("refs/heads/main", RefWriteCondition::Match(h), &h)
            .unwrap_err();
        assert!(matches!(err, TransportError::RefConflict));
    }

    #[test]
    fn update_ref_missing_creates_when_absent() {
        let t = MemoryTransport::new();
        let h = blake3_hash(b"initial");
        t.update_ref("refs/heads/main", RefWriteCondition::Missing, &h)
            .unwrap();
        assert_eq!(t.read_ref("refs/heads/main").unwrap(), Some(h));
    }

    #[test]
    fn update_ref_missing_fails_when_present() {
        let t = MemoryTransport::new();
        let h = blake3_hash(b"initial");
        t.update_ref("refs/heads/main", RefWriteCondition::Missing, &h)
            .unwrap();
        let err = t
            .update_ref("refs/heads/main", RefWriteCondition::Missing, &h)
            .unwrap_err();
        assert!(matches!(err, TransportError::RefConflict));
    }

    #[test]
    fn read_ref_with_invalid_name_returns_error() {
        let t = MemoryTransport::new();
        let err = t.read_ref("").unwrap_err();
        assert!(matches!(err, TransportError::InvalidRef(_)));
        let err2 = t.read_ref("/leading-slash").unwrap_err();
        assert!(matches!(err2, TransportError::InvalidRef(_)));
    }

    #[test]
    fn update_ref_with_invalid_name_returns_error() {
        let t = MemoryTransport::new();
        let h = blake3_hash(b"h");
        let err = t.update_ref("", RefWriteCondition::Any, &h).unwrap_err();
        assert!(matches!(err, TransportError::InvalidRef(_)));
    }

    // ------------------------------------------------------------------
    // list_refs tests (5 tests)
    // ------------------------------------------------------------------

    #[test]
    fn list_refs_with_prefix_returns_suffix_only() {
        let t = MemoryTransport::new();
        let h1 = blake3_hash(b"main-commit");
        let h2 = blake3_hash(b"dev-commit");
        let h3 = blake3_hash(b"tag-v1");
        t.write_ref("refs/heads/main", &h1).unwrap();
        t.write_ref("refs/heads/dev", &h2).unwrap();
        t.write_ref("refs/tags/v1", &h3).unwrap();

        let heads = t.list_refs("refs/heads/").unwrap();
        assert_eq!(heads.len(), 2);
        // Sorted alphabetically.
        assert_eq!(heads[0].name, "dev");
        assert_eq!(heads[0].hash, Some(h2));
        assert_eq!(heads[1].name, "main");
        assert_eq!(heads[1].hash, Some(h1));

        let tags = t.list_refs("refs/tags/").unwrap();
        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0].name, "v1");
        assert_eq!(tags[0].hash, Some(h3));
    }

    #[test]
    fn list_refs_empty_prefix_returns_all() {
        let t = MemoryTransport::new();
        t.write_ref("refs/heads/main", &blake3_hash(b"m")).unwrap();
        t.write_ref("refs/tags/v1", &blake3_hash(b"t")).unwrap();
        let all = t.list_refs("").unwrap();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn list_refs_returns_empty_when_none_match() {
        let t = MemoryTransport::new();
        t.write_ref("refs/heads/main", &blake3_hash(b"m")).unwrap();
        let tags = t.list_refs("refs/tags/").unwrap();
        assert!(tags.is_empty());
    }

    #[test]
    fn list_refs_sorted_alphabetically() {
        let t = MemoryTransport::new();
        t.write_ref("refs/heads/zebra", &blake3_hash(b"z")).unwrap();
        t.write_ref("refs/heads/alpha", &blake3_hash(b"a")).unwrap();
        t.write_ref("refs/heads/middle", &blake3_hash(b"m"))
            .unwrap();
        let refs = t.list_refs("refs/heads/").unwrap();
        assert_eq!(refs.len(), 3);
        assert_eq!(refs[0].name, "alpha");
        assert_eq!(refs[1].name, "middle");
        assert_eq!(refs[2].name, "zebra");
    }

    #[test]
    fn list_refs_invalid_prefix_returns_error() {
        let t = MemoryTransport::new();
        // A single "/" is an invalid prefix per validate_ref_prefix.
        let err = t.list_refs("/").unwrap_err();
        assert!(matches!(err, TransportError::InvalidRef(_)));
    }

    // ------------------------------------------------------------------
    // Full-interface integration test (1 test, exercises every verb)
    // ------------------------------------------------------------------

    // ------------------------------------------------------------------
    // pack_count / ref_count accessors
    // ------------------------------------------------------------------

    #[test]
    fn count_helpers_reflect_state() {
        let t = MemoryTransport::new();
        assert_eq!(t.pack_count(), 0);
        assert_eq!(t.ref_count(), 0);

        let key = PackKey::new([0x01u8; 32]);
        t.upload_pack(b"x", &key).unwrap();
        assert_eq!(t.pack_count(), 1);

        t.write_ref("refs/heads/main", &blake3_hash(b"h")).unwrap();
        assert_eq!(t.ref_count(), 1);
    }
}
