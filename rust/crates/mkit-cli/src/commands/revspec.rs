//! Shared revision-spec resolver (issue #227, parent #226).
//!
//! [`resolve_revision`] turns a user-supplied revision string into a
//! single object [`Hash`]. It is the keystone the diff/checkout/
//! cherry-pick/bisect commands build on so they all accept the same
//! grammar instead of each one hand-rolling a `hash::from_hex` call.
//!
//! Accepted grammar (a deliberately small subset of `git rev-parse`):
//!
//! - **Full hash** — exactly 64 hex chars (lower or upper), present in
//!   the object store.
//! - **Short hash** — a hex prefix of at least [`MIN_SHORT_HASH`] chars
//!   that unambiguously names exactly one object in the store. An
//!   ambiguous prefix (≥ 2 matches) is an error; a prefix matching none
//!   is an error.
//! - **Ref name** — a branch (`refs/heads/<name>`), a tag
//!   (`refs/tags/<name>`), or the literal `HEAD`. Branches win over
//!   tags on a name collision (matching the precedence the existing
//!   `checkout` command used).
//! - **Suffix navigation** — a `<base>` from any of the above followed
//!   by zero or more `~n` / `^` / `^n` steps walking the commit's
//!   first-parent chain. `~n` walks `n` first-parents (`~` alone == `~1`);
//!   `^` / `^n` selects the n-th parent (`^` == `^1`, 1-based). `^0` is
//!   the commit itself. `HEAD~2`, `main^`, `<hash>~1^2` all parse.
//!
//! The resolver intentionally does NOT accept pathspecs, `:/text`
//! message searches, reflog (`@{n}`) syntax, or ranges — `A..B` ranges
//! are split by the caller (`diff`) before each end reaches here.

use mkit_core::hash::{self, HEX_LEN, Hash};
use mkit_core::object::Object;
use mkit_core::refs;
use mkit_core::store::ObjectStore;
use std::path::Path;

/// Minimum length of an accepted short-hash prefix. Shorter prefixes are
/// rejected as too-ambiguous-by-construction rather than scanned, so a
/// stray 1–3 char token (e.g. a typo'd ref) fails fast.
pub const MIN_SHORT_HASH: usize = 4;

/// Errors raised while resolving a revision string.
#[derive(Debug, thiserror::Error)]
pub enum RevError {
    /// The base token matched no ref and no object.
    #[error("unknown revision '{0}'")]
    Unknown(String),
    /// A short-hash prefix matched more than one object.
    #[error("ambiguous short hash '{0}' matches multiple objects")]
    Ambiguous(String),
    /// A `~`/`^` suffix walked off the end of the commit graph.
    #[error("revision '{spec}': {detail}")]
    BadSuffix {
        /// The full spec the user supplied.
        spec: String,
        /// What specifically went wrong.
        detail: String,
    },
    /// The base resolved but the suffix navigation hit a non-commit
    /// object (a tree/blob cannot have parents).
    #[error("revision '{0}' resolves to a non-commit object; cannot walk parents")]
    NotACommit(String),
    /// Underlying ref / store failure.
    #[error("{0}")]
    Backend(String),
}

/// Resolve `spec` to a single object [`Hash`].
///
/// See the module docstring for the accepted grammar.
///
/// # Errors
/// Returns [`RevError`] when the spec is unknown, ambiguous, or the
/// suffix navigation is invalid.
pub fn resolve_revision(
    store: &ObjectStore,
    mkit_dir: &Path,
    spec: &str,
) -> Result<Hash, RevError> {
    // Split the base from any trailing `~`/`^` navigation. The base is
    // everything up to the first `~` or `^`.
    let split_at = spec.find(['~', '^']).unwrap_or(spec.len());
    let (base, suffix) = spec.split_at(split_at);
    if base.is_empty() {
        return Err(RevError::Unknown(spec.to_string()));
    }

    let mut current = resolve_base(store, mkit_dir, base)?;

    // Walk the suffix steps left-to-right.
    let mut rest = suffix;
    while !rest.is_empty() {
        let bytes = rest.as_bytes();
        match bytes[0] {
            b'~' => {
                let (n, consumed) = parse_count(&rest[1..]);
                current = walk_first_parent(store, spec, current, n)?;
                rest = &rest[1 + consumed..];
            }
            b'^' => {
                let (n, consumed) = parse_count(&rest[1..]);
                current = select_parent(store, spec, current, n)?;
                rest = &rest[1 + consumed..];
            }
            _ => {
                return Err(RevError::BadSuffix {
                    spec: spec.to_string(),
                    detail: format!("unexpected character in suffix '{rest}'"),
                });
            }
        }
    }
    Ok(current)
}

/// Resolve the base token (no `~`/`^` suffix) to a hash: ref, then
/// full/short hash.
fn resolve_base(store: &ObjectStore, mkit_dir: &Path, base: &str) -> Result<Hash, RevError> {
    // 1. HEAD.
    if base == "HEAD" {
        return match refs::resolve_head(mkit_dir) {
            Ok(Some(h)) => Ok(h),
            Ok(None) => Err(RevError::Unknown("HEAD".to_string())),
            Err(e) => Err(RevError::Backend(format!("resolve HEAD: {e}"))),
        };
    }

    // 2. Branch (refs/heads), then tag (refs/tags). `read_ref` /
    //    `read_tag` validate the name, returning `InvalidRefName` for a
    //    bad ref name — which we treat as "not a ref" and fall through
    //    to hash parsing (a bare hash is not a valid ref name anyway).
    if refs::validate_ref_name(base) {
        if let Ok(Some(h)) = refs::read_ref(mkit_dir, base) {
            return Ok(h);
        }
        if let Ok(Some(h)) = refs::read_tag(mkit_dir, base) {
            return Ok(h);
        }
    }

    // 3. Full 64-hex hash that exists in the store.
    if base.len() == HEX_LEN
        && let Ok(h) = hash::from_hex(base)
    {
        if store.contains(&h) {
            return Ok(h);
        }
        return Err(RevError::Unknown(base.to_string()));
    }

    // 4. Short hex prefix.
    if base.len() >= MIN_SHORT_HASH && base.len() < HEX_LEN && is_hex(base) {
        return resolve_short_hash(store, base);
    }

    Err(RevError::Unknown(base.to_string()))
}

/// Find the unique object whose hex starts with `prefix`. Errors on
/// zero matches ([`RevError::Unknown`]) or ≥ 2 matches
/// ([`RevError::Ambiguous`]).
fn resolve_short_hash(store: &ObjectStore, prefix: &str) -> Result<Hash, RevError> {
    let lower = prefix.to_ascii_lowercase();
    // Object layout: `objects/<2-hex>/<62-hex>`. The first two hex chars
    // (when present) name the shard directory, so we only scan one
    // shard. With a 1-char prefix (below MIN_SHORT_HASH, never reached)
    // we would have to scan 16 shards; the >= MIN_SHORT_HASH gate makes
    // the 2-char shard slice always available.
    let (shard, file_prefix) = lower.split_at(2);
    let shard_dir = store.objects_root().join(shard);
    let iter = match std::fs::read_dir(&shard_dir) {
        Ok(i) => i,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(RevError::Unknown(prefix.to_string()));
        }
        Err(e) => return Err(RevError::Backend(format!("scan objects: {e}"))),
    };

    let mut found: Option<Hash> = None;
    for entry in iter {
        let entry = entry.map_err(|e| RevError::Backend(format!("scan objects: {e}")))?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if name.len() != HEX_LEN - 2 || !name.starts_with(file_prefix) {
            continue;
        }
        let full = format!("{shard}{name}");
        let Ok(h) = hash::from_hex(&full) else {
            continue;
        };
        if found.is_some() {
            return Err(RevError::Ambiguous(prefix.to_string()));
        }
        found = Some(h);
    }
    found.ok_or_else(|| RevError::Unknown(prefix.to_string()))
}

/// Walk `n` first-parents from `commit`.
fn walk_first_parent(
    store: &ObjectStore,
    spec: &str,
    mut commit: Hash,
    n: u32,
) -> Result<Hash, RevError> {
    for _ in 0..n {
        let parents = parents_of(store, spec, &commit)?;
        let Some(first) = parents.first() else {
            return Err(RevError::BadSuffix {
                spec: spec.to_string(),
                detail: format!(
                    "commit {} has no parent (history root reached)",
                    hash::to_hex(&commit)
                ),
            });
        };
        commit = *first;
    }
    Ok(commit)
}

/// Select the `n`-th parent of `commit` (1-based). `n == 0` is the
/// commit itself.
fn select_parent(store: &ObjectStore, spec: &str, commit: Hash, n: u32) -> Result<Hash, RevError> {
    if n == 0 {
        return Ok(commit);
    }
    let parents = parents_of(store, spec, &commit)?;
    let idx = (n - 1) as usize;
    parents
        .get(idx)
        .copied()
        .ok_or_else(|| RevError::BadSuffix {
            spec: spec.to_string(),
            detail: format!(
                "commit {} has no parent #{n} (only {} parent(s))",
                hash::to_hex(&commit),
                parents.len()
            ),
        })
}

/// Read the parent list of a commit-or-remix object.
fn parents_of(store: &ObjectStore, spec: &str, commit: &Hash) -> Result<Vec<Hash>, RevError> {
    match store.read_object(commit) {
        Ok(Object::Commit(c)) => Ok(c.parents),
        Ok(Object::Remix(r)) => Ok(r.parents),
        Ok(_) => Err(RevError::NotACommit(spec.to_string())),
        Err(e) => Err(RevError::Backend(format!("read object: {e}"))),
    }
}

/// Parse a leading decimal count from `s`, returning `(count, consumed)`.
/// An absent count (next char is not a digit, or `s` is empty) yields
/// `(1, 0)` — matching `git`'s `~` == `~1` and `^` == `^1`.
fn parse_count(s: &str) -> (u32, usize) {
    let digits: String = s.chars().take_while(char::is_ascii_digit).collect();
    if digits.is_empty() {
        (1, 0)
    } else {
        // Saturate on overflow: a `~99999999999` walk would hit the
        // history root and error long before the count mattered, but we
        // must not panic on parse.
        let n = digits.parse::<u32>().unwrap_or(u32::MAX);
        (n, digits.len())
    }
}

fn is_hex(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mkit_core::object::{Commit, Identity, Object};
    use mkit_core::serialize;
    use mkit_core::{MKIT_DIR, refs};
    use tempfile::TempDir;

    fn author() -> Identity {
        Identity::ed25519([0u8; 32])
    }

    /// Build a throwaway repo with an object store + ref dir.
    fn fresh_repo() -> (TempDir, ObjectStore, std::path::PathBuf) {
        let dir = TempDir::new().unwrap();
        let store = ObjectStore::init(dir.path()).unwrap();
        let mkit_dir = dir.path().join(MKIT_DIR);
        refs::init(&mkit_dir).unwrap();
        (dir, store, mkit_dir)
    }

    /// Write a commit object with the given parents and return its hash.
    fn write_commit(store: &ObjectStore, parents: Vec<Hash>, seed: u8) -> Hash {
        let commit = Commit::new_unannotated(
            [seed; 32],
            parents,
            author(),
            [0u8; 32],
            vec![seed],
            u64::from(seed),
            [0u8; 64],
        );
        let bytes = serialize::serialize(&Object::Commit(commit)).unwrap();
        store.write(&bytes).unwrap()
    }

    #[test]
    fn resolves_full_hash() {
        let (_d, store, mkit) = fresh_repo();
        let c = write_commit(&store, vec![], 1);
        let hex = hash::to_hex(&c);
        assert_eq!(resolve_revision(&store, &mkit, &hex).unwrap(), c);
    }

    #[test]
    fn full_hash_not_in_store_is_unknown() {
        let (_d, store, mkit) = fresh_repo();
        let hex = "ab".repeat(32);
        let err = resolve_revision(&store, &mkit, &hex).unwrap_err();
        assert!(matches!(err, RevError::Unknown(_)));
    }

    #[test]
    fn resolves_unambiguous_short_hash() {
        let (_d, store, mkit) = fresh_repo();
        let c = write_commit(&store, vec![], 7);
        let hex = hash::to_hex(&c);
        let short = &hex[..12];
        assert_eq!(resolve_revision(&store, &mkit, short).unwrap(), c);
    }

    #[test]
    fn ambiguous_short_hash_errors() {
        let (_d, store, mkit) = fresh_repo();
        // Mine — in memory, hashing only — two blobs whose object hashes
        // share their first MIN_SHORT_HASH hex chars, then write JUST
        // those two to the store and query with the shared prefix. A
        // 4-nibble (16-bit) collision is found within a few hundred
        // candidates by the birthday bound, and we avoid fsync'ing
        // thousands of objects to disk. The two serialized payloads
        // resolve to the two object hashes (the store address is the
        // BLAKE3 of the serialized bytes).
        let mut seen: std::collections::HashMap<String, Vec<u8>> = std::collections::HashMap::new();
        let mut pair: Option<(String, Vec<u8>, Vec<u8>)> = None;
        for i in 0u32..200_000 {
            let bytes = serialize::serialize(&Object::Blob(mkit_core::object::Blob {
                data: i.to_le_bytes().to_vec(),
            }))
            .unwrap();
            let h = hash::hash(&bytes);
            let prefix = hash::to_hex(&h)[..MIN_SHORT_HASH].to_string();
            if let Some(prev) = seen.get(&prefix) {
                pair = Some((prefix, prev.clone(), bytes));
                break;
            }
            seen.insert(prefix, bytes);
        }
        let (prefix, a, b) = pair.expect("expected a 4-nibble prefix collision");
        store.write(&a).unwrap();
        store.write(&b).unwrap();
        let err = resolve_revision(&store, &mkit, &prefix).unwrap_err();
        assert!(matches!(err, RevError::Ambiguous(_)), "got {err:?}");
    }

    #[test]
    fn short_hash_no_match_is_unknown() {
        let (_d, store, mkit) = fresh_repo();
        write_commit(&store, vec![], 3);
        // "ffff" almost certainly does not prefix our single commit.
        let err = resolve_revision(&store, &mkit, "ffffffff").unwrap_err();
        assert!(matches!(err, RevError::Unknown(_)));
    }

    #[test]
    fn resolves_branch_ref() {
        let (_d, store, mkit) = fresh_repo();
        let c = write_commit(&store, vec![], 5);
        refs::write_ref(&mkit, "feature", &c).unwrap();
        assert_eq!(resolve_revision(&store, &mkit, "feature").unwrap(), c);
    }

    #[test]
    fn resolves_tag_ref() {
        let (_d, store, mkit) = fresh_repo();
        let c = write_commit(&store, vec![], 6);
        refs::write_tag(&mkit, "v1.0", &c).unwrap();
        assert_eq!(resolve_revision(&store, &mkit, "v1.0").unwrap(), c);
    }

    #[test]
    fn resolves_head() {
        let (_d, store, mkit) = fresh_repo();
        let c = write_commit(&store, vec![], 9);
        refs::write_ref(&mkit, "main", &c).unwrap();
        assert_eq!(resolve_revision(&store, &mkit, "HEAD").unwrap(), c);
    }

    #[test]
    fn resolves_head_tilde_n() {
        let (_d, store, mkit) = fresh_repo();
        let root = write_commit(&store, vec![], 1);
        let mid = write_commit(&store, vec![root], 2);
        let tip = write_commit(&store, vec![mid], 3);
        refs::write_ref(&mkit, "main", &tip).unwrap();
        assert_eq!(resolve_revision(&store, &mkit, "HEAD").unwrap(), tip);
        assert_eq!(resolve_revision(&store, &mkit, "HEAD~1").unwrap(), mid);
        assert_eq!(resolve_revision(&store, &mkit, "HEAD~2").unwrap(), root);
        // `~` alone == `~1`.
        assert_eq!(resolve_revision(&store, &mkit, "HEAD~").unwrap(), mid);
    }

    #[test]
    fn caret_selects_parent() {
        let (_d, store, mkit) = fresh_repo();
        let p1 = write_commit(&store, vec![], 1);
        let p2 = write_commit(&store, vec![], 2);
        let merge = write_commit(&store, vec![p1, p2], 3);
        refs::write_ref(&mkit, "main", &merge).unwrap();
        assert_eq!(resolve_revision(&store, &mkit, "HEAD^").unwrap(), p1);
        assert_eq!(resolve_revision(&store, &mkit, "HEAD^1").unwrap(), p1);
        assert_eq!(resolve_revision(&store, &mkit, "HEAD^2").unwrap(), p2);
        assert_eq!(resolve_revision(&store, &mkit, "HEAD^0").unwrap(), merge);
    }

    #[test]
    fn tilde_off_the_end_errors() {
        let (_d, store, mkit) = fresh_repo();
        let root = write_commit(&store, vec![], 1);
        refs::write_ref(&mkit, "main", &root).unwrap();
        let err = resolve_revision(&store, &mkit, "HEAD~1").unwrap_err();
        assert!(matches!(err, RevError::BadSuffix { .. }));
    }

    #[test]
    fn caret_past_parents_errors() {
        let (_d, store, mkit) = fresh_repo();
        let p1 = write_commit(&store, vec![], 1);
        let c = write_commit(&store, vec![p1], 2);
        refs::write_ref(&mkit, "main", &c).unwrap();
        let err = resolve_revision(&store, &mkit, "HEAD^2").unwrap_err();
        assert!(matches!(err, RevError::BadSuffix { .. }));
    }

    #[test]
    fn unknown_ref_errors() {
        let (_d, store, mkit) = fresh_repo();
        let err = resolve_revision(&store, &mkit, "nope").unwrap_err();
        assert!(matches!(err, RevError::Unknown(_)));
    }

    #[test]
    fn too_short_prefix_is_unknown() {
        let (_d, store, mkit) = fresh_repo();
        let c = write_commit(&store, vec![], 1);
        let hex = hash::to_hex(&c);
        // A 3-char prefix is below MIN_SHORT_HASH and not a valid ref.
        let err = resolve_revision(&store, &mkit, &hex[..3]).unwrap_err();
        assert!(matches!(err, RevError::Unknown(_)));
    }

    #[test]
    fn branch_wins_over_tag_on_collision() {
        let (_d, store, mkit) = fresh_repo();
        let branch_c = write_commit(&store, vec![], 1);
        let tag_c = write_commit(&store, vec![], 2);
        refs::write_ref(&mkit, "dup", &branch_c).unwrap();
        refs::write_tag(&mkit, "dup", &tag_c).unwrap();
        assert_eq!(resolve_revision(&store, &mkit, "dup").unwrap(), branch_c);
    }
}
