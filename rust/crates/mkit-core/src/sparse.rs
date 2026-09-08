//! Canonical-tree witnesses for sparse checkout (SPEC-SPARSE-CHECKOUT v2).
//!
//! A witness carries complete metadata for one tree. The verifier binds it to
//! an independently trusted object ID and derives the selected entries locally.
//! Directory entries authenticate child IDs; recursive consumers must verify a
//! witness for every selected child before declaring the traversal complete.
use crate::hash::{Hash, Hasher};
use crate::object::{EntryMode, Object, Tree, TreeEntry};
use crate::serialize::{deserialize, serialize};
use std::path::PathBuf;

pub const MAX_LEAVES: u64 = 1_000_000;
pub const MAX_FILTER_PATHS: usize = 100_000;
pub const MAX_FILTER_BYTES: usize = 1024 * 1024;
pub const SPARSE_WIRE_MAGIC: [u8; 4] = *b"MSP1";
pub const SPARSE_WIRE_VERSION: u8 = 2;
pub const SPARSE_WIRE_MAX_BYTES: usize = 16 * 1024 * 1024;
pub const SPARSE_CACHE_MAGIC: [u8; 4] = *b"MSPC";
pub const SPARSE_CACHE_VERSION: u8 = 2;
pub const SPARSE_CACHE_DIR: &str = "sparse";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SparseManifest {
    pub tree_hash: Hash,
    pub filter_hash: Hash,
}
#[derive(Debug, Clone)]
pub struct SparseProof {
    /// Exact canonical serialized tree object, bounded by the wire limit.
    pub tree_bytes: Vec<u8>,
}
#[derive(Debug, Clone)]
pub struct SparseResponse {
    pub manifest: SparseManifest,
    pub proof: SparseProof,
}
/// Locally derived selection after witness and requested-context verification.
#[derive(Debug, Clone)]
pub struct VerifiedSparseTree {
    pub manifest: SparseManifest,
    pub entries: Vec<TreeEntry>,
}
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SparseError {
    #[error("tree has {actual} entries, exceeds MAX_LEAVES")]
    TooManyLeaves { actual: u64 },
    #[error("filter has {actual} paths, exceeds MAX_FILTER_PATHS")]
    TooManyFilterPaths { actual: usize },
    #[error("source tree is not strictly sorted")]
    UnsortedTree,
    #[error("invalid canonical tree")]
    InvalidTree,
    #[error("unsupported filter; requires full authenticated metadata")]
    UnsupportedFilter,
    #[error("witness exceeds size limit; requires full authenticated metadata")]
    TooLarge,
}
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SparseWireError {
    #[error("sparse wire: truncated")]
    Truncated,
    #[error("sparse wire: bad magic")]
    BadMagic,
    #[error("sparse wire: unsupported version {0}")]
    UnsupportedVersion(u8),
    #[error("sparse wire: length out of bounds")]
    LengthOutOfBounds,
    #[error("sparse wire: response exceeds maximum size")]
    TooLarge,
    #[error("sparse wire: invalid tree witness")]
    InvalidTree,
}

/// Filters are UTF-8 repository-relative literal path prefixes. `.` selects
/// everything; an empty list selects nothing. Negation and globbing require the
/// authenticated full-metadata fallback, never an approximate sparse filter.
pub fn validate_filter(filter: &[PathBuf]) -> Result<(), SparseError> {
    if filter.len() > MAX_FILTER_PATHS {
        return Err(SparseError::TooManyFilterPaths {
            actual: filter.len(),
        });
    }
    let mut total = 0usize;
    for path in filter {
        let value = path.to_str().ok_or(SparseError::UnsupportedFilter)?;
        total = total
            .checked_add(value.len())
            .ok_or(SparseError::UnsupportedFilter)?;
        if total > MAX_FILTER_BYTES
            || value.is_empty()
            || value.contains(['!', '*', '?', '[', ']', '\\'])
            || (value != "."
                && value
                    .split('/')
                    .any(|p| p.is_empty() || p == "." || p == ".."))
        {
            return Err(SparseError::UnsupportedFilter);
        }
    }
    Ok(())
}
#[must_use]
pub fn hash_filter(filter: &[PathBuf]) -> Hash {
    let mut canonical: Vec<_> = filter
        .iter()
        .map(|p| p.as_os_str().as_encoded_bytes())
        .collect();
    canonical.sort_unstable();
    canonical.dedup();
    let mut h = Hasher::new();
    h.update(b"mkit-sparse-filter-v2\0");
    for bytes in canonical {
        h.update(&(bytes.len() as u64).to_le_bytes());
        h.update(bytes);
    }
    h.finalize()
}
fn matches(entry: &TreeEntry, filter: &[PathBuf]) -> bool {
    filter.iter().any(|p| {
        let prefix = p.as_os_str().as_encoded_bytes();
        prefix == b"."
            || prefix == entry.name
            || (entry.mode == EntryMode::Tree
                && prefix.starts_with(&entry.name)
                && prefix.get(entry.name.len()) == Some(&b'/'))
    })
}
fn validate_tree(tree: &Tree) -> Result<(), SparseError> {
    if tree.entries.len() as u64 > MAX_LEAVES {
        return Err(SparseError::TooManyLeaves {
            actual: tree.entries.len() as u64,
        });
    }
    if !tree.is_sorted() {
        return Err(SparseError::UnsortedTree);
    }
    if tree
        .entries
        .iter()
        .any(|e| !TreeEntry::validate_name(&e.name))
    {
        return Err(SparseError::InvalidTree);
    }
    Ok(())
}
#[must_use]
pub fn tree_hash(tree: &Tree) -> Hash {
    crate::merkle::compute_tree_id(tree)
}

pub fn build_sparse(tree: &Tree, filter: &[PathBuf]) -> Result<SparseResponse, SparseError> {
    validate_filter(filter)?;
    validate_tree(tree)?;
    // Preflight before cloning/serializing attacker-controlled names.
    let size = tree
        .entries
        .iter()
        .try_fold(10usize, |n, e| n.checked_add(37 + e.name.len()))
        .ok_or(SparseError::TooLarge)?;
    if size > SPARSE_WIRE_MAX_BYTES - 73 {
        return Err(SparseError::TooLarge);
    }
    let tree_bytes =
        serialize(&Object::Tree(tree.clone())).map_err(|_| SparseError::InvalidTree)?;
    Ok(SparseResponse {
        manifest: SparseManifest {
            tree_hash: tree_hash(tree),
            filter_hash: hash_filter(filter),
        },
        proof: SparseProof { tree_bytes },
    })
}
/// Authenticate the witness against the requested root and filter, then derive
/// the complete selection locally. No server-selected list is accepted.
pub fn verify_sparse(
    expected_tree: &Hash,
    filter: &[PathBuf],
    response: &SparseResponse,
) -> Result<VerifiedSparseTree, SparseWireError> {
    validate_filter(filter).map_err(|_| SparseWireError::InvalidTree)?;
    if response.manifest.tree_hash != *expected_tree
        || response.manifest.filter_hash != hash_filter(filter)
    {
        return Err(SparseWireError::InvalidTree);
    }
    let tree = witness_tree(&response.proof)?;
    if tree_hash(&tree) != *expected_tree {
        return Err(SparseWireError::InvalidTree);
    }
    Ok(VerifiedSparseTree {
        manifest: response.manifest,
        entries: tree
            .entries
            .into_iter()
            .filter(|entry| matches(entry, filter))
            .collect(),
    })
}

fn witness_tree(proof: &SparseProof) -> Result<Tree, SparseWireError> {
    if proof.tree_bytes.len() > SPARSE_WIRE_MAX_BYTES - 73 {
        return Err(SparseWireError::TooLarge);
    }
    let Object::Tree(tree) =
        deserialize(&proof.tree_bytes).map_err(|_| SparseWireError::InvalidTree)?
    else {
        return Err(SparseWireError::InvalidTree);
    };
    validate_tree(&tree).map_err(|_| SparseWireError::InvalidTree)?;
    if serialize(&Object::Tree(tree.clone())).map_err(|_| SparseWireError::InvalidTree)?
        != proof.tree_bytes
    {
        return Err(SparseWireError::InvalidTree);
    }
    Ok(tree)
}
/// The wire contains only the root, filter commitment and full tree witness.
/// Delivered entries are derived from that witness by `verify_sparse` consumers.
pub fn encode_sparse_response(resp: &SparseResponse) -> Result<Vec<u8>, SparseWireError> {
    let mut out = encode_sparse_cache(&resp.manifest, &resp.proof)?;
    out[..4].copy_from_slice(&SPARSE_WIRE_MAGIC);
    Ok(out)
}
pub fn decode_sparse_response(buf: &[u8]) -> Result<SparseResponse, SparseWireError> {
    let (manifest, proof) = decode_envelope(buf, SPARSE_WIRE_MAGIC)?;
    Ok(SparseResponse { manifest, proof })
}
pub fn encode_sparse_cache(
    manifest: &SparseManifest,
    proof: &SparseProof,
) -> Result<Vec<u8>, SparseWireError> {
    witness_tree(proof)?;
    let mut out = Vec::with_capacity(73 + proof.tree_bytes.len());
    out.extend_from_slice(&SPARSE_CACHE_MAGIC);
    out.push(SPARSE_CACHE_VERSION);
    out.extend_from_slice(&manifest.tree_hash);
    out.extend_from_slice(&manifest.filter_hash);
    out.extend_from_slice(
        &u32::try_from(proof.tree_bytes.len())
            .map_err(|_| SparseWireError::TooLarge)?
            .to_le_bytes(),
    );
    out.extend_from_slice(&proof.tree_bytes);
    Ok(out)
}
pub fn decode_sparse_cache(buf: &[u8]) -> Result<(SparseManifest, SparseProof), SparseWireError> {
    decode_envelope(buf, SPARSE_CACHE_MAGIC)
}
fn decode_envelope(
    buf: &[u8],
    magic: [u8; 4],
) -> Result<(SparseManifest, SparseProof), SparseWireError> {
    if buf.len() > SPARSE_WIRE_MAX_BYTES {
        return Err(SparseWireError::TooLarge);
    }
    if buf.len() < 5 {
        return Err(SparseWireError::Truncated);
    }
    if buf[..4] != magic {
        return Err(SparseWireError::BadMagic);
    }
    if buf[4] != SPARSE_WIRE_VERSION {
        return Err(SparseWireError::UnsupportedVersion(buf[4]));
    }
    if buf.len() < 73 {
        return Err(SparseWireError::Truncated);
    }
    let len = u32::from_le_bytes(
        buf[69..73]
            .try_into()
            .map_err(|_| SparseWireError::Truncated)?,
    ) as usize;
    if len != buf.len() - 73 {
        return Err(SparseWireError::LengthOutOfBounds);
    }
    let manifest = SparseManifest {
        tree_hash: buf[5..37]
            .try_into()
            .map_err(|_| SparseWireError::Truncated)?,
        filter_hash: buf[37..69]
            .try_into()
            .map_err(|_| SparseWireError::Truncated)?,
    };
    let proof = SparseProof {
        tree_bytes: buf[73..].to_vec(),
    };
    let tree = witness_tree(&proof)?;
    if tree_hash(&tree) != manifest.tree_hash {
        return Err(SparseWireError::InvalidTree);
    }
    Ok((manifest, proof))
}

/// Verify an entire selected hierarchy. Missing selected child witnesses fail;
/// ancestors are followed using only IDs authenticated by their parent tree.
/// Limits bound aggregate witness bytes, traversal count and path depth.
pub fn verify_sparse_hierarchy(
    root: Hash,
    filter: &[PathBuf],
    mut fetch: impl FnMut(&Hash, &[PathBuf]) -> Result<SparseResponse, SparseWireError>,
) -> Result<Vec<(Vec<u8>, TreeEntry)>, SparseWireError> {
    validate_filter(filter).map_err(|_| SparseWireError::InvalidTree)?;
    let mut canonical_filter = filter.to_vec();
    canonical_filter.sort();
    canonical_filter.dedup();
    let mut pending_bytes: usize = canonical_filter.iter().map(|p| p.as_os_str().len()).sum();
    let mut pending = vec![(root, Vec::<u8>::new(), canonical_filter, 0usize)];
    let mut result = Vec::new();
    let mut total = 0usize;
    let mut visited = 0usize;
    while let Some((id, path, filter, depth)) = pending.pop() {
        pending_bytes -= path.len() + filter.iter().map(|p| p.as_os_str().len()).sum::<usize>();
        visited += 1;
        if visited > 100_000 || depth > 256 {
            return Err(SparseWireError::TooLarge);
        }
        let response = fetch(&id, &filter)?;
        total = total
            .checked_add(response.proof.tree_bytes.len())
            .ok_or(SparseWireError::TooLarge)?;
        if total > 64 * 1024 * 1024 {
            return Err(SparseWireError::TooLarge);
        }
        let verified = verify_sparse(&id, &filter, &response)?;
        for entry in verified.entries {
            let mut full = path.clone();
            if !full.is_empty() {
                full.push(b'/');
            }
            full.extend_from_slice(&entry.name);
            if full.len() > 4096 || result.len() as u64 >= MAX_LEAVES {
                return Err(SparseWireError::TooLarge);
            }
            if entry.mode == EntryMode::Tree {
                let mut child_filter = Vec::new();
                for prefix in &filter {
                    let bytes = prefix.as_os_str().as_encoded_bytes();
                    if bytes == b"." || bytes == entry.name {
                        child_filter.push(PathBuf::from("."));
                    } else if bytes.starts_with(&entry.name)
                        && bytes.get(entry.name.len()) == Some(&b'/')
                    {
                        let suffix = std::str::from_utf8(&bytes[entry.name.len() + 1..])
                            .map_err(|_| SparseWireError::InvalidTree)?;
                        child_filter.push(PathBuf::from(suffix));
                    }
                }
                child_filter.sort();
                child_filter.dedup();
                pending_bytes = pending_bytes
                    .checked_add(
                        full.len()
                            + child_filter
                                .iter()
                                .map(|p| p.as_os_str().len())
                                .sum::<usize>(),
                    )
                    .ok_or(SparseWireError::TooLarge)?;
                if pending.len() >= 100_000 || pending_bytes > 64 * 1024 * 1024 {
                    return Err(SparseWireError::TooLarge);
                }
                pending.push((entry.object_hash, full.clone(), child_filter, depth + 1));
            }
            result.push((full, entry));
        }
    }
    result.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn tree() -> Tree {
        Tree {
            entries: vec![
                entry(b"a", EntryMode::Blob, [1; 32]),
                entry(b"b", EntryMode::Blob, [2; 32]),
            ],
        }
    }
    fn entry(name: &[u8], mode: EntryMode, object_hash: Hash) -> TreeEntry {
        TreeEntry {
            name: name.to_vec(),
            mode,
            object_hash,
        }
    }
    fn response(tree: &Tree, filter: &[PathBuf]) -> SparseResponse {
        build_sparse(tree, filter).unwrap()
    }
    #[test]
    fn canonical_identity_and_content_substitution() {
        let tree = tree();
        let root = Object::Tree(tree.clone()).id().unwrap();
        let filter = [PathBuf::from("a")];
        let r = response(&tree, &filter);
        assert_eq!(r.manifest.tree_hash, root);
        let verified = verify_sparse(&root, &filter, &r).unwrap();
        assert_eq!(verified.entries, vec![tree.entries[0].clone()]);
        for altered in [
            Tree {
                entries: vec![
                    entry(b"a", EntryMode::Blob, [9; 32]),
                    tree.entries[1].clone(),
                ],
            },
            Tree {
                entries: vec![
                    entry(b"a", EntryMode::Tree, [1; 32]),
                    tree.entries[1].clone(),
                ],
            },
            Tree {
                entries: vec![tree.entries[1].clone()],
            },
        ] {
            let forged = SparseResponse {
                manifest: r.manifest,
                proof: response(&altered, &filter).proof,
            };
            assert!(verify_sparse(&root, &filter, &forged).is_err());
        }
        assert!(verify_sparse(&[9; 32], &filter, &r).is_err());
    }
    #[test]
    fn wire_cache_reject_wrong_version_trailing_and_substitution() {
        let r = response(&tree(), &[PathBuf::from(".")]);
        let bytes = encode_sparse_response(&r).unwrap();
        let decoded = decode_sparse_response(&bytes).unwrap();
        assert_eq!(
            verify_sparse(&r.manifest.tree_hash, &[PathBuf::from(".")], &decoded)
                .unwrap()
                .entries,
            tree().entries
        );
        let mut bad = bytes.clone();
        bad[4] = 1;
        assert!(matches!(
            decode_sparse_response(&bad),
            Err(SparseWireError::UnsupportedVersion(1))
        ));
        let mut bad = bytes.clone();
        bad.push(0);
        assert!(decode_sparse_response(&bad).is_err());
        let mut bad = bytes;
        bad[5] ^= 1;
        assert!(decode_sparse_response(&bad).is_err());
        let cache = encode_sparse_cache(&r.manifest, &r.proof).unwrap();
        assert_eq!(decode_sparse_cache(&cache).unwrap().0, r.manifest);
    }
    #[test]
    fn hierarchy_authenticates_children_and_requires_completeness() {
        let child = tree();
        let root = Tree {
            entries: vec![entry(b"src", EntryMode::Tree, tree_hash(&child))],
        };
        let filter = [PathBuf::from("src/a")];
        let result = verify_sparse_hierarchy(tree_hash(&root), &filter, |id, f| {
            Ok(response(
                if *id == tree_hash(&root) {
                    &root
                } else {
                    &child
                },
                f,
            ))
        })
        .unwrap();
        assert_eq!(
            result.iter().map(|x| x.0.as_slice()).collect::<Vec<_>>(),
            vec![b"src".as_slice(), b"src/a".as_slice()]
        );
        assert!(
            verify_sparse_hierarchy(tree_hash(&root), &filter, |id, f| {
                if *id == tree_hash(&root) {
                    Ok(response(&root, f))
                } else {
                    Err(SparseWireError::Truncated)
                }
            })
            .is_err()
        );
        assert!(
            verify_sparse_hierarchy(tree_hash(&root), &filter, |_, f| Ok(response(&root, f)))
                .is_err()
        );
    }
    #[test]
    fn sparse_v2_golden_bytes() {
        let r = response(&tree(), &[PathBuf::from("a")]);
        let bytes = encode_sparse_response(&r).unwrap();
        if std::env::var_os("MKIT_UPDATE_SPARSE_GOLDEN").is_some() {
            std::fs::write(
                concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../tests/golden/sparse/response_v2.bin"
                ),
                &bytes,
            )
            .unwrap();
            return;
        }
        assert_eq!(
            bytes,
            include_bytes!("../../../tests/golden/sparse/response_v2.bin")
        );
        assert_eq!(r.manifest.tree_hash, Object::Tree(tree()).id().unwrap());
    }
    #[test]
    fn strict_filters_and_invalid_flattened_names() {
        for filter in ["", "/a", "a/", "../a", "a/*", "!a", "a//b"] {
            assert!(build_sparse(&tree(), &[PathBuf::from(filter)]).is_err());
        }
        let bad = Tree {
            entries: vec![entry(b"src/a", EntryMode::Blob, [0; 32])],
        };
        assert!(build_sparse(&bad, &[]).is_err());
        assert!(
            verify_sparse(&tree_hash(&tree()), &[], &response(&tree(), &[]))
                .unwrap()
                .entries
                .is_empty()
        );
        assert_eq!(
            verify_sparse(
                &tree_hash(&tree()),
                &[PathBuf::from(".")],
                &response(&tree(), &[PathBuf::from(".")])
            )
            .unwrap()
            .entries
            .len(),
            2
        );
    }
}
