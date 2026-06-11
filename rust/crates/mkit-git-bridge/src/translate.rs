//! mkit→git object translation (SPEC-GIT-BRIDGE §3–§8).
//!
//! [`translate_closure`] walks the reachable closure of a root object
//! bottom-up (children before parents, so a mirror is always
//! connectivity-valid mid-write) and emits each translated git object
//! exactly once through a caller-supplied sink. All per-object
//! mappings are pure functions; the only state is the blake3→sha1
//! cache the caller threads through, and that cache is rebuildable by
//! construction.

use crate::author;
use crate::error::{BridgeError, Refusal};
use crate::gitobj::{GitObject, GitType, Sha1Id, bytes_hex};
use crate::headers;
use crate::refname;
use mkit_core::object::{ChunkedBlob, Commit, EntryMode, Object, ObjectType, Tag, Tree};
use mkit_core::{Hash, ObjectStore};
use std::collections::HashMap;

/// Anything that can hand the translator deserialized mkit objects.
pub trait ObjectSource {
    fn read_object(&self, h: &Hash) -> Result<Object, BridgeError>;
}

impl ObjectSource for ObjectStore {
    fn read_object(&self, h: &Hash) -> Result<Object, BridgeError> {
        ObjectStore::read_object(self, h).map_err(|e| match e {
            mkit_core::store::StoreError::Decode(
                mkit_core::MkitError::UnsupportedObjectVersion,
            ) => Refusal::SchemaVersion { object: *h }.into(),
            other => BridgeError::Source(format!("{}: {other}", mkit_core::to_hex(h))),
        })
    }
}

/// Result of translating one closure: the root's git id plus how many
/// new objects were emitted (objects already in `known` are skipped).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TranslationBatch {
    pub root: Sha1Id,
    pub emitted: usize,
}

/// git mode string for an mkit tree-entry mode (§5).
#[must_use]
pub fn git_mode(mode: EntryMode) -> &'static [u8] {
    match mode {
        EntryMode::Blob => b"100644",
        EntryMode::Tree => b"40000",
        EntryMode::Symlink => b"120000",
        EntryMode::Executable => b"100755",
    }
}

/// The git type a translated mkit object carries (§7.1).
#[must_use]
pub fn git_type_of(t: ObjectType) -> Option<GitType> {
    Some(match t {
        ObjectType::Blob | ObjectType::ChunkedBlob => GitType::Blob,
        ObjectType::Tree => GitType::Tree,
        ObjectType::Commit => GitType::Commit,
        ObjectType::Tag => GitType::Tag,
        ObjectType::Remix | ObjectType::Delta => return None,
    })
}

// ─── pure per-object translations ──────────────────────────────────

/// §3: blob body is the data, verbatim.
#[must_use]
pub fn translate_blob(data: &[u8]) -> GitObject {
    GitObject {
        gtype: GitType::Blob,
        body: data.to_vec(),
    }
}

/// §4: flatten a content-defined chunked blob.
///
/// Refuses (per §4) anything a conformant mkit writer cannot have
/// produced — fixed-size chunking, at-or-below-threshold totals, or
/// boundaries that differ from the pinned `FastCDC` output — because
/// such manifests would not survive the §9 round trip.
pub fn translate_chunked<S: ObjectSource>(
    hash: &Hash,
    manifest: &ChunkedBlob,
    source: &S,
) -> Result<GitObject, BridgeError> {
    if manifest.chunk_size != 0 {
        return Err(Refusal::FixedSizeChunking {
            object: *hash,
            chunk_size: manifest.chunk_size,
        }
        .into());
    }
    if manifest.total_size <= mkit_core::worktree::CHUNK_THRESHOLD {
        // A conformant writer stores this as a plain blob (§4 item 2).
        return Err(Refusal::NonCanonicalChunking {
            object: *hash,
            detail: "total size at or below the 1 MiB chunking threshold",
        }
        .into());
    }
    let total = usize::try_from(manifest.total_size)
        .map_err(|_| BridgeError::Source("manifest total_size exceeds usize".into()))?;
    let mut body = Vec::with_capacity(total);
    let mut lengths = Vec::with_capacity(manifest.chunks.len());
    for chunk_hash in &manifest.chunks {
        match source.read_object(chunk_hash)? {
            Object::Blob(b) => {
                lengths.push(b.data.len());
                body.extend_from_slice(&b.data);
            }
            other => {
                return Err(BridgeError::Source(format!(
                    "chunk {} is a {}, not a blob",
                    mkit_core::to_hex(chunk_hash),
                    other.object_type().name()
                )));
            }
        }
    }
    if body.len() as u64 != manifest.total_size {
        return Err(BridgeError::Source(format!(
            "chunked blob {}: concatenated {} bytes, manifest says {}",
            mkit_core::to_hex(hash),
            body.len(),
            manifest.total_size
        )));
    }
    // §4 item 3: boundaries must equal the pinned FastCDC output, or
    // §9's re-chunking reconstructs a different manifest.
    let canonical: Vec<usize> = mkit_core::ChunkIterator::new(mkit_core::FastCdc::v1(), &body)
        .map(|b| b.length)
        .collect();
    if canonical != lengths {
        return Err(Refusal::NonCanonicalChunking {
            object: *hash,
            detail: "chunk boundaries differ from the pinned FastCDC output",
        }
        .into());
    }
    Ok(GitObject {
        gtype: GitType::Blob,
        body,
    })
}

/// §5: tree with entries re-sorted into git order.
pub fn translate_tree(
    tree: &Tree,
    resolve: &impl Fn(&Hash) -> Option<Sha1Id>,
) -> Result<GitObject, BridgeError> {
    let mut entries: Vec<(&mkit_core::object::TreeEntry, Sha1Id)> = tree
        .entries
        .iter()
        .map(|e| {
            resolve(&e.object_hash).map(|id| (e, id)).ok_or_else(|| {
                BridgeError::Source(format!(
                    "tree entry {:?} child not translated",
                    String::from_utf8_lossy(&e.name)
                ))
            })
        })
        .collect::<Result<_, _>>()?;
    // git sorts with directory names compared as `name + "/"`.
    entries.sort_by(|(a, _), (b, _)| {
        let key = |e: &mkit_core::object::TreeEntry| {
            let mut k = e.name.clone();
            if e.mode == EntryMode::Tree {
                k.push(b'/');
            }
            k
        };
        key(a).cmp(&key(b))
    });
    let mut body = Vec::new();
    for (e, id) in entries {
        body.extend_from_slice(git_mode(e.mode));
        body.push(b' ');
        body.extend_from_slice(&e.name);
        body.push(0);
        body.extend_from_slice(&id);
    }
    Ok(GitObject {
        gtype: GitType::Tree,
        body,
    })
}

/// §6: commit with the pinned header layout.
pub fn translate_commit(
    hash: &Hash,
    c: &Commit,
    tree_id: &Sha1Id,
    parent_ids: &[Sha1Id],
) -> Result<GitObject, BridgeError> {
    if c.timestamp > i64::MAX as u64 {
        return Err(Refusal::TimestampOverflow {
            object: *hash,
            timestamp: c.timestamp,
        }
        .into());
    }
    let mut body = Vec::new();
    push_line(
        &mut body,
        b"tree",
        crate::gitobj::sha1_hex(tree_id).as_bytes(),
    );
    for pid in parent_ids {
        push_line(
            &mut body,
            b"parent",
            crate::gitobj::sha1_hex(pid).as_bytes(),
        );
    }
    let person = author::line(&c.author, c.timestamp);
    push_line(&mut body, b"author", &person);
    push_line(&mut body, b"committer", &person);
    push_line(
        &mut body,
        headers::MKIT_SCHEMA.as_bytes(),
        headers::SCHEMA_VALUE.as_bytes(),
    );
    push_line(
        &mut body,
        headers::MKIT_AUTHOR.as_bytes(),
        headers::identity_value(&c.author).as_bytes(),
    );
    push_line(
        &mut body,
        headers::MKIT_SIGNER.as_bytes(),
        bytes_hex(&c.signer).as_bytes(),
    );
    push_line(
        &mut body,
        headers::MKIT_SIGNATURE.as_bytes(),
        bytes_hex(&c.signature).as_bytes(),
    );
    push_line(
        &mut body,
        headers::MKIT_TREE.as_bytes(),
        headers::hash_value(&c.tree_hash).as_bytes(),
    );
    for p in &c.parents {
        push_line(
            &mut body,
            headers::MKIT_PARENT.as_bytes(),
            headers::hash_value(p).as_bytes(),
        );
    }
    if c.message_hash != mkit_core::hash::ZERO {
        push_line(
            &mut body,
            headers::MKIT_MESSAGE_HASH.as_bytes(),
            headers::hash_value(&c.message_hash).as_bytes(),
        );
    }
    if c.content_digest != mkit_core::hash::ZERO {
        push_line(
            &mut body,
            headers::MKIT_CONTENT_DIGEST.as_bytes(),
            headers::hash_value(&c.content_digest).as_bytes(),
        );
    }
    body.push(b'\n');
    body.extend_from_slice(&c.message);
    Ok(GitObject {
        gtype: GitType::Commit,
        body,
    })
}

/// §7: annotated/signed tag object.
pub fn translate_tag(hash: &Hash, t: &Tag, target_id: &Sha1Id) -> Result<GitObject, BridgeError> {
    if t.timestamp > i64::MAX as u64 {
        return Err(Refusal::TimestampOverflow {
            object: *hash,
            timestamp: t.timestamp,
        }
        .into());
    }
    if refname::check_tag_name(&t.name).is_err() {
        return Err(Refusal::TagName { object: *hash }.into());
    }
    let Some(target_gtype) = git_type_of(t.target_type) else {
        // A tag pointing at a remix carries the remix policy.
        return Err(Refusal::Remix { object: t.target }.into());
    };
    let mut body = Vec::new();
    push_line(
        &mut body,
        b"object",
        crate::gitobj::sha1_hex(target_id).as_bytes(),
    );
    push_line(&mut body, b"type", target_gtype.name().as_bytes());
    push_line(&mut body, b"tag", &t.name);
    let person = author::line(&t.tagger, t.timestamp);
    push_line(&mut body, b"tagger", &person);
    push_line(
        &mut body,
        headers::MKIT_SCHEMA.as_bytes(),
        headers::SCHEMA_VALUE.as_bytes(),
    );
    push_line(
        &mut body,
        headers::MKIT_TAGGER.as_bytes(),
        headers::identity_value(&t.tagger).as_bytes(),
    );
    push_line(
        &mut body,
        headers::MKIT_SIGNER.as_bytes(),
        bytes_hex(&t.signer).as_bytes(),
    );
    push_line(
        &mut body,
        headers::MKIT_SIGNATURE.as_bytes(),
        bytes_hex(&t.signature).as_bytes(),
    );
    push_line(
        &mut body,
        headers::MKIT_TARGET.as_bytes(),
        headers::hash_value(&t.target).as_bytes(),
    );
    push_line(
        &mut body,
        headers::MKIT_TARGET_TYPE.as_bytes(),
        format!("{:02x}", t.target_type as u8).as_bytes(),
    );
    body.push(b'\n');
    body.extend_from_slice(&t.message);
    Ok(GitObject {
        gtype: GitType::Tag,
        body,
    })
}

fn push_line(body: &mut Vec<u8>, key: &[u8], value: &[u8]) {
    body.extend_from_slice(key);
    body.push(b' ');
    body.extend_from_slice(value);
    body.push(b'\n');
}

// ─── closure driver ─────────────────────────────────────────────────

/// Translate the reachable closure of `root`, emitting every *newly*
/// translated object through `sink` in dependency order (children
/// first). `known` is the blake3→sha1 cache; it is consulted to skip
/// already-translated subgraphs and updated with every emission.
// The concrete HashMap is deliberate: `known` is the on-disk map
// cache's in-memory form (map::load_map), not a generic lookup.
#[allow(clippy::implicit_hasher)]
pub fn translate_closure<S: ObjectSource>(
    source: &S,
    root: &Hash,
    known: &mut HashMap<Hash, Sha1Id>,
    sink: &mut dyn FnMut(&Hash, &GitObject) -> Result<(), BridgeError>,
) -> Result<TranslationBatch, BridgeError> {
    let mut emitted = 0usize;
    // Explicit stack: (hash, expanded?). Content addressing makes the
    // graph acyclic, so no cycle guard is needed; `known` collapses
    // diamonds.
    let mut stack: Vec<(Hash, bool)> = vec![(*root, false)];
    let mut parsed: HashMap<Hash, Object> = HashMap::new();

    while let Some((h, expanded)) = stack.pop() {
        if known.contains_key(&h) {
            continue;
        }
        if !expanded {
            let obj = match parsed.get(&h) {
                Some(_) => continue, // already queued for post-visit
                None => source.read_object(&h)?,
            };
            let deps = dependencies(&h, &obj)?;
            stack.push((h, true));
            parsed.insert(h, obj);
            for d in deps {
                if !known.contains_key(&d) && !parsed.contains_key(&d) {
                    stack.push((d, false));
                }
            }
            continue;
        }
        let obj = parsed
            .remove(&h)
            .ok_or_else(|| BridgeError::Source("post-visit without parse".into()))?;
        let git = translate_one(source, &h, &obj, &|child| known.get(child).copied())?;
        let id = git.id();
        sink(&h, &git)?;
        known.insert(h, id);
        emitted += 1;
    }

    let root_id = known
        .get(root)
        .copied()
        .ok_or_else(|| BridgeError::Source("root not translated".into()))?;
    Ok(TranslationBatch {
        root: root_id,
        emitted,
    })
}

/// The child hashes that must be translated before `obj` (§1.1 graph
/// edges). Chunk blobs of a manifest are *consumed*, not translated,
/// so they are not dependencies.
fn dependencies(hash: &Hash, obj: &Object) -> Result<Vec<Hash>, BridgeError> {
    Ok(match obj {
        Object::Blob(_) | Object::ChunkedBlob(_) => Vec::new(),
        Object::Tree(t) => t.entries.iter().map(|e| e.object_hash).collect(),
        Object::Commit(c) => {
            let mut v = Vec::with_capacity(1 + c.parents.len());
            v.push(c.tree_hash);
            v.extend_from_slice(&c.parents);
            v
        }
        Object::Tag(t) => vec![t.target],
        Object::Remix(_) => return Err(Refusal::Remix { object: *hash }.into()),
        Object::Delta(_) => {
            return Err(BridgeError::Source(format!(
                "delta object {} in store (pack-only type)",
                mkit_core::to_hex(hash)
            )));
        }
    })
}

fn translate_one<S: ObjectSource>(
    source: &S,
    hash: &Hash,
    obj: &Object,
    resolve: &impl Fn(&Hash) -> Option<Sha1Id>,
) -> Result<GitObject, BridgeError> {
    match obj {
        Object::Blob(b) => Ok(translate_blob(&b.data)),
        Object::ChunkedBlob(m) => translate_chunked(hash, m, source),
        Object::Tree(t) => translate_tree(t, resolve),
        Object::Commit(c) => {
            let tree_id = resolve(&c.tree_hash)
                .ok_or_else(|| BridgeError::Source("commit tree not translated".into()))?;
            let parent_ids: Vec<Sha1Id> = c
                .parents
                .iter()
                .map(|p| {
                    resolve(p)
                        .ok_or_else(|| BridgeError::Source("commit parent not translated".into()))
                })
                .collect::<Result<_, _>>()?;
            translate_commit(hash, c, &tree_id, &parent_ids)
        }
        Object::Tag(t) => {
            let target_id = resolve(&t.target)
                .ok_or_else(|| BridgeError::Source("tag target not translated".into()))?;
            translate_tag(hash, t, &target_id)
        }
        Object::Remix(_) => Err(Refusal::Remix { object: *hash }.into()),
        Object::Delta(_) => Err(BridgeError::Source("delta is pack-only".into())),
    }
}
