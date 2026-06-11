//! Verification-grade inverse of [`crate::translate`]
//! (SPEC-GIT-BRIDGE §9).
//!
//! **Not an import path.** Every function here is defined only on git
//! objects the v1 mapping can emit, and proves it by *re-translating*
//! the reconstructed mkit object and requiring byte equality with the
//! input — so header order, duplicate headers, unknown `mkit-*`
//! headers, reserved headers, foreign modes (`160000`), and any other
//! off-spec shape all fail closed with [`BridgeError::NotBridgeObject`]
//! or [`BridgeError::Integrity`].

use crate::author;
use crate::error::BridgeError;
use crate::gitobj::{GitObject, GitType, Sha1Id, sha1_from_hex};
use crate::headers;
use crate::translate;
use mkit_core::object::{
    Blob, ChunkedBlob, Commit, EntryMode, Object, ObjectType, Tag, Tree, TreeEntry,
};
use mkit_core::worktree::CHUNK_THRESHOLD;
use mkit_core::{ChunkIterator, FastCdc, Hash};
use std::collections::HashMap;

/// A reconstructed mkit object: its serialized v1 bytes and BLAKE3
/// hash. `extras` carries the chunk blobs a large flattened blob
/// re-chunks into (empty for everything else).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reconstructed {
    pub hash: Hash,
    pub bytes: Vec<u8>,
    pub object: Object,
    pub extras: Vec<(Hash, Vec<u8>)>,
}

fn finish(object: Object, extras: Vec<(Hash, Vec<u8>)>) -> Result<Reconstructed, BridgeError> {
    let bytes = mkit_core::serialize(&object)
        .map_err(|e| BridgeError::Integrity(format!("reserialize: {e}")))?;
    let hash = mkit_core::hash::hash(&bytes);
    Ok(Reconstructed {
        hash,
        bytes,
        object,
        extras,
    })
}

/// §9 blob rule: ≤ 1 MiB → plain blob; larger → pinned-FastCDC
/// chunk blobs + manifest (mirrors `worktree::store_file_object`).
pub fn reconstruct_blob(body: &[u8]) -> Result<Reconstructed, BridgeError> {
    if body.len() as u64 <= CHUNK_THRESHOLD {
        return finish(
            Object::Blob(Blob {
                data: body.to_vec(),
            }),
            Vec::new(),
        );
    }
    let mut extras = Vec::new();
    let chunks: Vec<Hash> = ChunkIterator::new(FastCdc::v1(), body)
        .map(|b| {
            let chunk = Object::Blob(Blob {
                data: body[b.offset..b.offset + b.length].to_vec(),
            });
            let bytes = mkit_core::serialize(&chunk)
                .map_err(|e| BridgeError::Integrity(format!("chunk serialize: {e}")))?;
            let h = mkit_core::hash::hash(&bytes);
            extras.push((h, bytes));
            Ok::<_, BridgeError>(h)
        })
        .collect::<Result<_, _>>()?;
    let manifest = Object::ChunkedBlob(ChunkedBlob {
        total_size: body.len() as u64,
        chunk_size: 0,
        chunks,
    });
    finish(manifest, extras)
}

/// §9 tree rule. `resolve` maps a child git id back to the BLAKE3 of
/// the already-reconstructed child (bottom-up order is the caller's
/// job).
pub fn reconstruct_tree(
    body: &[u8],
    resolve: &impl Fn(&Sha1Id) -> Option<Hash>,
) -> Result<Reconstructed, BridgeError> {
    let mut entries = Vec::new();
    let mut local: HashMap<Hash, Sha1Id> = HashMap::new();
    let mut rest = body;
    while !rest.is_empty() {
        let sp = rest
            .iter()
            .position(|&b| b == b' ')
            .ok_or_else(|| not_bridge("tree entry missing mode terminator"))?;
        let mode = match &rest[..sp] {
            b"100644" => EntryMode::Blob,
            b"40000" => EntryMode::Tree,
            b"120000" => EntryMode::Symlink,
            b"100755" => EntryMode::Executable,
            other => {
                return Err(not_bridge(&format!(
                    "git tree mode {:?} has no mkit equivalent",
                    String::from_utf8_lossy(other)
                )));
            }
        };
        rest = &rest[sp + 1..];
        let nul = rest
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| not_bridge("tree entry missing NUL"))?;
        let name = rest[..nul].to_vec();
        rest = &rest[nul + 1..];
        if rest.len() < 20 {
            return Err(not_bridge("tree entry truncated id"));
        }
        let mut id = [0u8; 20];
        id.copy_from_slice(&rest[..20]);
        rest = &rest[20..];
        let child = resolve(&id).ok_or_else(|| not_bridge("tree child id not reconstructible"))?;
        local.insert(child, id);
        entries.push(TreeEntry {
            name,
            mode,
            object_hash: child,
        });
    }
    // mkit canonical order: byte-lex on the raw name.
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    let tree = Tree { entries };
    // Prove exact bridge shape by re-translation.
    let retrans = translate::translate_tree(&tree, &|h| local.get(h).copied())?;
    if retrans.body != body {
        return Err(BridgeError::Integrity(
            "tree re-translation mismatch (not a bridge-emitted tree)".into(),
        ));
    }
    finish(Object::Tree(tree), Vec::new())
}

/// §9 commit rule: self-contained (everything rides in headers).
pub fn reconstruct_commit(body: &[u8]) -> Result<Reconstructed, BridgeError> {
    let parsed = ParsedBody::parse(body)?;
    parsed.check_schema()?;
    let tree_id = parsed.required_git_id("tree")?;
    let parent_ids = parsed.all_git_ids("parent")?;
    let author_line = parsed.required(b"author")?;
    let timestamp = author::parse_timestamp(author_line)
        .ok_or_else(|| not_bridge("author line is not bridge-synthesized"))?;
    let identity = headers::parse_identity(parsed.required_str(headers::MKIT_AUTHOR)?)
        .ok_or_else(|| not_bridge("mkit-author header malformed"))?;
    let commit = Commit {
        tree_hash: parsed.required_hash(headers::MKIT_TREE)?,
        parents: parsed.all_hashes(headers::MKIT_PARENT)?,
        author: identity,
        signer: parsed.required_hash(headers::MKIT_SIGNER)?,
        message: parsed.message.to_vec(),
        timestamp,
        message_hash: parsed
            .optional_hash(headers::MKIT_MESSAGE_HASH)?
            .unwrap_or(mkit_core::hash::ZERO),
        content_digest: parsed
            .optional_hash(headers::MKIT_CONTENT_DIGEST)?
            .unwrap_or(mkit_core::hash::ZERO),
        signature: parsed.required_signature(headers::MKIT_SIGNATURE)?,
    };
    if commit.parents.len() != parent_ids.len() {
        return Err(not_bridge("parent / mkit-parent count mismatch"));
    }
    let probe = mkit_core::hash::ZERO; // hash input unused by translate_commit checks
    let retrans = translate::translate_commit(&probe, &commit, &tree_id, &parent_ids)?;
    if retrans.body != body {
        return Err(BridgeError::Integrity(
            "commit re-translation mismatch (not a bridge-emitted commit)".into(),
        ));
    }
    finish(Object::Commit(commit), Vec::new())
}

/// §9 tag rule: self-contained like commits.
pub fn reconstruct_tag(body: &[u8]) -> Result<Reconstructed, BridgeError> {
    let parsed = ParsedBody::parse(body)?;
    parsed.check_schema()?;
    let target_id = parsed.required_git_id("object")?;
    let name = parsed.required(b"tag")?.to_vec();
    let tagger_line = parsed.required(b"tagger")?;
    let timestamp = author::parse_timestamp(tagger_line)
        .ok_or_else(|| not_bridge("tagger line is not bridge-synthesized"))?;
    let tagger = headers::parse_identity(parsed.required_str(headers::MKIT_TAGGER)?)
        .ok_or_else(|| not_bridge("mkit-tagger header malformed"))?;
    let tt_hex = parsed.required_str(headers::MKIT_TARGET_TYPE)?;
    let tt_byte = crate::gitobj::bytes_from_hex(tt_hex, 1)
        .ok_or_else(|| not_bridge("mkit-target-type malformed"))?[0];
    // Only target types the v1 mapping can emit (§7.1): remix/delta
    // targets are refused at translation time and unknown bytes are
    // future formats.
    let target_type = match tt_byte {
        0x01 => ObjectType::Blob,
        0x02 => ObjectType::Tree,
        0x03 => ObjectType::Commit,
        0x05 => ObjectType::ChunkedBlob,
        0x07 => ObjectType::Tag,
        _ => return Err(not_bridge("mkit-target-type not bridge-emittable")),
    };
    let tag = Tag {
        target: parsed.required_hash(headers::MKIT_TARGET)?,
        target_type,
        name,
        tagger,
        signer: parsed.required_hash(headers::MKIT_SIGNER)?,
        message: parsed.message.to_vec(),
        timestamp,
        signature: parsed.required_signature(headers::MKIT_SIGNATURE)?,
    };
    let probe = mkit_core::hash::ZERO;
    let retrans = translate::translate_tag(&probe, &tag, &target_id)?;
    if retrans.body != body {
        return Err(BridgeError::Integrity(
            "tag re-translation mismatch (not a bridge-emitted tag)".into(),
        ));
    }
    finish(Object::Tag(tag), Vec::new())
}

/// Dispatch on git type.
pub fn reconstruct(
    obj: &GitObject,
    resolve: &impl Fn(&Sha1Id) -> Option<Hash>,
) -> Result<Reconstructed, BridgeError> {
    match obj.gtype {
        GitType::Blob => reconstruct_blob(&obj.body),
        GitType::Tree => reconstruct_tree(&obj.body, resolve),
        GitType::Commit => reconstruct_commit(&obj.body),
        GitType::Tag => reconstruct_tag(&obj.body),
    }
}

fn not_bridge(msg: &str) -> BridgeError {
    BridgeError::NotBridgeObject(msg.to_owned())
}

// ─── header-block parsing ───────────────────────────────────────────

struct ParsedBody<'a> {
    headers: Vec<(&'a [u8], &'a [u8])>,
    message: &'a [u8],
}

impl<'a> ParsedBody<'a> {
    fn parse(body: &'a [u8]) -> Result<Self, BridgeError> {
        let split = body
            .windows(2)
            .position(|w| w == b"\n\n")
            .ok_or_else(|| not_bridge("no header/message separator"))?;
        let (head, message) = (&body[..=split], &body[split + 2..]);
        let mut headers = Vec::new();
        for line in head.split(|&b| b == b'\n').filter(|l| !l.is_empty()) {
            if line.starts_with(b" ") {
                // The bridge never emits continuation lines (§6.1).
                return Err(not_bridge("continuation header line"));
            }
            let sp = line
                .iter()
                .position(|&b| b == b' ')
                .ok_or_else(|| not_bridge("header line without value"))?;
            let key = &line[..sp];
            if headers::RESERVED.iter().any(|r| r.as_bytes() == key) {
                return Err(not_bridge("reserved mkit-* header present"));
            }
            headers.push((key, &line[sp + 1..]));
        }
        Ok(Self { headers, message })
    }

    /// §1.2: an actionable error for missing/foreign schema versions
    /// (instead of the generic re-translation mismatch).
    fn check_schema(&self) -> Result<(), BridgeError> {
        match self.required_str(headers::MKIT_SCHEMA) {
            Ok(v) if v == headers::SCHEMA_VALUE => Ok(()),
            Ok(v) => Err(not_bridge(&format!(
                "mkit-schema {v} is not covered by bridge mapping v1"
            ))),
            Err(_) => Err(not_bridge("missing mkit-schema header")),
        }
    }

    fn all(&self, key: &[u8]) -> Vec<&'a [u8]> {
        self.headers
            .iter()
            .filter(|(k, _)| *k == key)
            .map(|(_, v)| *v)
            .collect()
    }

    fn required(&self, key: &[u8]) -> Result<&'a [u8], BridgeError> {
        match self.all(key).as_slice() {
            [v] => Ok(v),
            [] => Err(not_bridge(&format!(
                "missing {}",
                String::from_utf8_lossy(key)
            ))),
            _ => Err(not_bridge(&format!(
                "duplicate {}",
                String::from_utf8_lossy(key)
            ))),
        }
    }

    fn required_str(&self, key: &str) -> Result<&'a str, BridgeError> {
        std::str::from_utf8(self.required(key.as_bytes())?)
            .map_err(|_| not_bridge(&format!("{key} not UTF-8")))
    }

    fn required_git_id(&self, key: &str) -> Result<Sha1Id, BridgeError> {
        sha1_from_hex(self.required_str(key)?)
            .ok_or_else(|| not_bridge(&format!("{key} is not a 40-hex id")))
    }

    fn all_git_ids(&self, key: &str) -> Result<Vec<Sha1Id>, BridgeError> {
        self.all(key.as_bytes())
            .into_iter()
            .map(|v| {
                std::str::from_utf8(v)
                    .ok()
                    .and_then(sha1_from_hex)
                    .ok_or_else(|| not_bridge(&format!("{key} is not a 40-hex id")))
            })
            .collect()
    }

    fn required_hash(&self, key: &str) -> Result<[u8; 32], BridgeError> {
        headers::parse_hash(self.required_str(key)?)
            .ok_or_else(|| not_bridge(&format!("{key} is not a 64-hex hash")))
    }

    fn optional_hash(&self, key: &str) -> Result<Option<[u8; 32]>, BridgeError> {
        match self.all(key.as_bytes()).as_slice() {
            [] => Ok(None),
            [v] => std::str::from_utf8(v)
                .ok()
                .and_then(headers::parse_hash)
                .map(Some)
                .ok_or_else(|| not_bridge(&format!("{key} is not a 64-hex hash"))),
            _ => Err(not_bridge(&format!("duplicate {key}"))),
        }
    }

    fn required_signature(&self, key: &str) -> Result<[u8; 64], BridgeError> {
        headers::parse_signature(self.required_str(key)?)
            .ok_or_else(|| not_bridge(&format!("{key} is not a 128-hex signature")))
    }

    fn all_hashes(&self, key: &str) -> Result<Vec<[u8; 32]>, BridgeError> {
        self.all(key.as_bytes())
            .into_iter()
            .map(|v| {
                std::str::from_utf8(v)
                    .ok()
                    .and_then(headers::parse_hash)
                    .ok_or_else(|| not_bridge(&format!("{key} is not a 64-hex hash")))
            })
            .collect()
    }
}
