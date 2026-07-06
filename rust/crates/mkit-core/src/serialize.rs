//! Canonical byte (de)serialization for [`Object`].
//!
//! Spec: `docs/specs/SPEC-OBJECTS.md`. The byte layout produced here is the
//! v1 on-disk format; the golden-vector tests in `tests/golden.rs` pin
//! it byte-for-byte.
//!
//! Every deserializer:
//! * Validates the 6-byte v1 prologue first.
//! * Enforces per-type bounds (entry counts, identity len, etc.).
//! * Rejects non-empty trailing bytes via [`MkitError::TrailingData`].

use crate::hash::{HASH_LEN, Hash};
use crate::object::{
    Blob, ChunkedBlob, Commit, Delta, EntryMode, IDENTITY_MAX_LEN, Identity, IdentityKind, MAGIC,
    MkitError, Object, ObjectType, Remix, RemixSource, SCHEMA_VERSION, TAG_NAME_MAX_LEN, Tag, Tree,
    TreeEntry,
};

const PROLOGUE_LEN: usize = 6;

/// Decode-side cap on tree entry count; writers (and the git
/// importer) must refuse anything larger or the store gains an
/// undecodable signed object.
pub const MAX_TREE_ENTRIES: u32 = 1_000_000;
const MAX_PARENTS: u32 = 1_000;
const MAX_REMIX_SOURCES: u32 = 10_000;
const MAX_CHUNKS: u32 = 1_000_000;

// ---------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------

/// Serialize an [`Object`] to its canonical byte form. Allocates fresh
/// each call; the result is fully owned.
///
/// Returns [`MkitError::OversizePayload`] if any length-prefixed field
/// exceeds the wire-format `u32` cap, and [`MkitError::InvalidIdentity`]
/// if the object carries a structurally invalid [`Identity`].
///
/// # Caller precondition: ordering
///
/// The writer does not reorder or validate entry/source ordering — it
/// encodes them verbatim — but [`deserialize`] enforces a strict
/// ascending order (`Tree` entries by `name`, `Remix` sources by
/// `(upstream_id, commit_hash)`). An `Object` built by hand with
/// out-of-order `Tree::entries` or `Remix::sources` will therefore
/// serialize cleanly yet fail to round-trip (`deserialize` rejects it
/// with `InvalidEntryOrder` / `InvalidSourceOrder`). Callers that bypass
/// the ordered-building helpers MUST ensure [`Tree::is_sorted`] /
/// [`Remix::sources_sorted`] hold before serializing — otherwise the
/// resulting (possibly signed) bytes are undecodable.
pub fn serialize(obj: &Object) -> Result<Vec<u8>, MkitError> {
    let mut buf = Vec::with_capacity(PROLOGUE_LEN + estimated_body_len(obj));
    write_prologue(&mut buf, obj.object_type());
    match obj {
        Object::Blob(b) => write_blob(&mut buf, b)?,
        Object::Tree(t) => write_tree(&mut buf, t)?,
        Object::Commit(c) => write_commit(&mut buf, c)?,
        Object::Remix(r) => write_remix(&mut buf, r)?,
        Object::ChunkedBlob(cb) => write_chunked_blob(&mut buf, cb)?,
        Object::Delta(d) => write_delta(&mut buf, d)?,
        Object::Tag(t) => write_tag(&mut buf, t)?,
    }
    Ok(buf)
}

/// The exact byte prefix of `serialize(Object::Blob(..))` for a payload
/// of `len` bytes: 6-byte object prologue plus the `u32` LE data
/// length. Lets ingest write a chunk as `prologue ‖ payload` straight
/// from the source buffer — no `Blob` allocation, no serialize copy.
/// Equivalence with [`serialize`] is pinned by proptest and,
/// transitively, the golden blob vectors.
///
/// # Errors
///
/// [`MkitError::OversizePayload`] if `len` exceeds the wire-format
/// `u32` cap.
pub fn blob_prologue(len: usize) -> Result<[u8; PROLOGUE_LEN + 4], MkitError> {
    let len_le = checked_u32("blob.data", len)?.to_le_bytes();
    let mut out = [0u8; PROLOGUE_LEN + 4];
    out[0] = ObjectType::Blob as u8;
    out[1..5].copy_from_slice(&MAGIC);
    out[5] = SCHEMA_VERSION;
    out[6..10].copy_from_slice(&len_le);
    Ok(out)
}

/// Deserialize bytes into an owned [`Object`]. Validates the prologue
/// and every per-type bound; rejects trailing data.
pub fn deserialize(data: &[u8]) -> Result<Object, MkitError> {
    if data.len() < PROLOGUE_LEN {
        return Err(MkitError::EmptyData);
    }
    let tag = ObjectType::from_u8(data[0])?;
    if data[1..5] != MAGIC {
        return Err(MkitError::InvalidMagic);
    }
    if data[5] != SCHEMA_VERSION {
        return Err(MkitError::UnsupportedObjectVersion);
    }
    let mut r = Reader::new(&data[PROLOGUE_LEN..]);
    let obj = match tag {
        ObjectType::Blob => Object::Blob(read_blob(&mut r)?),
        ObjectType::Tree => Object::Tree(read_tree(&mut r)?),
        ObjectType::Commit => Object::Commit(read_commit(&mut r)?),
        ObjectType::Remix => Object::Remix(read_remix(&mut r)?),
        ObjectType::ChunkedBlob => Object::ChunkedBlob(read_chunked_blob(&mut r)?),
        ObjectType::Delta => Object::Delta(read_delta(&mut r)?),
        ObjectType::Tag => Object::Tag(read_tag(&mut r)?),
    };
    if r.remaining() != 0 {
        return Err(MkitError::TrailingData);
    }
    Ok(obj)
}

// ---------------------------------------------------------------------
// Writers
// ---------------------------------------------------------------------

fn write_prologue(buf: &mut Vec<u8>, t: ObjectType) {
    buf.push(t as u8);
    buf.extend_from_slice(&MAGIC);
    buf.push(SCHEMA_VERSION);
}

fn write_u16_le(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn write_u32_le(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn write_u64_le(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn checked_u32(field: &'static str, len: usize) -> Result<u32, MkitError> {
    u32::try_from(len).map_err(|_| MkitError::OversizePayload { field, len })
}

fn write_lp_bytes(buf: &mut Vec<u8>, field: &'static str, data: &[u8]) -> Result<(), MkitError> {
    write_u32_le(buf, checked_u32(field, data.len())?);
    buf.extend_from_slice(data);
    Ok(())
}

fn write_identity(buf: &mut Vec<u8>, id: &Identity) -> Result<(), MkitError> {
    if !id.is_valid() {
        return Err(MkitError::InvalidIdentity);
    }
    buf.push(id.kind as u8);
    // `is_valid` already enforces 1..=IDENTITY_MAX_LEN, so the cast is
    // safe — but keep the guard so the encoder can never silently lose
    // bytes if `is_valid` is ever loosened.
    let len = u16::try_from(id.bytes.len()).map_err(|_| MkitError::InvalidIdentity)?;
    write_u16_le(buf, len);
    buf.extend_from_slice(&id.bytes);
    Ok(())
}

fn write_blob(buf: &mut Vec<u8>, b: &Blob) -> Result<(), MkitError> {
    write_lp_bytes(buf, "blob.data", &b.data)
}

fn write_tree(buf: &mut Vec<u8>, t: &Tree) -> Result<(), MkitError> {
    write_u32_le(buf, checked_u32("tree.entries", t.entries.len())?);
    for e in &t.entries {
        write_lp_bytes(buf, "tree.entry.name", &e.name)?;
        buf.push(e.mode as u8);
        buf.extend_from_slice(&e.object_hash);
    }
    Ok(())
}

fn write_commit(buf: &mut Vec<u8>, c: &Commit) -> Result<(), MkitError> {
    buf.extend_from_slice(&c.tree_hash);
    write_u32_le(buf, checked_u32("commit.parents", c.parents.len())?);
    for p in &c.parents {
        buf.extend_from_slice(p);
    }
    write_identity(buf, &c.author)?;
    write_lp_bytes(buf, "commit.message", &c.message)?;
    write_u64_le(buf, c.timestamp);
    buf.extend_from_slice(&c.signer);
    buf.extend_from_slice(&c.message_hash);
    buf.extend_from_slice(&c.content_digest);
    buf.extend_from_slice(&c.signature);
    Ok(())
}

fn write_remix(buf: &mut Vec<u8>, r: &Remix) -> Result<(), MkitError> {
    buf.extend_from_slice(&r.tree_hash);
    write_u32_le(buf, checked_u32("remix.parents", r.parents.len())?);
    for p in &r.parents {
        buf.extend_from_slice(p);
    }
    write_u32_le(buf, checked_u32("remix.sources", r.sources.len())?);
    for s in &r.sources {
        buf.extend_from_slice(&s.upstream_id);
        buf.extend_from_slice(&s.commit_hash);
    }
    write_identity(buf, &r.author)?;
    write_lp_bytes(buf, "remix.message", &r.message)?;
    write_u64_le(buf, r.timestamp);
    buf.extend_from_slice(&r.signer);
    buf.extend_from_slice(&r.signature);
    Ok(())
}

/// Reject pack-only / non-storable target types. A tag MUST point at a
/// type that can live in the object store (`Delta` is pack-only).
fn check_tag_target_type(t: ObjectType) -> Result<(), MkitError> {
    if matches!(t, ObjectType::Delta) {
        return Err(MkitError::TagTargetTypeInvalid(t as u8));
    }
    Ok(())
}

fn write_tag(buf: &mut Vec<u8>, t: &Tag) -> Result<(), MkitError> {
    if !t.name_is_valid() {
        return Err(MkitError::TagNameInvalid);
    }
    check_tag_target_type(t.target_type)?;
    buf.extend_from_slice(&t.target);
    buf.push(t.target_type as u8);
    write_lp_bytes(buf, "tag.name", &t.name)?;
    write_identity(buf, &t.tagger)?;
    write_lp_bytes(buf, "tag.message", &t.message)?;
    write_u64_le(buf, t.timestamp);
    buf.extend_from_slice(&t.signer);
    buf.extend_from_slice(&t.signature);
    Ok(())
}

fn write_chunked_blob(buf: &mut Vec<u8>, cb: &ChunkedBlob) -> Result<(), MkitError> {
    write_u64_le(buf, cb.total_size);
    write_u32_le(buf, cb.chunk_size);
    write_u32_le(buf, checked_u32("chunked_blob.chunks", cb.chunks.len())?);
    for c in &cb.chunks {
        buf.extend_from_slice(c);
    }
    Ok(())
}

fn write_delta(buf: &mut Vec<u8>, d: &Delta) -> Result<(), MkitError> {
    buf.extend_from_slice(&d.base_hash);
    write_u32_le(buf, d.result_size);
    write_lp_bytes(buf, "delta.instructions", &d.instructions)
}

fn estimated_body_len(obj: &Object) -> usize {
    match obj {
        Object::Blob(b) => 4 + b.data.len(),
        Object::Tree(t) => {
            4 + t
                .entries
                .iter()
                .map(|e| 4 + e.name.len() + 1 + 32)
                .sum::<usize>()
        }
        Object::Commit(c) => {
            32 + 4
                + c.parents.len() * 32
                + 1
                + 2
                + c.author.bytes.len()
                + 4
                + c.message.len()
                + 8
                + 32
                + 32
                + 32
                + 64
        }
        Object::Remix(r) => {
            32 + 4
                + r.parents.len() * 32
                + 4
                + r.sources.len() * 64
                + 1
                + 2
                + r.author.bytes.len()
                + 4
                + r.message.len()
                + 8
                + 32
                + 64
        }
        Object::ChunkedBlob(cb) => 8 + 4 + 4 + cb.chunks.len() * 32,
        Object::Delta(d) => 32 + 4 + 4 + d.instructions.len(),
        Object::Tag(t) => {
            32 + 1
                + 4
                + t.name.len()
                + 1
                + 2
                + t.tagger.bytes.len()
                + 4
                + t.message.len()
                + 8
                + 32
                + 64
        }
    }
}

// ---------------------------------------------------------------------
// Reader
// ---------------------------------------------------------------------

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    fn need(&self, n: usize) -> Result<(), MkitError> {
        if self.remaining() < n {
            Err(MkitError::UnexpectedEof)
        } else {
            Ok(())
        }
    }

    fn read_u8(&mut self) -> Result<u8, MkitError> {
        self.need(1)?;
        let v = self.data[self.pos];
        self.pos += 1;
        Ok(v)
    }

    fn read_u16(&mut self) -> Result<u16, MkitError> {
        self.need(2)?;
        let mut a = [0u8; 2];
        a.copy_from_slice(&self.data[self.pos..self.pos + 2]);
        self.pos += 2;
        Ok(u16::from_le_bytes(a))
    }

    fn read_u32(&mut self) -> Result<u32, MkitError> {
        self.need(4)?;
        let mut a = [0u8; 4];
        a.copy_from_slice(&self.data[self.pos..self.pos + 4]);
        self.pos += 4;
        Ok(u32::from_le_bytes(a))
    }

    fn read_u64(&mut self) -> Result<u64, MkitError> {
        self.need(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(&self.data[self.pos..self.pos + 8]);
        self.pos += 8;
        Ok(u64::from_le_bytes(a))
    }

    fn read_hash(&mut self) -> Result<Hash, MkitError> {
        self.need(HASH_LEN)?;
        let mut h = [0u8; HASH_LEN];
        h.copy_from_slice(&self.data[self.pos..self.pos + HASH_LEN]);
        self.pos += HASH_LEN;
        Ok(h)
    }

    fn read_fixed<const N: usize>(&mut self) -> Result<[u8; N], MkitError> {
        self.need(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(&self.data[self.pos..self.pos + N]);
        self.pos += N;
        Ok(out)
    }

    fn read_lp_bytes(&mut self) -> Result<Vec<u8>, MkitError> {
        let len = self.read_u32()? as usize;
        self.need(len)?;
        let v = self.data[self.pos..self.pos + len].to_vec();
        self.pos += len;
        Ok(v)
    }

    fn read_identity(&mut self) -> Result<Identity, MkitError> {
        let kind = IdentityKind::from_u8(self.read_u8()?)?;
        let len = self.read_u16()?;
        if len == 0 {
            return Err(MkitError::InvalidIdentity);
        }
        if len > IDENTITY_MAX_LEN {
            return Err(MkitError::IdentityTooLarge);
        }
        match kind {
            IdentityKind::Ed25519 if len != 32 => return Err(MkitError::InvalidIdentity),
            _ => {}
        }
        let len = len as usize;
        self.need(len)?;
        let bytes = self.data[self.pos..self.pos + len].to_vec();
        self.pos += len;
        let id = Identity { kind, bytes };
        // Enforce the full structural invariant at the read boundary so a
        // malformed object from disk/remote can't deserialize with an
        // invalid payload (e.g. a binary `DidKey` that isn't a printable
        // multibase string). `is_valid` is the single source of truth and
        // the serialize side already gates on it (#223).
        if !id.is_valid() {
            return Err(MkitError::InvalidIdentity);
        }
        Ok(id)
    }
}

// ---------------------------------------------------------------------
// Readers
// ---------------------------------------------------------------------

fn read_blob(r: &mut Reader<'_>) -> Result<Blob, MkitError> {
    Ok(Blob {
        data: r.read_lp_bytes()?,
    })
}

fn read_tree(r: &mut Reader<'_>) -> Result<Tree, MkitError> {
    let count = r.read_u32()?;
    if count > MAX_TREE_ENTRIES {
        return Err(MkitError::TooManyEntries);
    }
    // Cheap upper bound: each entry is at least name_len(4) + mode(1) +
    // hash(32) = 37 bytes plus a 1-byte name. Reject impossible counts
    // before we allocate the entry vec.
    if (count as usize).saturating_mul(4 + 1 + 1 + HASH_LEN) > r.remaining() {
        return Err(MkitError::UnexpectedEof);
    }
    let mut entries = Vec::with_capacity(count as usize);
    let mut prev: Option<Vec<u8>> = None;
    for _ in 0..count {
        let name = r.read_lp_bytes()?;
        if !TreeEntry::validate_name(&name) {
            return Err(MkitError::InvalidEntryName);
        }
        if let Some(p) = &prev
            && p.as_slice() >= name.as_slice()
        {
            return Err(MkitError::InvalidEntryOrder);
        }
        let mode = EntryMode::from_u8(r.read_u8()?)?;
        let object_hash = r.read_hash()?;
        prev = Some(name.clone());
        entries.push(TreeEntry {
            name,
            mode,
            object_hash,
        });
    }
    Ok(Tree { entries })
}

fn read_commit(r: &mut Reader<'_>) -> Result<Commit, MkitError> {
    let tree_hash = r.read_hash()?;
    let parent_count = r.read_u32()?;
    if parent_count > MAX_PARENTS {
        return Err(MkitError::TooManyParents);
    }
    // Cheap upper bound: each parent is HASH_LEN bytes on the wire. If
    // the remaining buffer can't even hold the parent hashes, the
    // header is lying and we must not pre-allocate for it.
    if (parent_count as usize).saturating_mul(HASH_LEN) > r.remaining() {
        return Err(MkitError::UnexpectedEof);
    }
    let mut parents = Vec::with_capacity(parent_count as usize);
    for _ in 0..parent_count {
        parents.push(r.read_hash()?);
    }
    let author = r.read_identity()?;
    let message = r.read_lp_bytes()?;
    let timestamp = r.read_u64()?;
    let signer = r.read_fixed::<32>()?;
    let message_hash = r.read_hash()?;
    let content_digest = r.read_hash()?;
    let signature = r.read_fixed::<64>()?;
    Ok(Commit {
        tree_hash,
        parents,
        author,
        signer,
        message,
        timestamp,
        message_hash,
        content_digest,
        signature,
    })
}

fn read_remix(r: &mut Reader<'_>) -> Result<Remix, MkitError> {
    let tree_hash = r.read_hash()?;
    let parent_count = r.read_u32()?;
    if parent_count > MAX_PARENTS {
        return Err(MkitError::TooManyParents);
    }
    // Cheap upper bound: each parent is HASH_LEN bytes on the wire.
    if (parent_count as usize).saturating_mul(HASH_LEN) > r.remaining() {
        return Err(MkitError::UnexpectedEof);
    }
    let mut parents = Vec::with_capacity(parent_count as usize);
    for _ in 0..parent_count {
        parents.push(r.read_hash()?);
    }
    let source_count = r.read_u32()?;
    if source_count > MAX_REMIX_SOURCES {
        return Err(MkitError::TooManySources);
    }
    // Each source is two hashes (upstream_id + commit_hash) = 2 *
    // HASH_LEN bytes. Reject impossible counts before allocating.
    if (source_count as usize).saturating_mul(2 * HASH_LEN) > r.remaining() {
        return Err(MkitError::UnexpectedEof);
    }
    let mut sources = Vec::with_capacity(source_count as usize);
    for _ in 0..source_count {
        let upstream_id = r.read_hash()?;
        let commit_hash = r.read_hash()?;
        sources.push(RemixSource {
            upstream_id,
            commit_hash,
        });
    }
    let author = r.read_identity()?;
    let message = r.read_lp_bytes()?;
    let timestamp = r.read_u64()?;
    let signer = r.read_fixed::<32>()?;
    let signature = r.read_fixed::<64>()?;
    // Sort check: strict ascending by (upstream_id, commit_hash).
    if sources.len() > 1 {
        for w in sources.windows(2) {
            let a = &w[0];
            let b = &w[1];
            let bad = match a.upstream_id.cmp(&b.upstream_id) {
                core::cmp::Ordering::Greater => true,
                core::cmp::Ordering::Equal => a.commit_hash >= b.commit_hash,
                core::cmp::Ordering::Less => false,
            };
            if bad {
                return Err(MkitError::InvalidSourceOrder);
            }
        }
    }
    Ok(Remix {
        tree_hash,
        parents,
        sources,
        author,
        signer,
        message,
        timestamp,
        signature,
    })
}

fn read_tag(r: &mut Reader<'_>) -> Result<Tag, MkitError> {
    let target = r.read_hash()?;
    let target_type = ObjectType::from_u8(r.read_u8()?)?;
    check_tag_target_type(target_type)?;
    // `name` is length-prefixed; bound it by TAG_NAME_MAX_LEN before we
    // copy so a bogus header can't force a large allocation.
    let name_len = r.read_u32()? as usize;
    if name_len == 0 || name_len > TAG_NAME_MAX_LEN as usize {
        return Err(MkitError::TagNameInvalid);
    }
    r.need(name_len)?;
    let name = r.data[r.pos..r.pos + name_len].to_vec();
    r.pos += name_len;
    if name.iter().any(|&b| matches!(b, 0 | b'/' | b'\\')) {
        return Err(MkitError::TagNameInvalid);
    }
    let tagger = r.read_identity()?;
    let message = r.read_lp_bytes()?;
    let timestamp = r.read_u64()?;
    let signer = r.read_fixed::<32>()?;
    let signature = r.read_fixed::<64>()?;
    Ok(Tag {
        target,
        target_type,
        name,
        tagger,
        signer,
        message,
        timestamp,
        signature,
    })
}

fn read_chunked_blob(r: &mut Reader<'_>) -> Result<ChunkedBlob, MkitError> {
    let total_size = r.read_u64()?;
    let chunk_size = r.read_u32()?;
    let chunk_count = r.read_u32()?;
    if chunk_count > MAX_CHUNKS {
        return Err(MkitError::TooManyChunks);
    }
    if (chunk_count as usize).saturating_mul(HASH_LEN) > r.remaining() {
        return Err(MkitError::UnexpectedEof);
    }
    let mut chunks = Vec::with_capacity(chunk_count as usize);
    for _ in 0..chunk_count {
        chunks.push(r.read_hash()?);
    }
    Ok(ChunkedBlob {
        total_size,
        chunk_size,
        chunks,
    })
}

fn read_delta(r: &mut Reader<'_>) -> Result<Delta, MkitError> {
    let base_hash = r.read_hash()?;
    let result_size = r.read_u32()?;
    let instructions = r.read_lp_bytes()?;
    Ok(Delta {
        base_hash,
        result_size,
        instructions,
    })
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::{ZERO, hash};
    use proptest::prelude::*;

    fn ed25519_id() -> Identity {
        Identity::ed25519([0xAA; 32])
    }

    proptest! {
        /// `blob_prologue(len) ‖ payload` must be byte-identical to
        /// `serialize(Object::Blob(payload))` — the zero-copy chunk
        /// write path depends on this equivalence, which transitively
        /// pins it to the golden blob vectors.
        #[test]
        fn blob_prologue_plus_payload_equals_serialize_blob(
            payload in proptest::collection::vec(any::<u8>(), 0..2048)
        ) {
            let via_serialize = serialize(&Object::Blob(Blob {
                data: payload.clone(),
            })).unwrap();
            let header = blob_prologue(payload.len()).unwrap();
            let mut via_parts = header.to_vec();
            via_parts.extend_from_slice(&payload);
            prop_assert_eq!(via_parts, via_serialize);
        }
    }

    #[test]
    fn blob_prologue_rejects_oversize_len() {
        assert!(blob_prologue(u32::MAX as usize + 1).is_err());
        assert!(blob_prologue(0).is_ok());
    }

    #[test]
    fn blob_roundtrip() {
        let obj = Object::Blob(Blob {
            data: b"hello world".to_vec(),
        });
        let bytes = serialize(&obj).expect("valid blob serialises");
        // Prologue
        assert_eq!(bytes[0], 0x01);
        assert_eq!(&bytes[1..5], b"MKT1");
        assert_eq!(bytes[5], 0x01);
        let parsed = deserialize(&bytes).unwrap();
        assert_eq!(obj, parsed);
    }

    #[test]
    fn empty_blob_size_is_10() {
        let obj = Object::Blob(Blob { data: vec![] });
        let bytes = serialize(&obj).unwrap();
        assert_eq!(bytes.len(), 10);
        assert_eq!(deserialize(&bytes).unwrap(), obj);
    }

    #[test]
    fn empty_tree_roundtrip() {
        let obj = Object::Tree(Tree { entries: vec![] });
        let bytes = serialize(&obj).unwrap();
        assert_eq!(deserialize(&bytes).unwrap(), obj);
    }

    #[test]
    fn tree_with_three_entries_roundtrip() {
        let obj = Object::Tree(Tree {
            entries: vec![
                TreeEntry {
                    name: b"alpha".to_vec(),
                    mode: EntryMode::Blob,
                    object_hash: hash(b"a"),
                },
                TreeEntry {
                    name: b"beta".to_vec(),
                    mode: EntryMode::Tree,
                    object_hash: hash(b"b"),
                },
                TreeEntry {
                    name: b"gamma".to_vec(),
                    mode: EntryMode::Executable,
                    object_hash: hash(b"g"),
                },
            ],
        });
        assert_eq!(deserialize(&serialize(&obj).unwrap()).unwrap(), obj);
    }

    #[test]
    fn commit_with_one_parent_roundtrip() {
        let obj = Object::Commit(Commit::new_unannotated(
            hash(b"tree"),
            vec![hash(b"parent")],
            ed25519_id(),
            [0xAA; 32],
            b"initial".to_vec(),
            1_711_300_000,
            [0xBB; 64],
        ));
        assert_eq!(deserialize(&serialize(&obj).unwrap()).unwrap(), obj);
    }

    #[test]
    fn root_commit_roundtrip() {
        let obj = Object::Commit(Commit::new_unannotated(
            hash(b"tree"),
            vec![],
            ed25519_id(),
            [0x11; 32],
            b"genesis".to_vec(),
            1_000_000,
            [0x22; 64],
        ));
        assert_eq!(deserialize(&serialize(&obj).unwrap()).unwrap(), obj);
    }

    #[test]
    fn commit_with_opaque_identity_roundtrip() {
        let mid = vec![42u8, 0, 0, 0, 0, 0, 0, 0];
        let obj = Object::Commit(Commit::new_unannotated(
            hash(b"tree"),
            vec![],
            Identity::opaque(mid.clone()),
            [0xAA; 32],
            b"opaque author".to_vec(),
            1_700_000_000,
            [0xBB; 64],
        ));
        let parsed = deserialize(&serialize(&obj).unwrap()).unwrap();
        if let Object::Commit(c) = &parsed {
            assert_eq!(c.author.kind, IdentityKind::Opaque);
            assert_eq!(c.author.bytes, mid);
        } else {
            panic!("not a commit");
        }
        assert_eq!(parsed, obj);
    }

    #[test]
    fn remix_with_one_source_roundtrip() {
        let obj = Object::Remix(Remix {
            tree_hash: hash(b"tree"),
            parents: vec![],
            sources: vec![RemixSource {
                upstream_id: hash(b"project-a"),
                commit_hash: hash(b"commit-x"),
            }],
            author: ed25519_id(),
            signer: [0xCC; 32],
            message: b"remixed".to_vec(),
            timestamp: 1_711_300_100,
            signature: [0xDD; 64],
        });
        assert_eq!(deserialize(&serialize(&obj).unwrap()).unwrap(), obj);
    }

    #[test]
    fn chunked_blob_roundtrip() {
        let obj = Object::ChunkedBlob(ChunkedBlob {
            total_size: 3 * 65536,
            chunk_size: 65536,
            chunks: vec![hash(b"c1"), hash(b"c2"), hash(b"c3")],
        });
        let bytes = serialize(&obj).unwrap();
        assert_eq!(bytes[0], 0x05);
        assert_eq!(deserialize(&bytes).unwrap(), obj);
    }

    #[test]
    fn chunked_blob_cdc_marker_roundtrips() {
        let obj = Object::ChunkedBlob(ChunkedBlob {
            total_size: 100_000,
            chunk_size: 0,
            chunks: vec![hash(b"x"), hash(b"y")],
        });
        assert_eq!(deserialize(&serialize(&obj).unwrap()).unwrap(), obj);
    }

    fn sample_tag() -> Tag {
        Tag {
            target: hash(b"target-commit"),
            target_type: ObjectType::Commit,
            name: b"v1.0.0".to_vec(),
            tagger: ed25519_id(),
            signer: [0xAA; 32],
            message: b"release 1.0.0".to_vec(),
            timestamp: 1_711_300_000,
            signature: [0xCC; 64],
        }
    }

    #[test]
    fn tag_roundtrip() {
        let obj = Object::Tag(sample_tag());
        let bytes = serialize(&obj).unwrap();
        assert_eq!(bytes[0], 0x07, "tag object_type tag");
        assert_eq!(&bytes[1..5], b"MKT1");
        assert_eq!(bytes[5], 0x01);
        assert_eq!(deserialize(&bytes).unwrap(), obj);
    }

    #[test]
    fn tag_empty_message_roundtrip() {
        let mut t = sample_tag();
        t.message = vec![];
        let obj = Object::Tag(t);
        assert_eq!(deserialize(&serialize(&obj).unwrap()).unwrap(), obj);
    }

    #[test]
    fn tag_rejects_empty_name() {
        let mut t = sample_tag();
        t.name = vec![];
        assert_eq!(serialize(&Object::Tag(t)), Err(MkitError::TagNameInvalid));
    }

    #[test]
    fn tag_rejects_delta_target_type() {
        let mut t = sample_tag();
        t.target_type = ObjectType::Delta;
        assert_eq!(
            serialize(&Object::Tag(t)),
            Err(MkitError::TagTargetTypeInvalid(ObjectType::Delta as u8))
        );
    }

    #[test]
    fn tag_decode_rejects_forbidden_name_byte() {
        // Hand-craft a tag whose name embeds a `/`. The writer would
        // reject it, so build the wire bytes directly.
        let mut buf = vec![0x07, b'M', b'K', b'T', b'1', 0x01];
        buf.extend_from_slice(&[0u8; 32]); // target
        buf.push(ObjectType::Commit as u8); // target_type
        buf.extend_from_slice(&3u32.to_le_bytes()); // name_len
        buf.extend_from_slice(b"a/b");
        assert_eq!(deserialize(&buf), Err(MkitError::TagNameInvalid));
    }

    // ---- Negative tests ----

    #[test]
    fn deserialize_empty_input() {
        assert_eq!(deserialize(&[]), Err(MkitError::EmptyData));
    }

    #[test]
    fn rejects_invalid_object_type() {
        let bad = [0xFF, b'M', b'K', b'T', b'1', 0x01];
        assert_eq!(deserialize(&bad), Err(MkitError::InvalidObjectType(0xFF)));
    }

    #[test]
    fn rejects_bad_magic() {
        let bad = [0x01, b'X', b'Y', b'Z', b'W', 0x01, 0, 0, 0, 0];
        assert_eq!(deserialize(&bad), Err(MkitError::InvalidMagic));
    }

    #[test]
    fn rejects_unsupported_schema_version() {
        let bad = [0x01, b'M', b'K', b'T', b'1', 0x02, 0, 0, 0, 0];
        assert_eq!(deserialize(&bad), Err(MkitError::UnsupportedObjectVersion));
    }

    #[test]
    fn rejects_truncated_blob() {
        // length=100 but only 2 bytes follow
        let bad = [
            0x01, b'M', b'K', b'T', b'1', 0x01, 0x64, 0x00, 0x00, 0x00, 0xAA, 0xBB,
        ];
        assert_eq!(deserialize(&bad), Err(MkitError::UnexpectedEof));
    }

    #[test]
    fn rejects_unsorted_tree_entries() {
        // Build an unsorted tree by hand — can't go through serialize()
        // because writers don't validate ordering today.
        let mut buf = vec![0x02, b'M', b'K', b'T', b'1', 0x01];
        buf.extend_from_slice(&2u32.to_le_bytes());
        // entry "z.txt"
        buf.extend_from_slice(&5u32.to_le_bytes());
        buf.extend_from_slice(b"z.txt");
        buf.push(EntryMode::Blob as u8);
        buf.extend_from_slice(&[0u8; 32]);
        // entry "a.txt"
        buf.extend_from_slice(&5u32.to_le_bytes());
        buf.extend_from_slice(b"a.txt");
        buf.push(EntryMode::Blob as u8);
        buf.extend_from_slice(&[0u8; 32]);
        assert_eq!(deserialize(&buf), Err(MkitError::InvalidEntryOrder));
    }

    #[test]
    fn rejects_trailing_bytes() {
        let obj = Object::Blob(Blob {
            data: b"hello".to_vec(),
        });
        let mut bytes = serialize(&obj).unwrap();
        bytes.push(0xFF);
        assert_eq!(deserialize(&bytes), Err(MkitError::TrailingData));
    }

    #[test]
    fn rejects_zero_length_identity() {
        let mut buf = vec![0x03, b'M', b'K', b'T', b'1', 0x01];
        buf.extend_from_slice(&[0u8; 32]); // tree_hash
        buf.extend_from_slice(&0u32.to_le_bytes()); // parent_count
        buf.push(IdentityKind::Opaque as u8);
        buf.extend_from_slice(&0u16.to_le_bytes()); // len = 0
        assert_eq!(deserialize(&buf), Err(MkitError::InvalidIdentity));
    }

    #[test]
    fn rejects_unknown_identity_kind() {
        let mut buf = vec![0x03, b'M', b'K', b'T', b'1', 0x01];
        buf.extend_from_slice(&[0u8; 32]);
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.push(0xEE); // unknown kind
        buf.extend_from_slice(&4u16.to_le_bytes());
        buf.extend_from_slice(b"xxxx");
        assert_eq!(deserialize(&buf), Err(MkitError::UnknownIdentityKind(0xEE)));
    }

    #[test]
    fn rejects_ed25519_with_wrong_length() {
        let mut buf = vec![0x03, b'M', b'K', b'T', b'1', 0x01];
        buf.extend_from_slice(&[0u8; 32]);
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.push(IdentityKind::Ed25519 as u8);
        buf.extend_from_slice(&8u16.to_le_bytes());
        buf.extend_from_slice(b"12345678");
        assert_eq!(deserialize(&buf), Err(MkitError::InvalidIdentity));
    }

    #[test]
    fn rejects_oversize_identity() {
        let mut buf = vec![0x03, b'M', b'K', b'T', b'1', 0x01];
        buf.extend_from_slice(&[0u8; 32]);
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.push(IdentityKind::Opaque as u8);
        buf.extend_from_slice(&(IDENTITY_MAX_LEN + 1).to_le_bytes());
        buf.extend(core::iter::repeat_n(0u8, IDENTITY_MAX_LEN as usize + 1));
        assert_eq!(deserialize(&buf), Err(MkitError::IdentityTooLarge));
    }

    #[test]
    fn rejects_too_many_tree_entries() {
        let mut buf = vec![0x02, b'M', b'K', b'T', b'1', 0x01];
        buf.extend_from_slice(&(MAX_TREE_ENTRIES + 1).to_le_bytes());
        assert_eq!(deserialize(&buf), Err(MkitError::TooManyEntries));
    }

    #[test]
    fn rejects_truncated_chunk_list() {
        let mut buf = vec![0x05, b'M', b'K', b'T', b'1', 0x01];
        buf.extend_from_slice(&1024u64.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&2u32.to_le_bytes()); // chunk_count = 2
        buf.extend_from_slice(&[0xAA; 32]); // only one chunk
        assert_eq!(deserialize(&buf), Err(MkitError::UnexpectedEof));
    }

    // ---- Fallible-serialize tests (review follow-up #22) ----

    #[test]
    fn serialize_rejects_invalid_identity_in_commit() {
        // Empty payload is structurally invalid for every kind.
        let bad_id = Identity {
            kind: IdentityKind::Opaque,
            bytes: Vec::new(),
        };
        let obj = Object::Commit(Commit::new_unannotated(
            hash(b"tree"),
            vec![],
            bad_id,
            [0; 32],
            b"x".to_vec(),
            0,
            [0; 64],
        ));
        assert_eq!(serialize(&obj), Err(MkitError::InvalidIdentity));
    }

    #[test]
    fn read_identity_rejects_non_multibase_didkey() {
        // Wire format: [u8 kind][u16 LE len][payload]. A DidKey payload must
        // be a printable-ASCII multibase string, so a malformed object with a
        // binary/whitespace DidKey payload must be rejected at the read
        // boundary, not silently deserialized (#223).
        let id_bytes = |payload: &[u8]| {
            let mut b = vec![0x02u8]; // IdentityKind::DidKey
            let len = u16::try_from(payload.len()).expect("test payload fits u16");
            b.extend_from_slice(&len.to_le_bytes());
            b.extend_from_slice(payload);
            b
        };
        // NUL, high byte, and whitespace payloads all reject.
        for bad in [b"z\x00ab".as_slice(), b"z\xff", b"z6Mk has space"] {
            let buf = id_bytes(bad);
            assert_eq!(
                Reader::new(&buf).read_identity(),
                Err(MkitError::InvalidIdentity),
                "should reject DidKey payload {bad:?} at the read boundary"
            );
        }
        // A real did:key multibase payload round-trips.
        let good = id_bytes(b"z6MkExample");
        let id = Reader::new(&good).read_identity().unwrap();
        assert_eq!(id.kind, IdentityKind::DidKey);
        assert_eq!(id.bytes, b"z6MkExample");
    }

    #[test]
    fn serialize_rejects_invalid_identity_in_remix() {
        // Ed25519 with non-32-byte payload.
        let bad_id = Identity {
            kind: IdentityKind::Ed25519,
            bytes: vec![0u8; 16],
        };
        let obj = Object::Remix(Remix {
            tree_hash: ZERO,
            parents: vec![],
            sources: vec![],
            author: bad_id,
            signer: [0; 32],
            message: b"x".to_vec(),
            timestamp: 0,
            signature: [0; 64],
        });
        assert_eq!(serialize(&obj), Err(MkitError::InvalidIdentity));
    }

    /// `read_commit` claims `parent_count = MAX_PARENTS` (`1_000`) but
    /// the remaining buffer is too small to ever hold that many
    /// 32-byte parent hashes. The pre-allocation guard must reject the
    /// header before the parent vec is sized from attacker input.
    #[test]
    fn rejects_truncated_commit_parents() {
        let mut buf = vec![0x03, b'M', b'K', b'T', b'1', 0x01];
        buf.extend_from_slice(&[0u8; 32]); // tree_hash
        // Within MAX_PARENTS (1_000) so the existing TooManyParents
        // guard doesn't fire — we want to confirm the capacity-vs-
        // remaining check rejects too. 1_000 parents = 32_000 bytes,
        // but only a single 32-byte hash follows.
        buf.extend_from_slice(&1_000u32.to_le_bytes()); // parent_count
        buf.extend_from_slice(&[0xAA; 32]); // only one parent worth
        assert_eq!(deserialize(&buf), Err(MkitError::UnexpectedEof));
    }

    /// `read_remix` claims `source_count = MAX_REMIX_SOURCES` (`10_000`)
    /// but the remaining buffer cannot accommodate even one source
    /// (which is 64 bytes — two hashes). Reject without allocating.
    #[test]
    fn rejects_truncated_remix_sources() {
        let mut buf = vec![0x04, b'M', b'K', b'T', b'1', 0x01];
        buf.extend_from_slice(&[0u8; 32]); // tree_hash
        buf.extend_from_slice(&0u32.to_le_bytes()); // parent_count
        // 10_000 sources × 64 bytes = 640_000 bytes required, but the
        // buffer is empty after this point.
        buf.extend_from_slice(&10_000u32.to_le_bytes()); // source_count
        assert_eq!(deserialize(&buf), Err(MkitError::UnexpectedEof));
    }

    #[test]
    fn rejects_too_many_commit_parents() {
        let mut buf = vec![0x03, b'M', b'K', b'T', b'1', 0x01];
        buf.extend_from_slice(&[0u8; 32]); // tree_hash
        buf.extend_from_slice(&(MAX_PARENTS + 1).to_le_bytes()); // parent_count
        assert_eq!(deserialize(&buf), Err(MkitError::TooManyParents));
    }

    #[test]
    fn rejects_too_many_remix_parents() {
        let mut buf = vec![0x04, b'M', b'K', b'T', b'1', 0x01];
        buf.extend_from_slice(&[0u8; 32]); // tree_hash
        buf.extend_from_slice(&(MAX_PARENTS + 1).to_le_bytes()); // parent_count
        assert_eq!(deserialize(&buf), Err(MkitError::TooManyParents));
    }

    #[test]
    fn rejects_too_many_remix_sources() {
        let mut buf = vec![0x04, b'M', b'K', b'T', b'1', 0x01];
        buf.extend_from_slice(&[0u8; 32]); // tree_hash
        buf.extend_from_slice(&0u32.to_le_bytes()); // parent_count
        buf.extend_from_slice(&(MAX_REMIX_SOURCES + 1).to_le_bytes()); // source_count
        assert_eq!(deserialize(&buf), Err(MkitError::TooManySources));
    }

    #[test]
    fn rejects_too_many_chunks() {
        let mut buf = vec![0x05, b'M', b'K', b'T', b'1', 0x01];
        buf.extend_from_slice(&1024u64.to_le_bytes()); // total_size
        buf.extend_from_slice(&0u32.to_le_bytes()); // chunk_size
        buf.extend_from_slice(&(MAX_CHUNKS + 1).to_le_bytes()); // chunk_count
        assert_eq!(deserialize(&buf), Err(MkitError::TooManyChunks));
    }

    #[test]
    fn rejects_remix_out_of_order_sources() {
        // read_remix's decode-path sort check: sources must be strictly
        // ascending by (upstream_id, commit_hash) (SPEC-OBJECTS remix
        // source ordering). The encoder (write_remix) does not itself
        // sort or validate — it trusts the caller — so a decode-path
        // regression here would only be caught by feeding a crafted
        // (but encoder-producible) out-of-order Remix through
        // `serialize` + `deserialize`, not by round-tripping a
        // well-formed one.
        let sources = vec![
            RemixSource {
                upstream_id: [2u8; 32],
                commit_hash: [0u8; 32],
            },
            RemixSource {
                upstream_id: [1u8; 32], // decreases -> violates strict ascending order
                commit_hash: [0u8; 32],
            },
        ];
        let remix = Remix {
            tree_hash: hash(b"tree"),
            parents: vec![],
            sources,
            author: Identity::ed25519([0u8; 32]),
            signer: [0u8; 32],
            message: b"msg".to_vec(),
            timestamp: 0,
            signature: [0u8; 64],
        };
        let bytes = serialize(&Object::Remix(remix)).unwrap();
        assert_eq!(deserialize(&bytes), Err(MkitError::InvalidSourceOrder));
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn checked_u32_rejects_oversize() {
        // Direct unit test on the bounds helper — we cannot allocate a
        // Vec with > u32::MAX entries in a unit test, so exercise the
        // guard surface itself. This pins the field-name string so
        // downstream consumers can grep on it. 32-bit targets cannot
        // even construct `n`, so the test is gated on pointer width.
        let n: usize = u32::MAX as usize + 1;
        let err = checked_u32("blob.data", n).unwrap_err();
        assert_eq!(
            err,
            MkitError::OversizePayload {
                field: "blob.data",
                len: n,
            }
        );
    }

    // -- Property tests -------------------------------------------------
    //
    // Round-trip invariants exercised against arbitrary inputs via
    // `proptest`. The example tests above cover specific vectors and
    // the goldens pin wire bytes; the properties below catch the
    // boundary cases the examples miss (empty payloads, max-length
    // strings, non-ASCII bytes, etc.).
    proptest::proptest! {
        /// Any blob round-trips byte-for-byte through serialize/deserialize.
        #[test]
        fn proptest_blob_roundtrip(data in proptest::collection::vec(proptest::num::u8::ANY, 0..4096)) {
            let obj = Object::Blob(Blob { data });
            let bytes = serialize(&obj).expect("blob serialises");
            let parsed = deserialize(&bytes).expect("blob deserialises");
            proptest::prop_assert_eq!(obj, parsed);
        }

        /// Any commit (single parent, fixed identity) round-trips
        /// byte-for-byte. Covers arbitrary tree hashes, arbitrary parent
        /// hashes, arbitrary message bytes including non-UTF-8 sequences
        /// (commit messages are bytes per SPEC-OBJECTS §5). Signer + sig
        /// arrays are constructed from a u8 seed (proptest only ships
        /// `uniform32` natively; 64-byte signatures get a tiled seed).
        #[test]
        fn proptest_commit_roundtrip(
            tree in proptest::array::uniform32(proptest::num::u8::ANY),
            parent in proptest::array::uniform32(proptest::num::u8::ANY),
            signer in proptest::array::uniform32(proptest::num::u8::ANY),
            msg in proptest::collection::vec(proptest::num::u8::ANY, 0..2048),
            sig_seed in proptest::num::u8::ANY,
            ts in 0u64..u64::from(u32::MAX),
        ) {
            let mut sig = [0u8; 64];
            sig.fill(sig_seed);
            let commit = Commit::new_unannotated(
                tree,
                vec![parent],
                ed25519_id(),
                signer,
                msg,
                ts,
                sig,
            );
            let obj = Object::Commit(commit);
            let bytes = serialize(&obj).expect("commit serialises");
            let parsed = deserialize(&bytes).expect("commit deserialises");
            proptest::prop_assert_eq!(obj, parsed);
        }
    }
}
