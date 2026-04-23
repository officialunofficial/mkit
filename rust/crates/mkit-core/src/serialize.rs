//! Canonical byte (de)serialization for [`Object`].
//!
//! Spec: `docs/SPEC-OBJECTS.md`. The byte layout produced here MUST be
//! byte-for-byte identical to the Zig reference in `src/serialize.zig`
//! — that contract is enforced by the golden-vector tests in
//! `tests/golden.rs`.
//!
//! Every deserializer:
//! * Validates the 6-byte v1 prologue first.
//! * Enforces per-type bounds (entry counts, identity len, etc.).
//! * Rejects non-empty trailing bytes via [`MkitError::TrailingData`].

use crate::hash::{HASH_LEN, Hash};
use crate::object::{
    Blob, ChunkedBlob, Commit, Delta, EntryMode, IDENTITY_MAX_LEN, Identity, IdentityKind, MAGIC,
    MkitError, Object, ObjectType, Remix, RemixSource, SCHEMA_VERSION, Tree, TreeEntry,
};

const PROLOGUE_LEN: usize = 6;

const MAX_TREE_ENTRIES: u32 = 1_000_000;
const MAX_PARENTS: u32 = 1_000;
const MAX_REMIX_SOURCES: u32 = 10_000;
const MAX_CHUNKS: u32 = 1_000_000;

// ---------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------

/// Serialize an [`Object`] to its canonical byte form. Allocates fresh
/// each call; the result is fully owned.
#[must_use]
pub fn serialize(obj: &Object) -> Vec<u8> {
    let mut buf = Vec::with_capacity(PROLOGUE_LEN + estimated_body_len(obj));
    write_prologue(&mut buf, obj.object_type());
    match obj {
        Object::Blob(b) => write_blob(&mut buf, b),
        Object::Tree(t) => write_tree(&mut buf, t),
        Object::Commit(c) => write_commit(&mut buf, c),
        Object::Remix(r) => write_remix(&mut buf, r),
        Object::ChunkedBlob(cb) => write_chunked_blob(&mut buf, cb),
        Object::Delta(d) => write_delta(&mut buf, d),
    }
    buf
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

fn write_lp_bytes(buf: &mut Vec<u8>, data: &[u8]) {
    write_u32_le(buf, u32::try_from(data.len()).expect("len fits in u32"));
    buf.extend_from_slice(data);
}

fn write_identity(buf: &mut Vec<u8>, id: &Identity) {
    debug_assert!(id.is_valid(), "writers expect valid identities");
    buf.push(id.kind as u8);
    write_u16_le(buf, u16::try_from(id.bytes.len()).expect("len fits in u16"));
    buf.extend_from_slice(&id.bytes);
}

fn write_blob(buf: &mut Vec<u8>, b: &Blob) {
    write_lp_bytes(buf, &b.data);
}

fn write_tree(buf: &mut Vec<u8>, t: &Tree) {
    write_u32_le(
        buf,
        u32::try_from(t.entries.len()).expect("len fits in u32"),
    );
    for e in &t.entries {
        write_lp_bytes(buf, &e.name);
        buf.push(e.mode as u8);
        buf.extend_from_slice(&e.object_hash);
    }
}

fn write_commit(buf: &mut Vec<u8>, c: &Commit) {
    buf.extend_from_slice(&c.tree_hash);
    write_u32_le(
        buf,
        u32::try_from(c.parents.len()).expect("len fits in u32"),
    );
    for p in &c.parents {
        buf.extend_from_slice(p);
    }
    write_identity(buf, &c.author);
    write_lp_bytes(buf, &c.message);
    write_u64_le(buf, c.timestamp);
    buf.extend_from_slice(&c.signer);
    buf.extend_from_slice(&c.message_hash);
    buf.extend_from_slice(&c.content_digest);
    buf.extend_from_slice(&c.signature);
}

fn write_remix(buf: &mut Vec<u8>, r: &Remix) {
    buf.extend_from_slice(&r.tree_hash);
    write_u32_le(
        buf,
        u32::try_from(r.parents.len()).expect("len fits in u32"),
    );
    for p in &r.parents {
        buf.extend_from_slice(p);
    }
    write_u32_le(
        buf,
        u32::try_from(r.sources.len()).expect("len fits in u32"),
    );
    for s in &r.sources {
        buf.extend_from_slice(&s.upstream_id);
        buf.extend_from_slice(&s.commit_hash);
    }
    write_identity(buf, &r.author);
    write_lp_bytes(buf, &r.message);
    write_u64_le(buf, r.timestamp);
    buf.extend_from_slice(&r.signer);
    buf.extend_from_slice(&r.signature);
}

fn write_chunked_blob(buf: &mut Vec<u8>, cb: &ChunkedBlob) {
    write_u64_le(buf, cb.total_size);
    write_u32_le(buf, cb.chunk_size);
    write_u32_le(
        buf,
        u32::try_from(cb.chunks.len()).expect("len fits in u32"),
    );
    for c in &cb.chunks {
        buf.extend_from_slice(c);
    }
}

fn write_delta(buf: &mut Vec<u8>, d: &Delta) {
    buf.extend_from_slice(&d.base_hash);
    write_u32_le(buf, d.result_size);
    write_lp_bytes(buf, &d.instructions);
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
        Ok(Identity { kind, bytes })
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
    let mut parents = Vec::with_capacity(parent_count as usize);
    for _ in 0..parent_count {
        parents.push(r.read_hash()?);
    }
    let source_count = r.read_u32()?;
    if source_count > MAX_REMIX_SOURCES {
        return Err(MkitError::TooManySources);
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
    // Sort check matches src/serialize.zig: strict ascending by
    // (upstream_id, commit_hash).
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

    fn ed25519_id() -> Identity {
        Identity::ed25519([0xAA; 32])
    }

    #[test]
    fn blob_roundtrip() {
        let obj = Object::Blob(Blob {
            data: b"hello world".to_vec(),
        });
        let bytes = serialize(&obj);
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
        let bytes = serialize(&obj);
        assert_eq!(bytes.len(), 10);
        assert_eq!(deserialize(&bytes).unwrap(), obj);
    }

    #[test]
    fn empty_tree_roundtrip() {
        let obj = Object::Tree(Tree { entries: vec![] });
        let bytes = serialize(&obj);
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
        assert_eq!(deserialize(&serialize(&obj)).unwrap(), obj);
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
        assert_eq!(deserialize(&serialize(&obj)).unwrap(), obj);
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
        assert_eq!(deserialize(&serialize(&obj)).unwrap(), obj);
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
        let parsed = deserialize(&serialize(&obj)).unwrap();
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
        assert_eq!(deserialize(&serialize(&obj)).unwrap(), obj);
    }

    #[test]
    fn chunked_blob_roundtrip() {
        let obj = Object::ChunkedBlob(ChunkedBlob {
            total_size: 3 * 65536,
            chunk_size: 65536,
            chunks: vec![hash(b"c1"), hash(b"c2"), hash(b"c3")],
        });
        let bytes = serialize(&obj);
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
        assert_eq!(deserialize(&serialize(&obj)).unwrap(), obj);
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
        let mut bytes = serialize(&obj);
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

    #[test]
    fn deterministic_serialization() {
        let obj = Object::Blob(Blob {
            data: b"deterministic".to_vec(),
        });
        let a = serialize(&obj);
        let b = serialize(&obj);
        assert_eq!(a, b);
        assert_eq!(hash(&a), hash(&b));
        // Ensure hash() and ZERO are linked correctly — silly sanity.
        assert_ne!(a, vec![0u8; a.len()]);
        let _ = ZERO;
    }
}
