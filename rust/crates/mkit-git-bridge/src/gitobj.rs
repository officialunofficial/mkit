//! git object encoding: `SHA1("<type> <len>\0" || body)` ids and
//! zlib loose-object storage (SPEC-GIT-BRIDGE §2).

use crate::error::BridgeError;
use flate2::Compression;
use flate2::write::ZlibEncoder;
use sha1::{Digest, Sha1};
use std::io::Write as _;
use std::path::{Path, PathBuf};

/// 20-byte git object id.
pub type Sha1Id = [u8; 20];

/// The four storable git object types the bridge emits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GitType {
    Blob,
    Tree,
    Commit,
    Tag,
}

impl GitType {
    /// The ASCII type name used in the object header.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Blob => "blob",
            Self::Tree => "tree",
            Self::Commit => "commit",
            Self::Tag => "tag",
        }
    }

    /// Parse a git object-header type name.
    #[must_use]
    pub fn from_name(name: &[u8]) -> Option<Self> {
        Some(match name {
            b"blob" => Self::Blob,
            b"tree" => Self::Tree,
            b"commit" => Self::Commit,
            b"tag" => Self::Tag,
            _ => return None,
        })
    }
}

/// An encoded git object: type + body (the bytes after the
/// `"<type> <len>\0"` header).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitObject {
    pub gtype: GitType,
    pub body: Vec<u8>,
}

impl GitObject {
    /// The full header+body byte string the id is computed over.
    #[must_use]
    pub fn raw(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.gtype.name().len() + 12 + self.body.len());
        out.extend_from_slice(self.gtype.name().as_bytes());
        out.push(b' ');
        out.extend_from_slice(self.body.len().to_string().as_bytes());
        out.push(0);
        out.extend_from_slice(&self.body);
        out
    }

    /// git object id: SHA-1 of [`Self::raw`].
    #[must_use]
    pub fn id(&self) -> Sha1Id {
        let mut h = Sha1::new();
        h.update(self.gtype.name().as_bytes());
        h.update(b" ");
        h.update(self.body.len().to_string().as_bytes());
        h.update([0u8]);
        h.update(&self.body);
        h.finalize().into()
    }

    /// Loose-object path under a `.git` (or bare repo) directory.
    #[must_use]
    pub fn loose_path(git_dir: &Path, id: &Sha1Id) -> PathBuf {
        let hex = sha1_hex(id);
        git_dir.join("objects").join(&hex[..2]).join(&hex[2..])
    }

    /// Write this object loose into `git_dir/objects/`, returning its
    /// id. Idempotent: an existing object file is left untouched
    /// (same bytes by content addressing). The write is
    /// temp-file + rename so a crash never leaves a torn object.
    pub fn write_loose(&self, git_dir: &Path) -> Result<Sha1Id, BridgeError> {
        let id = self.id();
        let path = Self::loose_path(git_dir, &id);
        if path.exists() {
            return Ok(id);
        }
        let dir = path
            .parent()
            .ok_or_else(|| BridgeError::Source("loose path has no parent".into()))?;
        std::fs::create_dir_all(dir)?;
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
        enc.write_all(&self.raw())?;
        let compressed = enc.finish()?;
        // Unique per process so concurrent writers never share a tmp
        // path; content addressing makes the rename race benign.
        let tmp = dir.join(format!(".tmp-{}-{}", std::process::id(), sha1_hex(&id)));
        std::fs::write(&tmp, &compressed)?;
        match std::fs::rename(&tmp, &path) {
            Ok(()) => Ok(id),
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                // Lost a race to another writer: same content, fine.
                if path.exists() { Ok(id) } else { Err(e.into()) }
            }
        }
    }
}

impl GitObject {
    /// Parse `"<type> <len>\0<body>"` bytes (the inverse of
    /// [`Self::raw`]; what a zlib-decompressed loose object contains).
    #[must_use]
    pub fn parse_raw(raw: &[u8]) -> Option<Self> {
        let sp = raw.iter().position(|&b| b == b' ')?;
        let gtype = GitType::from_name(&raw[..sp])?;
        let nul = raw.iter().position(|&b| b == 0)?;
        let len: usize = std::str::from_utf8(&raw[sp + 1..nul]).ok()?.parse().ok()?;
        let body = raw.get(nul + 1..)?;
        (body.len() == len).then(|| Self {
            gtype,
            body: body.to_vec(),
        })
    }

    /// Read and parse a loose object from a git objects dir,
    /// verifying the bytes hash back to the requested id (also
    /// rejects non-canonical headers, since [`Self::id`] re-renders
    /// the canonical form).
    pub fn read_loose(git_dir: &Path, id: &Sha1Id) -> Result<Self, BridgeError> {
        let compressed = std::fs::read(Self::loose_path(git_dir, id))?;
        let mut dec = flate2::read::ZlibDecoder::new(&compressed[..]);
        let mut raw = Vec::new();
        std::io::Read::read_to_end(&mut dec, &mut raw)?;
        let obj = Self::parse_raw(&raw)
            .ok_or_else(|| BridgeError::NotBridgeObject("malformed loose object header".into()))?;
        if obj.id() != *id {
            return Err(BridgeError::Integrity(format!(
                "loose object {} hashes to {}",
                sha1_hex(id),
                sha1_hex(&obj.id())
            )));
        }
        Ok(obj)
    }
}

/// Lowercase hex of a 20-byte git id.
#[must_use]
pub fn sha1_hex(id: &Sha1Id) -> String {
    let mut s = String::with_capacity(40);
    for b in id {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Strict inverse of [`sha1_hex`] (lowercase only).
#[must_use]
pub fn sha1_from_hex(s: &str) -> Option<Sha1Id> {
    let bytes = s.as_bytes();
    if bytes.len() != 40 {
        return None;
    }
    let mut out = [0u8; 20];
    for (i, pair) in bytes.chunks(2).enumerate() {
        let hi = hex_val(pair[0])?;
        let lo = hex_val(pair[1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

pub(crate) fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

/// Lowercase hex of arbitrary bytes (used for the 64-byte signature
/// and 32-byte hash header values).
#[must_use]
pub fn bytes_hex(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Strict lowercase-hex decode of an exact expected length.
#[must_use]
pub fn bytes_from_hex(s: &str, expect_len: usize) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    if bytes.len() != expect_len * 2 {
        return None;
    }
    let mut out = Vec::with_capacity(expect_len);
    for pair in bytes.chunks(2) {
        out.push((hex_val(pair[0])? << 4) | hex_val(pair[1])?);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_blob_id_matches_git() {
        // `git hash-object -t blob /dev/null`
        let obj = GitObject {
            gtype: GitType::Blob,
            body: Vec::new(),
        };
        assert_eq!(
            sha1_hex(&obj.id()),
            "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"
        );
    }

    #[test]
    fn empty_tree_id_matches_git() {
        let obj = GitObject {
            gtype: GitType::Tree,
            body: Vec::new(),
        };
        assert_eq!(
            sha1_hex(&obj.id()),
            "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
        );
    }

    #[test]
    fn hello_blob_id_matches_git() {
        // `printf 'hello\n' | git hash-object --stdin`
        let obj = GitObject {
            gtype: GitType::Blob,
            body: b"hello\n".to_vec(),
        };
        assert_eq!(
            sha1_hex(&obj.id()),
            "ce013625030ba8dba906f756967f9e9ca394464a"
        );
    }

    #[test]
    fn loose_write_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let obj = GitObject {
            gtype: GitType::Blob,
            body: b"abc".to_vec(),
        };
        let id = obj.write_loose(dir.path()).unwrap();
        let path = GitObject::loose_path(dir.path(), &id);
        assert!(path.exists());
        // Idempotent second write.
        assert_eq!(obj.write_loose(dir.path()).unwrap(), id);
        // Decompresses back to header+body.
        let compressed = std::fs::read(path).unwrap();
        let mut dec = flate2::read::ZlibDecoder::new(&compressed[..]);
        let mut raw = Vec::new();
        std::io::Read::read_to_end(&mut dec, &mut raw).unwrap();
        assert_eq!(raw, obj.raw());
    }

    #[test]
    fn hex_round_trips() {
        let id: Sha1Id = [0xAB; 20];
        assert_eq!(sha1_from_hex(&sha1_hex(&id)).unwrap(), id);
        assert!(sha1_from_hex("AB").is_none());
        assert!(bytes_from_hex("0aff", 2).is_some());
        assert!(bytes_from_hex("0AFF", 2).is_none(), "uppercase rejected");
    }
}
