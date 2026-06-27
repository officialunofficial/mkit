// Denormalized commit-log metadata: extract the fields the lobby renders from a
// raw commit/remix object ONCE (on write), so the room DO can serve `ListCommits`
// from a colocated SQLite table instead of walking R2 object-by-object per read.
//
// This module is the PURE, unit-tested core of that redesign — it has no DO/R2
// dependency, just `mkit_core` decoding — so the wire-correct mapping (which
// MUST match the client's `decodeLogObject`) is verified by `cargo test`.

use mkit_core::hash::to_hex;
use mkit_core::object::Object;

/// Whether a logged object is a commit or a remix (fork head). Mirrors the
/// client's `kind` discriminator that drives the fork badge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitKind {
    Commit,
    Remix,
}

impl CommitKind {
    /// Lowercase wire string, matching the client's `'commit'` / `'remix'`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Commit => "commit",
            Self::Remix => "remix",
        }
    }
}

/// The denormalized fields of one log entry. Field-for-field the inputs the
/// client's `decodeLogObject` produces: `signer_hex` (author), `message`,
/// `timestamp` (unix seconds → the client renders ISO), `kind`, `sources`
/// (remix only), plus the first `parent` used to walk the chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitMeta {
    pub parent: Option<[u8; 32]>,
    pub signer_hex: String,
    pub message: String,
    pub timestamp: u64,
    pub kind: CommitKind,
    /// `(upstream_id_hex, commit_hash_hex)` per remix source; empty for commits.
    pub sources: Vec<(String, String)>,
}

impl CommitMeta {
    /// Encode `sources` as the compact JSON the DO column stores and the client
    /// reads back: `[[upstreamHex, commitHex], …]` (`"[]"` for a plain commit).
    pub fn sources_json(&self) -> String {
        // Hand-built (no serde needed): each pair is two 64-hex strings, so
        // there's nothing to escape.
        let mut s = String::from("[");
        for (i, (up, c)) in self.sources.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str("[\"");
            s.push_str(up);
            s.push_str("\",\"");
            s.push_str(c);
            s.push_str("\"]");
        }
        s.push(']');
        s
    }
}

/// Decode a raw object's bytes into commit-log metadata, or `None` if the bytes
/// aren't a commit/remix (the walk stops there, exactly like the client decoder).
pub fn extract_commit_meta(bytes: &[u8]) -> Option<CommitMeta> {
    match mkit_core::serialize::deserialize(bytes).ok()? {
        Object::Commit(c) => Some(CommitMeta {
            parent: c.parents.first().copied(),
            signer_hex: to_hex(&c.signer),
            message: String::from_utf8_lossy(&c.message).into_owned(),
            timestamp: c.timestamp,
            kind: CommitKind::Commit,
            sources: Vec::new(),
        }),
        Object::Remix(r) => Some(CommitMeta {
            parent: r.parents.first().copied(),
            signer_hex: to_hex(&r.signer),
            message: String::from_utf8_lossy(&r.message).into_owned(),
            timestamp: r.timestamp,
            kind: CommitKind::Remix,
            sources: r
                .sources
                .iter()
                .map(|s| (to_hex(&s.upstream_id), to_hex(&s.commit_hash)))
                .collect(),
        }),
        // Not a commit/remix (blob/tree/tag/…) — the walk stops here.
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mkit_core::object::{Blob, Commit, Identity, Object, Remix, RemixSource};
    use mkit_core::serialize::serialize;

    fn commit_bytes() -> Vec<u8> {
        let signer = [7u8; 32];
        let c = Commit::new_unannotated(
            [1u8; 32],                 // tree_hash
            vec![[9u8; 32]],           // parents (first parent = 0x09…)
            Identity::ed25519(signer), // author
            signer,                    // signer (the Ed25519 pubkey the client surfaces)
            b"hello world".to_vec(),   // message
            1_700_000_000,             // timestamp (unix seconds)
            [0u8; 64],                 // signature (not validated by (de)serialize)
        );
        serialize(&Object::Commit(c)).unwrap()
    }

    #[test]
    fn extracts_commit_metadata() {
        let m = extract_commit_meta(&commit_bytes()).expect("a commit");
        assert_eq!(m.kind, CommitKind::Commit);
        assert_eq!(m.message, "hello world");
        assert_eq!(m.timestamp, 1_700_000_000);
        assert_eq!(m.signer_hex, "07".repeat(32));
        assert_eq!(m.parent, Some([9u8; 32]));
        assert!(m.sources.is_empty());
    }

    #[test]
    fn extracts_remix_sources_and_kind() {
        let signer = [3u8; 32];
        let r = Remix {
            tree_hash: [1u8; 32],
            parents: vec![[9u8; 32]],
            sources: vec![RemixSource { upstream_id: [0xaa; 32], commit_hash: [0xbb; 32] }],
            author: Identity::ed25519(signer),
            signer,
            message: b"remix".to_vec(),
            timestamp: 42,
            signature: [0u8; 64],
        };
        let m = extract_commit_meta(&serialize(&Object::Remix(r)).unwrap()).expect("a remix");
        assert_eq!(m.kind, CommitKind::Remix);
        assert_eq!(m.sources, vec![("aa".repeat(32), "bb".repeat(32))]);
        assert_eq!(m.parent, Some([9u8; 32]));
    }

    #[test]
    fn sources_json_for_commit_is_empty_array() {
        let m = extract_commit_meta(&commit_bytes()).unwrap();
        assert_eq!(m.sources_json(), "[]");
    }

    #[test]
    fn sources_json_encodes_remix_pairs() {
        let signer = [3u8; 32];
        let r = Remix {
            tree_hash: [1u8; 32],
            parents: vec![[9u8; 32]],
            sources: vec![
                RemixSource { upstream_id: [0xaa; 32], commit_hash: [0xbb; 32] },
                RemixSource { upstream_id: [0xcc; 32], commit_hash: [0xdd; 32] },
            ],
            author: Identity::ed25519(signer),
            signer,
            message: b"r".to_vec(),
            timestamp: 1,
            signature: [0u8; 64],
        };
        let m = extract_commit_meta(&serialize(&Object::Remix(r)).unwrap()).unwrap();
        assert_eq!(
            m.sources_json(),
            format!("[[\"{}\",\"{}\"],[\"{}\",\"{}\"]]", "aa".repeat(32), "bb".repeat(32), "cc".repeat(32), "dd".repeat(32))
        );
    }

    #[test]
    fn rejects_non_commit_object() {
        let blob = serialize(&Object::Blob(Blob { data: b"x".to_vec() })).unwrap();
        assert!(extract_commit_meta(&blob).is_none());
    }
}
