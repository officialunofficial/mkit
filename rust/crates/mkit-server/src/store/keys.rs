//! Key layouts: the registry of every row and index the server stores
//! (reconciliation R-17). Indexes are layouts, not queries.
//!
//! Every key is `<class tag> 0x00 …`: tags such as `p`/`px`/`pp` share
//! prefixes, and the terminator keeps a scan of one class from ever seeing
//! another. Integers are big-endian, so byte order is numeric order. The
//! partition identifies the namespace (and under D34 the shard), never the
//! key. `0x00` never occurs in a repo name, so the repo component can be
//! followed by more components; the last component of a key may hold any
//! bytes.
//!
//! | Class | Key | Value |
//! |---|---|---|
//! | layout version | `v 00` | be32 [`LAYOUT_VERSION`]; never on `RefsOnly` stores |
//! | ref | `r 00 <repo> 00 <refname>` | 32-byte id |
//! | replay record | `p 00 <scope:32>` | codec `ReplayRecord` |
//! | replay expiry index | `px 00 <expires_at:be64> <scope:32>` | empty |
//! | quota state | `q 00 <scope>` | codec `QuotaState` |
//! | quota window index | `qx 00 <window_start:be64> <scope>` | empty |
//! | grant epoch | `e 00` | be64; absent means 0, never written as 0 |
//! | timer (reserved, WP-1.24) | `w 00 <due_at:be64> <kind:u8> <ref>` | codec per kind |
//!
//! Reserved tags ([`RESERVED_TAGS`]), each laid out by the work package
//! that adds it: tickets `t`, membership `m`, outbox `o` / `oq` / `os`,
//! outbox backlog counter `oc`, relay high-water marks `rh`, object index
//! `i`, leases `l`, published pointers `pp`, tombstones `tb`, verification
//! cursors `vc`, epoch lease `el`, and the `ContentIndex` classes `h`, `g`,
//! `b`, `c`. A new row adds its layout here, with a golden test.

use bytes::{BufMut, Bytes, BytesMut};
use mkit_core::hash::Hash;

use super::kv::Key;
use crate::quota::QuotaScope;
use crate::repo::RepoName;

/// The key-layout version this binary writes. A binary that reads a newer
/// version refuses to serve the partition.
pub const LAYOUT_VERSION: u32 = 1;

/// Layout version tag.
pub const TAG_LAYOUT_VERSION: &str = "v";
/// Ref tag.
pub const TAG_REF: &str = "r";
/// Replay record tag.
pub const TAG_REPLAY: &str = "p";
/// Replay expiry index tag.
pub const TAG_REPLAY_EXPIRY: &str = "px";
/// Quota state tag.
pub const TAG_QUOTA: &str = "q";
/// Quota window index tag.
pub const TAG_QUOTA_WINDOW: &str = "qx";
/// Grant epoch tag.
pub const TAG_GRANT_EPOCH: &str = "e";
/// Timer tag (layout reserved for WP-1.24).
pub const TAG_TIMER: &str = "w";

/// Tags whose layouts later work packages add. No M0 key uses them.
pub const RESERVED_TAGS: &[&str] = &[
    "t", "tb", "m", "o", "oq", "os", "oc", "rh", "i", "l", "pp", "vc", "el", "h", "g", "b", "c",
];

/// A key decoded by [`parse`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParsedKey {
    /// `v 00`.
    LayoutVersion,
    /// `r 00 <repo> 00 <refname>`.
    Ref {
        /// Repository.
        repo: RepoName,
        /// Full ref name.
        name: String,
    },
    /// `p 00 <scope>`.
    Replay(Hash),
    /// `px 00 <expires_at> <scope>`.
    ReplayExpiry {
        /// Record expiry, Unix ms.
        expires_at_ms: u64,
        /// Record scope.
        scope: Hash,
    },
    /// `q 00 <scope>`.
    Quota(String),
    /// `qx 00 <window_start> <scope>`.
    QuotaWindow {
        /// Window start, Unix ms.
        window_start_ms: u64,
        /// Quota scope.
        scope: String,
    },
    /// `e 00`.
    GrantEpoch,
    /// `w 00 <due_at> <kind> <ref>`.
    Timer {
        /// Due time, Unix ms.
        due_at_ms: u64,
        /// Timer kind.
        kind: u8,
        /// What the timer refers to.
        reference: Bytes,
    },
}

fn key(tag: &str, parts: &[&[u8]]) -> Key {
    let mut buf =
        BytesMut::with_capacity(tag.len() + 1 + parts.iter().map(|p| p.len()).sum::<usize>());
    buf.put_slice(tag.as_bytes());
    buf.put_u8(0);
    for part in parts {
        buf.put_slice(part);
    }
    Key::new(buf.freeze())
}

/// The smallest key greater than every key starting with `prefix`.
fn successor(prefix: &Key) -> Key {
    let mut bytes = prefix.as_bytes().to_vec();
    while bytes.last() == Some(&0xff) {
        bytes.pop();
    }
    if let Some(last) = bytes.last_mut() {
        *last += 1;
    }
    Key::new(bytes)
}

/// `[<tag> 00, <tag> 01)`: every key of one class and no other.
#[must_use]
pub fn class_range(tag: &str) -> (Key, Key) {
    let start = key(tag, &[]);
    let end = successor(&start);
    (start, end)
}

/// Whether `key` is in the ref class (what a `RefsOnly` store accepts).
#[must_use]
pub fn is_ref_key(key: &Key) -> bool {
    key.as_bytes().starts_with(b"r\0")
}

/// `v 00`.
#[must_use]
pub fn layout_version() -> Key {
    key(TAG_LAYOUT_VERSION, &[])
}

/// `r 00 <repo> 00 <name>`.
#[must_use]
pub fn ref_key(repo: &RepoName, name: &str) -> Key {
    key(TAG_REF, &[repo.as_str().as_bytes(), b"\0", name.as_bytes()])
}

/// The scan range of every ref of `repo` whose name starts with `prefix`.
#[must_use]
pub fn ref_prefix_range(repo: &RepoName, prefix: &str) -> (Key, Key) {
    let start = ref_key(repo, prefix);
    let end = successor(&start);
    (start, end)
}

/// `p 00 <scope>`.
#[must_use]
pub fn replay(scope: &Hash) -> Key {
    key(TAG_REPLAY, &[scope])
}

/// `px 00 <expires_at> <scope>`.
#[must_use]
pub fn replay_expiry(expires_at_ms: u64, scope: &Hash) -> Key {
    key(TAG_REPLAY_EXPIRY, &[&expires_at_ms.to_be_bytes(), scope])
}

/// The expiry-index range of records expiring strictly before `before_ms`.
#[must_use]
pub fn replay_expiry_before(before_ms: u64) -> (Key, Key) {
    let (start, _) = class_range(TAG_REPLAY_EXPIRY);
    (start, key(TAG_REPLAY_EXPIRY, &[&before_ms.to_be_bytes()]))
}

/// `q 00 <scope>`.
#[must_use]
pub fn quota(scope: &QuotaScope) -> Key {
    key(TAG_QUOTA, &[scope.as_str().as_bytes()])
}

/// `qx 00 <window_start> <scope>`.
#[must_use]
pub fn quota_window(window_start_ms: u64, scope: &QuotaScope) -> Key {
    key(
        TAG_QUOTA_WINDOW,
        &[&window_start_ms.to_be_bytes(), scope.as_str().as_bytes()],
    )
}

/// The window-index range of windows starting strictly before `before_ms`.
#[must_use]
pub fn quota_window_before(before_ms: u64) -> (Key, Key) {
    let (start, _) = class_range(TAG_QUOTA_WINDOW);
    (start, key(TAG_QUOTA_WINDOW, &[&before_ms.to_be_bytes()]))
}

/// `e 00`.
#[must_use]
pub fn grant_epoch() -> Key {
    key(TAG_GRANT_EPOCH, &[])
}

/// `w 00 <due_at> <kind> <reference>` (reserved for WP-1.24).
#[must_use]
pub fn timer(due_at_ms: u64, kind: u8, reference: &[u8]) -> Key {
    key(TAG_TIMER, &[&due_at_ms.to_be_bytes(), &[kind], reference])
}

fn be64(bytes: &[u8]) -> Option<(u64, &[u8])> {
    let (head, rest) = bytes.split_first_chunk::<8>()?;
    Some((u64::from_be_bytes(*head), rest))
}

fn hash(bytes: &[u8]) -> Option<Hash> {
    Hash::try_from(bytes).ok()
}

/// Decode a key of any M0 class; `None` for a malformed key or a reserved
/// class.
#[must_use]
pub fn parse(key: &Key) -> Option<ParsedKey> {
    let bytes = key.as_bytes();
    let split = bytes.iter().position(|&b| b == 0)?;
    let (tag, body) = (&bytes[..split], &bytes[split + 1..]);
    let text = |b: &[u8]| String::from_utf8(b.to_vec()).ok();
    Some(match tag {
        b"v" if body.is_empty() => ParsedKey::LayoutVersion,
        b"e" if body.is_empty() => ParsedKey::GrantEpoch,
        b"r" => {
            let sep = body.iter().position(|&b| b == 0)?;
            ParsedKey::Ref {
                repo: RepoName::new(text(&body[..sep])?).ok()?,
                name: text(&body[sep + 1..])?,
            }
        }
        b"p" => ParsedKey::Replay(hash(body)?),
        b"px" => {
            let (expires_at_ms, rest) = be64(body)?;
            ParsedKey::ReplayExpiry {
                expires_at_ms,
                scope: hash(rest)?,
            }
        }
        b"q" => ParsedKey::Quota(text(body)?),
        b"qx" => {
            let (window_start_ms, rest) = be64(body)?;
            ParsedKey::QuotaWindow {
                window_start_ms,
                scope: text(rest)?,
            }
        }
        b"w" => {
            let (due_at_ms, rest) = be64(body)?;
            let (&kind, reference) = rest.split_first()?;
            ParsedKey::Timer {
                due_at_ms,
                kind,
                reference: Bytes::copy_from_slice(reference),
            }
        }
        _ => return None,
    })
}

/// The quota-state key a quota-window index key points at.
#[must_use]
pub fn quota_for_window(index: &Key) -> Option<Key> {
    match parse(index)? {
        ParsedKey::QuotaWindow { scope, .. } => Some(key(TAG_QUOTA, &[scope.as_bytes()])),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repo::NamespaceKey;
    use proptest::prelude::*;

    fn repo(name: &str) -> RepoName {
        RepoName::new(name).unwrap()
    }

    fn scope() -> QuotaScope {
        QuotaScope::for_signer(&NamespaceKey::deployment_default(), &[0xab; 32])
    }

    fn all_tags() -> Vec<&'static str> {
        let mut tags = vec![
            TAG_LAYOUT_VERSION,
            TAG_REF,
            TAG_REPLAY,
            TAG_REPLAY_EXPIRY,
            TAG_QUOTA,
            TAG_QUOTA_WINDOW,
            TAG_GRANT_EPOCH,
            TAG_TIMER,
        ];
        tags.extend_from_slice(RESERVED_TAGS);
        tags
    }

    #[test]
    fn layouts_golden_bytes() {
        let s = [0x11; 32];
        let q = format!("root\n{}", "ab".repeat(32));
        let cases: Vec<(Key, Vec<u8>)> = vec![
            (layout_version(), b"v\0".to_vec()),
            (
                ref_key(&repo("room-a"), "refs/heads/main"),
                b"r\0room-a\0refs/heads/main".to_vec(),
            ),
            (replay(&s), [&b"p\0"[..], &[0x11; 32]].concat()),
            (
                replay_expiry(0x0102_0304_0506_0708, &s),
                [&b"px\0"[..], &[1, 2, 3, 4, 5, 6, 7, 8], &[0x11; 32]].concat(),
            ),
            (quota(&scope()), [b"q\0", q.as_bytes()].concat()),
            (
                quota_window(256, &scope()),
                [&b"qx\0"[..], &[0, 0, 0, 0, 0, 0, 1, 0], q.as_bytes()].concat(),
            ),
            (grant_epoch(), b"e\0".to_vec()),
            (
                timer(1, 7, b"refs/heads/x"),
                [&b"w\0"[..], &[0, 0, 0, 0, 0, 0, 0, 1, 7], b"refs/heads/x"].concat(),
            ),
        ];
        for (key, golden) in cases {
            assert_eq!(key.as_bytes(), golden.as_slice());
        }
        assert_eq!(LAYOUT_VERSION, 1);
    }

    #[test]
    fn class_scans_never_overlap() {
        let tags = all_tags();
        for (i, a) in tags.iter().enumerate() {
            assert!(!tags[i + 1..].contains(a), "duplicate tag {a}");
            let (start, end) = class_range(a);
            for b in &tags {
                for tail in [&b""[..], b"\0", b"\xff\xff", b"x\0y"] {
                    let k = Key::new([b.as_bytes(), b"\0", tail].concat());
                    assert_eq!(start <= k && k < end, a == b, "{a} range vs {b} key");
                }
            }
        }
    }

    proptest! {
        #[test]
        fn ref_prefix_scan_bounds_cover_exactly_the_prefix(
            prefix in "[a-z/.-]{0,6}",
            name in "[a-z/.-]{0,10}",
            other in "[a-z]{1,3}",
        ) {
            let r = repo("repo");
            let (start, end) = ref_prefix_range(&r, &prefix);
            let k = ref_key(&r, &name);
            prop_assert_eq!(start <= k && k < end, name.starts_with(&prefix));
            // No other repo's refs, and no other class, fall in the range.
            let foreign = ref_key(&repo(&format!("repo{other}")), &name);
            prop_assert!(!(start <= foreign && foreign < end));
            prop_assert!(!(start <= replay(&[0; 32]) && replay(&[0; 32]) < end));
        }

        #[test]
        fn be64_orders_numerically(a: u64, b: u64) {
            let s = [0xff; 32];
            prop_assert_eq!(replay_expiry(a, &s).cmp(&replay_expiry(b, &s)), a.cmp(&b));
            let (start, end) = replay_expiry_before(b);
            let k = replay_expiry(a, &s);
            prop_assert_eq!(start <= k && k < end, a < b);
            let (start, end) = quota_window_before(b);
            let k = quota_window(a, &scope());
            prop_assert_eq!(start <= k && k < end, a < b);
        }
    }

    #[test]
    fn parse_roundtrip_every_class() {
        let s = [0x22; 32];
        let q = scope();
        let cases = vec![
            (layout_version(), ParsedKey::LayoutVersion),
            (
                ref_key(&repo("a"), "refs/tags/v1"),
                ParsedKey::Ref {
                    repo: repo("a"),
                    name: "refs/tags/v1".into(),
                },
            ),
            (replay(&s), ParsedKey::Replay(s)),
            (
                replay_expiry(9, &s),
                ParsedKey::ReplayExpiry {
                    expires_at_ms: 9,
                    scope: s,
                },
            ),
            (quota(&q), ParsedKey::Quota(q.as_str().into())),
            (
                quota_window(5, &q),
                ParsedKey::QuotaWindow {
                    window_start_ms: 5,
                    scope: q.as_str().into(),
                },
            ),
            (grant_epoch(), ParsedKey::GrantEpoch),
            (
                timer(3, 2, b"r"),
                ParsedKey::Timer {
                    due_at_ms: 3,
                    kind: 2,
                    reference: Bytes::from_static(b"r"),
                },
            ),
        ];
        for (key, parsed) in cases {
            assert_eq!(parse(&key), Some(parsed));
        }
        assert_eq!(quota_for_window(&quota_window(5, &q)), Some(quota(&q)));
        assert_eq!(quota_for_window(&quota(&q)), None);
        for bad in [
            &b"p\0short"[..],
            b"v\0x",
            b"px\0\0",
            b"el\0",
            b"no-terminator",
        ] {
            assert_eq!(parse(&Key::new(bad.to_vec())), None);
        }
    }
}
