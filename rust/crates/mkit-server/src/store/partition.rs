//! Storage partitions (D34 shards) and their portable byte encoding.

use bytes::{BufMut, Bytes, BytesMut};

use super::error::StoreError;
use crate::repo::{NamespaceKey, RepoName};

/// A storage partition: one D34 shard. Everything that must commit
/// atomically lives in one partition. The core computes the partition of
/// every operation; a backend maps partitions to whatever it likes (a
/// Durable Object each, rows keyed by partition in `SQLite`, a qmdb
/// instance each).
///
/// **Catch-all rule for backends.** The enum is `#[non_exhaustive]`: later
/// work adds kinds. A backend outside this crate never matches on it. It
/// stores and names partitions by [`Partition::encode`], which is stable
/// and injective, so a new kind needs no backend change. Existing
/// encodings never change; a new kind gets a new tag.
///
/// **Enumeration.** A store is never asked to list its partitions (a
/// Durable Object namespace cannot list its instances). The core knows
/// them: in single-partition mode the deployment's `Namespace` partitions
/// come from its configuration; under D34 the namespace coordinator keeps
/// a registry of every shard it has created (reserved key class `sr`,
/// laid out by WP-1.22). Backup and export walk that registry.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Partition {
    /// The whole namespace: single-partition mode. Used by M0 (today's
    /// single `root` Durable Object) and by the ssh / fs-layout path for
    /// good; not by D34-sharded deployments.
    Namespace(NamespaceKey),
    /// D34 (M1): the namespace coordinator: config, the grant epoch, the
    /// table of currently epoch-leased shards and the shard registry.
    /// Rarely written.
    Coordinator(NamespaceKey),
    /// D34 (M1): one per (repo, ref). A branch's head and packmap share it
    /// (`shard_ref` is the `refs/heads/<x>` name). Strongly consistent.
    Ref {
        /// Namespace.
        ns: NamespaceKey,
        /// Repository.
        repo: RepoName,
        /// The ref whose shard this is.
        shard_ref: String,
    },
    /// D34 (M1): repo membership by object-id prefix over the fixed
    /// `INDEX_FANOUT` (default 4096). Never resharded; eventually
    /// consistent.
    RepoIndex {
        /// Namespace.
        ns: NamespaceKey,
        /// Repository.
        repo: RepoName,
        /// Object-id prefix bucket.
        prefix: u16,
    },
    /// D34 (M1): the ref-name index `ListRefs` reads, hash-sharded over the
    /// fixed `REF_INDEX_FANOUT` (default 16). Eventually consistent.
    RefIndex {
        /// Namespace.
        ns: NamespaceKey,
        /// Repository.
        repo: RepoName,
        /// Ref-name hash bucket.
        bucket: u16,
    },
    /// A global `ContentIndex` shard, by object-id prefix over
    /// `INDEX_FANOUT`.
    ContentShard(u16),
}

impl Partition {
    /// The portable encoding: one kind tag byte (`n` namespace, `c`
    /// coordinator, `r` ref, `i` repo index, `x` ref index, `s` content
    /// shard), then each component followed by `0x00`. Strings are their
    /// UTF-8 bytes; integers are canonical decimal ASCII. Injective, so a
    /// backend may use it as an opaque name.
    ///
    /// # Errors
    /// [`StoreError::Invalid`] if a component contains `0x00`.
    pub fn encode(&self) -> Result<Bytes, StoreError> {
        let (tag, parts): (u8, Vec<String>) = match self {
            Self::Namespace(ns) => (b'n', vec![ns.as_str().into()]),
            Self::Coordinator(ns) => (b'c', vec![ns.as_str().into()]),
            Self::Ref {
                ns,
                repo,
                shard_ref,
            } => (
                b'r',
                vec![ns.as_str().into(), repo.as_str().into(), shard_ref.clone()],
            ),
            Self::RepoIndex { ns, repo, prefix } => (
                b'i',
                vec![ns.as_str().into(), repo.as_str().into(), prefix.to_string()],
            ),
            Self::RefIndex { ns, repo, bucket } => (
                b'x',
                vec![ns.as_str().into(), repo.as_str().into(), bucket.to_string()],
            ),
            Self::ContentShard(prefix) => (b's', vec![prefix.to_string()]),
        };
        let mut buf = BytesMut::new();
        buf.put_u8(tag);
        for part in parts {
            if part.as_bytes().contains(&0) {
                return Err(StoreError::Invalid(
                    "partition component contains 0x00".into(),
                ));
            }
            buf.put_slice(part.as_bytes());
            buf.put_u8(0);
        }
        Ok(buf.freeze())
    }

    /// Decode [`Partition::encode`] output.
    ///
    /// # Errors
    /// [`StoreError::Corrupt`] for an unknown tag, a wrong component count,
    /// a missing terminator, invalid UTF-8, an invalid repo name or a
    /// non-canonical integer.
    pub fn decode(bytes: &[u8]) -> Result<Self, StoreError> {
        let corrupt = || StoreError::Corrupt("malformed partition encoding".into());
        let (&tag, body) = bytes.split_first().ok_or_else(corrupt)?;
        let body = body.strip_suffix(&[0]).ok_or_else(corrupt)?;
        let parts = body
            .split(|&b| b == 0)
            .map(|p| String::from_utf8(p.to_vec()).map_err(|_| corrupt()))
            .collect::<Result<Vec<_>, _>>()?;
        let ns = |s: &String| NamespaceKey::from_stored(s.clone());
        let repo = |s: &String| RepoName::new(s.clone()).map_err(|_| corrupt());
        let int = |s: &String| {
            s.parse::<u16>()
                .ok()
                .filter(|n| n.to_string() == *s)
                .ok_or_else(corrupt)
        };
        Ok(match (tag, parts.as_slice()) {
            (b'n', [n]) => Self::Namespace(ns(n)),
            (b'c', [n]) => Self::Coordinator(ns(n)),
            (b'r', [n, r, shard_ref]) => Self::Ref {
                ns: ns(n),
                repo: repo(r)?,
                shard_ref: shard_ref.clone(),
            },
            (b'i', [n, r, p]) => Self::RepoIndex {
                ns: ns(n),
                repo: repo(r)?,
                prefix: int(p)?,
            },
            (b'x', [n, r, b]) => Self::RefIndex {
                ns: ns(n),
                repo: repo(r)?,
                bucket: int(b)?,
            },
            (b's', [p]) => Self::ContentShard(int(p)?),
            _ => return Err(corrupt()),
        })
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn ns(s: &str) -> NamespaceKey {
        NamespaceKey::from_stored(s.into())
    }

    fn repo(s: &str) -> RepoName {
        RepoName::new(s).unwrap()
    }

    #[test]
    fn partition_encoding_golden_bytes() {
        let cases: [(Partition, &[u8]); 6] = [
            (Partition::Namespace(ns("root")), b"nroot\0"),
            (Partition::Coordinator(ns("root")), b"croot\0"),
            (
                Partition::Ref {
                    ns: ns("root"),
                    repo: repo("a"),
                    shard_ref: "refs/heads/main".into(),
                },
                b"rroot\0a\0refs/heads/main\0",
            ),
            (
                Partition::RepoIndex {
                    ns: ns("root"),
                    repo: repo("a"),
                    prefix: 4095,
                },
                b"iroot\0a\x004095\0",
            ),
            (
                Partition::RefIndex {
                    ns: ns("root"),
                    repo: repo("a"),
                    bucket: 0,
                },
                b"xroot\0a\x000\0",
            ),
            (Partition::ContentShard(7), b"s7\0"),
        ];
        for (p, golden) in cases {
            assert_eq!(p.encode().unwrap().as_ref(), golden);
            assert_eq!(Partition::decode(golden).unwrap(), p);
        }
        let nul = Partition::Ref {
            ns: ns("root"),
            repo: repo("a"),
            shard_ref: "x\0y".into(),
        };
        assert!(matches!(nul.encode(), Err(StoreError::Invalid(_))));
        for bad in [
            &b""[..],
            b"nroot",
            b"s07\0",
            b"s65536\0",
            b"q1\0",
            b"croot\0x\0",
            b"ir\0 \x001\0",
        ] {
            assert!(
                matches!(Partition::decode(bad), Err(StoreError::Corrupt(_))),
                "{bad:?}"
            );
        }
    }

    fn partition() -> impl Strategy<Value = Partition> {
        let s = "[a-z0-9/._-]{0,8}";
        let r = "[!-~]{1,8}";
        prop_oneof![
            s.prop_map(|n| Partition::Namespace(ns(&n))),
            s.prop_map(|n| Partition::Coordinator(ns(&n))),
            (s, r, s).prop_map(|(n, rp, sr)| Partition::Ref {
                ns: ns(&n),
                repo: repo(&rp),
                shard_ref: sr,
            }),
            (s, r, any::<u16>()).prop_map(|(n, rp, prefix)| Partition::RepoIndex {
                ns: ns(&n),
                repo: repo(&rp),
                prefix,
            }),
            (s, r, any::<u16>()).prop_map(|(n, rp, bucket)| Partition::RefIndex {
                ns: ns(&n),
                repo: repo(&rp),
                bucket,
            }),
            any::<u16>().prop_map(Partition::ContentShard),
        ]
    }

    proptest! {
        #[test]
        fn partition_encoding_is_injective(a in partition(), b in partition()) {
            let (ea, eb) = (a.encode().unwrap(), b.encode().unwrap());
            prop_assert_eq!(Partition::decode(&ea).unwrap(), a.clone());
            prop_assert_eq!(ea == eb, a == b);
        }
    }
}
