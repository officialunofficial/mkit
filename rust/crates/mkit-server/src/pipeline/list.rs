//! Bounded, key-based ListRefs paging. The source seam also serves D34's
//! sixteen ref-index buckets once their rows exist (WP-1.28b).

use core::future::Future;

use mkit_core::hash::Hash;

use super::RefEntry;
use crate::refs::{self, MAX_REF_NAME_BYTES};
use crate::repo::RepoId;
use crate::rt::MaybeSend;
use crate::store::{Key, NamespaceStore, Partition, StoreError, codec, keys};

pub(super) const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const RESPONSE_HEADROOM: usize = 1024;
const TOKEN_VERSION: u8 = 1;
// [version:u8][repository+normalized-prefix binding:32][name length:u16 BE]
// [last emitted full ref name:UTF-8]. Store cursors never enter a token.
const TOKEN_HEADER: usize = 35;

pub(crate) struct ListPage {
    pub(crate) refs: Vec<RefEntry>,
    pub(crate) next: Option<Vec<u8>>,
}

pub(super) struct Scan {
    pub rows: Vec<(String, Hash)>,
    pub more: bool,
}

/// A source owns its key class and partition. It scans the normalized prefix
/// range strictly after `last`, returning full names in key order. `more`
/// means additional rows may remain beyond the last fetched key.
pub(super) trait BucketSource {
    fn scan(
        &self,
        repo: &RepoId,
        prefix: &str,
        last: Option<&str>,
        limit: u32,
    ) -> impl Future<Output = Result<Scan, StoreError>> + MaybeSend;
}

pub(super) struct RefBucket<'a, N> {
    pub store: &'a N,
    pub partition: &'a Partition,
}

impl<N: NamespaceStore> BucketSource for RefBucket<'_, N> {
    async fn scan(
        &self,
        repo: &RepoId,
        prefix: &str,
        last: Option<&str>,
        limit: u32,
    ) -> Result<Scan, StoreError> {
        let (prefix_start, end) = keys::ref_prefix_range(&repo.name, prefix);
        let start = last.map_or_else(
            || prefix_start.clone(),
            |name| {
                let mut bytes = keys::ref_key(&repo.name, name).as_bytes().to_vec();
                bytes.push(0);
                std::cmp::max(prefix_start.clone(), Key::new(bytes))
            },
        );
        let page = self
            .store
            .scan(self.partition, &start, &end, None, limit)
            .await?;
        let rows = page
            .entries
            .iter()
            .map(|(key, value)| match keys::parse(key) {
                Some(keys::ParsedKey::Ref { name, .. }) => Ok((name, codec::decode_ref_id(value)?)),
                _ => Err(StoreError::Corrupt("malformed ref key".into())),
            })
            .collect::<Result<_, _>>()?;
        Ok(Scan {
            rows,
            more: page.next.is_some(),
        })
    }
}

fn binding(repo: &RepoId, prefix: &str) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"mkit.list-refs-page-token.v1\0");
    for part in [repo.namespace.as_str(), repo.name.as_str(), prefix] {
        h.update(&(part.len() as u32).to_be_bytes());
        h.update(part.as_bytes());
    }
    *h.finalize().as_bytes()
}

fn encode_token(repo: &RepoId, prefix: &str, last: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(TOKEN_HEADER + last.len());
    bytes.push(TOKEN_VERSION);
    bytes.extend_from_slice(&binding(repo, prefix));
    bytes.extend_from_slice(&(last.len() as u16).to_be_bytes());
    bytes.extend_from_slice(last.as_bytes());
    bytes
}

pub(super) fn decode_token(repo: &RepoId, prefix: &str, bytes: &[u8]) -> Option<String> {
    if bytes.len() < TOKEN_HEADER || bytes.len() > TOKEN_HEADER + MAX_REF_NAME_BYTES {
        return None;
    }
    let name_len = usize::from(u16::from_be_bytes([bytes[33], bytes[34]]));
    if bytes[0] != TOKEN_VERSION
        || bytes[1..33] != binding(repo, prefix)
        || name_len == 0
        || bytes.len() != TOKEN_HEADER + name_len
    {
        return None;
    }
    let name = core::str::from_utf8(&bytes[TOKEN_HEADER..]).ok()?;
    if !refs::validate_ref_name(name) || !name.starts_with(prefix) {
        return None;
    }
    Some(name.to_owned())
}

fn varint_len(mut n: usize) -> usize {
    let mut len = 1;
    while n >= 128 {
        n >>= 7;
        len += 1;
    }
    len
}

// Proto3 ListRefsResponse.refs is a length-delimited RefEntry. JSON uses
// a base64 object id and a longer envelope. Ref grammar permits only ASCII
// alphanumerics, '.', '_' and '-', so the name needs no JSON escaping. Use
// the full name, at least as long as the stripped wire name, and leave room
// for the continuation token and response envelope.
fn row_wire_bound(name: &str) -> usize {
    let inner = 1 + varint_len(name.len()) + name.len() + 1 + 1 + 32;
    let proto = 1 + varint_len(inner) + inner;
    proto.max(name.len() + 96)
}

/// Read one bounded page. Every source is scanned once, sequentially.
/// A failed source fails the entire page; no partial merge is exposed.
pub(super) async fn page<S: BucketSource>(
    sources: &[S],
    repo: &RepoId,
    prefix: &str,
    last: Option<&str>,
    page_size: u32,
    byte_budget: usize,
) -> Result<ListPage, StoreError> {
    assert!(!sources.is_empty() && page_size > 0);
    let count = u32::try_from(sources.len()).unwrap_or(u32::MAX);
    let per_source = page_size.min(2 * page_size.div_ceil(count) + 8);
    let mut rows = Vec::new();
    let mut boundary: Option<String> = None;
    let mut source_more = false;
    for source in sources {
        let scan = source.scan(repo, prefix, last, per_source).await?;
        if scan.more {
            let Some((name, _)) = scan.rows.last() else {
                return Err(StoreError::Corrupt("empty continued ref scan".into()));
            };
            boundary = Some(boundary.map_or_else(|| name.clone(), |b| b.min(name.clone())));
            source_more = true;
        }
        rows.extend(scan.rows);
    }
    rows.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    let mut out: Vec<RefEntry> = Vec::new();
    let mut used = RESPONSE_HEADROOM;
    let mut stopped = false;
    for (name, id) in rows {
        if boundary.as_ref().is_some_and(|b| name > *b) {
            stopped = true;
            break;
        }
        if out.last().is_some_and(|r| r.name == name) {
            return Err(StoreError::Corrupt("duplicate ref index row".into()));
        }
        let bytes = row_wire_bound(&name);
        if out.len() >= page_size as usize || used + bytes > byte_budget {
            stopped = true;
            break;
        }
        used += bytes;
        out.push(RefEntry { name, id });
    }
    if out.is_empty() && (source_more || stopped) {
        return Err(StoreError::Corrupt("ref page made no progress".into()));
    }
    let next = if source_more || stopped {
        out.last().map(|r| encode_token(repo, prefix, &r.name))
    } else {
        None
    };
    Ok(ListPage { refs: out, next })
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use futures_executor::block_on;
    use proptest::prelude::*;

    use super::*;
    use crate::pipeline::{D34Shards, ShardMap};
    use crate::repo::{NamespaceKey, RepoName};

    #[derive(Clone)]
    struct MemoryBucket(Arc<Mutex<Vec<(String, Hash)>>>, bool);

    impl BucketSource for MemoryBucket {
        async fn scan(
            &self,
            _repo: &RepoId,
            prefix: &str,
            last: Option<&str>,
            limit: u32,
        ) -> Result<Scan, StoreError> {
            if self.1 {
                return Err(StoreError::Corrupt("failed bucket".into()));
            }
            let rows: Vec<_> = self
                .0
                .lock()
                .unwrap()
                .iter()
                .filter(|(name, _)| {
                    name.starts_with(prefix) && last.is_none_or(|v| name.as_str() > v)
                })
                .take(limit as usize + 1)
                .cloned()
                .collect();
            let more = rows.len() > limit as usize;
            Ok(Scan {
                rows: rows.into_iter().take(limit as usize).collect(),
                more,
            })
        }
    }

    fn repo(name: &str) -> RepoId {
        RepoId {
            namespace: NamespaceKey::deployment_default(),
            name: RepoName::new(name).unwrap(),
        }
    }

    fn buckets(names: &[String], count: usize) -> Vec<MemoryBucket> {
        assert!(count == 1 || count == 16);
        let mut parts = vec![Vec::new(); count];
        for name in names {
            let bucket = if count == 1 {
                0
            } else {
                let Partition::RefIndex { bucket, .. } =
                    D34Shards.ref_index(&repo("routing"), name)
                else {
                    unreachable!()
                };
                usize::from(bucket)
            };
            parts[bucket].push((name.clone(), [bucket as u8; 32]));
        }
        parts
            .into_iter()
            .map(|mut rows| {
                rows.sort_unstable_by(|a, b| a.0.cmp(&b.0));
                MemoryBucket(Arc::new(Mutex::new(rows)), false)
            })
            .collect()
    }

    fn all_pages(
        sources: &[MemoryBucket],
        repo: &RepoId,
        prefix: &str,
        n: u32,
        budget: usize,
    ) -> Vec<String> {
        all_pages_from(sources, repo, prefix, n, budget, None)
    }

    fn all_pages_from(
        sources: &[MemoryBucket],
        repo: &RepoId,
        prefix: &str,
        n: u32,
        budget: usize,
        mut token: Option<Vec<u8>>,
    ) -> Vec<String> {
        let mut names = Vec::new();
        let mut seen = std::collections::HashSet::new();
        loop {
            let last = token
                .as_deref()
                .map(|t| decode_token(repo, prefix, t).unwrap());
            let result = block_on(page(sources, repo, prefix, last.as_deref(), n, budget)).unwrap();
            assert!(result.refs.iter().all(|r| r.name.starts_with(prefix)));
            #[cfg(feature = "connect")]
            assert_encoded_bounds(&result);
            assert!(
                RESPONSE_HEADROOM
                    + result
                        .refs
                        .iter()
                        .map(|r| row_wire_bound(&r.name))
                        .sum::<usize>()
                    <= budget
            );
            for entry in result.refs {
                assert!(names.last().is_none_or(|prev| prev < &entry.name));
                names.push(entry.name);
            }
            match result.next {
                Some(next) => {
                    assert!(!names.is_empty());
                    assert!(seen.insert(next.clone()), "repeated token");
                    token = Some(next);
                }
                None => return names,
            }
        }
    }

    #[cfg(feature = "connect")]
    fn assert_encoded_bounds(page: &ListPage) {
        use crate::connect::proto::mkit::transport::v1::{
            ListRefsResponse, RefEntry as WireRefEntry,
        };
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        use buffa::Message as _;

        let response = ListRefsResponse {
            refs: page
                .refs
                .iter()
                .map(|r| WireRefEntry {
                    name: Some(r.name.clone()),
                    object_id: Some(r.id.to_vec()),
                    ..Default::default()
                })
                .collect(),
            next_page_token: page.next.as_ref().map(|t| URL_SAFE_NO_PAD.encode(t)),
            ..Default::default()
        };
        assert!(response.encoded_len() <= MAX_RESPONSE_BYTES as u32);
        assert!(serde_json::to_vec(&response).unwrap().len() <= MAX_RESPONSE_BYTES);
    }

    #[test]
    fn token_round_trip_and_binding() {
        let a = repo("a");
        let bytes = encode_token(&a, "refs/heads/", "refs/heads/main");
        assert_eq!(
            decode_token(&a, "refs/heads/", &bytes).as_deref(),
            Some("refs/heads/main")
        );
        assert_eq!(decode_token(&repo("b"), "refs/heads/", &bytes), None);
        assert_eq!(decode_token(&a, "refs/tags/", &bytes), None);
        assert_eq!(decode_token(&a, "refs/heads/", &bytes[..3]), None);
        let mut bad = bytes.clone();
        bad[0] = 2;
        assert_eq!(decode_token(&a, "refs/heads/", &bad), None);
        assert_eq!(decode_token(&a, "refs/heads/", &vec![0; 1000]), None);
    }

    #[test]
    fn failed_source_fails_entire_merge() {
        let names = vec!["refs/heads/main".to_owned()];
        let mut sources = buckets(&names, 16);
        sources[15].1 = true;
        assert!(block_on(page(&sources, &repo("a"), "", None, 10, 2048)).is_err());
    }

    #[test]
    fn ref_bucket_isolates_repositories_in_one_partition() {
        use crate::store::{Batch, NamespaceStore};

        let store = crate::MemoryKv::default();
        let a = repo("a");
        let b = repo("b");
        let partition = Partition::Namespace(a.namespace.clone());
        let name = "refs/heads/main";
        let batch = Batch::new()
            .put(keys::ref_key(&a.name, name), codec::encode_ref_id(&[1; 32]))
            .put(keys::ref_key(&b.name, name), codec::encode_ref_id(&[2; 32]));
        block_on(store.apply(&partition, batch)).unwrap();
        let source = RefBucket {
            store: &store,
            partition: &partition,
        };
        let first = block_on(page(&[source], &a, "", None, 10, 2048)).unwrap();
        assert_eq!(
            first.refs,
            vec![RefEntry {
                name: name.into(),
                id: [1; 32]
            }]
        );
        let source = RefBucket {
            store: &store,
            partition: &partition,
        };
        let second = block_on(page(&[source], &b, "", None, 10, 2048)).unwrap();
        assert_eq!(
            second.refs,
            vec![RefEntry {
                name: name.into(),
                id: [2; 32]
            }]
        );
    }

    #[test]
    fn prefix_boundaries_and_two_repositories() {
        let names = [
            "refs/heads/feat/x",
            "refs/heads/featx",
            "refs/heads/main",
            "refs/tags/v1",
        ]
        .map(str::to_owned);
        let sources = buckets(&names, 16);
        let a = repo("a");
        assert_eq!(
            all_pages(&sources, &a, "refs/heads/feat/", 1, 2048),
            vec![names[0].clone()]
        );
        assert_eq!(all_pages(&sources, &a, "", 2, 2048), names.to_vec());
        assert!(all_pages(&sources, &a, "nope/", 1, 2048).is_empty());
        let token = encode_token(&a, "", &names[0]);
        assert!(decode_token(&repo("b"), "", &token).is_none());
    }

    #[test]
    fn inserts_and_deletes_between_pages_preserve_stable_names_once() {
        let names: Vec<_> = (0..20).map(|i| format!("refs/heads/n{i:03}")).collect();
        let sources = buckets(&names, 16);
        let a = repo("a");
        let first = block_on(page(&sources, &a, "", None, 5, 2048)).unwrap();
        let first_names: Vec<_> = first.refs.iter().map(|r| r.name.clone()).collect();
        for source in &sources {
            source
                .0
                .lock()
                .unwrap()
                .retain(|(name, _)| name != "refs/heads/n012");
        }
        sources[0]
            .0
            .lock()
            .unwrap()
            .push(("refs/heads/n011a".into(), [0; 32]));
        sources[0]
            .0
            .lock()
            .unwrap()
            .sort_unstable_by(|a, b| a.0.cmp(&b.0));
        let mut actual = first_names;
        actual.extend(all_pages_from(&sources, &a, "", 5, 2048, first.next));
        for stable in names.iter().filter(|n| n.as_str() != "refs/heads/n012") {
            assert_eq!(actual.iter().filter(|n| *n == stable).count(), 1);
        }
    }

    #[test]
    fn listing_over_32_mib_obeys_two_mib_pages() {
        let names: Vec<_> = (0..64_000)
            .map(|i| format!("refs/heads/{i:05}{}", "a".repeat(494)))
            .collect();
        assert!(names.iter().map(|n| row_wire_bound(n)).sum::<usize>() > 32 * 1024 * 1024);
        let sources = buckets(&names, 1);
        assert_eq!(
            all_pages(&sources, &repo("large"), "", 10_000, MAX_RESPONSE_BYTES),
            names
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]
        #[test]
        fn random_merge_matches_sorted_listing(ids in proptest::collection::vec(0u16..500, 0..150), n in 1u32..80, budget in 2048usize..8192) {
            let mut names: Vec<_> = ids.into_iter().map(|i| format!("refs/heads/n{i:04}")).collect();
            names.sort(); names.dedup();
            let a = repo("random");
            for count in [1, 16] {
                let sources = buckets(&names, count);
                prop_assert_eq!(all_pages(&sources, &a, "", n, budget), names.clone());
            }
        }
    }
}
