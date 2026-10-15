//! Bounded, key-based `ListRefs` paging over direct refs or D34 index buckets.

use core::future::Future;

use mkit_core::hash::Hash;

use super::{D34Shards, RefEntry, ShardMap};
use crate::refs::MAX_REF_NAME_BYTES;
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

/// One bounded bucket scan.
#[derive(Debug)]
pub struct Scan {
    pub rows: Vec<(String, Hash)>,
    pub more: bool,
}

/// A source owns its key class and partition. It scans the normalized prefix
/// range strictly after `last`, returning full names in key order. `more`
/// means additional rows may remain beyond the last fetched key, and
/// requires at least one row: a scan with `more` and no rows fails the page
/// as `Corrupt`.
pub trait BucketSource {
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
                Some(_) => Err(StoreError::MalformedReply(
                    "ref key outside scanned range".into(),
                )),
                None => Err(StoreError::Corrupt("malformed ref key".into())),
            })
            .collect::<Result<_, _>>()?;
        Ok(Scan {
            rows,
            more: page.next.is_some(),
        })
    }
}

/// Validated D34 ref-index source.
#[derive(Debug)]
pub struct IndexBucket<'a, N> {
    pub store: &'a N,
    pub partition: &'a Partition,
}

impl<N: NamespaceStore> BucketSource for IndexBucket<'_, N> {
    async fn scan(
        &self,
        repo: &RepoId,
        prefix: &str,
        last: Option<&str>,
        limit: u32,
    ) -> Result<Scan, StoreError> {
        let (prefix_start, end) = keys::ref_index_prefix_range(&repo.name, prefix);
        let start = last.map_or_else(
            || prefix_start.clone(),
            |name| {
                let mut bytes = keys::ref_index_key(&repo.name, name).as_bytes().to_vec();
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
                Some(keys::ParsedKey::RefIndexEntry {
                    repo: row_repo,
                    name,
                }) if row_repo == repo.name
                    && crate::refs::validate_ref_name(&name)
                    && D34Shards.ref_index(repo, &name) == *self.partition =>
                {
                    Ok((name, codec::decode_ref_id(value)?))
                }
                _ => Err(StoreError::Corrupt(
                    "malformed or misrouted ref index row".into(),
                )),
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
        h.update(&u64::try_from(part.len()).unwrap_or(u64::MAX).to_be_bytes());
        h.update(part.as_bytes());
    }
    *h.finalize().as_bytes()
}

fn encode_token(repo: &RepoId, prefix: &str, last: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(TOKEN_HEADER + last.len());
    bytes.push(TOKEN_VERSION);
    bytes.extend_from_slice(&binding(repo, prefix));
    bytes.extend_from_slice(&u16::try_from(last.len()).unwrap_or(u16::MAX).to_be_bytes());
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
    // The name is only a scan position: a stored name that predates today's
    // grammar must still page. Names never contain NUL (the resume key is
    // `key(last) ‖ 00`).
    if name.contains('\0') || !name.starts_with(prefix) {
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

/// The rows each source may contribute to one page.
fn per_source(page_size: u32, sources: usize) -> u32 {
    let count = u32::try_from(sources).unwrap_or(u32::MAX);
    page_size.min(2 * page_size.div_ceil(count) + 8)
}

/// A continued scan must carry at least one row to bound the merge by.
fn continued_boundary(scan: &Scan) -> Result<Option<&str>, StoreError> {
    if !scan.more {
        return Ok(None);
    }
    scan.rows
        .last()
        .map(|(name, _)| Some(name.as_str()))
        .ok_or_else(|| StoreError::Corrupt("empty continued ref scan".into()))
}

/// Read one bounded page. Every source is scanned once, sequentially.
/// Tests also use it as the serial reference for [`page_in_waves`].
/// A failed source fails the entire page; no partial merge is exposed.
#[cfg(any(test, feature = "http-objects"))]
pub(super) async fn page<S: BucketSource>(
    sources: &[S],
    repo: &RepoId,
    prefix: &str,
    last: Option<&str>,
    page_size: u32,
    byte_budget: usize,
) -> Result<ListPage, StoreError> {
    assert!(!sources.is_empty() && page_size > 0);
    let per_source = per_source(page_size, sources.len());
    let mut scans = Vec::with_capacity(sources.len());
    for source in sources {
        let scan = source.scan(repo, prefix, last, per_source).await?;
        continued_boundary(&scan)?;
        scans.push(scan);
    }
    merge(repo, prefix, scans, page_size, byte_budget)
}

/// Rolling counterpart of `page`: keep up to six independently reserved
/// scans in flight, replenishing immediately after a successful completion.
/// Unknown/tight call allowances stay serial. A failure stops new launches;
/// all dispatched replies drain before returning the earliest source's error.
pub(super) async fn page_in_waves<S: BucketSource, N: NamespaceStore>(
    store: &N,
    sources: &[S],
    repo: &RepoId,
    prefix: &str,
    last: Option<&str>,
    page_size: u32,
    byte_budget: usize,
) -> Result<ListPage, StoreError> {
    use futures::StreamExt as _;
    assert!(!sources.is_empty() && page_size > 0);
    let per_source = per_source(page_size, sources.len());
    let mut scans: Vec<Option<Scan>> = (0..sources.len()).map(|_| None).collect();
    let mut pending = futures::stream::FuturesUnordered::new();
    let mut offset = 0;
    let mut failure: Option<(usize, StoreError)> = None;
    let dispatch = |index: usize, reservation: Option<crate::store::ReadReservation>| {
        let scan = sources[index].scan(repo, prefix, last, per_source);
        async move {
            (
                index,
                crate::store::ReadReservation::scope(&[reservation], scan).await,
            )
        }
    };
    loop {
        let required = (sources.len() - offset).min(crate::store::read_io::parallelism());
        let width = if store
            .read_call_allowance()
            .is_some_and(|calls| calls >= u32::try_from(required).unwrap_or(u32::MAX))
        {
            crate::store::read_io::parallelism()
        } else {
            1
        };
        while failure.is_none() && offset < sources.len() && pending.len() < width {
            match store.reserve_read_calls(1) {
                Ok(reservation) => pending.push(dispatch(offset, reservation)),
                Err(error) => {
                    failure = Some((offset, error));
                    break;
                }
            }
            offset += 1;
        }
        let Some((index, reply)) = pending.next().await else {
            break;
        };
        match reply.and_then(|scan| {
            continued_boundary(&scan)?;
            Ok(scan)
        }) {
            Ok(scan) => scans[index] = Some(scan),
            Err(error) => {
                if failure.as_ref().is_none_or(|(first, _)| index < *first) {
                    failure = Some((index, error));
                }
            }
        }
    }
    if let Some((_, error)) = failure {
        return Err(error);
    }
    let scans = scans
        .into_iter()
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| StoreError::Corrupt("missing completed ref scan".into()))?;
    merge(repo, prefix, scans, page_size, byte_budget)
}

/// Merge the sources' scans, in source order, into one page.
fn merge(
    repo: &RepoId,
    prefix: &str,
    scans: Vec<Scan>,
    page_size: u32,
    byte_budget: usize,
) -> Result<ListPage, StoreError> {
    let mut rows = Vec::new();
    let mut boundary: Option<String> = None;
    let mut source_more = false;
    for scan in scans {
        if let Some(name) = continued_boundary(&scan)? {
            boundary = Some(boundary.map_or_else(|| name.to_owned(), |b| b.min(name.to_owned())));
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

    struct RollingBucket {
        index: usize,
        started: Arc<Mutex<Vec<usize>>>,
        zero: Arc<Mutex<Option<futures::channel::oneshot::Receiver<()>>>>,
        six: Arc<Mutex<Option<futures::channel::oneshot::Sender<()>>>>,
    }
    impl BucketSource for RollingBucket {
        async fn scan(
            &self,
            _repo: &RepoId,
            _prefix: &str,
            _last: Option<&str>,
            _limit: u32,
        ) -> Result<Scan, StoreError> {
            self.started
                .lock()
                .expect("start record lock")
                .push(self.index);
            if self.index == 0 {
                let receive = self
                    .zero
                    .lock()
                    .expect("receiver lock")
                    .take()
                    .expect("bucket zero owns receiver");
                receive
                    .await
                    .map_err(|_| StoreError::unavailable("bucket six did not unlock zero"))?;
            }
            if self.index == 6 {
                self.six
                    .lock()
                    .expect("sender lock")
                    .take()
                    .expect("bucket six owns sender")
                    .send(())
                    .expect("bucket zero remains pending");
            }
            Ok(Scan {
                rows: vec![],
                more: false,
            })
        }
    }
    #[test]
    fn rolling_page_starts_seventh_bucket_while_first_is_blocked() {
        let (send, receive) = futures::channel::oneshot::channel();
        let started = Arc::new(Mutex::new(Vec::new()));
        let zero = Arc::new(Mutex::new(Some(receive)));
        let six = Arc::new(Mutex::new(Some(send)));
        let sources: Vec<_> = (0..16)
            .map(|index| RollingBucket {
                index,
                started: started.clone(),
                zero: zero.clone(),
                six: six.clone(),
            })
            .collect();
        let backend = crate::MemoryKv::default();
        let repo = repo("a");
        let mut read = Box::pin(page_in_waves(&backend, &sources, &repo, "", None, 10, 2048));
        let mut cx = std::task::Context::from_waker(futures::task::noop_waker_ref());
        let polled = read.as_mut().poll(&mut cx);
        assert!(
            started.lock().unwrap().contains(&6),
            "bucket six must start before bucket zero can finish"
        );
        match polled {
            std::task::Poll::Ready(result) => result,
            std::task::Poll::Pending => block_on(read),
        }
        .unwrap();
    }

    struct ActiveScan(Arc<std::sync::atomic::AtomicUsize>);
    impl Drop for ActiveScan {
        fn drop(&mut self) {
            self.0.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
    struct LedgerBucket<'a, N> {
        store: &'a N,
        active: Arc<std::sync::atomic::AtomicUsize>,
        peak: Arc<std::sync::atomic::AtomicUsize>,
    }
    impl<N: NamespaceStore> BucketSource for LedgerBucket<'_, N> {
        async fn scan(
            &self,
            _repo: &RepoId,
            _prefix: &str,
            _last: Option<&str>,
            limit: u32,
        ) -> Result<Scan, StoreError> {
            let active = self
                .active
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                + 1;
            self.peak
                .fetch_max(active, std::sync::atomic::Ordering::SeqCst);
            let _active = ActiveScan(self.active.clone());
            let mut yielded = false;
            futures::future::poll_fn(|cx| {
                if yielded {
                    std::task::Poll::Ready(())
                } else {
                    yielded = true;
                    cx.waker().wake_by_ref();
                    std::task::Poll::Pending
                }
            })
            .await;
            self.store
                .scan(
                    &Partition::Namespace(NamespaceKey::deployment_default()),
                    &Key::new(vec![0]),
                    &Key::new(vec![255]),
                    None,
                    limit,
                )
                .await?;
            Ok(Scan {
                rows: vec![],
                more: false,
            })
        }
    }
    struct UnknownAllowance<'a>(&'a crate::MemoryKv);
    impl NamespaceStore for UnknownAllowance<'_> {
        fn capabilities(&self) -> crate::StoreCapabilities {
            self.0.capabilities()
        }
        async fn get(&self, p: &Partition, key: &Key) -> Result<Option<crate::Value>, StoreError> {
            self.0.get(p, key).await
        }
        async fn scan(
            &self,
            p: &Partition,
            start: &Key,
            end: &Key,
            after: Option<&crate::Cursor>,
            limit: u32,
        ) -> Result<crate::ScanPage, StoreError> {
            self.0.scan(p, start, end, after, limit).await
        }
        async fn apply(
            &self,
            p: &Partition,
            batch: crate::Batch,
        ) -> Result<crate::BatchOutcome, StoreError> {
            self.0.apply(p, batch).await
        }
        async fn stats(&self, p: &Partition) -> Result<crate::PartitionStats, StoreError> {
            self.0.stats(p).await
        }
        async fn probe(&self) -> Result<(), StoreError> {
            self.0.probe().await
        }
    }
    #[test]
    fn rolling_page_charges_each_inherited_ledger_once_and_peaks_at_six() {
        let backend = crate::MemoryKv::default();
        let parent_calls = crate::budget::SliceBudget::new(16);
        let child_calls = crate::budget::SliceBudget::new(16);
        let parent = crate::indexed::budget::Budgeted::new(&backend, &parent_calls);
        let child = crate::indexed::budget::Budgeted::new(&parent, &child_calls);
        let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let peak = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let sources: Vec<_> = (0..16)
            .map(|_| LedgerBucket {
                store: &child,
                active: active.clone(),
                peak: peak.clone(),
            })
            .collect();
        block_on(page_in_waves(
            &child,
            &sources,
            &repo("a"),
            "",
            None,
            10,
            2048,
        ))
        .unwrap();
        assert_eq!(parent_calls.used(), 16);
        assert_eq!(child_calls.used(), 16);
        assert!(!parent_calls.refused() && !child_calls.refused());
        assert_eq!(peak.load(std::sync::atomic::Ordering::SeqCst), 6);
        assert_eq!(active.load(std::sync::atomic::Ordering::SeqCst), 0);
    }
    #[test]
    fn rolling_page_unknown_allowance_stays_serial_without_double_charge() {
        let backend = crate::MemoryKv::default();
        let unknown = UnknownAllowance(&backend);
        let calls = crate::budget::SliceBudget::new(16);
        let store = crate::indexed::budget::Budgeted::new(&unknown, &calls);
        let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let peak = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let sources: Vec<_> = (0..16)
            .map(|_| LedgerBucket {
                store: &store,
                active: active.clone(),
                peak: peak.clone(),
            })
            .collect();
        block_on(page_in_waves(
            &store,
            &sources,
            &repo("a"),
            "",
            None,
            10,
            2048,
        ))
        .unwrap();
        assert_eq!(calls.used(), 16);
        assert!(!calls.refused());
        assert_eq!(peak.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(active.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    struct OrderedFailureBucket {
        index: usize,
        completed: Arc<Mutex<Vec<usize>>>,
        boundary_error: bool,
    }

    impl BucketSource for OrderedFailureBucket {
        async fn scan(
            &self,
            _repo: &RepoId,
            _prefix: &str,
            _last: Option<&str>,
            _limit: u32,
        ) -> Result<Scan, StoreError> {
            // Make the first source finish after the later failing source.
            if self.index == 0 {
                let mut yielded = false;
                futures::future::poll_fn(|cx| {
                    if yielded {
                        std::task::Poll::Ready(())
                    } else {
                        yielded = true;
                        cx.waker().wake_by_ref();
                        std::task::Poll::Pending
                    }
                })
                .await;
            }
            self.completed.lock().unwrap().push(self.index);
            if self.index == 0 && self.boundary_error {
                Ok(Scan {
                    rows: Vec::new(),
                    more: true,
                })
            } else if self.index <= 1 {
                Err(StoreError::Corrupt(format!("bucket {}", self.index).into()))
            } else {
                Ok(Scan {
                    rows: Vec::new(),
                    more: false,
                })
            }
        }
    }

    #[test]
    fn waved_page_consumes_first_source_error_and_drains_only_dispatched_wave() {
        for boundary_error in [false, true] {
            let completed = Arc::new(Mutex::new(Vec::new()));
            let sources = (0..16)
                .map(|index| OrderedFailureBucket {
                    index,
                    completed: completed.clone(),
                    boundary_error,
                })
                .collect::<Vec<_>>();
            let error = block_on(page_in_waves(
                &crate::MemoryKv::default(),
                &sources,
                &repo("a"),
                "",
                None,
                10,
                2048,
            ))
            .err()
            .unwrap();
            assert!(matches!(error, StoreError::Corrupt(_)));
            let expected = if boundary_error {
                "empty continued ref scan"
            } else {
                "bucket 0"
            };
            assert!(error.to_string().contains(expected), "{error}");
            let completed = completed.lock().unwrap();
            assert_eq!(completed.len(), crate::store::read_io::parallelism());
            assert_eq!(completed.last(), Some(&0));
            assert!(completed.iter().all(|index| *index < 6));
        }
    }

    #[test]
    fn waved_page_tight_budget_preserves_first_source_error() {
        let completed = Arc::new(Mutex::new(Vec::new()));
        let sources = (0..16)
            .map(|index| OrderedFailureBucket {
                index,
                completed: completed.clone(),
                boundary_error: false,
            })
            .collect::<Vec<_>>();
        let backend = crate::MemoryKv::default();
        let calls = crate::budget::SliceBudget::new(1);
        let store = crate::indexed::budget::Budgeted::new(&backend, &calls);
        let error = block_on(page_in_waves(
            &store,
            &sources,
            &repo("a"),
            "",
            None,
            10,
            2048,
        ))
        .err()
        .unwrap();
        assert!(error.to_string().contains("bucket 0"));
        assert_eq!(*completed.lock().unwrap(), vec![0]);
        assert_eq!(calls.used(), 1);
        assert!(
            !calls.refused(),
            "unused later sources cannot refuse a reservation"
        );
    }

    #[test]
    fn waved_page_matches_serial_page_for_empty_and_mixed_buckets() {
        let names = ["refs/heads/a", "refs/heads/b", "refs/tags/a"].map(str::to_owned);
        for prefix in ["", "refs/heads/", "absent/"] {
            for count in [1, 16] {
                let sources = buckets(&names, count);
                let repo = repo("a");
                let serial = block_on(page(&sources, &repo, prefix, None, 1, 2048)).unwrap();
                let waved = block_on(page_in_waves(
                    &crate::MemoryKv::default(),
                    &sources,
                    &repo,
                    prefix,
                    None,
                    1,
                    2048,
                ))
                .unwrap();
                assert_eq!(waved.refs, serial.refs);
                assert_eq!(waved.next, serial.next);
            }
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
            parts[bucket].push((name.clone(), [u8::try_from(bucket).unwrap_or(u8::MAX); 32]));
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

    fn real_index_pages(
        store: &crate::MemoryKv,
        repo: &RepoId,
        prefix: &str,
        n: u32,
    ) -> Vec<String> {
        let partitions = D34Shards.ref_index_partitions(repo);
        let sources = partitions
            .iter()
            .map(|partition| IndexBucket { store, partition })
            .collect::<Vec<_>>();
        let mut token = None;
        let mut names = Vec::new();
        loop {
            let last = token
                .as_deref()
                .map(|bytes| decode_token(repo, prefix, bytes).unwrap());
            let result = block_on(page(&sources, repo, prefix, last.as_deref(), n, 8192)).unwrap();
            names.extend(result.refs.into_iter().map(|entry| entry.name));
            match result.next {
                Some(next) => token = Some(next),
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
        assert!(response.encoded_len() <= u32::try_from(MAX_RESPONSE_BYTES).unwrap_or(u32::MAX));
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
    fn misrouted_index_row_is_corrupt() {
        use crate::store::{Batch, NamespaceStore};
        let store = crate::MemoryKv::default();
        let repo = repo("a");
        let name = "refs/heads/main";
        let proper = D34Shards.ref_index(&repo, name);
        let wrong = D34Shards
            .ref_index_partitions(&repo)
            .into_iter()
            .find(|p| p != &proper)
            .unwrap();
        block_on(store.apply(
            &wrong,
            Batch::new().put(
                keys::ref_index_key(&repo.name, name),
                codec::encode_ref_id(&[1; 32]),
            ),
        ))
        .unwrap();
        let source = IndexBucket {
            store: &store,
            partition: &wrong,
        };
        assert!(matches!(
            block_on(page(&[source], &repo, "", None, 10, 2048)),
            Err(StoreError::Corrupt(_))
        ));
    }

    #[test]
    fn invalid_ref_name_in_index_is_corrupt() {
        use crate::store::{Batch, NamespaceStore};
        let store = crate::MemoryKv::default();
        let repo = repo("a");
        let name = "refs/heads//bad";
        let partition = D34Shards.ref_index(&repo, name);
        block_on(store.apply(
            &partition,
            Batch::new().put(
                keys::ref_index_key(&repo.name, name),
                codec::encode_ref_id(&[1; 32]),
            ),
        ))
        .unwrap();
        let source = IndexBucket {
            store: &store,
            partition: &partition,
        };
        assert!(matches!(
            block_on(page(&[source], &repo, "", None, 10, 2048)),
            Err(StoreError::Corrupt(_))
        ));
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

        #[test]
        fn real_memory_index_pages_equal_sorted_listing(ids in proptest::collection::vec(0u16..150, 0..50), n in 1u32..25) {
            use crate::store::{Batch, NamespaceStore};
            let store = crate::MemoryKv::default();
            let a = repo("a");
            let b = repo("b");
            let mut names = ids.into_iter().map(|id| format!("refs/heads/n{id:04}")).collect::<Vec<_>>();
            names.sort(); names.dedup();
            for name in &names {
                let target = D34Shards.ref_index(&a, name);
                block_on(store.apply(&target, Batch::new().put(keys::ref_index_key(&a.name, name), codec::encode_ref_id(&[1;32])))).unwrap();
                let foreign = D34Shards.ref_index(&b, name);
                block_on(store.apply(&foreign, Batch::new().put(keys::ref_index_key(&b.name, name), codec::encode_ref_id(&[2;32])))).unwrap();
            }
            prop_assert_eq!(real_index_pages(&store, &a, "", n), names.clone());
            prop_assert_eq!(real_index_pages(&store, &b, "", n), names.clone());
            let expected = names.iter().filter(|name| name.starts_with("refs/heads/n0")).cloned().collect::<Vec<_>>();
            prop_assert_eq!(real_index_pages(&store, &a, "refs/heads/n0", n), expected);
        }
    }
}
