//! Key-level [`NamespaceStore`] cases: reads, preconditions, scans,
//! limits, isolation, capabilities, the `NotAfter` deadline (rule 8),
//! capacity (rule 7) and the golden encodings a backend stores.

use futures::FutureExt as _;
use futures::future::join_all;
use mkit_core::protocol::AdvanceOutcome;
use mkit_server::quota::QuotaState;
use mkit_server::store::{BlockEntry, ObjectState, codec, export_header, keys};
use mkit_server::{
    Batch, BatchOutcome, Clock, Code, Cursor, Key, KeyClasses, MAX_BATCH_BYTES, MAX_BATCH_OPS,
    MAX_KEY_BYTES, MAX_VALUE_BYTES, NamespaceStore, Partition, Precondition, ReplayRecord,
    ReplayState, StoreError, StoredRejection, StoredResult, SystemClock, Value,
};

use super::CaseResult::{Pass, Skip};
use super::{
    KEY_PREFIX, KvHarness, NO_CLOCK, Outcome, clocked, commit, k, need_all_classes, need_atomic,
    not_written, outcome, part, put_all, range, rows, scan_all, v,
};
use BatchOutcome::{Committed, DeadlinePassed, PreconditionFailed};
use Precondition::{Absent, Equals, NotAfter, Present};

fn failed(index: usize, observed: Option<Value>) -> BatchOutcome {
    PreconditionFailed { index, observed }
}

/// The host clock, Unix ms, as a deadline base for the real-clock cases.
fn wall_ms() -> u64 {
    u64::try_from(SystemClock.now_ms()).unwrap_or(0)
}

/// `get` and `has` of a key never written.
pub async fn kv_get_missing_none<H: KvHarness>(h: H) -> Outcome {
    let (s, p) = (h.store(), part("kv_get_missing_none"));
    ensure_eq!(ok!(s.get(&p, &k(b"a")).await), None);
    ensure!(!ok!(s.has(&p, &k(b"a")).await), "has of a missing key");
    Ok(Pass)
}

/// A put is read back; a later put replaces it.
pub async fn kv_put_then_get<H: KvHarness>(h: H) -> Outcome {
    let (s, p) = (h.store(), part("kv_put_then_get"));
    commit(&s, &p, Batch::new().put(k(b"a"), v(b"1"))).await?;
    ensure_eq!(ok!(s.get(&p, &k(b"a")).await), Some(v(b"1")));
    commit(&s, &p, Batch::new().put(k(b"a"), v(b"2"))).await?;
    ensure_eq!(ok!(s.get(&p, &k(b"a")).await), Some(v(b"2")));
    Ok(Pass)
}

/// An empty value is stored, and stays distinct from an absent key in
/// every read and precondition.
pub async fn kv_empty_value_distinct_from_absent<H: KvHarness>(h: H) -> Outcome {
    let (s, p) = (h.store(), part("kv_empty_value_distinct_from_absent"));
    let (a, empty) = (k(b"a"), Value::default());
    commit(&s, &p, Batch::new().put(a.clone(), empty.clone())).await?;
    ensure_eq!(ok!(s.get(&p, &a).await), Some(empty.clone()));
    ensure!(ok!(s.has(&p, &a).await), "has of an empty value");
    ensure_eq!(
        ok!(s.get_many(&p, std::slice::from_ref(&a)).await),
        vec![Some(empty.clone())]
    );
    ensure_eq!(rows(&s, &p).await?, vec![(a.clone(), empty.clone())]);
    let absent = Batch::new()
        .require(Absent(a.clone()))
        .put(a.clone(), v(b"x"));
    ensure_eq!(
        outcome(&s, &p, absent).await?,
        failed(0, Some(empty.clone()))
    );
    commit(&s, &p, Batch::new().require(Present(a.clone()))).await?;
    commit(
        &s,
        &p,
        Batch::new().require(Equals(a.clone(), empty.clone())),
    )
    .await?;
    let missing = Batch::new().require(Equals(k(b"missing"), empty));
    ensure_eq!(outcome(&s, &p, missing).await?, failed(0, None));
    commit(&s, &p, Batch::new().delete(a.clone())).await?;
    ensure_eq!(ok!(s.get(&p, &a).await), None);
    Ok(Pass)
}

/// A delete removes the key; deleting an absent key commits.
pub async fn kv_delete_then_get_none<H: KvHarness>(h: H) -> Outcome {
    let (s, p) = (h.store(), part("kv_delete_then_get_none"));
    commit(&s, &p, Batch::new().put(k(b"a"), v(b"1"))).await?;
    commit(&s, &p, Batch::new().delete(k(b"a"))).await?;
    ensure_eq!(ok!(s.get(&p, &k(b"a")).await), None);
    commit(&s, &p, Batch::new().delete(k(b"a"))).await?;
    Ok(Pass)
}

/// `has` agrees with `get`.
pub async fn kv_has_matches_get<H: KvHarness>(h: H) -> Outcome {
    let (s, p) = (h.store(), part("kv_has_matches_get"));
    commit(&s, &p, Batch::new().put(k(b"a"), v(b"1"))).await?;
    for key in [k(b"a"), k(b"b"), k(b"a\0")] {
        let got = ok!(s.get(&p, &key).await).is_some();
        ensure_eq!(ok!(s.has(&p, &key).await), got);
    }
    Ok(Pass)
}

/// `get_many` answers in input order, repeats included.
pub async fn kv_get_many_order_and_missing<H: KvHarness>(h: H) -> Outcome {
    let (s, p) = (h.store(), part("kv_get_many_order_and_missing"));
    put_all(&s, &p, &[(k(b"a"), v(b"1")), (k(b"b"), v(b"2"))]).await?;
    let got = ok!(s.get_many(&p, &[k(b"b"), k(b"z"), k(b"a"), k(b"b")]).await);
    ensure_eq!(got, vec![Some(v(b"2")), None, Some(v(b"1")), Some(v(b"2"))]);
    ensure_eq!(ok!(s.get_many(&p, &[]).await), Vec::<Option<Value>>::new());
    Ok(Pass)
}

/// `Absent` holds on a missing key and fails, observing the value, on a
/// present one.
pub async fn kv_absent_ok_and_fail<H: KvHarness>(h: H) -> Outcome {
    let (s, p) = (h.store(), part("kv_absent_ok_and_fail"));
    let put = |val: &[u8]| Batch::new().require(Absent(k(b"a"))).put(k(b"a"), v(val));
    commit(&s, &p, put(b"1")).await?;
    ensure_eq!(outcome(&s, &p, put(b"2")).await?, failed(0, Some(v(b"1"))));
    ensure_eq!(ok!(s.get(&p, &k(b"a")).await), Some(v(b"1")));
    Ok(Pass)
}

/// `Present` fails, observing `None`, on a missing key and holds on a
/// present one.
pub async fn kv_present_ok_and_fail<H: KvHarness>(h: H) -> Outcome {
    let (s, p) = (h.store(), part("kv_present_ok_and_fail"));
    let put = |val: &[u8]| Batch::new().require(Present(k(b"a"))).put(k(b"a"), v(val));
    ensure_eq!(outcome(&s, &p, put(b"1")).await?, failed(0, None));
    ensure_eq!(ok!(s.get(&p, &k(b"a")).await), None);
    commit(&s, &p, Batch::new().put(k(b"a"), v(b"1"))).await?;
    commit(&s, &p, put(b"2")).await?;
    ensure_eq!(ok!(s.get(&p, &k(b"a")).await), Some(v(b"2")));
    Ok(Pass)
}

/// `Equals` holds only on the exact value and reports what it saw.
pub async fn kv_equals_ok_and_fail_reports_observed<H: KvHarness>(h: H) -> Outcome {
    let (s, p) = (h.store(), part("kv_equals_ok_and_fail_reports_observed"));
    let put = |key: &[u8], want: &[u8]| {
        Batch::new()
            .require(Equals(k(key), v(want)))
            .put(k(key), v(b"new"))
    };
    commit(&s, &p, Batch::new().put(k(b"a"), v(b"1"))).await?;
    ensure_eq!(
        outcome(&s, &p, put(b"a", b"2")).await?,
        failed(0, Some(v(b"1")))
    );
    ensure_eq!(
        outcome(&s, &p, put(b"a", b"")).await?,
        failed(0, Some(v(b"1")))
    );
    ensure_eq!(outcome(&s, &p, put(b"z", b"1")).await?, failed(0, None));
    ensure_eq!(ok!(s.get(&p, &k(b"z")).await), None);
    commit(&s, &p, put(b"a", b"1")).await?;
    ensure_eq!(ok!(s.get(&p, &k(b"a")).await), Some(v(b"new")));
    Ok(Pass)
}

/// Preconditions are checked in order and the first failure is reported:
/// what gives `AdvanceRefs` its packmap-before-head precedence
/// (`apps/vcs-worker/src/worker_impl/refstore.rs:215-255`).
pub async fn kv_first_failing_precondition_index<H: KvHarness>(h: H) -> Outcome {
    let (s, p) = (h.store(), part("kv_first_failing_precondition_index"));
    gate!(need_atomic(&s, &p).await);
    commit(&s, &p, Batch::new().put(k(b"a"), v(b"1"))).await?;
    let batch = Batch::new()
        .require(Present(k(b"a")))
        .require(Absent(k(b"b")))
        .require(Equals(k(b"a"), v(b"9")))
        .require(Absent(k(b"a")))
        .put(k(b"b"), v(b"2"));
    ensure_eq!(outcome(&s, &p, batch).await?, failed(2, Some(v(b"1"))));
    ensure_eq!(ok!(s.get(&p, &k(b"b")).await), None);
    Ok(Pass)
}

/// A multi-write batch whose last precondition fails writes nothing.
pub async fn kv_failed_batch_writes_nothing<H: KvHarness>(h: H) -> Outcome {
    let (s, p) = (h.store(), part("kv_failed_batch_writes_nothing"));
    gate!(need_atomic(&s, &p).await);
    put_all(&s, &p, &[(k(b"a"), v(b"1")), (k(b"b"), v(b"2"))]).await?;
    let before = rows(&s, &p).await?;
    let batch = Batch::new()
        .require(Present(k(b"a")))
        .require(Absent(k(b"b")))
        .put(k(b"a"), v(b"x"))
        .delete(k(b"b"))
        .put(k(b"c"), v(b"3"));
    ensure_eq!(outcome(&s, &p, batch).await?, failed(1, Some(v(b"2"))));
    ensure_eq!(rows(&s, &p).await?, before);
    Ok(Pass)
}

/// Writes apply in order, so the later write to a key wins: put then
/// delete leaves it absent, delete then put leaves the put.
pub async fn kv_put_delete_same_key_last_write_wins<H: KvHarness>(h: H) -> Outcome {
    let (s, p) = (h.store(), part("kv_put_delete_same_key_last_write_wins"));
    gate!(need_atomic(&s, &p).await);
    commit(&s, &p, Batch::new().put(k(b"b"), v(b"0"))).await?;
    let batch = Batch::new()
        .put(k(b"a"), v(b"1"))
        .delete(k(b"a"))
        .delete(k(b"b"))
        .put(k(b"b"), v(b"2"))
        .put(k(b"c"), v(b"1"))
        .put(k(b"c"), v(b"3"));
    commit(&s, &p, batch).await?;
    ensure_eq!(
        rows(&s, &p).await?,
        vec![(k(b"b"), v(b"2")), (k(b"c"), v(b"3"))]
    );
    Ok(Pass)
}

/// A batch without writes only checks; an empty batch commits.
pub async fn kv_check_only_batch_writes_nothing<H: KvHarness>(h: H) -> Outcome {
    let (s, p) = (h.store(), part("kv_check_only_batch_writes_nothing"));
    commit(&s, &p, Batch::new()).await?;
    commit(&s, &p, Batch::new().require(Absent(k(b"a")))).await?;
    let check = Batch::new().require(Present(k(b"a")));
    ensure_eq!(outcome(&s, &p, check).await?, failed(0, None));
    ensure_eq!(rows(&s, &p).await?, vec![]);
    Ok(Pass)
}

/// Suffixes that sort by raw bytes, not as text: `0x00`, `0xff`, and keys
/// that are prefixes of each other.
const ORDER_SUFFIXES: [&[u8]; 10] = [
    b"b", b"\xff", b"a\x01", b"", b"a\0\0", b"ab", b"a", b"\0", b"a\xff", b"a\0",
];

/// A scan returns keys in ascending raw-byte order.
pub async fn kv_scan_byte_order<H: KvHarness>(h: H) -> Outcome {
    let (s, p) = (h.store(), part("kv_scan_byte_order"));
    let mut rows_in: Vec<_> = ORDER_SUFFIXES.iter().map(|x| (k(x), v(x))).collect();
    put_all(&s, &p, &rows_in).await?;
    rows_in.sort();
    ensure_eq!(rows(&s, &p).await?, rows_in);
    Ok(Pass)
}

/// `[start, end)`: the start key is in, the end key is out; an empty or
/// inverted range is empty.
pub async fn kv_scan_bounds_half_open<H: KvHarness>(h: H) -> Outcome {
    let (s, p) = (h.store(), part("kv_scan_bounds_half_open"));
    let all: Vec<_> = ORDER_SUFFIXES.iter().map(|x| (k(x), v(x))).collect();
    put_all(&s, &p, &all).await?;
    let got = scan_all(&s, &p, (&k(b"a\0"), &k(b"a\xff")), 2).await?;
    let want: Vec<_> = [&b"a\0"[..], b"a\0\0", b"a\x01", b"ab"]
        .iter()
        .map(|x| (k(x), v(x)))
        .collect();
    ensure_eq!(got, want);
    ensure_eq!(scan_all(&s, &p, (&k(b"a"), &k(b"a")), 3).await?, vec![]);
    ensure_eq!(scan_all(&s, &p, (&k(b"b"), &k(b"a")), 3).await?, vec![]);
    Ok(Pass)
}

/// Paging resumes strictly after the cursor, whether the last key read is
/// still there or has since been deleted, and never repeats or skips a key.
pub async fn kv_scan_cursor_resumes_strictly_after<H: KvHarness>(h: H) -> Outcome {
    let (s, p) = (h.store(), part("kv_scan_cursor_resumes_strictly_after"));
    let all: Vec<_> = [b"a", b"b", b"c", b"d"]
        .iter()
        .map(|x| (k(*x), v(*x)))
        .collect();
    put_all(&s, &p, &all).await?;
    let (start, end) = range();
    let (mut seen, mut after) = (vec![], None);
    for _ in 0..all.len() * 2 {
        if seen.len() >= 2 {
            break;
        }
        let page = ok!(s.scan(&p, &start, &end, after.as_ref(), 2).await);
        seen.extend(page.entries);
        after = Some(page.next.ok_or("the scan ended with entries unread")?);
    }
    ensure!(seen.len() >= 2, "the scan returned no entries");
    ensure_eq!(seen, all[..seen.len()].to_vec());
    let last = seen[seen.len() - 1].0.clone();
    // The cursor's key is still there: resuming must not return it again.
    let again = ok!(s.scan(&p, &start, &end, after.as_ref(), 1).await);
    ensure!(
        again.entries.iter().all(|e| e.0 > last),
        "resumed at the cursor"
    );
    commit(&s, &p, Batch::new().delete(last)).await?;
    let mut rest = vec![];
    for _ in 0..all.len() * 2 {
        let Some(cursor) = after.take() else { break };
        let page = ok!(s.scan(&p, &start, &end, Some(&cursor), 2).await);
        rest.extend(page.entries);
        after = page.next;
    }
    ensure_eq!(rest, all[seen.len()..].to_vec());
    Ok(Pass)
}

/// Keys added behind a cursor stay behind it; keys added ahead of it are
/// returned by the next pages.
pub async fn kv_scan_pagination_stable_under_concurrent_puts_after_cursor<H: KvHarness>(
    h: H,
) -> Outcome {
    let (s, p) = (
        h.store(),
        part("kv_scan_pagination_stable_under_concurrent_puts"),
    );
    put_all(
        &s,
        &p,
        &[(k(b"b"), v(b"")), (k(b"d"), v(b"")), (k(b"f"), v(b""))],
    )
    .await?;
    let (start, end) = range();
    let page = ok!(s.scan(&p, &start, &end, None, 1).await);
    ensure_eq!(page.entries, vec![(k(b"b"), v(b""))]);
    put_all(
        &s,
        &p,
        &[(k(b"a"), v(b"")), (k(b"c"), v(b"")), (k(b"g"), v(b""))],
    )
    .await?;
    let mut seen = vec![];
    let mut after = page.next;
    for _ in 0..16 {
        let Some(cursor) = after.take() else { break };
        let page = ok!(s.scan(&p, &start, &end, Some(&cursor), 1).await);
        seen.extend(page.entries.into_iter().map(|e| e.0));
        after = page.next;
    }
    ensure!(after.is_none(), "the scan did not end");
    ensure_eq!(seen, vec![k(b"c"), k(b"d"), k(b"f"), k(b"g")]);
    Ok(Pass)
}

/// Whatever page sizes the backend picks, a page never ends the scan
/// (`next = None`) while unread entries remain; paging at every limit
/// returns every entry exactly once.
pub async fn kv_scan_short_page_still_returns_next<H: KvHarness>(h: H) -> Outcome {
    let (s, p) = (h.store(), part("kv_scan_short_page_still_returns_next"));
    let all: Vec<_> = (0_u8..9).map(|i| (k(&[b'k', i]), v(&[i]))).collect();
    put_all(&s, &p, &all).await?;
    let (start, end) = range();
    for limit in 1..=10 {
        let (mut read, mut after) = (0, None);
        for page_no in 0.. {
            ensure!(
                page_no <= 2 * all.len(),
                "limit {limit}: the scan did not end"
            );
            let page = ok!(s.scan(&p, &start, &end, after.as_ref(), limit).await);
            ensure!(
                read + page.entries.len() <= all.len(),
                "limit {limit}: extra entries"
            );
            ensure_eq!(page.entries, all[read..read + page.entries.len()].to_vec());
            read += page.entries.len();
            match page.next {
                Some(next) => after = Some(next),
                None => break,
            }
        }
        ensure!(
            read == all.len(),
            "limit {limit}: ended after {read} entries"
        );
    }
    Ok(Pass)
}

/// A cursor from another range, or bytes no scan returned, is `Invalid`.
pub async fn kv_scan_foreign_cursor_rejected<H: KvHarness>(h: H) -> Outcome {
    let (s, p) = (h.store(), part("kv_scan_foreign_cursor_rejected"));
    let all: Vec<_> = [b"a1", b"a2", b"c1", b"c2"]
        .iter()
        .map(|x| (k(*x), v(*x)))
        .collect();
    put_all(&s, &p, &all).await?;
    let a = ok!(s.scan(&p, &k(b"a"), &k(b"b"), None, 1).await);
    let Some(foreign) = a.next else {
        return Err("a partial scan returned no cursor".into());
    };
    let forged = [
        foreign,
        Cursor::new(&b""[..]),
        Cursor::new(vec![0xff; 8]),
        Cursor::new(keys::grant_epoch().into_bytes()),
    ];
    for cursor in &forged {
        let page = s.scan(&p, &k(b"c"), &k(b"d"), Some(cursor), 10).await;
        ensure_err!(page, StoreError::Invalid(_));
    }
    Ok(Pass)
}

/// A page holds at most `limit` entries; a `limit` of 0 is `Invalid`.
pub async fn kv_scan_limit_respected<H: KvHarness>(h: H) -> Outcome {
    let (s, p) = (h.store(), part("kv_scan_limit_respected"));
    let all: Vec<_> = (0_u8..6).map(|i| (k(&[i]), v(&[i]))).collect();
    put_all(&s, &p, &all).await?;
    let (start, end) = range();
    for limit in 1..=7_u32 {
        let page = ok!(s.scan(&p, &start, &end, None, limit).await);
        ensure!(
            page.entries.len() <= limit as usize,
            "limit {limit} exceeded"
        );
    }
    ensure_err!(
        s.scan(&p, &start, &end, None, 0).await,
        StoreError::Invalid(_)
    );
    Ok(Pass)
}

/// A key over `MAX_KEY_BYTES`, written or checked, is `Invalid` and
/// writes nothing; a key of exactly the limit is accepted.
pub async fn kv_oversize_key_invalid<H: KvHarness>(h: H) -> Outcome {
    let (s, p) = (h.store(), part("kv_oversize_key_invalid"));
    let max = k(&vec![b'x'; MAX_KEY_BYTES - KEY_PREFIX.len()]);
    let long = k(&vec![b'x'; MAX_KEY_BYTES + 1 - KEY_PREFIX.len()]);
    for batch in [
        Batch::new().put(long.clone(), v(b"1")),
        Batch::new().delete(long.clone()),
        Batch::new()
            .require(Absent(long.clone()))
            .put(long.clone(), v(b"1")),
    ] {
        ensure_err!(s.apply(&p, batch).await, StoreError::Invalid(_));
    }
    ensure_eq!(rows(&s, &p).await?, vec![]);
    commit(&s, &p, Batch::new().put(max.clone(), v(b"1"))).await?;
    ensure_eq!(ok!(s.get(&p, &max).await), Some(v(b"1")));
    Ok(Pass)
}

/// A value over `MAX_VALUE_BYTES`, written or compared, is `Invalid` and
/// writes nothing; a value of exactly the limit round-trips.
pub async fn kv_oversize_value_invalid<H: KvHarness>(h: H) -> Outcome {
    let (s, p) = (h.store(), part("kv_oversize_value_invalid"));
    let long = Value::new(vec![7; MAX_VALUE_BYTES + 1]);
    let max = Value::new(vec![7; MAX_VALUE_BYTES]);
    let put = Batch::new().put(k(b"a"), long.clone());
    ensure_err!(s.apply(&p, put).await, StoreError::Invalid(_));
    let check = Batch::new()
        .require(Equals(k(b"a"), long))
        .put(k(b"a"), v(b"1"));
    ensure_err!(s.apply(&p, check).await, StoreError::Invalid(_));
    ensure_eq!(rows(&s, &p).await?, vec![]);
    commit(&s, &p, Batch::new().put(k(b"a"), max.clone())).await?;
    ensure_eq!(ok!(s.get(&p, &k(b"a")).await), Some(max));
    Ok(Pass)
}

/// More than `MAX_BATCH_OPS` operations or `MAX_BATCH_BYTES` in one batch
/// is `Invalid` and writes nothing, counting the value bytes of `Equals`
/// preconditions; exactly `MAX_BATCH_OPS` operations or `MAX_BATCH_BYTES`
/// commits.
pub async fn kv_batch_limits_invalid<H: KvHarness>(h: H) -> Outcome {
    let (s, p) = (h.store(), part("kv_batch_limits_invalid"));
    let puts = |n: usize, len: usize| {
        (0..n).fold(Batch::new(), |b, i| {
            b.put(k(&i.to_be_bytes()), Value::new(vec![1; len]))
        })
    };
    let ops = puts(MAX_BATCH_OPS, 1).require(Absent(k(b"z")));
    ensure_err!(s.apply(&p, ops).await, StoreError::Invalid(_));
    let bytes = puts(MAX_BATCH_BYTES / MAX_VALUE_BYTES + 1, MAX_VALUE_BYTES);
    ensure_err!(s.apply(&p, bytes).await, StoreError::Invalid(_));
    // Two full values fit alone; the precondition's bytes tip it over.
    let (ka, kb) = (k(b"a"), k(b"b"));
    let full = Value::new(vec![1; MAX_VALUE_BYTES]);
    let checked = Batch::new()
        .require(Equals(ka.clone(), full.clone()))
        .put(kb.clone(), full.clone());
    ensure_err!(s.apply(&p, checked).await, StoreError::Invalid(_));
    ensure_eq!(rows(&s, &p).await?, vec![]);
    gate!(need_atomic(&s, &p).await);
    commit(&s, &p, puts(MAX_BATCH_OPS, 1)).await?;
    ensure_eq!(rows(&s, &p).await?.len(), MAX_BATCH_OPS);
    let rest = MAX_BATCH_BYTES - MAX_VALUE_BYTES - ka.as_bytes().len() - kb.as_bytes().len();
    let exact = |extra: usize| {
        Batch::new()
            .put(ka.clone(), full.clone())
            .put(kb.clone(), Value::new(vec![2; rest + extra]))
    };
    ensure_err!(s.apply(&p, exact(1)).await, StoreError::Invalid(_));
    commit(&s, &p, exact(0)).await?;
    Ok(Pass)
}

/// Partitions of every kind, decoded from their golden encodings, are
/// independent keyspaces (rule 6).
const GOLDEN_PARTITIONS: [&[u8]; 7] = [
    b"nroot\0",
    b"croot\0",
    b"rroot\0a\0refs/heads/main\0",
    b"iroot\0a\x004095\0",
    b"xroot\0a\x000\0",
    b"s7\0",
    b"s8\0",
];

/// The same key in different partitions holds different values; a write
/// or delete in one never shows in another.
pub async fn kv_partitions_isolated<H: KvHarness>(h: H) -> Outcome {
    let s = h.store();
    let parts = GOLDEN_PARTITIONS
        .iter()
        .map(|g| Partition::decode(g))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    for (p, tag) in parts.iter().zip(b'0'..) {
        commit(&s, p, Batch::new().put(k(b"a"), v(&[tag]))).await?;
    }
    commit(&s, &parts[0], Batch::new().delete(k(b"a"))).await?;
    for (p, tag) in parts.iter().zip(b'0'..).skip(1) {
        ensure_eq!(rows(&s, p).await?, vec![(k(b"a"), v(&[tag]))]);
    }
    ensure_eq!(ok!(s.get(&parts[0], &k(b"a")).await), None);
    Ok(Pass)
}

/// Stored values come back byte-exact: the golden codec bytes (mirrors
/// `store::codec`'s golden tests) round-trip through the backend and
/// decode to what was encoded.
pub async fn kv_codec_golden_values_roundtrip<H: KvHarness>(h: H) -> Outcome {
    let (s, p) = (h.store(), part("kv_codec_golden_values_roundtrip"));
    let rejected = StoredRejection::new(Code::PermissionDenied, "no").ok_or("not final")?;
    let record = |state| ReplayRecord {
        fingerprint: [9; 32],
        expires_at_ms: -5,
        state,
    };
    let head = format!(
        r#"{{"fingerprint":"{}","expires_at_ms":-5,"state":"#,
        "09".repeat(32)
    );
    let replay = [
        (
            record(ReplayState::Committed(StoredResult::Rejected(rejected))),
            format!(
                r#"{head}{{"state":"committed","result":{{"kind":"rejected","code":"permission_denied","message":"no"}}}}}}"#
            ),
        ),
        (
            record(ReplayState::Committed(StoredResult::AdvanceRefs(
                AdvanceOutcome::PackmapConflict,
            ))),
            format!(
                r#"{head}{{"state":"committed","result":{{"kind":"advance_packmap_conflict"}}}}}}"#
            ),
        ),
        (
            record(ReplayState::InFlight { resumable: true }),
            format!(r#"{head}{{"state":"in_flight","resumable":true}}}}"#),
        ),
    ];
    let quota = QuotaState {
        window_start: 1_700_000_000_000,
        ops: 3,
        bytes: u64::MAX,
    };
    let block = BlockEntry::new("dmca", 7);
    let state = ObjectState::new(u64::MAX, 1_700_000_000_000, 2, true);
    let mut cases: Vec<(Value, Vec<u8>)> = replay
        .iter()
        .map(|(r, json)| {
            (
                codec::encode_replay_record(r),
                [b"\x01", json.as_bytes()].concat(),
            )
        })
        .collect();
    cases.extend([
        (
            codec::encode_quota_state(&quota),
            b"\x01{\"window_start\":1700000000000,\"ops\":3,\"bytes\":18446744073709551615}".to_vec(),
        ),
        (codec::encode_hold(9), b"\x01{\"expires_at_ms\":9}".to_vec()),
        (
            codec::encode_block_entry(&block),
            b"\x01{\"reason\":\"dmca\",\"blocked_at_ms\":7}".to_vec(),
        ),
        (
            codec::encode_object_state(&state),
            b"\x01{\"seq\":18446744073709551615,\"changed_at_ms\":1700000000000,\"holders\":2,\"deleting\":true}".to_vec(),
        ),
        (codec::encode_ref_id(&[4; 32]), vec![4; 32]),
        (codec::encode_u64(u64::MAX - 1), vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe]),
        (codec::encode_u32(1), vec![0, 0, 0, 1]),
    ]);
    let stored: Vec<_> = cases
        .iter()
        .zip(0_u8..)
        .map(|((val, _), i)| (k(&[b'g', i]), val.clone()))
        .collect();
    put_all(&s, &p, &stored).await?;
    for ((_, golden), i) in cases.iter().zip(0_u8..) {
        let got = ok!(s.get(&p, &k(&[b'g', i])).await).ok_or("golden value missing")?;
        ensure_eq!(got.as_bytes(), golden.as_slice());
    }
    for ((r, _), i) in replay.iter().zip(0_u8..) {
        let got = ok!(s.get(&p, &k(&[b'g', i])).await).ok_or("missing")?;
        ensure_eq!(&ok!(codec::decode_replay_record(&got)), r);
    }
    Ok(Pass)
}

/// Sixteen tasks race `Absent(k) + Put(k)`: exactly one commits, and every
/// loser observes the winner's value. Holds on single-writer backends too.
pub async fn kv_concurrent_absent_single_winner<H: KvHarness>(h: H) -> Outcome {
    let (s, p) = (h.store(), part("kv_concurrent_absent_single_winner"));
    let racers = (0_u8..16).map(|i| {
        let batch = Batch::new().require(Absent(k(b"a"))).put(k(b"a"), v(&[i]));
        s.apply(&p, batch)
    });
    let mut outcomes = vec![];
    for result in join_all(racers).await {
        outcomes.push(ok!(result));
    }
    let winner = ok!(s.get(&p, &k(b"a")).await).ok_or("no winner stored")?;
    let won = outcomes.iter().filter(|o| **o == Committed).count();
    ensure_eq!(won, 1);
    for o in outcomes.iter().filter(|o| **o != Committed) {
        ensure_eq!(o, &failed(0, Some(winner.clone())));
    }
    Ok(Pass)
}

/// Tags of every class, including reserved ones, that share a prefix.
const CLASS_TAGS: [&str; 16] = [
    "o", "oq", "os", "oc", "p", "px", "pp", "t", "tb", "e", "el", "r", "rr", "rh", "n", "nl",
];

/// A key of class `tag` with a body that stresses the terminator.
fn class_key(tag: &str, body: &[u8]) -> Key {
    Key::new([tag.as_bytes(), b"\0", body].concat())
}

/// A `RefsOnly` store rejects every other class as `Unsupported`, written
/// or checked, and writes nothing; an `All` store accepts every class.
pub async fn kv_refs_only_rejects_other_classes<H: KvHarness>(h: H) -> Outcome {
    let (s, p) = (h.store(), part("kv_refs_only_rejects_other_classes"));
    let refs_only = s.capabilities().key_classes == KeyClasses::RefsOnly;
    for tag in CLASS_TAGS.iter().filter(|t| **t != "r") {
        let key = class_key(tag, b"x");
        let put = Batch::new().put(key.clone(), v(b"1"));
        let check = Batch::new().require(Absent(key.clone()));
        if refs_only {
            ensure_err!(s.apply(&p, put).await, StoreError::Unsupported(_));
            ensure_err!(s.apply(&p, check).await, StoreError::Unsupported(_));
            not_written(&s, &p, &key).await?;
        } else {
            commit(&s, &p, put).await?;
            ensure_eq!(ok!(s.get(&p, &key).await), Some(v(b"1")));
        }
    }
    commit(&s, &p, Batch::new().put(k(b"ref"), v(b"1"))).await?;
    if refs_only {
        ensure_eq!(rows(&s, &p).await?, vec![(k(b"ref"), v(b"1"))]);
    }
    Ok(Pass)
}

/// Without `atomic_multi_key` a batch holds one write and at most one key
/// precondition on that key (plus `NotAfter`); anything more is
/// `Unsupported` and writes nothing. With it, multi-key batches commit.
pub async fn kv_non_atomic_rejects_multi_write_batch<H: KvHarness>(h: H) -> Outcome {
    let (s, p) = (h.store(), part("kv_non_atomic_rejects_multi_write_batch"));
    let (ka, kb) = (k(b"a"), k(b"b"));
    // In this order each batch commits on an atomic store.
    let multi = [
        Batch::new()
            .put(ka.clone(), v(b"1"))
            .put(kb.clone(), v(b"1")),
        Batch::new()
            .require(Present(kb.clone()))
            .put(ka.clone(), v(b"2")),
        Batch::new()
            .require(Present(ka.clone()))
            .require(Present(kb.clone())),
        Batch::new().put(ka.clone(), v(b"1")).delete(ka.clone()),
    ];
    if s.capabilities().atomic_multi_key {
        for batch in multi {
            commit(&s, &p, batch).await?;
        }
        return Ok(Pass);
    }
    for batch in multi {
        ensure_err!(s.apply(&p, batch).await, StoreError::Unsupported(_));
        not_written(&s, &p, &ka).await?;
        not_written(&s, &p, &kb).await?;
    }
    let one = Batch::new()
        .require(NotAfter(u64::MAX))
        .require(Absent(ka.clone()))
        .put(ka.clone(), v(b"1"));
    commit(&s, &p, one).await?;
    commit(&s, &p, Batch::new().require(Present(ka.clone())).delete(ka)).await?;
    Ok(Pass)
}

/// The layout-version row `v` round-trips on stores that hold it.
pub async fn kv_layout_version_key_roundtrip<H: KvHarness>(h: H) -> Outcome {
    let (s, p) = (h.store(), part("kv_layout_version_key_roundtrip"));
    let key = keys::layout_version();
    let put = Batch::new()
        .require(Absent(key.clone()))
        .put(key.clone(), codec::encode_u32(keys::LAYOUT_VERSION));
    if s.capabilities().implicit_layout_version.is_some() {
        ensure_err!(s.apply(&p, put).await, StoreError::Unsupported(_));
        not_written(&s, &p, &key).await?;
        return Ok(Skip(
            "store reports implicit_layout_version; it never holds `v`",
        ));
    }
    commit(&s, &p, put).await?;
    let got = ok!(s.get(&p, &key).await).ok_or("`v` missing")?;
    ensure_eq!(ok!(codec::decode_u32(&got)), keys::LAYOUT_VERSION);
    Ok(Pass)
}

/// A `RefsOnly` store reports its implicit layout version (and exports
/// under it); a store of every class reports none and holds `v`.
pub async fn kv_refs_only_reports_implicit_layout_version<H: KvHarness>(h: H) -> Outcome {
    let (s, p) = (
        h.store(),
        part("kv_refs_only_reports_implicit_layout_version"),
    );
    let caps = s.capabilities();
    let refs_only = caps.key_classes == KeyClasses::RefsOnly;
    ensure_eq!(caps.implicit_layout_version.is_some(), refs_only);
    if let Some(version) = caps.implicit_layout_version {
        ensure!(
            version <= keys::LAYOUT_VERSION,
            "implicit version {version} is newer"
        );
        ensure_eq!(ok!(export_header(&s, &p, 0).await).layout_version, version);
    }
    Ok(Pass)
}

/// `probe` succeeds on a healthy store.
pub async fn kv_probe_ok<H: KvHarness>(h: H) -> Outcome {
    ok!(h.store().probe().await);
    Ok(Pass)
}

/// Every key is `<tag> 00 …`, so a class scan never sees a class whose tag
/// extends its own (`o`/`oq`, `p`/`px`/`pp`, `t`/`tb`, `e`/`el`, …).
pub async fn kv_class_tags_are_zero_terminated<H: KvHarness>(h: H) -> Outcome {
    let (s, p) = (h.store(), part("kv_class_tags_are_zero_terminated"));
    gate!(need_all_classes(&s, &p).await);
    let bodies: [&[u8]; 3] = [b"", b"\0", b"\xff\xff"];
    let all: Vec<_> = CLASS_TAGS
        .iter()
        .flat_map(|t| {
            bodies
                .iter()
                .map(move |b| (class_key(t, b), v(t.as_bytes())))
        })
        .collect();
    put_all(&s, &p, &all).await?;
    for tag in CLASS_TAGS {
        let (start, end) = keys::class_range(tag);
        let got = scan_all(&s, &p, (&start, &end), 5).await?;
        let want: Vec<_> = all
            .iter()
            .filter(|(_, val)| val.as_bytes() == tag.as_bytes())
            .cloned()
            .collect();
        ensure_eq!(got.len(), want.len());
        ensure!(
            got.iter().all(|r| want.contains(r)),
            "class {tag} scan saw another class"
        );
    }
    Ok(Pass)
}

/// Real clock: a deadline 60 s in the past fails as `DeadlinePassed`,
/// reporting a backend reading after it, and writes nothing.
pub async fn kv_not_after_past_deadline_fails_writing_nothing<H: KvHarness>(h: H) -> Outcome {
    let (s, p) = (
        h.store(),
        part("kv_not_after_past_deadline_fails_writing_nothing"),
    );
    for deadline in [wall_ms() - 60_000, 0] {
        let batch = Batch::new()
            .require(NotAfter(deadline))
            .put(k(b"a"), v(b"1"));
        match outcome(&s, &p, batch).await? {
            DeadlinePassed { backend_now } if backend_now > deadline => {}
            other => return Err(format!("deadline {deadline}: {other:?}")),
        }
    }
    ensure_eq!(rows(&s, &p).await?, vec![]);
    Ok(Pass)
}

/// Real clock: a deadline 60 s in the future commits.
pub async fn kv_not_after_future_deadline_commits<H: KvHarness>(h: H) -> Outcome {
    let (s, p) = (h.store(), part("kv_not_after_future_deadline_commits"));
    let batch = Batch::new()
        .require(NotAfter(wall_ms() + 60_000))
        .put(k(b"a"), v(b"1"));
    commit(&s, &p, batch).await?;
    ensure_eq!(ok!(s.get(&p, &k(b"a")).await), Some(v(b"1")));
    Ok(Pass)
}

/// `NotAfter` is checked in order with the key preconditions: a failing
/// deadline first is `DeadlinePassed` even if a later `Equals` fails too;
/// a failing `Equals` first wins over a later deadline.
pub async fn kv_not_after_is_checked_before_later_preconditions<H: KvHarness>(h: H) -> Outcome {
    let (s, p) = (
        h.store(),
        part("kv_not_after_is_checked_before_later_preconditions"),
    );
    let past = NotAfter(wall_ms() - 60_000);
    let wrong = Equals(k(b"a"), v(b"never"));
    let first = Batch::new()
        .require(past.clone())
        .require(wrong.clone())
        .put(k(b"a"), v(b"1"));
    ensure!(
        matches!(outcome(&s, &p, first).await?, DeadlinePassed { .. }),
        "a failing NotAfter at index 0 must be reported"
    );
    let second = Batch::new()
        .require(wrong)
        .require(past)
        .put(k(b"a"), v(b"1"));
    ensure_eq!(outcome(&s, &p, second).await?, failed(0, None));
    ensure_eq!(ok!(s.get(&p, &k(b"a")).await), None);
    Ok(Pass)
}

/// Injected clock: the deadline is read when the batch applies, not when
/// it was built; a reading equal to the deadline still commits.
pub async fn kv_not_after_evaluated_at_apply_not_at_build<H: KvHarness>(h: H) -> Outcome {
    let Some((s, clock)) = clocked(&h, 1_000) else {
        return Ok(NO_CLOCK);
    };
    let p = part("kv_not_after_evaluated_at_apply_not_at_build");
    let batch = || Batch::new().require(NotAfter(1_500)).put(k(b"a"), v(b"1"));
    let late = batch();
    clock.set(1_501);
    ensure_eq!(
        outcome(&s, &p, late).await?,
        DeadlinePassed { backend_now: 1_501 }
    );
    ensure_eq!(ok!(s.get(&p, &k(b"a")).await), None);
    clock.set(1_500);
    commit(&s, &p, batch()).await?;
    Ok(Pass)
}

/// Injected clock: the backend's clock decides, never the caller's.
pub async fn kv_not_after_uses_store_clock_not_caller_clock<H: KvHarness>(h: H) -> Outcome {
    let Some((s, clock)) = clocked(&h, 1_000) else {
        return Ok(NO_CLOCK);
    };
    let p = part("kv_not_after_uses_store_clock_not_caller_clock");
    // In the caller's (host clock's) past, in the store's future: commits.
    commit(
        &s,
        &p,
        Batch::new().require(NotAfter(2_000)).put(k(b"a"), v(b"1")),
    )
    .await?;
    // In the caller's future, in the store's past: fails.
    let future = wall_ms() + 60_000;
    let ahead = i64::try_from(future + 1).map_err(|e| e.to_string())?;
    clock.set(ahead);
    let batch = Batch::new().require(NotAfter(future)).put(k(b"a"), v(b"2"));
    ensure!(
        matches!(outcome(&s, &p, batch).await?, DeadlinePassed { .. }),
        "the store clock is past the deadline"
    );
    ensure_eq!(ok!(s.get(&p, &k(b"a")).await), Some(v(b"1")));
    Ok(Pass)
}

/// Injected clock: a reading before the epoch fails closed, as `u64::MAX`.
pub async fn kv_not_after_pre_epoch_clock_fails_closed<H: KvHarness>(h: H) -> Outcome {
    let Some((s, clock)) = clocked(&h, -5) else {
        return Ok(NO_CLOCK);
    };
    let p = part("kv_not_after_pre_epoch_clock_fails_closed");
    for now in [-5, -1, i64::MIN] {
        clock.set(now);
        let batch = Batch::new()
            .require(NotAfter(u64::MAX - 1))
            .put(k(b"a"), v(b"1"));
        ensure_eq!(
            outcome(&s, &p, batch).await?,
            DeadlinePassed {
                backend_now: u64::MAX
            }
        );
    }
    ensure_eq!(ok!(s.get(&p, &k(b"a")).await), None);
    Ok(Pass)
}

/// `NotAfter` names no key, so a single-key ref batch with a key
/// precondition and a deadline is accepted by every store, `RefsOnly` and
/// non-atomic ones included.
pub async fn kv_not_after_on_single_key_batch<H: KvHarness>(h: H) -> Outcome {
    let (s, p) = (h.store(), part("kv_not_after_on_single_key_batch"));
    let batch = |deadline| {
        Batch::new()
            .require(NotAfter(deadline))
            .require(Absent(k(b"a")))
            .put(k(b"a"), v(b"1"))
    };
    let late = outcome(&s, &p, batch(wall_ms() - 60_000)).await?;
    ensure!(
        matches!(late, DeadlinePassed { .. }),
        "late batch: {late:?}"
    );
    commit(&s, &p, batch(wall_ms() + 60_000)).await?;
    ensure_eq!(ok!(s.get(&p, &k(b"a")).await), Some(v(b"1")));
    Ok(Pass)
}

/// At its cap a store rejects batches that add data with `Full` and writes
/// nothing, keeps serving reads, and commits delete-only batches, their
/// preconditions included (rule 7); after pruning, puts work again.
pub async fn kv_full_store_rejects_writes_but_serves_reads_and_deletes<H: KvHarness>(
    h: H,
) -> Outcome {
    let Some(s) = h.store_with_capacity(16 * 1024) else {
        return Ok(Skip("harness cannot build a capacity-limited store"));
    };
    let p = part("kv_full_store_rejects_writes");
    let val = Value::new(vec![5; 1024]);
    let mut written = vec![];
    for i in 0_u8..=64 {
        let key = k(&[b'f', i]);
        match s
            .apply(&p, Batch::new().put(key.clone(), val.clone()))
            .await
        {
            Ok(Committed) => written.push(key),
            Err(StoreError::Full) => {
                ensure_eq!(ok!(s.get(&p, &key).await), None);
                break;
            }
            other => return Err(format!("filling the store: {other:?}")),
        }
    }
    ensure!(written.len() < 65, "the store never reported Full");
    ensure!(
        written.len() >= 2,
        "the store is full after {} rows",
        written.len()
    );
    ensure_eq!(rows(&s, &p).await?.len(), written.len());
    let (first, second) = (written[0].clone(), written[1].clone());
    let prune = if s.capabilities().atomic_multi_key {
        Batch::new()
            .require(Equals(first.clone(), val.clone()))
            .require(Present(second.clone()))
            .delete(first)
            .delete(second)
    } else {
        Batch::new()
            .require(Equals(first.clone(), val.clone()))
            .delete(first)
    };
    commit(&s, &p, prune).await?;
    commit(&s, &p, Batch::new().put(k(b"after"), v(b"1"))).await?;
    Ok(Pass)
}

/// `stats` grows with 1,000 rows and shrinks back (at least 90% of the
/// growth reclaimed) once they are deleted (rule 7, R-31).
pub async fn kv_stats_reports_growth_and_shrink<H: KvHarness>(h: H) -> Outcome {
    let (s, p) = (h.store(), part("kv_stats_reports_growth_and_shrink"));
    h.refresh_stats(&s).await;
    let base = ok!(s.stats(&p).await);
    let all: Vec<_> = (0_u16..1000)
        .map(|i| (k(&i.to_be_bytes()), Value::new(vec![3; 100])))
        .collect();
    put_all(&s, &p, &all).await?;
    h.refresh_stats(&s).await;
    let grown = ok!(s.stats(&p).await);
    ensure!(grown.bytes >= base.bytes + 100_000, "{base:?} -> {grown:?}");
    if let (Some(before), Some(after)) = (base.keys, grown.keys) {
        ensure_eq!(after, before + 1000);
    }
    let per = if s.capabilities().atomic_multi_key {
        50
    } else {
        1
    };
    for chunk in all.chunks(per) {
        let batch = chunk
            .iter()
            .fold(Batch::new(), |b, (key, _)| b.delete(key.clone()));
        commit(&s, &p, batch).await?;
    }
    h.refresh_stats(&s).await;
    let shrunk = ok!(s.stats(&p).await);
    let slack = (grown.bytes - base.bytes) / 10;
    ensure!(
        shrunk.bytes <= base.bytes + slack,
        "{grown:?} -> {shrunk:?}"
    );
    Ok(Pass)
}

/// A panic inside the check-and-write step (here: the store clock) leaves
/// the partition fully before or after the batch and the store usable
/// (rule 4: a poisoned lock is recovered, never propagated). The apply may
/// panic or return any error (a blocking adapter maps the join error).
pub async fn kv_panic_in_check_and_write_recovers<H: KvHarness>(h: H) -> Outcome {
    let Some((s, clock)) = clocked(&h, 1_000) else {
        return Ok(NO_CLOCK);
    };
    let p = part("kv_panic_in_check_and_write_recovers");
    commit(&s, &p, Batch::new().put(k(b"a"), v(b"1"))).await?;
    clock.panic_next();
    let batch = Batch::new()
        .require(NotAfter(u64::MAX))
        .put(k(b"b"), v(b"2"));
    let result = std::panic::AssertUnwindSafe(s.apply(&p, batch))
        .catch_unwind()
        .await;
    let after = rows(&s, &p).await?;
    let before = vec![(k(b"a"), v(b"1"))];
    let written = vec![(k(b"a"), v(b"1")), (k(b"b"), v(b"2"))];
    match result {
        Ok(Ok(Committed)) => ensure_eq!(after, written),
        Ok(Ok(other)) => return Err(format!("the batch could only commit: {other:?}")),
        Err(_) | Ok(Err(_)) => {
            ensure!(
                after == before || after == written,
                "torn partition: {after:?}"
            );
        }
    }
    commit(
        &s,
        &p,
        Batch::new().require(NotAfter(1_000)).put(k(b"c"), v(b"3")),
    )
    .await?;
    ensure_eq!(ok!(s.get(&p, &k(b"a")).await), Some(v(b"1")));
    Ok(Pass)
}
