//! [`BlobStore`] cases: content addressing, length checks, visibility,
//! ranges, streaming and deletion.

use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use futures::StreamExt as _;
use mkit_core::hash::hash;
use mkit_server::{BlobBody, BlobKey, BlobStore, ByteRange, CommitOutcome, PackSink, StoreError};

use super::CaseResult::Pass;
use super::{BlobHarness, Outcome};

/// Largest piece a streamed body may carry (R-25).
const MAX_PIECE: usize = 1024 * 1024;

fn key_of(bytes: &[u8]) -> BlobKey {
    BlobKey::new(hash(bytes))
}

/// Upload `chunks` under `key`, declaring `len` bytes.
async fn put<B: BlobStore>(
    store: &B,
    key: BlobKey,
    len: u64,
    chunks: &[&[u8]],
) -> Result<CommitOutcome, StoreError> {
    let mut sink = store.begin(key, len).await?;
    for chunk in chunks {
        sink.write(Bytes::copy_from_slice(chunk)).await?;
    }
    sink.commit().await
}

/// A body's bytes; checks a stream's declared length and piece sizes.
async fn read(body: BlobBody) -> Result<Bytes, String> {
    match body {
        BlobBody::Bytes(bytes) => Ok(bytes),
        BlobBody::Stream { len, mut stream } => {
            let mut out = BytesMut::new();
            while let Some(piece) = stream.next().await {
                let piece = ok!(piece);
                ensure!(piece.len() <= MAX_PIECE, "a {}-byte piece", piece.len());
                out.extend_from_slice(&piece);
            }
            ensure_eq!(out.len() as u64, len);
            Ok(out.freeze())
        }
    }
}

/// The whole blob, or `range` of it; `None` if absent.
async fn get<B: BlobStore>(
    store: &B,
    key: &BlobKey,
    range: Option<ByteRange>,
) -> Result<Option<Bytes>, String> {
    match ok!(store.get(key, range).await) {
        Some(body) => Ok(Some(read(body).await?)),
        None => Ok(None),
    }
}

/// Nothing is visible under `key`.
async fn absent<B: BlobStore>(store: &B, key: &BlobKey) -> Result<(), String> {
    ensure_eq!(ok!(store.head(key).await), None);
    ensure_eq!(get(store, key, None).await?, None);
    Ok(())
}

/// A committed blob reads back whole, with its length.
pub async fn blob_roundtrip<H: BlobHarness>(h: H) -> Outcome {
    let s = h.store();
    let key = key_of(b"hello world");
    ensure_eq!(
        ok!(put(&s, key, 11, &[b"hello world"]).await),
        CommitOutcome::Created
    );
    ensure_eq!(
        get(&s, &key, None).await?,
        Some(Bytes::from_static(b"hello world"))
    );
    Ok(Pass)
}

/// The empty blob commits with no writes and reads back empty.
pub async fn blob_zero_length<H: BlobHarness>(h: H) -> Outcome {
    let s = h.store();
    let key = key_of(b"");
    ensure_eq!(ok!(put(&s, key, 0, &[]).await), CommitOutcome::Created);
    ensure_eq!(get(&s, &key, None).await?, Some(Bytes::new()));
    ensure_eq!(ok!(s.head(&key).await).map(|m| m.len), Some(0));
    Ok(Pass)
}

/// Bytes whose BLAKE3 is not the key are `Invalid`; nothing is visible
/// under either key.
pub async fn blob_hash_mismatch_rejected_nothing_visible<H: BlobHarness>(h: H) -> Outcome {
    let s = h.store();
    let wrong = key_of(b"other");
    ensure_err!(put(&s, wrong, 5, &[b"hello"]).await, StoreError::Invalid(_));
    absent(&s, &wrong).await?;
    absent(&s, &key_of(b"hello")).await?;
    Ok(Pass)
}

/// Fewer bytes than declared are `Invalid` at commit; nothing is visible.
pub async fn blob_len_short_rejected<H: BlobHarness>(h: H) -> Outcome {
    let s = h.store();
    let key = key_of(b"hello");
    ensure_err!(put(&s, key, 6, &[b"hello"]).await, StoreError::Invalid(_));
    absent(&s, &key).await?;
    Ok(Pass)
}

/// More bytes than declared are `Invalid` (at the write or the commit);
/// nothing is visible.
pub async fn blob_len_long_rejected<H: BlobHarness>(h: H) -> Outcome {
    let s = h.store();
    let key = key_of(b"hello");
    ensure_err!(
        put(&s, key, 4, &[b"hel", b"lo"]).await,
        StoreError::Invalid(_)
    );
    absent(&s, &key).await?;
    Ok(Pass)
}

/// An aborted upload leaves nothing visible; the key can be uploaded later.
pub async fn blob_abort_leaves_nothing<H: BlobHarness>(h: H) -> Outcome {
    let s = h.store();
    let key = key_of(b"hello");
    let mut sink = ok!(s.begin(key, 5).await);
    ok!(sink.write(Bytes::from_static(b"hello")).await);
    sink.abort().await;
    absent(&s, &key).await?;
    ensure_eq!(
        ok!(put(&s, key, 5, &[b"hello"]).await),
        CommitOutcome::Created
    );
    Ok(Pass)
}

/// A sink dropped without `commit` or `abort` leaves nothing visible.
pub async fn blob_dropped_sink_leaves_nothing<H: BlobHarness>(h: H) -> Outcome {
    let s = h.store();
    let key = key_of(b"hello");
    let mut sink = ok!(s.begin(key, 5).await);
    ok!(sink.write(Bytes::from_static(b"hello")).await);
    drop(sink);
    absent(&s, &key).await?;
    ensure_eq!(
        ok!(put(&s, key, 5, &[b"hello"]).await),
        CommitOutcome::Created
    );
    Ok(Pass)
}

/// Re-uploading identical bytes succeeds (`AlreadyPresent`, or `Created`
/// from a backend that cannot tell cheaply) and leaves the blob intact.
pub async fn blob_identical_reput_already_present<H: BlobHarness>(h: H) -> Outcome {
    let s = h.store();
    let key = key_of(b"hello");
    ok!(put(&s, key, 5, &[b"he", b"llo"]).await);
    ok!(put(&s, key, 5, &[b"hello"]).await);
    ensure_eq!(
        get(&s, &key, None).await?,
        Some(Bytes::from_static(b"hello"))
    );
    Ok(Pass)
}

/// Two concurrent uploads of the same blob both succeed.
pub async fn blob_concurrent_same_key_both_succeed<H: BlobHarness>(h: H) -> Outcome {
    let s = Arc::new(h.store());
    let data = Bytes::from(vec![9_u8; 256 * 1024]);
    let key = key_of(&data);
    let tasks: Vec<_> = (0..2)
        .map(|_| {
            let (s, data) = (s.clone(), data.clone());
            tokio::spawn(async move {
                let pieces: Vec<&[u8]> = data.chunks(4096).collect();
                put(&*s, key, data.len() as u64, &pieces).await
            })
        })
        .collect();
    for task in tasks {
        ok!(ok!(task.await));
    }
    ensure_eq!(get(&*s, &key, None).await?, Some(data));
    Ok(Pass)
}

/// A missing blob: `get` and `head` are `None`, `delete` is `false`.
pub async fn blob_get_missing_none<H: BlobHarness>(h: H) -> Outcome {
    let s = h.store();
    let key = key_of(b"never");
    absent(&s, &key).await?;
    ensure!(!ok!(s.delete(&key).await), "deleting a missing blob");
    Ok(Pass)
}

/// `head` reports the committed length.
pub async fn blob_head_len<H: BlobHarness>(h: H) -> Outcome {
    let s = h.store();
    let data = vec![1_u8; 1000];
    let key = key_of(&data);
    ok!(put(&s, key, 1000, &[&data[..300], &data[300..]]).await);
    ensure_eq!(ok!(s.head(&key).await).map(|m| m.len), Some(1000));
    Ok(Pass)
}

/// Ranges are inclusive and clamped to the end; a start at or past the end
/// is `RangeNotSatisfiable`, a start after the end `Invalid`.
pub async fn blob_range_first_middle_last<H: BlobHarness>(h: H) -> Outcome {
    let s = h.store();
    let key = key_of(b"0123456789");
    ok!(put(&s, key, 10, &[b"0123456789"]).await);
    let range = |start, end_inclusive| {
        Some(ByteRange {
            start,
            end_inclusive,
        })
    };
    for (start, end, want) in [(0, 0, "0"), (3, 5, "345"), (9, 9, "9"), (8, 100, "89")] {
        let got = get(&s, &key, range(start, end)).await?;
        ensure_eq!(got, Some(Bytes::from_static(want.as_bytes())));
    }
    let past = s.get(&key, range(10, 12)).await;
    ensure_err!(past, StoreError::RangeNotSatisfiable { len: 10 });
    ensure_err!(s.get(&key, range(5, 4)).await, StoreError::Invalid(_));
    Ok(Pass)
}

/// Many writes of varying size keep their order.
pub async fn blob_multi_chunk_write_order<H: BlobHarness>(h: H) -> Outcome {
    let s = h.store();
    let data: Vec<u8> = (0..251_u8).cycle().take(100_000).collect();
    let mut pieces: Vec<&[u8]> = vec![];
    let (mut at, mut size) = (0, 1);
    while at < data.len() {
        let end = (at + size).min(data.len());
        pieces.push(&data[at..end]);
        (at, size) = (end, size * 3 % 7919 + 1);
    }
    let key = key_of(&data);
    ok!(put(&s, key, data.len() as u64, &pieces).await);
    ensure_eq!(get(&s, &key, None).await?, Some(Bytes::from(data)));
    Ok(Pass)
}

/// `probe` succeeds on a healthy store.
pub async fn blob_probe_ok<H: BlobHarness>(h: H) -> Outcome {
    ok!(h.store().probe().await);
    Ok(Pass)
}

/// A deleted blob is gone (R-06); a second delete is `false`; it can be
/// uploaded again.
pub async fn blob_delete_then_get_none<H: BlobHarness>(h: H) -> Outcome {
    let s = h.store();
    let key = key_of(b"x");
    ok!(put(&s, key, 1, &[b"x"]).await);
    ensure!(ok!(s.delete(&key).await), "delete of a present blob");
    absent(&s, &key).await?;
    ensure!(!ok!(s.delete(&key).await), "second delete");
    ensure_eq!(ok!(put(&s, key, 1, &[b"x"]).await), CommitOutcome::Created);
    Ok(Pass)
}

/// A 5 MiB blob is served as a stream of pieces of at most 1 MiB, never
/// one buffer (R-25); a large range reads back exactly.
pub async fn blob_get_large_is_streamed<H: BlobHarness>(h: H) -> Outcome {
    let s = h.store();
    let data: Bytes = (0..253_u8).cycle().take(5 * 1024 * 1024).collect();
    let key = key_of(&data);
    let pieces: Vec<&[u8]> = data.chunks(64 * 1024).collect();
    ok!(put(&s, key, data.len() as u64, &pieces).await);
    let body = ok!(s.get(&key, None).await).ok_or("large blob missing")?;
    ensure!(
        matches!(body, BlobBody::Stream { .. }),
        "not streamed: {body:?}"
    );
    ensure_eq!(read(body).await?, data);
    let range = ByteRange {
        start: 1,
        end_inclusive: 3 * 1024 * 1024,
    };
    let got = get(&s, &key, Some(range)).await?;
    ensure_eq!(got, Some(data.slice(1..=3 * 1024 * 1024)));
    Ok(Pass)
}
