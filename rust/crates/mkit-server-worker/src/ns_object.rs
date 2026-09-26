//! The Durable Object side of the key-level contract: decode one
//! [`NsRequest`], run it on the object's `SqlKvStore`, answer one
//! [`NsReply`].
//!
//! The object is a pure key-value store: it evaluates batch preconditions
//! (with `NotAfter` against its own clock) and nothing else. No pipeline
//! logic (CAS, quota, replay) runs in it, so any other backend can replace
//! it. [`serve`] is the whole protocol and is generic over the store, so
//! the host tests run it over a simulated Durable Object connection;
//! `NsObject` is the wasm32 shell around it.

use core::future::Future;
use mkit_server::sql::SqlError;
use mkit_server::storage_error::StorageOp;
use mkit_server::store::export_page;

use mkit_server::{Cursor, Key, NamespaceStore, Partition, ScanPage, StoreError};

use crate::wire::{Blob, NsCall, NsErrKind, NsReply, NsRequest, WireOutcome};

/// Answer one request body with a reply body. Never fails: a malformed
/// request is an `Invalid` reply, a failed store an error reply whose
/// backend detail goes to the log only.
pub async fn serve<S: NamespaceStore>(store: &S, body: &str) -> String {
    let reply = match serde_json::from_str::<NsRequest>(body) {
        Ok(request) => match Partition::decode(&request.part.0) {
            Ok(p) => dispatch(store, &p, request.call)
                .await
                .unwrap_or_else(|e| failure(&e)),
            Err(_) => NsReply::Err {
                kind: NsErrKind::Invalid,
                message: "malformed partition".into(),
            },
        },
        Err(_) => NsReply::Err {
            kind: NsErrKind::Invalid,
            message: "malformed request".into(),
        },
    };
    encode(&reply)
}

/// A reply body.
pub(crate) fn encode(reply: &NsReply) -> String {
    serde_json::to_string(reply).unwrap_or_else(|_| {
        // Serializing these types cannot fail; stay total anyway.
        r#"{"reply":"err","kind":"unavailable","message":"reply encoding failed"}"#.to_owned()
    })
}

/// The reply for a store failure, logging an `Unavailable`'s detail.
pub(crate) fn failure(e: &StoreError) -> NsReply {
    if let StoreError::Unavailable(source) = e {
        // A SQL failure keeps its engine text redacted: expose it here, for
        // the log only.
        let detail = match source.downcast_ref::<SqlError>() {
            Some(SqlError::Backend(text)) => text.expose().to_owned(),
            _ => source.to_string(),
        };
        let (line, _) = mkit_server::storage_error::describe_and_map(StorageOp::SqlExec, detail);
        crate::log_failure(&line);
    }
    NsReply::error(e)
}

async fn dispatch<S: NamespaceStore>(
    store: &S,
    p: &Partition,
    call: NsCall,
) -> Result<NsReply, StoreError> {
    let key = |b: Blob| Key::new(b.0);
    Ok(match call {
        NsCall::Get { key: k } => NsReply::Value {
            value: store
                .get(p, &key(k))
                .await?
                .map(|v| Blob(v.into_bytes().into())),
        },
        NsCall::GetMany { keys } => {
            let keys: Vec<Key> = keys.into_iter().map(key).collect();
            NsReply::Values {
                values: store
                    .get_many(p, &keys)
                    .await?
                    .into_iter()
                    .map(|v| v.map(|v| Blob(v.into_bytes().into())))
                    .collect(),
            }
        }
        NsCall::Scan {
            start,
            end,
            after,
            limit,
        } => {
            let (start, end) = (key(start), key(end));
            let (start, end) = (&start, &end);
            let page = bounded_page(
                limit,
                after.map(|c| Cursor::new(c.0)),
                |after, n| async move { store.scan(p, start, end, after.as_ref(), n).await },
            )
            .await?;
            NsReply::page(page)
        }
        NsCall::Apply { batch } => NsReply::Outcome {
            outcome: WireOutcome::from(store.apply(p, batch.into()).await?),
        },
        NsCall::Stats => {
            let stats = store.stats(p).await?;
            NsReply::Stats {
                bytes: stats.bytes,
                keys: stats.keys,
            }
        }
        NsCall::Probe => {
            store.probe().await?;
            NsReply::Ok
        }
        NsCall::Export { after, limit } => {
            let page = bounded_page(
                limit,
                after.map(|c| Cursor::new(c.0)),
                |after, n| async move {
                    let page = export_page(store, p, after.as_ref(), n).await?;
                    Ok(ScanPage {
                        entries: page.records.into_iter().map(|r| (r.key, r.value)).collect(),
                        next: page.next,
                    })
                },
            )
            .await?;
            NsReply::page(page)
        }
    })
}

/// Most entries one scan or export page returns, whatever the caller asks.
pub const MAX_PAGE_ENTRIES: u32 = 1000;

/// Key and value bytes after which a scan or export page ends early and
/// returns `next`: a page of 512 KiB values stays a few MiB of JSON in a
/// 128 MB isolate, not hundreds.
pub const MAX_PAGE_BYTES: usize = 8 * 1024 * 1024;

/// Entries read from the store per step: one step overshoots the byte
/// budget by at most this many maximum-size values.
const PAGE_STEP: u32 = 16;

/// A page of at most `limit` (clamped to [`MAX_PAGE_ENTRIES`]) entries and
/// about [`MAX_PAGE_BYTES`], read in steps of [`PAGE_STEP`] through `step`
/// (`after`, `limit`) → page. A short page with `next` is allowed by the
/// contract: callers page until `next` is `None`.
async fn bounded_page<F, Fut>(
    limit: u32,
    after: Option<Cursor>,
    mut step: F,
) -> Result<ScanPage, StoreError>
where
    F: FnMut(Option<Cursor>, u32) -> Fut,
    Fut: Future<Output = Result<ScanPage, StoreError>>,
{
    if limit == 0 {
        // The store's own `Invalid`.
        return step(after, 0).await;
    }
    let limit = limit.min(MAX_PAGE_ENTRIES);
    let (mut page, mut bytes, mut cursor) = (ScanPage::default(), 0, after);
    loop {
        let have = u32::try_from(page.entries.len()).unwrap_or(limit);
        let got = step(cursor.take(), (limit - have).min(PAGE_STEP)).await?;
        bytes += got
            .entries
            .iter()
            .map(|(k, v)| k.as_bytes().len() + v.as_bytes().len())
            .sum::<usize>();
        page.entries.extend(got.entries);
        match got.next {
            Some(next) if page.entries.len() < limit as usize && bytes < MAX_PAGE_BYTES => {
                cursor = Some(next);
            }
            next => {
                page.next = next;
                return Ok(page);
            }
        }
    }
}

#[cfg(target_arch = "wasm32")]
pub use object::{DoConn, NsObject};

#[cfg(target_arch = "wasm32")]
mod object {
    use std::cell::OnceCell;

    use mkit_server::sql::{Capacity, SqlKvStore};
    use worker::{Method, Request, Response, State};

    use super::{encode, failure, serve};
    use crate::do_sql::{DO_CAPACITY, DoSqlConn};

    /// The connection a partition's Durable Object runs its store on: the
    /// fail-once fault wraps it under `test-faults`.
    #[cfg(feature = "test-faults")]
    pub type DoConn = crate::faults::FaultConn<DoSqlConn>;
    /// The connection a partition's Durable Object runs its store on: the
    /// fail-once fault wraps it under `test-faults`.
    #[cfg(not(feature = "test-faults"))]
    pub type DoConn = DoSqlConn;

    /// One partition's Durable Object: its store, opened (and migrated) on
    /// the first request and kept for the object's lifetime. The
    /// `#[durable_object]` class itself stays in the deployment's cdylib
    /// (M0-17) and holds one of these.
    #[derive(Debug)]
    pub struct NsObject {
        conn: DoConn,
        capacity: Capacity,
        store: OnceCell<SqlKvStore<DoConn>>,
    }

    impl NsObject {
        /// The object for `state`, capped at [`DO_CAPACITY`]; gives the
        /// state back.
        #[must_use]
        pub fn new(state: State) -> (Self, State) {
            let (conn, state) = DoSqlConn::from_state(state);
            #[cfg(feature = "test-faults")]
            let conn = crate::faults::FaultConn::new(conn);
            let object = Self {
                conn,
                capacity: DO_CAPACITY,
                store: OnceCell::new(),
            };
            (object, state)
        }

        /// Cap the store at `capacity` instead (e.g. Workers Free's 1 GB,
        /// [`crate::do_sql::DO_FREE_MAX_BYTES`]).
        #[must_use]
        pub fn with_capacity(mut self, capacity: Capacity) -> Self {
            self.capacity = capacity;
            self
        }

        /// The store, opened on first use: migration runs once per
        /// instance.
        fn store(&self) -> Result<&SqlKvStore<DoConn>, mkit_server::StoreError> {
            if let Some(store) = self.store.get() {
                return Ok(store);
            }
            let store = SqlKvStore::open_with_capacity(self.conn.clone(), self.capacity)?;
            Ok(self.store.get_or_init(|| store))
        }

        /// Answer one `POST` from [`crate::ns_client`].
        pub async fn handle(&self, mut req: Request) -> worker::Result<Response> {
            if req.method() != Method::Post {
                return Response::error("method not allowed", 405);
            }
            let body = req.text().await?;
            let reply = match self.store() {
                Ok(store) => serve(store, &body).await,
                Err(e) => encode(&failure(&e)),
            };
            let mut response = Response::ok(reply)?;
            response
                .headers_mut()
                .set("Content-Type", "application/json")?;
            Ok(response)
        }
    }
}

#[cfg(test)]
mod tests {
    use futures::executor::block_on;
    use mkit_server::{Batch, MemoryKv, Precondition, Value};

    use super::*;
    use crate::wire::WireBatch;

    fn request(call: NsCall) -> String {
        let p = Partition::decode(b"nroot\0").unwrap();
        serde_json::to_string(&NsRequest::new(&p, call).unwrap()).unwrap()
    }

    fn reply(store: &MemoryKv, call: NsCall) -> NsReply {
        serde_json::from_str(&block_on(serve(store, &request(call)))).unwrap()
    }

    #[test]
    fn serve_dispatches_and_reports_typed_errors() {
        let store = MemoryKv::default();
        let k = Key::new(b"r\0x".to_vec());
        let batch = Batch::new()
            .require(Precondition::Absent(k.clone()))
            .put(k.clone(), Value::new(b"1".to_vec()));
        let apply = || NsCall::Apply {
            batch: WireBatch::from(batch.clone()),
        };
        assert_eq!(
            reply(&store, apply()),
            NsReply::Outcome {
                outcome: WireOutcome::Committed
            }
        );
        assert!(matches!(
            reply(&store, apply()),
            NsReply::Outcome {
                outcome: WireOutcome::PreconditionFailed { index: 0, .. }
            }
        ));
        assert_eq!(
            reply(
                &store,
                NsCall::Get {
                    key: Blob(b"r\0x".to_vec())
                }
            ),
            NsReply::Value {
                value: Some(Blob(b"1".to_vec()))
            }
        );
        assert_eq!(reply(&store, NsCall::Probe), NsReply::Ok);
        let NsReply::Page { entries, next } = reply(
            &store,
            NsCall::Export {
                after: None,
                limit: 10,
            },
        ) else {
            panic!("not a page");
        };
        assert_eq!(entries, vec![(Blob(b"r\0x".to_vec()), Blob(b"1".to_vec()))]);
        assert_eq!(next, None);
        // A zero scan limit is the store's `Invalid`, typed on the wire.
        assert!(matches!(
            reply(
                &store,
                NsCall::Scan {
                    start: Blob::default(),
                    end: Blob(vec![0xff]),
                    after: None,
                    limit: 0
                }
            ),
            NsReply::Err {
                kind: NsErrKind::Invalid,
                ..
            }
        ));
        for body in ["", "{}", r#"{"part":"!!","call":{"op":"probe"}}"#] {
            let r: NsReply = serde_json::from_str(&block_on(serve(&store, body))).unwrap();
            assert!(
                matches!(
                    r,
                    NsReply::Err {
                        kind: NsErrKind::Invalid,
                        ..
                    }
                ),
                "{body}: {r:?}"
            );
        }
        let bad_part = r#"{"part":"cQ==","call":{"op":"probe"}}"#;
        let r: NsReply = serde_json::from_str(&block_on(serve(&store, bad_part))).unwrap();
        assert!(matches!(
            r,
            NsReply::Err {
                kind: NsErrKind::Invalid,
                ..
            }
        ));
    }

    fn put(store: &MemoryKv, k: Vec<u8>, v: Vec<u8>) {
        let p = Partition::decode(b"nroot\0").unwrap();
        block_on(store.apply(&p, Batch::new().put(Key::new(k), Value::new(v)))).unwrap();
    }

    /// Page through `call(after)` to the end; each page's raw byte size.
    fn pages(
        store: &MemoryKv,
        call: impl Fn(Option<Blob>) -> NsCall,
    ) -> (Vec<Vec<u8>>, Vec<usize>) {
        let (mut keys, mut sizes, mut after) = (Vec::new(), Vec::new(), None);
        loop {
            let NsReply::Page { entries, next } = reply(store, call(after.take())) else {
                panic!("not a page");
            };
            assert!(entries.len() <= MAX_PAGE_ENTRIES as usize);
            sizes.push(entries.iter().map(|(k, v)| k.0.len() + v.0.len()).sum());
            keys.extend(entries.into_iter().map(|(k, _)| k.0));
            match next {
                Some(n) => after = Some(n),
                None => return (keys, sizes),
            }
        }
    }

    #[test]
    fn scan_and_export_pages_are_clamped_and_byte_bounded() {
        // 40 maximum-size values: 20 MiB, over the page byte budget.
        let big = MemoryKv::default();
        let key = |i: u16| [b"r\0big\0".as_slice(), &i.to_be_bytes()].concat();
        for i in 0..40 {
            put(&big, key(i), vec![7; mkit_server::MAX_VALUE_BYTES]);
        }
        let scan = |after| NsCall::Scan {
            start: Blob::default(),
            end: Blob(vec![0xff]),
            after,
            limit: u32::MAX,
        };
        let export = |after| NsCall::Export {
            after,
            limit: u32::MAX,
        };
        let step = PAGE_STEP as usize * (mkit_server::MAX_VALUE_BYTES + 1024);
        for call in [&scan as &dyn Fn(Option<Blob>) -> NsCall, &export] {
            let (keys, sizes) = pages(&big, call);
            assert_eq!(keys, (0..40).map(key).collect::<Vec<_>>());
            assert!(sizes.len() > 1, "{sizes:?}");
            assert!(
                sizes.iter().all(|&s| s <= MAX_PAGE_BYTES + step),
                "{sizes:?}"
            );
        }
        // 1,100 small rows: a limit of u32::MAX returns at most 1,000.
        let small = MemoryKv::default();
        for i in 0..1100_u16 {
            put(&small, key(i), vec![1]);
        }
        for call in [&scan as &dyn Fn(Option<Blob>) -> NsCall, &export] {
            let NsReply::Page { entries, next } = reply(&small, call(None)) else {
                panic!("not a page");
            };
            assert_eq!(entries.len(), MAX_PAGE_ENTRIES as usize);
            assert!(next.is_some());
            assert_eq!(pages(&small, call).0.len(), 1100);
        }
    }
}
