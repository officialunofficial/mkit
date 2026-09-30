//! [`DoNamespaceStore`]: the Worker-side [`NamespaceStore`]. Every call is
//! one POST to the Durable Object that holds its partition
//! ([`crate::naming::do_target`]), carrying one [`NsRequest`]; the object
//! answers one [`NsReply`] ([`crate::ns_object`]).
//!
//! One Durable Object round trip per method (a Durable Object sustains
//! roughly 200 to 500 writing requests per second): `get_many` and `apply`
//! are one call each, and the client never has more than one call in
//! flight. Batches are validated here as well as in the object, so an
//! oversize batch costs no round trip. Transport and decode failures are
//! logged and returned as `Unavailable` with a fixed message; a typed
//! [`NsReply::Err`] keeps its kind (`Full` stays `Full`).

use core::future::Future;
use mkit_server::indexed::budget::SliceBudget;

use mkit_server::storage_error::StorageOp;
use mkit_server::store::ExportPage;
use mkit_server::{
    Batch, BatchOutcome, Cursor, Key, MAX_SCAN_RANGES, MaybeSend, MaybeSync, NamespaceStore,
    Partition, PartitionStats, RangeScan, ScanPage, StoreCapabilities, StoreError, Value,
};

use crate::backend_error;
use crate::naming::{DoTarget, do_target};
use crate::wire::{self, Blob, NsCall, NsReply, NsRequest, WireBatch, WireRangeScan};

/// Delivers one request body to a Durable Object and returns its reply
/// body: Durable Object stubs on Workers (`StubTransport`, wasm32), an
/// in-process loopback in tests.
pub trait NsTransport: MaybeSend + MaybeSync {
    /// POST `body` to `target`'s `/<op>`. A failure to deliver it or a
    /// non-success status is `Unavailable` (logged, redacted).
    fn call(
        &self,
        target: &DoTarget,
        op: &'static str,
        body: String,
    ) -> impl Future<Output = Result<String, StoreError>> + MaybeSend;
}

/// Charge before dispatch; clients and spawned work retain the same counter.
///
/// # Errors
/// Returns unavailable once the invocation's backend allowance is spent.
pub fn charge_request(budget: Option<&SliceBudget>) -> Result<(), StoreError> {
    budget.map_or(Ok(()), SliceBudget::charge)
}

/// The key-level store over per-partition Durable Objects.
#[derive(Debug, Clone)]
pub struct DoNamespaceStore<T> {
    transport: T,
    probe_partition: Partition,
    reserved_batch_ops: usize,
    request_budget: Option<SliceBudget>,
}

fn op(call: &NsCall) -> &'static str {
    match call {
        NsCall::Get { .. } => "get",
        NsCall::GetMany { .. } => "get_many",
        NsCall::Scan { .. } => "scan",
        NsCall::ScanMany { .. } => "scan_many",
        NsCall::Apply { .. } => "apply",
        NsCall::Stats => "stats",
        NsCall::Probe => "probe",
        NsCall::Export { .. } => "export",
        #[cfg(feature = "test-faults")]
        NsCall::TestSnapshot => "test_snapshot",
        #[cfg(feature = "test-faults")]
        NsCall::TestImport { .. } => "test_import",
    }
}

fn unexpected(reply: &NsReply) -> StoreError {
    backend_error(
        StorageOp::MetaDecode,
        format_args!("unexpected reply {reply:?}"),
    )
}

fn blob(bytes: &[u8]) -> Blob {
    Blob::from(bytes)
}

impl<T: NsTransport> DoNamespaceStore<T> {
    /// A store whose calls go through `transport`.
    #[must_use]
    pub fn new(transport: T, probe_partition: Partition) -> Self {
        Self {
            transport,
            probe_partition,
            reserved_batch_ops: 0,
            request_budget: None,
        }
    }

    /// Share an invocation's backend allowance with its other clients.
    #[must_use]
    pub fn with_budget(mut self, budget: SliceBudget) -> Self {
        self.request_budget = Some(budget);
        self
    }

    /// Reserve operations for an explicitly configured target-local apply seam.
    #[must_use]
    pub fn with_apply_reserve(mut self, ops: usize) -> Self {
        self.reserved_batch_ops = ops;
        self
    }

    /// The transport.
    #[must_use]
    pub fn transport(&self) -> &T {
        &self.transport
    }

    async fn call(&self, p: &Partition, call: NsCall) -> Result<NsReply, StoreError> {
        let target = do_target(p)?;
        let op = op(&call);
        let body = serde_json::to_string(&NsRequest::new(p, call)?)
            .map_err(|e| backend_error(StorageOp::RequestSerialize, e))?;
        charge_request(self.request_budget.as_ref())?;
        let reply = self.transport.call(&target, op, body).await?;
        match serde_json::from_str::<NsReply>(&reply) {
            Ok(NsReply::Err { kind, message }) => Err(kind.into_error(message)),
            Ok(reply) => Ok(reply),
            Err(e) => Err(backend_error(StorageOp::MetaDecode, e)),
        }
    }

    /// One page of the portable export of `p` (M0-02b), read in the
    /// partition's Durable Object: for app-level dumps (WP-1.29).
    ///
    /// # Errors
    /// As [`NamespaceStore::scan`].
    pub async fn export_page(
        &self,
        p: &Partition,
        after: Option<&Cursor>,
        limit: u32,
    ) -> Result<ExportPage, StoreError> {
        let call = NsCall::Export {
            after: after.map(|c| blob(c.as_bytes())),
            limit,
        };
        match self.call(p, call).await? {
            NsReply::Page { entries, next } => {
                let mut page = ExportPage::default();
                page.records = wire::export_records(p, entries);
                page.next = next.map(|c| Cursor::new(c.0));
                Ok(page)
            }
            other => Err(unexpected(&other)),
        }
    }
}

impl<T: NsTransport> NamespaceStore for DoNamespaceStore<T> {
    fn capabilities(&self) -> StoreCapabilities {
        let mut caps = StoreCapabilities::full();
        caps.reserved_batch_ops = self.reserved_batch_ops;
        caps
    }

    async fn get(&self, p: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
        let call = NsCall::Get {
            key: blob(key.as_bytes()),
        };
        match self.call(p, call).await? {
            NsReply::Value { value } => Ok(wire::into_value(value)),
            other => Err(unexpected(&other)),
        }
    }

    async fn get_many(
        &self,
        p: &Partition,
        keys: &[Key],
    ) -> Result<Vec<Option<Value>>, StoreError> {
        if keys.is_empty() {
            return Ok(Vec::new());
        }
        let call = NsCall::GetMany {
            keys: keys.iter().map(|k| blob(k.as_bytes())).collect(),
        };
        match self.call(p, call).await? {
            NsReply::Values { values } if values.len() == keys.len() => {
                Ok(values.into_iter().map(wire::into_value).collect())
            }
            other => Err(unexpected(&other)),
        }
    }

    async fn scan(
        &self,
        p: &Partition,
        start: &Key,
        end: &Key,
        after: Option<&Cursor>,
        limit: u32,
    ) -> Result<ScanPage, StoreError> {
        let call = NsCall::Scan {
            start: blob(start.as_bytes()),
            end: blob(end.as_bytes()),
            after: after.map(|c| blob(c.as_bytes())),
            limit,
        };
        match self.call(p, call).await? {
            NsReply::Page { entries, next } => Ok(wire::scan_page(entries, next)),
            other => Err(unexpected(&other)),
        }
    }

    async fn scan_many(
        &self,
        p: &Partition,
        ranges: &[RangeScan],
    ) -> Result<Vec<ScanPage>, StoreError> {
        if ranges.len() > MAX_SCAN_RANGES {
            return Err(StoreError::Invalid("too many scan ranges".into()));
        }
        if ranges.is_empty() {
            return Ok(Vec::new());
        }
        let requested = ranges.len();
        let ranges = ranges
            .iter()
            .map(|r| WireRangeScan {
                start: blob(r.start.as_bytes()),
                end: blob(r.end.as_bytes()),
                after: r.after.as_ref().map(|c| blob(c.as_bytes())),
                limit: r.limit,
            })
            .collect();
        match self.call(p, NsCall::ScanMany { ranges }).await? {
            NsReply::Pages { pages } if !pages.is_empty() && pages.len() <= requested => Ok(pages
                .into_iter()
                .map(|page| wire::scan_page(page.entries, page.next))
                .collect()),
            other => Err(unexpected(&other)),
        }
    }

    async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        let mut caps = self.capabilities();
        // Only RefIndex targets append snapshot metadata. RefShard planners
        // retain the full batch limit for writes and opportunistic pruning.
        if !matches!(p, Partition::RefIndex { .. }) {
            caps.reserved_batch_ops = 0;
        }
        batch.validate(&caps)?;
        let call = NsCall::Apply {
            batch: WireBatch::from(batch),
        };
        match self.call(p, call).await? {
            NsReply::Outcome { outcome } => Ok(outcome.into()),
            other => Err(unexpected(&other)),
        }
    }

    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        match self.call(p, NsCall::Stats).await? {
            NsReply::Stats { bytes, keys } => Ok(wire::stats(bytes, keys)),
            other => Err(unexpected(&other)),
        }
    }

    /// Probe the partition selected by the deployment adapter.
    async fn probe(&self) -> Result<(), StoreError> {
        match self.call(&self.probe_partition, NsCall::Probe).await? {
            NsReply::Ok => Ok(()),
            other => Err(unexpected(&other)),
        }
    }
}

#[cfg(target_arch = "wasm32")]
pub use stub::{StubTransport, WorkerNamespaceStore};

#[cfg(target_arch = "wasm32")]
mod stub {
    use mkit_server::StoreError;
    use mkit_server::storage_error::StorageOp;
    use worker::js_sys;
    use worker::wasm_bindgen::{JsCast, JsValue};
    use worker::{Env, Method, ObjectNamespace, Request, RequestInit};

    use super::{DoNamespaceStore, NsTransport};
    use crate::backend_error;
    use crate::naming::{DoTarget, Placement};

    /// Durable Object stubs from a `worker::Env`, placed by [`Placement`].
    #[derive(Debug, Clone)]
    pub struct StubTransport {
        env: Env,
        placement: Placement,
    }

    /// The Workers key-level store.
    pub type WorkerNamespaceStore = DoNamespaceStore<StubTransport>;

    impl StubTransport {
        /// Stubs from `env`'s bindings, with `placement` (M0: the default,
        /// none).
        #[must_use]
        pub fn new(env: Env, placement: Placement) -> Self {
            Self { env, placement }
        }

        /// `ns.jurisdiction(name)`, which workers-rs does not wrap.
        fn jurisdiction(ns: &ObjectNamespace, name: &str) -> Result<ObjectNamespace, JsValue> {
            let f = js_sys::Reflect::get(ns.as_ref(), &"jurisdiction".into())?
                .dyn_into::<js_sys::Function>()?;
            Ok(f.call1(ns.as_ref(), &JsValue::from_str(name))?
                .unchecked_into())
        }
    }

    impl NsTransport for StubTransport {
        async fn call(
            &self,
            target: &DoTarget,
            op: &'static str,
            body: String,
        ) -> Result<String, StoreError> {
            let mut ns = self
                .env
                .durable_object(target.binding)
                .map_err(|e| backend_error(StorageOp::MetaBinding, e))?;
            if let Some(name) = &self.placement.jurisdiction {
                ns = Self::jurisdiction(&ns, name)
                    .map_err(|e| backend_error(StorageOp::MetaBinding, format!("{e:?}")))?;
            }
            let id = ns
                .id_from_name(&target.name)
                .map_err(|e| backend_error(StorageOp::MetaStub, e))?;
            let stub = match &self.placement.location_hint {
                Some(hint) => id.get_stub_with_location_hint(hint),
                None => id.get_stub(),
            }
            .map_err(|e| backend_error(StorageOp::MetaStub, e))?;
            let mut init = RequestInit::new();
            init.with_method(Method::Post)
                .with_body(Some(JsValue::from_str(&body)));
            let request = Request::new_with_init(&format!("https://ns/{op}"), &init)
                .map_err(|e| backend_error(StorageOp::MetaRequest, e))?;
            let mut response = stub
                .fetch_with_request(request)
                .await
                .map_err(|e| backend_error(StorageOp::MetaCall, e))?;
            let status = response.status_code();
            if status != 200 {
                return Err(backend_error(
                    StorageOp::MetaCall,
                    format_args!("durable object answered {status}"),
                ));
            }
            response
                .text()
                .await
                .map_err(|e| backend_error(StorageOp::MetaDecode, e))
        }
    }
}
