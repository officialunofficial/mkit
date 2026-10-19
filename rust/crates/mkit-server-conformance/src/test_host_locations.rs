//! Expiring, credential-free loopback pack locations for conformance only.
use axum::{
    Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::get,
};
use bytes::Bytes;
use mkit_core::protocol::PackKey;
use mkit_server::pack_location::{PackLocation, PackLocationConfig, PackLocationProvider};
use mkit_server::{BlobKey, BlobStore, Clock, ManualClock, MemoryBlobStore};
use std::collections::BTreeMap;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

#[derive(Debug, Clone)]
pub(super) struct Locations {
    origin: String,
    blobs: MemoryBlobStore,
    clock: Arc<ManualClock>,
    issued: Arc<Mutex<BTreeMap<String, (PackKey, i64)>>>,
    corrupt: Arc<AtomicBool>,
    requests: Arc<AtomicUsize>,
    credentials: Arc<AtomicBool>,
}
impl Locations {
    pub(super) fn new(origin: String, blobs: MemoryBlobStore, clock: Arc<ManualClock>) -> Self {
        Self {
            origin,
            blobs,
            clock,
            issued: Arc::default(),
            corrupt: Arc::default(),
            requests: Arc::default(),
            credentials: Arc::default(),
        }
    }
    pub(super) fn config(&self) -> Result<Arc<PackLocationConfig>, String> {
        PackLocationConfig::new(Arc::new(self.clone()), 1_000)
            .map(|config| Arc::new(config.with_test_loopback_http()))
            .map_err(|error| error.to_string())
    }
    pub(super) fn mount(&self, router: Router) -> Router {
        router.merge(
            Router::new()
                .route("/__mkit_test/pack-locations/{token}", get(fetch))
                .with_state(self.clone()),
        )
    }
    pub(super) fn corrupt(&self, value: bool) {
        self.corrupt.store(value, Ordering::Relaxed);
    }
    pub(super) fn fetches(&self) -> (usize, bool) {
        (
            self.requests.load(Ordering::Relaxed),
            self.credentials.load(Ordering::Relaxed),
        )
    }
}
impl PackLocationProvider for Locations {
    fn locate(
        &self,
        key: PackKey,
        total_bytes: u64,
        expires_at_ms: i64,
    ) -> mkit_server::BoxFuture<'_, Result<Option<PackLocation>, mkit_server::ServerError>> {
        Box::pin(async move {
            let token = crate::wire::profile::random_hex::<32>();
            let mut issued = self.issued.lock().unwrap();
            issued.retain(|_, (_, expiry)| *expiry > self.clock.now_ms());
            issued.insert(token.clone(), (key, expires_at_ms));
            Ok(Some(PackLocation {
                url: format!("{}/__mkit_test/pack-locations/{token}", self.origin),
                expires_at_ms,
                total_bytes,
            }))
        })
    }
}
async fn fetch(
    state: State<Locations>,
    token: Path<String>,
    headers: HeaderMap,
) -> impl axum::response::IntoResponse {
    use axum::response::IntoResponse as _;
    let mut response = fetch_bytes(state, token, headers).await.into_response();
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}
async fn fetch_bytes(
    State(state): State<Locations>,
    Path(token): Path<String>,
    headers: HeaderMap,
) -> Result<Bytes, StatusCode> {
    state.requests.fetch_add(1, Ordering::Relaxed);
    if headers.keys().any(|name| {
        name == "authorization"
            || name.as_str().starts_with("x-mkit-")
            || [
                "x-envelope-version",
                "x-audience",
                "x-repository",
                "x-content-commitment",
                "x-created-at",
                "x-expires-at",
                "x-nonce",
                "x-public-key",
                "x-signature",
                "x-digest",
            ]
            .contains(&name.as_str())
    }) {
        state.credentials.store(true, Ordering::Relaxed);
        return Err(StatusCode::BAD_REQUEST);
    }
    let (key, expiry) = state
        .issued
        .lock()
        .unwrap()
        .get(&token)
        .copied()
        .ok_or(StatusCode::NOT_FOUND)?;
    if state.clock.now_ms() >= expiry {
        return Err(StatusCode::NOT_FOUND);
    }
    let body = state
        .blobs
        .get(&BlobKey::pack(key.into_hash()), None)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    let bytes = match body {
        mkit_server::BlobBody::Bytes(bytes) => bytes,
        mkit_server::BlobBody::Stream { stream, .. } => {
            use futures::TryStreamExt as _;
            let chunks: Vec<Bytes> = stream
                .try_collect()
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            Bytes::from(chunks.concat())
        }
    };
    if state.corrupt.load(Ordering::Relaxed) {
        let mut corrupt = bytes.to_vec();
        if let Some(first) = corrupt.first_mut() {
            *first ^= 1;
        }
        Ok(Bytes::from(corrupt))
    } else {
        Ok(bytes)
    }
}
