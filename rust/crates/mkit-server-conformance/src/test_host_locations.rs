//! Expiring, credential-free loopback pack locations for conformance only.
use crate::control::{self, PackLocationState, Request, Response};
use axum::{
    Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::get,
};
use bytes::Bytes;
use mkit_core::protocol::PackKey;
use mkit_server::pack_location::{PackLocation, PackLocationConfig, PackLocationProvider};
use mkit_server::store::adapter_spi::{codec, keys, publication::Witness};
use mkit_server::{
    Addressing, Batch, BlobKey, BlobStore, Clock, ManualClock, MemoryBlobStore, MemoryKv,
    NamespaceStore, PackSink, Partition,
};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

#[derive(Debug, Clone)]
pub(super) struct Locations {
    origin: String,
    meta: Arc<MemoryKv>,
    addressing: Addressing,
    fixtures: bool,
    corrupt_packs: Arc<Mutex<BTreeSet<mkit_core::hash::Hash>>>,
    blobs: MemoryBlobStore,
    clock: Arc<ManualClock>,
    issued: Arc<Mutex<BTreeMap<String, (PackKey, i64)>>>,
    corrupt: Arc<AtomicBool>,
    requests: Arc<AtomicUsize>,
    credentials: Arc<AtomicBool>,
}
impl Locations {
    pub(super) fn new(
        origin: String,
        blobs: MemoryBlobStore,
        clock: Arc<ManualClock>,
        meta: Arc<MemoryKv>,
        addressing: Addressing,
        fixtures: bool,
    ) -> Self {
        Self {
            origin,
            meta,
            addressing,
            fixtures,
            corrupt_packs: Arc::default(),
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
        let mut routes = Router::new().route("/__mkit_test/pack-locations/{token}", get(fetch));
        if self.fixtures {
            routes = routes
                .route(control::CAPABILITIES_PATH, get(capabilities))
                .route(control::CONTROL_PATH, axum::routing::post(command));
        }
        router.merge(
            routes
                .layer(axum::extract::DefaultBodyLimit::max(4 * 1_048_576 + 4096))
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
    if state.corrupt.load(Ordering::Relaxed)
        || state
            .corrupt_packs
            .lock()
            .unwrap()
            .contains(&key.into_hash())
    {
        let mut corrupt = bytes.to_vec();
        if let Some(first) = corrupt.first_mut() {
            *first ^= 1;
        }
        Ok(Bytes::from(corrupt))
    } else {
        Ok(bytes)
    }
}

async fn capabilities() -> axum::Json<control::Capabilities> {
    axum::Json(control::Capabilities {
        version: control::VERSION,
        controls: vec!["pack-locations.fixture".into(), "clock.advance".into()],
        durability_profile: "isolated volatile memory".into(),
        unsupported: BTreeMap::new(),
    })
}
async fn command(
    State(state): State<Locations>,
    axum::Json(request): axum::Json<Request>,
) -> Result<axum::Json<Response>, StatusCode> {
    match request {
        Request::AdvanceClock { delta_ms } => {
            let delta = i64::try_from(delta_ms).map_err(|_| StatusCode::BAD_REQUEST)?;
            let next = state
                .clock
                .now_ms()
                .checked_add(delta)
                .ok_or(StatusCode::BAD_REQUEST)?;
            state.clock.set(next);
            Ok(axum::Json(Response {
                now_ms: Some(next),
                ..Response::default()
            }))
        }
        Request::PackLocationFixture {
            repository,
            pack,
            state: status,
        } => {
            install_fixture(&state, &repository, pack, status).await?;
            Ok(axum::Json(Response::default()))
        }
        _ => Err(StatusCode::NOT_IMPLEMENTED),
    }
}
async fn install_fixture(
    state: &Locations,
    repository: &str,
    pack: Vec<u8>,
    status: PackLocationState,
) -> Result<(), StatusCode> {
    if pack.is_empty() || pack.len() > 1_048_576 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let repo = state
        .addressing
        .resolve(Some(repository), false)
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .repo;
    let hash = mkit_core::hash::hash(&pack);
    let length = pack.len() as u64;
    let mut sink = state
        .blobs
        .begin(BlobKey::pack(hash), length)
        .await
        .map_err(internal)?;
    sink.write(Bytes::from(pack)).await.map_err(internal)?;
    sink.commit().await.map_err(internal)?;
    let now = u64::try_from(state.clock.now_ms()).map_err(|_| StatusCode::BAD_REQUEST)?;
    mkit_server::takedown::inventory::complete(state.meta.as_ref(), &hash, length, now)
        .await
        .map_err(internal)?;
    let witness = Witness {
        generation: 0,
        sequence: 0,
        published: status != PackLocationState::Pending,
        held: status == PackLocationState::Held,
        boundary: false,
    };
    let visibility = if status == PackLocationState::Private {
        codec::StoredVisibility::Private
    } else {
        codec::StoredVisibility::Public
    };
    state
        .meta
        .apply(
            &Partition::Namespace(repo.namespace.clone()),
            Batch::new()
                .put(
                    keys::repo_record(&repo.name),
                    codec::encode_repo_record(&codec::RepoRecord { created_at_ms: now }),
                )
                .put(keys::membership(&repo.name, &hash), witness.encode())
                .put(
                    keys::repo_visibility(&repo.name),
                    codec::encode_repo_visibility(&codec::RepoVisibilityV1 {
                        visibility,
                        last_created_ms: now,
                        last_statement_id: None,
                        changed_ms: now,
                    }),
                ),
        )
        .await
        .map_err(internal)?;
    if status == PackLocationState::Denied {
        state
            .meta
            .apply(
                &mkit_server::store::content_shard(&hash),
                Batch::new().put(
                    keys::block(&hash),
                    codec::encode_block_entry(&mkit_server::store::BlockEntry::new(
                        "conformance",
                        now,
                    )),
                ),
            )
            .await
            .map_err(internal)?;
    }
    if status == PackLocationState::Corrupt {
        state.corrupt_packs.lock().unwrap().insert(hash);
    }
    Ok(())
}
fn internal(_: mkit_server::StoreError) -> StatusCode {
    StatusCode::INTERNAL_SERVER_ERROR
}
