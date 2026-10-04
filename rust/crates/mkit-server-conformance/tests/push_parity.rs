#![cfg(feature = "test-host")]

use axum::{
    body::{Body, to_bytes},
    middleware::Next,
};
use buffa::Message;
use http::{Request, Response};
use mkit_core::{
    hash::{Hash, to_hex, to_hex_bytes},
    layout::RepoLayout,
    object::{Blob, Commit, EntryMode, Identity, Object, Tree, TreeEntry},
    refs::RefWriteCondition,
    serialize::serialize,
    sign::{KeyPair, sign_commit},
    store::ObjectStore,
    transfer,
};
use mkit_push::{
    Clock, Destination, Entry, HttpTransport, Limits, Outcome, PackmapMode, Plan, Push, Signer,
    proto::*,
};
use mkit_server::Clock as _;
use mkit_server_conformance::{
    test_host::TestHost,
    wire::{Feature, Profile, WireAuth},
};
use mkit_transport_connect::{ConnectTransport, EnvelopeSigner};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

struct TestSigner(KeyPair);
impl Signer for TestSigner {
    fn public_key(&self) -> Hash {
        self.0.public.0
    }
    async fn sign(&self, digest: &Hash) -> Result<[u8; 64], String> {
        {
            use ed25519_dalek::Signer as _;
            Ok(ed25519_dalek::SigningKey::from_bytes(&self.0.secret.0)
                .sign(digest)
                .to_bytes())
        }
    }
}
impl EnvelopeSigner for TestSigner {
    fn public_key_hex(&self) -> String {
        to_hex(&self.0.public.0)
    }
    fn sign_hex(&self, digest: &Hash) -> Result<String, String> {
        {
            use ed25519_dalek::Signer as _;
            Ok(to_hex_bytes(
                &ed25519_dalek::SigningKey::from_bytes(&self.0.secret.0)
                    .sign(digest)
                    .to_bytes(),
            ))
        }
    }
}
struct TestClock<'a> {
    host: &'a TestHost,
    waits: Mutex<Vec<Duration>>,
}
impl Clock for TestClock<'_> {
    fn now_ms(&self) -> i64 {
        self.host.clock().now_ms()
    }
    fn nonce(&self) -> Result<Hash, String> {
        let mut nonce = [0; 32];
        getrandom::fill(&mut nonce).map_err(|error| error.to_string())?;
        Ok(nonce)
    }
    async fn wait(&self, duration: Duration) {
        self.waits
            .lock()
            .expect("valid parity fixture")
            .push(duration);
        self.host
            .clock()
            .advance(i64::try_from(duration.as_millis()).expect("test duration fits"));
    }
}
struct Channel(reqwest::Client);
impl HttpTransport for Channel {
    async fn send(
        &self,
        request: Request<Vec<u8>>,
        limit: usize,
    ) -> Result<Response<Vec<u8>>, String> {
        let mut retry = Request::new(request.body().clone());
        *retry.method_mut() = request.method().clone();
        *retry.uri_mut() = request.uri().clone();
        *retry.headers_mut() = request.headers().clone();
        let response = self.send_once(request, limit).await?;
        // Fixture-only loss marker: the original write landed but its reply
        // disappeared. Retry belongs to the injected host transport.
        if response.headers().get("x-test-response-lost").is_some() {
            self.send_once(retry, limit).await
        } else {
            Ok(response)
        }
    }
}
impl Channel {
    async fn send_once(
        &self,
        request: Request<Vec<u8>>,
        limit: usize,
    ) -> Result<Response<Vec<u8>>, String> {
        let (parts, body) = request.into_parts();
        let mut response = self
            .0
            .request(parts.method, parts.uri.to_string())
            .headers(parts.headers)
            .body(body)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let mut result = Response::builder().status(response.status());
        *result.headers_mut().expect("valid parity fixture") = response.headers().clone();
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? {
            if bytes.len() + chunk.len() > limit {
                return Err("response limit".into());
            }
            bytes.extend_from_slice(&chunk);
        }
        result.body(bytes).map_err(|e| e.to_string())
    }
}
#[derive(Clone, Copy, Debug)]
enum Fault {
    None,
    Replay,
    Pending,
    PackmapRace,
    Indexed,
    Sharded,
}
#[derive(Debug)]
struct Record {
    method: String,
    body: Vec<u8>,
    nonce: Option<String>,
    ref_hint: Option<String>,
}
#[derive(Debug)]
struct Recorder {
    calls: Mutex<Vec<Record>>,
    fault: Fault,
    fired: AtomicUsize,
    verification: std::sync::OnceLock<VerificationEnv>,
}
impl Recorder {
    async fn handle(self: Arc<Self>, request: Request<Body>, next: Next) -> Response<Body> {
        let (parts, body) = request.into_parts();
        let body = to_bytes(body, 32 << 20)
            .await
            .expect("valid parity fixture");
        let method = parts
            .uri
            .path()
            .rsplit('/')
            .next()
            .expect("valid parity fixture")
            .to_owned();
        self.calls
            .lock()
            .expect("valid parity fixture")
            .push(Record {
                method: method.clone(),
                body: body.to_vec(),
                ref_hint: parts
                    .headers
                    .get("x-mkit-ref")
                    .map(|h| h.to_str().expect("valid ref hint").to_owned()),
                nonce: parts
                    .headers
                    .get("idempotency-key")
                    .map(|h| h.to_str().expect("valid parity fixture").to_owned()),
            });
        if method == "AdvanceRefs" && self.fired.fetch_add(1, Ordering::Relaxed) == 0 {
            match self.fault {
                Fault::Pending => {
                    use base64::Engine as _;
                    let detail = PendingVerification {
                        retry_after_ms: Some(2000),
                        ..Default::default()
                    }
                    .encode_to_vec();
                    let json = serde_json::json!({"code":"unavailable", "message":"pending verification", "details":[{"type":"mkit.transport.v1.PendingVerification", "value":base64::engine::general_purpose::STANDARD.encode(detail)}]});
                    return Response::builder()
                        .status(503)
                        .header("content-type", "application/json")
                        .header("retry-after", "2")
                        .body(Body::from(json.to_string()))
                        .expect("valid parity fixture");
                }
                Fault::PackmapRace => {
                    return Response::builder()
                        .header("content-type", "application/proto")
                        .body(Body::from(
                            AdvanceRefsResponse {
                                outcome: Some(AdvanceOutcome::PackmapConflict.into()),
                                ..Default::default()
                            }
                            .encode_to_vec(),
                        ))
                        .expect("valid parity fixture");
                }
                Fault::Replay => {
                    let mut copy = Request::new(Body::from(body.clone()));
                    *copy.method_mut() = parts.method.clone();
                    *copy.uri_mut() = parts.uri.clone();
                    *copy.headers_mut() = parts.headers.clone();
                    let first = next.clone().run(copy).await;
                    assert_eq!(first.status(), 200);
                    // Consume the lost reply before replaying the identical request.
                    let _ = to_bytes(first.into_body(), 1 << 20)
                        .await
                        .expect("valid parity fixture");
                    return Response::builder()
                        .status(503)
                        .header("content-type", "application/json")
                        .header("x-test-response-lost", "1")
                        .body(Body::from(
                            r#"{"code":"unavailable","message":"response lost"}"#,
                        ))
                        .expect("valid loss response");
                }
                Fault::None | Fault::Indexed | Fault::Sharded => {}
            }
        }
        let response = next.run(Request::from_parts(parts, Body::from(body))).await;
        self.finish_indexed(&method, response).await
    }

    async fn finish_indexed(&self, method: &str, response: Response<Body>) -> Response<Body> {
        if matches!(self.fault, Fault::Indexed)
            && method == "AdvanceRefs"
            && response.status() == 503
        {
            let (parts, body) = response.into_parts();
            let bytes = to_bytes(body, 1 << 20).await.expect("valid parity fixture");
            let error: serde_json::Value =
                serde_json::from_slice(&bytes).expect("valid parity fixture");
            assert!(
                error["details"]
                    .as_array()
                    .expect("valid parity fixture")
                    .iter()
                    .any(|detail| {
                        detail["type"]
                            .as_str()
                            .expect("valid parity fixture")
                            .ends_with("PendingVerification")
                    })
            );
            drain_indexed(self.verification.get().expect("valid parity fixture")).await;
            return Response::from_parts(parts, Body::from(bytes));
        }
        response
    }
}
async fn host(fault: Fault) -> (TestHost, Arc<Recorder>) {
    let record = Arc::new(Recorder {
        calls: Mutex::new(Vec::new()),
        fault,
        fired: AtomicUsize::new(0),
        verification: std::sync::OnceLock::new(),
    });
    let capture = record.clone();
    let mut profile = Profile::new(WireAuth::AuthV2 {
        audience: String::new(),
        repository: if matches!(fault, Fault::Indexed | Fault::Sharded) {
            format!(
                "ed25519-{}/parity",
                to_hex(&KeyPair::from_seed([42; 32]).public.0)
            )
        } else {
            "default".into()
        },
        seed: [42; 32],
    });
    profile.atomic_advance = true;
    profile.sharding_d34 = matches!(fault, Fault::Sharded);
    profile.max_pack_bytes = 16 << 20;
    profile.features.insert(Feature::Tickets);
    let host = TestHost::start_with_test_layers(
        profile,
        |_, _| Ok(mkit_server::pipeline::Hooks::new()),
        |config| {
            config.begin_upload_threshold_bytes = 0;
            if matches!(fault, Fault::Indexed | Fault::Sharded) {
                let namespace = mkit_core::repo_identity::Namespace::Ed25519(
                    KeyPair::from_seed([42; 32]).public.0,
                );
                config.addressing = mkit_server::Addressing::Multi(
                    mkit_server::MultiAddressing::new().with_namespace_policy(
                        mkit_server::policy::NamespacePolicy::Allowlist(
                            [namespace].into_iter().collect(),
                        ),
                    ),
                );
                config.write_policy = mkit_server::policy::WritePolicy::Owner;
                if matches!(fault, Fault::Indexed) {
                    config.indexed = Some(mkit_server::indexed::IndexedConfig::scheduled(16 << 20));
                }
            }
        },
        move |app| {
            app.layer(axum::middleware::from_fn(move |request, next| {
                let capture = capture.clone();
                async move { capture.handle(request, next).await }
            }))
        },
    )
    .await
    .expect("valid parity fixture");
    if matches!(fault, Fault::Indexed) {
        record
            .verification
            .set(VerificationEnv {
                kv: host.kv().clone(),
                blobs: host.blobs().clone(),
                clock: host.clock().clone(),
            })
            .expect("valid parity fixture");
    }
    (host, record)
}
fn fixture(store: &ObjectStore, size: usize, salt: u8) -> Hash {
    // Deterministic incompressible bytes, so multipart coverage survives native
    // workspace feature unification enabling the C zstd writer.
    let data: Vec<u8> = (0..size.div_ceil(32))
        .flat_map(|index| {
            mkit_core::hash::hash(&[index.to_le_bytes().as_slice(), &[salt]].concat())
        })
        .take(size)
        .collect();
    let blob = Object::Blob(Blob { data });
    let blob_id = store
        .write(&serialize(&blob).expect("valid parity fixture"))
        .expect("valid parity fixture");
    let tree = Object::Tree(Tree {
        entries: vec![TreeEntry {
            name: b"file.bin".to_vec(),
            mode: EntryMode::Blob,
            object_hash: blob_id,
        }],
    });
    let tree_id = store
        .write(&serialize(&tree).expect("valid parity fixture"))
        .expect("valid parity fixture");
    let signer = KeyPair::from_seed([42; 32]);
    let mut commit = Commit::new_unannotated(
        tree_id,
        Vec::new(),
        Identity::ed25519(signer.public.0),
        signer.public.0,
        vec![salt],
        42,
        [0; 64],
    );
    commit.signature = sign_commit(&commit, &signer)
        .expect("valid parity fixture")
        .0;
    store
        .write(&serialize(&Object::Commit(commit)).expect("valid parity fixture"))
        .expect("valid parity fixture")
}
fn entries(store: &ObjectStore, tip: Hash) -> Vec<Entry> {
    let plan = transfer::plan_pack(store, tip, None).expect("valid parity fixture");
    plan.raw
        .iter()
        .map(|id| Entry::Raw {
            id: *id,
            bytes: store.read(id).expect("valid parity fixture"),
        })
        .chain(plan.deltas.into_iter().map(|delta| Entry::Delta {
            base: delta.base,
            stream: delta.stream,
        }))
        .collect()
}
async fn primitive(
    host: &TestHost,
    store: &ObjectStore,
    tip: Hash,
    cap: u64,
    lease: RefWriteCondition,
) -> (Outcome, Vec<Duration>) {
    let plan = Plan::prepare(
        entries(store, tip),
        Limits {
            payload_bytes: cap,
            max_pack_bytes: host.profile().max_pack_bytes,
            max_parts: 10_000,
            ..Limits::default()
        },
    )
    .expect("valid parity fixture");
    let push = Push::new(
        Destination::new(host.base_url().into(), repository(host).into())
            .expect("valid parity fixture"),
        "main",
        lease,
        tip,
        PackmapMode::Append {
            self_contained: true,
        },
        plan,
        host.clock().now_ms() + 120_000,
    )
    .expect("valid parity fixture");
    let channel = Channel(
        reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("valid parity fixture"),
    );
    let clock = TestClock {
        host,
        waits: Mutex::new(Vec::new()),
    };
    let result = push
        .run(&channel, &TestSigner(KeyPair::from_seed([42; 32])), &clock)
        .await
        .expect("valid parity fixture");
    (
        result,
        clock.waits.into_inner().expect("valid parity fixture"),
    )
}
async fn cli(
    host: &TestHost,
    store: Arc<ObjectStore>,
    tip: Hash,
    cap: u64,
    lease: RefWriteCondition,
) -> Outcome {
    let uri = format!("{}/{}", host.base_url(), repository(host))
        .parse()
        .expect("valid parity fixture");
    tokio::task::spawn_blocking(move || {
        let transport = ConnectTransport::connect_for_test_with_signer(
            uri,
            Some(Arc::new(TestSigner(KeyPair::from_seed([42; 32])))),
        );
        match mkit_cli::remote_dispatch::push_branch_with_limits(
            &transport, &store, "main", tip, lease, 0, cap,
        ) {
            Ok(()) => Outcome::Committed,
            Err(mkit_cli::remote_dispatch::DispatchError::NonFastForwardPush { .. }) => {
                Outcome::HeadConflict
            }
            Err(error) => panic!("CLI push: {error:?}"),
        }
    })
    .await
    .expect("valid parity fixture")
}
fn mutations(record: &Recorder) -> Vec<(String, Vec<u8>)> {
    let calls = record.calls.lock().expect("valid parity fixture");
    calls
        .iter()
        .filter_map(|call| {
            let bytes = match call.method.as_str() {
                "BeginUpload" | "UpdateRef" => call.body.clone(),
                "UploadPack" => normalize_stream::<UploadPackRequest>(&call.body, |message| {
                    if let Some(upload_pack_request::Body::Header(header)) = &mut message.body {
                        header.ticket_token = None;
                    }
                }),
                "UploadPart" => normalize_stream::<UploadPartRequest>(&call.body, |message| {
                    if let Some(upload_part_request::Msg::Header(header)) = &mut message.msg {
                        header.ticket_token = None;
                    }
                }),
                "CompleteUpload" => {
                    let mut request = CompleteUploadRequest::decode_from_slice(&call.body)
                        .expect("valid parity fixture");
                    request.ticket_token = None;
                    request
                        .receipts
                        .iter_mut()
                        .enumerate()
                        .for_each(|(index, receipt)| {
                            *receipt =
                                vec![u8::try_from(index).expect("ticket or part index fits")];
                        });
                    request.encode_to_vec()
                }
                "AdvanceRefs" => {
                    let mut request = AdvanceRefsRequest::decode_from_slice(&call.body)
                        .expect("valid parity fixture");
                    request
                        .ticket_ids
                        .iter_mut()
                        .enumerate()
                        .for_each(|(index, id)| {
                            *id = vec![u8::try_from(index).expect("ticket or part index fits")];
                        });
                    request.encode_to_vec()
                }
                _ => return None,
            };
            Some((call.method.clone(), bytes))
        })
        .collect()
}
fn normalize_stream<M: Message + Default>(bytes: &[u8], normalize: impl Fn(&mut M)) -> Vec<u8> {
    let mut cursor = bytes;
    let mut out = Vec::new();
    while !cursor.is_empty() {
        assert_eq!(cursor[0], 0);
        let len =
            u32::from_be_bytes(cursor[1..5].try_into().expect("valid parity fixture")) as usize;
        let mut message = M::decode_from_slice(&cursor[5..5 + len]).expect("valid parity fixture");
        normalize(&mut message);
        let bytes = message.encode_to_vec();
        out.extend_from_slice(
            &(u32::try_from(bytes.len()).expect("test frame fits")).to_be_bytes(),
        );
        out.extend_from_slice(&bytes);
        cursor = &cursor[5 + len..];
    }
    out
}

#[tokio::test(flavor = "multi_thread")]
async fn cli_and_async_push_have_identical_ticketed_mutations() {
    for (size, cap, fault) in [
        (0, 1 << 20, Fault::None),
        (512, 700, Fault::None),
        (9 << 20, 16 << 20, Fault::None),
        (1024, 1 << 20, Fault::Replay),
        (1024, 1 << 20, Fault::Pending),
        (1024, 1 << 20, Fault::PackmapRace),
        (1024, 1 << 20, Fault::Indexed),
    ] {
        let temp = tempfile::tempdir().expect("valid parity fixture");
        let store = Arc::new(
            ObjectStore::init(&RepoLayout::single(temp.path())).expect("valid parity fixture"),
        );
        let tip = fixture(&store, size, 3);
        let (native_host, native_record) = host(fault).await;
        let (async_host, async_record) = host(fault).await;
        assert_eq!(
            cli(
                &native_host,
                store.clone(),
                tip,
                cap,
                RefWriteCondition::Missing
            )
            .await,
            Outcome::Committed,
            "{fault:?}"
        );
        let (result, waits) =
            primitive(&async_host, &store, tip, cap, RefWriteCondition::Missing).await;
        assert_eq!(result, Outcome::Committed, "{fault:?}");
        assert_same_mutations(&native_record, &async_record);
        if matches!(fault, Fault::Pending) {
            assert_eq!(waits, vec![Duration::from_secs(2)]);
        }
        if matches!(fault, Fault::Pending | Fault::Replay) {
            for record in [&native_record, &async_record] {
                let calls = record.calls.lock().expect("valid parity fixture");
                let advances: Vec<_> = calls
                    .iter()
                    .filter(|call| call.method == "AdvanceRefs")
                    .collect();
                assert_eq!(advances.len(), 2);
                assert_eq!(
                    advances[0].nonce, advances[1].nonce,
                    "pending changed nonce"
                );
                assert_eq!(advances[0].body, advances[1].body);
            }
        }
        native_host.shutdown().await;
        async_host.shutdown().await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn stale_head_and_append_packmap_match_cli() {
    for fault in [Fault::None, Fault::Sharded] {
        stale_head_and_append(fault).await;
    }
}

async fn stale_head_and_append(fault: Fault) {
    let temp = tempfile::tempdir().expect("valid parity fixture");
    let store = Arc::new(
        ObjectStore::init(&RepoLayout::single(temp.path())).expect("valid parity fixture"),
    );
    let old = fixture(&store, 512, 1);
    let new = fixture(&store, 1024, 2);
    let (native_host, native_record) = host(fault).await;
    let (async_host, async_record) = host(fault).await;
    seed_pair(&native_host, &async_host, &store, old).await;
    if matches!(fault, Fault::Sharded) {
        assert_unrelayed_packmap(&native_host).await;
        assert_unrelayed_packmap(&async_host).await;
    }
    clear_record(&native_record);
    clear_record(&async_record);
    assert_eq!(
        cli(
            &native_host,
            store.clone(),
            new,
            1 << 20,
            RefWriteCondition::Missing
        )
        .await,
        Outcome::HeadConflict
    );
    assert_eq!(
        primitive(
            &async_host,
            &store,
            new,
            1 << 20,
            RefWriteCondition::Missing
        )
        .await
        .0,
        Outcome::HeadConflict
    );
    assert_same_mutations(&native_record, &async_record);
    assert_packmap_downloads(&native_record, &async_record);
    clear_record(&native_record);
    clear_record(&async_record);
    assert_eq!(
        cli(
            &native_host,
            store.clone(),
            new,
            1 << 20,
            RefWriteCondition::Match(old)
        )
        .await,
        Outcome::Committed
    );
    assert_eq!(
        primitive(
            &async_host,
            &store,
            new,
            1 << 20,
            RefWriteCondition::Match(old)
        )
        .await
        .0,
        Outcome::Committed
    );
    assert_same_mutations(&native_record, &async_record);
    assert_packmap_downloads(&native_record, &async_record);
    native_host.shutdown().await;
    async_host.shutdown().await;
}

async fn seed_pair(
    native: &TestHost,
    asynchronous: &TestHost,
    store: &Arc<ObjectStore>,
    tip: Hash,
) {
    assert_eq!(
        cli(
            native,
            store.clone(),
            tip,
            1 << 20,
            RefWriteCondition::Missing
        )
        .await,
        Outcome::Committed
    );
    assert_eq!(
        primitive(
            asynchronous,
            store,
            tip,
            1 << 20,
            RefWriteCondition::Missing
        )
        .await
        .0,
        Outcome::Committed
    );
}

async fn assert_unrelayed_packmap(host: &TestHost) {
    use mkit_core::protocol::{PackKey, Transport, TransportError};
    let uri = format!("{}/{}", host.base_url(), repository(host))
        .parse()
        .expect("valid parity URI");
    tokio::task::spawn_blocking(move || {
        let transport = ConnectTransport::connect_for_test_with_signer(
            uri,
            Some(Arc::new(TestSigner(KeyPair::from_seed([42; 32])))),
        );
        let root = transport
            .read_ref("refs/mkit/packmap/main")
            .expect("packmap ref")
            .expect("packmap exists");
        let key = PackKey::from_hash(root);
        assert!(
            matches!(
                transport.download_blob(&key),
                Err(TransportError::PackNotFound)
            ),
            "membership relay has not run; the unhinted download must miss"
        );
        let bytes = transport
            .download_blob_via_ref(&key, "refs/heads/main")
            .expect("ref shard sees packmap");
        assert_eq!(mkit_core::pack::pack_key(&bytes), root);
    })
    .await
    .expect("probe completes");
}

fn assert_packmap_downloads(native: &Recorder, asynchronous: &Recorder) {
    let downloads = |record: &Recorder| {
        record
            .calls
            .lock()
            .expect("valid parity fixture")
            .iter()
            .filter(|call| call.method == "DownloadPack")
            .map(|call| (call.body.clone(), call.ref_hint.clone()))
            .collect::<Vec<_>>()
    };
    let native = downloads(native);
    let asynchronous = downloads(asynchronous);
    assert!(!native.is_empty(), "existing chain was actually read");
    assert!(
        native
            .iter()
            .all(|(_, hint)| hint.as_deref() == Some("refs/heads/main"))
    );
    assert_eq!(native, asynchronous, "download wire and ref-shard hint");
}

fn clear_record(record: &Recorder) {
    record.calls.lock().expect("valid parity fixture").clear();
}

fn assert_same_mutations(native: &Recorder, asynchronous: &Recorder) {
    let native = mutations(native);
    let asynchronous = mutations(asynchronous);
    assert_eq!(native.len(), asynchronous.len(), "mutation count");
    for ((left_method, left), (right_method, right)) in native.iter().zip(&asynchronous) {
        assert_eq!(left_method, right_method);
        assert!(
            left == right,
            "{left_method} differs: native {} bytes {}, async {} bytes {}",
            left.len(),
            to_hex(&mkit_core::hash::hash(left)),
            right.len(),
            to_hex(&mkit_core::hash::hash(right))
        );
    }
}

#[derive(Debug)]
struct VerificationEnv {
    kv: Arc<mkit_server::MemoryKv>,
    blobs: mkit_server::MemoryBlobStore,
    clock: Arc<mkit_server::ManualClock>,
}

async fn drain_indexed(env: &VerificationEnv) {
    use mkit_server::indexed::{
        budget::BlobWindows,
        job::{FailClosedExtraction, SliceLimits, VerifyTimer},
    };
    use mkit_server::pipeline::SinglePartition;
    use mkit_server::timers::{TickBudget, TimerRegistry, run_due};
    let registry = TimerRegistry::new()
        .register(VerifyTimer {
            remote: env.kv.clone(),
            blobs: env.blobs.clone(),
            windows: BlobWindows(&env.blobs),
            shards: Arc::new(SinglePartition),
            cfg: mkit_server::indexed::IndexedConfig::scheduled(16 << 20),
            limits: SliceLimits::default(),
            lease: mkit_server::pipeline::LeaseParams::default(),
            clock: env.clock.clone(),
            metrics: Arc::new(mkit_server::NoopMetrics),
            extension: FailClosedExtraction,
        })
        .register(mkit_server::relay::RelayHandler {
            target: env.kv.clone(),
            hook: mkit_server::relay::NoHook,
            budget: mkit_server::relay::RelayBudget::default(),
        });
    let partition = mkit_server::Partition::Namespace(mkit_server::NamespaceKey::from_namespace(
        &mkit_core::repo_identity::Namespace::Ed25519(KeyPair::from_seed([42; 32]).public.0),
    ));
    for _ in 0..40 {
        env.clock.advance(1000);
        run_due(
            env.kv.as_ref(),
            &partition,
            &registry,
            env.clock.as_ref(),
            u64::try_from(env.clock.now_ms()).expect("positive test clock"),
            &TickBudget::default(),
        )
        .await
        .expect("valid parity fixture");
    }
}

fn repository(host: &TestHost) -> &str {
    match &host.profile().auth {
        WireAuth::AuthV2 { repository, .. } => repository,
        _ => panic!("signed profile required"),
    }
}
