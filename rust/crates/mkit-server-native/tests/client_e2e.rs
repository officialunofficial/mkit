//! The `mkit+http://` client end to end: `mkit_transport_connect`'s
//! `ConnectTransport` (what `mkit push`/`pull`/`fetch` run) against
//! `mkit-server serve` over FS blobs and fs-layout refs, the setup the
//! removed `mkit serve --http` had. Ported from `mkit-transport-connect`'s
//! `tests/e2e.rs` (WP-M0-15), which drove that crate's own server.
//!
//! The server runs on its own runtime; the client is synchronous and
//! blocks on its own, so each test drives it from the test thread.

#![allow(clippy::unwrap_used)] // unwrap is the assertion in tests

mod common;

use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

use buffa::Message as _;
use ed25519_dalek::{Signer as _, SigningKey};
use mkit_core::hash::hash;
use mkit_core::protocol::{
    AdvanceOutcome, CommitOutcome, PackKey, RefWriteCondition, Transport as _, TransportError,
};
use mkit_core::transfer;
use mkit_server_conformance::wire::client::{Client, Rpc, UNARY_JSON};
use mkit_server_native::{Shutdown, server};
use mkit_transport_connect::generated::{UpdateRefRequest, UpdateRefResponse};
use mkit_transport_connect::{ConnectTransport, EnvelopeSigner, ServerInfoView, UploadEvent};

struct ReadSigner(SigningKey);

impl EnvelopeSigner for ReadSigner {
    fn public_key_hex(&self) -> String {
        mkit_core::hash::to_hex_bytes(&self.0.verifying_key().to_bytes())
    }

    fn sign_hex(&self, message: &[u8; 32]) -> Result<String, String> {
        Ok(mkit_core::hash::to_hex_bytes(
            &self.0.sign(message).to_bytes(),
        ))
    }
}

/// A running `mkit-server serve --unsafe-allow-any-peer` over a temp root.
struct Served {
    runtime: tokio::runtime::Runtime,
    origin: String,
    shutdown: Shutdown,
    task: Option<tokio::task::JoinHandle<std::io::Result<()>>>,
    /// The timer driver (relay delivery), when the metadata has one.
    timers: Option<tokio::task::JoinHandle<()>>,
    /// Holds the root's locks; dropped after `runtime` (field order).
    _opened: server::Opened,
    root: tempfile::TempDir,
}

impl Served {
    fn start() -> Self {
        Self::start_with_sqlite(false)
    }

    fn start_with_sqlite(sqlite: bool) -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let root = common::repo_root();
        let sqlite_meta = format!("sqlite:{}", common::s(&root.path().join("meta.sqlite3")));
        let meta = if sqlite {
            sqlite_meta.as_str()
        } else {
            "fs-layout"
        };
        let cfg = common::resolve_with(
            &[
                "--listen",
                "127.0.0.1:0",
                "--repo-root",
                common::s(root.path()),
                "--unsafe-allow-any-peer",
                "--meta",
                meta,
            ],
            &[],
        )
        .unwrap();
        let mut opened = server::open(&cfg).unwrap();
        let shutdown = Shutdown::new();
        let (listener, origin) = runtime.block_on(common::listener());
        let timers = opened
            .timers
            .take()
            .map(|driver| runtime.block_on(driver.start(shutdown.clone())).unwrap());
        let task = {
            let _guard = runtime.enter();
            common::spawn_serve(listener, opened.router.clone(), &shutdown)
        };
        Self {
            runtime,
            origin,
            shutdown,
            task: Some(task),
            timers,
            _opened: opened,
            root,
        }
    }

    fn start_ticketed() -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let root = common::repo_root();
        let ticket_file = root.path().join("ticket.keys");
        common::secret_file(
            &ticket_file,
            b"dev 1111111111111111111111111111111111111111111111111111111111111111\n",
        );
        let (listener, origin) = runtime.block_on(common::listener());
        let meta = format!("sqlite:{}", common::s(&root.path().join("meta.sqlite3")));
        let mut cfg = common::resolve_with(
            &[
                "--listen",
                "127.0.0.1:0",
                "--repo-root",
                common::s(root.path()),
                "--meta",
                &meta,
                "--ticket-key-file",
                common::s(&ticket_file),
                "--auth",
                "auth-v2",
                "--audience",
                &origin,
                "--max-pack-bytes",
                "67108864",
            ],
            &[],
        )
        .unwrap();
        cfg.pipeline.begin_upload_threshold_bytes = 0;
        let opened = server::open(&cfg).unwrap();
        let shutdown = Shutdown::new();
        let task = {
            let _guard = runtime.enter();
            common::spawn_serve(listener, opened.router.clone(), &shutdown)
        };
        Self {
            runtime,
            origin,
            shutdown,
            task: Some(task),
            timers: None,
            _opened: opened,
            root,
        }
    }

    fn signed_client(&self) -> ConnectTransport {
        ConnectTransport::connect_with_signer(
            &format!("mkit+{}", self.origin),
            Some(Arc::new(ReadSigner(SigningKey::from_bytes(&[42; 32])))),
        )
        .unwrap()
    }

    /// The `mkit+http://` client `mkit` builds for this server's URL.
    fn client(&self) -> ConnectTransport {
        ConnectTransport::connect(&format!("mkit+{}", self.origin)).unwrap()
    }

    /// A raw Connect client, for requests `ConnectTransport` never sends.
    fn raw(&self) -> Client {
        Client::new(&self.origin.parse().unwrap()).unwrap()
    }
}

#[test]
fn ticketed_fs_parts_resume_and_three_pack_advance() {
    let served = Served::start_ticketed();
    let seen = Arc::new(AtomicUsize::new(0));
    let interrupted = Arc::new(AtomicBool::new(false));
    let observer_seen = seen.clone();
    let observer_interrupted = interrupted.clone();
    let client = served.signed_client().with_upload_observer(move |event| {
        if matches!(event, UploadEvent::PartSent { .. }) {
            observer_seen.fetch_add(1, Ordering::SeqCst);
        }
        if matches!(event, UploadEvent::BeforePart)
            && observer_seen.load(Ordering::SeqCst) == 2
            && !observer_interrupted.swap(true, Ordering::SeqCst)
        {
            return false;
        }
        true
    });
    let info = client.server_info();
    let part_size = match info {
        ServerInfoView::V2(info) => usize::try_from(info.part_size.unwrap()).unwrap(),
        other => panic!("expected V2 server: {other:?}"),
    };
    let big = vec![0x83; part_size * 2 + 17];
    let big_key = PackKey::new(hash(&big));
    let head = "refs/heads/main";
    let error = client
        .upload_pack_via_ref(&big, &big_key, head)
        .unwrap_err();
    assert!(matches!(error, TransportError::RemoteError(_)), "{error:?}");
    assert_eq!(seen.load(Ordering::SeqCst), 2);
    client.upload_pack_via_ref(&big, &big_key, head).unwrap();
    assert_eq!(
        seen.load(Ordering::SeqCst),
        3,
        "only the final part was sent"
    );
    assert_eq!(client.download_pack(&big_key).unwrap(), big);

    let small_a = b"native ticketed pack A".to_vec();
    let small_b = b"native ticketed pack B".to_vec();
    let a = PackKey::new(hash(&small_a));
    let b = PackKey::new(hash(&small_b));
    client.upload_pack_via_ref(&small_a, &a, head).unwrap();
    client.upload_pack_via_ref(&small_b, &b, head).unwrap();
    let node =
        transfer::encode_packlist(None, &[*big_key.as_bytes(), *a.as_bytes(), *b.as_bytes()])
            .unwrap();
    let node_key = PackKey::new(hash(&node));
    client.upload_blob_via_ref(&node, &node_key, head).unwrap();
    let tip = hash(b"native ticketed tip");
    assert_eq!(
        client
            .advance_refs_committing(
                head,
                RefWriteCondition::Missing,
                &tip,
                "refs/mkit/packmap/main",
                RefWriteCondition::Missing,
                node_key.as_bytes(),
                &[big_key, a, b, node_key],
            )
            .unwrap(),
        CommitOutcome::Advanced(AdvanceOutcome::Committed),
    );
    assert_eq!(client.read_ref(head).unwrap(), Some(tip));
}

impl Drop for Served {
    fn drop(&mut self) {
        self.shutdown.trigger();
        if let Some(timers) = self.timers.take() {
            let _ = self.runtime.block_on(timers);
        }
        if let Some(task) = self.task.take() {
            let result = self.runtime.block_on(task);
            if !std::thread::panicking() {
                result.unwrap().unwrap();
            }
        }
    }
}

#[test]
fn push_then_pull_round_trip() {
    let served = Served::start();
    let client = served.client();

    // An empty root lists no refs and has no packs; neither is an error.
    assert!(client.list_refs("").unwrap().is_empty());
    let missing = PackKey::new(hash(b"does-not-exist"));
    assert!(!client.pack_exists(&missing).unwrap());

    let payload = b"hello mkit connect transport".to_vec();
    let key = PackKey::new(hash(&payload));
    client.upload_pack(&payload, &key).unwrap();
    assert!(client.pack_exists(&key).unwrap());
    assert_eq!(client.download_pack(&key).unwrap(), payload);

    let commit = hash(b"pretend-commit-object");
    client
        .update_ref("refs/heads/main", RefWriteCondition::Missing, &commit)
        .unwrap();
    assert_eq!(client.read_ref("refs/heads/main").unwrap(), Some(commit));
    let refs = client.list_refs("").unwrap();
    assert_eq!(refs.len(), 1);
    assert_eq!(refs[0].name, "refs/heads/main");
    assert_eq!(refs[0].hash, Some(commit));

    // The pack and the ref are the root's files, as `mkit serve` wrote them.
    let root = served.root.path();
    assert!(
        root.join("packs")
            .join(mkit_core::hash::to_hex(key.as_bytes()))
            .is_file()
    );
    assert!(root.join("refs/heads/main").is_file());
}

/// `--meta sqlite` shards per (repository, ref) by default (D34): a push is
/// readable at once by name, and its branch appears in `ListRefs` within
/// the relay bound. The wait is a bounded poll, never a fixed sleep.
#[test]
fn push_then_pull_round_trip_under_the_d34_default() {
    use mkit_server::relay::RELAY_LAG_BOUND_MS;

    let served = Served::start_with_sqlite(true);
    let client = served.client();
    let payload = b"d34 default pack".to_vec();
    let key = PackKey::new(hash(&payload));
    client.upload_pack(&payload, &key).unwrap();
    let commit = hash(b"d34 default tip");
    client
        .update_ref("refs/heads/main", RefWriteCondition::Missing, &commit)
        .unwrap();
    // Strongly consistent by name.
    assert_eq!(client.read_ref("refs/heads/main").unwrap(), Some(commit));
    assert_eq!(client.download_pack(&key).unwrap(), payload);
    // Eventual by listing.
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(RELAY_LAG_BOUND_MS);
    let refs = loop {
        let refs = client.list_refs("").unwrap();
        if !refs.is_empty() || std::time::Instant::now() >= deadline {
            break refs;
        }
        std::thread::yield_now();
        std::thread::park_timeout(std::time::Duration::from_millis(20));
    };
    assert_eq!(
        refs.len(),
        1,
        "the listing catches up within the relay bound"
    );
    assert_eq!(refs[0].name, "refs/heads/main");
    assert_eq!(refs[0].hash, Some(commit));
}

#[test]
fn signed_client_can_clone_from_current_server() {
    let served = Served::start();
    let writer = served.client();
    let payload = b"signed clone pack".to_vec();
    let pack = PackKey::new(hash(&payload));
    writer.upload_pack(&payload, &pack).unwrap();
    let commit = hash(b"signed clone tip");
    writer
        .update_ref("refs/heads/main", RefWriteCondition::Missing, &commit)
        .unwrap();

    // These are the Connect reads a clone makes to discover and fetch the
    // advertised branch. The current server must still accept their envelopes.
    let reader = ConnectTransport::connect_with_signer(
        &format!("mkit+{}", served.origin),
        Some(Arc::new(ReadSigner(SigningKey::from_bytes(&[42; 32])))),
    )
    .unwrap();
    assert_eq!(reader.read_ref("refs/heads/main").unwrap(), Some(commit));
    assert_eq!(reader.list_refs("").unwrap()[0].name, "refs/heads/main");
    assert!(reader.pack_exists(&pack).unwrap());
    assert_eq!(reader.download_pack(&pack).unwrap(), payload);
}

#[test]
fn update_ref_cas_conflict_is_ref_conflict() {
    let served = Served::start();
    let client = served.client();
    client
        .update_ref(
            "refs/heads/main",
            RefWriteCondition::Missing,
            &hash(b"first"),
        )
        .unwrap();
    // A second MISSING write against an existing ref is `failed_precondition`
    // (SPEC-TRANSPORT-CONNECT §3, §5), which the client maps to RefConflict.
    let err = client
        .update_ref(
            "refs/heads/main",
            RefWriteCondition::Missing,
            &hash(b"second"),
        )
        .unwrap_err();
    assert!(matches!(err, TransportError::RefConflict), "{err:?}");
    assert_eq!(
        client.read_ref("refs/heads/main").unwrap(),
        Some(hash(b"first"))
    );
}

#[test]
fn update_ref_rejects_unspecified_expectation() {
    let served = Served::start();
    // `ConnectTransport` always names an expectation, so send the request
    // raw.
    let req = UpdateRefRequest {
        name: Some("refs/heads/main".to_owned()),
        new_id: Some(hash(b"x").to_vec()),
        ..Default::default()
    };
    let got = served
        .runtime
        .block_on(
            served
                .raw()
                .unary::<UpdateRefResponse>(Rpc::UpdateRef, req.encode_to_vec(), &[]),
        )
        .unwrap();
    let err = got.expect_err("UNSPECIFIED expectation must be rejected");
    assert_eq!(err.code, "invalid_argument", "{err:?}");
    assert_eq!(served.client().read_ref("refs/heads/main").unwrap(), None);
}

#[test]
fn download_pack_missing_digest_is_pack_not_found() {
    let served = Served::start();
    let err = served
        .client()
        .download_pack(&PackKey::new(hash(b"nope")))
        .unwrap_err();
    assert!(matches!(err, TransportError::PackNotFound), "{err:?}");
}

#[test]
fn advance_refs_reports_head_conflict_as_typed_outcome() {
    let served = Served::start();
    let client = served.client();
    let (head, packmap) = ("refs/heads/main", "refs/mkit/packmap/main");
    let (head_v1, packmap_v1) = (hash(b"head-v1"), hash(b"packmap-v1"));
    let outcome = client
        .advance_refs(
            head,
            RefWriteCondition::Missing,
            &head_v1,
            packmap,
            RefWriteCondition::Missing,
            &packmap_v1,
        )
        .unwrap();
    assert_eq!(outcome, AdvanceOutcome::Committed);

    // Someone else moves the head. An advance still expecting the old head
    // is a successful RPC with a typed HEAD_CONFLICT, never an error.
    let external = hash(b"head-v2-external");
    client
        .update_ref(head, RefWriteCondition::Match(head_v1), &external)
        .unwrap();
    let outcome = client
        .advance_refs(
            head,
            RefWriteCondition::Match(head_v1),
            &hash(b"head-v2-mine"),
            packmap,
            RefWriteCondition::Match(packmap_v1),
            &hash(b"packmap-v2"),
        )
        .unwrap();
    assert_eq!(outcome, AdvanceOutcome::HeadConflict);
    assert_eq!(client.read_ref(head).unwrap(), Some(external));
}

/// `grpc.health.v1.Health` (mkit#796) answers `SERVING` for the server and
/// the transport service, and `not_found` for any other service: what an
/// operator's `grpc_health_probe` or load-balancer probe calls. Connect
/// JSON, so no health proto is needed.
#[test]
fn health_check_reports_serving() {
    let served = Served::start();
    let raw = served.raw();
    let check = |service: &str| {
        let body = serde_json::to_vec(&serde_json::json!({ "service": service })).unwrap();
        served
            .runtime
            .block_on(raw.post("/grpc.health.v1.Health/Check", UNARY_JSON, &[], body))
            .unwrap()
    };
    for service in ["", "mkit.transport.v1.TransportService"] {
        let reply = check(service);
        assert_eq!(reply.status, 200, "{service:?}");
        let json: serde_json::Value = serde_json::from_slice(&reply.body).unwrap();
        assert_eq!(json["status"], "SERVING", "{service:?}: {json}");
    }
    let reply = check("acme.NoSuchService");
    assert_eq!(reply.status, 404);
    let json: serde_json::Value = serde_json::from_slice(&reply.body).unwrap();
    assert_eq!(json["code"], "not_found", "{json}");
}

/// Capability discovery follows the actual storage adapter's transaction support.
#[test]
fn get_server_info_reports_fs_layout_and_sqlite_atomicity() {
    for sqlite in [false, true] {
        let served = Served::start_with_sqlite(sqlite);
        let client = served.client();
        assert_eq!(client.supports_atomic_advance(), sqlite);
        assert_eq!(
            client.supports_atomic_advance(),
            sqlite,
            "cached capability"
        );
        let ServerInfoView::V2(info) = client.server_info() else {
            panic!("native server must advertise STC v2");
        };
        assert_eq!(info.protocol.as_deref(), Some("mkit.transport.v1"));
        assert_eq!(info.spec_version, Some(2));
        assert_eq!(info.atomic_advance, Some(sqlite));
    }
}
