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

use buffa::Message as _;
use mkit_core::hash::hash;
use mkit_core::protocol::{
    AdvanceOutcome, PackKey, RefWriteCondition, Transport as _, TransportError,
};
use mkit_server_conformance::wire::client::{Client, Rpc, UNARY_JSON};
use mkit_server_native::{Shutdown, server};
use mkit_transport_connect::ConnectTransport;
use mkit_transport_connect::generated::{UpdateRefRequest, UpdateRefResponse};

/// A running `mkit-server serve --unsafe-allow-any-peer` over a temp root.
struct Served {
    runtime: tokio::runtime::Runtime,
    origin: String,
    shutdown: Shutdown,
    task: Option<tokio::task::JoinHandle<std::io::Result<()>>>,
    /// Holds the root's locks; dropped after `runtime` (field order).
    _opened: server::Opened,
    root: tempfile::TempDir,
}

impl Served {
    fn start() -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let root = common::repo_root();
        let cfg = common::resolve_with(
            &[
                "--listen",
                "127.0.0.1:0",
                "--repo-root",
                common::s(root.path()),
                "--unsafe-allow-any-peer",
            ],
            &[],
        )
        .unwrap();
        assert_eq!(cfg.meta, mkit_server_native::config::MetaChoice::FsLayout);
        let opened = server::open(&cfg).unwrap();
        let shutdown = Shutdown::new();
        let (listener, origin) = runtime.block_on(common::listener());
        let task = {
            let _guard = runtime.enter();
            common::spawn_serve(listener, opened.router.clone(), &shutdown)
        };
        Self {
            runtime,
            origin,
            shutdown,
            task: Some(task),
            _opened: opened,
            root,
        }
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

impl Drop for Served {
    fn drop(&mut self) {
        self.shutdown.trigger();
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
