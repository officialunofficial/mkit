#![cfg(feature = "test-host")]
#![allow(
    clippy::unwrap_used,
    clippy::cast_possible_truncation,
    clippy::too_many_lines,
    clippy::similar_names
)] // unwrap is the assertion in test helpers
//! `mkit-client` per-RPC calls against a real in-process server: anonymous and
//! signed reads, bounded downloads, CAS writes with replayed identity, the
//! manual per-RPC upload path, typed pending and admission outcomes, and
//! unpack with signature verification.

use axum::{body::Body, middleware::Next};
use http::{Request, Response};
use mkit_client::{
    Client, Clock, Destination, Entry, Error, HttpTransport, Limits, MemorySink, PackmapMode, Plan,
    Push, Signer, UnpackOptions, proto, unpack,
};
use mkit_core::{
    hash::{Hash, hash},
    layout::RepoLayout,
    object::{Blob, Commit, EntryMode, Identity, Object, Tree, TreeEntry},
    pack::{PackWriter, pack_key},
    refs::RefWriteCondition,
    serialize::serialize,
    sign::{KeyPair, sign_commit},
    store::ObjectStore,
    transfer,
    upload_parts::PartPlan,
};
use mkit_server::Clock as _;
use mkit_server_conformance::{
    test_host::TestHost,
    wire::{Feature, Profile, WireAuth},
};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

struct TestSigner(KeyPair);
impl Signer for TestSigner {
    fn public_key(&self) -> Hash {
        self.0.public.0
    }
    async fn sign(&self, digest: &Hash) -> Result<[u8; 64], String> {
        use ed25519_dalek::Signer as _;
        Ok(ed25519_dalek::SigningKey::from_bytes(&self.0.secret.0)
            .sign(digest)
            .to_bytes())
    }
}
struct TestClock<'a> {
    host: &'a TestHost,
    waits: Mutex<usize>,
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
    async fn wait(&self, _: Duration) {
        *self.waits.lock().unwrap() += 1;
    }
}
struct Channel(reqwest::Client);
impl HttpTransport for Channel {
    async fn send(
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
        *result.headers_mut().unwrap() = response.headers().clone();
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
fn channel() -> Channel {
    Channel(
        reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap(),
    )
}

/// One-shot faults injected in front of the real server.
#[derive(Default)]
struct Faults {
    pending_advance: Mutex<bool>,
    challenge_begin: Mutex<bool>,
}
impl Faults {
    async fn handle(self: Arc<Self>, request: Request<Body>, next: Next) -> Response<Body> {
        let method = request.uri().path().rsplit('/').next().unwrap().to_owned();
        if method == "AdvanceRefs" && std::mem::take(&mut *self.pending_advance.lock().unwrap()) {
            use base64::Engine as _;
            use buffa::Message as _;
            let detail = proto::PendingVerification {
                retry_after_ms: Some(2000),
                ..Default::default()
            }
            .encode_to_vec();
            let json = serde_json::json!({"code":"unavailable","message":"pending verification","details":[
                {"type":"mkit.transport.v1.PendingVerification","value":base64::engine::general_purpose::STANDARD.encode(detail)}]});
            return Response::builder()
                .status(503)
                .header("content-type", "application/json")
                .body(Body::from(json.to_string()))
                .unwrap();
        }
        if method == "BeginUpload" && std::mem::take(&mut *self.challenge_begin.lock().unwrap()) {
            return Response::builder()
                .status(402)
                .header("content-type", "application/json")
                .header("www-authenticate", "Payment id=\"a\"")
                .body(Body::from(
                    r#"{"code":"permission_denied","message":"pay"}"#,
                ))
                .unwrap();
        }
        next.run(request).await
    }
}

const SEED: [u8; 32] = [42; 32];

async fn host() -> (TestHost, Arc<Faults>) {
    let faults = Arc::new(Faults::default());
    let capture = faults.clone();
    let mut profile = Profile::new(WireAuth::AuthV2 {
        audience: String::new(),
        repository: "default".into(),
        seed: SEED,
    });
    profile.atomic_advance = true;
    profile.max_pack_bytes = 16 << 20;
    profile.features.insert(Feature::Tickets);
    let host = TestHost::start_with_test_layers(
        profile,
        |_, _| Ok(mkit_server::pipeline::Hooks::new()),
        |config| config.begin_upload_threshold_bytes = 0,
        move |app| {
            app.layer(axum::middleware::from_fn(move |request, next| {
                let capture = capture.clone();
                async move { capture.handle(request, next).await }
            }))
        },
    )
    .await
    .unwrap();
    (host, faults)
}

fn fixture(store: &ObjectStore, size: usize, salt: u8) -> Hash {
    let data: Vec<u8> = (0..size.div_ceil(32))
        .flat_map(|index| hash(&[index.to_le_bytes().as_slice(), &[salt]].concat()))
        .take(size)
        .collect();
    let blob_id = store
        .write(&serialize(&Object::Blob(Blob { data })).unwrap())
        .unwrap();
    let tree = Object::Tree(Tree {
        entries: vec![TreeEntry {
            name: b"file.bin".to_vec(),
            mode: EntryMode::Blob,
            object_hash: blob_id,
        }],
    });
    let tree_id = store.write(&serialize(&tree).unwrap()).unwrap();
    let signer = KeyPair::from_seed(SEED);
    let mut commit = Commit::new_unannotated(
        tree_id,
        Vec::new(),
        Identity::ed25519(signer.public.0),
        signer.public.0,
        vec![salt],
        42,
        [0; 64],
    );
    commit.signature = sign_commit(&commit, &signer).unwrap().0;
    store
        .write(&serialize(&Object::Commit(commit)).unwrap())
        .unwrap()
}
fn entries(store: &ObjectStore, tip: Hash) -> Vec<Entry> {
    let plan = transfer::plan_pack(store, tip, None).unwrap();
    plan.raw
        .iter()
        .map(|id| Entry::Raw {
            id: *id,
            bytes: store.read(id).unwrap(),
        })
        .chain(plan.deltas.into_iter().map(|delta| Entry::Delta {
            base: delta.base,
            stream: delta.stream,
        }))
        .collect()
}
fn dest(host: &TestHost) -> Destination {
    Destination::new(host.base_url().into(), "default".into()).unwrap()
}
fn store(dir: &tempfile::TempDir) -> ObjectStore {
    ObjectStore::init(&RepoLayout::single(dir.path())).unwrap()
}

async fn push(host: &TestHost, store: &ObjectStore, tip: Hash) {
    let plan = Plan::prepare(
        entries(store, tip),
        Limits {
            payload_bytes: 1 << 20,
            max_pack_bytes: host.profile().max_pack_bytes,
            max_parts: 10_000,
            ..Limits::default()
        },
    )
    .unwrap();
    let outcome = Push::new(
        dest(host),
        "main",
        RefWriteCondition::Missing,
        tip,
        PackmapMode::Append {
            self_contained: true,
        },
        plan,
        host.clock().now_ms() + 120_000,
    )
    .unwrap()
    .run(
        &channel(),
        &TestSigner(KeyPair::from_seed(SEED)),
        &TestClock {
            host,
            waits: Mutex::new(0),
        },
    )
    .await
    .unwrap();
    assert_eq!(outcome, mkit_client::Outcome::Committed);
}

#[tokio::test(flavor = "multi_thread")]
async fn anonymous_and_signed_reads_agree_and_unpack_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(&dir);
    let tip = fixture(&store, 2048, 1);
    let (host, _) = host().await;
    push(&host, &store, tip).await;

    let transport = channel();
    let signer = TestSigner(KeyPair::from_seed(SEED));
    let clock = TestClock {
        host: &host,
        waits: Mutex::new(0),
    };
    let anon = Client::anonymous(&transport, dest(&host));
    let signed = Client::signed(&transport, dest(&host), &signer, &clock);

    assert_eq!(anon.server_info().await.unwrap().spec_version, Some(2));
    for read in [anon.read_ref("refs/heads/main", None).await.unwrap(), {
        signed.read_ref("refs/heads/main", None).await.unwrap()
    }] {
        assert_eq!(read.value, Some(tip));
    }
    assert!(
        anon.read_ref("refs/heads/none", None)
            .await
            .unwrap()
            .value
            .is_none()
    );
    assert!(
        anon.read_ref("refs/heads/main", None)
            .await
            .unwrap()
            .identity
            .is_none()
    );
    assert!(
        signed
            .read_ref("refs/heads/main", None)
            .await
            .unwrap()
            .identity
            .is_some()
    );

    let listed = anon.list_all_refs("refs/", 4).await.unwrap();
    assert!(
        listed.iter().any(|r| r.name == "heads/main" && r.id == tip),
        "{listed:?}"
    );
    let page = signed
        .list_refs("refs/heads/", 1, "", None)
        .await
        .unwrap()
        .value;
    assert_eq!(page.refs.len(), 1);

    let packmap = anon
        .read_ref("refs/mkit/packmap/main", None)
        .await
        .unwrap()
        .value
        .unwrap();
    let packs = anon
        .resolve_pack_chain(packmap, "refs/mkit/packmap/main")
        .await
        .unwrap();
    assert_eq!(packs.len(), 1);
    assert!(
        anon.pack_exists(&packs[0], Some("refs/mkit/packmap/main"), None)
            .await
            .unwrap()
            .value
    );
    assert!(
        signed
            .pack_exists(&packs[0], None, None)
            .await
            .unwrap()
            .value
    );
    assert!(!anon.pack_exists(&[7; 32], None, None).await.unwrap().value);

    // Bounded download: a cap below the pack size fails, the exact size works.
    let pack = anon
        .download_pack(&packs[0], Some("refs/mkit/packmap/main"), 1 << 20, None)
        .await
        .unwrap()
        .value;
    assert_eq!(pack_key(&pack), packs[0]);
    let signed_pack = signed
        .download_pack(
            &packs[0],
            Some("refs/mkit/packmap/main"),
            pack.len() as u64,
            None,
        )
        .await
        .unwrap()
        .value;
    assert_eq!(signed_pack, pack);
    assert!(matches!(
        anon.download_pack(&packs[0], None, pack.len() as u64 - 1, None)
            .await,
        Err(Error::Limit(_))
    ));

    let mut sink = MemorySink::default();
    let unpacked = unpack(&packs[0], &pack, &mut sink, UnpackOptions::default()).unwrap();
    assert!(unpacked.ids.contains(&tip));
    assert_eq!(*clock.waits.lock().unwrap(), 0);
    host.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn update_ref_replays_the_saved_reply_for_the_same_identity() {
    let (host, _) = host().await;
    let transport = channel();
    let signer = TestSigner(KeyPair::from_seed(SEED));
    let clock = TestClock {
        host: &host,
        waits: Mutex::new(0),
    };
    let client = Client::signed(&transport, dest(&host), &signer, &clock);
    let id = client.new_identity().unwrap();

    client
        .update_ref(
            "refs/heads/side",
            RefWriteCondition::Missing,
            [5; 32],
            Some(&id),
        )
        .await
        .unwrap();
    // The same identity (as after a restart) is answered from the saved reply.
    let replay = client
        .update_ref(
            "refs/heads/side",
            RefWriteCondition::Missing,
            [5; 32],
            Some(&id),
        )
        .await
        .unwrap();
    assert_eq!(replay.identity, Some(id));
    // A fresh identity is a new operation and meets the precondition.
    let fresh = client
        .update_ref("refs/heads/side", RefWriteCondition::Missing, [5; 32], None)
        .await
        .unwrap_err();
    assert!(fresh.is_ref_conflict(), "{fresh:?}");
    assert_eq!(
        client
            .read_ref("refs/heads/side", None)
            .await
            .unwrap()
            .value,
        Some([5; 32])
    );
    client
        .update_ref(
            "refs/heads/side",
            RefWriteCondition::Match([5; 32]),
            [6; 32],
            None,
        )
        .await
        .unwrap();
    client
        .delete_ref("refs/heads/side", RefWriteCondition::Match([6; 32]), None)
        .await
        .unwrap();
    assert!(
        client
            .read_ref("refs/heads/side", None)
            .await
            .unwrap()
            .value
            .is_none()
    );
    assert_eq!(*clock.waits.lock().unwrap(), 0);
    host.shutdown().await;
}

fn raw_pack(entries: &[Entry]) -> (Hash, Vec<u8>) {
    let mut writer = PackWriter::new_raw_only();
    for entry in entries {
        if let Entry::Raw { id, bytes } = entry {
            writer.push_raw(*id, bytes).unwrap();
        }
    }
    let pack = writer.finish().unwrap();
    (pack_key(&pack), pack)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_push_driven_rpc_by_rpc_with_typed_pending_and_admission() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(&dir);
    let tip = fixture(&store, 1024, 2);
    let input = entries(&store, tip);
    let (host, faults) = host().await;
    let transport = channel();
    let signer = TestSigner(KeyPair::from_seed(SEED));
    let clock = TestClock {
        host: &host,
        waits: Mutex::new(0),
    };
    let client = Client::signed(&transport, dest(&host), &signer, &clock);

    let (pack_id, pack) = raw_pack(&input);
    let node = transfer::encode_packlist(None, &[pack_id]).unwrap();
    let node_id = pack_key(&node);

    // An admission challenge arrives as a typed error, with nothing consumed.
    *faults.challenge_begin.lock().unwrap() = true;
    let challenged = client
        .begin_upload("refs/heads/main", &pack_id, pack.len() as u64, None)
        .await
        .unwrap_err();
    let Error::PaymentRequired(required) = challenged else {
        panic!("{challenged:?}");
    };
    assert_eq!(required.www_authenticate, ["Payment id=\"a\""]);

    let mut tickets = Vec::new();
    for (id, bytes) in [(&pack_id, &pack), (&node_id, &node)] {
        let begun = client
            .begin_upload("refs/heads/main", id, bytes.len() as u64, None)
            .await
            .unwrap()
            .value;
        let Some(proto::begin_upload_response::Result::Ticket(ticket)) = begun.result else {
            panic!("a ticket is expected");
        };
        client
            .upload_pack(id, bytes, ticket.token.as_deref(), None)
            .await
            .unwrap();
        tickets.push(ticket.id.clone().unwrap());
    }
    let request = proto::AdvanceRefsRequest {
        head_ref: Some("refs/heads/main".into()),
        head_expectation: Some(proto::RefExpectation::Missing.into()),
        head_new_id: Some(tip.to_vec()),
        packmap_ref: Some("refs/mkit/packmap/main".into()),
        packmap_expectation: Some(proto::RefExpectation::Missing.into()),
        packmap_new_id: Some(node_id.to_vec()),
        ticket_ids: tickets,
        ..Default::default()
    };
    // A pending answer comes back as a hint; the same identity then resumes.
    *faults.pending_advance.lock().unwrap() = true;
    let id = client.new_identity().unwrap();
    let pending = client.advance_refs(&request, Some(&id)).await.unwrap_err();
    assert!(
        matches!(pending, Error::PendingVerification { retry_after } if retry_after == Duration::from_secs(2)),
        "{pending:?}"
    );
    let done = client.advance_refs(&request, Some(&id)).await.unwrap();
    assert_eq!(done.identity, Some(id));
    assert_eq!(
        done.value.outcome.and_then(|o| o.as_known()),
        Some(proto::AdvanceOutcome::Committed)
    );
    assert_eq!(
        client
            .read_ref("refs/heads/main", None)
            .await
            .unwrap()
            .value,
        Some(tip)
    );
    assert_eq!(*clock.waits.lock().unwrap(), 0, "per-RPC calls never wait");
    host.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn multipart_upload_runs_rpc_by_rpc() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(&dir);
    let tip = fixture(&store, 9 << 20, 3);
    let input = entries(&store, tip);
    let (host, _) = host().await;
    let transport = channel();
    let signer = TestSigner(KeyPair::from_seed(SEED));
    let clock = TestClock {
        host: &host,
        waits: Mutex::new(0),
    };
    let client = Client::signed(&transport, dest(&host), &signer, &clock);
    let (pack_id, pack) = raw_pack(&input);
    let begun = client
        .begin_upload("refs/heads/main", &pack_id, pack.len() as u64, None)
        .await
        .unwrap()
        .value;
    let Some(proto::begin_upload_response::Result::Ticket(ticket)) = begun.result else {
        panic!("a ticket is expected");
    };
    let part_size = ticket.part_size.unwrap();
    assert!((pack.len() as u64) > part_size, "multipart expected");
    let plan = PartPlan::new(pack.len() as u64, part_size, 10_000).unwrap();
    let mut receipts = Vec::new();
    for index in 0..plan.count() {
        let offset = plan.offset(index).unwrap() as usize;
        let len = plan.expected_len(index).unwrap() as usize;
        let part = &pack[offset..offset + len];
        // A part of the wrong length is refused before anything is sent.
        assert!(
            client
                .upload_part(&ticket, &plan, index, &part[..len - 1], None)
                .await
                .is_err()
        );
        let uploaded = client
            .upload_part(&ticket, &plan, index, part, None)
            .await
            .unwrap();
        receipts.push(uploaded.value.receipt.unwrap());
    }
    client
        .complete_upload(ticket.token.as_deref().unwrap(), receipts, None)
        .await
        .unwrap();
    host.shutdown().await;
}
