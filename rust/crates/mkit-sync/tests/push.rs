//! Repository push against the real loopback server, including signed writes,
//! competing branch leases and transport-owned multipart receipts.
#![cfg(feature = "connect-native")]
#![allow(clippy::unwrap_used)]

mod support;

use std::sync::{
    Arc, Barrier, Mutex,
    atomic::{AtomicBool, Ordering},
};

use ed25519_dalek::{Signer as _, SigningKey};
use mkit_core::{
    hash::{Hash, to_hex, to_hex_bytes},
    layout::RepoLayout,
    pack::{PackWriter, pack_key},
    protocol::{PackKey, Transport as _},
    refs,
    serialize::serialize,
    store::ObjectStore,
    transfer::{
        self,
        packmap::{ChainState, plan_advance},
    },
};
use mkit_sync::{
    PushError, PushLease, PushOptions, PushTarget, SyncError, SyncEvent, SyncObserver,
    TransportSource, push,
};
use mkit_transport_connect::{
    ConnectTransport, EnvelopeSigner, MemoryPartReceiptStore, UploadEvent,
};
use support::{Live, NS, WRITER_SEED, build_commit, self_certifying_namespace};

struct Signer(SigningKey);
impl EnvelopeSigner for Signer {
    fn public_key_hex(&self) -> String {
        to_hex(self.0.verifying_key().as_bytes())
    }
    fn sign_hex(&self, digest: &Hash) -> Result<String, String> {
        Ok(to_hex_bytes(&self.0.sign(digest).to_bytes()))
    }
}

fn transport(origin: &str, repository: &str) -> ConnectTransport {
    ConnectTransport::connect_with_signer(
        &format!("mkit+{origin}/{repository}"),
        Some(Arc::new(Signer(SigningKey::from_bytes(&[WRITER_SEED; 32])))),
    )
    .unwrap()
}

fn options<'a>() -> PushOptions<'a> {
    PushOptions::default().with_target(PushTarget::Branch {
        local: "main".into(),
        remote: "main".into(),
        lease: PushLease::FastForward,
    })
}

fn repository() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
    dir
}

fn commit(dir: &std::path::Path, parent: Option<Hash>, content: &[u8], stamp: u64) -> Hash {
    let layout = RepoLayout::single(dir);
    let store = ObjectStore::open(&layout).unwrap();
    let (objects, tip) = build_commit(WRITER_SEED, parent, &[("file", content)], stamp);
    for object in objects {
        assert_eq!(
            store.write(&serialize(&object).unwrap()).unwrap(),
            object.id().unwrap()
        );
    }
    refs::write_ref(&layout, "main", &tip).unwrap();
    tip
}

/// Sequential reference encoding retains the original push engine's plan
/// order. Compare both content-addressed IDs and all uploaded bytes, so parallel
/// preparation cannot silently reorder frames or alter packmap publication.
fn assert_first_push_pack_parity(dir: &std::path::Path, tx: &ConnectTransport, tip: Hash) {
    let store = ObjectStore::open(&RepoLayout::single(dir)).unwrap();
    let plan = transfer::plan_pack(&store, tip, None).unwrap();
    assert!(plan.self_contained);
    let mut writer = PackWriter::new();
    for id in plan.raw {
        writer.push_raw(id, &store.read(&id).unwrap()).unwrap();
    }
    for delta in plan.deltas {
        writer.push_delta(&delta.base, &delta.stream).unwrap();
    }
    let expected_pack = writer.finish().unwrap();
    let expected_pack_key = pack_key(&expected_pack);
    let expected_node_bytes = transfer::encode_packlist(None, &[expected_pack_key]).unwrap();
    let expected_node_key = pack_key(&expected_node_bytes);
    #[cfg(feature = "pack-zstd")]
    assert_eq!(
        (to_hex(&expected_pack_key), to_hex(&expected_node_key)),
        (
            "ff5ee54ec4e52ca5a66382270b5da5eb0ea0ed684bd9ae154d475006f8b5fff8".into(),
            "a9fa3c1e86908e0399cf886c080997f2673a2fe64defc4dd37ce088aa6b4e0d1".into()
        )
    );
    let planned = plan_advance(ChainState::Missing, &[expected_pack_key], None)
        .unwrap()
        .unwrap();
    assert_eq!(planned.key, expected_node_key);
    assert_eq!(planned.bytes, expected_node_bytes);
    assert_eq!(planned.condition, refs::RefWriteCondition::Missing);
    let advertised = tx.read_ref("refs/mkit/packmap/main").unwrap().unwrap();
    assert_eq!(
        advertised,
        expected_node_key,
        "packmap ID differs: actual {}, expected {}",
        to_hex(&advertised),
        to_hex(&expected_node_key)
    );
    let actual_node_bytes = tx
        .download_blob_via_ref(&PackKey::from_hash(advertised), "refs/heads/main")
        .unwrap();
    assert_eq!(actual_node_bytes, expected_node_bytes);
    let node = transfer::decode_packlist(&actual_node_bytes).unwrap();
    assert_eq!(node.prev, None);
    assert_eq!(node.packs, vec![expected_pack_key]);
    let actual_pack = tx
        .download_pack_via_ref(&PackKey::from_hash(node.packs[0]), "refs/heads/main")
        .unwrap();
    assert_eq!(pack_key(&actual_pack), expected_pack_key);
    assert_eq!(actual_pack, expected_pack);
}

#[test]
fn first_push_fast_forward_and_non_fast_forward_preserve_refs() {
    let live = Live::self_certifying();
    let tx = transport(
        &live.origin,
        &format!("{}/push", self_certifying_namespace()),
    );
    let source = TransportSource::new(&tx);
    let dir = repository();
    let first = commit(dir.path(), None, b"first", 1);
    let report = push(dir.path(), &source, &options()).unwrap();
    assert_eq!((report.refs, report.steps, report.tip), (1, 1, Some(first)));
    assert_eq!(tx.read_ref("refs/heads/main").unwrap(), Some(first));
    assert_first_push_pack_parity(dir.path(), &tx, first);
    let second = commit(dir.path(), Some(first), b"second", 2);
    assert_eq!(
        push(dir.path(), &source, &options()).unwrap().tip,
        Some(second)
    );
    assert_eq!(tx.read_ref("refs/heads/main").unwrap(), Some(second));
    commit(dir.path(), None, b"unrelated", 3);
    assert!(
        matches!(push(dir.path(), &source, &options()), Err(PushError::NonFastForwardPush { branch }) if branch == "main")
    );
    assert_eq!(tx.read_ref("refs/heads/main").unwrap(), Some(second));
    assert_eq!(
        refs::read_remote_ref(&RepoLayout::single(dir.path()), "default", "main").unwrap(),
        Some(second)
    );
}

/// Both pushes finish uploading their first data pack before either may advance.
struct UploadBarrier {
    barrier: Arc<Barrier>,
    waited: AtomicBool,
}
impl SyncObserver for UploadBarrier {
    fn event(&self, event: &SyncEvent) {
        if matches!(event, SyncEvent::PackUploaded { .. })
            && !self.waited.swap(true, Ordering::SeqCst)
        {
            self.barrier.wait();
        }
    }
}

#[test]
fn concurrent_pushes_have_one_cas_winner() {
    let live = Live::self_certifying();
    let name = format!("{}/race", self_certifying_namespace());
    let tx = transport(&live.origin, &name);
    let dirs = [repository(), repository()];
    let base = commit(dirs[0].path(), None, b"base", 1);
    assert_eq!(commit(dirs[1].path(), None, b"base", 1), base);
    push(dirs[0].path(), &TransportSource::new(&tx), &options()).unwrap();
    refs::write_remote_ref(
        &RepoLayout::single(dirs[1].path()),
        "default",
        "main",
        &base,
    )
    .unwrap();
    let tips = [
        commit(dirs[0].path(), Some(base), b"left", 2),
        commit(dirs[1].path(), Some(base), b"right", 2),
    ];
    let barrier = Arc::new(Barrier::new(2));
    let results = std::thread::scope(|scope| {
        let handles = dirs
            .iter()
            .map(|dir| {
                let barrier = Arc::clone(&barrier);
                let origin = &live.origin;
                let name = &name;
                scope.spawn(move || {
                    let tx = transport(origin, name);
                    let observer = UploadBarrier {
                        barrier,
                        waited: AtomicBool::new(false),
                    };
                    let mut opts = options();
                    opts.control.observer = &observer;
                    push(dir.path(), &TransportSource::new(&tx), &opts)
                })
            })
            .collect::<Vec<_>>();
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(
        results.iter().filter(|result| result.is_ok()).count(),
        1,
        "{results:?}"
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(PushError::NonFastForwardPush { .. })))
            .count(),
        1,
        "{results:?}"
    );
    let winner = results.iter().position(Result::is_ok).unwrap();
    assert_eq!(tx.read_ref("refs/heads/main").unwrap(), Some(tips[winner]));
    for (index, dir) in dirs.iter().enumerate() {
        assert_eq!(
            refs::read_remote_ref(&RepoLayout::single(dir.path()), "default", "main").unwrap(),
            Some(if index == winner { tips[index] } else { base })
        );
    }
}

#[test]
fn signed_push_to_authority_uuidv7_repository() {
    let live = Live::authority();
    let tx = transport(&live.origin, &format!("{NS}/signed-push"));
    let dir = repository();
    let tip = commit(dir.path(), None, b"authority", 1);
    assert_eq!(
        push(dir.path(), &TransportSource::new(&tx), &options())
            .unwrap()
            .tip,
        Some(tip)
    );
    assert_eq!(tx.read_ref("refs/heads/main").unwrap(), Some(tip));
    assert!(
        live.calls
            .lock()
            .unwrap()
            .iter()
            .any(|(principal, _)| principal.ed25519() == Some(&support::public_key(WRITER_SEED)))
    );
}

/// A larger upload cap than the ordinary read fixtures, so a single pack
/// crosses the server's 8 MiB multipart boundary.
struct MultipartServer {
    origin: String,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl MultipartServer {
    fn new() -> Self {
        let (sender, receiver) = std::sync::mpsc::channel();
        let (shutdown, stopped) = tokio::sync::oneshot::channel();
        let thread = std::thread::spawn(move || {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap()
                .block_on(async move {
                    let bound = connectrpc::server::Server::bind("127.0.0.1:0")
                        .await
                        .unwrap();
                    let origin = format!("http://{}", bound.local_addr().unwrap());
                    let mut cfg = mkit_server::pipeline::PipelineConfig::new(
                        mkit_server::Addressing::Multi(
                            mkit_server::MultiAddressing::new().with_namespace_policy(
                                mkit_server::policy::NamespacePolicy::Any {
                                    unsafe_without_admission: true,
                                },
                            ),
                        ),
                        mkit_server::pipeline::AuthMode::AuthV2(
                            mkit_server::auth_v2::AuthV2Config::new(&origin, "").unwrap(),
                        ),
                        mkit_server::upload::UploadLimits::new(32 << 20, 1024),
                    );
                    cfg.ticket_keys = Some(
                        mkit_server::upload::token::TicketKeys::new(vec![(
                            "tickets".into(),
                            [9; 32],
                        )])
                        .unwrap(),
                    );
                    let clock = Arc::new(mkit_server::SystemClock);
                    let pipeline = mkit_server::pipeline::Pipeline::new(
                        mkit_server::MemoryBlobStore::default(),
                        mkit_server::MemoryKv::with_clock(clock.clone()),
                        mkit_server::pipeline::Hooks::new(),
                        cfg,
                        clock,
                        Arc::new(mkit_server::NoopMetrics),
                    )
                    .unwrap();
                    sender.send(origin).unwrap();
                    bound
                        .serve_with_service_and_shutdown(
                            mkit_server::connect::service(Arc::new(pipeline)),
                            async {
                                let _ = stopped.await;
                            },
                        )
                        .await
                        .unwrap();
                });
        });
        Self {
            origin: receiver.recv().unwrap(),
            shutdown: Some(shutdown),
            thread: Some(thread),
        }
    }
}
impl Drop for MultipartServer {
    fn drop(&mut self) {
        if let Some(sender) = self.shutdown.take() {
            let _ = sender.send(());
        }
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}

#[test]
fn multipart_push_resumes_acknowledged_parts_across_transport_instances() {
    let live = MultipartServer::new();
    let name = format!("{}/multipart", self_certifying_namespace());
    let dir = repository();
    let mut random = 0x8c17_a9e5_u32;
    let bytes = (0..(9 << 20))
        .map(|_| {
            random ^= random << 13;
            random ^= random >> 17;
            random ^= random << 5;
            random.to_le_bytes()[0]
        })
        .collect::<Vec<_>>();
    let tip = commit(dir.path(), None, &bytes, 1);
    let receipts = Arc::new(MemoryPartReceiptStore::default());
    let stopped = Arc::new(AtomicBool::new(false));
    let cancel = Arc::clone(&stopped);
    let tx = transport(&live.origin, &name)
        .with_receipt_store(receipts.clone())
        .with_upload_observer(move |event| {
            if matches!(event, UploadEvent::PartSent { index: 0, .. }) {
                cancel.store(true, Ordering::SeqCst);
            }
            !cancel.load(Ordering::SeqCst)
        });
    assert!(push(dir.path(), &TransportSource::new(&tx), &options()).is_err());
    assert!(
        stopped.load(Ordering::SeqCst),
        "must reach the first acknowledged part"
    );
    assert_eq!(tx.read_ref("refs/heads/main").unwrap(), None);
    assert_eq!(
        refs::read_remote_ref(&RepoLayout::single(dir.path()), "default", "main").unwrap(),
        None
    );
    drop(tx);
    let events = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&events);
    let tx = transport(&live.origin, &name)
        .with_receipt_store(receipts)
        .with_upload_observer(move |event| {
            seen.lock().unwrap().push(event);
            true
        });
    assert_eq!(
        push(dir.path(), &TransportSource::new(&tx), &options())
            .unwrap()
            .tip,
        Some(tip)
    );
    assert_eq!(tx.read_ref("refs/heads/main").unwrap(), Some(tip));
    let events = events.lock().unwrap();
    assert!(events.iter().any(|event| matches!(event, UploadEvent::PartsPlanned { resumed: 1, saved_bytes, .. } if *saved_bytes > 0)), "{events:?}");
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, UploadEvent::PartSent { index: 0, .. })),
        "acknowledged part was uploaded again: {events:?}"
    );
}

/// Cancellation comes from the caller after actual packing progress, before
/// the sealed pack can be uploaded or either remote ref can be published.
struct CancelAfterPacking(AtomicBool);
impl SyncObserver for CancelAfterPacking {
    fn event(&self, event: &SyncEvent) {
        if matches!(event, SyncEvent::ObjectsPacked { count } if *count > 0) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    fn cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

#[test]
fn caller_observer_cancels_packing_before_publication() {
    let live = Live::self_certifying();
    let tx = transport(
        &live.origin,
        &format!("{}/cancelled", self_certifying_namespace()),
    );
    let dir = repository();
    commit(dir.path(), None, b"cancel after real progress", 1);
    let observer = CancelAfterPacking(AtomicBool::new(false));
    let mut opts = options();
    opts.control.observer = &observer;
    assert!(matches!(
        push(dir.path(), &TransportSource::new(&tx), &opts),
        Err(PushError::Sync(SyncError::Interrupted))
    ));
    assert!(
        observer.0.load(Ordering::SeqCst),
        "caller must observe actual ObjectsPacked progress"
    );
    assert_eq!(tx.read_ref("refs/heads/main").unwrap(), None);
    assert_eq!(tx.read_ref("refs/mkit/packmap/main").unwrap(), None);
    assert_eq!(
        refs::read_remote_ref(&RepoLayout::single(dir.path()), "default", "main").unwrap(),
        None
    );
}
