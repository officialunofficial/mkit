//! Repository push against the real loopback server, including signed writes,
//! competing branch leases and caller-owned multipart receipts.
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
    ClientSource, NativeClock, NativeHttp, PushError, PushLease, PushOptions, PushTarget,
    RemoteSource, SyncError, SyncEvent, SyncObserver, TransportSource, push,
};
use mkit_transport_connect::{
    ConnectTransport, EnvelopeSigner, MemoryPartReceiptStore, UploadEvent,
};
use support::{Dalek, Live, NS, WRITER_SEED, build_commit, destination, self_certifying_namespace};

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

/// Run the same repository operation and assertions against both Connect drivers.
#[derive(Clone, Copy, Debug)]
enum Backend {
    Transport,
    Client,
}

impl Backend {
    const ALL: [Self; 2] = [Self::Transport, Self::Client];

    fn with_source<R>(
        self,
        origin: &str,
        repository: &str,
        run: impl FnOnce(&dyn RemoteSource) -> R,
    ) -> R {
        self.with_receipts(
            origin,
            repository,
            Arc::new(mkit_client::MemoryPartReceiptStore::default()),
            run,
        )
    }

    fn with_receipts<R>(
        self,
        origin: &str,
        repository: &str,
        receipts: Arc<dyn mkit_client::PartReceiptStore>,
        run: impl FnOnce(&dyn RemoteSource) -> R,
    ) -> R {
        match self {
            Self::Transport => {
                let tx = transport(origin, repository).with_receipt_store(receipts);
                run(&TransportSource::new(&tx))
            }
            Self::Client => {
                let http = NativeHttp::new().unwrap();
                let signer = Dalek::new(WRITER_SEED);
                let client = mkit_client::Client::signed(
                    &http,
                    destination(origin, repository),
                    &signer,
                    &NativeClock,
                );
                run(&ClientSource::new(&client, &http).with_receipt_store(receipts))
            }
        }
    }
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
fn assert_first_push_pack_parity(dir: &std::path::Path, tx: &dyn RemoteSource, tip: Hash) {
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
    for backend in Backend::ALL {
        let live = Live::self_certifying();
        let name = format!("{}/push", self_certifying_namespace());
        backend.with_source(&live.origin, &name, |source| {
            let dir = repository();
            let first = commit(dir.path(), None, b"first", 1);
            let report = push(dir.path(), source, &options()).unwrap();
            assert_eq!((report.refs, report.steps, report.tip), (1, 1, Some(first)));
            assert_eq!(source.read_ref("refs/heads/main").unwrap(), Some(first));
            assert_first_push_pack_parity(dir.path(), source, first);
            let second = commit(dir.path(), Some(first), b"second", 2);
            assert_eq!(
                push(dir.path(), source, &options()).unwrap().tip,
                Some(second)
            );
            assert_eq!(source.read_ref("refs/heads/main").unwrap(), Some(second));
            commit(dir.path(), None, b"unrelated", 3);
            assert!(
                matches!(push(dir.path(), source, &options()), Err(PushError::NonFastForwardPush { branch }) if branch == "main")
            );
            assert_eq!(source.read_ref("refs/heads/main").unwrap(), Some(second));
            assert_eq!(
                refs::read_remote_ref(&RepoLayout::single(dir.path()), "default", "main").unwrap(),
                Some(second)
            );
            });
    }
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
    for backend in Backend::ALL {
        let live = Live::self_certifying();
        let name = format!("{}/race", self_certifying_namespace());
        let dirs = [repository(), repository()];
        let base = commit(dirs[0].path(), None, b"base", 1);
        assert_eq!(commit(dirs[1].path(), None, b"base", 1), base);
        backend.with_source(&live.origin, &name, |source| {
            push(dirs[0].path(), source, &options()).unwrap();
        });
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
                        let observer = UploadBarrier {
                            barrier,
                            waited: AtomicBool::new(false),
                        };
                        let mut opts = options();
                        opts.control.observer = &observer;
                        backend.with_source(origin, name, |source| push(dir.path(), source, &opts))
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
        backend.with_source(&live.origin, &name, |source| {
            assert_eq!(
                source.read_ref("refs/heads/main").unwrap(),
                Some(tips[winner])
            );
        });
        for (index, dir) in dirs.iter().enumerate() {
            assert_eq!(
                refs::read_remote_ref(&RepoLayout::single(dir.path()), "default", "main").unwrap(),
                Some(if index == winner { tips[index] } else { base })
            );
        }
    }
}

#[test]
fn signed_push_to_authority_uuidv7_repository() {
    for backend in Backend::ALL {
        let live = Live::authority();
        backend.with_source(&live.origin, &format!("{NS}/signed-push"), |source| {
            let dir = repository();
            let tip = commit(dir.path(), None, b"authority", 1);
            assert_eq!(push(dir.path(), source, &options()).unwrap().tip, Some(tip));
            assert_eq!(source.read_ref("refs/heads/main").unwrap(), Some(tip));
            assert!(live.calls.lock().unwrap().iter().any(
                |(principal, _)| principal.ed25519() == Some(&support::public_key(WRITER_SEED))
            ));
        });
    }
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

/// Stop exactly after the caller-owned store has durably acknowledged part zero.
/// The next client must load that exact receipt and must never store it again.
#[derive(Default)]
struct StopAfterReceipt {
    inner: mkit_client::MemoryPartReceiptStore,
    interrupted: AtomicBool,
    saved: Mutex<Vec<(mkit_client::TicketMetadata, mkit_client::StoredPart)>>,
    loaded: Mutex<Vec<(mkit_client::TicketMetadata, mkit_client::StoredPart)>>,
}

impl mkit_client::PartReceiptStore for StopAfterReceipt {
    fn load(
        &self,
        ticket: &mkit_client::TicketMetadata,
        plan: &mkit_core::upload_parts::PartPlan,
    ) -> mkit_core::protocol::TransportResult<Vec<mkit_client::StoredPart>> {
        let parts = self.inner.load(ticket, plan)?;
        self.loaded
            .lock()
            .unwrap()
            .extend(parts.iter().cloned().map(|part| (ticket.clone(), part)));
        Ok(parts)
    }

    fn put(
        &self,
        ticket: &mkit_client::TicketMetadata,
        part: &mkit_client::StoredPart,
    ) -> mkit_core::protocol::TransportResult<()> {
        self.inner.put(ticket, part)?;
        self.saved
            .lock()
            .unwrap()
            .push((ticket.clone(), part.clone()));
        if part.index == 0 && !self.interrupted.swap(true, Ordering::SeqCst) {
            return Err(mkit_core::protocol::TransportError::ProtocolError);
        }
        Ok(())
    }

    fn forget(&self, ticket_id: &[u8; 32]) -> mkit_core::protocol::TransportResult<()> {
        self.inner.forget(ticket_id)
    }

    fn sweep(&self, now_ms: i64) -> mkit_core::protocol::TransportResult<()> {
        self.inner.sweep(now_ms)
    }
}

#[test]
fn multipart_receipts_resume_across_fresh_clients_and_both_backends() {
    for backend in Backend::ALL {
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
        let receipts = Arc::new(StopAfterReceipt::default());
        backend.with_receipts(&live.origin, &name, receipts.clone(), |source| {
            assert!(push(dir.path(), source, &options()).is_err(), "{backend:?}");
            assert_eq!(source.read_ref("refs/heads/main").unwrap(), None);
            assert_eq!(source.read_ref("refs/mkit/packmap/main").unwrap(), None);
        });
        assert!(receipts.interrupted.load(Ordering::SeqCst));
        assert_eq!(
            refs::read_remote_ref(&RepoLayout::single(dir.path()), "default", "main").unwrap(),
            None
        );
        let first_receipt = receipts.saved.lock().unwrap()[0].clone();
        assert_eq!(first_receipt.1.index, 0);
        assert!(!first_receipt.1.receipt.is_empty());
        let resumed_backend = match backend {
            Backend::Transport => Backend::Client,
            Backend::Client => Backend::Transport,
        };
        resumed_backend.with_receipts(&live.origin, &name, receipts.clone(), |source| {
            assert_eq!(push(dir.path(), source, &options()).unwrap().tip, Some(tip));
            assert_eq!(source.read_ref("refs/heads/main").unwrap(), Some(tip));
            // Verify every uploaded byte and both content-addressed IDs.
            let store = ObjectStore::open(&RepoLayout::single(dir.path())).unwrap();
            let plan = transfer::plan_pack(&store, tip, None).unwrap();
            let mut writer = PackWriter::new();
            for id in plan.raw {
                writer.push_raw(id, &store.read(&id).unwrap()).unwrap();
            }
            for delta in plan.deltas {
                writer.push_delta(&delta.base, &delta.stream).unwrap();
            }
            let expected_pack = writer.finish().unwrap();
            let pack_key = pack_key(&expected_pack);
            let expected_node = transfer::encode_packlist(None, &[pack_key]).unwrap();
            assert_eq!(
                source.read_ref("refs/mkit/packmap/main").unwrap(),
                Some(mkit_core::pack::pack_key(&expected_node))
            );
            assert_eq!(
                source
                    .download_blob_via_ref(
                        &PackKey::from_hash(mkit_core::pack::pack_key(&expected_node)),
                        "refs/heads/main",
                    )
                    .unwrap(),
                expected_node
            );
            assert_eq!(
                source
                    .download_pack_via_ref(&PackKey::from_hash(pack_key), "refs/heads/main")
                    .unwrap(),
                expected_pack
            );
        });
        assert!(receipts.loaded.lock().unwrap().contains(&first_receipt));
        assert_eq!(
            receipts
                .saved
                .lock()
                .unwrap()
                .iter()
                .filter(|(_, part)| part.index == 0)
                .count(),
            1,
            "the acknowledged part was resent when changing Connect drivers"
        );
        assert_eq!(
            refs::read_remote_ref(&RepoLayout::single(dir.path()), "default", "main").unwrap(),
            Some(tip)
        );
    }
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
    for backend in Backend::ALL {
        let live = Live::self_certifying();
        let name = format!("{}/cancelled", self_certifying_namespace());
        backend.with_source(&live.origin, &name, |source| {
            let dir = repository();
            commit(dir.path(), None, b"cancel after real progress", 1);
            let observer = CancelAfterPacking(AtomicBool::new(false));
            let mut opts = options();
            opts.control.observer = &observer;
            assert!(matches!(
                push(dir.path(), source, &opts),
                Err(PushError::Sync(SyncError::Interrupted))
            ));
            assert!(
                observer.0.load(Ordering::SeqCst),
                "caller must observe actual ObjectsPacked progress"
            );
            assert_eq!(source.read_ref("refs/heads/main").unwrap(), None);
            assert_eq!(source.read_ref("refs/mkit/packmap/main").unwrap(), None);
            assert_eq!(
                refs::read_remote_ref(&RepoLayout::single(dir.path()), "default", "main").unwrap(),
                None
            );
        });
    }
}

#[test]
fn caller_owned_session_keeps_upload_commitments_across_fresh_clients() {
    let live = Live::self_certifying();
    let name = format!("{}/session", self_certifying_namespace());
    let dir = repository();
    let tip = commit(dir.path(), None, b"session", 1);
    let store = ObjectStore::open(&RepoLayout::single(dir.path())).unwrap();
    let plan = transfer::plan_pack(&store, tip, None).unwrap();
    let mut writer = PackWriter::new();
    for id in plan.raw {
        writer.push_raw(id, &store.read(&id).unwrap()).unwrap();
    }
    for delta in plan.deltas {
        writer.push_delta(&delta.base, &delta.stream).unwrap();
    }
    let pack = writer.finish().unwrap();
    let key = PackKey::from_hash(pack_key(&pack));
    let node = transfer::encode_packlist(None, &[key.into_hash()]).unwrap();
    let node_key = PackKey::from_hash(pack_key(&node));
    let session = mkit_sync::ClientSession::default();
    {
        let http = NativeHttp::new().unwrap();
        let signer = Dalek::new(WRITER_SEED);
        let client = mkit_client::Client::signed(
            &http,
            destination(&live.origin, &name),
            &signer,
            &NativeClock,
        );
        let source = ClientSource::new(&client, &http)
            .with_session(&session)
            .unwrap();
        source
            .upload_pack_via_ref(&pack, &key, "refs/heads/main")
            .unwrap();
        source
            .upload_blob_via_ref(&node, &node_key, "refs/heads/main")
            .unwrap();
    }
    let http = NativeHttp::new().unwrap();
    let signer = Dalek::new(WRITER_SEED);
    let client = mkit_client::Client::signed(
        &http,
        destination(&live.origin, &name),
        &signer,
        &NativeClock,
    );
    let source = ClientSource::new(&client, &http)
        .with_session(&session)
        .unwrap();
    assert_eq!(
        source
            .advance_refs_committing(
                "refs/heads/main",
                refs::RefWriteCondition::Missing,
                &tip,
                "refs/mkit/packmap/main",
                refs::RefWriteCondition::Missing,
                node_key.as_bytes(),
                &[key, node_key],
            )
            .unwrap(),
        mkit_core::protocol::CommitOutcome::Advanced(
            mkit_core::protocol::AdvanceOutcome::Committed
        )
    );
    assert_eq!(source.read_ref("refs/heads/main").unwrap(), Some(tip));
    assert_eq!(
        source.read_ref("refs/mkit/packmap/main").unwrap(),
        Some(node_key.into_hash())
    );
}

type BeforeWrite<'a> = Box<dyn FnOnce() + 'a>;
type BeforeEachWrite<'a> = Box<dyn FnMut() + 'a>;
type BeforePackmapRead<'a> = (usize, BeforeWrite<'a>);

/// Interleave a complete competing push at a deterministic source boundary.
/// The underlying source still performs every read, upload and atomic commit.
struct InterleavedSource<'a> {
    inner: &'a dyn RemoteSource,
    skip_split_estimate: bool,
    before_write: std::cell::RefCell<Option<BeforeWrite<'a>>>,
    before_head_read: std::cell::RefCell<Option<BeforeWrite<'a>>>,
    before_each_write: std::cell::RefCell<Option<BeforeEachWrite<'a>>>,
    before_packmap_read: std::cell::RefCell<Option<BeforePackmapRead<'a>>>,
    packmap_reads: std::cell::Cell<usize>,
    calls: std::cell::RefCell<Vec<&'static str>>,
}

impl<'a> InterleavedSource<'a> {
    fn new(inner: &'a dyn RemoteSource) -> Self {
        Self {
            inner,
            skip_split_estimate: false,
            before_write: std::cell::RefCell::default(),
            before_head_read: std::cell::RefCell::default(),
            before_each_write: std::cell::RefCell::default(),
            before_packmap_read: std::cell::RefCell::default(),
            packmap_reads: std::cell::Cell::new(0),
            calls: std::cell::RefCell::default(),
        }
    }

    fn interleave_write(&self) {
        if let Some(run) = self.before_each_write.borrow_mut().as_mut() {
            run();
        }
        let run = self.before_write.borrow_mut().take();
        if let Some(run) = run {
            run();
        }
    }
}

impl RemoteSource for InterleavedSource<'_> {
    fn list_branches(&self) -> Result<Vec<refs::Ref>, mkit_sync::SourceError> {
        self.calls.borrow_mut().push("list");
        self.inner.list_branches()
    }

    fn read_ref(&self, name: &str) -> Result<Option<Hash>, mkit_sync::SourceError> {
        if name == "refs/mkit/packmap/main" {
            let count = self.packmap_reads.get() + 1;
            self.packmap_reads.set(count);
            let run = if self
                .before_packmap_read
                .borrow()
                .as_ref()
                .is_some_and(|(at, _)| *at == count)
            {
                self.before_packmap_read.borrow_mut().take()
            } else {
                None
            };
            if let Some((_, run)) = run {
                run();
            }
            self.calls.borrow_mut().push("packmap");
        } else {
            let run = self.before_head_read.borrow_mut().take();
            if let Some(run) = run {
                run();
            }
            self.calls.borrow_mut().push("head");
        }
        self.inner.read_ref(name)
    }

    fn download_blob_via_ref(
        &self,
        key: &PackKey,
        name: &str,
    ) -> Result<Vec<u8>, mkit_sync::SourceError> {
        self.calls.borrow_mut().push("node");
        self.inner.download_blob_via_ref(key, name)
    }

    fn download_pack_via_ref(
        &self,
        key: &PackKey,
        name: &str,
    ) -> Result<Vec<u8>, mkit_sync::SourceError> {
        self.calls.borrow_mut().push("pack");
        self.inner.download_pack_via_ref(key, name)
    }

    fn supports_push(&self) -> bool {
        self.inner.supports_push()
    }

    fn supports_atomic_advance(&self) -> bool {
        self.inner.supports_atomic_advance()
    }

    fn atomic_force_head_condition(&self, observed_head: Option<Hash>) -> refs::RefWriteCondition {
        self.inner.atomic_force_head_condition(observed_head)
    }

    fn upload_limits(&self) -> mkit_core::protocol::UploadLimits {
        let mut limits = self.inner.upload_limits();
        if self.skip_split_estimate {
            limits.tickets_per_advance = None;
        }
        limits
    }

    fn upload_pack_via_ref(
        &self,
        bytes: &[u8],
        key: &PackKey,
        name: &str,
    ) -> Result<(), mkit_sync::SourceError> {
        self.calls.borrow_mut().push("upload-pack");
        self.inner.upload_pack_via_ref(bytes, key, name)
    }

    fn upload_blob_via_ref(
        &self,
        bytes: &[u8],
        key: &PackKey,
        name: &str,
    ) -> Result<(), mkit_sync::SourceError> {
        self.calls.borrow_mut().push("upload-node");
        self.inner.upload_blob_via_ref(bytes, key, name)
    }

    fn update_ref(
        &self,
        name: &str,
        condition: refs::RefWriteCondition,
        tip: &Hash,
    ) -> Result<(), mkit_sync::SourceError> {
        self.interleave_write();
        self.calls.borrow_mut().push("update-head");
        self.inner.update_ref(name, condition, tip)
    }

    fn advance_refs_committing(
        &self,
        head: &str,
        head_condition: refs::RefWriteCondition,
        tip: &Hash,
        packmap: &str,
        packmap_condition: refs::RefWriteCondition,
        node: &Hash,
        keys: &[PackKey],
    ) -> Result<mkit_core::protocol::CommitOutcome, mkit_sync::SourceError> {
        self.interleave_write();
        self.calls.borrow_mut().push("advance");
        self.inner.advance_refs_committing(
            head,
            head_condition,
            tip,
            packmap,
            packmap_condition,
            node,
            keys,
        )
    }

    fn repository_address(&self) -> Option<(String, String)> {
        self.inner.repository_address()
    }

    fn repository_error(&self, error: mkit_sync::SourceError) -> SyncError {
        self.inner.repository_error(error)
    }
}

fn force_options<'a>() -> PushOptions<'a> {
    PushOptions::default().with_target(PushTarget::Branch {
        local: "main".into(),
        remote: "main".into(),
        lease: PushLease::Force,
    })
}

fn assert_fresh_clone(
    source: &dyn RemoteSource,
    origin: &str,
    name: &str,
    tip: Hash,
    content: &[u8],
) {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("clone");
    mkit_sync::clone(
        &target,
        source,
        &mkit_sync::CloneRemote {
            name: "default".into(),
            url: format!("mkit+{origin}/{name}"),
            kind: "http".into(),
        },
        &mkit_sync::SyncOptions::default(),
        &mkit_sync::NoopObserver,
    )
    .unwrap();
    assert_eq!(
        refs::read_ref(&RepoLayout::single(&target), "main").unwrap(),
        Some(tip)
    );
    assert_eq!(std::fs::read(target.join("file")).unwrap(), content);
}

fn force_push_during_rebaseline(appending: bool, before_packmap_read: bool) {
    for backend in Backend::ALL {
        let live = Live::self_certifying();
        let name = format!("{}/force-reset", self_certifying_namespace());
        backend.with_source(&live.origin, &name, |source| {
            assert!(source.supports_atomic_advance());
            let victim = repository();
            let first = commit(victim.path(), None, b"first closure", 1);
            push(victim.path(), source, &options()).unwrap();
            let prior = commit(victim.path(), Some(first), b"second closure", 2);
            push(victim.path(), source, &options()).unwrap();
            let (tip, content) = if appending {
                (
                    commit(victim.path(), Some(first), b"forced closure", 3),
                    b"forced closure".as_slice(),
                )
            } else {
                refs::write_ref(&RepoLayout::single(victim.path()), "main", &first).unwrap();
                (first, b"first closure".as_slice())
            };
            let competitor = repository();
            let reset_tip = commit(competitor.path(), None, b"unrelated reset closure", 4);
            refs::write_remote_ref(
                &RepoLayout::single(competitor.path()),
                "default",
                "main",
                &prior,
            )
            .unwrap();
            let reset = || {
                let mut opts = PushOptions::default().with_target(PushTarget::Branch {
                    local: "main".into(),
                    remote: "main".into(),
                    lease: PushLease::WithLease,
                });
                opts.rebaseline_threshold = 1;
                assert_eq!(
                    push(competitor.path(), source, &opts).unwrap().tip,
                    Some(reset_tip)
                );
                let node = source.read_ref("refs/mkit/packmap/main").unwrap().unwrap();
                let bytes = source
                    .download_blob_via_ref(&PackKey::from_hash(node), "refs/heads/main")
                    .unwrap();
                assert_eq!(transfer::decode_packlist(&bytes).unwrap().prev, None);
            };
            let raced = InterleavedSource::new(source);
            if before_packmap_read {
                *raced.before_packmap_read.borrow_mut() = Some((2, Box::new(reset)));
            } else {
                *raced.before_write.borrow_mut() = Some(Box::new(reset));
            }
            assert_eq!(
                push(victim.path(), &raced, &force_options()).unwrap().tip,
                Some(tip)
            );
            assert!(raced.before_write.borrow().is_none());
            assert!(raced.before_packmap_read.borrow().is_none());
            assert_eq!(source.read_ref("refs/heads/main").unwrap(), Some(tip));
            assert_fresh_clone(source, &live.origin, &name, tip, content);
        });
    }
}

#[test]
fn force_head_only_replans_after_concurrent_atomic_rebaseline() {
    force_push_during_rebaseline(false, false);
}

#[test]
fn force_append_replans_after_concurrent_atomic_rebaseline() {
    force_push_during_rebaseline(true, false);
}

#[test]
fn force_append_replans_if_chain_reset_before_packmap_probe() {
    force_push_during_rebaseline(true, true);
}

#[test]
fn force_push_success_adds_only_one_strong_packmap_read() {
    for backend in Backend::ALL {
        for force in [false, true] {
            let live = Live::self_certifying();
            let name = format!("{}/push-calls", self_certifying_namespace());
            backend.with_source(&live.origin, &name, |source| {
                let dir = repository();
                let first = commit(dir.path(), None, b"first", 1);
                push(dir.path(), source, &options()).unwrap();
                let measured = InterleavedSource::new(source);
                let opts = if force { force_options() } else { options() };
                push(dir.path(), &measured, &opts).unwrap();
                let head_only = measured.calls.take();
                if force {
                    assert_eq!(head_only.len(), 3, "{backend:?}: {head_only:?}");
                    assert_eq!(head_only.iter().filter(|&&call| call == "head").count(), 1);
                    assert_eq!(
                        head_only.iter().filter(|&&call| call == "packmap").count(),
                        1
                    );
                    assert_eq!(head_only.last(), Some(&"advance"));
                } else {
                    assert_eq!(head_only, ["head", "update-head"], "{backend:?}");
                }
                commit(dir.path(), Some(first), b"second", 2);
                push(dir.path(), &measured, &opts).unwrap();
                let appending = measured.calls.take();
                assert_eq!(appending.iter().filter(|&&call| call == "head").count(), 1);
                assert_eq!(
                    appending.iter().filter(|&&call| call == "packmap").count(),
                    2 + usize::from(force)
                );
                assert_eq!(appending.iter().filter(|&&call| call == "node").count(), 1);
                assert_eq!(
                    appending
                        .iter()
                        .filter(|&&call| call == "upload-pack")
                        .count(),
                    1
                );
                assert_eq!(
                    appending
                        .iter()
                        .filter(|&&call| call == "upload-node")
                        .count(),
                    1
                );
                assert_eq!(
                    appending.iter().filter(|&&call| call == "advance").count(),
                    1
                );
                assert_eq!(
                    appending.len(),
                    7 + usize::from(force),
                    "{backend:?}: {appending:?}"
                );
            });
        }
    }
}

#[test]
fn force_push_rebaseline_replans_share_the_eight_attempt_budget() {
    for backend in Backend::ALL {
        for appending in [false, true] {
            let live = Live::self_certifying();
            let name = format!("{}/force-contention", self_certifying_namespace());
            backend.with_source(&live.origin, &name, |source| {
                let victim = repository();
                let first = commit(victim.path(), None, b"first", 1);
                push(victim.path(), source, &options()).unwrap();
                if appending {
                    commit(victim.path(), Some(first), b"forced", 2);
                }
                let competitor = repository();
                let attempts = std::cell::Cell::new(0_u64);
                let raced = InterleavedSource::new(source);
                *raced.before_each_write.borrow_mut() = Some(Box::new(|| {
                    let count = attempts.get() + 1;
                    attempts.set(count);
                    assert!(count <= 8, "force push retried beyond the existing budget");
                    let prior = source.read_ref("refs/heads/main").unwrap().unwrap();
                    refs::write_remote_ref(
                        &RepoLayout::single(competitor.path()), "default", "main", &prior,
                    ).unwrap();
                    commit(competitor.path(), None, format!("reset {count}").as_bytes(), 10 + count);
                    let mut opts = PushOptions::default().with_target(PushTarget::Branch {
                        local: "main".into(),
                        remote: "main".into(),
                        lease: PushLease::WithLease,
                    });
                    opts.rebaseline_threshold = 1;
                    push(competitor.path(), source, &opts).unwrap();
                }));
                assert!(matches!(push(victim.path(), &raced, &force_options()), Err(PushError::PackmapContended { branch }) if branch == "main"));
                assert_eq!(attempts.get(), 8, "{backend:?}, appending={appending}");
                let final_tip = refs::read_ref(&RepoLayout::single(competitor.path()), "main").unwrap().unwrap();
                assert_fresh_clone(source, &live.origin, &name, final_tip, b"reset 8");
            });
        }
    }
}

#[test]
fn force_head_only_replans_after_packmap_aba_between_snapshot_reads() {
    for backend in Backend::ALL {
        let live = Live::self_certifying();
        let name = format!("{}/force-aba", self_certifying_namespace());
        backend.with_source(&live.origin, &name, |source| {
            let victim = repository();
            let first = commit(victim.path(), None, b"first", 1);
            push(victim.path(), source, &options()).unwrap();
            let original_node = source.read_ref("refs/mkit/packmap/main").unwrap().unwrap();
            let tip = commit(victim.path(), Some(first), b"second", 2);
            let mut raced = InterleavedSource::new(source);
            // Exercise the direct planner's packmap-then-head snapshot. The
            // inner source still performs its ordinary ticketed uploads.
            raced.skip_split_estimate = true;
            // Capture the original packmap, then observe the head of a newer
            // chain. A reset back to the identical old node defeats a packmap
            // guard alone: the empty plan depends on the newer head's closure.
            *raced.before_head_read.borrow_mut() = Some(Box::new(|| {
                push(victim.path(), source, &options()).unwrap();
                assert_eq!(source.read_ref("refs/heads/main").unwrap(), Some(tip));
                assert_ne!(
                    source.read_ref("refs/mkit/packmap/main").unwrap(),
                    Some(original_node)
                );
            }));
            *raced.before_write.borrow_mut() = Some(Box::new(|| {
                let newer_node = source.read_ref("refs/mkit/packmap/main").unwrap().unwrap();
                assert_eq!(
                    source
                        .advance_refs_committing(
                            "refs/heads/main",
                            refs::RefWriteCondition::Match(tip),
                            &first,
                            "refs/mkit/packmap/main",
                            refs::RefWriteCondition::Match(newer_node),
                            &original_node,
                            &[],
                        )
                        .unwrap(),
                    mkit_core::protocol::CommitOutcome::Advanced(
                        mkit_core::protocol::AdvanceOutcome::Committed,
                    )
                );
                assert_eq!(
                    source.read_ref("refs/mkit/packmap/main").unwrap(),
                    Some(original_node)
                );
                assert_eq!(source.read_ref("refs/heads/main").unwrap(), Some(first));
            }));
            assert_eq!(
                push(victim.path(), &raced, &force_options()).unwrap().tip,
                Some(tip)
            );
            assert!(raced.before_head_read.borrow().is_none());
            assert!(raced.before_write.borrow().is_none());
            assert_eq!(&raced.calls.borrow()[..2], ["packmap", "head"]);
            assert_fresh_clone(source, &live.origin, &name, tip, b"second");
        });
    }
}
