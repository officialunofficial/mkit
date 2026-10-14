//! Process-kill parity at the caller-owned multipart receipt durability boundary.
#![cfg(feature = "connect-native")]
#![allow(clippy::unwrap_used)]

mod support;

use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::{Child, Command},
    sync::Arc,
    time::{Duration, Instant},
};

use ed25519_dalek::{Signer as _, SigningKey};
use mkit_client::{PartReceiptStore, StoredPart, TicketMetadata};
use mkit_core::{
    hash::{Hash, to_hex, to_hex_bytes},
    layout::RepoLayout,
    pack::{PackWriter, pack_key},
    protocol::{PackKey, TransportResult},
    refs,
    serialize::serialize,
    store::ObjectStore,
    transfer,
    upload_parts::PartPlan,
};
use mkit_sync::{
    ClientSource, NativeClock, NativeHttp, PushLease, PushOptions, PushTarget, RemoteSource,
    TransportSource, push,
};
use mkit_transport_connect::{ConnectTransport, EnvelopeSigner};
use support::{Dalek, WRITER_SEED, build_commit, destination, self_certifying_namespace};

struct Signer(SigningKey);
impl EnvelopeSigner for Signer {
    fn public_key_hex(&self) -> String {
        to_hex(self.0.verifying_key().as_bytes())
    }
    fn sign_hex(&self, digest: &Hash) -> Result<String, String> {
        Ok(to_hex_bytes(&self.0.sign(digest).to_bytes()))
    }
}

fn with_source<R>(
    backend: &str,
    origin: &str,
    repository: &str,
    receipts: Arc<dyn PartReceiptStore>,
    run: impl FnOnce(&dyn RemoteSource) -> R,
) -> R {
    match backend {
        "transport" => {
            let tx = ConnectTransport::connect_with_signer(
                &format!("mkit+{origin}/{repository}"),
                Some(Arc::new(Signer(SigningKey::from_bytes(&[WRITER_SEED; 32])))),
            )
            .unwrap()
            .with_receipt_store(receipts);
            run(&TransportSource::new(&tx))
        }
        "client" => {
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
        _ => panic!("unknown test backend"),
    }
}

fn options<'a>() -> PushOptions<'a> {
    PushOptions::default().with_target(PushTarget::Branch {
        local: "main".into(),
        remote: "main".into(),
        lease: PushLease::FastForward,
    })
}

/// A test-only disk format. Every ticket binding field and opaque receipt is
/// fsynced before a marker lets the parent kill the child. Audit files survive
/// successful cache cleanup so the parent can verify loads and part put counts.
struct FileReceiptStore {
    root: PathBuf,
    stop_after_first: bool,
}

fn durable_write(path: &Path, bytes: &[u8]) {
    let temporary = path.with_extension("tmp");
    let mut file = File::create(&temporary).unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
    fs::rename(&temporary, path).unwrap();
    File::open(path.parent().unwrap())
        .unwrap()
        .sync_all()
        .unwrap();
}

fn binding(ticket: &TicketMetadata) -> Vec<u8> {
    let mut bytes = ticket.ticket_id.to_vec();
    for value in [
        &ticket.audience,
        &ticket.repository,
        &ticket.signer,
        &ticket.head_ref,
    ] {
        bytes.extend_from_slice(&(value.len() as u64).to_le_bytes());
        bytes.extend_from_slice(value.as_bytes());
    }
    bytes.extend_from_slice(ticket.pack_key.as_bytes());
    bytes.extend_from_slice(&ticket.bytes.to_le_bytes());
    bytes.extend_from_slice(&ticket.part_size.to_le_bytes());
    bytes.extend_from_slice(&ticket.expires_unix_ms.to_le_bytes());
    bytes
}

fn part_bytes(part: &StoredPart) -> Vec<u8> {
    let mut bytes = part.index.to_le_bytes().to_vec();
    bytes.extend_from_slice(&part.len.to_le_bytes());
    bytes.extend_from_slice(&part.receipt);
    bytes
}

impl FileReceiptStore {
    fn ticket_dir(&self, ticket_id: &[u8; 32]) -> PathBuf {
        self.root.join(to_hex(ticket_id))
    }
}

impl PartReceiptStore for FileReceiptStore {
    fn load(&self, ticket: &TicketMetadata, plan: &PartPlan) -> TransportResult<Vec<StoredPart>> {
        let dir = self.ticket_dir(&ticket.ticket_id);
        if fs::read(dir.join("binding")).ok().as_deref() != Some(binding(ticket).as_slice()) {
            return Ok(Vec::new());
        }
        let mut parts = Vec::new();
        for index in 0..plan.count() {
            let Ok(bytes) = fs::read(dir.join(format!("part-{index}"))) else {
                continue;
            };
            assert!(bytes.len() > 12, "receipt must contain opaque server bytes");
            let saved_index = u32::from_le_bytes(bytes[..4].try_into().unwrap());
            let len = u64::from_le_bytes(bytes[4..12].try_into().unwrap());
            assert_eq!(saved_index, index);
            assert_eq!(plan.expected_len(index).unwrap(), len);
            let part = StoredPart {
                index,
                len,
                receipt: bytes[12..].to_vec(),
                from_disk: true,
            };
            durable_write(&self.root.join(format!("loaded-{index}")), &bytes);
            parts.push(part);
        }
        Ok(parts)
    }

    fn put(&self, ticket: &TicketMetadata, part: &StoredPart) -> TransportResult<()> {
        let dir = self.ticket_dir(&ticket.ticket_id);
        fs::create_dir_all(&dir).unwrap();
        File::open(&self.root).unwrap().sync_all().unwrap();
        durable_write(&dir.join("binding"), &binding(ticket));
        durable_write(&dir.join(format!("part-{}", part.index)), &part_bytes(part));
        let mut audit = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.root.join("puts"))
            .unwrap();
        writeln!(audit, "{}", part.index).unwrap();
        audit.sync_all().unwrap();
        if self.stop_after_first && part.index == 0 {
            durable_write(&self.root.join("durable-part-zero"), &part_bytes(part));
            // The parent kills this process while put is blocked, so neither
            // a second part nor any remote or local ref can be published.
            loop {
                std::thread::park();
            }
        }
        Ok(())
    }

    fn forget(&self, ticket_id: &[u8; 32]) -> TransportResult<()> {
        let dir = self.ticket_dir(ticket_id);
        if dir.exists() {
            fs::remove_dir_all(dir).unwrap();
            File::open(&self.root).unwrap().sync_all().unwrap();
        }
        Ok(())
    }

    fn sweep(&self, _now_ms: i64) -> TransportResult<()> {
        // The fixture contains only the current, unexpired ticket.
        Ok(())
    }
}

/// This libtest entry point is also launched by the parent with --exact.
/// Without the private child environment it has no work; the parent testcase
/// always executes both crash and resume phases and checks their outcomes.
#[test]
fn multipart_push_child() {
    let Ok(backend) = std::env::var("MKIT_MULTIPART_CHILD_BACKEND") else {
        return;
    };
    let origin = std::env::var("MKIT_MULTIPART_CHILD_ORIGIN").unwrap();
    let name = std::env::var("MKIT_MULTIPART_CHILD_NAME").unwrap();
    let repository = PathBuf::from(std::env::var_os("MKIT_MULTIPART_CHILD_REPO").unwrap());
    let receipts = FileReceiptStore {
        root: PathBuf::from(std::env::var_os("MKIT_MULTIPART_CHILD_RECEIPTS").unwrap()),
        stop_after_first: std::env::var("MKIT_MULTIPART_CHILD_PHASE").unwrap() == "crash",
    };
    with_source(&backend, &origin, &name, Arc::new(receipts), |source| {
        let tip = refs::read_ref(&RepoLayout::single(&repository), "main").unwrap();
        assert_eq!(push(&repository, source, &options()).unwrap().tip, tip);
    });
}

/// Kill/reap children on failure as well as on the deliberate crash path.
struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn child(
    backend: &str,
    origin: &str,
    name: &str,
    repository: &Path,
    receipts: &Path,
    phase: &str,
) -> ChildGuard {
    ChildGuard(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "multipart_push_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("MKIT_MULTIPART_CHILD_BACKEND", backend)
            .env("MKIT_MULTIPART_CHILD_ORIGIN", origin)
            .env("MKIT_MULTIPART_CHILD_NAME", name)
            .env("MKIT_MULTIPART_CHILD_REPO", repository)
            .env("MKIT_MULTIPART_CHILD_RECEIPTS", receipts)
            .env("MKIT_MULTIPART_CHILD_PHASE", phase)
            .spawn()
            .unwrap(),
    )
}

fn wait_for_marker(child: &mut ChildGuard, marker: &Path) {
    let deadline = Instant::now() + Duration::from_secs(90);
    while !marker.exists() {
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "uploader exited before durable receipt"
        );
        assert!(
            Instant::now() < deadline,
            "uploader never persisted part zero"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn wait_for_success(child: &mut ChildGuard) {
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(status.success(), "fresh process failed to resume: {status}");
            return;
        }
        assert!(
            Instant::now() < deadline,
            "fresh process did not finish resuming"
        );
        std::thread::sleep(Duration::from_millis(20));
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

struct PreparedRepository {
    repository: tempfile::TempDir,
    tip: Hash,
    expected_pack: Vec<u8>,
    expected_node: Vec<u8>,
}

fn prepare_repository() -> PreparedRepository {
    let repository = tempfile::tempdir().unwrap();
    let layout = RepoLayout::single(repository.path());
    ObjectStore::init(&layout).unwrap();
    let store = ObjectStore::open(&layout).unwrap();
    let mut random = 0x8c17_a9e5_u32;
    let bytes = (0..(9 << 20))
        .map(|_| {
            random ^= random << 13;
            random ^= random >> 17;
            random ^= random << 5;
            random.to_le_bytes()[0]
        })
        .collect::<Vec<_>>();
    let (objects, tip) = build_commit(WRITER_SEED, None, &[("file", &bytes)], 1);
    for object in objects {
        assert_eq!(
            store.write(&serialize(&object).unwrap()).unwrap(),
            object.id().unwrap()
        );
    }
    refs::write_ref(&layout, "main", &tip).unwrap();
    let plan = transfer::plan_pack(&store, tip, None).unwrap();
    let mut writer = PackWriter::new();
    for id in plan.raw {
        writer.push_raw(id, &store.read(&id).unwrap()).unwrap();
    }
    for delta in plan.deltas {
        writer.push_delta(&delta.base, &delta.stream).unwrap();
    }
    let expected_pack = writer.finish().unwrap();
    assert!(expected_pack.len() > 8 << 20);
    let expected_key = pack_key(&expected_pack);
    let expected_node = transfer::encode_packlist(None, &[expected_key]).unwrap();

    PreparedRepository {
        repository,
        tip,
        expected_pack,
        expected_node,
    }
}

#[test]
fn multipart_push_resumes_after_process_kill_on_both_backends() {
    for backend in ["transport", "client"] {
        let live = MultipartServer::new();
        let name = format!("{}/crash", self_certifying_namespace());
        let PreparedRepository {
            repository,
            tip,
            expected_pack,
            expected_node,
        } = prepare_repository();
        let layout = RepoLayout::single(repository.path());
        let expected_key = pack_key(&expected_pack);
        let expected_node_key = pack_key(&expected_node);
        let receipts = tempfile::tempdir().unwrap();
        let marker = receipts.path().join("durable-part-zero");
        let mut interrupted = child(
            backend,
            &live.origin,
            &name,
            repository.path(),
            receipts.path(),
            "crash",
        );
        wait_for_marker(&mut interrupted, &marker);
        interrupted.0.kill().unwrap();
        assert!(!interrupted.0.wait().unwrap().success());
        assert_eq!(
            fs::read_to_string(receipts.path().join("puts")).unwrap(),
            "0\n"
        );
        assert_eq!(
            refs::read_remote_ref(&layout, "default", "main").unwrap(),
            None
        );
        with_source(
            backend,
            &live.origin,
            &name,
            Arc::new(mkit_client::MemoryPartReceiptStore::default()),
            |source| {
                assert_eq!(source.read_ref("refs/heads/main").unwrap(), None);
                assert_eq!(source.read_ref("refs/mkit/packmap/main").unwrap(), None);
            },
        );
        let mut resumed = child(
            backend,
            &live.origin,
            &name,
            repository.path(),
            receipts.path(),
            "resume",
        );
        wait_for_success(&mut resumed);
        assert_eq!(
            fs::read(receipts.path().join("loaded-0")).unwrap(),
            fs::read(&marker).unwrap()
        );
        assert_eq!(
            fs::read_to_string(receipts.path().join("puts")).unwrap(),
            "0\n1\n",
            "acknowledged part zero must not be resent: {backend}"
        );
        assert_eq!(
            refs::read_remote_ref(&layout, "default", "main").unwrap(),
            Some(tip)
        );
        with_source(
            backend,
            &live.origin,
            &name,
            Arc::new(mkit_client::MemoryPartReceiptStore::default()),
            |source| {
                assert_eq!(source.read_ref("refs/heads/main").unwrap(), Some(tip));
                assert_eq!(
                    source.read_ref("refs/mkit/packmap/main").unwrap(),
                    Some(expected_node_key)
                );
                assert_eq!(
                    source
                        .download_blob_via_ref(
                            &PackKey::from_hash(expected_node_key),
                            "refs/heads/main"
                        )
                        .unwrap(),
                    expected_node
                );
                assert_eq!(
                    source
                        .download_pack_via_ref(&PackKey::from_hash(expected_key), "refs/heads/main")
                        .unwrap(),
                    expected_pack
                );
            },
        );
    }
}
