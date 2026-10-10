//! A published source repository and the instruments a fork test needs: a
//! counting store whose every call costs 50 ms of modeled time, a crash
//! switch, and a driver that runs the deployment's own timers to completion.
#![allow(
    clippy::unwrap_used,
    dead_code,
    unreachable_pub,
    clippy::many_single_char_names
)]
use mkit_core::{
    hash::{Hash, hash},
    object::{Blob, Commit, EntryMode, Identity, Object, Tree, TreeEntry},
    pack::PackWriter,
    serialize::serialize,
    sign::{KeyPair, sign_commit},
};
use mkit_server::{
    Batch, BatchOutcome, BlobKey, BoxFuture, Clock, Cursor, Key, ManualClock, MemoryBlobStore,
    MemoryKv, NamespaceKey, NamespaceStore, Partition, PartitionStats, RangeScan, RepoId, RepoName,
    ScanPage, StoreCapabilities, StoreError, Value,
    indexed::{
        IndexedConfig,
        budget::{BlobWindows, PackWindows, Window, WindowError},
        job::{FailClosedExtraction, SliceLimits, VerifyTimer},
    },
    pipeline::{D34Shards, LeaseParams, ShardMap},
    timers::{TickBudget, TimerRegistry, run_due},
};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicI64, AtomicU64, Ordering},
};

pub const AUDIENCE: &str = "https://fork.example";

/// What a crash does to the next matching call.
#[derive(Default)]
pub struct Crash {
    /// Applies left before one fails; negative disarms.
    pub applies: AtomicI64,
    /// Whether the failing apply still commits (a lost reply).
    pub lost_reply: std::sync::atomic::AtomicBool,
    pub armed: std::sync::atomic::AtomicBool,
}

/// Counts calls and charges each 50 ms to the clock.
#[derive(Clone)]
pub struct Counting {
    pub inner: Arc<MemoryKv>,
    pub clock: Arc<ManualClock>,
    pub calls: Arc<AtomicU64>,
    pub crash: Arc<Crash>,
    pub log: Arc<Mutex<Vec<(Partition, Batch)>>>,
    pub record: Arc<std::sync::atomic::AtomicBool>,
    /// Scans of repository index partitions.
    pub scans: Arc<AtomicU64>,
    /// Modeled milliseconds each call costs; zero while a fixture is built.
    pub latency_ms: Arc<AtomicI64>,
    /// Runs once, before the first apply that writes a key of this class.
    pub trigger: Arc<Mutex<Option<(&'static str, Hook)>>>,
}

pub type Hook = Arc<dyn Fn() -> BoxFuture<'static, ()> + Send + Sync>;
impl Counting {
    pub fn new(clock: Arc<ManualClock>) -> Self {
        Self {
            inner: Arc::new(MemoryKv::with_clock(clock.clone())),
            clock,
            calls: Arc::default(),
            crash: Arc::default(),
            log: Arc::default(),
            record: Arc::default(),
            scans: Arc::default(),
            latency_ms: Arc::default(),
            trigger: Arc::default(),
        }
    }
    fn tick(&self) {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.clock.advance(self.latency_ms.load(Ordering::SeqCst));
    }
    pub fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
    /// Fail the `n`th apply from now (1 = the next), once.
    pub fn crash_after(&self, n: i64, lost_reply: bool) {
        self.crash.applies.store(n, Ordering::SeqCst);
        self.crash.lost_reply.store(lost_reply, Ordering::SeqCst);
        self.crash.armed.store(true, Ordering::SeqCst);
    }
}
impl NamespaceStore for Counting {
    fn capabilities(&self) -> StoreCapabilities {
        self.inner.capabilities()
    }
    async fn get(&self, p: &Partition, k: &Key) -> Result<Option<Value>, StoreError> {
        self.tick();
        self.inner.get(p, k).await
    }
    async fn get_many(&self, p: &Partition, k: &[Key]) -> Result<Vec<Option<Value>>, StoreError> {
        self.tick();
        self.inner.get_many(p, k).await
    }
    async fn scan_many(&self, p: &Partition, r: &[RangeScan]) -> Result<Vec<ScanPage>, StoreError> {
        self.tick();
        if matches!(p, Partition::RepoIndex { .. }) {
            self.scans.fetch_add(r.len() as u64, Ordering::SeqCst);
        }
        self.inner.scan_many(p, r).await
    }
    async fn scan(
        &self,
        p: &Partition,
        s: &Key,
        e: &Key,
        a: Option<&Cursor>,
        l: u32,
    ) -> Result<ScanPage, StoreError> {
        self.tick();
        if matches!(p, Partition::RepoIndex { .. }) {
            self.scans.fetch_add(1, Ordering::SeqCst);
        }
        self.inner.scan(p, s, e, a, l).await
    }
    async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        self.tick();
        if self.record.load(Ordering::SeqCst) {
            self.log.lock().unwrap().push((p.clone(), batch.clone()));
        }
        let hook = {
            let mut trigger = self.trigger.lock().unwrap();
            let hit = trigger.as_ref().is_some_and(|(tag, _)| {
                batch.writes.iter().any(|w| {
                    matches!(w, mkit_server::Write::Put(k, _)
                        if k.as_bytes().starts_with(format!("{tag}\0").as_bytes()))
                })
            });
            if hit {
                trigger.take().map(|(_, hook)| hook)
            } else {
                None
            }
        };
        if let Some(hook) = hook {
            hook().await;
        }
        if self.crash.armed.load(Ordering::SeqCst)
            && self.crash.applies.fetch_sub(1, Ordering::SeqCst) == 1
        {
            self.crash.armed.store(false, Ordering::SeqCst);
            if self.crash.lost_reply.load(Ordering::SeqCst) {
                self.inner.apply(p, batch).await?;
            }
            return Err(StoreError::Unavailable("injected crash".into()));
        }
        self.inner.apply(p, batch).await
    }
    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        self.tick();
        self.inner.stats(p).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.inner.probe().await
    }
}

pub struct Windows(pub MemoryBlobStore);
impl PackWindows for Windows {
    fn read<'a>(
        &'a self,
        pack: &'a Hash,
        offset: u64,
        length: u64,
        etag: Option<&'a str>,
    ) -> BoxFuture<'a, Result<Window, WindowError>> {
        Box::pin(async move { BlobWindows(&self.0).read(pack, offset, length, etag).await })
    }
}

pub type Pipeline =
    mkit_server::pipeline::Pipeline<MemoryBlobStore, Counting, mkit_server::pipeline::Hooks>;

pub fn signed_commit(tree: Hash, parents: Vec<Hash>, seed: u8, message: &[u8]) -> (Object, Hash) {
    let key = KeyPair::from_seed([seed; 32]);
    let mut commit = Commit::new_unannotated(
        tree,
        parents,
        Identity::ed25519(key.public.0),
        key.public.0,
        message.to_vec(),
        42,
        [0; 64],
    );
    commit.signature = sign_commit(&commit, &key).unwrap().0;
    let commit = Object::Commit(commit);
    let id = commit.id().unwrap();
    (commit, id)
}

pub fn blob(tag: u32, size: usize) -> (Hash, Vec<u8>) {
    let mut data = tag.to_be_bytes().to_vec();
    data.extend((0..size).map(|i| u8::try_from(i % 251).unwrap()));
    let object = Object::Blob(Blob { data });
    (object.id().unwrap(), serialize(&object).unwrap())
}

/// A pack of `files` blobs, a tree naming them and a commit on it
/// (`parents` empty for a root). Returns the pack bytes, head and tree.
pub fn tree_pack(
    files: u32,
    size: usize,
    base: u32,
    parents: Vec<Hash>,
    message: &[u8],
) -> (Vec<u8>, Hash, Hash) {
    tree_pack_extra(files, 0, size, base, parents, message)
}

/// [`tree_pack`] plus `extra` blobs the tree does not name (surplus entries).
pub fn tree_pack_extra(
    files: u32,
    extra: u32,
    size: usize,
    base: u32,
    parents: Vec<Hash>,
    message: &[u8],
) -> (Vec<u8>, Hash, Hash) {
    let mut writer = PackWriter::new_raw_only();
    let mut entries = Vec::new();
    for n in 0..extra {
        let (id, raw) = blob(base + 5_000_000 + n, size);
        writer.push_raw(id, &raw).unwrap();
    }
    for n in 0..files {
        let (id, raw) = blob(base + n, size);
        writer.push_raw(id, &raw).unwrap();
        entries.push(TreeEntry {
            name: format!("f{n:06}").into_bytes(),
            mode: EntryMode::Blob,
            object_hash: id,
        });
    }
    let tree = Object::Tree(Tree { entries });
    let tree_id = tree.id().unwrap();
    writer
        .push_raw(tree_id, &serialize(&tree).unwrap())
        .unwrap();
    let (commit, head) = signed_commit(tree_id, parents, 7, message);
    writer.push_raw(head, &serialize(&commit).unwrap()).unwrap();
    (writer.finish().unwrap(), head, tree_id)
}

pub struct Source {
    pub clock: Arc<ManualClock>,
    pub store: Counting,
    pub blobs: MemoryBlobStore,
    pub pipe: Arc<Pipeline>,
    pub repo: RepoId,
    pub namespace: mkit_core::repo_identity::Namespace,
    pub shards: Arc<dyn ShardMap>,
    pub cfg: IndexedConfig,
    pub head: Hash,
    pub packmap: Hash,
    pub pack: Hash,
    pub tree: Hash,
    pub nonce: u32,
    pub name: String,
}

impl Source {
    pub fn config(
        namespace: mkit_core::repo_identity::Namespace,
    ) -> mkit_server::pipeline::PipelineConfig {
        let mut cfg = mkit_server::pipeline::PipelineConfig::new(
            mkit_server::Addressing::Multi(
                mkit_server::MultiAddressing::new().with_namespace_policy(
                    mkit_server::policy::NamespacePolicy::Allowlist([namespace].into()),
                ),
            ),
            mkit_server::pipeline::AuthMode::AuthV2(
                mkit_server::auth_v2::AuthV2Config::new(AUDIENCE, "fork-test").unwrap(),
            ),
            mkit_server::upload::UploadLimits::new(1 << 30, 64),
        );
        cfg.begin_upload_threshold_bytes = 0;
        cfg.write_policy = mkit_server::policy::WritePolicy::Owner;
        cfg.sharding = mkit_server::pipeline::Sharding::D34;
        cfg.indexed = Some(IndexedConfig::scheduled(1 << 30));
        cfg.ticket_keys = Some(
            mkit_server::upload::token::TicketKeys::new(vec![("test".into(), [7; 32])]).unwrap(),
        );
        cfg
    }

    /// Publish a repository of `files` blobs on `refs/heads/main`.
    pub async fn build(name: &str, files: u32) -> Self {
        Self::build_with(name, files, |cfg| cfg).await
    }

    pub async fn build_with(
        name: &str,
        files: u32,
        tweak: impl FnOnce(
            mkit_server::pipeline::PipelineConfig,
        ) -> mkit_server::pipeline::PipelineConfig,
    ) -> Self {
        Self::build_full(name, files, 0, tweak).await
    }

    pub async fn build_full(
        name: &str,
        files: u32,
        extra: u32,
        tweak: impl FnOnce(
            mkit_server::pipeline::PipelineConfig,
        ) -> mkit_server::pipeline::PipelineConfig,
    ) -> Self {
        Self::build_policy(name, files, extra, false, tweak).await
    }

    /// With `policy`, an inspection-style publication policy runs the
    /// canonical publication walk even when `takedown_denial` is off.
    pub async fn build_policy(
        name: &str,
        files: u32,
        extra: u32,
        policy: bool,
        tweak: impl FnOnce(
            mkit_server::pipeline::PipelineConfig,
        ) -> mkit_server::pipeline::PipelineConfig,
    ) -> Self {
        let clock = Arc::new(ManualClock::new(1_700_000_000_000));
        let store = Counting::new(clock.clone());
        let blobs = MemoryBlobStore::default();
        let owner = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let namespace =
            mkit_core::repo_identity::Namespace::Ed25519(*owner.verifying_key().as_bytes());
        let repo = RepoId {
            namespace: NamespaceKey::from_namespace(&namespace),
            name: RepoName::new(name).unwrap(),
        };
        let config = tweak(Self::config(namespace));
        let cfg = config.indexed.unwrap_or(IndexedConfig::scheduled(1 << 30));
        let pipe = Pipeline::new(
            blobs.clone(),
            store.clone(),
            mkit_server::pipeline::Hooks::new(),
            config,
            clock.clone(),
            Arc::new(mkit_server::telemetry::NoopMetrics),
        )
        .unwrap();
        let pipe = if policy {
            pipe.with_publication_policy(Arc::new(AllowAll)).unwrap()
        } else {
            pipe
        };
        let (bytes, head, tree) = tree_pack_extra(files, extra, 8, 0, Vec::new(), b"head");
        let pack = hash(&bytes);
        let mut source = Self {
            clock,
            store,
            blobs,
            pipe: Arc::new(pipe),
            repo,
            namespace,
            shards: Arc::new(D34Shards),
            cfg,
            head,
            packmap: [0; 32],
            pack,
            tree,
            nonce: 1,
            name: name.to_owned(),
        };
        source.packmap = source.push(bytes, head, None, &[pack]).await;
        source
    }

    /// The same deployment, addressed as another repository of the namespace.
    pub fn at(&self, name: &str) -> Self {
        Self {
            clock: self.clock.clone(),
            store: self.store.clone(),
            blobs: self.blobs.clone(),
            pipe: self.pipe.clone(),
            repo: RepoId {
                namespace: self.repo.namespace.clone(),
                name: RepoName::new(name).unwrap(),
            },
            namespace: self.namespace,
            shards: self.shards.clone(),
            cfg: self.cfg,
            head: [0; 32],
            packmap: [0; 32],
            pack: [0; 32],
            tree: [0; 32],
            nonce: self.nonce + 1_000,
            name: name.to_owned(),
        }
    }

    pub fn next_nonce(&mut self) -> u32 {
        self.nonce += 1;
        self.nonce
    }

    /// Push `bytes` (a pack whose commit is `head`) plus a packmap node on
    /// top of `prev`, advance `refs/heads/main` and drive the deployment's
    /// timers until the head is published. Returns the new packmap id.
    pub async fn push(
        &mut self,
        bytes: Vec<u8>,
        head: Hash,
        prev: Option<Hash>,
        packs: &[Hash],
    ) -> Hash {
        self.push_to("refs/heads/main", bytes, head, prev, packs, true)
            .await
    }

    pub async fn push_to(
        &mut self,
        branch: &str,
        bytes: Vec<u8>,
        head: Hash,
        prev: Option<Hash>,
        packs: &[Hash],
        first: bool,
    ) -> Hash {
        self.try_push_to(branch, bytes, head, prev, packs, first)
            .await
            .unwrap()
    }

    /// [`Self::push`], answering the refusal's public message instead of panicking.
    pub async fn try_push(
        &mut self,
        bytes: Vec<u8>,
        head: Hash,
        prev: Option<Hash>,
        packs: &[Hash],
    ) -> Result<Hash, String> {
        self.try_push_to("refs/heads/main", bytes, head, prev, packs, true)
            .await
    }

    pub async fn try_push_to(
        &mut self,
        branch: &str,
        bytes: Vec<u8>,
        head: Hash,
        prev: Option<Hash>,
        packs: &[Hash],
        first: bool,
    ) -> Result<Hash, String> {
        let pack = hash(&bytes);
        let packmap_bytes = mkit_core::transfer::encode_packlist(prev, packs).unwrap();
        let map = hash(&packmap_bytes);
        let n1 = self.next_nonce();
        let n2 = self.next_nonce();
        let tickets = vec![
            self.upload(bytes, n1, branch).await,
            self.upload(packmap_bytes, n2, branch).await,
        ];
        let name = branch.strip_prefix("refs/heads/").unwrap().to_owned();
        let map_ref = format!("refs/mkit/packmap/{name}");
        let current = self.published(branch).await;
        let condition = |id: Option<Hash>| match id {
            None => mkit_core::refs::RefWriteCondition::Missing,
            Some(id) => mkit_core::refs::RefWriteCondition::Match(id),
        };
        let update = |name: &str, cond, id| mkit_server::RefUpdate {
            name: name.into(),
            condition: cond,
            new: Some(id),
        };
        let _ = first;
        let (cur_head, cur_map) = current.unwrap_or((None, None));
        let n = self.next_nonce();
        let auth = self.authenticate(mkit_server::Procedure::AdvanceRefs, n);
        let first_try = self
            .pipe
            .advance_refs_with_tickets(
                &auth,
                update(branch, condition(cur_head), head),
                update(&map_ref, condition(cur_map), map),
                tickets.clone(),
            )
            .await;
        assert!(
            first_try
                .as_ref()
                .is_err_and(|e| e.public_message() == "pack verification pending"),
            "scheduled verification answers pending first: {first_try:?}"
        );
        let registry = self.registry();
        let source = self.shards.ref_shard(&self.repo, branch);
        let _ = pack;
        for _ in 0..4_096 {
            let now = u64::try_from(self.clock.now_ms()).unwrap();
            let report = run_due(
                &self.store,
                &source,
                &registry,
                self.clock.as_ref(),
                now,
                &TickBudget::default(),
            )
            .await
            .unwrap();
            let n = self.next_nonce();
            let auth = self.authenticate(mkit_server::Procedure::AdvanceRefs, n);
            match self
                .pipe
                .advance_refs_with_tickets(
                    &auth,
                    update(branch, condition(cur_head), head),
                    update(&map_ref, condition(cur_map), map),
                    tickets.clone(),
                )
                .await
            {
                Ok(_) => break,
                Err(e) if e.public_message() == "pack verification pending" => {}
                Err(e) => return Err(e.public_message().to_owned()),
            }
            let next = report
                .next_wake_ms
                .unwrap_or(now + 1_000)
                .max(u64::try_from(self.clock.now_ms()).unwrap() + 1);
            self.clock.set(i64::try_from(next).unwrap());
        }
        for _ in 0..64 {
            if self
                .published(branch)
                .await
                .is_some_and(|(h, m)| h == Some(head) && m == Some(map))
            {
                self.drain(&registry, &source).await;
                return Ok(map);
            }
            let now = u64::try_from(self.clock.now_ms()).unwrap();
            let report = run_due(
                &self.store,
                &source,
                &registry,
                self.clock.as_ref(),
                now,
                &TickBudget::default(),
            )
            .await
            .unwrap();
            let next = report
                .next_wake_ms
                .unwrap_or(now + 1_000)
                .max(u64::try_from(self.clock.now_ms()).unwrap() + 1);
            self.clock.set(i64::try_from(next).unwrap());
        }
        Err("push was not published".into())
    }

    /// Run the timers until the relay queue is empty.
    pub async fn drain(&self, registry: &TimerRegistry<'static, Counting>, source: &Partition) {
        let (start, end) = mkit_server::store::adapter_spi::keys::class_range("or");
        for _ in 0..64 {
            let now = u64::try_from(self.clock.now_ms()).unwrap();
            let report = run_due(
                &self.store,
                source,
                registry,
                self.clock.as_ref(),
                now,
                &TickBudget::default(),
            )
            .await
            .unwrap();
            let queued = self
                .store
                .inner
                .scan(source, &start, &end, None, 1)
                .await
                .unwrap()
                .entries;
            if queued.is_empty() && report.fired == 0 {
                return;
            }
            let next = report
                .next_wake_ms
                .unwrap_or(now + 1_000)
                .max(u64::try_from(self.clock.now_ms()).unwrap() + 1);
            self.clock.set(i64::try_from(next).unwrap());
        }
    }

    pub async fn published(&self, branch: &str) -> Option<(Option<Hash>, Option<Hash>)> {
        let p = self.shards.ref_shard(&self.repo, branch);
        let row = mkit_server::store::adapter_spi::publication::read(
            self.store.inner.as_ref(),
            &p,
            &self.repo.name,
            branch,
        )
        .await
        .unwrap();
        row.value.head.map(|_| (row.value.head, row.value.packmap))
    }

    pub fn registry(&self) -> TimerRegistry<'static, Counting> {
        TimerRegistry::new()
            .register(VerifyTimer {
                remote: self.store.clone(),
                blobs: self.blobs.clone(),
                windows: Windows(self.blobs.clone()),
                shards: self.shards.clone(),
                cfg: self.cfg,
                limits: SliceLimits::default(),
                lease: LeaseParams::default(),
                clock: self.clock.clone(),
                metrics: Arc::new(mkit_server::telemetry::NoopMetrics),
                extension: FailClosedExtraction,
            })
            .register(mkit_server::relay::RelayHandler {
                target: self.store.clone(),
                hook: mkit_server::relay::NoHook,
                budget: mkit_server::relay::RelayBudget::default(),
            })
            .register(
                mkit_server::timers::publication_recheck::PublicationRecheck::new(
                    self.store.clone(),
                ),
            )
    }

    /// The deployment's timers plus the fork job's.
    pub fn fork_registry(&self, takedown_denial: bool) -> TimerRegistry<'static, Counting> {
        self.registry().register(mkit_server::fork::ForkTimer {
            store: self.store.clone(),
            shards: self.shards.clone(),
            clock: self.clock.clone(),
            takedown_denial,
            extract_min_bytes: Some(self.cfg.extract_min_bytes),
        })
    }

    pub fn authenticate(
        &self,
        procedure: mkit_server::Procedure,
        nonce: u32,
    ) -> mkit_server::pipeline::Authenticated {
        self.authenticate_body(procedure, nonce, b"fork-test")
    }

    /// [`Self::authenticate`] over a given unary body, as a request to this
    /// repository signed by the namespace owner.
    pub fn authenticate_body(
        &self,
        procedure: mkit_server::Procedure,
        nonce: u32,
        body: &[u8],
    ) -> mkit_server::pipeline::Authenticated {
        use ed25519_dalek::{Signer, SigningKey};
        use mkit_core::{
            hash::{to_hex, to_hex_bytes},
            write_auth::{Context, Operation as SignedOp},
        };
        let owner = SigningKey::from_bytes(&[7; 32]);
        let identity = format!("{}/{}", self.namespace, self.name);
        let digest = to_hex(&hash(body));
        let commitment = format!("body:{digest}");
        let nonce = format!("{nonce:064x}");
        let now = self.clock.now_ms();
        let expires = now + 300_000;
        let envelope = SignedOp {
            context: Context {
                audience: AUDIENCE,
                repository: &identity,
            },
            procedure: procedure.connect_path(),
            commitment: &commitment,
            created_at: now,
            expires_at: expires,
            nonce: &nonce,
        };
        let signature = owner.sign(&envelope.digest().unwrap());
        let headers = [
            ("x-envelope-version", "2".to_owned()),
            ("x-audience", AUDIENCE.to_owned()),
            ("x-repository", identity),
            ("x-public-key", to_hex(owner.verifying_key().as_bytes())),
            ("x-signature", to_hex_bytes(&signature.to_bytes())),
            ("x-content-commitment", commitment),
            ("x-digest", digest),
            ("x-created-at", now.to_string()),
            ("x-expires-at", expires.to_string()),
            ("idempotency-key", nonce),
        ];
        self.pipe
            .authenticate(&mkit_server::pipeline::RequestMeta {
                procedure,
                header: &|name| {
                    headers
                        .iter()
                        .find(|(key, _)| *key == name)
                        .map(|(_, value)| value.clone())
                },
                header_values: None,
                unary_body: Some(body),
                transport_principal: None,
            })
            .unwrap()
    }

    async fn upload(&mut self, bytes: Vec<u8>, nonce: u32, branch: &str) -> Hash {
        use mkit_server::{BeginUploadResult, BlobStore, PackSink};
        let pack = hash(&bytes);
        let auth = self.authenticate(mkit_server::Procedure::BeginUpload, nonce);
        let BeginUploadResult::Ticket { id, .. } = self
            .pipe
            .begin_upload(&auth, branch, &pack, bytes.len() as u64)
            .await
            .unwrap()
        else {
            panic!("expected ticket")
        };
        let mut sink = self
            .blobs
            .begin(BlobKey::pack(pack), bytes.len() as u64)
            .await
            .unwrap();
        sink.write(bytes::Bytes::from(bytes)).await.unwrap();
        sink.commit().await.unwrap();
        let mut marker = b"mkit-upload-marker:v1\0".to_vec();
        marker.extend(id);
        marker.extend(pack);
        let mut sink = self
            .blobs
            .begin(BlobKey::upload_marker(hash(&marker)), marker.len() as u64)
            .await
            .unwrap();
        sink.write(bytes::Bytes::from(marker)).await.unwrap();
        sink.commit().await.unwrap();
        id
    }
}

/// A pack holding only a commit on `tree` (an existing member), with `parents`.
pub fn commit_pack(tree: Hash, parents: Vec<Hash>, message: &[u8]) -> (Vec<u8>, Hash) {
    let mut writer = PackWriter::new_raw_only();
    let (commit, head) = signed_commit(tree, parents, 9, message);
    writer.push_raw(head, &serialize(&commit).unwrap()).unwrap();
    (writer.finish().unwrap(), head)
}

/// A publication policy that clears everything and holds nothing.
pub struct AllowAll;
impl mkit_server::pipeline::clearance::PublicationPolicy for AllowAll {
    fn prepare<'a>(
        &'a self,
        _: &'a mkit_server::Operation,
        value: &'a mkit_server::store::adapter_spi::publication::Pair,
    ) -> BoxFuture<
        'a,
        Result<mkit_server::store::adapter_spi::publication::Advance, mkit_server::ServerError>,
    > {
        use mkit_server::store::adapter_spi::publication::{Advance, Clearance};
        let value = value.clone();
        Box::pin(async move {
            Ok(Advance {
                sequence: 1,
                generation: 0,
                value,
                additions: Vec::new(),
                dependencies: Vec::new(),
                external_bases: Vec::new(),
                obligations: Vec::new(),
                state: Clearance::Cleared,
                operation: [0; 32],
            })
        })
    }
    fn pack_available(&self, _: &RepoId, _: &Hash) -> bool {
        true
    }
}

/// A shard map that does not enumerate its index shards.
pub struct Opaque(pub D34Shards);
impl ShardMap for Opaque {
    fn ref_shard(&self, repo: &RepoId, ref_name: &str) -> Partition {
        self.0.ref_shard(repo, ref_name)
    }
    fn coordinator(&self, ns: &NamespaceKey) -> Partition {
        self.0.coordinator(ns)
    }
    fn ref_index(&self, repo: &RepoId, ref_name: &str) -> Partition {
        self.0.ref_index(repo, ref_name)
    }
    fn ref_index_partitions(&self, repo: &RepoId) -> Vec<Partition> {
        self.0.ref_index_partitions(repo)
    }
    fn membership(&self, repo: &RepoId, pack: &BlobKey) -> Partition {
        self.0.membership(repo, pack)
    }
    fn object_index(&self, repo: &RepoId, object: &Hash) -> Partition {
        self.0.object_index(repo, object)
    }
}
