//! Deterministic call- and round-count probes for signed ref writes —
//! the write-path twin of `read_rounds.rs`.
//!
//! The same paused-clock model applies: every backend call costs
//! [`WARM_MS`] virtual milliseconds, and a partition's first touch costs
//! [`COLD_MS`] in the cold run. The runtime's virtual elapsed is the
//! dependent-round count; each test pins the per-shape totals, so a
//! pipeline change that adds or removes a call moves the numbers here.
//! No production behavior changes: the stores and the probe are
//! test-only wrappers over the memory backends.

use super::super::indexed;
use super::super::scheduled::Ref;
use super::*;
use crate::MaybeSend;
use crate::indexed::IndexedConfig;
use crate::indexed::budget::BlobWindows;
use crate::indexed::job::{FailClosedExtraction, SliceLimits, VerifyTimer};
use crate::relay::{NoHook, RelayBudget, RelayHandler};
use crate::rt::ManualSleep;
use crate::store::read_probe::{self, Config};
use crate::store::{
    BlobBody, BlobMeta, ByteRange, Cursor, MultipartBlobStore, NamespaceStore, PackSink, RangeScan,
    UnsupportedPartSink,
};
use crate::timers::{TickBudget, TimerRegistry, run_due};
use std::collections::BTreeMap;
use std::sync::atomic::AtomicU64;
use std::time::Duration;

/// Warm cost of one backend call, matching `read_rounds::LATENCY`.
const WARM_MS: u64 = 30;
/// First-touch cost of a cold partition.
const COLD_MS: u64 = 300;

/// The write-path stage a recorded call serves, for the per-phase
/// breakdown. Attribution uses the call's partition kind and tag set; a
/// fused call lands in the phase that owns most of its keys.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Phase {
    /// Nonce/replay lookup: `p`/`px` rows read standalone.
    AuthReplay,
    /// Authorizer hook inputs and the coordinator's registry, authority
    /// and visibility rows (`nr`, `rr`, `rl`, `rv`, `rj`, `e`, `ag`,
    /// `lr`, `fc`, `nl`, `rb`, `rn`, quota totals).
    Authorize,
    /// Coordinator lease grant and recovery: `ls`, `lrc` rows and every
    /// coordinator apply batch (lease grant, registration, activation).
    Lease,
    /// The fused read-ahead, snapshot fills, ticket reads, membership,
    /// denial, object-index and verification-state reads feeding a plan.
    PlanSnapshot,
    /// The ref-shard `apply` committing the write: refs, replay outcome,
    /// outbox rows and publication rows inside the one guarded batch.
    GuardedApply,
    /// Published-pair reads of a `source_ref` capture/fence (`pp`, `pr`,
    /// `py`, `pm`, `av`) and relay queue rows (`or`, `rh`, `rs`).
    PublicationRelay,
    /// Outbox sequence/backlog reads outside a guarded batch.
    Outbox,
    /// Outcome and reservation reads/commits outside the apply batch.
    OutcomeSink,
}

/// One backend call the probe observed.
#[derive(Debug)]
struct KvCall {
    /// Store op (`get`, `get_many`, `scan`, `scan_many`, `apply`).
    op: &'static str,
    /// The partition the call addressed.
    partition: Partition,
    /// Read and precondition key-class tags, in call order.
    reads: Vec<&'static str>,
    /// `apply` put/delete key-class tags; empty for reads.
    writes: Vec<&'static str>,
    /// The write stage the call was attributed to.
    phase: Phase,
}

/// Key-class tag: the bytes before the first `0x00` terminator.
fn tag(key: &Key) -> &'static str {
    let tag = key.as_bytes().split(|b| *b == 0).next().unwrap_or_default();
    match tag {
        b"r" => "r",
        b"x" => "x",
        b"p" => "p",
        b"px" => "px",
        b"pp" => "pp",
        b"av" => "av",
        b"pr" => "pr",
        b"py" => "py",
        b"pm" => "pm",
        b"v" => "v",
        b"rk" => "rk",
        b"e" => "e",
        b"el" => "el",
        b"ls" => "ls",
        b"lr" => "lr",
        b"lrc" => "lrc",
        b"ag" => "ag",
        b"fc" => "fc",
        b"nr" => "nr",
        b"rr" => "rr",
        b"rl" => "rl",
        b"rv" => "rv",
        b"rj" => "rj",
        b"nl" => "nl",
        b"rb" => "rb",
        b"rn" => "rn",
        b"q" => "q",
        b"qx" => "qx",
        b"qs" => "qs",
        b"qv" => "qv",
        b"qc" => "qc",
        b"qt" => "qt",
        b"t" => "t",
        b"ti" => "ti",
        b"tc" => "tc",
        b"tu" => "tu",
        b"o" => "o",
        b"oq" => "oq",
        b"os" => "os",
        b"oc" => "oc",
        b"or" => "or",
        b"rh" => "rh",
        b"rs" => "rs",
        b"m" => "m",
        b"vs" => "vs",
        b"vc" => "vc",
        b"i" => "i",
        b"w" => "w",
        b"h" => "h",
        b"g" => "g",
        b"gp" => "gp",
        b"b" => "b",
        b"tb" => "tb",
        b"c" => "c",
        b"ct" => "ct",
        b"sm" => "sm",
        b"am" => "am",
        b"im" => "im",
        b"if" => "if",
        b"iv" => "iv",
        b"ih" => "ih",
        b"ia" => "ia",
        b"ir" => "ir",
        b"bk" => "bk",
        b"cp" => "cp",
        b"cg" => "cg",
        b"fj" => "fj",
        b"fo" => "fo",
        b"ah" => "ah",
        b"an" => "an",
        b"ao" => "ao",
        b"ae" => "ae",
        b"ai" => "ai",
        b"ps" => "ps",
        _ => "?",
    }
}

/// Classify a recorded call into a [`Phase`]. A call whose tag set is
/// dominated by one stage's rows takes that stage; fused reads (the
/// read-ahead carries replay, lease and outbox keys) count as
/// `PlanSnapshot`, the stage they serve.
fn classify(call: &KvCall) -> Phase {
    let reads = &call.reads;
    let writes = &call.writes;
    if call.op == "apply" {
        if writes.iter().any(|t| matches!(*t, "ls" | "lrc"))
            || matches!(call.partition, Partition::Coordinator(_))
        {
            return Phase::Lease;
        }
        if !writes.is_empty() && writes.iter().all(|t| matches!(*t, "o" | "oq" | "p" | "px")) {
            return Phase::OutcomeSink;
        }
        return Phase::GuardedApply;
    }
    if matches!(call.partition, Partition::Coordinator(_)) {
        if reads.iter().any(|t| matches!(*t, "ls" | "lrc")) {
            return Phase::Lease;
        }
        return Phase::Authorize;
    }
    if !reads.is_empty() && reads.iter().all(|t| matches!(*t, "p" | "px")) {
        return Phase::AuthReplay;
    }
    if !reads.is_empty() && reads.iter().all(|t| matches!(*t, "o" | "oq")) {
        return Phase::OutcomeSink;
    }
    if !reads.is_empty()
        && reads
            .iter()
            .all(|t| matches!(*t, "os" | "oc" | "oq" | "or" | "rh" | "rs"))
    {
        return Phase::Outbox;
    }
    if !reads.is_empty() && reads.iter().all(|t| *t == "el") {
        return Phase::Lease;
    }
    if !reads.is_empty()
        && reads
            .iter()
            .all(|t| matches!(*t, "pp" | "av" | "pr" | "py" | "pm"))
    {
        return Phase::PublicationRelay;
    }
    Phase::PlanSnapshot
}

/// A `MemoryKv` that logs every backend call and, when armed, delays each
/// by the virtual latency: warm `latency_ms`, or the cold first-touch
/// cost [`read_probe::partition_latency_ms`] applies to index and content
/// partitions inside `run_cold`.
struct ProbeKv {
    inner: MemoryKv,
    latency_ms: Arc<AtomicU64>,
    calls: Arc<Mutex<Vec<KvCall>>>,
}

/// A [`Phase`]'s trace label, used for the probe's own delay records so
/// `read_probe::summary` reports the same per-phase structure.
fn phase_name(phase: Phase) -> &'static str {
    match phase {
        Phase::AuthReplay => "authenticate_replay",
        Phase::Authorize => "authorize",
        Phase::Lease => "lease",
        Phase::PlanSnapshot => "plan_snapshot",
        Phase::GuardedApply => "guarded_apply",
        Phase::PublicationRelay => "publication_relay",
        Phase::Outbox => "outbox",
        Phase::OutcomeSink => "outcome_sink",
    }
}

impl ProbeKv {
    fn new(inner: MemoryKv) -> Self {
        Self {
            inner,
            latency_ms: Arc::new(AtomicU64::new(0)),
            calls: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Classify one call, wait out its virtual latency — the partition's
    /// cold first touch, else warm — then append it to the log.
    async fn call(&self, mut call: KvCall) {
        call.phase = classify(&call);
        let warm = self.latency_ms.load(Ordering::SeqCst);
        if warm != 0 {
            let ms = read_probe::partition_latency_ms(&call.partition, warm);
            read_probe::delay(ms, phase_name(call.phase)).await;
        }
        self.calls.lock().unwrap().push(call);
    }

    fn observed(op: &'static str, p: &Partition, keys: &[Key]) -> KvCall {
        KvCall {
            op,
            partition: p.clone(),
            reads: keys.iter().map(tag).collect(),
            writes: Vec::new(),
            phase: Phase::PlanSnapshot,
        }
    }

    fn observed_apply(p: &Partition, batch: &Batch) -> KvCall {
        KvCall {
            op: "apply",
            partition: p.clone(),
            reads: batch
                .preconditions
                .iter()
                .filter_map(|pre| match pre {
                    Precondition::Absent(k)
                    | Precondition::Present(k)
                    | Precondition::Equals(k, _) => Some(tag(k)),
                    Precondition::NotAfter(_) => None,
                })
                .collect(),
            writes: batch
                .writes
                .iter()
                .map(|write| match write {
                    Write::Put(k, _) | Write::Delete(k) | Write::Increment(k) => tag(k),
                })
                .collect(),
            phase: Phase::PlanSnapshot,
        }
    }
}

impl NamespaceStore for ProbeKv {
    fn capabilities(&self) -> StoreCapabilities {
        self.inner.capabilities()
    }

    async fn get(&self, p: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
        self.call(Self::observed("get", p, std::slice::from_ref(key)))
            .await;
        self.inner.get(p, key).await
    }

    async fn get_many(
        &self,
        p: &Partition,
        keys: &[Key],
    ) -> Result<Vec<Option<Value>>, StoreError> {
        self.call(Self::observed("get_many", p, keys)).await;
        self.inner.get_many(p, keys).await
    }

    async fn scan(
        &self,
        p: &Partition,
        start: &Key,
        end: &Key,
        after: Option<&Cursor>,
        limit: u32,
    ) -> Result<ScanPage, StoreError> {
        self.call(Self::observed("scan", p, std::slice::from_ref(start)))
            .await;
        self.inner.scan(p, start, end, after, limit).await
    }

    async fn scan_many(
        &self,
        p: &Partition,
        ranges: &[RangeScan],
    ) -> Result<Vec<ScanPage>, StoreError> {
        let keys: Vec<Key> = ranges.iter().map(|r| r.start.clone()).collect();
        self.call(Self::observed("scan_many", p, &keys)).await;
        self.inner.scan_many(p, ranges).await
    }

    async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        self.call(Self::observed_apply(p, &batch)).await;
        self.inner.apply(p, batch).await
    }

    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        self.inner.stats(p).await
    }

    async fn probe(&self) -> Result<(), StoreError> {
        self.inner.probe().await
    }
}

/// Shared delay and call log for a `ProbeBlobs` and the sinks it hands
/// out. The blob store counts as one cold domain.
#[derive(Clone, Default)]
struct BlobProbe {
    latency_ms: Arc<AtomicU64>,
    cold_ms: Arc<AtomicU64>,
    touched: Arc<AtomicBool>,
    calls: Arc<Mutex<Vec<(&'static str, BlobKey)>>>,
}

impl BlobProbe {
    /// Record the call always — like `ProbeKv` — and wait out its
    /// virtual latency when the model is armed.
    async fn call(&self, op: &'static str, key: BlobKey) {
        let warm = self.latency_ms.load(Ordering::SeqCst);
        if warm != 0 {
            let cold = self.cold_ms.load(Ordering::SeqCst);
            let ms = if cold != 0 && !self.touched.swap(true, Ordering::SeqCst) {
                cold
            } else {
                warm
            };
            read_probe::delay(ms, "blob").await;
        }
        self.calls.lock().unwrap().push((op, key));
    }
}

/// A `MemoryBlobStore` that logs and delays every blob op the same way.
#[derive(Clone)]
struct ProbeBlobs {
    inner: MemoryBlobStore,
    probe: BlobProbe,
}

/// The upload sink a `ProbeBlobs` hands out; `write`, `commit` and
/// `abort` cost a call each, like a real multipart backend's RPCs.
struct ProbeSink {
    inner: <MemoryBlobStore as BlobStore>::Sink,
    probe: BlobProbe,
    key: BlobKey,
}

impl PackSink for ProbeSink {
    async fn write(&mut self, chunk: Bytes) -> Result<(), StoreError> {
        self.probe.call("sink_write", self.key).await;
        self.inner.write(chunk).await
    }
    async fn commit(self) -> Result<crate::store::CommitOutcome, StoreError> {
        self.probe.call("sink_commit", self.key).await;
        self.inner.commit().await
    }
    async fn abort(self) {
        self.probe.call("sink_abort", self.key).await;
        self.inner.abort().await;
    }
}

impl BlobStore for ProbeBlobs {
    type Sink = ProbeSink;

    async fn begin(&self, key: BlobKey, len: u64) -> Result<Self::Sink, StoreError> {
        self.probe.call("begin", key).await;
        Ok(ProbeSink {
            inner: self.inner.begin(key, len).await?,
            probe: self.probe.clone(),
            key,
        })
    }

    async fn get(
        &self,
        key: &BlobKey,
        range: Option<ByteRange>,
    ) -> Result<Option<BlobBody>, StoreError> {
        self.probe.call("blob_get", *key).await;
        self.inner.get(key, range).await
    }

    async fn head(&self, key: &BlobKey) -> Result<Option<BlobMeta>, StoreError> {
        self.probe.call("blob_head", *key).await;
        self.inner.head(key).await
    }

    async fn probe(&self) -> Result<(), StoreError> {
        self.inner.probe().await
    }

    async fn delete(&self, key: &BlobKey) -> Result<bool, StoreError> {
        self.probe.call("blob_delete", *key).await;
        self.inner.delete(key).await
    }
}

impl MultipartBlobStore for ProbeBlobs {
    type PartSink = UnsupportedPartSink;
    const MAX_PARTS: u32 = u32::MAX;
}

/// The PW1 hold's sleeper: the hold's 100 ms poll sleeps wait on `fire`,
/// while the outer `with_timeout` arm stays pending so a fired poll can
/// never race the retried write to `Elapsed`. Mirrors `pending_hold`'s
/// `LateReadySleep` discrimination.
struct HoldSleep(ManualSleep);

impl crate::rt::Sleep for HoldSleep {
    fn sleep(&self, duration: Duration) -> crate::rt::BoxFuture<'static, ()> {
        if duration <= Duration::from_millis(100) {
            self.0.sleep(duration)
        } else {
            Box::pin(futures::future::pending())
        }
    }
}

/// The probe fixture: a pipeline over the instrumented stores.
struct PFx<H: HookSet = Hooks> {
    pipe: Pipeline<ProbeBlobs, ProbeKv, H>,
    clock: Arc<ManualClock>,
    metrics: Arc<SpyMetrics>,
    owner: SigningKey,
    identity: String,
    numbers: AtomicU32,
    /// The PW1 hold's manual sleep, when the fixture enables it.
    sleeper: Option<Arc<HoldSleep>>,
}

fn probe_tweaked<H: HookSet>(
    sharding: Sharding,
    denial: bool,
    indexed: IndexedConfig,
    hooks: H,
    hold: Option<Duration>,
) -> PFx<H> {
    let owner = key(7);
    let namespace = Namespace::Ed25519(*owner.verifying_key().as_bytes());
    let identity = format!("{namespace}/{REPO}");
    let mut config = cfg(authv2());
    config.addressing = Addressing::Multi(
        MultiAddressing::new()
            .with_namespace_policy(NamespacePolicy::Allowlist([namespace].into())),
    );
    config.write_policy = WritePolicy::Owner;
    config.sharding = sharding;
    config.takedown_denial = denial;
    config.ticket_keys =
        Some(crate::upload::token::TicketKeys::new(vec![("test".into(), [7; 32])]).unwrap());
    config.indexed = Some(IndexedConfig {
        extract_min_bytes: EXTRACT_MIN,
        ..indexed
    });
    let clock = clock();
    let metrics = Arc::new(SpyMetrics::default());
    // A zero hold disables the hold outright (`then_some` on `is_zero`),
    // so only a nonzero hold gets a manual sleeper.
    let sleeper = hold
        .filter(|d| !d.is_zero())
        .map(|_| Arc::new(HoldSleep(ManualSleep::new())));
    let mut pipe = Pipeline::new(
        ProbeBlobs {
            inner: MemoryBlobStore::default(),
            probe: BlobProbe::default(),
        },
        ProbeKv::new(store(&clock)),
        hooks,
        config,
        clock.clone(),
        metrics.clone(),
    )
    .unwrap();
    if let Some(hold) = hold.filter(|d| !d.is_zero()) {
        pipe = pipe.with_pending_advance_hold(
            hold,
            sleeper.clone().unwrap(),
            ms(clock.now_ms()) + 60_000,
        );
    }
    PFx {
        pipe,
        clock,
        metrics,
        owner,
        identity,
        numbers: AtomicU32::new(1000),
        sleeper,
    }
}

impl<H: HookSet> PFx<H> {
    fn number(&self) -> u32 {
        self.numbers.fetch_add(1, Ordering::SeqCst)
    }

    fn auth_req(&self, request: &Req) -> Authenticated {
        let lookup = |name: &str| {
            request
                .headers
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, v)| v.clone())
        };
        self.pipe
            .authenticate(&RequestMeta {
                procedure: request.procedure,
                header: &lookup,
                header_values: None,
                unary_body: Some(&request.body),
                transport_principal: None,
            })
            .unwrap()
    }

    fn auth(&self, procedure: Procedure) -> Authenticated {
        self.auth_req(&indexed::signed(
            &self.owner,
            &self.identity,
            procedure,
            self.number(),
        ))
    }

    fn drain_kv(&self) -> Vec<KvCall> {
        std::mem::take(&mut *self.pipe.meta.calls.lock().unwrap())
    }

    fn drain_blobs(&self) -> Vec<(&'static str, BlobKey)> {
        std::mem::take(&mut *self.pipe.blobs.probe.calls.lock().unwrap())
    }
}

/// Seed blob state for `pack` as a committed pack plus upload marker for
/// `ticket`, without a session: the seed path `indexed::upload` uses.
fn seed_pack_blob<H: HookSet>(fx: &PFx<H>, pack: &[u8], ticket: Hash) {
    let pack_id = hash(pack);
    block_on(async {
        let mut sink = fx
            .pipe
            .blobs
            .inner
            .begin(BlobKey::pack(pack_id), pack.len() as u64)
            .await
            .unwrap();
        sink.write(Bytes::copy_from_slice(pack)).await.unwrap();
        sink.commit().await.unwrap();
        write_upload_marker(
            &fx.pipe.blobs.inner,
            &ticket,
            &pack_id,
            fx.pipe.clock.as_ref(),
            fx.pipe.metrics.as_ref(),
        )
        .await
        .unwrap();
    });
}

/// One pack holding a two-commit history: root `head` and its child
/// `head2`. A CAS move `head`→`head2` stays inside the ref's own packlist
/// closure, so the shape is admissible under takedown denial too.
fn pack_chain() -> (Vec<u8>, Hash, Hash) {
    let (tree, commit, head) = indexed::signed_objects();
    let tree_id = tree.id().unwrap();
    let signer = KeyPair::from_seed([9; 32]);
    let mut child = Commit::new_unannotated(
        tree_id,
        vec![head],
        Identity::ed25519(signer.public.0),
        signer.public.0,
        b"indexed-two".to_vec(),
        43,
        [0; 64],
    );
    child.signature = sign_commit(&child, &signer).unwrap().0;
    let child = Object::Commit(child);
    let head2 = child.id().unwrap();
    let mut writer = PackWriter::new_raw_only();
    writer
        .push_raw(tree_id, &serialize(&tree).unwrap())
        .unwrap();
    writer.push_raw(head, &serialize(&commit).unwrap()).unwrap();
    writer.push_raw(head2, &serialize(&child).unwrap()).unwrap();
    (writer.finish().unwrap(), head, head2)
}

/// A second signed history: `indexed::pack()` with a different message,
/// so its head is a distinct commit the membership index can resolve.
fn pack_two() -> (Vec<u8>, Hash) {
    let tree = Object::Tree(Tree {
        entries: Vec::new(),
    });
    let tree_id = tree.id().unwrap();
    let signer = KeyPair::from_seed([9; 32]);
    let mut commit = Commit::new_unannotated(
        tree_id,
        Vec::new(),
        Identity::ed25519(signer.public.0),
        signer.public.0,
        b"indexed-two".to_vec(),
        42,
        [0; 64],
    );
    commit.signature = sign_commit(&commit, &signer).unwrap().0;
    let commit = Object::Commit(commit);
    let head = commit.id().unwrap();
    let mut writer = PackWriter::new_raw_only();
    writer
        .push_raw(tree_id, &serialize(&tree).unwrap())
        .unwrap();
    writer.push_raw(head, &serialize(&commit).unwrap()).unwrap();
    (writer.finish().unwrap(), head)
}

/// A signed `UploadPack` stream auth: the `pack:` commitment header the
/// upload session's auth-v2 check requires (`Req::committed`'s shape).
fn stream_signed(owner: &SigningKey, identity: &str, pack: &[u8], number: u32) -> Req {
    let commitment = format!("pack:{}:{}", to_hex(&hash(pack)), pack.len());
    let nonce = nonce(number);
    let envelope = SignedOp {
        context: AuthContext {
            audience: AUDIENCE,
            repository: identity,
        },
        procedure: Procedure::UploadPack.connect_path(),
        commitment: &commitment,
        created_at: T0,
        expires_at: T0 + 300_000,
        nonce: &nonce,
    };
    let signature = owner.sign(&envelope.digest().unwrap());
    let mut request = Req::unsigned(Procedure::UploadPack);
    for (name, value) in [
        ("x-envelope-version", "2".to_owned()),
        ("x-audience", AUDIENCE.to_owned()),
        ("x-repository", identity.to_owned()),
        ("x-public-key", to_hex(owner.verifying_key().as_bytes())),
        ("x-signature", to_hex_bytes(&signature.to_bytes())),
        ("x-content-commitment", commitment),
        ("x-created-at", T0.to_string()),
        ("x-expires-at", (T0 + 300_000).to_string()),
        ("idempotency-key", nonce),
    ] {
        request = request.header(name, &value);
    }
    request
}

/// `BeginUpload` for `bytes`: the ticket id and bearer token a ticketed
/// `UploadPack` session or an advance consumes.
async fn begin_ticket<H: HookSet>(fx: &PFx<H>, head_ref: &str, bytes: &[u8]) -> (Hash, Vec<u8>) {
    let a = fx.auth(Procedure::BeginUpload);
    let BeginUploadResult::Ticket { id, token, .. } = fx
        .pipe
        .begin_upload(&a, head_ref, &hash(bytes), bytes.len() as u64)
        .await
        .unwrap()
    else {
        panic!("expected an upload ticket")
    };
    (id, token)
}

/// Seed `head_ref` + its packmap through a real ticketed advance,
/// mirroring `Fx::push_pack`'s denial-aware pair. Returns the packmap
/// target the advance committed.
fn seed_ref<H: HookSet>(fx: &PFx<H>, head_ref: &str, pack: &[u8], head: Hash) -> Hash {
    let pack_id = hash(pack);
    let map_ref = mkit_attest::grant::head_packmap(head_ref).unwrap();
    let (ticket, _) = block_on(begin_ticket(fx, head_ref, pack));
    let mut tickets = vec![ticket];
    let (map, map_id) = if fx.pipe.cfg.takedown_denial {
        let map = mkit_core::transfer::encode_packlist(None, &[pack_id]).unwrap();
        let (ticket, _) = block_on(begin_ticket(fx, head_ref, &map));
        tickets.push(ticket);
        (Some(map.clone()), hash(&map))
    } else {
        (None, pack_id)
    };
    seed_pack_blob(fx, pack, tickets[0]);
    if let Some(map) = &map {
        seed_pack_blob(fx, map, tickets[1]);
    }
    let outcome = block_on(fx.pipe.advance_refs_with_tickets(
        &fx.auth(Procedure::AdvanceRefs),
        upd(head_ref, Missing, head),
        upd(&map_ref, Missing, map_id),
        tickets,
    ));
    assert_eq!(outcome.unwrap(), AdvanceOutcome::Committed);
    map_id
}

/// Deliver the membership/publication rows a commit queued on the outbox
/// relay: in D34 `m` and `pm` land on the repo-index partition only when
/// the relay timer runs on the source ref partition.
async fn settle_relay<H: HookSet>(fx: &PFx<H>, sources: &[Partition]) {
    for source in sources {
        settle(fx, source).await;
    }
}

/// The seeded repository state the write shapes run against.
struct Seeded {
    /// `refs/heads/main`'s committed target.
    head: Hash,
    /// `head`'s child commit, packed beside it: `main`'s move target.
    head2: Hash,
    /// `main`'s committed packmap target — the packlist covering both
    /// commits — reused as `feat`'s packmap by `AdvanceCreate`.
    map_a: Hash,
}

fn seed_state<H: HookSet>(fx: &PFx<H>) -> Seeded {
    let (pack_a, head, head2) = pack_chain();
    let (pack_b, head3) = pack_two();
    let map_a = seed_ref(fx, HEAD, &pack_a, head);
    seed_ref(fx, "refs/heads/two", &pack_b, head3);
    let repo = RepoId {
        namespace: NamespaceKey::from_namespace(&Namespace::Ed25519(
            *fx.owner.verifying_key().as_bytes(),
        )),
        name: RepoName::new(REPO).unwrap(),
    };
    block_on(settle_relay(
        fx,
        &[
            fx.pipe.shards.ref_shard(&repo, HEAD),
            fx.pipe.shards.ref_shard(&repo, "refs/heads/two"),
        ],
    ));
    Seeded { head, head2, map_a }
}

/// One measured segment's totals.
struct Report {
    /// Ordered KV call log.
    calls: Vec<KvCall>,
    /// Ordered blob-call log.
    blobs: Vec<(&'static str, BlobKey)>,
    /// Paused-clock elapsed milliseconds for the segment.
    virtual_ms: f64,
    /// Per-phase KV call counts.
    phases: BTreeMap<Phase, u32>,
    /// Per-phase union waits and peak fan-in from the delay trace:
    /// `{phase: {rpcs, wait_ms, rounds, peak}}`.
    waits: serde_json::Value,
}

impl Report {
    /// Dependent rounds: virtual wall elapsed at the warm unit. Under the
    /// paused runtime every overlapping delay coalesces, so
    /// `virtual_ms / WARM_MS` is the critical path through the dependent
    /// chain; cold runs mix in [`COLD_MS`] first touches.
    #[allow(clippy::cast_precision_loss)] // The unit fits in f64 mantissa.
    fn rounds(&self) -> f64 {
        self.virtual_ms / WARM_MS as f64
    }
    fn kv(&self) -> usize {
        self.calls.len()
    }
    fn blob_calls(&self) -> usize {
        self.blobs.len()
    }
}

/// Run `f` under the paused clock with the latency model armed, and
/// collect the segment's call log and elapsed virtual time. `cold`
/// charges [`COLD_MS`] for the first touch of each index or content
/// partition and of the blob domain.
fn probe<H, F>(fx: &PFx<H>, cold: bool, f: F) -> (F::Output, Report)
where
    H: HookSet,
    F: Future,
{
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .start_paused(true)
        .build()
        .unwrap();
    fx.drain_kv();
    fx.drain_blobs();
    fx.pipe.meta.latency_ms.store(WARM_MS, Ordering::SeqCst);
    let blob = &fx.pipe.blobs.probe;
    blob.touched.store(false, Ordering::SeqCst);
    blob.latency_ms.store(WARM_MS, Ordering::SeqCst);
    blob.cold_ms
        .store(if cold { COLD_MS } else { 0 }, Ordering::SeqCst);
    let trace = Arc::new(Mutex::new(Vec::new()));
    let start = runtime.block_on(async { tokio::time::Instant::now() });
    let scoped = read_probe::run(
        Config {
            concurrency: crate::store::read_io::PARALLELISM,
            trace: trace.clone(),
        },
        f,
    );
    let out = runtime.block_on(async {
        if cold {
            read_probe::run_cold(COLD_MS, &[], scoped).await
        } else {
            scoped.await
        }
    });
    let virtual_ms = runtime
        .block_on(async { tokio::time::Instant::now() - start })
        .as_secs_f64()
        * 1000.0;
    fx.pipe.meta.latency_ms.store(0, Ordering::SeqCst);
    blob.latency_ms.store(0, Ordering::SeqCst);
    blob.cold_ms.store(0, Ordering::SeqCst);
    let events = std::mem::take(&mut *trace.lock().unwrap());
    let calls = fx.drain_kv();
    let mut phases: BTreeMap<Phase, u32> = BTreeMap::new();
    for call in &calls {
        *phases.entry(call.phase).or_default() += 1;
    }
    (
        out,
        Report {
            calls,
            blobs: fx.drain_blobs(),
            virtual_ms,
            phases,
            waits: read_probe::summary(&events),
        },
    )
}

/// The single-ref and paired-ref write shapes the lane pins.
#[derive(Clone, Copy, Debug)]
enum WOp {
    /// `UpdateRef` Match CAS on the seeded `refs/heads/main`.
    UpdateMatch,
    /// `UpdateRef` Missing, creating `refs/heads/topic`.
    UpdateCreate,
    /// Ticketless `AdvanceRefs` creating `refs/heads/feat` + packmap.
    AdvanceCreate,
    /// `AdvanceRefs` from the published `refs/heads/main` (CR1).
    AdvanceSource,
    /// `UpdateRef` Missing creating `refs/tags/v1`.
    TagCreate,
    /// `UpdateRef` Match + `None`, deleting `refs/heads/main`.
    RefDelete,
}

/// AD1: an admission hook that records the planner's per-ref effects.
struct EffectAdmission {
    effects: Arc<Mutex<Vec<RefEffect>>>,
}

impl Admission for EffectAdmission {
    fn admit(
        &self,
        input: &AdmissionInput<'_>,
    ) -> impl Future<Output = Result<AdmissionDecision, ServerError>> + MaybeSend {
        self.effects
            .lock()
            .unwrap()
            .extend(input.resolved_ref_updates.iter().map(|r| r.effect));
        std::future::ready(Ok(AdmissionDecision::allow(Vec::new())))
    }
}

/// The hooks row for the AD1 matrix variant; `effects` is shared so the
/// test can prove the hook really ran.
fn effect_hooks(
    effects: Arc<Mutex<Vec<RefEffect>>>,
) -> Hooks<OpenAuthorizer, EffectAdmission, NoPreReceive, NoReceipts, NoOutcomes> {
    Hooks {
        authorizer: OpenAuthorizer,
        admission: EffectAdmission { effects },
        pre_receive: NoPreReceive,
        receipts: NoReceipts,
        outcomes: NoOutcomes,
    }
}

/// The signed write path polls deeper than the default test stack
/// allows; measured segments run on a dedicated thread with headroom.
fn big_stack<T: Send>(f: impl FnOnce() -> T + Send) -> T {
    std::thread::scope(|scope| {
        std::thread::Builder::new()
            .stack_size(128 << 20)
            .spawn_scoped(scope, f)
            .unwrap()
            .join()
            .unwrap()
    })
}

/// Measure `op` on a freshly seeded fixture: warm or cold latency model.
fn measured<H: HookSet>(
    sharding: Sharding,
    denial: bool,
    hooks: impl Fn() -> H + Send + Sync,
    op: WOp,
    cold: bool,
) -> (String, Report) {
    big_stack(|| {
        let fx = probe_tweaked(sharding, denial, IndexedConfig::default(), hooks(), None);
        let seeded = seed_state(&fx);
        probe(&fx, cold, run_op(&fx, op, &seeded))
    })
}

fn print_report(result: &str, report: &Report) {
    eprintln!(
        "result: {result} | kv={} blobs={} virtual_ms={:.0} rounds={:.0} phases={:?}",
        report.kv(),
        report.blob_calls(),
        report.virtual_ms,
        report.rounds(),
        report.phases,
    );
    eprintln!("waits: {}", report.waits);
    for (i, call) in report.calls.iter().enumerate() {
        eprintln!(
            "{i:3} {op:9} {kind} {phase:?} reads={reads:?} writes={writes:?}",
            op = call.op,
            kind = call.partition.kind(),
            phase = call.phase,
            reads = call.reads,
            writes = call.writes,
        );
    }
    for (i, (op, key)) in report.blobs.iter().enumerate() {
        eprintln!("blob {i:3} {op:12} {key:?}");
    }
}

/// What one matrix cell must measure: the outcome, exact call counts and
/// modeled wall, and the phase split both runs share.
struct Expect {
    /// `"committed"`, or the server error's public message.
    outcome: &'static str,
    /// KV calls, identical in warm and cold runs.
    kv: usize,
    /// Blob-store calls, identical in warm and cold runs.
    blobs: usize,
    /// Modeled wall at [`WARM_MS`] per call.
    warm_ms: u64,
    /// Modeled wall with [`COLD_MS`] first touches.
    cold_ms: u64,
    /// `(phase, calls)` in `BTreeMap` order.
    phases: &'static [(Phase, u32)],
}

use Phase::{Authorize, GuardedApply, Lease, Outbox, PlanSnapshot, PublicationRelay};

/// Cell order inside each op row: `[Single, D34] × [denial off, on]`.
const SHAPES: [(WOp, [Expect; 4]); 6] = [
    (
        WOp::UpdateMatch,
        [
            Expect {
                outcome: "committed",
                kv: 4,
                blobs: 2,
                warm_ms: 150,
                cold_ms: 420,
                phases: &[(PlanSnapshot, 3), (GuardedApply, 1)],
            },
            Expect {
                outcome: "committed",
                kv: 48,
                blobs: 2,
                warm_ms: 1110,
                cold_ms: 3270,
                phases: &[(PlanSnapshot, 46), (GuardedApply, 2)],
            },
            Expect {
                outcome: "committed",
                kv: 4,
                blobs: 2,
                warm_ms: 150,
                cold_ms: 960,
                phases: &[(PlanSnapshot, 3), (GuardedApply, 1)],
            },
            Expect {
                outcome: "committed",
                kv: 50,
                blobs: 2,
                warm_ms: 1140,
                cold_ms: 4650,
                phases: &[(PlanSnapshot, 46), (GuardedApply, 2), (PublicationRelay, 2)],
            },
        ],
    ),
    (
        WOp::UpdateCreate,
        [
            Expect {
                outcome: "committed",
                kv: 4,
                blobs: 2,
                warm_ms: 150,
                cold_ms: 420,
                phases: &[(PlanSnapshot, 3), (GuardedApply, 1)],
            },
            // Denial: a ticketless create cannot carry a packlist, so the
            // open-closure check (retryable inside the lag window) rejects at plan time — before any apply.
            Expect {
                outcome: "repository membership not yet visible",
                kv: 5,
                blobs: 2,
                warm_ms: 180,
                cold_ms: 990,
                phases: &[(PlanSnapshot, 5)],
            },
            Expect {
                outcome: "committed",
                kv: 7,
                blobs: 2,
                warm_ms: 240,
                cold_ms: 1050,
                phases: &[
                    (Lease, 2),
                    (PlanSnapshot, 3),
                    (GuardedApply, 1),
                    (Outbox, 1),
                ],
            },
            Expect {
                outcome: "repository membership not yet visible",
                kv: 8,
                blobs: 2,
                warm_ms: 270,
                cold_ms: 1620,
                phases: &[(Lease, 2), (PlanSnapshot, 5), (Outbox, 1)],
            },
        ],
    ),
    (
        WOp::AdvanceCreate,
        [
            Expect {
                outcome: "committed",
                kv: 4,
                blobs: 2,
                warm_ms: 150,
                cold_ms: 420,
                phases: &[(PlanSnapshot, 3), (GuardedApply, 1)],
            },
            Expect {
                outcome: "committed",
                kv: 48,
                blobs: 2,
                warm_ms: 1110,
                cold_ms: 3270,
                phases: &[(PlanSnapshot, 46), (GuardedApply, 2)],
            },
            Expect {
                outcome: "committed",
                kv: 7,
                blobs: 2,
                warm_ms: 240,
                cold_ms: 1050,
                phases: &[
                    (Lease, 2),
                    (PlanSnapshot, 3),
                    (GuardedApply, 1),
                    (Outbox, 1),
                ],
            },
            Expect {
                outcome: "committed",
                kv: 52,
                blobs: 10,
                warm_ms: 1350,
                cold_ms: 5400,
                phases: &[
                    (Lease, 4),
                    (PlanSnapshot, 43),
                    (GuardedApply, 1),
                    (PublicationRelay, 2),
                    (Outbox, 2),
                ],
            },
        ],
    ),
    (
        WOp::AdvanceSource,
        [
            Expect {
                outcome: "committed",
                kv: 8,
                blobs: 2,
                warm_ms: 270,
                cold_ms: 540,
                phases: &[(PlanSnapshot, 5), (GuardedApply, 1), (PublicationRelay, 2)],
            },
            Expect {
                outcome: "committed",
                kv: 47,
                blobs: 2,
                warm_ms: 1080,
                cold_ms: 3240,
                phases: &[(PlanSnapshot, 43), (GuardedApply, 2), (PublicationRelay, 2)],
            },
            Expect {
                outcome: "committed",
                kv: 11,
                blobs: 2,
                warm_ms: 360,
                cold_ms: 1170,
                phases: &[
                    (Authorize, 2),
                    (Lease, 2),
                    (PlanSnapshot, 3),
                    (GuardedApply, 1),
                    (PublicationRelay, 2),
                    (Outbox, 1),
                ],
            },
            Expect {
                outcome: "committed",
                kv: 52,
                blobs: 8,
                warm_ms: 1320,
                cold_ms: 4830,
                phases: &[
                    (Authorize, 2),
                    (Lease, 4),
                    (PlanSnapshot, 39),
                    (GuardedApply, 1),
                    (PublicationRelay, 4),
                    (Outbox, 2),
                ],
            },
        ],
    ),
    (
        WOp::TagCreate,
        [
            Expect {
                outcome: "committed",
                kv: 4,
                blobs: 2,
                warm_ms: 150,
                cold_ms: 420,
                phases: &[(PlanSnapshot, 3), (GuardedApply, 1)],
            },
            Expect {
                outcome: "committed",
                kv: 38,
                blobs: 6,
                warm_ms: 870,
                cold_ms: 3300,
                phases: &[(PlanSnapshot, 37), (GuardedApply, 1)],
            },
            Expect {
                outcome: "committed",
                kv: 7,
                blobs: 2,
                warm_ms: 240,
                cold_ms: 1050,
                phases: &[
                    (Lease, 2),
                    (PlanSnapshot, 3),
                    (GuardedApply, 1),
                    (Outbox, 1),
                ],
            },
            Expect {
                outcome: "committed",
                kv: 46,
                blobs: 6,
                warm_ms: 1080,
                cold_ms: 4590,
                phases: &[
                    (Lease, 4),
                    (PlanSnapshot, 37),
                    (GuardedApply, 1),
                    (PublicationRelay, 2),
                    (Outbox, 2),
                ],
            },
        ],
    ),
    (
        WOp::RefDelete,
        [
            Expect {
                outcome: "committed",
                kv: 2,
                blobs: 0,
                warm_ms: 60,
                cold_ms: 60,
                phases: &[(PlanSnapshot, 1), (GuardedApply, 1)],
            },
            Expect {
                outcome: "committed",
                kv: 2,
                blobs: 0,
                warm_ms: 60,
                cold_ms: 60,
                phases: &[(PlanSnapshot, 1), (GuardedApply, 1)],
            },
            Expect {
                outcome: "committed",
                kv: 2,
                blobs: 0,
                warm_ms: 60,
                cold_ms: 60,
                phases: &[(PlanSnapshot, 1), (GuardedApply, 1)],
            },
            Expect {
                outcome: "committed",
                kv: 2,
                blobs: 0,
                warm_ms: 60,
                cold_ms: 60,
                phases: &[(PlanSnapshot, 1), (GuardedApply, 1)],
            },
        ],
    ),
];

/// Check one measured cell against its pin; on mismatch, dump the call
/// trace to stderr and return the delta description for the caller's
/// failure list.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // Virtual ms are small and positive.
fn pin(cell: &str, cold: bool, result: &str, report: &Report, expect: &Expect) -> Option<String> {
    let phases: Vec<(Phase, u32)> = report
        .phases
        .iter()
        .map(|(phase, calls)| (*phase, *calls))
        .collect();
    let ok = result == expect.outcome
        && report.kv() == expect.kv
        && report.blob_calls() == expect.blobs
        && report.virtual_ms.round() as u64 == if cold { expect.cold_ms } else { expect.warm_ms }
        && phases == expect.phases;
    if ok {
        return None;
    }
    print_report(result, report);
    Some(format!(
        "{cell} cold={cold}: expected outcome={} kv={} blobs={} ms={} phases={:?}; got result={result} kv={} blobs={} ms={:.0} phases={phases:?}",
        expect.outcome,
        expect.kv,
        expect.blobs,
        if cold { expect.cold_ms } else { expect.warm_ms },
        expect.phases,
        report.kv(),
        report.blob_calls(),
        report.virtual_ms,
    ))
}

/// Pin every write shape across sharding × denial, under the default
/// hooks and the AD1 effect-recording admission hook (whose counts must
/// match — an in-memory hook adds no backend calls).
#[test]
fn signed_write_shapes_report_rounds() {
    let mut failures = Vec::new();
    for (op, cells) in &SHAPES {
        let effects = Arc::new(Mutex::new(Vec::new()));
        for sharding in [Sharding::Single, Sharding::D34] {
            for denial in [false, true] {
                let expect =
                    &cells[usize::from(sharding == Sharding::D34) * 2 + usize::from(denial)];
                for cold in [false, true] {
                    let cell = format!("{op:?} {sharding:?} denial={denial}");
                    let (result, report) = measured(sharding, denial, Hooks::new, *op, cold);
                    if let Some(mismatch) = pin(&cell, cold, &result, &report, expect) {
                        failures.push(mismatch);
                    }
                    let handle = effects.clone();
                    let (ad_result, ad_report) = measured(
                        sharding,
                        denial,
                        move || effect_hooks(handle.clone()),
                        *op,
                        cold,
                    );
                    if let Some(mismatch) = pin(
                        &format!("{cell} hooks=ad1"),
                        cold,
                        &ad_result,
                        &ad_report,
                        expect,
                    ) {
                        failures.push(mismatch);
                    }
                }
            }
        }
        // An identical-measurement pin is only meaningful if admission ran.
        assert!(
            !effects.lock().unwrap().is_empty(),
            "{op:?}: AD1 hook recorded no effects — admission never ran"
        );
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// `"committed"` for a committed `UpdateRef`, else the server error's
/// public message — what `Expect::outcome` pins.
fn outcome_update(result: Result<UpdateRefResult, ServerError>) -> String {
    match result {
        Ok(UpdateRefResult::Committed) => "committed".to_owned(),
        Ok(other) => format!("{other:?}"),
        Err(error) => error.public_message().to_owned(),
    }
}

/// The same for `AdvanceRefs`.
fn outcome_advance(result: Result<AdvanceOutcome, ServerError>) -> String {
    match result {
        Ok(AdvanceOutcome::Committed) => "committed".to_owned(),
        Ok(other) => format!("{other:?}"),
        Err(error) => error.public_message().to_owned(),
    }
}

async fn run_op<H: HookSet>(fx: &PFx<H>, op: WOp, seeded: &Seeded) -> String {
    let (head, head2) = (seeded.head, seeded.head2);
    match op {
        // The embedder's move: CAS `main` onto the second member commit.
        WOp::UpdateMatch => outcome_update(
            fx.pipe
                .update_ref(
                    &fx.auth(Procedure::UpdateRef),
                    upd(HEAD, Match(head), head2),
                )
                .await,
        ),
        // A fresh branch at a member commit.
        WOp::UpdateCreate => outcome_update(
            fx.pipe
                .update_ref(
                    &fx.auth(Procedure::UpdateRef),
                    upd("refs/heads/topic", Missing, head2),
                )
                .await,
        ),
        // Ticketless branch create: `feat` at `head2` with the packlist
        // covering `main`'s pack (`head2` is `head`'s child inside it).
        WOp::AdvanceCreate => outcome_advance(
            fx.pipe
                .advance_refs(
                    &fx.auth(Procedure::AdvanceRefs),
                    upd("refs/heads/feat", Missing, head2),
                    upd(
                        &mkit_attest::grant::head_packmap("refs/heads/feat").unwrap(),
                        Missing,
                        seeded.map_a,
                    ),
                )
                .await,
        ),
        // CR1: create `copy` from `main`'s published pair.
        WOp::AdvanceSource => outcome_advance(
            fx.pipe
                .advance_refs_from_published(
                    &fx.auth(Procedure::AdvanceRefs),
                    HEAD.to_owned(),
                    "refs/heads/copy".to_owned(),
                    Some(head),
                )
                .await,
        ),
        // A tag at `main`'s commit.
        WOp::TagCreate => outcome_update(
            fx.pipe
                .update_ref(
                    &fx.auth(Procedure::UpdateRef),
                    upd("refs/tags/v1", Missing, head),
                )
                .await,
        ),
        // Delete `main`; each cell's fresh fixture leaves it at `head`.
        WOp::RefDelete => outcome_update(
            fx.pipe
                .update_ref(
                    &fx.auth(Procedure::UpdateRef),
                    RefUpdate {
                        name: HEAD.to_owned(),
                        condition: Match(head),
                        new: None,
                    },
                )
                .await,
        ),
    }
}

/// Run the ref shard's timers until nothing verification-related is due —
/// SP2's tiny-slice settle, on the same timer handlers the pipeline's
/// scheduled tests drive.
async fn settle<H: HookSet>(fx: &PFx<H>, source: &Partition) {
    let handler = VerifyTimer {
        remote: Ref(&fx.pipe.meta),
        blobs: Ref(&fx.pipe.blobs),
        windows: BlobWindows(&fx.pipe.blobs),
        shards: fx.pipe.shards.clone(),
        cfg: fx.pipe.cfg.indexed.unwrap(),
        takedown_denial: fx.pipe.cfg.takedown_denial,
        limits: SliceLimits {
            window_bytes: 64 << 10,
            ..SliceLimits::default()
        },
        lease: LeaseParams::from(&fx.pipe.cfg),
        clock: fx.clock.clone(),
        metrics: fx.metrics.clone(),
        extension: FailClosedExtraction,
    };
    let registry = TimerRegistry::new()
        .register(handler)
        .register(RelayHandler {
            target: Ref(&fx.pipe.meta),
            hook: NoHook,
            budget: RelayBudget::default(),
        })
        .register(crate::timers::publication_recheck::PublicationRecheck::new(
            Ref(&fx.pipe.meta),
        ));
    for _ in 0..12 {
        run_due(
            &fx.pipe.meta,
            source,
            &registry,
            fx.clock.as_ref(),
            ms(fx.clock.now_ms()),
            &TickBudget::default(),
        )
        .await
        .unwrap();
        fx.clock.advance(1);
    }
}

/// A boundary inside a measured segment: the label plus how many calls
/// and virtual milliseconds had elapsed when the step finished.
struct StepMark {
    label: &'static str,
    kv: usize,
    blobs: usize,
    virtual_ms: f64,
}

/// A counted boundary helper for multi-step flows.
struct Steps {
    fx_calls: Arc<Mutex<Vec<KvCall>>>,
    blob_calls: Arc<Mutex<Vec<(&'static str, BlobKey)>>>,
    start: tokio::time::Instant,
    marks: Vec<StepMark>,
}

impl Steps {
    fn new<H: HookSet>(fx: &PFx<H>) -> Self {
        Self {
            fx_calls: fx.pipe.meta.calls.clone(),
            blob_calls: fx.pipe.blobs.probe.calls.clone(),
            start: tokio::time::Instant::now(),
            marks: Vec::new(),
        }
    }
    fn mark(&mut self, label: &'static str) {
        self.marks.push(StepMark {
            label,
            kv: self.fx_calls.lock().unwrap().len(),
            blobs: self.blob_calls.lock().unwrap().len(),
            virtual_ms: self.start.elapsed().as_secs_f64() * 1000.0,
        });
    }
}

/// One ticketed `BeginUpload` + `UploadPack` session, measured.
async fn upload<H: HookSet>(fx: &PFx<H>, bytes: &[u8]) -> Hash {
    let (ticket, token) = begin_ticket(fx, HEAD, bytes).await;
    let a = fx.auth_req(&stream_signed(&fx.owner, &fx.identity, bytes, fx.number()));
    let mut session = fx
        .pipe
        .open_ticketed_upload(&a, Some(&hash(bytes)), Some(bytes.len() as u64), &token)
        .await
        .unwrap();
    session
        .push(
            Some(&hash(bytes)),
            Some(0),
            Bytes::copy_from_slice(bytes),
            true,
        )
        .await
        .unwrap();
    session.finish().await.unwrap();
    ticket
}

/// The embedder's small-pack flow end to end: `BeginUpload` +
/// `UploadPack` through the real session, the ticketed `AdvanceRefs`,
/// scheduled verification (SP2), and the commit — with PW1's hold absent
/// (client retry) or at `hold_ms`. Returns per-step call deltas.
async fn embedder<H: HookSet>(fx: &PFx<H>, steps: &mut Steps) {
    async fn advance<H: HookSet>(
        fx: &PFx<H>,
        a: &Authenticated,
        head: Hash,
        map_id: Hash,
        tickets: Vec<Hash>,
    ) -> Result<AdvanceOutcome, ServerError> {
        fx.pipe
            .advance_refs_with_tickets(
                a,
                upd(HEAD, Missing, head),
                upd(PACKMAP, Missing, map_id),
                tickets,
            )
            .await
    }
    let (bytes, head) = indexed::pack();
    let pack_id = hash(&bytes);
    let mut tickets = vec![upload(fx, &bytes).await];
    // Denial-aware flows carry the packlist under its own ticket.
    let map_id = if fx.pipe.cfg.takedown_denial {
        let map = mkit_core::transfer::encode_packlist(None, &[pack_id]).unwrap();
        tickets.push(upload(fx, &map).await);
        hash(&map)
    } else {
        pack_id
    };
    steps.mark("upload");

    let a = fx.auth(Procedure::AdvanceRefs);
    let repo = a.repo().repo.clone();
    let source = fx.pipe.shards.ref_shard(&repo, HEAD);
    if let Some(sleeper) = &fx.sleeper {
        // PW1: drive the attempt until the hold's sleeper is asked — the
        // parked point. Armed delays are tokio sleeps; a paused-runtime
        // yield of one warm unit lands each repoll exactly on the next
        // delay's deadline, so the attempt advances call by call.
        let mut waiting = Box::pin(advance(fx, &a, head, map_id, tickets));
        let mut cx = std::task::Context::from_waker(futures::task::noop_waker_ref());
        while sleeper.0.requested().is_empty() {
            assert!(
                waiting.as_mut().poll(&mut cx).is_pending(),
                "advance returned before the hold parked"
            );
            tokio::time::sleep(Duration::from_millis(WARM_MS)).await;
        }
        steps.mark("advance_parked");
        settle(fx, &source).await;
        steps.mark("settle");
        // Mirror pending_hold: the parked request observes the finished
        // jobs at its first 100 ms server poll — inside the 1 s hold.
        fx.clock.advance(88);
        sleeper.0.fire();
        assert_eq!(
            waiting.await.unwrap(),
            AdvanceOutcome::Committed,
            "held advance must commit after verification"
        );
    } else {
        // PW1 absent: the first ticketed advance answers pending, the
        // embedder verifies out of band (SP2 settle), then retries.
        let error = advance(fx, &a, head, map_id, tickets.clone())
            .await
            .unwrap_err();
        assert_eq!(error.public_message(), "pack verification pending");
        steps.mark("advance_pending");
        settle(fx, &source).await;
        steps.mark("settle");
        assert_eq!(
            advance(fx, &fx.auth(Procedure::AdvanceRefs), head, map_id, tickets)
                .await
                .unwrap(),
            AdvanceOutcome::Committed,
            "retry after verification must commit"
        );
    }
    steps.mark("advance_commit");
}

/// `(label, kv, blobs, virtual_ms)` for one flow step, in order.
type StepPins = [(&'static str, usize, usize, u64); 4];

/// The embedder flow's pin: PW1 hold setting plus the warm and cold step
/// tables. A zero hold runs the embedder's client-retry path; nonzero
/// parks the request inside the server hold.
struct FlowExpect {
    hold_ms: u64,
    warm: StepPins,
    cold: StepPins,
}

/// SP2 scheduled verification + the ticketed advance, per
/// `(sharding, denial)` and hold. `upload` covers `BeginUpload` +
/// `UploadPack`; `settle` is the out-of-band verification timers; the
/// `advance_*` steps are the request-path writes.
const EMBEDDER: [(Sharding, bool, FlowExpect); 8] = [
    (
        Sharding::Single,
        false,
        FlowExpect {
            hold_ms: 0,
            warm: [
                ("upload", 7, 6, 390),
                ("advance_pending", 5, 2, 210),
                ("settle", 62, 1, 1890),
                ("advance_commit", 9, 2, 330),
            ],
            cold: [
                ("upload", 7, 6, 660),
                ("advance_pending", 5, 2, 210),
                ("settle", 62, 1, 2160),
                ("advance_commit", 9, 2, 330),
            ],
        },
    ),
    (
        Sharding::Single,
        true,
        FlowExpect {
            hold_ms: 0,
            warm: [
                ("upload", 11, 12, 690),
                ("advance_pending", 5, 4, 210),
                ("settle", 90, 2, 2700),
                ("advance_commit", 54, 4, 1320),
            ],
            cold: [
                ("upload", 11, 12, 960),
                ("advance_pending", 5, 4, 210),
                ("settle", 90, 2, 3510),
                ("advance_commit", 54, 4, 2400),
            ],
        },
    ),
    (
        Sharding::D34,
        false,
        FlowExpect {
            hold_ms: 0,
            warm: [
                ("upload", 7, 6, 390),
                ("advance_pending", 5, 2, 210),
                ("settle", 97, 1, 2940),
                ("advance_commit", 9, 2, 330),
            ],
            cold: [
                ("upload", 7, 6, 660),
                ("advance_pending", 5, 2, 210),
                ("settle", 97, 1, 3750),
                ("advance_commit", 9, 2, 330),
            ],
        },
    ),
    (
        Sharding::D34,
        true,
        FlowExpect {
            hold_ms: 0,
            warm: [
                ("upload", 11, 12, 690),
                ("advance_pending", 5, 4, 210),
                ("settle", 123, 2, 3720),
                ("advance_commit", 54, 4, 1320),
            ],
            cold: [
                ("upload", 11, 12, 960),
                ("advance_pending", 5, 4, 210),
                ("settle", 123, 2, 5070),
                ("advance_commit", 54, 4, 2400),
            ],
        },
    ),
    (
        Sharding::Single,
        false,
        FlowExpect {
            hold_ms: 1000,
            warm: [
                ("upload", 7, 6, 390),
                ("advance_parked", 6, 2, 270),
                ("settle", 62, 1, 1890),
                ("advance_commit", 10, 0, 300),
            ],
            cold: [
                ("upload", 7, 6, 660),
                ("advance_parked", 6, 2, 270),
                ("settle", 62, 1, 2160),
                ("advance_commit", 10, 0, 300),
            ],
        },
    ),
    (
        Sharding::Single,
        true,
        FlowExpect {
            hold_ms: 1000,
            warm: [
                ("upload", 11, 12, 690),
                ("advance_parked", 6, 4, 270),
                ("settle", 90, 2, 2700),
                ("advance_commit", 55, 0, 1290),
            ],
            cold: [
                ("upload", 11, 12, 960),
                ("advance_parked", 6, 4, 270),
                ("settle", 90, 2, 3510),
                ("advance_commit", 55, 0, 2370),
            ],
        },
    ),
    (
        Sharding::D34,
        false,
        FlowExpect {
            hold_ms: 1000,
            warm: [
                ("upload", 7, 6, 390),
                ("advance_parked", 6, 2, 270),
                ("settle", 97, 1, 2940),
                ("advance_commit", 10, 0, 300),
            ],
            cold: [
                ("upload", 7, 6, 660),
                ("advance_parked", 6, 2, 270),
                ("settle", 97, 1, 3750),
                ("advance_commit", 10, 0, 300),
            ],
        },
    ),
    (
        Sharding::D34,
        true,
        FlowExpect {
            hold_ms: 1000,
            warm: [
                ("upload", 11, 12, 690),
                ("advance_parked", 6, 4, 270),
                ("settle", 123, 2, 3720),
                ("advance_commit", 55, 0, 1290),
            ],
            cold: [
                ("upload", 11, 12, 960),
                ("advance_parked", 6, 4, 270),
                ("settle", 123, 2, 5070),
                ("advance_commit", 55, 0, 2370),
            ],
        },
    ),
];

/// The embedder's upload → scheduled verify → ticketed-advance flow,
/// pinned per step for PW1 at 0 ms (client retry) and 1000 ms (the hold
/// parks while verification settles).
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)] // Step deltas round small positive virtual ms into u64 pins.
#[test]
fn embedder_upload_advance_reports_rounds() {
    let mut failures = Vec::new();
    for (sharding, denial, expect) in &EMBEDDER {
        for cold in [false, true] {
            let cell = format!(
                "embedder {sharding:?} denial={denial} hold={}ms",
                expect.hold_ms
            );
            let (marks, report) = big_stack(|| {
                let fx = probe_tweaked(
                    *sharding,
                    *denial,
                    IndexedConfig::scheduled(1 << 30),
                    Hooks::new(),
                    Some(Duration::from_millis(expect.hold_ms)),
                );
                probe(&fx, cold, async {
                    let mut steps = Steps::new(&fx);
                    embedder(&fx, &mut steps).await;
                    steps.marks
                })
            });
            let steps = if cold { &expect.cold } else { &expect.warm };
            let mut prev = (0usize, 0usize, 0u64);
            let mut deltas = Vec::with_capacity(marks.len());
            for mark in &marks {
                deltas.push((
                    mark.label,
                    mark.kv - prev.0,
                    mark.blobs - prev.1,
                    (mark.virtual_ms - prev.2 as f64).round() as u64,
                ));
                prev = (mark.kv, mark.blobs, mark.virtual_ms.round() as u64);
            }
            assert_eq!(
                marks.last().map(|m| m.kv),
                Some(report.kv()),
                "{cell} cold={cold}: step marks must cover every recorded call"
            );
            if deltas.as_slice() != steps.as_slice() {
                print_report(&cell, &report);
                failures.push(format!(
                    "{cell} cold={cold}: expected steps {steps:?}; got {deltas:?}"
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
