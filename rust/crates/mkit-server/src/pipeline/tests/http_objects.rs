//! HTTP object serving over the real indexed pipeline and memory stores
//! (WP-4.12, SPEC-HTTP-OBJECTS). Repositories are built by real ticketed
//! advances, so extraction, holders and index rows are the production ones.
#![allow(clippy::unwrap_used)] // Invalid fixtures should fail the test immediately.

use std::sync::atomic::AtomicU32;

use bytes::Bytes;
use futures::StreamExt as _;
use mkit_core::object::{
    Blob, ChunkedBlob, Commit, EntryMode, Identity, Object, ObjectType, Tag, Tree, TreeEntry,
};
use mkit_core::pack::PackWriter;
use mkit_core::repo_identity::Namespace;
use mkit_core::serialize::serialize;
use mkit_core::sign::{KeyPair, sign_commit};

use super::indexed::signed;
use super::*;
use crate::http_objects::{
    AdmitDecision, AdmitRequest, Admitted, HttpAdmission, HttpBody, HttpObjectRequest,
    HttpObjectResponse, HttpObjectsConfig, METRIC_HTTP_INLINE_CAPPED, METRIC_HTTP_REACH_CAPPED,
    ProofRequest, ProofServer, TakedownGate, TakedownVerdict,
};
use crate::repo::MultiAddressing;
use crate::store::{
    BlobBody, BlobKey, BlobMeta, BlobStore, ByteRange, MultipartBlobStore, PackSink,
    UnsupportedPartSink,
};
use crate::upload::marker::write_upload_marker;

const EXTRACT_MIN: u64 = 1024;
const TAG_REF: &str = "refs/heads/rel";
const TAG_PACKMAP: &str = "refs/mkit/packmap/rel";

type Calls = Arc<Mutex<Vec<(&'static str, BlobKey)>>>;

/// How `SpyBlobs` answers a ranged `get` of an extracted object.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum Reads {
    /// From the memory store.
    #[default]
    Normal,
    /// The read fails after the length was confirmed.
    Fails,
    /// One byte too few, then the stream ends.
    Short,
    /// One byte too many.
    Long,
    /// Lazily produced 64 KiB pieces; see `SpyBlobs::produced`.
    Pieces,
}

/// A memory blob store that records every `get` and `head` by key and can
/// misbehave on extracted-object reads.
#[derive(Clone)]
struct SpyBlobs {
    inner: MemoryBlobStore,
    calls: Calls,
    reads: Arc<Mutex<Reads>>,
    produced: Arc<AtomicU32>,
}

impl BlobStore for SpyBlobs {
    type Sink = <MemoryBlobStore as BlobStore>::Sink;

    async fn begin(&self, key: BlobKey, len: u64) -> Result<Self::Sink, StoreError> {
        self.inner.begin(key, len).await
    }

    async fn get(
        &self,
        key: &BlobKey,
        range: Option<ByteRange>,
    ) -> Result<Option<BlobBody>, StoreError> {
        self.calls.lock().unwrap().push(("get", *key));
        let mode = *self.reads.lock().unwrap();
        if mode == Reads::Normal || *key != BlobKey::object(*key.hash()) {
            return self.inner.get(key, range).await;
        }
        let body = self.inner.get(key, range).await?;
        let Some(BlobBody::Bytes(bytes)) = body else {
            return Ok(body);
        };
        Ok(Some(match mode {
            Reads::Fails => return Err(StoreError::unavailable("injected read fault")),
            Reads::Short => BlobBody::Bytes(bytes.slice(..bytes.len() - 1)),
            Reads::Long => {
                let mut longer = bytes.to_vec();
                longer.push(0);
                BlobBody::Bytes(Bytes::from(longer))
            }
            Reads::Pieces => {
                let produced = self.produced.clone();
                let len = bytes.len() as u64;
                let stream = futures::stream::unfold(0_usize, move |at| {
                    let (produced, bytes) = (produced.clone(), bytes.clone());
                    async move {
                        (at < bytes.len()).then(|| {
                            produced.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            let end = (at + 65_536).min(bytes.len());
                            (Ok(bytes.slice(at..end)), end)
                        })
                    }
                });
                BlobBody::Stream {
                    len,
                    stream: Box::pin(stream),
                }
            }
            Reads::Normal => unreachable!(),
        }))
    }

    async fn head(&self, key: &BlobKey) -> Result<Option<BlobMeta>, StoreError> {
        self.calls.lock().unwrap().push(("head", *key));
        self.inner.head(key).await
    }

    async fn probe(&self) -> Result<(), StoreError> {
        self.inner.probe().await
    }

    async fn delete(&self, key: &BlobKey) -> Result<bool, StoreError> {
        self.inner.delete(key).await
    }
}

impl MultipartBlobStore for SpyBlobs {
    type PartSink = UnsupportedPartSink;
    const MAX_PARTS: u32 = u32::MAX;
}

/// An authorizer that answers with a scripted code and records what it saw.
#[derive(Default)]
struct Scripted {
    verdict: Mutex<Option<Code>>,
    seen: Mutex<Vec<(Procedure, &'static str)>>,
}

impl Authorizer for Scripted {
    async fn authorize(&self, op: &Operation) -> Result<AuthzFacts, ServerError> {
        if matches!(
            op.procedure(),
            Procedure::HttpGetObject | Procedure::HttpGetRefPath
        ) {
            assert_eq!(op.authz.caller_view, CallerView::Anonymous);
            assert!(op.auth.is_none() && op.write_grant.is_none());
        }
        self.seen
            .lock()
            .unwrap()
            .push((op.procedure(), op.principal.kind()));
        match *self.verdict.lock().unwrap() {
            None => Ok(AuthzFacts::default()),
            Some(code) => Err(ServerError::new(code, "scripted")),
        }
    }
}

impl Authorizer for Arc<Scripted> {
    async fn authorize(&self, op: &Operation) -> Result<AuthzFacts, ServerError> {
        self.as_ref().authorize(op).await
    }
}

type Scripts = Hooks<Arc<Scripted>>;

fn scripted(az: &Arc<Scripted>) -> Scripts {
    Hooks {
        authorizer: az.clone(),
        admission: DefaultAdmission,
        pre_receive: NoPreReceive,
        receipts: NoReceipts,
        outcomes: NoOutcomes,
    }
}

struct Fx<H: HookSet = Hooks> {
    pipe: Pipeline<SpyBlobs, Arc<Spy>, H>,
    clock: Arc<ManualClock>,
    metrics: Arc<SpyMetrics>,
    owner: SigningKey,
    calls: Calls,
    numbers: AtomicU32,
}

fn http_cfg() -> HttpObjectsConfig {
    HttpObjectsConfig::default()
}

fn fixture() -> Fx {
    fixture_with(Hooks::new(), http_cfg())
}

fn fixture_with<H: HookSet>(hooks: H, http: HttpObjectsConfig) -> Fx<H> {
    fixture_tweaked(hooks, http, |_| {})
}

fn fixture_tweaked<H: HookSet>(
    hooks: H,
    http: HttpObjectsConfig,
    tweak: impl FnOnce(&mut PipelineConfig),
) -> Fx<H> {
    let owner = key(7);
    let namespace = Namespace::Ed25519(*owner.verifying_key().as_bytes());
    let mut config = cfg(authv2());
    config.addressing = Addressing::Multi(
        MultiAddressing::new()
            .with_namespace_policy(NamespacePolicy::Allowlist([namespace].into())),
    );
    config.write_policy = WritePolicy::Owner;
    config.ticket_keys =
        Some(crate::upload::token::TicketKeys::new(vec![("test".into(), [7; 32])]).unwrap());
    config.indexed = Some(crate::indexed::IndexedConfig {
        extract_min_bytes: EXTRACT_MIN,
        ..crate::indexed::IndexedConfig::default()
    });
    config.http_objects = Some(http);
    tweak(&mut config);
    let clock = clock();
    let metrics = Arc::new(SpyMetrics::default());
    let calls = Calls::default();
    let pipe = Pipeline::new(
        SpyBlobs {
            inner: MemoryBlobStore::default(),
            calls: calls.clone(),
            reads: Arc::default(),
            produced: Arc::default(),
        },
        Arc::new(Spy::new(store(&clock))),
        hooks,
        config,
        clock.clone(),
        metrics.clone(),
    )
    .unwrap();
    Fx {
        pipe,
        clock,
        metrics,
        owner,
        calls,
        numbers: AtomicU32::new(1000),
    }
}

/// The body bytes of a response, checking a stream's declared length.
fn body_of(body: HttpBody) -> Vec<u8> {
    match body {
        HttpBody::Empty => Vec::new(),
        HttpBody::Bytes(bytes) => bytes.to_vec(),
        HttpBody::Stream { len, stream } => block_on(async move {
            let mut stream = stream;
            let mut out = Vec::new();
            while let Some(piece) = stream.next().await {
                out.extend_from_slice(&piece.unwrap());
            }
            assert_eq!(
                out.len() as u64,
                len,
                "a stream carries its declared length"
            );
            out
        }),
    }
}

/// A response with its body read.
struct Got {
    status: u16,
    headers: Vec<(&'static str, String)>,
    body: Vec<u8>,
}

impl Got {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

fn read(response: HttpObjectResponse) -> Got {
    Got {
        status: response.status,
        headers: response.headers,
        body: body_of(response.body),
    }
}

impl<H: HookSet> Fx<H> {
    fn number(&self) -> u32 {
        self.numbers
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    }

    fn namespace(&self) -> String {
        Namespace::Ed25519(*self.owner.verifying_key().as_bytes()).to_string()
    }

    fn identity(&self, name: &str) -> String {
        format!("{}/{name}", self.namespace())
    }

    fn auth(&self, req: &Req) -> Authenticated {
        let lookup = |name: &str| {
            req.headers
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, v)| v.clone())
        };
        self.pipe
            .authenticate(&RequestMeta {
                procedure: req.procedure,
                header: &lookup,
                header_values: None,
                unary_body: Some(&req.body),
                transport_principal: None,
            })
            .unwrap()
    }

    /// Push `objects` as one pack and advance `head_ref` to `head`.
    fn push_ref(
        &self,
        name: &str,
        objects: &[&Object],
        refs: (&str, &str),
        head: Hash,
        conditions: (RefWriteCondition, RefWriteCondition),
    ) -> (AdvanceOutcome, Hash) {
        let mut writer = PackWriter::new_raw_only();
        for object in objects {
            writer
                .push_raw(object.id().unwrap(), &serialize(object).unwrap())
                .unwrap();
        }
        self.push_pack(name, &writer.finish().unwrap(), refs, head, conditions)
    }

    /// Upload `pack` under a ticket and advance `head_ref` to `head`.
    fn push_pack(
        &self,
        name: &str,
        pack: &[u8],
        (head_ref, packmap_ref): (&str, &str),
        head: Hash,
        conditions: (RefWriteCondition, RefWriteCondition),
    ) -> (AdvanceOutcome, Hash) {
        let identity = self.identity(name);
        let pack_id = hash(pack);
        let upload =
            |bytes: &[u8]| {
                let id = hash(bytes);
                let begin = signed(
                    &self.owner,
                    &identity,
                    Procedure::BeginUpload,
                    self.number(),
                );
                let BeginUploadResult::Ticket { id: ticket, .. } = block_on(
                    self.pipe
                        .begin_upload(&self.auth(&begin), head_ref, &id, bytes.len() as u64),
                )
                .unwrap() else {
                    panic!("expected an upload ticket");
                };
                block_on(async {
                    let mut sink = self
                        .pipe
                        .blobs
                        .begin(BlobKey::pack(id), bytes.len() as u64)
                        .await
                        .unwrap();
                    sink.write(Bytes::copy_from_slice(bytes)).await.unwrap();
                    sink.commit().await.unwrap();
                    write_upload_marker(&self.pipe.blobs, &ticket, &id)
                        .await
                        .unwrap();
                });
                ticket
            };
        let mut tickets = vec![upload(pack)];
        let (map_id, map_condition) = if self.pipe.cfg.takedown_denial {
            let map = mkit_core::transfer::encode_packlist(None, &[pack_id]).unwrap();
            tickets.push(upload(&map));
            let condition = match conditions.1 {
                Match(old_pack) => Match(hash(
                    &mkit_core::transfer::encode_packlist(None, &[old_pack]).unwrap(),
                )),
                other => other,
            };
            (hash(&map), condition)
        } else {
            (pack_id, conditions.1)
        };
        let advance = signed(
            &self.owner,
            &identity,
            Procedure::AdvanceRefs,
            self.number(),
        );
        let outcome = block_on(self.pipe.advance_refs_with_tickets(
            &self.auth(&advance),
            upd(head_ref, conditions.0, head),
            upd(packmap_ref, map_condition, map_id),
            tickets,
        ))
        .unwrap();
        (outcome, pack_id)
    }

    /// Push `objects` to `refs/heads/main` of `name`, creating it or moving
    /// it from `previous`.
    fn push(
        &self,
        name: &str,
        objects: &[&Object],
        head: Hash,
        previous: Option<(Hash, Hash)>,
    ) -> Hash {
        let conditions = previous.map_or((Missing, Missing), |(head, pack)| {
            (Match(head), Match(pack))
        });
        let (outcome, pack) = self.push_ref(name, objects, (HEAD, PACKMAP), head, conditions);
        assert_eq!(outcome, AdvanceOutcome::Committed);
        pack
    }

    fn request(
        &self,
        method: &str,
        path: &str,
        query: Option<&str>,
        headers: &[(&str, &str)],
    ) -> HttpObjectResponse {
        let lookup = |name: &str| -> Vec<String> {
            headers
                .iter()
                .filter(|(n, _)| n.eq_ignore_ascii_case(name))
                .map(|(_, v)| (*v).to_owned())
                .collect()
        };
        let names: Vec<_> = headers.iter().map(|(name, _)| *name).collect();
        block_on(self.pipe.serve_http_object(&HttpObjectRequest {
            method,
            raw_path: path,
            raw_query: query.map(crate::http_objects::RedactedQuery::new),
            headers: &lookup,
            header_names: &names,
        }))
    }

    fn get(&self, path: &str) -> Got {
        read(self.request("GET", path, None, &[]))
    }

    fn get_with(&self, path: &str, headers: &[(&str, &str)]) -> Got {
        read(self.request("GET", path, None, headers))
    }

    fn object_url(&self, name: &str, id: &Hash) -> String {
        format!("/{}/-/objects/{}", self.identity(name), to_hex(id))
    }

    fn ref_url(&self, name: &str, branch: &str, file: &str) -> String {
        format!("/{}/-/refs/heads/{branch}/-/{file}", self.identity(name))
    }

    fn blob_calls(&self, key: BlobKey) -> Vec<&'static str> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, k)| *k == key)
            .map(|(op, _)| *op)
            .collect()
    }

    fn clear_calls(&self) {
        self.calls.lock().unwrap().clear();
    }
}

fn blob(data: &[u8]) -> Object {
    Object::Blob(Blob {
        data: data.to_vec(),
    })
}

fn tree(entries: &[(&str, EntryMode, &Object)]) -> Object {
    Object::Tree(Tree {
        entries: entries
            .iter()
            .map(|(name, mode, object)| TreeEntry {
                name: name.as_bytes().to_vec(),
                mode: *mode,
                object_hash: object.id().unwrap(),
            })
            .collect(),
    })
}

fn commit(tree: &Object, parents: &[&Object], message: &str) -> Object {
    let signer = KeyPair::from_seed([9; 32]);
    let mut commit = Commit::new_unannotated(
        tree.id().unwrap(),
        parents.iter().map(|p| p.id().unwrap()).collect(),
        Identity::ed25519(signer.public.0),
        signer.public.0,
        message.as_bytes().to_vec(),
        42,
        [0; 64],
    );
    commit.signature = sign_commit(&commit, &signer).unwrap().0;
    Object::Commit(commit)
}

fn manifest(chunks: &[&[u8]]) -> (Object, Vec<Object>) {
    let objects: Vec<_> = chunks.iter().map(|data| blob(data)).collect();
    let manifest = Object::ChunkedBlob(ChunkedBlob {
        total_size: chunks.iter().map(|c| c.len() as u64).sum(),
        chunk_size: 0,
        chunks: objects.iter().map(|o| o.id().unwrap()).collect(),
    });
    (manifest, objects)
}

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from((i * 31 + usize::from(seed) * 7) % 251).unwrap())
        .collect()
}

/// One repository's content, every kind of byte source in it.
struct Data {
    all: Vec<Object>,
    commit: Object,
    root: Object,
    small: Object,
    big: Object,
    manifest: Object,
    chunks: Vec<Object>,
    dir: Object,
    small_bytes: Vec<u8>,
    big_bytes: Vec<u8>,
    chunk_bytes: Vec<Vec<u8>>,
}

fn data() -> Data {
    let small_bytes = pattern(100, 1);
    let big_bytes = pattern(70_000, 2);
    let chunk_bytes = vec![pattern(60_000, 3), pattern(30_000, 4), pattern(5_000, 5)];
    let small = blob(&small_bytes);
    let big = blob(&big_bytes);
    let link = blob(b"small.txt");
    let empty = blob(b"");
    let inner = blob(&pattern(50, 6));
    let (manifest, chunks) = manifest(&chunk_bytes.iter().map(Vec::as_slice).collect::<Vec<_>>());
    let dir = tree(&[("inner.txt", EntryMode::Blob, &inner)]);
    let dir_object = dir.clone();
    let root = tree(&[
        ("big.bin", EntryMode::Blob, &big),
        ("chunked.bin", EntryMode::Blob, &manifest),
        ("dir", EntryMode::Tree, &dir),
        ("empty", EntryMode::Blob, &empty),
        ("link", EntryMode::Symlink, &link),
        ("small.txt", EntryMode::Blob, &small),
    ]);
    let commit = commit(&root, &[], "content");
    let mut all = vec![
        small.clone(),
        big.clone(),
        link.clone(),
        empty.clone(),
        inner.clone(),
        manifest.clone(),
        dir,
        root.clone(),
        commit.clone(),
    ];
    all.extend(chunks.iter().cloned());
    Data {
        all,
        commit,
        root,
        small,
        big,
        manifest,
        chunks,
        dir: dir_object,
        small_bytes,
        big_bytes,
        chunk_bytes,
    }
}

impl Data {
    fn refs(&self) -> Vec<&Object> {
        self.all.iter().collect()
    }

    fn head(&self) -> Hash {
        self.commit.id().unwrap()
    }

    fn whole(&self) -> Vec<u8> {
        self.chunk_bytes.concat()
    }
}

fn published() -> (Fx, Data) {
    let fx = fixture();
    let d = data();
    fx.push("room", &d.refs(), d.head(), None);
    (fx, d)
}

fn id(o: &Object) -> Hash {
    o.id().unwrap()
}

const IMMUTABLE: &str = "public, max-age=31536000, immutable";

#[test]
fn serves_every_byte_source_by_id() {
    let (fx, d) = published();
    // A small blob comes from its own pack entry.
    let got = fx.get(&fx.object_url("room", &id(&d.small)));
    assert_eq!(got.status, 200);
    assert_eq!(got.body, d.small_bytes);
    assert_eq!(
        got.header("ETag"),
        Some(format!("\"{}\"", to_hex(&id(&d.small))).as_str())
    );
    assert_eq!(got.header("Content-Type"), Some("application/octet-stream"));
    assert_eq!(got.header("X-Mkit-Object-Type"), Some("blob"));
    assert_eq!(got.header("Cache-Control"), Some(IMMUTABLE));
    assert_eq!(got.header("Content-Length"), Some("100"));
    assert_eq!(got.header("X-Mkit-Commit"), None);
    // A file blob was extracted for this repository and is read by range.
    fx.clear_calls();
    let got = fx.get(&fx.object_url("room", &id(&d.big)));
    assert_eq!(got.status, 200);
    assert_eq!(got.body, d.big_bytes);
    assert!(fx.blob_calls(BlobKey::object(id(&d.big))).contains(&"get"));
    // The manifest serves its reassembled content, byte for byte.
    let got = fx.get(&fx.object_url("room", &id(&d.manifest)));
    assert_eq!(got.status, 200);
    assert_eq!(got.body, d.whole());
    assert_eq!(got.header("X-Mkit-Object-Type"), Some("chunked_blob"));
    assert_eq!(got.header("Content-Length"), Some("95000"));
    // A tree and a commit serve their canonical bytes.
    for (object, ty) in [(&d.root, "tree"), (&d.commit, "commit")] {
        let got = fx.get(&fx.object_url("room", &id(object)));
        assert_eq!(got.status, 200);
        assert_eq!(got.body, serialize(object).unwrap());
        assert_eq!(
            got.header("Content-Type"),
            Some("application/vnd.mkit.object")
        );
        assert_eq!(got.header("X-Mkit-Object-Type"), Some(ty));
    }
}

impl<H: HookSet> Fx<H> {
    /// Mark `name` private, as `SetRepoVisibility` would.
    fn make_private(&self, name: &str) {
        let repo = RepoId {
            namespace: NamespaceKey::from_namespace(&Namespace::Ed25519(
                *self.owner.verifying_key().as_bytes(),
            )),
            name: RepoName::new(name).unwrap(),
        };
        let batch = Batch::new().put(
            keys::repo_visibility(&repo.name),
            codec::encode_repo_visibility(&codec::RepoVisibilityV1 {
                visibility: codec::StoredVisibility::Private,
                last_created_ms: 0,
                last_statement_id: None,
            }),
        );
        let p = self.pipe.shards.coordinator(&repo.namespace);
        assert_eq!(
            block_on(self.pipe.meta.inner.apply(&p, batch)).unwrap(),
            BatchOutcome::Committed
        );
    }

    fn repo_id(&self, name: &str) -> RepoId {
        RepoId {
            namespace: NamespaceKey::from_namespace(&Namespace::Ed25519(
                *self.owner.verifying_key().as_bytes(),
            )),
            name: RepoName::new(name).unwrap(),
        }
    }

    /// The seed the object-store holder row of `object` carries for `name`.
    fn holder(&self, name: &str, object: &Hash) -> Option<crate::store::HolderRecord> {
        let repo = self.repo_id(name);
        let content = crate::store::ContentIndex::new(crate::store::BorrowedStore(&self.pipe.meta));
        block_on(content.holder_record(
            object,
            &crate::store::Holder::new(repo.namespace, repo.name),
        ))
        .unwrap()
    }
}

fn assert_uniform_404(got: &Got) {
    assert_eq!(got.status, 404);
    assert_eq!(got.header("Cache-Control"), Some("no-store"));
    for absent in ["ETag", "X-Mkit-Object", "X-Mkit-Commit", "Content-Range"] {
        assert_eq!(got.header(absent), None, "{absent}");
    }
    assert_eq!(got.body, b"not found");
}

#[test]
fn ref_paths_resolve_to_the_leaf_and_carry_the_commit() {
    let (fx, d) = published();
    let commit = to_hex(&d.head());
    for (file, want, ty) in [
        ("small.txt", d.small_bytes.clone(), "blob"),
        ("big.bin", d.big_bytes.clone(), "blob"),
        ("chunked.bin", d.whole(), "chunked_blob"),
        ("dir/inner.txt", pattern(50, 6), "blob"),
        // A symlink is content: its target text, never followed.
        ("link", b"small.txt".to_vec(), "blob"),
        ("empty", Vec::new(), "blob"),
    ] {
        let got = fx.get(&fx.ref_url("room", "main", file));
        assert_eq!(got.status, 200, "{file}");
        assert_eq!(got.body, want, "{file}");
        assert_eq!(got.header("X-Mkit-Commit"), Some(commit.as_str()), "{file}");
        assert_eq!(got.header("X-Mkit-Object-Type"), Some(ty), "{file}");
        assert_eq!(
            got.header("Cache-Control"),
            Some("public, no-cache"),
            "{file}"
        );
        assert_eq!(got.header("Accept-Ranges"), Some("bytes"));
    }
    // The root and a subdirectory serve their canonical tree bytes.
    for (file, tree) in [("", &d.root), ("dir", &d.dir)] {
        let got = fx.get(&fx.ref_url("room", "main", file));
        assert_eq!(got.status, 200, "{file:?}");
        assert_eq!(got.body, serialize(tree).unwrap());
        assert_eq!(got.header("X-Mkit-Object-Type"), Some("tree"));
        assert_eq!(
            got.header("Content-Type"),
            Some("application/vnd.mkit.object")
        );
    }
}

#[test]
fn every_miss_is_the_same_404() {
    let (fx, d) = published();
    let other = fixture();
    let (other_data, gone) = (data(), [0x77; 32]);
    other.push("elsewhere", &other_data.refs(), other_data.head(), None);
    fx.push("private", &d.refs(), d.head(), None);
    fx.make_private("private");
    let urls = [
        // A ref that does not exist, a non-tree intermediate, a missing entry.
        fx.ref_url("room", "gone", "small.txt"),
        fx.ref_url("room", "main", "small.txt/deeper"),
        fx.ref_url("room", "main", "nothing"),
        fx.ref_url("room", "main", "dir/nothing"),
        // An id no pack of this repository holds.
        fx.object_url("room", &gone),
        // A repository that does not exist, and a private one.
        format!(
            "/{}/-/objects/{}",
            fx.identity("missing"),
            to_hex(&id(&d.small))
        ),
        fx.object_url("private", &id(&d.small)),
        fx.ref_url("private", "main", "small.txt"),
    ];
    let mut first: Option<Got> = None;
    for url in &urls {
        let got = fx.get(url);
        assert_uniform_404(&got);
        if let Some(first) = &first {
            assert_eq!(got.headers, first.headers, "{url}");
        }
        first.get_or_insert(got);
        // HEAD is the same response without the body.
        let head = read(fx.request("HEAD", url, None, &[]));
        assert_eq!(head.status, 404);
        assert_eq!(head.headers, first.as_ref().unwrap().headers, "{url}");
        assert!(head.body.is_empty());
    }
    // A conditional request cannot turn a miss into a 304.
    let etag = format!("\"{}\"", to_hex(&id(&d.small)));
    let got = fx.get_with(
        &fx.ref_url("room", "gone", "x"),
        &[("if-none-match", &etag)],
    );
    assert_uniform_404(&got);
}

#[test]
fn a_ref_to_a_tag_peels_to_its_commit() {
    let fx = fixture();
    let d = data();
    fx.push("room", &d.refs(), d.head(), None);
    let tag = Object::Tag(Tag {
        target: d.head(),
        target_type: ObjectType::Commit,
        name: b"v1".to_vec(),
        tagger: Identity::ed25519(KeyPair::from_seed([9; 32]).public.0),
        signer: KeyPair::from_seed([9; 32]).public.0,
        message: b"tag".to_vec(),
        timestamp: 1,
        signature: [0; 64],
    });
    let mut signed_tag = tag.clone();
    if let Object::Tag(t) = &mut signed_tag {
        t.signature = mkit_core::sign::sign_tag(t, &KeyPair::from_seed([9; 32]))
            .unwrap()
            .0;
    }
    let (outcome, _) = fx.push_ref(
        "room",
        &[&signed_tag],
        (TAG_REF, TAG_PACKMAP),
        id(&signed_tag),
        (Missing, Missing),
    );
    assert_eq!(outcome, AdvanceOutcome::Committed);
    let got = fx.get(&fx.ref_url("room", "rel", "small.txt"));
    assert_eq!(got.status, 200);
    assert_eq!(got.body, d.small_bytes);
    assert_eq!(
        got.header("X-Mkit-Commit"),
        Some(to_hex(&d.head()).as_str())
    );
}

#[test]
fn tag_peeling_accepts_16_tags_and_rejects_17() {
    for depth in [16, 17] {
        let (fx, d) = published();
        let signer = KeyPair::from_seed([9; 32]);
        let mut tags = Vec::new();
        let mut target = d.head();
        for index in 0..depth {
            let mut tag = Tag {
                target,
                target_type: if index == 0 {
                    ObjectType::Commit
                } else {
                    ObjectType::Tag
                },
                name: format!("v{index}").into_bytes(),
                tagger: Identity::ed25519(signer.public.0),
                signer: signer.public.0,
                message: b"tag chain".to_vec(),
                timestamp: 1,
                signature: [0; 64],
            };
            tag.signature = mkit_core::sign::sign_tag(&tag, &signer).unwrap().0;
            let object = Object::Tag(tag);
            target = id(&object);
            tags.push(object);
        }
        let objects: Vec<_> = tags.iter().collect();
        let (outcome, _) = fx.push_ref(
            "room",
            &objects,
            (TAG_REF, TAG_PACKMAP),
            target,
            (Missing, Missing),
        );
        assert_eq!(outcome, AdvanceOutcome::Committed);
        let got = fx.get(&fx.ref_url("room", "rel", "small.txt"));
        if depth == 16 {
            assert_eq!(got.status, 200);
            assert_eq!(got.body, d.small_bytes);
            assert_eq!(
                got.header("X-Mkit-Commit"),
                Some(to_hex(&d.head()).as_str())
            );
        } else {
            assert_uniform_404(&got);
        }
    }
}

#[test]
fn excluded_packmap_refs_exhaust_the_ref_scan_budget() {
    for page_limit in [4, 1_000] {
        let fx = fixture_tweaked(
            Hooks::new(),
            HttpObjectsConfig {
                max_walk_objects: 32,
                ..http_cfg()
            },
            |cfg| cfg.list_page_limit = page_limit,
        );
        let d = data();
        fx.push("room", &d.refs(), d.head(), None);
        let repo = fx.repo_id("room");
        // Move the published tip after the excluded namespace in listing order.
        let partition = fx.pipe.shards.ref_shard(&repo, HEAD);
        let mut batch = Batch::new().delete(keys::published_ref(&repo.name, HEAD));
        batch = batch.put(
            keys::published_ref(&repo.name, "refs/tags/z"),
            codec::encode_ref_id(&d.head()),
        );
        assert_eq!(
            block_on(fx.pipe.meta.inner.apply(&partition, batch)).unwrap(),
            BatchOutcome::Committed
        );
        for index in 0..100 {
            let batch = Batch::new().put(
                keys::published_ref(&repo.name, &format!("refs/mkit/packmap/p{index:03}")),
                codec::encode_ref_id(&[0x55; 32]),
            );
            assert_eq!(
                block_on(fx.pipe.meta.inner.apply(&partition, batch)).unwrap(),
                BatchOutcome::Committed
            );
        }
        let (scan_start, _) = keys::ref_prefix_range(&repo.name, "refs/");
        let scan_count = || {
            fx.pipe
                .meta
                .seen
                .lock()
                .unwrap()
                .iter()
                .filter(|key| key.as_bytes().starts_with(scan_start.as_bytes()))
                .count()
        };
        let before = scan_count();
        assert_uniform_404(&fx.get(&fx.object_url("room", &id(&d.small))));
        assert_eq!(fx.metrics.count(METRIC_HTTP_REACH_CAPPED), 1);
        let after = scan_count();
        assert!(
            after - before <= 32_usize.div_ceil(page_limit as usize),
            "ref scan exceeded its page budget"
        );
    }
}

#[test]
fn formatting_the_raw_query_is_redacted() {
    let request = HttpObjectRequest {
        method: "GET",
        raw_path: "/secret-path",
        raw_query: Some(crate::http_objects::RedactedQuery::new(
            "token=secret-query-token",
        )),
        headers: &|_| Vec::new(),
        header_names: &[],
    };
    let query = request.raw_query.unwrap();
    for rendered in [
        format!("{request:?}"),
        format!("{:?}", request.raw_query),
        format!("{query}"),
        format!("{query:#?}"),
    ] {
        assert!(!rendered.contains("secret-query-token"), "{rendered}");
    }
}

/// A second history for `main`: a root commit over one new file.
fn rewound() -> (Vec<Object>, Object, Object) {
    let file = blob(&pattern(2_000, 9));
    let root = tree(&[("new.bin", EntryMode::Blob, &file)]);
    let head = commit(&root, &[], "rewound");
    (vec![file.clone(), root, head.clone()], file, head)
}

#[test]
fn an_orphaned_member_is_unreachable_until_the_cache_expires() {
    let fx = fixture();
    let d = data();
    let pack = fx.push("room", &d.refs(), d.head(), None);
    // Reachable now: the walk proves it and the proof is cached.
    let got = fx.get(&fx.object_url("room", &id(&d.big)));
    assert_eq!(got.status, 200);
    // Force-push an unrelated history over `main`.
    let (objects, file, head) = rewound();
    let refs: Vec<_> = objects.iter().collect();
    fx.push("room", &refs, id(&head), Some((d.head(), pack)));
    // The old content is still a member, but a proof not yet cached fails.
    let got = fx.get(&fx.object_url("room", &id(&d.small)));
    assert_uniform_404(&got);
    // The cached proof outlives the rewind for `reachability_lag_ms` only.
    let before = fx.get(&fx.object_url("room", &id(&d.big)));
    assert_eq!(before.status, 200);
    fx.clock
        .advance(i64::try_from(http_cfg().reachability_lag_ms).unwrap());
    assert_uniform_404(&fx.get(&fx.object_url("room", &id(&d.big))));
    // The new content is reachable, and the old ref-path content is gone.
    assert_eq!(fx.get(&fx.object_url("room", &id(&file))).status, 200);
    assert_uniform_404(&fx.get(&fx.ref_url("room", "main", "small.txt")));
}

#[test]
fn remix_sources_and_delta_bases_are_not_followed() {
    let fx = fixture();
    let d = data();
    let pack = fx.push("room", &d.refs(), d.head(), None);
    // `main` becomes a remix whose `sources` name the old commit, over a tree
    // that holds a file stored as a delta against the old big file.
    let mut variant = d.big_bytes.clone();
    variant[10] ^= 0xff;
    let derived = blob(&variant);
    let root = tree(&[("derived.bin", EntryMode::Blob, &derived)]);
    let signer = KeyPair::from_seed([9; 32]);
    let mut remix = mkit_core::object::Remix {
        tree_hash: id(&root),
        parents: Vec::new(),
        sources: vec![mkit_core::object::RemixSource {
            upstream_id: [0xcd; 32],
            commit_hash: d.head(),
        }],
        author: Identity::ed25519(signer.public.0),
        signer: signer.public.0,
        message: b"remix".to_vec(),
        timestamp: 43,
        signature: [0; 64],
    };
    remix.signature = mkit_core::sign::sign_remix(&remix, &signer).unwrap().0;
    let remix = Object::Remix(remix);
    let mut writer = PackWriter::new();
    let base = serialize(&d.big).unwrap();
    writer
        .push_delta(
            &id(&d.big),
            &mkit_core::delta::encode(&base, &serialize(&derived).unwrap()).unwrap(),
        )
        .unwrap();
    for object in [&root, &remix] {
        writer
            .push_raw(id(object), &serialize(object).unwrap())
            .unwrap();
    }
    let (outcome, _) = fx.push_pack(
        "room",
        &writer.finish().unwrap(),
        (HEAD, PACKMAP),
        id(&remix),
        (Match(d.head()), Match(pack)),
    );
    assert_eq!(outcome, AdvanceOutcome::Committed);
    // The delta's own reconstruction is served and reachable.
    let got = fx.get(&fx.object_url("room", &id(&derived)));
    assert_eq!((got.status, got.body), (200, variant));
    // Neither the remix source's commit nor the delta's base is reachable.
    for old in [&d.commit, &d.big, &d.small] {
        assert_uniform_404(&fx.get(&fx.object_url("room", &id(old))));
    }
}

#[test]
fn a_capped_walk_is_a_404_with_a_metric_and_a_ref_path_warms_the_cache() {
    let fx = fixture_with(
        Hooks::new(),
        HttpObjectsConfig {
            max_walk_objects: 1,
            ..http_cfg()
        },
    );
    let d = data();
    fx.push("room", &d.refs(), d.head(), None);
    let url = fx.object_url("room", &id(&d.small));
    assert_uniform_404(&fx.get(&url));
    assert_eq!(fx.metrics.count(METRIC_HTTP_REACH_CAPPED), 1);
    // Serving the ref path proves its leaf reachable, so the id URL works
    // without a walk (which this configuration could never finish).
    assert_eq!(fx.get(&fx.ref_url("room", "main", "small.txt")).status, 200);
    assert_eq!(fx.get(&url).status, 200);
    assert_eq!(fx.metrics.count(METRIC_HTTP_REACH_CAPPED), 1);
}

#[test]
fn the_decode_budget_caps_resolution_and_the_walk() {
    let minimum = EXTRACT_MIN + 10;
    let fx = fixture_with(
        Hooks::new(),
        HttpObjectsConfig {
            max_inline_object_bytes: minimum,
            http_decode_budget: minimum,
            ..http_cfg()
        },
    );
    // A root tree of 60 entries decodes to more bytes than the budget.
    let files: Vec<Object> = (0..60).map(|i| blob(&[i; 8])).collect();
    let names: Vec<String> = (0..60).map(|i| format!("f{i:02}")).collect();
    let entries: Vec<_> = names
        .iter()
        .zip(&files)
        .map(|(n, f)| (n.as_str(), EntryMode::Blob, f))
        .collect();
    let root = tree(&entries);
    assert!(serialize(&root).unwrap().len() as u64 > minimum);
    let head = commit(&root, &[], "wide");
    let mut objects: Vec<&Object> = files.iter().collect();
    objects.extend([&root, &head]);
    fx.push("room", &objects, id(&head), None);
    // The ref path cannot afford the tree: an infrastructure 503, not a 404.
    let got = fx.get(&fx.ref_url("room", "main", "f00"));
    assert_eq!(got.status, 503);
    assert_eq!(got.header("Cache-Control"), Some("no-store"));
    // The walk gives up the same way as any cap.
    assert_uniform_404(&fx.get(&fx.object_url("room", &id(&files[1]))));
    assert_eq!(fx.metrics.count(METRIC_HTTP_REACH_CAPPED), 1);
}

#[test]
fn a_chunk_only_blob_is_served_from_this_repositorys_pack_never_the_global_copy() {
    let fx = fixture();
    let shared = pattern(20_000, 11);
    let shared_blob = blob(&shared);
    // Repository `other` keeps the blob as a file: it is extracted and held.
    let file_root = tree(&[("file", EntryMode::Blob, &shared_blob)]);
    let other_head = commit(&file_root, &[], "file");
    fx.push(
        "other",
        &[&shared_blob, &file_root, &other_head],
        id(&other_head),
        None,
    );
    assert!(fx.holder("other", &id(&shared_blob)).is_some());
    assert_eq!(
        block_on(fx.pipe.blobs.inner.head(&BlobKey::object(id(&shared_blob))))
            .unwrap()
            .map(|m| m.len),
        Some(20_000)
    );
    // Repository `room` has it only as a chunk of a manifest: no holder.
    let rest = pattern(3_000, 12);
    let (manifest, chunks) = manifest(&[&shared, &rest]);
    let root = tree(&[("big.bin", EntryMode::Blob, &manifest)]);
    let head = commit(&root, &[], "chunks");
    let mut objects: Vec<&Object> = chunks.iter().collect();
    objects.extend([&manifest, &root, &head]);
    fx.push("room", &objects, id(&head), None);
    assert!(fx.holder("room", &id(&shared_blob)).is_none());
    fx.clear_calls();
    let got = fx.get(&fx.object_url("room", &id(&shared_blob)));
    assert_eq!((got.status, got.body), (200, shared));
    assert_eq!(
        fx.blob_calls(BlobKey::object(id(&shared_blob))),
        Vec::<&str>::new()
    );
}

#[test]
fn a_member_of_another_repository_is_a_404_that_never_reads_the_global_store() {
    let fx = fixture();
    let d = data();
    fx.push("other", &d.refs(), d.head(), None);
    let small = fixture_data_for_room(&fx);
    fx.clear_calls();
    // `room` mentions nothing of `other`'s content and is not a member.
    for object in [&d.big, &d.manifest] {
        let got = fx.get(&fx.object_url("room", &id(object)));
        assert_uniform_404(&got);
        for key in [
            BlobKey::object(id(object)),
            BlobKey::object_offsets(id(object)),
        ] {
            assert_eq!(fx.blob_calls(key), Vec::<&str>::new());
        }
    }
    // The same request to `other` is served from its extraction.
    assert_eq!(fx.get(&fx.object_url("other", &id(&d.big))).status, 200);
    drop(small);
}

/// Give `room` some unrelated content of its own.
fn fixture_data_for_room<H: HookSet>(fx: &Fx<H>) -> Object {
    let file = blob(&pattern(3_000, 21));
    let root = tree(&[("mine", EntryMode::Blob, &file)]);
    let head = commit(&root, &[], "mine");
    fx.push("room", &[&file, &root, &head], id(&head), None);
    file
}

#[test]
fn a_broken_extraction_is_a_503_never_a_guess() {
    let (fx, d) = published();
    let object = BlobKey::object(id(&d.big));
    // The holder row exists but the object is gone.
    assert!(block_on(fx.pipe.blobs.inner.delete(&object)).unwrap());
    let got = fx.get(&fx.object_url("room", &id(&d.big)));
    assert_eq!(got.status, 503);
    assert_eq!(got.header("Cache-Control"), Some("no-store"));
    // The object is back with the wrong length.
    let wrong = pattern(69_999, 2);
    block_on(async {
        let sink = fx
            .pipe
            .blobs
            .inner
            .begin(object, wrong.len() as u64)
            .await
            .unwrap();
        let mut sink = sink;
        sink.write(Bytes::from(wrong.clone())).await.unwrap();
        sink.commit_with_root(mkit_core::hash::hash(&wrong))
            .await
            .unwrap();
    });
    assert_eq!(fx.get(&fx.object_url("room", &id(&d.big))).status, 503);
    assert_eq!(fx.get(&fx.ref_url("room", "main", "big.bin")).status, 503);
    // A manifest whose holder row is gone has no reassembled copy: 503, and no
    // reassembly on the fly.
    let holder = fx.holder("room", &id(&d.manifest)).unwrap();
    let repo = fx.repo_id("room");
    let content = crate::store::ContentIndex::new(crate::store::BorrowedStore(&fx.pipe.meta));
    assert!(
        block_on(content.remove_holder(
            &id(&d.manifest),
            &crate::store::Holder::new(repo.namespace, repo.name),
            holder.seq,
            u64::try_from(T0).unwrap(),
        ))
        .unwrap()
    );
    let got = fx.get(&fx.object_url("room", &id(&d.manifest)));
    assert_eq!(got.status, 503);
    // Everything else is unaffected.
    assert_eq!(fx.get(&fx.object_url("room", &id(&d.small))).status, 200);
}

#[test]
fn a_pack_entry_over_the_inline_cap_is_a_503_with_a_metric() {
    let fx = fixture_with(
        Hooks::new(),
        HttpObjectsConfig {
            max_inline_object_bytes: EXTRACT_MIN + 10,
            ..http_cfg()
        },
    );
    let d = data();
    fx.push("room", &d.refs(), d.head(), None);
    // chunk 2 (30,000 bytes) is chunk-only: no extracted copy, over the cap.
    let got = fx.get(&fx.object_url("room", &id(&d.chunks[1])));
    assert_eq!(got.status, 503);
    assert_eq!(fx.metrics.count(METRIC_HTTP_INLINE_CAPPED), 1);
    // Small objects and extracted ones are unaffected.
    assert_eq!(fx.get(&fx.object_url("room", &id(&d.small))).status, 200);
    assert_eq!(fx.get(&fx.object_url("room", &id(&d.big))).status, 200);
}

#[test]
#[allow(clippy::too_many_lines)] // One table over every byte source.
fn ranges_and_conditionals_over_every_byte_source() {
    let (fx, d) = published();
    let whole = d.whole();
    // (URL, full content): an inline blob, an extracted blob, an extracted
    // manifest and the empty file.
    let sources = [
        (
            fx.ref_url("room", "main", "small.txt"),
            d.small_bytes.clone(),
        ),
        (fx.ref_url("room", "main", "big.bin"), d.big_bytes.clone()),
        (fx.ref_url("room", "main", "chunked.bin"), whole.clone()),
    ];
    for (url, content) in &sources {
        let n = content.len();
        let partial = |range: &str, start: usize, end: usize| {
            let got = fx.get_with(url, &[("range", range)]);
            assert_eq!(got.status, 206, "{url} {range}");
            assert_eq!(got.body, content[start..=end], "{url} {range}");
            assert_eq!(
                got.header("Content-Range"),
                Some(format!("bytes {start}-{end}/{n}").as_str())
            );
            assert_eq!(
                got.header("Content-Length"),
                Some((end - start + 1).to_string().as_str())
            );
            assert_eq!(got.header("Accept-Ranges"), Some("bytes"));
        };
        partial("bytes=10-19", 10, 19);
        partial("bytes=10-", 10, n - 1);
        partial("bytes=-10", n - 10, n - 1);
        partial(&format!("bytes=5-{}", n + 1_000), 5, n - 1);
        partial("bytes=0-0", 0, 0);
        // A multi-range request and an invalid one are strict 200s.
        for range in ["bytes=0-1,5-6", "bytes=5-2", "bytes=x-y", "pages=1-2"] {
            let got = fx.get_with(url, &[("range", range)]);
            assert_eq!((got.status, got.body.len()), (200, n), "{range}");
            assert_eq!(got.header("Content-Range"), None);
        }
        // Unsatisfiable: 416 with the size, `no-store`, no body.
        for range in [
            format!("bytes={n}-"),
            format!("bytes={}-{}", n + 5, n + 9),
            "bytes=-0".into(),
        ] {
            let got = fx.get_with(url, &[("range", &range)]);
            assert_eq!(got.status, 416, "{range}");
            assert_eq!(
                got.header("Content-Range"),
                Some(format!("bytes */{n}").as_str())
            );
            assert_eq!(got.header("Cache-Control"), Some("no-store"));
            assert!(got.body.is_empty());
        }
        // A weak `If-Range`, or one that does not match, gives the full 200; a
        // matching strong one slices.
        let strong = fx.get(url).header("ETag").unwrap().to_owned();
        for validator in [
            format!("W/{strong}"),
            "\"other\"".to_owned(),
            "Wed, 21 Oct 2015 07:28:00 GMT".to_owned(),
        ] {
            let got = fx.get_with(url, &[("range", "bytes=1-2"), ("if-range", &validator)]);
            assert_eq!((got.status, got.body.len()), (200, n), "{validator}");
        }
        let got = fx.get_with(url, &[("range", "bytes=1-2"), ("if-range", &strong)]);
        assert_eq!((got.status, got.body), (206, content[1..=2].to_vec()));
        // HEAD carries the same headers and no body.
        let head = read(fx.request("HEAD", url, None, &[("range", "bytes=1-2")]));
        assert_eq!((head.status, head.body.len()), (206, 0));
        assert_eq!(head.header("Content-Length"), Some("2"));
        assert_eq!(
            head.header("Content-Range"),
            Some(format!("bytes 1-2/{n}").as_str())
        );
        // 304: weak comparison, `*` and lists; before Range; repeating the 200's
        // validator and metadata headers.
        for header in [
            strong.clone(),
            format!("W/{strong}"),
            "*".into(),
            format!("\"x\", {strong}"),
        ] {
            let got = fx.get_with(
                url,
                &[("if-none-match", &header), ("range", "bytes=1000000-")],
            );
            assert_eq!(got.status, 304, "{header}");
            assert!(got.body.is_empty());
            let ok = fx.get(url);
            for name in [
                "ETag",
                "Cache-Control",
                "X-Mkit-Object",
                "X-Mkit-Object-Type",
                "X-Mkit-Commit",
            ] {
                assert_eq!(got.header(name), ok.header(name), "{name}");
            }
            assert_eq!(got.header("Content-Length"), None);
        }
        assert_eq!(
            fx.get_with(url, &[("if-none-match", "\"nope\"")]).status,
            200
        );
    }
    // A range across a chunk boundary of a manifest (chunk 1 is 60,000 bytes).
    let got = fx.get_with(&sources[2].0, &[("range", "bytes=59990-60010")]);
    assert_eq!(
        (got.status, got.body),
        (206, whole[59_990..=60_010].to_vec())
    );
    // Every range of the empty file is unsatisfiable, and it still serves.
    let empty = fx.ref_url("room", "main", "empty");
    assert_eq!(fx.get(&empty).status, 200);
    for range in ["bytes=0-0", "bytes=0-", "bytes=-1", "bytes=-0"] {
        let got = fx.get_with(&empty, &[("range", range)]);
        assert_eq!(got.status, 416, "{range}");
        assert_eq!(got.header("Content-Range"), Some("bytes */0"));
    }
    // An extracted read asks the store for exactly the selected range.
    fx.clear_calls();
    fx.get_with(&sources[1].0, &[("range", "bytes=100-199")]);
    assert_eq!(
        fx.blob_calls(BlobKey::object(id(&d.big))),
        vec!["head", "get"]
    );
}

#[test]
fn precedence_before_the_repository_is_looked_up() {
    let az = Arc::new(Scripted::default());
    let fx = fixture_with(scripted(&az), http_cfg());
    let d = data();
    fx.push("room", &d.refs(), d.head(), None);
    let url = fx.object_url("room", &id(&d.small));
    az.seen.lock().unwrap().clear();
    // Step 1: OPTIONS is 204 with no authorization, even for a bad URL.
    let got = read(fx.request("OPTIONS", "/not/a/route", None, &[]));
    assert_eq!(got.status, 204);
    assert_eq!(got.header("Allow"), Some("GET, HEAD, OPTIONS"));
    // Step 2: any other method is 405 before syntax is checked.
    for method in ["POST", "PUT", "DELETE", "PATCH", "get"] {
        let got = read(fx.request(method, "/malformed", None, &[]));
        assert_eq!(got.status, 405, "{method}");
        assert_eq!(got.header("Allow"), Some("GET, HEAD, OPTIONS"));
        assert_eq!(got.header("Cache-Control"), Some("no-store"));
    }
    // Step 3: syntax is 400 before the Authorizer or any lookup.
    for (path, query) in [
        ("/malformed", None),
        (url.as_str(), Some("")),
        (url.as_str(), Some("nope=1")),
        (url.as_str(), Some("range=1-2")),
    ] {
        let got = read(fx.request("GET", path, query, &[]));
        assert_eq!(got.status, 400, "{path} {query:?}");
        assert_eq!(got.header("Cache-Control"), Some("no-store"));
    }
    assert!(
        az.seen.lock().unwrap().is_empty(),
        "no hook call for a 400 or 405"
    );
    // Every response carries the security headers, errors included.
    for got in [
        fx.get("/malformed"),
        fx.get(&url),
        fx.get(&fx.object_url("room", &[1; 32])),
        read(fx.request("POST", &url, None, &[])),
        read(fx.request("OPTIONS", &url, None, &[])),
    ] {
        assert_eq!(got.header("X-Content-Type-Options"), Some("nosniff"));
        assert_eq!(
            got.header("Content-Security-Policy"),
            Some("sandbox; default-src 'none'")
        );
        assert_eq!(got.header("Referrer-Policy"), Some("no-referrer"));
    }
    // Step 6: the Authorizer runs for every read, as `anonymous`, whatever the
    // request carries, under the HTTP procedure names.
    az.seen.lock().unwrap().clear();
    fx.get_with(
        &url,
        &[
            ("authorization", "Bearer secret"),
            ("x-signature", "00"),
            ("x-repository", "other/repo"),
        ],
    );
    fx.get(&fx.ref_url("room", "main", "small.txt"));
    assert_eq!(
        *az.seen.lock().unwrap(),
        vec![
            (Procedure::HttpGetObject, "anonymous"),
            (Procedure::HttpGetRefPath, "anonymous"),
        ]
    );
}

#[test]
fn authorizer_errors_map_to_their_statuses() {
    let az = Arc::new(Scripted::default());
    let fx = fixture_with(scripted(&az), http_cfg());
    let d = data();
    fx.push("room", &d.refs(), d.head(), None);
    let url = fx.object_url("room", &id(&d.small));
    assert_eq!(fx.get(&url).status, 200);
    for (code, status) in [
        (Code::NotFound, 404),
        (Code::PermissionDenied, 403),
        // A public read has no credentials to lack: §3 only allows 403.
        (Code::Unauthenticated, 403),
        (Code::Unavailable, 503),
        (Code::Internal, 503),
        (Code::InvalidArgument, 503),
    ] {
        *az.verdict.lock().unwrap() = Some(code);
        let got = fx.get(&url);
        assert_eq!(got.status, status, "{code:?}");
        assert_eq!(got.header("Cache-Control"), Some("no-store"));
        if status == 404 {
            assert_uniform_404(&got);
        }
    }
}

// ---- seams -----------------------------------------------------------------

#[derive(Default)]
struct Gate {
    calls: Mutex<Vec<String>>,
}

impl crate::http_objects::TokenGate for Gate {
    fn precheck(
        &self,
        token: &crate::Redacted,
        _: i64,
    ) -> Result<crate::url_token::Prechecked, crate::url_token::TokenRejected> {
        self.calls.lock().unwrap().push(token.expose().to_owned());
        Err(crate::url_token::TokenRejected)
    }
    fn ttl_ms(&self) -> u64 {
        0
    }
}

#[test]
fn the_token_gate_runs_before_the_repository_lookup_and_a_public_repository_ignores_it() {
    let gate = Arc::new(Gate::default());
    let (fx, d) = published();
    let fx = Fx {
        pipe: fx.pipe.with_http_seams({
            let gate = gate.clone();
            move |mut seams| {
                seams.tokens = gate;
                seams
            }
        }),
        ..fx
    };
    let url = fx.object_url("room", &id(&d.small));
    // No token, no call.
    assert_eq!(fx.get(&url).status, 200);
    assert!(gate.calls.lock().unwrap().is_empty());
    // A failing precheck does not affect a public repository.
    let got = read(fx.request("GET", &url, Some("token=abc.def"), &[]));
    assert_eq!(got.status, 200);
    // It also runs for a repository that does not exist, before the lookup.
    let missing = format!(
        "/{}/-/objects/{}",
        fx.identity("missing"),
        to_hex(&id(&d.small))
    );
    assert_uniform_404(&read(fx.request("GET", &missing, Some("token=xyz"), &[])));
    assert_eq!(*gate.calls.lock().unwrap(), ["abc.def", "xyz"]);
}

struct Takedown {
    verdict: Mutex<fn() -> TakedownVerdict>,
    stops: Option<Hash>,
    seen: Mutex<Vec<Hash>>,
}

impl TakedownGate for Takedown {
    fn stops_descent(&self, _: &RepoId, id: &Hash) -> bool {
        self.stops == Some(*id)
    }

    fn check<'a>(
        &'a self,
        _: &'a RepoId,
        leaf: &'a Hash,
    ) -> crate::BoxFuture<'a, Result<TakedownVerdict, ServerError>> {
        self.seen.lock().unwrap().push(*leaf);
        let verdict = *self.verdict.lock().unwrap();
        Box::pin(async move { Ok(verdict()) })
    }
}

fn with_seams<H: HookSet>(
    fx: Fx<H>,
    edit: impl FnOnce(&mut crate::http_objects::HttpSeams),
) -> Fx<H> {
    Fx {
        pipe: fx.pipe.with_http_seams(|mut seams| {
            edit(&mut seams);
            seams
        }),
        ..fx
    }
}

#[test]
fn takedown_runs_after_reachability_and_before_a_304() {
    let (fx, d) = published();
    let gate = Arc::new(Takedown {
        verdict: Mutex::new(|| TakedownVerdict::Clear),
        stops: None,
        seen: Mutex::default(),
    });
    let fx = with_seams(fx, |s| s.takedown = gate.clone());
    let url = fx.object_url("room", &id(&d.small));
    assert_eq!(fx.get(&url).status, 200);
    assert_eq!(*gate.seen.lock().unwrap(), [id(&d.small)]);
    // An unreachable id never reaches the gate.
    gate.seen.lock().unwrap().clear();
    assert_uniform_404(&fx.get(&fx.object_url("room", &[9; 32])));
    assert!(gate.seen.lock().unwrap().is_empty());
    // A verdict of 404 and a 451 both beat a matching validator.
    let etag = format!("\"{}\"", to_hex(&id(&d.small)));
    for (verdict, status) in [
        (
            (|| TakedownVerdict::NotFound) as fn() -> TakedownVerdict,
            404,
        ),
        (
            || {
                TakedownVerdict::Respond(
                    HttpObjectResponse::error(451)
                        .with_header("Link", "<https://x.test>; rel=\"blocked-by\""),
                )
            },
            451,
        ),
    ] {
        *gate.verdict.lock().unwrap() = verdict;
        let got = fx.get_with(&url, &[("if-none-match", &etag)]);
        assert_eq!(got.status, status);
        assert_eq!(got.header("ETag"), None);
    }
}

#[test]
fn the_walk_stops_at_a_gated_object() {
    let (fx, d) = published();
    // Stopping at the root tree hides everything below it from id URLs.
    let gate = Arc::new(Takedown {
        verdict: Mutex::new(|| TakedownVerdict::Clear),
        stops: Some(id(&d.root)),
        seen: Mutex::default(),
    });
    let fx = with_seams(fx, |s| s.takedown = gate);
    assert_uniform_404(&fx.get(&fx.object_url("room", &id(&d.small))));
    // The root tree itself is a child of the commit, so it is still found.
    assert_eq!(fx.get(&fx.object_url("room", &id(&d.root))).status, 200);
}

struct Admit {
    seen: Mutex<Vec<(bool, bool, u64)>>,
    ended: Arc<Mutex<Vec<(u64, bool)>>>,
    challenge: bool,
}

impl HttpAdmission for Admit {
    fn admit<'a>(
        &'a self,
        request: &'a AdmitRequest<'a>,
    ) -> crate::BoxFuture<'a, Result<AdmitDecision, ServerError>> {
        self.seen
            .lock()
            .unwrap()
            .push((request.head, request.ref_path, request.declared_bytes));
        Box::pin(async move {
            if self.challenge {
                return Ok(AdmitDecision::Respond(
                    HttpObjectResponse::error(402).with_header("WWW-Authenticate", "Payment x"),
                ));
            }
            let ended = self.ended.clone();
            Ok(AdmitDecision::Allow(Admitted {
                private: true,
                headers: vec![("Payment-Receipt", "r".to_owned())],
                on_end: Some(Box::new(move |bytes, result| {
                    ended.lock().unwrap().push((bytes, result.is_ok()));
                })),
            }))
        })
    }
}

#[test]
fn admission_runs_after_304_and_416_and_reports_the_body_end() {
    let (fx, d) = published();
    let admit = Arc::new(Admit {
        seen: Mutex::default(),
        ended: Arc::default(),
        challenge: false,
    });
    let fx = with_seams(fx, |s| s.admission = admit.clone());
    let url = fx.ref_url("room", "main", "big.bin");
    let n = d.big_bytes.len();
    // 200: private, the receipt passes through, the hook sees every byte.
    let got = fx.get(&url);
    assert_eq!(got.status, 200);
    assert_eq!(got.header("Cache-Control"), Some("private, no-cache"));
    assert_eq!(got.header("Payment-Receipt"), Some("r"));
    assert_eq!(*admit.seen.lock().unwrap(), [(false, true, n as u64)]);
    assert_eq!(*admit.ended.lock().unwrap(), [(n as u64, true)]);
    // A range declares its own length; a HEAD declares the GET count but
    // reports zero bytes served.
    admit.seen.lock().unwrap().clear();
    admit.ended.lock().unwrap().clear();
    fx.get_with(&url, &[("range", "bytes=0-99")]);
    read(fx.request("HEAD", &url, None, &[]));
    assert_eq!(
        *admit.seen.lock().unwrap(),
        [(false, true, 100), (true, true, n as u64)]
    );
    assert_eq!(*admit.ended.lock().unwrap(), [(100, true), (0, true)]);
    // 304 and 416 never call it, and a 304 selects the private policy.
    admit.seen.lock().unwrap().clear();
    let etag = fx.get(&url).header("ETag").unwrap().to_owned();
    admit.seen.lock().unwrap().clear();
    let got = fx.get_with(&url, &[("if-none-match", &etag)]);
    assert_eq!(got.header("Cache-Control"), Some("private, no-cache"));
    assert_eq!(fx.get_with(&url, &[("range", "bytes=999999-")]).status, 416);
    assert!(admit.seen.lock().unwrap().is_empty());
    // A body dropped before its end reports what was sent and a failure.
    admit.ended.lock().unwrap().clear();
    let response = fx.request("GET", &url, None, &[]);
    drop(response);
    assert_eq!(*admit.ended.lock().unwrap(), [(0, false)]);
}

#[test]
fn an_admission_challenge_is_the_response_and_a_denial_is_a_403() {
    let (fx, d) = published();
    let admit = Arc::new(Admit {
        seen: Mutex::default(),
        ended: Arc::default(),
        challenge: true,
    });
    let fx = with_seams(fx, |s| s.admission = admit);
    let got = fx.get(&fx.object_url("room", &id(&d.small)));
    assert_eq!(got.status, 402);
    assert_eq!(got.header("WWW-Authenticate"), Some("Payment x"));
    assert_eq!(got.header("ETag"), None);
    assert_eq!(got.header("Cache-Control"), Some("no-store"));
}

type ProofCall = (Hash, ObjectType, Option<Hash>, bool, Option<(u64, u64)>);

struct Proofs(Mutex<Vec<ProofCall>>);

impl ProofServer for Proofs {
    fn serve<'a>(
        &'a self,
        request: &'a ProofRequest<'a>,
    ) -> crate::BoxFuture<'a, Result<HttpObjectResponse, ServerError>> {
        self.0.lock().unwrap().push((
            request.leaf,
            request.ty,
            request.commit,
            request.ref_path,
            request.query.range,
        ));
        Box::pin(async { Ok(HttpObjectResponse::new(200).with_header("Accept-Ranges", "none")) })
    }
}

#[test]
fn every_proof_request_goes_through_the_proof_seam_after_resolution() {
    let (fx, d) = published();
    let commit = to_hex(&d.head());
    let object = fx.object_url("room", &id(&d.manifest));
    let context = format!("proof=1&commit={commit}&path=chunked.bin");
    let range = format!("{context}&range=10-19");
    // The default answers 416 for every proof representation.
    for (path, query) in [
        (object.as_str(), context.as_str()),
        (object.as_str(), range.as_str()),
    ] {
        let got = read(fx.request("GET", path, Some(query), &[]));
        assert_eq!(got.status, 416, "{query}");
        assert_eq!(got.header("Cache-Control"), Some("no-store"));
    }
    let got = read(fx.request(
        "GET",
        &fx.ref_url("room", "main", "chunked.bin"),
        Some("proof=1"),
        &[],
    ));
    assert_eq!(got.status, 416);
    // Resolution still comes first: a miss is the uniform 404, never a proof.
    let missing = fx.object_url("room", &[3; 32]);
    assert_uniform_404(&read(fx.request("GET", &missing, Some(&context), &[])));
    // A proof server sees the resolved leaf, its type and the commit.
    let proofs = Arc::new(Proofs(Mutex::default()));
    let fx = with_seams(fx, |s| s.proofs = proofs.clone());
    let got = read(fx.request("GET", &object, Some(&range), &[]));
    assert_eq!(
        (got.status, got.header("Accept-Ranges")),
        (200, Some("none"))
    );
    fx.request(
        "GET",
        &fx.ref_url("room", "main", "big.bin"),
        Some("proof=1"),
        &[],
    );
    assert_eq!(
        *proofs.0.lock().unwrap(),
        [
            (
                id(&d.manifest),
                ObjectType::ChunkedBlob,
                None,
                false,
                Some((10, 19))
            ),
            (id(&d.big), ObjectType::Blob, Some(d.head()), true, None),
        ]
    );
}

struct Maintained;

impl crate::http_objects::Reachability for Maintained {
    fn known_reachable<'a>(
        &'a self,
        _: &'a RepoId,
        _: &'a Hash,
        _: u64,
    ) -> crate::BoxFuture<'a, Result<bool, ServerError>> {
        Box::pin(async { Ok(true) })
    }

    fn record(&self, _: &RepoId, _: &Hash, _: u64) {}

    fn invalidate(&self, _: &RepoId) {}
}

#[test]
fn a_maintained_reachable_set_replaces_the_walk_but_not_membership() {
    let fx = fixture();
    let d = data();
    let pack = fx.push("room", &d.refs(), d.head(), None);
    let (objects, _, head) = rewound();
    let refs: Vec<_> = objects.iter().collect();
    fx.push("room", &refs, id(&head), Some((d.head(), pack)));
    assert_uniform_404(&fx.get(&fx.object_url("room", &id(&d.small))));
    let fx = with_seams(fx, |s| s.reachability = Arc::new(Maintained));
    assert_eq!(fx.get(&fx.object_url("room", &id(&d.small))).status, 200);
    // A non-member is a 404 whatever the set says.
    assert_uniform_404(&fx.get(&fx.object_url("room", &[5; 32])));
}

fn pieces(response: HttpObjectResponse) -> Vec<Result<usize, Code>> {
    let HttpBody::Stream { stream, .. } = response.body else {
        panic!("expected a streamed body");
    };
    block_on(async move {
        let mut stream = stream;
        let mut out = Vec::new();
        while let Some(piece) = stream.next().await {
            out.push(piece.map(|b| b.len()).map_err(|e| e.code()));
        }
        out
    })
}

#[test]
fn an_extracted_body_is_length_checked_and_read_one_piece_at_a_time() {
    let (fx, d) = published();
    let url = fx.ref_url("room", "main", "big.bin");
    let n = d.big_bytes.len();
    // A backend that returns one byte too few or too many fails the body,
    // never a silently wrong one.
    *fx.pipe.blobs.reads.lock().unwrap() = Reads::Short;
    let short = pieces(fx.request("GET", &url, None, &[]));
    assert_eq!(short, vec![Ok(n - 1), Err(Code::Unavailable)]);
    *fx.pipe.blobs.reads.lock().unwrap() = Reads::Long;
    assert_eq!(
        pieces(fx.request("GET", &url, None, &[])),
        vec![Err(Code::Unavailable)]
    );
    // A failing read is a 503 before any header is promised.
    *fx.pipe.blobs.reads.lock().unwrap() = Reads::Fails;
    assert_eq!(fx.get(&url).status, 503);
    // The wrapper never reads ahead: one backend piece per piece consumed.
    *fx.pipe.blobs.reads.lock().unwrap() = Reads::Pieces;
    let response = fx.request("GET", &url, None, &[]);
    let HttpBody::Stream { len, mut stream } = response.body else {
        panic!("expected a stream");
    };
    assert_eq!(len, n as u64);
    let produced = || {
        fx.pipe
            .blobs
            .produced
            .load(std::sync::atomic::Ordering::SeqCst)
    };
    assert_eq!(produced(), 0);
    let first = block_on(stream.next()).unwrap().unwrap();
    assert_eq!((first.len(), produced()), (65_536, 1));
    let second = block_on(stream.next()).unwrap().unwrap();
    assert_eq!((second.len(), produced()), (n - 65_536, 2));
    assert!(block_on(stream.next()).is_none());
    // A stream whose declared length disagrees is refused at open: 503.
    *fx.pipe.blobs.reads.lock().unwrap() = Reads::Normal;
    assert_eq!(fx.get(&url).status, 200);
}

#[test]
fn a_body_that_cannot_open_after_admission_reports_the_failure() {
    let (fx, _) = published();
    let admit = Arc::new(Admit {
        seen: Mutex::default(),
        ended: Arc::default(),
        challenge: false,
    });
    let fx = with_seams(fx, |s| s.admission = admit.clone());
    *fx.pipe.blobs.reads.lock().unwrap() = Reads::Fails;
    assert_eq!(fx.get(&fx.ref_url("room", "main", "big.bin")).status, 503);
    assert_eq!(*admit.ended.lock().unwrap(), [(0, false)]);
}

// ---- private repositories, credentials, configuration ------------------------

#[test]
fn a_private_repository_is_invisible_whatever_the_request_carries() {
    let (fx, d) = published();
    fx.make_private("room");
    let url = fx.object_url("room", &id(&d.small));
    for headers in [
        vec![],
        vec![("authorization", "Bearer x")],
        vec![("x-write-grant", "abc"), ("x-public-key", "00")],
    ] {
        assert_uniform_404(&fx.get_with(&url, &headers));
    }
    assert_uniform_404(&fx.get(&fx.ref_url("room", "main", "small.txt")));
}

#[test]
fn the_feature_needs_indexed_mode_and_sane_limits() {
    let owner = key(7);
    let namespace = Namespace::Ed25519(*owner.verifying_key().as_bytes());
    let base = || {
        let mut config = cfg(authv2());
        config.addressing = Addressing::Multi(
            MultiAddressing::new()
                .with_namespace_policy(NamespacePolicy::Allowlist([namespace].into())),
        );
        config.write_policy = WritePolicy::Owner;
        config.ticket_keys =
            Some(crate::upload::token::TicketKeys::new(vec![("test".into(), [7; 32])]).unwrap());
        config
    };
    let build = |config: PipelineConfig| {
        let clock = clock();
        Pipeline::new(
            MemoryBlobStore::default(),
            store(&clock),
            Hooks::new(),
            config,
            clock,
            Arc::new(crate::telemetry::NoopMetrics),
        )
        .map(|_| ())
    };
    // Off by default, and refused without indexed mode.
    assert!(base().http_objects.is_none());
    assert!(build(base()).is_ok());
    let mut config = base();
    config.http_objects = Some(http_cfg());
    assert_eq!(
        build(config).unwrap_err().public_message(),
        "HTTP object serving requires indexed mode"
    );
    let min = crate::indexed::IndexedConfig::default().extract_min_bytes;
    for limits in [
        HttpObjectsConfig {
            read_deadline: Duration::ZERO,
            ..http_cfg()
        },
        HttpObjectsConfig {
            read_reconcile_grace: Duration::ZERO,
            ..http_cfg()
        },
        HttpObjectsConfig {
            max_walk_objects: 0,
            ..http_cfg()
        },
        HttpObjectsConfig {
            reachability_lag_ms: 0,
            ..http_cfg()
        },
        HttpObjectsConfig {
            reach_cache_entries: 0,
            ..http_cfg()
        },
        HttpObjectsConfig {
            max_inline_object_bytes: min + 9,
            ..http_cfg()
        },
        HttpObjectsConfig {
            http_decode_budget: http_cfg().max_inline_object_bytes - 1,
            ..http_cfg()
        },
    ] {
        let mut config = base();
        config.indexed = Some(crate::indexed::IndexedConfig::default());
        config.http_objects = Some(limits);
        assert_eq!(
            build(config).unwrap_err().public_message(),
            "invalid HTTP object limits"
        );
    }
    let mut config = base();
    config.indexed = Some(crate::indexed::IndexedConfig::default());
    config.http_objects = Some(HttpObjectsConfig {
        max_inline_object_bytes: min + 10,
        ..http_cfg()
    });
    assert!(build(config).is_ok());
    // Without the configuration a pipeline answers no route at all.
    let plain = env(AuthMode::Open);
    let pipe = Pipeline::new(
        plain.pipe.blobs,
        Arc::new(plain.pipe.meta),
        plain.pipe.hooks,
        plain.pipe.cfg,
        plain.pipe.clock,
        plain.pipe.metrics,
    )
    .unwrap();
    let response = block_on(pipe.serve_http_object(&HttpObjectRequest {
        method: "GET",
        raw_path: "/-/refs/heads/main/-/",
        raw_query: None,
        headers: &|_| Vec::new(),
        header_names: &[],
    }));
    assert_eq!(response.status, 404);
}

// ---- redaction ---------------------------------------------------------------

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<String>>);

struct Fields<'a>(&'a Mutex<String>);

impl tracing::field::Visit for Fields<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn core::fmt::Debug) {
        use std::fmt::Write as _;
        let _ = write!(self.0.lock().unwrap(), "{}={value:?} ", field.name());
    }
}

impl tracing::Subscriber for Capture {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, attrs: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        attrs.record(&mut Fields(&self.0));
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, values: &tracing::span::Record<'_>) {
        values.record(&mut Fields(&self.0));
    }
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        use std::fmt::Write as _;
        let _ = write!(self.0.lock().unwrap(), "{} ", event.metadata().name());
        event.record(&mut Fields(&self.0));
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

#[test]
fn a_token_and_the_raw_query_never_reach_a_log_line_or_a_response() {
    const SECRET: &str = "s3cr3t-token-value";
    let capture = Capture::default();
    // Another dispatcher registers callsites against every subscriber, so a
    // callsite first reached by a concurrent test is not cached as disabled.
    let _idle = tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default());
    let mut rendered = String::new();
    tracing::subscriber::with_default(capture.clone(), || {
        use std::fmt::Write as _;
        tracing::callsite::rebuild_interest_cache();
        let (fx, d) = published();
        let query = format!("token={SECRET}");
        let secret_path = format!("/{}/-/refs/heads/main/-/small.txt", fx.identity("room"));
        let missing = format!(
            "/{}/-/objects/{}",
            fx.identity("nope"),
            to_hex(&id(&d.small))
        );
        let broken = format!("{secret_path}%ZZ");
        fx.make_private("room");
        // Success, every kind of miss, a private repository, a bad URL, an
        // unauthorized hook and a broken store all carry the token.
        for path in [
            &secret_path,
            &missing,
            &broken,
            &fx.object_url("room", &id(&d.big)),
        ] {
            let response = fx.request("GET", path, Some(&query), &[("authorization", SECRET)]);
            write!(rendered, "{response:?} ").unwrap();
        }
        let az = Arc::new(Scripted::default());
        let hooked = fixture_with(scripted(&az), http_cfg());
        hooked.push("room", &d.refs(), d.head(), None);
        *az.verdict.lock().unwrap() = Some(Code::Unavailable);
        let response = hooked.request(
            "GET",
            &hooked.object_url("room", &id(&d.small)),
            Some(&query),
            &[],
        );
        write!(rendered, "{response:?}").unwrap();
    });
    let logs = capture.0.lock().unwrap().clone();
    assert!(!logs.is_empty(), "the request path logs");
    for text in [&logs, &rendered] {
        assert!(!text.contains(SECRET), "a token reached {text}");
        assert!(!text.contains("token="));
        assert!(!text.contains("small.txt"), "a request path reached a log");
    }
}

// ---- the golden response rows ------------------------------------------------

const RESPONSES: &str =
    include_str!("../../../../../tests/golden/http-objects/response-cases.json");
const GOLDEN_LEAF: &str = "b0145b689c72cfb1b8b1e7ec756c2c4a1e0b4f0469393e4ff4a30d8c3d6a0d6f";
const GOLDEN_COMMIT: &str = "1d8c6225d142427a5791e289bb616393f299292880d59b43cbbebcb6d2c9b145";

/// Rows this work package does not decide: CORS (WP-4.16), bearer gating and
/// the key document (WP-4.16 and the deployment mode), private and token
/// paths (WP-4.15), Admission (WP-4.13), proofs (WP-4.14b), takedown
/// (WP-5.9a) and redirects (WP-4.16).
const OTHER_WORK_PACKAGES: &[&str] = &[
    "preflight_before_auth",
    "syntax_before_bearer",
    "bearer_before_repo",
    "private_missing_token",
    "private_invalid_token",
    "unreachable_commit",
    "wrong_leaf",
    "tombstone_before_304_and_admission",
    "tombstone_head_no_body",
    "global_block_without_repository_tombstone",
    "blocked_before_tombstone_before_304",
    "chunk_only_under_tombstoned_manifest",
    "chunk_only_under_blocked_untombstoned_manifest",
    "not_modified_proof_paid_policy",
    "bearer_gated_public_id",
    "outside_content",
    "proof_content_cap",
    "proof_encoded_cap",
    "unsupported_leaf",
    "challenge",
    "admission_deny",
    "private_id",
    "private_ref",
    "paid",
    "paid_ref",
    "head",
    "proof_object",
    "proof_ref",
    "proof_blob_range",
    "proof_span",
    "proof_private",
    "proof_paid",
    "receipt",
    "public_redirect",
    "admitted_ref_served_directly",
    "cors_configured",
    "key_document_exempt",
];

/// What a row's placeholders stand for in this fixture.
struct Row {
    leaf: Hash,
    size: usize,
}

fn substitute(value: &str, row: &Row, head: &Hash) -> String {
    let value = value
        .replace(GOLDEN_LEAF, &to_hex(&row.leaf))
        .replace(GOLDEN_COMMIT, &to_hex(head));
    if value == "100" {
        row.size.to_string()
    } else if value.ends_with("/100") {
        value.replace("/100", &format!("/{}", row.size))
    } else {
        value
    }
}

#[test]
#[allow(clippy::too_many_lines)] // One arm per golden row.
fn the_golden_response_rows_hold() {
    let table: serde_json::Value = serde_json::from_str(RESPONSES).unwrap();
    let (fx, d) = published();
    let small = Row {
        leaf: id(&d.small),
        size: 100,
    };
    let (mut uniform, mut covered) = (Vec::<Got>::new(), Vec::<String>::new());
    for case in table["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        if OTHER_WORK_PACKAGES.contains(&name) {
            continue;
        }
        let request = &case["request"];
        let etag = format!("\"{}\"", to_hex(&id(&d.small)));
        let by_id = fx.object_url("room", &id(&d.small));
        let by_ref = fx.ref_url("room", "main", "small.txt");
        let route_is_ref = request["route"] == "ref";
        let target = if route_is_ref {
            by_ref.clone()
        } else {
            by_id.clone()
        };
        let with_range = |headers: &[(&str, &str)]| fx.get_with(&target, headers);
        let mut row = Row {
            leaf: small.leaf,
            size: 100,
        };
        let got = match name {
            "method_before_syntax" => read(fx.request("POST", "/malformed", None, &[])),
            "missing_repository" => fx.get_with(
                &format!(
                    "/{}/-/objects/{}",
                    fx.identity("missing"),
                    to_hex(&id(&d.small))
                ),
                &[("if-none-match", &etag), ("payment-authorization", "x")],
            ),
            "authorizer_private" => {
                let private = fixture();
                private.push("room", &d.refs(), d.head(), None);
                private.make_private("room");
                private.get_with(
                    &private.object_url("room", &id(&d.small)),
                    &[("if-none-match", &etag)],
                )
            }
            "authorizer_not_found" | "authorizer_public" | "infrastructure_failure" => {
                let az = Arc::new(Scripted::default());
                let hooked = fixture_with(scripted(&az), http_cfg());
                hooked.push("room", &d.refs(), d.head(), None);
                *az.verdict.lock().unwrap() = Some(match name {
                    "authorizer_not_found" => Code::NotFound,
                    "authorizer_public" => Code::PermissionDenied,
                    _ => Code::Unavailable,
                });
                hooked.get_with(
                    &hooked.object_url("room", &id(&d.small)),
                    &[("if-none-match", &etag)],
                )
            }
            "missing_ref" => fx.get_with(
                &fx.ref_url("room", "gone", "x"),
                &[("if-none-match", &etag)],
            ),
            "non_tree" => fx.get_with(
                &fx.ref_url("room", "main", "small.txt/x"),
                &[("if-none-match", &etag)],
            ),
            "missing_entry" => fx.get_with(
                &fx.ref_url("room", "main", "absent"),
                &[("if-none-match", &etag)],
            ),
            "nonmember" | "unreachable_id" | "pending" => fx.get_with(
                &fx.object_url("room", &[7; 32]),
                &[("if-none-match", &etag)],
            ),
            "public_token_ignored" => read(fx.request("GET", &by_id, Some("token=nope"), &[])),
            "unsatisfiable_before_admission" => with_range(&[("range", "bytes=100-200")]),
            "not_modified_before_range_admission" => {
                let admit = Arc::new(Admit {
                    seen: Mutex::default(),
                    ended: Arc::default(),
                    challenge: true,
                });
                let paid = with_seams(fixture(), |s| s.admission = admit.clone());
                paid.push("room", &d.refs(), d.head(), None);
                let got = paid.get_with(
                    &paid.ref_url("room", "main", "small.txt"),
                    &[("if-none-match", &etag), ("range", "bytes=200-300")],
                );
                assert!(admit.seen.lock().unwrap().is_empty());
                got
            }
            "not_modified_paid_policy" => {
                let paid = with_seams(fixture(), |s| s.admission = Arc::new(Loose));
                paid.push("room", &d.refs(), d.head(), None);
                paid.get_with(
                    &paid.object_url("room", &id(&d.small)),
                    &[("if-none-match", &etag)],
                )
            }
            "public_id" | "public_ref" => fx.get(&target),
            "chunked_content" => {
                row = Row {
                    leaf: id(&d.manifest),
                    size: 95_000,
                };
                fx.get(&fx.object_url("room", &id(&d.manifest)))
            }
            "canonical_tree" => {
                row = Row {
                    leaf: id(&d.root),
                    size: serialize(&d.root).unwrap().len(),
                };
                fx.get(&fx.object_url("room", &id(&d.root)))
            }
            "single_range" => with_range(&[("range", "bytes=10-19")]),
            "if_range_match" => with_range(&[("range", "bytes=10-19"), ("if-range", &etag)]),
            "if_range_miss" => {
                with_range(&[("range", "bytes=10-19"), ("if-range", "\"different\"")])
            }
            "multi_range" => with_range(&[("range", "bytes=0-1,5-6")]),
            other => {
                panic!("golden row {other} is neither covered nor assigned to another work package")
            }
        };
        assert_eq!(got.status, case["expect"]["status"], "{name}");
        for (header, want) in case["expect"]["headers"].as_object().unwrap() {
            // CORS is WP-4.16's: the handler leaves it to the mount.
            if header.starts_with("Access-Control") {
                continue;
            }
            // Ranged and conditional rows use the golden 100-byte size for the
            // small blob; Cache-Control for a configured Admission is private.
            let want = substitute(want.as_str().unwrap(), &row, &d.head());
            assert_eq!(got.header(header), Some(want.as_str()), "{name}: {header}");
        }
        for absent in case["expect"]["absent_headers"].as_array().unwrap() {
            let absent = absent.as_str().unwrap();
            let prefix = absent.strip_suffix('*');
            assert!(
                !got.headers.iter().any(|(n, _)| prefix.map_or_else(
                    || n.eq_ignore_ascii_case(absent),
                    |p| n.to_ascii_lowercase().starts_with(&p.to_ascii_lowercase()),
                )),
                "{name}: {absent} must be absent"
            );
        }
        if case["expect"]["body_equivalence_group"] == "uniform_404" {
            uniform.push(got);
        }
        covered.push(name.to_owned());
    }
    // Every row is either checked here or handed to the work package that
    // owns it: a new row cannot slip in unclassified.
    for case in table["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        assert!(
            covered.iter().any(|c| c == name) || OTHER_WORK_PACKAGES.contains(&name),
            "{name}"
        );
    }
    assert_eq!((covered.len(), uniform.len()), (24, 9));
    for got in &uniform[1..] {
        assert_eq!(
            (got.status, &got.headers, &got.body),
            (uniform[0].status, &uniform[0].headers, &uniform[0].body)
        );
    }
}

// ---- review fixes ------------------------------------------------------------

/// Reachable only through a subtree that a cap or the decode budget hides
/// from the walk's first pass: `(fx, target)` under the given limits.
fn deep_target(http: HttpObjectsConfig, files: usize, oversized: bool) -> (Fx, Hash, Hash) {
    let fx = fixture_with(Hooks::new(), http);
    let target = blob(&pattern(20, 31));
    let below = tree(&[("target", EntryMode::Blob, &target)]);
    let filler: Vec<Object> = (0..files)
        .map(|i| blob(&[u8::try_from(i).unwrap(); 3]))
        .collect();
    let names: Vec<String> = (0..files).map(|i| format!("f{i:03}")).collect();
    // 22 + 32 * 200 bytes as a Blob's canonical form (10 + 6,412): the size
    // of a manifest of 200 chunks, larger than the budget below.
    let manifest_sized = blob(&pattern(6_412, 32));
    let mut entries: Vec<(&str, EntryMode, &Object)> = filler
        .iter()
        .zip(&names)
        .map(|(f, n)| (n.as_str(), EntryMode::Blob, f))
        .collect();
    if oversized {
        entries.push(("a-oversized", EntryMode::Blob, &manifest_sized));
    }
    entries.push(("zz", EntryMode::Tree, &below));
    entries.sort_by(|a, b| a.0.cmp(b.0));
    let root = tree(&entries);
    let head = commit(&root, &[], "deep");
    let mut objects: Vec<&Object> = filler.iter().collect();
    objects.extend([&target, &below, &root, &head]);
    if oversized {
        objects.push(&manifest_sized);
    }
    fx.push("room", &objects, id(&head), None);
    let sibling = id(filler.first().unwrap_or(&target));
    (fx, id(&target), sibling)
}

#[test]
fn an_object_the_budget_cannot_afford_does_not_abort_the_walk() {
    // A manifest-sized file bigger than the decode budget is skipped; the
    // walk still finds the target in the sibling subtree.
    let http = HttpObjectsConfig {
        max_inline_object_bytes: EXTRACT_MIN + 10,
        http_decode_budget: 4_096,
        ..http_cfg()
    };
    let (fx, target, _) = deep_target(http, 3, true);
    assert_eq!(fx.get(&fx.object_url("room", &target)).status, 200);
    assert_eq!(fx.metrics.count(METRIC_HTTP_REACH_CAPPED), 0);
}

#[test]
fn a_wide_tree_is_bounded_by_the_walk_cap_but_never_hides_a_direct_child() {
    let http = HttpObjectsConfig {
        max_walk_objects: 6,
        ..http_cfg()
    };
    let (fx, target, sibling) = deep_target(http, 30, false);
    // The subtree past the cap is never queued: a capped 404 and a metric.
    assert_uniform_404(&fx.get(&fx.object_url("room", &target)));
    assert_eq!(fx.metrics.count(METRIC_HTTP_REACH_CAPPED), 1);
    // A direct child of a decoded tree is compared even when it is not queued.
    assert_eq!(fx.get(&fx.object_url("room", &sibling)).status, 200);
    // The same repository is fully walkable under the default cap.
    let (open, target, _) = deep_target(http_cfg(), 30, false);
    assert_eq!(open.get(&open.object_url("room", &target)).status, 200);
}

#[test]
fn the_authorizer_runs_for_an_anonymous_read_under_the_authority_role_too() {
    let az = Arc::new(Scripted::default());
    let fx = fixture_tweaked(scripted(&az), http_cfg(), |config| {
        config.authorizer_role = AuthorizerRole::Authority;
    });
    let d = data();
    fx.push("room", &d.refs(), d.head(), None);
    az.seen.lock().unwrap().clear();
    let url = fx.object_url("room", &id(&d.small));
    assert_eq!(fx.get(&url).status, 200);
    assert_eq!(
        *az.seen.lock().unwrap(),
        vec![(Procedure::HttpGetObject, "anonymous")]
    );
    *az.verdict.lock().unwrap() = Some(Code::PermissionDenied);
    assert_eq!(fx.get(&url).status, 403);
    *az.verdict.lock().unwrap() = Some(Code::NotFound);
    assert_uniform_404(&fx.get(&url));
}

#[test]
fn repeated_validators_never_widen_a_response() {
    let (fx, d) = published();
    let url = fx.ref_url("room", "main", "small.txt");
    let etag = fx.get(&url).header("ETag").unwrap().to_owned();
    // Two If-Range headers are not one matching strong validator: full 200.
    let got = fx.get_with(
        &url,
        &[
            ("range", "bytes=1-2"),
            ("if-range", &etag),
            ("if-range", "\"other\""),
        ],
    );
    assert_eq!((got.status, got.body.len()), (200, d.small_bytes.len()));
    // Two Range headers are ignored the same way.
    let got = fx.get_with(&url, &[("range", "bytes=1-2"), ("range", "bytes=3-4")]);
    assert_eq!((got.status, got.body.len()), (200, d.small_bytes.len()));
}

/// An admission that allows without asking for `private`: a configured
/// Admission still makes every success private (§5.3).
struct Loose;

impl HttpAdmission for Loose {
    fn admit<'a>(
        &'a self,
        _: &'a AdmitRequest<'a>,
    ) -> crate::BoxFuture<'a, Result<AdmitDecision, ServerError>> {
        Box::pin(async { Ok(AdmitDecision::Allow(Admitted::default())) })
    }
}

#[test]
fn a_configured_admission_makes_the_200_and_its_304_private_alike() {
    let (fx, d) = published();
    let fx = with_seams(fx, |s| s.admission = Arc::new(Loose));
    for url in [
        fx.object_url("room", &id(&d.small)),
        fx.ref_url("room", "main", "small.txt"),
    ] {
        let ok = fx.get(&url);
        let etag = ok.header("ETag").unwrap().to_owned();
        let cached = fx.get_with(&url, &[("if-none-match", &etag)]);
        assert_eq!((ok.status, cached.status), (200, 304));
        assert!(ok.header("Cache-Control").unwrap().starts_with("private,"));
        assert_eq!(ok.header("Cache-Control"), cached.header("Cache-Control"));
    }
}

mod paid_reads;
mod private_tokens;

struct ServingStop(Arc<AtomicBool>);
impl clearance::PublicationPolicy for ServingStop {
    fn prepare<'a>(
        &'a self,
        _: &'a Operation,
        value: &'a crate::store::publication::Pair,
    ) -> crate::BoxFuture<'a, Result<crate::store::publication::Advance, ServerError>> {
        Box::pin(async move { Ok(clearance::immediate(value.clone(), [0; 32], vec![])) })
    }
    fn pack_available(&self, _: &RepoId, _: &Hash) -> bool {
        !self.0.load(Ordering::SeqCst)
    }
}

#[test]
fn held_serving_stop_overrides_warm_reachability_extracted_bytes_and_proofs() {
    let (mut fx, d) = published();
    let stopped = Arc::new(AtomicBool::new(false));
    fx.pipe = fx
        .pipe
        .with_publication_policy(Arc::new(ServingStop(stopped.clone())))
        .unwrap();
    let proofs = Arc::new(Proofs(Mutex::new(Vec::new())));
    let fx = with_seams(fx, |s| s.proofs = proofs.clone());
    for object in [&d.small, &d.big, &d.manifest] {
        assert_eq!(fx.get(&fx.object_url("room", &id(object))).status, 200);
    }
    assert_eq!(fx.get(&fx.ref_url("room", "main", "small.txt")).status, 200);
    stopped.store(true, Ordering::SeqCst);
    for path in [
        fx.object_url("room", &id(&d.small)),
        fx.object_url("room", &id(&d.big)),
        fx.object_url("room", &id(&d.manifest)),
        fx.ref_url("room", "main", "small.txt"),
    ] {
        for method in ["GET", "HEAD"] {
            let got = read(fx.request(method, &path, None, &[("if-none-match", "*")]));
            assert_eq!(got.status, 404);
            assert_eq!(got.header("Cache-Control"), Some("no-store"));
            assert_eq!(got.header("ETag"), None);
        }
    }
    assert_eq!(
        read(fx.request(
            "GET",
            &fx.ref_url("room", "main", "small.txt"),
            Some("proof=1"),
            &[]
        ))
        .status,
        404
    );
    assert!(proofs.0.lock().unwrap().is_empty());
}

mod takedown_denial;
