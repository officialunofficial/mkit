use super::intent::*;
use super::*;
use crate::pipeline::SinglePartition;
use crate::{MemoryKv, NamespaceKey, NamespaceStore, Partition};
use serde_json::json;
use std::sync::Arc;

fn service() -> Service<Arc<MemoryKv>> {
    Service::new(
        Arc::new(MemoryKv::with_clock(Arc::new(crate::ManualClock::new(10)))),
        Partition::Namespace(NamespaceKey::deployment_default()),
        Arc::new(SinglePartition),
    )
}
#[test]
fn strict_registered_and_deployment_reason_tokens() {
    for token in [
        "legal",
        "policy",
        "malware",
        "abuse",
        "manual",
        "x-restricted.1",
    ] {
        assert!(reason_token(token));
    }
    for token in [
        "other",
        "Manual",
        "x-",
        "x-CAPITAL",
        "x-private_reason",
        "x-contains space",
    ] {
        assert!(!reason_token(token));
    }
}
#[test]
fn selector_is_exactly_named_ids_or_one_whole_pack() {
    let named = json!({"repository":"root/repo","objectIds":[base64::Engine::encode(&base64::engine::general_purpose::STANDARD,[1u8;32])],"operationId":"one","reason":"policy review"});
    assert!(Request::parse(&named).is_ok());
    let mut both = named.clone();
    both["packId"] = named["objectIds"][0].clone();
    assert!(Request::parse(&both).is_err());
    let mut duplicate = named.clone();
    duplicate["objectIds"] = json!([named["objectIds"][0], named["objectIds"][0]]);
    assert!(Request::parse(&duplicate).is_err());
    let pack = json!({"repository":"root/repo","packId":named["objectIds"][0],"operationId":"whole","reason":"review"});
    assert!(Request::parse(&pack).is_ok());
}
#[tokio::test]
async fn retry_before_acceptance_keeps_creation_time_and_rejects_changed_payload() {
    let service = service();
    let id = [5u8; 32];
    let first = service
        .draft(&service.store, id, "body:first", 10)
        .await
        .unwrap();
    let retry = service
        .draft(&service.store, id, "body:first", 200)
        .await
        .unwrap();
    assert_eq!(first.created, retry.created);
    assert!(
        service
            .draft(&service.store, id, "body:changed", 201)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn accepted_action_activates_from_staged_headers_without_source_reread() {
    use crate::indexed::budget::SliceBudget;
    use crate::store::{BorrowedStore, content_shard};
    use crate::{Batch, BatchOutcome, ContentIndex, Value};
    use mkit_core::hash::hash;
    let service = service();
    let id = [7u8; 32];
    let object = [8u8; 32];
    let action = denial::BlockAction {
        id: hash(&[id.as_slice(), object.as_slice()].concat()),
        takedown_id: id,
        reason: "policy".into(),
        blocked_at_ms: 10,
        chunk_ids: Vec::new(),
    };
    let staged = denial::stage_action(&service.store, &object, &action, 10)
        .await
        .unwrap();
    let bytes = serde_json::to_vec(&staged).unwrap();
    let root = Partition::Namespace(NamespaceKey::deployment_default());
    service
        .store
        .apply(
            &content_shard(&object),
            Batch::new().put(staged_key(&object, &id), Value::new(bytes.clone())),
        )
        .await
        .unwrap();
    let record = json!({"version":1,"id":id,"digest":"body:accepted","operation":"accepted","repository":"root/repo",
        "reason":"private","reason_token":"policy","created":10,"pack":null,
        "actions":[{"object":object,"descriptor_hash":hash(&bytes)}],"activation_cursor":0,"preservation_pending":true});
    assert_eq!(
        service
            .store
            .apply(
                &root,
                Batch::new().put(
                    request_key(&id),
                    Value::new(record.to_string().into_bytes())
                )
            )
            .await
            .unwrap(),
        BatchOutcome::Committed
    );
    // No blob backend or original inventory source is present. Only the
    // immutable accepted descriptor remains, as after source loss.
    service
        .resume(id, 11, &SliceBudget::new(crate::limits::REQUEST_CALLS))
        .await
        .unwrap();
    service
        .resume(id, 12, &SliceBudget::new(crate::limits::REQUEST_CALLS))
        .await
        .unwrap();
    assert!(
        ContentIndex::new(BorrowedStore(&service.store))
            .blocked(&object)
            .await
            .unwrap()
            .is_some()
    );
    let raw = service
        .store
        .get(&root, &request_key(&id))
        .await
        .unwrap()
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(raw.as_bytes()).unwrap();
    assert_eq!(value["activation_cursor"], 1);
    assert_eq!(value["preservation_pending"], true);
}

#[tokio::test]
async fn whole_pack_over_256_objects_is_one_pending_action() {
    use crate::admin::AdminOperations;
    use crate::indexed::budget::SliceBudget;
    use crate::pipeline::ShardMap;
    use crate::store::keys;
    use crate::{Batch, BlobKey, Value};
    use mkit_core::{
        hash::hash,
        object::{Blob, Object},
        pack::PackWriter,
        serialize::serialize,
    };
    let service = service();
    let mut writer = PackWriter::new_raw_only();
    let mut objects = Vec::new();
    for n in 0u32..300 {
        let object = Object::Blob(Blob {
            data: n.to_le_bytes().to_vec(),
        });
        let bytes = serialize(&object).unwrap();
        let id = hash(&bytes);
        writer.push_raw(id, &bytes).unwrap();
        objects.push((id, object));
    }
    let pack = writer.finish().unwrap();
    let id = hash(&pack);
    for (object_id, object) in &objects {
        inventory::stage(
            &service.store,
            &id,
            pack.len() as u64,
            object_id,
            object,
            None,
            10,
        )
        .await
        .unwrap();
    }
    inventory::complete(&service.store, &id, pack.len() as u64, 10)
        .await
        .unwrap();
    let repository = crate::RepoId {
        namespace: NamespaceKey::deployment_default(),
        name: crate::RepoName::new("repo").unwrap(),
    };
    let partition = SinglePartition.membership(&repository, &BlobKey::pack(id));
    service
        .store
        .apply(
            &partition,
            Batch::new().put(keys::membership(&repository.name, &id), Value::default()),
        )
        .await
        .unwrap();
    let input = json!({"repository":"root/repo","packId":base64::Engine::encode(&base64::engine::general_purpose::STANDARD,id),"operationId":"whole-300","reason":"private","reasonToken":"policy"});
    let budget = SliceBudget::new(crate::limits::REQUEST_CALLS);
    let prepared = service
        .plan(
            crate::admin::TAKEDOWN_PATH,
            &input,
            "body:whole",
            11,
            &budget,
        )
        .await
        .unwrap();
    let response = prepared.response.clone();
    service
        .store
        .apply(
            &Partition::Namespace(NamespaceKey::deployment_default()),
            prepared.batch,
        )
        .await
        .unwrap();
    let response = service
        .after_commit(crate::admin::TAKEDOWN_PATH, &input, response, 11, &budget)
        .await
        .unwrap();
    let reply: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    let request = mkit_core::hash::from_hex(reply["takedownId"].as_str().unwrap()).unwrap();
    let raw = service
        .store
        .get(&partition, &request_key(&request))
        .await
        .unwrap()
        .unwrap();
    let record: serde_json::Value = serde_json::from_slice(raw.as_bytes()).unwrap();
    assert_eq!(record["actions"].as_array().unwrap().len(), 1);
    assert_eq!(record["actions"][0]["object"], json!(id));
    assert_eq!(reply["complete"], false);
    assert_eq!(record["activation_cursor"], 1);
    assert_eq!(record["preservation_pending"], true);
}

mod accounting {
    use super::*;
    use crate::admin::{
        AdminOperations, BodyCapture, Config, Engine, Headers, Prepared, Response, TAKEDOWN_PATH,
    };
    use crate::indexed::budget::SliceBudget;
    use crate::store::{codec, content_shard, index::IndexValue, keys};
    use crate::{
        Batch, BatchOutcome, Cursor, Key, PartitionStats, RangeScan, ScanPage, StoreCapabilities,
        StoreError, Value,
    };
    use ed25519_dalek::{Signer, SigningKey};
    use mkit_core::{
        hash::{Hash, hash, to_hex},
        object::{Blob, Object},
        pack::PackWriter,
        serialize::serialize,
    };
    use std::sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    #[derive(Default)]
    struct Faults {
        draft: usize,
        acceptance: usize,
        activation: usize,
        audit: usize,
        reject_operations: bool,
        header_per_object: usize,
        header_attempts: std::collections::BTreeMap<Key, usize>,
    }
    #[derive(Clone)]
    struct Counted {
        inner: Arc<MemoryKv>,
        calls: Arc<AtomicUsize>,
        faults: Arc<Mutex<Faults>>,
    }
    impl Counted {
        fn count(&self) {
            self.calls.fetch_add(1, Ordering::SeqCst);
        }
        fn total(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }
    impl NamespaceStore for Counted {
        fn capabilities(&self) -> StoreCapabilities {
            self.inner.capabilities()
        }
        async fn get(&self, p: &Partition, k: &Key) -> Result<Option<Value>, StoreError> {
            self.count();
            if self.faults.lock().unwrap().reject_operations && k.as_bytes().starts_with(b"ao\0") {
                return Err(StoreError::unavailable(
                    "injected operation replay read failure",
                ));
            }
            self.inner.get(p, k).await
        }
        async fn has(&self, p: &Partition, k: &Key) -> Result<bool, StoreError> {
            self.count();
            self.inner.has(p, k).await
        }
        async fn get_many(
            &self,
            p: &Partition,
            keys: &[Key],
        ) -> Result<Vec<Option<Value>>, StoreError> {
            self.count();
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
            self.count();
            self.inner.scan(p, start, end, after, limit).await
        }
        async fn scan_many(
            &self,
            p: &Partition,
            ranges: &[RangeScan],
        ) -> Result<Vec<ScanPage>, StoreError> {
            self.count();
            self.inner.scan_many(p, ranges).await
        }
        async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
            self.count();
            let fail = {
                let mut faults = self.faults.lock().unwrap();
                let puts = batch
                    .writes
                    .iter()
                    .filter_map(|w| {
                        if let crate::Write::Put(k, _) = w {
                            Some(k)
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>();
                let draft = puts
                    .iter()
                    .any(|k| k.as_bytes().starts_with(b"b\0\xffintent-draft\0"));
                let request = puts
                    .iter()
                    .any(|k| k.as_bytes().starts_with(b"b\0\xffrequest\0"));
                let nonce = puts.iter().any(|k| k.as_bytes().starts_with(b"an\0"));
                let counter = if draft {
                    Some(&mut faults.draft)
                } else if request && nonce {
                    Some(&mut faults.acceptance)
                } else if request {
                    Some(&mut faults.activation)
                } else if !nonce && puts.iter().any(|k| k.as_bytes() == b"ah\0") {
                    Some(&mut faults.audit)
                } else {
                    None
                };
                if let Some(counter) = counter {
                    if *counter > 0 {
                        *counter -= 1;
                        true
                    } else {
                        false
                    }
                } else if let Some(header) =
                    puts.iter().find(|k| k.as_bytes().ends_with(b"\0actions"))
                {
                    let limit = faults.header_per_object;
                    let attempt = faults.header_attempts.entry((*header).clone()).or_default();
                    *attempt += 1;
                    *attempt <= limit
                } else {
                    false
                }
            };
            if fail {
                return Ok(BatchOutcome::PreconditionFailed {
                    index: 0,
                    observed: None,
                });
            }
            self.inner.apply(p, batch).await
        }
        async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
            self.count();
            self.inner.stats(p).await
        }
        async fn probe(&self) -> Result<(), StoreError> {
            self.count();
            self.inner.probe().await
        }
    }
    #[derive(Clone)]
    struct Observed {
        service: Service<Counted>,
        phases: Arc<Mutex<Vec<(u32, u32)>>>,
    }
    impl AdminOperations for Observed {
        fn plan<'a>(
            &'a self,
            path: &'a str,
            input: &'a serde_json::Value,
            digest: &'a str,
            now: u64,
            budget: &'a SliceBudget,
        ) -> crate::BoxFuture<'a, Result<Prepared, crate::ServerError>> {
            Box::pin(async move {
                let used = budget.used();
                let calls = self.service.store.total();
                let result = self.service.plan(path, input, digest, now, budget).await;
                assert_eq!(
                    budget.used() - used,
                    u32::try_from(self.service.store.total() - calls).unwrap(),
                    "every plan namespace call must charge the shared request budget"
                );
                self.phases.lock().unwrap().push((used, budget.used()));
                result
            })
        }
        fn after_commit<'a>(
            &'a self,
            path: &'a str,
            input: &'a serde_json::Value,
            response: Response,
            now: u64,
            budget: &'a SliceBudget,
        ) -> crate::BoxFuture<'a, Result<Response, crate::ServerError>> {
            Box::pin(async move {
                let used = budget.used();
                let calls = self.service.store.total();
                let result = self
                    .service
                    .after_commit(path, input, response, now, budget)
                    .await;
                assert_eq!(
                    budget.used() - used,
                    u32::try_from(self.service.store.total() - calls).unwrap(),
                    "every activation namespace call must charge the shared request budget"
                );
                self.phases.lock().unwrap().push((used, budget.used()));
                result
            })
        }
    }
    fn root() -> Partition {
        Partition::Namespace(NamespaceKey::deployment_default())
    }
    fn signed(input: &serde_json::Value, nonce: u8) -> (Headers, BodyCapture) {
        let mut body = BodyCapture::default();
        body.push(input.to_string().as_bytes());
        let nonce = to_hex(&[nonce; 32]);
        let digest = body.digest();
        let canonical = format!(
            "mkit-admin:v1\noperator\nhttps://server.example\n{TAKEDOWN_PATH}\n{digest}\n0\n60000\n{nonce}"
        );
        let signature = mkit_core::hash::to_hex_bytes(
            &SigningKey::from_bytes(&[71; 32])
                .sign(&hash(canonical.as_bytes()))
                .to_bytes(),
        );
        let values = [
            "1".into(),
            "operator".into(),
            "https://server.example".into(),
            "0".into(),
            "60000".into(),
            nonce,
            digest,
            signature,
        ];
        (
            crate::admin::HEADER_NAMES
                .into_iter()
                .zip(values)
                .map(|(k, v)| (k.into(), v))
                .collect(),
            body,
        )
    }
    struct Fixture {
        engine: Engine<Counted>,
        observed: Observed,
        input: serde_json::Value,
        pack: Hash,
        objects: Vec<Hash>,
    }
    impl Fixture {
        async fn new(count: u32, whole_pack: bool) -> Self {
            let inner = Arc::new(MemoryKv::with_clock(Arc::new(crate::ManualClock::new(10))));
            let mut writer = PackWriter::new_raw_only();
            let mut objects = Vec::new();
            for n in 0..count {
                let object = Object::Blob(Blob {
                    data: n.to_le_bytes().to_vec(),
                });
                let raw = serialize(&object).unwrap();
                let id = hash(&raw);
                writer.push_raw(id, &raw).unwrap();
                objects.push((id, object, raw.len()));
            }
            let bytes = writer.finish().unwrap();
            let pack = hash(&bytes);
            let repo = crate::RepoId {
                namespace: NamespaceKey::deployment_default(),
                name: crate::RepoName::new("repo").unwrap(),
            };
            for (id, object, size) in &objects {
                inventory::stage(&inner, &pack, bytes.len() as u64, id, object, None, 10)
                    .await
                    .unwrap();
                let row = IndexValue {
                    frame_offset: 5,
                    frame_length: 5,
                    wire_type: 0,
                    decoded_size: *size as u64,
                    chain_depth: 0,
                    delta_base: None,
                };
                inner
                    .apply(
                        &root(),
                        Batch::new().put(
                            keys::object_index(&repo.name, id, &pack),
                            codec::encode_object_index(id, &row).unwrap(),
                        ),
                    )
                    .await
                    .unwrap();
            }
            inventory::complete(&inner, &pack, bytes.len() as u64, 10)
                .await
                .unwrap();
            inner
                .apply(
                    &root(),
                    Batch::new().put(keys::membership(&repo.name, &pack), Value::default()),
                )
                .await
                .unwrap();
            let store = Counted {
                inner,
                calls: Arc::new(AtomicUsize::new(0)),
                faults: Arc::new(Mutex::new(Faults::default())),
            };
            let observed = Observed {
                service: Service::new(store.clone(), root(), Arc::new(SinglePartition)),
                phases: Arc::new(Mutex::new(Vec::new())),
            };
            let key = SigningKey::from_bytes(&[71; 32]);
            let config = Config::parse("https://server.example", &json!({"version":1,"keys":[{"keyId":"operator","alg":"ed25519","publicKey":to_hex(key.verifying_key().as_bytes()),"roles":["moderation"]}]}).to_string()).unwrap();
            let engine =
                Engine::new(store, root(), config).with_operations(Arc::new(observed.clone()));
            let objects = objects.into_iter().map(|(id, _, _)| id).collect::<Vec<_>>();
            let mut input = json!({"repository":"root/repo","operationId":"counted","reason":"private review","reasonToken":"policy"});
            if whole_pack {
                input["packId"] = json!(base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    pack
                ));
            } else {
                input["objectIds"] = json!(
                    objects
                        .iter()
                        .map(|id| base64::Engine::encode(
                            &base64::engine::general_purpose::STANDARD,
                            id
                        ))
                        .collect::<Vec<_>>()
                );
            }
            Self {
                engine,
                observed,
                input,
                pack,
                objects,
            }
        }
        fn store(&self) -> &Counted {
            &self.observed.service.store
        }
        async fn dispatch(&self, nonce: u8) -> (Response, usize, u32) {
            self.store().calls.store(0, Ordering::SeqCst);
            self.observed.phases.lock().unwrap().clear();
            let (headers, body) = signed(&self.input, nonce);
            let response = self.engine.handle(TAKEDOWN_PATH, &headers, &body, 10).await;
            let calls = self.store().total();
            let phases = self.observed.phases.lock().unwrap();
            assert!(calls <= 10_000, "actual signed dispatch calls: {calls}");
            assert!(
                phases.windows(2).all(|p| p[0].1 == p[1].0),
                "request budget reset between retries: {phases:?}"
            );
            assert_eq!(phases.first().unwrap().0, 0);
            let charged = phases.last().unwrap().1;
            assert!(charged <= crate::limits::REQUEST_CALLS);
            assert!(
                calls - charged as usize <= 1000,
                "unbudgeted ledger reserve exceeded"
            );
            eprintln!(
                "signed dispatch nonce={nonce}: status={}, actual={calls}, intent={charged}, ledger={}, phases={phases:?}",
                response.status,
                calls - charged as usize
            );
            (response, calls, charged)
        }
        async fn snapshot(&self) -> ScanPage {
            let rows = self
                .store()
                .inner
                .scan(
                    &root(),
                    &Key::new(Vec::new()),
                    &Key::new(vec![255]),
                    None,
                    1000,
                )
                .await
                .unwrap();
            assert!(
                rows.next.is_none(),
                "snapshot covers every durable root row"
            );
            rows
        }
        async fn replay(&self, nonce: u8) -> (Response, usize, u32) {
            let before = self.snapshot().await;
            let replay_key = to_hex(&hash(
                format!("https://server.example\noperator\n{}", to_hex(&[nonce; 32])).as_bytes(),
            ));
            let key = Key::new([b"an\0".as_slice(), replay_key.as_bytes()].concat());
            let raw = &before.entries.iter().find(|(k, _)| k == &key).unwrap().1;
            let stored: serde_json::Value = serde_json::from_slice(raw.as_bytes()).unwrap();
            let expected: Response = serde_json::from_value(stored["result"].clone()).unwrap();
            assert_eq!(expected.status, 200);
            self.store().calls.store(0, Ordering::SeqCst);
            self.observed.phases.lock().unwrap().clear();
            let (headers, body) = signed(&self.input, nonce);
            let response = self.engine.handle(TAKEDOWN_PATH, &headers, &body, 10).await;
            let calls = self.store().total();
            assert_eq!(
                calls, 1,
                "one failed conditional nonce apply returns stored result"
            );
            assert!(
                self.observed.phases.lock().unwrap().is_empty(),
                "completed replay has no runtime phases"
            );
            assert_eq!(
                response, expected,
                "replay returns the exact stored response"
            );
            assert_eq!(
                self.snapshot().await,
                before,
                "replay commits no writes to audit, cursor, timer or nonce"
            );
            (response, calls, 0)
        }
        async fn resume_activation(&self) -> Result<(), crate::ServerError> {
            self.store().calls.store(0, Ordering::SeqCst);
            let budget = SliceBudget::new(4000);
            let id = hash(&[b"mkit-takedown:v1\0".as_slice(), b"counted"].concat());
            let service = Service::new(self.store().clone(), root(), Arc::new(SinglePartition));
            let resumed = service.resume(id, 10, &budget).await;
            assert_eq!(
                self.store().total(),
                budget.used() as usize,
                "every recovery call charges the shared purse"
            );
            assert!(budget.used() <= 4000);
            eprintln!(
                "activation recovery: objects={}, actual={}, charged={}, complete={}",
                self.objects.len(),
                self.store().total(),
                budget.used(),
                resumed.is_ok(),
            );
            resumed
        }
        async fn record(&self) -> serde_json::Value {
            let id = hash(&[b"mkit-takedown:v1\0".as_slice(), b"counted"].concat());
            let raw = self
                .store()
                .inner
                .get(&root(), &request_key(&id))
                .await
                .unwrap()
                .unwrap();
            serde_json::from_slice(raw.as_bytes()).unwrap()
        }
    }
    #[tokio::test]
    async fn signed_256_named_ids_count_every_call_on_acceptance_and_both_replays() {
        let fixture = Fixture::new(256, false).await;
        let (first, calls, charged) = fixture.dispatch(1).await;
        assert_eq!(first.status, 200);
        assert!(charged > 3000);
        assert!(calls < (crate::limits::REQUEST_CALLS as usize));
        assert_eq!(fixture.record().await["activation_cursor"], 256);
        let (nonce, calls, charged) = fixture.replay(1).await;
        assert_eq!(nonce, first);
        assert_eq!(calls, 1);
        assert_eq!(charged, 0);
        let (operation, calls, charged) = fixture.dispatch(2).await;
        assert_eq!(operation, first);
        assert_eq!(calls, 5);
        assert_eq!(charged, 1);
        assert_eq!(fixture.record().await["preservation_pending"], true);
    }
    #[tokio::test]
    async fn fifteen_root_acceptance_races_exhaust_one_shared_request_budget() {
        let fixture = Fixture::new(256, false).await;
        fixture.store().faults.lock().unwrap().acceptance = 15;
        let (failed, calls, charged) = fixture.dispatch(3).await;
        assert_eq!(failed.status, 503);
        assert_eq!(charged, crate::limits::REQUEST_CALLS);
        assert!(calls >= (crate::limits::REQUEST_CALLS as usize));
        assert!(fixture.observed.phases.lock().unwrap().len() > 2);
        let request = hash(&[b"mkit-takedown:v1\0".as_slice(), b"counted"].concat());
        assert!(
            fixture
                .store()
                .inner
                .get(&root(), &request_key(&request))
                .await
                .unwrap()
                .is_none()
        );
        for object in &fixture.objects {
            assert!(
                fixture
                    .store()
                    .inner
                    .get(&content_shard(object), &denial::action_key(object))
                    .await
                    .unwrap()
                    .is_none()
            );
        }
        fixture.store().faults.lock().unwrap().acceptance = 0;
        assert_eq!(fixture.dispatch(4).await.0.status, 200);
        assert_eq!(fixture.record().await["activation_cursor"], 256);
    }
    #[tokio::test]
    async fn per_object_header_races_bound_activation_and_stored_replay_leaves_recovery() {
        let fixture = Fixture::new(256, false).await;
        fixture.store().faults.lock().unwrap().header_per_object = 7;
        let (failed, calls, charged) = fixture.dispatch(5).await;
        assert_eq!(failed.status, 503);
        assert!(charged >= 4000);
        assert!(calls < (crate::limits::REQUEST_CALLS as usize));
        let record = fixture.record().await;
        assert!(record["activation_cursor"].as_u64().unwrap() > 0);
        assert!(record["activation_cursor"].as_u64().unwrap() < 256);
        assert_eq!(record["preservation_pending"], true);
        let (headers, body) = signed(&fixture.input, 5);
        let retry = fixture
            .engine
            .handle(TAKEDOWN_PATH, &headers, &body, 10)
            .await;
        assert_eq!(
            retry.status, 503,
            "partial activation cannot replay success"
        );
        let reply: serde_json::Value = serde_json::from_slice(&retry.body).unwrap();
        assert_eq!(reply["code"], "unavailable");
        assert_eq!(
            reply["takedownId"],
            to_hex(&hash(
                &[b"mkit-takedown:v1\0".as_slice(), b"counted"].concat()
            ))
        );
        assert!(
            fixture.record().await["activation_cursor"]
                .as_u64()
                .unwrap()
                > record["activation_cursor"].as_u64().unwrap()
        );
        let mut cursor = record["activation_cursor"].as_u64().unwrap();
        for _ in 0..4 {
            let resumed = fixture.resume_activation().await;
            let next = fixture.record().await["activation_cursor"]
                .as_u64()
                .unwrap();
            assert!(
                next > cursor,
                "each bounded recovery slice must advance durable activation"
            );
            cursor = next;
            if resumed.is_ok() {
                break;
            }
            assert_eq!(resumed.unwrap_err().code(), crate::Code::Unavailable);
        }
        assert_eq!(cursor, 256);
        assert_eq!(fixture.replay(5).await.0.status, 200);
    }
    #[tokio::test]
    async fn root_activation_cursor_races_use_same_request_budget_and_preserve_denial() {
        let fixture = Fixture::new(1, false).await;
        fixture.store().faults.lock().unwrap().activation = usize::MAX;
        fixture.store().faults.lock().unwrap().audit = 15;
        let (failed, calls, charged) = fixture.dispatch(6).await;
        assert_eq!(failed.status, 503);
        assert!(charged > 1000);
        assert!(calls < 4000);
        assert_eq!(fixture.record().await["activation_cursor"], 0);
        assert!(
            fixture
                .store()
                .inner
                .get(
                    &content_shard(&fixture.objects[0]),
                    &denial::action_key(&fixture.objects[0])
                )
                .await
                .unwrap()
                .is_some()
        );
        let (headers, body) = signed(&fixture.input, 6);
        assert_eq!(
            fixture
                .engine
                .handle(TAKEDOWN_PATH, &headers, &body, 10)
                .await
                .status,
            503
        );
        assert_eq!(fixture.record().await["activation_cursor"], 0);
        fixture.store().faults.lock().unwrap().activation = 0;
        fixture.resume_activation().await.unwrap();
        assert_eq!(fixture.record().await["activation_cursor"], 1);
        assert_eq!(fixture.replay(6).await.0.status, 200);
    }
    #[tokio::test]
    async fn alternate_nonce_completion_stores_success_before_returning() {
        let fixture = Fixture::new(1, false).await;
        fixture.store().faults.lock().unwrap().activation = usize::MAX;
        assert_eq!(fixture.dispatch(20).await.0.status, 503);
        fixture.store().faults.lock().unwrap().activation = 0;
        assert_eq!(fixture.dispatch(21).await.0.status, 200);
        fixture.store().faults.lock().unwrap().reject_operations = true;
        assert_eq!(fixture.replay(21).await.0.status, 200);
        assert_eq!(fixture.replay(20).await.0.status, 200);
    }
    #[tokio::test]
    async fn timer15_restart_finalizes_interrupted_signed_acceptance() {
        let fixture = Fixture::new(1, false).await;
        fixture.store().faults.lock().unwrap().activation = usize::MAX;
        assert_eq!(fixture.dispatch(22).await.0.status, 503);
        assert_eq!(fixture.record().await["activation_cursor"], 0);
        fixture.store().faults.lock().unwrap().activation = 0;
        let clock = Arc::new(crate::ManualClock::new(10));
        let work = super::super::work::Work {
            purge: None,
            metadata: fixture.store().clone(),
            serving: crate::MemoryBlobStore::default(),
            preserved: crate::MemoryBlobStore::default(),
            root: root(),
            shards: Arc::new(SinglePartition),
            addressing: crate::Addressing::Single {
                repo: crate::RepoId {
                    namespace: NamespaceKey::deployment_default(),
                    name: crate::RepoName::new("repo").unwrap(),
                },
            },
            retention_ms: 1000,
            discovery_margin_ms: 5000,
            profile: crate::takedown::acquisition::Profile::scheduled(),
            clock: clock.clone(),
        };
        let registry = crate::timers::TimerRegistry::new().register(work);
        let fired = crate::timers::run_due(
            fixture.store(),
            &root(),
            &registry,
            clock.as_ref(),
            10,
            &crate::timers::TickBudget::new(1, 1, 16, 1000),
        )
        .await
        .unwrap();
        assert_eq!(fired.fired, 1);
        assert_eq!(fixture.record().await["activation_cursor"], 1);
        let key = SigningKey::from_bytes(&[71; 32]);
        let config = Config::parse("https://server.example", &json!({"version":1,"keys":[{"keyId":"operator","alg":"ed25519","publicKey":to_hex(key.verifying_key().as_bytes()),"roles":["audit"]}]}).to_string()).unwrap();
        let engine = Engine::new(fixture.store().clone(), root(), config);
        let (headers, body) = signed(&fixture.input, 22);
        assert_eq!(
            engine
                .handle(TAKEDOWN_PATH, &headers, &body, 10)
                .await
                .status,
            200
        );
        let operation = fixture
            .store()
            .inner
            .get(&root(), &Key::new(b"ao\0counted".to_vec()))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(operation.as_bytes()).unwrap()["result"]["status"],
            200
        );
        assert_eq!(fixture.replay(22).await.0.status, 200);
    }
    #[tokio::test]
    async fn whole_pack_geometry_and_draft_header_retries_stay_bounded() {
        let fixture = Fixture::new(300, true).await;
        fixture.store().faults.lock().unwrap().draft = 15;
        fixture.store().faults.lock().unwrap().acceptance = 15;
        fixture.store().faults.lock().unwrap().header_per_object = 7;
        let (first, calls, _) = fixture.dispatch(7).await;
        assert_eq!(first.status, 200);
        assert!(calls < 500);
        let record = fixture.record().await;
        assert_eq!(record["actions"].as_array().unwrap().len(), 1);
        assert_eq!(record["actions"][0]["object"], json!(fixture.pack));
        assert_eq!(record["activation_cursor"], 1);
        assert_eq!(fixture.replay(7).await.0, first);
        assert_eq!(fixture.dispatch(8).await.0, first);
    }
}
