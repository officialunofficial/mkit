#![allow(clippy::unwrap_used)]
use super::*;
use crate::admin::{BodyCapture, Config, Engine, Headers, Reply};
use crate::pipeline::SinglePartition;
use crate::timers::Fired;
use crate::{
    Addressing, BatchOutcome, Clock, ManualClock, MemoryBlobStore, MemoryKv, NamespaceKey,
    Partition, Precondition,
};
use ed25519_dalek::{Signer, SigningKey};
use futures::StreamExt;
use mkit_core::hash::hash;
use std::sync::Arc;

type Runtime = Work<Arc<MemoryKv>, MemoryBlobStore, MemoryBlobStore>;
struct Fixture {
    work: Arc<Runtime>,
    clock: Arc<ManualClock>,
    action: Hash,
    object: Hash,
    bytes: Vec<u8>,
}
fn config(role: &str) -> Config {
    Config::parse("https://server.example", &json!({"version":1,"keys":[{"keyId":"operator","alg":"ed25519","publicKey":to_hex(SigningKey::from_bytes(&[71;32]).verifying_key().as_bytes()),"roles":[role]}]}).to_string()).unwrap()
}
fn request(path: &str, input: &Json, nonce: u8) -> (Headers, BodyCapture) {
    let mut bytes = input.to_string().into_bytes();
    if path == admin::READ_PRESERVED_PATH {
        let mut framed = vec![0];
        framed.extend_from_slice(&u32::try_from(bytes.len()).unwrap().to_be_bytes());
        framed.extend(bytes);
        bytes = framed;
    }
    let mut body = BodyCapture::default();
    body.push(&bytes);
    let nonce = to_hex(&[nonce; 32]);
    let digest = body.digest();
    let canonical = format!(
        "mkit-admin:v1\noperator\nhttps://server.example\n{path}\n{digest}\n0\n60000\n{nonce}"
    );
    let signature = SigningKey::from_bytes(&[71; 32]).sign(&hash(canonical.as_bytes()));
    let values = [
        "1".to_owned(),
        "operator".into(),
        "https://server.example".into(),
        "0".into(),
        "60000".into(),
        nonce,
        digest,
        hex_signature(&signature.to_bytes()),
    ];
    (
        admin::HEADER_NAMES
            .into_iter()
            .zip(values)
            .map(|(k, v)| (k.into(), v))
            .collect(),
        body,
    )
}
fn hex_signature(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut text, b| {
        write!(text, "{b:02x}").unwrap();
        text
    })
}
impl Fixture {
    fn engine(&self, role: &str) -> Arc<Engine<Arc<MemoryKv>>> {
        Arc::new(
            Engine::new(
                self.work.metadata.clone(),
                self.work.root.clone(),
                config(role),
            )
            .with_operations(self.work.clone()),
        )
    }
    fn get(&self) -> Json {
        json!({"takedownId":to_hex(&self.action)})
    }
    fn read(&self, offset: u64) -> Json {
        json!({"takedownId":to_hex(&self.action),"objectId":STANDARD.encode(self.object),"offset":offset.to_string()})
    }
    fn hold(&self, enabled: bool) -> Json {
        json!({"takedownId":to_hex(&self.action),"enabled":enabled,"reason":"court order","operatorLabel":"on-call"})
    }
    async fn state(&self) -> State {
        self.work
            .state(&self.work.metadata, &self.action, 10)
            .await
            .unwrap()
            .0
    }
    async fn put_state(&self, state: &State) {
        self.work
            .metadata
            .apply(
                &self.work.root,
                Batch::new().put(
                    work::key(b"state", &self.action, &[]),
                    intent::encode(state).unwrap(),
                ),
            )
            .await
            .unwrap();
    }
    async fn step(&self) {
        let budget = SliceBudget::new(700);
        let fired = self
            .work
            .step(
                &self.work.metadata,
                self.action,
                u64::try_from(self.clock.now_ms()).unwrap(),
                &budget,
            )
            .await
            .unwrap();
        let (Fired::Reschedule { batch, .. } | Fired::Done(batch)) = fired else {
            panic!("unexpected timer result")
        };
        assert_eq!(
            self.work
                .metadata
                .apply(&self.work.root, batch)
                .await
                .unwrap(),
            BatchOutcome::Committed
        );
    }
    async fn head(&self) -> u64 {
        self.work
            .metadata
            .get(&self.work.root, &Key::new(b"ah\0".to_vec()))
            .await
            .unwrap()
            .map_or(0, |v| {
                serde_json::from_slice::<Json>(v.as_bytes()).unwrap()["seq"]
                    .as_u64()
                    .unwrap()
            })
    }
    async fn audit(&self) -> Vec<Json> {
        let page = self
            .work
            .metadata
            .scan(
                &self.work.root,
                &Key::new(b"ae\0".to_vec()),
                &Key::new(b"ae\x01".to_vec()),
                None,
                100,
            )
            .await
            .unwrap();
        let entries: Vec<Json> = page
            .entries
            .iter()
            .map(|(_, v)| serde_json::from_slice(v.as_bytes()).unwrap())
            .collect();
        let mut previous = "00".repeat(32);
        for (i, entry) in entries.iter().enumerate() {
            assert_eq!(entry["seq"], (i + 1).to_string());
            assert_eq!(entry["prevHash"], previous);
            let mut unhashed = entry.clone();
            unhashed.as_object_mut().unwrap().remove("entryHash");
            let mut bytes = b"mkit-admin-audit:v1".to_vec();
            bytes.extend(serde_json::to_vec(&unhashed).unwrap());
            previous = to_hex(&hash(&bytes));
            assert_eq!(entry["entryHash"], previous);
        }
        assert_eq!(self.head().await, entries.len() as u64);
        entries
    }
}
#[allow(
    clippy::too_many_lines,
    reason = "Build durable verified state and independently owned preservation pieces."
)]
async fn fixture(size: usize) -> Fixture {
    let clock = Arc::new(ManualClock::new(100));
    let metadata = Arc::new(MemoryKv::with_clock(clock.clone()));
    let root = Partition::Namespace(NamespaceKey::deployment_default());
    let work = Arc::new(Work {
        purge: None,
        metadata: metadata.clone(),
        serving: MemoryBlobStore::default(),
        preserved: MemoryBlobStore::default(),
        root: root.clone(),
        shards: Arc::new(SinglePartition),
        addressing: Addressing::Multi(crate::repo::MultiAddressing::new().with_namespace_policy(
            crate::policy::NamespacePolicy::Any {
                unsafe_without_admission: true,
            },
        )),
        retention_ms: 1000,
        discovery_margin_ms: 5000,
        profile: super::super::acquisition::Profile::scheduled(),
        clock: clock.clone(),
    });
    let bytes: Vec<u8> = (0..size).map(|i| u8::try_from(i % 251).unwrap()).collect();
    let object = hash(&bytes);
    let action = [7; 32];
    let record = intent::Record {
        version: 1,
        id: action,
        digest: format!("body:{}", to_hex(&[8; 32])),
        operation: "fixture".into(),
        repository: "root/repo".into(),
        reason: "policy".into(),
        reason_token: "policy".into(),
        created: 10,
        pack: None,
        actions: vec![intent::Reference {
            object,
            descriptor_hash: [9; 32],
        }],
        activation_cursor: 1,
        preservation_pending: true,
    };
    metadata
        .apply(
            &root,
            Batch::new().put(
                intent::request_key(&action),
                intent::encode(&record).unwrap(),
            ),
        )
        .await
        .unwrap();
    let (mut state, _) = work.state(&metadata, &action, 10).await.unwrap();
    state.phase = Phase::Retain;
    state.resume_phase = Phase::Retain;
    state.verification = work::Verification::Verified;
    state.verified_objects = 1;
    let info = ObjectInfo {
        kind: 0,
        size: size as u64,
        copied: size as u64,
        verified: true,
        ..ObjectInfo::default()
    };
    metadata
        .apply(
            &root,
            Batch::new()
                .put(
                    work::key(b"state", &action, &[]),
                    intent::encode(&state).unwrap(),
                )
                .put(
                    work::key(b"object", &action, &object),
                    intent::encode(&info).unwrap(),
                ),
        )
        .await
        .unwrap();
    for (i, part) in bytes.chunks(copy::PIECE_BYTES).enumerate() {
        let offset = (i * copy::PIECE_BYTES) as u64;
        let piece = copy::write(&work.preserved, &action, &object, offset, part)
            .await
            .unwrap();
        metadata
            .apply(
                &root,
                Batch::new().put(
                    work::key(
                        b"piece",
                        &action,
                        &[object.as_slice(), &offset.to_be_bytes()].concat(),
                    ),
                    intent::encode(&piece).unwrap(),
                ),
            )
            .await
            .unwrap();
    }
    Fixture {
        work,
        clock,
        action,
        object,
        bytes,
    }
}
fn message(bytes: &Bytes) -> (u8, Json) {
    let len = u32::from_be_bytes(bytes[1..5].try_into().unwrap()) as usize;
    assert_eq!(len, bytes.len() - 5);
    (bytes[0], serde_json::from_slice(&bytes[5..]).unwrap())
}
async fn messages(reply: Reply) -> Vec<(u8, Json)> {
    match reply {
        Reply::Stream(mut stream) => {
            let mut out = vec![];
            while let Some(chunk) = stream.next().await {
                out.push(message(&chunk.unwrap()));
            }
            out
        }
        Reply::Unary(response) => panic!("unexpected unary: {response:?}"),
    }
}
#[tokio::test]
async fn every_operation_is_signed_role_checked_replayed_and_audited() {
    let f = fixture(64).await;
    let operations = [
        (admin::GET_TAKEDOWN_PATH, f.get()),
        (
            admin::LIST_TAKEDOWNS_PATH,
            json!({"scope":{"repository":"root/repo"},"pageSize":10}),
        ),
        (admin::SET_LEGAL_HOLD_PATH, f.hold(true)),
        (admin::READ_PRESERVED_PATH, f.read(0)),
    ];
    for (i, (path, input)) in operations.into_iter().enumerate() {
        let (headers, body) = request(path, &input, u8::try_from(i).unwrap() + 1);
        let wrong = f
            .engine("audit")
            .handle_streamed(path, &headers, &body, None, 100)
            .await;
        assert!(matches!(wrong, Reply::Unary(Response { status: 403, .. })));
        let head = f.head().await;
        let bad = f
            .engine("moderation")
            .handle_streamed(path, &headers, &body, None, 100)
            .await;
        assert!(matches!(bad, Reply::Unary(Response { status: 403, .. })));
        assert_eq!(f.head().await, head); // failed nonce replays are byte-free terminal errors
        let (headers, body) = request(path, &input, u8::try_from(i).unwrap() + 20);
        let accepted = f
            .engine("moderation")
            .handle_streamed(path, &headers, &body, None, 100)
            .await;
        let head = f.head().await;
        let replay = f
            .engine("moderation")
            .handle_streamed(path, &headers, &body, None, 100)
            .await;
        match (accepted, replay) {
            (Reply::Unary(a), Reply::Unary(b)) => {
                assert_eq!(a.status, 200);
                assert_eq!(a, b);
                assert_eq!(f.head().await, head);
            }
            (a @ Reply::Stream(_), b @ Reply::Stream(_)) => {
                assert_eq!(messages(a).await, messages(b).await);
                assert_eq!(f.head().await, head + 1);
            }
            _ => panic!("replay type mismatch"),
        }
    }
    f.audit().await;
}
#[tokio::test]
async fn status_keeps_acquisition_verification_discovery_hold_and_completion_separate() {
    let f = fixture(64).await;
    let engine = f.engine("moderation");
    let get = |nonce| request(admin::GET_TAKEDOWN_PATH, &f.get(), nonce);
    let (h, b) = get(1);
    let response = engine.handle(admin::GET_TAKEDOWN_PATH, &h, &b, 100).await;
    let state: Json = serde_json::from_slice(&response.body).unwrap();
    let record = &state["takedown"];
    assert_eq!(record["complete"], false);
    assert_eq!(record["preservationVerified"], true);
    assert_eq!(record["acquisitionPending"], false);
    assert_eq!(record["discoveryStatus"], "incomplete");
    assert_eq!(record["legalHold"], false);
    assert!(!response.body.windows(f.bytes.len()).any(|b| b == f.bytes));
    let mut state = f.state().await;
    state.verification = work::Verification::CanonicalPending;
    state.phase = Phase::Acquire;
    state.resume_phase = Phase::Seed;
    state.hold = true;
    f.put_state(&state).await;
    let (h, b) = get(2);
    let response = engine.handle(admin::GET_TAKEDOWN_PATH, &h, &b, 100).await;
    let state: Json = serde_json::from_slice(&response.body).unwrap();
    let record = &state["takedown"];
    assert_eq!(record["complete"], false);
    assert_eq!(record["preservationVerified"], false);
    assert_eq!(record["acquisitionPending"], true);
    assert_eq!(record["discoveryStatus"], "pending");
    assert_eq!(record["legalHold"], true);
    f.audit().await;
}
#[tokio::test]
async fn fresh_retry_roles_retention_and_ownership_never_replay_bytes() {
    let f = fixture(64).await;
    let engine = f.engine("moderation");
    let (h, b) = request(admin::READ_PRESERVED_PATH, &f.read(0), 1);
    assert_eq!(
        messages(
            engine
                .clone()
                .handle_streamed(admin::READ_PRESERVED_PATH, &h, &b, None, 100)
                .await
        )
        .await
        .len(),
        2
    );
    let nonce = f
        .work
        .metadata
        .scan(
            &f.work.root,
            &Key::new(b"an\0".to_vec()),
            &Key::new(b"an\x01".to_vec()),
            None,
            10,
        )
        .await
        .unwrap();
    let raw = nonce.entries[0].1.as_bytes();
    assert!(raw.len() < 1024);
    assert!(!raw.windows(f.bytes.len()).any(|b| b == f.bytes));
    let revoked = f
        .engine("audit")
        .handle_streamed(admin::READ_PRESERVED_PATH, &h, &b, None, 100)
        .await;
    assert!(matches!(
        revoked,
        Reply::Unary(Response { status: 403, .. })
    ));
    f.clock.set(1010);
    let expired = engine
        .clone()
        .handle_streamed(admin::READ_PRESERVED_PATH, &h, &b, None, 1010)
        .await;
    assert!(matches!(
        expired,
        Reply::Unary(Response { status: 400, .. })
    ));
    let mut state = f.state().await;
    state.hold = true;
    f.put_state(&state).await;
    assert_eq!(
        messages(
            engine
                .clone()
                .handle_streamed(admin::READ_PRESERVED_PATH, &h, &b, None, 1010)
                .await
        )
        .await
        .len(),
        2
    );
    f.work
        .metadata
        .apply(
            &f.work.root,
            Batch::new().delete(intent::request_key(&f.action)),
        )
        .await
        .unwrap();
    assert!(matches!(
        engine
            .handle_streamed(admin::READ_PRESERVED_PATH, &h, &b, None, 1010)
            .await,
        Reply::Unary(Response { status: 404, .. })
    ));
    f.audit().await;
}
#[tokio::test]
async fn offsets_final_rules_and_empty_at_size_are_exact() {
    let f = fixture(copy::PIECE_BYTES + 37).await;
    let engine = f.engine("moderation");
    for (nonce, offset) in [0, 3, copy::PIECE_BYTES as u64, f.bytes.len() as u64]
        .into_iter()
        .enumerate()
    {
        let (h, b) = request(
            admin::READ_PRESERVED_PATH,
            &f.read(offset),
            u8::try_from(nonce).unwrap() + 1,
        );
        let frames = messages(
            engine
                .clone()
                .handle_streamed(admin::READ_PRESERVED_PATH, &h, &b, None, 100)
                .await,
        )
        .await;
        assert_eq!(frames.last().unwrap(), &(2, json!({"metadata":{}})));
        let mut position = offset;
        let mut returned = vec![];
        let mut lasts = 0;
        for (flag, msg) in &frames[..frames.len() - 1] {
            assert_eq!(*flag, 0);
            assert_eq!(msg["offset"], position.to_string());
            let bytes = STANDARD.decode(msg["data"].as_str().unwrap()).unwrap();
            position += bytes.len() as u64;
            returned.extend(bytes);
            lasts += usize::from(msg["last"] == true);
        }
        assert_eq!(lasts, 1);
        assert_eq!(returned, &f.bytes[usize::try_from(offset).unwrap()..]);
        assert_eq!(position, f.bytes.len() as u64);
        if offset == f.bytes.len() as u64 {
            assert_eq!(frames[0].1["data"], "");
        }
    }
    let (h, b) = request(
        admin::READ_PRESERVED_PATH,
        &f.read(f.bytes.len() as u64 + 1),
        10,
    );
    assert!(matches!(
        engine
            .handle_streamed(admin::READ_PRESERVED_PATH, &h, &b, None, 100)
            .await,
        Reply::Unary(Response { status: 400, .. })
    ));
    f.audit().await;
}
#[tokio::test]
async fn corrupt_second_piece_is_audited_connect_error_without_last() {
    let f = fixture(copy::PIECE_BYTES + 37).await;
    let engine = f.engine("moderation");
    let (h, b) = request(admin::READ_PRESERVED_PATH, &f.read(0), 1);
    let Reply::Stream(mut stream) = engine
        .handle_streamed(admin::READ_PRESERVED_PATH, &h, &b, None, 100)
        .await
    else {
        panic!("expected stream")
    };
    let first = message(&stream.next().await.unwrap().unwrap());
    assert_eq!(first.0, 0);
    assert_eq!(first.1["last"], false);
    let row = work::key(
        b"piece",
        &f.action,
        &[
            f.object.as_slice(),
            &(copy::PIECE_BYTES as u64).to_be_bytes(),
        ]
        .concat(),
    );
    let raw = f
        .work
        .metadata
        .get(&f.work.root, &row)
        .await
        .unwrap()
        .unwrap();
    let mut piece: copy::Piece = intent::decode(&raw).unwrap();
    piece.object = [9; 32];
    f.work
        .metadata
        .apply(
            &f.work.root,
            Batch::new()
                .require(Precondition::Equals(row.clone(), raw))
                .put(row, intent::encode(&piece).unwrap()),
        )
        .await
        .unwrap();
    let error = message(&stream.next().await.unwrap().unwrap());
    assert_eq!(error.0, 2);
    assert_eq!(error.1["error"]["code"], "data_loss");
    assert!(error.1.get("last").is_none());
    assert!(stream.next().await.is_none());
    let entries = f.audit().await;
    assert_eq!(entries.last().unwrap()["result"]["code"], "data_loss");
}
#[tokio::test]
async fn expiry_between_pieces_ends_with_error_and_no_success_last() {
    let f = fixture(copy::PIECE_BYTES + 37).await;
    let (h, b) = request(admin::READ_PRESERVED_PATH, &f.read(0), 1);
    let Reply::Stream(mut stream) = f
        .engine("moderation")
        .handle_streamed(admin::READ_PRESERVED_PATH, &h, &b, None, 100)
        .await
    else {
        panic!("stream")
    };
    assert_eq!(
        message(&stream.next().await.unwrap().unwrap()).1["last"],
        false
    );
    f.clock.set(1010);
    let error = message(&stream.next().await.unwrap().unwrap());
    assert_eq!(error.0, 2);
    assert_eq!(error.1["error"]["code"], "failed_precondition");
    assert!(stream.next().await.is_none());
    f.audit().await;
}
#[tokio::test]
async fn signed_hold_commits_with_audit_and_nonce_and_blocks_actual_purge() {
    let f = fixture(64).await;
    let engine = f.engine("moderation");
    let (h, b) = request(admin::SET_LEGAL_HOLD_PATH, &f.hold(true), 1);
    assert_eq!(
        engine
            .handle(admin::SET_LEGAL_HOLD_PATH, &h, &b, 100)
            .await
            .status,
        200
    );
    let seq = f.head().await;
    assert!(f.state().await.hold);
    f.clock.set(1010);
    f.step().await;
    assert_ne!(f.state().await.phase, Phase::Purging);
    let (rh, rb) = request(admin::READ_PRESERVED_PATH, &f.read(0), 2);
    assert_eq!(
        messages(
            engine
                .clone()
                .handle_streamed(admin::READ_PRESERVED_PATH, &rh, &rb, None, 1010)
                .await
        )
        .await
        .len(),
        2
    );
    let (h, b) = request(admin::SET_LEGAL_HOLD_PATH, &f.hold(false), 3);
    assert_eq!(
        engine
            .handle(admin::SET_LEGAL_HOLD_PATH, &h, &b, 1010)
            .await
            .status,
        200
    );
    f.step().await;
    assert_eq!(f.state().await.phase, Phase::Purging);
    let (h, b) = request(admin::SET_LEGAL_HOLD_PATH, &f.hold(true), 4);
    assert_eq!(
        engine
            .handle(admin::SET_LEGAL_HOLD_PATH, &h, &b, 1010)
            .await
            .status,
        400
    );
    f.step().await;
    f.step().await;
    assert!(f.state().await.purged);
    assert!(matches!(
        engine
            .handle_streamed(admin::READ_PRESERVED_PATH, &rh, &rb, None, 1010)
            .await,
        Reply::Unary(Response { status: 400, .. })
    ));
    let entries = f.audit().await;
    assert_eq!(
        entries[usize::try_from(seq - 1).unwrap()]["actor"],
        "operator"
    );
    assert_eq!(
        entries[usize::try_from(seq - 1).unwrap()]["details"],
        "court order"
    );
}
#[tokio::test]
async fn list_pagination_rejects_foreign_scope_token_and_reports_missing_state_pending() {
    let f = fixture(64).await;
    let engine = f.engine("moderation");
    let raw = f
        .work
        .metadata
        .get(&f.work.root, &intent::request_key(&f.action))
        .await
        .unwrap()
        .unwrap();
    let mut record: intent::Record = intent::decode(&raw).unwrap();
    record.id = [8; 32];
    record.repository = "root/other".into();
    f.work
        .metadata
        .apply(
            &f.work.root,
            Batch::new().put(
                intent::request_key(&record.id),
                intent::encode(&record).unwrap(),
            ),
        )
        .await
        .unwrap();
    let input = json!({"scope":{"namespace":"root"},"pageSize":1});
    let (h, b) = request(admin::LIST_TAKEDOWNS_PATH, &input, 1);
    let first = engine.handle(admin::LIST_TAKEDOWNS_PATH, &h, &b, 100).await;
    assert_eq!(first.status, 200);
    let first: Json = serde_json::from_slice(&first.body).unwrap();
    assert_eq!(first["takedowns"].as_array().unwrap().len(), 1);
    assert!(!first["nextPageToken"].as_str().unwrap().is_empty());
    let input =
        json!({"scope":{"namespace":"root"},"pageSize":1,"pageToken":first["nextPageToken"]});
    let (h, b) = request(admin::LIST_TAKEDOWNS_PATH, &input, 2);
    let second = engine.handle(admin::LIST_TAKEDOWNS_PATH, &h, &b, 100).await;
    let second: Json = serde_json::from_slice(&second.body).unwrap();
    assert_eq!(second["takedowns"][0]["repository"], "root/other");
    assert_eq!(second["takedowns"][0]["acquisitionPending"], true);
    assert_eq!(second["nextPageToken"], "");
    let input =
        json!({"scope":{"repository":"root/repo"},"pageSize":1,"pageToken":first["nextPageToken"]});
    let (h, b) = request(admin::LIST_TAKEDOWNS_PATH, &input, 3);
    assert_eq!(
        engine
            .handle(admin::LIST_TAKEDOWNS_PATH, &h, &b, 100)
            .await
            .status,
        400
    );
    f.audit().await;
}

#[tokio::test]
async fn absent_and_empty_list_scopes_list_all_and_tokens_bind_all_scope() {
    let f = fixture(64).await;
    let engine = f.engine("moderation");
    let raw = f
        .work
        .metadata
        .get(&f.work.root, &intent::request_key(&f.action))
        .await
        .unwrap()
        .unwrap();
    let mut record: intent::Record = intent::decode(&raw).unwrap();
    record.id = [8; 32];
    record.repository = "root/other".into();
    f.work
        .metadata
        .apply(
            &f.work.root,
            Batch::new().put(
                intent::request_key(&record.id),
                intent::encode(&record).unwrap(),
            ),
        )
        .await
        .unwrap();
    let (h, b) = request(admin::LIST_TAKEDOWNS_PATH, &json!({"pageSize":1}), 1);
    let first = engine.handle(admin::LIST_TAKEDOWNS_PATH, &h, &b, 100).await;
    assert_eq!(first.status, 200);
    let first: Json = serde_json::from_slice(&first.body).unwrap();
    let (h, b) = request(
        admin::LIST_TAKEDOWNS_PATH,
        &json!({"scope":{},"pageSize":1,"pageToken":first["nextPageToken"]}),
        2,
    );
    let second = engine.handle(admin::LIST_TAKEDOWNS_PATH, &h, &b, 100).await;
    assert_eq!(second.status, 200);
    let second: Json = serde_json::from_slice(&second.body).unwrap();
    assert_eq!(second["takedowns"][0]["repository"], "root/other");
    assert_eq!(second["nextPageToken"], "");
    f.audit().await;
}
#[tokio::test]
async fn read_retry_rechecks_current_key_expiry_and_buffered_adapter_cannot_return_descriptor() {
    let f = fixture(64).await;
    let config = Config::parse("https://server.example", &json!({"version":1,"keys":[{"keyId":"operator","alg":"ed25519","publicKey":to_hex(SigningKey::from_bytes(&[71;32]).verifying_key().as_bytes()),"roles":["moderation"],"notAfterMs":"150"}]}).to_string()).unwrap();
    let engine = Arc::new(
        Engine::new(f.work.metadata.clone(), f.work.root.clone(), config)
            .with_operations(f.work.clone()),
    );
    let (h, b) = request(admin::READ_PRESERVED_PATH, &f.read(0), 1);
    assert_eq!(
        messages(
            engine
                .clone()
                .handle_streamed(admin::READ_PRESERVED_PATH, &h, &b, None, 100)
                .await
        )
        .await
        .len(),
        2
    );
    assert_eq!(
        engine
            .handle(admin::READ_PRESERVED_PATH, &h, &b, 100)
            .await
            .status,
        400
    );
    assert!(matches!(
        engine
            .handle_streamed(admin::READ_PRESERVED_PATH, &h, &b, None, 151)
            .await,
        Reply::Unary(Response { status: 401, .. })
    ));
    // Unauthenticated expiry is metrics-only; buffered adapter rejection is audited.
    assert_eq!(f.audit().await.len(), 2);
}
#[tokio::test]
async fn changed_or_missing_piece_backend_never_releases_unverified_payload() {
    for remove in [false, true] {
        let f = fixture(copy::PIECE_BYTES + 37).await;
        let (h, b) = request(admin::READ_PRESERVED_PATH, &f.read(0), 1);
        let Reply::Stream(mut stream) = f
            .engine("moderation")
            .handle_streamed(admin::READ_PRESERVED_PATH, &h, &b, None, 100)
            .await
        else {
            panic!("stream")
        };
        assert_eq!(
            message(&stream.next().await.unwrap().unwrap()).1["last"],
            false
        );
        let row = work::key(
            b"piece",
            &f.action,
            &[
                f.object.as_slice(),
                &(copy::PIECE_BYTES as u64).to_be_bytes(),
            ]
            .concat(),
        );
        let raw = f
            .work
            .metadata
            .get(&f.work.root, &row)
            .await
            .unwrap()
            .unwrap();
        let piece: copy::Piece = intent::decode(&raw).unwrap();
        if remove {
            f.work
                .preserved
                .delete(&crate::BlobKey::pack(piece.storage))
                .await
                .unwrap();
        } else {
            // A stored copy from a different owning action has a valid blob
            // content hash, but must fail the freshly checked owner header.
            let other = copy::write(
                &f.work.preserved,
                &[9; 32],
                &f.object,
                piece.offset,
                &f.bytes[copy::PIECE_BYTES..],
            )
            .await
            .unwrap();
            let changed = copy::Piece {
                storage: other.storage,
                ..piece
            };
            f.work
                .metadata
                .apply(
                    &f.work.root,
                    Batch::new().put(row, intent::encode(&changed).unwrap()),
                )
                .await
                .unwrap();
        }
        let error = message(&stream.next().await.unwrap().unwrap());
        assert_eq!(error.0, 2);
        assert_eq!(
            error.1["error"]["code"],
            if remove { "not_found" } else { "data_loss" }
        );
        assert!(error.1.get("last").is_none());
        assert!(stream.next().await.is_none());
        assert_eq!(
            f.audit().await.last().unwrap()["result"]["code"],
            error.1["error"]["code"]
        );
    }
}
#[tokio::test]
async fn hold_planned_before_purge_cannot_take_ownership_after_purge_commits() {
    let f = fixture(64).await;
    let planned = f
        .work
        .plan_legal_hold(&f.work.metadata, f.action, true, 100)
        .await
        .unwrap();
    f.clock.set(1010);
    f.step().await;
    assert_eq!(f.state().await.phase, Phase::Purging);
    assert!(matches!(
        f.work.metadata.apply(&f.work.root, planned).await.unwrap(),
        BatchOutcome::PreconditionFailed { .. }
    ));
    assert!(!f.state().await.hold);
    f.audit().await;
}

#[derive(Clone, Debug)]
struct RejectAcceptance {
    store: Arc<MemoryKv>,
    blocked: Arc<std::sync::atomic::AtomicBool>,
}
impl NamespaceStore for RejectAcceptance {
    fn capabilities(&self) -> crate::StoreCapabilities {
        self.store.capabilities()
    }
    async fn get(&self, p: &Partition, k: &Key) -> Result<Option<crate::Value>, crate::StoreError> {
        self.store.get(p, k).await
    }
    async fn scan(
        &self,
        p: &Partition,
        start: &Key,
        end: &Key,
        after: Option<&Cursor>,
        limit: u32,
    ) -> Result<crate::ScanPage, crate::StoreError> {
        self.store.scan(p, start, end, after, limit).await
    }
    async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, crate::StoreError> {
        if self.blocked.load(std::sync::atomic::Ordering::SeqCst)
            && batch
                .writes
                .iter()
                .any(|write| matches!(write,crate::Write::Put(key,_) if key.as_bytes()==b"ah\0"))
        {
            return Err(crate::StoreError::unavailable(
                "injected acceptance storage failure",
            ));
        }
        self.store.apply(p, batch).await
    }
    async fn stats(&self, p: &Partition) -> Result<crate::PartitionStats, crate::StoreError> {
        self.store.stats(p).await
    }
    async fn probe(&self) -> Result<(), crate::StoreError> {
        self.store.probe().await
    }
}
#[tokio::test]
async fn audit_failure_cannot_commit_a_hold_or_release_bytes() {
    let f = fixture(64).await;
    let store = RejectAcceptance {
        store: f.work.metadata.clone(),
        blocked: Arc::new(std::sync::atomic::AtomicBool::new(true)),
    };
    let engine = Arc::new(
        Engine::new(store, f.work.root.clone(), config("moderation"))
            .with_operations(f.work.clone()),
    );
    let (h, b) = request(admin::SET_LEGAL_HOLD_PATH, &f.hold(true), 1);
    assert_eq!(
        engine
            .handle(admin::SET_LEGAL_HOLD_PATH, &h, &b, 100)
            .await
            .status,
        503
    );
    assert!(!f.state().await.hold);
    assert_eq!(f.head().await, 0);
    let (h, b) = request(admin::READ_PRESERVED_PATH, &f.read(0), 2);
    assert!(matches!(
        engine
            .handle_streamed(admin::READ_PRESERVED_PATH, &h, &b, None, 100)
            .await,
        Reply::Unary(Response { status: 503, .. })
    ));
    let nonces = f
        .work
        .metadata
        .scan(
            &f.work.root,
            &Key::new(b"an\0".to_vec()),
            &Key::new(b"an\x01".to_vec()),
            None,
            10,
        )
        .await
        .unwrap();
    assert_eq!(nonces.entries.len(), 2);
    for (_, value) in nonces.entries {
        assert!(serde_json::from_slice::<Json>(value.as_bytes()).unwrap()["result"].is_null());
    }
    f.audit().await;
}

#[tokio::test]
async fn legal_hold_reason_and_label_follow_existing_utf8_byte_bounds() {
    let f = fixture(64).await;
    let engine = f.engine("moderation");
    for (nonce, reason, label, expected) in [
        (1, "x".repeat(513), "label".into(), 400),
        (2, "court order".into(), "x".repeat(129), 400),
        (3, "é".repeat(257), "label".into(), 400),
        (4, "é".repeat(256), "x".repeat(128), 200),
    ] {
        let mut input = f.hold(true);
        input["reason"] = json!(reason);
        input["operatorLabel"] = json!(label);
        let (h, b) = request(admin::SET_LEGAL_HOLD_PATH, &input, nonce);
        assert_eq!(
            engine
                .handle(admin::SET_LEGAL_HOLD_PATH, &h, &b, 100)
                .await
                .status,
            expected
        );
        assert_eq!(f.state().await.hold, expected == 200);
    }
    f.audit().await;
}

#[tokio::test]
async fn every_restricted_in_flight_retry_is_audited_without_replacing_nonce() {
    let f = fixture(64).await;
    let blocked = Arc::new(
        Engine::new(
            RejectAcceptance {
                store: f.work.metadata.clone(),
                blocked: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            },
            f.work.root.clone(),
            config("moderation"),
        )
        .with_operations(f.work.clone()),
    );
    let operations = [
        (admin::GET_TAKEDOWN_PATH, f.get()),
        (admin::LIST_TAKEDOWNS_PATH, json!({"pageSize":10})),
        (admin::SET_LEGAL_HOLD_PATH, f.hold(true)),
        (admin::READ_PRESERVED_PATH, f.read(0)),
    ];
    for (i, (path, input)) in operations.into_iter().enumerate() {
        let (h, b) = request(path, &input, u8::try_from(i).unwrap() + 1);
        assert!(matches!(
            blocked
                .clone()
                .handle_streamed(path, &h, &b, None, 100)
                .await,
            Reply::Unary(Response { status: 503, .. })
        ));
        for _ in 0..2 {
            assert!(matches!(
                f.engine("moderation")
                    .handle_streamed(path, &h, &b, None, 100)
                    .await,
                Reply::Unary(Response { status: 409, .. })
            ));
        }
        let entries = f.audit().await;
        assert_eq!(entries.len(), (i + 1) * 2);
        for entry in &entries[i * 2..] {
            assert_eq!(entry["procedure"], path);
            assert_eq!(entry["result"]["code"], "aborted");
        }
    }
    assert!(!f.state().await.hold);
}
#[tokio::test]
async fn list_accepts_protojson_null_scope_and_quoted_page_size() {
    let f = fixture(64).await;
    let input = json!({"scope":null,"pageSize":"10"});
    let (h, b) = request(admin::LIST_TAKEDOWNS_PATH, &input, 1);
    let response = f
        .engine("moderation")
        .handle(admin::LIST_TAKEDOWNS_PATH, &h, &b, 100)
        .await;
    assert_eq!(response.status, 200);
    let response: Json = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(response["takedowns"].as_array().unwrap().len(), 1);
    f.audit().await;
}
