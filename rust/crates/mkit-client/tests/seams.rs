//! Host policy seams: operation-scoped signing and the pre-dispatch observer,
//! on the per-RPC calls, the whole push and the public envelope signer.
#![allow(
    clippy::unwrap_used,
    clippy::type_complexity,
    clippy::unnecessary_wraps,
    clippy::too_many_lines
)]

use base64::Engine as _;
use buffa::Message;
use http::{Request, Response};
use mkit_client::{
    Attempt, AttemptHeaders, Client, Clock, Destination, Entry, Error, HttpTransport, Limits,
    Observer, PackmapMode, Plan, Push, RefMove, RefTarget, SignError, Signer, SigningRequest, Veto,
    WriteIntent, procedures, proto,
};
use mkit_core::{
    hash::{Hash, hash},
    object::{Blob, Object},
    pack::pack_key,
    refs::RefWriteCondition,
    serialize::serialize,
    upload_parts::PartPlan,
    write_auth::{self, ContentCommitment, Context},
};
use std::{
    cell::{Cell, RefCell},
    collections::HashSet,
    rc::Rc,
    time::Duration,
};

type Log = Rc<RefCell<Vec<String>>>;

// ---- scripted boundaries ---------------------------------------------------

struct Script {
    handler: Box<dyn Fn(usize, &Request<Vec<u8>>) -> Result<Response<Vec<u8>>, String>>,
    seen: RefCell<Vec<Request<Vec<u8>>>>,
    log: Log,
}
impl Script {
    fn new(
        log: &Log,
        handler: impl Fn(usize, &Request<Vec<u8>>) -> Result<Response<Vec<u8>>, String> + 'static,
    ) -> Self {
        Self {
            handler: Box::new(handler),
            seen: RefCell::new(Vec::new()),
            log: log.clone(),
        }
    }
    fn sent(&self) -> usize {
        self.seen.borrow().len()
    }
}
impl HttpTransport for Script {
    async fn send(&self, request: Request<Vec<u8>>, _: usize) -> Result<Response<Vec<u8>>, String> {
        self.log
            .borrow_mut()
            .push(format!("send {}", method(&request)));
        let response = (self.handler)(self.seen.borrow().len(), &request);
        self.seen.borrow_mut().push(request);
        response
    }
}
fn method(request: &Request<Vec<u8>>) -> String {
    request.uri().path().rsplit('/').next().unwrap().to_owned()
}
fn unary<M: Message>(message: &M) -> Result<Response<Vec<u8>>, String> {
    Ok(Response::builder()
        .status(200)
        .header("content-type", "application/proto")
        .body(message.encode_to_vec())
        .unwrap())
}
fn stream<M: Message>(message: &M) -> Result<Response<Vec<u8>>, String> {
    let bytes = message.encode_to_vec();
    let mut body = vec![0];
    body.extend_from_slice(&u32::try_from(bytes.len()).unwrap().to_be_bytes());
    body.extend_from_slice(&bytes);
    body.extend_from_slice(&[2, 0, 0, 0, 2]);
    body.extend_from_slice(b"{}");
    Ok(Response::builder()
        .status(200)
        .header("content-type", "application/connect+proto")
        .body(body)
        .unwrap())
}
fn error(status: u16, body: &str) -> Result<Response<Vec<u8>>, String> {
    Ok(Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(body.as_bytes().to_vec())
        .unwrap())
}

struct TestClock {
    now: Cell<i64>,
    nonces: Cell<u8>,
    /// Where `wait` leaves the clock, to land exactly on an expiry.
    after_wait: Cell<Option<i64>>,
}
impl TestClock {
    fn new() -> Self {
        Self {
            now: Cell::new(1_000_000),
            nonces: Cell::new(0),
            after_wait: Cell::new(None),
        }
    }
}
impl Clock for TestClock {
    fn now_ms(&self) -> i64 {
        self.now.get()
    }
    fn nonce(&self) -> Result<Hash, String> {
        self.nonces.set(self.nonces.get() + 1);
        Ok([self.nonces.get(); 32])
    }
    async fn wait(&self, _: Duration) {
        if let Some(now) = self.after_wait.get() {
            self.now.set(now);
        }
    }
}

/// Records every signing request. Refuses the procedures it is told to, and
/// can move the clock while signing.
struct PolicySigner {
    log: Log,
    refuse: HashSet<&'static str>,
    seen: RefCell<Vec<(String, ContentCommitment, Attempt)>>,
    advance_clock: Option<(Rc<TestClock>, i64)>,
}
impl PolicySigner {
    fn new(log: &Log) -> Self {
        Self {
            log: log.clone(),
            refuse: HashSet::new(),
            seen: RefCell::new(Vec::new()),
            advance_clock: None,
        }
    }
}
impl Signer for PolicySigner {
    fn public_key(&self) -> Hash {
        [1; 32]
    }
    async fn sign(&self, _: &Hash) -> Result<[u8; 64], String> {
        unreachable!("the client calls sign_operation");
    }
    async fn sign_operation(
        &self,
        request: &SigningRequest<'_>,
        digest: &Hash,
    ) -> Result<[u8; 64], SignError> {
        let name = request.procedure.rsplit('/').next().unwrap();
        self.log.borrow_mut().push(format!("sign {name}"));
        self.seen.borrow_mut().push((
            request.procedure.to_owned(),
            request.commitment,
            request.attempt,
        ));
        assert_eq!(request.audience, "https://vcs.example.org");
        assert_eq!(request.repository, "default");
        if self.refuse.contains(name) {
            return Err(SignError::Refused(format!("{name} is out of scope")));
        }
        if let Some((clock, to)) = &self.advance_clock {
            clock.now.set(*to);
        }
        let mut out = [0; 64];
        out[..32].copy_from_slice(digest);
        Ok(out)
    }
}

/// Records every intent it is shown; vetoes and extra headers are scripted.
struct Recorder {
    log: Log,
    veto: HashSet<&'static str>,
    headers: Vec<(&'static str, &'static str)>,
    seen: RefCell<Vec<Seen>>,
}
#[derive(Clone, Debug)]
struct Seen {
    method: String,
    moves: Vec<RefMove>,
    target_ref: Option<String>,
    pack_id: Option<Hash>,
    bytes: Option<u64>,
    tickets: Vec<Hash>,
    part_index: Option<u32>,
    new_objects: Option<Vec<Hash>>,
    attempt: Attempt,
}
impl Recorder {
    fn new(log: &Log) -> Self {
        Self {
            log: log.clone(),
            veto: HashSet::new(),
            headers: Vec::new(),
            seen: RefCell::new(Vec::new()),
        }
    }
}
impl Observer for Recorder {
    async fn before_dispatch(
        &self,
        intent: &WriteIntent<'_>,
        attempt: &Attempt,
    ) -> Result<AttemptHeaders, Veto> {
        let name = intent.method();
        self.log.borrow_mut().push(format!("observe {name}"));
        self.seen.borrow_mut().push(Seen {
            method: name.to_owned(),
            moves: intent.ref_moves.to_vec(),
            target_ref: intent.target_ref.map(str::to_owned),
            pack_id: intent.pack_id,
            bytes: intent.bytes,
            tickets: intent.ticket_ids.to_vec(),
            part_index: intent.part_index,
            new_objects: intent.new_objects.map(<[Hash]>::to_vec),
            attempt: *attempt,
        });
        if self.veto.contains(name) {
            return Err(Veto::new(format!("{name} blocked")));
        }
        Ok(self
            .headers
            .iter()
            .fold(AttemptHeaders::new(), |h, (k, v)| h.with(*k, *v)))
    }
}

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    match future
        .as_mut()
        .poll(&mut std::task::Context::from_waker(std::task::Waker::noop()))
    {
        std::task::Poll::Ready(value) => value,
        std::task::Poll::Pending => panic!("scripted boundaries complete immediately"),
    }
}
fn destination() -> Destination {
    Destination::new("https://vcs.example.org".into(), "default".into()).unwrap()
}
fn log() -> Log {
    Rc::default()
}
fn header(request: &Request<Vec<u8>>, name: &str) -> String {
    request
        .headers()
        .get(name)
        .unwrap_or_else(|| panic!("no {name}"))
        .to_str()
        .unwrap()
        .to_owned()
}
fn ok_update() -> Script {
    Script::new(&log(), |_, _| unary(&proto::UpdateRefResponse::default()))
}

// ---- signer ------------------------------------------------------------------

#[test]
fn a_signer_that_refuses_one_procedure_blocks_only_that_call() {
    let log = log();
    let script = Script::new(&log, |_, request| match method(request).as_str() {
        "ReadRef" => unary(&proto::ReadRefResponse {
            exists: Some(false),
            ..Default::default()
        }),
        _ => unary(&proto::UpdateRefResponse::default()),
    });
    let mut signer = PolicySigner::new(&log);
    signer.refuse.insert("UpdateRef");
    let clock = TestClock::new();
    let client = Client::signed(&script, destination(), &signer, &clock);

    let refused =
        block_on(client.update_ref("refs/heads/main", RefWriteCondition::Missing, [7; 32], None))
            .unwrap_err();
    assert!(matches!(refused, Error::SignerRefused(ref why) if why.contains("UpdateRef")));
    assert_eq!(script.sent(), 0, "a refused operation sends nothing");

    // Other procedures are unaffected.
    assert!(
        block_on(client.read_ref("refs/heads/main", None))
            .unwrap()
            .value
            .is_none()
    );
    assert_eq!(script.sent(), 1);
    assert_eq!(
        signer.seen.borrow().last().unwrap().0,
        procedures::UPDATE_REF.replace("UpdateRef", "ReadRef")
    );
}

#[test]
fn a_plain_digest_signer_keeps_working() {
    struct Plain;
    impl Signer for Plain {
        fn public_key(&self) -> Hash {
            [1; 32]
        }
        async fn sign(&self, digest: &Hash) -> Result<[u8; 64], String> {
            let mut out = [0; 64];
            out[..32].copy_from_slice(digest);
            Ok(out)
        }
    }
    let script = ok_update();
    let clock = TestClock::new();
    let client = Client::signed(&script, destination(), &Plain, &clock);
    block_on(client.update_ref("refs/heads/main", RefWriteCondition::Any, [1; 32], None)).unwrap();
    assert_eq!(script.sent(), 1);
}

#[test]
fn the_signer_sees_every_commitment_form() {
    let log = log();
    let script = Script::new(&log, |_, request| match method(request).as_str() {
        "UploadPack" => stream(&proto::UploadPackResponse::default()),
        "UploadPart" => stream(&proto::UploadPartResponse::default()),
        _ => unary(&proto::BeginUploadResponse::default()),
    });
    let signer = PolicySigner::new(&log);
    let observer = Recorder::new(&log);
    let clock = TestClock::new();
    let client = Client::signed(&script, destination(), &signer, &clock).with_observer(&observer);

    let pack = vec![9_u8; 100];
    let pack_id = pack_key(&pack);
    block_on(client.upload_pack(&pack_id, &pack, None, None)).unwrap();
    let plan = PartPlan::new((8 << 20) + 100, 8 << 20, 4).unwrap();
    let ticket = proto::UploadTicket {
        id: Some([5; 32].to_vec()),
        token: Some(vec![1, 2, 3]),
        ..Default::default()
    };
    block_on(client.upload_part(&ticket, &plan, 1, &pack, None)).unwrap();
    block_on(client.begin_upload("refs/heads/main", &pack_id, 100, None)).unwrap();

    let seen = signer.seen.borrow();
    assert!(matches!(seen[0].1, ContentCommitment::Pack { id, len: 100 } if id == pack_id));
    assert!(
        matches!(seen[1].1, ContentCommitment::Part(ref p) if p.ticket == [5; 32] && p.index == 1 && p.len == 100)
    );
    assert!(matches!(seen[2].1, ContentCommitment::Body(_)));

    // The observer is told what each write is about.
    let told = observer.seen.borrow();
    assert_eq!((told[0].pack_id, told[0].bytes), (Some(pack_id), Some(100)));
    assert!(
        told[0].new_objects.is_none(),
        "a per-RPC upload cannot know"
    );
    assert_eq!((told[1].part_index, told[1].bytes), (Some(1), Some(100)));
    assert_eq!(told[1].tickets, [[5; 32]]);
    assert_eq!(told[2].target_ref.as_deref(), Some("refs/heads/main"));
    assert_eq!((told[2].pack_id, told[2].bytes), (Some(pack_id), Some(100)));
}

// ---- observer ----------------------------------------------------------------

#[test]
fn an_observer_veto_stops_every_write_before_anything_is_signed_or_sent() {
    let plan = PartPlan::new((8 << 20) + 100, 8 << 20, 4).unwrap();
    let ticket = proto::UploadTicket {
        id: Some([5; 32].to_vec()),
        token: Some(vec![1]),
        ..Default::default()
    };
    for name in [
        "BeginUpload",
        "UploadPack",
        "UploadPart",
        "CompleteUpload",
        "AdvanceRefs",
        "UpdateRef",
    ] {
        let log = log();
        let script = Script::new(&log, |_, _| error(500, r#"{"code":"internal"}"#));
        let signer = PolicySigner::new(&log);
        let mut observer = Recorder::new(&log);
        observer.veto.insert(name);
        let clock = TestClock::new();
        let client =
            Client::signed(&script, destination(), &signer, &clock).with_observer(&observer);
        let pack = vec![9_u8; 100];
        let result = match name {
            "BeginUpload" => {
                block_on(client.begin_upload("refs/heads/main", &[1; 32], 1, None)).map(|_| ())
            }
            "UploadPack" => {
                block_on(client.upload_pack(&pack_key(&pack), &pack, None, None)).map(|_| ())
            }
            "UploadPart" => {
                block_on(client.upload_part(&ticket, &plan, 1, &pack, None)).map(|_| ())
            }
            "CompleteUpload" => {
                block_on(client.complete_upload(&[1], vec![vec![1]], None)).map(|_| ())
            }
            "AdvanceRefs" => block_on(client.advance_refs(&advance(), None)).map(|_| ()),
            _ => block_on(client.delete_ref("refs/heads/x", RefWriteCondition::Any, None))
                .map(|_| ()),
        };
        assert!(
            matches!(result, Err(Error::Vetoed(ref why)) if why == &format!("{name} blocked")),
            "{name}: {result:?}"
        );
        assert_eq!(script.sent(), 0, "{name}: no byte was sent");
        assert!(
            signer.seen.borrow().is_empty(),
            "{name}: nothing was signed"
        );
        assert_eq!(*log.borrow(), [format!("observe {name}")]);
    }
}

fn advance() -> proto::AdvanceRefsRequest {
    proto::AdvanceRefsRequest {
        head_ref: Some("refs/heads/main".into()),
        head_expectation: Some(proto::RefExpectation::Match.into()),
        head_expected_id: Some([3; 32].to_vec()),
        head_new_id: Some([4; 32].to_vec()),
        packmap_ref: Some("refs/mkit/packmap/main".into()),
        packmap_expectation: Some(proto::RefExpectation::Missing.into()),
        packmap_new_id: Some([5; 32].to_vec()),
        ticket_ids: vec![[6; 32].to_vec(), [7; 32].to_vec()],
        ..Default::default()
    }
}

#[test]
fn the_observer_sees_the_exact_ref_moves_and_runs_before_the_signer() {
    let log = log();
    let script = Script::new(&log, |_, request| match method(request).as_str() {
        "AdvanceRefs" => unary(&proto::AdvanceRefsResponse::default()),
        _ => unary(&proto::UpdateRefResponse::default()),
    });
    let signer = PolicySigner::new(&log);
    let observer = Recorder::new(&log);
    let clock = TestClock::new();
    let client = Client::signed(&script, destination(), &signer, &clock).with_observer(&observer);

    block_on(client.update_ref(
        "refs/heads/main",
        RefWriteCondition::Match([8; 32]),
        [9; 32],
        None,
    ))
    .unwrap();
    block_on(client.delete_ref("refs/heads/old", RefWriteCondition::Missing, None)).unwrap();
    block_on(client.advance_refs(&advance(), None)).unwrap();
    let copy = proto::AdvanceRefsRequest {
        head_ref: Some("refs/heads/copy".into()),
        head_expectation: Some(proto::RefExpectation::Missing.into()),
        packmap_ref: Some("refs/mkit/packmap/copy".into()),
        packmap_expectation: Some(proto::RefExpectation::Missing.into()),
        source_ref: Some("refs/heads/main".into()),
        expected_tip: Some([2; 32].to_vec()),
        ..Default::default()
    };
    block_on(client.advance_refs(&copy, None)).unwrap();

    assert_eq!(
        *log.borrow(),
        [
            "observe UpdateRef",
            "sign UpdateRef",
            "send UpdateRef",
            "observe UpdateRef",
            "sign UpdateRef",
            "send UpdateRef",
            "observe AdvanceRefs",
            "sign AdvanceRefs",
            "send AdvanceRefs",
            "observe AdvanceRefs",
            "sign AdvanceRefs",
            "send AdvanceRefs",
        ],
        "observer, then signer, then dispatch"
    );
    let seen = observer.seen.borrow();
    assert_eq!(
        seen[0].moves,
        [RefMove::new(
            "refs/heads/main",
            RefWriteCondition::Match([8; 32]),
            RefTarget::Set([9; 32])
        )]
    );
    assert_eq!(
        seen[1].moves,
        [RefMove::new(
            "refs/heads/old",
            RefWriteCondition::Missing,
            RefTarget::Delete
        )]
    );
    assert_eq!(
        seen[2].moves,
        [
            RefMove::new(
                "refs/heads/main",
                RefWriteCondition::Match([3; 32]),
                RefTarget::Set([4; 32])
            ),
            RefMove::new(
                "refs/mkit/packmap/main",
                RefWriteCondition::Missing,
                RefTarget::Set([5; 32])
            ),
        ]
    );
    assert_eq!(seen[2].tickets, [[6; 32], [7; 32]]);
    assert_eq!(
        seen[3].moves,
        [RefMove::new(
            "refs/heads/copy",
            RefWriteCondition::Missing,
            RefTarget::CopyFrom {
                source: "refs/heads/main".into(),
                expected_tip: Some([2; 32])
            }
        )]
    );
    // The moves are the ones in the request bytes.
    let sent = &script.seen.borrow()[2];
    let decoded = proto::AdvanceRefsRequest::decode_from_slice(sent.body()).unwrap();
    assert_eq!(decoded.head_new_id, advance().head_new_id);
    assert_eq!(decoded.packmap_new_id, advance().packmap_new_id);
}

#[test]
fn observer_and_signer_share_one_attempt_tied_to_the_signed_envelope() {
    let log = log();
    let script = ok_update();
    let signer = PolicySigner::new(&log);
    let observer = Recorder::new(&log);
    let clock = TestClock::new();
    let client = Client::signed(&script, destination(), &signer, &clock).with_observer(&observer);
    let identity = client.new_identity().unwrap();
    block_on(client.update_ref(
        "refs/heads/main",
        RefWriteCondition::Any,
        [1; 32],
        Some(&identity),
    ))
    .unwrap();
    let attempt = observer.seen.borrow()[0].attempt;
    assert_eq!(attempt, signer.seen.borrow()[0].2);
    assert_eq!(attempt.number, 1);
    assert_eq!(attempt.nonce, identity.nonce);
    assert_eq!(attempt.created_at_ms, identity.created_at_ms);
    assert_eq!(attempt.expires_at_ms, identity.expires_at_ms);
    let request = &script.seen.borrow()[0];
    assert_eq!(
        header(request, "idempotency-key"),
        identity.idempotency_key()
    );
    assert_eq!(
        header(request, "x-created-at"),
        attempt.created_at_ms.to_string()
    );
    assert_eq!(
        header(request, "x-expires-at"),
        attempt.expires_at_ms.to_string()
    );
}

#[test]
fn per_attempt_headers_ride_along_unsigned_and_reserved_names_are_refused() {
    let write = |headers: Vec<(&'static str, &'static str)>| {
        let log = log();
        let script = ok_update();
        let signer = PolicySigner::new(&log);
        let mut observer = Recorder::new(&log);
        observer.headers = headers;
        let clock = TestClock::new();
        let client =
            Client::signed(&script, destination(), &signer, &clock).with_observer(&observer);
        let result =
            block_on(client.update_ref("refs/heads/main", RefWriteCondition::Any, [1; 32], None));
        let signatures = signer.seen.borrow().len();
        let request = script.seen.borrow().first().cloned();
        (result, signatures, request)
    };

    let (result, signatures, request) = write(vec![
        (
            "traceparent",
            "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
        ),
        ("x-request-id", "abc"),
    ]);
    result.unwrap();
    assert_eq!(signatures, 1);
    let request = request.unwrap();
    assert_eq!(header(&request, "x-request-id"), "abc");
    assert!(request.headers().contains_key("traceparent"));
    assert!(request.headers().contains_key("x-signature"));

    for reserved in [
        "X-Signature",
        "x-public-key",
        "x-digest",
        "x-created-at",
        "x-expires-at",
        "x-envelope-version",
        "x-audience",
        "x-repository",
        "x-content-commitment",
        "x-write-grant",
        "x-mkit-ref",
        "x-mkit-anything",
        "x-forwarded-for",
        "host",
        "content-type",
        "content-length",
        "transfer-encoding",
        "connect-protocol-version",
        "cookie",
        "idempotency-key",
        "authorization",
        "connection",
        "keep-alive",
        "proxy-authorization",
        "te",
        "trailer",
        "upgrade",
    ] {
        let (result, signatures, request) = write(vec![(reserved, "v")]);
        assert!(
            matches!(result, Err(Error::ReservedHeader(ref name)) if name == &reserved.to_ascii_lowercase()),
            "{reserved}: {result:?}"
        );
        assert_eq!(signatures, 0, "{reserved}: refused before signing");
        assert!(request.is_none(), "{reserved}: nothing sent");
    }
    // Malformed and duplicate names.
    assert!(matches!(
        write(vec![("bad name", "v")]).0,
        Err(Error::Invalid(_))
    ));
    assert!(matches!(
        write(vec![("x-a", "1"), ("X-A", "2")]).0,
        Err(Error::Invalid(_))
    ));
}

// ---- deadline ------------------------------------------------------------------

#[test]
fn an_envelope_that_expires_before_dispatch_is_never_sent() {
    let log = log();
    let script = ok_update();
    let clock = Rc::new(TestClock::new());
    let mut signer = PolicySigner::new(&log);
    // The signer takes longer than the validity window.
    signer.advance_clock = Some((clock.clone(), 1_000_000 + 300_000));
    let client = Client::signed(&script, destination(), &signer, &*clock);
    let result =
        block_on(client.update_ref("refs/heads/main", RefWriteCondition::Any, [1; 32], None));
    assert!(matches!(result, Err(Error::EnvelopeExpired)), "{result:?}");
    assert_eq!(script.sent(), 0);

    // An identity that has already ended never reaches the observer or signer.
    clock.now.set(2_000_000);
    let log = self::log();
    let signer = PolicySigner::new(&log);
    let observer = Recorder::new(&log);
    let client = Client::signed(&script, destination(), &signer, &*clock).with_observer(&observer);
    let stale = mkit_client::Identity::new([1; 32], 1_500_000, 1_800_000);
    let result = block_on(client.update_ref(
        "refs/heads/main",
        RefWriteCondition::Any,
        [1; 32],
        Some(&stale),
    ));
    assert!(matches!(result, Err(Error::EnvelopeExpired)), "{result:?}");
    assert!(log.borrow().is_empty());
    assert_eq!(script.sent(), 0);
}

#[test]
fn a_malformed_advance_is_refused_before_policy_or_dispatch() {
    let log = log();
    let script = ok_update();
    let signer = PolicySigner::new(&log);
    let observer = Recorder::new(&log);
    let clock = TestClock::new();
    let client = Client::signed(&script, destination(), &signer, &clock).with_observer(&observer);
    for request in [
        proto::AdvanceRefsRequest::default(),
        proto::AdvanceRefsRequest {
            head_new_id: Some(vec![1; 5]),
            ..advance()
        },
    ] {
        assert!(matches!(
            block_on(client.advance_refs(&request, None)),
            Err(Error::Invalid(_))
        ));
    }
    assert!(log.borrow().is_empty());
    assert_eq!(script.sent(), 0);
}

// ---- public envelope signer ------------------------------------------------------

struct RealSigner(ed25519_dalek::SigningKey);
impl Signer for RealSigner {
    fn public_key(&self) -> Hash {
        self.0.verifying_key().to_bytes()
    }
    async fn sign(&self, digest: &Hash) -> Result<[u8; 64], String> {
        use ed25519_dalek::Signer as _;
        Ok(self.0.sign(digest).to_bytes())
    }
}

fn verify(
    request_headers: &http::HeaderMap,
    procedure: &str,
    expected: write_auth::ExpectedCommitment<'_>,
    now: i64,
) -> Result<write_auth::Authorized, write_auth::AuthError> {
    let get = |name: &str| {
        request_headers
            .get(name)
            .map(|v| v.to_str().unwrap().to_owned())
    };
    write_auth::verify_headers_with(
        Context {
            audience: "https://vcs.example.org",
            repository: "default",
        },
        procedure,
        expected,
        now,
        &write_auth::Headers {
            version: get("x-envelope-version"),
            audience: get("x-audience"),
            repository: get("x-repository"),
            public_key: get("x-public-key"),
            signature: get("x-signature"),
            digest: get("x-digest"),
            commitment: get("x-content-commitment"),
            created_at: get("x-created-at"),
            expires_at: get("x-expires-at"),
            idempotency_key: get("idempotency-key"),
        },
    )
}

#[test]
fn the_public_envelope_signer_verifies_against_the_server_validator() {
    let log = log();
    let script = ok_update();
    let signer = RealSigner(ed25519_dalek::SigningKey::from_bytes(&[42; 32]));
    let mut observer = Recorder::new(&log);
    observer.headers = vec![("x-request-id", "r1")];
    let clock = TestClock::new();
    let client = Client::signed(&script, destination(), &signer, &clock).with_observer(&observer);

    // A procedure the host dispatches through its own binding.
    let body = b"in-process request body";
    let commitment = ContentCommitment::Body(hash(body));
    let procedure = procedures::UPDATE_REF;
    let moves = [RefMove::new(
        "refs/heads/main",
        RefWriteCondition::Any,
        RefTarget::Set([1; 32]),
    )];
    let intent = WriteIntent::new(procedure).with_ref_moves(&moves);
    let identity = client.new_identity().unwrap();
    let envelope =
        block_on(client.sign_envelope(procedure, &commitment, Some(&identity), Some(&intent)))
            .unwrap();
    assert_eq!(envelope.identity, identity);
    assert_eq!(header_of(&envelope.headers, "x-request-id"), "r1");
    let text = commitment.to_string();
    let authorized = verify(
        &envelope.headers,
        procedure,
        write_auth::ExpectedCommitment::Exact(&text),
        clock.now_ms(),
    )
    .unwrap();
    assert_eq!(authorized.nonce, identity.idempotency_key());
    assert_eq!(authorized.commitment, text);
    // The observer ran for the supplied intent, once, as attempt 1.
    assert_eq!(observer.seen.borrow().len(), 1);
    assert_eq!(observer.seen.borrow()[0].moves, moves);
    // A different procedure does not verify.
    assert!(
        verify(
            &envelope.headers,
            procedures::ADVANCE_REFS,
            write_auth::ExpectedCommitment::Exact(&text),
            clock.now_ms()
        )
        .is_err()
    );
    // Not dispatched by the client.
    assert_eq!(script.sent(), 0);

    // A pack commitment verifies as a pack stream.
    let pack = ContentCommitment::Pack {
        id: [3; 32],
        len: 10,
    };
    let envelope = block_on(client.sign_envelope(
        procedures::UPLOAD_PACK,
        &pack,
        None,
        Some(&WriteIntent::new(procedures::UPLOAD_PACK)),
    ))
    .unwrap();
    verify(
        &envelope.headers,
        procedures::UPLOAD_PACK,
        write_auth::ExpectedCommitment::PackStream,
        clock.now_ms(),
    )
    .unwrap();
    assert_eq!(observer.seen.borrow().len(), 2);
}
fn header_of(headers: &http::HeaderMap, name: &str) -> String {
    headers.get(name).unwrap().to_str().unwrap().to_owned()
}

#[test]
fn the_public_envelope_signer_applies_the_same_policy() {
    let log = log();
    let script = ok_update();
    let mut signer = PolicySigner::new(&log);
    signer.refuse.insert("UpdateRef");
    let mut observer = Recorder::new(&log);
    observer.veto.insert("AdvanceRefs");
    let clock = TestClock::new();
    let client = Client::signed(&script, destination(), &signer, &clock).with_observer(&observer);
    let commitment = ContentCommitment::Body([1; 32]);
    assert!(matches!(
        block_on(client.sign_envelope(
            procedures::UPDATE_REF,
            &commitment,
            None,
            Some(&WriteIntent::new(procedures::UPDATE_REF))
        )),
        Err(Error::SignerRefused(_))
    ));
    let intent = WriteIntent::new(procedures::ADVANCE_REFS);
    assert!(matches!(
        block_on(client.sign_envelope(procedures::ADVANCE_REFS, &commitment, None, Some(&intent))),
        Err(Error::Vetoed(_))
    ));
    let anonymous = Client::anonymous(&script, destination());
    assert!(matches!(
        block_on(anonymous.sign_envelope(procedures::UPDATE_REF, &commitment, None, None)),
        Err(Error::Invalid(_))
    ));
}

// ---- whole push --------------------------------------------------------------------

fn blob(salt: u8) -> Entry {
    let bytes = serialize(&Object::Blob(Blob {
        data: vec![salt; 10],
    }))
    .unwrap();
    Entry::Raw {
        id: hash(&bytes),
        bytes,
    }
}
fn info() -> proto::GetServerInfoResponse {
    proto::GetServerInfoResponse {
        protocol: Some("mkit.transport.v1".into()),
        spec_version: Some(2),
        atomic_advance: Some(true),
        max_pack_bytes: Some(1 << 20),
        max_parts: Some(16),
        begin_upload_threshold_bytes: Some(1 << 40),
        ..Default::default()
    }
}
fn push_fixture() -> (Push, Hash) {
    let limits = Limits::from_server_info(&info(), 1 << 16, 1 << 20).unwrap();
    let entry = blob(1);
    let Entry::Raw { id, .. } = entry.clone() else {
        unreachable!()
    };
    let plan = Plan::prepare([entry], limits).unwrap();
    (
        Push::new(
            destination(),
            "main",
            RefWriteCondition::Missing,
            [4; 32],
            PackmapMode::Append {
                self_contained: true,
            },
            plan,
            i64::MAX,
        )
        .unwrap(),
        id,
    )
}
fn server(
    log: &Log,
    advance: impl Fn(usize) -> Result<Response<Vec<u8>>, String> + 'static,
) -> Script {
    let calls = Cell::new(0);
    Script::new(log, move |_, request| match method(request).as_str() {
        "GetServerInfo" => unary(&info()),
        "UploadPack" => stream(&proto::UploadPackResponse::default()),
        "ReadRef" => unary(&proto::ReadRefResponse {
            exists: Some(false),
            ..Default::default()
        }),
        "AdvanceRefs" => {
            calls.set(calls.get() + 1);
            advance(calls.get())
        }
        other => panic!("unexpected {other}"),
    })
}

#[test]
fn a_whole_push_runs_the_observer_and_signer_for_every_write() {
    let log = log();
    let script = server(&log, |_| {
        unary(&proto::AdvanceRefsResponse {
            outcome: Some(proto::AdvanceOutcome::Committed.into()),
            ..Default::default()
        })
    });
    let signer = PolicySigner::new(&log);
    let observer = Recorder::new(&log);
    let clock = TestClock::new();
    let (push, object) = push_fixture();
    let outcome = block_on(push.run_with(&script, &signer, &clock, &observer)).unwrap();
    assert_eq!(outcome, mkit_client::Outcome::Committed);

    let seen = observer.seen.borrow();
    let methods: Vec<_> = seen.iter().map(|s| s.method.as_str()).collect();
    assert_eq!(methods, ["UploadPack", "UploadPack", "AdvanceRefs"]);
    // The data pack names the objects it introduces; the packmap node does not.
    assert_eq!(seen[0].new_objects.as_deref(), Some(&[object][..]));
    assert!(seen[1].new_objects.is_none());
    assert_eq!(seen[2].moves.len(), 2);
    assert_eq!(seen[2].moves[0].name, "refs/heads/main");
    assert_eq!(seen[2].moves[0].new, RefTarget::Set([4; 32]));
    assert_eq!(seen[2].moves[1].name, "refs/mkit/packmap/main");
    // Observer precedes signer precedes dispatch, per write.
    let log = log.borrow();
    for name in ["UploadPack", "AdvanceRefs"] {
        let at = |what: String| log.iter().position(|l| *l == what).unwrap();
        assert!(at(format!("observe {name}")) < at(format!("sign {name}")));
        assert!(at(format!("sign {name}")) < at(format!("send {name}")));
    }

    // Without an observer the push is unchanged (`run`).
    let script = server(&self::log(), |_| {
        unary(&proto::AdvanceRefsResponse {
            outcome: Some(proto::AdvanceOutcome::Committed.into()),
            ..Default::default()
        })
    });
    let outcome = block_on(push.run(&script, &PolicySigner::new(&self::log()), &clock)).unwrap();
    assert_eq!(outcome, mkit_client::Outcome::Committed);
}

#[test]
fn a_veto_in_a_whole_push_sends_no_write() {
    let log = log();
    let script = server(&log, |_| unreachable!());
    let signer = PolicySigner::new(&log);
    let mut observer = Recorder::new(&log);
    observer.veto.insert("UploadPack");
    let clock = TestClock::new();
    let (push, _) = push_fixture();
    let result = block_on(push.run_with(&script, &signer, &clock, &observer));
    assert!(matches!(result, Err(Error::Vetoed(_))), "{result:?}");
    let sent: Vec<_> = script.seen.borrow().iter().map(method).collect();
    assert_eq!(sent, ["GetServerInfo"], "only discovery went out");
    assert!(signer.seen.borrow().is_empty());

    // A signer that refuses the final advance still lets the earlier steps
    // happen but sends no advance.
    let log = self::log();
    let script = server(&log, |_| unreachable!());
    let mut signer = PolicySigner::new(&log);
    signer.refuse.insert("AdvanceRefs");
    let observer = Recorder::new(&log);
    let result = block_on(push.run_with(&script, &signer, &clock, &observer));
    assert!(matches!(result, Err(Error::SignerRefused(_))), "{result:?}");
    assert!(
        !script
            .seen
            .borrow()
            .iter()
            .any(|r| method(r) == "AdvanceRefs")
    );
}

#[test]
fn a_poll_resends_the_same_envelope_and_a_renewed_envelope_is_a_new_attempt() {
    let pending = {
        let detail = proto::PendingVerification {
            retry_after_ms: Some(1000),
            ..Default::default()
        }
        .encode_to_vec();
        serde_json::json!({"code":"unavailable","details":[
            {"type":"type.googleapis.com/mkit.transport.v1.PendingVerification",
             "value":base64::engine::general_purpose::STANDARD.encode(detail)}]})
        .to_string()
    };
    let log = log();
    let script = server(&log, move |call| match call {
        1 => error(503, &pending),
        2 => error(401, r#"{"code":"unauthenticated"}"#),
        _ => unary(&proto::AdvanceRefsResponse {
            outcome: Some(proto::AdvanceOutcome::Committed.into()),
            ..Default::default()
        }),
    });
    let signer = PolicySigner::new(&log);
    let observer = Recorder::new(&log);
    let clock = TestClock::new();
    let (push, _) = push_fixture();
    block_on(push.run_with(&script, &signer, &clock, &observer)).unwrap();

    let advances: Vec<_> = script
        .seen
        .borrow()
        .iter()
        .filter(|r| method(r) == "AdvanceRefs")
        .cloned()
        .collect();
    assert_eq!(advances.len(), 3);
    // The poll after "pending" resends the identical signed bytes.
    assert_eq!(
        header(&advances[0], "x-signature"),
        header(&advances[1], "x-signature")
    );
    // The rejection after a pending answer renews the envelope: a new attempt
    // with a new nonce, observed and signed again.
    assert_ne!(
        header(&advances[1], "idempotency-key"),
        header(&advances[2], "idempotency-key")
    );
    let seen = observer.seen.borrow();
    let attempts: Vec<_> = seen
        .iter()
        .filter(|s| s.method == "AdvanceRefs")
        .map(|s| (s.attempt.number, s.attempt.nonce))
        .collect();
    assert_eq!(attempts.len(), 2, "observer once per signed envelope");
    assert_eq!(attempts[0].0, 1);
    assert_eq!(attempts[1].0, 2);
    assert_ne!(attempts[0].1, attempts[1].1);
    let signings = signer.seen.borrow();
    let signed_attempts: Vec<_> = signings
        .iter()
        .filter(|s| s.0.ends_with("AdvanceRefs"))
        .map(|s| (s.2.number, s.2.nonce))
        .collect();
    assert_eq!(
        signed_attempts, attempts,
        "signer sees the observer's attempts"
    );
}

#[test]
fn sign_envelope_cannot_skip_or_mislabel_the_observed_intent() {
    let log = log();
    let script = ok_update();
    let signer = PolicySigner::new(&log);
    let observer = Recorder::new(&log);
    let clock = TestClock::new();
    let client = Client::signed(&script, destination(), &signer, &clock).with_observer(&observer);
    let commitment = ContentCommitment::Body([1; 32]);
    // A write without an intent, and an intent for another procedure.
    assert!(matches!(
        block_on(client.sign_envelope(procedures::UPDATE_REF, &commitment, None, None)),
        Err(Error::Invalid(_))
    ));
    let other = WriteIntent::new(procedures::ADVANCE_REFS);
    assert!(matches!(
        block_on(client.sign_envelope(procedures::UPDATE_REF, &commitment, None, Some(&other))),
        Err(Error::Invalid(_))
    ));
    assert!(log.borrow().is_empty(), "no seam ran");
    // A non-write procedure needs no intent and is not observed.
    let read = "/mkit.transport.v1.TransportService/ReadRef";
    block_on(client.sign_envelope(read, &commitment, None, None)).unwrap();
    assert!(observer.seen.borrow().is_empty());
    // An administrative procedure is outside the six write RPCs: it reaches the
    // signer, and is observed only when the host passes an intent.
    let admin = "/mkit.transport.v1.TransportService/SetRepoVisibility";
    block_on(client.sign_envelope(admin, &commitment, None, None)).unwrap();
    assert!(observer.seen.borrow().is_empty());
    assert_eq!(signer.seen.borrow().last().unwrap().0, admin);
    block_on(client.sign_envelope(admin, &commitment, None, Some(&WriteIntent::new(admin))))
        .unwrap();
    assert_eq!(observer.seen.borrow().len(), 1);
}

#[test]
fn replaying_a_persisted_identity_runs_the_seams_again_with_the_same_nonce() {
    let log = log();
    let script = ok_update();
    let signer = PolicySigner::new(&log);
    let observer = Recorder::new(&log);
    let clock = TestClock::new();
    let client = Client::signed(&script, destination(), &signer, &clock).with_observer(&observer);
    let identity = client.new_identity().unwrap();
    for _ in 0..2 {
        block_on(client.update_ref(
            "refs/heads/main",
            RefWriteCondition::Any,
            [1; 32],
            Some(&identity),
        ))
        .unwrap();
    }
    let seen = observer.seen.borrow();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0].attempt, seen[1].attempt);
    assert_eq!(seen[1].attempt.nonce, identity.nonce);
    let sent = script.seen.borrow();
    assert_eq!(
        header(&sent[0], "x-signature"),
        header(&sent[1], "x-signature")
    );
}

#[test]
fn a_window_cut_short_by_the_push_deadline_is_a_deadline_error() {
    let log = log();
    let script = server(&log, |_| unreachable!());
    let clock = Rc::new(TestClock::new());
    let mut signer = PolicySigner::new(&log);
    signer.advance_clock = Some((clock.clone(), 1_000_000 + 10_000));
    let limits = Limits::from_server_info(&info(), 1 << 16, 1 << 20).unwrap();
    let plan = Plan::prepare([blob(1)], limits).unwrap();
    let push = Push::new(
        destination(),
        "main",
        RefWriteCondition::Missing,
        [4; 32],
        PackmapMode::Append {
            self_contained: true,
        },
        plan,
        1_000_000 + 5_000,
    )
    .unwrap();
    let result = block_on(push.run(&script, &signer, &*clock));
    assert!(matches!(result, Err(Error::Deadline)), "{result:?}");
}

#[test]
fn a_poll_that_lands_on_the_expiry_renews_the_envelope() {
    let pending = pending_body();
    let log = log();
    let script = server(&log, move |call| match call {
        1 => error(503, &pending),
        _ => unary(&proto::AdvanceRefsResponse {
            outcome: Some(proto::AdvanceOutcome::Committed.into()),
            ..Default::default()
        }),
    });
    let signer = PolicySigner::new(&log);
    let observer = Recorder::new(&log);
    let clock = TestClock::new();
    // The envelope is created at 1_000_000 and expires 300 s later.
    clock.after_wait.set(Some(1_300_000));
    let (push, _) = push_fixture();
    block_on(push.run_with(&script, &signer, &clock, &observer)).unwrap();
    let advances: Vec<_> = script
        .seen
        .borrow()
        .iter()
        .filter(|r| method(r) == "AdvanceRefs")
        .cloned()
        .collect();
    assert_eq!(advances.len(), 2);
    assert_ne!(
        header(&advances[0], "idempotency-key"),
        header(&advances[1], "idempotency-key"),
        "an envelope at its expiry is not re-sent"
    );
    let numbers: Vec<_> = observer
        .seen
        .borrow()
        .iter()
        .filter(|s| s.method == "AdvanceRefs")
        .map(|s| s.attempt.number)
        .collect();
    assert_eq!(numbers, [1, 2]);
}

fn pending_body() -> String {
    let detail = proto::PendingVerification {
        retry_after_ms: Some(1000),
        ..Default::default()
    }
    .encode_to_vec();
    serde_json::json!({"code":"unavailable","details":[
        {"type":"type.googleapis.com/mkit.transport.v1.PendingVerification",
         "value":base64::engine::general_purpose::STANDARD.encode(detail)}]})
    .to_string()
}

fn ticket_info() -> proto::GetServerInfoResponse {
    proto::GetServerInfoResponse {
        max_pack_bytes: Some(32 << 20),
        begin_upload_threshold_bytes: Some(0),
        ..info()
    }
}

#[test]
fn a_ticketed_multipart_push_reports_tickets_and_new_objects_on_each_rpc() {
    let log = log();
    let ticket = proto::UploadTicket {
        id: Some([9; 32].to_vec()),
        token: Some(vec![1, 2, 3]),
        part_size: Some(8 << 20),
        expires_unix_ms: Some(i64::MAX),
        ..Default::default()
    };
    let script = Script::new(&log, move |_, request| match method(request).as_str() {
        "GetServerInfo" => unary(&ticket_info()),
        "BeginUpload" => unary(&proto::BeginUploadResponse {
            result: Some(proto::begin_upload_response::Result::Ticket(Box::new(
                ticket.clone(),
            ))),
            ..Default::default()
        }),
        "UploadPart" => stream(&proto::UploadPartResponse {
            receipt: Some(vec![7]),
            ..Default::default()
        }),
        "UploadPack" => stream(&proto::UploadPackResponse::default()),
        "CompleteUpload" => unary(&proto::CompleteUploadResponse::default()),
        "ReadRef" => unary(&proto::ReadRefResponse {
            exists: Some(false),
            ..Default::default()
        }),
        "AdvanceRefs" => unary(&proto::AdvanceRefsResponse {
            outcome: Some(proto::AdvanceOutcome::Committed.into()),
            ..Default::default()
        }),
        other => panic!("unexpected {other}"),
    });
    let limits = Limits::from_server_info(&ticket_info(), 16 << 20, 64 << 20).unwrap();
    let bytes = serialize(&Object::Blob(Blob {
        // Incompressible, so the pack exceeds one part with or without zstd.
        data: {
            let mut state = 0x9e37_79b9_7f4a_7c15_u64;
            (0..(8 << 20) + 1000)
                .map(|_| {
                    state = state
                        .wrapping_mul(6_364_136_223_846_793_005)
                        .wrapping_add(1_442_695_040_888_963_407);
                    (state >> 56) as u8
                })
                .collect()
        },
    }))
    .unwrap();
    let id = hash(&bytes);
    let plan = Plan::prepare([Entry::Raw { id, bytes }], limits).unwrap();
    let push = Push::new(
        destination(),
        "main",
        RefWriteCondition::Missing,
        [4; 32],
        PackmapMode::Append {
            self_contained: true,
        },
        plan,
        i64::MAX,
    )
    .unwrap();
    let signer = PolicySigner::new(&log);
    let observer = Recorder::new(&log);
    let clock = TestClock::new();
    block_on(push.run_with(&script, &signer, &clock, &observer)).unwrap();

    let seen = observer.seen.borrow();
    let methods: Vec<_> = seen.iter().map(|s| s.method.as_str()).collect();
    assert_eq!(
        methods,
        [
            "BeginUpload",
            "UploadPart",
            "UploadPart",
            "CompleteUpload",
            "BeginUpload",
            "UploadPack",
            "AdvanceRefs"
        ]
    );
    // The data pack: every RPC of its upload names the object and the ticket.
    for step in &seen[..4] {
        assert_eq!(
            step.new_objects.as_deref(),
            Some(&[id][..]),
            "{}",
            step.method
        );
    }
    assert_eq!(seen[1].tickets, [[9; 32]]);
    assert_eq!(seen[2].part_index, Some(1));
    assert_eq!(seen[3].tickets, [[9; 32]]);
    // The packmap node: ticketed single-shot, no objects.
    assert!(seen[4].new_objects.is_none() && seen[5].new_objects.is_none());
    assert_eq!(seen[5].tickets, [[9; 32]]);
    // The advance consumes both tickets.
    assert_eq!(seen[6].tickets.len(), 2);
}

#[test]
fn a_pack_with_a_delta_entry_reports_no_new_objects() {
    let log = log();
    let script = server(&log, |_| {
        unary(&proto::AdvanceRefsResponse {
            outcome: Some(proto::AdvanceOutcome::Committed.into()),
            ..Default::default()
        })
    });
    let limits = Limits::from_server_info(&info(), 1 << 16, 1 << 20).unwrap();
    let plan = Plan::prepare(
        [
            blob(1),
            Entry::Delta {
                base: [1; 32],
                stream: vec![0; 4],
            },
        ],
        limits,
    )
    .unwrap();
    let push = Push::new(
        destination(),
        "main",
        RefWriteCondition::Missing,
        [4; 32],
        PackmapMode::Append {
            self_contained: true,
        },
        plan,
        i64::MAX,
    )
    .unwrap();
    let signer = PolicySigner::new(&log);
    let observer = Recorder::new(&log);
    let clock = TestClock::new();
    block_on(push.run_with(&script, &signer, &clock, &observer)).unwrap();
    let seen = observer.seen.borrow();
    assert_eq!(seen[0].method, "UploadPack");
    assert!(seen[0].new_objects.is_none());
}
