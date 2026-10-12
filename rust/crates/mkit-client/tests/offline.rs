//! Per-RPC behaviour against a scripted transport: typed outcomes, caller-owned
//! identity, response caps, the packmap chain walk and fail-closed unpacking.
#![allow(
    clippy::unwrap_used,
    clippy::type_complexity,
    clippy::unnecessary_wraps
)] // unwrap is the assertion in test helpers

use base64::{Engine as _, engine::general_purpose::STANDARD};
use buffa::Message;
use http::{Request, Response};
use mkit_client::{
    Client, Clock, Destination, Error, HttpTransport, Identity as ClientIdentity, MemorySink,
    Signer, UnpackOptions, Verification, proto, unpack,
};
use mkit_core::{
    admission::encode_admission_challenge,
    hash::{Hash, hash},
    object::{Commit, Identity, Object},
    pack::{PackWriter, pack_key},
    refs::RefWriteCondition,
    serialize::serialize,
    sign::{KeyPair, sign_commit},
    transfer,
};
use std::{cell::RefCell, collections::HashMap, time::Duration};

type Handler = Box<dyn Fn(&Request<Vec<u8>>) -> Result<Response<Vec<u8>>, String>>;

struct Script {
    handler: Handler,
    seen: RefCell<Vec<(Request<Vec<u8>>, usize)>>,
}
impl Script {
    fn new(
        handler: impl Fn(&Request<Vec<u8>>) -> Result<Response<Vec<u8>>, String> + 'static,
    ) -> Self {
        Self {
            handler: Box::new(handler),
            seen: RefCell::new(Vec::new()),
        }
    }
}
impl HttpTransport for Script {
    async fn send(
        &self,
        request: Request<Vec<u8>>,
        limit: usize,
    ) -> Result<Response<Vec<u8>>, String> {
        let response = (self.handler)(&request);
        self.seen.borrow_mut().push((request, limit));
        response
    }
}

struct TestSigner;
impl Signer for TestSigner {
    fn public_key(&self) -> Hash {
        [1; 32]
    }
    async fn sign(&self, digest: &Hash) -> Result<[u8; 64], String> {
        let mut out = [0; 64];
        out[..32].copy_from_slice(digest);
        Ok(out)
    }
}
/// A clock that refuses to wait: per-RPC calls must never schedule.
struct NoWaitClock {
    nonces: RefCell<u8>,
}
impl Clock for NoWaitClock {
    fn now_ms(&self) -> i64 {
        1_000_000
    }
    fn nonce(&self) -> Result<Hash, String> {
        let mut n = self.nonces.borrow_mut();
        *n += 1;
        Ok([*n; 32])
    }
    async fn wait(&self, _: Duration) {
        panic!("a per-RPC call waited");
    }
}
fn clock() -> NoWaitClock {
    NoWaitClock {
        nonces: RefCell::new(0),
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
fn json(status: u16, headers: &[(&str, &str)], body: &str) -> Result<Response<Vec<u8>>, String> {
    let mut builder = Response::builder()
        .status(status)
        .header("content-type", "application/json");
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    Ok(builder.body(body.as_bytes().to_vec()).unwrap())
}
fn proto_reply(content_type: &str, body: Vec<u8>) -> Result<Response<Vec<u8>>, String> {
    Ok(Response::builder()
        .status(200)
        .header("content-type", content_type)
        .body(body)
        .unwrap())
}
fn frame(out: &mut Vec<u8>, bytes: &[u8]) {
    out.push(0);
    out.extend_from_slice(&u32::try_from(bytes.len()).unwrap().to_be_bytes());
    out.extend_from_slice(bytes);
}
fn end(out: &mut Vec<u8>) {
    out.push(2);
    out.extend_from_slice(&2_u32.to_be_bytes());
    out.extend_from_slice(b"{}");
}
fn download_reply(
    key: &Hash,
    declared: u64,
    data: &[u8],
    chunk: usize,
) -> Result<Response<Vec<u8>>, String> {
    let mut body = Vec::new();
    frame(
        &mut body,
        &proto::DownloadPackResponse {
            body: Some(
                proto::DownloadPackHeader {
                    total_bytes: Some(declared),
                    ..Default::default()
                }
                .into(),
            ),
            ..Default::default()
        }
        .encode_to_vec(),
    );
    let mut offset = 0;
    let mut parts: Vec<&[u8]> = data.chunks(chunk.max(1)).collect();
    if parts.is_empty() {
        parts.push(&[]);
    }
    for (i, part) in parts.iter().enumerate() {
        frame(
            &mut body,
            &proto::DownloadPackResponse {
                body: Some(
                    proto::PackChunk {
                        pack_id: Some(key.to_vec()),
                        offset: Some(offset),
                        data: Some(part.to_vec()),
                        last: Some(i + 1 == parts.len()),
                        ..Default::default()
                    }
                    .into(),
                ),
                ..Default::default()
            }
            .encode_to_vec(),
        );
        offset += part.len() as u64;
    }
    end(&mut body);
    proto_reply("application/connect+proto", body)
}

fn anonymous(script: &Script) -> Client<'_, Script> {
    Client::anonymous(script, destination())
}

// ---- admission -----------------------------------------------------------

fn challenge_body() -> String {
    let detail = encode_admission_challenge(
        &[("mpp", "id=\"a\", realm=\"x, y\""), ("x402", "opaque")],
        "pay to read",
    );
    serde_json::json!({
        "code": "permission_denied",
        "message": "payment required",
        "details": [{"type": "mkit.transport.v1.AdmissionChallenge", "value": STANDARD.encode(detail)}],
    })
    .to_string()
}

#[test]
fn payment_required_carries_every_challenge_and_header() {
    let script = Script::new(|_| {
        json(
            402,
            &[
                ("www-authenticate", "Payment id=\"a\", realm=\"x, y\""),
                ("www-authenticate", "Payment id=\"b\""),
                ("payment-required", "eyJ4NDAyIjoxfQ"),
            ],
            &challenge_body(),
        )
    });
    let error = block_on(anonymous(&script).read_ref("refs/heads/main", None)).unwrap_err();
    let Error::PaymentRequired(required) = error else {
        panic!("expected a typed challenge");
    };
    let schemes: Vec<_> = required
        .challenges
        .iter()
        .map(|c| c.scheme.as_str())
        .collect();
    assert_eq!(schemes, ["mpp", "x402"]);
    assert_eq!(required.challenges[0].value, "id=\"a\", realm=\"x, y\"");
    assert_eq!(required.description, "pay to read");
    assert_eq!(required.www_authenticate.len(), 2);
    assert_eq!(required.payment_required, ["eyJ4NDAyIjoxfQ"]);
}

#[test]
fn a_402_without_a_connect_body_still_parses_from_headers() {
    let script = Script::new(|_| {
        Ok(Response::builder()
            .status(402)
            .header("content-type", "text/html")
            .header("www-authenticate", "Payment id=\"p\"")
            .header("payment-required", "abc")
            .body(b"<html>pay</html>".to_vec())
            .unwrap())
    });
    let error = block_on(anonymous(&script).pack_exists(&[3; 32], None, None)).unwrap_err();
    let Error::PaymentRequired(required) = error else {
        panic!("expected a typed challenge");
    };
    assert!(required.challenges.is_empty());
    assert_eq!(required.www_authenticate, ["Payment id=\"p\""]);
    assert_eq!(required.payment_required, ["abc"]);
}

#[test]
fn malformed_or_duplicated_challenge_details_are_invalid() {
    let bad_scheme = encode_admission_challenge(&[("Bad Scheme", "v")], "");
    let single = |detail: &[u8]| {
        serde_json::json!({"code":"permission_denied","details":[
            {"type":"mkit.transport.v1.AdmissionChallenge","value":STANDARD.encode(detail)}]})
        .to_string()
    };
    let doubled = {
        let good = STANDARD.encode(encode_admission_challenge(&[("mpp", "v")], ""));
        serde_json::json!({"code":"permission_denied","details":[
            {"type":"mkit.transport.v1.AdmissionChallenge","value":good},
            {"type":"mkit.transport.v1.AdmissionChallenge","value":good}]})
        .to_string()
    };
    for body in [single(&bad_scheme), single(&[]), doubled] {
        let script = Script::new(move |_| json(402, &[], &body));
        let error = block_on(anonymous(&script).read_ref("refs/heads/main", None)).unwrap_err();
        assert!(matches!(error, Error::Invalid(_)), "{error:?}");
    }
}

// ---- resumable outcomes, never a wait ------------------------------------

/// A well-formed advance: the client reads its ref moves back for the observer.
fn valid_advance() -> proto::AdvanceRefsRequest {
    proto::AdvanceRefsRequest {
        head_ref: Some("refs/heads/main".into()),
        head_expectation: Some(proto::RefExpectation::Missing.into()),
        head_new_id: Some([1; 32].to_vec()),
        packmap_ref: Some("refs/mkit/packmap/main".into()),
        packmap_expectation: Some(proto::RefExpectation::Missing.into()),
        packmap_new_id: Some([2; 32].to_vec()),
        ..Default::default()
    }
}

#[test]
fn per_rpc_calls_return_typed_resumable_outcomes_without_waiting() {
    let pending = {
        let detail = proto::PendingVerification {
            retry_after_ms: Some(2000),
            ..Default::default()
        }
        .encode_to_vec();
        serde_json::json!({"code":"unavailable","details":[
            {"type":"type.googleapis.com/mkit.transport.v1.PendingVerification","value":STANDARD.encode(detail)}]})
        .to_string()
    };
    let cases: Vec<(u16, Vec<(&str, &str)>, String)> = vec![
        (503, vec![("retry-after", "5")], pending),
        (
            503,
            vec![],
            r#"{"code":"unavailable","message":"repository membership not yet visible"}"#.into(),
        ),
        (
            503,
            vec![("retry-after", "7")],
            r#"{"code":"unavailable"}"#.into(),
        ),
        (503, vec![], r#"{"code":"unavailable"}"#.into()),
    ];
    let signer = TestSigner;
    let clock = clock();
    for (index, (status, headers, body)) in cases.into_iter().enumerate() {
        let script = Script::new(move |_| json(status, &headers, &body));
        let client = Client::signed(&script, destination(), &signer, &clock);
        let error = block_on(client.advance_refs(&valid_advance(), None)).unwrap_err();
        match (index, error) {
            (0, Error::PendingVerification { retry_after }) => {
                assert_eq!(retry_after, Duration::from_secs(5));
            }
            (1, Error::MembershipNotVisible) => {}
            (2, Error::RetryAfter { ms }) => assert_eq!(ms, 7000),
            (3, Error::Remote(error)) => assert_eq!(error.code, "unavailable"),
            (index, error) => panic!("case {index}: {error:?}"),
        }
    }
}

// ---- caller-owned identity -----------------------------------------------

fn ref_reply() -> Result<Response<Vec<u8>>, String> {
    proto_reply(
        "application/proto",
        proto::ReadRefResponse {
            exists: Some(true),
            object_id: Some(vec![9; 32]),
            ..Default::default()
        }
        .encode_to_vec(),
    )
}

#[test]
fn a_caller_identity_is_used_exactly_and_reported() {
    let script = Script::new(|_| ref_reply());
    let signer = TestSigner;
    let clock = clock();
    let client = Client::signed(&script, destination(), &signer, &clock);
    let identity = client.new_identity().unwrap();
    let nonces_after_new = *clock.nonces.borrow();

    let first = block_on(client.read_ref("refs/heads/main", Some(&identity))).unwrap();
    let replay = block_on(client.read_ref("refs/heads/main", Some(&identity))).unwrap();
    assert_eq!(first.value, Some([9; 32]));
    assert_eq!(first.identity, Some(identity));
    assert_eq!(replay.identity, Some(identity));
    assert_eq!(
        *clock.nonces.borrow(),
        nonces_after_new,
        "no new nonce was drawn"
    );

    let seen = script.seen.borrow();
    assert_eq!(seen.len(), 2);
    for name in [
        "idempotency-key",
        "x-created-at",
        "x-expires-at",
        "x-signature",
        "x-digest",
        "x-content-commitment",
    ] {
        assert_eq!(
            seen[0].0.headers()[name],
            seen[1].0.headers()[name],
            "{name}"
        );
    }
    assert_eq!(
        seen[0].0.headers()["idempotency-key"].to_str().unwrap(),
        identity.idempotency_key()
    );
    assert_eq!(
        seen[0].0.headers()["x-expires-at"].to_str().unwrap(),
        identity.expires_at_ms.to_string()
    );
    assert_eq!(seen[0].0.body(), seen[1].0.body());
    drop(seen);

    // Without one, each call draws its own and returns it.
    let a = block_on(client.read_ref("refs/heads/main", None)).unwrap();
    let b = block_on(client.read_ref("refs/heads/main", None)).unwrap();
    assert_ne!(a.identity.unwrap().nonce, b.identity.unwrap().nonce);
    assert_eq!(
        script.seen.borrow()[2].0.headers()["idempotency-key"]
            .to_str()
            .unwrap(),
        a.identity.unwrap().idempotency_key()
    );
}

#[test]
fn invalid_identities_and_unsigned_writes_are_refused_before_sending() {
    let script = Script::new(|_| ref_reply());
    let signer = TestSigner;
    let clock = clock();
    let client = Client::signed(&script, destination(), &signer, &clock);
    let mut identity = client.new_identity().unwrap();
    identity = ClientIdentity::new(
        identity.nonce,
        identity.created_at_ms,
        identity.created_at_ms + 300_001,
    );
    let error = block_on(client.read_ref("refs/heads/main", Some(&identity))).unwrap_err();
    assert!(matches!(error, Error::Invalid(_)));
    identity = ClientIdentity::new(
        identity.nonce,
        identity.created_at_ms,
        identity.created_at_ms,
    );
    assert!(block_on(client.read_ref("refs/heads/main", Some(&identity))).is_err());

    let anonymous = Client::anonymous(&script, destination());
    let write = block_on(anonymous.update_ref(
        "refs/heads/main",
        RefWriteCondition::Missing,
        [1; 32],
        None,
    ));
    assert!(matches!(write, Err(Error::Invalid(_))));
    let with_identity = block_on(anonymous.read_ref("refs/heads/main", Some(&identity)));
    assert!(matches!(with_identity, Err(Error::Invalid(_))));
    assert!(script.seen.borrow().is_empty(), "nothing was sent");
}

#[test]
fn anonymous_reads_carry_no_credentials() {
    let script = Script::new(|_| {
        proto_reply(
            "application/proto",
            proto::PackExistsResponse {
                exists: Some(true),
                ..Default::default()
            }
            .encode_to_vec(),
        )
    });
    let found =
        block_on(anonymous(&script).pack_exists(&[5; 32], Some("refs/mkit/packmap/main"), None))
            .unwrap();
    assert!(found.value);
    assert!(found.identity.is_none());
    let seen = script.seen.borrow();
    let headers = seen[0].0.headers();
    for name in ["x-signature", "x-public-key", "idempotency-key", "x-digest"] {
        assert!(!headers.contains_key(name), "{name}");
    }
    assert_eq!(headers["x-repository"], "default");
    assert_eq!(headers["x-mkit-ref"], "refs/mkit/packmap/main");
}

// ---- listing -------------------------------------------------------------

#[test]
fn list_refs_pages_with_a_two_mib_response_cap() {
    let script = Script::new(|request| {
        let asked = proto::ListRefsRequest::decode_from_slice(request.body()).unwrap();
        let (name, next) = match asked.page_token.as_deref() {
            Some("") | None => ("a", "t1"),
            Some("t1") => ("b", "t2"),
            _ => ("c", ""),
        };
        proto_reply(
            "application/proto",
            proto::ListRefsResponse {
                refs: vec![proto::RefEntry {
                    name: Some(name.into()),
                    object_id: Some(vec![1; 32]),
                    ..Default::default()
                }],
                next_page_token: Some(next.into()),
                ..Default::default()
            }
            .encode_to_vec(),
        )
    });
    let client = anonymous(&script);
    let all = block_on(client.list_all_refs("refs/heads/", 8)).unwrap();
    let names: Vec<_> = all.iter().map(|r| r.name.as_str()).collect();
    assert_eq!(names, ["a", "b", "c"]);
    assert!(
        script
            .seen
            .borrow()
            .iter()
            .all(|(_, limit)| *limit == 2 * 1024 * 1024)
    );
    assert!(matches!(
        block_on(client.list_all_refs("refs/heads/", 2)),
        Err(Error::Limit(_))
    ));
}

// ---- DownloadPack caps ---------------------------------------------------

fn sample_pack(seed: u8) -> (Hash, Vec<u8>) {
    let mut writer = PackWriter::new_raw_only();
    let bytes = vec![seed; 40];
    writer.push_raw(hash(&bytes), &bytes).unwrap();
    let pack = writer.finish().unwrap();
    (pack_key(&pack), pack)
}

#[test]
fn download_pack_is_bounded_by_the_callers_cap() {
    let (key, pack) = sample_pack(1);
    let size = pack.len() as u64;
    let honest = {
        let pack = pack.clone();
        Script::new(move |_| download_reply(&key, size, &pack, 16))
    };
    let client = anonymous(&honest);
    let got = block_on(client.download_pack(&key, None, size, None)).unwrap();
    assert_eq!(got.value, pack);
    let limit = honest.seen.borrow()[0].1;
    assert!(
        limit >= pack.len() && limit < pack.len() + 64 * 1024,
        "{limit}"
    );

    // A declared size over the cap fails before any chunk is trusted.
    assert!(matches!(
        block_on(client.download_pack(&key, None, size - 1, None)),
        Err(Error::Limit(_))
    ));

    // A header that under-declares, a wrong id and padded data are all rejected.
    let liar = {
        let pack = pack.clone();
        Script::new(move |_| download_reply(&key, size - 1, &pack, 16))
    };
    assert!(block_on(anonymous(&liar).download_pack(&key, None, 1 << 20, None)).is_err());
    let (_, other) = sample_pack(2);
    let swapped = {
        let other = other.clone();
        Script::new(move |_| download_reply(&key, other.len() as u64, &other, 16))
    };
    assert!(matches!(
        block_on(anonymous(&swapped).download_pack(&key, None, 1 << 20, None)),
        Err(Error::Invalid(_))
    ));
}

// ---- packmap chain -------------------------------------------------------

#[test]
fn the_packmap_chain_walks_oldest_first_and_lists_each_pack_once() {
    let (a, b, c) = ([1; 32], [2; 32], [3; 32]);
    let mut nodes: HashMap<Hash, Vec<u8>> = HashMap::new();
    let mut put = |prev: Option<Hash>, packs: &[Hash]| {
        let bytes = transfer::encode_packlist(prev, packs).unwrap();
        let key = pack_key(&bytes);
        nodes.insert(key, bytes);
        key
    };
    let first = put(None, &[a, b]);
    let second = put(Some(first), &[c, a]);
    let script = Script::new(move |request| {
        let body = request.body();
        let asked = proto::DownloadPackRequest::decode_from_slice(&body[5..]).unwrap();
        let key: Hash = asked.pack_id.unwrap().try_into().unwrap();
        let bytes = &nodes[&key];
        download_reply(&key, bytes.len() as u64, bytes, 1024)
    });
    let order =
        block_on(anonymous(&script).resolve_pack_chain(second, "refs/mkit/packmap/main")).unwrap();
    assert_eq!(order, [a, b, c]);
    assert!(
        script
            .seen
            .borrow()
            .iter()
            .all(|(request, _)| request.headers()["x-mkit-ref"] == "refs/mkit/packmap/main")
    );
}

// ---- unpacking and signature verification --------------------------------

fn commit(signer: &KeyPair, label: u8) -> Commit {
    Commit::new_unannotated(
        [label; 32],
        Vec::new(),
        Identity::ed25519(signer.public.0),
        signer.public.0,
        vec![label],
        7,
        [0; 64],
    )
}
fn pack_of(commit: &Commit) -> (Hash, Hash, Vec<u8>) {
    let bytes = serialize(&Object::Commit(commit.clone())).unwrap();
    let id = hash(&bytes);
    let mut writer = PackWriter::new_raw_only();
    writer.push_raw(id, &bytes).unwrap();
    let pack = writer.finish().unwrap();
    (pack_key(&pack), id, pack)
}

#[test]
fn unpack_verifies_signatures_by_default_and_fails_closed() {
    let key = KeyPair::from_seed([7; 32]);

    let mut signed = commit(&key, 1);
    signed.signature = sign_commit(&signed, &key).unwrap().0;
    let (pack_id, id, pack) = pack_of(&signed);
    let mut sink = MemorySink::default();
    let done = unpack(&pack_id, &pack, &mut sink, UnpackOptions::default()).unwrap();
    assert_eq!(done.ids, [id]);
    assert!(sink.objects.contains_key(&id));

    let unsigned = commit(&key, 2);
    let (pack_id, id, pack) = pack_of(&unsigned);
    let mut sink = MemorySink::default();
    let error = unpack(&pack_id, &pack, &mut sink, UnpackOptions::default()).unwrap_err();
    assert!(matches!(error, Error::Signature { .. }), "{error:?}");
    assert!(
        sink.objects.is_empty(),
        "an unverified commit never reaches the sink"
    );

    let mut tampered = commit(&key, 3);
    tampered.signature = sign_commit(&tampered, &key).unwrap().0;
    tampered.message = b"changed".to_vec();
    let (pack_id, id_tampered, pack) = pack_of(&tampered);
    let mut sink = MemorySink::default();
    assert!(matches!(
        unpack(&pack_id, &pack, &mut sink, UnpackOptions::default()),
        Err(Error::Signature { .. })
    ));
    assert!(sink.objects.is_empty());

    // The explicit opt-out stores both.
    let skip = UnpackOptions::default().with_verification(Verification::Skip);
    let mut sink = MemorySink::default();
    unpack(&pack_id, &pack, &mut sink, skip).unwrap();
    assert!(sink.objects.contains_key(&id_tampered));
    let (pack_id, _, pack) = pack_of(&unsigned);
    unpack(&pack_id, &pack, &mut sink, skip).unwrap();
    assert!(sink.objects.contains_key(&id));
}

#[test]
fn unpack_rejects_a_pack_that_is_not_the_requested_one() {
    let key = KeyPair::from_seed([7; 32]);
    let mut signed = commit(&key, 4);
    signed.signature = sign_commit(&signed, &key).unwrap().0;
    let (_, _, pack) = pack_of(&signed);
    let mut sink = MemorySink::default();
    let error = unpack(&[0; 32], &pack, &mut sink, UnpackOptions::default()).unwrap_err();
    assert!(matches!(error, Error::Invalid(_)));
    assert!(sink.objects.is_empty());
}

#[test]
fn a_failing_sink_aborts_the_unpack() {
    struct Full;
    impl mkit_client::ObjectSink for Full {
        fn get(&mut self, _: &Hash) -> Result<Option<Vec<u8>>, String> {
            Ok(None)
        }
        fn put(&mut self, _: Hash, _: &[u8]) -> Result<(), String> {
            Err("disk full".into())
        }
    }
    let key = KeyPair::from_seed([7; 32]);
    let mut signed = commit(&key, 5);
    signed.signature = sign_commit(&signed, &key).unwrap().0;
    let (pack_id, _, pack) = pack_of(&signed);
    let error = unpack(&pack_id, &pack, &mut Full, UnpackOptions::default()).unwrap_err();
    assert!(matches!(error, Error::Sink(message) if message == "disk full"));
}

#[test]
fn a_stream_end_frame_challenge_is_a_typed_payment_required() {
    let (key, _) = sample_pack(1);
    let script = Script::new(move |_| {
        let mut body = Vec::new();
        let detail = encode_admission_challenge(&[("mpp", "v")], "pay");
        let end = serde_json::json!({"error": {"code":"permission_denied","details":[
            {"type":"mkit.transport.v1.AdmissionChallenge","value":STANDARD.encode(detail)}]}})
        .to_string();
        body.push(2);
        body.extend_from_slice(&u32::try_from(end.len()).unwrap().to_be_bytes());
        body.extend_from_slice(end.as_bytes());
        proto_reply("application/connect+proto", body)
    });
    let error = block_on(anonymous(&script).download_pack(&key, None, 1 << 20, None)).unwrap_err();
    assert!(matches!(error, Error::PaymentRequired(r) if r.challenges.len() == 1));
}

#[test]
fn a_flood_of_empty_frames_is_rejected_without_collecting_them() {
    let (key, _) = sample_pack(1);
    let script = Script::new(move |_| {
        let mut body = Vec::new();
        for _ in 0..10_000 {
            frame(&mut body, &[]);
        }
        end(&mut body);
        proto_reply("application/connect+proto", body)
    });
    let error = block_on(anonymous(&script).download_pack(&key, None, 1 << 20, None)).unwrap_err();
    assert!(matches!(error, Error::Invalid(_)), "{error:?}");
}
