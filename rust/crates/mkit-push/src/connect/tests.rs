use super::*;

fn pending(value: Option<u32>, header: Option<&str>) -> RemoteError {
    let detail = crate::proto::PendingVerification {
        retry_after_ms: value,
        ..Default::default()
    }
    .encode_to_vec();
    let mut error = RemoteError {
        code: "unavailable".into(),
        message: String::new(),
        details: vec![Detail {
            type_url: "type.googleapis.com/mkit.transport.v1.PendingVerification".into(),
            value: Some(STANDARD_NO_PAD.encode(detail)),
        }],
        status: 503,
        headers: HeaderMap::new(),
    };
    if let Some(header) = header {
        error.headers.insert("retry-after", header.parse().unwrap());
    }
    error
}

#[test]
fn only_typed_pending_honors_bounded_retry_hints() {
    for (value, header, milliseconds) in [
        (None, None, 1000),
        (Some(0), None, 1000),
        (Some(2000), Some("5"), 5000),
        (Some(u32::MAX), Some("999999999999999"), 60_000),
    ] {
        assert_eq!(
            pending_delay(&pending(value, header)),
            Some(Duration::from_millis(milliseconds))
        );
    }
    let mut error = pending(Some(2000), Some("5"));
    error.details[0].value = Some("invalid".into());
    assert_eq!(pending_delay(&error), None);
    error = pending(Some(2000), Some("5"));
    error.code = "permission_denied".into();
    assert_eq!(pending_delay(&error), None);
    error = pending(Some(2000), Some("5"));
    error.details.push(error.details[0].clone());
    assert_eq!(pending_delay(&error), None);
}

#[test]
fn streaming_end_errors_and_truncation_fail_closed() {
    for bytes in [
        b"\0".as_slice(),
        b"\0\0\0\0\x05abc",
        b"\x01\0\0\0\0",
        b"\0\0\0\0\0",
    ] {
        assert!(decode_stream(bytes).is_err());
    }
    let mut bytes = Vec::new();
    frame(&mut bytes, b"protobuf").unwrap();
    let end = br#"{"error":{"code":"failed_precondition","message":"ticket rejected"}}"#;
    bytes.push(2);
    bytes.extend_from_slice(&u32::try_from(end.len()).unwrap().to_be_bytes());
    bytes.extend_from_slice(end);
    assert!(
        matches!(decode_stream(&bytes), Err(Error::Remote(error)) if error.code == "failed_precondition")
    );
}

struct ScriptClock {
    now: std::cell::Cell<i64>,
    wake_at: std::cell::Cell<Option<i64>>,
    nonce: std::cell::Cell<u8>,
}
impl Clock for ScriptClock {
    fn now_ms(&self) -> i64 {
        self.now.get()
    }
    fn nonce(&self) -> Result<Hash, String> {
        let next = self.nonce.get() + 1;
        self.nonce.set(next);
        Ok([next; 32])
    }
    async fn wait(&self, duration: Duration) {
        self.now.set(
            self.wake_at
                .take()
                .unwrap_or_else(|| self.now.get() + i64::try_from(duration.as_millis()).unwrap()),
        );
    }
}
struct ScriptSigner;
impl Signer for ScriptSigner {
    fn public_key(&self) -> Hash {
        [1; 32]
    }
    async fn sign(&self, _: &Hash) -> Result<[u8; 64], String> {
        Ok([0; 64])
    }
}
enum Reply {
    Pending,
    ExpiredInTransit(i64),
    Unauthenticated,
    Committed,
    Lost,
}
struct ScriptTransport {
    replies: std::cell::RefCell<std::collections::VecDeque<Reply>>,
    requests: std::cell::RefCell<Vec<Request<Vec<u8>>>>,
}
impl HttpTransport for ScriptTransport {
    async fn send(&self, request: Request<Vec<u8>>, _: usize) -> Result<Response<Vec<u8>>, String> {
        let reply = self
            .replies
            .borrow_mut()
            .pop_front()
            .expect("script has a reply");
        if let Reply::ExpiredInTransit(server_now) = reply {
            let expiry: i64 = request.headers()["x-expires-at"]
                .to_str()
                .unwrap()
                .parse()
                .unwrap();
            assert!(
                expiry < server_now,
                "server clock or transit made this credential expire"
            );
        }
        self.requests.borrow_mut().push(request);
        let (status, content_type, bytes) = match reply {
            Reply::Pending => {
                let detail = crate::proto::PendingVerification {
                    retry_after_ms: Some(2000),
                    ..Default::default()
                }
                .encode_to_vec();
                let error = serde_json::json!({"code":"unavailable", "details":[{
                    "type":"mkit.transport.v1.PendingVerification", "value":STANDARD_NO_PAD.encode(detail)
                }]});
                (503, "application/json", error.to_string().into_bytes())
            }
            Reply::ExpiredInTransit(_) | Reply::Unauthenticated => (
                401,
                "application/json",
                br#"{"code":"unauthenticated","message":"credential rejected"}"#.to_vec(),
            ),
            Reply::Committed => (
                200,
                "application/proto",
                crate::proto::AdvanceRefsResponse {
                    outcome: Some(crate::proto::AdvanceOutcome::Committed.into()),
                    ..Default::default()
                }
                .encode_to_vec(),
            ),
            Reply::Lost => return Err("response lost".into()),
        };
        Ok(Response::builder()
            .status(status)
            .header("content-type", content_type)
            .body(bytes)
            .unwrap())
    }
}
fn ready<F: std::future::Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    match future
        .as_mut()
        .poll(&mut std::task::Context::from_waker(std::task::Waker::noop()))
    {
        std::task::Poll::Ready(value) => value,
        std::task::Poll::Pending => panic!("scripted boundaries complete immediately"),
    }
}
fn script(
    replies: impl IntoIterator<Item = Reply>,
    wake_at: Option<i64>,
) -> (ScriptTransport, ScriptClock) {
    (
        ScriptTransport {
            replies: std::cell::RefCell::new(replies.into_iter().collect()),
            requests: std::cell::RefCell::new(Vec::new()),
        },
        ScriptClock {
            now: std::cell::Cell::new(0),
            wake_at: std::cell::Cell::new(wake_at),
            nonce: std::cell::Cell::new(0),
        },
    )
}
fn advance_script(
    transport: &ScriptTransport,
    clock: &ScriptClock,
) -> Result<crate::proto::AdvanceRefsResponse, Error> {
    let destination = Destination::new("https://vcs.example.org".into(), "default".into()).unwrap();
    let rpc = Rpc {
        transport,
        signer: &ScriptSigner,
        clock,
        destination: &destination,
        deadline_ms: 600_000,
    };
    ready(rpc.advance(&crate::proto::AdvanceRefsRequest {
        head_ref: Some("refs/heads/main".into()),
        head_expectation: Some(crate::proto::RefExpectation::Missing.into()),
        head_new_id: Some(vec![7; 32]),
        packmap_ref: Some("refs/mkit/packmap/main".into()),
        packmap_expectation: Some(crate::proto::RefExpectation::Missing.into()),
        packmap_new_id: Some(vec![8; 32]),
        ticket_ids: vec![vec![9; 32]],
        ..Default::default()
    }))
}
#[test]
fn pending_renews_after_local_expiry_and_once_after_expiry_in_transit() {
    for (wake_at, replies, count) in [
        (300_001, vec![Reply::Pending, Reply::Committed], 2),
        (
            298_000,
            vec![
                Reply::Pending,
                Reply::ExpiredInTransit(301_000),
                Reply::Committed,
            ],
            3,
        ),
    ] {
        let (transport, clock) = script(replies, Some(wake_at));
        assert_eq!(
            advance_script(&transport, &clock)
                .unwrap()
                .outcome
                .unwrap()
                .as_known(),
            Some(crate::proto::AdvanceOutcome::Committed)
        );
        let requests = transport.requests.borrow();
        assert_eq!(requests.len(), count);
        assert!(
            requests
                .iter()
                .all(|request| request.body() == requests[0].body())
        );
        assert_ne!(
            requests[0].headers()["idempotency-key"],
            requests[count - 1].headers()["idempotency-key"]
        );
        if count == 3 {
            assert_eq!(
                requests[0].headers(),
                requests[1].headers(),
                "still locally valid poll preserves identity"
            );
        }
    }
}
#[test]
fn post_pending_authentication_recovery_is_bounded_and_never_hides_response_loss() {
    for (replies, count, authentication) in [
        (
            vec![
                Reply::Pending,
                Reply::ExpiredInTransit(301_000),
                Reply::Unauthenticated,
            ],
            3,
            true,
        ),
        (vec![Reply::Pending, Reply::Lost], 2, false),
        (vec![Reply::Unauthenticated], 1, true),
    ] {
        let (transport, clock) = script(replies, Some(298_000));
        let error = advance_script(&transport, &clock).unwrap_err();
        if authentication {
            assert!(matches!(error, Error::Remote(error) if error.code == "unauthenticated"));
        } else {
            assert!(matches!(error, Error::Transport(_)));
            let requests = transport.requests.borrow();
            assert_eq!(requests[0].headers(), requests[1].headers());
            assert_eq!(requests[0].body(), requests[1].body());
        }
        assert_eq!(transport.requests.borrow().len(), count);
    }
}
