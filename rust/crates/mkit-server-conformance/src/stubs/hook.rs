//! [`FakeHook`]: a `mkit.server.hooks.v1` hook service for tests (feature
//! `stubs`).
//!
//! It is a strict Connect-JSON server on `127.0.0.1` that behaves like a
//! well-written hook:
//!
//! - **Verifies every request** as SPEC-SERVER §7.1 requires, with
//!   [`HookVerifier`] (the receiving side of the server's `HookSigner`, pinned
//!   to the golden signature vectors): the eight `X-Mkit-Hook-*` headers, the
//!   key id against its key list (with the §7.2 validity bounds), the audience
//!   against its own origin, the validity window, the body digest, the strict
//!   Ed25519 signature and replay of a nonce inside its window. A request that
//!   fails any check is answered `401` and recorded with the reason.
//! - **Answers from a script**: per procedure, queued [`Reply`]s first, then
//!   the default (Authorize allows, Admit allows with a fresh reservation id,
//!   Outcome acknowledges). [`FakeHook::set_down`] answers `503` to everything.
//! - **Records every call** ([`FakeHook::calls`]): the procedure, the verdict,
//!   the key id, the nonce and the body. Bodies can carry admission
//!   credentials, so `Debug` prints only their length.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::Duration;

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, Request, Response, StatusCode};
use bytes::Bytes;
use mkit_server::hooks::{HookVerifier, VerifierKey};

/// The Connect path of every hook procedure.
pub const SERVICE: &str = "/mkit.server.hooks.v1.HooksService";

/// The largest request body the stub reads.
const MAX_BODY: usize = 1 << 20;

/// One key of the §7.2 key list the stub trusts.
pub type HookKey = VerifierKey;

/// A scripted answer.
#[derive(Debug, Clone)]
pub struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: Bytes,
    delay: Duration,
    stall: bool,
}

impl Reply {
    /// `200` with a JSON body.
    #[must_use]
    pub fn json(body: impl Into<String>) -> Self {
        Self::body(200, "application/json", body.into().into_bytes())
    }

    /// `status` with `content_type` and `body`.
    #[must_use]
    pub fn body(status: u16, content_type: &str, body: Vec<u8>) -> Self {
        Self {
            status,
            headers: vec![("content-type".to_owned(), content_type.to_owned())],
            body: Bytes::from(body),
            delay: Duration::ZERO,
            stall: false,
        }
    }

    /// `status` with an empty body.
    #[must_use]
    pub fn status(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: Bytes::new(),
            delay: Duration::ZERO,
            stall: false,
        }
    }

    /// `302` to `location`.
    #[must_use]
    pub fn redirect(location: &str) -> Self {
        let mut reply = Self::status(302);
        reply
            .headers
            .push(("location".to_owned(), location.to_owned()));
        reply
    }

    /// Never answer (the request stays open until the client gives up).
    #[must_use]
    pub fn stall() -> Self {
        Self {
            stall: true,
            ..Self::status(200)
        }
    }

    /// Answer after `delay`.
    #[must_use]
    pub fn delayed(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }
}

/// One request as the stub received and judged it.
#[derive(Clone)]
pub struct RecordedCall {
    /// The procedure name, e.g. `Admit`.
    pub procedure: String,
    /// Whether every §7.1 check passed.
    pub verified: bool,
    /// Why a check failed, if one did.
    pub failure: Option<String>,
    /// The `X-Mkit-Hook-Key-Id`, if sent.
    pub key_id: Option<String>,
    /// The `X-Mkit-Hook-Audience`, if sent.
    pub audience: Option<String>,
    /// The `X-Mkit-Hook-Nonce`, if sent.
    pub nonce: Option<String>,
    /// The request's `Content-Type`, if sent.
    pub content_type: Option<String>,
    /// Every header name that arrived (lowercase).
    pub header_names: Vec<String>,
    /// The exact body bytes.
    pub body: Vec<u8>,
    /// The status the stub answered.
    pub status: u16,
}

impl RecordedCall {
    /// The body as JSON.
    ///
    /// # Panics
    /// If the body is not JSON.
    #[must_use]
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).expect("a JSON hook body")
    }
}

impl fmt::Debug for RecordedCall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecordedCall")
            .field("procedure", &self.procedure)
            .field("verified", &self.verified)
            .field("failure", &self.failure)
            .field("key_id", &self.key_id)
            .field("body_len", &self.body.len())
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

#[derive(Default)]
struct Inner {
    scripts: HashMap<String, VecDeque<Reply>>,
    calls: Vec<RecordedCall>,
}

struct Shared {
    origin: String,
    verifier: HookVerifier,
    state: Mutex<Inner>,
    down: AtomicBool,
    reservations: AtomicU64,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A running fake hook service on its own thread and runtime; dropping it
/// stops it. Its origin (the audience signatures must name) is
/// [`FakeHook::origin`].
pub struct FakeHook {
    addr: SocketAddr,
    shared: Arc<Shared>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl fmt::Debug for FakeHook {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeHook")
            .field("origin", &self.shared.origin)
            .finish_non_exhaustive()
    }
}

impl FakeHook {
    /// Start a stub that trusts `keys`.
    ///
    /// # Panics
    /// If the loopback listener or the server thread cannot start.
    #[must_use]
    pub fn start(keys: Vec<HookKey>) -> Self {
        Self::start_on("127.0.0.1:0", keys)
    }

    /// Start on `bind` (an `ip:port`), for a test that needs a fixed port.
    ///
    /// # Panics
    /// If the listener or the server thread cannot start.
    #[must_use]
    pub fn start_on(bind: &str, keys: Vec<HookKey>) -> Self {
        let listener = std::net::TcpListener::bind(bind).expect("bind the fake hook");
        listener
            .set_nonblocking(true)
            .expect("a non-blocking listener");
        let addr = listener.local_addr().expect("the listener's address");
        let origin = format!("http://{addr}");
        let shared = Arc::new(Shared {
            verifier: HookVerifier::new(origin.clone(), keys, now_ms).with_replay_protection(),
            origin,
            state: Mutex::new(Inner::default()),
            down: AtomicBool::new(false),
            reservations: AtomicU64::new(0),
        });
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let state = Arc::clone(&shared);
        let thread = std::thread::Builder::new()
            .name("fake-hook".to_owned())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()
                    .expect("the fake hook runtime");
                runtime.block_on(async move {
                    let listener =
                        tokio::net::TcpListener::from_std(listener).expect("a tokio listener");
                    let app = axum::Router::new().fallback(handle).with_state(state);
                    tokio::select! {
                        _ = axum::serve(listener, app).into_future() => {}
                        _ = stopped => {}
                    }
                });
                runtime.shutdown_background();
            })
            .expect("spawn the fake hook thread");
        Self {
            addr,
            shared,
            stop: Some(stop),
            thread: Some(thread),
        }
    }

    /// `http://127.0.0.1:<port>`: the audience a signature must name and a
    /// valid `--hook-*-url` for a native server.
    #[must_use]
    pub fn origin(&self) -> String {
        self.shared.origin.clone()
    }

    /// The listening address.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Queue `reply` for the next unanswered request to `procedure`
    /// (`Authorize`, `Admit` or `Outcome`); once the queue is empty the default
    /// answer returns.
    pub fn script(&self, procedure: &str, reply: Reply) {
        self.shared
            .lock()
            .scripts
            .entry(procedure.to_owned())
            .or_default()
            .push_back(reply);
    }

    /// Answer `503` to every request while `down`.
    pub fn set_down(&self, down: bool) {
        self.shared.down.store(down, Ordering::SeqCst);
    }

    /// Every request so far, oldest first.
    #[must_use]
    pub fn calls(&self) -> Vec<RecordedCall> {
        self.shared.lock().calls.clone()
    }

    /// The calls to `procedure`, oldest first.
    #[must_use]
    pub fn calls_to(&self, procedure: &str) -> Vec<RecordedCall> {
        self.calls()
            .into_iter()
            .filter(|call| call.procedure == procedure)
            .collect()
    }

    /// Forget the recorded calls (nonces already seen stay seen).
    pub fn clear_calls(&self) {
        self.shared.lock().calls.clear();
    }
}

impl Drop for FakeHook {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name)?.to_str().ok()
}

fn respond(reply: &Reply) -> Response<Body> {
    let mut builder =
        Response::builder().status(StatusCode::from_u16(reply.status).unwrap_or(StatusCode::OK));
    for (name, value) in &reply.headers {
        builder = builder.header(name, value);
    }
    builder
        .body(Body::from(reply.body.clone()))
        .expect("a well-formed reply")
}

fn default_reply(shared: &Shared, procedure: &str) -> Reply {
    match procedure {
        "Authorize" => Reply::json(r#"{"allow":{}}"#),
        "Admit" => {
            let n = shared.reservations.fetch_add(1, Ordering::SeqCst) + 1;
            Reply::json(format!(r#"{{"allow":{{"reservationId":"fake-{n}"}}}}"#))
        }
        "Outcome" => Reply::json("{}"),
        _ => Reply::status(501),
    }
}

async fn handle(State(shared): State<Arc<Shared>>, request: Request<Body>) -> Response<Body> {
    let (parts, body) = request.into_parts();
    // Read the whole body first, so a client never sees a reset instead of
    // the answer.
    let body = axum::body::to_bytes(body, MAX_BODY)
        .await
        .unwrap_or_default()
        .to_vec();
    let path = parts.uri.path().to_owned();
    let procedure = path
        .strip_prefix(&format!("{SERVICE}/"))
        .unwrap_or_default()
        .to_owned();
    let verdict = if parts.method == axum::http::Method::POST && !procedure.is_empty() {
        let pairs: Vec<(&str, &str)> = parts
            .headers
            .iter()
            .filter_map(|(name, value)| Some((name.as_str(), value.to_str().ok()?)))
            .collect();
        shared
            .verifier
            .verify(&path, &pairs, &body)
            .map(|_| ())
            .map_err(|e| e.to_string())
    } else {
        Err("not a hook procedure".to_owned())
    };
    let reply = match &verdict {
        Err(_) => Reply::json(r#"{"code":"unauthenticated","message":"hook request rejected"}"#),
        Ok(()) if shared.down.load(Ordering::SeqCst) => Reply::status(503),
        Ok(()) => {
            let scripted = shared
                .lock()
                .scripts
                .get_mut(&procedure)
                .and_then(VecDeque::pop_front);
            scripted.unwrap_or_else(|| default_reply(&shared, &procedure))
        }
    };
    let reply = if verdict.is_err() {
        Reply {
            status: 401,
            ..reply
        }
    } else {
        reply
    };
    shared.lock().calls.push(RecordedCall {
        procedure,
        verified: verdict.is_ok(),
        failure: verdict.err(),
        key_id: header(&parts.headers, "x-mkit-hook-key-id").map(str::to_owned),
        audience: header(&parts.headers, "x-mkit-hook-audience").map(str::to_owned),
        nonce: header(&parts.headers, "x-mkit-hook-nonce").map(str::to_owned),
        content_type: header(&parts.headers, "content-type").map(str::to_owned),
        header_names: parts
            .headers
            .keys()
            .map(|n| n.as_str().to_owned())
            .collect(),
        body,
        status: reply.status,
    });
    if reply.stall {
        std::future::pending::<()>().await;
    }
    if !reply.delay.is_zero() {
        tokio::time::sleep(reply.delay).await;
    }
    respond(&reply)
}
