//! `mkit-server serve` with remote hooks (WP-3.8), end to end against
//! `FakeHook`, a strict hook service that verifies every signed request:
//! the flags, the signed channel, Authorize and Admit on the write path,
//! Outcome delivery after commit and its retries, the shutdown drain, the
//! enc sibling and the redaction of admission credentials.

#![allow(clippy::unwrap_used)] // unwrap is the assertion in tests

mod common;

use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use mkit_server::hooks::HookSigner;
use mkit_server_conformance::stubs::hook::{FakeHook, HookKey, Reply};
use mkit_server_conformance::wire::client::{Client, Rpc, RpcError};
use mkit_server_conformance::wire::sign::Signer;
use mkit_server_native::config::ServeConfig;
use mkit_server_native::{Shutdown, server};
use mkit_transport_connect::generated::{RefExpectation, UpdateRefRequest, UpdateRefResponse};

const HOOK_SEED: [u8; 32] = [0x22; 32];
const REPOSITORY: &str = "default";
const CREDENTIAL: &str = "Payment cred-secret-7f3a91";

/// The buffer every trace line of the process lands in (see
/// [`capture_traces`]).
static TRACES: OnceLock<Arc<Mutex<Vec<u8>>>> = OnceLock::new();

#[derive(Clone)]
struct Buffer(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Buffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Buffer {
    type Writer = Buffer;
    fn make_writer(&'a self) -> Buffer {
        self.clone()
    }
}

/// Install a process-wide subscriber at TRACE that keeps every line.
fn capture_traces() -> Arc<Mutex<Vec<u8>>> {
    Arc::clone(TRACES.get_or_init(|| {
        let buffer = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .with_writer(Buffer(Arc::clone(&buffer)))
            .finish();
        tracing::subscriber::set_global_default(subscriber).unwrap();
        buffer
    }))
}

/// A `mkit-server serve` on a loopback port with hooks pointed at a
/// `FakeHook`.
struct Rig {
    hook: FakeHook,
    root: tempfile::TempDir,
    key_file: std::path::PathBuf,
    ticket_file: std::path::PathBuf,
    origin: String,
    addr: std::net::SocketAddr,
    shutdown: Shutdown,
    served: Option<tokio::task::JoinHandle<Result<(), mkit_server_native::config::ConfigError>>>,
    locks: Option<server::ServerLocks>,
    signer: Signer,
    client: Client,
}

fn free_addr() -> std::net::SocketAddr {
    let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    reserved.local_addr().unwrap()
}

fn hook_keys() -> Vec<HookKey> {
    let signer = HookSigner::new("hook-1", zeroize::Zeroizing::new(HOOK_SEED)).unwrap();
    vec![HookKey::new("hook-1", signer.public_key())]
}

impl Rig {
    /// A server with the hook `roles` (`authorize`, `admit`, `outcome`) on.
    async fn start(roles: &[&str], extra: &[&str]) -> Self {
        let root = common::repo_root();
        let hook = FakeHook::start(hook_keys());
        Self::start_on(root, hook, roles, extra).await
    }

    async fn start_on(
        root: tempfile::TempDir,
        hook: FakeHook,
        roles: &[&str],
        extra: &[&str],
    ) -> Self {
        let key_file = root.path().join("hook.key");
        let seed_hex = mkit_core::hash::to_hex(&HOOK_SEED);
        common::secret_file(&key_file, format!("hook-1 {seed_hex}\n").as_bytes());
        let ticket_file = root.path().join("ticket.keys");
        common::secret_file(&ticket_file, format!("t-1 {}\n", "5".repeat(64)).as_bytes());
        let addr = free_addr();
        let origin = format!("http://{addr}");
        let mut rig = Self {
            hook,
            root,
            key_file,
            ticket_file,
            origin: origin.clone(),
            addr,
            shutdown: Shutdown::new(),
            served: None,
            locks: None,
            signer: Signer::new([0x61; 32], &origin, REPOSITORY),
            client: Client::new(&origin.parse().unwrap()).unwrap(),
        };
        rig.boot(roles, extra).await;
        rig
    }

    fn config(&self, roles: &[&str], extra: &[&str]) -> ServeConfig {
        let db = self.root.path().join("meta.sqlite3");
        let meta = format!("sqlite:{}", common::s(&db));
        let hook_url = self.hook.origin();
        let mut flags: Vec<String> = vec![
            "--listen".into(),
            self.addr.to_string(),
            "--repo-root".into(),
            common::s(self.root.path()).into(),
            "--meta".into(),
            meta,
            "--auth".into(),
            "auth-v2".into(),
            "--audience".into(),
            self.origin.clone(),
            "--repository".into(),
            REPOSITORY.into(),
            "--ticket-key-file".into(),
            common::s(&self.ticket_file).into(),
            "--hook-key-file".into(),
            common::s(&self.key_file).into(),
        ];
        for role in roles {
            flags.push(format!("--hook-{role}-url"));
            flags.push(hook_url.clone());
        }
        flags.extend(extra.iter().map(|s| (*s).to_owned()));
        let flags: Vec<&str> = flags.iter().map(String::as_str).collect();
        common::resolve_with(&flags, &[]).unwrap()
    }

    async fn boot(&mut self, roles: &[&str], extra: &[&str]) {
        let cfg = self.config(roles, extra);
        let (services, locks) = server::open(&cfg).unwrap().into_parts();
        self.locks = Some(locks);
        self.shutdown = Shutdown::new();
        let shutdown = self.shutdown.clone();
        self.served = Some(tokio::spawn(async move {
            server::serve_services(&cfg, services, shutdown).await
        }));
        // Wait for the listener.
        for _ in 0..200 {
            if tokio::net::TcpStream::connect(self.addr).await.is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("the server never listened");
    }

    /// Stop the server; `serve_services` returns after the drain.
    async fn stop(&mut self) {
        self.shutdown.trigger();
        let served = self.served.take().unwrap();
        tokio::time::timeout(Duration::from_mins(1), served)
            .await
            .expect("the server stops")
            .unwrap()
            .unwrap();
        self.locks = None;
    }

    /// `UpdateRef refs/heads/<name>` to `id` under expectation ANY.
    async fn update(&self, name: &str, id: u8) -> Result<UpdateRefResponse, RpcError> {
        self.update_with(name, id, &[]).await
    }

    async fn update_with(
        &self,
        name: &str,
        id: u8,
        extra: &[(&str, &str)],
    ) -> Result<UpdateRefResponse, RpcError> {
        use buffa::Message as _;
        let request = UpdateRefRequest {
            name: Some(format!("refs/heads/{name}")),
            expectation: Some(RefExpectation::REF_EXPECTATION_ANY.into()),
            new_id: Some(vec![id; 32]),
            ..Default::default()
        };
        let body = request.encode_to_vec();
        let mut headers = self
            .signer
            .sign_body(Rpc::UpdateRef.procedure(), &body)
            .headers;
        headers.extend(
            extra
                .iter()
                .map(|(n, v)| ((*n).to_owned(), (*v).to_owned())),
        );
        self.client
            .unary(Rpc::UpdateRef, body, &headers)
            .await
            .unwrap()
    }

    /// Wait until the stub has recorded `count` calls to `procedure`.
    async fn wait_calls(&self, procedure: &str, count: usize, secs: u64) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
        loop {
            let seen = self.hook.calls_to(procedure).len();
            if seen >= count {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "wanted {count} {procedure} calls, saw {seen}: {:?}",
                self.hook.calls()
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

fn reservation_of(body: &serde_json::Value) -> String {
    body["outcome"]["reservationId"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn signed_authorize_admit_and_outcome_reach_the_hook() {
    let mut rig = Rig::start(&["authorize", "admit", "outcome"], &[]).await;
    rig.update("main", 1).await.expect("the write is admitted");
    rig.wait_calls("Outcome", 1, 20).await;
    let calls = rig.hook.calls();
    for call in &calls {
        assert!(call.verified, "{call:?}");
        assert_eq!(call.key_id.as_deref(), Some("hook-1"));
        assert_eq!(call.audience.as_deref(), Some(rig.hook.origin().as_str()));
        assert_eq!(call.content_type.as_deref(), Some("application/json"));
    }
    let authorize = rig.hook.calls_to("Authorize");
    let admit = rig.hook.calls_to("Admit");
    let outcome = rig.hook.calls_to("Outcome");
    assert_eq!(
        (authorize.len(), admit.len(), outcome.len()),
        (1, 1, 1),
        "{calls:?}"
    );
    // Admit names the server's audience, not the hook's.
    let admit_body = String::from_utf8(admit[0].body.clone()).unwrap();
    assert!(admit_body.contains(&rig.origin), "{admit_body}");
    // The outcome is the committed one, for the reservation Admit granted.
    let outcome_json = outcome[0].json();
    assert_eq!(reservation_of(&outcome_json), "fake-1", "{outcome_json}");
    assert!(
        outcome_json["outcome"]["committed"].is_object(),
        "{outcome_json}"
    );
    assert_eq!(outcome_json["outcome"]["audience"], rig.origin.as_str());
    rig.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authorize_deny_and_allow() {
    let mut rig = Rig::start(&["authorize"], &[]).await;
    rig.hook.script(
        "Authorize",
        Reply::json(r#"{"deny":{"code":"permission_denied","message":"not for you"}}"#),
    );
    let err = rig.update("main", 1).await.unwrap_err();
    assert_eq!(err.code, "permission_denied", "{err:?}");
    assert_eq!(err.message, "not for you");
    // A deny wrote nothing, and the next write is allowed.
    rig.update("main", 2).await.expect("allowed after the deny");
    let calls = rig.hook.calls_to("Authorize");
    assert_eq!(calls.len(), 2);
    assert!(calls.iter().all(|c| c.verified));
    // Authorize alone leaves the built-in admission and local outcomes.
    assert!(rig.hook.calls_to("Admit").is_empty());
    assert!(rig.hook.calls_to("Outcome").is_empty());
    rig.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_down_authorizer_fails_closed_and_writes_nothing() {
    let mut rig = Rig::start(&["authorize"], &[]).await;
    rig.hook.set_down(true);
    let err = rig.update("main", 1).await.unwrap_err();
    assert_eq!(err.code, "unavailable", "{err:?}");
    rig.hook.set_down(false);
    rig.update("main", 1).await.expect("recovers with the hook");
    rig.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_authority_role_is_wired() {
    let mut rig = Rig::start(&["authorize", "admit"], &["--authorizer-role", "authority"]).await;
    rig.update("main", 1).await.expect("the authority allows");
    assert_eq!(rig.hook.calls_to("Authorize").len(), 1);
    rig.hook.set_down(true);
    let err = rig.update("main", 2).await.unwrap_err();
    assert_eq!(err.code, "unavailable", "{err:?}");
    rig.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_admission_challenge_is_a_402() {
    let mut rig = Rig::start(&["admit"], &[]).await;
    rig.hook.script(
        "Admit",
        Reply::json(
            r#"{"challenge":{"challenges":[{"scheme":"payment","value":"id=\"c1\""}],"description":"pay to write"}}"#,
        ),
    );
    let err = rig.update("main", 1).await.unwrap_err();
    assert_eq!(err.http_status, 402, "{err:?}");
    rig.stop().await;
}

/// A failed delivery retries with a fresh nonce each time, until a 2xx, and
/// the retries carry one and the same reservation.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn outcome_retries_carry_fresh_nonces_until_acknowledged() {
    let mut rig = Rig::start(&["admit", "outcome"], &[]).await;
    rig.hook.script("Outcome", Reply::status(503));
    rig.hook.script("Outcome", Reply::status(500));
    rig.update("main", 1).await.unwrap();
    rig.wait_calls("Outcome", 3, 40).await;
    let outcomes = rig.hook.calls_to("Outcome");
    let statuses: Vec<u16> = outcomes.iter().map(|c| c.status).collect();
    assert_eq!(statuses, [503, 500, 200], "{outcomes:?}");
    let nonces: std::collections::BTreeSet<_> =
        outcomes.iter().map(|c| c.nonce.clone().unwrap()).collect();
    assert_eq!(nonces.len(), 3, "a nonce was reused: {outcomes:?}");
    assert!(outcomes.iter().all(|c| c.verified));
    let reservations: std::collections::BTreeSet<_> =
        outcomes.iter().map(|c| reservation_of(&c.json())).collect();
    assert_eq!(reservations.len(), 1);
    // Acknowledged: nothing more arrives.
    tokio::time::sleep(Duration::from_secs(4)).await;
    assert_eq!(rig.hook.calls_to("Outcome").len(), 3);
    rig.stop().await;
}

/// The shutdown drain waits for a delivery in flight, and an outcome the hook
/// could not take survives a restart and is delivered by the next server.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_drain_delivers_in_flight_and_a_restart_delivers_the_rest() {
    let mut rig = Rig::start(&["admit", "outcome"], &[]).await;
    // The first delivery is slow: it is in flight when the shutdown starts.
    rig.hook.script(
        "Outcome",
        Reply::json("{}").delayed(Duration::from_millis(1500)),
    );
    rig.update("main", 1).await.unwrap();
    rig.wait_calls("Outcome", 1, 20).await;
    rig.stop().await;
    let outcomes = rig.hook.calls_to("Outcome");
    assert_eq!(outcomes.len(), 1, "{outcomes:?}");
    assert_eq!(outcomes[0].status, 200);

    // A delivery the hook refuses is retried after a restart.
    rig.hook.script("Outcome", Reply::status(503));
    rig.boot(&["admit", "outcome"], &[]).await;
    rig.update("main", 2).await.unwrap();
    rig.wait_calls("Outcome", 2, 20).await;
    rig.stop().await;
    let before = rig.hook.calls_to("Outcome").len();
    rig.boot(&["admit", "outcome"], &[]).await;
    rig.wait_calls("Outcome", before + 1, 30).await;
    let last = rig.hook.calls_to("Outcome").pop().unwrap();
    assert_eq!(last.status, 200);
    assert!(last.verified);
    rig.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn admission_credentials_reach_the_hook_and_never_the_logs() {
    let traces = capture_traces();
    let mut rig = Rig::start(&["admit", "outcome"], &[]).await;
    rig.update_with("main", 1, &[("payment-authorization", CREDENTIAL)])
        .await
        .unwrap();
    rig.wait_calls("Outcome", 1, 20).await;
    let admit = String::from_utf8(rig.hook.calls_to("Admit")[0].body.clone()).unwrap();
    assert!(admit.contains("cred-secret-7f3a91"), "{admit}");
    // Nor does the outcome carry it.
    let outcome = String::from_utf8(rig.hook.calls_to("Outcome")[0].body.clone()).unwrap();
    assert!(!outcome.contains("cred-secret"), "{outcome}");
    rig.stop().await;
    let logged = String::from_utf8_lossy(&traces.lock().unwrap()).into_owned();
    assert!(!logged.is_empty(), "the capture saw nothing");
    assert!(
        !logged.contains("cred-secret"),
        "a credential reached the logs"
    );
    assert!(
        !logged.contains(&mkit_core::hash::to_hex(&HOOK_SEED)),
        "the hook seed was logged"
    );
}

/// The enc listener's session pipeline is a sibling of the HTTP one and
/// inherits its hooks: a write over `mkit+enc://` calls the remote hooks.
#[cfg(feature = "enc")]
#[test]
#[allow(clippy::too_many_lines)] // One end-to-end setup.
fn the_enc_sibling_pipeline_hits_the_hook() {
    use std::os::unix::fs::PermissionsExt as _;

    use commonware_codec::Encode as _;
    use commonware_cryptography::Signer as _;
    use commonware_cryptography::ed25519::PrivateKey;
    use mkit_core::protocol::{RefWriteCondition, Transport as _};
    use mkit_transport_enc::tcp::{TokioExecutor, connect_tcp_with_executor};

    let root = common::repo_root();
    // Key material and the peers file are not ref files: keep them out of the
    // served root, in a 0700 directory.
    let aux = tempfile::tempdir().unwrap();
    let dir = aux.path().join("enc");
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let server_seed = [0x5au8; 32];
    let server_key = dir.join("server.key");
    common::secret_file(&server_key, &server_seed);
    let client_key = PrivateKey::from_seed(91);
    let client_public: [u8; 32] = client_key
        .public_key()
        .encode()
        .as_ref()
        .try_into()
        .unwrap();
    let peers = aux.path().join("peers.txt");
    std::fs::write(
        &peers,
        format!("{}\n", mkit_core::hash::to_hex(&client_public)),
    )
    .unwrap();
    let hook = FakeHook::start(hook_keys());
    let key_file = root.path().join("hook.key");
    common::secret_file(
        &key_file,
        format!("hook-1 {}\n", mkit_core::hash::to_hex(&HOOK_SEED)).as_bytes(),
    );
    let ticket_file = root.path().join("ticket.keys");
    common::secret_file(&ticket_file, format!("t-1 {}\n", "5".repeat(64)).as_bytes());
    let http = free_addr();
    let db = root.path().join("meta.sqlite3");
    let hook_url = hook.origin();
    let flags = [
        "--listen",
        &http.to_string(),
        "--listen-enc",
        "127.0.0.1:0",
        "--enc-authorized-peers",
        common::s(&peers),
        "--enc-server-key",
        common::s(&server_key),
        "--repo-root",
        common::s(root.path()),
        "--meta",
        &format!("sqlite:{}", common::s(&db)),
        "--auth",
        "auth-v2",
        "--audience",
        &format!("http://{http}"),
        "--repository",
        REPOSITORY,
        "--ticket-key-file",
        common::s(&ticket_file),
        "--hook-key-file",
        common::s(&key_file),
        "--hook-authorize-url",
        &hook_url,
        "--hook-admit-url",
        &hook_url,
    ];
    let cfg = common::resolve_with(&flags, &[]).unwrap();
    let (services, _locks) = server::open(&cfg).unwrap().into_parts();
    let service = services.enc.unwrap();
    let server_pub: [u8; 32] = service
        .key
        .public_key()
        .encode()
        .as_ref()
        .try_into()
        .unwrap();
    let opts = cfg.enc.clone().unwrap();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let listener = runtime
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let shutdown = Shutdown::new();
    let stop = shutdown.clone();
    let served = runtime
        .spawn(async move { mkit_server_native::enc::serve(listener, service, &opts, stop).await });
    let client = connect_tcp_with_executor(
        &addr.ip().to_string(),
        addr.port(),
        &server_pub,
        client_key,
        TokioExecutor::new().unwrap(),
    )
    .unwrap();
    client
        .update_ref("refs/heads/main", RefWriteCondition::Missing, &[7; 32])
        .expect("the enc write passes the remote hooks");
    assert_eq!(client.read_ref("refs/heads/main").unwrap(), Some([7; 32]));
    drop(client);
    for procedure in ["Authorize", "Admit"] {
        let calls = hook.calls_to(procedure);
        assert!(
            !calls.is_empty(),
            "the enc session never called {procedure}"
        );
        assert!(calls.iter().all(|c| c.verified), "{calls:?}");
    }
    shutdown.trigger();
    let _ = runtime.block_on(async { tokio::time::timeout(Duration::from_secs(30), served).await });
}

/// `Choice` forwards what the pipeline reads: an authority authorizer must
/// not be open, and a non-default admission needs ticket keys.
#[test]
fn choice_forwards_is_open_and_is_default_into_the_pipeline() {
    use mkit_server::policy::AuthorizerRole;
    use mkit_server_native::hooks::build::build;
    use mkit_server_native::hooks::config::HookSettings;
    use mkit_server_native::server::{SinkOptions, open_with};

    struct Nothing;
    impl mkit_server::pipeline::OutcomeSink for Nothing {
        async fn deliver(
            &self,
            _: &mkit_server::pipeline::Outcome,
        ) -> Result<(), mkit_server::pipeline::DeliveryError> {
            Ok(())
        }
    }
    let root = common::repo_root();
    let db = root.path().join("meta.sqlite3");
    let meta = format!("sqlite:{}", common::s(&db));
    let audience = "https://vcs.example";
    let flags = [
        "--listen",
        "127.0.0.1:0",
        "--repo-root",
        common::s(root.path()),
        "--meta",
        &meta,
        "--auth",
        "auth-v2",
        "--audience",
        audience,
    ];
    // The local hooks: open authorizer, default admission.
    let local = build(None, audience).unwrap();
    let mut cfg = common::resolve_with(&flags, &[]).unwrap();
    cfg.pipeline.authorizer_role = AuthorizerRole::Authority;
    let err = open_with(&cfg, local.hooks, Nothing, SinkOptions::default()).unwrap_err();
    assert!(err.message.contains("authority"), "{}", err.message);
    // A remote admission is not the default: without ticket keys the
    // pipeline refuses it. With the default admission it does not.
    let mut settings = HookSettings::new("hook-1", HOOK_SEED).unwrap();
    settings.admit = Some("https://hooks.example".to_owned());
    let remote = build(Some(&settings), audience).unwrap();
    let cfg = common::resolve_with(&flags, &[]).unwrap();
    let err = open_with(&cfg, remote.hooks, Nothing, SinkOptions::default()).unwrap_err();
    assert!(
        err.message.contains("admission requires"),
        "{}",
        err.message
    );
    let local = build(None, audience).unwrap();
    drop(open_with(&cfg, local.hooks, Nothing, SinkOptions::default()).unwrap());
}
