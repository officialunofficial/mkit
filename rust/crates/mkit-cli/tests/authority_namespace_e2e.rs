//! Authority-mode namespace addressing end to end: the real `mkit` binary
//! against a REAL in-process `mkit-server` pipeline configured with
//! `namespace_mode = authority` (SPEC-SERVER §6.2.2), whose namespaces are
//! opaque names such as a `UUIDv7` — not owner-certifying keys.
//!
//! * the client accepts `mkit+http://<host>/<uuid>/<name>` for clone, push
//!   and pull (SPEC-TRANSPORT-CONNECT §7.4's union grammar);
//! * a private repository answers `not_found` to an unsigned caller and to
//!   a signer the Authority hook denies, indistinguishable from a missing
//!   repository; the hook's reader key clones it through an envelope-signed
//!   request;
//! * `mkit visibility set` in envelope mode flips visibility under an
//!   opaque namespace (statement mode stays self-certifying-only);
//! * each mode refuses the other's namespaces over the wire, and plain
//!   `https://` is refused client-side with the sync-remote guidance;
//! * `MKIT_API_TOKEN` is sent as `Authorization: Bearer …` but discarded
//!   before any hook sees it, and the hook records only signer principals.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

mod common;

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::Output;
use std::sync::{Arc, Mutex, mpsc};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use connectrpc::server::Server;
use ed25519_dalek::{Signer as _, SigningKey};
use mkit_core::hash::{hash, to_hex};
use mkit_core::sign::{KeyPair, save_key};
use mkit_server::auth_v2::AuthV2Config;
use mkit_server::authority::AuthorityFence;
use mkit_server::namespace::NamespaceMode;
use mkit_server::pipeline::{
    Admission, AdmissionDecision, AdmissionInput, AuthMode, Authorizer, Hooks, Pipeline,
    PipelineConfig,
};
use mkit_server::policy::{AuthorizerRole, NamespacePolicy};
use mkit_server::upload::{UploadLimits, token::TicketKeys};
use mkit_server::url_token::{UrlTokenConfig, UrlTokenKeys};
use mkit_server::{
    Addressing, AuthzFacts, CallerView, MemoryBlobStore, MemoryKv, MultiAddressing, Operation,
    Principal, ServerError, SystemClock,
};

/// The authority-mode namespace every case addresses (SPEC-SERVER §6.2.2
/// opaque grammar: `[a-z0-9][a-z0-9._-]{0,71}`).
const NS: &str = "019c88c3-a904-7bd1-8a5d-3182a0c6978a";
/// The hook's writer: pushes and flips visibility.
const WRITER_SEED: u8 = 0x11;
/// The hook's reader: may read private repositories.
const READER_SEED: u8 = 0x22;
/// A signer the hook denies.
const STRANGER_SEED: u8 = 0x33;
/// The deployment key that fences the namespace's authority generation.
const DEPLOY_SEED: [u8; 32] = [0x44; 32];

fn public_key(seed: u8) -> [u8; 32] {
    KeyPair::from_seed([seed; 32]).public.0
}

/// A person with a repository, a signing key and their own config directory.
struct Party {
    root: tempfile::TempDir,
    repo: PathBuf,
    xdg: PathBuf,
}

impl Party {
    fn new(seed: u8) -> Self {
        // Absolute signing keys must stay under the effective uid's home,
        // even when the platform's default temporary directory is elsewhere.
        let key_home = mkit_cli::config::home_dir_for_euid().unwrap();
        let root = tempfile::tempdir_in(key_home).unwrap();
        let repo = root.path().join("repo");
        let xdg = root.path().join("xdg");
        std::fs::create_dir_all(&repo).unwrap();
        std::fs::create_dir_all(&xdg).unwrap();
        let party = Self { root, repo, xdg };
        assert!(party.run(&["init"]).status.success());
        let keys = party.repo.join(".mkit").join("keys");
        std::fs::create_dir_all(&keys).unwrap();
        save_key(&keys.join("default.key"), &KeyPair::from_seed([seed; 32])).unwrap();
        party
    }

    fn run(&self, args: &[&str]) -> Output {
        common::mkit(&self.repo, &self.xdg, args)
    }

    fn ok(&self, args: &[&str]) -> String {
        let out = self.run(args);
        assert!(
            out.status.success(),
            "mkit {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    }

    fn commit(&self, file: &str, text: &str, message: &str) {
        std::fs::write(self.repo.join(file), text).unwrap();
        self.ok(&["add", file]);
        self.ok(&["commit", "-m", message]);
    }

    /// `mkit remote add` refuses the loopback `mkit+http://` development
    /// scheme, so the remote is written to the repo config directly.
    fn add_remote(&self, name: &str, url: &str) {
        let path = self.repo.join(".mkit").join("config");
        let mut config = std::fs::read_to_string(&path).unwrap_or_default();
        let _ = write!(
            config,
            "\nremote.{name}.url = {url}\nremote.{name}.type = http\n"
        );
        std::fs::write(path, config).unwrap();
    }

    /// Sign requests with this key for `url`, and trust it.
    fn connect_to(&self, url: &str) {
        self.ok(&["config", "transport_auth", "envelope"]);
        self.ok(&["config", "trusted_remote_endpoint", url]);
    }

    /// A clone starts with no `.mkit/keys`, so point the user config at this
    /// party's key by absolute path (a user-only key).
    fn use_key_outside_the_repo(&self) {
        let key = self.repo.join(".mkit").join("keys").join("default.key");
        self.ok(&["config", "signing_key", key.to_str().unwrap()]);
    }

    /// `mkit clone <url> <dir>` into a fresh directory with this party's
    /// config.
    fn clone(&self, url: &str, dir: &str) -> Output {
        let target = self.root.path().join(dir);
        common::mkit(
            self.root.path(),
            &self.xdg,
            &["clone", url, target.to_str().unwrap()],
        )
    }

    fn cloned_file(&self, dir: &str, file: &str) -> String {
        std::fs::read_to_string(self.root.path().join(dir).join(file)).unwrap()
    }
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// What the Authority hook observed: the operation's principal plus the
/// provisional facts the pipeline established (never the hook's own reply).
type HookCalls = Arc<Mutex<Vec<(Principal, AuthzFacts)>>>;

/// The deployment's authority: writer view for the writer key, reader view
/// for the reader key, defaults for anonymous, and a refusal for any other
/// signer (SPEC-SERVER §6.2.2's embedder-decided access).
#[derive(Debug, Clone, Default)]
struct Authority(HookCalls);
impl Authorizer for Authority {
    async fn authorize(&self, op: &Operation) -> Result<AuthzFacts, ServerError> {
        self.0
            .lock()
            .unwrap()
            .push((op.principal.clone(), op.authz.clone()));
        match &op.principal {
            Principal::Anonymous => Ok(AuthzFacts::default()),
            p if p.ed25519() == Some(&public_key(WRITER_SEED)) => {
                let mut facts = AuthzFacts::default();
                facts.caller_view = CallerView::Writer;
                facts.authority_generation = Some(0);
                // Deliberately untrusted: the pipeline must never adopt ownership.
                facts.owner = true;
                Ok(facts)
            }
            p if p.ed25519() == Some(&public_key(READER_SEED)) => {
                let mut facts = AuthzFacts::default();
                facts.caller_view = CallerView::Reader;
                facts.owner = true;
                Ok(facts)
            }
            _ => Err(ServerError::permission_denied("hook denied")),
        }
    }
}

/// Records whether any credential header — notably `Authorization`, where
/// `MKIT_API_TOKEN` arrives as `Bearer …` — ever reaches admission.
#[derive(Debug, Default)]
struct AdmitLog {
    calls: usize,
    saw_authorization: bool,
}

/// Admits every write, after asserting the pipeline withheld the facts a
/// hook must not see.
#[derive(Debug, Clone, Default)]
struct Admit(Arc<Mutex<AdmitLog>>);
impl Admission for Admit {
    async fn admit(&self, input: &AdmissionInput<'_>) -> Result<AdmissionDecision, ServerError> {
        assert!(!input.op.authz.owner);
        assert!(input.op.authz.grant.is_none());
        let mut log = self.0.lock().unwrap();
        log.calls += 1;
        for header in input.credential_headers {
            if header.name.eq_ignore_ascii_case("authorization") {
                log.saw_authorization = true;
            }
        }
        Ok(AdmissionDecision::allow(vec![])
            .with_reservation(format!("r:{}", input.idempotency_key.unwrap_or("unsigned"))))
    }
}

type TestHooks = Hooks<Authority, Admit>;
type TestPipeline = Pipeline<MemoryBlobStore, Arc<MemoryKv>, TestHooks>;

/// An in-process mkit-server on a loopback port; stops when dropped.
struct Live {
    origin: String,
    calls: HookCalls,
    admit: Arc<Mutex<AdmitLog>>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Live {
    /// An authority-mode deployment (Multi addressing, `Any` namespace
    /// policy, `AuthorizerRole::Authority`, a dedicated deployment fence),
    /// with `NS` registered at generation 0 before it serves.
    fn authority() -> Self {
        let (origin_tx, origin_rx) = mpsc::channel();
        let (hooks_tx, hooks_rx) = mpsc::channel();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let thread = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let bound = Server::bind("127.0.0.1:0").await.unwrap();
                let origin = format!("http://{}", bound.local_addr().unwrap());
                let mut cfg = PipelineConfig::new(
                    Addressing::Multi(MultiAddressing::new().with_namespace_policy(
                        NamespacePolicy::Any {
                            unsafe_without_admission: false,
                        },
                    )),
                    AuthMode::AuthV2(AuthV2Config::new(&origin, "").unwrap()),
                    UploadLimits::new(4 << 20, 64),
                );
                cfg.namespace_mode = NamespaceMode::Authority;
                cfg.authorizer_role = AuthorizerRole::Authority;
                cfg.list_repos_authority_full = true;
                cfg.write_quota = None;
                cfg.ticket_keys = Some(TicketKeys::new(vec![("tickets".into(), [9; 32])]).unwrap());
                cfg.url_tokens = Some(UrlTokenConfig::new(
                    UrlTokenKeys::parse_key_file(&format!("active {}", to_hex(&[11; 32]))).unwrap(),
                ));
                cfg.authority_fence = Some(
                    AuthorityFence::parse_with_mode(
                        &format!(
                            "deployment {} *",
                            to_hex(
                                SigningKey::from_bytes(&DEPLOY_SEED)
                                    .verifying_key()
                                    .as_bytes()
                            )
                        ),
                        NamespaceMode::Authority,
                    )
                    .unwrap(),
                );
                let authorizer = Authority::default();
                let admission = Admit::default();
                let defaults = Hooks::new();
                let hooks = Hooks {
                    authorizer: authorizer.clone(),
                    admission: admission.clone(),
                    pre_receive: defaults.pre_receive,
                    receipts: defaults.receipts,
                    outcomes: defaults.outcomes,
                };
                let clock = Arc::new(SystemClock);
                let pipeline: TestPipeline = Pipeline::new(
                    MemoryBlobStore::default(),
                    Arc::new(MemoryKv::with_clock(clock.clone())),
                    hooks,
                    cfg,
                    clock,
                    Arc::new(mkit_server::NoopMetrics),
                )
                .unwrap();
                // Authority namespaces exist only once a deployment
                // statement registers their generation (SPEC-SERVER
                // §6.2.2); a write to an unregistered namespace is refused.
                assert_eq!(
                    pipeline
                        .set_authority_generation(&generation(&origin, NS, 0))
                        .await
                        .unwrap(),
                    0
                );
                origin_tx.send(origin).unwrap();
                hooks_tx
                    .send((authorizer.0.clone(), admission.0.clone()))
                    .unwrap();
                bound
                    .serve_with_service_and_shutdown(
                        mkit_server::connect::service(Arc::new(pipeline)),
                        async {
                            let _ = shutdown_rx.await;
                        },
                    )
                    .await
                    .unwrap();
            });
        });
        let (calls, admit) = hooks_rx.recv().unwrap();
        Self {
            origin: origin_rx.recv().unwrap(),
            calls,
            admit,
            shutdown: Some(shutdown_tx),
            thread: Some(thread),
        }
    }

    /// A default (self-certifying) deployment for the mode-isolation
    /// checks: `ed25519-…`/`0x…` namespaces only.
    fn self_certifying() -> Self {
        let owner =
            mkit_attest::grant::Namespace::parse(&format!("ed25519-{}", to_hex(&[0x55; 32])))
                .unwrap();
        let (origin_tx, origin_rx) = mpsc::channel();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let thread = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let bound = Server::bind("127.0.0.1:0").await.unwrap();
                let origin = format!("http://{}", bound.local_addr().unwrap());
                origin_tx.send(origin.clone()).unwrap();
                let mut cfg = PipelineConfig::new(
                    Addressing::Multi(MultiAddressing::new().with_namespace_policy(
                        NamespacePolicy::Allowlist(BTreeSet::from([owner])),
                    )),
                    AuthMode::AuthV2(AuthV2Config::new(&origin, "").unwrap()),
                    UploadLimits::new(64 << 20, 64),
                );
                cfg.ticket_keys = Some(
                    TicketKeys::parse(
                        "dev 1111111111111111111111111111111111111111111111111111111111111111",
                    )
                    .unwrap(),
                );
                let clock = Arc::new(SystemClock);
                let pipeline = Pipeline::new(
                    MemoryBlobStore::default(),
                    MemoryKv::with_clock(clock.clone()),
                    Hooks::new(),
                    cfg,
                    clock,
                    Arc::new(mkit_server::NoopMetrics),
                )
                .unwrap();
                bound
                    .serve_with_service_and_shutdown(
                        mkit_server::connect::service(Arc::new(pipeline)),
                        async {
                            let _ = shutdown_rx.await;
                        },
                    )
                    .await
                    .unwrap();
            });
        });
        Self {
            origin: origin_rx.recv().unwrap(),
            calls: HookCalls::default(),
            admit: Arc::new(Mutex::new(AdmitLog::default())),
            shutdown: Some(shutdown_tx),
            thread: Some(thread),
        }
    }

    fn host(&self) -> &str {
        self.origin.trim_start_matches("http://")
    }
}

impl Drop for Live {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// A `mkit-authority-generation:v1` statement the deployment fence accepts:
/// `<unpadded-base64url text>.<unpadded-base64url signature>` signed by the
/// deployment key over `BLAKE3(text)` (mkit-server `authority.rs`).
fn generation(audience: &str, namespace: &str, n: u64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap())
        .unwrap();
    let text = format!(
        "mkit-authority-generation:v1\ndeployment\n{namespace}\n{n}\n{audience}\n{now}\n{}\n{}",
        now + 60_000,
        to_hex(&hash(namespace.as_bytes()))
    );
    let sig = SigningKey::from_bytes(&DEPLOY_SEED).sign(&hash(text.as_bytes()));
    format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(text),
        URL_SAFE_NO_PAD.encode(sig.to_bytes())
    )
}

/// A private repository and a missing one answer identically: `not_found`,
/// never a permission hint (SPEC-SERVER §9.3 uniform absence).
fn assert_not_found(out: &Output, identity: &str, what: &str) {
    assert!(!out.status.success(), "{what}: the clone must fail");
    let text = stderr(out).to_lowercase();
    let expected = format!("repository `{identity}` not found at").to_lowercase();
    assert!(
        text.contains(&expected),
        "{what}: expected `{expected}`, got: {text}"
    );
    for hint in ["permission", "denied"] {
        assert!(
            !text.contains(hint),
            "{what}: a private repository must not be told apart from a missing one: {text}"
        );
    }
}

#[allow(clippy::too_many_lines)] // the settled a–d flow reads as one linear story
#[test]
fn authority_namespace_public_private_and_signer_reads_end_to_end() {
    let writer = Party::new(WRITER_SEED);
    let reader = Party::new(READER_SEED);
    let stranger = Party::new(STRANGER_SEED);
    let anon = Party::new(0x77);
    let live = Live::authority();
    let pub_url = format!("mkit+http://{}/{NS}/public", live.host());
    let priv_url = format!("mkit+http://{}/{NS}/private", live.host());
    let missing_url = format!("mkit+http://{}/{NS}/missing", live.host());

    // The writer pushes `<NS>/private`, then flips it private in envelope
    // mode. `MKIT_API_TOKEN` rides along on the pushes so the admission log
    // proves the Bearer header never reaches a hook.
    writer.connect_to(&priv_url);
    writer.add_remote("priv", &priv_url);
    writer.commit("secret.txt", "private\n", "private commit");
    let pushed = common::mkit_env(
        &writer.repo,
        &writer.xdg,
        &["push", "priv"],
        &[("MKIT_API_TOKEN", "test-token")],
    );
    assert!(pushed.status.success(), "{}", stderr(&pushed));
    let out = writer.ok(&["visibility", "set", &priv_url, "private"]);
    assert!(out.contains("is now private"), "{out}");

    // `<NS>/public`, pushed signed with the same bearer token in the air.
    writer.connect_to(&pub_url);
    writer.add_remote("origin", &pub_url);
    writer.commit("a.txt", "public\n", "public commit");
    let pushed = common::mkit_env(
        &writer.repo,
        &writer.xdg,
        &["push", "origin"],
        &[("MKIT_API_TOKEN", "test-token")],
    );
    assert!(pushed.status.success(), "{}", stderr(&pushed));

    // An anonymous caller clones the public repository, then pulls the
    // writer's next commit; a second pull is a no-op.
    let cloned = anon.clone(&pub_url, "pub");
    assert!(cloned.status.success(), "{}", stderr(&cloned));
    assert_eq!(anon.cloned_file("pub", "a.txt"), "public\n");
    let clone_dir = anon.root.path().join("pub");
    writer.commit("b.txt", "second\n", "second commit");
    writer.ok(&["push", "origin"]);
    let pulled = common::mkit(&clone_dir, &anon.xdg, &["pull"]);
    assert!(pulled.status.success(), "{}", stderr(&pulled));
    assert_eq!(
        std::fs::read_to_string(clone_dir.join("b.txt")).unwrap(),
        "second\n"
    );
    let head = |dir: &std::path::Path| {
        let out = common::mkit(dir, &anon.xdg, &["rev-parse", "HEAD"]);
        assert!(out.status.success(), "{}", stderr(&out));
        String::from_utf8(out.stdout).unwrap()
    };
    let before = head(&clone_dir);
    let again = common::mkit(&clone_dir, &anon.xdg, &["pull"]);
    assert!(again.status.success(), "{}", stderr(&again));
    assert_eq!(head(&clone_dir), before, "a second pull must not move HEAD");

    // The hook's reader clones the private repository signed; an unsigned
    // caller and a denied signer both see the missing-repository answer.
    reader.connect_to(&priv_url);
    reader.use_key_outside_the_repo();
    let out = reader.clone(&priv_url, "priv");
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(reader.cloned_file("priv", "secret.txt"), "private\n");

    stranger.connect_to(&priv_url);
    stranger.use_key_outside_the_repo();
    let private_unsigned = anon.clone(&priv_url, "priv-anon");
    let private_denied = stranger.clone(&priv_url, "priv-stranger");
    let missing = anon.clone(&missing_url, "missing");
    assert_not_found(&private_unsigned, &format!("{NS}/private"), "anonymous");
    assert_not_found(&private_denied, &format!("{NS}/private"), "denied signer");
    assert_not_found(&missing, &format!("{NS}/missing"), "missing repository");
    // Signed callers get the same answer on a missing repository as on the
    // private one: a hook outcome never distinguishes the two.
    for (party, label) in [(&stranger, "stranger"), (&reader, "reader")] {
        party.connect_to(&missing_url);
        let out = party.clone(&missing_url, &format!("missing-{label}"));
        assert_not_found(&out, &format!("{NS}/missing"), label);
    }
    let error_text = |out: &Output| {
        let text = stderr(out);
        text[text.find("error:").unwrap_or(0)..].to_owned()
    };
    assert_eq!(
        error_text(&private_unsigned).replace("private", "R"),
        error_text(&missing).replace("missing", "R"),
        "a denied private clone must read byte-identically to a missing one"
    );
    assert_eq!(
        error_text(&private_denied).replace("private", "R"),
        error_text(&missing).replace("missing", "R"),
        "a denied signed clone must read byte-identically to a missing one"
    );

    // The hook saw only envelope signers — writer, reader and the denied
    // stranger — and the pipeline never adopted the hook's deliberately
    // untrusted `owner`/`grant` facts (SPEC-SERVER §6.2.2).
    let calls = live.calls.lock().unwrap();
    for (seed, who) in [
        (WRITER_SEED, "writer"),
        (READER_SEED, "reader"),
        (STRANGER_SEED, "denied signer"),
    ] {
        assert!(
            calls
                .iter()
                .any(|(p, _)| p.ed25519() == Some(&public_key(seed))),
            "the Authority hook must see the {who}'s signer key"
        );
    }
    assert!(
        calls
            .iter()
            .all(|(p, _)| matches!(p, Principal::Signer { .. })),
        "every hook call must carry an envelope signer: {calls:?}"
    );
    assert!(
        calls.iter().all(|(_, f)| !f.owner && f.grant.is_none()),
        "the pipeline must not adopt untrusted ownership facts: {calls:?}"
    );
    drop(calls);
    let admit = live.admit.lock().unwrap();
    assert!(admit.calls > 0, "the signed pushes must run admission");
    assert!(
        !admit.saw_authorization,
        "the `Bearer` `MKIT_API_TOKEN` header must be discarded before admission (writes; \
         the server unit test `bearer_authorization_is_not_selected_for_hooks` is the control)"
    );
}

#[test]
fn each_namespace_mode_refuses_the_others_namespaces_over_the_wire() {
    let anon = Party::new(0x77);
    let live = Live::authority();
    // Well-formed self-certifying namespaces the client accepts — and the
    // authority-mode server refuses with `invalid_argument` (each server
    // enforces only its own mode's grammar, SPEC-TRANSPORT-CONNECT §7.4).
    for namespace in [
        format!("ed25519-{}", to_hex(&public_key(0x55))),
        format!("0x{}", mkit_core::hash::to_hex_bytes(&[0x77; 20])),
    ] {
        let url = format!("mkit+http://{}/{namespace}/repo", live.host());
        let out = anon.clone(&url, format!("bad-{namespace}").as_str());
        assert!(!out.status.success(), "{url} must fail");
        let text = stderr(&out).to_lowercase();
        assert!(text.contains("invalid x-repository"), "{url}: {text}");
        assert!(!text.contains("not found"), "{url}: {text}");
    }

    // And in reverse: the opaque UUIDv7 namespace the authority server
    // serves is `invalid_argument` at a self-certifying deployment.
    let self_cert = Live::self_certifying();
    let url = format!("mkit+http://{}/{NS}/repo", self_cert.host());
    let out = anon.clone(&url, "opaque-at-self-cert");
    assert!(!out.status.success(), "{url} must fail");
    let text = stderr(&out).to_lowercase();
    assert!(text.contains("invalid x-repository"), "{url}: {text}");
    assert!(!text.contains("not found"), "{url}: {text}");
}

#[test]
fn malformed_path_segments_and_plain_https_are_refused_client_side() {
    let anon = Party::new(0x77);
    let live = Live::authority();
    // A malformed namespace or name never leaves the client: the error
    // names the offending segment and the §7.4 grammars.
    for (n, (path, segment)) in [
        (String::from("Bad/repo"), "Bad"),
        (format!("{NS}/Repo"), "Repo"),
    ]
    .iter()
    .enumerate()
    {
        let url = format!("mkit+http://{}/{path}", live.host());
        let out = anon.clone(&url, &format!("malformed-{n}"));
        assert!(!out.status.success(), "{url} must fail");
        let text = stderr(&out);
        assert!(text.contains(&format!("`{segment}`")), "{url}: {text}");
        assert!(text.contains("§7.4"), "{url}: {text}");
    }

    // Plain `https://` is not a sync remote: at that origin plain HTTP
    // serves objects by path (SPEC-HTTP-OBJECTS); the error points at the
    // `mkit+https://` form.
    let url = format!("https://{}/{NS}/public", live.host());
    let out = anon.clone(&url, "plain-https");
    assert!(!out.status.success(), "{url} must fail");
    let text = stderr(&out);
    assert!(text.contains("is not a sync remote"), "{text}");
    assert!(text.contains("SPEC-HTTP-OBJECTS"), "{text}");
    assert!(text.contains(&format!("mkit+{url}")), "{text}");
}
