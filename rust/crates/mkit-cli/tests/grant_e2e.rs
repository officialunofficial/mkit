//! WP-2.13 / WP-2.14 end to end (E1): the real `mkit` binary against a REAL
//! in-process `mkit-server` pipeline (memory stores, Multi addressing, auth
//! v2, grants on), plus a stub for the `Retry-After` loop.
//!
//! * the owner creates a write grant, the grantee stores it, and the grantee's
//!   push succeeds through the installed `GrantSource`;
//! * `epoch bump` makes that grant fail with `permission_denied`, and a grant
//!   created at the new epoch works (the higher epoch is selected);
//! * a bump over the step bound is refused;
//! * `grant revoke --prune` lists and removes the grants it invalidates;
//! * a pending bump waits `Retry-After` and re-sends the identical statement.
//!
//! The private-clone half (E2) needs the WP-2.9 server and is a carry-forward.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

mod common;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use connectrpc::server::Server;
use connectrpc::{ConnectError, RequestContext, Response, Router, handler_fn};
use mkit_attest::grant::{AcceptedSchemes, EpochStatement, OwnerScheme, SignedHeader};
use mkit_core::sign::{KeyPair, save_key};
use mkit_server::auth_v2::AuthV2Config;
use mkit_server::pipeline::{AuthMode, Hooks, Pipeline, PipelineConfig};
use mkit_server::policy::NamespacePolicy;
use mkit_server::upload::UploadLimits;
use mkit_server::{Addressing, MemoryBlobStore, MemoryKv, MultiAddressing, SystemClock};
use mkit_transport_connect::generated;

/// A person with a repository, a signing key and their own config directory.
struct Party {
    _root: tempfile::TempDir,
    repo: PathBuf,
    xdg: PathBuf,
    public_key: String,
}

impl Party {
    fn new(seed: u8) -> Self {
        let root = tempfile::tempdir().unwrap();
        let repo = root.path().join("repo");
        let xdg = root.path().join("xdg");
        std::fs::create_dir_all(&repo).unwrap();
        std::fs::create_dir_all(&xdg).unwrap();
        let party = Self {
            _root: root,
            repo,
            xdg,
            public_key: mkit_core::hash::to_hex_bytes(&KeyPair::from_seed([seed; 32]).public.0),
        };
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

    fn namespace(&self) -> String {
        format!("ed25519-{}", self.public_key)
    }

    fn commit(&self, file: &str, text: &str, message: &str) {
        std::fs::write(self.repo.join(file), text).unwrap();
        self.ok(&["add", file]);
        self.ok(&["commit", "-m", message]);
    }

    /// `mkit remote add` refuses the loopback `mkit+http://` development
    /// scheme, so the remote is written to the repo config directly.
    fn add_remote(&self, url: &str) {
        let path = self.repo.join(".mkit").join("config");
        let mut config = std::fs::read_to_string(&path).unwrap_or_default();
        config.push_str("\nremote.origin.url = ");
        config.push_str(url);
        config.push_str("\nremote.origin.type = http\n");
        std::fs::write(path, config).unwrap();
    }

    /// Sign requests with this key for `url`, and trust it.
    fn connect_to(&self, url: &str) {
        self.ok(&["config", "transport_auth", "envelope"]);
        self.ok(&["config", "trusted_remote_endpoint", url]);
        self.add_remote(url);
    }
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// An in-process mkit-server on a loopback port; stops when dropped.
struct Live {
    origin: String,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Live {
    fn start(owner_namespace: &str) -> Self {
        let owner = mkit_attest::grant::Namespace::parse(owner_namespace).unwrap();
        let (addr_tx, addr_rx) = mpsc::channel();
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
                addr_tx.send(origin.clone()).unwrap();
                let mut cfg = PipelineConfig::new(
                    Addressing::Multi(MultiAddressing::new().with_namespace_policy(
                        NamespacePolicy::Allowlist(BTreeSet::from([owner])),
                    )),
                    AuthMode::AuthV2(AuthV2Config::new(&origin, "").unwrap()),
                    UploadLimits {
                        max_total_bytes: 64 << 20,
                        max_chunks: 64,
                    },
                );
                cfg.grants = Some(
                    mkit_server::GrantConfig::new_allowing_loopback(
                        &origin,
                        AcceptedSchemes::of(&[OwnerScheme::Ed25519, OwnerScheme::Secp256k1Eip191]),
                        vec![],
                    )
                    .unwrap(),
                );
                cfg.ticket_keys = Some(
                    mkit_server::upload::token::TicketKeys::parse(
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
            origin: addr_rx.recv().unwrap(),
            shutdown: Some(shutdown_tx),
            thread: Some(thread),
        }
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

fn grant_file(party: &Party, name: &str, header: &str) -> String {
    let path: &Path = &party.repo.join(name);
    std::fs::write(path, header).unwrap();
    path.to_str().unwrap().to_owned()
}

#[test]
fn grantee_push_revocation_and_reissue_against_a_real_server() {
    let owner = Party::new(0x11);
    let grantee = Party::new(0x22);
    let live = Live::start(&owner.namespace());
    let url = format!(
        "mkit+http://{}/{}/site",
        live.origin.trim_start_matches("http://"),
        owner.namespace()
    );
    owner.connect_to(&url);
    grantee.connect_to(&url);

    // The owner creates the repository by pushing.
    owner.commit("a.txt", "owner\n", "first");
    owner.ok(&["push", "origin"]);
    assert_eq!(
        owner
            .ok(&["epoch", "show", "origin"])
            .lines()
            .last()
            .unwrap(),
        "epoch     0"
    );

    // The grantee has no grant yet: the push is refused.
    grantee.commit("base.txt", "grantee base\n", "base");
    grantee.ok(&["switch", "-c", "feature"]);
    grantee.commit("b.txt", "grantee 1\n", "grantee one");
    let denied = grantee.run(&["push", "origin"]);
    assert!(!denied.status.success(), "a push without a grant must fail");
    assert!(
        stderr(&denied).to_lowercase().contains("denied")
            || stderr(&denied).to_lowercase().contains("permission"),
        "{}",
        stderr(&denied)
    );

    // The owner grants write on refs/heads/* at the server's current epoch
    // (read over the wire; the audience defaults to the trusted remote).
    let header = owner.ok(&[
        "grant",
        "create",
        "--cap",
        "write,read",
        "--grantee",
        &grantee.public_key,
        "--repo",
        "site",
        "--refs",
        "refs/heads/*=cuf",
        "--ttl",
        "1h",
    ]);
    let signed = SignedHeader::parse(header.trim()).unwrap();
    let statement = mkit_attest::grant::Grant::parse(&signed.statement).unwrap();
    assert_eq!(statement.epoch, 0);
    assert_eq!(statement.audiences, std::slice::from_ref(&live.origin));
    assert_eq!(statement.capabilities.token(), "read,write");
    let out = grantee.ok(&[
        "grant",
        "add",
        &grant_file(&grantee, "g0.txt", header.trim()),
    ]);
    assert!(out.starts_with("added grant "), "{out}");

    // The installed GrantSource presents it: the push goes through.
    let pushed = grantee.run(&["push", "origin"]);
    assert!(pushed.status.success(), "{}", stderr(&pushed));
    owner.ok(&["fetch", "origin"]);
    let refs = owner.ok(&["show-ref"]);
    assert!(refs.contains("refs/remotes/origin/feature"), "{refs}");

    // Bumping the epoch revokes it: the same push now fails.
    let bumped = owner.ok(&["epoch", "bump", "origin"]);
    assert!(bumped.contains("epoch     1 (was 0)"), "{bumped}");
    assert_eq!(
        owner
            .ok(&["epoch", "show", "origin"])
            .lines()
            .last()
            .unwrap(),
        "epoch     1"
    );
    grantee.commit("b.txt", "grantee 2\n", "grantee two");
    let revoked = grantee.run(&["push", "origin"]);
    assert!(!revoked.status.success(), "a revoked grant must not work");
    let text = stderr(&revoked).to_lowercase();
    assert!(
        text.contains("denied") || text.contains("permission"),
        "{text}"
    );

    // A grant created at the new epoch works, and outranks the stale one.
    let header = owner.ok(&[
        "grant",
        "create",
        "--cap",
        "write",
        "--grantee",
        &grantee.public_key,
        "--repo",
        "site",
        "--refs",
        "refs/heads/*=cuf",
        "--ttl",
        "1h",
        "--store",
    ]);
    let fresh =
        mkit_attest::grant::Grant::parse(&SignedHeader::parse(header.trim()).unwrap().statement)
            .unwrap();
    assert_eq!(fresh.epoch, 1);
    grantee.ok(&[
        "grant",
        "add",
        &grant_file(&grantee, "g1.txt", header.trim()),
    ]);
    let listed = grantee.ok(&["grant", "list", "--check"]);
    assert!(listed.contains("stale epoch"), "{listed}");
    assert!(listed.contains("epoch current"), "{listed}");
    let pushed = grantee.run(&["push", "origin"]);
    assert!(pushed.status.success(), "{}", stderr(&pushed));

    // An epoch step over the bound is refused before anything is signed.
    let too_far = owner.run(&["epoch", "bump", "origin", "--by", "1025"]);
    assert_eq!(too_far.status.code(), Some(64));
    assert!(stderr(&too_far).contains("1024"), "{}", stderr(&too_far));
    assert!(
        owner
            .ok(&["epoch", "show", "origin"])
            .ends_with("epoch     1\n")
    );

    // `grant revoke --prune` lists the local grants it invalidates, bumps, and
    // removes them; the grant created with --store above is the one.
    let revoke = owner.run(&["grant", "revoke", "origin", "--prune"]);
    assert!(revoke.status.success(), "{}", stderr(&revoke));
    let text = stderr(&revoke);
    assert!(text.contains("revoking: 1 local grant(s)"), "{text}");
    assert!(text.contains("removed 1 local grant(s)"), "{text}");
    assert!(String::from_utf8_lossy(&revoke.stdout).contains("epoch     2 (was 1)"));
    assert!(owner.ok(&["grant", "list"]).starts_with("no grants in "));
    // The grantee's held grants are now all stale.
    let listed = grantee.ok(&["grant", "list", "--check"]);
    assert_eq!(listed.matches("stale epoch").count(), 2, "{listed}");
}

// ---------------------------------------------------------------------------
// The Retry-After loop, against a stub that keeps the epoch RPC pending.
// ---------------------------------------------------------------------------

type Visibility = (http::HeaderMap, generated::SetRepoVisibilityRequest);

struct Stub {
    port: u16,
    statements: Arc<Mutex<Vec<String>>>,
    visibility: Arc<Mutex<Vec<Visibility>>>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Stub {
    /// `SetGrantEpoch` answers `unavailable` + `Retry-After: 1` `pending`
    /// times, then reports epoch 5. `GetGrantEpoch` says 4.
    fn start(pending: usize) -> Self {
        let statements = Arc::new(Mutex::new(Vec::new()));
        let seen = statements.clone();
        let visibility: Arc<Mutex<Vec<Visibility>>> = Arc::default();
        let vis = visibility.clone();
        let left = Arc::new(AtomicUsize::new(pending));
        let (addr_tx, addr_rx) = mpsc::channel();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let thread = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let bound = Server::bind("127.0.0.1:0").await.unwrap();
                addr_tx.send(bound.local_addr().unwrap().port()).unwrap();
                let service = "mkit.transport.v1.TransportService";
                let router = Router::new()
                    .route(
                        service,
                        "GetGrantEpoch",
                        handler_fn(
                            |_: RequestContext, _: generated::GetGrantEpochRequest| async {
                                Ok::<_, ConnectError>(Response::new(
                                    generated::GetGrantEpochResponse {
                                        epoch: Some(4),
                                        ..Default::default()
                                    },
                                ))
                            },
                        ),
                    )
                    .route(
                        service,
                        "SetGrantEpoch",
                        handler_fn(
                            move |_: RequestContext, req: generated::SetGrantEpochRequest| {
                                seen.lock()
                                    .unwrap()
                                    .push(req.signed_statement.clone().unwrap_or_default());
                                let pending = left
                                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                                        n.checked_sub(1)
                                    })
                                    .is_ok();
                                async move {
                                    if pending {
                                        let mut headers = http::HeaderMap::new();
                                        headers.insert("retry-after", "1".parse().unwrap());
                                        return Err(ConnectError::unavailable(
                                            "revocation in progress",
                                        )
                                        .with_headers(headers));
                                    }
                                    Ok(Response::new(generated::SetGrantEpochResponse {
                                        epoch: Some(5),
                                        ..Default::default()
                                    }))
                                }
                            },
                        ),
                    )
                    .route(
                        service,
                        "SetRepoVisibility",
                        handler_fn(
                            move |ctx: RequestContext, req: generated::SetRepoVisibilityRequest| {
                                vis.lock().unwrap().push((ctx.headers().clone(), req));
                                async {
                                    Ok::<_, ConnectError>(Response::new(
                                        generated::SetRepoVisibilityResponse::default(),
                                    ))
                                }
                            },
                        ),
                    );
                bound
                    .serve_with_graceful_shutdown(router, async {
                        let _ = shutdown_rx.await;
                    })
                    .await
                    .unwrap();
            });
        });
        Self {
            port: addr_rx.recv().unwrap(),
            statements,
            visibility,
            shutdown: Some(shutdown_tx),
            thread: Some(thread),
        }
    }
}

impl Drop for Stub {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[test]
fn a_pending_bump_waits_retry_after_and_resends_the_identical_statement() {
    let owner = Party::new(0x11);
    let stub = Stub::start(2);
    let url = format!(
        "mkit+http://127.0.0.1:{}/{}/site",
        stub.port,
        owner.namespace()
    );
    owner.add_remote(&url);
    let started = Instant::now();
    let out = owner.run(&["epoch", "bump", "origin"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(String::from_utf8_lossy(&out.stdout).contains("epoch     5 (was 4)"));
    assert!(
        started.elapsed() >= Duration::from_secs(2),
        "two Retry-After: 1 waits, took {:?}",
        started.elapsed()
    );
    let sent = stub.statements.lock().unwrap().clone();
    assert_eq!(sent.len(), 3);
    assert!(
        sent.iter().all(|s| s == &sent[0]),
        "every retry is byte-identical"
    );
    let header = SignedHeader::parse(&sent[0]).unwrap();
    let statement = EpochStatement::parse(&header.statement).unwrap();
    assert_eq!(statement.new_epoch, 5);
    assert_eq!(
        statement.audiences,
        [format!("http://127.0.0.1:{}", stub.port)]
    );
}

#[test]
fn a_bump_that_stays_pending_stops_at_the_timeout_and_says_it_may_still_finish() {
    let owner = Party::new(0x11);
    let stub = Stub::start(usize::MAX);
    let url = format!(
        "mkit+http://127.0.0.1:{}/{}/site",
        stub.port,
        owner.namespace()
    );
    owner.add_remote(&url);
    let out = owner.run(&["epoch", "bump", "origin", "--timeout", "2s"]);
    assert_eq!(out.status.code(), Some(75), "{}", stderr(&out));
    let text = stderr(&out);
    assert!(text.contains("still completing"), "{text}");
    assert!(text.contains("may yet finish"), "{text}");
    // Wall-clock bound: the first send, then one after the 1 s wait that fits;
    // a third would end past 2 s.
    assert_eq!(stub.statements.lock().unwrap().len(), 2);
}

#[test]
fn a_loopback_audience_needs_a_loopback_dev_remote() {
    let owner = Party::new(0x11);
    // A production-looking remote (never contacted: the audience check comes
    // first) can't be given a loopback audience.
    let out = owner.run(&[
        "grant",
        "create",
        "--cap",
        "read",
        "--all",
        "--grantee",
        &owner.public_key,
        "--audience",
        "http://127.0.0.1:8080",
        "--offline",
    ]);
    assert_eq!(out.status.code(), Some(64));
    assert!(stderr(&out).contains("loopback"), "{}", stderr(&out));
}

#[test]
fn visibility_set_sends_a_signed_request_or_an_unsigned_owner_statement() {
    use generated::set_repo_visibility_request::Mode;

    let owner = Party::new(0x11);
    let stub = Stub::start(0);
    let url = format!(
        "mkit+http://127.0.0.1:{}/{}/site",
        stub.port,
        owner.namespace()
    );
    let repository = format!("{}/site", owner.namespace());
    owner.add_remote(&url);

    // Envelope mode needs the ambient signing identity, and says how to get it.
    let out = owner.run(&["visibility", "set", "origin", "private"]);
    assert_eq!(out.status.code(), Some(77), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("transport_auth envelope"),
        "{}",
        stderr(&out)
    );
    assert!(stub.visibility.lock().unwrap().is_empty());
    // Signing flags only make sense for a statement.
    let out = owner.run(&[
        "visibility",
        "set",
        "origin",
        "private",
        "--print-statement",
    ]);
    assert_eq!(out.status.code(), Some(64));
    assert!(stderr(&out).contains("add --statement"), "{}", stderr(&out));

    owner.ok(&["config", "transport_auth", "envelope"]);
    owner.ok(&["config", "trusted_remote_endpoint", &url]);
    let out = owner.ok(&["visibility", "set", "origin", "private"]);
    assert_eq!(out.trim(), format!("{repository} is now private"));
    {
        let seen = stub.visibility.lock().unwrap();
        let (headers, request) = &seen[0];
        assert!(headers.contains_key("x-signature") && headers.contains_key("x-public-key"));
        assert_eq!(
            headers.get("x-repository").unwrap().to_str().unwrap(),
            repository
        );
        assert!(!headers.contains_key("x-write-grant"));
        assert!(matches!(
            &request.mode,
            Some(Mode::Visibility(v)) if v.as_known() == Some(generated::RepoVisibility::REPO_VISIBILITY_PRIVATE)
        ));
    }

    // Statement mode: no envelope, X-Repository present, and the statement is
    // an owner-signed mkit-repo-visibility:v1 that verifies for this audience.
    let out = owner.ok(&["visibility", "set", "origin", "public", "--statement"]);
    assert_eq!(out.trim(), format!("{repository} is now public"));
    let seen = stub.visibility.lock().unwrap();
    let (headers, request) = &seen[1];
    for name in [
        "x-signature",
        "x-public-key",
        "x-digest",
        "x-envelope-version",
    ] {
        assert!(!headers.contains_key(name), "{name}");
    }
    assert_eq!(
        headers.get("x-repository").unwrap().to_str().unwrap(),
        repository
    );
    let Some(Mode::SignedStatement(header)) = &request.mode else {
        panic!("statement mode expected: {request:?}")
    };
    let audience = format!("http://127.0.0.1:{}", stub.port);
    let cfg = mkit_attest::grant::VerifierConfig::new_allowing_loopback(
        &audience,
        AcceptedSchemes::of(&[OwnerScheme::Ed25519]),
        vec![],
    )
    .unwrap();
    let verified = mkit_attest::grant::verify_visibility_statement(
        &cfg,
        header,
        &mkit_core::repo_identity::RepositoryIdentity::parse(&repository).unwrap(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| i64::try_from(d.as_millis()).unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        verified.statement().visibility,
        mkit_attest::grant::Visibility::Public
    );
}

#[test]
fn epoch_show_and_grant_list_check_pin_their_output() {
    let owner = Party::new(0x11);
    let stub = Stub::start(0);
    let url = format!(
        "mkit+http://127.0.0.1:{}/{}/site",
        stub.port,
        owner.namespace()
    );
    owner.add_remote(&url);
    owner.ok(&["config", "trusted_remote_endpoint", &url]);
    let filters = vec![
        (r"[0-9a-f]{64}", "<hex>"),
        (r"127\.0\.0\.1:\d+", "127.0.0.1:<port>"),
        (r"\d{4}-\d\d-\d\d \d\d:\d\d:\d\d \+0000", "<date>"),
        (r"\d{13}", "<ms>"),
    ];

    // The stub stores epoch 4. Grants at 3, 4 and 5: stale, current, future.
    for epoch in ["3", "4", "5"] {
        owner.ok(&[
            "grant",
            "create",
            "--cap",
            "read",
            "--all",
            "--grantee",
            &owner.public_key,
            "--audience",
            &format!("http://127.0.0.1:{}", stub.port),
            "--epoch",
            epoch,
            "--store",
        ]);
    }
    insta::with_settings!({filters => filters.clone()}, {
        insta::assert_snapshot!("epoch_show_human", owner.ok(&["epoch", "show", "origin"]));
        insta::assert_snapshot!("epoch_show_json", owner.ok(&["epoch", "show", "origin", "--json"]));
        insta::assert_snapshot!(
            "grant_list_check_human",
            owner.ok(&["grant", "list", "--check", "--remote", "origin"])
        );
        insta::assert_snapshot!(
            "grant_list_check_json",
            owner.ok(&["grant", "list", "--check", "--remote", "origin", "--json"])
        );
        insta::assert_snapshot!("epoch_bump_human", owner.ok(&["epoch", "bump", "origin"]));
        insta::assert_snapshot!("epoch_bump_json", owner.ok(&["epoch", "bump", "origin", "--json"]));
    });
}

#[test]
fn a_grant_for_another_audience_is_unchecked_and_survives_prune() {
    let owner = Party::new(0x11);
    let stub = Stub::start(0);
    let url = format!(
        "mkit+http://127.0.0.1:{}/{}/site",
        stub.port,
        owner.namespace()
    );
    owner.add_remote(&url);
    owner.ok(&["config", "trusted_remote_endpoint", &url]);
    let here = format!("http://127.0.0.1:{}", stub.port);
    let create = |audiences: &[&str], epoch: &str| {
        let mut args = vec![
            "grant",
            "create",
            "--cap",
            "read",
            "--all",
            "--grantee",
            &owner.public_key,
            "--epoch",
            epoch,
            "--store",
        ];
        for a in audiences {
            args.extend(["--audience", a]);
        }
        owner.ok(&args);
    };
    // Epoch 1 grants are below the stub's stored epoch (0 -> bump to 1 makes
    // them stale only where the bump reaches).
    create(&["https://other.example"], "4");
    create(&[&here, "https://other.example"], "4");
    create(&[&here], "4");

    let listed = owner.ok(&["grant", "list", "--check", "--remote", "origin"]);
    assert!(
        listed.contains("unchecked (audience is not the checked remote)"),
        "{listed}"
    );
    assert!(listed.contains("epoch current"), "{listed}");

    let out = owner.run(&["grant", "revoke", "origin", "--prune"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let text = stderr(&out);
    assert!(
        text.contains("still valid at https://other.example"),
        "{text}"
    );
    assert!(text.contains("removed 1 local grant(s)"), "{text}");
    let left = owner.ok(&["grant", "list"]);
    assert_eq!(left.matches("epoch 4").count(), 2, "{left}");
}

#[test]
fn add_warns_when_the_grant_is_for_a_future_epoch() {
    let owner = Party::new(0x11);
    let grantee = Party::new(0x22);
    let stub = Stub::start(0);
    let url = format!(
        "mkit+http://127.0.0.1:{}/{}/site",
        stub.port,
        owner.namespace()
    );
    let audience = format!("http://127.0.0.1:{}", stub.port);
    owner.add_remote(&url);
    grantee.add_remote(&url);
    let make = |epoch: &str| {
        owner.ok(&[
            "grant",
            "create",
            "--cap",
            "read",
            "--all",
            "--grantee",
            &grantee.public_key,
            "--audience",
            &audience,
            "--epoch",
            epoch,
            "--remote",
            "origin",
        ])
    };
    // The stub stores epoch 4: a grant for 5 warns, one for 4 does not.
    let future = grant_file(&grantee, "future.txt", make("5").trim());
    let out = grantee.run(&["grant", "add", "--remote", "origin", &future]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("is for epoch 5 but")
            && stderr(&out).contains("is at epoch 4")
            && stderr(&out).contains("outranks your other grants"),
        "{}",
        stderr(&out)
    );
    let current = grant_file(&grantee, "current.txt", make("4").trim());
    let out = grantee.run(&["grant", "add", "--remote", "origin", &current]);
    assert!(
        out.status.success() && !stderr(&out).contains("warning"),
        "{}",
        stderr(&out)
    );
    // --offline never contacts the remote.
    let other = grant_file(&grantee, "other.txt", make("6").trim());
    let out = grantee.run(&["grant", "add", "--offline", &other]);
    assert!(
        out.status.success() && !stderr(&out).contains("warning"),
        "{}",
        stderr(&out)
    );
}

#[cfg(unix)]
#[test]
fn ctrl_c_cancels_a_pending_bump_and_says_it_may_still_complete() {
    use std::process::{Command, Stdio};

    let owner = Party::new(0x11);
    let stub = Stub::start(usize::MAX);
    let url = format!(
        "mkit+http://127.0.0.1:{}/{}/site",
        stub.port,
        owner.namespace()
    );
    owner.add_remote(&url);
    let child = Command::new(env!("CARGO_BIN_EXE_mkit"))
        .args(["epoch", "bump", "origin"])
        .current_dir(&owner.repo)
        .env("XDG_CONFIG_HOME", &owner.xdg)
        .env("HOME", &owner.xdg)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Wait until the first send has been answered `unavailable`, so the
    // command is in its Retry-After wait, then interrupt it.
    let deadline = Instant::now() + Duration::from_secs(20);
    while stub.statements.lock().unwrap().is_empty() {
        assert!(
            Instant::now() < deadline,
            "the bump never reached the server"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let killed = Command::new("kill")
        .args(["-INT", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(killed.success());
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(75), "{}", stderr(&out));
    let text = stderr(&out);
    assert!(text.contains("interrupted"), "{text}");
    assert!(text.contains("may still complete"), "{text}");
    assert!(out.stdout.is_empty());
}
