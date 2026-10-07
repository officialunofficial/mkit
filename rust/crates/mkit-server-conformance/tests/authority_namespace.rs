//! Both namespace trust models through the real pipeline and Connect binding.
#![allow(clippy::unwrap_used)]

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use ed25519_dalek::{Signer as _, SigningKey};
use mkit_core::hash::{hash, to_hex};
use mkit_server::auth_v2::AuthV2Config;
use mkit_server::authority::AuthorityFence;
use mkit_server::namespace::NamespaceMode;
use mkit_server::pipeline::{
    Admission, AdmissionDecision, AdmissionInput, AuthMode, Authorizer, Hooks, Pipeline,
    PipelineConfig, RequestMeta,
};
use mkit_server::policy::{AuthorizerRole, NamespacePolicy};
use mkit_server::store::adapter_spi::keys;
use mkit_server::upload::{UploadLimits, token::TicketKeys};
use mkit_server::url_token::{Binding, UrlTarget, UrlTokenConfig, UrlTokenKeys};
use mkit_server::{
    Addressing, AuthzFacts, Code, MemoryBlobStore, MemoryKv, MultiAddressing, NamespaceStore,
    Operation, Principal, Procedure, ServerError, SystemClock,
};
use mkit_server_conformance::wire::{
    client::Client,
    sign::{SignedOp, Signer, now_ms},
};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use url::Url;

const NS: &str = "019c88c3-a904-7bd1-8a5d-3182a0c6978a";
const OTHER_NS: &str = "019c88c3-a904-7bd1-8a5d-3182a0c6978b";
const REF: &str = "refs/heads/main";
const OWNER_REFUSAL: &str = "owner statements are not supported in authority namespace mode";

#[derive(Debug, Clone, Default)]
struct Authority(Arc<Mutex<Vec<AuthzFacts>>>);
impl Authorizer for Authority {
    async fn authorize(&self, op: &Operation) -> Result<AuthzFacts, ServerError> {
        self.0.lock().unwrap().push(op.authz.clone());
        match &op.principal {
            Principal::Anonymous => Ok(AuthzFacts::default()),
            p if p.ed25519()
                == Some(SigningKey::from_bytes(&[7; 32]).verifying_key().as_bytes()) =>
            {
                let mut facts = AuthzFacts::default();
                facts.caller_view = mkit_server::CallerView::Writer;
                facts.authority_generation = Some(0);
                // Deliberately untrusted: the pipeline must never adopt ownership.
                facts.owner = true;
                Ok(facts)
            }
            p if p.ed25519()
                == Some(SigningKey::from_bytes(&[5; 32]).verifying_key().as_bytes()) =>
            {
                let mut facts = AuthzFacts::default();
                facts.caller_view = mkit_server::CallerView::Reader;
                facts.owner = true;
                Ok(facts)
            }
            _ => Err(ServerError::permission_denied("hook denied")),
        }
    }
}
#[derive(Debug)]
struct Admit;
impl Admission for Admit {
    async fn admit(&self, input: &AdmissionInput<'_>) -> Result<AdmissionDecision, ServerError> {
        assert!(!input.op.authz.owner);
        assert!(input.op.authz.grant.is_none());
        Ok(AdmissionDecision::allow(vec![])
            .with_reservation(format!("r:{}", input.idempotency_key.unwrap())))
    }
}
type TestHooks = Hooks<Authority, Admit>;
type TestPipeline = Pipeline<MemoryBlobStore, Arc<MemoryKv>, TestHooks>;

fn config(audience: &str, mode: NamespaceMode) -> PipelineConfig {
    let addressing = Addressing::Multi(MultiAddressing::new().with_namespace_policy(
        NamespacePolicy::Any {
            unsafe_without_admission: false,
        },
    ));
    let mut cfg = PipelineConfig::new(
        addressing,
        AuthMode::AuthV2(AuthV2Config::new(audience, "").unwrap()),
        UploadLimits::new(4 << 20, 64),
    );
    cfg.namespace_mode = mode;
    cfg.authorizer_role = AuthorizerRole::Authority;
    cfg.list_repos_authority_full = true;
    cfg.write_quota = None;
    cfg.ticket_keys = Some(TicketKeys::new(vec![("tickets".into(), [9; 32])]).unwrap());
    cfg.url_tokens = Some(UrlTokenConfig::new(
        UrlTokenKeys::parse_key_file(&format!("active {}", to_hex(&[11; 32]))).unwrap(),
    ));
    if mode == NamespaceMode::Authority {
        cfg.authority_fence = Some(
            AuthorityFence::parse_with_mode(
                &format!(
                    "deployment {} *",
                    to_hex(SigningKey::from_bytes(&[8; 32]).verifying_key().as_bytes())
                ),
                mode,
            )
            .unwrap(),
        );
    }
    cfg
}

fn build(cfg: PipelineConfig) -> Result<(TestPipeline, Arc<MemoryKv>, Authority), ServerError> {
    let meta = Arc::new(MemoryKv::default());
    let authorizer = Authority::default();
    let defaults = Hooks::new();
    let hooks = Hooks {
        authorizer: authorizer.clone(),
        admission: Admit,
        pre_receive: defaults.pre_receive,
        receipts: defaults.receipts,
        outcomes: defaults.outcomes,
    };
    let pipe = Pipeline::new(
        MemoryBlobStore::default(),
        meta.clone(),
        hooks,
        cfg,
        Arc::new(SystemClock),
        Arc::new(mkit_server::NoopMetrics),
    )?;
    Ok((pipe, meta, authorizer))
}

fn generation(audience: &str, namespace: &str, n: u64) -> String {
    let now = now_ms();
    let text = format!(
        "mkit-authority-generation:v1\ndeployment\n{namespace}\n{n}\n{audience}\n{now}\n{}\n{}",
        now + 60_000,
        to_hex(&hash(namespace.as_bytes()))
    );
    let sig = SigningKey::from_bytes(&[8; 32]).sign(&hash(text.as_bytes()));
    format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(text),
        URL_SAFE_NO_PAD.encode(sig.to_bytes())
    )
}

async fn registered(pipe: &TestPipeline, audience: &str, namespace: &str) {
    assert_eq!(
        pipe.set_authority_generation(&generation(audience, namespace, 0))
            .await
            .unwrap(),
        0
    );
}

async fn rpc(client: &Client, signer: &Signer, procedure: Procedure, body: Value) -> Value {
    let bytes = serde_json::to_vec(&body).unwrap();
    let credentials = signer.sign_body(procedure.connect_path(), &bytes);
    let response = client
        .post(
            procedure.connect_path(),
            "application/json",
            &credentials.headers,
            bytes,
        )
        .await
        .unwrap();
    assert_eq!(
        response.status,
        200,
        "{}",
        String::from_utf8_lossy(&response.body)
    );
    serde_json::from_slice(&response.body).unwrap()
}

#[tokio::test]
async fn uuid_namespace_write_read_list_visibility_url_and_wildcard_key() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let audience = format!("http://{}", listener.local_addr().unwrap());
    let cfg = config(&audience, NamespaceMode::Authority);
    let tokens = cfg.url_tokens.clone().unwrap();
    let (pipe, _, hook) = build(cfg).unwrap();
    for namespace in [NS, OTHER_NS] {
        registered(&pipe, &audience, namespace).await;
    }
    let pipe = Arc::new(pipe);
    let app = axum::Router::new().fallback_service(mkit_server::connect::service(pipe.clone()));
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let client = Client::new(&Url::parse(&audience).unwrap()).unwrap();
    let repository = format!("{NS}/repository");
    let signer = Signer::new([7; 32], &audience, &repository);
    rpc(
        &client,
        &signer,
        Procedure::UpdateRef,
        json!({"name":REF,"newId":STANDARD.encode([1;32]),"expectation":"REF_EXPECTATION_ANY"}),
    )
    .await;
    let read = rpc(&client, &signer, Procedure::ReadRef, json!({"name":REF})).await;
    assert_eq!(read["objectId"], STANDARD.encode([1; 32]));
    rpc(
        &client,
        &signer,
        Procedure::SetRepoVisibility,
        json!({"visibility":"REPO_VISIBILITY_PRIVATE"}),
    )
    .await;
    let listing = rpc(
        &client,
        &signer,
        Procedure::ListRepos,
        json!({"namespace":NS}),
    )
    .await;
    assert_eq!(listing["repos"][0]["name"], "repository");
    let issued = rpc(
        &client,
        &signer,
        Procedure::IssueObjectUrl,
        json!({"refPath":{"ref":REF,"path":""},"ttlSeconds":60}),
    )
    .await;
    let token = issued["token"].as_str().unwrap();
    let target = UrlTarget::path(REF, "").unwrap();
    let bound = tokens
        .precheck(token, now_ms())
        .unwrap()
        .check_binding(
            &Binding {
                audience: &audience,
                repository: &repository,
                target: &target,
            },
            now_ms(),
            60_000,
        )
        .unwrap();
    assert_eq!(bound.epoch(), 0);
    // The same dedicated key fences two independently registered opaque namespaces.
    for namespace in [NS, OTHER_NS] {
        assert_eq!(
            pipe.set_authority_generation(&generation(&audience, namespace, 1))
                .await
                .unwrap(),
            1
        );
        assert_eq!(pipe.get_authority_generation(namespace).await.unwrap(), 1);
    }
    assert!(
        hook.0
            .lock()
            .unwrap()
            .iter()
            .all(|f| !f.owner && f.grant.is_none())
    );
    server.abort();
}

#[tokio::test]
async fn registration_precedes_the_first_write_over_the_wire() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let audience = format!("http://{}", listener.local_addr().unwrap());
    let (pipe, meta, hook) = build(config(&audience, NamespaceMode::Authority)).unwrap();
    let pipe = Arc::new(pipe);
    let app = axum::Router::new().fallback_service(mkit_server::connect::service(pipe.clone()));
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let client = Client::new(&Url::parse(&audience).unwrap()).unwrap();
    let signer = Signer::new([7; 32], &audience, &format!("{NS}/repository"));
    let body =
        json!({"name":REF,"newId":STANDARD.encode([1;32]),"expectation":"REF_EXPECTATION_ANY"});
    let bytes = serde_json::to_vec(&body).unwrap();
    let credentials = signer.sign_body(Procedure::UpdateRef.connect_path(), &bytes);
    let refused = client
        .post(
            Procedure::UpdateRef.connect_path(),
            "application/json",
            &credentials.headers,
            bytes,
        )
        .await
        .unwrap();
    assert_eq!(refused.status, 403);
    assert!(String::from_utf8_lossy(&refused.body).contains("namespace not registered"));
    assert!(hook.0.lock().unwrap().is_empty());
    // Registration needs no namespace record and creates none.
    assert_eq!(pipe.get_authority_generation(NS).await.unwrap(), 0);
    assert_eq!(
        pipe.set_authority_generation(&generation(&audience, NS, 0))
            .await
            .unwrap(),
        0
    );
    let key = NamespaceMode::Authority.namespace(NS).unwrap().key();
    let partition = mkit_server::Partition::Namespace(key);
    assert!(
        meta.get(&partition, &keys::namespace_record())
            .await
            .unwrap()
            .is_none()
    );
    rpc(&client, &signer, Procedure::UpdateRef, body).await;
    assert!(
        meta.get(&partition, &keys::namespace_record())
            .await
            .unwrap()
            .is_some()
    );
    let other = Signer::new([7; 32], &audience, &format!("{OTHER_NS}/repository"));
    let credentials = other.sign_body(Procedure::ReadRef.connect_path(), b"{}");
    let read = client
        .post(
            Procedure::ReadRef.connect_path(),
            "application/json",
            &credentials.headers,
            b"{}".to_vec(),
        )
        .await
        .unwrap();
    assert_ne!(read.status, 500);
    server.abort();
}

fn request<'a>(
    procedure: Procedure,
    headers: &'a dyn Fn(&str) -> Option<String>,
    body: Option<&'a [u8]>,
) -> RequestMeta<'a> {
    RequestMeta {
        procedure,
        header: headers,
        header_values: None,
        unary_body: body,
        transport_principal: None,
    }
}
fn lookup(credentials: &SignedOp, name: &str) -> Option<String> {
    credentials
        .headers
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.clone())
}
fn auth(
    pipe: &TestPipeline,
    signer: &Signer,
    procedure: Procedure,
) -> mkit_server::pipeline::Authenticated {
    let body = b"{}";
    let credentials = signer.sign_body(procedure.connect_path(), body);
    pipe.authenticate(&request(
        procedure,
        &|name| lookup(&credentials, name),
        Some(body),
    ))
    .unwrap()
}

#[test]
fn default_mode_refuses_uuid_and_authority_startup_refuses_inconsistent_configs() {
    let audience = "https://vcs.example";
    let (pipe, _, _) = build(config(audience, NamespaceMode::SelfCertifying)).unwrap();
    let signer = Signer::new([7; 32], audience, &format!("{NS}/repository"));
    let credentials = signer.sign_body(Procedure::ReadRef.connect_path(), b"{}");
    assert_eq!(
        pipe.authenticate(&request(
            Procedure::ReadRef,
            &|name| lookup(&credentials, name),
            Some(b"{}")
        ))
        .unwrap_err()
        .code(),
        Code::InvalidArgument
    );
    for mutation in 0..8 {
        let mut cfg = config(audience, NamespaceMode::Authority);
        match mutation {
            0 => cfg.authority_fence = None,
            1 => cfg.authorizer_role = AuthorizerRole::Check,
            2 => cfg.addressing = Addressing::Multi(MultiAddressing::new()),
            3 => {
                cfg.addressing = Addressing::Single {
                    repo: mkit_server::RepoId {
                        namespace: mkit_server::NamespaceKey::deployment_default(),
                        name: mkit_server::RepoName::new("repository").unwrap(),
                    },
                }
            }
            4 => cfg.namespace_mode = NamespaceMode::SelfCertifying,
            5 => cfg.admin_keys = vec![SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes()],
            6 => {
                cfg.ticket_keys = Some(TicketKeys::new(vec![("tickets".into(), [8; 32])]).unwrap());
            }
            _ => {
                cfg.url_tokens = Some(UrlTokenConfig::new(
                    UrlTokenKeys::parse_key_file(&format!("active {}", to_hex(&[8; 32]))).unwrap(),
                ));
            }
        }
        assert_eq!(
            build(cfg).unwrap_err().code(),
            Code::InvalidArgument,
            "{mutation}"
        );
    }
}

#[tokio::test]
async fn authority_mode_refuses_valid_owner_grant_epoch_and_visibility_statements() {
    use mkit_attest::grant::{
        AcceptedSchemes, Capabilities, EpochStatement, Grant, OwnerScheme, RepoScope,
        RepositoryIdentity, SignedHeader, Visibility, VisibilityStatement,
    };
    let audience = "https://vcs.example";
    let owner = Signer::new([7; 32], audience, "unused");
    let namespace = mkit_core::repo_identity::Namespace::Ed25519(
        SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes(),
    );
    let identity = RepositoryIdentity::parse(&format!("{namespace}/repository")).unwrap();
    let now = now_ms();
    let grant = Grant {
        namespace,
        scope: RepoScope::Repository(identity.clone()),
        grantee: SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes(),
        capabilities: Capabilities::Write,
        audiences: vec![audience.into()],
        ref_scopes: Some(mkit_attest::grant::RefScopes::parse("refs/heads/*=cuf").unwrap()),
        epoch: 0,
        created_ms: now - 1000,
        expiry_ms: now + 60_000,
        nonce: [1; 32],
    };
    let wrap = |bytes: Vec<u8>| {
        SignedHeader {
            scheme: OwnerScheme::Ed25519,
            blob: owner.sign_grant_statement(&bytes).to_vec(),
            statement: bytes,
        }
        .encode()
        .unwrap()
    };
    let grant_header = wrap(grant.encode().unwrap());
    let epoch = wrap(
        EpochStatement {
            namespace,
            new_epoch: 1,
            audiences: vec![audience.into()],
            created_ms: now - 1000,
            expiry_ms: now + 60_000,
            nonce: [2; 32],
        }
        .encode()
        .unwrap(),
    );
    let visibility = wrap(
        VisibilityStatement {
            repository: identity.clone(),
            visibility: Visibility::Private,
            audiences: vec![audience.into()],
            created_ms: now - 1000,
            expiry_ms: now + 60_000,
            nonce: [3; 32],
        }
        .encode()
        .unwrap(),
    );
    let mut cfg = config(audience, NamespaceMode::Authority);
    cfg.grants = Some(
        mkit_server::GrantConfig::new(
            audience,
            AcceptedSchemes::of(&[OwnerScheme::Ed25519]),
            vec![],
        )
        .unwrap(),
    );
    let verifier = mkit_attest::grant::VerifierConfig::new(
        audience,
        AcceptedSchemes::of(&[OwnerScheme::Ed25519]),
        vec![],
    )
    .unwrap();
    mkit_attest::grant::verify_grant_owner(&verifier, &grant_header).unwrap();
    mkit_attest::grant::verify_epoch_statement(&verifier, &epoch, now).unwrap();
    mkit_attest::grant::verify_visibility_statement(&verifier, &visibility, &identity, now)
        .unwrap();
    let (pipe, _, _) = build(cfg).unwrap();
    assert!(pipe.server_info().grant_schemes.is_empty());
    let signer = Signer::new([7; 32], audience, &format!("{NS}/repository"));
    let credentials = signer
        .sign_body(Procedure::ReadRef.connect_path(), b"{}")
        .with_header("x-write-grant", grant_header);
    let e = pipe
        .authenticate(&request(
            Procedure::ReadRef,
            &|name| lookup(&credentials, name),
            Some(b"{}"),
        ))
        .unwrap_err();
    assert_eq!(e.public_message(), OWNER_REFUSAL);
    assert_eq!(
        pipe.set_grant_epoch(&epoch)
            .await
            .unwrap_err()
            .public_message(),
        OWNER_REFUSAL
    );
    let a = auth(&pipe, &signer, Procedure::SetRepoVisibility);
    assert_eq!(
        pipe.set_repo_visibility(
            &a,
            mkit_server::pipeline::VisibilityRequest::Statement(visibility)
        )
        .await
        .unwrap_err()
        .public_message(),
        OWNER_REFUSAL
    );
}

#[cfg(feature = "http-objects")]
#[tokio::test]
async fn hook_writer_view_owns_storage_objects_and_url_issuance_without_existence_leaks() {
    use mkit_core::{refs::RefWriteCondition, serialize::serialize};
    use mkit_server::RefUpdate;
    use mkit_server::pipeline::{ReaderView, RepoVisibility, VisibilityRequest};
    let audience = "https://vcs.example";
    let mut cfg = config(audience, NamespaceMode::Authority);
    cfg.indexed = Some(mkit_server::indexed::IndexedConfig::default());
    cfg.http_objects = Some(mkit_server::http_objects::HttpObjectsConfig::default());
    let (pipe, _, _) = build(cfg).unwrap();
    registered(&pipe, audience, NS).await;
    let repository = format!("{NS}/repository");
    let signer = Signer::new([7; 32], audience, &repository);
    let (pack, tree, commit) = canonical_pack();
    let tree_id = tree.id().unwrap();
    let head = commit.id().unwrap();
    let pack_id = hash(&pack);
    let (id, repo) = upload_pack(&pipe, &signer, &pack).await;
    let update = |name: &str, id| RefUpdate {
        name: name.into(),
        condition: RefWriteCondition::Missing,
        new: Some(id),
    };
    pipe.advance_refs_with_tickets(
        &auth(&pipe, &signer, Procedure::AdvanceRefs),
        update(REF, head),
        update("refs/mkit/packmap/main", pack_id),
        vec![id],
    )
    .await
    .unwrap();
    pipe.set_repo_visibility(
        &auth(&pipe, &signer, Procedure::SetRepoVisibility),
        VisibilityRequest::Envelope(RepoVisibility::Private),
    )
    .await
    .unwrap();
    let credentials = signer.sign_body(Procedure::ListRefs.connect_path(), b"{}");
    let headers = |name: &str| lookup(&credentials, name);
    let envelope = request(Procedure::ListRefs, &headers, Some(b"{}"));
    let counter = pipe.repo_storage(&repo, &envelope).await.unwrap();
    assert_eq!(counter.stored_bytes, pack.len() as u64);
    let many = pipe
        .repo_storage_many(
            &repo.namespace,
            &[
                repo.name.clone(),
                mkit_server::RepoName::new("missing").unwrap(),
                repo.name.clone(),
            ],
            &envelope,
        )
        .await
        .unwrap();
    assert_eq!(many, vec![Some(counter), None, Some(counter)]);
    let reader = pipe
        .object_reader(repo.clone(), ReaderView::Owner(&envelope))
        .await
        .unwrap();
    assert_eq!(
        reader
            .read_canonical(&[head, tree_id, [0; 32]])
            .await
            .unwrap(),
        vec![
            Some(serialize(&commit).unwrap()),
            Some(serialize(&tree).unwrap()),
            None
        ]
    );
    assert!(reader.object_metadata(&[head]).await.unwrap()[0].is_some());
    let urls = reader
        .issue_urls(&[UrlTarget::Object(head)], 60)
        .await
        .unwrap();
    assert_private_http_token(
        &pipe,
        &repository,
        head,
        urls[0].as_ref().unwrap(),
        &serialize(&commit).unwrap(),
    )
    .await;
    for name in ["repository", "missing"] {
        for seed in [5, 6] {
            assert_owner_absence(&pipe, audience, &repo, name, seed).await;
        }
    }
}

#[cfg(all(feature = "http-objects", feature = "test-host"))]
async fn authority_http_host() -> (mkit_server_conformance::test_host::TestHost, TestPipeline) {
    use mkit_server_conformance::test_host::TestHost;
    use mkit_server_conformance::wire::{Profile, WireAuth};
    let hooks = || {
        let defaults = Hooks::new();
        Hooks {
            authorizer: Authority::default(),
            admission: Admit,
            pre_receive: defaults.pre_receive,
            receipts: defaults.receipts,
            outcomes: defaults.outcomes,
        }
    };
    let configure_http = |cfg: &mut PipelineConfig| {
        let AuthMode::AuthV2(auth) = &cfg.auth else {
            panic!("expected auth v2");
        };
        *cfg = config(auth.audience(), NamespaceMode::Authority);
        cfg.indexed = Some(mkit_server::indexed::IndexedConfig::default());
        cfg.http_objects = Some(mkit_server::http_objects::HttpObjectsConfig::default());
    };
    let host = TestHost::start_with_test_layers(
        Profile::new(WireAuth::AuthV2 {
            audience: "http://placeholder.invalid".into(),
            repository: "repository".into(),
            seed: [7; 32],
        }),
        |_, _| Ok(hooks()),
        configure_http,
        |app| app,
    )
    .await
    .unwrap();
    let audience = host.base_url();
    let mut cfg = config(audience, NamespaceMode::Authority);
    configure_http(&mut cfg);
    // Seed objects with the same stores, mode, keys, and clock as the HTTP host.
    let pipe = Pipeline::new(
        host.blobs().clone(),
        host.kv().clone(),
        hooks(),
        cfg,
        host.clock().clone(),
        Arc::new(mkit_server::NoopMetrics),
    )
    .unwrap();
    (host, pipe)
}

#[cfg(all(feature = "http-objects", feature = "test-host"))]
#[tokio::test]
async fn authority_http_routes_cross_test_host_early_gate_and_keep_uniform_absence() {
    use mkit_core::{refs::RefWriteCondition, serialize::serialize};
    use mkit_server::RefUpdate;
    use mkit_server::pipeline::{ReaderView, RepoVisibility, VisibilityRequest};
    let (host, pipe) = authority_http_host().await;
    let audience = host.base_url();
    registered(&pipe, audience, NS).await;
    let repository = format!("{NS}/repository");
    let signer = Signer::new([7; 32], audience, &repository);
    let (pack, _, commit) = canonical_pack();
    let head = commit.id().unwrap();
    let pack_id = hash(&pack);
    let (id, repo) = upload_pack(&pipe, &signer, &pack).await;
    let update = |name: &str, id| RefUpdate {
        name: name.into(),
        condition: RefWriteCondition::Missing,
        new: Some(id),
    };
    pipe.advance_refs_with_tickets(
        &auth(&pipe, &signer, Procedure::AdvanceRefs),
        update(REF, head),
        update("refs/mkit/packmap/main", pack_id),
        vec![id],
    )
    .await
    .unwrap();
    pipe.set_repo_visibility(
        &auth(&pipe, &signer, Procedure::SetRepoVisibility),
        VisibilityRequest::Envelope(RepoVisibility::Private),
    )
    .await
    .unwrap();
    // Tokens must be issued strictly after the visibility change.
    host.clock().advance(1);
    let credentials = signer.sign_body(Procedure::ListRefs.connect_path(), b"{}");
    let headers = |name: &str| lookup(&credentials, name);
    let envelope = request(Procedure::ListRefs, &headers, Some(b"{}"));
    let reader = pipe
        .object_reader(repo, ReaderView::Owner(&envelope))
        .await
        .unwrap();
    let urls = reader
        .issue_urls(&[UrlTarget::Object(head)], 60)
        .await
        .unwrap();
    let client = Client::new(&Url::parse(audience).unwrap()).unwrap();
    let path = format!("/{repository}/-/objects/{}", to_hex(&head));
    let allowed_path = format!("{path}?token={}", urls[0].as_ref().unwrap().expose());
    let allowed = client.get(&allowed_path).await.unwrap();
    assert_eq!(allowed.status, 200);
    assert_eq!(allowed.body, serialize(&commit).unwrap());
    let allowed_head = client.read("HEAD", &allowed_path, &[]).await.unwrap();
    assert_eq!(allowed_head.status, 200);
    assert!(allowed_head.body.is_empty());
    let denied = client.get(&path).await.unwrap();
    let missing = client
        .get(&format!("/{NS}/missing/-/objects/{}", to_hex(&head)))
        .await
        .unwrap();
    assert_eq!((denied.status, missing.status), (404, 404));
    assert_eq!(denied.body, missing.body);
    for namespace in [
        format!("ed25519-{}", "11".repeat(32)),
        format!("0x{}", "11".repeat(20)),
        "root".into(),
    ] {
        let invalid = client
            .get(&format!(
                "/{namespace}/repository/-/objects/{}",
                to_hex(&head)
            ))
            .await
            .unwrap();
        assert_eq!(invalid.status, 400);
    }
    host.shutdown().await;
}

#[cfg(feature = "http-objects")]
async fn assert_owner_absence(
    pipe: &TestPipeline,
    audience: &str,
    repo: &mkit_server::RepoId,
    name: &str,
    seed: u8,
) {
    use mkit_server::pipeline::ReaderView;
    let unauthorized = Signer::new([seed; 32], audience, &format!("{NS}/{name}"));
    let credentials = unauthorized.sign_body(Procedure::ListRefs.connect_path(), b"{}");
    let headers = |n: &str| lookup(&credentials, n);
    let envelope = request(Procedure::ListRefs, &headers, Some(b"{}"));
    let target = mkit_server::RepoId {
        namespace: repo.namespace.clone(),
        name: mkit_server::RepoName::new(name).unwrap(),
    };
    let error = pipe.repo_storage(&target, &envelope).await.unwrap_err();
    assert_eq!(
        (error.code(), error.public_message()),
        (Code::NotFound, "repository not found")
    );
    assert_eq!(
        pipe.repo_storage_many(
            &repo.namespace,
            std::slice::from_ref(&target.name),
            &envelope
        )
        .await
        .unwrap(),
        vec![None]
    );
    let error = pipe
        .object_reader(target, ReaderView::Owner(&envelope))
        .await
        .unwrap_err();
    assert_eq!(
        (error.code(), error.public_message()),
        (Code::NotFound, "repository not found")
    );
}

#[cfg(feature = "http-objects")]
fn canonical_pack() -> (
    Vec<u8>,
    mkit_core::object::Object,
    mkit_core::object::Object,
) {
    use mkit_core::{
        object::{Commit, Identity, Object, Tree},
        pack::PackWriter,
        serialize::serialize,
        sign::{KeyPair, sign_commit},
    };
    let tree = Object::Tree(Tree { entries: vec![] });
    let tree_id = tree.id().unwrap();
    let commit_key = KeyPair::from_seed([4; 32]);
    let mut commit = Commit::new_unannotated(
        tree_id,
        vec![],
        Identity::ed25519(commit_key.public.0),
        commit_key.public.0,
        b"namespace conformance".to_vec(),
        42,
        [0; 64],
    );
    commit.signature = sign_commit(&commit, &commit_key).unwrap().0;
    let commit = Object::Commit(commit);
    let mut pack = PackWriter::new_raw_only();
    for object in [&tree, &commit] {
        pack.push_raw(object.id().unwrap(), &serialize(object).unwrap())
            .unwrap();
    }
    let pack = pack.finish().unwrap();
    (pack, tree, commit)
}

#[cfg(feature = "http-objects")]
async fn upload_pack(
    pipe: &TestPipeline,
    signer: &Signer,
    pack: &[u8],
) -> (mkit_core::hash::Hash, mkit_server::RepoId) {
    use mkit_server::BeginUploadResult;
    let pack_id = hash(pack);
    let a = auth(pipe, signer, Procedure::BeginUpload);
    let repo = a.repo().repo.clone();
    let BeginUploadResult::Ticket { id, token, .. } = pipe
        .begin_upload(&a, REF, &pack_id, pack.len() as u64)
        .await
        .unwrap()
    else {
        panic!("expected ticket");
    };
    let stream = signer.sign_pack(
        Procedure::UploadPack.connect_path(),
        &pack_id,
        pack.len() as u64,
    );
    let a = pipe
        .authenticate(&request(
            Procedure::UploadPack,
            &|name| lookup(&stream, name),
            None,
        ))
        .unwrap();
    let mut upload = pipe
        .open_ticketed_upload(&a, Some(&pack_id), Some(pack.len() as u64), &token)
        .await
        .unwrap();
    upload
        .push(
            Some(&pack_id),
            Some(0),
            bytes::Bytes::copy_from_slice(pack),
            true,
        )
        .await
        .unwrap();
    upload.finish().await.unwrap();
    (id, repo)
}

#[cfg(feature = "http-objects")]
async fn assert_private_http_token(
    pipe: &TestPipeline,
    repository: &str,
    head: mkit_core::hash::Hash,
    token: &mkit_server::url_token::MintedToken,
    expected: &[u8],
) {
    use futures::StreamExt as _;
    use mkit_server::http_objects::{
        HttpBody, HttpObjectRequest, RedactedQuery,
        route::{self, RepoPrefix},
    };
    let path = format!("/{repository}/-/objects/{}", to_hex(&head));
    assert!(route::parse(&path, None, RepoPrefix::Required).is_err());
    let query = format!("token={}", token.expose());
    let headers = |_: &str| Vec::new();
    let mut request = HttpObjectRequest {
        method: "GET",
        raw_path: &path,
        raw_query: None,
        headers: &headers,
        header_names: &[],
    };
    assert_eq!(pipe.serve_http_object(&request).await.status, 404);
    request.raw_query = Some(RedactedQuery::new(&query));
    let response = pipe.serve_http_object(&request).await;
    assert_eq!(response.status, 200);
    let body = match response.body {
        HttpBody::Bytes(bytes) => bytes.to_vec(),
        HttpBody::Stream { mut stream, .. } => {
            let mut bytes = Vec::new();
            while let Some(chunk) = stream.next().await {
                bytes.extend_from_slice(&chunk.unwrap());
            }
            bytes
        }
        HttpBody::Empty => Vec::new(),
    };
    assert_eq!(body, expected);
}
