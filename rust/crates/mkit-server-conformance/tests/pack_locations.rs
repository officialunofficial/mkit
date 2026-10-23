#![cfg(feature = "test-host")]
#![allow(clippy::unwrap_used)]
//! Pack locations exercise the real Connect and credential-free HTTP boundaries.
use buffa::Message as _;
use bytes::Bytes;
use mkit_client::{Client, Destination, HttpTransport};
use mkit_core::hash::hash;
use mkit_server::store::adapter_spi::{codec, keys};
use mkit_server::{Batch, BlobKey, BlobStore, Clock, NamespaceStore, PackSink};
use mkit_server_conformance::wire::client::{Client as RawClient, Rpc, frame};
use mkit_server_conformance::{
    test_host::TestHost,
    wire::{Feature, Profile, Verdict, WireAuth, WireTarget, run},
};
use mkit_transport_connect::generated::__buffa::oneof::download_pack_response::Body;
use mkit_transport_connect::generated::{DownloadPackRequest, DownloadPackResponse};

fn profile() -> Profile {
    let mut profile = Profile::new(WireAuth::None);
    profile.features.insert(Feature::PackLocations);
    profile
}
async fn seed(host: &TestHost, bytes: &[u8]) {
    let mut sink = host
        .blobs()
        .begin(BlobKey::pack(hash(bytes)), bytes.len() as u64)
        .await
        .unwrap();
    sink.write(Bytes::copy_from_slice(bytes)).await.unwrap();
    sink.commit().await.unwrap();
}
async fn download_repo(
    host: &TestHost,
    bytes: &[u8],
    accept: bool,
    repository: &str,
) -> mkit_server_conformance::wire::client::StreamReply<DownloadPackResponse> {
    RawClient::new(&host.base_url().parse().unwrap())
        .unwrap()
        .stream(
            Rpc::DownloadPack,
            frame(
                &DownloadPackRequest {
                    pack_id: Some(hash(bytes).to_vec()),
                    accept_location: Some(accept),
                    ..Default::default()
                }
                .encode_to_vec(),
            ),
            &[("x-repository".into(), repository.into())],
        )
        .await
        .unwrap()
}
#[tokio::test]
async fn profile_pack_locations_round_trip_and_default_stream() {
    let host = TestHost::start(profile()).await.unwrap();
    let report = run(
        &WireTarget {
            base_url: host.base_url().parse().unwrap(),
            profile: host.profile().clone(),
        },
        Some("pack_locations."),
    )
    .await;
    for name in [
        "pack_locations.opt_in_round_trip",
        "pack_locations.no_location_without_opt_in",
    ] {
        assert!(
            matches!(report.verdict(name), Some(Verdict::Pass(_))),
            "{}",
            report.tap()
        );
    }
    assert_eq!(host.pack_location_fetches(), (1, false));
    host.shutdown().await;
}
#[tokio::test]
async fn denial_after_issue_expires_within_advertised_bound() {
    let (host, repository, repo) = scoped_host().await;
    let bytes = b"verified bounded location pack";
    seed(&host, bytes).await;
    set_membership(&host, &repo, bytes, true, false).await;
    let reply = download_repo(&host, bytes, true, &repository).await;
    let Some(Body::Location(location)) = reply.messages[0].body.as_ref() else {
        panic!("expected a location");
    };
    let raw = RawClient::new(&host.base_url().parse().unwrap()).unwrap();
    let info = raw
        .post(
            "/mkit.transport.v1.TransportService/GetServerInfo",
            "application/proto",
            &[],
            Vec::new(),
        )
        .await
        .unwrap();
    let info = mkit_server_conformance::wire::client::decode_unary::<
        mkit_transport_connect::generated::GetServerInfoResponse,
    >(&info)
    .unwrap()
    .unwrap();
    let expiry = location.expires_at_ms.unwrap();
    assert!(expiry > host.clock().now_ms());
    assert!(
        expiry - host.clock().now_ms()
            <= i64::try_from(info.max_pack_location_lifetime_ms.unwrap()).unwrap()
    );
    let url = location.url.as_ref().unwrap();
    assert_eq!(reqwest::get(url).await.unwrap().status(), 200);
    let batch = Batch::new().put(
        keys::block(&hash(bytes)),
        codec::encode_block_entry(&mkit_server::store::BlockEntry::new("test", 0)),
    );
    host.kv()
        .apply(&mkit_server::store::content_shard(&hash(bytes)), batch)
        .await
        .unwrap();
    for accept in [false, true] {
        let denied = download_repo(&host, bytes, accept, &repository).await;
        assert_eq!(
            denied.messages,
            [] as [mkit_client::proto::DownloadPackResponse; 0]
        );
        assert_eq!(denied.error.unwrap().code, "not_found");
    }
    host.clock().set(location.expires_at_ms.unwrap());
    assert_eq!(reqwest::get(url).await.unwrap().status(), 404);
    host.shutdown().await;
}

async fn scoped_host() -> (TestHost, String, mkit_server::RepoId) {
    let host = TestHost::start_with_test_layers(
        profile(),
        |_, _| Ok(mkit_server::pipeline::Hooks::new()),
        |config| {
            config.addressing = mkit_server::Addressing::Multi(mkit_server::MultiAddressing::new());
            config.auth = mkit_server::pipeline::AuthMode::AuthV2(
                mkit_server::auth_v2::AuthV2Config::new("http://localhost", "default").unwrap(),
            );
            config.indexed = Some(mkit_server::indexed::IndexedConfig::default());
            config.ticket_keys = Some(
                mkit_server::upload::token::TicketKeys::new(vec![("test".into(), [7; 32])])
                    .unwrap(),
            );
            config.begin_upload_threshold_bytes = 0;
            config.takedown_denial = true;
            config.write_policy = mkit_server::policy::WritePolicy::Owner;
        },
        |app| app,
    )
    .await
    .unwrap();
    let repository = format!("ed25519-{}/packs", "11".repeat(32));
    let repo = mkit_server::Addressing::Multi(mkit_server::MultiAddressing::new())
        .resolve(Some(&repository), false)
        .unwrap()
        .repo;
    host.kv()
        .apply(
            &mkit_server::Partition::Namespace(repo.namespace.clone()),
            Batch::new().put(
                keys::repo_record(&repo.name),
                codec::encode_repo_record(&codec::RepoRecord { created_at_ms: 0 }),
            ),
        )
        .await
        .unwrap();
    (host, repository, repo)
}
async fn set_membership(
    host: &TestHost,
    repo: &mkit_server::RepoId,
    bytes: &[u8],
    published: bool,
    held: bool,
) {
    mkit_server::takedown::inventory::complete(
        host.kv().as_ref(),
        &hash(bytes),
        bytes.len() as u64,
        u64::try_from(host.clock().now_ms()).unwrap(),
    )
    .await
    .unwrap();
    let witness = mkit_server::store::adapter_spi::publication::Witness {
        generation: 0,
        sequence: 0,
        published,
        held,
        boundary: false,
    };
    host.kv()
        .apply(
            &mkit_server::Partition::Namespace(repo.namespace.clone()),
            Batch::new().put(keys::membership(&repo.name, &hash(bytes)), witness.encode()),
        )
        .await
        .unwrap();
}
#[tokio::test]
async fn held_pending_private_and_other_repository_never_issue_locations() {
    let (host, repository, repo) = scoped_host().await;
    let bytes = b"repository-owned verified pack";
    seed(&host, bytes).await;
    set_membership(&host, &repo, bytes, true, false).await;
    assert!(matches!(
        download_repo(&host, bytes, true, &repository)
            .await
            .messages[0]
            .body,
        Some(Body::Location(_))
    ));
    for (published, held) in [(true, true), (false, false)] {
        set_membership(&host, &repo, bytes, published, held).await;
        for accept in [false, true] {
            let reply = download_repo(&host, bytes, accept, &repository).await;
            assert_eq!(
                reply.messages,
                [] as [mkit_client::proto::DownloadPackResponse; 0]
            );
            assert_eq!(reply.error.unwrap().code, "not_found");
        }
    }
    set_membership(&host, &repo, bytes, true, false).await;
    let other = repository.replace("/packs", "/other");
    let other_repo = mkit_server::Addressing::Multi(mkit_server::MultiAddressing::new())
        .resolve(Some(&other), false)
        .unwrap()
        .repo;
    host.kv()
        .apply(
            &mkit_server::Partition::Namespace(other_repo.namespace.clone()),
            Batch::new().put(
                keys::repo_record(&other_repo.name),
                codec::encode_repo_record(&codec::RepoRecord { created_at_ms: 0 }),
            ),
        )
        .await
        .unwrap();
    for accept in [false, true] {
        let reply = download_repo(&host, bytes, accept, &other).await;
        assert_eq!(
            reply.messages,
            [] as [mkit_client::proto::DownloadPackResponse; 0]
        );
        assert_eq!(reply.error.unwrap().code, "not_found");
    }
    host.kv()
        .apply(
            &mkit_server::Partition::Namespace(repo.namespace.clone()),
            Batch::new().put(
                keys::repo_visibility(&repo.name),
                codec::encode_repo_visibility(&codec::RepoVisibilityV1 {
                    visibility: codec::StoredVisibility::Private,
                    last_created_ms: 0,
                    last_statement_id: None,
                    changed_ms: 0,
                }),
            ),
        )
        .await
        .unwrap();
    for accept in [false, true] {
        let reply = download_repo(&host, bytes, accept, &repository).await;
        assert_eq!(
            reply.messages,
            [] as [mkit_client::proto::DownloadPackResponse; 0]
        );
        assert_eq!(reply.error.unwrap().code, "not_found");
    }
    host.shutdown().await;
}

struct Channel(reqwest::Client);
impl HttpTransport for Channel {
    async fn send(
        &self,
        request: http::Request<Vec<u8>>,
        limit: usize,
    ) -> Result<http::Response<Vec<u8>>, String> {
        let (parts, body) = request.into_parts();
        let mut response = self
            .0
            .request(parts.method, parts.uri.to_string())
            .headers(parts.headers)
            .body(body)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let mut result = http::Response::builder().status(response.status());
        *result.headers_mut().unwrap() = response.headers().clone();
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? {
            if bytes.len() + chunk.len() > limit {
                return Err("response limit".into());
            }
            bytes.extend_from_slice(&chunk);
        }
        result.body(bytes).map_err(|e| e.to_string())
    }
    fn supports_pack_locations(&self) -> bool {
        true
    }
    fn allows_test_pack_location_http(&self) -> bool {
        true
    }
    async fn fetch_pack_location(
        &self,
        url: &str,
        limit: usize,
        timeout: Option<std::time::Duration>,
    ) -> Result<Vec<u8>, String> {
        let mut request = self.0.get(url);
        if let Some(timeout) = timeout {
            request = request.timeout(timeout);
        }
        let mut response = request
            .send()
            .await
            .map_err(|e| e.to_string())?
            .error_for_status()
            .map_err(|e| e.to_string())?;
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? {
            if bytes.len() + chunk.len() > limit {
                return Err("location limit".into());
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }
}
#[tokio::test]
async fn client_verifies_corrupt_location_and_retries_streaming_once() {
    let host = TestHost::start(profile()).await.unwrap();
    let bytes = b"verified pack body";
    seed(&host, bytes).await;
    host.corrupt_pack_locations(true);
    let channel = Channel(
        reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap(),
    );
    let client = Client::anonymous(
        &channel,
        Destination::new(host.base_url().into(), "default".into()).unwrap(),
    );
    let reply = client
        .download_pack(&hash(bytes), None, 1024, None)
        .await
        .unwrap();
    assert_eq!(reply.value, bytes);
    assert_eq!(host.pack_location_fetches(), (1, false));
    let disabled = Client::anonymous(
        &channel,
        Destination::new(host.base_url().into(), "default".into()).unwrap(),
    )
    .with_pack_locations(false);
    assert_eq!(
        disabled
            .download_pack(&hash(bytes), None, 1024, None)
            .await
            .unwrap()
            .value,
        bytes
    );
    assert_eq!(host.pack_location_fetches(), (1, false));
    host.shutdown().await;
}

#[tokio::test]
async fn portable_pack_location_profile_exercises_all_scenarios() {
    let mut profile = Profile::new(WireAuth::AuthV2 {
        audience: "http://placeholder.invalid".into(),
        repository: "default".into(),
        seed: [0x61; 32],
    });
    profile.max_pack_bytes = 1 << 20;
    profile.features.extend([
        Feature::PackLocations,
        Feature::PackLocationFixtures,
        Feature::MultiRepo,
        Feature::IndexedMode,
        Feature::Tickets,
    ]);
    let host = TestHost::start(profile).await.unwrap();
    let wire = run(
        &WireTarget {
            base_url: host.base_url().parse().unwrap(),
            profile: host.profile().clone(),
        },
        Some("pack_locations."),
    )
    .await;
    assert_eq!(wire.cases.len(), 2, "{}", wire.tap());
    for name in [
        "pack_locations.opt_in_round_trip",
        "pack_locations.no_location_without_opt_in",
    ] {
        assert!(
            matches!(wire.verdict(name), Some(Verdict::Pass(_))),
            "{}",
            wire.tap()
        );
    }
    let report = mkit_server_conformance::controlled::run(
        &WireTarget {
            base_url: host.base_url().parse().unwrap(),
            profile: host.profile().clone(),
        },
        &std::collections::BTreeMap::default(),
        Some("pack_locations."),
    )
    .await;
    for name in [
        "pack_locations.guard_refusals",
        "pack_locations.denial_after_issue_bound",
        "pack_locations.corrupt_location_fallback",
    ] {
        assert!(
            matches!(report.verdict(name), Some(Verdict::Pass(_))),
            "{}",
            report.tap()
        );
    }
    assert!(
        !host.pack_location_fetches().1,
        "location fetch carried mkit credentials"
    );
    host.shutdown().await;
}

const FIXTURE_CASES: [&str; 3] = [
    "pack_locations.guard_refusals",
    "pack_locations.denial_after_issue_bound",
    "pack_locations.corrupt_location_fallback",
];

async fn split_proxy(origin: &str, controls: bool) -> (url::Url, tokio::task::JoinHandle<()>) {
    let origin = origin.to_owned();
    let app = axum::Router::new().fallback(move |request: axum::extract::Request| {
        let origin = origin.clone();
        async move {
            let is_control = request.uri().path().starts_with("/__mkit_test/v1/");
            if is_control != controls {
                return axum::response::Response::builder()
                    .status(404)
                    .body(axum::body::Body::empty())
                    .unwrap();
            }
            let (parts, body) = request.into_parts();
            let body = axum::body::to_bytes(body, 1 << 20).await.unwrap();
            let mut headers = parts.headers;
            headers.remove(http::header::HOST);
            headers.remove(http::header::TRANSFER_ENCODING);
            let response = reqwest::Client::new()
                .request(parts.method, format!("{origin}{}", parts.uri))
                .headers(headers)
                .body(body)
                .send()
                .await
                .unwrap();
            let mut result = axum::response::Response::builder().status(response.status());
            let mut headers = response.headers().clone();
            // The upstream body is decoded and buffered before being forwarded.
            headers.remove(http::header::CONTENT_LENGTH);
            headers.remove(http::header::TRANSFER_ENCODING);
            *result.headers_mut().unwrap() = headers;
            result
                .body(axum::body::Body::from(response.bytes().await.unwrap()))
                .unwrap()
        }
    });
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap())
        .parse()
        .unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (url, task)
}

#[tokio::test]
async fn pack_location_fixtures_use_separate_control_origin() {
    let mut profile = Profile::new(WireAuth::AuthV2 {
        audience: "http://placeholder.invalid".into(),
        repository: "default".into(),
        seed: [0x61; 32],
    });
    profile.features.extend([
        Feature::PackLocations,
        Feature::PackLocationFixtures,
        Feature::MultiRepo,
        Feature::IndexedMode,
        Feature::Tickets,
    ]);
    let host = TestHost::start(profile).await.unwrap();
    let (wire_url, wire_task) = split_proxy(host.base_url(), false).await;
    let (control_url, control_task) = split_proxy(host.base_url(), true).await;
    let target = WireTarget {
        base_url: wire_url,
        profile: host.profile().clone(),
    };
    let wire = run(&target, Some("pack_locations.")).await;
    assert_eq!(wire.cases.len(), 2, "{}", wire.tap());
    for name in [
        "pack_locations.opt_in_round_trip",
        "pack_locations.no_location_without_opt_in",
    ] {
        assert!(
            matches!(wire.verdict(name), Some(Verdict::Pass(_))),
            "{}",
            wire.tap()
        );
    }
    let report = mkit_server_conformance::controlled::run_with_control(
        &target,
        &control_url,
        &std::collections::BTreeMap::default(),
        Some("pack_locations."),
    )
    .await;
    assert_eq!(report.cases.len(), 3, "{}", report.tap());
    for name in FIXTURE_CASES {
        assert!(
            matches!(report.verdict(name), Some(Verdict::Pass(_))),
            "{}",
            report.tap()
        );
    }
    wire_task.abort();
    control_task.abort();
    host.shutdown().await;
}

#[tokio::test]
async fn pack_location_missing_controls_require_declared_skips() {
    use mkit_server_conformance::{controlled, test_host::ControlledHost};
    let mut profile = Profile::new(WireAuth::AuthV2 {
        audience: "http://placeholder.invalid".into(),
        repository: "default".into(),
        seed: [0x61; 32],
    });
    profile.features.insert(Feature::PackLocations);
    let host = ControlledHost::start(profile).await.unwrap();
    let target = WireTarget {
        base_url: host.base_url().parse().unwrap(),
        profile: host.profile().clone(),
    };
    let undeclared = controlled::run(
        &target,
        &std::collections::BTreeMap::default(),
        Some("pack_locations."),
    )
    .await;
    assert_eq!(undeclared.cases.len(), 3, "{}", undeclared.tap());
    assert!(
        undeclared
            .cases
            .iter()
            .all(|case| matches!(case.verdict, Verdict::Fail(_))),
        "{}",
        undeclared.tap()
    );
    let skips = FIXTURE_CASES
        .into_iter()
        .map(|name| (name.into(), "host has no location fixture control".into()))
        .collect();
    let declared = controlled::run(&target, &skips, Some("pack_locations.")).await;
    assert_eq!(declared.cases.len(), 3, "{}", declared.tap());
    assert!(
        declared
            .cases
            .iter()
            .all(|case| matches!(case.verdict, Verdict::Skip(_))),
        "{}",
        declared.tap()
    );
    host.shutdown().await;
}

#[tokio::test]
async fn reference_pack_location_fixtures_reject_sharded_storage() {
    let mut profile = Profile::new(WireAuth::AuthV2 {
        audience: "http://placeholder.invalid".into(),
        repository: "default".into(),
        seed: [0x61; 32],
    });
    profile.sharding_d34 = true;
    profile.features.extend([
        Feature::PackLocations,
        Feature::PackLocationFixtures,
        Feature::MultiRepo,
        Feature::IndexedMode,
        Feature::Tickets,
    ]);
    let error = TestHost::start(profile).await.unwrap_err();
    assert_eq!(
        error,
        "reference pack-location fixtures require unsharded storage"
    );
}
