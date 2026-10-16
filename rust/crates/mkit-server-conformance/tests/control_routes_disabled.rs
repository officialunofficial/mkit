//! The public Connect service never installs the test-control interface.
use std::sync::Arc;

use mkit_server::pipeline::{Hooks, Pipeline, PipelineConfig};
use mkit_server::{MemoryBlobStore, MemoryKv, NoopMetrics, SystemClock};
use mkit_server_conformance::{control, wire::client::Client};

#[tokio::test]
async fn public_service_has_no_test_control_routes() {
    let pipeline = Arc::new(
        Pipeline::new(
            MemoryBlobStore::default(),
            MemoryKv::default(),
            Hooks::new(),
            PipelineConfig::new(
                mkit_server::Addressing::Single {
                    repo: mkit_server::RepoId {
                        namespace: mkit_server::NamespaceKey::deployment_default(),
                        name: mkit_server::RepoName::new("default").unwrap(),
                    },
                },
                mkit_server::pipeline::AuthMode::Open,
                mkit_server::upload::UploadLimits::new(1 << 20, 64),
            ),
            Arc::new(SystemClock),
            Arc::new(NoopMetrics),
        )
        .unwrap(),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap())
        .parse()
        .unwrap();
    let app = axum::Router::new().fallback_service(mkit_server::connect::service(pipeline));
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let client = Client::new(&base).unwrap();
    assert_eq!(
        client.get(control::CAPABILITIES_PATH).await.unwrap().status,
        404
    );
    assert_eq!(
        client
            .post(
                control::CONTROL_PATH,
                "application/json",
                &[],
                b"{\"operation\":\"resume\"}".to_vec()
            )
            .await
            .unwrap()
            .status,
        404
    );
    task.abort();
}
