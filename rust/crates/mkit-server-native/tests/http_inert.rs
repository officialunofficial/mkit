//! Shipped native defaults expose neither the Stage 2 routes nor URL keys.
#![cfg(feature = "http")]
#![allow(clippy::unwrap_used)] // Invalid fixtures are test failures.

use std::sync::Arc;

use axum::body::Body;
use clap::Parser as _;
use http::{Request, StatusCode};
use mkit_server::pipeline::{AuthMode, Hooks, Pipeline, PipelineConfig, RequestMeta};
use mkit_server::upload::UploadLimits;
use mkit_server::url_token::UrlTarget;
use mkit_server::{
    Addressing, Code, MemoryBlobStore, MemoryKv, NamespaceKey, NoopMetrics, Procedure, RepoId,
    RepoName, SystemClock,
};
use mkit_server_native::{RouterOptions, build_router};
use tower::ServiceExt as _;

fn pipeline() -> Pipeline<MemoryBlobStore, Arc<MemoryKv>, Hooks> {
    let cfg = PipelineConfig::new(
        Addressing::Single {
            repo: RepoId {
                namespace: NamespaceKey::deployment_default(),
                name: RepoName::new("default").unwrap(),
            },
        },
        AuthMode::Open,
        UploadLimits {
            max_total_bytes: 1 << 20,
            max_chunks: 64,
        },
    );
    assert!(cfg.indexed.is_none() && cfg.url_tokens.is_none() && cfg.scanner_retrieval.is_none());
    #[cfg(feature = "http-objects")]
    assert!(cfg.http_objects.is_none());
    Pipeline::new(
        MemoryBlobStore::default(),
        Arc::new(MemoryKv::default()),
        Hooks::new(),
        cfg,
        Arc::new(SystemClock),
        Arc::new(NoopMetrics),
    )
    .unwrap()
}

#[tokio::test]
async fn default_configuration_does_not_mount_objects_or_key_document() {
    let opts = RouterOptions::default();
    #[cfg(feature = "http-objects")]
    assert!(opts.http_objects.is_none());
    let router = build_router(Arc::new(pipeline()), &opts);
    for path in [
        "/-/objects/0000000000000000000000000000000000000000000000000000000000000000",
        "/.well-known/mkit-url-token-keys.json",
        "/_mkit/scanner/pack",
    ] {
        for method in ["GET", "OPTIONS"] {
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(path)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
            assert!(
                !response
                    .headers()
                    .contains_key("access-control-allow-origin")
            );
        }
    }
}

#[tokio::test]
async fn default_issue_object_url_is_unimplemented() {
    let pipe = pipeline();
    let auth = pipe
        .authenticate(&RequestMeta {
            procedure: Procedure::IssueObjectUrl,
            header: &|_| None,
            header_values: None,
            unary_body: Some(b""),
            transport_principal: None,
        })
        .unwrap();
    let error = pipe
        .issue_object_url(&auth, UrlTarget::Object([0; 32]), 60)
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::Unimplemented);
}

#[derive(Debug, clap::Parser)]
struct Serve {
    #[command(flatten)]
    args: mkit_server_native::config::ServeArgs,
}

#[test]
fn url_token_flags_follow_the_explicit_adapter_feature() {
    let help = <Serve as clap::CommandFactory>::command()
        .render_long_help()
        .to_string();
    for flag in ["--url-token-key-file", "--url-token-ttl"] {
        assert_eq!(help.contains(flag), cfg!(feature = "http-objects"));
        #[cfg(not(feature = "http-objects"))]
        {
            let error = Serve::try_parse_from(["serve", flag, "unused"]).unwrap_err();
            assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
        }
    }
    let args = Serve::try_parse_from(["serve", "--repo-root", "."])
        .unwrap()
        .args;
    #[cfg(feature = "http-objects")]
    assert!(args.url_token_key_file.is_none() && args.url_token_ttl.is_none());
    #[cfg(not(feature = "http-objects"))]
    let _ = args;
}

#[test]
#[cfg(not(feature = "test-faults"))]
fn shipped_scanner_retrieval_refuses_activation_before_the_launch_gate() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join(".mkit")).unwrap();
    let args = Serve::try_parse_from([
        "serve",
        "--repo-root",
        root.path().to_str().unwrap(),
        "--listen",
        "127.0.0.1:0",
        "--unsafe-allow-any-peer",
        "--scanner-retrieval",
    ])
    .unwrap()
    .args;
    let error = mkit_server_native::config::resolve(&args, &|_| None).unwrap_err();
    assert!(error.message.contains("4.18"), "{error}");
}
