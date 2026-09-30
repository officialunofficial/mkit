//! Test-only workerd probes for the production FetchChannel.
use super::fetch::{Endpoint, FetchChannel};
use crate::sleep::WorkerSleep;
use core::time::Duration;
use mkit_server::hooks::{ChannelError, HookChannel, HookRequest, HookSigner};
use mkit_server::{Sleep, with_timeout};
use zeroize::Zeroizing;

/// Exercise the real channel with a harness-local HTTPS route interception.
pub async fn run(mode: &str) -> worker::Result<worker::Response> {
    if mode.starts_with("inspect-") {
        return inspect_probe().await;
    }
    let endpoint = Endpoint::new("https://hook-probe.invalid/prefix")
        .map_err(|e| worker::Error::RustError(e.to_string()))?;
    let channel = FetchChannel::new(endpoint);
    let signer = HookSigner::new("probe", Zeroizing::new([0x19; 32]))
        .map_err(|e| worker::Error::RustError(e.to_string()))?;
    let procedure = "/mkit.server.hooks.v1.HooksService/Admit";
    let body = b"{ \"probe\": true }".to_vec();
    let headers = signer
        .headers(
            "https://hook-probe.invalid",
            procedure,
            &body,
            100_000,
            &[1; 32],
        )
        .map_err(|e| worker::Error::RustError(e.to_string()))?;
    let request = HookRequest::new(procedure, headers, body, Duration::from_millis(40), 4);
    let result = if mode == "cancel" {
        match with_timeout(
            &WorkerSleep,
            Duration::from_millis(5),
            channel.call(request),
        )
        .await
        {
            Err(_) => Err(ChannelError::Timeout),
            Ok(result) => result,
        }
    } else {
        channel.call(request).await
    };
    // Give the local peer time to observe the dropped socket or body reader.
    WorkerSleep.sleep(Duration::from_millis(5)).await;
    let answer = match result {
        Err(ChannelError::Timeout) => serde_json::json!({"timedOut":true}),
        Ok(response) => serde_json::json!({"status":response.status,"bytes":response.body.len()}),
        Err(_) => serde_json::json!({"transportError":true}),
    };
    worker::Response::from_json(&answer)
}

async fn inspect_probe() -> worker::Result<worker::Response> {
    use mkit_server::hooks::{HookClient, InspectVerdict, RemoteInspector};
    use mkit_server::{NamespaceKey, OpKind, Operation, Principal, RefUpdate, RepoId, RepoName};
    use std::sync::Arc;

    let fail = |error: String| worker::Error::RustError(error);
    let endpoint =
        Endpoint::new("https://hook-probe.invalid/prefix").map_err(|e| fail(e.to_string()))?;
    let client = HookClient::new(
        FetchChannel::new(endpoint),
        "https://vcs.example.test",
        Some(
            HookSigner::new("probe", Zeroizing::new([0x19; 32]))
                .map_err(|e| fail(e.to_string()))?,
        ),
        Arc::new(crate::clock::WorkerClock),
        Arc::new(WorkerSleep),
    )
    .map_err(|e| fail(e.to_string()))?;
    let inspector = RemoteInspector::new("probe", Arc::new(client));
    let op = Operation::new(
        RepoId {
            namespace: NamespaceKey::deployment_default(),
            name: RepoName::new("probe").map_err(|e| fail(e.to_string()))?,
        },
        Principal::Anonymous,
        None,
        OpKind::UpdateRef(RefUpdate {
            name: "refs/heads/main".into(),
            condition: mkit_core::refs::RefWriteCondition::Missing,
            new: Some([3; 32]),
        }),
    );
    let objects = vec![serde_json::from_value(serde_json::json!({
        "id": "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI=", "size": "123", "kind": "INSPECT_OBJECT_KIND_BLOB"
    })).map_err(|e| fail(e.to_string()))?];
    let mut verdicts = Vec::new();
    for _ in 0..2 {
        verdicts.push(
            match inspector
                .inspect(&op, "inspection:runtime-probe", &objects)
                .await
            {
                Ok(InspectVerdict::Pass) => "pass",
                Ok(InspectVerdict::Reject(_)) => "reject",
                Err(error) if error.code() == mkit_server::Code::Unavailable => "unavailable",
                Err(_) => "unexpected",
            },
        );
    }
    worker::Response::from_json(&serde_json::json!({"verdicts":verdicts}))
}
