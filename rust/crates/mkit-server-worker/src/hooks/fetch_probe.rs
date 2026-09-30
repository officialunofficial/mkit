//! Test-only workerd probes for the production FetchChannel.
use super::fetch::{Endpoint, FetchChannel};
use crate::sleep::WorkerSleep;
use core::time::Duration;
use mkit_server::hooks::{ChannelError, HookChannel, HookRequest, HookSigner};
use mkit_server::{Sleep, with_timeout};
use zeroize::Zeroizing;

/// Exercise the real channel with a harness-local HTTPS route interception.
pub async fn run(mode: &str) -> worker::Result<worker::Response> {
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
