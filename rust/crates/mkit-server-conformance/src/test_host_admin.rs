//! Two signed admin routes used by the portable takedown fixture.
use mkit_core::hash::to_hex;
use mkit_server::admin::{BodyCapture, Config, Engine};
use mkit_server::{Clock as _, ManualClock, MemoryKv};
use std::sync::Arc;

pub(super) fn config(origin: &str) -> Result<Config, String> {
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x77; 32]);
    Config::parse(origin, &serde_json::json!({"version":1,"keys":[{"keyId":"operator","alg":"ed25519","publicKey":to_hex(key.verifying_key().as_bytes()),"roles":["moderation"]}]}).to_string()).map_err(|e| e.to_string())
}

pub(super) async fn dispatch(
    axum::Extension(engine): axum::Extension<Arc<Engine<Arc<MemoryKv>>>>,
    axum::Extension(clock): axum::Extension<Arc<ManualClock>>,
    uri: http::Uri,
    headers: http::HeaderMap,
    bytes: bytes::Bytes,
) -> axum::response::Response {
    let headers = headers
        .iter()
        .filter_map(|(k, v)| v.to_str().ok().map(|v| (k.to_string(), v.to_owned())))
        .collect();
    let mut body = BodyCapture::default();
    body.push(&bytes);
    let response = engine
        .handle(uri.path(), &headers, &body, clock.now_ms())
        .await;
    axum::response::IntoResponse::into_response((
        http::StatusCode::from_u16(response.status)
            .unwrap_or(http::StatusCode::INTERNAL_SERVER_ERROR),
        [
            ("content-type", response.content_type),
            ("cache-control", "no-store".into()),
        ],
        response.body,
    ))
}
