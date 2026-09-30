//! Default-off signed operator routes on the canonical Worker paths.
use mkit_server::admin::Config;
use crate::adapter::ConfigError;
/// Operator public keys are configured only through this Worker secret.
pub const KEYS_SECRET: &str = "ADMIN_KEYS";
/// Parse keys and reject reuse of ticket/MAC and URL-token keys.
/// # Errors
/// A malformed, empty or overlapping key list.
pub fn parse(var: &impl Fn(&str)->Option<String>, audience:&str, tickets:Option<&mkit_server::upload::token::TicketKeys>) -> Result<Option<Config>,ConfigError> {
    let Some(json) = var(KEYS_SECRET) else { return Ok(None); };
    let config = Config::parse(audience, &json).map_err(|_| ConfigError("ADMIN_KEYS is invalid".into()))?;
    if tickets.is_some_and(|keys| config.public_keys().iter().any(|key| keys.contains_ed25519_public(key))) {
        return Err(ConfigError("ADMIN_KEYS must differ from TICKET_KEYS".into()));
    }
    Ok(Some(config))
}
#[cfg(target_arch = "wasm32")]
pub(crate) async fn serve(mut req:worker::Request, env:worker::Env, cfg:&crate::adapter::WorkerConfig)->worker::Result<worker::Response> {
    use futures::StreamExt;
    use mkit_server::admin::{BodyCapture, Engine, Response};
    let Some(config) = &cfg.admin else { return worker::Response::error("admin disabled",404); };
    if req.method() != worker::Method::Post { return worker::Response::error("POST required",405); }
    let headers = req.headers().entries().collect();
    let reply = match mkit_server::admin::precheck(&headers) {
        Err(reply) => reply,
        Ok(()) => {
            let url = req.url()?;
            let path = format!("{}{}",url.path(),url.query().map_or(String::new(),|q|format!("?{q}")));
            let mut capture = BodyCapture::default();
            let mut stream = req.stream()?;
            while let Some(chunk) = stream.next().await { capture.push(&chunk?); }
            let store = crate::ns_client::DoNamespaceStore::new(crate::naming::StubTransport::new(env.clone(),cfg.placement.clone()),cfg.probe_partition());
            let engine = Engine::new(store.clone(), cfg.probe_partition(),config.clone(),cfg.purge.is_some());
            let reply = engine.handle(&path,&headers,&capture,mkit_server::Clock::now_ms(&crate::clock::WorkerClock)).await;
            if reply.status == 200 && path == mkit_server::admin::PURGE_PATH {
                if let Some(id) = serde_json::from_slice::<serde_json::Value>(&reply.body).ok().and_then(|v| v.get("purgeId").and_then(|v|v.as_str()).map(str::to_owned)) {
                    if let Ok(Some(request)) = mkit_server::purge::read_request(&store,&cfg.probe_partition(),&id).await {
                        let _ = crate::purge::immediate(&env,cfg,&request).await;
                    }
                }
            }
            reply
        }
    };
    let Response {status, content_type, body} = reply;
    let mut response = worker::Response::from_bytes(body)?.with_status(status);
    response.headers_mut().set("content-type",&content_type)?;
    response.headers_mut().set("cache-control","no-store")?;
    Ok(response)
}
