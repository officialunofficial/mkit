//! Default-off signed operator routes on the canonical Worker paths.
use crate::adapter::ConfigError;
use mkit_server::admin::Config;
/// Operator public keys are configured only through this Worker secret.
pub const KEYS_SECRET: &str = "ADMIN_KEYS";
/// Parse keys and reject reuse of ticket/MAC and URL-token keys.
/// # Errors
/// A malformed, empty or overlapping key list.
pub fn parse(
    var: &impl Fn(&str) -> Option<String>,
    audience: &str,
    tickets: Option<&mkit_server::upload::token::TicketKeys>,
) -> Result<Option<Config>, ConfigError> {
    let Some(json) = var(KEYS_SECRET) else {
        return Ok(None);
    };
    let config =
        Config::parse(audience, &json).map_err(|_| ConfigError("ADMIN_KEYS is invalid".into()))?;
    if !config.enabled() {
        return Ok(None);
    }
    if tickets.is_some_and(|keys| {
        config
            .public_keys()
            .iter()
            .any(|key| keys.contains_ed25519_public(key))
    }) {
        return Err(ConfigError(
            "ADMIN_KEYS must differ from TICKET_KEYS".into(),
        ));
    }
    Ok(Some(config))
}
#[cfg(any(target_arch = "wasm32", test))]
fn supported_path(path: &str) -> bool {
    path == mkit_server::admin::AUDIT_PATH || path == mkit_server::admin::PURGE_PATH
}
#[cfg(any(target_arch = "wasm32", test))]
fn purge_enabled(cfg: &crate::adapter::WorkerConfig) -> bool {
    cfg.hooks
        .as_ref()
        .is_some_and(|hooks| hooks.roles.cache_purge && hooks.http.is_some())
}

#[cfg(target_arch = "wasm32")]
pub(crate) async fn serve(
    mut req: worker::Request,
    env: worker::Env,
    cfg: &crate::adapter::WorkerConfig,
) -> worker::Result<worker::Response> {
    use futures::StreamExt;
    use mkit_server::admin::{BodyCapture, Engine, Response};
    let Some(config) = &cfg.admin else {
        return worker::Response::error("admin disabled", 404);
    };
    if !supported_path(&req.path()) {
        return worker::Response::error("admin operation unavailable", 404);
    }
    if req.method() != worker::Method::Post {
        return worker::Response::error("POST required", 405);
    }
    let headers = req.headers().entries().collect();
    let reply = if let Err(reply) = mkit_server::admin::precheck(&headers) {
        reply
    } else {
        let url = req.url()?;
        let path = format!(
            "{}{}",
            url.path(),
            url.query().map_or(String::new(), |q| format!("?{q}"))
        );
        let mut capture = BodyCapture::default();
        let mut stream = req.stream()?;
        while let Some(chunk) = stream.next().await {
            capture.push(&chunk?);
        }
        let store = crate::ns_client::DoNamespaceStore::new(
            crate::ns_client::StubTransport::new(env.clone(), cfg.placement.clone()),
            cfg.probe_partition(),
        );
        let engine = Engine::new(store, cfg.probe_partition(), config.clone())
            .with_purge(purge_enabled(cfg));
        engine
            .handle(
                &path,
                &headers,
                &capture,
                mkit_server::Clock::now_ms(&crate::clock::WorkerClock),
            )
            .await
    };
    let Response {
        status,
        content_type,
        body,
    } = reply;
    let mut response = worker::Response::from_bytes(body)?.with_status(status);
    response.headers_mut().set("content-type", &content_type)?;
    response.headers_mut().set("cache-control", "no-store")?;
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn manual_purge_is_exposed_and_takedown_stays_unexposed() {
        assert!(supported_path(mkit_server::admin::AUDIT_PATH));
        assert!(supported_path(mkit_server::admin::PURGE_PATH));
        assert!(!supported_path(
            "/mkit.server.admin.v1.AdminService/Takedown"
        ));
    }

    #[test]
    fn purge_activation_requires_the_signed_purge_role() {
        let mut cfg = crate::adapter::WorkerConfig::from_vars(|name| match name {
            "AUTH_AUDIENCE" => Some("https://server.example".into()),
            "AUTH_REPOSITORY" => Some("repo".into()),
            _ => None,
        })
        .unwrap();
        assert!(!purge_enabled(&cfg));
        let mut hooks = crate::hooks::config::HookVars {
            roles: crate::hooks::config::HookRoles {
                authorize: false,
                admit: false,
                outcome: true,
                cache_purge: false,
            },
            timeout: std::time::Duration::from_secs(5),
            authorizer_role: mkit_server::policy::AuthorizerRole::Check,
            http: None,
        };
        cfg.hooks = Some(hooks.clone());
        assert!(!purge_enabled(&cfg));
        hooks.roles.cache_purge = true;
        cfg.hooks = Some(hooks.clone());
        assert!(
            !purge_enabled(&cfg),
            "service binding alone cannot sign global purge"
        );
        hooks.http = Some(crate::hooks::config::HttpVars {
            endpoint: crate::hooks::fetch::Endpoint::new("https://hooks.example").unwrap(),
            validity: std::time::Duration::from_secs(60),
        });
        cfg.hooks = Some(hooks);
        assert!(purge_enabled(&cfg));
    }

    #[test]
    fn keys_default_off_and_overlap_is_refused() {
        assert!(
            parse(&|_| None, "https://server.example", None)
                .unwrap()
                .is_none()
        );
        assert!(
            parse(
                &|_| Some(r#"{"version":1,"keys":[]}"#.into()),
                "https://server.example",
                None
            )
            .unwrap()
            .is_none()
        );
        let signer =
            mkit_server::hooks::HookSigner::new("fixture", zeroize::Zeroizing::new([19; 32]))
                .unwrap();
        let public = mkit_core::hash::to_hex(&signer.public_key());
        let json=serde_json::json!({"version":1,"keys":[{"keyId":"operator","alg":"ed25519","publicKey":public,"roles":["audit"]}]}).to_string();
        let tickets =
            mkit_server::upload::token::TicketKeys::new(vec![("ticket".into(), [19; 32])]).unwrap();
        assert!(
            parse(
                &|_| Some(json.clone()),
                "https://server.example",
                Some(&tickets)
            )
            .is_err()
        );
        assert!(
            parse(&|_| Some(json.clone()), "https://server.example", None)
                .unwrap()
                .unwrap()
                .enabled()
        );
    }
}
