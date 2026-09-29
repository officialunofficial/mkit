//! [`BindingChannel`]: the hook Worker over a service binding (SPEC-SERVER
//! §7.3). A service binding is not reachable from the public internet, so the
//! channel reports [`HookChannel::isolated`] and sends no signature; the hook
//! Worker must have no public route (its `workers.dev` and preview URLs
//! disabled), which the adapter cannot check (see the crate README).
//!
//! URL building and the response cap are pure so host tests reach them; the
//! channel itself needs the `worker` runtime and is wasm32-only.

/// The origin every binding call names. A service binding routes by binding,
/// not by host: the hook Worker sees only the path, so this is a fixed,
/// unresolvable placeholder.
pub const ORIGIN: &str = "https://mkit-hook.invalid";

/// The URL of `procedure` (a Connect path such as
/// `/mkit.server.hooks.v1.HooksService/Admit`) on the binding.
#[must_use]
pub fn hook_url(procedure: &str) -> String {
    format!("{ORIGIN}{procedure}")
}

/// A response body read under a cap: at most `max + 1` bytes are kept, so the
/// caller can tell "exactly `max`" from "more" without holding the rest
/// (SPEC-SERVER §6.6; `HookRequest::max_response_bytes`).
#[derive(Debug)]
pub struct CappedBody {
    bytes: Vec<u8>,
    max: usize,
}

impl CappedBody {
    /// An empty body capped at `max` bytes.
    #[must_use]
    pub fn new(max: usize) -> Self {
        Self {
            bytes: Vec::new(),
            max,
        }
    }

    /// Keep the part of `chunk` that fits under `max + 1`. `true` when the
    /// body is now over the cap and reading should stop.
    pub fn push(&mut self, chunk: &[u8]) -> bool {
        let room = (self.max + 1).saturating_sub(self.bytes.len());
        self.bytes
            .extend_from_slice(&chunk[..room.min(chunk.len())]);
        self.bytes.len() > self.max
    }

    /// The bytes kept.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

#[cfg(target_arch = "wasm32")]
pub use channel::BindingChannel;

#[cfg(target_arch = "wasm32")]
mod channel {
    use core::pin::Pin;

    use http_body::Body as _;
    use mkit_server::Redacted;
    use mkit_server::hooks::{ChannelError, HookChannel, HookRequest, HookResponse};
    use worker::js_sys::Uint8Array;
    use worker::{Env, Fetcher, Headers, Method, RequestInit, RequestRedirect};

    use super::{CappedBody, hook_url};
    use crate::adapter::ConfigError;
    use crate::hooks::config::BINDING;

    /// The hook Worker behind the [`BINDING`] service binding.
    #[derive(Debug, Clone)]
    pub struct BindingChannel {
        fetcher: Fetcher,
    }

    impl BindingChannel {
        /// The channel over `env`'s [`BINDING`].
        ///
        /// # Errors
        /// [`ConfigError`] when the binding is absent.
        pub fn from_env(env: &Env) -> Result<Self, ConfigError> {
            env.service(BINDING)
                .map(|fetcher| Self { fetcher })
                .map_err(|_| {
                    ConfigError(format!("the {BINDING} service binding is not configured"))
                })
        }
    }

    fn transport(kind: &'static str) -> ChannelError {
        ChannelError::Transport(Redacted::new(kind))
    }

    impl HookChannel for BindingChannel {
        fn audience(&self) -> Option<&str> {
            None
        }

        fn isolated(&self) -> bool {
            true
        }

        async fn call(&self, request: HookRequest) -> Result<HookResponse, ChannelError> {
            let headers = Headers::new();
            for (name, value) in &request.headers {
                headers
                    .set(name, value)
                    .map_err(|_| transport("bad request header"))?;
            }
            // The JS copy of the body cannot be wiped; the Rust one is, when
            // `request` drops.
            let body = Uint8Array::from(request.body.as_slice());
            let mut init = RequestInit::new();
            init.with_method(Method::Post)
                .with_headers(headers)
                // A followed redirect would replay a body with credentials.
                .with_redirect(RequestRedirect::Manual)
                .with_body(Some(body.into()));
            let response = self
                .fetcher
                .fetch(hook_url(request.procedure), Some(init))
                .await
                .map_err(|_| transport("binding call failed"))?;
            let status = response.status().as_u16();
            let content_type = response
                .headers()
                .get(http::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
            let mut body = response.into_body();
            let mut capped = CappedBody::new(request.max_response_bytes);
            // Stream, and stop at the cap: the rest is never buffered.
            while let Some(frame) =
                futures::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await
            {
                let frame = frame.map_err(|_| transport("response body failed"))?;
                if let Ok(data) = frame.into_data()
                    && capped.push(&data)
                {
                    break;
                }
            }
            Ok(HookResponse::new(status, content_type, capped.into_bytes()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_are_the_placeholder_origin_plus_the_procedure() {
        assert_eq!(
            hook_url("/mkit.server.hooks.v1.HooksService/Admit"),
            "https://mkit-hook.invalid/mkit.server.hooks.v1.HooksService/Admit"
        );
    }

    #[test]
    fn the_cap_keeps_exactly_max_plus_one() {
        let mut body = CappedBody::new(4);
        assert!(!body.push(b"ab"));
        assert!(!body.push(b"cd"));
        assert!(body.push(b"efgh"));
        assert_eq!(body.into_bytes(), b"abcde");
        let mut exact = CappedBody::new(4);
        assert!(!exact.push(b"abcd"));
        assert_eq!(exact.into_bytes(), b"abcd");
        let mut once = CappedBody::new(3);
        assert!(once.push(&[7; 100]));
        assert_eq!(once.into_bytes().len(), 4);
        let mut zero = CappedBody::new(0);
        assert!(zero.push(b"x"));
        assert_eq!(zero.into_bytes(), b"x");
        // Further chunks after the cap add nothing.
        let mut full = CappedBody::new(2);
        assert!(full.push(b"abc"));
        assert!(full.push(b"zzz"));
        assert_eq!(full.into_bytes(), b"abc");
    }
}
