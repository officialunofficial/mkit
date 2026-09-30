//! Signed HTTPS hooks (WP-3.9c). One fetch, manual redirects, bounded streaming.

use crate::adapter::ConfigError;

/// A validated endpoint. Paths may contain credentials; Debug prints no URL.
#[derive(Clone, PartialEq, Eq)]
pub struct Endpoint {
    base: String,
    origin: String,
}

impl core::fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Endpoint([REDACTED])")
    }
}

impl Endpoint {
    /// Validate and canonicalize an HTTPS base URL, including a path prefix.
    ///
    /// # Errors
    /// Non-HTTPS URLs, userinfo, queries and fragments are refused.
    pub fn new(text: &str) -> Result<Self, ConfigError> {
        let bad =
            || ConfigError("HOOK_URL must be HTTPS without userinfo, query or fragment".into());
        let url = url::Url::parse(text).map_err(|_| bad())?;
        // Reject even empty userinfo, which Url's username accessor erases.
        let authority = text
            .split_once("://")
            .map(|(_, rest)| rest.split('/').next().unwrap_or(rest));
        if url.scheme() != "https"
            || url.host().is_none()
            || authority.is_some_and(|s| s.contains('@'))
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(bad());
        }
        let origin = url.origin().ascii_serialization();
        Ok(Self {
            base: format!("{origin}{}", url.path().trim_end_matches('/')),
            origin,
        })
    }

    /// Canonical origin used by the hook signature; excludes the path prefix.
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// Append an exact Connect procedure path to the configured prefix.
    #[must_use]
    pub fn url(&self, procedure: &str) -> String {
        format!("{}{procedure}", self.base)
    }
}

// The cancellation guard is shared with host tests; it also runs if the caller
// drops the future while either headers or a response body is pending.
#[cfg(any(test, target_arch = "wasm32"))]
struct CancelOnDrop<F: FnOnce()>(Option<F>);
#[cfg(any(test, target_arch = "wasm32"))]
impl<F: FnOnce()> Drop for CancelOnDrop<F> {
    fn drop(&mut self) {
        if let Some(cancel) = self.0.take() {
            cancel();
        }
    }
}

#[cfg(any(test, target_arch = "wasm32"))]
async fn bounded<T>(
    exchange: impl core::future::Future<Output = Result<T, mkit_server::hooks::ChannelError>>,
    sleep: &dyn mkit_server::Sleep,
    timeout: core::time::Duration,
    cancel: impl FnOnce(),
) -> Result<T, mkit_server::hooks::ChannelError> {
    let _cancel = CancelOnDrop(Some(cancel));
    match futures::future::select(Box::pin(exchange), sleep.sleep(timeout)).await {
        futures::future::Either::Left((answer, _)) => answer,
        futures::future::Either::Right(_) => Err(mkit_server::hooks::ChannelError::Timeout),
    }
}

#[cfg(target_arch = "wasm32")]
pub use channel::{FetchChannel, WorkerChannel};

#[cfg(target_arch = "wasm32")]
mod channel {
    use super::{Endpoint, bounded};
    use crate::hooks::binding::{BindingChannel, CappedBody};
    use crate::sleep::WorkerSleep;
    use core::pin::Pin;
    use http_body::Body as _;
    use mkit_server::Redacted;
    use mkit_server::hooks::{ChannelError, HookChannel, HookRequest, HookResponse};
    use worker::{Fetch, Headers, Method, Request, RequestInit, RequestRedirect};

    /// The stock Worker entry points select binding or signed HTTPS hooks.
    #[derive(Debug)]
    pub enum WorkerChannel {
        /// Isolated, unsigned service binding.
        Binding(BindingChannel),
        /// Public HTTPS endpoint, signed by `HookClient`.
        Http(FetchChannel),
    }

    impl HookChannel for WorkerChannel {
        fn audience(&self) -> Option<&str> {
            match self {
                Self::Binding(c) => c.audience(),
                Self::Http(c) => c.audience(),
            }
        }
        fn isolated(&self) -> bool {
            matches!(self, Self::Binding(_))
        }
        async fn call(&self, request: HookRequest) -> Result<HookResponse, ChannelError> {
            match self {
                Self::Binding(c) => c.call(request).await,
                Self::Http(c) => c.call(request).await,
            }
        }
    }

    /// A single signed HTTPS route. It performs no retries.
    #[derive(Debug, Clone)]
    pub struct FetchChannel {
        endpoint: Endpoint,
    }

    impl FetchChannel {
        /// Build from an already validated HTTPS endpoint.
        #[must_use]
        pub fn new(endpoint: Endpoint) -> Self {
            Self { endpoint }
        }
    }

    fn transport(reason: &'static str) -> ChannelError {
        ChannelError::Transport(Redacted::new(reason))
    }

    impl HookChannel for FetchChannel {
        fn audience(&self) -> Option<&str> {
            Some(self.endpoint.origin())
        }
        async fn call(&self, request: HookRequest) -> Result<HookResponse, ChannelError> {
            let abort = web_sys::AbortController::new()
                .map_err(|_| transport("fetch cancellation unavailable"))?;
            let signal = worker::AbortSignal::from(abort.signal());
            let headers = Headers::new();
            for (name, value) in &request.headers {
                headers
                    .set(name, value)
                    .map_err(|_| transport("bad hook header"))?;
            }
            // Rust bytes are wiped by HookRequest. The JS copy cannot be wiped.
            let bytes = worker::js_sys::Uint8Array::from(request.body.as_slice());
            let mut init = RequestInit::new();
            init.with_method(Method::Post)
                .with_headers(headers)
                .with_redirect(RequestRedirect::Manual)
                .with_body(Some(bytes.into()));
            let outbound = Request::new_with_init(&self.endpoint.url(request.procedure), &init)
                .map_err(|_| transport("bad hook request"))?;
            let exchange = async {
                let response = Fetch::Request(outbound)
                    .send_with_signal(&signal)
                    .await
                    .map_err(|_| transport("hook fetch failed"))?;
                let response = worker::HttpResponse::try_from(response)
                    .map_err(|_| transport("bad hook response"))?;
                let status = response.status().as_u16();
                let content_type = response
                    .headers()
                    .get(http::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_owned);
                let mut body = response.into_body();
                let mut capped = CappedBody::new(request.max_response_bytes);
                while let Some(frame) =
                    futures::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await
                {
                    let frame = frame.map_err(|_| transport("hook body failed"))?;
                    if let Ok(data) = frame.into_data()
                        && capped.push(&data)
                    {
                        break;
                    }
                }
                Ok(HookResponse::new(status, content_type, capped.into_bytes()))
            };
            // One timeout covers fetching headers AND reading a stalled body.
            bounded(exchange, &WorkerSleep, request.timeout, || abort.abort()).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn https_origin_prefix_and_redaction() {
        let endpoint = Endpoint::new("HTTPS://Hooks.Example:443/secret/prefix/").unwrap();
        assert_eq!(endpoint.origin(), "https://hooks.example");
        assert_eq!(
            endpoint.url("/procedure"),
            "https://hooks.example/secret/prefix/procedure"
        );
        assert!(!format!("{endpoint:?}").contains("secret"));
    }
    #[test]
    fn invalid_urls_do_not_leak() {
        for url in [
            "http://localhost",
            "http://hooks.example",
            "https://secret@hooks.example",
            "https://@hooks.example",
            "https://hooks.example/?secret",
            "https://hooks.example/#secret",
            "",
            "ftp://hooks.example",
        ] {
            let error = Endpoint::new(url).unwrap_err();
            assert!(!error.0.contains("secret"));
        }
    }
}

#[cfg(test)]
mod cancellation_tests {
    use super::*;
    use futures::{FutureExt, executor::block_on, future};
    use mkit_server::ManualSleep;
    use std::{
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    };
    #[test]
    fn stalled_exchange_times_out_and_aborts() {
        let sleep = ManualSleep::new();
        let cancelled = Arc::new(AtomicBool::new(false));
        let flag = cancelled.clone();
        let mut call = Box::pin(bounded(
            future::pending::<Result<(), _>>(),
            &sleep,
            Duration::from_millis(5),
            move || flag.store(true, Ordering::SeqCst),
        ));
        assert!((&mut call).now_or_never().is_none());
        sleep.fire();
        assert!(matches!(
            block_on(call),
            Err(mkit_server::hooks::ChannelError::Timeout)
        ));
        assert!(cancelled.load(Ordering::SeqCst));
    }
    #[test]
    fn caller_cancellation_aborts() {
        let sleep = ManualSleep::new();
        let cancelled = Arc::new(AtomicBool::new(false));
        let flag = cancelled.clone();
        let mut call = Box::pin(bounded(
            future::pending::<Result<(), _>>(),
            &sleep,
            Duration::from_secs(1),
            move || flag.store(true, Ordering::SeqCst),
        ));
        assert!((&mut call).now_or_never().is_none());
        drop(call);
        assert!(cancelled.load(Ordering::SeqCst));
    }
}
