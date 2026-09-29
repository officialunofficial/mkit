//! [`HttpChannel`]: one hook service over HTTPS (SPEC-SERVER §§6.1, 7.1).

use core::fmt;
use core::time::Duration;

use bytes::Bytes;
use mkit_server::Redacted;
use mkit_server::hooks::{ChannelError, HookChannel, HookRequest, HookResponse};
use url::{Host, Url};

/// Why a hook base URL is refused. The text is fixed and never quotes the URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpChannelError(&'static str);

impl fmt::Display for HttpChannelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for HttpChannelError {}

/// A hook service reached over HTTPS with signed requests. Plain `http` is
/// accepted only for a loopback host, redirects are never followed, and the
/// response is read under a size cap (SPEC-SERVER §6.1).
pub struct HttpChannel {
    client: reqwest::Client,
    /// The base URL without a trailing slash; a procedure path is appended.
    base: String,
    /// The canonical origin: lowercase host, default port dropped.
    origin: String,
}

impl fmt::Debug for HttpChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpChannel")
            .field("origin", &self.origin)
            .finish_non_exhaustive()
    }
}

/// The canonical origin and slash-free base of `base_url`, or why it is
/// refused. Pure, so the rules test without a socket.
///
/// # Errors
/// `https` or loopback `http` only; no userinfo, query or fragment.
fn parse_base(base_url: &str) -> Result<(String, String, bool), HttpChannelError> {
    let refuse = HttpChannelError;
    let url = Url::parse(base_url).map_err(|_| refuse("hook URL is not a valid URL"))?;
    let loopback = match url.host() {
        Some(Host::Domain(name)) => name == "localhost",
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        None => return Err(refuse("hook URL has no host")),
    };
    match url.scheme() {
        "https" => {}
        "http" if loopback => {}
        "http" => return Err(refuse("plain http is allowed only to a loopback host")),
        _ => return Err(refuse("hook URL must be https")),
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(refuse("hook URL must not carry credentials"));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(refuse("hook URL must not carry a query or fragment"));
    }
    let origin = url.origin().ascii_serialization();
    let path = url.path().trim_end_matches('/');
    Ok((
        format!("{origin}{path}"),
        origin,
        url.scheme() == "http" && loopback,
    ))
}

/// Check `base_url` against the channel's rules without building a client.
///
/// # Errors
/// As [`HttpChannel::new`].
pub(super) fn validate_base_url(base_url: &str) -> Result<(), HttpChannelError> {
    parse_base(base_url).map(|_| ())
}

/// The canonical origin and slash-free base of a validated URL.
pub(super) fn canonical_base(base_url: &str) -> Result<String, HttpChannelError> {
    parse_base(base_url).map(|(base, _, _)| base)
}

impl HttpChannel {
    /// A channel to the hook service at `base_url`, which may carry a path
    /// prefix (`https://hooks.example/mkit`).
    ///
    /// # Errors
    /// [`HttpChannelError`] for a base URL the spec refuses, or a client that
    /// cannot be built.
    pub fn new(base_url: &str) -> Result<Self, HttpChannelError> {
        let (base, origin, loopback_http) = parse_base(base_url)?;
        let mut builder = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            // A followed redirect would replay a signed body, credentials
            // included, to another origin.
            .redirect(reqwest::redirect::Policy::none())
            .referer(false);
        if loopback_http {
            // A proxy would see signed bodies in cleartext, and `localhost`
            // must not be re-pointed by /etc/hosts or a resolver.
            builder = builder.no_proxy().resolve_to_addrs(
                "localhost",
                &[
                    std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
                    std::net::SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, 0)),
                ],
            );
        }
        let client = builder
            .build()
            .map_err(|_| HttpChannelError("hook HTTP client could not be built"))?;
        Ok(Self {
            client,
            base,
            origin,
        })
    }
}

fn transport(kind: &'static str) -> ChannelError {
    ChannelError::Transport(Redacted::new(kind))
}

impl HookChannel for HttpChannel {
    fn audience(&self) -> Option<&str> {
        Some(&self.origin)
    }

    async fn call(&self, request: HookRequest) -> Result<HookResponse, ChannelError> {
        let mut call = self
            .client
            .post(format!("{}{}", self.base, request.procedure))
            .timeout(request.timeout);
        for (name, value) in &request.headers {
            call = call.header(*name, value);
        }
        let max = request.max_response_bytes;
        // The body buffer is wiped when the last reference drops.
        let mut response = call
            .body(Bytes::from_owner(request.body))
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    ChannelError::Timeout
                } else {
                    transport("request failed")
                }
            })?;
        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        // Never size a buffer from `Content-Length`: stop at `max + 1`, so
        // core sees the oversize itself and a 2xx still acknowledges.
        let mut body = Vec::new();
        while body.len() <= max {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    let room = (max + 1 - body.len()).min(chunk.len());
                    body.extend_from_slice(&chunk[..room]);
                }
                Ok(None) => break,
                Err(e) if e.is_timeout() => return Err(ChannelError::Timeout),
                Err(_) => return Err(transport("response body failed")),
            }
        }
        Ok(HookResponse::new(status, content_type, body))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_origin_and_prefix() {
        let (base, origin, loopback) = parse_base("HTTPS://Hooks.Example:443/mkit/v1/").unwrap();
        assert_eq!(origin, "https://hooks.example");
        assert_eq!(base, "https://hooks.example/mkit/v1");
        assert!(!loopback);
        let (base, origin, loopback) = parse_base("http://127.0.0.1:9000").unwrap();
        assert_eq!(
            (base.as_str(), origin.as_str()),
            ("http://127.0.0.1:9000", "http://127.0.0.1:9000")
        );
        assert!(loopback);
        assert!(parse_base("http://localhost").is_ok());
        assert!(parse_base("http://[::1]:8080/x").is_ok());
        mkit_core::write_auth::validate_audience(&origin).unwrap();
    }

    #[test]
    fn refuses_what_the_spec_refuses() {
        for bad in [
            "http://hooks.example",
            "http://10.0.0.1",
            "http://localhost.evil.example",
            "ftp://hooks.example",
            "https://user:pw@hooks.example",
            "https://user@hooks.example",
            "https://hooks.example/?a=1",
            "https://hooks.example/#frag",
            "hooks.example",
            "",
        ] {
            assert!(parse_base(bad).is_err(), "{bad}");
        }
    }
}
