//! One signed, bounded, size-checked hook call.

use core::time::Duration;
use std::sync::Arc;

use mkit_core::write_auth::validate_audience;
use serde::Serialize;
use serde::de::DeserializeOwned;
use zeroize::Zeroizing;

use super::channel::{ChannelError, HookChannel, HookRequest, HookResponse};
use super::sign::{HookSigner, NonceSource, OsNonces};
use crate::rt::{Clock, Sleep, with_timeout};

/// The default per-call timeout (SPEC-SERVER §8, informative).
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
/// The largest response body core accepts (SPEC-SERVER §6.6).
pub const MAX_RESPONSE_BYTES: usize = 65_536;

/// A hook RPC this adapter calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rpc {
    Authorize,
    Admit,
    Outcome,
    CachePurge,
}

impl Rpc {
    pub(crate) const fn path(self) -> &'static str {
        match self {
            Self::Authorize => "/mkit.server.hooks.v1.HooksService/Authorize",
            Self::Admit => "/mkit.server.hooks.v1.HooksService/Admit",
            Self::Outcome => "/mkit.server.hooks.v1.HooksService/Outcome",
            Self::CachePurge => "/mkit.server.hooks.v1.HooksService/CachePurge",
        }
    }
}

/// A refused adapter configuration.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum HookConfigError {
    /// A channel that is not an isolated service binding must sign
    /// (SPEC-SERVER §7.1 versus §7.3).
    #[error("a non-isolated hook channel requires a signer")]
    SignerRequired,
    /// An unsigned channel is a service binding, which has no origin.
    #[error("an unsigned hook channel must not report an origin")]
    UnsignedOrigin,
    /// Signing binds the hook endpoint's canonical origin, so the channel
    /// must name one.
    #[error("a signed hook channel must report its canonical origin")]
    ChannelAudience,
    /// The named origin is not a canonical HTTP(S) origin, or is plain HTTP
    /// to a host that is not loopback (SPEC-SERVER §6.1).
    #[error("{0} is not a canonical origin (plain HTTP is loopback-only)")]
    Audience(&'static str),
}

/// Whether the authority of a canonical `http://` origin is a loopback host.
fn loopback(authority: &str) -> bool {
    let host = match authority.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or_default(),
        None => authority.split(':').next().unwrap_or_default(),
    };
    host == "localhost"
        || host == "::1"
        || host
            .parse::<std::net::Ipv4Addr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// Counts the bytes a value serialises to, without keeping any.
struct Counter(usize);

impl std::io::Write for Counter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 += bytes.len();
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Serialise into one exactly sized `Zeroizing` buffer. Growing a `Vec` while
/// serialising would free unwiped partial copies of any credential inside.
pub(super) fn encode<Req: Serialize>(request: &Req) -> Result<Zeroizing<Vec<u8>>, CallFailure> {
    let fail = |_| CallFailure("request not encodable");
    let mut size = Counter(0);
    serde_json::to_writer(&mut size, request).map_err(fail)?;
    let mut body = Zeroizing::new(Vec::with_capacity(size.0));
    serde_json::to_writer(&mut *body, request).map_err(fail)?;
    Ok(body)
}

/// Why a call produced no usable answer. The reason is a fixed string, never
/// hook-controlled text, so it is safe to log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CallFailure(pub(crate) &'static str);

/// The shared client the per-role types (`RemoteAuthorizer`,
/// `RemoteAdmission`, `RemoteOutcomes`) hold behind an `Arc`.
pub struct HookClient<C> {
    channel: C,
    signer: Option<HookSigner>,
    /// The channel's origin, validated once at construction; `Some` exactly
    /// when the client signs.
    hook_audience: Option<String>,
    server_audience: String,
    clock: Arc<dyn Clock>,
    sleep: Arc<dyn Sleep>,
    nonces: Arc<dyn NonceSource>,
}

impl<C> core::fmt::Debug for HookClient<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HookClient")
            .field("server_audience", &self.server_audience)
            .field("signer", &self.signer)
            .finish_non_exhaustive()
    }
}

impl<C: HookChannel> HookClient<C> {
    /// A client over `channel`. `server_audience` is this server's own
    /// canonical origin (the `audience` hook bodies carry, not the hook
    /// endpoint's). `clock` stamps signatures and `sleep` enforces call
    /// timeouts.
    ///
    /// # Errors
    /// [`HookConfigError`] when the channel is neither signed nor isolated,
    /// or an origin is malformed.
    pub fn new(
        channel: C,
        server_audience: impl Into<String>,
        signer: Option<HookSigner>,
        clock: Arc<dyn Clock>,
        sleep: Arc<dyn Sleep>,
    ) -> Result<Self, HookConfigError> {
        let server_audience = server_audience.into();
        validate_audience(&server_audience).map_err(|_| HookConfigError::Audience("server"))?;
        if signer.is_none() && !channel.isolated() {
            return Err(HookConfigError::SignerRequired);
        }
        // A signed channel must report its origin, since the signature binds
        // it, and is held to §6.1; an unsigned one is a service binding and
        // has none (§7.3).
        match (channel.audience(), signer.is_some()) {
            (Some(_), false) => return Err(HookConfigError::UnsignedOrigin),
            (Some(origin), true) => {
                let plain_remote = origin
                    .strip_prefix("http://")
                    .is_some_and(|rest| !loopback(rest));
                if validate_audience(origin).is_err() || plain_remote {
                    return Err(HookConfigError::Audience("hook"));
                }
            }
            (None, true) => return Err(HookConfigError::ChannelAudience),
            (None, false) => {}
        }
        let hook_audience = channel.audience().map(str::to_owned);
        Ok(Self {
            channel,
            signer,
            hook_audience,
            server_audience,
            clock,
            sleep,
            nonces: Arc::new(OsNonces),
        })
    }

    /// Replace the nonce source. A constant source makes the hook reject every
    /// request after the first as a replay, so this fails closed; it exists
    /// for tests that pin a signature.
    #[must_use]
    pub fn with_nonce_source(mut self, nonces: Arc<dyn NonceSource>) -> Self {
        self.nonces = nonces;
        self
    }

    #[cfg(test)]
    pub(crate) fn channel(&self) -> &C {
        &self.channel
    }

    /// This server's canonical origin, as bodies carry it.
    pub(crate) fn server_audience(&self) -> &str {
        &self.server_audience
    }

    /// Sign and send `request` to `rpc` and return the hook's answer whatever
    /// its status. Every signature carries a fresh nonce and validity window.
    async fn send<Req: Serialize>(
        &self,
        rpc: Rpc,
        request: &Req,
        timeout: Duration,
    ) -> Result<HookResponse, CallFailure> {
        let body = encode(request)?;
        let mut headers = vec![
            ("Content-Type", "application/json".to_owned()),
            ("Connect-Protocol-Version", "1".to_owned()),
        ];
        if let Some(signer) = &self.signer {
            let audience = self
                .hook_audience
                .as_deref()
                .ok_or(CallFailure("no hook origin"))?;
            let mut nonce = [0u8; 32];
            if !self.nonces.fill(&mut nonce) {
                return Err(CallFailure("no nonce"));
            }
            headers.extend(
                signer
                    .headers(audience, rpc.path(), &body, self.clock.now_ms(), &nonce)
                    .map_err(|_| CallFailure("cannot sign"))?,
            );
        }
        let call = self.channel.call(HookRequest {
            procedure: rpc.path(),
            headers,
            body,
            timeout,
            max_response_bytes: MAX_RESPONSE_BYTES,
        });
        with_timeout(&*self.sleep, timeout, call)
            .await
            .map_err(|_| CallFailure("timeout"))?
            .map_err(|err| match err {
                ChannelError::Timeout => CallFailure("timeout"),
                ChannelError::TooLarge => CallFailure("response too large"),
                _ => CallFailure("transport error"),
            })
    }

    /// Call a decision RPC: a 2xx JSON answer of at most 64 KiB that decodes
    /// as `Res`, or a failure (unknown JSON fields are ignored).
    pub(crate) async fn decide<Req, Res>(
        &self,
        rpc: Rpc,
        request: &Req,
        timeout: Duration,
    ) -> Result<Res, CallFailure>
    where
        Req: Serialize,
        Res: DeserializeOwned,
    {
        let response = self.send(rpc, request, timeout).await?;
        if !(200..300).contains(&response.status) {
            return Err(CallFailure("non-2xx status"));
        }
        if response.body.len() > MAX_RESPONSE_BYTES {
            return Err(CallFailure("response too large"));
        }
        let json = response.content_type.as_deref().is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|media| media.trim().eq_ignore_ascii_case("application/json"))
        });
        if !json {
            return Err(CallFailure("non-JSON content type"));
        }
        serde_json::from_slice(&response.body).map_err(|_| CallFailure("malformed response"))
    }

    /// Call a delivery RPC: any 2xx acknowledges, whatever the body.
    pub(crate) async fn deliver<Req: Serialize>(
        &self,
        rpc: Rpc,
        request: &Req,
        timeout: Duration,
    ) -> Result<(), CallFailure> {
        let response = self.send(rpc, request, timeout).await?;
        if (200..300).contains(&response.status) {
            Ok(())
        } else {
            Err(CallFailure("non-2xx status"))
        }
    }
}
