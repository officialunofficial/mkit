//! The transport a hook call travels over (SPEC-SERVER §§6.1, 7.3).
//!
//! Core builds, signs and validates hook traffic; a channel only moves bytes.
//! The native adapter's HTTPS client (WP-3.8) and the Workers service binding
//! (WP-3.9) implement [`HookChannel`]; tests use an in-memory one.

use core::time::Duration;

use zeroize::Zeroizing;

use crate::error::Redacted;
use crate::rt::{MaybeSend, MaybeSync};

/// One Connect unary call, ready to send.
///
/// The body may carry admission credentials, so [`core::fmt::Debug`] prints
/// only its length and the body is wiped when dropped. Channels must not log
/// it.
#[non_exhaustive]
pub struct HookRequest {
    /// The full Connect path, e.g. `/mkit.server.hooks.v1.HooksService/Admit`;
    /// the channel appends it to its base URL and does not follow redirects.
    pub procedure: &'static str,
    /// Every header to send: `Content-Type`, `Connect-Protocol-Version` and,
    /// on a signed channel, the eight `X-Mkit-Hook-*` headers.
    pub headers: Vec<(&'static str, String)>,
    /// The exact JSON body; the signature covers these bytes.
    pub body: Zeroizing<Vec<u8>>,
    /// How long the call may take. Core also enforces it, so a channel that
    /// can cancel the underlying request should.
    pub timeout: Duration,
    /// Stop reading the response after this many bytes plus one and report
    /// [`ChannelError::TooLarge`]. Core re-checks the length it receives.
    pub max_response_bytes: usize,
}

impl core::fmt::Debug for HookRequest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HookRequest")
            .field("procedure", &self.procedure)
            .field("body_bytes", &self.body.len())
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

/// A hook's HTTP response, whatever its status.
#[non_exhaustive]
pub struct HookResponse {
    /// The HTTP status.
    pub status: u16,
    /// The `Content-Type` header, if any.
    pub content_type: Option<String>,
    /// At most `max_response_bytes + 1` bytes of the body.
    pub body: Vec<u8>,
}

impl HookResponse {
    /// A response with `status`, `content_type` and `body`.
    #[must_use]
    pub fn new(status: u16, content_type: Option<String>, body: Vec<u8>) -> Self {
        Self {
            status,
            content_type,
            body,
        }
    }
}

impl core::fmt::Debug for HookResponse {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HookResponse")
            .field("status", &self.status)
            .field("body_bytes", &self.body.len())
            .finish_non_exhaustive()
    }
}

/// Why a channel produced no response. Every variant means "the hook did not
/// answer": the adapter fails closed (SPEC-SERVER §8).
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum ChannelError {
    /// The channel gave up waiting.
    #[error("hook call timed out")]
    Timeout,
    /// The response exceeded `max_response_bytes`.
    #[error("hook response too large")]
    TooLarge,
    /// Connection, TLS, binding or other failure. The text is operator-only.
    #[error("hook transport failed")]
    Transport(Redacted),
}

/// A route to one hook service.
pub trait HookChannel: MaybeSend + MaybeSync {
    /// The hook endpoint's canonical origin, the `<audience>` a signature
    /// binds (SPEC-SERVER §7.1). `None` for a channel with no origin, which is
    /// then only usable unsigned and isolated.
    fn audience(&self) -> Option<&str>;

    /// Whether this is a platform service binding unreachable from the public
    /// internet, the only channel that may skip signing (SPEC-SERVER §7.3).
    fn isolated(&self) -> bool {
        false
    }

    /// Send `request` and return the hook's response.
    ///
    /// # Errors
    /// [`ChannelError`] when there is no response to return.
    fn call(
        &self,
        request: HookRequest,
    ) -> impl core::future::Future<Output = Result<HookResponse, ChannelError>> + MaybeSend;
}
