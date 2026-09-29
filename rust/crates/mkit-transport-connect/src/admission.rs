//! Protocol-neutral admission responder, strict header filter, and one-shot retry.
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use http::{HeaderMap, HeaderName, HeaderValue};
use mkit_core::protocol::{AdmissionRequired, TransportError, TransportResult};

/// Context passed to a responder. All challenge fields are untrusted server data.
pub struct AdmissionContext<'a> {
    /// Canonical remote origin.
    pub origin: &'a str,
    /// Repository identity.
    pub repository: &'a str,
    /// Full Connect procedure path.
    pub procedure: &'a str,
    /// Bounded challenge and response headers.
    pub required: &'a AdmissionRequired,
}

/// A user-installed responder (for example a CLI subprocess).
pub trait AdmissionResponder: Send + Sync {
    /// Return request header names and opaque values.
    ///
    /// # Errors
    /// Returns a configuration error for a bad helper setup, or a failed error
    /// for an unsuccessful helper run.
    fn respond(
        &self,
        ctx: &AdmissionContext<'_>,
    ) -> Result<Vec<(String, String)>, AdmissionResponderError>;
}

/// Failure from a responder, with an exit-code-relevant class.
#[derive(Debug)]
pub enum AdmissionResponderError {
    /// Invalid local helper configuration.
    Configuration(String),
    /// Subprocess or protocol failure.
    Failed(String),
}

impl std::fmt::Display for AdmissionResponderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Configuration(message) | Self::Failed(message) => f.write_str(message),
        }
    }
}
impl std::error::Error for AdmissionResponderError {}

/// Installed responder and optional user-approved header names.
pub struct AdmissionPolicy {
    /// Responder invoked at most once per logical write.
    pub responder: Arc<dyn AdmissionResponder>,
    /// Additional case-insensitive names in the request header allowlist.
    pub extra_allowed: HashSet<String>,
}

impl AdmissionPolicy {
    /// Construct a policy with the default header allowlist.
    #[must_use]
    pub fn new(responder: Arc<dyn AdmissionResponder>) -> Self {
        Self {
            responder,
            extra_allowed: HashSet::new(),
        }
    }

    /// Add a user-approved request header name.
    #[must_use]
    pub fn with_extra_allowed(mut self, name: impl Into<String>) -> Self {
        self.extra_allowed.insert(name.into().to_ascii_lowercase());
        self
    }
}

/// Hard-reserved request headers, independent of the allowlist.
#[must_use]
pub fn is_reserved(name: &str, bearer: bool) -> bool {
    let name = name.to_ascii_lowercase();
    if bearer && name == "authorization" {
        return true;
    }
    if ["x-mkit-", "x-forwarded-", "content-", "connect-", "proxy-"]
        .iter()
        .any(|prefix| name.starts_with(prefix))
    {
        return true;
    }
    [
        "x-public-key",
        "x-signature",
        "x-digest",
        "x-created-at",
        "x-expires-at",
        "x-envelope-version",
        "x-audience",
        "x-repository",
        "x-content-commitment",
        "x-write-grant",
        "x-mkit-ref",
        "host",
        "transfer-encoding",
        "cookie",
        "idempotency-key",
        "connection",
        "keep-alive",
        "te",
        "trailer",
        "upgrade",
    ]
    .contains(&name.as_str())
}

fn token(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn reject(name: &str, reason: &str) -> TransportError {
    let safe_name: String = name
        .chars()
        .take(64)
        .flat_map(char::escape_default)
        .collect();
    TransportError::AdmissionConfiguration(format!(
        "header `{safe_name}` {reason}; review `mkit config remote.<name>.admission_headers`"
    ))
}

/// Validate all helper output before any header reaches the retry.
///
/// # Errors
/// The first invalid header aborts the operation.
pub fn filter_headers(
    headers: Vec<(String, String)>,
    extra_allowed: &HashSet<String>,
    carried: &HeaderMap,
    bearer: bool,
) -> TransportResult<HeaderMap> {
    if headers.is_empty() {
        return Err(reject("<count>", "contains no headers"));
    }
    if headers.len() > 8 {
        return Err(reject("<count>", "exceeds the 8-header limit"));
    }
    let mut out = HeaderMap::new();
    let mut seen = HashSet::new();
    for (name, value) in headers {
        let lower = name.to_ascii_lowercase();
        if !token(&name) {
            return Err(reject(&name, "is not a valid HTTP token"));
        }
        if !seen.insert(lower.clone()) {
            return Err(reject(&name, "is duplicated"));
        }
        if value.len() > 8_192
            || !value
                .bytes()
                .all(|b| b == b'\t' || (0x20..=0x7e).contains(&b))
        {
            return Err(reject(&name, "has an invalid or overlong value"));
        }
        if is_reserved(&name, bearer) {
            return Err(reject(&name, "is reserved"));
        }
        if ![
            "payment-authorization",
            "payment-signature",
            "authorization",
        ]
        .contains(&lower.as_str())
            && !extra_allowed.contains(&lower)
        {
            return Err(reject(&name, "is not on the allowlist"));
        }
        if carried.contains_key(name.as_str())
            || ["accept-encoding"].contains(&lower.as_str())
            || lower.starts_with("grpc-")
        {
            return Err(reject(&name, "is already carried by the request"));
        }
        let header_name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| reject(&name, "is not a valid HTTP token"))?;
        let mut header_value =
            HeaderValue::from_str(&value).map_err(|_| reject(&name, "has an invalid value"))?;
        header_value.set_sensitive(true);
        out.insert(header_name, header_value);
    }
    Ok(out)
}

/// Run the normal retry ladder, then one helper-backed ladder on a challenge.
/// The responder runs in the caller thread, outside every executor `block_on`.
pub(crate) fn retry_once<T>(
    policy: Option<&AdmissionPolicy>,
    runs: &AtomicUsize,
    context: (&str, &str, &'static str),
    carried: &HeaderMap,
    bearer: bool,
    mut attempt: impl FnMut(&HeaderMap) -> TransportResult<T>,
) -> TransportResult<T> {
    let empty = HeaderMap::new();
    let required = match attempt(&empty) {
        Err(TransportError::AdmissionRequired(required)) => required,
        result => return result,
    };
    let Some(policy) = policy else {
        return Err(TransportError::AdmissionRequired(required));
    };
    let headers = respond_to_challenge(policy, runs, context, carried, bearer, *required)?;
    match attempt(&headers) {
        Err(TransportError::AdmissionRequired(required)) => {
            Err(TransportError::AdmissionRequired(Box::new(
                required.with_reason("remote challenged again after the admission helper ran"),
            )))
        }
        result => result,
    }
}

pub(crate) fn respond_to_challenge(
    policy: &AdmissionPolicy,
    runs: &AtomicUsize,
    context: (&str, &str, &'static str),
    carried: &HeaderMap,
    bearer: bool,
    required: AdmissionRequired,
) -> TransportResult<HeaderMap> {
    if runs
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
            (n < 8).then_some(n + 1)
        })
        .is_err()
    {
        return Err(TransportError::AdmissionRequired(Box::new(
            required.with_reason("admission helper run limit reached"),
        )));
    }
    let ctx = AdmissionContext {
        origin: context.0,
        repository: context.1,
        procedure: context.2,
        required: &required,
    };
    let response = policy.responder.respond(&ctx).map_err(|e| match e {
        AdmissionResponderError::Configuration(message) => {
            TransportError::AdmissionConfiguration(message)
        }
        AdmissionResponderError::Failed(message) => TransportError::AdmissionHelperFailed(message),
    })?;
    filter_headers(response, &policy.extra_allowed, carried, bearer)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeResponder {
        output: Vec<(String, String)>,
        fail: bool,
        calls: Arc<AtomicUsize>,
    }
    impl AdmissionResponder for FakeResponder {
        fn respond(
            &self,
            _: &AdmissionContext<'_>,
        ) -> Result<Vec<(String, String)>, AdmissionResponderError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail {
                Err(AdmissionResponderError::Failed("failed".into()))
            } else {
                Ok(self.output.clone())
            }
        }
    }

    fn required() -> TransportError {
        TransportError::AdmissionRequired(Box::new(AdmissionRequired::new(
            Vec::new(),
            String::new(),
            Vec::new(),
            Vec::new(),
        )))
    }

    #[test]
    fn helper_failures_filter_rejections_and_per_transport_cap_do_not_retry() {
        let calls = Arc::new(AtomicUsize::new(0));
        let runs = AtomicUsize::new(0);
        let context = (
            "https://example.invalid",
            "default",
            "/mkit.transport.v1.TransportService/UpdateRef",
        );
        for (output, fail) in [
            (
                vec![("Payment-Authorization".into(), "secret".into())],
                true,
            ),
            (vec![("X-Not-Allowed".into(), "secret".into())], false),
        ] {
            let policy = AdmissionPolicy::new(Arc::new(FakeResponder {
                output,
                fail,
                calls: calls.clone(),
            }));
            let attempts = AtomicUsize::new(0);
            let error: TransportResult<()> = retry_once(
                Some(&policy),
                &runs,
                context,
                &HeaderMap::new(),
                false,
                |_| {
                    attempts.fetch_add(1, Ordering::SeqCst);
                    Err(required())
                },
            );
            assert!(matches!(
                error,
                Err(TransportError::AdmissionHelperFailed(_)
                    | TransportError::AdmissionConfiguration(_))
            ));
            assert_eq!(attempts.load(Ordering::SeqCst), 1);
        }
        runs.store(8, Ordering::SeqCst);
        let policy = AdmissionPolicy::new(Arc::new(FakeResponder {
            output: vec![("Payment-Authorization".into(), "secret".into())],
            fail: false,
            calls: calls.clone(),
        }));
        let before = calls.load(Ordering::SeqCst);
        let error: TransportResult<()> = retry_once(
            Some(&policy),
            &runs,
            context,
            &HeaderMap::new(),
            false,
            |_| Err(required()),
        );
        assert!(error.unwrap_err().to_string().contains("run limit"));
        assert_eq!(calls.load(Ordering::SeqCst), before);
    }

    fn filter(name: &str, value: &str, extra: &[&str], bearer: bool) -> TransportResult<HeaderMap> {
        filter_headers(
            vec![(name.into(), value.into())],
            &extra.iter().map(|s| (*s).into()).collect(),
            &HeaderMap::new(),
            bearer,
        )
    }

    #[test]
    fn reserved_matrix_always_wins_over_allowlist() {
        for name in [
            "x-public-key",
            "x-signature",
            "x-digest",
            "x-created-at",
            "x-expires-at",
            "x-envelope-version",
            "x-audience",
            "x-repository",
            "x-content-commitment",
            "x-write-grant",
            "x-mkit-ref",
            "host",
            "transfer-encoding",
            "cookie",
            "idempotency-key",
            "connection",
            "keep-alive",
            "te",
            "trailer",
            "upgrade",
            "x-mkit-any",
            "x-forwarded-any",
            "content-any",
            "connect-any",
            "proxy-any",
        ] {
            let error = filter(name, "value", &[name], false).unwrap_err();
            assert!(error.to_string().contains("reserved"), "{name}");
        }
        assert!(filter("authorization", "Payment abc", &[], false).is_ok());
        assert!(
            filter("Authorization", "Payment abc", &[], true)
                .unwrap_err()
                .to_string()
                .contains("reserved")
        );
    }

    #[test]
    fn allowlist_grammar_value_and_carried_limits() {
        for name in ["Payment-Authorization", "PAYMENT-SIGNATURE"] {
            assert!(filter(name, "value", &[], false).is_ok());
        }
        assert!(filter("X-Payment", "value", &["x-payment"], false).is_ok());
        assert!(
            filter("X-Other", "value", &[], false)
                .unwrap_err()
                .to_string()
                .contains("allowlist")
        );
        for name in ["bad name", "bad:name", &"x".repeat(65)] {
            assert!(filter(name, "value", &[name], false).is_err());
        }
        assert!(filter("X-Payment", &"v".repeat(8_192), &["x-payment"], false).is_ok());
        for value in [&"v".repeat(8_193), "a\r", "a\n", "a\0", "a\x7f", "é"] {
            assert!(filter("X-Payment", value, &["x-payment"], false).is_err());
        }
        let eight = (0..8)
            .map(|n| (format!("x-test-{n}"), "v".into()))
            .collect();
        let mut extra: HashSet<String> = (0..9).map(|n| format!("x-test-{n}")).collect();
        extra.insert("x-payment".into());
        assert!(filter_headers(eight, &extra, &HeaderMap::new(), false).is_ok());
        let nine = (0..9)
            .map(|n| (format!("x-test-{n}"), "v".into()))
            .collect();
        assert!(filter_headers(nine, &extra, &HeaderMap::new(), false).is_err());
        assert!(
            filter_headers(
                vec![
                    ("X-Payment".into(), "a".into()),
                    ("x-payment".into(), "b".into())
                ],
                &extra,
                &HeaderMap::new(),
                false
            )
            .is_err()
        );
        let mut carried = HeaderMap::new();
        carried.insert("x-payment", "here".parse().unwrap());
        assert!(
            filter_headers(
                vec![("x-payment".into(), "else".into())],
                &extra,
                &carried,
                false
            )
            .unwrap_err()
            .to_string()
            .contains("already carried")
        );
    }
}
