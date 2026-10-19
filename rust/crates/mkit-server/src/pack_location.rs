//! Default-off, bounded locations for already verified pack downloads.

use std::sync::Arc;

use mkit_core::protocol::PackKey;

use crate::{BoxFuture, MaybeSend, MaybeSync, ServerError};

/// One pack's external location. Providers must enforce its expiry at the
/// origin and every cache, including after a denial or takedown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackLocation {
    /// HTTPS URL that needs no mkit credentials.
    pub url: String,
    /// Expiry in Unix epoch milliseconds.
    pub expires_at_ms: i64,
    /// Exact verified pack length.
    pub total_bytes: u64,
}

/// Deployment adapter for single-pack download URLs. Called only after the
/// normal download's authorization, membership and visibility checks and
/// successful opening of the stored pack. Returning `None` keeps streaming.
///
/// The provider must bind the URL to exactly `key`, enforce `expires_at_ms`
/// at the origin and caches, and never extend that lifetime on cache fills.
/// A deployment must not promise takedown faster than the configured bound.
pub trait PackLocationProvider: core::fmt::Debug + MaybeSend + MaybeSync {
    /// Issue a location, or decline and stream. Provider errors also fall back
    /// to streaming; they must not expose storage credentials in errors.
    fn locate(
        &self,
        key: PackKey,
        total_bytes: u64,
        expires_at_ms: i64,
    ) -> BoxFuture<'_, Result<Option<PackLocation>, ServerError>>;
}

/// A location provider with a deployment-wide maximum lifetime.
#[derive(Debug, Clone)]
pub struct PackLocationConfig {
    provider: Arc<dyn PackLocationProvider>,
    max_lifetime_ms: u64,
    allow_loopback_http: bool,
}

impl PackLocationConfig {
    /// Enable HTTPS locations with a positive lifetime of at most five minutes.
    ///
    /// # Errors
    /// Invalid or unbounded lifetime.
    pub fn new(
        provider: Arc<dyn PackLocationProvider>,
        max_lifetime_ms: u64,
    ) -> Result<Self, ServerError> {
        if !(1..=300_000).contains(&max_lifetime_ms) {
            return Err(ServerError::invalid_argument(
                "pack location lifetime must be in 1..=300000 milliseconds",
            ));
        }
        Ok(Self {
            provider,
            max_lifetime_ms,
            allow_loopback_http: false,
        })
    }

    /// Permit a local HTTP fixture listener. Never available in normal builds.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn with_test_loopback_http(mut self) -> Self {
        self.allow_loopback_http = true;
        self
    }

    /// Maximum validity interval advertised to clients.
    #[must_use]
    pub fn max_lifetime_ms(&self) -> u64 {
        self.max_lifetime_ms
    }

    pub(crate) async fn locate(
        &self,
        key: PackKey,
        total_bytes: u64,
        now_ms: i64,
    ) -> Option<PackLocation> {
        let expiry = now_ms.checked_add(i64::try_from(self.max_lifetime_ms).ok()?)?;
        let location = self
            .provider
            .locate(key, total_bytes, expiry)
            .await
            .ok()??;
        (location.total_bytes == total_bytes
            && location.expires_at_ms > now_ms
            && location.expires_at_ms <= expiry
            && valid_url(&location.url, self.allow_loopback_http))
        .then_some(location)
    }
}

fn valid_url(url: &str, allow_loopback: bool) -> bool {
    if url
        .bytes()
        .any(|b| b.is_ascii_control() || b.is_ascii_whitespace() || b == b'\\')
        || url.contains('#')
    {
        return false;
    }
    let (https, rest) = if let Some(rest) = url.strip_prefix("https://") {
        (true, rest)
    } else if allow_loopback {
        let Some(rest) = url.strip_prefix("http://") else {
            return false;
        };
        (false, rest)
    } else {
        return false;
    };
    let authority = rest.split(['/', '?']).next().unwrap_or_default();
    if authority.len() > 512 {
        return false;
    }
    let scheme = if https { "https" } else { "http" };
    if mkit_core::write_auth::validate_audience(&format!("{scheme}://{authority}")).is_err() {
        return false;
    }
    https
        || authority
            .strip_prefix("127.0.0.1:")
            .or_else(|| authority.strip_prefix("[::1]:"))
            .is_some_and(|port| port.parse::<u16>().is_ok_and(|port| port != 0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_executor::block_on;

    #[derive(Debug)]
    struct Provider(PackLocation);
    impl PackLocationProvider for Provider {
        fn locate(
            &self,
            _: PackKey,
            _: u64,
            _: i64,
        ) -> BoxFuture<'_, Result<Option<PackLocation>, ServerError>> {
            Box::pin(async { Ok(Some(self.0.clone())) })
        }
    }

    #[test]
    fn provider_response_must_obey_length_expiry_and_scheme() {
        let valid = PackLocation {
            url: "https://cdn.example.test/pack".into(),
            expires_at_ms: 1100,
            total_bytes: 23,
        };
        for (url, expires_at_ms, total_bytes, accepted) in [
            (valid.url.as_str(), 1100, 23, true),
            (valid.url.as_str(), 1101, 23, false),
            (valid.url.as_str(), 1000, 23, false),
            (valid.url.as_str(), 1100, 24, false),
            ("http://cdn.example.test/pack", 1100, 23, false),
            ("https://user@cdn.example.test/pack", 1100, 23, false),
            ("https://cdn.example.test:invalid/pack", 1100, 23, false),
            ("https:///pack", 1100, 23, false),
        ] {
            let config = PackLocationConfig::new(
                Arc::new(Provider(PackLocation {
                    url: url.into(),
                    expires_at_ms,
                    total_bytes,
                })),
                100,
            )
            .unwrap();
            assert_eq!(
                block_on(config.locate(PackKey::new([1; 32]), 23, 1000)).is_some(),
                accepted
            );
        }
    }

    #[test]
    fn loopback_exception_is_explicit_and_bounded() {
        assert!(!valid_url("http://127.0.0.1:8080/pack", false));
        assert!(valid_url("http://127.0.0.1:8080/pack", true));
        assert!(valid_url("http://[::1]:8080/pack", true));
        assert!(!valid_url("http://127.0.0.1.example.test:8080/pack", true));
        assert!(!valid_url("http://localhost:8080/pack", true));
        let provider = Arc::new(Provider(PackLocation {
            url: String::new(),
            expires_at_ms: 0,
            total_bytes: 0,
        }));
        assert!(PackLocationConfig::new(provider.clone(), 0).is_err());
        assert!(PackLocationConfig::new(provider, 300_001).is_err());
    }
}
