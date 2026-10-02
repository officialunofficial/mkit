//! Request-local inspection checks and cached settled data, without futures.

use mkit_server::StoreError;
use mkit_server::pipeline::Sharding;
pub use mkit_server::store::inspection_mode::{Outcome, check_mode};
use std::cell::RefCell;

/// Public one-way mode refusal text.
pub const MISMATCH_MESSAGE: &str = "deployment inspection mismatch";
/// Public malformed marker refusal text.
pub const CORRUPT_MESSAGE: &str = "deployment inspection marker corrupt";
/// Public transient backend failure text.
pub const STORAGE_MESSAGE: &str = "deployment storage unavailable";

/// Definitive refusal or request-local backend failure.
#[derive(Debug)]
pub enum GuardError {
    /// A definitive marker refusal.
    Refused(Outcome),
    /// Transient storage errors are never cached.
    Storage(StoreError),
}
impl core::fmt::Display for GuardError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Storage(error) => write!(f, "{STORAGE_MESSAGE}: {error}"),
            Self::Refused(Outcome::Disabled) => {
                write!(f, "{MISMATCH_MESSAGE}: inspection cannot be disabled")
            }
            Self::Refused(Outcome::NonEmpty) => write!(
                f,
                "{MISMATCH_MESSAGE}: cannot enable inspection on a nonempty store"
            ),
            Self::Refused(_) => f.write_str(CORRUPT_MESSAGE),
        }
    }
}
impl std::error::Error for GuardError {}
impl GuardError {
    /// Client-safe text without backend detail.
    #[must_use]
    pub fn public_message(&self) -> &'static str {
        match self {
            Self::Storage(_) => STORAGE_MESSAGE,
            Self::Refused(Outcome::Disabled | Outcome::NonEmpty) => MISMATCH_MESSAGE,
            Self::Refused(_) => CORRUPT_MESSAGE,
        }
    }
}

/// Map a cached or freshly observed outcome to the adapter's response.
///
/// # Errors
/// Returns the definitive marker refusal.
pub fn into_result(outcome: Outcome) -> Result<(), GuardError> {
    if outcome == Outcome::Ok {
        Ok(())
    } else {
        Err(GuardError::Refused(outcome))
    }
}

/// Cached data keyed by inspection mode and deployment object selection.
#[derive(Debug, Clone)]
pub struct Settled {
    enabled: bool,
    sharding: Sharding,
    multi: bool,
    jurisdiction: Option<String>,
    outcome: Outcome,
}
impl Settled {
    /// Read a settled result, invalidating observations of another config.
    pub fn cached(
        cache: &RefCell<Option<Self>>,
        enabled: bool,
        sharding: Sharding,
        multi: bool,
        jurisdiction: Option<&str>,
    ) -> Option<Outcome> {
        let mut cached = cache.borrow_mut();
        if cached.as_ref().is_some_and(|entry| {
            entry.enabled != enabled
                || entry.sharding != sharding
                || entry.multi != multi
                || entry.jurisdiction.as_deref() != jurisdiction
        }) {
            *cached = None;
        }
        cached.as_ref().map(|entry| entry.outcome)
    }
    /// Cache the first definitive result for this key; log transient errors
    /// without caching them. An older completion cannot overwrite newer data.
    ///
    /// # Errors
    /// Returns a marker refusal or the request's transient backend failure.
    pub fn finish(
        cache: &RefCell<Option<Self>>,
        enabled: bool,
        sharding: Sharding,
        multi: bool,
        jurisdiction: Option<&str>,
        result: Result<Outcome, StoreError>,
    ) -> Result<(), GuardError> {
        let outcome = result.map_err(|error| {
            crate::log_failure(&format!("{STORAGE_MESSAGE}: {error}"));
            GuardError::Storage(error)
        })?;
        if outcome != Outcome::Ok {
            crate::log_failure(&GuardError::Refused(outcome).to_string());
        }
        let mut cached = cache.borrow_mut();
        if cached.is_none() {
            *cached = Some(Self {
                enabled,
                sharding,
                multi,
                jurisdiction: jurisdiction.map(str::to_owned),
                outcome,
            });
        }
        into_result(outcome)
    }
}
