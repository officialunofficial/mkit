//! Deployment sharding checks with a cache of settled data, never request futures.

use std::cell::RefCell;

use mkit_server::pipeline::Sharding;
use mkit_server::store::keys;
use mkit_server::{
    Batch, BatchOutcome, Key, NamespaceKey, NamespaceStore, Partition, Precondition, StoreError,
    Value,
};

/// Public mode refusal text.
pub const MISMATCH_MESSAGE: &str = "deployment sharding mismatch";
/// Public corruption refusal text.
pub const CORRUPT_MESSAGE: &str = "deployment sharding marker corrupt";
/// Public addressing refusal text.
pub const ADDRESSING_MISMATCH_MESSAGE: &str = "deployment addressing mismatch";
/// Public addressing corruption refusal text.
pub const ADDRESSING_CORRUPT_MESSAGE: &str = "deployment addressing marker corrupt";
/// Public transient backend failure text.
pub const STORAGE_MESSAGE: &str = "deployment storage unavailable";

/// The addressing modes the `am 00` marker records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressingMode {
    /// `single`.
    Single,
    /// `multi`.
    Multi,
}

impl AddressingMode {
    /// The marker's UTF-8 value.
    fn name(self) -> &'static str {
        match self {
            Self::Single => "single",
            Self::Multi => "multi",
        }
    }
}

/// A definitive observation of the deployment markers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The configured mode matches or was recorded.
    Ok,
    /// The marker (or unmarked single data) names a different mode.
    Mismatch {
        /// Mode in storage.
        stored: Sharding,
        /// Mode requested by this deployment.
        configured: Sharding,
    },
    /// The `am` marker (or unmarked single data) names a different addressing.
    AddressingMismatch {
        /// Addressing in storage.
        stored: AddressingMode,
        /// Addressing requested by this deployment.
        configured: AddressingMode,
    },
    /// The marker or conditional-write reply cannot be decoded.
    Corrupt,
    /// The `am` marker or conditional-write reply cannot be decoded.
    AddressingCorrupt,
}

impl Outcome {
    /// Map a definitive outcome to the adapter's response.
    pub fn into_result(self) -> Result<(), GuardError> {
        match self {
            Self::Ok => Ok(()),
            refusal => Err(GuardError::Refused(refusal)),
        }
    }
}

/// Server-side refusal detail; backend errors are never cached.
#[derive(Debug)]
pub enum GuardError {
    /// A definitive refusal.
    Refused(Outcome),
    /// A request-local, retryable storage failure.
    Storage(StoreError),
}
impl core::fmt::Display for GuardError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Refused(Outcome::Mismatch { stored, configured }) => write!(
                f,
                "{MISMATCH_MESSAGE}: configured={} stored={}",
                mode_name(*configured),
                mode_name(*stored)
            ),
            Self::Refused(Outcome::AddressingMismatch { stored, configured }) => write!(
                f,
                "{ADDRESSING_MISMATCH_MESSAGE}: configured={} stored={}",
                configured.name(),
                stored.name()
            ),
            Self::Refused(Outcome::AddressingCorrupt) => f.write_str(ADDRESSING_CORRUPT_MESSAGE),
            Self::Refused(_) => f.write_str(CORRUPT_MESSAGE),
            Self::Storage(error) => write!(f, "{STORAGE_MESSAGE}: {error}"),
        }
    }
}
impl std::error::Error for GuardError {}
impl GuardError {
    /// Public text used in an unavailable response, without backend detail.
    #[must_use]
    pub fn public_message(&self) -> &'static str {
        match self {
            Self::Refused(Outcome::Mismatch { .. }) => MISMATCH_MESSAGE,
            Self::Refused(Outcome::AddressingMismatch { .. }) => ADDRESSING_MISMATCH_MESSAGE,
            Self::Refused(Outcome::AddressingCorrupt) => ADDRESSING_CORRUPT_MESSAGE,
            Self::Refused(_) => CORRUPT_MESSAGE,
            Self::Storage(_) => STORAGE_MESSAGE,
        }
    }
}

/// Plain cached data, keyed by the config that selected the deployment's objects.
/// This deliberately contains no future, promise, transport or request handle.
#[derive(Debug, Clone)]
pub struct Settled {
    mode: Sharding,
    addressing: bool,
    jurisdiction: Option<String>,
    outcome: Outcome,
}

impl Settled {
    /// Read the cache, dropping observations made for a different config key.
    /// No borrow survives this call or any subsequent store await.
    pub fn cached(
        cache: &RefCell<Option<Self>>,
        mode: Sharding,
        multi: bool,
        jurisdiction: Option<&str>,
    ) -> Option<Outcome> {
        let mut cached = cache.borrow_mut();
        if cached.as_ref().is_some_and(|entry| {
            entry.mode != mode
                || entry.addressing != multi
                || entry.jurisdiction.as_deref() != jurisdiction
        }) {
            *cached = None;
        }
        cached.as_ref().map(|entry| entry.outcome.clone())
    }

    /// Cache the first definitive result for this key. A transient storage error
    /// returns to its request without changing the cache. An older config's
    /// completion cannot replace an already settled result for a newer config.
    pub fn finish(
        cache: &RefCell<Option<Self>>,
        mode: Sharding,
        multi: bool,
        jurisdiction: Option<&str>,
        result: Result<Outcome, StoreError>,
    ) -> Result<(), GuardError> {
        let outcome = match result {
            Ok(outcome) => outcome,
            Err(error) => {
                crate::log_failure(&format!("{STORAGE_MESSAGE}: {error}"));
                return Err(GuardError::Storage(error));
            }
        };
        // Every fresh refusal logs, even if another request settled first.
        match &outcome {
            Outcome::Ok => {}
            Outcome::Mismatch { stored, configured } => crate::log_failure(&format!(
                "{MISMATCH_MESSAGE}: configured={} stored={}",
                mode_name(*configured),
                mode_name(*stored)
            )),
            Outcome::AddressingMismatch { stored, configured } => {
                crate::log_failure(&format!(
                    "{ADDRESSING_MISMATCH_MESSAGE}: configured={} stored={}",
                    configured.name(),
                    stored.name()
                ));
            }
            Outcome::Corrupt => crate::log_failure(CORRUPT_MESSAGE),
            Outcome::AddressingCorrupt => crate::log_failure(ADDRESSING_CORRUPT_MESSAGE),
        }
        let mut cached = cache.borrow_mut();
        if cached.is_none() {
            *cached = Some(Self {
                mode,
                addressing: multi,
                jurisdiction: jurisdiction.map(str::to_owned),
                outcome: outcome.clone(),
            });
        }
        outcome.into_result()
    }
}

fn mode_name(mode: Sharding) -> &'static str {
    match mode {
        Sharding::Single => "single",
        Sharding::D34 => "d34",
        _ => "unsupported",
    }
}

fn compare(observed: &Value, configured: Sharding) -> Outcome {
    let stored = match observed.as_bytes() {
        b"single" => Sharding::Single,
        b"d34" => Sharding::D34,
        _ => return Outcome::Corrupt,
    };
    if stored == configured {
        Outcome::Ok
    } else {
        Outcome::Mismatch { stored, configured }
    }
}

/// Run one request's independent marker check with its own store handle.
/// At most three calls: get, scan, apply. A failed Absent uses its observation.
///
/// # Errors
/// Backend errors are returned separately from definitive marker outcomes.
pub async fn check_mode<S: NamespaceStore>(
    store: &S,
    sharding: Sharding,
) -> Result<Outcome, StoreError> {
    if !matches!(sharding, Sharding::Single | Sharding::D34) {
        return Ok(Outcome::Corrupt);
    }
    let root = Partition::Namespace(NamespaceKey::deployment_default());
    let marker = keys::sharding_marker();
    if let Some(observed) = store.get(&root, &marker).await? {
        return Ok(compare(&observed, sharding));
    }
    // The exclusive upper bound is above every permitted (<= MAX_KEY_BYTES) key.
    let rows = store
        .scan(
            &root,
            &Key::new(Vec::new()),
            &Key::new(vec![0xff; mkit_server::MAX_KEY_BYTES + 1]),
            None,
            1,
        )
        .await?;
    if let Some((key, value)) = rows.entries.first()
        && *key == marker
    {
        return Ok(compare(value, sharding));
    }
    if !rows.entries.is_empty() && sharding == Sharding::D34 {
        return Ok(Outcome::Mismatch {
            stored: Sharding::Single,
            configured: sharding,
        });
    }
    let batch = Batch::new()
        .require(Precondition::Absent(marker.clone()))
        .put(marker, Value::new(mode_name(sharding).as_bytes().to_vec()));
    Ok(match store.apply(&root, batch).await? {
        BatchOutcome::Committed => Outcome::Ok,
        BatchOutcome::PreconditionFailed {
            observed: Some(value),
            ..
        } => compare(&value, sharding),
        BatchOutcome::PreconditionFailed { observed: None, .. }
        | BatchOutcome::DeadlinePassed { .. } => Outcome::Corrupt,
    })
}

fn compare_addressing(observed: &Value, configured: AddressingMode) -> Outcome {
    let stored = match observed.as_bytes() {
        b"single" => AddressingMode::Single,
        b"multi" => AddressingMode::Multi,
        _ => return Outcome::AddressingCorrupt,
    };
    if stored == configured {
        Outcome::Ok
    } else {
        Outcome::AddressingMismatch { stored, configured }
    }
}

/// Run one request's independent addressing-marker check with its own store
/// handle. An absent `am` marker is legacy only when the root holds committed
/// data: the layout-version row every first write installs. The housekeeping
/// rows the object writes before or without one (`sm`, `bk` backup state,
/// `w` timers) say nothing about addressing and are never data. At most
/// three calls: get, get, apply. A failed Absent uses its observation.
///
/// # Errors
/// Backend errors are returned separately from definitive marker outcomes.
pub async fn check_addressing<S: NamespaceStore>(
    store: &S,
    multi: bool,
) -> Result<Outcome, StoreError> {
    let configured = if multi {
        AddressingMode::Multi
    } else {
        AddressingMode::Single
    };
    let root = Partition::Namespace(NamespaceKey::deployment_default());
    let marker = keys::addressing_marker();
    if let Some(observed) = store.get(&root, &marker).await? {
        return Ok(compare_addressing(&observed, configured));
    }
    if multi && store.get(&root, &keys::layout_version()).await?.is_some() {
        return Ok(Outcome::AddressingMismatch {
            stored: AddressingMode::Single,
            configured,
        });
    }
    let batch = Batch::new()
        .require(Precondition::Absent(marker.clone()))
        .put(marker, Value::new(configured.name().as_bytes().to_vec()));
    Ok(match store.apply(&root, batch).await? {
        BatchOutcome::Committed => Outcome::Ok,
        BatchOutcome::PreconditionFailed {
            observed: Some(value),
            ..
        } => compare_addressing(&value, configured),
        BatchOutcome::PreconditionFailed { observed: None, .. }
        | BatchOutcome::DeadlinePassed { .. } => Outcome::AddressingCorrupt,
    })
}

#[cfg(test)]
#[path = "sharding_guard_v050_tests.rs"]
mod stored_v050_tests;
