//! One-way deployment inspection marker, checked before other startup writes.
//!
//! This prerequisite exposes the guard without wiring it into the pipeline.
//! First activation must precede sharding/addressing markers and user writes.

use super::keys;
use crate::{
    Batch, BatchOutcome, Key, NamespaceKey, NamespaceStore, Partition, Precondition, StoreError,
    Value,
};

/// A definitive inspection startup observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Configuration matches, or the marker was installed on an empty store.
    Ok,
    /// A marked deployment cannot turn inspection off.
    Disabled,
    /// Inspection cannot first be enabled after storage has been populated.
    NonEmpty,
    /// The marker or conditional-write response is invalid.
    Corrupt,
}

/// Compare the strict marker codec with the configured mode.
#[must_use]
pub fn compare(value: &Value, enabled: bool) -> Outcome {
    match (value.as_bytes(), enabled) {
        (b"on", true) => Outcome::Ok,
        (b"on", false) => Outcome::Disabled,
        _ => Outcome::Corrupt,
    }
}

/// Check the deployment root, using the sharding guard's bounded empty probe.
/// Mode off never creates a marker; mode on permits zero inspectors.
/// Run before any other startup writes, while startup owns initialization.
///
/// # Errors
/// Backend errors are transient and must not be cached as settled outcomes.
pub async fn check_mode<S: NamespaceStore>(
    store: &S,
    enabled: bool,
) -> Result<Outcome, StoreError> {
    let root = Partition::Namespace(NamespaceKey::deployment_default());
    let marker = keys::inspection_marker();
    if let Some(value) = store.get(&root, &marker).await? {
        return Ok(compare(&value, enabled));
    }
    if !enabled {
        return Ok(Outcome::Ok);
    }
    let page = store
        .scan(
            &root,
            &Key::default(),
            &Key::new(vec![0xff; crate::MAX_KEY_BYTES + 1]),
            None,
            1,
        )
        .await?;
    if let Some((key, value)) = page.entries.first() {
        return Ok(if key == &marker {
            compare(value, enabled)
        } else {
            Outcome::NonEmpty
        });
    }
    let batch = Batch::new()
        .require(Precondition::Absent(marker.clone()))
        .require(Precondition::Absent(keys::layout_version()))
        .put(marker, Value::new(b"on".to_vec()));
    Ok(match store.apply(&root, batch).await? {
        BatchOutcome::Committed => Outcome::Ok,
        BatchOutcome::PreconditionFailed {
            index: 0,
            observed: Some(value),
        } => compare(&value, enabled),
        BatchOutcome::PreconditionFailed {
            index: 1,
            observed: Some(_),
            ..
        } => Outcome::NonEmpty,
        _ => Outcome::Corrupt,
    })
}
