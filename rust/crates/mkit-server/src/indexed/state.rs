//! Per-(repository, pack) verification state, outside the advance batch.

use crate::repo::RepoName;
use crate::store::{codec::CODEC_V1, keys};
use crate::{
    Batch, BatchOutcome, NamespaceStore, Partition, Precondition, ServerError, StoreError, Value,
};
use mkit_core::hash::Hash;
use serde::{Deserialize, Serialize};

/// Native inline verifier lease: long enough for ordinary packs, bounded so
/// a crashed verifier can be retried. Operators cap concurrent decodes.
pub const VERIFICATION_LEASE_MS: u64 = 30_000;

/// Durable verification result. Only failures determined by pack content
/// alone are `Rejected`; repository membership misses are retried.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum VerificationV1 {
    Pending { lease_until_ms: u64 },
    Verified { pack_len: u64, verified_at_ms: u64 },
    Rejected { code: String, message: String },
}

/// Encode one state with the metadata codec version byte.
///
/// # Panics
/// Serialization of this fixed integer-and-string DTO into a `Vec` cannot
/// fail; a failure here indicates a broken serializer invariant.
#[must_use]
pub fn encode(value: &VerificationV1) -> Value {
    let mut bytes = vec![CODEC_V1];
    serde_json::to_writer(&mut bytes, value).expect("verification DTO serializes");
    Value::new(bytes)
}

/// Decode a state, failing closed on corrupt or future values.
pub fn decode(value: &Value) -> Result<VerificationV1, StoreError> {
    let Some((&CODEC_V1, body)) = value.as_bytes().split_first() else {
        return Err(StoreError::Corrupt("bad verification version".into()));
    };
    serde_json::from_slice(body).map_err(|_| StoreError::Corrupt("bad verification state".into()))
}

/// Three-operation state CAS: `NotAfter`, prior-value guard, and put.
pub async fn write<S: NamespaceStore>(
    store: &S,
    source: &Partition,
    repo: &RepoName,
    pack: &Hash,
    prior: Option<&Value>,
    state: &VerificationV1,
    deadline_ms: u64,
) -> Result<bool, StoreError> {
    let key = keys::verification(repo, pack);
    let guard = match prior {
        Some(value) => Precondition::Equals(key.clone(), value.clone()),
        None => Precondition::Absent(key.clone()),
    };
    let batch = Batch::new()
        .require(Precondition::NotAfter(deadline_ms))
        .require(guard)
        .put(key, encode(state));
    match store.apply(source, batch).await? {
        BatchOutcome::Committed => Ok(true),
        BatchOutcome::PreconditionFailed { .. } => Ok(false),
        BatchOutcome::DeadlinePassed { .. } => Err(StoreError::unavailable(std::io::Error::other(
            "verification deadline passed",
        ))),
    }
}

/// Release only the pending state this invocation wrote. A concurrent
/// verifier's newer state, or a content rejection, survives the CAS loss.
pub async fn clear_pending<S: NamespaceStore>(
    store: &S,
    source: &Partition,
    repo: &RepoName,
    pack: &Hash,
    pending_raw: &Value,
    deadline_ms: u64,
) -> Result<(), StoreError> {
    let key = keys::verification(repo, pack);
    let batch = Batch::new()
        .require(Precondition::NotAfter(deadline_ms))
        .require(Precondition::Equals(key.clone(), pending_raw.clone()))
        .delete(key);
    let _ = store.apply(source, batch).await?;
    Ok(())
}

/// Read the current state and its exact CAS value.
pub async fn read<S: NamespaceStore>(
    store: &S,
    source: &Partition,
    repo: &RepoName,
    pack: &Hash,
) -> Result<Option<(VerificationV1, Value)>, StoreError> {
    store
        .get(source, &keys::verification(repo, pack))
        .await?
        .map(|raw| Ok((decode(&raw)?, raw)))
        .transpose()
}

/// Live lease held by another verifier, with no replay outcome.
#[must_use]
pub fn concurrent_pending(state: &VerificationV1, now_ms: u64) -> Option<ServerError> {
    match state {
        VerificationV1::Pending { lease_until_ms } if *lease_until_ms > now_ms => {
            Some(super::pending(lease_until_ms.saturating_sub(now_ms)))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codec_golden_and_live_lease_boundary() {
        let state = VerificationV1::Verified {
            pack_len: 123,
            verified_at_ms: 456,
        };
        let bytes = encode(&state);
        assert_eq!(
            bytes.as_bytes(),
            b"\x01{\"state\":\"verified\",\"pack_len\":123,\"verified_at_ms\":456}"
        );
        assert_eq!(decode(&bytes).unwrap(), state);
        assert!(decode(&Value::new(b"\x02{}".to_vec())).is_err());
        let pending = VerificationV1::Pending {
            lease_until_ms: 1000,
        };
        assert!(concurrent_pending(&pending, 999).is_some());
        assert!(concurrent_pending(&pending, 1000).is_none());
    }
}
