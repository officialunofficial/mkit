//! Root-pinned backend multipart for extracted objects. Unlike ticketed pack
//! staging, completion never reads the part payloads. A pinned CV per slot makes
//! concurrent replacements byte-identical after verification; `ETags` only select
//! backend receipts. All access is server-internal, never client authority.

use bytes::Bytes;
use futures::{StreamExt as _, channel::mpsc};
use mkit_core::hash::{Hash, hash, to_hex_bytes};
use mkit_core::upload_parts::{PartPlan, merge_to_root};
use mkit_server::store::ReadReservation;
use mkit_server::{BlobKey, BlobStore, CommitOutcome, PartSink, StoreError};
use serde::{Deserialize, Serialize};

use super::{ObjectBucket, R2BlobStore, Running, Withheld};

const MAX_META: usize = 2 << 20;
const MAX_ID: usize = 1024;
const MAX_ETAG: usize = 1024;
const MAX_RECEIPT: usize = 65 + MAX_ETAG;

/// Server-internal object receipt; distinct from the capped public pack receipt.
/// Backend `ETags` are opaque and can exceed the pack wire tag limit.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedObjectPartRef {
    /// Zero-based deterministic part slot.
    pub index: u32,
    /// Exact verified part length.
    pub len: u64,
    /// Versioned CV/session binding followed by the bounded opaque backend tag.
    pub tag: Vec<u8>,
}

fn invalid() -> StoreError {
    StoreError::Invalid("invalid verified object session".into())
}
fn failed(detail: String) -> StoreError {
    super::backend_error(mkit_server::storage_error::StorageOp::BlobPut, detail)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Definition {
    object: String,
    root: Hash,
    len: u64,
    part_size: u64,
    cvs: Vec<Hash>,
    operation: Hash,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Session {
    definition: Definition,
    upload: String,
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, StoreError> {
    let mut bytes = vec![1];
    serde_json::to_writer(&mut bytes, value).map_err(|_| invalid())?;
    if bytes.len() > MAX_META {
        return Err(invalid());
    }
    Ok(bytes)
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, StoreError> {
    let Some((&1, rest)) = bytes.split_first() else {
        return Err(invalid());
    };
    serde_json::from_slice(rest).map_err(|_| invalid())
}

impl<B: ObjectBucket> R2BlobStore<B> {
    fn object_session_key(&self, operation: &Hash) -> String {
        let root = self.keyspace.rsplit_once('/').map_or("", |(root, _)| root);
        let prefix = if root.is_empty() {
            String::new()
        } else {
            format!("{root}/")
        };
        format!(
            "{prefix}server-object-uploads/{}/meta",
            to_hex_bytes(operation)
        )
    }

    async fn read_object_metadata(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        let Some((len, mut stream)) = self.bucket.get(key, None).await.map_err(failed)? else {
            return Ok(None);
        };
        if len > MAX_META as u64 {
            return Err(invalid());
        }
        let mut bytes = Vec::with_capacity(usize::try_from(len).map_err(|_| invalid())?);
        while let Some(piece) = stream.next().await {
            let piece = piece.map_err(failed)?;
            if piece.len() > MAX_META - bytes.len() {
                return Err(invalid());
            }
            bytes.extend_from_slice(&piece);
        }
        if bytes.len() as u64 != len {
            return Err(invalid());
        }
        Ok(Some(bytes))
    }

    async fn put_object_metadata(&self, key: String, bytes: Bytes) -> Result<(), StoreError> {
        let mut put = Running::spawn(&self.bucket, key, bytes.len() as u64);
        put.send(bytes).await;
        put.finish().await.map_err(failed)?;
        Ok(())
    }

    /// Immutable canonical root/length binding shared by all R2 object writers.
    /// The canonical verifier supplies the object-id/content-root relationship;
    /// this binding prevents competing storage operations changing that root.
    pub(super) async fn pin_object_root(
        &self,
        object: &str,
        root: Hash,
        len: u64,
    ) -> Result<(), StoreError> {
        let key = format!(
            "server-object-roots/{}",
            to_hex_bytes(&hash(object.as_bytes()))
        );
        let mut expected = vec![1];
        expected.extend_from_slice(&root);
        expected.extend_from_slice(&len.to_be_bytes());
        if let Some(observed) = self.read_object_metadata(&key).await? {
            return if observed == expected {
                Ok(())
            } else {
                Err(invalid())
            };
        }
        let published = self
            .put_object_metadata(key.clone(), Bytes::from(expected.clone()))
            .await;
        if self.read_object_metadata(&key).await?.as_deref() == Some(expected.as_slice()) {
            return Ok(());
        }
        published?;
        Err(invalid())
    }

    /// Start or resume a server-owned root-pinned extraction upload. `cvs` must
    /// be computed from verified repository-local sources in bounded slices.
    /// No caller-supplied CV becomes a receipt until actual bytes verify.
    pub async fn begin_verified_object(
        &self,
        key: BlobKey,
        plan: &PartPlan,
        root: Hash,
        cvs: &[Hash],
        operation: Hash,
    ) -> Result<Vec<u8>, StoreError> {
        ReadReservation::scope(&[], async {
            key.expected_root(Some(root))?;
            if plan.count() > 10_000 {
                return Err(invalid());
            }
            if cvs.len() != plan.count() as usize
                || merge_to_root(plan, cvs).map_err(|_| invalid())? != root
            {
                return Err(invalid());
            }
            let definition = Definition {
                object: self.object_key(&key)?,
                root,
                len: plan.total(),
                part_size: plan.part_size(),
                cvs: cvs.to_vec(),
                operation,
            };
            self.pin_object_root(&definition.object, root, plan.total())
                .await?;
            let meta_key = self.object_session_key(&operation);
            if let Some(bytes) = self.read_object_metadata(&meta_key).await? {
                let old: Session = decode(&bytes)?;
                if old.definition != definition
                    || old.upload.is_empty()
                    || old.upload.len() > MAX_ID
                {
                    return Err(invalid());
                }
                return Ok(operation.to_vec());
            }
            let upload = self
                .bucket
                .create_object_upload(&definition.object)
                .await
                .map_err(failed)?;
            if upload.is_empty() || upload.len() > MAX_ID {
                return Err(invalid());
            }
            let candidate = Session { definition, upload };
            let bytes = encode(&candidate)?;
            // Conditional PUT selects one immutable session; a losing creator
            // aborts only its own private upload, never the winner's session.
            let result = self
                .put_object_metadata(meta_key.clone(), Bytes::from(bytes))
                .await;
            let observed = self.read_object_metadata(&meta_key).await;
            if let Ok(Some(bytes)) = observed {
                let winner: Session = decode(&bytes)?;
                if winner.upload != candidate.upload {
                    let _ = self
                        .bucket
                        .abort_object_upload(&candidate.definition.object, &candidate.upload)
                        .await;
                }
                if winner.definition != candidate.definition {
                    return Err(invalid());
                }
                result?;
                Ok(operation.to_vec())
            } else {
                // An uncertain write may have committed. Leave the upload
                // conservatively; lifecycle abort reclaims orphaned sessions.
                result?;
                Err(StoreError::unavailable(
                    "object session publication unavailable",
                ))
            }
        })
        .await
    }

    async fn checked_object_session(
        &self,
        key: BlobKey,
        token: &[u8],
        plan: &PartPlan,
    ) -> Result<(Session, Hash), StoreError> {
        if plan.count() > 10_000 {
            return Err(invalid());
        }
        let operation: Hash = token.try_into().map_err(|_| invalid())?;
        let bytes = self
            .read_object_metadata(&self.object_session_key(&operation))
            .await?
            .ok_or(StoreError::SessionGone)?;
        let session: Session = decode(&bytes)?;
        let d = &session.definition;
        if d.operation != operation
            || d.object != self.object_key(&key)?
            || d.len != plan.total()
            || d.part_size != plan.part_size()
            || d.cvs.len() != plan.count() as usize
            || session.upload.is_empty()
            || session.upload.len() > MAX_ID
            || merge_to_root(plan, &d.cvs).map_err(|_| invalid())?
                != key.expected_root(Some(d.root))?
        {
            return Err(invalid());
        }
        Ok((session, hash(&bytes)))
    }

    /// Open one fixed-CV private part. Competing same-slot writers are required
    /// to verify identical bytes, even if backend `ETags` are not unique hashes.
    pub async fn begin_verified_object_part(
        &self,
        key: BlobKey,
        token: &[u8],
        plan: &PartPlan,
        index: u32,
        cv: Hash,
    ) -> Result<VerifiedObjectPart<B>, StoreError> {
        ReadReservation::scope(&[], async {
            let (session, binding) = self.checked_object_session(key, token, plan).await?;
            if session.definition.cvs.get(index as usize) != Some(&cv) {
                return Err(invalid());
            }
            let core = Withheld::part(cv, plan, index)?;
            let number = u16::try_from(index + 1).map_err(|_| invalid())?;
            let (tx, rx) = mpsc::channel(0);
            let done = self.bucket.spawn_object_part(
                session.definition.object.clone(),
                session.upload.clone(),
                number,
                core.len,
                rx,
            );
            Ok(VerifiedObjectPart {
                store: self.clone(),
                key,
                token: token.to_vec(),
                plan: *plan,
                binding,
                cv,
                core,
                put: Running {
                    tx: Some(tx),
                    done: Some(done),
                    answer: None,
                },
                failed: false,
            })
        })
        .await
    }

    /// Validate every pinned identity/root before bounded backend publication.
    /// Finalization reads one bounded metadata object, never part payloads.
    pub async fn complete_verified_object(
        &self,
        key: BlobKey,
        token: &[u8],
        plan: &PartPlan,
        parts: &[VerifiedObjectPartRef],
        root: Hash,
    ) -> Result<CommitOutcome, StoreError> {
        ReadReservation::scope(&[], async {
            let (session, binding) = self.checked_object_session(key, token, plan).await?;
            if session.definition.root != root || parts.len() != plan.count() as usize {
                return Err(invalid());
            }
            let mut selected = Vec::with_capacity(parts.len());
            for (index, part) in parts.iter().enumerate() {
                let cv = &session.definition.cvs[index];
                if part.index as usize != index
                    || part.len != plan.expected_len(part.index).map_err(|_| invalid())?
                    || part.tag.len() < 66
                    || part.tag.len() > MAX_RECEIPT
                    || part.tag[0] != 1
                    || &part.tag[1..33] != cv
                    || part.tag[33..65] != binding
                {
                    return Err(invalid());
                }
                let etag = std::str::from_utf8(&part.tag[65..]).map_err(|_| invalid())?;
                if etag.is_empty() || etag.len() > MAX_ETAG {
                    return Err(invalid());
                }
                selected.push((
                    u16::try_from(index + 1).map_err(|_| invalid())?,
                    etag.to_owned(),
                ));
            }
            self.pin_object_root(&session.definition.object, root, plan.total())
                .await?;
            if let Some(meta) = self.head(&key).await? {
                return if meta.len == plan.total() {
                    Ok(CommitOutcome::AlreadyPresent)
                } else {
                    Err(invalid())
                };
            }
            match self
                .bucket
                .complete_object_upload(&session.definition.object, &session.upload, selected)
                .await
            {
                Ok(()) => Ok(CommitOutcome::Created),
                Err(detail) => {
                    // Lost completion reply/duplicate completion is recoverable
                    // only under the immutable root/length binding checked above.
                    if matches!(self.head(&key).await?, Some(meta) if meta.len == plan.total()) {
                        Ok(CommitOutcome::AlreadyPresent)
                    } else {
                        Err(failed(detail))
                    }
                }
            }
        })
        .await
    }

    /// Abort this private session without deleting immutable metadata. A new
    /// attempt needs a new operation identity; stale handles cannot be rebound.
    pub async fn abort_verified_object(
        &self,
        key: BlobKey,
        token: &[u8],
        plan: &PartPlan,
    ) -> Result<(), StoreError> {
        ReadReservation::scope(&[], async {
            let (session, _) = self.checked_object_session(key, token, plan).await?;
            self.bucket
                .abort_object_upload(&session.definition.object, &session.upload)
                .await
                .map_err(failed)
        })
        .await
    }
}

/// One bounded streaming part, whose backend receipt is released only after
/// exact-length/CV verification and revalidation of its immutable session.
#[derive(Debug)]
pub struct VerifiedObjectPart<B: ObjectBucket> {
    store: R2BlobStore<B>,
    key: BlobKey,
    token: Vec<u8>,
    plan: PartPlan,
    binding: Hash,
    cv: Hash,
    core: Withheld,
    put: Running<String>,
    failed: bool,
}

impl<B: ObjectBucket> PartSink for VerifiedObjectPart<B> {
    async fn write(&mut self, chunk: Bytes) -> Result<(), StoreError> {
        ReadReservation::scope(&[], async {
            if self.failed
                || chunk.is_empty()
                || chunk.len() > mkit_server::store::MAX_BLOB_PIECE_BYTES
            {
                self.failed = true;
                return Err(invalid());
            }
            match self.core.push(chunk) {
                Ok(forward) => {
                    self.put.send(forward).await;
                    Ok(())
                }
                Err(error) => {
                    self.failed = true;
                    Err(error)
                }
            }
        })
        .await
    }
    async fn commit(mut self) -> Result<Vec<u8>, StoreError> {
        ReadReservation::scope(&[], async {
            if self.failed {
                self.put.fail().await;
                return Err(invalid());
            }
            let last = match self.core.finish(None) {
                Ok(last) => last,
                Err(error) => {
                    self.put.fail().await;
                    return Err(error);
                }
            };
            let (_, binding) = self
                .store
                .checked_object_session(self.key, &self.token, &self.plan)
                .await?;
            if binding != self.binding {
                self.put.fail().await;
                return Err(invalid());
            }
            if let Some(last) = last {
                self.put.send(last).await;
            }
            let etag = self.put.finish().await.map_err(failed)?;
            if etag.is_empty() || etag.len() > MAX_ETAG {
                return Err(invalid());
            }
            let mut tag = vec![1];
            tag.extend_from_slice(&self.cv);
            tag.extend_from_slice(&self.binding);
            tag.extend_from_slice(etag.as_bytes());
            Ok(tag)
        })
        .await
    }
    async fn abort(self) {
        ReadReservation::scope(&[], async {
            self.put.fail().await;
        })
        .await;
    }
}

#[cfg(test)]
mod bounds_tests {
    use super::*;

    #[test]
    fn maximum_geometry_metadata_and_receipts_have_explicit_bounds() {
        let definition = Definition {
            object: "x".repeat(MAX_ID),
            root: [255; 32],
            len: u64::MAX,
            part_size: u64::MAX,
            cvs: vec![[255; 32]; 10_000],
            operation: [255; 32],
        };
        let session = Session {
            definition,
            upload: "x".repeat(MAX_ID),
        };
        let bytes = encode(&session).unwrap();
        assert!(bytes.len() < MAX_META);
        let decoded: Session = decode(&bytes).unwrap();
        assert_eq!(decoded.definition.cvs.len(), 10_000);
        assert_eq!(MAX_RECEIPT * 10_000, 10_890_000);
        // Full receipt tags plus selected opaque backend strings dominate
        // Rust-side finalization storage; no part payload is retained.
        const { assert!(MAX_RECEIPT * 10_000 + MAX_ETAG * 10_000 + 2 * MAX_META < 26 << 20) };
    }
}
