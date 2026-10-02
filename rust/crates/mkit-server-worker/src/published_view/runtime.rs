use super::{MAX_BYTES, SNAPSHOTS_BINDING, SnapshotBucket, SnapshotCache, SnapshotObject};
use futures::StreamExt;
use mkit_server::StoreError;
use mkit_server::indexed::budget::SliceBudget;
use worker::{Cache, Conditional, Env, Response};
fn error(e: impl core::fmt::Display) -> StoreError {
    crate::backend_error(mkit_server::storage_error::StorageOp::MetaCall, e)
}
async fn bounded(mut stream: worker::ByteStream) -> Result<Vec<u8>, StoreError> {
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(error)?;
        if chunk.len() > MAX_BYTES.saturating_sub(bytes.len()) {
            return Err(StoreError::Invalid("snapshot body too large".into()));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
/// R2 implementation with conditional replacement and bounded body reads.
#[derive(Clone, Debug)]
pub struct WorkerSnapshotBucket(pub Env, pub Option<SliceBudget>);
impl SnapshotBucket for WorkerSnapshotBucket {
    async fn get(&self, key: &str) -> Result<Option<SnapshotObject>, StoreError> {
        crate::ns_client::charge_request(self.1.as_ref())?;
        let bucket = self.0.bucket(SNAPSHOTS_BINDING).map_err(error)?;
        let Some(object) = bucket.get(key).execute().await.map_err(error)? else {
            return Ok(None);
        };
        if object.size() > MAX_BYTES as u64 {
            return Err(StoreError::Invalid("snapshot object too large".into()));
        }
        let etag = object.etag();
        let stored_at_ms = object.uploaded().as_millis();
        let body = object
            .body()
            .ok_or_else(|| error("snapshot body missing"))?;
        let bytes = bounded(body.stream().map_err(error)?).await?;
        Ok(Some(SnapshotObject {
            etag,
            stored_at_ms,
            bytes,
        }))
    }
    async fn replace(
        &self,
        key: &str,
        etag: Option<&str>,
        bytes: Vec<u8>,
    ) -> Result<bool, StoreError> {
        if bytes.len() > MAX_BYTES {
            return Err(StoreError::Invalid("snapshot object too large".into()));
        }
        let condition = match etag {
            Some(etag) => Conditional {
                etag_matches: Some(etag.to_owned()),
                ..Default::default()
            },
            None => Conditional {
                etag_does_not_match: Some("*".into()),
                ..Default::default()
            },
        };
        crate::ns_client::charge_request(self.1.as_ref())?;
        Ok(self
            .0
            .bucket(SNAPSHOTS_BINDING)
            .map_err(error)?
            .put(key, bytes)
            .only_if(condition)
            .execute()
            .await
            .map_err(error)?
            .is_some())
    }
    async fn delete(&self, key: &str) -> Result<(), StoreError> {
        crate::ns_client::charge_request(self.1.as_ref())?;
        self.0
            .bucket(SNAPSHOTS_BINDING)
            .map_err(error)?
            .delete(key)
            .await
            .map_err(error)
    }
}
/// Default Cache API, with deployment-scoped internal keys and no public route.
#[derive(Debug)]
pub struct WorkerCache(pub Option<SliceBudget>);
impl SnapshotCache for WorkerCache {
    async fn get(&self, key: &str) -> Result<Option<(u64, Vec<u8>)>, StoreError> {
        crate::ns_client::charge_request(self.0.as_ref())?;
        let Some(mut response) = Cache::default().get(key, false).await.map_err(error)? else {
            return Ok(None);
        };
        let at_ms = response
            .headers()
            .get("x-mkit-snapshot-cache-at")
            .map_err(error)?
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| error("snapshot cache timestamp"))?;
        let bytes = bounded(response.stream().map_err(error)?).await?;
        Ok(Some((at_ms, bytes)))
    }
    async fn put(&self, key: &str, at_ms: u64, bytes: Vec<u8>) -> Result<(), StoreError> {
        if bytes.len() > MAX_BYTES {
            return Err(StoreError::Invalid("snapshot cache body too large".into()));
        }
        let mut response = Response::from_bytes(bytes).map_err(error)?;
        response
            .headers_mut()
            .set("cache-control", "public, max-age=1")
            .map_err(error)?;
        response
            .headers_mut()
            .set("x-mkit-snapshot-cache-at", &at_ms.to_string())
            .map_err(error)?;
        crate::ns_client::charge_request(self.0.as_ref())?;
        Cache::default().put(key, response).await.map_err(error)
    }
}
