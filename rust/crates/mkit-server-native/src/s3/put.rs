//! The commit `PUT` of [`S3BlobStore`]: retries, backoff, and the deadlines
//! that keep a stalled upload from holding a request forever.

use std::fs::File;
use std::hash::{BuildHasher as _, Hasher as _};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use mkit_server::storage_error::StorageOp;
use mkit_server::{BlobKey, CommitOutcome, StoreError};
use reqwest::header::{self, HeaderMap, HeaderValue};
use reqwest::{Method, Response, StatusCode};

use super::sink::spool_stream;
use super::{S3BlobStore, describe, fail, s3_error_code};

/// How many times a commit sends its `PUT` before it gives up.
pub const PUT_ATTEMPTS: u32 = 3;

/// The slowest upload a `PUT` deadline allows for: a `PUT` of `len` bytes
/// may take [`PUT_DEADLINE_BASE`] plus `len` at this rate, in total.
pub const PUT_MIN_BYTES_PER_SEC: u64 = 1024 * 1024;

/// The fixed part of a `PUT` deadline.
pub const PUT_DEADLINE_BASE: Duration = Duration::from_mins(1);

/// The longest a `Retry-After` is honored for.
const MAX_RETRY_AFTER: Duration = Duration::from_secs(10);

/// When the last byte of a `PUT` body was handed to the connection.
#[derive(Debug)]
pub(super) struct Progress(Mutex<Instant>);

impl Progress {
    fn new() -> Self {
        Self(Mutex::new(Instant::now()))
    }

    pub(super) fn touch(&self) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = Instant::now();
    }

    fn idle(&self) -> Duration {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .elapsed()
    }
}

/// Resolve once `progress` has been idle for `limit`: the bucket stopped
/// reading the body, or answering after it.
async fn stalled(progress: &Progress, limit: Duration) {
    loop {
        let idle = progress.idle();
        if idle >= limit {
            return;
        }
        tokio::time::sleep(limit.saturating_sub(idle).max(Duration::from_millis(10))).await;
    }
}

/// The whole-`PUT` deadline for `len` bytes.
fn put_deadline(len: u64) -> Duration {
    PUT_DEADLINE_BASE + Duration::from_secs(len / PUT_MIN_BYTES_PER_SEC)
}

/// A random `u64` for jitter (no RNG dependency: `RandomState` keys are
/// random per process and advance per instance).
fn jitter_seed() -> u64 {
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u128(Instant::now().elapsed().as_nanos());
    h.finish()
}

/// The pause before retry `attempt` (1-based): exponential from 100 ms
/// with equal jitter, and at least the bucket's `Retry-After` (capped).
fn backoff(attempt: u32, retry_after: Option<Duration>) -> Duration {
    let base_ms = 100_u64 << (2 * (attempt.saturating_sub(1)).min(8));
    let half = base_ms / 2;
    let jittered = Duration::from_millis(half + jitter_seed() % (half + 1));
    jittered.max(retry_after.map_or(Duration::ZERO, |d| d.min(MAX_RETRY_AFTER)))
}

/// A `Retry-After` of whole seconds on a `429` or `503`.
fn retry_after(resp: &Response) -> Option<Duration> {
    if !matches!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE
    ) {
        return None;
    }
    let secs = resp
        .headers()
        .get(header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim()
        .parse()
        .ok()?;
    Some(Duration::from_secs(secs))
}

/// How one `PUT` attempt ended.
enum Attempt {
    Done(CommitOutcome),
    Fatal(StoreError),
    Retry {
        detail: String,
        after: Option<Duration>,
    },
}

/// A `PUT` answer worth retrying: a concurrent-delete conflict, throttling,
/// a server fault, or S3's `400 RequestTimeout` (the body arrived too
/// slowly).
fn retryable(status: StatusCode, code: Option<&str>) -> bool {
    status == StatusCode::CONFLICT
        || status == StatusCode::TOO_MANY_REQUESTS
        || status.is_server_error()
        || (status == StatusCode::BAD_REQUEST && code == Some("RequestTimeout"))
}

impl S3BlobStore {
    /// `PUT` the verified spool under `key`, if absent (see the module
    /// docs): up to [`PUT_ATTEMPTS`] attempts, each bounded by a stall
    /// timeout and a whole-`PUT` deadline.
    pub(super) async fn put_verified(
        &self,
        key: &BlobKey,
        spool: Arc<File>,
        len: u64,
        sha256: &str,
    ) -> Result<CommitOutcome, StoreError> {
        let path = self.object_path(key);
        let mut last = String::new();
        for attempt in 0..PUT_ATTEMPTS {
            match self.put_once(&path, &spool, len, sha256).await {
                Attempt::Done(outcome) => return Ok(outcome),
                Attempt::Fatal(e) => return Err(e),
                Attempt::Retry { detail, after } => {
                    last = detail;
                    if attempt + 1 < PUT_ATTEMPTS {
                        tokio::time::sleep(backoff(attempt + 1, after)).await;
                    }
                }
            }
        }
        // A key only ever holds verified bytes: if it is present now (a
        // racing writer, or our own PUT whose answer was lost), ours are.
        if matches!(self.head_len(&path).await, Ok(Some(n)) if n == len) {
            return Ok(CommitOutcome::AlreadyPresent);
        }
        Err(fail(StorageOp::BlobPut, last))
    }

    async fn put_once(&self, path: &str, spool: &Arc<File>, len: u64, sha256: &str) -> Attempt {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from(len));
        headers.insert(header::IF_NONE_MATCH, HeaderValue::from_static("*"));
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );
        let progress = Arc::new(Progress::new());
        let body =
            reqwest::Body::wrap_stream(spool_stream(Arc::clone(spool), len, Arc::clone(&progress)));
        // The PUT client has no read timeout (reqwest's runs from the
        // request's start, so it would cut off any upload longer than it):
        // the stall timeout and the deadline bound the attempt instead.
        let send = self.send_with(
            &self.put_client,
            Method::PUT,
            path,
            sha256,
            headers,
            Some(body),
        );
        let resp = tokio::select! {
            resp = send => resp,
            () = stalled(&progress, self.stall_timeout) => {
                return Attempt::Retry {
                    detail: format!("PUT: no progress for {:?}", self.stall_timeout),
                    after: None,
                };
            }
            () = tokio::time::sleep(put_deadline(len)) => {
                return Attempt::Retry {
                    detail: format!("PUT: exceeded its {:?} deadline", put_deadline(len)),
                    after: None,
                };
            }
        };
        let resp = match resp {
            Ok(resp) => resp,
            Err(e) => {
                return Attempt::Retry {
                    detail: format!("PUT: {e}"),
                    after: None,
                };
            }
        };
        let status = resp.status();
        match status {
            StatusCode::OK => return Attempt::Done(CommitOutcome::Created),
            StatusCode::PRECONDITION_FAILED => {
                return Attempt::Done(CommitOutcome::AlreadyPresent);
            }
            _ => {}
        }
        let after = retry_after(&resp);
        let line = describe(&resp, "PUT", status).0;
        let code = s3_error_code(resp).await;
        let detail = match &code {
            Some(code) => format!("{line} {code}"),
            None => line,
        };
        if retryable(status, code.as_deref()) {
            Attempt::Retry { detail, after }
        } else {
            Attempt::Fatal(fail(StorageOp::BlobPut, detail))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_is_jittered_exponential_and_honors_retry_after() {
        for attempt in 1..=3 {
            let base = 100_u64 << (2 * (attempt - 1));
            for _ in 0..50 {
                let d = backoff(attempt, None).as_millis();
                assert!(
                    (u128::from(base / 2)..=u128::from(base)).contains(&d),
                    "{d}"
                );
            }
        }
        let d = backoff(1, Some(Duration::from_secs(2)));
        assert!(d >= Duration::from_secs(2));
        let capped = backoff(1, Some(Duration::from_hours(1)));
        assert!(capped <= MAX_RETRY_AFTER, "{capped:?}");
    }

    #[test]
    fn request_timeout_and_server_faults_retry() {
        assert!(retryable(StatusCode::BAD_REQUEST, Some("RequestTimeout")));
        assert!(!retryable(StatusCode::BAD_REQUEST, Some("InvalidArgument")));
        assert!(!retryable(StatusCode::FORBIDDEN, Some("AccessDenied")));
        for s in [409, 429, 500, 503] {
            assert!(retryable(StatusCode::from_u16(s).unwrap(), None));
        }
        assert_eq!(
            put_deadline(4 << 30),
            PUT_DEADLINE_BASE + Duration::from_secs(4096)
        );
    }
}
