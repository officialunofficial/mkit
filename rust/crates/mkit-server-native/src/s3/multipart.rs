//! CV-keyed S3 parts, assembled with a private `UploadPartCopy` multipart upload.

use std::fmt::Write as _;

use bytes::Bytes;
use futures_util::{StreamExt as _, stream};
use mkit_core::hash::to_hex_bytes;
use mkit_core::upload_parts::{PartPlan, merge_to_root};
use mkit_server::storage_error::StorageOp;
use mkit_server::{BlobKey, BlobStore, CommitOutcome, MultipartBlobStore, PartRef, StoreError};
use mkit_transport_s3::sigv4;
use reqwest::header::{self, HeaderMap, HeaderValue};
use reqwest::{Method, Response, StatusCode};

use super::sink::{self, S3PartSink};
use super::{EMPTY_SHA256, S3BlobStore, absent_or_error, fail, status_error};

const META_MAGIC: &[u8; 5] = b"MKUP1";
const META_LEN: usize = 53;
const COPY_CONCURRENCY: usize = 8;
const RESPONSE_LIMIT: usize = 256 * 1024;
const MAX_LIST_KEYS: usize = 20_000;

fn meta(key: BlobKey, plan: &PartPlan) -> Vec<u8> {
    let mut out = Vec::with_capacity(META_LEN);
    out.extend_from_slice(META_MAGIC);
    out.extend_from_slice(key.hash());
    out.extend_from_slice(&plan.total().to_be_bytes());
    out.extend_from_slice(&plan.part_size().to_be_bytes());
    out
}

fn tag<'a>(xml: &'a str, name: &str) -> Option<&'a str> {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    let after = xml.split_once(&open)?.1;
    Some(after.split_once(&close)?.0)
}

fn tags<'a>(xml: &'a str, name: &str) -> Vec<&'a str> {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    let mut rest = xml;
    let mut result = Vec::new();
    while let Some((_, after)) = rest.split_once(&open) {
        let Some((value, tail)) = after.split_once(&close) else {
            break;
        };
        result.push(value);
        rest = tail;
    }
    result
}

async fn bounded_bytes(resp: Response) -> Result<Vec<u8>, StoreError> {
    let mut body = Vec::new();
    let mut stream = resp.bytes_stream();
    while let Some(piece) = stream.next().await {
        let piece = piece.map_err(|e| fail(StorageOp::BlobRead, e))?;
        if piece.len() > RESPONSE_LIMIT - body.len() {
            return Err(fail(StorageOp::BlobRead, "S3 XML response too large"));
        }
        body.extend_from_slice(&piece);
    }
    Ok(body)
}

async fn bounded_text(resp: Response) -> Result<String, StoreError> {
    String::from_utf8(bounded_bytes(resp).await?).map_err(|e| fail(StorageOp::BlobRead, e))
}

fn xml_ok(xml: &str, what: &str) -> Result<(), StoreError> {
    if xml.contains("<Error>") || xml.contains("<Error ") {
        return Err(fail(
            StorageOp::BlobPut,
            format!("{what}: S3 Error {}", tag(xml, "Code").unwrap_or("Unknown")),
        ));
    }
    Ok(())
}

fn header_value(value: &str) -> Result<HeaderValue, StoreError> {
    HeaderValue::from_str(value)
        .map_err(|_| StoreError::Invalid("invalid S3 request header".into()))
}

impl S3BlobStore {
    fn session_prefix(&self, session: &[u8]) -> Result<String, StoreError> {
        if session.len() != 32 {
            return Err(StoreError::SessionGone);
        }
        let parent = self
            .object_base
            .trim_end_matches('/')
            .rsplit_once('/')
            .map_or("", |(p, _)| p);
        Ok(format!(
            "{parent}/server-uploads/{}/",
            to_hex_bytes(session)
        ))
    }

    fn part_path(prefix: &str, index: u32, cv: &[u8; 32]) -> String {
        format!("{prefix}{index}-{}", to_hex_bytes(cv))
    }

    /// Sign canonical queries and all present x-amz headers, including copy source.
    async fn send_query(
        &self,
        method: Method,
        path: &str,
        pairs: &[(&str, &str)],
        mut headers: HeaderMap,
        body: Option<Bytes>,
    ) -> Result<Response, StoreError> {
        let query = sigv4::canonical_query_string(pairs);
        let payload_hash = body
            .as_ref()
            .map_or_else(|| EMPTY_SHA256.to_owned(), |b| sigv4::sha256_hex(b));
        let now = self.clock.now_ms().div_euclid(1000);
        let date = sigv4::format_date(now);
        let datetime = sigv4::format_iso8601(now);
        let host = sigv4::parse_host(&self.origin);
        headers.insert("x-amz-date", header_value(&datetime)?);
        headers.insert("x-amz-content-sha256", header_value(&payload_hash)?);
        let mut names = vec!["host", "x-amz-content-sha256", "x-amz-date"];
        if headers.contains_key("x-amz-copy-source") {
            names.push("x-amz-copy-source");
        }
        names.sort_unstable();
        let signed = names.join(";");
        let mut canonical_headers = String::new();
        for name in &names {
            let value = if *name == "host" {
                host
            } else {
                headers
                    .get(*name)
                    .and_then(|v| v.to_str().ok())
                    .ok_or_else(|| StoreError::Invalid("invalid signed S3 header".into()))?
            };
            let _ = writeln!(canonical_headers, "{name}:{}", value.trim());
        }
        let canonical = format!(
            "{}\n{path}\n{query}\n{canonical_headers}\n{signed}\n{payload_hash}",
            method.as_str()
        );
        let scope = format!("{date}/{}/s3/aws4_request", self.credentials.region);
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{datetime}\n{scope}\n{}",
            sigv4::sha256_hex(canonical.as_bytes())
        );
        let key = sigv4::derive_signing_key(
            &self.credentials.secret_access_key,
            &date,
            &self.credentials.region,
        );
        let signature = to_hex_bytes(&sigv4::hmac_sha256(&key, string_to_sign.as_bytes()));
        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed}, Signature={signature}",
            self.credentials.access_key_id
        );
        let mut authorization = header_value(&authorization)?;
        authorization.set_sensitive(true);
        headers.insert(header::AUTHORIZATION, authorization);
        let url = if query.is_empty() {
            format!("{}{path}", self.origin)
        } else {
            format!("{}{path}?{query}", self.origin)
        };
        let mut request = self.client.request(method, url).headers(headers);
        if let Some(body) = body {
            request = request.body(body);
        }
        request
            .send()
            .await
            .map_err(|e| fail(StorageOp::BlobPut, e))
    }

    async fn put_meta(&self, path: &str, value: Vec<u8>) -> Result<(), StoreError> {
        let mut headers = HeaderMap::new();
        headers.insert(header::IF_NONE_MATCH, HeaderValue::from_static("*"));
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from(value.len()));
        let resp = self
            .send_query(Method::PUT, path, &[], headers, Some(Bytes::from(value)))
            .await?;
        match resp.status() {
            StatusCode::OK | StatusCode::PRECONDITION_FAILED => Ok(()),
            _ => Err(status_error(StorageOp::BlobPut, "PUT meta", resp).await),
        }
    }

    async fn read_meta(&self, path: &str) -> Result<Option<Vec<u8>>, StoreError> {
        let resp = self
            .send(Method::GET, path, HeaderMap::new())
            .await
            .map_err(|e| fail(StorageOp::BlobRead, e))?;
        match resp.status() {
            StatusCode::OK => {
                let bytes = bounded_bytes(resp).await?;
                if bytes.len() != META_LEN {
                    return Err(StoreError::SessionGone);
                }
                Ok(Some(bytes))
            }
            StatusCode::NOT_FOUND => {
                absent_or_error(StorageOp::BlobRead, "GET meta", resp).await?;
                Ok(None)
            }
            _ => Err(status_error(StorageOp::BlobRead, "GET meta", resp).await),
        }
    }

    pub(super) async fn check_meta(&self, path: &str, expected: &[u8]) -> Result<(), StoreError> {
        if self.read_meta(path).await?.as_deref() == Some(expected) {
            Ok(())
        } else {
            Err(StoreError::SessionGone)
        }
    }

    pub(super) async fn delete_path(&self, path: &str) -> Result<(), StoreError> {
        let resp = self
            .send(Method::DELETE, path, HeaderMap::new())
            .await
            .map_err(|e| fail(StorageOp::BlobPut, e))?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(status_error(StorageOp::BlobPut, "DELETE", resp).await)
        }
    }

    async fn list_prefix(&self, prefix: &str) -> Result<Vec<String>, StoreError> {
        let mut result = Vec::new();
        let mut cursor: Option<String> = None;
        let key_prefix = prefix
            .strip_prefix(&format!("/{}/", self.bucket))
            .ok_or_else(|| StoreError::Invalid("invalid S3 prefix".into()))?;
        loop {
            let mut pairs = vec![("list-type", "2"), ("prefix", key_prefix)];
            if let Some(c) = cursor.as_deref() {
                pairs.push(("continuation-token", c));
            }
            let resp = self
                .send_query(
                    Method::GET,
                    &format!("/{}", self.bucket),
                    &pairs,
                    HeaderMap::new(),
                    None,
                )
                .await?;
            if !resp.status().is_success() {
                return Err(status_error(StorageOp::BlobRead, "LIST", resp).await);
            }
            let xml = bounded_text(resp).await?;
            xml_ok(&xml, "LIST")?;
            result.extend(
                tags(&xml, "Key")
                    .into_iter()
                    .map(|key| format!("/{}/{key}", self.bucket)),
            );
            if result.len() > MAX_LIST_KEYS {
                return Err(fail(
                    StorageOp::BlobRead,
                    "too many multipart staging objects",
                ));
            }
            match tag(&xml, "IsTruncated") {
                Some("false") => return Ok(result),
                Some("true") => {}
                _ => return Err(fail(StorageOp::BlobRead, "LIST missing IsTruncated")),
            }
            let next = tag(&xml, "NextContinuationToken")
                .ok_or_else(|| fail(StorageOp::BlobRead, "LIST missing continuation"))?;
            if cursor.as_deref() == Some(next) {
                return Err(fail(StorageOp::BlobRead, "LIST repeated continuation"));
            }
            cursor = Some(next.to_owned());
        }
    }

    pub(super) async fn delete_siblings(
        &self,
        prefix: &str,
        index: u32,
        current: &str,
    ) -> Result<(), StoreError> {
        for path in self.list_prefix(&format!("{prefix}{index}-")).await? {
            if path != current {
                self.delete_path(&path).await?;
            }
        }
        Ok(())
    }

    async fn create_upload(&self, final_path: &str) -> Result<String, StoreError> {
        let resp = self
            .send_query(
                Method::POST,
                final_path,
                &[("uploads", "")],
                HeaderMap::new(),
                None,
            )
            .await?;
        if !resp.status().is_success() {
            return Err(status_error(StorageOp::BlobPut, "CreateMultipartUpload", resp).await);
        }
        let xml = bounded_text(resp).await?;
        xml_ok(&xml, "CreateMultipartUpload")?;
        tag(&xml, "UploadId")
            .filter(|id| !id.is_empty())
            .map(str::to_owned)
            .ok_or_else(|| fail(StorageOp::BlobPut, "missing UploadId"))
    }

    async fn copy_part(
        &self,
        final_path: &str,
        source: &str,
        upload_id: &str,
        index: u32,
    ) -> Result<(u32, String), StoreError> {
        let mut headers = HeaderMap::new();
        headers.insert("x-amz-copy-source", header_value(source)?);
        let number = (index + 1).to_string();
        let resp = self
            .send_query(
                Method::PUT,
                final_path,
                &[("partNumber", &number), ("uploadId", upload_id)],
                headers,
                None,
            )
            .await?;
        if resp.status() == StatusCode::NOT_FOUND {
            return Err(StoreError::Invalid("part object missing".into()));
        }
        if !resp.status().is_success() {
            return Err(status_error(StorageOp::BlobPut, "UploadPartCopy", resp).await);
        }
        let xml = bounded_text(resp).await?;
        xml_ok(&xml, "UploadPartCopy")?;
        let etag = tag(&xml, "ETag")
            .filter(|v| {
                !v.is_empty()
                    && v.bytes()
                        .all(|b| b.is_ascii_hexdigit() || b == b'"' || b == b'-')
            })
            .ok_or_else(|| fail(StorageOp::BlobPut, "UploadPartCopy missing ETag"))?;
        Ok((index, etag.to_owned()))
    }

    async fn complete_upload(
        &self,
        final_path: &str,
        upload_id: &str,
        etags: &[(u32, String)],
    ) -> Result<CommitOutcome, StoreError> {
        let mut xml = String::from("<CompleteMultipartUpload>");
        for (index, etag) in etags {
            let _ = write!(
                xml,
                "<Part><PartNumber>{}</PartNumber><ETag>{etag}</ETag></Part>",
                index + 1
            );
        }
        xml.push_str("</CompleteMultipartUpload>");
        let mut headers = HeaderMap::new();
        headers.insert(header::IF_NONE_MATCH, HeaderValue::from_static("*"));
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/xml"),
        );
        let resp = self
            .send_query(
                Method::POST,
                final_path,
                &[("uploadId", upload_id)],
                headers,
                Some(Bytes::from(xml)),
            )
            .await?;
        if resp.status() == StatusCode::PRECONDITION_FAILED {
            return Ok(CommitOutcome::AlreadyPresent);
        }
        if !resp.status().is_success() {
            return Err(status_error(StorageOp::BlobPut, "CompleteMultipartUpload", resp).await);
        }
        let body = bounded_text(resp).await?;
        xml_ok(&body, "CompleteMultipartUpload")?;
        if !body.contains("<CompleteMultipartUploadResult")
            || !body.contains("</CompleteMultipartUploadResult>")
        {
            return Err(fail(
                StorageOp::BlobPut,
                "CompleteMultipartUpload missing result",
            ));
        }
        Ok(CommitOutcome::Created)
    }

    async fn abort_upload(&self, final_path: &str, upload_id: &str) -> Result<(), StoreError> {
        let resp = self
            .send_query(
                Method::DELETE,
                final_path,
                &[("uploadId", upload_id)],
                HeaderMap::new(),
                None,
            )
            .await?;
        if resp.status().is_success() || resp.status() == StatusCode::NOT_FOUND {
            Ok(())
        } else {
            Err(status_error(StorageOp::BlobPut, "AbortMultipartUpload", resp).await)
        }
    }
}

impl MultipartBlobStore for S3BlobStore {
    type PartSink = S3PartSink;
    const MAX_PARTS: u32 = 10_000;

    fn supports_multipart(&self) -> bool {
        true
    }

    async fn begin_multipart_for_ticket(
        &self,
        key: BlobKey,
        len: u64,
        part_size: u64,
        ticket_id: [u8; 32],
    ) -> Result<Vec<u8>, StoreError> {
        let plan = PartPlan::new(len, part_size, Self::MAX_PARTS)
            .map_err(|e| StoreError::Invalid(e.to_string().into()))?;
        let meta_path = format!("{}meta", self.session_prefix(&ticket_id)?);
        let expected = meta(key, &plan);
        self.put_meta(&meta_path, expected.clone()).await?;
        self.check_meta(&meta_path, &expected).await?;
        Ok(ticket_id.to_vec())
    }

    async fn begin_part(
        &self,
        key: BlobKey,
        session: &[u8],
        plan: &PartPlan,
        index: u32,
        expected_cv: [u8; 32],
    ) -> Result<Self::PartSink, StoreError> {
        let prefix = self.session_prefix(session)?;
        let meta_path = format!("{prefix}meta");
        let expected_meta = meta(key, plan);
        self.check_meta(&meta_path, &expected_meta).await?;
        let path = Self::part_path(&prefix, index, &expected_cv);
        sink::begin_part(
            self,
            path,
            meta_path,
            expected_meta,
            prefix,
            plan,
            index,
            expected_cv,
        )
        .await
    }

    async fn complete(
        &self,
        key: BlobKey,
        session: &[u8],
        plan: &PartPlan,
        parts: &[PartRef],
    ) -> Result<CommitOutcome, StoreError> {
        if self.head(&key).await?.is_some() {
            return Ok(CommitOutcome::AlreadyPresent);
        }
        let prefix = self.session_prefix(session)?;
        let meta_path = format!("{prefix}meta");
        self.check_meta(&meta_path, &meta(key, plan)).await?;
        if parts.len() != plan.count() as usize {
            return Err(StoreError::Invalid("wrong number of parts".into()));
        }
        let mut cvs = Vec::with_capacity(parts.len());
        for (position, part) in parts.iter().enumerate() {
            let index = u32::try_from(position)
                .map_err(|_| StoreError::Invalid("part index overflow".into()))?;
            if part.index != index
                || part.len
                    != plan
                        .expected_len(index)
                        .map_err(|e| StoreError::Invalid(e.to_string().into()))?
                || part.tag.len() != 32
            {
                return Err(StoreError::Invalid("part geometry or tag mismatch".into()));
            }
            cvs.push(
                <[u8; 32]>::try_from(part.tag.as_slice())
                    .map_err(|_| StoreError::Invalid("invalid part tag".into()))?,
            );
        }
        if merge_to_root(plan, &cvs).map_err(|e| StoreError::Invalid(e.to_string().into()))?
            != *key.hash()
        {
            return Err(StoreError::Invalid("merged part root mismatch".into()));
        }
        let mut sources = Vec::with_capacity(parts.len());
        for (part, cv) in parts.iter().zip(cvs.iter()) {
            let source = Self::part_path(&prefix, part.index, cv);
            match self.head_len(&source).await? {
                Some(len) if len == part.len => sources.push((part.index, source)),
                _ => {
                    return if self.read_meta(&meta_path).await?.is_none() {
                        Err(StoreError::SessionGone)
                    } else {
                        Err(StoreError::Invalid(
                            "part object missing or wrong length".into(),
                        ))
                    };
                }
            }
        }
        let final_path = self.object_path(&key)?;
        let upload_id = self.create_upload(&final_path).await?;
        let result = async {
            let path = final_path.as_str();
            let id = upload_id.as_str();
            let copies = stream::iter(sources.into_iter().map(|(index, source)| async move {
                self.copy_part(path, &source, id, index).await
            }))
            .buffer_unordered(COPY_CONCURRENCY);
            let mut etags: Vec<_> = copies
                .collect::<Vec<_>>()
                .await
                .into_iter()
                .collect::<Result<_, _>>()?;
            etags.sort_by_key(|(index, _)| *index);
            self.complete_upload(&final_path, &upload_id, &etags).await
        }
        .await;
        if (result.is_err() || matches!(result, Ok(CommitOutcome::AlreadyPresent)))
            && let Err(e) = self.abort_upload(&final_path, &upload_id).await
        {
            tracing::warn!(error = %e, "S3 private multipart abort failed");
        }
        let outcome = match result {
            Err(StoreError::Invalid(_)) if self.read_meta(&meta_path).await?.is_none() => {
                return Err(StoreError::SessionGone);
            }
            other => other?,
        };
        self.delete_path(&meta_path).await?;
        for path in self.list_prefix(&prefix).await? {
            if let Err(e) = self.delete_path(&path).await {
                tracing::warn!(error = %e, "S3 part cleanup failed");
            }
        }
        Ok(outcome)
    }

    async fn abort(&self, _key: BlobKey, session: &[u8]) -> Result<(), StoreError> {
        for path in self.list_prefix(&self.session_prefix(session)?).await? {
            self.delete_path(&path).await?;
        }
        Ok(())
    }
}
