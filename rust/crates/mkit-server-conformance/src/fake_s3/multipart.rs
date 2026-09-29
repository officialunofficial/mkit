//! Strict S3 multipart and `ListObjectsV2` simulation.

use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;

use axum::body::{Body, to_bytes};
use axum::http::{HeaderMap, Method, StatusCode};
use bytes::Bytes;
use sha2::{Digest as _, Sha256};

use super::{
    Answer, S3Error, Shared, err, header_str, hex, not_implemented, percent_decode,
    precondition_failed,
};

const MIN_PART_BYTES: usize = 5 * 1024 * 1024;

pub(super) struct Upload {
    bucket: String,
    key: String,
    parts: BTreeMap<u32, (Bytes, String)>,
}

fn invalid_part() -> S3Error {
    err(
        StatusCode::BAD_REQUEST,
        "InvalidPart",
        "one or more parts are invalid",
    )
}

fn copy_part_xml(etag: &str, number: u32) -> String {
    if number % 2 == 1 {
        // MinIO's Go encoding/xml escapes quotation marks as &#34;.
        format!(
            "<CopyPartResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><LastModified>2024-01-01T00:00:00.000Z</LastModified><ETag>{}</ETag></CopyPartResult>",
            etag.replace('"', "&#34;")
        )
    } else {
        format!(
            "<CopyPartResult><ETag>{}</ETag></CopyPartResult>",
            etag.replace('"', "&quot;")
        )
    }
}

fn query_pairs(query: &str) -> Result<HashMap<String, String>, S3Error> {
    let mut result = HashMap::new();
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let decoded = |raw: &str| {
            String::from_utf8(percent_decode(raw)).map_err(|_| {
                err(
                    StatusCode::BAD_REQUEST,
                    "InvalidArgument",
                    "invalid query encoding",
                )
            })
        };
        if result.insert(decoded(key)?, decoded(value)?).is_some() {
            return Err(err(
                StatusCode::BAD_REQUEST,
                "InvalidArgument",
                "duplicate query key",
            ));
        }
    }
    Ok(result)
}

fn tag<'a>(xml: &'a str, name: &str) -> Option<&'a str> {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    Some(xml.split_once(&open)?.1.split_once(&close)?.0)
}

async fn read_signed_body(
    headers: &HeaderMap,
    body: Body,
    received: &mut u64,
) -> Result<Bytes, S3Error> {
    let bytes = to_bytes(body, 1024 * 1024).await.map_err(|_| {
        err(
            StatusCode::BAD_REQUEST,
            "IncompleteBody",
            "body too large or incomplete",
        )
    })?;
    *received = bytes.len() as u64;
    if header_str(headers, "x-amz-content-sha256") != Some(hex(&Sha256::digest(&bytes)).as_str()) {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "XAmzContentSHA256Mismatch",
            "signed body hash mismatch",
        ));
    }
    Ok(bytes)
}

fn max_keys(pairs: &HashMap<String, String>) -> Result<usize, S3Error> {
    pairs.get("max-keys").map_or(Ok(1000), |value| {
        value
            .parse::<usize>()
            .map_err(|_| not_implemented("invalid max-keys"))
    })
}

pub(super) async fn serve_query(
    shared: &Shared,
    parts: &axum::http::request::Parts,
    bucket: &str,
    key: &str,
    query: &str,
    body: Body,
    received: &mut u64,
) -> Result<Answer, S3Error> {
    let pairs = query_pairs(query)?;
    if key.is_empty()
        && parts.method == Method::GET
        && pairs.get("list-type").is_some_and(|v| v == "2")
        && pairs.keys().all(|k| {
            matches!(
                k.as_str(),
                "list-type" | "prefix" | "continuation-token" | "max-keys"
            )
        })
    {
        *received = super::drain(body).await;
        return list(
            shared,
            bucket,
            pairs.get("prefix").map_or("", String::as_str),
            pairs.get("continuation-token").map(String::as_str),
            max_keys(&pairs)?,
        );
    }
    if !key.is_empty()
        && parts.method == Method::POST
        && pairs.len() == 1
        && pairs.contains_key("uploads")
    {
        *received = super::drain(body).await;
        let mut objects = shared.lock();
        let id = format!("fake-mpu-{}", objects.next_request_id);
        objects.uploads.insert(
            id.clone(),
            Upload {
                bucket: bucket.to_owned(),
                key: key.to_owned(),
                parts: BTreeMap::new(),
            },
        );
        let mut answer = Answer::ok(StatusCode::OK);
        answer.body = Bytes::from(format!(
            "<InitiateMultipartUploadResult><UploadId>{id}</UploadId></InitiateMultipartUploadResult>"
        ));
        return Ok(answer);
    }
    if !key.is_empty()
        && parts.method == Method::PUT
        && pairs.len() == 2
        && let (Some(id), Some(number)) = (pairs.get("uploadId"), pairs.get("partNumber"))
    {
        *received = super::drain(body).await;
        let number: u32 = number
            .parse()
            .ok()
            .filter(|n| (1..=10_000).contains(n))
            .ok_or_else(invalid_part)?;
        let source = header_str(&parts.headers, "x-amz-copy-source")
            .ok_or_else(|| not_implemented("UploadPart without copy source"))?;
        let (source_bucket, source_key) = source
            .strip_prefix('/')
            .and_then(|v| v.split_once('/'))
            .ok_or_else(invalid_part)?;
        let mut objects = shared.lock();
        let data = objects
            .buckets
            .get(source_bucket)
            .and_then(|b| b.get(source_key))
            .cloned()
            .ok_or_else(|| err(StatusCode::NOT_FOUND, "NoSuchKey", "copy source missing"))?;
        let etag = format!("\"{}\"", &hex(&Sha256::digest(&data))[..32]);
        if header_str(&parts.headers, "x-amz-copy-source-if-match") != Some(etag.as_str()) {
            return Err(precondition_failed());
        }
        let upload = objects
            .uploads
            .get_mut(id)
            .filter(|u| u.bucket == bucket && u.key == key)
            .ok_or_else(|| err(StatusCode::NOT_FOUND, "NoSuchUpload", "upload missing"))?;
        upload.parts.insert(number, (data, etag.clone()));
        let mut answer = Answer::ok(StatusCode::OK);
        answer.body = Bytes::from(copy_part_xml(&etag, number));
        return Ok(answer);
    }
    if !key.is_empty()
        && pairs.len() == 1
        && let Some(id) = pairs.get("uploadId")
    {
        if parts.method == Method::DELETE {
            *received = super::drain(body).await;
            shared.lock().uploads.remove(id);
            return Ok(Answer::ok(StatusCode::NO_CONTENT));
        }
        if parts.method == Method::POST {
            let bytes = read_signed_body(&parts.headers, body, received).await?;
            return complete(shared, &parts.headers, bucket, key, id, &bytes);
        }
    }
    *received = super::drain(body).await;
    Err(not_implemented("query subresource"))
}

fn complete(
    shared: &Shared,
    headers: &HeaderMap,
    bucket: &str,
    key: &str,
    id: &str,
    body: &[u8],
) -> Result<Answer, S3Error> {
    if header_str(headers, "if-none-match") != Some("*") {
        return Err(not_implemented("completion without If-None-Match: *"));
    }
    let xml = std::str::from_utf8(body).map_err(|_| invalid_part())?;
    let mut listed = Vec::new();
    let mut rest = xml;
    while let Some((_, after)) = rest.split_once("<Part>") {
        let (part, tail) = after.split_once("</Part>").ok_or_else(invalid_part)?;
        let number: u32 = tag(part, "PartNumber")
            .and_then(|v| v.parse().ok())
            .ok_or_else(invalid_part)?;
        let etag = tag(part, "ETag").ok_or_else(invalid_part)?;
        listed.push((number, etag.to_owned()));
        rest = tail;
    }
    let mut objects = shared.lock();
    if let Some((race_bucket, race_key, bytes)) = objects.complete_conflict.take() {
        objects
            .buckets
            .entry(race_bucket)
            .or_default()
            .insert(race_key, bytes);
    }
    let upload = objects
        .uploads
        .get(id)
        .filter(|u| u.bucket == bucket && u.key == key)
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "NoSuchUpload", "upload missing"))?;
    if listed.is_empty() || listed.len() != upload.parts.len() {
        return Err(invalid_part());
    }
    let mut bytes = Vec::new();
    let mut standard = None;
    for (index, (number, etag)) in listed.iter().enumerate() {
        if *number != u32::try_from(index + 1).map_err(|_| invalid_part())? {
            return Err(invalid_part());
        }
        let (part, stored_etag) = upload.parts.get(number).ok_or_else(invalid_part)?;
        if etag != stored_etag {
            return Err(invalid_part());
        }
        if index + 1 != listed.len() {
            if part.len() < MIN_PART_BYTES || standard.is_some_and(|n| n != part.len()) {
                return Err(invalid_part());
            }
            standard = Some(part.len());
        }
        bytes.extend_from_slice(part);
    }
    if objects
        .buckets
        .get(bucket)
        .is_some_and(|b| b.contains_key(key))
    {
        return Err(precondition_failed());
    }
    objects
        .buckets
        .entry(bucket.to_owned())
        .or_default()
        .insert(key.to_owned(), Bytes::from(bytes));
    objects.uploads.remove(id);
    let mut answer = Answer::ok(StatusCode::OK);
    answer.body =
        Bytes::from_static(b"<CompleteMultipartUploadResult></CompleteMultipartUploadResult>");
    Ok(answer)
}

fn list(
    shared: &Shared,
    bucket: &str,
    prefix: &str,
    cursor: Option<&str>,
    max_keys: usize,
) -> Result<Answer, S3Error> {
    if !(1..=1000).contains(&max_keys) {
        return Err(not_implemented("invalid max-keys"));
    }
    let objects = shared.lock();
    let keys: Vec<_> = objects
        .buckets
        .get(bucket)
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "NoSuchBucket", "bucket missing"))?
        .keys()
        .filter(|key| key.starts_with(prefix) && cursor.is_none_or(|c| key.as_str() > c))
        .take(max_keys + 1)
        .cloned()
        .collect();
    let truncated = keys.len() > max_keys;
    let mut xml = format!("<ListBucketResult><IsTruncated>{truncated}</IsTruncated>");
    for key in keys.iter().take(max_keys) {
        let _ = write!(xml, "<Contents><Key>{key}</Key></Contents>");
    }
    if truncated {
        let _ = write!(
            xml,
            "<NextContinuationToken>{}</NextContinuationToken>",
            keys[max_keys - 1]
        );
    }
    xml.push_str("</ListBucketResult>");
    let mut answer = Answer::ok(StatusCode::OK);
    answer.body = Bytes::from(xml);
    Ok(answer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake_s3::{FakeS3Options, Objects};
    use std::sync::Mutex;

    #[test]
    fn minio_copy_response_bytes_escape_quotes_as_go_xml() {
        let body = copy_part_xml("\"d41d8cd98f00b204e9800998ecf8427e\"", 1);
        assert_eq!(body.as_bytes(), b"<CopyPartResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><LastModified>2024-01-01T00:00:00.000Z</LastModified><ETag>&#34;d41d8cd98f00b204e9800998ecf8427e&#34;</ETag></CopyPartResult>");
    }

    fn shared(sizes: &[usize]) -> Shared {
        let mut objects = Objects::default();
        objects.buckets.insert("bucket".into(), BTreeMap::new());
        objects.uploads.insert(
            "upload".into(),
            Upload {
                bucket: "bucket".into(),
                key: "pack".into(),
                parts: sizes
                    .iter()
                    .enumerate()
                    .map(|(i, &size)| {
                        (
                            u32::try_from(i + 1).expect("small test part count"),
                            (Bytes::from(vec![0; size]), format!("etag-{i}")),
                        )
                    })
                    .collect(),
            },
        );
        Shared {
            opts: FakeS3Options::default(),
            objects: Mutex::new(objects),
        }
    }

    fn body(count: usize) -> String {
        let mut xml = String::new();
        for i in 0..count {
            let _ = write!(
                xml,
                "<Part><PartNumber>{}</PartNumber><ETag>etag-{i}</ETag></Part>",
                i + 1
            );
        }
        xml
    }

    fn headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("if-none-match", "*".parse().expect("static header"));
        headers
    }

    #[test]
    fn complete_enforces_minimum_uniform_sizes_etags_and_condition() {
        for sizes in [
            &[MIN_PART_BYTES - 1, 1][..],
            &[MIN_PART_BYTES, MIN_PART_BYTES + 1, 1],
        ] {
            let shared = shared(sizes);
            let error = complete(
                &shared,
                &headers(),
                "bucket",
                "pack",
                "upload",
                body(sizes.len()).as_bytes(),
            )
            .err()
            .expect("invalid parts fail");
            assert_eq!(error.code, "InvalidPart");
        }
        let shared = shared(&[MIN_PART_BYTES, 1]);
        let wrong_etag = body(2).replace("etag-0", "wrong");
        assert_eq!(
            complete(
                &shared,
                &headers(),
                "bucket",
                "pack",
                "upload",
                wrong_etag.as_bytes()
            )
            .err()
            .expect("wrong tag fails")
            .code,
            "InvalidPart"
        );
        assert_eq!(
            complete(
                &shared,
                &HeaderMap::new(),
                "bucket",
                "pack",
                "upload",
                body(2).as_bytes()
            )
            .err()
            .expect("condition required")
            .status,
            StatusCode::NOT_IMPLEMENTED
        );
        assert!(
            complete(
                &shared,
                &headers(),
                "bucket",
                "pack",
                "upload",
                body(2).as_bytes()
            )
            .is_ok()
        );
        let conflict = self::shared(&[MIN_PART_BYTES, 1]);
        conflict
            .lock()
            .buckets
            .get_mut("bucket")
            .expect("bucket")
            .insert("pack".into(), Bytes::from_static(b"old"));
        assert_eq!(
            complete(
                &conflict,
                &headers(),
                "bucket",
                "pack",
                "upload",
                body(2).as_bytes()
            )
            .err()
            .expect("conflict")
            .status,
            StatusCode::PRECONDITION_FAILED
        );
    }
}
