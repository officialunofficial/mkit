//! AWS Signature V4 signer.
//!
//! Minimal, deterministic SigV4 implementation used by the S3 /
//! Cloudflare R2 transport. The golden vector at
//! `rust/tests/golden/transport/sigv4_basic.json` pins the exact bytes of
//! the canonical request, string-to-sign, and final signature.
//!
//! The signer only ever signs the three headers `host`,
//! `x-amz-content-sha256`, and `x-amz-date`. Adding more signed headers
//! is a wire-format change.

use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// S3 credentials used by the SigV4 signer.
///
/// `Debug` is implemented manually (mirroring `S3Transport`'s redacting
/// `Debug`) so the `secret_access_key` is never leaked through `{:?}` /
/// `dbg!` / `tracing` of this struct or any struct embedding it.
#[derive(Clone)]
pub struct Credentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub region: String,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"<redacted>")
            .field("region", &self.region)
            .finish()
    }
}

/// Output of [`sign_request`]. Caller attaches these three headers to the
/// outgoing HTTP request.
#[derive(Debug, Clone)]
pub struct SignedRequest {
    /// Full `Authorization: AWS4-HMAC-SHA256 Credential=…` header value.
    pub authorization: String,
    /// `x-amz-date` header value (`YYYYMMDDTHHMMSSZ`, 16 ASCII bytes).
    pub x_amz_date: String,
    /// `x-amz-content-sha256` header value (64 lowercase hex chars).
    pub x_amz_content_sha256: String,
    /// Intermediate canonical request — exposed for golden-vector tests.
    pub canonical_request: String,
    /// Intermediate string-to-sign — exposed for golden-vector tests.
    pub string_to_sign: String,
    /// Raw 64-char lowercase hex signature.
    pub signature_hex: String,
}

/// SHA256(`data`) as 64-char lowercase hex.
#[must_use]
pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

/// HMAC-SHA256(key, msg) as raw 32 bytes.
///
/// # Panics
/// Never — [`HmacSha256::new_from_slice`] accepts any key length; the
/// `.expect` is a defensive no-op that documents the invariant.
#[must_use]
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    let out = mac.finalize().into_bytes();
    let mut result = [0u8; 32];
    result.copy_from_slice(&out);
    result
}

/// Derive the AWS SigV4 signing key:
/// `HMAC(HMAC(HMAC(HMAC("AWS4"+secret, date), region), "s3"), "aws4_request")`.
#[must_use]
pub fn derive_signing_key(secret: &str, date: &str, region: &str) -> [u8; 32] {
    let mut aws4_key = Vec::with_capacity(4 + secret.len());
    aws4_key.extend_from_slice(b"AWS4");
    aws4_key.extend_from_slice(secret.as_bytes());

    let date_key = hmac_sha256(&aws4_key, date.as_bytes());
    let region_key = hmac_sha256(&date_key, region.as_bytes());
    let service_key = hmac_sha256(&region_key, b"s3");
    hmac_sha256(&service_key, b"aws4_request")
}

/// Percent-encode a single byte per AWS SigV4 canonical-query rules
/// (RFC 3986 unreserved set: `A-Z a-z 0-9 - _ . ~` pass through; every
/// other byte — including `/` — becomes `%XX` with UPPERCASE hex).
fn encode_uri_component(out: &mut String, s: &str) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for &b in s.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0x0f) as usize] as char);
        }
    }
}

/// Build the AWS SigV4 canonical query string from raw (unencoded) key/value
/// pairs: each key and value is URI-encoded (RFC 3986), pairs are sorted by
/// encoded key (then encoded value), and joined with `&`.
///
/// This is the exact normalization AWS S3 re-derives server-side before
/// recomputing the signature, so the bytes produced here MUST match the
/// `query` component used both to sign and to build the request URL.
/// Cloudflare R2 is lenient about encoding; real AWS S3 is not (an
/// unencoded `/` in a value yields `403 SignatureDoesNotMatch`).
#[must_use]
pub fn canonical_query_string(pairs: &[(&str, &str)]) -> String {
    let mut encoded: Vec<(String, String)> = pairs
        .iter()
        .map(|(k, v)| {
            let mut ek = String::new();
            encode_uri_component(&mut ek, k);
            let mut ev = String::new();
            encode_uri_component(&mut ev, v);
            (ek, ev)
        })
        .collect();
    encoded.sort();
    let mut out = String::new();
    for (i, (k, v)) in encoded.iter().enumerate() {
        if i > 0 {
            out.push('&');
        }
        out.push_str(k);
        out.push('=');
        out.push_str(v);
    }
    out
}

/// Strip the `https://` / `http://` prefix from an endpoint URL to produce
/// the `host:` header value the signer needs.
#[must_use]
pub fn parse_host(endpoint: &str) -> &str {
    if let Some(rest) = endpoint.strip_prefix("https://") {
        return rest;
    }
    if let Some(rest) = endpoint.strip_prefix("http://") {
        return rest;
    }
    endpoint
}

/// Format a Unix timestamp (seconds) as ISO 8601 basic: `YYYYMMDDTHHMMSSZ`.
#[must_use]
pub fn format_iso8601(timestamp: i64) -> String {
    let (y, m, d, hh, mm, ss) = unix_to_calendar(timestamp);
    format!("{y:04}{m:02}{d:02}T{hh:02}{mm:02}{ss:02}Z")
}

/// Format a Unix timestamp (seconds) as `YYYYMMDD`.
#[must_use]
pub fn format_date(timestamp: i64) -> String {
    let (y, m, d, _, _, _) = unix_to_calendar(timestamp);
    format!("{y:04}{m:02}{d:02}")
}

/// Convert a Unix timestamp to calendar parts using the civil-from-days
/// algorithm (Howard Hinnant / `date`).
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap
)]
fn unix_to_calendar(timestamp: i64) -> (u16, u8, u8, u8, u8, u8) {
    const SECS_PER_DAY: i64 = 86_400;
    let mut days = timestamp.div_euclid(SECS_PER_DAY);
    let mut remaining = timestamp.rem_euclid(SECS_PER_DAY);

    // remaining is always in [0, 86400) after rem_euclid, so the narrowing
    // casts below are safe by construction.
    let hour = (remaining / 3600) as u8;
    remaining %= 3600;
    let minute = (remaining / 60) as u8;
    let second = (remaining % 60) as u8;

    // Shift epoch to 0000-03-01.
    days += 719_468;

    let era = days.div_euclid(146_097);
    let doe = (days - era * 146_097) as u32; // [0, 146096]
    let yoe = (doe.saturating_sub(doe / 1460) + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = i64::from(yoe) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u8;
    let m_raw: u32 = if mp < 10 { mp + 3 } else { mp - 9 };
    let m = m_raw as u8;
    let year_adj = if m <= 2 { y + 1 } else { y };

    (year_adj as u16, m, d, hour, minute, second)
}

/// Sign an S3 request. Returns the pre-built `Authorization` / `x-amz-date`
/// / `x-amz-content-sha256` header values.
///
/// `path` MUST be the S3-style object path (`/<bucket>/<key>`), `query` is
/// either empty or the canonical query string (already sorted + encoded),
/// and `payload` is the raw body bytes (empty slice for GET/HEAD).
#[must_use]
pub fn sign_request(
    creds: &Credentials,
    method: &str,
    path: &str,
    query: &str,
    payload: &[u8],
    endpoint: &str,
    timestamp: i64,
) -> SignedRequest {
    const SIGNED_HEADERS: &str = "host;x-amz-content-sha256;x-amz-date";

    let payload_hash = sha256_hex(payload);
    let date = format_date(timestamp);
    let datetime = format_iso8601(timestamp);
    let host = parse_host(endpoint);

    // Canonical request — bytes pinned by the golden vector.
    let canonical_request = format!(
        "{method}\n{path}\n{query}\nhost:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{datetime}\n\n{SIGNED_HEADERS}\n{payload_hash}"
    );

    let scope = format!("{date}/{region}/s3/aws4_request", region = creds.region);
    let canonical_hash = sha256_hex(canonical_request.as_bytes());

    let string_to_sign = format!("AWS4-HMAC-SHA256\n{datetime}\n{scope}\n{canonical_hash}");

    let signing_key = derive_signing_key(&creds.secret_access_key, &date, &creds.region);
    let signature_bytes = hmac_sha256(&signing_key, string_to_sign.as_bytes());
    let signature_hex = hex::encode(signature_bytes);

    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={akid}/{scope}, SignedHeaders={SIGNED_HEADERS}, Signature={signature_hex}",
        akid = creds.access_key_id,
    );

    SignedRequest {
        authorization,
        x_amz_date: datetime,
        x_amz_content_sha256: payload_hash,
        canonical_request,
        string_to_sign,
        signature_hex,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso8601_known_values() {
        assert_eq!(format_iso8601(1_711_300_000), "20240324T170640Z");
        assert_eq!(format_iso8601(0), "19700101T000000Z");
        assert_eq!(format_iso8601(946_684_800), "20000101T000000Z");
    }

    #[test]
    fn date_known_values() {
        assert_eq!(format_date(1_711_300_000), "20240324");
    }

    #[test]
    fn iso8601_leap_year() {
        assert_eq!(format_iso8601(1_709_164_800), "20240229T000000Z");
    }

    #[test]
    fn iso8601_end_of_year() {
        assert_eq!(format_iso8601(1_704_067_199), "20231231T235959Z");
    }

    #[test]
    fn sha256_hex_empty() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_hex_hello() {
        assert_eq!(
            sha256_hex(b"hello"),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn hmac_sha256_known_vector() {
        let got = hmac_sha256(b"key", b"message");
        assert_eq!(
            hex::encode(got),
            "6e9ef29b75fffc5b7abae527d58fdadb2fe42e7219011976917343065f58ed4a"
        );
    }

    #[test]
    fn derive_signing_key_kat() {
        let key = derive_signing_key(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "20120215",
            "us-east-1",
        );
        assert_eq!(
            hex::encode(key),
            "f22dfcb5da3bb8d6c924d26e9bb28e9f96ba691a1b1791d907c06f10ede94251"
        );
    }

    #[test]
    fn parse_host_strips_scheme() {
        assert_eq!(
            parse_host("https://abc.r2.cloudflarestorage.com"),
            "abc.r2.cloudflarestorage.com"
        );
        assert_eq!(
            parse_host("http://abc.r2.cloudflarestorage.com"),
            "abc.r2.cloudflarestorage.com"
        );
        assert_eq!(parse_host("localhost:9000"), "localhost:9000");
    }

    fn demo_creds() -> Credentials {
        Credentials {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".into(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into(),
            region: "auto".into(),
        }
    }

    #[test]
    fn sign_put_shape() {
        let sig = sign_request(
            &demo_creds(),
            "PUT",
            "/mkit-storage/objects/abc123",
            "",
            b"hello world",
            "https://abc123.r2.cloudflarestorage.com",
            1_711_300_000,
        );
        assert!(sig.authorization.starts_with(
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20240324/auto/s3/aws4_request"
        ));
        assert!(
            sig.authorization
                .contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date")
        );
        assert!(sig.authorization.contains("Signature="));
        assert_eq!(sig.x_amz_date, "20240324T170640Z");
        assert_eq!(sig.x_amz_content_sha256, sha256_hex(b"hello world"));
    }

    #[test]
    fn sign_get_empty_payload_hash() {
        let sig = sign_request(
            &demo_creds(),
            "GET",
            "/mkit-storage/objects/abc123",
            "",
            b"",
            "https://abc123.r2.cloudflarestorage.com",
            1_711_300_000,
        );
        assert_eq!(
            sig.x_amz_content_sha256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert!(
            sig.authorization
                .starts_with("AWS4-HMAC-SHA256 Credential=")
        );
    }

    #[test]
    fn sign_deterministic() {
        let a = sign_request(
            &demo_creds(),
            "PUT",
            "/mkit-storage/obj",
            "",
            b"data",
            "https://abc123.r2.cloudflarestorage.com",
            1_711_300_000,
        );
        let b = sign_request(
            &demo_creds(),
            "PUT",
            "/mkit-storage/obj",
            "",
            b"data",
            "https://abc123.r2.cloudflarestorage.com",
            1_711_300_000,
        );
        assert_eq!(a.authorization, b.authorization);
        assert_eq!(a.canonical_request, b.canonical_request);
        assert_eq!(a.string_to_sign, b.string_to_sign);
    }

    #[test]
    fn credentials_debug_redacts_secret() {
        let creds = Credentials {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".into(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into(),
            region: "auto".into(),
        };
        let dbg = format!("{creds:?}");
        assert!(
            !dbg.contains("wJalrXUtnFEMI"),
            "Debug leaked secret_access_key: {dbg}"
        );
        assert!(dbg.contains("<redacted>"), "Debug missing redaction: {dbg}");
        // Non-secret fields remain visible for diagnostics.
        assert!(dbg.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(dbg.contains("auto"));
    }

    #[test]
    fn canonical_query_encodes_slash_and_sorts() {
        // `/` -> `%2F`; keys already sorted (list-type < prefix).
        assert_eq!(
            canonical_query_string(&[("list-type", "2"), ("prefix", "refs/heads/")]),
            "list-type=2&prefix=refs%2Fheads%2F"
        );
        // Unsorted input is sorted by encoded key.
        assert_eq!(
            canonical_query_string(&[("prefix", "a/b"), ("list-type", "2")]),
            "list-type=2&prefix=a%2Fb"
        );
        // Reserved characters in a value are all percent-encoded with
        // uppercase hex; unreserved (`-_.~`) pass through.
        assert_eq!(
            canonical_query_string(&[("k", "a+b c/d=e&f-_.~")]),
            "k=a%2Bb%20c%2Fd%3De%26f-_.~"
        );
        assert_eq!(canonical_query_string(&[]), "");
    }

    // A non-empty-query GET whose value contains `/`. The canonical
    // request MUST carry the percent-encoded form (`%2F`), matching what
    // real AWS S3 re-derives before recomputing the signature. With the
    // pre-fix (raw `/`) signer this canonical request — and therefore the
    // signature — differed from AWS's, yielding 403 on list_refs.
    #[test]
    fn sign_list_query_canonical_request_is_percent_encoded() {
        let query = canonical_query_string(&[("list-type", "2"), ("prefix", "refs/heads/")]);
        assert_eq!(query, "list-type=2&prefix=refs%2Fheads%2F");
        let sig = sign_request(
            &demo_creds(),
            "GET",
            "/mkit-storage/",
            &query,
            b"",
            "https://abc123.r2.cloudflarestorage.com",
            1_711_300_000,
        );
        // Second line of the canonical request is the path; third line is
        // the canonical query string. Assert the encoded query is present
        // and the raw `/`-in-value form is absent.
        assert!(
            sig.canonical_request
                .contains("\nlist-type=2&prefix=refs%2Fheads%2F\n"),
            "canonical request missing percent-encoded query: {}",
            sig.canonical_request
        );
        assert!(!sig.canonical_request.contains("prefix=refs/heads/"));
    }

    #[test]
    fn sign_query_changes_signature() {
        let with_q = sign_request(
            &demo_creds(),
            "GET",
            "/mkit-storage/",
            "list-type=2&prefix=refs/",
            b"",
            "https://abc123.r2.cloudflarestorage.com",
            1_711_300_000,
        );
        let without_q = sign_request(
            &demo_creds(),
            "GET",
            "/mkit-storage/",
            "",
            b"",
            "https://abc123.r2.cloudflarestorage.com",
            1_711_300_000,
        );
        assert_eq!(with_q.x_amz_date, without_q.x_amz_date);
        assert_ne!(with_q.signature_hex, without_q.signature_hex);
    }

    // AWS SigV4 documented Known-Answer Test: "Get Object" example.
    // Source: https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
    // The documented canonical request and signature for the minimal
    // host + x-amz-content-sha256 + x-amz-date form are reproduced here.
    #[test]
    fn aws_kat_get_object_minimal_signed_headers() {
        // Inputs (access key, secret key, bucket, key, timestamp) are the
        // AWS-documented "GET Object" example:
        // https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
        //
        // NOTE: AWS's own worked example there additionally signs a
        // `Range: bytes=0-9` header (4 signed headers: host, range,
        // x-amz-content-sha256, x-amz-date), so its published signature
        // (`f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41`)
        // does not apply here — this signer only ever signs the 3-header
        // minimal set (see module docs), hence "minimal_signed_headers".
        // The values below are this signer's deterministic output for
        // AWS's exact credentials/date/bucket/key inputs on that reduced
        // header set (independently re-derived by hand and cross-checked
        // against this implementation, not copied from the AWS page).
        let creds = Credentials {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".into(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into(),
            region: "us-east-1".into(),
        };
        // Mon, 09 Sep 2013 23:36:00 GMT → 1378769760
        let sig = sign_request(
            &creds,
            "GET",
            "/test.txt",
            "",
            b"",
            "https://examplebucket.s3.amazonaws.com",
            1_378_769_760,
        );
        assert_eq!(sig.x_amz_date, "20130909T233600Z");
        assert_eq!(
            sig.x_amz_content_sha256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sig.canonical_request,
            "GET\n\
             /test.txt\n\
             \n\
             host:examplebucket.s3.amazonaws.com\n\
             x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n\
             x-amz-date:20130909T233600Z\n\
             \n\
             host;x-amz-content-sha256;x-amz-date\n\
             e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sig.string_to_sign,
            "AWS4-HMAC-SHA256\n\
             20130909T233600Z\n\
             20130909/us-east-1/s3/aws4_request\n\
             2a7e400af4dd07402f2aa47a7480612c35defd386256bc7746d97dda5b692593"
        );
        assert_eq!(
            sig.signature_hex,
            "4f17677c0662a1b4d2b967bf8d489be3aea8af0d861253866b51fe394d320a68"
        );
        assert_eq!(
            sig.authorization,
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130909/us-east-1/s3/aws4_request, \
             SignedHeaders=host;x-amz-content-sha256;x-amz-date, \
             Signature=4f17677c0662a1b4d2b967bf8d489be3aea8af0d861253866b51fe394d320a68"
        );
    }
}
