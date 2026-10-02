//! The one `ServerError` → `ConnectError` table (A14). Handlers never build
//! a `ConnectError` themselves: they return a [`ServerError`] and `?` maps
//! it here, so only the public message, never a log detail, reaches the
//! wire (issue #794), and the M3 response shaping (HTTP status, headers such
//! as `WWW-Authenticate`, typed details such as `AdmissionChallenge`)
//! reaches it too.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use connectrpc::{ConnectError, ErrorCode};
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};

use crate::error::{Code, ServerError};
use crate::upload::UploadError;

/// The Connect code for `code`: the same 16 codes, one to one.
fn error_code(code: Code) -> ErrorCode {
    match code {
        Code::Canceled => ErrorCode::Canceled,
        Code::Unknown => ErrorCode::Unknown,
        Code::InvalidArgument => ErrorCode::InvalidArgument,
        Code::DeadlineExceeded => ErrorCode::DeadlineExceeded,
        Code::NotFound => ErrorCode::NotFound,
        Code::AlreadyExists => ErrorCode::AlreadyExists,
        Code::PermissionDenied => ErrorCode::PermissionDenied,
        Code::ResourceExhausted => ErrorCode::ResourceExhausted,
        Code::FailedPrecondition => ErrorCode::FailedPrecondition,
        Code::Aborted => ErrorCode::Aborted,
        Code::OutOfRange => ErrorCode::OutOfRange,
        Code::Unimplemented => ErrorCode::Unimplemented,
        Code::Internal => ErrorCode::Internal,
        Code::Unavailable => ErrorCode::Unavailable,
        Code::DataLoss => ErrorCode::DataLoss,
        Code::Unauthenticated => ErrorCode::Unauthenticated,
    }
}

/// A connectrpc error (e.g. a broken request stream) as the [`ServerError`]
/// a request is recorded with: its code, and its message for the log.
pub(super) fn recorded(err: &ConnectError) -> ServerError {
    let code = match err.code {
        ErrorCode::Canceled => Code::Canceled,
        ErrorCode::InvalidArgument => Code::InvalidArgument,
        ErrorCode::DeadlineExceeded => Code::DeadlineExceeded,
        ErrorCode::NotFound => Code::NotFound,
        ErrorCode::AlreadyExists => Code::AlreadyExists,
        ErrorCode::PermissionDenied => Code::PermissionDenied,
        ErrorCode::ResourceExhausted => Code::ResourceExhausted,
        ErrorCode::FailedPrecondition => Code::FailedPrecondition,
        ErrorCode::Aborted => Code::Aborted,
        ErrorCode::OutOfRange => Code::OutOfRange,
        ErrorCode::Unimplemented => Code::Unimplemented,
        ErrorCode::Internal => Code::Internal,
        ErrorCode::Unavailable => Code::Unavailable,
        ErrorCode::DataLoss => Code::DataLoss,
        ErrorCode::Unauthenticated => Code::Unauthenticated,
        // `ErrorCode` is non-exhaustive.
        _ => Code::Unknown,
    };
    ServerError::new(code, err.message.clone().unwrap_or_default())
}

/// `err`'s response headers. `ServerError` already refused credentials,
/// framing headers and control characters; a name or value `http` still
/// rejects is dropped with a warning, its value never logged.
fn header_map(err: &ServerError) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in err.headers() {
        let encoded = HeaderName::from_bytes(name.as_bytes())
            .ok()
            .zip(HeaderValue::from_str(value).ok());
        if let Some((name, value)) = encoded {
            map.append(name, value);
        } else {
            tracing::warn!(header = ?name, "dropped an unencodable error response header");
        }
    }
    map
}

impl From<ServerError> for ConnectError {
    fn from(err: ServerError) -> Self {
        let mut out = ConnectError::new(error_code(err.code()), err.public_message());
        if let Some(status) = err.http_status().and_then(|s| StatusCode::from_u16(s).ok()) {
            out = out.with_http_status(status);
        }
        if !err.headers().is_empty() {
            out = out.with_headers(header_map(&err));
        }
        for detail in err.details() {
            out = out.with_detail(connectrpc::ErrorDetail {
                type_url: detail.type_name.clone(),
                value: Some(STANDARD_NO_PAD.encode(&detail.value)),
                debug: None,
            });
        }
        out
    }
}

/// An `UploadPack` framing error on the Connect wire: its code and
/// `mkit-transport-connect`'s message.
#[must_use]
pub fn from_upload_error(err: UploadError) -> ConnectError {
    ServerError::from(err).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorDetail;

    #[test]
    fn every_code_keeps_its_name() {
        let codes = [
            Code::Canceled,
            Code::Unknown,
            Code::InvalidArgument,
            Code::DeadlineExceeded,
            Code::NotFound,
            Code::AlreadyExists,
            Code::PermissionDenied,
            Code::ResourceExhausted,
            Code::FailedPrecondition,
            Code::Aborted,
            Code::OutOfRange,
            Code::Unimplemented,
            Code::Internal,
            Code::Unavailable,
            Code::DataLoss,
            Code::Unauthenticated,
        ];
        for code in codes {
            assert_eq!(error_code(code).as_str(), code.as_str());
            let back = recorded(&ConnectError::new(error_code(code), "m"));
            assert_eq!(back.code(), code);
        }
    }

    #[test]
    fn internal_detail_never_crosses() {
        let err: ConnectError = ServerError::internal("storage failure", "bucket=secret").into();
        assert_eq!(err.code, ErrorCode::Internal);
        assert_eq!(err.message.as_deref(), Some("storage failure"));
        let json = String::from_utf8(err.to_json().to_vec()).unwrap();
        assert!(!json.contains("secret"), "{json}");
        assert!(err.details.is_empty());
    }

    #[test]
    fn shaping_crosses() {
        let err: ConnectError = ServerError::permission_denied("pay")
            .with_http_status(402)
            .with_header("WWW-Authenticate", "Payment id=a")
            .with_header("WWW-Authenticate", "Payment id=b")
            .with_detail(ErrorDetail {
                type_name: "mkit.test.Detail".to_owned(),
                value: bytes::Bytes::from_static(&[1, 2, 3]),
            })
            .into();
        assert_eq!(err.http_status(), StatusCode::PAYMENT_REQUIRED);
        let values: Vec<_> = err
            .response_headers()
            .get_all("www-authenticate")
            .iter()
            .collect();
        assert_eq!(values, ["Payment id=a", "Payment id=b"]);
        assert_eq!(err.details.len(), 1);
        assert_eq!(err.details[0].type_url, "mkit.test.Detail");
        assert_eq!(err.details[0].value.as_deref(), Some("AQID"));
    }

    #[test]
    fn upload_errors_keep_the_connect_message() {
        let err = from_upload_error(UploadError::HeaderMissing {
            stream_empty: false,
        });
        assert_eq!(err.code, ErrorCode::InvalidArgument);
        assert_eq!(
            err.message.as_deref(),
            Some("UploadPack: first message MUST be `header`")
        );
        let big = from_upload_error(UploadError::TotalTooLarge { total: 9, cap: 8 });
        assert_eq!(big.code, ErrorCode::ResourceExhausted);
    }
}
