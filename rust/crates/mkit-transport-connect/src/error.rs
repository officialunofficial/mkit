//! Connect-code -> [`TransportError`] mapping (SPEC-TRANSPORT-CONNECT §5),
//! the client-side direction.
//!
//! The mapping table lives in `docs/specs/SPEC-TRANSPORT-CONNECT.md`. This
//! module implements the client-side (Connect code -> `TransportError`)
//! direction — the inverse of the server's table (`mkit-server`'s Connect
//! binding), with [`TransportError::RemoteError`] as the fallback arm for any
//! code the table does not otherwise list.
//!
//! One wrinkle the spec calls out explicitly: `invalid_argument` is raised
//! by two different RPC families for two different reasons — a bad ref name
//! (`ListRefs`/`ReadRef`/`UpdateRef`/`AdvanceRefs`) maps to
//! [`TransportError::InvalidRef`], while a malformed `UploadPack` stream
//! (missing header, out-of-order chunk, byte-count mismatch) maps to
//! [`TransportError::ProtocolError`]. The Connect code alone can't
//! disambiguate, so callers pass an [`ErrorContext`] naming which family
//! they called.
//!
//! A second wrinkle: `connectrpc`'s own client collapses a genuine
//! transport-level failure (DNS, TCP connect, TLS handshake — anything with
//! no [`ConnectError`] in its `source()` chain) into `unavailable`
//! (internally, via a private `map_transport_send_error` helper), the
//! same code a server uses for a real backend-overload response. This
//! module can't tell the two apart either, so both surface as
//! [`TransportError::ServerError`] with a representative status (503) —
//! not [`TransportError::ConnectionFailed`]. This is intentional, not a
//! gap: [`mkit_core::protocol::is_retryable`] treats `ServerError { status:
//! 503 }` exactly like `ConnectionFailed` (both retryable), so retry
//! behavior is identical either way.

use base64::Engine as _;
use buffa::Message as _;
use connectrpc::{ConnectError, ErrorCode};
use mkit_core::protocol::{AdmissionChallengeEntry, AdmissionRequired, TransportError};

use crate::proto::mkit::transport::v1::{AdmissionChallenge, PendingVerification};
use crate::status::STATUS_MARKER;

// TODO(R-138): use mkit_core::admission bounds once the server admission bundle lands.
const MAX_CHALLENGES: usize = 8;
const MAX_SCHEME: usize = 64;
const MAX_VALUE: usize = 8_192;
const MAX_DESCRIPTION: usize = 512;
const MAX_DETAIL_BASE64: usize = 88_836;
const CHALLENGE_TYPE: &str = "mkit.transport.v1.AdmissionChallenge";

fn visible_header_values(
    err: &ConnectError,
    name: &'static str,
) -> Result<Vec<String>, TransportError> {
    let mut values = Vec::new();
    for value in err.response_headers().get_all(name) {
        let bytes = value.as_bytes();
        if values.len() == 8
            || bytes.len() > MAX_VALUE
            || !bytes
                .iter()
                .all(|b| *b == b'\t' || (0x20..=0x7e).contains(b))
        {
            return Err(TransportError::InvalidResponse);
        }
        values
            .push(String::from_utf8(bytes.to_vec()).map_err(|_| TransportError::InvalidResponse)?);
    }
    Ok(values)
}

fn admission_required(err: &ConnectError) -> Option<Result<AdmissionRequired, TransportError>> {
    let stamped_402 = err
        .response_headers()
        .get(STATUS_MARKER)
        .is_some_and(|v| v == "402");
    let details: Vec<_> = err
        .details
        .iter()
        .filter(|detail| {
            detail
                .type_url
                .strip_prefix("type.googleapis.com/")
                .unwrap_or(&detail.type_url)
                == CHALLENGE_TYPE
        })
        .collect();
    if !(stamped_402 || (err.code == ErrorCode::PermissionDenied && !details.is_empty())) {
        return None;
    }
    Some((|| {
        if details.len() > 1 {
            return Err(TransportError::InvalidResponse);
        }
        let (challenges, description) = if let Some(detail) = details.first() {
            let encoded = detail.value.as_deref().unwrap_or("");
            if encoded.len() > MAX_DETAIL_BASE64 {
                return Err(TransportError::InvalidResponse);
            }
            let bytes = base64::engine::general_purpose::STANDARD_NO_PAD
                .decode(encoded)
                .or_else(|_| base64::engine::general_purpose::STANDARD.decode(encoded))
                .map_err(|_| TransportError::InvalidResponse)?;
            let decoded = AdmissionChallenge::decode_from_slice(&bytes)
                .map_err(|_| TransportError::InvalidResponse)?;
            if decoded.challenges.len() > MAX_CHALLENGES {
                return Err(TransportError::InvalidResponse);
            }
            let mut challenges = Vec::with_capacity(decoded.challenges.len());
            for challenge in decoded.challenges {
                let scheme = challenge.scheme.unwrap_or_default();
                let value = challenge.value.unwrap_or_default();
                let valid_scheme = !scheme.is_empty()
                    && scheme.len() <= MAX_SCHEME
                    && scheme.bytes().enumerate().all(|(i, b)| {
                        b.is_ascii_lowercase()
                            || b.is_ascii_digit()
                            || (i > 0 && matches!(b, b'.' | b'-'))
                    });
                if !valid_scheme || value.len() > MAX_VALUE {
                    return Err(TransportError::InvalidResponse);
                }
                challenges.push(AdmissionChallengeEntry { scheme, value });
            }
            let description = decoded.description.unwrap_or_default();
            if description.len() > MAX_DESCRIPTION {
                return Err(TransportError::InvalidResponse);
            }
            (challenges, description)
        } else {
            (Vec::new(), String::new())
        };
        Ok(AdmissionRequired::new(
            challenges,
            description,
            visible_header_values(err, "www-authenticate")?,
            visible_header_values(err, "payment-required")?,
        ))
    })())
}

/// Recognise only a typed `AdvanceRefs` unavailable response. Malformed
/// details deliberately fall back to the ordinary retry ladder.
pub(crate) fn pending_verification_delay(err: &ConnectError) -> Option<std::time::Duration> {
    if err.code != ErrorCode::Unavailable {
        return None;
    }
    let detail = err.details.iter().find(|detail| {
        detail
            .type_url
            .strip_prefix("type.googleapis.com/")
            .unwrap_or(&detail.type_url)
            == "mkit.transport.v1.PendingVerification"
    })?;
    let value = detail.value.as_deref().unwrap_or("");
    let bytes = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(value)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(value))
        .ok()?;
    let pending = PendingVerification::decode_from_slice(&bytes).ok()?;
    Some(std::time::Duration::from_millis(u64::from(
        pending.retry_after_ms.unwrap_or(0).clamp(1_000, 60_000),
    )))
}

/// Which RPC family raised the error — needed to disambiguate
/// `invalid_argument` (see module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ErrorContext {
    /// `ListRefs` / `ReadRef` / `UpdateRef` / `AdvanceRefs` / `PackExists` /
    /// `DownloadPack` — RPCs whose `invalid_argument` means "bad ref name or
    /// digest".
    Ref,
    /// `UploadPack` — `invalid_argument` here means "malformed
    /// client-stream protocol" (SPEC-TRANSPORT-CONNECT §6.1).
    Upload,
}

/// Representative HTTP-style status used for
/// [`TransportError::ServerError`] when the Connect code is `unavailable`
/// (5xx-equivalent) but no more specific status is available.
const UNAVAILABLE_STATUS: u16 = 503;

/// Representative status for `resource_exhausted` (429-equivalent).
const RESOURCE_EXHAUSTED_STATUS: u16 = 429;

/// Map a [`ConnectError`] to a [`TransportError`] per
/// SPEC-TRANSPORT-CONNECT §5's inverse mapping.
pub(crate) fn map_connect_error(err: ConnectError, ctx: ErrorContext) -> TransportError {
    if let Some(required) = admission_required(&err) {
        return match required {
            Ok(required) => TransportError::AdmissionRequired(Box::new(required)),
            Err(error) => error,
        };
    }
    let message = || err.message.clone().unwrap_or_default();
    match err.code {
        ErrorCode::NotFound => TransportError::PackNotFound,
        ErrorCode::PermissionDenied | ErrorCode::Unauthenticated => TransportError::AccessDenied,
        ErrorCode::FailedPrecondition => TransportError::RefConflict,
        ErrorCode::InvalidArgument => match ctx {
            ErrorContext::Ref => TransportError::InvalidRef(message()),
            ErrorContext::Upload => TransportError::ProtocolError,
        },
        ErrorCode::ResourceExhausted => TransportError::ServerError {
            status: RESOURCE_EXHAUSTED_STATUS,
        },
        ErrorCode::Unavailable | ErrorCode::Aborted => TransportError::ServerError {
            status: UNAVAILABLE_STATUS,
        },
        _ => TransportError::RemoteError(message()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::mkit::transport::v1::Challenge;
    use connectrpc::ErrorDetail;

    fn admission_error(challenge: AdmissionChallenge) -> ConnectError {
        ConnectError::permission_denied("never display this secret")
            .with_detail(ErrorDetail::from_message(CHALLENGE_TYPE, &challenge))
    }

    fn challenge(scheme: &str, value: &str) -> Challenge {
        Challenge {
            scheme: Some(scheme.into()),
            value: Some(value.into()),
            ..Default::default()
        }
    }

    #[test]
    fn admission_golden_and_display_are_safe() {
        let json = include_str!("../../../tests/golden/transport/admission-challenge-error.json");
        let error: ConnectError = serde_json::from_str(json).unwrap();
        let TransportError::AdmissionRequired(required) =
            map_connect_error(error, ErrorContext::Ref)
        else {
            panic!("expected admission")
        };
        assert_eq!(
            required
                .challenges
                .iter()
                .map(|c| c.scheme.as_str())
                .collect::<Vec<_>>(),
            ["mpp", "x402"]
        );
        assert_eq!(required.description, "Example upload payment required.");
        assert!(!mkit_core::protocol::is_retryable(
            &TransportError::AdmissionRequired(required.clone())
        ));
        let mut modified = *required;
        modified.description = "bad\x1b[31m\r\u{202e}text".into();
        let display = modified.to_string();
        assert!(display.contains("mpp, x402"));
        assert!(display.contains("\\u{1b}"));
        assert!(display.contains("\\u{d}"));
        assert!(display.contains("\\u{202e}"));
        assert!(!display.contains("fake-example"));
    }

    #[test]
    fn admission_bounds_and_detail_rules() {
        let valid = AdmissionChallenge {
            challenges: vec![challenge(&"a".repeat(64), &"v".repeat(8_192)); 8],
            description: Some("d".repeat(512)),
            ..Default::default()
        };
        assert!(matches!(
            map_connect_error(admission_error(valid.clone()), ErrorContext::Ref),
            TransportError::AdmissionRequired(_)
        ));
        for invalid in [
            AdmissionChallenge {
                challenges: vec![challenge("ok", "v"); 9],
                ..Default::default()
            },
            AdmissionChallenge {
                challenges: vec![challenge(&"a".repeat(65), "v")],
                ..Default::default()
            },
            AdmissionChallenge {
                challenges: vec![challenge("a", &"v".repeat(8_193))],
                ..Default::default()
            },
            AdmissionChallenge {
                description: Some("d".repeat(513)),
                ..Default::default()
            },
            AdmissionChallenge {
                challenges: vec![challenge("UPPER", "v")],
                ..Default::default()
            },
        ] {
            assert!(matches!(
                map_connect_error(admission_error(invalid), ErrorContext::Ref),
                TransportError::InvalidResponse
            ));
        }
        let mut two = admission_error(valid);
        two.details.push(two.details[0].clone());
        assert!(matches!(
            map_connect_error(two, ErrorContext::Ref),
            TransportError::InvalidResponse
        ));
        let mut oversized = ConnectError::permission_denied("x").with_detail(ErrorDetail {
            type_url: CHALLENGE_TYPE.into(),
            value: Some("!".repeat(88_837)),
            debug: None,
        });
        assert!(matches!(
            map_connect_error(oversized.clone(), ErrorContext::Ref),
            TransportError::InvalidResponse
        ));
        oversized.details[0].value = Some("%%%".into());
        assert!(matches!(
            map_connect_error(oversized, ErrorContext::Ref),
            TransportError::InvalidResponse
        ));
    }

    #[test]
    fn admission_status_headers_and_unrelated_details() {
        let mut raw = ConnectError::new(ErrorCode::Unknown, "untrusted body with secret");
        raw.response_headers_mut()
            .insert(STATUS_MARKER, "402".parse().unwrap());
        raw.response_headers_mut()
            .append("www-authenticate", "Payment a".parse().unwrap());
        raw.response_headers_mut()
            .append("payment-required", "x".parse().unwrap());
        raw.response_headers_mut()
            .append("x-other", "secret".parse().unwrap());
        let TransportError::AdmissionRequired(required) = map_connect_error(raw, ErrorContext::Ref)
        else {
            panic!("expected admission")
        };
        assert!(required.challenges.is_empty());
        assert!(required.description.is_empty());
        assert_eq!(required.www_authenticate, ["Payment a"]);
        assert_eq!(required.payment_required, ["x"]);
        assert!(!format!("{required:?}").contains("secret"));

        let detail = ErrorDetail::from_message(CHALLENGE_TYPE, &AdmissionChallenge::default());
        let mut prefixed = ConnectError::permission_denied("x").with_detail(detail.clone());
        prefixed.details[0].type_url = format!("type.googleapis.com/{CHALLENGE_TYPE}");
        assert!(matches!(
            map_connect_error(prefixed, ErrorContext::Ref),
            TransportError::AdmissionRequired(_)
        ));
        let unavailable = ConnectError::unavailable("x").with_detail(detail);
        assert!(mkit_core::protocol::is_retryable(&map_connect_error(
            unavailable,
            ErrorContext::Ref
        )));
        assert!(matches!(
            map_connect_error(ConnectError::permission_denied("x"), ErrorContext::Ref),
            TransportError::AccessDenied
        ));
        let notice = ErrorDetail {
            type_url: "mkit.transport.v1.RedactionNotice".into(),
            value: None,
            debug: None,
        };
        assert!(matches!(
            map_connect_error(
                ConnectError::permission_denied("x").with_detail(notice),
                ErrorContext::Ref
            ),
            TransportError::AccessDenied
        ));
    }

    #[test]
    fn admission_header_bounds_are_enforced() {
        let mut error = ConnectError::unknown("body");
        error
            .response_headers_mut()
            .insert(STATUS_MARKER, "402".parse().unwrap());
        for _ in 0..8 {
            error
                .response_headers_mut()
                .append("payment-required", "v".repeat(8_192).parse().unwrap());
        }
        assert!(matches!(
            map_connect_error(error.clone(), ErrorContext::Ref),
            TransportError::AdmissionRequired(_)
        ));
        error
            .response_headers_mut()
            .append("payment-required", "v".parse().unwrap());
        assert!(matches!(
            map_connect_error(error, ErrorContext::Ref),
            TransportError::InvalidResponse
        ));
        let mut error = ConnectError::unknown("body");
        error
            .response_headers_mut()
            .insert(STATUS_MARKER, "402".parse().unwrap());
        error
            .response_headers_mut()
            .insert("www-authenticate", "v".repeat(8_193).parse().unwrap());
        assert!(matches!(
            map_connect_error(error, ErrorContext::Ref),
            TransportError::InvalidResponse
        ));
        for invalid in [b"\x7f".as_slice(), b"\x80".as_slice()] {
            let mut error = ConnectError::unknown("body");
            error
                .response_headers_mut()
                .insert(STATUS_MARKER, "402".parse().unwrap());
            if let Ok(value) = http::HeaderValue::from_bytes(invalid) {
                error
                    .response_headers_mut()
                    .insert("payment-required", value);
                assert!(matches!(
                    map_connect_error(error, ErrorContext::Ref),
                    TransportError::InvalidResponse
                ));
            }
        }
    }

    fn pending_error(value: Option<String>) -> ConnectError {
        ConnectError::unavailable("verification pending").with_detail(connectrpc::ErrorDetail {
            type_url: "mkit.transport.v1.PendingVerification".to_owned(),
            value,
            debug: None,
        })
    }

    #[test]
    fn pending_delay_clamps_all_boundaries() {
        for (value, expected) in [
            (None, 1_000),
            (Some(0), 1_000),
            (Some(500), 1_000),
            (Some(5_000), 5_000),
            (Some(120_000), 60_000),
            (Some(u32::MAX), 60_000),
        ] {
            let bytes = buffa::Message::encode_to_vec(&PendingVerification {
                retry_after_ms: value,
                ..Default::default()
            });
            let error = pending_error(Some(
                base64::engine::general_purpose::STANDARD_NO_PAD.encode(bytes),
            ));
            assert_eq!(
                pending_verification_delay(&error),
                Some(std::time::Duration::from_millis(expected))
            );
        }
        assert_eq!(
            pending_verification_delay(&pending_error(None)),
            Some(std::time::Duration::from_millis(1_000))
        );
    }

    #[test]
    fn golden_pending_error_decodes_to_five_seconds() {
        let json = include_str!("../../../tests/golden/transport/pending-verification-error.json");
        let error: ConnectError = serde_json::from_str(json).unwrap();
        assert_eq!(
            pending_verification_delay(&error),
            Some(std::time::Duration::from_secs(5))
        );
    }

    #[test]
    fn malformed_and_other_code_details_are_plain_errors() {
        let mut malformed = pending_error(Some("%%%".to_owned()));
        assert_eq!(pending_verification_delay(&malformed), None);
        malformed.code = ErrorCode::Aborted;
        assert_eq!(pending_verification_delay(&malformed), None);
        let mut other_type = pending_error(None);
        other_type.details[0].type_url = "mkit.transport.v1.SomethingElse".to_owned();
        assert_eq!(pending_verification_delay(&other_type), None);
        let mut prefixed = pending_error(None);
        prefixed.details[0].type_url = PendingVerification::TYPE_URL.to_owned();
        assert!(pending_verification_delay(&prefixed).is_some());
    }

    #[test]
    fn aborted_is_retryable() {
        let err = map_connect_error(
            ConnectError::new(ErrorCode::Aborted, "in flight"),
            ErrorContext::Ref,
        );
        assert!(matches!(err, TransportError::ServerError { status: 503 }));
        assert!(mkit_core::protocol::is_retryable(&err));
    }
}
