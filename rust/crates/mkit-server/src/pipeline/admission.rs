//! Stage 3 validation and transport-neutral challenge shaping.

use bytes::Bytes;
use mkit_core::admission::{encode_admission_challenge, validate_challenges};

use super::{Allowance, AuthMode, Pipeline, RequestMeta, Snapshot, meta_error};
use crate::error::{Redacted, ServerError};
use crate::pipeline::HookSet;
use crate::pipeline::hooks::{Admission, AdmissionDecision, AdmissionInput, CredentialHeader};
use crate::store::{MultipartBlobStore, NamespaceStore, Partition, codec, keys};

fn invalid(reason: &'static str) -> ServerError {
    tracing::warn!(reason, "invalid admission decision");
    ServerError::unavailable("admission unavailable")
}

fn credential_denial() -> ServerError {
    ServerError::permission_denied("admission denied")
}

fn header_values(meta: &RequestMeta<'_>, name: &str) -> Vec<String> {
    meta.header_values.map_or_else(
        || {
            (meta.header)(&name.to_ascii_lowercase())
                .into_iter()
                .collect()
        },
        |values| values(name),
    )
}

fn valid_token68(value: &str) -> bool {
    let Some((scheme, rest)) = value.get(..7).zip(value.get(7..)) else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case("Payment") {
        return false;
    }
    let token = rest.trim_start_matches(' ');
    if rest.len() == token.len() || token.is_empty() || token.contains(',') {
        return false;
    }
    let unpadded = token.trim_end_matches('=');
    !unpadded.is_empty()
        && unpadded
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~+/".contains(&b))
        && token[unpadded.len()..].bytes().all(|b| b == b'=')
}

/// Validate configurable request names before a pipeline starts.
pub(super) fn valid_extra_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if lower.is_empty()
        || !lower
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
    {
        return false;
    }
    ![
        "authorization",
        "host",
        "cookie",
        "transfer-encoding",
        "connection",
        "keep-alive",
        "te",
        "trailer",
        "upgrade",
        "idempotency-key",
        "x-public-key",
        "x-signature",
        "x-digest",
        "x-created-at",
        "x-expires-at",
        "x-envelope-version",
        "x-audience",
        "x-repository",
        "x-content-commitment",
        "x-write-grant",
        "x-mkit-ref",
    ]
    .contains(&lower.as_str())
        && !["x-mkit-", "x-forwarded-", "content-", "connect-", "proxy-"]
            .iter()
            .any(|prefix| lower.starts_with(prefix))
}

/// At most this many credential headers reach admission.
pub(super) const MAX_CREDENTIAL_HEADERS: usize = 8;
/// Longest accepted credential header value.
const MAX_CREDENTIAL_VALUE: usize = 8_192;

/// One credential header as delivered, before validation.
#[derive(Clone, PartialEq, Eq)]
pub(super) struct CapturedCredential {
    name: String,
    values: Vec<Redacted>,
}

/// Record the credential headers of a signed request. Nothing is judged
/// here: validation runs only if admission does (SPEC-SERVER §6.6).
pub(super) fn capture_credentials(
    meta: &RequestMeta<'_>,
    extras: &[String],
) -> Vec<CapturedCredential> {
    [
        "Payment-Authorization",
        "PAYMENT-SIGNATURE",
        "Authorization",
    ]
    .into_iter()
    .chain(extras.iter().map(String::as_str))
    .filter_map(|name| {
        let values = header_values(meta, name);
        (!values.is_empty()).then(|| CapturedCredential {
            name: name.to_owned(),
            values: values.into_iter().map(Redacted::new).collect(),
        })
    })
    .collect()
}

/// Validate the captured headers into what admission sees. Only
/// `Authorization` must be comma-free (brief B6); a non-Payment or malformed
/// one is silently not forwarded, an oversized Payment one is denied.
pub(super) fn validate_credentials(
    captured: &[CapturedCredential],
) -> Result<Vec<CredentialHeader>, ServerError> {
    let mut selected = Vec::new();
    for header in captured {
        let [value] = header.values.as_slice() else {
            if header.name.eq_ignore_ascii_case("Authorization") {
                continue;
            }
            return Err(credential_denial());
        };
        let value = value.expose();
        if header.name.eq_ignore_ascii_case("Authorization") {
            if is_payment_scheme(value) && value.len() > MAX_CREDENTIAL_VALUE {
                return Err(credential_denial());
            }
            if !valid_token68(value) {
                continue;
            }
        } else if value.len() > MAX_CREDENTIAL_VALUE
            || !value
                .bytes()
                .all(|b| b == b'\t' || (0x20..=0x7e).contains(&b))
        {
            return Err(credential_denial());
        }
        selected.push(CredentialHeader::new(&header.name, Redacted::new(value)));
    }
    if selected.len() > MAX_CREDENTIAL_HEADERS {
        return Err(credential_denial());
    }
    Ok(selected)
}

fn is_payment_scheme(value: &str) -> bool {
    value
        .get(..7)
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("Payment"))
}

#[cfg(test)]
pub(super) fn select_credentials(
    meta: &RequestMeta<'_>,
    extras: &[String],
) -> Result<Vec<CredentialHeader>, ServerError> {
    validate_credentials(&capture_credentials(meta, extras))
}

fn validate_headers(headers: &[(String, String)], allow: bool) -> Result<(), ServerError> {
    if headers.len() > 8 {
        return Err(invalid("too many response headers"));
    }
    let mut unique = std::collections::BTreeSet::new();
    for (name, value) in headers {
        let permitted = if allow {
            name.eq_ignore_ascii_case("Payment-Receipt")
                || name.eq_ignore_ascii_case("PAYMENT-RESPONSE")
        } else {
            name.eq_ignore_ascii_case("WWW-Authenticate")
                || name.eq_ignore_ascii_case("PAYMENT-REQUIRED")
        };
        if !permitted
            || value.len() > 8_192
            || !value.bytes().all(|b| (0x20..=0x7e).contains(&b))
            || (!name.eq_ignore_ascii_case("WWW-Authenticate")
                && !unique.insert(name.to_ascii_lowercase()))
        {
            return Err(invalid("invalid response header"));
        }
    }
    Ok(())
}

pub(super) fn validate_decision(decision: &AdmissionDecision) -> Result<(), ServerError> {
    match decision {
        AdmissionDecision::Allow {
            reservation,
            response_headers,
            external_ref,
            ..
        } => {
            validate_headers(response_headers, true)?;
            if let Some(rid) = reservation
                && (!keys::validate_reservation_id(rid) || rid.starts_with("s:"))
            {
                return Err(invalid("invalid reservation id"));
            }
            if let Some(reference) = external_ref
                && (reference.len() > 256 || !reference.bytes().all(|b| (0x21..=0x7e).contains(&b)))
            {
                return Err(invalid("invalid external reference"));
            }
        }
        AdmissionDecision::Challenge {
            challenges,
            description,
            response_headers,
        } => {
            let pairs: Vec<_> = challenges
                .iter()
                .map(|c| (c.scheme.as_str(), c.value.as_str()))
                .collect();
            validate_challenges(&pairs, description)
                .map_err(|_| invalid("invalid challenge bounds"))?;
            validate_headers(response_headers, false)?;
        }
        AdmissionDecision::Deny(_) => {}
    }
    Ok(())
}

fn deny(err: &ServerError) -> ServerError {
    let message = err.public_message();
    let safe = message.len() <= 512 && !message.chars().any(char::is_control);
    ServerError::permission_denied(if safe {
        message.to_owned()
    } else {
        "admission denied".to_owned()
    })
    .with_http_status(403)
}

impl<B: MultipartBlobStore, N: NamespaceStore, H: HookSet> Pipeline<B, N, H> {
    pub(super) async fn check_outbox_backpressure(
        &self,
        partition: &Partition,
        ahead: Option<&Snapshot>,
    ) -> Result<(), ServerError> {
        let Some(cap) = self.cfg.outbox_backlog_cap else {
            return Ok(());
        };
        if !self.meta.capabilities().atomic_multi_key {
            return Ok(());
        }
        let key = keys::outcome_backlog();
        let value = match ahead {
            Some(snapshot) if snapshot.contains(&key) => snapshot.get(&key).cloned(),
            _ => self.meta.get(partition, &key).await.map_err(meta_error)?,
        };
        let backlog = value
            .as_ref()
            .map(codec::decode_backlog)
            .transpose()
            .map_err(meta_error)?
            .unwrap_or_default();
        if backlog.rows > cap.rows || backlog.bytes > cap.bytes {
            self.metrics.incr(
                "mkit_server_outbox_backpressure",
                &[("shard_kind", partition.kind())],
                1,
            );
            return Err(
                ServerError::unavailable("outbox backlog; retry").with_header("Retry-After", "30")
            );
        }
        Ok(())
    }

    pub(super) async fn admit(&self, input: AdmissionInput<'_>) -> Result<Allowance, ServerError> {
        self.admit_for(input, true).await
    }

    pub(super) async fn admit_streaming(
        &self,
        input: AdmissionInput<'_>,
    ) -> Result<Allowance, ServerError> {
        self.admit_for(input, false).await
    }

    async fn admit_for(
        &self,
        mut input: AdmissionInput<'_>,
        unary: bool,
    ) -> Result<Allowance, ServerError> {
        tracing::debug!(stage = "admission");
        input.write_quota = self.cfg.write_quota;
        input.audience = match &self.cfg.auth {
            AuthMode::AuthV2(config) => Some(config.audience()),
            _ => None,
        };
        let decision = self
            .hooks
            .admission()
            .admit(&input)
            .await
            .map_err(ServerError::strip_admission_shape)?;
        validate_decision(&decision)?;
        match decision {
            AdmissionDecision::Allow {
                charges,
                reservation,
                response_headers,
                external_ref,
            } => Ok(Allowance {
                charges,
                reservation,
                response_headers,
                external_ref,
            }),
            AdmissionDecision::Challenge {
                challenges,
                description,
                response_headers,
            } => {
                if !unary {
                    return Err(ServerError::permission_denied("admission required"));
                }
                let pairs: Vec<_> = challenges
                    .iter()
                    .map(|c| (c.scheme.as_str(), c.value.as_str()))
                    .collect();
                let bytes = encode_admission_challenge(&pairs, &description);
                let mut error = ServerError::admission_challenge(Bytes::from(bytes));
                for (name, value) in response_headers {
                    error = error
                        .try_with_header(name, value)
                        .map_err(|_| invalid("invalid response header"))?;
                }
                Err(error)
            }
            AdmissionDecision::Deny(err) => Err(deny(&err)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::op::Procedure;

    #[test]
    fn decision_validator_rejects_every_bound_without_echoing_values() {
        let good = AdmissionDecision::challenge(
            vec![super::super::Challenge {
                scheme: "mpp".into(),
                value: "pay".into(),
            }],
            "pay",
        );
        assert!(validate_decision(&good).is_ok());
        let invalid = [
            AdmissionDecision::challenge(vec![], ""),
            AdmissionDecision::challenge(
                vec![super::super::Challenge {
                    scheme: "Mpp".into(),
                    value: "v".into(),
                }],
                "",
            ),
            AdmissionDecision::challenge(
                vec![super::super::Challenge {
                    scheme: "mpp".into(),
                    value: "v".repeat(8193),
                }],
                "",
            ),
            AdmissionDecision::challenge(
                vec![super::super::Challenge {
                    scheme: "mpp".into(),
                    value: "v".into(),
                }],
                "x".repeat(513),
            ),
            AdmissionDecision::challenge(
                vec![super::super::Challenge {
                    scheme: "mpp".into(),
                    value: "v\n".into(),
                }],
                "",
            ),
            good.clone().with_response_header("Set-Cookie", "secret"),
            good.clone()
                .with_response_header("PAYMENT-REQUIRED", "bad\n"),
            AdmissionDecision::allow(Vec::new()).with_response_header("WWW-Authenticate", "v"),
            AdmissionDecision::allow(Vec::new()).with_response_header("Payment-Receipt", "bad\t"),
            AdmissionDecision::allow(Vec::new()).with_reservation("s:synthetic"),
            AdmissionDecision::allow(Vec::new()).with_reservation("bad/id"),
            AdmissionDecision::allow(Vec::new()).with_external_ref("bad space"),
            AdmissionDecision::allow(Vec::new()).with_external_ref("x".repeat(257)),
        ];
        for decision in invalid {
            let err = validate_decision(&decision).unwrap_err();
            assert_eq!(err.public_message(), "admission unavailable");
        }
        assert!(
            validate_decision(
                &AdmissionDecision::allow(Vec::new())
                    .with_response_header("Payment-Receipt", "receipt")
            )
            .is_ok()
        );
        assert!(
            validate_decision(&good.with_response_header("WWW-Authenticate", "Payment token"))
                .is_ok()
        );
    }

    #[test]
    fn credential_selection_and_debug_redaction() {
        let values = |name: &str| match name.to_ascii_lowercase().as_str() {
            "payment-authorization" => vec!["secret-one".into()],
            "payment-signature" => vec!["secret-two".into()],
            "authorization" => vec!["Payment   abc+/==".into()],
            "x-extra" => vec!["secret-three".into()],
            _ => Vec::new(),
        };
        let first = |name: &str| values(name).into_iter().next();
        let meta = RequestMeta {
            procedure: Procedure::UpdateRef,
            header: &first,
            header_values: Some(&values),
            unary_body: None,
            transport_principal: None,
        };
        let selected = select_credentials(&meta, &["X-Extra".into()]).unwrap();
        assert_eq!(selected.len(), 4);
        assert!(
            selected.iter().any(|header| header.name == "Authorization"
                && header.value.expose() == "Payment   abc+/==")
        );
        let debug = format!("{selected:?} {meta:?}");
        for secret in ["secret-one", "secret-two", "secret-three", "abc+/"] {
            assert!(!debug.contains(secret));
        }
        for reserved in [
            "Authorization",
            "X-Public-Key",
            "X-Mkit-Thing",
            "Content-Type",
            "X-Forwarded-For",
        ] {
            assert!(!valid_extra_name(reserved));
        }
        assert!(valid_extra_name("X-Extra"));
    }

    #[test]
    fn malformed_credentials_deny_without_echoing_values() {
        for raw in ["bad\n", &"x".repeat(8193)] {
            let values = |name: &str| {
                if name.eq_ignore_ascii_case("Payment-Authorization") {
                    vec![raw.into()]
                } else {
                    Vec::new()
                }
            };
            let first = |name: &str| values(name).into_iter().next();
            let meta = RequestMeta {
                procedure: Procedure::UpdateRef,
                header: &first,
                header_values: Some(&values),
                unary_body: None,
                transport_principal: None,
            };
            assert_eq!(
                select_credentials(&meta, &[]).unwrap_err().code(),
                crate::Code::PermissionDenied
            );
        }
        let values = |name: &str| {
            if name.eq_ignore_ascii_case("PAYMENT-SIGNATURE") {
                vec!["a".into(), "b".into()]
            } else {
                Vec::new()
            }
        };
        let first = |name: &str| values(name).into_iter().next();
        let meta = RequestMeta {
            procedure: Procedure::UpdateRef,
            header: &first,
            header_values: Some(&values),
            unary_body: None,
            transport_principal: None,
        };
        assert!(select_credentials(&meta, &[]).is_err());
    }

    fn select(
        pairs: &[(&str, &[&str])],
        extras: &[String],
    ) -> Result<Vec<CredentialHeader>, ServerError> {
        let values = |name: &str| {
            pairs
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>())
                .unwrap_or_default()
        };
        let first = |name: &str| values(name).into_iter().next();
        let meta = RequestMeta {
            procedure: Procedure::UpdateRef,
            header: &first,
            header_values: Some(&values),
            unary_body: None,
            transport_principal: None,
        };
        select_credentials(&meta, extras)
    }

    #[test]
    fn commas_are_allowed_except_in_authorization() {
        let extras = ["X-Extra".to_owned()];
        let selected = select(
            &[
                ("Payment-Authorization", &["a,b"]),
                ("PAYMENT-SIGNATURE", &["c,d"]),
                ("X-Extra", &["e,f"]),
            ],
            &extras,
        )
        .unwrap();
        assert_eq!(selected.len(), 3);
        // Authorization must stay comma-free and single-line, and be Payment.
        for authorization in [
            &["Payment a,b"][..],
            &["Payment a", "Payment b"],
            &["Bearer abc"],
        ] {
            let selected = select(&[("Authorization", authorization)], &[]).unwrap();
            assert!(selected.is_empty(), "{authorization:?}");
        }
    }

    #[test]
    fn oversized_payment_authorization_and_header_count_are_denied() {
        let long = format!("Payment {}", "a".repeat(8_192));
        assert_eq!(
            select(&[("Authorization", &[long.as_str()])], &[])
                .unwrap_err()
                .code(),
            crate::Code::PermissionDenied
        );
        // Over eight selected headers: three defaults plus six extras.
        let names: Vec<String> = (0..6).map(|i| format!("X-E{i}")).collect();
        let pairs: Vec<(&str, &[&str])> = ["Payment-Authorization", "PAYMENT-SIGNATURE"]
            .into_iter()
            .chain(names.iter().map(String::as_str))
            .map(|n| (n, &["v"][..]))
            .chain([("Authorization", &["Payment abc"][..])])
            .collect();
        assert_eq!(
            select(&pairs, &names).unwrap_err().code(),
            crate::Code::PermissionDenied
        );
    }
}
