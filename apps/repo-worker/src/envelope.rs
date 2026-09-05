// SPDX-License-Identifier: MIT OR Apache-2.0
//! Auth v2 adapter. Verification is shared with the native transport; there is
//! no fallback to a destination-free or content-free signature contract.

pub use mkit_core::write_auth::{Authorized, Context, Headers as EnvelopeHeaders};
pub const FRESHNESS_WINDOW_MS: i64 = mkit_core::write_auth::MAX_VALIDITY_MS;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyEnvelope {
    Ok {
        public_key: String,
        body_digest: String,
        idempotency_key: String,
        authorization: Authorized,
    },
    Err {
        status: u16,
        error: &'static str,
    },
}

pub fn verify_envelope(
    context: Context<'_>,
    procedure: &str,
    actual_body_digest: &str,
    now: i64,
    headers: &EnvelopeHeaders,
) -> VerifyEnvelope {
    verify(
        context,
        procedure,
        Some(&format!("body:{actual_body_digest}")),
        now,
        headers,
    )
}

pub fn verify_stream_envelope(
    context: Context<'_>,
    procedure: &str,
    now: i64,
    headers: &EnvelopeHeaders,
) -> VerifyEnvelope {
    verify(context, procedure, None, now, headers)
}

fn verify(
    context: Context<'_>,
    procedure: &str,
    commitment: Option<&str>,
    now: i64,
    headers: &EnvelopeHeaders,
) -> VerifyEnvelope {
    match mkit_core::write_auth::verify_headers(context, procedure, commitment, now, headers) {
        Ok(authorization) => VerifyEnvelope::Ok {
            public_key: authorization.public_key.clone(),
            body_digest: headers.digest.clone().unwrap_or_default(),
            idempotency_key: authorization.nonce.clone(),
            authorization,
        },
        Err(error) => VerifyEnvelope::Err {
            status: 401,
            error: error.0,
        },
    }
}
