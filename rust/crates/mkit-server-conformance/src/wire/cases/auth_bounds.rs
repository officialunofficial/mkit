//! Auth v2 field and window bounds, each from an explicit SPEC-TRANSPORT-CONNECT
//! §7.1 MUST:
//!
//! - the nonce is "64 lowercase hexadecimal characters" (a canonical field);
//! - the signature is "strict Ed25519";
//! - "sender clocks may lead the server by at most 30,000 ms".
//!
//! Not asserted, because §7.1 does not state it: lowercase hex in
//! `X-Public-Key` and `X-Signature` (mkit-core rejects uppercase; the spec
//! names neither header's encoding).
// TODO(spec pass): add `auth.v2_key_and_signature_hex_lowercase` once the
// spec defines the header encodings.
//
// The clock-lead case assumes the suite's clock is within about 5 s of the
// server's (it signs 20 s and 40 s ahead of its own clock).

use mkit_core::hash::from_hex;
use mkit_transport_connect::generated::UpdateRefResponse;

use super::auth::{UNAUTH, rejected, signed_main};
use super::{A, CaseResult, Ctx, Exp, sign_unary, update_req, want_code, want_ok};
use crate::wire::client::Rpc;
use crate::wire::sign::now_ms;

pub(super) async fn v2_nonce_not_canonical(ctx: Ctx) -> CaseResult {
    let signer = ctx.v2_signer("main")?;
    let good = crate::wire::profile::random_hex::<32>();
    let nonces = [
        ("an uppercase nonce", good.to_ascii_uppercase()),
        ("a 63-character nonce", good[..63].to_owned()),
        ("a 65-character nonce", format!("{good}0")),
        ("a non-hex nonce", format!("{}g", &good[..63])),
    ];
    for (what, nonce) in nonces {
        let op = signed_main(&ctx, &signer, |env| env.nonce = nonce);
        rejected(&ctx, &op, what).await?;
    }
    Ok(())
}

/// The Ed25519 group order ℓ, little-endian.
const ELL: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];

/// `sig` with `S` replaced by `S + ℓ`: the same point equation, but a
/// non-canonical scalar that strict verification rejects.
fn malleate(sig: &[u8; 64]) -> [u8; 64] {
    let mut out = *sig;
    let mut carry = 0u16;
    for (i, l) in ELL.iter().enumerate() {
        let sum = u16::from(sig[32 + i]) + u16::from(*l) + carry;
        out[32 + i] = sum.to_le_bytes()[0];
        carry = sum >> 8;
    }
    out
}

pub(super) async fn v2_signature_not_strict(ctx: Ctx) -> CaseResult {
    let signer = ctx.v2_signer("main")?;
    let op = signed_main(&ctx, &signer, |_| {});
    let hex = op.header("x-signature");
    let sig: [u8; 64] = decode64(hex).ok_or("suite bug: signature is not 64 hex bytes")?;
    let non_canonical = mkit_core::hash::to_hex_bytes(&malleate(&sig));
    rejected(
        &ctx,
        &op.clone().with_header("x-signature", non_canonical),
        "a signature with S + ℓ",
    )
    .await?;
    // The original still verifies: the rejection was the scalar's.
    want_ok(
        ctx.send::<UpdateRefResponse>(&op).await?,
        "the canonical signature",
    )?;
    Ok(())
}

fn decode64(hex: &str) -> Option<[u8; 64]> {
    let (a, b) = (
        from_hex(hex.get(..64)?).ok()?,
        from_hex(hex.get(64..)?).ok()?,
    );
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&a);
    out[32..].copy_from_slice(&b);
    Some(out)
}

pub(super) async fn v2_clock_lead_bound(ctx: Ctx) -> CaseResult {
    let signer = ctx.v2_signer("main")?;
    let at = |lead_ms: i64, leaf: &str| {
        let req = update_req(&ctx.head(leaf), Exp::Missing, &A);
        sign_unary(&signer, Rpc::UpdateRef, &req, |env| {
            env.created_at = now_ms() + lead_ms;
            env.expires_at = env.created_at + 60_000;
        })
    };
    let beyond = at(40_000, "beyond");
    want_code(
        ctx.send::<UpdateRefResponse>(&beyond).await?,
        UNAUTH,
        "created 40 s ahead",
    )?;
    ctx.expect_ref(&ctx.head("beyond"), None).await?;
    let within = at(20_000, "within");
    want_ok(
        ctx.send::<UpdateRefResponse>(&within).await?,
        "created 20 s ahead",
    )?;
    ctx.expect_ref(&ctx.head("within"), Some(&A)).await
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signature, Signer as _, SigningKey};

    use super::*;

    #[test]
    fn malleated_signature_fails_strict_verification_only_by_its_scalar() {
        let key = SigningKey::from_bytes(&[3; 32]);
        let sig = key.sign(b"m").to_bytes();
        let bad = malleate(&sig);
        assert_ne!(bad, sig);
        assert_eq!(bad[..32], sig[..32], "R unchanged");
        let vk = key.verifying_key();
        assert!(vk.verify_strict(b"m", &Signature::from_bytes(&sig)).is_ok());
        assert!(
            vk.verify_strict(b"m", &Signature::from_bytes(&bad))
                .is_err()
        );
    }
}
