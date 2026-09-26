//! Signed `secp256k1-eip191` and `webauthn-p256` golden vectors for the
//! verifier (SPEC-WRITE-GRANTS §4, §4.1, §4.3, §4.4, §7):
//!
//! * `secp256k1-eip191.json`: a grant, an epoch statement and a visibility
//!   statement signed by the web3.js documented key (RFC 6979, low-S), each
//!   with fields, id, EIP-191 digest, the 65-byte blob, the header and its
//!   contexts;
//! * `webauthn-p256.json`: the same three statements and three client-data
//!   shape variants asserted by the RFC 6979 §A.2.5 P-256 key for the
//!   configured relying parties, each with `authenticatorData`,
//!   `clientDataJSON`, the raw low-S signature, the blob and the header;
//! * `reject/verify-secp256k1-*.json`, `reject/verify-webauthn-*.json`: one
//!   §4 / §4.3 / §4.4 failure each, re-signed so that only that rule fails.
//!
//! `scripts/golden/grants_ref.py` re-signs every accept vector with
//! python-`ecdsa` (secp256k1, RFC 6979) and pycryptodome (P-256, RFC 6979),
//! both deterministic, so blobs and headers are equal, and re-runs every
//! context and reject through its own verifier written from the spec.

use k256::ecdsa::SigningKey as K1Key;
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::point::AffineCoordinates;
use mkit_attest::eth;
use mkit_attest::grant::{
    AcceptedSchemes, Capability, EpochStatement, GrantRequest, MAX_CLIENT_DATA_DEPTH, RelyingParty,
    VerifierConfig, Visibility, VisibilityStatement, WebAuthnAssertion, verify_epoch_statement,
    verify_grant_owner, verify_visibility_statement, webauthn_challenge,
};
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256Key};
use sha2::{Digest, Sha256};

use super::signed::{GrantContext, epoch_fields, grant_context_json, identity, visibility_fields};
use super::*;

const AUDIENCE: &str = "https://git.example.com";
const CREATED: i64 = 1_790_000_000_000;
const DAY_MS: i64 = 86_400_000;
const HOUR_MS: i64 = 3_600_000;
/// The web3.js documented key (also in `eth-primitives.json`).
const K1_OWNER: &str = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
const K1_OTHER: [u8; 32] = [0x22; 32];
/// The RFC 6979 §A.2.5 P-256 private key.
const P256_OWNER: &str = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";
const P256_OTHER: [u8; 32] = [0x44; 32];
const K1_N: &str = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
const P256_N: &str = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
/// `x = p` on P-256, whose reduction `x = 0` is on the curve with this `y`
/// (from `eth-primitives.json`).
const P256_X_EQ_P: &str = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff\
                           66485c780e2f83d72433bd5d84a06bb6541c2af31dae871728bf856a174f93f4";
const RP_ID: &str = "example.com";
const ORIGIN: &str = "https://example.com";
const WWW_ORIGIN: &str = "https://www.example.com";
const WALLET_RP_ID: &str = "wallet.example";
const WALLET_ORIGIN: &str = "https://wallet.example";
const K1_TOKEN: &str = "secp256k1-eip191";
const WA_TOKEN: &str = "webauthn-p256";

/// Whether a fixture path is one of this module's verify rejects.
pub(super) fn is_ecdsa_reject(path: &str) -> bool {
    path.starts_with("reject/verify-secp256k1-") || path.starts_with("reject/verify-webauthn-")
}

fn h<const N: usize>(s: &str) -> [u8; N] {
    hex::decode(s).unwrap().try_into().unwrap()
}

/// `n - s` for a 32-byte big-endian `s < n`.
fn neg(n: &[u8; 32], s: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let d = i16::from(n[i]) - i16::from(s[i]) - borrow;
        borrow = i16::from(d < 0);
        out[i] = (d + 256 * borrow).to_le_bytes()[0];
    }
    out
}

/// A secp256k1 `r ‖ s ‖ v` over `digest` whose SEC 1 recovery yields the
/// point at infinity: `R = kG`, `r = x(R)`, `s = e / k`, so
/// `r⁻¹(sR − eG) = O`. A verifier must refuse it (no key recovers).
#[allow(clippy::many_single_char_names)] // the ECDSA equation
fn k1_infinity_forgery(digest: &[u8; 32]) -> [u8; 65] {
    type S = k256::Scalar;
    let e = <S as Reduce<k256::FieldBytes>>::reduce(&(*digest).into());
    for k in 2u64..1000 {
        let k = S::from(k);
        let point = (k256::ProjectivePoint::GENERATOR * k).to_affine();
        let x = point.x();
        let r = <S as Reduce<k256::FieldBytes>>::reduce(&x);
        if r.to_bytes() != x {
            continue; // x >= n: r would not name R
        }
        let s = e * k.invert().unwrap();
        let mut out = [0u8; 65];
        out[..32].copy_from_slice(&r.to_bytes());
        out[32..64].copy_from_slice(&s.to_bytes());
        let sig = k256::ecdsa::Signature::from_slice(&out[..64]).unwrap();
        if sig.normalize_s() != sig {
            continue; // keep only low s, so the scalar checks pass
        }
        out[64] = 27 + u8::from(bool::from(point.y_is_odd()));
        return out;
    }
    unreachable!("some small k gives a low s")
}

/// A P-256 `r ‖ s` that verifies against the point at infinity for the
/// SHA-256 `digest`: `r = x(kG)`, `s = e / k`. Libraries that represent
/// the identity as `(0, 0)` accept it for the all-zero public key; a
/// verifier must refuse that key before it checks the signature.
#[allow(clippy::many_single_char_names)] // the ECDSA equation
fn p256_infinity_forgery(digest: &[u8; 32]) -> [u8; 64] {
    type S = p256::Scalar;
    let e = <S as Reduce<p256::FieldBytes>>::reduce(&(*digest).into());
    for k in 2u64..1000 {
        let k = S::from(k);
        let x = (p256::ProjectivePoint::GENERATOR * k).to_affine().x();
        let r = <S as Reduce<p256::FieldBytes>>::reduce(&x);
        let s = e * k.invert().unwrap();
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&r.to_bytes());
        out[32..].copy_from_slice(&s.to_bytes());
        if eth::p256_check_raw_low_s(&out).is_ok() {
            return out;
        }
    }
    unreachable!("some small k gives a low s")
}

fn relying_parties() -> Vec<RelyingParty> {
    vec![
        RelyingParty::new(RP_ID, [ORIGIN, WWW_ORIGIN]).unwrap(),
        RelyingParty::new(WALLET_RP_ID, [WALLET_ORIGIN]).unwrap(),
    ]
}

fn relying_parties_json() -> Value {
    relying_parties()
        .iter()
        .map(|rp| json!({ "id": rp.id(), "origins": rp.origins() }))
        .collect()
}

/// A configuration with the relying parties above (unused unless
/// `webauthn-p256` is accepted).
fn cfg(audience: &str, schemes: &[OwnerScheme]) -> VerifierConfig {
    VerifierConfig::new(audience, AcceptedSchemes::of(schemes), relying_parties()).unwrap()
}

fn signed_header(statement: &[u8], scheme: OwnerScheme, blob: Vec<u8>) -> String {
    SignedHeader {
        statement: statement.to_vec(),
        scheme,
        blob,
    }
    .encode()
    .unwrap()
}

// ---- keys ------------------------------------------------------------------

fn k1_key(secret: &[u8; 32]) -> K1Key {
    K1Key::from_slice(secret).unwrap()
}

fn k1_xy(key: &K1Key) -> [u8; 64] {
    key.verifying_key().to_sec1_point(false).as_bytes()[1..]
        .try_into()
        .unwrap()
}

fn k1_ns(key: &K1Key) -> Namespace {
    Namespace::Address(eth::address_secp256k1(&k1_xy(key)).unwrap())
}

fn p256_key(secret: &[u8; 32]) -> P256Key {
    P256Key::from_slice(secret).unwrap()
}

fn p256_xy(key: &P256Key) -> [u8; 64] {
    key.verifying_key().to_sec1_point(false).as_bytes()[1..]
        .try_into()
        .unwrap()
}

fn p256_ns(key: &P256Key) -> Namespace {
    Namespace::Address(eth::address_p256(&p256_xy(key)).unwrap())
}

fn k1_owner() -> K1Key {
    k1_key(&h(K1_OWNER))
}

fn p256_owner() -> P256Key {
    p256_key(&h(P256_OWNER))
}

// ---- signing -----------------------------------------------------------------

/// `r ‖ s ‖ v` over the EIP-191 digest, RFC 6979 and low-S (k256 normalizes).
fn eip191_blob(key: &K1Key, statement: &[u8]) -> [u8; 65] {
    let (sig, recid) = key.sign_prehash_recoverable(&eth::eip191_hash(statement));
    let mut out = [0u8; 65];
    out[..64].copy_from_slice(&sig.to_bytes());
    out[64] = 27 + recid.to_byte();
    out
}

fn authenticator_data(rp_id: &str, flags: u8, extra: &[u8]) -> Vec<u8> {
    let mut out = Sha256::digest(rp_id.as_bytes()).to_vec();
    out.push(flags);
    out.extend_from_slice(&42u32.to_be_bytes());
    out.extend_from_slice(extra);
    out
}

/// The client data a browser writes for a same-origin `get`.
fn client_data(challenge: &str, origin: &str) -> String {
    format!(
        r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"{origin}","crossOrigin":false}}"#
    )
}

/// RFC 6979 P-256 over `auth ‖ SHA-256(client data)`, normalized to low-S
/// as §4.4 requires of the client (the `p256` crate does not normalize).
fn p256_sign(key: &P256Key, auth: &[u8], client_data: &[u8]) -> [u8; 64] {
    let signed = [auth, &Sha256::digest(client_data)[..]].concat();
    let sig: P256Signature = key.sign(&signed);
    sig.normalize_s().to_bytes().into()
}

fn assertion(key: &P256Key, auth: Vec<u8>, client_data: &str) -> WebAuthnAssertion {
    WebAuthnAssertion {
        signature: p256_sign(key, &auth, client_data.as_bytes()),
        public_key: p256_xy(key),
        authenticator_data: auth,
        client_data_json: client_data.as_bytes().to_vec(),
    }
}

// ---- statements ----------------------------------------------------------------

fn grant_for(ns: Namespace, nonce: u8) -> Grant {
    Grant {
        namespace: ns,
        scope: repo(ns, "website"),
        grantee: grantee(),
        capabilities: Capabilities::ReadWrite,
        audiences: texts(&[AUDIENCE, "https://git.example.org"]),
        ref_scopes: Some(scopes(&texts(&[
            "refs/heads/main=cu",
            "refs/heads/wip/*=cufd",
        ]))),
        epoch: 0,
        created_ms: CREATED,
        expiry_ms: CREATED + DAY_MS,
        nonce: [nonce; 32],
    }
}

fn epoch_for(ns: Namespace, nonce: u8) -> EpochStatement {
    EpochStatement {
        namespace: ns,
        new_epoch: 1,
        audiences: texts(&[AUDIENCE]),
        created_ms: CREATED,
        expiry_ms: CREATED + HOUR_MS,
        nonce: [nonce; 32],
    }
}

fn visibility_for(ns: Namespace, nonce: u8) -> VisibilityStatement {
    VisibilityStatement {
        repository: RepositoryIdentity::new(Some(ns), "website").unwrap(),
        visibility: Visibility::Private,
        audiences: texts(&[AUDIENCE]),
        created_ms: CREATED,
        expiry_ms: CREATED + HOUR_MS,
        nonce: [nonce; 32],
    }
}

/// One statement kind with its canonical bytes and fields.
#[derive(Clone)]
enum Statement {
    Grant(Grant),
    Epoch(EpochStatement),
    Visibility(VisibilityStatement),
}

impl Statement {
    fn kind(&self) -> &'static str {
        match self {
            Self::Grant(_) => "grant",
            Self::Epoch(_) => "epoch",
            Self::Visibility(_) => "visibility",
        }
    }

    fn bytes(&self) -> Vec<u8> {
        match self {
            Self::Grant(g) => g.encode().unwrap(),
            Self::Epoch(e) => e.encode().unwrap(),
            Self::Visibility(v) => v.encode().unwrap(),
        }
    }

    fn fields(&self) -> Value {
        match self {
            Self::Grant(g) => fields_json(g),
            Self::Epoch(e) => epoch_fields(e),
            Self::Visibility(v) => visibility_fields(v),
        }
    }
}

// ---- contexts --------------------------------------------------------------------

/// A per-request context and its expected error, by statement kind.
enum Context {
    Grant(GrantContext, Option<GrantError>),
    /// `(name, audience, now)`.
    Epoch(&'static str, &'static str, i64, Option<GrantError>),
    /// `(name, audience, repository, now)`.
    Visibility(&'static str, &'static str, String, i64, Option<GrantError>),
}

fn grant_contexts(ns: Namespace) -> Vec<Context> {
    let site = format!("{ns}/website");
    let (w, r) = (Capability::Write, Capability::Read);
    let g = grantee();
    vec![
        Context::Grant(
            ("write-at-created", AUDIENCE, site.clone(), g, w, CREATED),
            None,
        ),
        Context::Grant(
            (
                "read-last-ms",
                AUDIENCE,
                site.clone(),
                g,
                r,
                CREATED + DAY_MS - 1,
            ),
            None,
        ),
        Context::Grant(
            ("at-expiry", AUDIENCE, site.clone(), g, w, CREATED + DAY_MS),
            Some(GrantError::Expired),
        ),
        Context::Grant(
            (
                "other-namespace",
                AUDIENCE,
                format!("{}/website", key_ns()),
                g,
                w,
                CREATED,
            ),
            Some(GrantError::NamespaceMismatch),
        ),
        Context::Grant(
            (
                "audience-not-listed",
                "https://git.example.net",
                site.clone(),
                g,
                w,
                CREATED,
            ),
            Some(GrantError::AudienceNotListed),
        ),
        Context::Grant(
            ("grantee-mismatch", AUDIENCE, site, [1; 32], w, CREATED),
            Some(GrantError::GranteeMismatch),
        ),
    ]
}

fn accept_only(ns: Namespace) -> Vec<Context> {
    vec![Context::Grant(
        (
            "write-at-created",
            AUDIENCE,
            format!("{ns}/website"),
            grantee(),
            Capability::Write,
            CREATED,
        ),
        None,
    )]
}

fn epoch_contexts() -> Vec<Context> {
    vec![
        Context::Epoch("at-created", AUDIENCE, CREATED, None),
        Context::Epoch(
            "at-expiry",
            AUDIENCE,
            CREATED + HOUR_MS,
            Some(GrantError::Expired),
        ),
        Context::Epoch(
            "audience-not-listed",
            "https://git.example.org",
            CREATED,
            Some(GrantError::AudienceNotListed),
        ),
    ]
}

fn visibility_contexts(ns: Namespace) -> Vec<Context> {
    vec![
        Context::Visibility(
            "at-created",
            AUDIENCE,
            format!("{ns}/website"),
            CREATED,
            None,
        ),
        Context::Visibility(
            "other-repository",
            AUDIENCE,
            format!("{ns}/blog"),
            CREATED,
            Some(GrantError::RepositoryMismatch),
        ),
    ]
}

fn run_grant(cfg: &VerifierConfig, header: &str, ctx: &GrantContext) -> Result<(), GrantError> {
    let (_, _, repository, signer, capability, now) = ctx;
    let repository = identity(repository);
    verify_grant_owner(cfg, header)?
        .check(
            cfg,
            &GrantRequest {
                repository: &repository,
                signer,
                capability: *capability,
                now_ms: *now,
            },
        )
        .map(|_| ())
}

fn run_context(schemes: &[OwnerScheme], header: &str, ctx: &Context) -> Result<(), GrantError> {
    match ctx {
        Context::Grant(c, _) => run_grant(&cfg(c.1, schemes), header, c),
        Context::Epoch(_, audience, now, _) => {
            verify_epoch_statement(&cfg(audience, schemes), header, *now).map(|_| ())
        }
        Context::Visibility(_, audience, repository, now, _) => verify_visibility_statement(
            &cfg(audience, schemes),
            header,
            &identity(repository),
            *now,
        )
        .map(|_| ()),
    }
}

fn expected(ctx: &Context) -> Option<GrantError> {
    match ctx {
        Context::Grant(_, e) | Context::Epoch(.., e) | Context::Visibility(.., e) => *e,
    }
}

fn context_json(ctx: &Context) -> Value {
    let mut v = match ctx {
        Context::Grant(c, _) => grant_context_json(c, None),
        Context::Epoch(name, audience, now, _) => {
            json!({ "name": name, "audience": audience, "now": now })
        }
        Context::Visibility(name, audience, repository, now, _) => {
            json!({ "name": name, "audience": audience, "repository": repository, "now": now })
        }
    };
    v["expected_error"] = json!(expected(ctx).map(GrantError::reason));
    v
}

// ---- vectors ----------------------------------------------------------------------

/// One signed vector: the statement, its blob, the scheme-specific fields
/// of the fixture, and its contexts.
struct Vector {
    name: &'static str,
    statement: Statement,
    scheme: OwnerScheme,
    blob: Vec<u8>,
    extra: Value,
    contexts: Vec<Context>,
}

impl Vector {
    fn header(&self) -> String {
        signed_header(&self.statement.bytes(), self.scheme, self.blob.clone())
    }

    fn json(&self) -> Value {
        let bytes = self.statement.bytes();
        let mut v = json!({
            "kind": self.statement.kind(),
            "name": self.name,
            "fields": self.statement.fields(),
            "statement": String::from_utf8(bytes.clone()).unwrap(),
            "id": hex(blake3::hash(&bytes).as_bytes()),
        });
        for (k, x) in self.extra.as_object().unwrap() {
            v[k] = x.clone();
        }
        v["blob_hex"] = json!(hex(&self.blob));
        v["header"] = json!(self.header());
        v["contexts"] = self.contexts.iter().map(context_json).collect();
        v
    }
}

fn k1_vector(name: &'static str, statement: Statement, contexts: Vec<Context>) -> Vector {
    let bytes = statement.bytes();
    Vector {
        name,
        blob: eip191_blob(&k1_owner(), &bytes).to_vec(),
        extra: json!({ "eip191_digest": hex(&eth::eip191_hash(&bytes)) }),
        scheme: OwnerScheme::Secp256k1Eip191,
        statement,
        contexts,
    }
}

fn k1_vectors() -> Vec<Vector> {
    let ns = k1_ns(&k1_owner());
    vec![
        k1_vector(
            "grant-read-write",
            Statement::Grant(grant_for(ns, 0xa1)),
            grant_contexts(ns),
        ),
        k1_vector(
            "epoch-1",
            Statement::Epoch(epoch_for(ns, 0xa2)),
            epoch_contexts(),
        ),
        k1_vector(
            "visibility-private",
            Statement::Visibility(visibility_for(ns, 0xa3)),
            visibility_contexts(ns),
        ),
    ]
}

/// A client data builder: `(challenge, origin) -> clientDataJSON`.
type ClientDataFn = fn(&str, &str) -> String;

fn wa_vector(
    name: &'static str,
    statement: Statement,
    (rp_id, origin, flags, extra_auth): (&str, &str, u8, &[u8]),
    client_data_fn: ClientDataFn,
    contexts: Vec<Context>,
) -> Vector {
    let bytes = statement.bytes();
    let challenge = webauthn_challenge(&bytes);
    let cd = client_data_fn(&challenge, origin);
    let a = assertion(
        &p256_owner(),
        authenticator_data(rp_id, flags, extra_auth),
        &cd,
    );
    Vector {
        name,
        blob: a.encode().unwrap(),
        extra: json!({
            "rp_id": rp_id,
            "challenge": challenge,
            "authenticator_data_hex": hex(&a.authenticator_data),
            "client_data_json": cd,
            "signature_hex": hex(&a.signature),
        }),
        scheme: OwnerScheme::WebAuthnP256,
        statement,
        contexts,
    }
}

fn wa_vectors() -> Vec<Vector> {
    let ns = p256_ns(&p256_owner());
    let grant = Statement::Grant(grant_for(ns, 0xb1));
    vec![
        wa_vector(
            "grant-read-write",
            grant.clone(),
            (RP_ID, ORIGIN, 0x05, &[]),
            client_data,
            grant_contexts(ns),
        ),
        wa_vector(
            "epoch-1-wallet-rp-no-cross-origin",
            Statement::Epoch(epoch_for(ns, 0xb2)),
            (WALLET_RP_ID, WALLET_ORIGIN, 0x01, &[]),
            |c, o| format!(r#"{{"type":"webauthn.get","challenge":"{c}","origin":"{o}"}}"#),
            epoch_contexts(),
        ),
        wa_vector(
            "visibility-private-second-origin",
            Statement::Visibility(visibility_for(ns, 0xb3)),
            (RP_ID, WWW_ORIGIN, 0x01, &[]),
            client_data,
            visibility_contexts(ns),
        ),
        wa_vector(
            "grant-client-data-escaped",
            grant.clone(),
            (RP_ID, ORIGIN, 0x01, &[]),
            |c, _| {
                format!(
                    r#"{{"type":"webauthn.get","challenge":"{c}","origin":"https:\/\/example.com"}}"#
                )
            },
            accept_only(ns),
        ),
        wa_vector(
            "grant-client-data-extra-members",
            grant.clone(),
            (RP_ID, ORIGIN, 0x01, &[]),
            |c, o| {
                format!(
                    r#"{{"type":"webauthn.get","challenge":"{c}","origin":"{o}","crossOrigin":false,"other_keys_can_be_added_here":"do not compare clientDataJSON against a template. See https://goo.gl/yabPex","x":[1,-2.5e3,{{"a":null,"b":[true]}}]}}"#
                )
            },
            accept_only(ns),
        ),
        wa_vector(
            "grant-authenticator-data-extensions",
            grant,
            // UP, UV, BE, BS and ED, then a CBOR extension map {"credProtect": 2}.
            (
                RP_ID,
                ORIGIN,
                0x9d,
                &[
                    0xa1, 0x6b, b'c', b'r', b'e', b'd', b'P', b'r', b'o', b't', b'e', b'c', b't',
                    0x02,
                ],
            ),
            client_data,
            accept_only(ns),
        ),
        wa_vector(
            "grant-client-data-at-limits",
            // Nested exactly MAX_CLIENT_DATA_DEPTH deep (the top-level object
            // is depth 1), with the largest finite binary64 and an underflow.
            Statement::Grant(grant_for(ns, 0xb1)),
            (RP_ID, ORIGIN, 0x01, &[]),
            |c, o| {
                let depth = MAX_CLIENT_DATA_DEPTH - 1;
                format!(
                    r#"{{"type":"webauthn.get","challenge":"{c}","origin":"{o}","n":[1.7976931348623157e308,-1e-400,123456789012345678901234567890],"x":{}{{}}{}}}"#,
                    "[".repeat(depth - 1),
                    "]".repeat(depth - 1)
                )
            },
            accept_only(ns),
        ),
    ]
}

fn scheme_file(scheme: OwnerScheme, vectors: &[Vector], owner: Value) -> Value {
    let mut file = owner;
    file["spec"] = json!("SPEC-WRITE-GRANTS §4, §4.1, §4.3, §4.4, §7");
    file["scheme"] = json!(scheme.token());
    file["accepted_schemes"] = json!([scheme.token()]);
    file["relying_parties"] = relying_parties_json();
    file["vectors"] = vectors.iter().map(Vector::json).collect();
    file
}

fn k1_file() -> Value {
    let key = k1_owner();
    let xy = k1_xy(&key);
    scheme_file(
        OwnerScheme::Secp256k1Eip191,
        &k1_vectors(),
        json!({
            "owner_private_key": K1_OWNER,
            "owner_x": hex(&xy[..32]),
            "owner_y": hex(&xy[32..]),
            "namespace": k1_ns(&key).to_string(),
        }),
    )
}

fn wa_file() -> Value {
    let key = p256_owner();
    let xy = p256_xy(&key);
    scheme_file(
        OwnerScheme::WebAuthnP256,
        &wa_vectors(),
        json!({
            "owner_private_key": P256_OWNER,
            "owner_x": hex(&xy[..32]),
            "owner_y": hex(&xy[32..]),
            "namespace": p256_ns(&key).to_string(),
        }),
    )
}

// ---- verify rejects --------------------------------------------------------------

/// `(file stem, rule, accepted schemes, header, context, expected error)`.
type Reject = (
    &'static str,
    &'static str,
    Vec<OwnerScheme>,
    String,
    GrantContext,
    GrantError,
);

fn write_ctx(ns: Namespace) -> GrantContext {
    (
        "",
        AUDIENCE,
        format!("{ns}/website"),
        grantee(),
        Capability::Write,
        CREATED,
    )
}

#[allow(clippy::too_many_lines)] // a data table
fn k1_rejects() -> Vec<Reject> {
    let key = k1_owner();
    let ns = k1_ns(&key);
    let g = grant_for(ns, 0xa1);
    let bytes = g.encode().unwrap();
    let sig = eip191_blob(&key, &bytes);
    let k1 = vec![OwnerScheme::Secp256k1Eip191];
    let with = |blob: &[u8]| signed_header(&bytes, OwnerScheme::Secp256k1Eip191, blob.to_vec());
    let edit = |at: usize, value: &[u8]| {
        let mut b = sig;
        b[at..at + value.len()].copy_from_slice(value);
        with(&b)
    };
    let n: [u8; 32] = h(K1_N);
    let mut high = sig;
    high[32..64].copy_from_slice(&neg(&n, &sig[32..64]));
    high[64] = if sig[64] == 27 { 28 } else { 27 };
    // The smallest `r` that is no secp256k1 x-coordinate.
    let mut r = [0u8; 32];
    r[31] = (1u8..=255)
        .find(|i| {
            let mut sec1 = [2u8; 33];
            sec1[32] = *i;
            sec1[1..32].fill(0);
            k256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).is_err()
        })
        .unwrap();
    // The ed25519 owner's grant, signed by this key under the ECDSA scheme.
    let ed_grant = grant_for(key_ns(), 0xa1).encode().unwrap();
    let other = k1_key(&K1_OTHER);
    vec![
        (
            "verify-secp256k1-high-s",
            "§4.4: s > n/2 is rejected, never normalized (the owner's signature with n - s and v flipped)",
            k1.clone(),
            with(&high),
            write_ctx(ns),
            GrantError::HighS,
        ),
        (
            "verify-secp256k1-v-0",
            "§4: v is 27 or 28 (a wallet's v = 0 is the client's to fix)",
            k1.clone(),
            edit(64, &[0]),
            write_ctx(ns),
            GrantError::SignatureRecoveryId,
        ),
        (
            "verify-secp256k1-v-29",
            "§4: v is 27 or 28",
            k1.clone(),
            edit(64, &[29]),
            write_ctx(ns),
            GrantError::SignatureRecoveryId,
        ),
        (
            "verify-secp256k1-s-zero",
            "§4.4: s in [1, n - 1]",
            k1.clone(),
            edit(32, &[0; 32]),
            write_ctx(ns),
            GrantError::SignatureScalar,
        ),
        (
            "verify-secp256k1-r-n",
            "§4.4: r in [1, n - 1]",
            k1.clone(),
            edit(0, &n),
            write_ctx(ns),
            GrantError::SignatureScalar,
        ),
        (
            "verify-secp256k1-r-not-x-coordinate",
            "§4: no key recovers when r is not the x-coordinate of a curve point",
            k1.clone(),
            edit(0, &r),
            write_ctx(ns),
            GrantError::BadSignature,
        ),
        (
            "verify-secp256k1-other-owner",
            "§4, §7 step 4: the recovered address is not the namespace (signed by another key)",
            k1.clone(),
            with(&eip191_blob(&other, &bytes)),
            write_ctx(ns),
            GrantError::OwnerMismatch,
        ),
        (
            "verify-secp256k1-64-byte-blob",
            "§4: a secp256k1-eip191 blob is exactly r || s || v (65 bytes)",
            k1.clone(),
            with(&sig[..64]),
            write_ctx(ns),
            GrantError::SignatureLength,
        ),
        (
            "verify-secp256k1-ed25519-namespace",
            "§4: secp256k1-eip191 is valid only for a 0x namespace",
            k1.clone(),
            signed_header(
                &ed_grant,
                OwnerScheme::Secp256k1Eip191,
                eip191_blob(&key, &ed_grant).to_vec(),
            ),
            write_ctx(key_ns()),
            GrantError::SchemeNamespaceMismatch,
        ),
        (
            "verify-secp256k1-recovers-infinity",
            "§4, §4.1: no key recovers when s·R = e·G (R = kG, r = x(R), s = e/k gives the point \
             at infinity, which is no public key)",
            k1.clone(),
            with(&k1_infinity_forgery(&eth::eip191_hash(&bytes))),
            write_ctx(ns),
            GrantError::BadSignature,
        ),
        (
            "verify-secp256k1-not-advertised",
            "§4, §7 step 3: a scheme the deployment does not advertise fails",
            vec![OwnerScheme::Ed25519, OwnerScheme::WebAuthnP256],
            with(&sig),
            write_ctx(ns),
            GrantError::SchemeNotAdvertised,
        ),
    ]
}

#[allow(clippy::too_many_lines)] // a data table
fn wa_rejects() -> Vec<Reject> {
    let key = p256_owner();
    let ns = p256_ns(&key);
    let g = grant_for(ns, 0xb1);
    let bytes = g.encode().unwrap();
    let c = webauthn_challenge(&bytes);
    let wa = vec![OwnerScheme::WebAuthnP256];
    let good_cd = client_data(&c, ORIGIN);
    let good = assertion(&key, authenticator_data(RP_ID, 0x01, &[]), &good_cd);
    let header = |a: &WebAuthnAssertion| {
        signed_header(&bytes, OwnerScheme::WebAuthnP256, a.encode().unwrap())
    };
    let signed_cd = |cd: &str| {
        header(&assertion(
            &key,
            authenticator_data(RP_ID, 0x01, &[]),
            &cd.replace("CH", &c).replace("OR", ORIGIN),
        ))
    };
    let n: [u8; 32] = h(P256_N);
    let mut high = good.clone();
    high.signature[32..].copy_from_slice(&neg(&n, &good.signature[32..]));
    let mut s_zero = good.clone();
    s_zero.signature[32..].fill(0);
    let mut off_curve = good.clone();
    off_curve.public_key[63] ^= 1;
    let mut x_eq_p = good.clone();
    x_eq_p.public_key = h(P256_X_EQ_P);
    let other = p256_key(&P256_OTHER);
    let theirs = assertion(&other, authenticator_data(RP_ID, 0x01, &[]), &good_cd);
    let mut forged = good.clone();
    forged.signature = theirs.signature;
    let mut reserialized = good.clone();
    reserialized.signature = p256_sign(
        &key,
        &good.authenticator_data,
        good_cd.replace(':', ": ").as_bytes(),
    );
    let mut trailing = good.encode().unwrap();
    trailing.push(0);
    let ed_grant = grant_for(key_ns(), 0xb1).encode().unwrap();
    // The all-zero key (x = y = 0: pycryptodome's encoding of the point at
    // infinity) owning its own namespace, with a signature that verifies
    // against the point at infinity.
    let zero_ns = Namespace::Address(eth::keccak256(&[0; 64])[12..].try_into().unwrap());
    let zero_bytes = grant_for(zero_ns, 0xb4).encode().unwrap();
    let zero_cd = client_data(&webauthn_challenge(&zero_bytes), ORIGIN);
    let zero_auth = authenticator_data(RP_ID, 0x01, &[]);
    let zero_digest: [u8; 32] =
        Sha256::digest([&zero_auth[..], &Sha256::digest(zero_cd.as_bytes())[..]].concat()).into();
    let zero_key = WebAuthnAssertion {
        public_key: [0; 64],
        signature: p256_infinity_forgery(&zero_digest),
        authenticator_data: zero_auth,
        client_data_json: zero_cd.into_bytes(),
    };
    let depth = MAX_CLIENT_DATA_DEPTH;
    let too_deep = format!(
        r#"{{"type":"webauthn.get","challenge":"CH","origin":"OR","x":{}{{}}{}}}"#,
        "[".repeat(depth - 1),
        "]".repeat(depth - 1)
    );
    vec![
        (
            "verify-webauthn-key-zero",
            "§4.1: the public key is a valid P-256 point; x = y = 0 is not (some libraries encode \
             the point at infinity so, and this signature verifies against infinity)",
            wa.clone(),
            signed_header(
                &zero_bytes,
                OwnerScheme::WebAuthnP256,
                zero_key.encode().unwrap(),
            ),
            write_ctx(zero_ns),
            GrantError::InvalidOwnerKey,
        ),
        (
            "verify-webauthn-client-data-too-deep",
            "§4.3 rule 2: clientDataJSON nests at most 64 deep (here 65: the top-level object is 1)",
            wa.clone(),
            signed_cd(&too_deep),
            write_ctx(ns),
            GrantError::ClientData,
        ),
        (
            "verify-webauthn-client-data-number-overflow",
            "§4.3 rule 2: every number is finite as an IEEE 754 binary64 value (1e400 is not)",
            wa.clone(),
            signed_cd(r#"{"type":"webauthn.get","challenge":"CH","origin":"OR","x":1e400}"#),
            write_ctx(ns),
            GrantError::ClientData,
        ),
        (
            "verify-webauthn-high-s",
            "§4.4: s > n/2 is rejected, never normalized (the owner's signature with n - s)",
            wa.clone(),
            header(&high),
            write_ctx(ns),
            GrantError::HighS,
        ),
        (
            "verify-webauthn-s-zero",
            "§4.4: s in [1, n - 1]",
            wa.clone(),
            header(&s_zero),
            write_ctx(ns),
            GrantError::SignatureScalar,
        ),
        (
            "verify-webauthn-key-off-curve",
            "§4.1: the public key is a valid P-256 point (y flipped in its last bit)",
            wa.clone(),
            header(&off_curve),
            write_ctx(ns),
            GrantError::InvalidOwnerKey,
        ),
        (
            "verify-webauthn-key-x-equals-p",
            "§4.1: the public key is a valid P-256 point (x = p, whose reduction 0 is on the curve)",
            wa.clone(),
            header(&x_eq_p),
            write_ctx(ns),
            GrantError::InvalidOwnerKey,
        ),
        (
            "verify-webauthn-other-owner",
            "§4, §7 step 4: the public key's address is not the namespace (another key's valid assertion)",
            wa.clone(),
            header(&theirs),
            write_ctx(ns),
            GrantError::OwnerMismatch,
        ),
        (
            "verify-webauthn-authenticator-data-36-bytes",
            "§4.3 rule 1: authenticatorData is at least 37 bytes",
            wa.clone(),
            header(&assertion(
                &key,
                authenticator_data(RP_ID, 0x01, &[])[..36].to_vec(),
                &good_cd,
            )),
            write_ctx(ns),
            GrantError::AuthenticatorData,
        ),
        (
            "verify-webauthn-user-not-present",
            "§4.3 rule 1: the user-present flag is set (UV alone does not count), re-signed",
            wa.clone(),
            header(&assertion(
                &key,
                authenticator_data(RP_ID, 0x04, &[]),
                &good_cd,
            )),
            write_ctx(ns),
            GrantError::UserNotPresent,
        ),
        (
            "verify-webauthn-relying-party-not-configured",
            "§4.3 rule 4: the rpIdHash is the SHA-256 of a configured relying party id",
            wa.clone(),
            header(&assertion(
                &key,
                authenticator_data("evil.example", 0x01, &[]),
                &good_cd,
            )),
            write_ctx(ns),
            GrantError::RelyingPartyMismatch,
        ),
        (
            "verify-webauthn-origin-not-configured",
            "§4.3 rule 4: origin is a configured origin, byte for byte",
            wa.clone(),
            signed_cd(&client_data("CH", "https://evil.example")),
            write_ctx(ns),
            GrantError::OriginNotAllowed,
        ),
        (
            "verify-webauthn-origin-of-other-relying-party",
            "§4.3 rule 4: origin is configured for the relying party whose id hash matched",
            wa.clone(),
            signed_cd(&client_data("CH", WALLET_ORIGIN)),
            write_ctx(ns),
            GrantError::OriginNotAllowed,
        ),
        (
            "verify-webauthn-type-create",
            "§4.3 rule 2: type is the string webauthn.get",
            wa.clone(),
            signed_cd(r#"{"type":"webauthn.create","challenge":"CH","origin":"OR"}"#),
            write_ctx(ns),
            GrantError::ClientDataType,
        ),
        (
            "verify-webauthn-challenge-other-statement",
            "§4.3 rule 2: challenge is the base64url BLAKE3 of this statement",
            wa.clone(),
            signed_cd(&client_data(
                &webauthn_challenge(b"another statement"),
                ORIGIN,
            )),
            write_ctx(ns),
            GrantError::Challenge,
        ),
        (
            "verify-webauthn-challenge-padded",
            "§4.3 rule 2: challenge is exactly 43 characters of unpadded base64url",
            wa.clone(),
            signed_cd(&client_data("CH=", ORIGIN)),
            write_ctx(ns),
            GrantError::Challenge,
        ),
        (
            "verify-webauthn-cross-origin-true",
            "§4.3 rule 2: crossOrigin, if present, is false",
            wa.clone(),
            signed_cd(
                r#"{"type":"webauthn.get","challenge":"CH","origin":"OR","crossOrigin":true}"#,
            ),
            write_ctx(ns),
            GrantError::CrossOrigin,
        ),
        (
            "verify-webauthn-cross-origin-string",
            "§4.3 rule 2: crossOrigin, if present, is the literal false (not the string)",
            wa.clone(),
            signed_cd(
                r#"{"type":"webauthn.get","challenge":"CH","origin":"OR","crossOrigin":"false"}"#,
            ),
            write_ctx(ns),
            GrantError::CrossOrigin,
        ),
        (
            "verify-webauthn-top-origin",
            "§4.3 rule 2: a topOrigin member is rejected",
            wa.clone(),
            signed_cd(
                r#"{"type":"webauthn.get","challenge":"CH","origin":"OR","crossOrigin":false,"topOrigin":"OR"}"#,
            ),
            write_ctx(ns),
            GrantError::TopOrigin,
        ),
        (
            "verify-webauthn-duplicate-member",
            "§4.3 rule 2: no duplicate member names (two origins)",
            wa.clone(),
            signed_cd(
                r#"{"type":"webauthn.get","challenge":"CH","origin":"https://evil.example","origin":"OR"}"#,
            ),
            write_ctx(ns),
            GrantError::ClientData,
        ),
        (
            "verify-webauthn-duplicate-escaped-member",
            "§4.3 rule 2: no duplicate member names, compared after unescaping",
            wa.clone(),
            signed_cd(
                r#"{"type":"webauthn.get","type":"webauthn.get","challenge":"CH","origin":"OR"}"#,
            ),
            write_ctx(ns),
            GrantError::ClientData,
        ),
        (
            "verify-webauthn-duplicate-nested-member",
            "§4.3 rule 2: no duplicate member names at any depth",
            wa.clone(),
            signed_cd(
                r#"{"type":"webauthn.get","challenge":"CH","origin":"OR","x":[{"a":1,"a":2}]}"#,
            ),
            write_ctx(ns),
            GrantError::ClientData,
        ),
        (
            "verify-webauthn-lone-surrogate",
            "§4.3 rule 2: clientDataJSON is RFC 8259 JSON of Unicode text (no unpaired surrogate)",
            wa.clone(),
            signed_cd(r#"{"type":"webauthn.get","challenge":"CH","origin":"OR","x":"\ud800"}"#),
            write_ctx(ns),
            GrantError::ClientData,
        ),
        (
            "verify-webauthn-bad-signature",
            "§4, §4.3: the signature verifies under the blob's public key (another key signed)",
            wa.clone(),
            header(&forged),
            write_ctx(ns),
            GrantError::BadSignature,
        ),
        (
            "verify-webauthn-reserialized-client-data",
            "§4.3 rule 3: the signature covers the exact received clientDataJSON, never a reserialization",
            wa.clone(),
            header(&reserialized),
            write_ctx(ns),
            GrantError::BadSignature,
        ),
        (
            "verify-webauthn-blob-trailing-byte",
            "§4: nothing follows the fourth length-prefixed field",
            wa.clone(),
            signed_header(&bytes, OwnerScheme::WebAuthnP256, trailing),
            write_ctx(ns),
            GrantError::WebAuthnBlob,
        ),
        (
            "verify-webauthn-ed25519-namespace",
            "§4: webauthn-p256 is valid only for a 0x namespace",
            wa.clone(),
            signed_header(&ed_grant, OwnerScheme::WebAuthnP256, good.encode().unwrap()),
            write_ctx(key_ns()),
            GrantError::SchemeNamespaceMismatch,
        ),
        (
            "verify-webauthn-not-advertised",
            "§4, §7 step 3: a scheme the deployment does not advertise fails",
            vec![OwnerScheme::Ed25519, OwnerScheme::Secp256k1Eip191],
            header(&good),
            write_ctx(ns),
            GrantError::SchemeNotAdvertised,
        ),
    ]
}

fn rejects() -> Vec<Reject> {
    let mut all = k1_rejects();
    all.extend(wa_rejects());
    all
}

fn reject_json(r: &Reject) -> Value {
    let (_, rule, schemes, header, ctx, err) = r;
    let mut context = grant_context_json(ctx, None);
    context.as_object_mut().unwrap().remove("name");
    let audience = context.as_object_mut().unwrap().remove("audience").unwrap();
    json!({
        "rule": rule,
        "kind": "grant",
        "accepted_schemes": schemes.iter().map(|s| s.token()).collect::<Vec<_>>(),
        "relying_parties": relying_parties_json(),
        "audience": audience,
        "header": header,
        "context": context,
        "expected_error": err.reason(),
    })
}

/// Writes the ECDSA fixtures; the caller then rewrites `MANIFEST.txt`.
pub(super) fn write_ecdsa() {
    write_json(&format!("{K1_TOKEN}.json"), &k1_file());
    write_json(&format!("{WA_TOKEN}.json"), &wa_file());
    for r in rejects() {
        write_json(&format!("reject/{}.json", r.0), &reject_json(&r));
    }
}

fn check_vectors(file: &Value, vectors: &[Vector]) {
    let fixtures = file["vectors"].as_array().unwrap();
    assert_eq!(fixtures.len(), vectors.len());
    let schemes = [vectors[0].scheme];
    for (fixture, v) in fixtures.iter().zip(vectors) {
        let header = fixture["header"].as_str().unwrap();
        assert_eq!(header, v.header(), "{}", v.name);
        let parsed = SignedHeader::parse(header).unwrap();
        assert_eq!(hex(&parsed.blob), fixture["blob_hex"].as_str().unwrap());
        for ctx in &v.contexts {
            assert_eq!(
                run_context(&schemes, header, ctx),
                expected(ctx).map_or(Ok(()), Err),
                "{}",
                v.name
            );
        }
    }
}

#[test]
fn secp256k1_eip191_goldens() {
    maybe_write();
    let file = read(&format!("{K1_TOKEN}.json"));
    assert_eq!(file, k1_file());
    // The owner is the web3.js documented key (`eth-primitives.json`).
    assert_eq!(
        file["namespace"],
        "0x2c7536e3605d9c16a7a3d7b1898e529396a65c23"
    );
    check_vectors(&file, &k1_vectors());
}

#[test]
fn webauthn_p256_goldens() {
    maybe_write();
    let file = read(&format!("{WA_TOKEN}.json"));
    assert_eq!(file, wa_file());
    let vectors = wa_vectors();
    check_vectors(&file, &vectors);
    // Every signature is raw low-S and parses back from the blob.
    for v in &vectors {
        let a = WebAuthnAssertion::parse(&v.blob).unwrap();
        assert_eq!(
            eth::p256_check_raw_low_s(&a.signature),
            Ok(()),
            "{}",
            v.name
        );
    }
}

/// Every `reject/verify-{secp256k1,webauthn}-*.json` fails verification with
/// exactly its expected error.
#[test]
fn ecdsa_grant_verify_reject_goldens() {
    maybe_write();
    let expected = rejects();
    let files: Vec<String> = fixture_files()
        .into_iter()
        .filter(|p| is_ecdsa_reject(p))
        .collect();
    let mut names: Vec<String> = expected
        .iter()
        .map(|r| format!("reject/{}.json", r.0))
        .collect();
    names.sort();
    assert_eq!(files, names);
    for r in &expected {
        let fixture = read(&format!("reject/{}.json", r.0));
        assert_eq!(fixture, reject_json(r), "{}", r.0);
        let cfg = cfg(AUDIENCE, &r.2);
        assert_eq!(run_grant(&cfg, &r.3, &r.4), Err(r.5), "{}", r.0);
    }
}
