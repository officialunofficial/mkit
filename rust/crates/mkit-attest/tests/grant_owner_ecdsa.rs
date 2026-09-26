//! The ECDSA owner schemes (SPEC-WRITE-GRANTS §4, §4.1, §4.3, §4.4):
//! `secp256k1-eip191` and `webauthn-p256`, through the public verifiers,
//! with freshly signed statements. The signed goldens are in
//! `golden_grants` (`secp256k1-eip191.json`, `webauthn-p256.json`).
#![cfg(feature = "grants")]
#![allow(clippy::unwrap_used)] // unwrap is the assertion in tests

use k256::ecdsa::SigningKey as K1Key;
use mkit_attest::eth;
use mkit_attest::grant::{
    AcceptedSchemes, Capabilities, Capability, EpochStatement, Grant, GrantError, GrantRequest,
    Namespace, OwnerScheme, RefFlags, RefPattern, RefScopes, RelyingParty, RepoScope,
    RepositoryIdentity, SignedHeader, VerifierConfig, Visibility, VisibilityStatement,
    WebAuthnAssertion, verify_epoch_statement, verify_for_registration, verify_grant_owner,
    verify_owner_signature, verify_visibility_statement, webauthn_challenge,
};
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256Key};
use proptest::prelude::*;
use sha2::{Digest, Sha256};

const AUDIENCE: &str = "https://git.example.com";
const CREATED: i64 = 1_790_000_000_000;
const EXPIRY: i64 = CREATED + 3_600_000;
const GRANTEE: [u8; 32] = [0xea; 32];
const RP_ID: &str = "example.com";
const ORIGIN: &str = "https://example.com";
const OTHER_RP_ID: &str = "wallet.example";
const OTHER_ORIGIN: &str = "https://wallet.example";
const K1_N: &str = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
const P256_N: &str = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
const P256_P: &str = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";

// ---- shared ------------------------------------------------------------

fn h32(s: &str) -> [u8; 32] {
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

fn relying_parties() -> Vec<RelyingParty> {
    vec![
        RelyingParty::new(RP_ID, [ORIGIN, "https://www.example.com"]).unwrap(),
        RelyingParty::new(OTHER_RP_ID, [OTHER_ORIGIN]).unwrap(),
    ]
}

fn cfg() -> VerifierConfig {
    VerifierConfig::new(
        AUDIENCE,
        AcceptedSchemes::of(&[
            OwnerScheme::Ed25519,
            OwnerScheme::Secp256k1Eip191,
            OwnerScheme::WebAuthnP256,
        ]),
        relying_parties(),
    )
    .unwrap()
}

fn grant(ns: Namespace) -> Grant {
    Grant {
        namespace: ns,
        scope: RepoScope::Repository(RepositoryIdentity::new(Some(ns), "website").unwrap()),
        grantee: GRANTEE,
        capabilities: Capabilities::ReadWrite,
        audiences: vec![AUDIENCE.into()],
        ref_scopes: Some(
            RefScopes::new(vec![(
                RefPattern::parse("refs/heads/*").unwrap(),
                RefFlags::parse("cu").unwrap(),
            )])
            .unwrap(),
        ),
        epoch: 2,
        created_ms: CREATED,
        expiry_ms: EXPIRY,
        nonce: [0x31; 32],
    }
}

fn header(statement: &[u8], scheme: OwnerScheme, blob: Vec<u8>) -> String {
    SignedHeader {
        statement: statement.to_vec(),
        scheme,
        blob,
    }
    .encode()
    .unwrap()
}

fn check_grant(header: &str, ns: Namespace) -> Result<(), GrantError> {
    let cfg = cfg();
    let site = RepositoryIdentity::new(Some(ns), "website").unwrap();
    verify_grant_owner(&cfg, header)?
        .check(
            &cfg,
            &GrantRequest {
                repository: &site,
                signer: &GRANTEE,
                capability: Capability::Write,
                now_ms: CREATED,
            },
        )
        .map(|_| ())
}

// ---- secp256k1-eip191 --------------------------------------------------

fn k1(seed: u8) -> (K1Key, Namespace) {
    let key = K1Key::from_slice(&[seed; 32]).unwrap();
    let point = key.verifying_key().to_sec1_point(false);
    let xy: [u8; 64] = point.as_bytes()[1..].try_into().unwrap();
    (
        key,
        Namespace::Address(eth::address_secp256k1(&xy).unwrap()),
    )
}

fn eip191_sign(key: &K1Key, statement: &[u8]) -> [u8; 65] {
    let (sig, recid) = key.sign_prehash_recoverable(&eth::eip191_hash(statement));
    let mut out = [0u8; 65];
    out[..64].copy_from_slice(&sig.to_bytes());
    out[64] = 27 + recid.to_byte();
    out
}

fn verify_k1(statement: &[u8], blob: &[u8], ns: &Namespace) -> Result<(), GrantError> {
    verify_owner_signature(&cfg(), OwnerScheme::Secp256k1Eip191, statement, blob, ns)
}

#[test]
fn secp256k1_grant_epoch_and_visibility_verify() {
    let (key, ns) = k1(0x21);
    let g = grant(ns);
    let bytes = g.encode().unwrap();
    let h = header(
        &bytes,
        OwnerScheme::Secp256k1Eip191,
        eip191_sign(&key, &bytes).to_vec(),
    );
    assert_eq!(check_grant(&h, ns), Ok(()));
    let owner = verify_grant_owner(&cfg(), &h).unwrap();
    assert_eq!(owner.scheme(), OwnerScheme::Secp256k1Eip191);
    assert_eq!(owner.relying_party(), None);
    assert!(verify_for_registration(&cfg(), &h, &GRANTEE).is_ok());

    let epoch = EpochStatement {
        namespace: ns,
        new_epoch: 3,
        audiences: vec![AUDIENCE.into()],
        created_ms: CREATED,
        expiry_ms: EXPIRY,
        nonce: [0x32; 32],
    };
    let bytes = epoch.encode().unwrap();
    let h = header(
        &bytes,
        OwnerScheme::Secp256k1Eip191,
        eip191_sign(&key, &bytes).to_vec(),
    );
    assert_eq!(
        verify_epoch_statement(&cfg(), &h, CREATED)
            .unwrap()
            .statement(),
        &epoch
    );

    let site = RepositoryIdentity::new(Some(ns), "website").unwrap();
    let vis = VisibilityStatement {
        repository: site.clone(),
        visibility: Visibility::Public,
        audiences: vec![AUDIENCE.into()],
        created_ms: CREATED,
        expiry_ms: EXPIRY,
        nonce: [0x33; 32],
    };
    let bytes = vis.encode().unwrap();
    let h = header(
        &bytes,
        OwnerScheme::Secp256k1Eip191,
        eip191_sign(&key, &bytes).to_vec(),
    );
    assert_eq!(
        verify_visibility_statement(&cfg(), &h, &site, CREATED)
            .unwrap()
            .statement(),
        &vis
    );
    // Another owner's statement signed by this key: recovery works, the
    // address is not that namespace.
    let (_, other) = k1(0x22);
    let foreign = grant(other).encode().unwrap();
    let h = header(
        &foreign,
        OwnerScheme::Secp256k1Eip191,
        eip191_sign(&key, &foreign).to_vec(),
    );
    assert_eq!(
        verify_grant_owner(&cfg(), &h).map(|_| ()),
        Err(GrantError::OwnerMismatch)
    );
}

#[test]
fn secp256k1_owner_signature_rejects() {
    let (key, ns) = k1(0x21);
    let statement = grant(ns).encode().unwrap();
    let sig = eip191_sign(&key, &statement);
    assert_eq!(verify_k1(&statement, &sig, &ns), Ok(()));
    for len in [0, 64, 66] {
        let mut blob = sig.to_vec();
        blob.resize(len, 27);
        assert_eq!(
            verify_k1(&statement, &blob, &ns),
            Err(GrantError::SignatureLength),
            "{len}"
        );
    }
    for v in [0u8, 1, 26, 29, 255] {
        let mut bad = sig;
        bad[64] = v;
        assert_eq!(
            verify_k1(&statement, &bad, &ns),
            Err(GrantError::SignatureRecoveryId),
            "{v}"
        );
    }
    let n = h32(K1_N);
    for (at, value) in [(0, [0u8; 32]), (32, [0u8; 32]), (0, n), (32, n)] {
        let mut bad = sig;
        bad[at..at + 32].copy_from_slice(&value);
        assert_eq!(
            verify_k1(&statement, &bad, &ns),
            Err(GrantError::SignatureScalar),
            "{at}"
        );
    }
    let mut twin = sig;
    twin[32..64].copy_from_slice(&neg(&n, &sig[32..64]));
    twin[64] = if sig[64] == 27 { 28 } else { 27 };
    assert_eq!(verify_k1(&statement, &twin, &ns), Err(GrantError::HighS));
    assert_eq!(eth::normalize_eip191_signature(twin), Ok(sig));
    // An `r` that is no secp256k1 x-coordinate: no key recovers.
    let mut r = [0u8; 32];
    let r = (1u8..=255)
        .find(|i| {
            r[31] = *i;
            let mut sec1 = [2u8; 33];
            sec1[1..].copy_from_slice(&r);
            k256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).is_err()
        })
        .unwrap();
    let mut bad = sig;
    bad[..32].fill(0);
    bad[31] = r;
    assert_eq!(
        verify_k1(&statement, &bad, &ns),
        Err(GrantError::BadSignature)
    );
    // The ECDSA schemes need a `0x` namespace; an unadvertised scheme fails.
    assert_eq!(
        verify_k1(&statement, &sig, &Namespace::Ed25519([9; 32])),
        Err(GrantError::SchemeNamespaceMismatch)
    );
    let ed_only = VerifierConfig::new(
        AUDIENCE,
        AcceptedSchemes::of(&[OwnerScheme::Ed25519]),
        vec![],
    )
    .unwrap();
    assert_eq!(
        verify_owner_signature(
            &ed_only,
            OwnerScheme::Secp256k1Eip191,
            &statement,
            &sig,
            &ns
        ),
        Err(GrantError::SchemeNotAdvertised)
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// A normalized EIP-191 signature verifies against its own address, and
    /// no single-byte change to the blob or the statement verifies against
    /// that namespace.
    #[test]
    fn secp256k1_owner_roundtrip_and_tamper(
        seed in prop::array::uniform32(1u8..),
        statement in prop::collection::vec(any::<u8>(), 1..300),
        pos in any::<usize>(),
        flip in 1u8..,
    ) {
        let key = K1Key::from_slice(&seed).unwrap();
        let point = key.verifying_key().to_sec1_point(false);
        let ns = Namespace::Address(
            eth::address_secp256k1(&point.as_bytes()[1..].try_into().unwrap()).unwrap(),
        );
        let sig = eip191_sign(&key, &statement);
        prop_assert_eq!(verify_k1(&statement, &sig, &ns), Ok(()));
        let mut bad = sig;
        bad[pos % 65] ^= flip;
        prop_assert!(verify_k1(&statement, &bad, &ns).is_err());
        let mut other = statement.clone();
        let i = pos % other.len();
        other[i] ^= flip;
        prop_assert!(verify_k1(&other, &sig, &ns).is_err());
    }
}

// ---- webauthn-p256 -------------------------------------------------------

struct Passkey {
    key: P256Key,
    xy: [u8; 64],
    ns: Namespace,
}

fn passkey(seed: u8) -> Passkey {
    let key = P256Key::from_slice(&[seed; 32]).unwrap();
    let point = key.verifying_key().to_sec1_point(false);
    let xy: [u8; 64] = point.as_bytes()[1..].try_into().unwrap();
    let ns = Namespace::Address(eth::address_p256(&xy).unwrap());
    Passkey { key, xy, ns }
}

fn auth_data(rp_id: &str, flags: u8, extra: &[u8]) -> Vec<u8> {
    let mut out = Sha256::digest(rp_id.as_bytes()).to_vec();
    out.push(flags);
    out.extend_from_slice(&7u32.to_be_bytes());
    out.extend_from_slice(extra);
    out
}

fn client_data(challenge: &str, origin: &str) -> String {
    format!(
        r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"{origin}","crossOrigin":false}}"#
    )
}

/// RFC 6979 P-256 over `auth ‖ SHA-256(client_data)`, normalized to low-S.
fn p256_sign(key: &P256Key, auth: &[u8], client_data: &[u8]) -> [u8; 64] {
    let signed = [auth, &Sha256::digest(client_data)[..]].concat();
    let sig: P256Signature = key.sign(&signed);
    sig.normalize_s().to_bytes().into()
}

fn assertion(pk: &Passkey, auth: Vec<u8>, client_data: &str) -> WebAuthnAssertion {
    let signature = p256_sign(&pk.key, &auth, client_data.as_bytes());
    WebAuthnAssertion {
        public_key: pk.xy,
        authenticator_data: auth,
        client_data_json: client_data.as_bytes().to_vec(),
        signature,
    }
}

fn verify_wa(statement: &[u8], a: &WebAuthnAssertion, ns: &Namespace) -> Result<(), GrantError> {
    verify_owner_signature(
        &cfg(),
        OwnerScheme::WebAuthnP256,
        statement,
        &a.encode().unwrap(),
        ns,
    )
}

/// A statement, its owner and a verifying assertion.
fn webauthn_fixture() -> (Passkey, Vec<u8>, String) {
    let pk = passkey(0x41);
    let statement = grant(pk.ns).encode().unwrap();
    let challenge = webauthn_challenge(&statement);
    (pk, statement, challenge)
}

#[test]
fn webauthn_grant_epoch_and_visibility_verify() {
    let (pk, statement, challenge) = webauthn_fixture();
    let a = assertion(
        &pk,
        auth_data(RP_ID, 0x01, &[]),
        &client_data(&challenge, ORIGIN),
    );
    let h = header(&statement, OwnerScheme::WebAuthnP256, a.encode().unwrap());
    assert_eq!(check_grant(&h, pk.ns), Ok(()));
    let owner = verify_grant_owner(&cfg(), &h).unwrap();
    assert_eq!(owner.scheme(), OwnerScheme::WebAuthnP256);
    assert_eq!(owner.relying_party(), Some((RP_ID, ORIGIN)));

    let epoch = EpochStatement {
        namespace: pk.ns,
        new_epoch: 3,
        audiences: vec![AUDIENCE.into()],
        created_ms: CREATED,
        expiry_ms: EXPIRY,
        nonce: [0x42; 32],
    };
    let bytes = epoch.encode().unwrap();
    let a = assertion(
        &pk,
        auth_data(RP_ID, 0x05, &[]),
        &client_data(&webauthn_challenge(&bytes), ORIGIN),
    );
    let h = header(&bytes, OwnerScheme::WebAuthnP256, a.encode().unwrap());
    let verified = verify_epoch_statement(&cfg(), &h, CREATED).unwrap();
    assert_eq!(verified.statement(), &epoch);
    assert_eq!(verified.relying_party(), Some((RP_ID, ORIGIN)));

    let site = RepositoryIdentity::new(Some(pk.ns), "website").unwrap();
    let vis = VisibilityStatement {
        repository: site.clone(),
        visibility: Visibility::Private,
        audiences: vec![AUDIENCE.into()],
        created_ms: CREATED,
        expiry_ms: EXPIRY,
        nonce: [0x43; 32],
    };
    let bytes = vis.encode().unwrap();
    let a = assertion(
        &pk,
        auth_data(OTHER_RP_ID, 0x01, &[]),
        &client_data(&webauthn_challenge(&bytes), OTHER_ORIGIN),
    );
    let h = header(&bytes, OwnerScheme::WebAuthnP256, a.encode().unwrap());
    let verified = verify_visibility_statement(&cfg(), &h, &site, CREATED).unwrap();
    assert_eq!(verified.relying_party(), Some((OTHER_RP_ID, OTHER_ORIGIN)));
}

#[test]
fn webauthn_client_data_shapes_that_verify() {
    let (pk, statement, c) = webauthn_fixture();
    for (name, auth, cd) in [
        (
            "no crossOrigin",
            auth_data(RP_ID, 0x01, &[]),
            format!(r#"{{"type":"webauthn.get","challenge":"{c}","origin":"{ORIGIN}"}}"#),
        ),
        (
            "extra members and order",
            auth_data(RP_ID, 0x01, &[]),
            format!(
                r#"{{"origin":"https://www.example.com","challenge":"{c}","type":"webauthn.get","other_keys_can_be_added_here":"do not compare clientDataJSON against a template","n":[1,-2.5e3,{{"a":null}}]}}"#
            ),
        ),
        (
            "escaped names and values",
            auth_data(RP_ID, 0x01, &[]),
            format!(
                r#"{{"type":"webauthn.get","challenge":"{c}","origin":"https:\/\/example.com"}}"#
            ),
        ),
        (
            "whitespace",
            auth_data(RP_ID, 0x01, &[]),
            format!(
                "\n\t{{ \"type\" : \"webauthn.get\" ,\r\n \"challenge\":\"{c}\", \"origin\":\"{ORIGIN}\" }}  "
            ),
        ),
        (
            "user verified, backup flags, extensions",
            auth_data(RP_ID, 0x1d | 0x80, &[0xa1, 0x63, b'f', b'o', b'o', 0xf5]),
            client_data(&c, ORIGIN),
        ),
    ] {
        let a = assertion(&pk, auth, &cd);
        assert_eq!(verify_wa(&statement, &a, &pk.ns), Ok(()), "{name}");
    }
}

#[test]
#[allow(clippy::too_many_lines)] // a table of rejections
fn webauthn_owner_signature_rejects() {
    let (pk, statement, c) = webauthn_fixture();
    let good_cd = client_data(&c, ORIGIN);
    let good = assertion(&pk, auth_data(RP_ID, 0x01, &[]), &good_cd);
    assert_eq!(verify_wa(&statement, &good, &pk.ns), Ok(()));
    let resigned = |auth: Vec<u8>, cd: &str| assertion(&pk, auth, cd);
    let cd = |body: &str| body.replace("CH", &c).replace("OR", ORIGIN);
    let cases: Vec<(&str, WebAuthnAssertion, GrantError)> = vec![
        (
            "user not present (UV set)",
            resigned(auth_data(RP_ID, 0x04, &[]), &good_cd),
            GrantError::UserNotPresent,
        ),
        (
            "36-byte authenticatorData",
            resigned(auth_data(RP_ID, 0x01, &[])[..36].to_vec(), &good_cd),
            GrantError::AuthenticatorData,
        ),
        (
            "unconfigured relying party",
            resigned(auth_data("evil.example", 0x01, &[]), &good_cd),
            GrantError::RelyingPartyMismatch,
        ),
        (
            "relying-party id hash of an origin",
            resigned(auth_data(ORIGIN, 0x01, &[]), &good_cd),
            GrantError::RelyingPartyMismatch,
        ),
        (
            "origin not configured",
            resigned(
                auth_data(RP_ID, 0x01, &[]),
                &client_data(&c, "https://evil.example"),
            ),
            GrantError::OriginNotAllowed,
        ),
        (
            "origin of the other relying party",
            resigned(auth_data(RP_ID, 0x01, &[]), &client_data(&c, OTHER_ORIGIN)),
            GrantError::OriginNotAllowed,
        ),
        (
            "origin missing",
            resigned(
                auth_data(RP_ID, 0x01, &[]),
                &cd(r#"{"type":"webauthn.get","challenge":"CH"}"#),
            ),
            GrantError::OriginNotAllowed,
        ),
        (
            "origin not a string",
            resigned(
                auth_data(RP_ID, 0x01, &[]),
                &cd(r#"{"type":"webauthn.get","challenge":"CH","origin":["OR"]}"#),
            ),
            GrantError::OriginNotAllowed,
        ),
        (
            "origin with a trailing slash",
            resigned(
                auth_data(RP_ID, 0x01, &[]),
                &client_data(&c, "https://example.com/"),
            ),
            GrantError::OriginNotAllowed,
        ),
        (
            "type create",
            resigned(
                auth_data(RP_ID, 0x01, &[]),
                &cd(r#"{"type":"webauthn.create","challenge":"CH","origin":"OR"}"#),
            ),
            GrantError::ClientDataType,
        ),
        (
            "type missing",
            resigned(
                auth_data(RP_ID, 0x01, &[]),
                &cd(r#"{"challenge":"CH","origin":"OR"}"#),
            ),
            GrantError::ClientDataType,
        ),
        (
            "challenge of another statement",
            resigned(
                auth_data(RP_ID, 0x01, &[]),
                &client_data(&webauthn_challenge(b"other"), ORIGIN),
            ),
            GrantError::Challenge,
        ),
        (
            "challenge padded",
            resigned(
                auth_data(RP_ID, 0x01, &[]),
                &client_data(&format!("{c}="), ORIGIN),
            ),
            GrantError::Challenge,
        ),
        (
            "challenge in another case",
            resigned(
                auth_data(RP_ID, 0x01, &[]),
                &client_data(&c.to_uppercase(), ORIGIN),
            ),
            GrantError::Challenge,
        ),
        (
            "challenge of the statement bytes",
            resigned(
                auth_data(RP_ID, 0x01, &[]),
                &client_data(&base64_url(&statement), ORIGIN),
            ),
            GrantError::Challenge,
        ),
        (
            "crossOrigin true",
            resigned(
                auth_data(RP_ID, 0x01, &[]),
                &cd(r#"{"type":"webauthn.get","challenge":"CH","origin":"OR","crossOrigin":true}"#),
            ),
            GrantError::CrossOrigin,
        ),
        (
            "crossOrigin \"false\"",
            resigned(
                auth_data(RP_ID, 0x01, &[]),
                &cd(
                    r#"{"type":"webauthn.get","challenge":"CH","origin":"OR","crossOrigin":"false"}"#,
                ),
            ),
            GrantError::CrossOrigin,
        ),
        (
            "crossOrigin null",
            resigned(
                auth_data(RP_ID, 0x01, &[]),
                &cd(r#"{"type":"webauthn.get","challenge":"CH","origin":"OR","crossOrigin":null}"#),
            ),
            GrantError::CrossOrigin,
        ),
        (
            "topOrigin",
            resigned(
                auth_data(RP_ID, 0x01, &[]),
                &cd(
                    r#"{"type":"webauthn.get","challenge":"CH","origin":"OR","crossOrigin":false,"topOrigin":"OR"}"#,
                ),
            ),
            GrantError::TopOrigin,
        ),
        (
            "duplicate challenge",
            resigned(
                auth_data(RP_ID, 0x01, &[]),
                &cd(r#"{"type":"webauthn.get","challenge":"CH","challenge":"CH","origin":"OR"}"#),
            ),
            GrantError::ClientData,
        ),
        (
            "duplicate via escape",
            resigned(
                auth_data(RP_ID, 0x01, &[]),
                &cd(
                    r#"{"type":"webauthn.get","type":"webauthn.get","challenge":"CH","origin":"OR"}"#,
                ),
            ),
            GrantError::ClientData,
        ),
        (
            "duplicate nested",
            resigned(
                auth_data(RP_ID, 0x01, &[]),
                &cd(
                    r#"{"type":"webauthn.get","challenge":"CH","origin":"OR","x":[{"a":1,"a":2}]}"#,
                ),
            ),
            GrantError::ClientData,
        ),
        (
            "lone surrogate",
            resigned(
                auth_data(RP_ID, 0x01, &[]),
                &cd(r#"{"type":"webauthn.get","challenge":"CH","origin":"OR","x":"\ud800"}"#),
            ),
            GrantError::ClientData,
        ),
        (
            "trailing garbage",
            resigned(auth_data(RP_ID, 0x01, &[]), &format!("{good_cd}x")),
            GrantError::ClientData,
        ),
        (
            "top-level array",
            resigned(auth_data(RP_ID, 0x01, &[]), &format!("[{good_cd}]")),
            GrantError::ClientData,
        ),
    ];
    for (name, a, err) in &cases {
        assert_eq!(verify_wa(&statement, a, &pk.ns), Err(*err), "{name}");
    }

    // Invalid UTF-8 inside a string.
    let mut bytes =
        cd(r#"{"type":"webauthn.get","challenge":"CH","origin":"OR","x":"?"}"#).into_bytes();
    let q = bytes.iter().rposition(|b| *b == b'?').unwrap();
    bytes[q] = 0xff;
    let auth = auth_data(RP_ID, 0x01, &[]);
    let signature = p256_sign(&pk.key, &auth, &bytes);
    let a = WebAuthnAssertion {
        public_key: pk.xy,
        authenticator_data: auth,
        client_data_json: bytes,
        signature,
    };
    assert_eq!(
        verify_wa(&statement, &a, &pk.ns),
        Err(GrantError::ClientData)
    );

    // Signature rules (§4.4): high-s, zero, out of range; never normalized.
    let n = h32(P256_N);
    let mut high = good.clone();
    high.signature[32..].copy_from_slice(&neg(&n, &good.signature[32..]));
    assert_eq!(verify_wa(&statement, &high, &pk.ns), Err(GrantError::HighS));
    for (at, value) in [(0, [0u8; 32]), (32, [0u8; 32]), (0, n), (32, n)] {
        let mut bad = good.clone();
        bad.signature[at..at + 32].copy_from_slice(&value);
        assert_eq!(
            verify_wa(&statement, &bad, &pk.ns),
            Err(GrantError::SignatureScalar),
            "{at}"
        );
    }
    // The key (§4.1): off the curve, x >= p, and another owner.
    let mut off = good.clone();
    off.public_key[63] ^= 1;
    assert_eq!(
        verify_wa(&statement, &off, &pk.ns),
        Err(GrantError::InvalidOwnerKey)
    );
    let mut zero = good.clone();
    zero.public_key = [0; 64];
    assert_eq!(
        verify_wa(&statement, &zero, &pk.ns),
        Err(GrantError::InvalidOwnerKey)
    );
    let mut x_ge_p = good.clone();
    x_ge_p.public_key[..32].copy_from_slice(&h32(P256_P));
    assert_eq!(
        verify_wa(&statement, &x_ge_p, &pk.ns),
        Err(GrantError::InvalidOwnerKey)
    );
    let other = passkey(0x44);
    let theirs = assertion(&other, auth_data(RP_ID, 0x01, &[]), &good_cd);
    assert_eq!(
        verify_wa(&statement, &theirs, &pk.ns),
        Err(GrantError::OwnerMismatch)
    );
    // Another key's signature under the owner's public key.
    let mut forged = good.clone();
    forged.signature = theirs.signature;
    assert_eq!(
        verify_wa(&statement, &forged, &pk.ns),
        Err(GrantError::BadSignature)
    );
    // A signature over a reserialized clientDataJSON (§4.3 rule 3).
    let respaced = good_cd.replace(':', ": ");
    let mut reserialized = good.clone();
    reserialized.signature = p256_sign(&pk.key, &good.authenticator_data, respaced.as_bytes());
    assert_eq!(
        verify_wa(&statement, &reserialized, &pk.ns),
        Err(GrantError::BadSignature)
    );
    // The flags byte is signed: setting UP afterwards breaks the signature.
    let mut unsigned_up = resigned(auth_data(RP_ID, 0x04, &[]), &good_cd);
    unsigned_up.authenticator_data[32] |= 0x01;
    assert_eq!(
        verify_wa(&statement, &unsigned_up, &pk.ns),
        Err(GrantError::BadSignature)
    );

    // Framing (§4): nothing after the fourth field; fixed lengths.
    let blob = good.encode().unwrap();
    let run = |blob: &[u8]| {
        verify_owner_signature(&cfg(), OwnerScheme::WebAuthnP256, &statement, blob, &pk.ns)
    };
    assert_eq!(
        run(&[&blob[..], &[0]].concat()),
        Err(GrantError::WebAuthnBlob)
    );
    assert_eq!(run(&blob[..blob.len() - 1]), Err(GrantError::WebAuthnBlob));
    assert_eq!(run(&[]), Err(GrantError::WebAuthnBlob));
    let mut short_key = 63u32.to_le_bytes().to_vec();
    short_key.extend_from_slice(&blob[4 + 1..]);
    assert_eq!(run(&short_key), Err(GrantError::WebAuthnBlob));

    // The scheme on an `ed25519-` namespace, and unadvertised.
    assert_eq!(
        verify_wa(&statement, &good, &Namespace::Ed25519([9; 32])),
        Err(GrantError::SchemeNamespaceMismatch)
    );
    let no_wa = VerifierConfig::new(
        AUDIENCE,
        AcceptedSchemes::of(&[OwnerScheme::Secp256k1Eip191]),
        relying_parties(),
    )
    .unwrap();
    assert_eq!(
        verify_owner_signature(&no_wa, OwnerScheme::WebAuthnP256, &statement, &blob, &pk.ns),
        Err(GrantError::SchemeNotAdvertised)
    );
}

fn base64_url(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[test]
fn webauthn_owner_verified_rechecks_relying_party() {
    let (pk, statement, c) = webauthn_fixture();
    let a = assertion(
        &pk,
        auth_data(RP_ID, 0x01, &[]),
        &client_data(&c, "https://www.example.com"),
    );
    let h = header(&statement, OwnerScheme::WebAuthnP256, a.encode().unwrap());
    let owner = verify_grant_owner(&cfg(), &h).unwrap();
    let site = RepositoryIdentity::new(Some(pk.ns), "website").unwrap();
    let req = GrantRequest {
        repository: &site,
        signer: &GRANTEE,
        capability: Capability::Write,
        now_ms: CREATED,
    };
    assert!(owner.check(&cfg(), &req).is_ok());
    let schemes = AcceptedSchemes::of(&[OwnerScheme::WebAuthnP256]);
    // The origin was removed from the relying party.
    let narrowed = VerifierConfig::new(
        AUDIENCE,
        schemes,
        vec![RelyingParty::new(RP_ID, [ORIGIN]).unwrap()],
    )
    .unwrap();
    assert_eq!(
        owner.check(&narrowed, &req).map(|_| ()),
        Err(GrantError::OriginNotAllowed)
    );
    // The relying party was removed.
    let other = VerifierConfig::new(
        AUDIENCE,
        schemes,
        vec![RelyingParty::new(OTHER_RP_ID, ["https://www.example.com"]).unwrap()],
    )
    .unwrap();
    assert_eq!(
        owner.check(&other, &req).map(|_| ()),
        Err(GrantError::OriginNotAllowed)
    );
    // The scheme was dropped.
    let k1_only = VerifierConfig::new(
        AUDIENCE,
        AcceptedSchemes::of(&[OwnerScheme::Secp256k1Eip191]),
        vec![],
    )
    .unwrap();
    assert_eq!(
        owner.check(&k1_only, &req).map(|_| ()),
        Err(GrantError::SchemeNotAdvertised)
    );
}

#[test]
fn webauthn_client_normalizes_der_signatures() {
    // What an authenticator returns: DER, possibly high-s. The client turns
    // it into raw low-S (`eth::p256_der_to_low_s_raw`), and the result
    // verifies; the raw high-s form does not.
    let (pk, statement, c) = webauthn_fixture();
    let auth = auth_data(RP_ID, 0x01, &[]);
    let cd = client_data(&c, ORIGIN);
    let signed = [&auth[..], &Sha256::digest(cd.as_bytes())[..]].concat();
    let low: P256Signature = pk.key.sign(&signed);
    let low = low.normalize_s();
    let n = h32(P256_N);
    let high_s = neg(&n, &low.to_bytes()[32..]);
    let high = P256Signature::from_scalars(low.r().to_bytes(), high_s).unwrap();
    let der = high.to_der();
    let raw = eth::p256_der_to_low_s_raw(der.as_bytes()).unwrap();
    assert_eq!(raw, <[u8; 64]>::from(low.to_bytes()));
    let mut a = WebAuthnAssertion {
        public_key: pk.xy,
        authenticator_data: auth,
        client_data_json: cd.into_bytes(),
        signature: raw,
    };
    assert_eq!(verify_wa(&statement, &a, &pk.ns), Ok(()));
    a.signature = high.to_bytes().into();
    assert_eq!(verify_wa(&statement, &a, &pk.ns), Err(GrantError::HighS));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    /// An assertion over any statement, with any flags that include UP and
    /// any trailing `authenticatorData`, verifies; no single-byte change to
    /// its blob verifies.
    #[test]
    fn webauthn_owner_roundtrip_and_tamper(
        seed in prop::array::uniform32(1u8..),
        statement in prop::collection::vec(any::<u8>(), 1..200),
        flags in any::<u8>(),
        extra in prop::collection::vec(any::<u8>(), 0..40),
        pos in any::<usize>(),
        flip in 1u8..,
    ) {
        let Ok(key) = P256Key::from_slice(&seed) else { return Ok(()) };
        let point = key.verifying_key().to_sec1_point(false);
        let xy: [u8; 64] = point.as_bytes()[1..].try_into().unwrap();
        let pk = Passkey { ns: Namespace::Address(eth::address_p256(&xy).unwrap()), key, xy };
        let a = assertion(
            &pk,
            auth_data(RP_ID, flags | 0x01, &extra),
            &client_data(&webauthn_challenge(&statement), ORIGIN),
        );
        prop_assert_eq!(verify_wa(&statement, &a, &pk.ns), Ok(()));
        let blob = a.encode().unwrap();
        let mut bad = blob.clone();
        let i = pos % bad.len();
        bad[i] ^= flip;
        prop_assert!(
            verify_owner_signature(&cfg(), OwnerScheme::WebAuthnP256, &statement, &bad, &pk.ns)
                .is_err()
        );
        let parsed = WebAuthnAssertion::parse(&blob).unwrap();
        prop_assert_eq!(parsed, a);
    }
}
