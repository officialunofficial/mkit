//! The `webauthn-p256` owner scheme (SPEC-WRITE-GRANTS §4, §4.3, §4.4):
//! the blob codec, the deployment's relying parties, the strict
//! `clientDataJSON` check and the assertion verifier.
//!
//! A client builds the blob from what its authenticator returned: the
//! credential public key as raw `x ‖ y`, `authenticatorData`, the exact
//! `clientDataJSON` bytes whose `challenge` is [`webauthn_challenge`] of the
//! statement, and the DER signature turned into low-S raw `r ‖ s` with
//! [`crate::eth::p256_der_to_low_s_raw`]. Then [`WebAuthnAssertion::encode`].
//!
//! This module is independent of the DSSE wrapping helper in
//! [`crate::webauthn`] (SPEC-EXTERNAL-SIGNER §14), whose rules differ.

use std::collections::BTreeSet;
use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{Signature, VerifyingKey};
use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use sha2::{Digest, Sha256};

use super::GrantError;
use super::config::is_loopback_origin;
use crate::eth::{self, Address, EthError};

/// Shortest `authenticatorData`: rpIdHash (32), flags (1), signCount (4).
const MIN_AUTHENTICATOR_DATA: usize = 37;
/// The user-present flag bit of `authenticatorData[32]`.
const FLAG_USER_PRESENT: u8 = 0x01;
/// The only accepted `clientDataJSON.type`.
const CLIENT_DATA_TYPE_GET: &str = "webauthn.get";
/// Longest relying-party id: a DNS name.
const MAX_RP_ID_LEN: usize = 253;
/// Deepest accepted `clientDataJSON` nesting (§4.3 rule 2): the top-level
/// object is depth 1, and each array or object inside adds one. An explicit
/// limit, independent of (and below) `serde_json`'s own recursion cap.
pub const MAX_CLIENT_DATA_DEPTH: usize = 64;

// ---- relying parties ---------------------------------------------------

/// A `WebAuthn` relying party a deployment accepts `webauthn-p256`
/// assertions for (§4.3 rule 4): its id, whose SHA-256 the authenticator
/// puts in `authenticatorData`, and the origins a `clientDataJSON` from it
/// may name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelyingParty {
    id: String,
    id_hash: [u8; 32],
    origins: Vec<String>,
}

impl RelyingParty {
    /// A relying party with `id` and its allowed `origins`.
    ///
    /// `id` is a lowercase DNS name: dot-separated labels of `a-z`, `0-9` and
    /// `-`, each 1 to 63 bytes without a leading or trailing `-`, at most 253
    /// bytes in all, and a last label that is not all digits (a `WebAuthn`
    /// relying-party id is a domain, never an IP address). Each origin is a
    /// non-empty string of printable ASCII (`0x21..=0x7E`), compared byte for
    /// byte with `clientDataJSON.origin`; there is at least one and no
    /// duplicate. Origins are not otherwise parsed, so native-app origins
    /// (for example `android:apk-key-hash:…`) can be listed.
    ///
    /// # Errors
    /// `RelyingParty` for any rule above.
    pub fn new<'a>(
        id: &str,
        origins: impl IntoIterator<Item = &'a str>,
    ) -> Result<Self, GrantError> {
        if !is_dns_name(id) {
            return Err(GrantError::RelyingParty);
        }
        let mut list: Vec<String> = Vec::new();
        for origin in origins {
            let printable =
                !origin.is_empty() && origin.bytes().all(|b| (0x21..=0x7E).contains(&b));
            if !printable || list.iter().any(|o| o == origin) {
                return Err(GrantError::RelyingParty);
            }
            list.push(origin.to_owned());
        }
        if list.is_empty() {
            return Err(GrantError::RelyingParty);
        }
        Ok(Self {
            id: id.to_owned(),
            id_hash: Sha256::digest(id.as_bytes()).into(),
            origins: list,
        })
    }

    /// The relying-party id.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The origins allowed for this relying party.
    #[must_use]
    pub fn origins(&self) -> &[String] {
        &self.origins
    }

    /// Whether this relying party is a loopback one: id `localhost` or
    /// `*.localhost`, or a loopback origin ([`is_loopback_origin`]).
    pub(crate) fn is_loopback(&self) -> bool {
        self.id == "localhost"
            || self.id.ends_with(".localhost")
            || self.origins.iter().any(|o| is_loopback_origin(o))
    }

    /// Whether `origin` is configured for this relying party.
    pub(crate) fn allows(&self, origin: &str) -> bool {
        self.origins.iter().any(|o| o == origin)
    }
}

fn is_dns_name(id: &str) -> bool {
    if id.is_empty() || id.len() > MAX_RP_ID_LEN {
        return false;
    }
    let labels_ok = id.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    });
    let last_is_number = id
        .rsplit('.')
        .next()
        .is_some_and(|l| l.bytes().all(|b| b.is_ascii_digit()));
    labels_ok && !last_is_number
}

// ---- blob codec ----------------------------------------------------------

/// The four fields of a `webauthn-p256` blob (§4), each encoded as
/// `[u32 LE length][bytes]` (SPEC-CONVENTIONS §3), in this order, with
/// nothing after the fourth.
///
/// This is plain data: parsing checks the framing and the two fixed
/// lengths only. [`super::verify_owner_signature`] does the §4.3 checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebAuthnAssertion {
    /// The credential public key: `x ‖ y`, each 32 bytes big-endian.
    pub public_key: [u8; 64],
    /// The authenticator's `authenticatorData`, as returned.
    pub authenticator_data: Vec<u8>,
    /// The exact `clientDataJSON` bytes the authenticator signed over.
    pub client_data_json: Vec<u8>,
    /// The signature as raw low-S `r ‖ s` (§4.4); see
    /// [`crate::eth::p256_der_to_low_s_raw`].
    pub signature: [u8; 64],
}

impl WebAuthnAssertion {
    /// Split a blob into its four fields.
    ///
    /// # Errors
    /// `WebAuthnBlob` for a truncated length or field, bytes after the
    /// fourth field, or a public key or signature field that is not exactly
    /// 64 bytes.
    pub fn parse(blob: &[u8]) -> Result<Self, GrantError> {
        let mut rest = blob;
        let public_key = take_field(&mut rest)?;
        let authenticator_data = take_field(&mut rest)?;
        let client_data_json = take_field(&mut rest)?;
        let signature = take_field(&mut rest)?;
        if !rest.is_empty() {
            return Err(GrantError::WebAuthnBlob);
        }
        Ok(Self {
            public_key: public_key
                .try_into()
                .map_err(|_| GrantError::WebAuthnBlob)?,
            authenticator_data: authenticator_data.to_vec(),
            client_data_json: client_data_json.to_vec(),
            signature: signature.try_into().map_err(|_| GrantError::WebAuthnBlob)?,
        })
    }

    /// The blob bytes; `parse(encode(a)) == a`.
    ///
    /// # Errors
    /// `WebAuthnBlob` if a field is longer than `u32::MAX` bytes.
    pub fn encode(&self) -> Result<Vec<u8>, GrantError> {
        let fields: [&[u8]; 4] = [
            &self.public_key,
            &self.authenticator_data,
            &self.client_data_json,
            &self.signature,
        ];
        let mut out = Vec::with_capacity(16 + fields.iter().map(|f| f.len()).sum::<usize>());
        for field in fields {
            let len = u32::try_from(field.len()).map_err(|_| GrantError::WebAuthnBlob)?;
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(field);
        }
        Ok(out)
    }
}

fn take_field<'a>(rest: &mut &'a [u8]) -> Result<&'a [u8], GrantError> {
    let (len, tail) = rest
        .split_first_chunk::<4>()
        .ok_or(GrantError::WebAuthnBlob)?;
    let len = usize::try_from(u32::from_le_bytes(*len)).map_err(|_| GrantError::WebAuthnBlob)?;
    if tail.len() < len {
        return Err(GrantError::WebAuthnBlob);
    }
    let (field, tail) = tail.split_at(len);
    *rest = tail;
    Ok(field)
}

/// The `challenge` a `webauthn-p256` assertion over `statement` carries
/// (§4.3 rule 2): the unpadded base64url of the statement's 32-byte
/// BLAKE3, 43 characters.
#[must_use]
pub fn webauthn_challenge(statement: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(mkit_core::hash::hash(statement))
}

// ---- strict clientDataJSON -------------------------------------------------

/// What the §4.3 checks need to know about one member value.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Member {
    /// A string, after JSON unescaping.
    Str(String),
    /// The literal `false`.
    False,
    /// Anything else.
    Other,
}

/// The top-level members §4.3 rule 2 and rule 4 read.
#[derive(Debug, Default)]
struct ClientData {
    ty: Option<Member>,
    challenge: Option<Member>,
    origin: Option<Member>,
    cross_origin: Option<Member>,
    top_origin: bool,
}

/// Walk one JSON value at nesting `depth` (the top-level object is 1),
/// rejecting a repeated member name in any object, an array or object
/// deeper than [`MAX_CLIENT_DATA_DEPTH`], and a non-finite number.
#[derive(Clone, Copy)]
struct Walk {
    depth: usize,
}

impl Walk {
    fn enter<E: de::Error>(self) -> Result<Self, E> {
        if self.depth > MAX_CLIENT_DATA_DEPTH {
            return Err(E::custom("nesting too deep"));
        }
        Ok(Self {
            depth: self.depth + 1,
        })
    }
}

impl<'de> DeserializeSeed<'de> for Walk {
    type Value = Member;

    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Member, D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Walk {
    type Value = Member;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_bool<E>(self, v: bool) -> Result<Member, E> {
        Ok(if v { Member::Other } else { Member::False })
    }

    fn visit_i64<E>(self, _: i64) -> Result<Member, E> {
        Ok(Member::Other)
    }

    fn visit_u64<E>(self, _: u64) -> Result<Member, E> {
        Ok(Member::Other)
    }

    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Member, E> {
        // serde_json already refuses a number outside the `f64` range; the
        // rule is §4.3's, so it is stated here too.
        if v.is_finite() {
            Ok(Member::Other)
        } else {
            Err(E::custom("non-finite number"))
        }
    }

    fn visit_str<E>(self, v: &str) -> Result<Member, E> {
        Ok(Member::Str(v.to_owned()))
    }

    fn visit_unit<E>(self) -> Result<Member, E> {
        Ok(Member::Other)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Member, A::Error> {
        let inner = self.enter()?;
        while seq.next_element_seed(inner)?.is_some() {}
        Ok(Member::Other)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Member, A::Error> {
        walk_object(&mut map, self.enter()?, |_, _| {})?;
        Ok(Member::Other)
    }
}

/// Walk one object's members (their values walked with `inner`), calling
/// `each` with every (decoded) name and value; a repeated name is an error.
fn walk_object<'de, A: MapAccess<'de>>(
    map: &mut A,
    inner: Walk,
    mut each: impl FnMut(&str, Member),
) -> Result<(), A::Error> {
    let mut seen = BTreeSet::new();
    while let Some(name) = map.next_key::<String>()? {
        let value = map.next_value_seed(inner)?;
        each(&name, value);
        if !seen.insert(name) {
            return Err(de::Error::custom("duplicate member name"));
        }
    }
    Ok(())
}

/// The top level: an object whose §4.3 members are recorded.
struct TopLevel;

impl<'de> DeserializeSeed<'de> for TopLevel {
    type Value = ClientData;

    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<ClientData, D::Error> {
        d.deserialize_any(TopLevel)
    }
}

impl<'de> Visitor<'de> for TopLevel {
    type Value = ClientData;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<ClientData, A::Error> {
        let mut out = ClientData::default();
        let inner = Walk { depth: 1 }.enter()?;
        walk_object(&mut map, inner, |name, value| match name {
            "type" => out.ty = Some(value),
            "challenge" => out.challenge = Some(value),
            "origin" => out.origin = Some(value),
            "crossOrigin" => out.cross_origin = Some(value),
            "topOrigin" => out.top_origin = true,
            _ => {}
        })?;
        Ok(out)
    }
}

/// §4.3 rule 2's syntax: an RFC 8259 object with no duplicate member name
/// at any depth (names compared after unescaping), nesting at most
/// [`MAX_CLIENT_DATA_DEPTH`] deep, every number finite as an IEEE 754
/// binary64 value, valid UTF-8 and nothing but whitespace after it.
/// `serde_json` also refuses unpaired surrogate escapes, raw control
/// characters, `NaN`, comments and trailing commas.
fn parse_client_data(bytes: &[u8]) -> Result<ClientData, GrantError> {
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let data = TopLevel
        .deserialize(&mut de)
        .map_err(|_| GrantError::ClientData)?;
    de.end().map_err(|_| GrantError::ClientData)?;
    Ok(data)
}

// ---- verification ------------------------------------------------------------

/// The relying party and origin an accepted assertion was bound to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WebAuthnBinding {
    pub(crate) rp_id: String,
    pub(crate) origin: String,
}

/// §4, §4.1, §4.3 and §4.4 for a `webauthn-p256` blob over `statement`,
/// with the owner `namespace` (a `0x` address). Every failure maps to one
/// code (§11), but the order is fixed so that the golden reject vectors,
/// and `scripts/golden/grants_ref.py`, name the same first failure:
/// framing (`WebAuthnBlob`); scalars and low-S (`SignatureScalar`,
/// `HighS`); the key is a P-256 point (`InvalidOwnerKey`) whose address is
/// the namespace (`OwnerMismatch`); `authenticatorData` length and the UP
/// flag (`AuthenticatorData`, `UserNotPresent`); the relying party
/// (`RelyingPartyMismatch`); `clientDataJSON` syntax (`ClientData`),
/// `type`, `challenge`, `crossOrigin`, `topOrigin`, then `origin` for that
/// relying party (`OriginNotAllowed`); and last the signature over
/// `authenticatorData ‖ SHA-256(clientDataJSON)` as received
/// (`BadSignature`).
pub(crate) fn verify_webauthn(
    relying_parties: &[RelyingParty],
    statement: &[u8],
    blob: &[u8],
    namespace: &Address,
) -> Result<WebAuthnBinding, GrantError> {
    let a = WebAuthnAssertion::parse(blob)?;
    eth::p256_check_raw_low_s(&a.signature).map_err(|e| match e {
        EthError::HighS => GrantError::HighS,
        _ => GrantError::SignatureScalar,
    })?;
    let address = eth::address_p256(&a.public_key).map_err(|_| GrantError::InvalidOwnerKey)?;
    if address != *namespace {
        return Err(GrantError::OwnerMismatch);
    }

    let auth = &a.authenticator_data;
    if auth.len() < MIN_AUTHENTICATOR_DATA {
        return Err(GrantError::AuthenticatorData);
    }
    if auth[32] & FLAG_USER_PRESENT == 0 {
        return Err(GrantError::UserNotPresent);
    }
    let rp = relying_parties
        .iter()
        .find(|rp| rp.id_hash[..] == auth[..32])
        .ok_or(GrantError::RelyingPartyMismatch)?;

    let data = parse_client_data(&a.client_data_json)?;
    if data.ty != Some(Member::Str(CLIENT_DATA_TYPE_GET.to_owned())) {
        return Err(GrantError::ClientDataType);
    }
    if data.challenge != Some(Member::Str(webauthn_challenge(statement))) {
        return Err(GrantError::Challenge);
    }
    if !matches!(data.cross_origin, None | Some(Member::False)) {
        return Err(GrantError::CrossOrigin);
    }
    if data.top_origin {
        return Err(GrantError::TopOrigin);
    }
    let origin = match data.origin {
        Some(Member::Str(o)) if rp.allows(&o) => o,
        _ => return Err(GrantError::OriginNotAllowed),
    };

    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[1..].copy_from_slice(&a.public_key);
    let key = VerifyingKey::from_sec1_bytes(&sec1).map_err(|_| GrantError::InvalidOwnerKey)?;
    let signature = Signature::from_slice(&a.signature).map_err(|_| GrantError::SignatureScalar)?;
    let mut signed = Vec::with_capacity(auth.len() + 32);
    signed.extend_from_slice(auth);
    signed.extend_from_slice(&Sha256::digest(&a.client_data_json));
    key.verify(&signed, &signature)
        .map_err(|_| GrantError::BadSignature)?;
    Ok(WebAuthnBinding {
        rp_id: rp.id.clone(),
        origin,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webauthn_relying_party_rules() {
        let rp = RelyingParty::new("example.com", ["https://example.com"]).unwrap();
        assert_eq!(rp.id(), "example.com");
        assert_eq!(rp.origins(), ["https://example.com"]);
        assert_eq!(rp.id_hash, <[u8; 32]>::from(Sha256::digest(b"example.com")));
        assert!(
            RelyingParty::new("a-1.b2.example", ["android:apk-key-hash:x", "https://a"]).is_ok()
        );
        assert!(RelyingParty::new("localhost", ["http://localhost:8080"]).is_ok());
        let long_ok = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        assert_eq!(long_ok.len(), 253);
        assert!(RelyingParty::new(&long_ok, ["https://x"]).is_ok());
        for bad in [
            "",
            "Example.com",
            "example..com",
            ".example.com",
            "example.com.",
            "-a.example",
            "a-.example",
            "ex_ample.com",
            "127.0.0.1",
            "example.123",
            &format!("{long_ok}x"),
            &format!("{}.com", "a".repeat(64)),
        ] {
            assert_eq!(
                RelyingParty::new(bad, ["https://example.com"]),
                Err(GrantError::RelyingParty),
                "{bad}"
            );
        }
        for origins in [
            &[][..],
            &[""][..],
            &["https://a b"][..],
            &["https://é"][..],
            &["https://a", "https://a"][..],
        ] {
            assert_eq!(
                RelyingParty::new("example.com", origins.iter().copied()),
                Err(GrantError::RelyingParty),
                "{origins:?}"
            );
        }
    }

    #[test]
    fn webauthn_relying_party_loopback() {
        for (id, origin, loopback) in [
            ("localhost", "https://example.com", true),
            ("dev.localhost", "https://example.com", true),
            ("example.com", "http://127.0.0.1:8080", true),
            ("example.com", "http://[::1]", true),
            ("example.com", "https://example.com", false),
            ("localhost.example", "https://localhost.example", false),
        ] {
            assert_eq!(
                RelyingParty::new(id, [origin]).unwrap().is_loopback(),
                loopback,
                "{id} {origin}"
            );
        }
    }

    /// 2^1024 − 2^970 − 1: the largest integer that rounds to `f64::MAX`.
    const MAX_ROUNDING_INT: &str = "179769313486231580793728971405303415079934132710037826936173778980444968292764750946649017977587207096330286416692887910946555547851940402630657488671505820681908902000708383676273854845817711531764475730270069855571366959622842914819860834936475292719074168444365510704342711559699508093042880177904174497791";
    /// 2^1024 − 2^970: halfway to 2^1024, so it rounds (to even) to infinity.
    const TIE_INT: &str = "179769313486231580793728971405303415079934132710037826936173778980444968292764750946649017977587207096330286416692887910946555547851940402630657488671505820681908902000708383676273854845817711531764475730270069855571366959622842914819860834936475292719074168444365510704342711559699508093042880177904174497792";

    #[test]
    fn webauthn_client_data_strict_json() {
        let ok = |s: &str| parse_client_data(s.as_bytes());
        let d = ok(r#" {"type":"webauthn.get","challenge":"c","origin":"o","crossOrigin":false,"x":[1,{"a":null}]} "#)
            .unwrap();
        assert_eq!(d.ty, Some(Member::Str("webauthn.get".into())));
        assert_eq!(d.challenge, Some(Member::Str("c".into())));
        assert_eq!(d.origin, Some(Member::Str("o".into())));
        assert_eq!(d.cross_origin, Some(Member::False));
        assert!(!d.top_origin);
        // Names and values are compared after unescaping.
        let d = ok(r#"{"type":"webauthn.get","topOrigin":1}"#).unwrap();
        assert_eq!(d.ty, Some(Member::Str("webauthn.get".into())));
        assert!(d.top_origin);
        assert_eq!(
            ok(r#"{"crossOrigin":"false"}"#).unwrap().cross_origin,
            Some(Member::Str("false".into()))
        );
        assert_eq!(
            ok(r#"{"crossOrigin":true}"#).unwrap().cross_origin,
            Some(Member::Other)
        );
        for bad in [
            r#"{"type":"a","type":"a"}"#,
            r#"{"type":"a","type":"a"}"#,
            r#"{"x":{"a":1,"a":1}}"#,
            r#"{"x":[{"a":1},{"b":[{"c":1,"c":2}]}]}"#,
            r#"{"x":"\ud800"}"#,
            r#"{"\udc00":1}"#,
            r#"{"x":1,}"#,
            r#"{"x":NaN}"#,
            r#"{"x":1} x"#,
            r#"{"x":1}{}"#,
            "{\"x\":\"a\u{1}\"}",
            "\u{feff}{}",
            r#"["type"]"#,
            r#""webauthn.get""#,
            "",
            "{",
        ] {
            assert_eq!(
                parse_client_data(bad.as_bytes()).unwrap_err(),
                GrantError::ClientData,
                "{bad}"
            );
        }
        assert_eq!(
            parse_client_data(b"{\"x\":\"\xff\"}").unwrap_err(),
            GrantError::ClientData
        );
        // Nesting: the top-level object is depth 1; depth 64 is accepted,
        // 65 is not, whatever mix of arrays and objects gets there.
        let nest = |depth: usize, open: &str, close: &str| {
            format!(
                "{{\"x\":{}1{}}}",
                open.repeat(depth - 1),
                close.repeat(depth - 1)
            )
        };
        assert!(parse_client_data(nest(MAX_CLIENT_DATA_DEPTH, "[", "]").as_bytes()).is_ok());
        assert!(parse_client_data(nest(MAX_CLIENT_DATA_DEPTH, "{\"a\":", "}").as_bytes()).is_ok());
        assert_eq!(
            parse_client_data(nest(MAX_CLIENT_DATA_DEPTH + 1, "[", "]").as_bytes()).unwrap_err(),
            GrantError::ClientData
        );
        assert_eq!(
            parse_client_data(nest(MAX_CLIENT_DATA_DEPTH + 1, "{\"a\":", "}").as_bytes())
                .unwrap_err(),
            GrantError::ClientData
        );
        // Numbers: finite binary64 values only.
        for good in [
            "1e308",
            "-1.7976931348623157e308",
            // Round to f64::MAX (correctly rounded parsing): finite.
            "1.7976931348623158e308",
            "-1.7976931348623158e308",
            MAX_ROUNDING_INT,
            "1e-400",
            "123456789012345678901234567890",
        ] {
            assert!(
                parse_client_data(format!("{{\"x\":{good}}}").as_bytes()).is_ok(),
                "{good}"
            );
        }
        for bad in [
            "1e400",
            "-1e400",
            &format!("1{}", "0".repeat(400)),
            // Just past the rounding boundary: infinity.
            "1.7976931348623159e308",
            "-1.7976931348623159e308",
            TIE_INT,
        ] {
            assert_eq!(
                parse_client_data(format!("{{\"x\":{bad}}}").as_bytes()).unwrap_err(),
                GrantError::ClientData,
                "{bad}"
            );
        }
        // The walk sees every depth, even inside arrays of arrays.
        let deep = format!("{}{{\"a\":1,\"a\":2}}{}", "[".repeat(50), "]".repeat(50));
        assert!(parse_client_data(format!("{{\"x\":{deep}}}").as_bytes()).is_err());
    }

    #[test]
    fn webauthn_blob_framing() {
        let a = WebAuthnAssertion {
            public_key: [1; 64],
            authenticator_data: vec![2; 37],
            client_data_json: b"{}".to_vec(),
            signature: [3; 64],
        };
        let blob = a.encode().unwrap();
        assert_eq!(blob.len(), 16 + 64 + 37 + 2 + 64);
        assert_eq!(&blob[..4], &64u32.to_le_bytes());
        assert_eq!(WebAuthnAssertion::parse(&blob).unwrap(), a);
        let mut trailing = blob.clone();
        trailing.push(0);
        assert_eq!(
            WebAuthnAssertion::parse(&trailing),
            Err(GrantError::WebAuthnBlob)
        );
        for cut in 0..blob.len() {
            assert_eq!(
                WebAuthnAssertion::parse(&blob[..cut]),
                Err(GrantError::WebAuthnBlob),
                "{cut}"
            );
        }
        let mut huge = blob.clone();
        huge[68..72].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            WebAuthnAssertion::parse(&huge),
            Err(GrantError::WebAuthnBlob)
        );
    }

    #[test]
    fn webauthn_challenge_is_43_base64url_chars() {
        let c = webauthn_challenge(b"statement");
        assert_eq!(c.len(), 43);
        assert_eq!(
            URL_SAFE_NO_PAD.decode(&c).unwrap(),
            blake3::hash(b"statement").as_bytes()
        );
    }

    /// Proptest case count: `PROPTEST_CASES` when set (for deeper local runs),
    /// else `default` (explicit `with_cases` would otherwise ignore the env).
    fn cases(default: u32) -> u32 {
        std::env::var("PROPTEST_CASES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    }

    fn json_value() -> impl proptest::strategy::Strategy<Value = serde_json::Value> {
        use proptest::prelude::*;
        use serde_json::Value;
        let leaf = prop_oneof![
            Just(Value::Null),
            any::<bool>().prop_map(Value::Bool),
            any::<i64>().prop_map(Value::from),
            (-1e300f64..1e300).prop_map(Value::from),
            "\\PC{0,8}".prop_map(Value::String),
        ];
        leaf.prop_recursive(4, 48, 6, |inner| {
            prop_oneof![
                prop::collection::vec(inner.clone(), 0..5).prop_map(Value::Array),
                prop::collection::btree_map("[a-z\\u{e9}\"\\\\]{0,4}", inner, 0..5)
                    .prop_map(|m| Value::Object(m.into_iter().collect())),
            ]
        })
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(cases(256)))]

        /// Differential against `serde_json::Value`: every duplicate-free
        /// object serde_json writes is accepted; the same object with one
        /// member repeated is rejected; and a one-byte mutation the strict
        /// walk accepts is valid JSON to serde_json too.
        #[test]
        fn webauthn_client_data_matches_serde_json(
            members in proptest::collection::btree_map("[a-z]{0,3}", json_value(), 1..5),
            pos in proptest::prelude::any::<usize>(),
            byte in proptest::prelude::any::<u8>(),
        ) {
            let object = serde_json::Value::Object(members.clone().into_iter().collect());
            let text = serde_json::to_vec(&object).unwrap();
            proptest::prop_assert!(parse_client_data(&text).is_ok());
            let (name, value) = members.iter().next().unwrap();
            let member = format!("{}:{}", serde_json::to_string(name).unwrap(), value);
            let duplicated = format!("{{{member},{}", &String::from_utf8(text.clone()).unwrap()[1..]);
            proptest::prop_assert_eq!(
                parse_client_data(duplicated.as_bytes()).unwrap_err(),
                GrantError::ClientData
            );
            let mut mutated = text;
            let i = pos % mutated.len();
            mutated[i] = byte;
            if parse_client_data(&mutated).is_ok() {
                proptest::prop_assert!(serde_json::from_slice::<serde_json::Value>(&mutated).is_ok());
            }
        }
    }
}
