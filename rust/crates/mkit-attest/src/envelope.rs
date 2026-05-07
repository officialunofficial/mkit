//! DSSE envelope — outer signed container for every mkit attestation.
//!
//! See `docs/SPEC-ATTESTATIONS.md` §2 / §4.1 and the upstream
//! <https://github.com/secure-systems-lab/dsse/blob/master/envelope.md>.
//!
//! Envelope shape (JCS-canonical key order):
//!
//! ```json
//! {
//!   "payload":     "<base64(payload_bytes)>",
//!   "payloadType": "<media-type>",
//!   "signatures":  [ { "keyid": "<...>", "sig": "<base64(sig_bytes)>" }, ... ]
//! }
//! ```
//!
//! Signed bytes are the DSSE Pre-Authentication Encoding (PAE):
//!
//! ```text
//! "DSSEv1" SP ascii(len(type)) SP type SP ascii(len(payload)) SP payload
//! ```
//!
//! mkit does not implement the hashed-PAE variant; the signer trait
//! always hands the signer the raw PAE and lets the signer decide
//! whether to pre-hash.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;

use crate::Error;
use crate::jcs::{self, Member, Value};
use mkit_core::Hash;

/// MIME type written into `payloadType` for every mkit attestation.
pub const PAYLOAD_TYPE_IN_TOTO: &str = "application/vnd.in-toto+json";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sig {
    pub keyid: String,
    /// Raw signature bytes (NOT base64). Encoder base64s on the way out.
    pub sig: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub payload_type: String,
    /// Raw payload bytes (NOT base64). Encoder base64s on the way out.
    pub payload: Vec<u8>,
    pub signatures: Vec<Sig>,
}

impl Envelope {
    /// Build the DSSE PAE for this envelope's `(payloadType, payload)`.
    #[must_use]
    pub fn pae(&self) -> Vec<u8> {
        pae_of(&self.payload_type, &self.payload)
    }

    /// Encode this envelope as JCS-canonical JSON. Caller owns the bytes.
    ///
    /// # Errors
    /// * [`Error::EnvelopeNeedsAtLeastOneSignature`] if `signatures` is empty.
    /// * [`Error::PayloadTypeEmpty`] if `payload_type` is `""`.
    pub fn encode(&self) -> Result<String, Error> {
        encode(self)
    }

    /// BLAKE3 of the encoded envelope bytes — the att-id used as the
    /// on-disk filename stem.
    ///
    /// # Errors
    /// Same as [`Envelope::encode`].
    pub fn attestation_id(&self) -> Result<Hash, Error> {
        let bytes = self.encode()?;
        Ok(attestation_id(bytes.as_bytes()))
    }
}

/// Free-function PAE builder. Used directly by verifiers.
#[must_use]
pub fn pae_of(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8 + 8 + payload_type.len() + 8 + payload.len() + 4);
    buf.extend_from_slice(b"DSSEv1 ");
    buf.extend_from_slice(payload_type.len().to_string().as_bytes());
    buf.push(b' ');
    buf.extend_from_slice(payload_type.as_bytes());
    buf.push(b' ');
    buf.extend_from_slice(payload.len().to_string().as_bytes());
    buf.push(b' ');
    buf.extend_from_slice(payload);
    buf
}

/// Encode an envelope as JCS-canonical JSON.
///
/// # Errors
/// See [`Envelope::encode`].
pub fn encode(env: &Envelope) -> Result<String, Error> {
    if env.signatures.is_empty() {
        return Err(Error::EnvelopeNeedsAtLeastOneSignature);
    }
    if env.payload_type.is_empty() {
        return Err(Error::PayloadTypeEmpty);
    }

    let payload_b64 = B64.encode(&env.payload);

    let sig_values: Vec<Value> = env
        .signatures
        .iter()
        .map(|s| {
            Value::Object(vec![
                Member::new("keyid", Value::String(s.keyid.clone())),
                Member::new("sig", Value::String(B64.encode(&s.sig))),
            ])
        })
        .collect();

    let root = Value::Object(vec![
        Member::new("payload", Value::String(payload_b64)),
        Member::new("payloadType", Value::String(env.payload_type.clone())),
        Member::new("signatures", Value::Array(sig_values)),
    ]);

    jcs::encode(&root)
}

/// Compute the att-id for an already-serialised envelope (BLAKE3 of bytes).
#[must_use]
pub fn attestation_id(envelope_bytes: &[u8]) -> Hash {
    mkit_core::hash::hash(envelope_bytes)
}

// ---------------------------------------------------------------------------
// Decoder — strict, matches exactly the byte shape our `encode` produces.
//
// The on-disk attestations mkit creates always come from this encoder,
// so we accept only its exact byte shape and reject anything with
// non-JCS spacing. If we ever need to ingest third-party DSSE envelopes
// we can re-canonicalise via serde + this writer before storing.
// ---------------------------------------------------------------------------

/// Decode a JCS-canonical DSSE envelope produced by [`encode`].
///
/// # Errors
/// [`Error::MalformedEnvelope`] if the input does not match the exact
/// byte shape this crate emits, or if the embedded base64 payload /
/// signatures fail to decode.
pub fn decode(bytes: &[u8]) -> Result<Envelope, Error> {
    let mut p = Parser { src: bytes, pos: 0 };
    p.expect(b"{\"payload\":")?;
    let payload_b64 = p.take_string()?;
    p.expect(b",\"payloadType\":")?;
    let payload_type = p.take_string()?;
    p.expect(b",\"signatures\":[")?;

    let mut sigs: Vec<Sig> = Vec::new();
    if !p.peek(b']') {
        loop {
            p.expect(b"{\"keyid\":")?;
            let keyid = p.take_string()?;
            p.expect(b",\"sig\":")?;
            let sig_b64 = p.take_string()?;
            p.expect(b"}")?;

            let sig_bytes = B64
                .decode(sig_b64.as_bytes())
                .map_err(|_| Error::MalformedEnvelope)?;
            sigs.push(Sig {
                keyid,
                sig: sig_bytes,
            });

            if p.peek(b',') {
                p.pos += 1;
                continue;
            }
            break;
        }
    }
    p.expect(b"]}")?;
    if p.pos != bytes.len() {
        return Err(Error::MalformedEnvelope);
    }

    let payload = B64
        .decode(payload_b64.as_bytes())
        .map_err(|_| Error::MalformedEnvelope)?;

    Ok(Envelope {
        payload_type,
        payload,
        signatures: sigs,
    })
}

struct Parser<'a> {
    src: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    fn expect(&mut self, s: &[u8]) -> Result<(), Error> {
        let end = self
            .pos
            .checked_add(s.len())
            .ok_or(Error::MalformedEnvelope)?;
        if end > self.src.len() {
            return Err(Error::MalformedEnvelope);
        }
        if &self.src[self.pos..end] != s {
            return Err(Error::MalformedEnvelope);
        }
        self.pos = end;
        Ok(())
    }

    fn peek(&self, c: u8) -> bool {
        self.pos < self.src.len() && self.src[self.pos] == c
    }

    /// Take a JSON string, returning an owned `String`. Backslash
    /// escapes are NOT supported (mkit never emits them inside an
    /// envelope key/value position — payload/sig are base64; keyids are
    /// ASCII URLs / hex).
    fn take_string(&mut self) -> Result<String, Error> {
        if self.pos >= self.src.len() || self.src[self.pos] != b'"' {
            return Err(Error::MalformedEnvelope);
        }
        self.pos += 1;
        let start = self.pos;
        while self.pos < self.src.len() && self.src[self.pos] != b'"' {
            if self.src[self.pos] == b'\\' {
                return Err(Error::MalformedEnvelope);
            }
            self.pos += 1;
        }
        if self.pos >= self.src.len() {
            return Err(Error::MalformedEnvelope);
        }
        let s = core::str::from_utf8(&self.src[start..self.pos])
            .map_err(|_| Error::MalformedEnvelope)?
            .to_owned();
        self.pos += 1; // closing "
        Ok(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pae_dsse_v1_reference_encoding() {
        // From the DSSE spec: PAE("hello", "body") = "DSSEv1 5 hello 4 body"
        let got = pae_of("hello", b"body");
        assert_eq!(got, b"DSSEv1 5 hello 4 body");
    }

    #[test]
    fn pae_empty_payload() {
        let got = pae_of("t", b"");
        assert_eq!(got, b"DSSEv1 1 t 0 ");
    }

    #[test]
    fn encode_one_signature_canonical_shape() {
        let env = Envelope {
            payload_type: PAYLOAD_TYPE_IN_TOTO.into(),
            payload: b"{}".to_vec(),
            signatures: vec![Sig {
                keyid: "blake3:aa".into(),
                sig: vec![0x01, 0x02, 0x03],
            }],
        };
        let got = env.encode().unwrap();
        // payload "{}" = 7b 7d → base64 "e30="
        // sig 01 02 03      → base64 "AQID"
        assert_eq!(
            got,
            "{\"payload\":\"e30=\",\
             \"payloadType\":\"application/vnd.in-toto+json\",\
             \"signatures\":[{\"keyid\":\"blake3:aa\",\"sig\":\"AQID\"}]}"
        );
    }

    #[test]
    fn encode_zero_signatures_rejected() {
        let env = Envelope {
            payload_type: "x".into(),
            payload: b"{}".to_vec(),
            signatures: vec![],
        };
        assert!(matches!(
            env.encode(),
            Err(Error::EnvelopeNeedsAtLeastOneSignature)
        ));
    }

    #[test]
    fn encode_empty_payload_type_rejected() {
        let env = Envelope {
            payload_type: String::new(),
            payload: b"{}".to_vec(),
            signatures: vec![Sig {
                keyid: "k".into(),
                sig: vec![1],
            }],
        };
        assert!(matches!(env.encode(), Err(Error::PayloadTypeEmpty)));
    }

    #[test]
    fn encode_decode_roundtrip() {
        let env = Envelope {
            payload_type: PAYLOAD_TYPE_IN_TOTO.into(),
            payload: b"{\"a\":1}".to_vec(),
            signatures: vec![
                Sig {
                    keyid: "blake3:aa".into(),
                    sig: vec![0x10, 0x20, 0x30, 0x40],
                },
                Sig {
                    keyid: "sigstore:https://example.com".into(),
                    sig: vec![0xAA, 0xBB, 0xCC],
                },
            ],
        };
        let bytes = env.encode().unwrap();
        let dec = decode(bytes.as_bytes()).unwrap();
        assert_eq!(dec, env);
    }

    #[test]
    fn decode_rejects_malformed() {
        assert!(matches!(decode(b"not json"), Err(Error::MalformedEnvelope)));
        assert!(matches!(decode(b"{}"), Err(Error::MalformedEnvelope)));

        // Trailing garbage.
        let env = Envelope {
            payload_type: "x".into(),
            payload: vec![],
            signatures: vec![Sig {
                keyid: "k".into(),
                sig: vec![],
            }],
        };
        let mut bad = env.encode().unwrap();
        bad.push_str("trailing");
        assert!(matches!(
            decode(bad.as_bytes()),
            Err(Error::MalformedEnvelope)
        ));
    }

    #[test]
    fn attestation_id_stable_across_equivalent_envelopes() {
        let a = Envelope {
            payload_type: PAYLOAD_TYPE_IN_TOTO.into(),
            payload: b"{}".to_vec(),
            signatures: vec![Sig {
                keyid: "k".into(),
                sig: vec![1],
            }],
        };
        let b = a.clone();
        assert_eq!(a.attestation_id().unwrap(), b.attestation_id().unwrap());
    }
}
