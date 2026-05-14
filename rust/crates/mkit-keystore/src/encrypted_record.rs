//! Encrypted software-key record format.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::{Zeroize, Zeroizing};

use crate::{Algorithm, Error, KeyAttrs, Result, SecretKey};

const MAGIC: &[u8; 8] = b"MKITKSV1";
const VERSION: u8 = 1;
const DEK_LEN: usize = 32;
const NONCE_LEN: usize = 24;

/// Wrapper for software-keystore data-encryption keys.
///
/// The record's inner XChaCha20-Poly1305 layer is the required AAD
/// authentication boundary. Current OS-native protectors use `aad` only as a
/// reserved context parameter and may ignore it; callers must not rely on the
/// protector layer alone to bind metadata to a wrapped DEK.
pub(crate) trait KeyProtector: std::fmt::Debug + Send + Sync {
    /// Stable protector identifier included in record AAD.
    fn id(&self) -> &'static str;

    /// Protect a random data-encryption key.
    fn wrap_dek(&self, dek: &[u8; DEK_LEN], aad: &[u8]) -> Result<Vec<u8>>;

    /// Recover a protected data-encryption key.
    fn unwrap_dek(&self, wrapped: &[u8], aad: &[u8]) -> Result<Zeroizing<[u8; DEK_LEN]>>;

    /// Best-effort cleanup for protector-side DEK state.
    fn delete_wrapped_dek(&self, _wrapped: &[u8]) -> Result<()> {
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EncryptedKeyRecord {
    pub(crate) algorithm: Algorithm,
    pub(crate) public_key: Vec<u8>,
    pub(crate) keyid: String,
    pub(crate) attrs: KeyAttrs,
    pub(crate) protector: String,
    nonce: [u8; NONCE_LEN],
    wrapped_dek: Vec<u8>,
    ciphertext: Vec<u8>,
}

impl EncryptedKeyRecord {
    pub(crate) fn encrypt(
        label: &str,
        secret: &SecretKey,
        attrs: KeyAttrs,
        public_key: Vec<u8>,
        keyid: String,
        protector: &dyn KeyProtector,
    ) -> Result<Self> {
        let mut dek = Zeroizing::new([0u8; DEK_LEN]);
        getrandom::fill(dek.as_mut_slice()).map_err(|_| Error::Internal("rng failed".into()))?;
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).map_err(|_| Error::Internal("rng failed".into()))?;

        let aad = record_aad(
            label,
            secret.algorithm(),
            &public_key,
            &keyid,
            &attrs,
            protector.id(),
        )?;
        let cipher = XChaCha20Poly1305::new_from_slice(&*dek)
            .map_err(|_| Error::Internal("invalid encryption key length".into()))?;
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: secret.expose_secret(),
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Internal("software key encryption failed".into()))?;
        let wrapped_dek = protector.wrap_dek(&dek, &aad)?;

        Ok(Self {
            algorithm: secret.algorithm(),
            public_key,
            keyid,
            attrs,
            protector: protector.id().into(),
            nonce,
            wrapped_dek,
            ciphertext,
        })
    }

    pub(crate) fn decrypt(&self, label: &str, protector: &dyn KeyProtector) -> Result<SecretKey> {
        if self.protector != protector.id() {
            return Err(Error::AccessDenied(format!(
                "record requires protector `{}`, got `{}`",
                self.protector,
                protector.id()
            )));
        }
        let aad = record_aad(
            label,
            self.algorithm,
            &self.public_key,
            &self.keyid,
            &self.attrs,
            protector.id(),
        )?;
        let dek = protector.unwrap_dek(&self.wrapped_dek, &aad)?;
        let cipher = XChaCha20Poly1305::new_from_slice(&*dek)
            .map_err(|_| Error::Internal("invalid encryption key length".into()))?;
        let mut plaintext = cipher
            .decrypt(
                XNonce::from_slice(&self.nonce),
                Payload {
                    msg: &self.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Encoding("software key record authentication failed".into()))?;
        if plaintext.len() != DEK_LEN {
            plaintext.zeroize();
            return Err(Error::InvalidKeyMaterial {
                algorithm: self.algorithm,
                reason: "decrypted secret is not 32 bytes".into(),
            });
        }
        let mut secret = Zeroizing::new([0u8; DEK_LEN]);
        secret.copy_from_slice(&plaintext);
        plaintext.zeroize();
        Ok(SecretKey::from_zeroizing(self.algorithm, secret))
    }

    #[cfg(test)]
    fn encrypt_with_material(
        label: &str,
        secret: &SecretKey,
        attrs: KeyAttrs,
        public_key: Vec<u8>,
        keyid: String,
        protector: &dyn KeyProtector,
        dek: [u8; DEK_LEN],
        nonce: [u8; NONCE_LEN],
    ) -> Result<Self> {
        let dek = Zeroizing::new(dek);
        let aad = record_aad(
            label,
            secret.algorithm(),
            &public_key,
            &keyid,
            &attrs,
            protector.id(),
        )?;
        let cipher = XChaCha20Poly1305::new_from_slice(&*dek)
            .map_err(|_| Error::Internal("invalid encryption key length".into()))?;
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: secret.expose_secret(),
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Internal("software key encryption failed".into()))?;
        let wrapped_dek = protector.wrap_dek(&dek, &aad)?;

        Ok(Self {
            algorithm: secret.algorithm(),
            public_key,
            keyid,
            attrs,
            protector: protector.id().into(),
            nonce,
            wrapped_dek,
            ciphertext,
        })
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.push(VERSION);
        out.push(algorithm_id(self.algorithm));
        out.push(attrs_bits(&self.attrs));
        write_bytes(&mut out, self.protector.as_bytes())?;
        write_bytes(&mut out, &self.public_key)?;
        write_bytes(&mut out, self.keyid.as_bytes())?;
        write_bytes(&mut out, &self.nonce)?;
        write_bytes(&mut out, &self.wrapped_dek)?;
        write_bytes(&mut out, &self.ciphertext)?;
        Ok(out)
    }

    pub(crate) fn wrapped_dek(&self) -> &[u8] {
        &self.wrapped_dek
    }

    pub(crate) fn decode(input: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(input);
        cursor.expect(MAGIC)?;
        let version = cursor.read_u8()?;
        if version != VERSION {
            return Err(Error::Encoding(format!(
                "unsupported software key record version: {version}"
            )));
        }
        let algorithm = algorithm_from_id(cursor.read_u8()?)?;
        let attrs = attrs_from_bits(cursor.read_u8()?)?;
        let protector = String::from_utf8(cursor.read_vec()?)
            .map_err(|error| Error::Encoding(format!("protector id is not UTF-8: {error}")))?;
        let public_key = cursor.read_vec()?;
        let keyid = String::from_utf8(cursor.read_vec()?)
            .map_err(|error| Error::Encoding(format!("keyid is not UTF-8: {error}")))?;
        let nonce_vec = cursor.read_vec()?;
        let nonce = nonce_vec
            .try_into()
            .map_err(|nonce: Vec<u8>| Error::Encoding(format!("nonce length: {}", nonce.len())))?;
        let wrapped_dek = cursor.read_vec()?;
        let ciphertext = cursor.read_vec()?;
        cursor.finish()?;
        Ok(Self {
            algorithm,
            public_key,
            keyid,
            attrs,
            protector,
            nonce,
            wrapped_dek,
            ciphertext,
        })
    }
}

fn record_aad(
    label: &str,
    algorithm: Algorithm,
    public_key: &[u8],
    keyid: &str,
    attrs: &KeyAttrs,
    protector: &str,
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    write_bytes(&mut out, b"software")?;
    write_bytes(&mut out, label.as_bytes())?;
    out.push(algorithm_id(algorithm));
    out.push(attrs_bits(attrs));
    write_bytes(&mut out, protector.as_bytes())?;
    write_bytes(&mut out, public_key)?;
    write_bytes(&mut out, keyid.as_bytes())?;
    Ok(out)
}

fn write_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    let len = u32::try_from(bytes.len())
        .map_err(|_| Error::Encoding("software key record field too large".into()))?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn algorithm_id(algorithm: Algorithm) -> u8 {
    match algorithm {
        Algorithm::Ed25519 => 1,
        Algorithm::Secp256k1 => 2,
        Algorithm::P256 => 3,
    }
}

fn algorithm_from_id(id: u8) -> Result<Algorithm> {
    match id {
        1 => Ok(Algorithm::Ed25519),
        2 => Ok(Algorithm::Secp256k1),
        3 => Ok(Algorithm::P256),
        other => Err(Error::Encoding(format!("unknown algorithm id: {other}"))),
    }
}

fn attrs_bits(attrs: &KeyAttrs) -> u8 {
    u8::from(attrs.extractable)
        | (u8::from(attrs.require_user_presence) << 1)
        | (u8::from(attrs.device_bound) << 2)
}

fn attrs_from_bits(bits: u8) -> Result<KeyAttrs> {
    if bits & !0b111 != 0 {
        return Err(Error::Encoding(format!(
            "unknown key attribute bits: {bits}"
        )));
    }
    Ok(KeyAttrs {
        extractable: bits & 0b001 != 0,
        require_user_presence: bits & 0b010 != 0,
        device_bound: bits & 0b100 != 0,
    })
}

struct Cursor<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn expect(&mut self, expected: &[u8]) -> Result<()> {
        let actual = self.take(expected.len())?;
        if actual != expected {
            return Err(Error::Encoding("invalid software key record magic".into()));
        }
        Ok(())
    }

    fn read_u8(&mut self) -> Result<u8> {
        let bytes = self.take(1)?;
        Ok(bytes[0])
    }

    fn read_vec(&mut self) -> Result<Vec<u8>> {
        let len_bytes = self.take(4)?;
        let len = u32::from_le_bytes(
            len_bytes
                .try_into()
                .map_err(|_| Error::Internal("length slice invariant failed".into()))?,
        );
        Ok(self.take(len as usize)?.to_vec())
    }

    fn finish(&self) -> Result<()> {
        if self.offset == self.input.len() {
            Ok(())
        } else {
            Err(Error::Encoding(
                "trailing bytes in software key record".into(),
            ))
        }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| Error::Encoding("software key record length overflow".into()))?;
        let Some(bytes) = self.input.get(self.offset..end) else {
            return Err(Error::Encoding("truncated software key record".into()));
        };
        self.offset = end;
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct TestProtector;

    impl KeyProtector for TestProtector {
        fn id(&self) -> &'static str {
            "test"
        }

        fn wrap_dek(&self, dek: &[u8; DEK_LEN], aad: &[u8]) -> Result<Vec<u8>> {
            let mut out = dek.to_vec();
            for (index, byte) in out.iter_mut().enumerate() {
                *byte ^= aad[index % aad.len()] ^ 0xa5;
            }
            Ok(out)
        }

        fn unwrap_dek(&self, wrapped: &[u8], aad: &[u8]) -> Result<Zeroizing<[u8; DEK_LEN]>> {
            if wrapped.len() != DEK_LEN {
                return Err(Error::Encoding("wrapped DEK length".into()));
            }
            let mut out = [0u8; DEK_LEN];
            out.copy_from_slice(wrapped);
            for (index, byte) in out.iter_mut().enumerate() {
                *byte ^= aad[index % aad.len()] ^ 0xa5;
            }
            Ok(Zeroizing::new(out))
        }
    }

    #[test]
    fn encrypted_record_round_trips() {
        let protector = TestProtector;
        let secret = SecretKey::new(Algorithm::Ed25519, [7; 32]);
        let record = EncryptedKeyRecord::encrypt(
            "default",
            &secret,
            KeyAttrs::default(),
            vec![1; 32],
            "ed25519:test".into(),
            &protector,
        )
        .expect("encrypt");

        let encoded = record.encode().expect("encode");
        let decoded = EncryptedKeyRecord::decode(&encoded).expect("decode");
        let decrypted = decoded.decrypt("default", &protector).expect("decrypt");
        assert_eq!(decrypted.algorithm(), Algorithm::Ed25519);
        assert_eq!(decrypted.expose_secret(), &[7; 32]);
    }

    #[test]
    fn encrypted_record_authenticates_label_aad() {
        let protector = TestProtector;
        let secret = SecretKey::new(Algorithm::Ed25519, [8; 32]);
        let record = EncryptedKeyRecord::encrypt(
            "default",
            &secret,
            KeyAttrs::default(),
            vec![2; 32],
            "ed25519:test".into(),
            &protector,
        )
        .expect("encrypt");

        assert!(record.decrypt("other", &protector).is_err());
    }

    #[test]
    fn record_aad_length_prefixes_variable_fields() {
        let attrs = KeyAttrs::default();
        let left = record_aad(
            "default",
            Algorithm::Ed25519,
            b"public\0key",
            "id",
            &attrs,
            "test",
        )
        .expect("left aad");
        let right = record_aad(
            "default",
            Algorithm::Ed25519,
            b"public",
            "key\0id",
            &attrs,
            "test",
        )
        .expect("right aad");

        assert_ne!(left, right);
    }

    #[test]
    fn encrypted_record_rejects_corrupt_encoding() {
        assert!(EncryptedKeyRecord::decode(b"short").is_err());
    }

    fn stable_record() -> EncryptedKeyRecord {
        let protector = TestProtector;
        EncryptedKeyRecord::encrypt_with_material(
            "default",
            &SecretKey::new(Algorithm::Ed25519, [0x42; 32]),
            KeyAttrs::default(),
            vec![0x24; 32],
            "ed25519:stable".into(),
            &protector,
            [0x11; DEK_LEN],
            [0x22; NONCE_LEN],
        )
        .expect("encrypt stable record")
    }

    fn assert_tamper_fails(
        mut record: EncryptedKeyRecord,
        mutate: impl FnOnce(&mut EncryptedKeyRecord),
    ) {
        let protector = TestProtector;
        mutate(&mut record);
        assert!(record.decrypt("default", &protector).is_err());
    }

    #[test]
    fn encrypted_record_rejects_tampered_ciphertext() {
        assert_tamper_fails(stable_record(), |record| record.ciphertext[0] ^= 0x01);
    }

    #[test]
    fn encrypted_record_rejects_tampered_nonce() {
        assert_tamper_fails(stable_record(), |record| record.nonce[0] ^= 0x01);
    }

    #[test]
    fn encrypted_record_rejects_tampered_wrapped_dek() {
        assert_tamper_fails(stable_record(), |record| record.wrapped_dek[0] ^= 0x01);
    }

    #[test]
    fn encrypted_record_rejects_tampered_public_key_aad() {
        assert_tamper_fails(stable_record(), |record| record.public_key[0] ^= 0x01);
    }

    #[test]
    fn encrypted_record_rejects_tampered_keyid_aad() {
        assert_tamper_fails(stable_record(), |record| record.keyid.push_str("-tampered"));
    }

    #[test]
    fn encrypted_record_rejects_tampered_attrs_aad() {
        assert_tamper_fails(stable_record(), |record| record.attrs.device_bound = true);
    }

    #[test]
    fn encrypted_record_rejects_tampered_protector_id_aad() {
        assert_tamper_fails(stable_record(), |record| record.protector = "other".into());
    }

    #[test]
    fn encrypted_record_bytes_are_stable_for_v1() {
        let encoded = stable_record().encode().expect("encode stable record");
        let encoded_hex = hex_lower(&encoded);
        assert_eq!(encoded_hex, stable_record_hex());
    }

    #[test]
    fn encrypted_record_v1_decodes_frozen_blob() {
        let protector = TestProtector;
        let frozen = hex_to_bytes(stable_record_hex());
        let decoded = EncryptedKeyRecord::decode(&frozen).expect("decode frozen record");
        let secret = decoded
            .decrypt("default", &protector)
            .expect("decrypt frozen record");
        assert_eq!(secret.algorithm(), Algorithm::Ed25519);
        assert_eq!(secret.expose_secret(), &[0x42; 32]);
    }

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        assert_eq!(hex.len() % 2, 0);
        (0..hex.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).expect("hex byte"))
            .collect()
    }

    fn stable_record_hex() -> &'static str {
        "4d4b49544b53563101010104000000746573742000000024242424242424242424242424242424242424242424242424242424242424240e000000656432353531393a737461626c651800000022222222222222222222222222222222222222222222222220000000f9fffde0ffe7e285b5bcb4b4b4c7dbd2c0c3d5c6d1b3b4b4b4d0d1d2d5c1d8c030000000c125a54e1efba6d6a70f5689ff3be3a070d5819657dcb8a6220934a533a21b67791eb2cb0db7cbdd4815ce51b3ea5ae0"
    }

    fn hex_lower(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
        out
    }
}
