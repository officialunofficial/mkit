//! `YubiKey` `OpenPGP` signing-slot keystore.

use card_backend_pcsc::PcscBackend;
use der::Encode as _;
use openpgp_card::ocard::algorithm::{AlgorithmAttributes, Curve};
use openpgp_card::ocard::crypto::{EccType, PublicKeyMaterial};
use openpgp_card::ocard::{KeyType, StatusBytes};
use openpgp_card::state::Open;
use openpgp_card::{Card, Error as OpenPgpError};
use p256::ecdsa::Signature as P256Signature;
use p256::elliptic_curve::sec1::ToEncodedPoint as _;
use p256::pkcs8::DecodePublicKey as _;
use secrecy::SecretString;
use sha2::{Digest as _, Sha256};
use yubikey::piv::{AlgorithmId as PivAlgorithmId, SlotAlgorithmId, SlotId};
use yubikey::{PinPolicy, TouchPolicy};

use crate::{
    Algorithm, BackendKind, Capabilities, Error, GenerateOptions, ImportOptions, KeyAttrs,
    KeyMetadata, KeySelector, KeySigner, Keystore, Result, SecretKey, validate_label,
};

const USER_PIN_ENV: &str = "MKIT_YUBIKEY_OPENPGP_PIN";
const ALLOW_TOUCH_ENV: &str = "MKIT_YUBIKEY_OPENPGP_ALLOW_TOUCH";
const PIV_PIN_ENV: &str = "MKIT_YUBIKEY_PIV_PIN";
const PIV_ALLOW_TOUCH_ENV: &str = "MKIT_YUBIKEY_PIV_ALLOW_TOUCH";

/// `YubiKey` `OpenPGP` backend over PC/SC.
#[derive(Clone, Debug, Default)]
pub struct YubiKeyKeystore;

#[derive(Clone, Debug)]
struct OpenPgpSigningKey {
    label: String,
    ident: String,
    public_key: Vec<u8>,
}

#[derive(Clone, Debug)]
struct PivSigningKey {
    label: String,
    slot: SlotId,
    public_key: Vec<u8>,
    pin_policy: PinPolicy,
    touch_policy: TouchPolicy,
}

#[derive(Clone, Debug)]
enum YubiKeySigningKey {
    OpenPgp(OpenPgpSigningKey),
    Piv(PivSigningKey),
}

impl YubiKeyKeystore {
    /// Create a `YubiKey` backend instance and fail closed when no usable card is present.
    pub fn new() -> Result<Self> {
        let cards = discover_openpgp_signing_keys()?;
        if cards.is_empty() {
            return Err(Error::BackendUnavailable(
                "no OpenPGP Ed25519 signing key found on a YubiKey-compatible card".into(),
            ));
        }
        Ok(Self)
    }

    fn resolve(selector: &KeySelector) -> Result<YubiKeySigningKey> {
        validate_label(&selector.label)?;
        match selector.algorithm.unwrap_or(Algorithm::Ed25519) {
            Algorithm::Ed25519 => resolve_openpgp(selector).map(YubiKeySigningKey::OpenPgp),
            Algorithm::P256 => resolve_piv(selector).map(YubiKeySigningKey::Piv),
            Algorithm::Secp256k1 => Err(Error::UnsupportedAlgorithm(Algorithm::Secp256k1)),
        }
    }
}

impl Keystore for YubiKeyKeystore {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            backend: BackendKind::YubiKey,
            algorithms: vec![Algorithm::Ed25519, Algorithm::P256],
            can_generate: false,
            can_import: false,
            can_export: false,
            can_delete: false,
            supports_listing: true,
            supports_user_presence: true,
            supports_device_bound: true,
            supports_non_extractable: true,
        }
    }

    fn generate(
        &self,
        _label: &str,
        algorithm: Algorithm,
        _attrs: KeyAttrs,
        _options: GenerateOptions,
    ) -> Result<Box<dyn KeySigner>> {
        match algorithm {
            Algorithm::Ed25519 => Err(Error::UnsupportedOperation(
                "YubiKey OpenPGP backend opens existing Ed25519 signing keys; generate with vendor tooling for V1",
            )),
            Algorithm::P256 => Err(Error::UnsupportedOperation(
                "YubiKey PIV/FIDO2 backend opens existing hardware keys; generate with vendor tooling or the CTAP external signer for V1",
            )),
            Algorithm::Secp256k1 => Err(Error::UnsupportedAlgorithm(algorithm)),
        }
    }

    fn import(
        &self,
        _label: &str,
        secret: SecretKey,
        _attrs: KeyAttrs,
        _options: ImportOptions,
    ) -> Result<Box<dyn KeySigner>> {
        match secret.algorithm() {
            Algorithm::Ed25519 => Err(Error::UnsupportedOperation(
                "YubiKey OpenPGP backend does not import extractable secret material in V1",
            )),
            Algorithm::P256 => Err(Error::UnsupportedOperation(
                "YubiKey PIV/FIDO2 backend does not import extractable secret material in V1",
            )),
            Algorithm::Secp256k1 => Err(Error::UnsupportedAlgorithm(secret.algorithm())),
        }
    }

    fn open(&self, selector: &KeySelector) -> Result<Box<dyn KeySigner>> {
        match Self::resolve(selector)? {
            YubiKeySigningKey::OpenPgp(card) => Ok(Box::new(YubiKeyOpenPgpSigner { card })),
            YubiKeySigningKey::Piv(key) => Ok(Box::new(YubiKeyPivSigner { key })),
        }
    }

    fn list(&self) -> Result<Vec<KeyMetadata>> {
        let mut out = Vec::new();
        for card in discover_openpgp_signing_keys()? {
            out.push(openpgp_metadata_for(&card));
        }
        for key in discover_piv_signing_keys()? {
            out.push(piv_metadata_for(&key));
        }
        out.sort_by(|left, right| {
            (&left.backend, &left.label).cmp(&(&right.backend, &right.label))
        });
        Ok(out)
    }

    fn export(&self, selector: &KeySelector) -> Result<SecretKey> {
        validate_label(&selector.label)?;
        Err(Error::NotExtractable(KeySelector {
            label: selector.label.clone(),
            algorithm: selector.algorithm.or(Some(Algorithm::Ed25519)),
        }))
    }

    fn delete(&self, selector: &KeySelector) -> Result<()> {
        validate_label(&selector.label)?;
        Err(Error::UnsupportedOperation(
            "YubiKey OpenPGP backend does not delete card keys in V1",
        ))
    }
}

struct YubiKeyOpenPgpSigner {
    card: OpenPgpSigningKey,
}

impl KeySigner for YubiKeyOpenPgpSigner {
    fn algorithm(&self) -> Algorithm {
        Algorithm::Ed25519
    }

    fn label(&self) -> &str {
        &self.card.label
    }

    fn metadata(&self) -> Result<KeyMetadata> {
        Ok(openpgp_metadata_for(&self.card))
    }

    fn public_key(&self) -> Result<Vec<u8>> {
        Ok(self.card.public_key.clone())
    }

    fn keyid(&self) -> Result<String> {
        Ok(keyid_for(&self.card.public_key))
    }

    fn sign(&mut self, msg: &[u8]) -> Result<Vec<u8>> {
        let pin = std::env::var(USER_PIN_ENV).map_err(|_| {
            Error::AuthenticationRequired(format!(
                "set {USER_PIN_ENV} to authorize OpenPGP signing for yubikey:{}",
                self.card.label
            ))
        })?;

        let mut card = open_card_by_ident(&self.card.ident)?;
        let mut transaction = card.transaction().map_err(map_openpgp_error)?;
        if transaction
            .user_interaction_flag(KeyType::Signing)
            .map_err(map_openpgp_error)?
            .is_some_and(|uif| uif.touch_policy().touch_required())
            && std::env::var_os(ALLOW_TOUCH_ENV).is_none()
        {
            return Err(Error::AuthenticationRequired(format!(
                "OpenPGP signing key requires touch; set {ALLOW_TOUCH_ENV}=1 to allow the hardware prompt"
            )));
        }

        transaction
            .verify_user_signing_pin(SecretString::from(pin))
            .map_err(map_openpgp_error)?;
        let signature = transaction
            .card()
            .signature_for_hash(openpgp_card::ocard::crypto::Hash::EdDSA(msg))
            .map_err(map_openpgp_error)?;
        normalize_ed25519_signature(signature)
    }
}

struct YubiKeyPivSigner {
    key: PivSigningKey,
}

impl KeySigner for YubiKeyPivSigner {
    fn algorithm(&self) -> Algorithm {
        Algorithm::P256
    }

    fn label(&self) -> &str {
        &self.key.label
    }

    fn metadata(&self) -> Result<KeyMetadata> {
        Ok(piv_metadata_for(&self.key))
    }

    fn public_key(&self) -> Result<Vec<u8>> {
        Ok(self.key.public_key.clone())
    }

    fn keyid(&self) -> Result<String> {
        Ok(format!("p256:{}", hex_lower(&self.key.public_key)))
    }

    fn sign(&mut self, msg: &[u8]) -> Result<Vec<u8>> {
        let pin = std::env::var(PIV_PIN_ENV).map_err(|_| {
            Error::AuthenticationRequired(format!(
                "set {PIV_PIN_ENV} to authorize PIV signing for yubikey:{}",
                self.key.label
            ))
        })?;
        if matches!(
            self.key.touch_policy,
            TouchPolicy::Always | TouchPolicy::Cached
        ) && std::env::var_os(PIV_ALLOW_TOUCH_ENV).is_none()
        {
            return Err(Error::AuthenticationRequired(format!(
                "PIV signing key requires touch; set {PIV_ALLOW_TOUCH_ENV}=1 to allow the hardware prompt"
            )));
        }

        let mut yubikey = yubikey::YubiKey::open().map_err(map_yubikey_error)?;
        if self.key.pin_policy != PinPolicy::Never {
            yubikey
                .verify_pin(pin.as_bytes())
                .map_err(map_yubikey_error)?;
        }
        let digest = Sha256::digest(msg);
        let der = yubikey::piv::sign_data(
            &mut yubikey,
            &digest,
            PivAlgorithmId::EccP256,
            self.key.slot,
        )
        .map_err(map_yubikey_error)?;
        let signature = P256Signature::from_der(&der)
            .map_err(|error| Error::Encoding(format!("PIV P-256 signature DER: {error}")))?;
        let signature = signature.normalize_s().unwrap_or(signature);
        Ok(signature.to_bytes().to_vec())
    }
}

fn resolve_openpgp(selector: &KeySelector) -> Result<OpenPgpSigningKey> {
    let cards = discover_openpgp_signing_keys()?;
    if let Some(card) = cards.iter().find(|card| {
        card.label == selector.label || card.ident.eq_ignore_ascii_case(&selector.label)
    }) {
        return Ok(card.clone());
    }

    if matches!(selector.label.as_str(), "default" | "main") && cards.len() == 1 {
        let mut card = cards[0].clone();
        card.label.clone_from(&selector.label);
        return Ok(card);
    }

    Err(Error::KeyNotFound(selector.clone()))
}

fn resolve_piv(selector: &KeySelector) -> Result<PivSigningKey> {
    if selector.label.starts_with("fido2-") || selector.label.starts_with("ctap-") {
        return Err(Error::UnsupportedOperation(
            "FIDO2/WebAuthn YubiKey signing must use the CTAP external signer in V1 because keystore signatures cannot carry WebAuthn assertion data",
        ));
    }

    let keys = discover_piv_signing_keys()?;
    if let Some(key) = keys.iter().find(|key| key.label == selector.label) {
        return Ok(key.clone());
    }
    if selector.label == "piv" && keys.len() == 1 {
        let mut key = keys[0].clone();
        key.label.clone_from(&selector.label);
        return Ok(key);
    }

    Err(Error::KeyNotFound(selector.clone()))
}

fn discover_openpgp_signing_keys() -> Result<Vec<OpenPgpSigningKey>> {
    let mut out = Vec::new();
    let cards = PcscBackend::card_backends(None).map_err(map_smartcard_error)?;
    for backend in cards {
        let Ok(backend) = backend else {
            continue;
        };
        let Ok(mut card) = Card::<Open>::new(backend) else {
            continue;
        };
        let Ok(mut tx) = card.transaction() else {
            continue;
        };
        let Ok(aid) = tx.application_identifier() else {
            continue;
        };
        let Ok(public_key) = ed25519_public_key(&mut tx) else {
            continue;
        };
        let ident = aid.ident();
        out.push(OpenPgpSigningKey {
            label: label_from_ident(&ident),
            ident,
            public_key,
        });
    }
    Ok(out)
}

fn discover_piv_signing_keys() -> Result<Vec<PivSigningKey>> {
    let mut yubikey = match yubikey::YubiKey::open() {
        Ok(yubikey) => yubikey,
        Err(yubikey::Error::PcscError { .. } | yubikey::Error::AppletNotFound { .. }) => {
            return Ok(Vec::new());
        }
        Err(error) => return Err(map_yubikey_error(error)),
    };
    let mut out = Vec::new();
    for key in yubikey::Key::list(&mut yubikey).map_err(map_yubikey_error)? {
        let slot = key.slot();
        if !matches!(
            slot,
            SlotId::Authentication | SlotId::Signature | SlotId::CardAuthentication
        ) {
            continue;
        }
        let metadata = yubikey::piv::metadata(&mut yubikey, slot).map_err(map_yubikey_error)?;
        if metadata.algorithm != SlotAlgorithmId::Asymmetric(PivAlgorithmId::EccP256) {
            continue;
        }
        let public_key = p256_public_key_from_certificate(key.certificate())?;
        let (pin_policy, touch_policy) = metadata
            .policy
            .unwrap_or((default_pin_policy(slot), TouchPolicy::Default));
        out.push(PivSigningKey {
            label: piv_label(slot),
            slot,
            public_key,
            pin_policy,
            touch_policy,
        });
    }
    Ok(out)
}

fn open_card_by_ident(ident: &str) -> Result<Card<Open>> {
    let cards = PcscBackend::card_backends(None).map_err(map_smartcard_error)?;
    Card::<Open>::open_by_ident(cards, ident).map_err(map_openpgp_error)
}

fn ed25519_public_key(tx: &mut Card<openpgp_card::state::Transaction<'_>>) -> Result<Vec<u8>> {
    match tx
        .algorithm_attributes(KeyType::Signing)
        .map_err(map_openpgp_error)?
    {
        AlgorithmAttributes::Ecc(attrs)
            if attrs.ecc_type() == EccType::EdDSA && attrs.curve() == &Curve::Ed25519 => {}
        _ => return Err(Error::UnsupportedAlgorithm(Algorithm::Ed25519)),
    }

    match tx
        .public_key_material(KeyType::Signing)
        .map_err(map_openpgp_error)?
    {
        PublicKeyMaterial::E(public) => ed25519_public_key_bytes(public.data()),
        PublicKeyMaterial::R(_) => Err(Error::UnsupportedAlgorithm(Algorithm::Ed25519)),
    }
}

fn ed25519_public_key_bytes(data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 32 {
        return Err(Error::Encoding(format!(
            "OpenPGP Ed25519 public key is too short: {} bytes",
            data.len()
        )));
    }
    Ok(data[data.len() - 32..].to_vec())
}

fn normalize_ed25519_signature(signature: Vec<u8>) -> Result<Vec<u8>> {
    if signature.len() == 64 {
        return Ok(signature);
    }
    if signature.len() > 64 {
        return Ok(signature[signature.len() - 64..].to_vec());
    }
    Err(Error::Encoding(format!(
        "OpenPGP Ed25519 signature is too short: {} bytes",
        signature.len()
    )))
}

fn openpgp_metadata_for(card: &OpenPgpSigningKey) -> KeyMetadata {
    KeyMetadata {
        label: card.label.clone(),
        backend: BackendKind::YubiKey,
        algorithm: Algorithm::Ed25519,
        public_key: card.public_key.clone(),
        keyid: keyid_for(&card.public_key),
        extractable: false,
        require_user_presence: true,
        device_bound: true,
    }
}

fn piv_metadata_for(key: &PivSigningKey) -> KeyMetadata {
    KeyMetadata {
        label: key.label.clone(),
        backend: BackendKind::YubiKey,
        algorithm: Algorithm::P256,
        public_key: key.public_key.clone(),
        keyid: format!("p256:{}", hex_lower(&key.public_key)),
        extractable: false,
        require_user_presence: key.pin_policy != PinPolicy::Never
            || matches!(key.touch_policy, TouchPolicy::Always | TouchPolicy::Cached),
        device_bound: true,
    }
}

fn p256_public_key_from_certificate(certificate: &yubikey::Certificate) -> Result<Vec<u8>> {
    let der = certificate
        .subject_pki()
        .to_der()
        .map_err(|error| Error::Encoding(format!("PIV certificate SPKI DER: {error}")))?;
    let public = p256::PublicKey::from_public_key_der(&der)
        .map_err(|error| Error::Encoding(format!("PIV P-256 public key: {error}")))?;
    Ok(public.to_encoded_point(true).as_bytes().to_vec())
}

fn piv_label(slot: SlotId) -> String {
    match slot {
        SlotId::Authentication => "piv-9a",
        SlotId::Signature => "piv-9c",
        SlotId::CardAuthentication => "piv-9e",
        _ => "piv-unknown",
    }
    .into()
}

fn default_pin_policy(slot: SlotId) -> PinPolicy {
    match slot {
        SlotId::CardAuthentication => PinPolicy::Never,
        SlotId::Signature => PinPolicy::Always,
        _ => PinPolicy::Once,
    }
}

fn keyid_for(public_key: &[u8]) -> String {
    format!("ed25519:{}", hex_lower(public_key))
}

fn label_from_ident(ident: &str) -> String {
    ident.replace(':', "").to_ascii_uppercase()
}

fn map_smartcard_error(error: impl std::fmt::Display) -> Error {
    Error::BackendUnavailable(format!("PC/SC smartcard access failed: {error}"))
}

fn map_openpgp_error(error: OpenPgpError) -> Error {
    match error {
        OpenPgpError::CardStatus(
            StatusBytes::PasswordNotChecked(_) | StatusBytes::SecurityStatusNotSatisfied,
        ) => Error::AuthenticationRequired(error.to_string()),
        OpenPgpError::CardStatus(StatusBytes::AuthenticationMethodBlocked) => {
            Error::AccessDenied(error.to_string())
        }
        OpenPgpError::CardStatus(StatusBytes::ConditionOfUseNotSatisfied) => Error::UserDeclined,
        OpenPgpError::UnsupportedAlgo(_) => Error::UnsupportedAlgorithm(Algorithm::Ed25519),
        OpenPgpError::Smartcard(_) => Error::Io(error.to_string()),
        OpenPgpError::NotFound(_) => Error::KeyNotFound(KeySelector {
            label: "openpgp-signing".into(),
            algorithm: Some(Algorithm::Ed25519),
        }),
        other => Error::Io(other.to_string()),
    }
}

fn map_yubikey_error(error: yubikey::Error) -> Error {
    match error {
        yubikey::Error::WrongPin { tries } => {
            Error::AuthenticationRequired(format!("PIV PIN rejected; {tries} tries remaining"))
        }
        yubikey::Error::AuthenticationError => Error::AuthenticationRequired(error.to_string()),
        yubikey::Error::PinLocked => Error::AccessDenied(error.to_string()),
        yubikey::Error::NotSupported | yubikey::Error::AlgorithmError => {
            Error::UnsupportedAlgorithm(Algorithm::P256)
        }
        yubikey::Error::NotFound => Error::KeyNotFound(KeySelector {
            label: "piv".into(),
            algorithm: Some(Algorithm::P256),
        }),
        yubikey::Error::PcscError { .. } | yubikey::Error::AppletNotFound { .. } => {
            Error::BackendUnavailable(error.to_string())
        }
        other => Error::Io(other.to_string()),
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capabilities_are_hardware_accurate() {
        let capabilities = YubiKeyKeystore.capabilities();
        assert_eq!(capabilities.backend, BackendKind::YubiKey);
        assert_eq!(
            capabilities.algorithms,
            vec![Algorithm::Ed25519, Algorithm::P256]
        );
        assert!(!capabilities.can_generate);
        assert!(!capabilities.can_import);
        assert!(!capabilities.can_export);
        assert!(!capabilities.can_delete);
        assert!(capabilities.supports_listing);
        assert!(capabilities.supports_user_presence);
        assert!(capabilities.supports_device_bound);
        assert!(capabilities.supports_non_extractable);
    }

    #[test]
    fn ident_labels_are_key_ref_safe() {
        assert_eq!(label_from_ident("0006:1234ABCD"), "00061234ABCD");
        validate_label(&label_from_ident("0006:1234ABCD")).expect("label is valid");
    }

    #[test]
    fn public_key_normalization_uses_trailing_ed25519_bytes() {
        let mut encoded = vec![0x40, 0x01];
        encoded.extend([7u8; 32]);
        assert_eq!(ed25519_public_key_bytes(&encoded).unwrap(), vec![7u8; 32]);
    }

    #[test]
    fn signature_normalization_uses_trailing_raw_signature() {
        let mut encoded = vec![0x01, 0x02];
        encoded.extend([9u8; 64]);
        assert_eq!(normalize_ed25519_signature(encoded).unwrap(), vec![9u8; 64]);
    }

    #[test]
    fn piv_labels_are_key_ref_safe() {
        assert_eq!(piv_label(SlotId::Signature), "piv-9c");
        validate_label(&piv_label(SlotId::Signature)).expect("label is valid");
    }

    #[test]
    fn fido2_labels_fail_closed_until_webauthn_data_fits_keystore_api() {
        let selector = KeySelector::new("fido2-release", Some(Algorithm::P256)).unwrap();
        match resolve_piv(&selector) {
            Err(Error::UnsupportedOperation(message)) => assert!(message.contains("WebAuthn")),
            other => panic!("unexpected result: {other:?}"),
        }
    }
}
