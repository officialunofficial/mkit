//! `YubiKey` `OpenPGP` signing-slot keystore.

use card_backend_pcsc::PcscBackend;
use der::Encode as _;
use openpgp_card::ocard::algorithm::{AlgorithmAttributes, Curve};
use openpgp_card::ocard::crypto::{EccType, PublicKeyMaterial};
use openpgp_card::ocard::{KeyType, StatusBytes};
use openpgp_card::state::Open;
use openpgp_card::{Card, Error as OpenPgpError};
use p256::ecdsa::Signature as P256Signature;
use p256::elliptic_curve::sec1::ToSec1Point as _;
use p256::pkcs8::DecodePublicKey as _;
use sha2::{Digest as _, Sha256};
use yubikey::piv::{AlgorithmId as PivAlgorithmId, SlotAlgorithmId, SlotId};
use yubikey::{PinPolicy, TouchPolicy};

use crate::{
    Algorithm, BackendKind, Capabilities, Error, KeyId, KeyLabel, KeyLister, KeyMetadata,
    KeyOpener, KeySelector, KeySigner, Keystore, PublicKeyBytes, Result, types::static_label,
    validate_label,
};

/// `YubiKey` `OpenPGP` backend over PC/SC.
#[derive(Clone, Debug, Default)]
pub struct YubiKeyKeystore;

#[derive(Clone, Debug)]
struct OpenPgpSigningKey {
    label: KeyLabel,
    ident: String,
    public_key: Vec<u8>,
}

#[derive(Clone, Debug)]
struct PivSigningKey {
    label: KeyLabel,
    serial: yubikey::Serial,
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
        let (openpgp_count, openpgp_error) = match discover_openpgp_signing_keys() {
            Ok(keys) => (keys.len(), None),
            Err(error) => (0, Some(error.to_string())),
        };
        let (piv_count, piv_error) = match discover_piv_signing_keys() {
            Ok(keys) => (keys.len(), None),
            Err(error) => (0, Some(error.to_string())),
        };
        ensure_any_signing_key(openpgp_count, piv_count, openpgp_error, piv_error)?;
        Ok(Self)
    }

    fn resolve(selector: &KeySelector) -> Result<YubiKeySigningKey> {
        validate_label(selector.label())?;
        match selector.algorithm {
            None => resolve_label_only(selector),
            Some(algorithm) => resolve_by_algorithm(selector, algorithm),
        }
    }
}

fn resolve_by_algorithm(selector: &KeySelector, algorithm: Algorithm) -> Result<YubiKeySigningKey> {
    match algorithm {
        Algorithm::Ed25519 => resolve_openpgp(selector).map(YubiKeySigningKey::OpenPgp),
        Algorithm::P256 => resolve_piv(selector).map(YubiKeySigningKey::Piv),
        Algorithm::Secp256k1 => Err(Error::UnsupportedAlgorithm(Algorithm::Secp256k1)),
        // YubiKey backends (OpenPGP + PIV) do not implement
        // BLS12-381; BLS threshold shares live in the software
        // backend.
        #[cfg(feature = "bls-threshold")]
        Algorithm::Bls12381Threshold => Err(Error::UnsupportedAlgorithm(algorithm)),
    }
}

fn resolve_label_only(selector: &KeySelector) -> Result<YubiKeySigningKey> {
    let mut matches = Vec::new();
    match resolve_openpgp(selector) {
        Ok(key) => matches.push(YubiKeySigningKey::OpenPgp(key)),
        Err(Error::KeyNotFound(_)) => {}
        Err(error) => return Err(error),
    }
    match resolve_piv(selector) {
        Ok(key) => matches.push(YubiKeySigningKey::Piv(key)),
        Err(Error::KeyNotFound(_)) => {}
        Err(error) => return Err(error),
    }
    match matches.as_slice() {
        [] => Err(Error::KeyNotFound(selector.clone())),
        [key] => Ok(key.clone()),
        _ => Err(Error::AmbiguousKeySelector(selector.clone())),
    }
}

fn ensure_any_signing_key(
    openpgp_count: usize,
    piv_count: usize,
    openpgp_error: Option<String>,
    piv_error: Option<String>,
) -> Result<()> {
    if openpgp_count > 0 || piv_count > 0 {
        return Ok(());
    }
    let mut message =
        "no OpenPGP Ed25519 or PIV P-256 signing key found on a YubiKey-compatible card".to_owned();
    if let Some(error) = openpgp_error {
        message.push_str("; OpenPGP discovery: ");
        message.push_str(&error);
    }
    if let Some(error) = piv_error {
        message.push_str("; PIV discovery: ");
        message.push_str(&error);
    }
    Err(Error::BackendUnavailable(message))
}

impl Keystore for YubiKeyKeystore {
    fn capabilities(&self) -> Capabilities {
        let openpgp = discover_openpgp_signing_keys().unwrap_or_default();
        let piv = discover_piv_signing_keys().unwrap_or_default();
        capabilities_for_discovered_keys(&openpgp, &piv)
    }

    fn opener(&self) -> Option<&dyn KeyOpener> {
        Some(self)
    }

    fn lister(&self) -> Option<&dyn KeyLister> {
        Some(self)
    }
}

impl KeyOpener for YubiKeyKeystore {
    fn open(&self, selector: &KeySelector) -> Result<Box<dyn KeySigner>> {
        match Self::resolve(selector)? {
            YubiKeySigningKey::OpenPgp(card) => Ok(Box::new(YubiKeyOpenPgpSigner { card })),
            YubiKeySigningKey::Piv(key) => Ok(Box::new(YubiKeyPivSigner { key })),
        }
    }
}

impl KeyLister for YubiKeyKeystore {
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
}

fn capabilities_for_discovered_keys(
    openpgp: &[OpenPgpSigningKey],
    piv: &[PivSigningKey],
) -> Capabilities {
    let mut algorithms = Vec::new();
    if !openpgp.is_empty() {
        algorithms.push(Algorithm::Ed25519);
    }
    if !piv.is_empty() {
        algorithms.push(Algorithm::P256);
    }
    let has_signing_key = !algorithms.is_empty();
    let supports_user_presence = !openpgp.is_empty()
        || piv.iter().any(|key| {
            key.pin_policy != PinPolicy::Never
                || matches!(key.touch_policy, TouchPolicy::Always | TouchPolicy::Cached)
        });
    Capabilities {
        backend: BackendKind::YubiKey,
        algorithms,
        can_generate: false,
        can_import: false,
        can_export: false,
        can_delete: false,
        // Capabilities are structural; token and PC/SC availability are checked by list().
        supports_listing: true,
        supports_user_presence,
        supports_device_bound: has_signing_key,
        supports_non_extractable: has_signing_key,
    }
}

struct YubiKeyOpenPgpSigner {
    card: OpenPgpSigningKey,
}

impl KeySigner for YubiKeyOpenPgpSigner {
    fn algorithm(&self) -> Algorithm {
        Algorithm::Ed25519
    }

    fn label(&self) -> &KeyLabel {
        &self.card.label
    }

    fn metadata(&self) -> Result<KeyMetadata> {
        Ok(openpgp_metadata_for(&self.card))
    }

    fn public_key(&self) -> Result<PublicKeyBytes> {
        Ok(PublicKeyBytes::new(self.card.public_key.clone()))
    }

    fn keyid(&self) -> Result<KeyId> {
        KeyId::new(keyid_for(&self.card.public_key))
    }

    fn sign(&mut self, msg: &[u8]) -> Result<Vec<u8>> {
        ensure_openpgp_interaction_available(self.card.label.as_str())?;

        let mut card = open_card_by_ident(&self.card.ident)?;
        let mut transaction = card.transaction().map_err(map_openpgp_error)?;
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

    fn label(&self) -> &KeyLabel {
        &self.key.label
    }

    fn metadata(&self) -> Result<KeyMetadata> {
        Ok(piv_metadata_for(&self.key))
    }

    fn public_key(&self) -> Result<PublicKeyBytes> {
        Ok(PublicKeyBytes::new(self.key.public_key.clone()))
    }

    fn keyid(&self) -> Result<KeyId> {
        KeyId::new(format!(
            "p256:{}",
            crate::types::hex_lower(&self.key.public_key)
        ))
    }

    fn sign(&mut self, msg: &[u8]) -> Result<Vec<u8>> {
        ensure_piv_interaction_available(&self.key)?;

        let mut yubikey =
            yubikey::YubiKey::open_by_serial(self.key.serial).map_err(map_yubikey_error)?;
        let public_key = piv_public_key_for_slot(&mut yubikey, self.key.slot)?;
        verify_piv_public_key_matches(&self.key, &public_key)?;
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
        let signature = signature.normalize_s();
        Ok(signature.to_bytes().to_vec())
    }
}

fn resolve_openpgp(selector: &KeySelector) -> Result<OpenPgpSigningKey> {
    let cards = discover_openpgp_signing_keys()?;
    if let Some(card) = cards.iter().find(|card| {
        card.label.as_str() == selector.label() || card.ident.eq_ignore_ascii_case(selector.label())
    }) {
        return Ok(card.clone());
    }

    if matches!(selector.label(), "default" | "main") && cards.len() == 1 {
        let mut card = cards[0].clone();
        card.label = selector.label_id().clone();
        return Ok(card);
    }

    Err(Error::KeyNotFound(selector.clone()))
}

fn resolve_piv(selector: &KeySelector) -> Result<PivSigningKey> {
    if selector.label().starts_with("fido2-") || selector.label().starts_with("ctap-") {
        return Err(Error::UnsupportedOperation(
            "FIDO2/WebAuthn YubiKey signing must use the CTAP external signer because keystore signatures cannot carry WebAuthn assertion data; this guard is based on fido2-/ctap- label prefixes",
        ));
    }

    let keys = discover_piv_signing_keys()?;
    resolve_piv_from_keys(selector, &keys)
}

fn resolve_piv_from_keys(selector: &KeySelector, keys: &[PivSigningKey]) -> Result<PivSigningKey> {
    let mut matches: Vec<_> = keys
        .iter()
        .filter(|key| {
            key.label.as_str() == selector.label() || piv_label(key.slot) == selector.label()
        })
        .cloned()
        .collect();

    if matches.is_empty() && selector.label() == "piv" && keys.len() == 1 {
        let mut key = keys[0].clone();
        key.label = selector.label_id().clone();
        return Ok(key);
    }

    match matches.as_mut_slice() {
        [] => Err(Error::KeyNotFound(selector.clone())),
        [key] => {
            key.label = selector.label_id().clone();
            Ok(key.clone())
        }
        _ => Err(Error::AmbiguousKeySelector(selector.clone())),
    }
}

fn discover_openpgp_signing_keys() -> Result<Vec<OpenPgpSigningKey>> {
    let mut out = Vec::new();
    let cards = PcscBackend::card_backends(None).map_err(map_smartcard_error)?;
    for backend in cards {
        let backend = backend.map_err(map_smartcard_error)?;
        let mut card = match Card::<Open>::new(backend) {
            Ok(card) => card,
            Err(error) if is_absent_openpgp_card(&error) => continue,
            Err(error) => return Err(map_openpgp_error(error)),
        };
        let mut tx = card.transaction().map_err(map_openpgp_error)?;
        let aid = tx.application_identifier().map_err(map_openpgp_error)?;
        let public_key = match ed25519_public_key(&mut tx) {
            Ok(public_key) => public_key,
            Err(Error::KeyNotFound(_) | Error::UnsupportedAlgorithm(Algorithm::Ed25519)) => {
                continue;
            }
            Err(error) => return Err(error),
        };
        let ident = aid.ident();
        out.push(OpenPgpSigningKey {
            label: KeyLabel::new(label_from_ident(&ident))?,
            ident,
            public_key,
        });
    }
    Ok(out)
}

fn discover_piv_signing_keys() -> Result<Vec<PivSigningKey>> {
    let mut context = match yubikey::reader::Context::open() {
        Ok(context) => context,
        Err(yubikey::Error::NotFound) => return Ok(Vec::new()),
        Err(yubikey::Error::PcscError { .. }) => {
            return Err(Error::BackendUnavailable(
                "PIV PC/SC smartcard access failed".into(),
            ));
        }
        Err(error) => return Err(map_yubikey_error(error)),
    };

    let mut out = Vec::new();
    for reader in context.iter().map_err(map_yubikey_error)? {
        let mut yubikey = match reader.open() {
            Ok(yubikey) => yubikey,
            Err(yubikey::Error::AppletNotFound { .. } | yubikey::Error::NotFound) => continue,
            Err(yubikey::Error::PcscError { .. }) => {
                return Err(Error::BackendUnavailable(
                    "PIV PC/SC smartcard access failed".into(),
                ));
            }
            Err(error) => return Err(map_yubikey_error(error)),
        };
        out.extend(discover_piv_signing_keys_on_card(&mut yubikey)?);
    }
    Ok(assign_piv_labels(out))
}

fn discover_piv_signing_keys_on_card(yubikey: &mut yubikey::YubiKey) -> Result<Vec<PivSigningKey>> {
    let mut out = Vec::new();
    for key in yubikey::Key::list(yubikey).map_err(map_yubikey_error)? {
        let slot = key.slot();
        if !matches!(
            slot,
            SlotId::Authentication | SlotId::Signature | SlotId::CardAuthentication
        ) {
            continue;
        }
        let metadata = yubikey::piv::metadata(yubikey, slot).map_err(map_yubikey_error)?;
        if metadata.algorithm != SlotAlgorithmId::Asymmetric(PivAlgorithmId::EccP256) {
            continue;
        }
        let public_key = p256_public_key_from_certificate(key.certificate())?;
        let (pin_policy, touch_policy) = piv_policy(metadata.policy, slot)?;
        out.push(PivSigningKey {
            label: piv_key_label(slot),
            serial: yubikey.serial(),
            slot,
            public_key,
            pin_policy,
            touch_policy,
        });
    }
    Ok(out)
}

fn is_absent_openpgp_card(error: &OpenPgpError) -> bool {
    matches!(error, OpenPgpError::NotFound(_))
}

fn piv_policy(
    policy: Option<(PinPolicy, TouchPolicy)>,
    slot: SlotId,
) -> Result<(PinPolicy, TouchPolicy)> {
    policy.ok_or_else(|| {
        Error::BackendUnavailable(format!(
            "cannot determine PIV PIN/touch policy for slot {}",
            piv_label(slot)
        ))
    })
}

fn assign_piv_labels(mut keys: Vec<PivSigningKey>) -> Vec<PivSigningKey> {
    for index in 0..keys.len() {
        let slot = keys[index].slot;
        let duplicate_slot_count = keys.iter().filter(|key| key.slot == slot).count();
        keys[index].label = if duplicate_slot_count > 1 {
            KeyLabel::new(serial_qualified_piv_label(keys[index].serial, slot))
                .expect("generated PIV label is valid")
        } else {
            piv_key_label(slot)
        };
    }
    keys.sort_by(|left, right| {
        (&left.label, left.serial, left.slot).cmp(&(&right.label, right.serial, right.slot))
    });
    keys
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

fn ensure_openpgp_interaction_available(_label: &str) -> Result<()> {
    Err(Error::AuthenticationRequired(
        "YubiKey OpenPGP signing requires an explicit PIN prompt provider; PINs via environment variables are not supported"
            .into(),
    ))
}

fn ensure_piv_interaction_available(key: &PivSigningKey) -> Result<()> {
    if key.pin_policy != PinPolicy::Never {
        return Err(Error::AuthenticationRequired(
            "YubiKey PIV signing requires an explicit PIN prompt provider; PINs via environment variables are not supported"
                .into(),
        ));
    }
    if matches!(key.touch_policy, TouchPolicy::Always | TouchPolicy::Cached) {
        return Err(Error::AuthenticationRequired(
            "YubiKey PIV signing key requires touch, but no bounded touch prompt flow is available"
                .into(),
        ));
    }
    Ok(())
}

fn openpgp_metadata_for(card: &OpenPgpSigningKey) -> KeyMetadata {
    KeyMetadata {
        label: card.label.clone(),
        backend: BackendKind::YubiKey,
        algorithm: Algorithm::Ed25519,
        public_key: PublicKeyBytes::new(card.public_key.clone()),
        keyid: KeyId::new(keyid_for(&card.public_key)).expect("generated key ID is valid"),
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
        public_key: PublicKeyBytes::new(key.public_key.clone()),
        keyid: KeyId::new(format!("p256:{}", crate::types::hex_lower(&key.public_key)))
            .expect("generated key ID is valid"),
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
    Ok(public.to_sec1_point(true).as_bytes().to_vec())
}

fn piv_public_key_for_slot(yubikey: &mut yubikey::YubiKey, slot: SlotId) -> Result<Vec<u8>> {
    for key in yubikey::Key::list(yubikey).map_err(map_yubikey_error)? {
        if key.slot() == slot {
            return p256_public_key_from_certificate(key.certificate());
        }
    }
    Err(Error::KeyNotFound(KeySelector {
        label: piv_key_label(slot),
        algorithm: Some(Algorithm::P256),
    }))
}

fn verify_piv_public_key_matches(key: &PivSigningKey, public_key: &[u8]) -> Result<()> {
    if key.public_key == public_key {
        return Ok(());
    }
    Err(Error::AccessDenied(format!(
        "YubiKey PIV slot {} on serial {} no longer matches resolved public key",
        key.label, key.serial
    )))
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

fn piv_key_label(slot: SlotId) -> KeyLabel {
    KeyLabel::new(piv_label(slot)).expect("static PIV label is valid")
}

fn serial_qualified_piv_label(serial: yubikey::Serial, slot: SlotId) -> String {
    let base = piv_label(slot);
    let suffix = base.strip_prefix("piv-").unwrap_or(&base);
    format!("piv-{}-{suffix}", serial.0)
}

fn keyid_for(public_key: &[u8]) -> String {
    format!("ed25519:{}", crate::types::hex_lower(public_key))
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
            label: static_label("openpgp-signing"),
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
            label: static_label("piv"),
            algorithm: Some(Algorithm::P256),
        }),
        yubikey::Error::PcscError { .. } | yubikey::Error::AppletNotFound { .. } => {
            Error::BackendUnavailable(error.to_string())
        }
        other => Error::Io(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn openpgp_test_key() -> OpenPgpSigningKey {
        OpenPgpSigningKey {
            label: KeyLabel::new("openpgp").unwrap(),
            ident: "0000:TEST".into(),
            public_key: vec![1; 32],
        }
    }

    fn piv_test_key(pin_policy: PinPolicy, touch_policy: TouchPolicy) -> PivSigningKey {
        PivSigningKey {
            label: KeyLabel::new("piv-9c").unwrap(),
            serial: yubikey::Serial(1234),
            slot: SlotId::Signature,
            public_key: vec![1; 33],
            pin_policy,
            touch_policy,
        }
    }

    #[test]
    fn capabilities_are_hardware_accurate() {
        let capabilities = capabilities_for_discovered_keys(
            &[openpgp_test_key()],
            &[piv_test_key(PinPolicy::Always, TouchPolicy::Never)],
        );
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
    fn capabilities_report_openpgp_only_algorithms() {
        let capabilities = capabilities_for_discovered_keys(&[openpgp_test_key()], &[]);
        assert_eq!(capabilities.algorithms, vec![Algorithm::Ed25519]);
        assert!(capabilities.supports_listing);
        assert!(capabilities.supports_user_presence);
        assert!(capabilities.supports_device_bound);
        assert!(capabilities.supports_non_extractable);
    }

    #[test]
    fn capabilities_report_piv_only_algorithms() {
        let capabilities = capabilities_for_discovered_keys(
            &[],
            &[piv_test_key(PinPolicy::Always, TouchPolicy::Never)],
        );
        assert_eq!(capabilities.algorithms, vec![Algorithm::P256]);
        assert!(capabilities.supports_listing);
        assert!(capabilities.supports_user_presence);
        assert!(capabilities.supports_device_bound);
        assert!(capabilities.supports_non_extractable);
    }

    #[test]
    fn capabilities_report_no_token_as_unavailable() {
        let capabilities = capabilities_for_discovered_keys(&[], &[]);
        assert!(capabilities.algorithms.is_empty());
        assert!(!capabilities.can_generate);
        assert!(!capabilities.can_import);
        assert!(!capabilities.can_export);
        assert!(!capabilities.can_delete);
        assert!(capabilities.supports_listing);
        assert!(!capabilities.supports_user_presence);
        assert!(!capabilities.supports_device_bound);
        assert!(!capabilities.supports_non_extractable);
    }

    #[test]
    fn capabilities_report_piv_user_presence_from_policy() {
        let without_presence = capabilities_for_discovered_keys(
            &[],
            &[piv_test_key(PinPolicy::Never, TouchPolicy::Never)],
        );
        assert_eq!(without_presence.algorithms, vec![Algorithm::P256]);
        assert!(!without_presence.supports_user_presence);
        assert!(without_presence.supports_device_bound);
        assert!(without_presence.supports_non_extractable);

        let with_touch = capabilities_for_discovered_keys(
            &[],
            &[piv_test_key(PinPolicy::Never, TouchPolicy::Always)],
        );
        assert!(with_touch.supports_user_presence);
    }

    #[test]
    fn availability_accepts_piv_only_signing_keys() {
        ensure_any_signing_key(0, 1, None, None).expect("PIV-only YubiKey is usable");
    }

    #[test]
    fn availability_accepts_openpgp_only_signing_keys() {
        ensure_any_signing_key(1, 0, None, None).expect("OpenPGP-only YubiKey is usable");
    }

    #[test]
    fn availability_fails_when_no_yubikey_signing_key_exists() {
        match ensure_any_signing_key(0, 0, Some("openpgp unavailable".into()), None) {
            Err(Error::BackendUnavailable(message)) => {
                assert!(message.contains("OpenPGP Ed25519 or PIV P-256"));
                assert!(message.contains("openpgp unavailable"));
            }
            other => panic!("unexpected availability result: {other:?}"),
        }
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
    fn openpgp_signing_requires_explicit_pin_prompt_provider() {
        let mut signer = YubiKeyOpenPgpSigner {
            card: OpenPgpSigningKey {
                label: KeyLabel::new("default").unwrap(),
                ident: "0000:TEST".into(),
                public_key: vec![1; 32],
            },
        };

        match signer.sign(b"message") {
            Err(Error::AuthenticationRequired(message)) => {
                assert!(message.contains("explicit PIN prompt provider"));
                assert!(message.contains("environment variables are not supported"));
                assert!(!message.contains("default"));
                assert!(!message.contains("yubikey:"));
            }
            other => panic!("unexpected signing result: {other:?}"),
        }
    }

    #[test]
    fn piv_pin_required_fails_before_device_io() {
        let key = PivSigningKey {
            label: KeyLabel::new("piv-9c").unwrap(),
            serial: yubikey::Serial(1234),
            slot: SlotId::Signature,
            public_key: vec![1; 33],
            pin_policy: PinPolicy::Always,
            touch_policy: TouchPolicy::Never,
        };

        match ensure_piv_interaction_available(&key) {
            Err(Error::AuthenticationRequired(message)) => {
                assert!(message.contains("explicit PIN prompt provider"));
                assert!(message.contains("environment variables are not supported"));
                assert!(!message.contains("piv-9c"));
                assert!(!message.contains("yubikey:"));
            }
            other => panic!("unexpected interaction result: {other:?}"),
        }
    }

    #[test]
    fn piv_touch_required_fails_without_bounded_prompt_flow() {
        let key = PivSigningKey {
            label: KeyLabel::new("piv-9c").unwrap(),
            serial: yubikey::Serial(1234),
            slot: SlotId::Signature,
            public_key: vec![1; 33],
            pin_policy: PinPolicy::Never,
            touch_policy: TouchPolicy::Always,
        };

        match ensure_piv_interaction_available(&key) {
            Err(Error::AuthenticationRequired(message)) => {
                assert!(message.contains("requires touch"));
                assert!(message.contains("bounded touch prompt flow"));
                assert!(!message.contains("piv-9c"));
                assert!(!message.contains("yubikey:"));
            }
            other => panic!("unexpected interaction result: {other:?}"),
        }
    }

    #[test]
    fn piv_missing_policy_metadata_fails_closed() {
        match piv_policy(None, SlotId::Signature) {
            Err(Error::BackendUnavailable(message)) => {
                assert!(message.contains("cannot determine PIV PIN/touch policy"));
                assert!(message.contains("piv-9c"));
            }
            other => panic!("unexpected policy result: {other:?}"),
        }
    }

    #[test]
    fn piv_labels_are_key_ref_safe() {
        assert_eq!(piv_label(SlotId::Signature), "piv-9c");
        validate_label(&piv_label(SlotId::Signature)).expect("label is valid");
    }

    #[test]
    fn piv_public_key_mismatch_fails_closed() {
        let key = PivSigningKey {
            label: KeyLabel::new("piv-9c").unwrap(),
            serial: yubikey::Serial(1234),
            slot: SlotId::Signature,
            public_key: vec![1; 33],
            pin_policy: PinPolicy::Always,
            touch_policy: TouchPolicy::Never,
        };

        verify_piv_public_key_matches(&key, &[1; 33]).expect("matching public key");
        assert!(matches!(
            verify_piv_public_key_matches(&key, &[2; 33]),
            Err(Error::AccessDenied(_))
        ));
    }

    fn test_piv_key(serial: u32, slot: SlotId) -> PivSigningKey {
        PivSigningKey {
            label: KeyLabel::new(piv_label(slot)).unwrap(),
            serial: yubikey::Serial(serial),
            slot,
            public_key: vec![1; 33],
            pin_policy: PinPolicy::Never,
            touch_policy: TouchPolicy::Never,
        }
    }

    #[test]
    fn piv_discovery_keeps_bare_labels_when_slots_are_unique() {
        let keys = assign_piv_labels(vec![
            test_piv_key(111, SlotId::Signature),
            test_piv_key(222, SlotId::Authentication),
        ]);

        assert!(keys.iter().any(|key| key.label == "piv-9c"));
        assert!(keys.iter().any(|key| key.label == "piv-9a"));
        let selector = KeySelector::new("piv-9c", Some(Algorithm::P256)).unwrap();
        let key = resolve_piv_from_keys(&selector, &keys).expect("bare unique slot resolves");
        assert_eq!(key.serial, yubikey::Serial(111));
    }

    #[test]
    fn piv_discovery_serial_qualifies_duplicate_slots() {
        let keys = assign_piv_labels(vec![
            test_piv_key(111, SlotId::Signature),
            test_piv_key(222, SlotId::Signature),
        ]);

        assert!(keys.iter().any(|key| key.label == "piv-111-9c"));
        assert!(keys.iter().any(|key| key.label == "piv-222-9c"));
        let bare = KeySelector::new("piv-9c", Some(Algorithm::P256)).unwrap();
        assert!(matches!(
            resolve_piv_from_keys(&bare, &keys),
            Err(Error::AmbiguousKeySelector(_))
        ));

        let qualified = KeySelector::new("piv-222-9c", Some(Algorithm::P256)).unwrap();
        let key = resolve_piv_from_keys(&qualified, &keys).expect("qualified slot resolves");
        assert_eq!(key.serial, yubikey::Serial(222));
    }

    #[test]
    fn fido2_labels_fail_closed_until_webauthn_data_fits_keystore_api() {
        let selector = KeySelector::new("fido2-release", Some(Algorithm::P256)).unwrap();
        match resolve_piv(&selector) {
            Err(Error::UnsupportedOperation(message)) => assert!(message.contains("WebAuthn")),
            other => panic!("unexpected result: {other:?}"),
        }
    }

    #[test]
    fn export_fails_for_non_extractable_hardware_backend() {
        let store = YubiKeyKeystore;
        assert!(store.exporter().is_none());
    }
}
