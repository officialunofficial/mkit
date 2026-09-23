// SPDX-License-Identifier: MIT OR Apache-2.0
//! Intrinsic MKHG v1 facts. Live authority belongs exclusively to the host registry.

use commonware_codec::{RangeCfg, Read, ReadExt, Write};
use ed25519_dalek::{Signature, VerifyingKey};
use mkit_core::{object::TreeEntry, refs::validate_ref_name, write_auth::validate_audience};
use serde::{Deserialize, Serialize};

pub const MAX_ENVELOPE: usize = 256 * 1024;
pub const MAX_PATHS: usize = 256;
const SIGN_DOMAIN: &[u8] = b"mkit.hosted-workspace-grant.v1\0";
const ID_DOMAIN: &[u8] = b"mkit.hosted-workspace-grant-id.v1\0";
const DAY_MS: u64 = 24 * 60 * 60 * 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    EnvelopeSize,
    Truncated,
    Magic,
    Version,
    Varint,
    Bound,
    Utf8,
    Context,
    Key,
    Path,
    Mask,
    Time,
    Signature,
    Trailing,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub components: Vec<String>,
    pub mask: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fields {
    pub audience: String,
    pub repository: String,
    pub exact_ref: String,
    pub workspace_id: [u8; 32],
    pub issuer: [u8; 32],
    pub subject: [u8; 32],
    pub receipt_signer: [u8; 32],
    pub authority_generation: u64,
    pub grant_generation: u64,
    pub initial_base: [u8; 32],
    pub not_before: u64,
    pub expires: u64,
    pub max_operations: u32,
    pub entries: Vec<Entry>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedGrant {
    pub fields: Fields,
    pub signature: [u8; 64],
}

fn checked_key(key: &[u8; 32]) -> Result<(), Error> {
    if key.iter().all(|byte| *byte == 0)
        || VerifyingKey::from_bytes(key).map_or(true, |key| key.is_weak())
    {
        return Err(Error::Key);
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn fixture() -> (SignedGrant, Vec<u8>) {
        let owner = SigningKey::from_bytes(&[7; 32]);
        let subject = SigningKey::from_bytes(&[8; 32]);
        let receipt = SigningKey::from_bytes(&[9; 32]);
        let fields = Fields {
            audience: "https://host.example".into(),
            repository: "repo".into(),
            exact_ref: "refs/heads/main".into(),
            workspace_id: [11; 32],
            issuer: owner.verifying_key().to_bytes(),
            subject: subject.verifying_key().to_bytes(),
            receipt_signer: receipt.verifying_key().to_bytes(),
            authority_generation: u64::MAX,
            grant_generation: 1,
            initial_base: [12; 32],
            not_before: 1_700_000_000_000,
            expires: 1_700_000_060_000,
            max_operations: 64,
            entries: vec![
                Entry {
                    components: vec!["a!".into(), "selected.txt".into()],
                    mask: 1,
                },
                Entry {
                    components: vec!["a".into(), "z*.txt".into()],
                    mask: 3,
                },
            ],
        };
        let unsigned = encode_unsigned(&fields).unwrap();
        let signature = owner.sign(&signing_digest(&unsigned)).to_bytes();
        let grant = SignedGrant { fields, signature };
        let signed = encode_signed(&grant).unwrap();
        (grant, signed)
    }

    #[test]
    fn canonical_round_trip_and_strict_signature() {
        let (grant, signed) = fixture();
        assert_eq!(verify_signature(&signed), Ok(grant));
        assert_ne!(
            grant_id(&signed),
            signing_digest(&signed[..signed.len() - 64])
        );
        let mut wrong = signed.clone();
        *wrong.last_mut().unwrap() ^= 1;
        assert_eq!(verify_signature(&wrong), Err(Error::Signature));
        wrong = signed.clone();
        wrong.extend_from_slice(&[0]);
        assert_eq!(decode(&wrong), Err(Error::Trailing));
        wrong = signed.clone();
        wrong[0] = b'X';
        assert_eq!(decode(&wrong), Err(Error::Magic));
    }

    #[test]
    fn selected_path_grammar_and_masks_are_literal() {
        let (mut grant, _) = fixture();
        assert!(validate(&grant.fields).is_ok()); // `*` is a literal name byte.
        grant.fields.entries[0].components[0] = ".MKIT-SCOPED".into();
        assert_eq!(validate(&grant.fields), Err(Error::Path));
        grant.fields.entries[0].components[0] = ".mkit".into();
        assert_eq!(validate(&grant.fields), Err(Error::Path));
        grant.fields.entries[0].components[0] = "a!".into();
        grant.fields.entries[0].mask = 2;
        assert_eq!(validate(&grant.fields), Err(Error::Mask));
        grant.fields.entries[0].mask = 1;
        grant.fields.entries.swap(0, 1);
        assert_eq!(validate(&grant.fields), Err(Error::Path));
    }

    #[test]
    fn length_and_varint_mutations_fail() {
        let (_, signed) = fixture();
        let mut overlong = signed.clone();
        // The first length is 20; rewrite it in a nonminimal two-byte form.
        overlong.splice(5..6, [0x94, 0x00]);
        assert_eq!(decode(&overlong), Err(Error::Varint));
        let mut overflow = signed.clone();
        overflow.splice(5..6, [0xff, 0xff, 0xff, 0xff, 0x10]);
        assert_eq!(decode(&overflow), Err(Error::Varint));
        assert_eq!(decode(&signed[..signed.len() - 1]), Err(Error::Truncated));
    }

    #[test]
    fn golden_bytes_are_committed() {
        let (grant, signed) = fixture();
        let root = std::path::Path::new("../../rust/tests/golden/hosted-workspace-grants");
        let mut cases = vec![("valid.bin", signed.clone(), None)];
        let mut nonminimal = signed.clone();
        nonminimal.splice(5..6, [0x94, 0]);
        cases.push(("nonminimal-varint.bin", nonminimal, Some(Error::Varint)));
        let mut overflow = signed.clone();
        overflow.splice(5..6, [0xff, 0xff, 0xff, 0xff, 0x10]);
        cases.push(("overflow-varint.bin", overflow, Some(Error::Varint)));
        let mut trailing = signed.clone();
        trailing.push(0);
        cases.push(("trailing.bin", trailing, Some(Error::Trailing)));
        let mut signature = signed.clone();
        *signature.last_mut().unwrap() ^= 1;
        cases.push(("wrong-signature.bin", signature, Some(Error::Signature)));
        let mut mask = signed.clone();
        mask[signed.len() - 65] = 2;
        cases.push(("invalid-mask.bin", mask, Some(Error::Mask)));
        let write =
            std::env::var_os("MKIT_WRITE_GOLDEN").as_deref() == Some(std::ffi::OsStr::new("1"));
        if write {
            std::fs::create_dir_all(root).unwrap();
        }
        let mut manifest = String::new();
        for (name, value, expected) in cases {
            let path = root.join(name);
            if write {
                std::fs::write(&path, &value).unwrap();
            }
            assert_eq!(std::fs::read(&path).unwrap(), value);
            if let Some(error) = expected {
                assert_eq!(verify_signature(&value), Err(error));
            }
            manifest.push_str(&format!("{}  {name}\n", blake3::hash(&value).to_hex()));
        }
        if write {
            std::fs::write(root.join("MANIFEST.txt"), &manifest).unwrap();
        }
        assert_eq!(
            std::fs::read_to_string(root.join("MANIFEST.txt")).unwrap(),
            manifest
        );
        let sidecar: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.join("valid.meta.json")).unwrap()).unwrap();
        assert_eq!(sidecar["grant_id"], hex_for_test(&grant_id(&signed)));
        assert_eq!(sidecar["authority_generation"], u64::MAX.to_string());
        assert_eq!(
            sidecar["workspace_id"],
            hex_for_test(&grant.fields.workspace_id)
        );
        assert_eq!(
            sidecar["entries"].as_array().unwrap().len(),
            grant.fields.entries.len()
        );
    }

    fn hex_for_test(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}

pub fn validate(fields: &Fields) -> Result<(), Error> {
    if fields.audience.len() > 512
        || validate_audience(&fields.audience).is_err()
        || fields.repository.is_empty()
        || fields.repository.len() > 255
        || !fields
            .repository
            .bytes()
            .all(|b| (0x21..=0x7e).contains(&b))
        || fields.exact_ref.len() > 1024
        || !fields.exact_ref.starts_with("refs/heads/")
        || !validate_ref_name(&fields.exact_ref)
    {
        return Err(Error::Context);
    }
    for key in [&fields.issuer, &fields.subject, &fields.receipt_signer] {
        checked_key(key)?;
    }
    if fields.authority_generation == 0
        || fields.grant_generation == 0
        || !(1..=256).contains(&fields.max_operations)
    {
        return Err(Error::Bound);
    }
    if fields
        .expires
        .checked_sub(fields.not_before)
        .is_none_or(|v| v == 0 || v > DAY_MS)
    {
        return Err(Error::Time);
    }
    if fields.entries.is_empty() || fields.entries.len() > MAX_PATHS {
        return Err(Error::Bound);
    }
    let mut previous = Vec::new();
    let mut total = 0usize;
    for entry in &fields.entries {
        if entry.mask != 1 && entry.mask != 3 {
            return Err(Error::Mask);
        }
        if entry.components.is_empty() || entry.components.len() > 32 {
            return Err(Error::Path);
        }
        let mut joined = Vec::new();
        for (index, component) in entry.components.iter().enumerate() {
            let bytes = component.as_bytes();
            if bytes.is_empty()
                || bytes.len() > 255
                || !TreeEntry::validate_name(bytes)
                || component.chars().any(char::is_control)
                || (index == 0 && bytes.eq_ignore_ascii_case(b".mkit-scoped"))
            {
                return Err(Error::Path);
            }
            if index != 0 {
                joined.push(b'/');
            }
            joined.extend_from_slice(bytes);
        }
        if joined.len() > 1024 || (!previous.is_empty() && joined <= previous) {
            return Err(Error::Path);
        }
        total = total.checked_add(joined.len()).ok_or(Error::Bound)?;
        if total > 64 * 1024 {
            return Err(Error::Bound);
        }
        previous = joined;
    }
    Ok(())
}

fn bytes(value: &[u8], output: &mut Vec<u8>) {
    value.len().write(output);
    output.extend_from_slice(value);
}

pub fn encode_unsigned(fields: &Fields) -> Result<Vec<u8>, Error> {
    validate(fields)?;
    let mut out = Vec::new();
    out.extend_from_slice(b"MKHG\x01");
    for value in [&fields.audience, &fields.repository, &fields.exact_ref] {
        bytes(value.as_bytes(), &mut out);
    }
    for value in [
        &fields.workspace_id,
        &fields.issuer,
        &fields.subject,
        &fields.receipt_signer,
    ] {
        value.write(&mut out);
    }
    for value in [fields.authority_generation, fields.grant_generation] {
        value.write(&mut out);
    }
    fields.initial_base.write(&mut out);
    for value in [fields.not_before, fields.expires] {
        value.write(&mut out);
    }
    fields.max_operations.write(&mut out);
    fields.entries.len().write(&mut out);
    for entry in &fields.entries {
        entry.components.len().write(&mut out);
        for component in &entry.components {
            bytes(component.as_bytes(), &mut out);
        }
        entry.mask.write(&mut out);
    }
    if out.len() + 64 > MAX_ENVELOPE {
        return Err(Error::EnvelopeSize);
    }
    Ok(out)
}

pub fn signing_digest(unsigned: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(SIGN_DOMAIN);
    h.update(unsigned);
    *h.finalize().as_bytes()
}

pub fn encode_signed(grant: &SignedGrant) -> Result<Vec<u8>, Error> {
    let mut out = encode_unsigned(&grant.fields)?;
    out.extend_from_slice(&grant.signature);
    Ok(out)
}

pub fn grant_id(signed: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(ID_DOMAIN);
    h.update(signed);
    *h.finalize().as_bytes()
}

struct Reader<'a> {
    input: &'a [u8],
    at: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], Error> {
        let end = self.at.checked_add(length).ok_or(Error::Bound)?;
        let slice = self.input.get(self.at..end).ok_or(Error::Truncated)?;
        self.at = end;
        Ok(slice)
    }
    fn count(&mut self, cap: usize) -> Result<usize, Error> {
        let mut remaining = &self.input[self.at..];
        let value = usize::read_cfg(&mut remaining, &RangeCfg::new(0..=u32::MAX as usize))
            .map_err(|_| Error::Varint)?;
        let consumed = self.input.len() - self.at - remaining.len();
        if consumed > 5 {
            return Err(Error::Varint);
        }
        if value > cap {
            return Err(Error::Bound);
        }
        self.at += consumed;
        Ok(value)
    }
    fn string(&mut self, cap: usize) -> Result<String, Error> {
        let count = self.count(cap)?;
        let text = std::str::from_utf8(self.take(count)?).map_err(|_| Error::Utf8)?;
        Ok(text.to_owned())
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let value = <[u8; N]>::read(&mut &self.input[self.at..]).map_err(|_| Error::Truncated)?;
        self.at += N;
        Ok(value)
    }
    fn u64(&mut self) -> Result<u64, Error> {
        let value = u64::read(&mut &self.input[self.at..]).map_err(|_| Error::Truncated)?;
        self.at += 8;
        Ok(value)
    }
}

pub fn decode(input: &[u8]) -> Result<SignedGrant, Error> {
    if input.len() > MAX_ENVELOPE {
        return Err(Error::EnvelopeSize);
    }
    let mut r = Reader { input, at: 0 };
    if r.take(4)? != b"MKHG" {
        return Err(Error::Magic);
    }
    if r.take(1)? != [1] {
        return Err(Error::Version);
    }
    let audience = r.string(512)?;
    let repository = r.string(255)?;
    let exact_ref = r.string(1024)?;
    let workspace_id = r.array()?;
    let issuer = r.array()?;
    let subject = r.array()?;
    let receipt_signer = r.array()?;
    let authority_generation = r.u64()?;
    let grant_generation = r.u64()?;
    let initial_base = r.array()?;
    let not_before = r.u64()?;
    let expires = r.u64()?;
    let max_operations = u32::from_be_bytes(r.array()?);
    let count = r.count(MAX_PATHS)?;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let depth = r.count(32)?;
        let mut components = Vec::with_capacity(depth);
        for _ in 0..depth {
            components.push(r.string(255)?);
        }
        entries.push(Entry {
            components,
            mask: r.take(1)?[0],
        });
    }
    let signature = r.array()?;
    if r.at != input.len() {
        return Err(Error::Trailing);
    }
    let grant = SignedGrant {
        fields: Fields {
            audience,
            repository,
            exact_ref,
            workspace_id,
            issuer,
            subject,
            receipt_signer,
            authority_generation,
            grant_generation,
            initial_base,
            not_before,
            expires,
            max_operations,
            entries,
        },
        signature,
    };
    validate(&grant.fields)?;
    Ok(grant)
}

/// Proves intrinsic signature validity only. It does not establish current authority.
pub fn verify_signature(input: &[u8]) -> Result<SignedGrant, Error> {
    let grant = decode(input)?;
    let unsigned = &input[..input.len() - 64];
    let key = VerifyingKey::from_bytes(&grant.fields.issuer).map_err(|_| Error::Key)?;
    key.verify_strict(
        &signing_digest(unsigned),
        &Signature::from_bytes(&grant.signature),
    )
    .map_err(|_| Error::Signature)?;
    Ok(grant)
}

#[cfg(feature = "hosting-wasm")]
mod wasm {
    use super::*;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use wasm_bindgen::prelude::*;
    #[derive(Serialize)]
    struct Facts {
        grant_id: String,
        audience: String,
        repository: String,
        exact_ref: String,
        workspace_id: String,
        issuer: String,
        subject: String,
        receipt_signer: String,
        authority_generation: String,
        grant_generation: String,
        initial_base: String,
        not_before: String,
        expires: String,
        max_operations: u32,
        entries: Vec<Entry>,
    }
    #[wasm_bindgen]
    pub fn hosting_verify_grant(base64url: &str) -> Result<String, JsValue> {
        let raw = URL_SAFE_NO_PAD
            .decode(base64url)
            .map_err(|_| JsValue::from_str("invalid base64url"))?;
        if URL_SAFE_NO_PAD.encode(&raw) != base64url {
            return Err(JsValue::from_str("noncanonical base64url"));
        }
        let grant = verify_signature(&raw).map_err(|e| JsValue::from_str(&format!("{e:?}")))?;
        let f = grant.fields;
        serde_json::to_string(&Facts {
            grant_id: hex(&grant_id(&raw)),
            audience: f.audience,
            repository: f.repository,
            exact_ref: f.exact_ref,
            workspace_id: hex(&f.workspace_id),
            issuer: hex(&f.issuer),
            subject: hex(&f.subject),
            receipt_signer: hex(&f.receipt_signer),
            authority_generation: f.authority_generation.to_string(),
            grant_generation: f.grant_generation.to_string(),
            initial_base: hex(&f.initial_base),
            not_before: f.not_before.to_string(),
            expires: f.expires.to_string(),
            max_operations: f.max_operations,
            entries: f.entries,
        })
        .map_err(|_| JsValue::from_str("serialization"))
    }
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
