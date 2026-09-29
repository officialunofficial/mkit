//! Owner signing for `mkit grant create`, `mkit epoch bump` and
//! `mkit visibility set` (WP-2.13, R-155).
//!
//! One module, three ways to get the SPEC-WRITE-GRANTS §4 signature:
//!
//! * **Native.** `ed25519` signs BLAKE3(statement) with the configured mkit
//!   signing key (the key `mkit commit` and the auth v2 envelope use), so the
//!   namespace is `ed25519-<pubkey>`. `secp256k1-eip191` signs the EIP-191
//!   digest with a software-keystore secp256k1 key through
//!   [`KeySigner::sign_prehash_recoverable_secp256k1`]; the namespace is the
//!   key's `0x` address. Hardware and OS-native keys can't do this and say so.
//! * **Print, then import.** `--print-statement` writes the exact statement
//!   bytes for a wallet or authenticator. The signature comes back with
//!   `--statement-file <that file> --signature <r‖s‖v hex>` (EIP-191), or
//!   `--webauthn-assertion <file>` (P-256, which needs a pinned relying party).
//!   Imported values are normalized (`v` of 0/1 becomes 27/28, a high `s`
//!   becomes low `s` with `v` flipped, a DER signature becomes raw low-`s`)
//!   and never trusted as given.
//! * Whatever the source, [`produce`] verifies the finished header with the
//!   `mkit-attest` verifier before anyone stores or sends it.

use std::fmt::Write as _;
use std::io::Read as _;
use std::path::Path;
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use clap::{Args, ValueEnum};
use mkit_attest::eth;
use mkit_attest::grant::{
    Namespace, OwnerScheme, RelyingParty, RepositoryIdentity, SignedHeader, WebAuthnAssertion,
    webauthn_challenge,
};
use mkit_core::hash::{hash, to_hex_bytes};
use mkit_keystore::{Algorithm, KeyRef, KeySelector, KeySigner, open_backend};
use mkit_transport_connect::EnvelopeSigner;

use super::{HeaderError, verify_epoch_header, verify_grant_header, verify_visibility_header};
use crate::config::Config;

/// Largest statement file or assertion file read.
const MAX_IMPORT_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SchemeArg {
    #[value(name = "ed25519")]
    Ed25519,
    #[value(name = "secp256k1-eip191")]
    Secp256k1Eip191,
    #[value(name = "webauthn-p256")]
    WebAuthnP256,
}

impl From<SchemeArg> for OwnerScheme {
    fn from(arg: SchemeArg) -> Self {
        match arg {
            SchemeArg::Ed25519 => Self::Ed25519,
            SchemeArg::Secp256k1Eip191 => Self::Secp256k1Eip191,
            SchemeArg::WebAuthnP256 => Self::WebAuthnP256,
        }
    }
}

/// The signing flags shared by the three commands.
#[derive(Debug, Clone, Default, Args)]
pub struct OwnerArgs {
    /// Owner signature scheme. Default `ed25519`: the configured mkit signing
    /// key. `secp256k1-eip191` uses a software-keystore secp256k1 key
    /// (`key.secp256k1_ref`).
    #[arg(long, value_enum, value_name = "SCHEME")]
    pub scheme: Option<SchemeArg>,
    /// Print the exact statement bytes to stdout (and the digest or challenge
    /// to sign on stderr) instead of signing, for a wallet or authenticator.
    #[arg(long)]
    pub print_statement: bool,
    /// Import a signature over the statement in this file (written with
    /// --print-statement): use with --signature or --webauthn-assertion.
    #[arg(long, value_name = "FILE")]
    pub statement_file: Option<std::path::PathBuf>,
    /// A 65-byte `r‖s‖v` EIP-191 signature in hex, from a wallet. `v` may be
    /// 0, 1, 27 or 28; a high `s` is normalized.
    #[arg(long, value_name = "HEX", requires = "statement_file")]
    pub signature: Option<String>,
    /// A `WebAuthn` assertion as JSON with base64url fields `publicKey` (64
    /// bytes, x‖y), `authenticatorData`, `clientDataJSON` and `signature`
    /// (DER or raw). Needs `grant.webauthn_rp` in the user config.
    #[arg(
        long,
        value_name = "FILE",
        requires = "statement_file",
        conflicts_with = "signature"
    )]
    pub webauthn_assertion: Option<std::path::PathBuf>,
}

/// A key that can sign natively.
pub struct NativeOwner {
    namespace: Namespace,
    scheme: OwnerScheme,
    inner: NativeKey,
}

enum NativeKey {
    Ed25519(Arc<dyn EnvelopeSigner>),
    Secp256k1(Mutex<Box<dyn KeySigner>>),
}

impl std::fmt::Debug for NativeOwner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeOwner")
            .field("namespace", &self.namespace.to_string())
            .field("scheme", &self.scheme)
            .finish_non_exhaustive()
    }
}

impl NativeOwner {
    /// An `ed25519` owner. The signer signs a raw 32-byte digest, which is
    /// exactly what §4 needs: BLAKE3 of the statement.
    ///
    /// # Errors
    /// A public key that is not 32 bytes of hex.
    pub fn ed25519(signer: Arc<dyn EnvelopeSigner>) -> Result<Self, String> {
        let key = mkit_core::hash::from_hex(&signer.public_key_hex())
            .map_err(|e| format!("signing key is not an Ed25519 public key: {e}"))?;
        Ok(Self {
            namespace: Namespace::Ed25519(key),
            scheme: OwnerScheme::Ed25519,
            inner: NativeKey::Ed25519(signer),
        })
    }

    /// A `secp256k1-eip191` owner from a keystore signer.
    ///
    /// # Errors
    /// A key that is not secp256k1.
    pub fn secp256k1(signer: Box<dyn KeySigner>) -> Result<Self, String> {
        if signer.algorithm() != Algorithm::Secp256k1 {
            return Err("the configured key is not a secp256k1 key".to_owned());
        }
        let public = signer
            .public_key()
            .map_err(|e| format!("keystore public key: {e}"))?;
        let point = k256::ecdsa::VerifyingKey::from_sec1_bytes(public.as_bytes())
            .map_err(|e| format!("keystore secp256k1 public key: {e}"))?
            .to_sec1_point(false);
        let xy: [u8; 64] = point
            .as_bytes()
            .get(1..65)
            .and_then(|b| b.try_into().ok())
            .ok_or("keystore secp256k1 public key has an unexpected encoding")?;
        let address = eth::address_secp256k1(&xy).map_err(|e| e.to_string())?;
        Ok(Self {
            namespace: Namespace::Address(address),
            scheme: OwnerScheme::Secp256k1Eip191,
            inner: NativeKey::Secp256k1(Mutex::new(signer)),
        })
    }

    /// Open `key.secp256k1_ref` from the configured keystore.
    ///
    /// # Errors
    /// A missing key or a backend that can't open it.
    pub fn open_secp256k1(cfg: &Config) -> Result<Self, String> {
        let text = cfg.key.secp256k1_ref_or_fallback();
        let key_ref = text
            .parse::<KeyRef>()
            .map_err(|e| format!("key.secp256k1_ref `{text}`: {e}"))?;
        let store =
            open_backend(key_ref.backend()).map_err(|e| format!("keystore backend: {e}"))?;
        let selector = KeySelector::new(key_ref.label().to_owned(), Some(Algorithm::Secp256k1))
            .map_err(|e| format!("key.secp256k1_ref `{text}`: {e}"))?;
        let opener = store.opener().ok_or_else(|| {
            format!(
                "keystore backend `{}` does not support opening keys",
                key_ref.backend()
            )
        })?;
        let signer = opener.open(&selector).map_err(|e| {
            format!(
                "no secp256k1 key `{text}` — run `mkit key generate --backend {} --algorithm secp256k1 --label {}` first: {e}",
                key_ref.backend(),
                key_ref.label()
            )
        })?;
        Self::secp256k1(signer)
    }

    #[must_use]
    pub fn namespace(&self) -> &Namespace {
        &self.namespace
    }

    #[must_use]
    pub fn scheme(&self) -> OwnerScheme {
        self.scheme
    }

    /// The §4 signature blob over `statement`.
    ///
    /// # Errors
    /// The signer refused (locked, hardware, unsupported).
    pub fn sign(&self, statement: &[u8]) -> Result<Vec<u8>, String> {
        match &self.inner {
            NativeKey::Ed25519(signer) => {
                let hex = signer.sign_hex(&hash(statement))?;
                hex::decode(hex).map_err(|e| format!("signer returned invalid hex: {e}"))
            }
            NativeKey::Secp256k1(signer) => {
                let mut guard = signer
                    .lock()
                    .map_err(|_| "keystore signer mutex poisoned".to_owned())?;
                let sig = guard
                    .sign_prehash_recoverable_secp256k1(&eth::eip191_hash(statement))
                    .map_err(|e| match e {
                        mkit_keystore::Error::UnsupportedOperation(_) => format!(
                            "this key can't sign secp256k1-eip191 natively ({e}); only software-keystore secp256k1 keys can — use --print-statement and import a wallet signature instead"
                        ),
                        other => format!("keystore signing failed: {other}"),
                    })?;
                Ok(sig.to_vec())
            }
        }
    }
}

/// How a statement gets its signature.
#[derive(Debug)]
pub enum Plan {
    /// Build the statement, sign it with a local key.
    Native(NativeOwner),
    /// Build the statement for `namespace` and print it.
    Print { namespace: Namespace },
    /// The statement and signature were made elsewhere.
    Import {
        statement: Vec<u8>,
        scheme: OwnerScheme,
        blob: Vec<u8>,
    },
}

/// What the caller knows when choosing a plan.
#[allow(missing_debug_implementations)] // holds a closure
pub struct SignCtx<'a> {
    /// Resolves the native Ed25519 key. Called only when needed.
    pub ed25519: &'a dyn Fn() -> Result<NativeOwner, String>,
    pub cfg: &'a Config,
    pub relying_parties: &'a [RelyingParty],
}

/// Choose how to sign. `namespace_hint` is the namespace the command asked
/// for (`--namespace`, or the repository's), if any.
///
/// # Errors
/// Contradictory flags, an unreadable import, or no usable key.
pub fn resolve(
    args: &OwnerArgs,
    namespace_hint: Option<Namespace>,
    ctx: &SignCtx<'_>,
) -> Result<Plan, String> {
    if let Some(path) = &args.statement_file {
        if args.print_statement {
            return Err("--print-statement and --statement-file can't be combined".to_owned());
        }
        let statement = read_statement_file(path)?;
        let (scheme, blob) = match (&args.signature, &args.webauthn_assertion) {
            (Some(hex), None) => (OwnerScheme::Secp256k1Eip191, import_eip191(hex)?.to_vec()),
            (None, Some(file)) => (
                OwnerScheme::WebAuthnP256,
                import_webauthn(file, ctx.relying_parties)?,
            ),
            _ => {
                return Err(
                    "--statement-file needs --signature <hex> or --webauthn-assertion <file>"
                        .to_owned(),
                );
            }
        };
        if let Some(chosen) = args.scheme
            && OwnerScheme::from(chosen) != scheme
        {
            return Err(format!(
                "--scheme {} doesn't match the imported signature ({})",
                OwnerScheme::from(chosen).token(),
                scheme.token()
            ));
        }
        return Ok(Plan::Import {
            statement,
            scheme,
            blob,
        });
    }
    if args.print_statement {
        let namespace = match namespace_hint {
            Some(ns) => ns,
            None => *native(args, ctx)?.namespace(),
        };
        return Ok(Plan::Print { namespace });
    }
    let owner = native(args, ctx)?;
    if let Some(hint) = namespace_hint
        && hint != *owner.namespace()
    {
        return Err(format!(
            "the signing key owns namespace {}, not {hint}; to sign for {hint} with a wallet or authenticator use --print-statement",
            owner.namespace()
        ));
    }
    Ok(Plan::Native(owner))
}

fn native(args: &OwnerArgs, ctx: &SignCtx<'_>) -> Result<NativeOwner, String> {
    match args.scheme.map_or(OwnerScheme::Ed25519, OwnerScheme::from) {
        OwnerScheme::Ed25519 => (ctx.ed25519)(),
        OwnerScheme::Secp256k1Eip191 => NativeOwner::open_secp256k1(ctx.cfg),
        _ => Err(
            "webauthn-p256 signatures come from an authenticator: run with --print-statement, sign the printed challenge, then pass --statement-file and --webauthn-assertion"
                .to_owned(),
        ),
    }
}

fn read_bounded(path: &Path, what: &str) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .and_then(|file| file.take(MAX_IMPORT_BYTES + 1).read_to_end(&mut bytes))
        .map_err(|e| format!("{what} {}: {e}", path.display()))?;
    if bytes.len() as u64 > MAX_IMPORT_BYTES {
        return Err(format!("{what} {} is too large", path.display()));
    }
    Ok(bytes)
}

fn read_statement_file(path: &Path) -> Result<Vec<u8>, String> {
    let bytes = read_bounded(path, "statement file")?;
    if bytes.last() == Some(&b'\n') {
        return Err(format!(
            "statement file {} ends with a line feed, but a statement has none; write it with `--print-statement > {}` and don't edit it",
            path.display(),
            path.display()
        ));
    }
    Ok(bytes)
}

/// A wallet's `r‖s‖v` in hex, normalized to the single form a verifier
/// accepts (§4.4).
///
/// # Errors
/// Not 65 bytes of hex, or `v`/`r`/`s` out of range.
pub fn import_eip191(hex_text: &str) -> Result<[u8; 65], String> {
    let text = hex_text.trim();
    let text = text.strip_prefix("0x").unwrap_or(text);
    let bytes = hex::decode(text).map_err(|e| format!("--signature is not hex: {e}"))?;
    let sig: [u8; 65] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("--signature must be 65 bytes (r‖s‖v), got {}", bytes.len()))?;
    eth::normalize_eip191_signature(sig).map_err(|e| format!("--signature: {e}"))
}

/// Build a `webauthn-p256` blob from an assertion file (see
/// [`OwnerArgs::webauthn_assertion`]). Refused unless a relying party is
/// pinned.
///
/// # Errors
/// No pinned relying party, a malformed file, or a signature that isn't DER
/// or low-`s` raw.
pub fn import_webauthn(path: &Path, rps: &[RelyingParty]) -> Result<Vec<u8>, String> {
    if rps.is_empty() {
        return Err(HeaderError::WebAuthnNotPinned.to_string());
    }
    let bytes = read_bounded(path, "WebAuthn assertion")?;
    let json: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| format!("WebAuthn assertion: not JSON: {e}"))?;
    let field = |name: &str| -> Result<Vec<u8>, String> {
        let text = json
            .get(name)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| format!("WebAuthn assertion: missing string field `{name}`"))?;
        URL_SAFE_NO_PAD
            .decode(text.trim_end_matches('='))
            .map_err(|e| format!("WebAuthn assertion: `{name}` is not base64url: {e}"))
    };
    let public_key: [u8; 64] = field("publicKey")?
        .as_slice()
        .try_into()
        .map_err(|_| "WebAuthn assertion: `publicKey` must be 64 bytes (x‖y)".to_owned())?;
    let signature = field("signature")?;
    let raw: [u8; 64] = match <[u8; 64]>::try_from(signature.as_slice()) {
        Ok(raw) => {
            eth::p256_check_raw_low_s(&raw).map_err(|e| {
                format!("WebAuthn assertion: raw `signature` must be low-s ({e}); supply the DER form and mkit will normalize it")
            })?;
            raw
        }
        Err(_) => eth::p256_der_to_low_s_raw(&signature)
            .map_err(|e| format!("WebAuthn assertion: `signature` is not strict DER ({e})"))?,
    };
    WebAuthnAssertion {
        public_key,
        authenticator_data: field("authenticatorData")?,
        client_data_json: field("clientDataJSON")?,
        signature: raw,
    }
    .encode()
    .map_err(|e| format!("WebAuthn assertion: {e}"))
}

/// Which statement a header carries, and so which verification applies.
#[derive(Debug, Clone, Copy)]
pub enum Kind<'a> {
    Grant,
    Epoch,
    Visibility(&'a RepositoryIdentity),
}

/// A statement with a verified owner signature.
#[derive(Debug, Clone)]
pub struct Signed {
    pub statement: Vec<u8>,
    pub header: String,
    pub scheme: OwnerScheme,
}

/// The outcome of [`produce`].
#[derive(Debug)]
pub enum Produced {
    Signed(Signed),
    Print {
        statement: Vec<u8>,
        namespace: Namespace,
    },
}

/// Carry out a [`Plan`]. `build` makes the statement bytes for a namespace and
/// is not called for an import. The header is verified against `kind` before
/// it is returned.
///
/// # Errors
/// The statement couldn't be built, the signer refused, or the verifier
/// rejected the result (the message names the rule).
pub fn produce(
    plan: Plan,
    build: impl FnOnce(&Namespace) -> Result<Vec<u8>, String>,
    kind: Kind<'_>,
    rps: &[RelyingParty],
    now_ms: i64,
) -> Result<Produced, String> {
    let (statement, scheme, blob) = match plan {
        Plan::Print { namespace } => {
            let statement = build(&namespace)?;
            return Ok(Produced::Print {
                statement,
                namespace,
            });
        }
        Plan::Native(owner) => {
            let statement = build(owner.namespace())?;
            let blob = owner.sign(&statement)?;
            (statement, owner.scheme(), blob)
        }
        Plan::Import {
            statement,
            scheme,
            blob,
        } => (statement, scheme, blob),
    };
    let header = SignedHeader {
        statement: statement.clone(),
        scheme,
        blob,
    }
    .encode()
    .map_err(|e| format!("header: {e}"))?;
    let rejected = |e: HeaderError| format!("the owner signature was rejected: {e}");
    match kind {
        Kind::Grant => verify_grant_header(&header, rps).map(|_| ()),
        Kind::Epoch => verify_epoch_header(&header, rps, now_ms).map(|_| ()),
        Kind::Visibility(repository) => {
            verify_visibility_header(&header, repository, rps, now_ms).map(|_| ())
        }
    }
    .map_err(rejected)?;
    Ok(Produced::Signed(Signed {
        statement,
        header,
        scheme,
    }))
}

/// Text for stderr when printing a statement to sign elsewhere.
#[must_use]
pub fn signing_instructions(statement: &[u8], namespace: &Namespace) -> String {
    let mut out = format!(
        "statement bytes: {} (namespace {namespace})\n",
        statement.len()
    );
    match namespace {
        Namespace::Ed25519(_) => {
            let _ = writeln!(
                out,
                "ed25519 message (BLAKE3 of the statement): {}",
                to_hex_bytes(&hash(statement))
            );
        }
        Namespace::Address(_) => {
            let _ = writeln!(
                out,
                "secp256k1-eip191: sign the statement bytes as an EIP-191 personal message (digest 0x{})",
                to_hex_bytes(&eth::eip191_hash(statement))
            );
            let _ = writeln!(
                out,
                "webauthn-p256: use this WebAuthn challenge (base64url): {}",
                webauthn_challenge(statement)
            );
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use k256::ecdsa::SigningKey as K256Key;
    use mkit_attest::grant::{Capabilities, Grant, RepoScope};

    use super::*;

    struct DalekSigner(ed25519_dalek::SigningKey);
    impl EnvelopeSigner for DalekSigner {
        fn public_key_hex(&self) -> String {
            to_hex_bytes(&self.0.verifying_key().to_bytes())
        }
        fn sign_hex(&self, message: &[u8; 32]) -> Result<String, String> {
            use ed25519_dalek::Signer as _;
            Ok(to_hex_bytes(&self.0.sign(message).to_bytes()))
        }
    }

    /// A keystore-shaped signer over a fixed k256 key, for exercising the
    /// module without a keystore on disk. The keystore's own tests cover
    /// `SoftwareSigner`.
    struct K256KeySigner {
        key: K256Key,
        label: mkit_keystore::KeyLabel,
    }
    impl KeySigner for K256KeySigner {
        fn algorithm(&self) -> Algorithm {
            Algorithm::Secp256k1
        }
        fn label(&self) -> &mkit_keystore::KeyLabel {
            &self.label
        }
        fn metadata(&self) -> mkit_keystore::Result<mkit_keystore::KeyMetadata> {
            unreachable!()
        }
        fn public_key(&self) -> mkit_keystore::Result<mkit_keystore::PublicKeyBytes> {
            Ok(mkit_keystore::PublicKeyBytes::new(
                self.key
                    .verifying_key()
                    .to_sec1_point(true)
                    .as_bytes()
                    .to_vec(),
            ))
        }
        fn keyid(&self) -> mkit_keystore::Result<mkit_keystore::KeyId> {
            unreachable!()
        }
        fn sign(&mut self, _msg: &[u8]) -> mkit_keystore::Result<Vec<u8>> {
            unreachable!()
        }
        fn sign_prehash_recoverable_secp256k1(
            &mut self,
            prehash: &[u8; 32],
        ) -> mkit_keystore::Result<[u8; 65]> {
            let (sig, recid) = self.key.sign_prehash_recoverable(prehash);
            let mut out = [0u8; 65];
            out[..64].copy_from_slice(&sig.normalize_s().to_bytes());
            out[64] = 27 + recid.to_byte();
            if sig.normalize_s() != sig {
                out[64] = if out[64] == 27 { 28 } else { 27 };
            }
            Ok(out)
        }
    }

    fn k256_owner(seed: u8) -> NativeOwner {
        NativeOwner::secp256k1(Box::new(K256KeySigner {
            key: K256Key::from_slice(&[seed; 32]).unwrap(),
            label: mkit_keystore::KeyLabel::new("test").unwrap(),
        }))
        .unwrap()
    }

    fn ed_owner(seed: u8) -> NativeOwner {
        NativeOwner::ed25519(Arc::new(DalekSigner(
            ed25519_dalek::SigningKey::from_bytes(&[seed; 32]),
        )))
        .unwrap()
    }

    const NOW: i64 = 1_800_000_000_000;

    fn grant_for(ns: &Namespace) -> Vec<u8> {
        Grant {
            namespace: *ns,
            scope: RepoScope::Namespace,
            grantee: [7; 32],
            capabilities: Capabilities::Read,
            audiences: vec!["https://git.example.com".to_owned()],
            ref_scopes: None,
            epoch: 0,
            created_ms: NOW,
            expiry_ms: NOW + 60_000,
            nonce: [9; 32],
        }
        .encode()
        .unwrap()
    }

    #[test]
    fn native_ed25519_and_secp256k1_grants_verify() {
        for owner in [ed_owner(3), k256_owner(0x11)] {
            let scheme = owner.scheme();
            let Produced::Signed(signed) = produce(
                Plan::Native(owner),
                |ns| Ok(grant_for(ns)),
                Kind::Grant,
                &[],
                NOW,
            )
            .unwrap() else {
                panic!("expected a signed header")
            };
            assert_eq!(signed.scheme, scheme);
            assert!(verify_grant_header(&signed.header, &[]).is_ok());
        }
    }

    #[test]
    fn wallet_signatures_are_normalized_for_every_v_spelling_and_high_s() {
        let owner = k256_owner(0x22);
        let ns = *owner.namespace();
        let statement = grant_for(&ns);
        let good: [u8; 65] = owner.sign(&statement).unwrap().try_into().unwrap();
        // The high-s twin: n - s, v flipped.
        let n = hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
            .unwrap();
        let mut twin = good;
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let d = i16::from(n[i]) - i16::from(good[32 + i]) - borrow;
            borrow = i16::from(d < 0);
            twin[32 + i] = (d + 256 * borrow).to_le_bytes()[0];
        }
        twin[64] = if good[64] == 27 { 28 } else { 27 };
        for base in [good, twin] {
            for v_style in [0u8, 27] {
                let mut wallet = base;
                wallet[64] = base[64] - 27 + v_style;
                let imported = import_eip191(&hex::encode(wallet)).unwrap();
                assert_eq!(imported, good, "v = {}", wallet[64]);
                let Produced::Signed(signed) = produce(
                    Plan::Import {
                        statement: statement.clone(),
                        scheme: OwnerScheme::Secp256k1Eip191,
                        blob: imported.to_vec(),
                    },
                    |_| unreachable!("imports don't build"),
                    Kind::Grant,
                    &[],
                    NOW,
                )
                .unwrap() else {
                    panic!()
                };
                assert!(verify_grant_header(&signed.header, &[]).is_ok());
            }
        }
        // 0x prefix accepted, wrong length and bad v refused.
        assert!(import_eip191(&format!("0x{}", hex::encode(good))).is_ok());
        assert!(import_eip191(&hex::encode(&good[..64])).is_err());
        let mut bad_v = good;
        bad_v[64] = 5;
        assert!(import_eip191(&hex::encode(bad_v)).is_err());
    }

    #[test]
    fn wallet_vectors_from_the_golden_file_normalize() {
        let golden: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../tests/golden/grants/eth-primitives.json"
        ))
        .unwrap();
        for case in golden["high_s"].as_array().unwrap() {
            let high = case["signature"].as_str().unwrap();
            let low = case["normalized"].as_str().unwrap();
            let high_bytes = hex::decode(high).unwrap();
            for v_style in [0u8, 27] {
                let mut sig = high_bytes.clone();
                sig[64] = sig[64] - 27 + v_style;
                assert_eq!(
                    hex::encode(import_eip191(&hex::encode(sig)).unwrap()),
                    low,
                    "{}",
                    case["name"]
                );
            }
        }
    }

    #[test]
    fn a_signature_from_another_key_is_rejected_naming_the_rule() {
        let owner = k256_owner(0x22);
        let statement = grant_for(owner.namespace());
        let other = k256_owner(0x33).sign(&statement).unwrap();
        let error = produce(
            Plan::Import {
                statement,
                scheme: OwnerScheme::Secp256k1Eip191,
                blob: other,
            },
            |_| unreachable!(),
            Kind::Grant,
            &[],
            NOW,
        )
        .unwrap_err();
        assert!(error.contains("owner mismatch"), "{error}");
    }

    #[test]
    fn webauthn_import_is_refused_without_a_pinned_relying_party() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("assertion.json");
        std::fs::write(&file, b"{}").unwrap();
        let error = import_webauthn(&file, &[]).unwrap_err();
        assert!(error.contains("pinned relying party"), "{error}");
    }

    #[test]
    fn webauthn_der_signatures_are_normalized_to_low_s() {
        let golden: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../tests/golden/grants/eth-primitives.json"
        ))
        .unwrap();
        let case = golden["p256_der"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == "high-s")
            .unwrap();
        let der = hex::decode(case["der"].as_str().unwrap()).unwrap();
        let low = hex::decode(case["raw_low_s"].as_str().unwrap()).unwrap();
        let b64 = |b: &[u8]| URL_SAFE_NO_PAD.encode(b);
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("assertion.json");
        std::fs::write(
            &file,
            serde_json::json!({
                "publicKey": b64(&[1u8; 64]),
                "authenticatorData": b64(&[0u8; 37]),
                "clientDataJSON": b64(b"{}"),
                "signature": b64(&der),
            })
            .to_string(),
        )
        .unwrap();
        let rps = vec![RelyingParty::new("example.com", ["https://example.com"]).unwrap()];
        let blob = import_webauthn(&file, &rps).unwrap();
        let parsed = WebAuthnAssertion::parse(&blob).unwrap();
        assert_eq!(parsed.signature.as_slice(), low.as_slice());
        // A raw high-s signature is refused rather than silently altered.
        let raw_high = hex::decode(case["raw_high_s"].as_str().unwrap()).unwrap();
        std::fs::write(
            &file,
            serde_json::json!({
                "publicKey": b64(&[1u8; 64]),
                "authenticatorData": b64(&[0u8; 37]),
                "clientDataJSON": b64(b"{}"),
                "signature": b64(&raw_high),
            })
            .to_string(),
        )
        .unwrap();
        assert!(import_webauthn(&file, &rps).unwrap_err().contains("low-s"));
    }

    #[test]
    fn print_plan_returns_the_statement_and_instructions_name_the_digests() {
        let owner = k256_owner(0x44);
        let ns = *owner.namespace();
        let Produced::Print {
            statement,
            namespace,
        } = produce(
            Plan::Print { namespace: ns },
            |ns| Ok(grant_for(ns)),
            Kind::Grant,
            &[],
            NOW,
        )
        .unwrap()
        else {
            panic!()
        };
        assert_eq!(namespace, ns);
        let text = signing_instructions(&statement, &namespace);
        assert!(text.contains(&to_hex_bytes(&eth::eip191_hash(&statement))));
        assert!(text.contains(&webauthn_challenge(&statement)));
    }

    #[test]
    fn namespace_hint_must_match_the_native_key() {
        let owner = ed_owner(5);
        let cfg = Config::with_defaults();
        let make = || Ok(ed_owner(5));
        let ctx = SignCtx {
            ed25519: &make,
            cfg: &cfg,
            relying_parties: &[],
        };
        let args = OwnerArgs {
            scheme: None,
            print_statement: false,
            statement_file: None,
            signature: None,
            webauthn_assertion: None,
        };
        let other = Namespace::Address([1; 20]);
        assert!(
            resolve(&args, Some(other), &ctx)
                .unwrap_err()
                .contains("--print-statement")
        );
        assert!(resolve(&args, Some(*owner.namespace()), &ctx).is_ok());
    }

    #[test]
    fn statement_files_with_a_trailing_line_feed_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("s.txt");
        std::fs::write(&file, b"x\n").unwrap();
        assert!(
            read_statement_file(&file)
                .unwrap_err()
                .contains("line feed")
        );
    }
}
