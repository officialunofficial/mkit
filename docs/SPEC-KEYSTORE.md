---
spec: SPEC-KEYSTORE
version: 1
status: draft
audience: implementers and reviewers of the `mkit-keystore` crate, its CLI surface (`mkit key`), and the keystore-backed commit and attestation signers
---

# SPEC-KEYSTORE — mkit signing-key keystore

Status: **Normative** for `mkit-keystore` behavior. This file does not
specify wire formats; it specifies the keystore vault abstraction inside
mkit. ("Vault" throughout this document refers to the mkit keystore vault
abstraction, **not** HashiCorp Vault or any external secret manager.)

Authority: this file is the source of truth for `mkit-keystore` behavior.
If code, docs, or tests disagree with this file, update the implementation or
amend this specification in the same change.

Scope reminder: this spec covers the crate `rust/crates/mkit-keystore`, the
`mkit key` CLI command, the keystore-backed `mkit_attest::Signer` adapter,
and the keystore-backed commit signer adapter. External signers are specified
by SPEC-EXTERNAL-SIGNER, not here.

## 1. Purpose

`mkit` treats signatures as trust anchors for commits, remix objects, and
DSSE-wrapped in-toto attestations. Today, long-term signing keys are raw
32-byte files under `.mkit/keys/`, protected by strict local filesystem
hardening. That is a useful compatibility baseline, but it is not a
cross-platform vault policy.

`mkit-keystore` provides a generic signing-key vault abstraction over
software, OS-native, and hardware-backed key stores. It is deliberately a
signing keystore, not a protocol lifecycle system. It returns signer handles;
callers decide what those signers are allowed to sign.

This spec distinguishes two milestones:

- **Foundation V1**: the first implementation milestone. It creates the crate,
  API, CLI, config, deterministic software backend, commit-signing adapter, and
  attestation adapter. It is sufficient to start using and testing the
  abstraction, but it does not close issue #104.
- **Keystore V1**: the production keystore scope. It adds encrypted-at-rest
  software storage, explicit raw-file compatibility, OS-native extractable
  storage backends where implemented, keystore-backed commit/attestation
  signing, and honest capability reporting. It does not claim Secure Enclave,
  Windows TPM/CNG provider keys, TPM/PCR-bound systemd credentials, cloud KMS,
  PKCS#11/HSM support, or FIDO2/WebAuthn keystore signing.

Issue #104 may be resolved by this narrowed production contract only if project
discussion accepts these deferred items; otherwise the deferred
hardware/provider features remain follow-up work.

### 1.1 Implementation Status

This section summarizes what is implemented in the crate today. It is a
reading aid; the per-section requirements below remain the normative contract.

Shipped against this spec:

- `rust/crates/mkit-keystore` crate, public API (`Keystore`, `KeySigner`,
  `KeyGenerator`, `KeyImporter`, `KeyOpener`, `KeyLister`, `KeyExporter`,
  `KeyDeleter`), structured `Error` enum, typed wrappers (`KeyLabel`,
  `KeyRefLabel`, `KeyId`, `PublicKeyBytes`, `KeyRef`, `KeySelector`).
- `Capabilities` reporting structurally tied to operation-trait availability,
  with capability-honesty tests in each backend module.
- Software backend with encrypted-at-rest records (`software:<label>`,
  XChaCha20-Poly1305 + length-prefixed AAD over backend / label / algorithm /
  public key / key ID / attrs / protector ID, wrapped DEK in an OS protector).
- Software-raw compatibility backend (`software-raw:<label>`), reusing
  `mkit_core::sign::{load_raw_32, save_raw_32}` hardening.
- OS-native backends behind feature flags: `macos-keychain`,
  `windows-credential` (Credential Manager via DPAPI), `linux-secret-service`,
  `systemd-creds`.
- `YubiKey` backend behind `backend-yubikey` — OpenPGP signing slot (Ed25519)
  and PIV signing slot (P-256). secp256k1 is reported `UnsupportedAlgorithm`;
  FIDO2/CTAP keys are not handled in this backend and remain on the external
  signer path.
- `mkit key {generate,list,import,export,delete}` CLI with the flags and
  defaults specified in §9.
- Keystore-backed commit signing (`signer = keystore`) and attestation
  signing (`attest.signer = keystore`).
- Repo-forbidden config gating for every selector in §8 and the legacy
  selectors in §8.3.

Not yet shipped against this spec:

- In-memory backend (`BackendKind::Memory` exists in the enum, but no
  `MemoryKeystore` is implemented in this build).
- External signer keystore bridge (`BackendKind::External`) — `open_backend`
  returns `BackendUnavailable`; external signing continues to live in
  `mkit-rpc` per §12.
- Cloud KMS backend (`BackendKind::Cloud`) — same as above.
- Secure Enclave, Windows TPM/CNG provider-backed keys, TPM/PCR-bound
  `systemd-creds` semantics, bounded PIN/touch prompt providers for YubiKey,
  hardware ECDSA verification-equivalence CI for every required platform.

## 2. Non-Negotiable Design Decisions

1. `mkit-core` must remain lean. It must not depend on platform keychain,
   credential-manager, D-Bus, TPM, Secure Enclave, YubiKey, or cloud KMS
   dependencies.
2. Platform and vault dependencies live in a new crate,
   `rust/crates/mkit-keystore`, behind feature flags where appropriate.
3. Existing raw key files remain supported for compatibility. The current
   `mkit keygen` command remains as a legacy compatibility surface unless a
   future spec explicitly removes it.
4. New keystore UX is exposed through `mkit key ...`, not by changing the
   meaning of `mkit keygen` in-place.
5. Repo-controlled config must never select a backend, label, key reference,
   signer binary, or signing algorithm. All such selectors are user-scoped.
6. No signing command may silently generate or rotate a key. Key creation is
   explicit through `mkit key generate` or legacy `mkit keygen`.
7. Backend capabilities are explicit. A backend must not pretend to support
   export, import, user presence, hardware binding, or algorithm support that
   it cannot actually provide.
8. Byte-equal signature equivalence is required only where the backend is
   deterministic for the algorithm and imported key material. Hardware and OS
   ECDSA backends may produce valid but non-byte-equal signatures.
9. WASM builds must not depend on native keystore code. Browser integrations
   use an in-memory backend or a JS-side signer bridge in a later phase.
10. Foundation V1 must not be presented as full issue #104 completion. Keystore
    V1 is the production scope in section 15.2; deferred hardware/provider
    claims remain follow-up work unless explicitly implemented and tested.
11. For Keystore V1, `software:<label>` is the encrypted-at-rest software
    backend. Production `mkit-cli` builds must enable the target-appropriate OS
    protector feature, while `mkit-keystore` default features remain empty.
    Raw-file compatibility is exposed only through the explicit
    `software-raw:<label>` backend token and must not be the secure default.
12. The encrypted software backend must use OS-protected envelope encryption,
    not a password-derived key or an unaudited local encryption scheme.

## 3. Scope

### 3.1 In Scope

- Cross-platform persistence of long-term signing keys.
- Algorithms: Ed25519, secp256k1, and P-256.
- Generation, import, export where allowed, enumeration, opening, signing,
  metadata lookup, and deletion.
- A uniform signer handle abstraction that hides whether the key is software,
  OS-native, hardware-bound, or external.
- `mkit-cli` integration through `mkit key {generate,list,import,export,delete}`.
- `mkit-attest` integration through a keystore-backed implementation of its
  existing `Signer` trait.
- Ed25519 commit signing through a keystore signer handle.
- Test vectors proving compatibility with current software signing semantics.
- Threat-model documentation updates.

### 3.2 Out Of Scope

- Protocol-level enrollment, revocation, expiry, authorization policy, account
  mapping, or chain/project scoping.
- Secret sharing, threshold signing, social recovery, or Shamir schemes.
- Generic secrets management, environment variable injection, or arbitrary
  secret storage.
- Arbitrary blob encryption or decryption APIs.
- PKCS#11/HSM abstraction beyond the narrow signing handle model.
- Network-aware key semantics such as `this key signs for chain X`.
- Cloud KMS support in Keystore V1.
- PKCS#11/HSM support in Keystore V1.
- Secure Enclave, Windows TPM/CNG provider keys, or TPM/PCR-bound
  `systemd-creds` behavior unless implemented and capability-tested.
- Replacing all existing raw-key workflows in Foundation V1.

## 4. Crate Boundary

The new crate is:

```text
rust/crates/mkit-keystore
```

Workspace integration:

- Add `crates/mkit-keystore` to `rust/Cargo.toml` workspace members.
- The crate must use workspace package metadata, lints, edition, MSRV, and
  license policy.
- Default features must build on Linux and macOS CI without native service
  daemons, TPM libraries, smartcard libraries, or OS-specific SDK setup beyond
  what the target already provides.
- `mkit-keystore` default features remain empty/lean. Production `mkit-cli`
  builds, packages, and CI release gates must enable the platform-appropriate
  encrypted software protector feature so the configured `software` default is
  usable on supported targets while the library crate remains feature-gated.

Allowed dependencies:

- Pure-Rust crypto dependencies already used by the workspace may be reused.
- New direct dependencies must satisfy `docs/release/SUPPLY-CHAIN.md` and
  `rust/deny.toml`.
- OS-specific dependencies must be optional and feature-gated.

Forbidden dependencies:

- `mkit-core` must not depend on `mkit-keystore`.
- `mkit-wasm` must not depend on native `mkit-keystore` backends.
- Default workspace builds must not require Linux Secret Service, systemd,
  TPM libraries, YubiKey libraries, Windows APIs, or macOS GUI keychain access.

## 5. Public Rust API

The API below is normative for the Foundation V1 shape. Exact module names may
change during implementation only if this file is updated in the same PR.

### 5.1 Algorithm

`mkit-keystore` must expose an algorithm enum equivalent to
`mkit_attest::Algorithm`:

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Algorithm {
    Ed25519,
    Secp256k1,
    P256,
}
```

Requirements:

- `Algorithm` must convert to and from `mkit_attest::Algorithm` when the
  `attest` integration feature is enabled.
- Canonical string forms are exactly `ed25519`, `secp256k1`, and `p256`.
- The enum must not include backend-specific variants.

### 5.2 Key Attributes

```rust
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyAttrs {
    pub extractable: bool,
    pub require_user_presence: bool,
    pub device_bound: bool,
}
```

Semantics:

- `extractable = true` means `export` may return secret material.
- `extractable = false` means export must fail with a typed non-extractable
  error.
- `require_user_presence = true` requests a per-operation user-presence gate
  such as Touch ID, PIN, biometric prompt, or hardware touch.
- `device_bound = true` requests that a key cannot be restored onto another
  machine through backup or cloud sync.

`KeyAttrs::default()` is `{ extractable: true, require_user_presence: false,
device_bound: false }` because software-style storage decrypts into process
memory. Stronger backends that hold non-extractable keys advertise that
through `Capabilities::supports_non_extractable` and must reject
`extractable = true` import paths they cannot honor.

Backends may reject unsupported attribute combinations. They must not silently
weaken requested attributes.

### 5.3 Capabilities

```rust
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capabilities {
    pub backend: BackendKind,
    pub algorithms: Vec<Algorithm>,
    pub can_generate: bool,
    pub can_import: bool,
    pub can_export: bool,
    pub can_delete: bool,
    pub supports_listing: bool,
    pub supports_user_presence: bool,
    pub supports_device_bound: bool,
    pub supports_non_extractable: bool,
}
```

`BackendKind` must identify the backend family without exposing internal
implementation details:

```rust
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BackendKind {
    Software,
    SoftwareRaw,
    MacosKeychain,
    WindowsCredentialManager,
    LinuxSecretService,
    SystemdCreds,
    YubiKey,
    External,
    Cloud,
    Memory,
}
```

Requirements:

- Operation booleans must match operation-specific trait availability on the
  `Keystore` registry. They describe structural backend support, not a guarantee
  that the current session, daemon, hardware token, or protector is available.
- A backend compiled in but unavailable at runtime must return an unavailable
  error from construction or operations, and must not silently fall back to a
  weaker backend.
- Capability checks must be testable without performing a signing operation.

### 5.4 Key Metadata

```rust
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyMetadata {
    label: KeyLabel,
    pub backend: BackendKind,
    pub algorithm: Algorithm,
    public_key: PublicKeyBytes,
    keyid: KeyId,
    pub extractable: bool,
    pub require_user_presence: bool,
    pub device_bound: bool,
}

impl KeyMetadata {
    pub fn label(&self) -> &str;
    pub fn label_id(&self) -> &KeyLabel;
    pub fn backend(&self) -> BackendKind;
    pub fn algorithm(&self) -> Algorithm;
    pub fn keyid(&self) -> &str;
    pub fn key_id(&self) -> &KeyId;
    pub fn public_key(&self) -> &[u8];
    pub fn public_key_bytes(&self) -> &PublicKeyBytes;
}
```

Public key encodings:

- Ed25519: 32-byte raw public key.
- secp256k1: 33-byte compressed SEC1 public key by default.
- P-256: 33-byte compressed SEC1 public key by default.

Canonical key IDs:

- Ed25519 new canonical form: `ed25519:<64 lowercase hex raw pubkey>`.
- Ed25519 legacy attestation form remains accepted where already supported:
  `blake3:<64 lowercase hex blake3(pubkey)>`.
- secp256k1: `secp256k1:<66 lowercase hex compressed SEC1 pubkey>`.
- P-256: `p256:<66 lowercase hex compressed SEC1 pubkey>`.

The keystore must expose canonical key IDs. Compatibility adapters may emit
legacy key IDs only where existing verifier contracts require them. Public
`KeyId` values must be non-empty, must not contain control characters, and must
be at most 256 bytes.

### 5.5 Secret Key Material

```rust
pub struct SecretKey {
    algorithm: Algorithm,
    bytes: zeroize::Zeroizing<[u8; 32]>,
}

impl SecretKey {
    pub fn new(algorithm: Algorithm, bytes: [u8; 32]) -> Self;
    pub fn from_zeroizing(
        algorithm: Algorithm,
        bytes: zeroize::Zeroizing<[u8; 32]>,
    ) -> Self;
    pub fn algorithm(&self) -> Algorithm;
    pub fn expose_secret(&self) -> &[u8; 32];
    pub fn into_bytes(self) -> zeroize::Zeroizing<[u8; 32]>;
}

impl core::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result;
}
```

Requirements:

- Ed25519 bytes are the raw 32-byte seed, matching current
  `.mkit/keys/default.key` semantics.
- secp256k1 bytes are a raw 32-byte scalar accepted by the existing k256
  signer.
- P-256 bytes are a raw 32-byte scalar accepted by the existing p256 signer.
- Invalid scalar values must be rejected during import or signer construction.
- Secret material must use `zeroize` or equivalent workspace-approved
  zeroization.
- Secret bytes must not be public fields.
- `Debug` must be manually implemented and must never include secret bytes.
- Any accessor exposing secret bytes must be named to make the risk explicit,
  for example `expose_secret` or `into_bytes`.

### 5.6 Signer Handle

```rust
pub trait KeySigner: Send {
    fn algorithm(&self) -> Algorithm;
    fn label(&self) -> &KeyLabel;
    fn metadata(&self) -> Result<KeyMetadata, Error>;
    fn public_key(&self) -> Result<PublicKeyBytes, Error>;
    fn keyid(&self) -> Result<KeyId, Error>;
    fn sign(&mut self, msg: &[u8]) -> Result<Vec<u8>, Error>;
}
```

Requirements:

- `sign` takes `&mut self` to support backends with sessions, prompts, retry
  counters, cached public-key state, or external connections.
- The trait is `Send`, not `Send + Sync`, intentionally. Issue #104 sketched
  `Send + Sync`, but the implementation needs `&mut self` signing because many
  real backends have session state, prompt state, retry counters, cached
  handles, or child-process state. A concrete signer may still be `Sync`, but
  callers must not rely on concurrent signing through one handle.
- `sign` signs the supplied message according to the selected algorithm's
  existing mkit semantics. It must not invent additional protocol-level domain
  separation.
- Ed25519 signing signs the supplied bytes directly. DSSE passes the PAE bytes.
  Commit signing passes the 32-byte `mkit-core` commit signing hash described
  in section 10.
- secp256k1/P-256 signing follows existing `mkit-attest` semantics: ECDSA over
  SHA-256 of the supplied bytes, compact `r || s`, low-S canonical. DSSE passes
  the PAE bytes.

### 5.7 Keystore

Selectors identify keys for read, export, and deletion operations:

```rust
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeySelector {
    label: KeyLabel,
    pub algorithm: Option<Algorithm>,
}

impl KeySelector {
    pub fn new(label: impl Into<String>, algorithm: Option<Algorithm>) -> Result<Self, Error>;
    pub fn label(&self) -> &str;
    pub fn label_id(&self) -> &KeyLabel;
    pub fn algorithm(&self) -> Option<Algorithm>;
}
```

`algorithm = None` means "select by label only" and is valid only when the
backend has exactly one key with that label. If a backend has multiple keys with
the same label across algorithms, label-only selection must fail with an
ambiguous-key error.

```rust
pub trait Keystore: Send + Sync {
    fn capabilities(&self) -> Capabilities;
    fn generator(&self) -> Option<&dyn KeyGenerator>;
    fn importer(&self) -> Option<&dyn KeyImporter>;
    fn opener(&self) -> Option<&dyn KeyOpener>;
    fn lister(&self) -> Option<&dyn KeyLister>;
    fn exporter(&self) -> Option<&dyn KeyExporter>;
    fn deleter(&self) -> Option<&dyn KeyDeleter>;
}

pub trait KeyGenerator: Send + Sync {
    fn generate(
        &self,
        label: &KeyLabel,
        algorithm: Algorithm,
        attrs: KeyAttrs,
        options: GenerateOptions,
    ) -> Result<Box<dyn KeySigner>, Error>;
}

pub trait KeyImporter: Send + Sync {
    fn import(
        &self,
        label: &KeyLabel,
        secret: SecretKey,
        attrs: KeyAttrs,
        options: ImportOptions,
    ) -> Result<Box<dyn KeySigner>, Error>;
}

pub trait KeyOpener: Send + Sync {
    fn open(&self, selector: &KeySelector) -> Result<Box<dyn KeySigner>, Error>;
}

pub trait KeyLister: Send + Sync {
    fn list(&self) -> Result<Vec<KeyMetadata>, Error>;
}

pub trait KeyExporter: Send + Sync {
    fn export(&self, selector: &KeySelector) -> Result<SecretKey, Error>;
}

pub trait KeyDeleter: Send + Sync {
    fn delete(&self, selector: &KeySelector) -> Result<(), Error>;
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GenerateOptions {
    pub overwrite: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ImportOptions {
    pub overwrite: bool,
}
```

Requirements:

- Labels are backend-local names and must be valid UTF-8.
- Labels must reject empty strings, `:`, path separators, NUL, control
  characters, and leading/trailing whitespace.
- Backends may either enforce label uniqueness across algorithms or allow the
  same label for multiple algorithms. If they allow duplicate labels, callers
  must use `KeySelector.algorithm = Some(...)` for open/export/delete.
- The canonical key identity for create/import conflict checks is
  `(label, algorithm)`.
- `generate` and `import` must refuse to overwrite an existing
  `(label, algorithm)` unless `options.overwrite = true`.
- If `options.overwrite = true`, replacement semantics are backend-defined but
  must never delete or replace any key other than the exact `(label, algorithm)`
  being created/imported. Backends should make replacement atomic where the
  underlying vault supports it; otherwise they must document the non-atomic
  behavior in their backend notes and tests.
- Encrypted software backends must prove the existing record decrypts before an
  overwrite replaces it. If the protector is permanently unavailable, recovery
  requires manual record removal and wrapped-DEK cleanup rather than silent data
  loss.
- `open` must fail if the selector is missing or ambiguous.
- `list` must return deterministic ordering by `(backend, label, algorithm)`
  where the backend can list keys.
- `delete` must delete only the selected key and must not delete by prefix.
- `export` must fail for non-extractable keys.
- Operation support must be represented by operation-specific traits available
  through `Keystore`; non-exportable backends must not implement `KeyExporter`.
- Public APIs that accept labels, key references, key IDs, or public key bytes
  must use typed wrappers rather than unconstrained `String` values.

### 5.8 Error Taxonomy

`mkit-keystore::Error` must distinguish at least:

- unavailable backend
- unsupported algorithm
- unsupported operation
- unsupported attributes
- invalid label
- key already exists
- key not found
- ambiguous key selector
- key is not extractable
- invalid key material
- authentication required
- user declined
- operation timed out
- backend I/O failure
- backend access denied
- serialization or encoding failure
- internal error

Errors must be structured enums, not stringly typed. CLI commands may render
human-friendly messages from them.

User-facing `Display` output must redact backend-local labels, selectors,
filesystem paths, and arbitrary backend payloads. Full diagnostics remain
available through structured fields and developer/debug output.

## 6. Backend Requirements

### 6.1 Foundation V1 Required Backend: Software Compatibility Vault

Foundation V1 must include a software backend in `mkit-keystore`.

Purpose:

- Provide deterministic tests and a complete cross-platform baseline.
- Provide import/export semantics for golden vectors.
- Allow CLI and integration work to land before all OS-native backends are
  available.
- Preserve current raw-key workflows through an abstraction without claiming
  they satisfy the encrypted-at-rest Keystore V1 vault requirement.

Storage:

- Foundation V1 software keystore storage is user-scoped, not repo-scoped.
- Default storage root is `$XDG_DATA_HOME/mkit/keys/` on Unix-like platforms,
  falling back to `~/.local/share/mkit/keys/` when `XDG_DATA_HOME` is unset.
  Non-Unix platforms must use the platform's per-user application data
  directory or a documented equivalent.
- `software:<label>` maps to exactly one encrypted key record under that
  user-scoped storage root in Keystore V1. It must not resolve relative
  to the current repo.
- `software-raw:<label>` maps to exactly one raw compatibility key record under
  a raw-specific storage subtree. It exists for deterministic tests,
  compatibility, and explicit migration work only. It must never be selected by
  default in Keystore V1.
- Legacy `.mkit/keys/*` files remain supported only through legacy raw-file
  flows such as `mkit keygen`, `signing_key`, and `repo-key` compatibility.
- The software backend may reuse the existing hardened raw-file functions for
  Foundation V1, but it must live behind the `mkit-keystore` abstraction.
- If it writes files, it must preserve or improve current hardening:
  - Unix `0600` key files.
  - Unix `0700` parent directories.
  - effective-uid owner checks.
  - no symlink final component.
  - symlink ancestor rejection.
  - atomic tmp + fsync + rename + parent fsync writes.
- It must not weaken current `mkit_core::sign::{load_raw_32, save_raw_32}`
  security properties.

Storage-security modes:

- **Compatibility raw-file mode** may be used for Foundation V1. It preserves
  current hardened `0600` raw-key behavior and is acceptable only as the first
  implementation milestone.
- Compatibility raw-file mode does not satisfy Keystore V1's encrypted-at-rest
  software-backend acceptance criterion and must be named `software-raw`.
- **Encrypted software-file mode** is required for Keystore V1
  and owns the `software` backend token. It must encrypt key material at rest
  using OS-protected envelope encryption:
  - Generate a fresh random data-encryption key (DEK) per stored key record.
  - Encrypt the 32-byte secret with an AEAD approved by workspace supply-chain
    review.
  - Bind record version, backend token, label, algorithm, public key, key ID,
    and key attributes as AEAD associated data.
  - Protect or wrap the DEK with an OS-native protection mechanism for the
    current platform: macOS Keychain, Windows DPAPI/Credential Manager,
    Linux Secret Service, or `systemd-creds` for headless/server Linux.
  - On Linux, the `software` backend may auto-select Secret Service only when a
    desktop session is detected and the protector opens cleanly. Secret Service
    errors must fail closed rather than silently falling back to a weaker
    protector. The backend may select `systemd-creds` for headless/server use
    when no desktop Secret Service session is detected, and must fail closed if
    no usable protector is available.
  - Fail closed if no configured OS protection mechanism is available.
  - Never derive the encryption key from an mkit-managed password, hidden
    passphrase, repo data, or environment variable.
- The software backend must be clearly reported as `BackendKind::Software` and
  documented as software-only, not hardware-bound.
- The software backend must not claim `supports_device_bound`,
  `supports_non_extractable`, or encrypted-at-rest properties unless implemented
  truthfully.
- The raw compatibility backend must be clearly reported as
  `BackendKind::SoftwareRaw` and must not claim encrypted-at-rest protection.

### 6.2 Memory Backend

An in-memory backend may be implemented for tests and WASM-like integrations.

Requirements:

- It must never be selected by default in the native CLI.
- It must not persist keys.
- It must be clearly identified as `BackendKind::Memory`.

### 6.3 macOS Keychain Backend

Feature name: `backend-macos-keychain`.

Default target: macOS only.

Requirements:

- Store extractable software keys as Keychain generic password or keychain key
  items under a stable service/account scheme.
- Implement deterministic listing of keys created by the mkit service/account
  scheme so `mkit key list --backend macos-keychain` works for Keystore
  V1.
- V1 create/import refuses existing `(label, algorithm)` values in the normal
  sequential case. Concurrent same-label create/import atomicity depends on the
  native Keychain primitive exposed by the selected dependency and is not a
  cross-process lock guarantee in V1.
- Keystore V1 stores extractable signing seeds in the user Keychain and must not
  claim Secure Enclave, non-extractable, or device-bound semantics.
- Device-bound Keychain storage using
  `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` and
  `kSecAttrSynchronizable = false` is follow-up work unless implemented and
  covered by capability tests.
- P-256 Secure Enclave support is optional after Foundation V1 but must report
  non-extractable and user-presence capabilities accurately if implemented.
- Ed25519 must not be advertised as Secure Enclave-backed. Apple Secure
  Enclave does not provide Ed25519 signing.

### 6.4 Windows Backend

Feature name: `backend-windows-credential`.

Default target: Windows only.

Requirements:

- Use Windows-native user-bound storage. Keystore V1 uses Credential Manager
  with DPAPI-protected extractable records unless a CNG provider-backed key
  implementation is added.
- Implement deterministic listing of keys created by the mkit target-name scheme
  so `mkit key list --backend windows-credential` works for Keystore V1.
- V1 create/import refuses existing `(label, algorithm)` values in the normal
  sequential case. Concurrent same-target create/import atomicity depends on the
  Credential Manager primitive exposed by the selected dependency and is not a
  cross-process lock guarantee in V1.
- Report TPM/provider-backed behavior only when actually using a TPM-capable
  provider such as `MS_PLATFORM_CRYPTO_PROVIDER`. Keystore V1 does not claim
  TPM/provider-backed behavior for Credential Manager records.
- Ed25519 hardware support must be capability-detected, not assumed.

### 6.5 Linux Secret Service Backend

Feature name: `backend-linux-secret-service`.

Default target: Linux desktop only.

Requirements:

- Use the Secret Service API through a reviewed dependency or a small adapter.
- Implement deterministic listing of keys created by the mkit service/attribute
  scheme so `mkit key list --backend linux-secret-service` works for
  Keystore V1.
- Must fail clearly when no service is available or the session is locked.
- V1 create/import refuses existing `(label, algorithm)` values in the normal
  sequential case. Concurrent same-attribute create/import atomicity depends on
  the Secret Service implementation and dependency surface and is not a
  cross-process lock guarantee in V1.
- Must not be selected by default for headless/server mode.

### 6.6 systemd-creds Backend

Feature name: `backend-systemd-creds`.

Default target: Linux headless/server.

Requirements:

- The `systemd-creds` backend may shell out to `systemd-creds` rather than link
  TPM2 libraries.
- Shelling out must avoid shell interpolation. Use `Command` with argv tokens.
- Backend must clearly report when `systemd-creds` is not available.
- Keystore V1 treats `systemd-creds` as encrypted credential storage. It does
  not claim TPM/PCR sealing or device binding unless the backend explicitly
  requests and verifies those properties.

### 6.7 YubiKey Backend

Feature name: `backend-yubikey`.

Requirements:

- Support may be split across OpenPGP, PIV, and FIDO2/CTAP implementations.
- Backend must advertise the exact applet and algorithm support it can use.
- FIDO2/WebAuthn signing must preserve the existing WebAuthn wrapping
  semantics already used by `mkit-attest` and contrib CTAP signer. V1 must
  fail closed through the keystore API for FIDO2/CTAP labels and route users to
  the external CTAP signer unless a future keystore signer API can return the
  full WebAuthn assertion metadata.
- User presence/PIN prompts must be represented through typed errors or an
  explicit prompt flow. Do not block indefinitely without timeout handling.
- Keystore V1 does not accept YubiKey PINs through environment variables. PIN-
  or touch-required signing fails closed with typed authentication errors until
  a bounded prompt provider is implemented. FIDO2/CTAP labels continue to route
  users to the external signer path.

Current implementation status:

- The shipped YubiKey backend covers OpenPGP signing slots (Ed25519) and PIV
  signing slots (P-256). secp256k1 is reported as `UnsupportedAlgorithm`.
- The backend is read-only over the keystore API: `can_generate`,
  `can_import`, `can_export`, and `can_delete` are all false; provisioning is
  done out of band with `ykman` / `gpg --card-edit`.
- `Capabilities::supports_user_presence` is derived from the discovered slot
  policies (`PinPolicy != Never` or `TouchPolicy ∈ { Always, Cached }`).
  `supports_device_bound` and `supports_non_extractable` are true iff at least
  one signing key was discovered.
- FIDO2/CTAP slots are not exposed by this backend at all. They remain on the
  external signer path; the "fail closed through the keystore API for
  FIDO2/CTAP labels" requirement is met implicitly because the backend will
  return `KeyNotFound` for any label that does not resolve to an OpenPGP or
  PIV signing slot.

### 6.8 External And Cloud Backends

External signer and cloud KMS support are not Foundation V1 blockers unless
this spec is amended.

If implemented later:

- External signing should reuse `mkit-rpc` signer protocol where practical.
- Cloud KMS backends must clearly identify non-extractability, algorithm
  support, and signature encoding.
- Cloud key refs must never be repo-controlled.

## 7. Canonical Key Reference Scheme

CLI and config must use a compact key reference syntax:

```text
<backend>:<label>
```

Examples:

```text
software:default
software-raw:default
macos-keychain:default
windows-credential:default
linux-secret-service:default
systemd-creds:release
yubikey:main
```

Rules:

- Backend names are lowercase ASCII tokens — see `BackendKind::as_str` for the
  authoritative list (`software`, `software-raw`, `macos-keychain`,
  `windows-credential`, `linux-secret-service`, `systemd-creds`, `yubikey`,
  `external`, `cloud`, `memory`).
- Labels are backend-local but must pass the label validation in section 5.7.
- A key ref must not contain paths, URLs, shell metacharacter semantics, or
  implicit environment expansion.
- A key ref must not be interpreted relative to the repo.
- Repo config must not set key refs.

Implementation note: the label component of a parsed `KeyRef` is a
`KeyRefLabel`, a typed wrapper that re-checks the general label rules in
§5.7 plus an extra reject list (`$ ~ * ? [ ] { } ; & | ` `' "`). This is
strictly stronger than the §5.7 validation: labels coming from a key-ref
string cannot contain shell or environment-expansion characters even if a
future backend would accept them in a non-ref context.

Foundation V1 may initially support only the software family while preserving
the syntax for later backends. Issue-complete V1 must support the required
backend matrix in section 15.2.

A full key ref includes the backend. For signing integrations,
`key.<algorithm>_ref = <backend>:<label>` is authoritative and must route to
that backend. `key.backend` is only the default backend for `mkit key` commands
when no explicit backend or configured key ref supplies one.

## 8. Config Specification

### 8.1 New User-Scoped Keys

Foundation V1 must introduce user-scoped config keys for keystore selection.
Exact names are normative unless amended here:

```text
signer = legacy
key.backend = software
key.default_ref = software:default
key.ed25519_ref = software:default
key.secp256k1_ref = software:default-secp256k1
key.p256_ref = software:default-p256
attest.signer = repo-key
```

Interpretation:

- `signer` selects the commit-signing source. Built-in default is `legacy`,
  which preserves existing raw-file `signing_key` behavior. Setting
  `signer = keystore` opts commit signing into `mkit-keystore`.
- `key.backend` is the default backend for `mkit key` commands when no backend
  is provided and no full key ref is being used.
- `key.default_ref` is the default key ref for generic commands.
- Per-algorithm refs override generic refs.
- `attest.signer = repo-key` remains the built-in default. Setting
  `attest.signer = keystore` opts attestation signing into the
  keystore-backed attestation signer.
- Existing `attest.signer = repo-key` and `attest.signer = external` remain
  supported.

Precedence:

- Commit signing always uses Ed25519. If `signer = legacy` or empty, commit
  signing uses the existing `signing_key` raw-file behavior. If
  `signer = keystore`, commit signing uses `key.ed25519_ref`; if empty, it uses
  `key.default_ref`; if both are empty, it fails with a config error rather than
  silently falling back to legacy raw-file signing.
- Keystore-backed attestation signing uses the ref for the selected algorithm:
  `key.ed25519_ref`, `key.secp256k1_ref`, or `key.p256_ref`. If the selected
  per-algorithm ref is empty, it uses `key.default_ref`.
- Commit signing and attestation signing intentionally share the same default
  per-algorithm key refs in Foundation V1. Separate attestation-only key refs
  are out of scope unless this spec is amended.
- CLI flags override config for the command being run because they are explicit
  user input.
- A configured full key ref's backend must not be ignored. For example,
  `key.default_ref = yubikey:main` selects the YubiKey backend for signing; it
  must not be silently reinterpreted as `software:main` because
  `key.backend = software` is also set.

### 8.2 Repo-Forbidden Keys

Every config key in section 8.1 must be present in `REPO_FORBIDDEN_KEYS` in
`rust/crates/mkit-cli/src/config.rs`. The `REPO_FORBIDDEN_KEYS` list may
include additional keys (for example `signing_key`,
`attest.external_signer_path`, `attest.external_signer_args`,
`attest.secp256k1_key_path`, `attest.p256_key_path`,
`attest.default_algorithm`) covering legacy signer selectors and other
private-key-influencing settings. Such extras must not be removed because
they enforce the same confused-deputy posture for the pre-keystore code path.

Reason:

- A malicious repo must not choose which private key signs attacker-controlled
  content.
- A malicious repo must not switch a user from file-backed signing to a
  hardware/cloud/backend signer.
- A malicious repo must not trigger user-presence prompts or confused-deputy
  through a user-trusted key.

### 8.3 Existing Keys

Existing keys remain valid:

```text
signing_key
attest.secp256k1_key_path
attest.p256_key_path
attest.external_signer_path
attest.external_signer_args
```

Compatibility behavior:

- `signing_key` continues to drive legacy raw-file Ed25519 commit signing.
- `attest.*_key_path` continues to drive legacy repo-key attestation signing.
- Existing security scope rules remain unchanged.
- Keystore refs do not replace existing path keys in Foundation V1; they are a
  parallel mechanism.

## 9. CLI Specification

The new command namespace is:

```text
mkit key <subcommand>
```

`mkit keygen` remains as a legacy compatibility command and may internally
delegate to the old raw-file implementation.

### 9.1 `mkit key generate`

Usage:

```text
mkit key generate [--backend <backend>] [--label <label>]
                  [--algorithm ed25519|secp256k1|p256]
                  [--extractable|--non-extractable]
                  [--device-bound]
                  [--require-user-presence]
                  [--force]
                  [--print-pubkey]
```

Defaults:

- `--backend`: `key.backend`, fallback `software` for Foundation V1.
- `--label`: parsed from the algorithm-specific configured key ref; if no ref
  is configured, defaults to `default` for Ed25519, `default-secp256k1` for
  secp256k1, and `default-p256` for P-256.
- `--algorithm`: `ed25519`.
- `extractable`: backend default. Software backend defaults to extractable.
- `device_bound`: false unless requested.
- `require_user_presence`: false unless requested.

Behavior:

- Must call `Keystore::generate` with `GenerateOptions { overwrite: false }`
  by default.
- Must call `Keystore::generate` with `GenerateOptions { overwrite: true }`
  when `--force` is provided.
- Must refuse overwrite unless `--force` is provided.
- Must print backend, label, algorithm, public key, key ID, and capabilities.
- If `--print-pubkey` is provided, must print the canonical key ID on a stable
  final line suitable for scripting.
- Must not create repo config.

### 9.2 `mkit key list`

Usage:

```text
mkit key list [--backend <backend>] [--json]
```

Behavior:

- Lists keys visible to the selected backend or default backend.
- Output order must be deterministic.
- Human output must include backend, label, algorithm, key ID, and capability
  flags.
- JSON output must be stable enough for downstream tooling and covered by
  tests if added.

### 9.3 `mkit key import`

Usage:

```text
mkit key import --algorithm ed25519|secp256k1|p256
                [--backend <backend>] [--label <label>]
                (--hex <64-hex> | --file <path>)
                [--extractable|--non-extractable]
                [--device-bound]
                [--require-user-presence]
                [--force]
```

Behavior:

- Import accepts exactly 32 bytes of secret material.
- Hex input must be 64 lowercase or uppercase hex characters; output remains
  lowercase.
- File input must be read with the same security posture as current raw-key
  loading where applicable.
- Invalid curve scalars must be rejected.
- Must call `Keystore::import` with `ImportOptions { overwrite: false }` by
  default.
- Must call `Keystore::import` with `ImportOptions { overwrite: true }` when
  `--force` is provided.
- Must refuse overwrite unless `--force` is provided.
- Must zeroize local secret buffers.

### 9.4 `mkit key export`

Usage:

```text
mkit key export [--backend <backend>] [--label <label>]
                [--algorithm ed25519|secp256k1|p256]
                --unsafe-print-secret
```

Behavior:

- Export is intentionally noisy and must require `--unsafe-print-secret` when
  printing secret material to stdout.
- Export must fail for non-extractable keys.
- Export must print only secret hex when scripting mode is requested. Human
  warnings must go to stderr.
- Foundation V1 supports stdout export only. Exporting directly to a file is
  deferred until a hardened file-output contract is added to this spec.
- Export must never happen implicitly as part of signing, listing, or metadata
  lookup.

### 9.5 `mkit key delete`

Usage:

```text
mkit key delete [--backend <backend>] [--label <label>]
                [--algorithm ed25519|secp256k1|p256]
                --yes
```

Behavior:

- Must require `--yes` in Foundation V1. No interactive prompt is required.
- Must delete exactly one selected key.
- Must report key-not-found distinctly from successful deletion.
- Must not delete legacy raw key files unless the selected backend is the
  software backend and the selected label maps to that exact key.
- For encrypted software storage, deletion intentionally fails if the selected
  record cannot be decrypted with its recorded protector. Manual recovery from a
  permanently lost protector requires removing the exact stored record plus its
  corresponding OS-protected wrapped DEK.

## 10. Commit Signing Integration

Current commit signing lives in `mkit-core::sign` and signs Ed25519 over the
current domain-separated commit signing hash.

Requirements:

- `mkit-core` continues to own canonical commit/remix signing bytes and
  verification.
- `mkit-core` must expose enough public helpers to support keystore signing
  without depending on `mkit-keystore`.
- The exact value handed to an Ed25519 keystore signer for commit signing is
  `mkit_core::sign::commit_signing_hash(commit)`, a 32-byte digest currently
  defined as `BLAKE3(len_le16(COMMIT_DOMAIN) || COMMIT_DOMAIN ||
  commit_signing_bytes(commit))`.
- Ed25519 keystore commit signing must produce the same commit signature as
  current `KeyPair` signing for the same seed and same commit object.
- Commit objects continue to embed the Ed25519 public key in `Commit.signer`.
- Verification remains unchanged for Foundation V1.
- Missing keystore keys must be hard errors. Do not auto-generate during
  commit.

Implementation options:

- Preferred: add a small adapter in `mkit-cli` that obtains the commit signing
  hash through `mkit_core::sign::commit_signing_hash`, asks the Ed25519
  keystore signer to sign exactly those 32 bytes, then stores the resulting
  64-byte signature in `Commit.signature`.
- Do not duplicate `domain_digest` construction in `mkit-cli` or
  `mkit-keystore`.

Required cleanup:

- `docs/SPEC-SIGNING.md` now describes `BLAKE3(len_le16(domain) || domain ||
  signing_bytes)` and matches the implementation. **Done.** Cross-reference
  SPEC-SIGNING §3 for the canonical formula and `mkit_core::sign::domain_digest`
  for the implementation.

## 11. Attestation Integration

Current attestation signing uses `mkit_attest::Signer`:

```rust
pub trait Signer {
    fn algorithm(&self) -> Algorithm;
    fn keyid(&self) -> Result<String, Error>;
    fn sign(&mut self, pae: &[u8]) -> Result<Vec<u8>, Error>;
}
```

Requirements:

- Add a keystore-backed attestation signer adapter.
- The adapter must implement the existing `mkit_attest::Signer` trait.
- It must sign DSSE PAE bytes using existing per-algorithm semantics:
  - Ed25519 signs PAE directly.
  - secp256k1 signs SHA-256(PAE), compact low-S ECDSA.
  - P-256 signs SHA-256(PAE), compact low-S ECDSA.
- Existing `repo-key` and `external` signers remain supported.
- `attest_factory` must accept `attest.signer = keystore` only from user-scoped
  config or CLI arguments.
- Keystore-backed signatures must verify through the existing
  `mkit_attest::verify` registry when the trust root contains the emitted
  public key.

Key ID compatibility:

- New keystore Ed25519 key IDs should be canonical `ed25519:<pubkey>`.
- Existing repo-key signer may continue using legacy `blake3:<hash(pubkey)>`.
- Verifier must continue accepting legacy `blake3:` for Ed25519.

## 12. External Signer Relationship

`mkit-rpc` already defines a signer protocol with `KEY_FORM_OPAQUE_HANDLE`.
`mkit-keystore` does not replace this protocol in Foundation V1.

Rules:

- External signers remain valid for TPM, Secure Enclave, CTAP, and custom
  integrations.
- `mkit-keystore` may later provide an external signer backend or bridge using
  the same RPC protocol.
- Foundation V1 keystore work must not mutate the v1 RPC wire schema unless
  this spec is updated with a compatibility analysis.
- If key refs are passed to external signers in the future, use
  `KEY_FORM_OPAQUE_HANDLE` and explicit key_ref bytes.

## 13. Security Requirements

### 13.1 Config And Confused Deputy

- Repo config must not select keystore backend, key ref, label, signer kind,
  external signer path, external signer args, or default signing algorithm.
- User-scoped config may select those values.
- CLI flags may select those values because the user explicitly invoked the
  command.
- Any new config key that can influence private-key selection or signing policy
  must be added to `REPO_FORBIDDEN_KEYS`.

### 13.2 No Silent Key Creation

- `commit`, `attest`, `merge`, `cherry-pick`, or any future signing command
  must not generate a key as a side effect.
- Missing key errors must point users to `mkit key generate` or legacy
  `mkit keygen`.

### 13.3 Secret Handling

- Secret material must be zeroized on drop.
- Debug output must redact secrets.
- Tests must not log generated secrets unless the test is explicitly verifying
  export behavior.
- Exported secrets are allowed only through explicit export commands/APIs.

### 13.4 Backend Honesty

- A backend must fail closed when requested attributes cannot be honored.
- A backend must not label a key as hardware-bound unless the private key is
  actually non-extractable from hardware or OS-protected storage.
- A backend must not label a key as device-bound if cloud sync or backup can
  restore it on another machine.

### 13.5 User Presence

- User-presence prompts must be opt-in unless the backend inherently requires
  them.
- CLI must surface enough context for the user to understand why a prompt is
  happening.
- Timeouts and user-declined outcomes must be distinct errors.

### 13.6 Audit Logging

Audit logging is not required for Foundation V1.

If later implemented:

- It must be opt-in.
- It must not log secret material, signatures, raw payloads, or private key
  bytes.
- It may log timestamp, backend, label, algorithm, key ID, operation, and
  success/failure.

## 14. Testing Requirements

### 14.1 Unit Tests

`mkit-keystore` must test:

- label validation
- key ref parsing
- capabilities reporting
- generate/open/list/delete
- import/export for extractable software keys
- non-extractable export failure where supported by a test backend
- invalid scalar rejection
- key-not-found and key-already-exists errors
- deterministic ordering of list output

### 14.2 Integration Tests

`mkit-cli` must test:

- `mkit key generate` creates a key through the Foundation V1 backend.
- `mkit key list` reports generated keys.
- `mkit key import` imports a known Ed25519 seed.
- `mkit key export --unsafe-print-secret` round-trips an imported extractable
  key.
- `mkit key delete --yes` deletes exactly the selected key.
- Repo config cannot set keystore selectors.
- User config can set keystore selectors.
- Missing keys fail without generation.

### 14.3 Golden Compatibility Tests

Required golden tests:

- Imported Ed25519 seed through software keystore produces byte-identical
  commit signatures to current `mkit_core::sign::KeyPair` for the same commit.
- Imported Ed25519 seed through software keystore produces byte-identical DSSE
  signatures to existing Ed25519 software signer for the same PAE, where key ID
  differences are accounted for separately.
- Imported secp256k1 scalar through software keystore produces byte-identical
  DSSE signature to existing `Secp256k1Signer` for the same PAE.
- Imported P-256 scalar through software keystore produces byte-identical DSSE
  signature to existing `P256Signer` for the same PAE.

Clarification:

- Byte-identical ECDSA signatures are required only for software deterministic
  signers.
- OS-native or hardware ECDSA backends must produce signatures that verify, but
  they are not required to be byte-identical unless the backend guarantees
  deterministic RFC 6979 behavior.

### 14.4 Platform-Gated Backend Tests

Each OS-native backend must include tests gated by target OS and feature flag.

Tests must not require developer-specific keychain state. They must create and
delete unique test labels.

Live OS-native backend tests are ignored by default and must fail loudly when
explicitly invoked without `MKIT_RUN_NATIVE_KEYSTORE_TESTS=1`. CI jobs that
claim native backend coverage must run those ignored tests with the required
environment gate set.

Hardware tests may be ignored by default and documented as manual tests.

### 14.5 Foundation V1 CI Gates

Foundation V1 must pass:

```text
cd rust
cargo fmt --check
cargo clippy --all-targets --all-features --workspace -- -D warnings
cargo build --locked --workspace
cargo nextest run --locked --workspace --all-features
cargo test --locked --workspace --doc
```

If all-features cannot include OS-native backends on every CI OS, features must
be structured so unsupported target-specific code is cfg-gated correctly.

## 15. Completion Requirements

### 15.1 Foundation V1 Completion Requirements

Foundation V1 is complete only when all items below are done. Completing this
section is not enough to close issue #104.

Crate:

- `rust/crates/mkit-keystore` exists.
- It is a workspace member.
- It exposes the API categories in section 5.
- It has structured errors.
- It has a software backend sufficient for deterministic tests and
  compatibility-mode persistence.
- It may have a memory backend for tests, but memory-only is not sufficient for
  Foundation V1.
- It builds without native platform services by default.

CLI:

- `mkit key generate` implemented.
- `mkit key list` implemented.
- `mkit key import` implemented.
- `mkit key export` implemented with explicit unsafe export flag.
- `mkit key delete` implemented with explicit `--yes`.
- `mkit keygen` remains supported.
- Help text and CLI tests are updated.

Config:

- Keystore config keys are implemented.
- Every keystore selector is repo-forbidden.
- Config tests prove repo config cannot select keys or backends.

Signing:

- `mkit-attest` can sign through a keystore-backed signer.
- Ed25519 commit signing can sign through a keystore-backed signer.
- Existing raw-file signing remains supported.
- Existing verification behavior remains unchanged.

Tests:

- Unit tests cover keystore API behavior.
- CLI integration tests cover new commands.
- Golden compatibility tests cover deterministic signature equivalence.
- Negative security tests cover repo-config rejection and missing-key behavior.

Docs/spec cleanup:

- `docs/SPEC-SIGNING.md` is updated to match current implementation:
  `BLAKE3(len_le16(domain) || domain || signing_bytes)`. **Done** — see
  `digest = BLAKE3(u16_le(domain.len) || domain || signing_bytes)` in
  SPEC-SIGNING §3 and the matching `domain_digest` implementation in
  `mkit_core::sign`.
- Threat model is updated with keystore backend assumptions. **In flight.**
- CLI docs may summarize this behavior, but this specification remains the
  source of truth unless amended in a later spec change.

Review:

- Crypto/key-handling changes receive dedicated review.
- Any new direct dependency receives supply-chain review.
- Any unsafe code must be justified locally and reviewed explicitly.

### 15.2 Keystore V1 Completion Requirements

Keystore V1 is complete only when all Foundation V1 requirements are complete
and all items below are done. Deferred provider claims from the original issue
remain out of scope unless explicitly added to this list.

Backends:

- Software encrypted-at-rest file mode is implemented or this spec is amended
  with an equivalent reviewed design.
- macOS Keychain backend is implemented and tested.
- Windows DPAPI/Credential Manager backend is implemented and tested.
- Linux Secret Service backend is implemented and tested.
- `systemd-creds` backend is implemented and tested for Linux headless/server
  use.
- YubiKey backend is implemented behind a feature flag, with OpenPGP/PIV
  discovery and FIDO2/CTAP fail-closed routing. PIN- or touch-required signing
  must fail closed until a bounded prompt provider is implemented.

Backend honesty:

- macOS Secure Enclave support, if present, advertises P-256 only.
- Windows TPM/provider-backed support is not claimed in Keystore V1.
- Linux desktop and headless backend selection is explicit or documented; a
  headless system must not silently try to use a locked desktop keyring.
- Hardware-backed Ed25519 limitations are documented and reflected in
  capabilities.

CLI and integrations:

- `mkit key {generate,list,import,export,delete}` works against every required
  backend where the backend supports the requested operation.
- macOS Keychain, Windows Credential Manager, Linux Secret Service, and
  `systemd-creds` must support deterministic listing for keys created through
  their V1 mkit backend schemes.
- `mkit-attest` accepts a keystore-backed signer for every supported algorithm
  and backend combination that can sign that algorithm.
- Ed25519 commit signing can use every backend that advertises usable Ed25519
  signing.

Tests and CI:

- Cross-platform CI covers macOS, Linux desktop-compatible paths,
  Linux headless/server-compatible paths, and Windows.
- Backend-specific tests are target- and feature-gated so unsupported backends
  do not break unrelated platforms.
- OS-native backend tests create unique labels, exercise supported create, list,
  open, export, and delete paths, and clean up without relying on
  developer-specific keychain state.
- Golden vectors cover deterministic software/importable backends.
- Hardware and OS ECDSA backends are tested for verification equivalence, not
  byte equality, unless the backend guarantees deterministic signatures.

Docs/spec cleanup:

- `docs/THREAT-MODEL.md` documents the accepted malware, disk extraction,
  backup exfiltration, and side-channel assumptions for each backend family.
- User-facing docs may summarize the final behavior, but this specification
  remains the implementation-review authority unless replaced by a later spec.

## 16. Implementation Phases

Status tags below describe what is in the current build. They are advisory;
the per-section requirements above remain normative.

### Phase 1: Foundation — shipped

- Add `mkit-keystore` crate. **Shipped.**
- Add core API, errors, label/key-ref parsing, capabilities. **Shipped.**
- Add memory backend for tests. **Not shipped** — `BackendKind::Memory` is
  defined but no `MemoryKeystore` implementation exists. Software-raw with
  a `tempfile`-backed root is used in the test suite instead.
- Add software backend reusing existing hardened raw-key behavior where
  practical. **Shipped** as `SoftwareRawKeystore`, which delegates to
  `mkit_core::sign::{load_raw_32, save_raw_32, save_raw_32_create_new}`.
- Add unit tests. **Shipped.**

### Phase 2: CLI Surface — shipped

- Add `commands/key.rs`. **Shipped** at
  `rust/crates/mkit-cli/src/commands/key.rs`.
- Wire `mkit key` in `mkit-cli/src/lib.rs`. **Shipped.**
- Preserve `mkit keygen`. **Shipped.**
- Add config keys and repo-forbidden tests. **Shipped** — see `KeyConfig` and
  `REPO_FORBIDDEN_KEYS` in `mkit-cli/src/config.rs`.
- Add CLI integration tests. **Shipped.**

### Phase 3: Attestation Integration — shipped

- Add keystore-backed `mkit_attest::Signer` adapter. **Shipped** as
  `KeystoreAttestSigner` in `commands/attest_factory.rs`.
- Extend `attest_factory` for `attest.signer = keystore`. **Shipped.**
- Add DSSE signing and verification tests. **Shipped.**

### Phase 4: Commit Integration — shipped

- Add or expose the minimal `mkit-core` helper needed for keystore commit
  signing without creating a dependency cycle. **Shipped** —
  `mkit_core::sign::commit_signing_hash` is exposed and used by
  `CommitSigner::Keystore` in `commands/commit.rs`.
- Teach `mkit commit` to use a configured Ed25519 keystore key ref.
  **Shipped** behind `signer = keystore`.
- Add golden equivalence tests. **Shipped** — see
  `keystore_commit_signature_matches_legacy_keypair_signature` in
  `commands/commit.rs` tests.

### Phase 5: Keystore V1 Backend Matrix — mostly shipped

- Make `software` the encrypted-at-rest software backend using OS-protected
  envelope encryption. **Shipped** — `SoftwareKeystore` + `EncryptedKeyRecord`
  (XChaCha20-Poly1305, length-prefixed AAD, OS protector wrapping the DEK).
- Move raw compatibility persistence to `software-raw`. **Shipped** as
  `SoftwareRawKeystore`.
- Implement macOS Keychain, Windows DPAPI/Credential Manager, Linux Secret
  Service, `systemd-creds`, and YubiKey OpenPGP/PIV/FIDO2 backends behind
  feature flags with honest capabilities. **Shipped** for macOS Keychain
  (`macos-keychain`), Windows Credential Manager (`windows-credential`),
  Linux Secret Service (`linux-secret-service`), `systemd-creds`
  (`systemd-creds`), and YubiKey OpenPGP + PIV (`backend-yubikey`).
  **Not shipped:** a dedicated YubiKey FIDO2/CTAP routing in this backend
  — FIDO2 stays on the external signer path per §6.7.
- Add backend factory/resolution so CLI, commit signing, and attestation signing
  route by full key ref. **Shipped** — `open_backend` plus `selection_for`
  in `commands/key.rs`, mirrored in commit and attest paths.
- Add platform-gated tests and capability honesty tests. **Shipped.**

### Phase 6: Production Readiness — in flight

- Add cross-platform CI for macOS, Windows, Linux desktop-compatible paths, and
  Linux headless/server-compatible paths. **Partially in flight** — live
  OS-native backend tests are gated by `MKIT_RUN_NATIVE_KEYSTORE_TESTS=1` per
  §14.4; CI matrix coverage is still being expanded.
- Add golden vectors and verification-equivalence tests. **Shipped** for
  deterministic software/software-raw signers; hardware/OS ECDSA
  verification-equivalence coverage is still expanding.
- Update threat model, user-facing docs, supply-chain review notes, and backend
  manual-test documentation. **Partially shipped** — see `docs/keystore.md`
  for the end-user overview; `docs/THREAT-MODEL.md` updates per §15.2 are
  still being landed.

## 17. Deferred Decisions

The following decisions are resolved for the Keystore V1 target:

1. The branch includes macOS Keychain, Windows DPAPI/Credential Manager, Linux
   Secret Service, `systemd-creds`, and YubiKey backends with capability reports
   limited to what they actually implement.
2. The encrypted software-file design is OS-protected envelope encryption. The
   `software` backend is encrypted-at-rest; raw compatibility is explicit via
   `software-raw`.
3. Whether a future `mkit key export --file <path>` mode is worth adding. It is
   out of scope for Foundation V1.
4. YubiKey support includes OpenPGP/PIV discovery and FIDO2/CTAP fail-closed
   routing for V1; bounded PIN/touch prompt signing is follow-up work.
5. Whether future releases need attestation-only key refs separate from the
   shared `key.<algorithm>_ref` defaults. Foundation V1 deliberately shares
   commit and attestation refs.

Foundation V1 uses these fixed conservative defaults:

- default backend: encrypted-at-rest software backend (`software`)
- raw compatibility backend: explicit `software-raw`
- commit signing source: legacy raw-file `signing_key`
- attestation signing source: existing `repo-key`
- new Ed25519 keystore key IDs: `ed25519:<pubkey>`
- repo-key attestation legacy key IDs: `blake3:<hash(pubkey)>`
- export mode: stdout only with `--unsafe-print-secret`
- commit and attestation refs: shared per-algorithm `key.*_ref` values
- no silent migration from raw files
- no implicit export
- no repo-controlled key refs
- no hardware capability claims without runtime proof
