# THREAT-MODEL — mkit security boundaries

Status: **Informative**. Companion document to `SECURITY.md` and the
SPEC-* normative specs. Audience: integrators, auditors, and
contributors changing crypto- or key-handling code.

This document states what mkit defends, what it does not, and where
the lines are drawn. It is the source of truth a reviewer consults
when a change touches signing, key files, configuration, transport
auth, or the release pipeline.

---

## 1. Scope

mkit is a content-addressed VCS with cryptographic signing
(`SPEC-SIGNING.md`) and an attestation subsystem
(`SPEC-ATTESTATIONS.md`, `SPEC-EXTERNAL-SIGNER.md`). mkit defends:

- The integrity of objects, packs, refs, and attestations stored in a
  repository — content addressing plus signed commits and DSSE
  envelopes detect tampering.
- The integrity of signatures produced by `mkit commit`, `mkit attest`,
  and external signers reachable through the documented protocol.
- The local user's signing keys, to the extent the host kernel and
  filesystem allow.

mkit does NOT defend:

- The semantics of an attestation predicate. mkit moves bytes; the
  consumer decides what they mean.
- Any property a signer chooses not to provide (e.g. timestamping
  unless the signer binds a transparency log entry).
- The host kernel, the user's TTY, the user's shell history, or any
  other process running as the same UID as `mkit`.

---

## 2. Trust boundaries

The following boundaries cross trust domains. Code that moves data
across one of these lines MUST treat the input as untrusted.

| Boundary                                     | Trusted side          | Untrusted side                              |
|----------------------------------------------|-----------------------|---------------------------------------------|
| Local user ↔ remote repo author              | the running user      | files inside a cloned tree, including       |
|                                              |                       | the repo's `.mkit/config`                   |
| Local user ↔ same-host other UID             | the running user      | other UIDs on the host                      |
| Transport peer (network)                     | the peer the user     | every other host on the path                |
|                                              | configured            |                                             |
| Release pipeline runner                      | the workflow YAML     | any artefact a third-party action emits     |

The "remote repo author" line is load-bearing. A user who runs
`mkit clone` accepts the remote's content into the working tree;
they do NOT thereby accept the remote's choice of signing key, key
file path, external signer binary, or trust-roots file.

---

## 3. Attacker models

For each attacker we enumerate what mkit claims to defend and what
it does not. "Defend" means the design intends a security property
and the implementation has tests or fuzz coverage backing it.

### 3.1 Hostile remote repo author

Attacker controls every file in the cloned tree, including
`.mkit/config`, working-tree contents, ref files, packs, and any
attestation envelope they push.

mkit defends:

- Object/pack/ref integrity. Tampered bytes fail BLAKE3 verification
  on read; pack readers refuse oversize allocations
  (`SPEC-PACKFILE.md`, `SPEC-DELTA.md`).
- Worktree containment. Symlinks pointing outside the repo root, and
  paths matching `.mkit` / `.git` (case-insensitive), are rejected
  during checkout.
- Signature and attestation verification. Trust roots come from the
  user-scoped trust-roots file (§5), not from the cloned repo.
- Choice of key material and external processes. Per §4, a hostile
  `.mkit/config` cannot select which key file is read, which binary
  is spawned as an external signer, which keystore backend/key ref is
  used, or what argv an external signer gets.

mkit does NOT defend:

- The semantic content of a verified attestation. A predicate that
  says "this commit is safe to deploy" is only as strong as the
  signer's policy.
- A user who manually runs `mkit config attest.external_signer_path
  /tmp/evil` after cloning. Local choice is the user's responsibility.

### 3.2 Local same-host attacker, different UID

Attacker has a shell on the same host under a different UID.

mkit defends:

- Key file confidentiality at the filesystem layer. Key files are
  mode `0600`, owner-checked against the running euid, and opened
  with `O_NOFOLLOW` so a symlink planted by another UID cannot
  redirect reads. The parent directory is created `0700` and its
  ownership is checked.

mkit does NOT defend against:

- A different-UID attacker who can read `/proc/<mkit-pid>/mem` (e.g.
  Linux without `kernel.yama.ptrace_scope = 1`).

### 3.3 Local same-host attacker who later gains code execution as the user

Attacker runs as the same UID as `mkit`, either by tricking the user
into running their code or by exploiting an unrelated process.

mkit does NOT defend against this case. Once an attacker runs as the
same UID, they can read the key file, spawn arbitrary external
signers, edit `.mkit/config`, and so on. mkit's threat model assumes
the local UID is trusted.

The mitigations in §4 and §5 are about preventing a *remote* repo
from escalating into this position via on-disk config.

### 3.4 MITM on SSH or HTTPS transport

Attacker is on the network path between the client and the remote.

mkit defends:

- HTTPS — via the system rustls trust store and TLS as configured
  by the user.
- SSH — via the user's `ssh(1)` configuration (see
  `SSH-SECURITY.md`). mkit does not implement its own SSH. A
  per-repo `ssh.user_known_hosts_file` and `ssh.identity_file`
  scoped to user config (§4) let a careful user pin trust without
  affecting other SSH sessions.

mkit does NOT defend:

- A user who disables host-key checking at the OpenSSH layer.
- A user who pins a known-bad CA in their system trust store.

### 3.5 Compromised release pipeline runner

Attacker has code execution on the GitHub Actions runner that
produces release artefacts.

mkit defends:

- Reproducibility of the binary build (`docs/release/REPRODUCIBILITY.md`).
- Provenance via cosign keyless signatures and CycloneDX SBOM
  (`docs/release/SUPPLY-CHAIN.md`).
- Pinning third-party actions by SHA so a compromised tag cannot
  silently swap an action's code.

mkit does NOT defend:

- A compromise of the GitHub Actions OIDC issuer or Sigstore root.
  Defence is transitive.

---

## 4. Configuration scope split

mkit reads two configuration files. Their scope is partitioned by
attacker model: a hostile clone can write `<repo>/.mkit/config` but
it cannot write the user-scoped file at
`$XDG_CONFIG_HOME/mkit/config` (`~/.config/mkit/config` by default).

Security-sensitive keys — anything that selects a key path or an
external process — live ONLY in user scope. A repo config that
attempts to set them is rejected with a warning; the value is
ignored.

| Key                                 | Scope     | Rationale                                                 |
|-------------------------------------|-----------|-----------------------------------------------------------|
| `signer`                            | **User**  | Selects legacy raw-file vs keystore commit signing.       |
| `key.backend`                       | **User**  | Selects the keystore backend family.                      |
| `key.default_ref`                   | **User**  | Selects a private signing key reference.                  |
| `key.ed25519_ref`                   | **User**  | Selects the Ed25519 private signing key reference.        |
| `key.secp256k1_ref`                 | **User**  | Selects the secp256k1 private signing key reference.      |
| `key.p256_ref`                      | **User**  | Selects the P-256 private signing key reference.          |
| `signing_key`                       | **User**  | Selects which key file is read for commit signing.        |
| `attest.signer`                     | **User**  | Selects `repo-key` / `external` / `keystore`.             |
| `attest.default_algorithm`          | **User**  | Selects the attestation signing algorithm.                |
| `attest.external_signer_path`       | **User**  | Selects which binary is spawned as a signer.              |
| `attest.external_signer_args`       | **User**  | Argv for the signer subprocess.                           |
| `attest.secp256k1_key_path`         | **User**  | Selects which secp256k1 key file is read.                 |
| `attest.p256_key_path`              | **User**  | Selects which P-256 key file is read.                     |
| `ssh.strict_host_key_checking`      | **User**  | Could weaken host-key verification.                       |
| `ssh.user_known_hosts_file`         | **User**  | Selects which file is the source of trust.                |
| `ssh.identity_file`                 | **User**  | Selects which private key SSH presents.                   |
| `user.identity`                     | **User**  | Author identity; cannot be repo-selected for signed data. |
| `default_branch`                    | Repo      | UX default. No security weight.                           |
| `remote_endpoint`                   | Repo      | Address; trust is on the user's transport config.         |
| `remote_bucket`                     | Repo      | Address.                                                  |
| `remote_type`                       | Repo      | Dispatch hint to the transport layer.                     |

Repo-safe keys are applied after the user file and may override user
defaults. The security fence is narrower and stricter: private-key,
signer, executable, trust-root, and host-key selectors are user-only
and are ignored when they appear in repo config.

---

## 5. Trust-roots scope

`mkit verify-attest` loads its trust roots from
`$XDG_CONFIG_HOME/mkit/trust-roots.toml` by default. The path is
**not** repo-local for the same reason as §4: a hostile clone must
not choose its own verifier.

A user can override the path on the command line for ad-hoc
verification, but the override is per-invocation; there is no repo
config knob that sets it.

---

## 6. Key file format and protections

| Property                | Value                                                            |
|-------------------------|------------------------------------------------------------------|
| Format                  | raw 32-byte Ed25519 seed (no PEM, no DER, no password wrap in v1) |
| Permissions             | mode `0600`, MUST be set on creation                              |
| Owner                   | euid of the running process; mismatch is a hard failure           |
| Open flag               | `O_NOFOLLOW` — symlink in the path is a hard failure              |
| Parent directory        | `0700`, owner-checked                                             |
| Write strategy          | tempfile in same directory, fsync, atomic rename, fsync of parent |
| Zeroisation             | seed buffers scrubbed at generation and file-I/O boundaries       |

`KeyPair::generate` scrubs its local seed buffer after constructing the
keypair. `KeyPair::from_seed` takes `[u8;32]`; callers that own long-lived
secret buffers must use a zeroising owner before and after the call.

The same protections apply to the secp256k1 and P-256 key files
selected via `attest.secp256k1_key_path` and `attest.p256_key_path`.

### 6.1 Keystore backends

Issue-complete V1 adds user-scoped software, OS-native, Linux desktop/headless,
and YubiKey-backed keystore backends selected by `mkit key ...`,
`signer = keystore`, and `attest.signer = keystore`.

Security assumptions:

- Keystores are user-scoped, not repo-scoped. On Unix-like systems the software
  default root is `$XDG_DATA_HOME/mkit/keys/`, falling back to
  `~/.local/share/mkit/keys/`; `software-raw` persists under a raw-specific
  subtree, and `systemd-creds` uses a separate user data subtree for encrypted
  credential files.
- Keystore selectors (`signer`, `key.backend`, and every `key.*_ref`) are
  user-scoped. A hostile repo cannot select a backend, label, key reference, or
  signing mode.
- `software:<label>` stores encrypted-at-rest software records. It protects
  against offline disk/backup disclosure to the extent the local OS-protected
  envelope material remains unavailable to the attacker. It does not protect
  against malware running as the user. Production `mkit-cli` builds enable the
  target OS protector features; the `mkit-keystore` library keeps default
  features empty for lean builds and tests.
- `software-raw:<label>` is the explicit raw-file compatibility backend. It
  keeps deterministic raw-key behavior for compatibility tests and migration
  workflows and is not the secure default.
- macOS Keychain, Windows Credential Manager, Linux Secret Service, and
  `systemd-creds` store extractable 32-byte signing secrets behind their
  platform protection boundary. They do not claim hardware binding,
  non-extractability, or user presence unless a future implementation changes
  the storage primitive and capability report together.
- Linux Secret Service is a desktop/session backend and may fail when no D-Bus
  service is available or the session is locked. `systemd-creds` is the
  headless/server Linux backend and shells out with argv tokens, not shell
  interpolation. The encrypted `software` backend auto-selects Secret Service
  first for desktop sessions, then `systemd-creds`, and fails closed if neither
  protector is available.
- YubiKey OpenPGP exposes existing Ed25519 signing-slot keys. YubiKey PIV
  exposes existing P-256 certificate-backed slots (`piv-9a`, `piv-9c`,
  `piv-9e`). Both are non-extractable and device-bound from mkit's point of
  view; signing requires explicit PIN environment variables and optional touch
  opt-in (`MKIT_YUBIKEY_OPENPGP_PIN`, `MKIT_YUBIKEY_OPENPGP_ALLOW_TOUCH`,
  `MKIT_YUBIKEY_PIV_PIN`, `MKIT_YUBIKEY_PIV_ALLOW_TOUCH`).
- FIDO2/CTAP WebAuthn signatures remain wired through the external signer path
  because the current keystore `KeySigner` API returns only a signature and
  cannot carry WebAuthn authenticator data plus client data JSON. The YubiKey
  keystore fails closed for `fido2-*`/`ctap-*` P-256 labels rather than emitting
  incomplete assertions.
- Signing commands never auto-generate keystore keys. Users must run
  `mkit key generate` or `mkit key import` explicitly.

Keystore non-goals in V1:

- Protection against malware or another process already running as the same
  UID. Such an attacker can request signatures from unlocked software/OS
  backends, read extractable secrets from software/raw/platform stores, or set
  the environment variables needed to prompt hardware-backed signing.
- Side-channel resistance beyond the underlying crypto/hardware libraries.

---

## 7. Out of scope

The following are explicitly out of scope. mkit makes no claim and
takes no defensive posture against them.

- Compromise of the host kernel, CPU microcode, or RAM (cold-boot,
  Rowhammer, side-channel attacks).
- An attacker with `root` or `Administrator` on the host.
- A multi-user host where `/proc/<pid>/mem` is readable by a
  non-`root` user. On Linux, set
  `kernel.yama.ptrace_scope = 1` (or stricter) before relying on
  mkit's key-file protections.
- Recovery from a compromised signing key. There is no on-chain or
  in-band revocation; the user's recourse is to publish a new key
  and re-sign forward history.

---

## 8. Verification gates

The following tests, fuzz targets, and CI gates are how we keep this
document honest. A change that weakens any of these requires a
matching update here.

- Golden vectors at `rust/tests/golden/` pin signing-byte and
  signing-hash shapes (`SPEC-SIGNING.md` §3, `SPEC-ATTESTATIONS.md` §4).
- `mkit-keystore` golden vectors pin deterministic imported-key behavior for
  explicit `software-raw` Ed25519, secp256k1, and P-256 signing, while unit
  storage tests assert that `software` writes encrypted records rather than raw
  seeds.
- Keystore capability tests assert that each backend advertises only supported
  algorithms, export/import/listing, user-presence, device-bound, and
  non-extractability properties.
- `cargo fuzz` targets cover delta decode, pack reader, and the
  object deserializer (`docs/FUZZ.md`).
- Integration tests assert that a hostile `<repo>/.mkit/config`
  cannot set any user-scoped key (warning + ignored).
- Integration tests assert key-file owner / mode / `O_NOFOLLOW`
  behaviour and the atomic-write contract.
- Rename-gate (`scripts/verify-rename.sh`) prevents legacy strings
  from re-entering the public build surface.
- CI matrix: `cargo fmt --check`, `cargo clippy --all-targets --
  -D warnings`, `cargo test --workspace --locked`, keystore backend feature
  jobs for macOS/Windows/Linux with opt-in live native-backend roundtrips,
  `cargo deny`, reproducible-build smoke, `mkit version` byte-exact assertion.

---

## 9. Reporting issues

See [`SECURITY.md`](../SECURITY.md). Use GitHub Security Advisories.
Do not file public issues for vulnerabilities.
