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

### 3.1a Hostile git upstream (`git-bridge` import)

Attacker controls a git repository that the user imports or fetches
with `mkit git import`/`fetch`/`pull` (feature `git-bridge`): every
object byte, ref name, tag chain, and the transport-level ref
advertisement.

mkit defends:

- Parser containment. Upstream bytes are read through a hardened
  parser layer (`gitparse`, fuzzed: commit/tag/tree targets) behind a
  `git cat-file --batch` subprocess; header blocks are size-capped,
  tag chains depth-capped (16), trees depth-capped (128).
- A refusal matrix instead of best-effort coercion. Gitlinks
  (submodules), unknown tree modes, duplicate/illegal tree entry
  names, negative or overflowing timestamps, oversized author
  payloads, and mkit-illegal ref names refuse per-ref with a warning
  — a hostile object cannot silently produce a misleading mkit twin
  (SPEC-GIT-IMPORT §3).
- Translation provenance. Every translated commit/tag is signed by
  the local IMPORT key, original raw bytes are retained
  sha1-addressed under `.mkit/git/<name>/raw/` as audit evidence, and
  each imported head gets a `git-import/v1` attestation binding the
  git commit id, canonical remote identity, and mkit twin.
  `mkit git verify` re-checks all of it offline.
- Tracking-ref containment. Fetches only move
  `refs/remotes/<name>/*` (plus tags); upstream force-pushes rewind
  tracking refs with a loud warning and never touch local branches.
- Accidental-overwrite guards on the way back. The origin guard
  refuses plain export toward any recorded import source, so a
  hostile (or merely confused) flow cannot replace an upstream with a
  disconnected re-translation that passes its push lease
  (SPEC-GIT-BRIDGE §14.2).

mkit does NOT defend:

- The semantic content of imported history. The import signature
  means "this is a faithful translation of those git bytes", not
  "those bytes are good". A hostile upstream's malicious source code
  imports faithfully.
- SHA-1 strength beyond its locator role. Object identity inside
  mkit is BLAKE3; sha1 is a locator for the git side. Fork-audit
  byte-checks (re-derivation + raw-bytes hashing) detect a swapped
  object for everything they check; sha1 collisions elsewhere are
  out of scope (SPEC-GIT-BRIDGE §14.3).
- A user who shares the import key with an untrusted party — the
  designated-importer model (SPEC-GIT-IMPORT §4) makes that key the
  root of the imported history's authenticity.

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

#### 3.4.1 Encrypted transport (`mkit+enc://`) peer authentication

The encrypted-stream transport uses two independent, *directional*
authentication mechanisms — do not conflate them:

- **Server-to-client** — the `?pubkey=<…>` value in the client's
  `mkit+enc://<host>:<port>?pubkey=<key>` URL pins the **server's**
  static ed25519 key. The client's `dial` aborts the handshake if the
  remote's actual key does not match. This authenticates the SERVER to
  the CLIENT (there is no TOFU; see SPEC-TRANSPORT-ENC §1). It does
  **not** say anything about who the client is.
- **Client-to-server** — authentication of the dialing client is the
  job of the server's bouncer **allowlist**, not of `?pubkey=`. Issue
  #178 makes `mkit serve --listen-enc` **fail-closed**: it refuses to
  bind without an `--enc-authorized-peers` allowlist (or the explicit
  `--unsafe-allow-any-enc-peer` dev escape). A client whose static
  ed25519 key is not on the allowlist is rejected at the handshake and
  never receives a `HelloResponse`, list-refs, packs, or update-ref.
  This closes the previous "accepts any peer" gap where the listener
  hardcoded a permissive bouncer.

The server identity is a stable key file (so pinned client `?pubkey=`
values survive restarts) and the allowlist / identity key paths are
user-scoped or CLI-only — never read from repo-local `.mkit/config`
(§4), so a hostile clone can neither authorize itself as a peer nor
swap the server identity.

### 3.5 Compromised release pipeline runner

Attacker has code execution on the GitHub Actions runner that
produces release artefacts.

mkit defends:

- Reproducibility of the binary build (`docs/RELEASE.md`).
- Provenance via cosign keyless signatures and CycloneDX SBOM
  (`docs/RELEASE.md`).
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

The per-key classification, the read-site fence, the runtime credential
gate on `remote_endpoint`, and the rules for adding a new config key
are codified in `docs/SPEC-CONFIG-SECURITY.md`. That spec is the
authoritative reference when reviewing a change that touches
`mkit-cli/src/config.rs` or a transport that consumes a
config-derived endpoint, key path, or credential.

`remote_endpoint`, `remote_bucket`, and `remote_type` are repo-safe
to *read* (a clone needs to be able to nominate a default mirror),
but `mkit push`, `mkit pull`, and `mkit fetch` will refuse to attach
ambient `MKIT_API_TOKEN` or `MKIT_R2_*` credentials to a
repo-configured endpoint unless the user has explicitly listed that
endpoint in user-scoped `trusted_remote_endpoint`. This closes the
hostile-clone credential-exfiltration channel tracked in issue #97
without breaking safe portable defaults for unauthenticated mirrors
and SSH-bearing remotes.

The gate is enforced at a single transport-dispatch choke point
(`remote_dispatch::open_trusted`), which runs the per-endpoint check
*before* it constructs any credential-bearing transport. The check is
keyed on the **resolved endpoint plus its provenance** — `repo_chosen`
(selected by repo-scoped config: the flat `remote_endpoint` or a
`remote.<name>.url` entry) versus user-chosen (user-scoped config or an
explicit CLI argument) — never on a remote *name*. This means the same
fence applies uniformly whether the credential-bearing endpoint comes
from the legacy single-remote field or from a named remote: a hostile
clone cannot smuggle ambient credentials to a new host by hiding the
endpoint behind a named remote, and a user-chosen endpoint with the
user's own credentials is never second-guessed. Unauthenticated and
SSH/file flows carry no ambient HTTP/S3 credentials and pass the gate
unchanged.

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
  only when a desktop session is detected and the protector opens cleanly;
  Secret Service errors fail closed rather than silently falling back to a
  weaker protector. `systemd-creds` is selected for headless/server Linux when
  no desktop Secret Service session is detected, and writes fail closed if no
  usable protector is available.
- YubiKey OpenPGP exposes existing Ed25519 signing-slot keys. YubiKey PIV
  exposes existing P-256 certificate-backed slots (`piv-9a`, `piv-9c`,
  `piv-9e`). Both are non-extractable and device-bound from mkit's point of
  view. Keystore V1 does not accept YubiKey PINs through environment variables;
  PIN- or touch-required signing fails closed with typed authentication errors
  until a bounded prompt provider is implemented.
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
  backends or read extractable secrets from software/raw/platform stores.
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
- `cargo fuzz` targets cover delta decode, pack reader, the object
  deserializer, and the encrypted software key record parser (`docs/FUZZ.md`).
- Integration tests assert that a hostile `<repo>/.mkit/config`
  cannot set any user-scoped key (warning + ignored). Per-key
  coverage lives in `rust/crates/mkit-cli/tests/repo_config_forbidden_keys.rs`,
  and the in-process meta-test
  `every_forbidden_key_is_actually_dropped_from_repo_scope` iterates
  the entire `REPO_FORBIDDEN_KEYS` list against a sentinel value.
  The exact stderr warning shape is pinned by an `insta` snapshot.
- Integration tests assert key-file owner / mode / `O_NOFOLLOW`
  behaviour and the atomic-write contract.
- CI matrix: `cargo fmt --check`, `cargo clippy --all-targets --
  -D warnings`, `cargo test --workspace --locked`, keystore backend feature
  jobs for macOS/Windows/Linux with opt-in live native-backend roundtrips,
  `cargo deny`, reproducible-build smoke, `mkit version` byte-exact assertion.

---

## 9. Reporting issues

See [`SECURITY.md`](../SECURITY.md). Use GitHub Security Advisories.
Do not file public issues for vulnerabilities.
