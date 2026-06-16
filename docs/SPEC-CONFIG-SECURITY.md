---
spec: SPEC-CONFIG-SECURITY
version: 1
status: normative
audience: config-key authors, config.rs reviewers, transport authors
---

# SPEC-CONFIG-SECURITY — repo-vs-user config trust split

Status: **Normative.** Companion to `docs/THREAT-MODEL.md` §4 and
`docs/SPEC-KEYSTORE.md` §8.2. Audience: anyone adding a new config
key, anyone reviewing a change that touches `mkit-cli/src/config.rs`,
and anyone writing a transport that consumes a config-derived
endpoint, key path, or credential.

This spec defines the per-key trust posture for every config knob
mkit reads, and the enforcement contract that keeps a hostile cloned
repo from escalating into the user's signing identity, ambient
network credentials, or arbitrary process execution. It exists
because the underlying constant — `REPO_FORBIDDEN_KEYS` — is easy to
forget to extend when new keys are added; this document gives the
review test "is the new key on this list?" a single canonical answer.

---

## 1. Threat

The attacker is a hostile remote repo author (THREAT-MODEL §3.1).
They control every byte in the cloned tree, including
`<repo>/.mkit/config`. They do NOT control
`$XDG_CONFIG_HOME/mkit/config`.

Without enforcement, any repo-scoped knob that names a file path,
selects a process to spawn, points at a network endpoint that will
carry ambient credentials, or selects a private signing key would be
attacker-controlled. This is the same confused-deputy shape closed
in GHSA-001 and tracked further in issue #97.

The defence is structural, not per-call: at the config READ site,
every key is classified as either repo-safe (`SAFE`) or user-only
(`UNSAFE`). UNSAFE keys appearing in `<repo>/.mkit/config` are
dropped with a stderr warning. They are only honoured when read from
`$XDG_CONFIG_HOME/mkit/config`.

The trust boundary is anchored in
`mkit-cli/src/config.rs::REPO_FORBIDDEN_KEYS`. That constant is the
single source of truth — `mkit-cli` is the only crate that performs
config-file I/O, so there is exactly one place to fence.

---

## 2. Per-key audit

The table below covers every key that `apply_kv` in
`mkit-cli/src/config.rs` recognises (in source order), plus the
`_url`-suffixed forward-compat slot.

| Key                                  | Scope      | Why this classification                                                                                                                                                              |
|--------------------------------------|------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `user.identity`                      | **UNSAFE** | Author identity bytes for commit objects. If repo-controlled, the attacker can spoof the author of a victim-signed commit (the victim's key still signs; only the name changes).      |
| `user.name`                          | SAFE       | Git-compatibility alias, **non-authoritative**: stored and round-tripped for parity with `git config user.name`, but no code path consumes it for authorship. Commit author resolution (`commit::resolve_author`) reads only `--author`, `user.identity`, or the signing-key fallback — never this field — so a repo-controlled value cannot influence the signed author. Repo-safe precisely because it is inert. |
| `user.email`                         | SAFE       | Git-compatibility alias, identical classification to `user.name`: non-authoritative metadata, never feeds the signed author. (The config command persists only the repo layer on write, so a user-scoped `user.email` is not materialized into the clone-traveling repo config.) |
| `trusted_remote_endpoint`            | **UNSAFE** | The trust selector for ambient HTTP/S3 credentials. If repo-controlled, every other defence in this list collapses — the attacker would self-trust their own exfil endpoint.          |
| `signer`                             | **UNSAFE** | Selects legacy raw-file vs keystore commit signing. A flip from `legacy` to `keystore` routes signing through a user-scoped key reference the attacker did not pick — same shape as the GHSA-001 confused-deputy. |
| `key.backend`                        | **UNSAFE** | Selects the keystore backend family (e.g. `software` vs `yubikey`). Could redirect signing to a hostile backend or surface a user-presence prompt for attacker-chosen content.      |
| `key.default_ref`                    | **UNSAFE** | Selects the default private signing key reference.                                                                                                                                  |
| `key.ed25519_ref`                    | **UNSAFE** | Selects the Ed25519 signing key reference.                                                                                                                                          |
| `key.secp256k1_ref`                  | **UNSAFE** | Selects the secp256k1 signing key reference.                                                                                                                                        |
| `key.p256_ref`                       | **UNSAFE** | Selects the P-256 signing key reference.                                                                                                                                            |
| `signing_key`                        | **UNSAFE** | Legacy raw-file key path. If repo-controlled, doubles as an arbitrary-file overwrite primitive when paired with auto-keygen (auto-keygen has since been removed; the path is still UNSAFE for the read direction). |
| `default_branch`                     | SAFE       | UX default. No security weight — the victim still verifies signed history regardless of which ref the repo nominates as default.                                                    |
| `remote_endpoint`                    | **SAFE** with runtime gate | A pure address. Repo-scoped endpoints are accepted, but `enforce_trusted_remote_endpoint` refuses to send ambient `MKIT_API_TOKEN` / `MKIT_R2_*` credentials unless the user has explicitly listed the same endpoint under `trusted_remote_endpoint`. |
| `remote_bucket`                      | SAFE       | Inert bucket-name slot. Not currently consumed by any transport; round-tripped only.                                                                                                |
| `remote_type`                        | SAFE       | Dispatch hint (`file` / `http` / `s3` / `ssh`). The exfil channel is the endpoint URL, not the dispatch label.                                                                       |
| `ssh.strict_host_key_checking`       | **UNSAFE** | Letting the repo disable host-key checking opens `mkit push` to MITM.                                                                                                              |
| `ssh.user_known_hosts_file`          | **UNSAFE** | The source of trust for SSH host-key verification.                                                                                                                                  |
| `ssh.identity_file`                  | **UNSAFE** | Selects which private key SSH presents. Same shape as `signing_key`.                                                                                                                |
| `attest.default_algorithm`           | **UNSAFE** | Selector. Flipping from `ed25519` to `secp256k1` / `p256` routes attestation signing to whichever non-Ed25519 key the user happens to have set up (confused-deputy).               |
| `attest.signer`                      | **UNSAFE** | Selector. Flipping from `repo-key` to `external` or `keystore` weaponises a user-scoped binary / keystore against attacker-chosen content.                                          |
| `attest.external_signer_path`        | **UNSAFE** | Arbitrary executable path → RCE under the user's UID.                                                                                                                              |
| `attest.external_signer_args`        | **UNSAFE** | Argv for the spawned signer. Combined with the path, gives the attacker full control of the subprocess.                                                                            |
| `attest.secp256k1_key_path`          | **UNSAFE** | Legacy raw-file path for a secp256k1 signing key.                                                                                                                                   |
| `attest.p256_key_path`               | **UNSAFE** | Legacy raw-file path for a P-256 signing key.                                                                                                                                       |
| Legacy: `author_mid`, `project_id`, `network` | SAFE | Silently dropped on read; retained for forward/back compatibility with old hand-edited files. None have a code path that consumes them.                                              |
| Forward-compat: `*_url`              | SAFE       | Reserved slot; no current consumer. If a future key in this namespace gains credential-routing or process-spawning behaviour, it MUST be promoted to UNSAFE in the same patch that introduces the consumer. |

### 2.1 Borderline cases

- **`remote_type`**: borderline because a hostile flip from `file` to
  `s3` could change the transport's credential-handling surface
  *given a user-trusted endpoint*. The defence rests on the endpoint
  itself being the credential carrier — `enforce_trusted_remote_endpoint`
  fences on `remote_endpoint`, not on `remote_type`. If a future
  transport ever decides credential routing from `remote_type`
  independent of `remote_endpoint`, this key MUST be reclassified as
  UNSAFE and added to `REPO_FORBIDDEN_KEYS`.
- **`remote_bucket`**: currently inert and SAFE. The same caveat as
  `remote_type` applies — if a future S3 transport ever signs requests
  using `remote_bucket` independent of `remote_endpoint`, the key must
  be promoted to UNSAFE.
- **`default_branch`**: SAFE because mkit verifies signed history
  regardless of which ref is nominated as default. A hostile clone
  pointing `default_branch = main` at attacker-controlled commits
  does not bypass signature verification.

---

## 3. Enforcement contract

The fence is implemented at the file-read site, not at the
field-consumer site, so every consumer gets the same guarantee
without needing to remember to check.

### 3.1 Read-site rule

In `mkit-cli::config::apply_file_inner`:

```text
if scope == ConfigScope::Repo && REPO_FORBIDDEN_KEYS.contains(key) {
    write stderr warning;
    skip the key (continue);
}
```

The key never reaches `apply_kv`, so the matching field on `Config`
stays at its default (empty string / `Vec::new()` / the documented
fallback). Higher-priority layers (user-scoped, defaults) are
untouched.

### 3.2 Write-site rule

In `mkit-cli::config::write`, only an explicit allow-list of
repo-safe keys is emitted:

```text
default_branch
remote_endpoint
remote_bucket
remote_type
```

Any other field on the in-memory `Config` is suppressed when
serialising `<repo>/.mkit/config`. The `mkit config <key> <value>`
command intercepts UNSAFE keys (`REPO_FORBIDDEN_KEYS.contains(key)`)
and writes them to the user-scoped file instead.

### 3.3 Warning shape

```text
warning: ignoring `<key>` from per-repo config at <path> \
  (security-sensitive keys are user-scoped only — see \
   <user-config-path> and docs/THREAT-MODEL.md)
```

The exact text is snapshot-tested
(`crates/mkit-cli/tests/snapshots/repo_config_forbidden_keys__repo_config_forbidden_warning.snap`).
Any wording change requires a reviewable `cargo insta` snapshot diff.

### 3.4 Runtime credential gate

`remote_endpoint` is repo-safe to *read*, but `mkit push`, `mkit pull`,
and `mkit fetch` call `enforce_trusted_remote_endpoint` before
attaching ambient credentials. The gate fires when ALL of:

- the merged endpoint is non-empty,
- the repo layer's `remote_endpoint` equals the merged endpoint
  (i.e. it came from `<repo>/.mkit/config`, not user config),
- the user layer's `trusted_remote_endpoint` does NOT equal the
  merged endpoint,
- the relevant ambient credential env var is set
  (`MKIT_API_TOKEN` for HTTP, `MKIT_R2_*` for S3).

When the gate fires, the command exits with a typed error directing
the user to `mkit config trusted_remote_endpoint <endpoint>`, which
writes to the user-scoped config. The repo-scoped knob can therefore
NEVER unilaterally trust a remote — the user's hand is always
required.

---

## 4. Test coverage

The fence is multiply-tested so a regression in any one layer cannot
hide:

1. **Per-key in-process drop test**
   (`mkit_cli::config::tests::repo_*_is_rejected` and the meta-test
   `every_forbidden_key_is_actually_dropped_from_repo_scope`). The
   meta-test iterates the entire `REPO_FORBIDDEN_KEYS` array, plants
   each key with a sentinel value in a repo-scoped file, and asserts
   the sentinel never appears in the merged `Config`. Adding a key
   to `REPO_FORBIDDEN_KEYS` without extending the meta-test causes a
   compile-fail-style panic with an actionable error message.
2. **Per-key end-to-end CLI test**
   (`crates/mkit-cli/tests/repo_config_forbidden_keys.rs`). For
   every UNSAFE key, plants `.mkit/config`, runs `mkit config
   <key>`, and asserts the value did NOT propagate to stdout and
   that stderr emitted the named warning.
3. **Warning-shape snapshot**
   (`tests/snapshots/repo_config_forbidden_keys__repo_config_forbidden_warning.snap`).
   Pins the exact stderr wording so cosmetic drift surfaces as a
   reviewable diff.
4. **Trusted-remote runtime-gate tests**
   (`config::tests::repo_*_remote_*requires_user_trust` and
   `trusted_http_remote_is_allowed`). Cover the
   `enforce_trusted_remote_endpoint` semantics for both HTTP and S3,
   plus the safe-path where the user has trusted the same endpoint.

---

## 5. Adding a new config key

When you add a key to `Config`:

1. Decide whether the key is SAFE or UNSAFE per §2. The default
   answer is **UNSAFE** — only reclassify after writing down why on
   this list.
2. If UNSAFE:
   - Add the key to `REPO_FORBIDDEN_KEYS`.
   - Add an arm to the meta-test's field-accessor `match` (the test
     panics with a descriptive error if you forget).
   - Add a per-key integration test in
     `tests/repo_config_forbidden_keys.rs`.
   - Update this spec's §2 table.
   - Update `docs/THREAT-MODEL.md` §4 if the key changes the user-vs-repo
     scope landscape.
3. If SAFE:
   - Document the reasoning in §2 (especially for borderline cases
     where the key names a destination or transport).
   - Add a repo-scoped acceptance test alongside any existing
     `roundtrip_repo_safe_keys`-style fixture.
4. If the key carries a credential, file path, or process-spawn
   primitive, also write a `mkit config` command path that routes
   the value to user-scoped storage (see `write_user_scoped` in
   `commands/config_cmd.rs`).

---

## 6. Non-goals

- This spec does not defend against an attacker who already runs as
  the user's UID (THREAT-MODEL §3.3). Once code runs as the user,
  it can edit `$XDG_CONFIG_HOME/mkit/config` directly and the
  scope split is moot.
- This spec does not protect against a user who manually opts in to
  a hostile remote by running `mkit config trusted_remote_endpoint
  <attacker>` after cloning. Local choice is the user's
  responsibility (THREAT-MODEL §3.1).
- This spec does not cover trust-roots file selection — see
  THREAT-MODEL §5. The trust-roots path is implicitly
  user-scoped-only because there is no repo config knob that sets it.
- The encrypted-transport peer-authorization allowlist and the
  server/client identity keys (issue #178) are likewise
  **user-scoped / CLI-only**. They are supplied as command-line flags
  (`--enc-authorized-peers`, `--enc-server-key`) or via a user-scoped
  environment variable (`MKIT_ENC_CLIENT_KEY`) and a user-scoped
  default path (`~/.config/mkit/enc/server.key`). They are members of
  the user-scoped key family alongside the legacy signing-key paths and
  trust-roots, and are **never** read from repo-local `.mkit/config` —
  there is no repo config knob that sets them, so a hostile repo cannot
  authorize itself as a peer or swap the server/client identity.

---

## 7. References

- `rust/crates/mkit-cli/src/config.rs` — single source of truth for
  `REPO_FORBIDDEN_KEYS` and the enforcement code path.
- `rust/crates/mkit-cli/tests/repo_config_forbidden_keys.rs` — per-key
  CLI regression suite.
- `docs/THREAT-MODEL.md` §4 — wider trust-boundary discussion.
- `docs/SPEC-KEYSTORE.md` §8.2 — the keystore-side requirement that
  every keystore selector be repo-forbidden.
- Issue #97 — the credential-exfiltration follow-up that motivated
  the runtime gate on `remote_endpoint`.
