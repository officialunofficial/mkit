# WP-2.4: mkit-attest grant and epoch statement codec plus the ed25519 scheme (split into 2.4a + 2.4b)

- **Milestone/track:** M2 / crypto (pure mkit-attest plus one small mkit-core module; may land during M0/M1)
- **Base:** `feat/mkit-server` at `392072d3` or later
- **Depends on:** S2 (merged, `09a38456`; SPEC-WRITE-GRANTS is normative)
- **Unblocks:** 2.5 (needs 2.4b + 2.3), 2.6/2.7/2.9 (server use), 2.12/2.13 (registry and CLI), and 1.4/1.16 (they
  reuse the §7.4 identity parser)
- **Area gates (registry):** `rust`, `wasm`, `golden` (+ `docs`: SPEC-WRITE-GRANTS §13.1; + `ci-yaml` if `fuzz.yml`
  is touched)

## Split (proposed; the registry needs two rows)

The full codec is the grant, epoch, visibility statements, the §3.1 text rules, the §3.3 ref scopes, the §4.2 header,
the ed25519 scheme, the §7 verifier, the §7.4 identity grammar and a fuzz target. With tests it is roughly
**2,000–2,300 changed lines**, well over the ~1,500 cap. Split at the parse/verify seam:

| PR | Branch | Content | Size |
|---|---|---|---|
| **2.4a** | `mkit-server/wp-2-4a-grant-codec` | §7.4 identity grammar (mkit-core), §3.1 text rules, the grant statement (§3.2–§3.5), ref scopes and effective flags (§3.3, §8.1), the header codec (§4.2), grant id (§3.4), fuzz target, codec goldens and reject vectors | L (~1,200–1,400) |
| **2.4b** | `mkit-server/wp-2-4b-grant-verifier` | Epoch statement (§5.1) with the §5.2 pure checks, visibility statement (§9.1), owner-scheme dispatch with the `ed25519` scheme (§4), the stateless verifier (§7 steps 1–10) and registration check (§10), signed goldens | M/L (~900–1,100) |

2.4b depends on 2.4a. 2.5 depends on 2.4b and 2.3. Registry updates for the orchestrator: replace row `2.4` with
`2.4a` (deps S2; gates rust, wasm, golden) and `2.4b` (deps 2.4a; gates rust, wasm, golden), and change 2.5's deps to
`2.3, 2.4b`.

## Conventions (both PRs)

- `git fetch origin && git switch -c <branch> origin/feat/mkit-server`. 2.4b branches from `feat/mkit-server` after
  2.4a merges.
- `export TMPDIR="$HOME/.cache/mkit-test-tmp"; mkdir -p "$TMPDIR"` before any test (the macOS `/tmp` symlink breaks
  mkit-attest's sign tests).
- Commit trailer: `Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>`. Don't poll CI or comment on
  GitHub or Linear.
- **No CI on `feat/mkit-server`.** Paste the local gate output into the PR body.
- Pre-production policy; `CHANGELOG.md` `[Unreleased]`; workspace lints; no `unsafe`; no proto change; stop above
  ~1500 changed lines (goldens and reject fixtures excluded).
- Carry-forward notes:
  - `connectrpc` 0.9.1 must not move in `rust/Cargo.lock`.
  - wasm32 clippy needs `--no-deps`. Baselines: **mkit-attest has 2 pre-existing lints**
    (`signer_external.rs:329`, `store.rs:235`) and **mkit-core has 6** (`ops/restore.rs:647/707/789`,
    `repo_lock.rs:136/216`, `protocol.rs:458`). New code adds none.
  - Test timeouts under load also happen on the base branch. Re-run alone and compare with base.

### Feature coordination with 2.3

The grant modules are gated on the `grants` feature. Final form (2.3 owns `sha3`):

```toml
grants = ["algo-ed25519", "algo-secp256k1", "algo-p256", "dep:sha3"]
```

If 2.4a merges before 2.3, it lands `grants = ["algo-ed25519"]`, and 2.3 widens the line on rebase. Not a default
feature.

## PRD and spec refs

- PRD §6.4 (grants, D5 audiences with no wildcard, D6 ref scopes, D19 capabilities, 30-day lifetime, epochs,
  `mkit-write-epoch:v1`, visibility, "the grant verifier lives in mkit-attest"), D5, D6, D19, M2-d.
- **SPEC-WRITE-GRANTS** (all normative):
  - §1.1 named parameters: `GRANT_MAX_LIFETIME_MS` = `EPOCH_STATEMENT_MAX_LIFETIME_MS` = 2,592,000,000;
    `MAX_EPOCH_STEP` 1024; `MAX_CLOCK_LEAD_MS` 30,000; `MAX_AUDIENCES` 8; `MAX_REF_SCOPES` 16;
    `MAX_STATEMENT_BYTES` 4,096; `MAX_GRANT_HEADER_BYTES` 8,192.
  - §2 namespace forms.
  - §3.1 text rules:
    - `\n`-joined, no final LF, no CR
    - bytes `0x21..=0x7E` inside fields; no empty field
    - canonical decimals; epoch ≤ u64::MAX; ms ≤ i64::MAX
    - lowercase hex
    - lists strictly ascending by bytes
    - ≤ 4096 bytes
  - §3.2 the eleven fields.
  - §3.3 the ref-scope ABNF, the `refs/mkit/packmap/` ban, and separator reasoning.
  - §3.4 grant id = BLAKE3(canonical bytes), 64 hex.
  - §3.5 the full rejection list.
  - §4 scheme table (`ed25519`: signed message = the 32-byte BLAKE3 of the statement, strict predicate of SPEC-SIGNING
    §1, blob = 64-byte signature, owner = the key named by the `ed25519-` namespace).
  - §4.2 header `<statement>.<scheme>.<blob>`: base64url with no padding, strict alphabet, zero trailing bits, ≤ 8192
    bytes, at most one header.
  - §5.1 the seven-field epoch statement; §5.2 acceptance checks 1–7 and the retry rule.
  - §7 verification order (steps 1–10 are stateless; step 11 reads state).
  - §8.1 effective flags.
  - §9.1 the seven-field visibility statement.
  - §10 registration (steps 1, 3, 4, 5, plus grantee = principal).
  - §11 error codes; §12.1 domain separators; §13.1 planned fixtures.
- SPEC-TRANSPORT-CONNECT §7.1 (audience origin rules; the auth v2 validity window is **inclusive** of expiry). §7.4
  (the identity grammar, lowercase only, longest identity 173 bytes).
- SPEC-REFS §3 (ref-name grammar: `mkit_core::refs::validate_ref_name`, `rust/crates/mkit-core/src/refs.rs:156`,
  implements it exactly).

## Existing code (tip `392072d3`)

| Symbol | Location | Use |
|---|---|---|
| `write_auth::validate_audience` | `rust/crates/mkit-core/src/write_auth.rs:69` | Audience origin rules (reuse; don't re-implement) |
| `write_auth::is_hex` | `write_auth.rs:56` | Lowercase fixed-length hex |
| `refs::validate_ref_name` | `rust/crates/mkit-core/src/refs.rs:156` | Ref-scope patterns |
| `hash::{hash, to_hex, from_hex}` | `rust/crates/mkit-core/src/hash.rs:24,84,121` | Grant id |
| `ed25519_dalek::VerifyingKey::verify_strict` | used at `write_auth.rs:221` | ed25519 scheme (strict predicate). **Not** `mkit_core::sign::verify` (`sign.rs:243`): that one adds a domain prefix. |
| `base64 = "0.23"` | `rust/crates/mkit-attest/Cargo.toml:69` | `engine::general_purpose::URL_SAFE_NO_PAD` rejects padding and (by default) non-zero trailing bits. Prove it with tests. |
| `mkit-server::repo::{RepoName, NamespaceKey}` | `rust/crates/mkit-server/src/repo.rs:24,56` | Permissive M0 types, no §7.4 grammar. 1.4 enforces the grammar in M1, and should reuse 2.4a's parser. |
| mkit-attest `Error` | `src/lib.rs:102` (flat, published) | Don't extend it; add `GrantError` |
| fuzz layout | `rust/fuzz/{Cargo.toml,src/lib.rs,fuzz_targets/*.rs}`; `run_one`/`MAX_ITER` in `rust/fuzz/src/lib.rs:37,764`; nightly matrix in `.github/workflows/fuzz.yml:33` (schedule/dispatch only) | New target `grant_parse` |

---

## WP-2.4a: grant codec

### Goal

A byte-exact, strict parser and encoder for `mkit-write-grant:v1` and its `X-Write-Grant` header encoding: one
canonical encoding per statement, no repair. It includes the §7.4 repository-identity grammar as a shared mkit-core
module, the ref-scope model with §8.1 effective flags, the grant id, a fuzz target, and goldens with one reject vector
per §3.5 rule.

### Scope

**IN:** as in the split table.

**OUT:**
- Signature verification, epoch and visibility statements, the verifier (2.4b).
- The ECDSA schemes (2.5).
- §8.2/§8.3 required-flag decisions and packmap coverage (server, 2.7).
- Any server or CLI use.

### Files

| File | Change |
|---|---|
| `rust/crates/mkit-core/src/repo_identity.rs` (new) + `lib.rs` (`pub mod repo_identity;` next to `refs` at :73) | §7.4 grammar: `Namespace::{Ed25519([u8;32]), Address([u8;20])}`, and `RepositoryIdentity { namespace: Option<Namespace>, name: String }` (a bare name only via an explicit `parse_bare_allowed`). Strict lowercase; name = `[a-z0-9][a-z0-9._-]{0,99}`; `Display` is canonical. |
| `rust/crates/mkit-attest/src/grant/mod.rs` (new, `#[cfg(feature = "grants")]`) | Module root and re-exports; `pub const DOMAIN_GRANT: &str = "mkit-write-grant:v1";`, and the §1.1 constants |
| `.../grant/text.rs` | §3.1 primitives, shared by grant, epoch, visibility and (via `pub`) 2.11's URL token |
| `.../grant/ref_scope.rs` | `RefPattern`, `RefFlags`, `RefScopes`, `effective_flags` |
| `.../grant/statement.rs` | `Grant` parse, encode and id |
| `.../grant/header.rs` | `OwnerScheme` tokens; `SignedHeader` parse and encode |
| `.../grant/error.rs` | `GrantError` |
| `rust/crates/mkit-attest/src/lib.rs` | `#[cfg(feature = "grants")] pub mod grant;` |
| `rust/crates/mkit-attest/Cargo.toml` | `grants` feature (see coordination) |
| `rust/fuzz/Cargo.toml`, `rust/fuzz/src/lib.rs`, `rust/fuzz/fuzz_targets/grant_parse.rs` | New target; `mkit-attest = { path = "../crates/mkit-attest", features = ["grants"] }` |
| `.github/workflows/fuzz.yml` | Append `grant_parse` to the matrix at :33 (schedule/dispatch only, so it never runs on the branch) |
| `rust/tests/golden/grants/{grant-statements.json,headers.json,MANIFEST.txt}`, `rust/tests/golden/grants/reject/*.json` | Goldens |
| `rust/crates/mkit-attest/tests/golden_grants.rs` | Reads fixtures. `MKIT_WRITE_GOLDEN=1` writes accept vectors. Reject vectors are hand-authored. |
| `scripts/golden/grants_ref.py` | Independent statement builder (cross-check) |
| `docs/specs/SPEC-WRITE-GRANTS.md` | Status paragraph + §13.1 fixture list |
| `CHANGELOG.md` | `### Added` |

### Design

```rust
// ---- mkit-core::repo_identity ----
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Namespace { Ed25519([u8; 32]), Address([u8; 20]) }
impl Namespace { pub fn parse(s: &str) -> Result<Self, IdentityError>; }          // Display: "ed25519-<64>" | "0x<40>"
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RepositoryIdentity { namespace: Option<Namespace>, name: String }
impl RepositoryIdentity {
    pub fn parse(s: &str) -> Result<Self, IdentityError>;              // requires "<ns>/<name>"
    pub fn parse_bare_allowed(s: &str) -> Result<Self, IdentityError>; // single-repo deployments
    pub fn namespace(&self) -> Option<&Namespace>; pub fn name(&self) -> &str;
}
pub const MAX_IDENTITY_LEN: usize = 173;

// ---- mkit-attest::grant ----
#[derive(Clone, Copy, Debug, PartialEq, Eq)] pub enum Capabilities { Read, ReadWrite, Write }
impl Capabilities { pub fn allows(self, c: Capability) -> bool; }
#[derive(Clone, Copy, Debug, PartialEq, Eq)] pub enum Capability { Read, Write }

#[derive(Clone, Debug, PartialEq, Eq)] pub enum RepoScope { Repository(RepositoryIdentity), Namespace }
impl RepoScope { pub fn covers(&self, ns: &Namespace, repo: &RepositoryIdentity) -> bool; }

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RefFlags(u8);  // bits c,u,f,d; `parse` requires a non-empty subsequence of "cufd" in order; Display canonical
impl RefFlags { pub const CREATE: Self; pub const UPDATE: Self; pub const FORCE: Self; pub const DELETE: Self;
                pub fn contains(self, other: Self) -> bool; pub fn union(self, other: Self) -> Self; }
#[derive(Clone, Debug, PartialEq, Eq)] pub enum RefPattern { Exact(String), Prefix(String) } // Prefix stores P (without "/*")
impl RefPattern { pub fn matches(&self, ref_name: &str) -> bool; }  // Prefix: name starts with "P/" (any depth)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefScopes(Vec<(RefPattern, RefFlags)>);   // 1..=16, ascending by whole entry text, unique pattern
impl RefScopes { pub fn effective_flags(&self, ref_name: &str) -> RefFlags; }   // §8.1 union over matching entries

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    pub namespace: Namespace,
    pub scope: RepoScope,
    pub grantee: [u8; 32],
    pub capabilities: Capabilities,
    pub audiences: Vec<String>,          // 1..=8, each validate_audience, strictly ascending
    pub ref_scopes: Option<RefScopes>,   // None <=> capabilities == Read ("-")
    pub epoch: u64,
    pub created_ms: i64,
    pub expiry_ms: i64,                  // created < expiry <= created + GRANT_MAX_LIFETIME_MS
    pub nonce: [u8; 32],
}
impl Grant {
    pub fn parse(bytes: &[u8]) -> Result<Self, GrantError>;   // every §3.5 rule; never repairs
    pub fn encode(&self) -> Result<Vec<u8>, GrantError>;      // validates; encode(parse(b)) == b
    pub fn id(bytes: &[u8]) -> [u8; 32];                      // BLAKE3 of canonical bytes (callers pass the parsed input)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnerScheme { Ed25519, Secp256k1Eip191, WebAuthnP256 }  // tokens "ed25519" | "secp256k1-eip191" | "webauthn-p256"
impl OwnerScheme { pub fn token(self) -> &'static str; pub fn from_token(s: &str) -> Option<Self>; }

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedHeader { pub statement: Vec<u8>, pub scheme: OwnerScheme, pub blob: Vec<u8> }
impl SignedHeader {
    pub fn parse(value: &str) -> Result<Self, GrantError>;   // <= 8192 bytes; exactly two '.'; strict base64url no pad
    pub fn encode(&self) -> String;
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum GrantError { /* one variant per §3.5 rule family + header errors */ }
impl GrantError { pub fn reason(&self) -> &'static str; }  // stable text for logs and fixtures; never shown to clients (§11)
```

`text.rs` primitives (`pub`, reused by 2.4b and 2.11):
- `split_fields(bytes, n) -> Result<Vec<&str>, GrantError>`: enforces ≤ 4096 bytes, exactly n fields, no empty field,
  no final LF, no CR, bytes `0x21..=0x7E` only.
- `decimal_u64`, `decimal_millis` (≤ i64::MAX), `hex32`, `sorted_list(field, sep, parse_item)` (strictly ascending,
  so no duplicates), `audiences(field)` (1–8, `validate_audience`, no `*`), and the matching encoders.

### Tests to write first

- `repo_identity`:
  - accepts the longest identity (173 bytes), and both namespace forms
  - rejects uppercase hex, 39/41-hex addresses, 63-hex keys, a name starting with `.`/`_`/`-`, a 101-byte name,
    uppercase name bytes, an empty name, a bare name via `parse`, and extra `/`
- `grant_roundtrip`: `encode(parse(b)) == b` for every accept vector; `parse(encode(g)) == g` via proptest over
  generated valid grants.
- `§3.5` rejects, **one test per rule**, each asserting the specific `GrantError`:
  - field count 10 and 12; an empty field; a final LF; a CR; a byte 0x20 or 0x7F inside a field
  - a wrong domain (including `mkit-write-grant:v2`, and trailing space)
  - namespace grammar; repository identity grammar; a repository scope in another namespace; a `*` scope form other
    than `<ns>/*` (for example `<ns>/foo*`)
  - decimal `+1`, `01`, epoch 2^64, millis 2^63
  - uppercase grantee or nonce, wrong-length hex
  - an unknown capability; `write,read` (non-canonical order)
  - audiences: bad origin (uppercase, default port, trailing dot, path, userinfo), `*`, a `*` inside a host, 9
    audiences, unsorted, duplicate
  - ref scopes `-` with `write`; ref scopes other than `-` with `read`
  - patterns: invalid ref name (per SPEC-REFS), a bare `*`, `refs/heads/*x`, `refs/mkit/packmap/*`,
    `refs/mkit/packmap/main`
  - flags: unknown flag, `uc`, `cc`, empty flags
  - 17 entries; unsorted entries; two entries with one pattern (`refs/heads/main=c;refs/heads/main=cu`)
  - `expiry == created`; `expiry < created`; lifetime of 30 days + 1 ms
  - a statement of 4097 bytes
- `effective_flags`:
  - an exact match
  - prefix at any depth (`refs/heads/wip/*` matches `refs/heads/wip/a/b`, not `refs/heads/wipx`, not
    `refs/heads/wip`)
  - union of overlapping entries
  - no match gives empty flags
  - documented: `refs/mkit/*` matches `refs/mkit/packmap/x`, and §8.3 (server, 2.7) overrides that
- `header`:
  - roundtrip
  - rejects padding `=`; `+`/`/` (standard alphabet); non-zero trailing bits (e.g. a final char `B` where only `A` is
    canonical); 1 or 3 dots; an empty segment; an unknown scheme token; 8193 bytes
- `grant_id_is_blake3_of_input_bytes`.
- Fuzz body `grant_parse_one_iteration(input)`: `Grant::parse` and `SignedHeader::parse` never panic; if parse
  succeeds, `encode` reproduces the input exactly. Register it in `rust/fuzz/src/lib.rs` `#[cfg(test)]` so
  `cargo test -p mkit-fuzz` runs it on stable.

### Golden-vector plan (mandatory)

- `grants/grant-statements.json`: accept vectors `{ name, statement (UTF-8 string), id }` covering:
  - `read` / `write` / `read,write`
  - a single repo and `<ns>/*`
  - `0x` and `ed25519-` namespaces
  - 1 and 8 audiences, including an IPv6 `[::1]:8443` origin and an `http://` origin with a port
  - 16 ref scopes; prefix and exact patterns; every flag subsequence shape (`c`, `cu`, `cufd`, `ud`, `d`)
  - epoch 0 and u64::MAX
  - `created` 0 and the maximum lifetime
  - the §3.4 example (it is illustrative in the spec, so it is also pinned here)
- `grants/headers.json`: `{ statement, scheme, blob_hex, header }` for each scheme token (blob contents arbitrary
  here; signatures come in 2.4b/2.5), plus header rejects.
- `grants/reject/<rule>.json`, one file per §3.5 rule (see the test list): `{ rule: "<§3.5 bullet>", statement,
  expected_error: "<GrantError::reason>" }`. `MANIFEST.txt` pins the BLAKE3 of every file.
- **Independent cross-check:** `scripts/golden/grants_ref.py` builds each accept statement from a field dict using
  only the spec text (join with `\n`, sort lists by bytes, canonical decimals), computes its BLAKE3 id (`b3sum` or
  WP-1.3's `scripts/golden/blake3_subtree_ref.py` if merged), and builds the header with
  `base64.urlsafe_b64encode(x).rstrip(b"=")`. It asserts byte equality with the fixtures. For each reject vector, the
  script states which spec rule it violates (a manual assertion per rule, printed as a table in the PR body).
- Spec: SPEC-WRITE-GRANTS Status paragraph ("lists none until then" → points to §13.1) and §13.1: list the new files
  (rebase over 2.3 if it merged first).

### Gate commands (repo root)

```bash
export TMPDIR="$HOME/.cache/mkit-test-tmp"; mkdir -p "$TMPDIR"
( cd rust && cargo fmt --check )
( cd rust && cargo clippy --all-targets --all-features --workspace -- -D warnings )
( cd rust && cargo nextest run -p mkit-core -p mkit-attest --all-features -p mkit-fuzz -p mkit-server -p mkit-wasm )
( cd rust && cargo test --doc -p mkit-core -p mkit-attest --all-features )
( cd rust && cargo check -p mkit-attest --features grants --target wasm32-unknown-unknown )
( cd rust && cargo check -p mkit-core --no-default-features --target wasm32-unknown-unknown )
( cd rust && cargo clippy -p mkit-attest --features grants --target wasm32-unknown-unknown --no-deps -- -D warnings 2>&1 | grep -E '^ +--> ' | sort -u )  # only the 2 attest baseline sites
( cd rust && cargo clippy -p mkit-core --no-default-features --target wasm32-unknown-unknown --no-deps -- -D warnings 2>&1 | grep -E '^ +--> ' | sort -u ) # only the 6 core baseline sites
( cd rust && cargo build -p mkit-wasm --target wasm32-unknown-unknown )
( cd rust/fuzz && cargo +nightly fuzz build grant_parse )     # fuzz build (golden gate); skip only if nightly is unavailable, and say so
actionlint .github/workflows/fuzz.yml                          # ci-yaml (matrix edited)
python3 scripts/golden/grants_ref.py rust/tests/golden/grants
just ci-scripts
just ci                                                        # mkit-core public API + Cargo.lock
```

### Acceptance checklist (2.4a)

- [ ] Every §3.5 rule has a unit test **and** a reject fixture; no rule is repaired.
- [ ] `encode(parse(b)) == b` for all accept vectors and the proptest; the fuzz target never panics, and its unit
      path runs in `cargo test -p mkit-fuzz`.
- [ ] `repo_identity` enforces §7.4 exactly; 1.4/1.16 are told (in the PR body) to reuse it.
- [ ] The audience check reuses `write_auth::validate_audience`; the ref-name check reuses `refs::validate_ref_name`.
- [ ] Goldens and the Python cross-check are committed and green; §13.1 is updated.
- [ ] wasm32 check passes; wasm clippy shows only baseline sites.

---

## WP-2.4b: epoch and visibility statements, ed25519 scheme, stateless verifier

### Goal

Parse and encode `mkit-write-epoch:v1` and `mkit-repo-visibility:v1`. Verify owner signatures through a scheme
dispatch whose `ed25519` arm is implemented here, with the ECDSA arms stubbed for 2.5. Expose a stateless verifier for
§7 steps 1–10, split into a cacheable owner check (steps 1, 3, 4, which the spec allows caching by exact header bytes)
and a per-request context check. Also expose the §5.2 and §9.1 statement acceptance checks that need no stored state,
the pure §5.2 check 7 (`epoch_transition`), and the §10 registration check.

### Files

| File | Change |
|---|---|
| `rust/crates/mkit-attest/src/grant/epoch.rs` (new) | `EpochStatement`, `epoch_transition`, `DOMAIN_EPOCH` |
| `.../grant/visibility.rs` (new) | `VisibilityStatement`, `Visibility`, `DOMAIN_VISIBILITY` |
| `.../grant/owner.rs` (new) | `AcceptedSchemes`, `verify_owner_signature` (ed25519 implemented; ECDSA → `GrantError::SchemeNotImplemented` until 2.5) |
| `.../grant/verify.rs` (new) | `OwnerVerified`, `GrantRequest`, `VerifiedGrant`, `verify_grant_owner`, `verify_epoch_statement`, `verify_visibility_statement`, `verify_for_registration`, `VerifierConfig` |
| `rust/tests/golden/grants/{grant-ed25519.json,epoch-ed25519.json,visibility-ed25519.json}`, `grants/reject/verify-*.json` | Goldens |
| `rust/crates/mkit-attest/tests/golden_grants.rs` | Extend |
| `scripts/golden/grants_ref.py` | Extend with pycryptodome Ed25519 signing |
| `docs/specs/SPEC-WRITE-GRANTS.md` §13.1, `CHANGELOG.md` | Update |

### Design

```rust
pub const DOMAIN_EPOCH: &str = "mkit-write-epoch:v1";
pub const DOMAIN_VISIBILITY: &str = "mkit-repo-visibility:v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochStatement { pub namespace: Namespace, pub new_epoch: u64, pub audiences: Vec<String>,
                            pub created_ms: i64, pub expiry_ms: i64, pub nonce: [u8; 32] }   // parse/encode: 7 fields, §3.5 rules
#[derive(Clone, Copy, Debug, PartialEq, Eq)] pub enum EpochTransition { Advance, Retry, Reject }
/// §5.2 check 7 + retry rule: stored < new <= stored + MAX_EPOCH_STEP (overflow-safe: saturating, so a namespace near
/// u64::MAX can still reach u64::MAX); new == stored -> Retry; else Reject.
#[must_use] pub fn epoch_transition(stored: u64, new: u64) -> EpochTransition;

#[derive(Clone, Copy, Debug, PartialEq, Eq)] pub enum Visibility { Public, Private }
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VisibilityStatement { pub repository: RepositoryIdentity /* must be namespaced */, pub visibility: Visibility,
    pub audiences: Vec<String>, pub created_ms: i64, pub expiry_ms: i64, pub nonce: [u8; 32] }

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AcceptedSchemes(u8);              // from GetServerInfo.grant_schemes tokens; unknown token -> error
impl AcceptedSchemes { pub fn from_tokens<'a>(t: impl IntoIterator<Item = &'a str>) -> Result<Self, GrantError>;
                       pub fn contains(self, s: OwnerScheme) -> bool; }

#[derive(Clone, Debug)]
#[non_exhaustive]                           // 2.5 adds the WebAuthn relying-party policy field
pub struct VerifierConfig { pub schemes: AcceptedSchemes }

/// §4: scheme advertised; scheme valid for the namespace form (ed25519 <-> `ed25519-`, ECDSA <-> `0x`);
/// signature verifies; recovered/derived owner == namespace. `ed25519`: blob.len() == 64,
/// key = namespace bytes, verify_strict over blake3(statement). ECDSA: SchemeNotImplemented (2.5).
pub fn verify_owner_signature(cfg: &VerifierConfig, scheme: OwnerScheme, statement: &[u8],
                              blob: &[u8], namespace: &Namespace) -> Result<(), GrantError>;

/// Steps 1, 3, 4 (stateless, cacheable by exact header bytes).
pub struct OwnerVerified<S> { pub statement: S, pub id: [u8; 32], pub scheme: OwnerScheme }
pub fn verify_grant_owner(cfg: &VerifierConfig, header: &str) -> Result<OwnerVerified<Grant>, GrantError>;

pub struct GrantRequest<'a> {
    pub audience: &'a str,                   // the deployment's own auth v2 audience (byte compare)
    pub repository: &'a RepositoryIdentity,  // X-Repository, or the ssh/enc path argument
    pub signer: &'a [u8; 32],                // X-Public-Key, or the ssh/enc transport principal
    pub capability: Capability,              // Write for write procedures, Read for private reads (§7 step 7)
    pub now_ms: i64,
}
/// Steps 2, 5, 6, 7, 9, 10 (every request). Step 8 (ref coverage) via `VerifiedGrant::effective_flags` (server, 2.7);
/// step 11 (epoch equality at authorize + inside apply) is the caller's.
impl OwnerVerified<Grant> { pub fn check(&self, req: &GrantRequest<'_>) -> Result<VerifiedGrant, GrantError>; }

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedGrant { pub id: [u8; 32], pub namespace: Namespace, pub scope: RepoScope,
    pub capabilities: Capabilities, pub ref_scopes: Option<RefScopes>, pub grantee: [u8; 32],
    pub audiences: Vec<String>, pub epoch: u64, pub created_ms: i64, pub expiry_ms: i64, pub scheme: OwnerScheme }
impl VerifiedGrant { pub fn effective_flags(&self, ref_name: &str) -> RefFlags; }

/// §5.2 checks 1–5 (6 = namespace policy and 7 = epoch_transition are the caller's).
pub fn verify_epoch_statement(cfg: &VerifierConfig, header: &str, audience: &str, now_ms: i64)
    -> Result<OwnerVerified<EpochStatement>, GrantError>;
/// §9.1 statement checks (scheme, signature, owner == repository namespace, audience, window).
/// "Only a greater `created` than the last accepted" is the caller's (state).
pub fn verify_visibility_statement(cfg: &VerifierConfig, header: &str, audience: &str, now_ms: i64)
    -> Result<OwnerVerified<VisibilityStatement>, GrantError>;
/// §10 registration: steps 1, 3, 4, 5 and grantee == principal.
pub fn verify_for_registration(cfg: &VerifierConfig, header: &str, audience: &str, principal: &[u8; 32])
    -> Result<OwnerVerified<Grant>, GrantError>;
```

**Time window (don't reuse auth v2's).** Grants, epoch and visibility statements are valid iff
`created ≤ now + MAX_CLOCK_LEAD_MS` **and** `now < expiry` (§7 step 10, §5.2 check 5, §9.1). Expiry is
**exclusive**. The auth v2 check at `write_auth.rs:213–215` rejects only `now > expires_at`, so expiry is inclusive
there. Test `now == expiry` → rejected.

### Tests to write first

- `ed25519_grant_verifies` (golden). A signature by another key is rejected. The `ed25519` scheme on a `0x`
  namespace is rejected. An unadvertised scheme is rejected. A 63- or 65-byte blob is rejected. A non-canonical
  signature (`s ≥ L`) is rejected by `verify_strict`. So is a small-order `A`: the namespace key is all zeros or
  another small-order point.
- `check_*`: repo scope mismatch; namespace mismatch with `X-Repository` (step 2); audience not listed (step 5; byte
  compare, so trailing slash or uppercase don't match); `read` grant for a write, and `write` grant for a private read
  (step 7); grantee ≠ signer (step 9); `now == expiry`, `now > expiry`, `created = now + 30_001` (rejected) and
  `created = now + 30_000` (accepted).
- `epoch_transition`:
  - (0, 1) and (0, 1024) → Advance; (0, 1025) → Reject; (5, 5) → Retry; (5, 4) → Reject
  - (u64::MAX − 10, u64::MAX) → Advance; (u64::MAX, u64::MAX) → Retry
- `epoch_statement` §3.5 rules (7 fields), `verify_epoch_statement` audience and window. `visibility_statement`: a
  bare-name repository is rejected; `public`/`private` only.
- `verify_for_registration`: grantee ≠ principal is rejected; audience missing is rejected.
- `owner_verified_is_cacheable`: the same header bytes give an identical `OwnerVerified`; changing one base64 char in
  the blob fails.
- The ECDSA schemes return `SchemeNotImplemented` (2.5 replaces those tests).

### Golden-vector plan (mandatory)

- `grants/grant-ed25519.json`: the owner seed (fixed, e.g. `0909…09`) and namespace `ed25519-<pub>`; grantee = the
  auth v2 golden key `ea4a6c63…d22c`; statement, id, 64-byte signature, full `X-Write-Grant` header; plus
  `accept_contexts` (audience, repository, signer, capability, now) and `reject_contexts`, each with its expected
  `GrantError::reason`.
- `grants/epoch-ed25519.json` and `grants/visibility-ed25519.json` in the same shape.
- `grants/reject/verify-*.json`: wrong scheme form, unadvertised scheme, bad signature, expired (at exactly expiry),
  future-dated.
- **Independent cross-check:** `scripts/golden/grants_ref.py` rebuilds each statement from the spec rules, signs
  BLAKE3(statement) with pycryptodome `eddsa.new(key, 'rfc8032')` from the seed, base64url-encodes it, and asserts the
  signature and header bytes are equal. Ed25519 is deterministic (RFC 8032), so the equality is exact.
- §13.1: list the files.

### Gate commands

As 2.4a, minus the fuzz and `actionlint` lines unless touched. Plus `bash scripts/check-crypto-stack-version.sh`
(unchanged pins). `just ci` if `Cargo.lock` changed; otherwise the rust + wasm lines suffice.

### Acceptance checklist (2.4b)

- [ ] `verify_grant_owner` + `check` implement §7 steps 1–7, 9 and 10 exactly. Step 8 is exposed as
      `effective_flags`; step 11 is documented as the caller's.
- [ ] The window is `created ≤ now + 30 s ∧ now < expiry`, with the tests above.
- [ ] `epoch_transition` is overflow-safe and matches §5.2 check 7 and the retry rule.
- [ ] The ed25519 scheme uses `verify_strict` over BLAKE3(statement), with the key from the namespace, bound to the
      `ed25519-` form.
- [ ] Every rejection maps to a `GrantError` whose `reason()` is stable. Nothing in the API picks a Connect code
      (§11 mapping is the server's: `permission_denied` for writes, `not_found` for private reads).
- [ ] Goldens are signed and cross-checked; §13.1 is updated; wasm32 check passes.

## Risks (both PRs)

- **Canonical-form holes.** Any accept-then-re-encode mismatch lets two byte strings share a meaning, and so change
  the grant id. The roundtrip proptest and the fuzz invariant (`encode(parse(b)) == b`) are the guard.
- **base64 leniency.** Confirm `URL_SAFE_NO_PAD` in base64 0.23 rejects non-zero trailing bits and padding (test
  both). If not, build a `GeneralPurpose` engine with `with_decode_allow_trailing_bits(false)` and
  `DecodePaddingMode::RequireNone`.
- **Prefix patterns over packmap refs.** `refs/*` and `refs/mkit/*` are legal and technically match
  `refs/mkit/packmap/…`. §8.3 (the server) must deny direct packmap writes regardless. Document this on
  `effective_flags`.
- **Shared-file churn.** `mkit-attest/{Cargo.toml,src/lib.rs}` and SPEC-WRITE-GRANTS §13.1 are also edited by 2.3
  and 2.5. Merge in registry order and rebase.
- **Scope creep.** URL-token minting and verification stay in 2.11 (`mkit-server`, dedicated key). 2.4a only makes
  `grant::text` public so 2.11 can reuse the §3.1 rules.

## Spec vs breakdown (specs win)

1. **No owner for the visibility statement.** SPEC-WRITE-GRANTS §9.1 defines an owner-signed
   `mkit-repo-visibility:v1` statement (any §4 scheme), but no WP in the breakdown or registry builds its codec. It
   belongs with the other owner-signed statements, so this brief assigns it to **2.4b**. 2.9 uses it.
2. **Rejection coverage.** The breakdown lists 7 reject vectors. §13.1 requires "one rejection for each §3.5 rule",
   which is ~30 cases (enumerated above).
3. **Ref-scope grammar.** The breakdown's risk "the ref-scope pattern grammar has to come from S2; don't invent it"
   is resolved: §3.3 pins the ABNF, the `cufd` flag order, the ban on patterns under `refs/mkit/packmap/`, and "no two
   entries sharing a pattern".
4. **Time window.** Grants and statements use `now < expiry` (exclusive), unlike auth v2's inclusive expiry. The
   breakdown is silent on this, and reusing the auth v2 window check would be wrong.
5. **Epoch "bounded increment".** The breakdown lists it as a statement field. In the spec it is an acceptance rule
   against the stored epoch (§5.2 check 7), exposed here as the pure `epoch_transition`.
6. **§7.4 grammar.** The breakdown assumes identity validation exists. It doesn't (M0-01's `RepoName` is permissive;
   G3 says the grammar lives "above write_auth"). 2.4a adds `mkit_core::repo_identity`, and 1.4/1.16 should reuse it
   rather than write a second parser.
