## Purpose

An owner can issue, import, inspect and revoke write and read grants from the CLI. A grantee's `mkit` then presents
the right grant automatically on every Connect request.
- The owner signs natively with an ed25519 key, or with a software-keystore secp256k1 key under `secp256k1-eip191`.
  Wallet signatures and WebAuthn assertions come in by import.
- `mkit epoch bump` / `mkit grant revoke` advance the grant epoch, honoring the server's `Retry-After` until
  completion.
- `mkit visibility set` switches a repository between public and private in either mode, envelope or signed
  statement.

## A. Fixed (do not change)

1. **SPEC-WRITE-GRANTS governs in full:**
   - §3: the statement fields, the canonical spellings (capabilities are exactly `read`, `read,write` or `write`),
     audiences and TTL bounds;
   - §4, §4.1–§4.4: headers and owner schemes; the low-`s` requirement, the `v` rule and EIP-191;
   - §5: epoch statements, including step bounds and "the same epoch is a retry";
   - §8.2: ref-scope flags;
   - §9.1: visibility statements;
   - §12: epochs are **per deployment**, and disclosing a grant is harmless.

   Where the M1–M2 breakdown disagrees, the spec wins. Known cases:
   - `--cap write,read` is not canonical;
   - the store is keyed by grant id, not "(audience, namespace)";
   - the breakdown's "keystore k256 signs natively" needs B3.
2. **P-18 (the plan's grant UX):**
   - selection prefers the most specific scope, then the latest expiry;
   - ed25519 and software-keystore secp256k1 sign natively; wallets and WebAuthn come in by import;
   - there is a single trusted signing remote;
   - WebAuthn fails closed without relying-party pinning.
3. **R-129 carry-forwards:**
   - the epoch ranking rule (B6);
   - the docs say a write-only grant never implies read on a private repository, except `GetReceipt`;
   - the full tie is already decided deterministically by header bytes. Keep it.
4. **R-125: the epoch and visibility clients honor `Retry-After` on `unavailable`.**
5. **Unsigned RPCs:** `GetGrantEpoch`, `SetGrantEpoch` and statement-mode `SetRepoVisibility` never carry an auth v2
   envelope.
   - `GetGrantEpoch`/`SetGrantEpoch` also carry no `X-Repository`.
   - Statement-mode `SetRepoVisibility` carries `X-Repository` equal to the statement's repository (the WP-2.9 server
     checks it).
6. **The CLI stays server-free:** `scripts/check-cli-baseline.sh` passes, and no normal dependency on server crates is
   added.
7. **R-128:** add **no** new `TransportError` variant. Typed outcomes are result enums on the new
   `ConnectTransport` methods.
8. **2.10's client signing and the `GrantSource` trait stay unchanged.** Extend `LocalGrants` only.
9. **Config security:** nothing in this bundle is settable from a repository config (SPEC-CONFIG-SECURITY; the
   pattern is `config.rs` forbidden keys and `tests/repo_config_forbidden_keys.rs`).

## B. Decided (do not change)

### Part 1: WP-2.13

- **B1. The store (D-B6).**
  - It lives at `xdg_config_home()/mkit/grants/`, next to the user config file. There is exactly one file per grant,
    named `<grant id hex>.grant`, holding the raw §4.2 header value and nothing else. Everything else is derived by
    parsing.
  - The directory is 0700 and the files 0600, written atomically (temp file plus rename).
  - It is never repository-scoped. Add it to the SPEC-CONFIG-SECURITY classification, and add a test that a
    repository config can't relocate it.
  - **On load:**
    - re-parse and **re-verify** every file's owner signature;
    - skip a malformed or unverifiable file with one warning each, never fatally;
    - bound the load: at most 1,024 files, each at most 16 KiB. Report the excess and skip it.
  - The store never reads a repository path.
- **B2. The owner-signing module.** One module used by `grant create`, `epoch bump` and `visibility set`. Modes:
  - **ed25519:** the configured mkit signing key, through the existing keystore/key-file paths. The namespace is
    derived from the key.
  - **secp256k1-eip191, native:** a software-keystore secp256k1 key via B3. The namespace is the `0x` address.
  - **secp256k1-eip191, wallet import:** `--print-statement` prints the exact bytes (and the EIP-191 digest) to sign
    externally. `--signature <hex>` imports a 65-byte `r‖s‖v`:
    - accept a `v` of 27/28 or 0/1;
    - normalize a high `s` and flip `v` (`mkit_attest::eth::normalize_eip191_signature`);
    - never trust the input as given.
  - **webauthn-p256, import:** `--webauthn-assertion <file>` imports an assertion; DER signatures are normalized to low
    `s` (`p256_der_to_low_s_raw`). This requires B7.
  - Every produced header is verified with the `mkit-attest` verifier **before** it is stored or sent. A failure is an
    error that names the failing rule.
- **B3. Keystore prehash signing (D-B1).**
  - Add a narrow `sign_prehash_recoverable_secp256k1(&[u8; 32]) -> [u8; 65]` (low `s`, `v` of 27/28) to the
    **software** keystore backend only.
  - Hardware backends keep reporting secp256k1 as unsupported.
  - No secret export and no `KeyExporter` fallback.
  - Add a SPEC-KEYSTORE note.
- **B4. `mkit grant create`.**
  - **Flags:**
    - `--namespace` (defaults to the signing key's namespace);
    - `--repo NAME | --all` (the namespace scope);
    - `--audience` (repeatable, 1–8; defaults to B9's single trusted remote audience);
    - `--refs pattern=flags` (repeatable);
    - `--cap read|read,write|write`;
    - `--grantee <ed25519 pubkey hex>`;
    - `--ttl` (at most 30 days);
    - `--epoch` (defaults to the remote's current epoch via `GetGrantEpoch`, or 0 with `--offline`).
  - **Canonicalize:** sort and dedupe audiences and ref scopes, and spell capabilities canonically. A non-canonical
    `--cap` spelling (e.g. `write,read`) is accepted and canonicalized.
  - `--store` also adds the grant to the local store. Otherwise the header goes to stdout, for handing to the grantee.
- **B5. `mkit grant add <file|->` and `mkit grant list [--check]`.**
  - **`add`:**
    - verifies the owner signature before storing;
    - rejects anything the verifier rejects, with the rule named;
    - warns when the grant's epoch is above the remote's current epoch (the B6 caveat);
    - is idempotent on the same grant id.
  - **`list`:**
    - shows id, namespace, scope, capabilities, ref scopes, audiences, epoch, expiry and status (`valid`, `expired`,
      `not yet valid`);
    - `--check` calls `GetGrantEpoch` per (namespace, audience) and marks `stale epoch` / `future epoch`;
    - `--json` for machine output.
- **B6. Installing the `GrantSource` and the epoch rule (D-B2).**
  - Build `LocalGrants` from the store and install it at the Connect open path (`remote_dispatch/mod.rs`
    `open_with_config*`).
  - **Selection:**
    1. filter to grants valid for the request;
    2. among those, rank **the higher epoch first, per (namespace, audience)**;
    3. then P-18: the most specific scope, then the latest expiry;
    4. the existing header-byte full tie comes last.
  - There is no pruning on import.
  - **Document the known downside:** a grant pre-issued for epoch e+1 outranks a live e-grant until the bump. `grant add`
    warns about it (B5).
- **B7. WebAuthn relying-party pinning (D-B3).**
  - The user-only config `grant.webauthn_rp = <rp_id> <origin>...` (repeatable) pins the relying parties used to verify
    imported WebAuthn assertions.
  - Without a matching pin, a WebAuthn import is **refused**.
  - The key is repository-forbidden.

### Part 2: WP-2.14

- **B8. The transport (D-B5).**
  - Add `open_connect_with_config` (or an equivalent) returning the concrete `ConnectTransport`.
  - Add `ConnectTransport::{get_grant_epoch, set_grant_epoch, set_repo_visibility}`.
  - Each returns a typed result enum with `Done(..)` and `Pending { retry_after: Duration }`.
  - They sit next to the existing API. `TransportError` is unchanged (A7).
  - **`Retry-After`:**
    - parse delay-seconds only;
    - clamp to 1–60 s;
    - a missing or garbage value is 1 s;
    - reuse #1201's `visible_header_values` plumbing.
- **B9. The audience and the trusted remote.**
  - Epoch and visibility statements default their audience to the named remote's origin, the same audience the auth v2
    envelope uses. `--audience` overrides.
  - A loopback audience (`localhost`, `127.0.0.0/8`, `::1`) is refused unless the remote itself is a loopback
    `mkit+http://` remote. That is the existing dev path.
- **B10. `mkit epoch show <remote> [--namespace]` and `mkit epoch bump <remote> [--by n] [--audience ...]`.**
  - **`bump`:**
    - reads the current epoch;
    - builds `mkit-write-epoch:v1` for current + n (n = 1 by default);
    - signs it through B2;
    - calls `SetGrantEpoch`.
  - A step over the spec bound is refused locally with the bound named.
  - **On `Pending`:**
    - wait `retry_after`;
    - re-send the **identical statement bytes** (§5.2 retry), never re-signing with a new nonce;
    - bound the total wait (default 5 min, `--timeout`);
    - Ctrl-C cancels cleanly and prints that the epoch may still complete server-side.
  - **Output:** the epoch actually stored.
- **B11. `mkit grant revoke <remote> [--prune]`.**
  - It is sugar for `epoch bump --by 1`.
  - It first lists the local grants for that (namespace, audience) that the bump invalidates, then prints a reissue
    hint.
  - `--prune` deletes those grants from the store after success.
- **B12. `mkit visibility set <remote> public|private [--statement]` (D-B4).**
  - **Envelope mode (default):** a signed auth v2 write of `SetRepoVisibility{visibility}` with the repository signing
    key, i.e. the owner.
  - **Statement mode (`--statement`):**
    - build and sign a `VisibilityStatement` through B2, with `created` = now;
    - send it unsigned, with `X-Repository` (A5), honoring `Pending`.
  - **Split the `envelope.rs` classification by mode:**
    - a request with `signed_statement` set is unsigned;
    - otherwise it is `Body`-signed as today;
    - remove the `TODO(WP-2.9 client)`.
  - Keep the "every generated RPC is classified" test green.

### Both parts

- **B13. Docs and plan.**
  - Update `docs/CLI.md`, the man page, completions and the `mkit` Agent Skill `SKILL.md` (find it in the repo).
    `tests/help_snapshot.rs` enforces them.
  - **The docs state:**
    - a write-only grant never implies read on a private repository, except `GetReceipt`;
    - each signed read may prompt for a signature, when the key needs one (R-129);
    - the B6 pre-issued-epoch caveat;
    - the difference between the client `mkit grant add` store and the operator-side `mkit-server grant register`
      (WP-2.12, Stage 2).
  - Keep the two names distinct.
  - **R-155 (2.13):** B1–B7, D-B1–D-B3 and D-B6, and the three breakdown disagreements (A1).
  - **R-156 (2.14):** B8–B12, D-B4 and D-B5, and the E2 status.
  - Add a CHANGELOG line per WP.

## C. Your decisions

- **The module layout** in `mkit-cli`. Clap wiring follows the `commands/key.rs` pattern.
- **Where the end-to-end tests live.** `check-cli-baseline.sh` constrains normal edges only.
  - A **dev-dependency** of `mkit-cli` on `mkit-server` (memory backends, `connect`), driving the real `mkit` binary or
    the dispatch code against an in-process server, is allowed.
  - Otherwise, use `mkit-server-native` tests driving `ConnectTransport` with headers produced by the CLI's store code.
  - Document the choice.
- **The `--json` shapes and the human output format.** Pin them with trycmd/insta.
- **Warning texts.**

## D. Escalate (stop and report) if

- B3 can't be done without exposing secret key material or touching hardware backends.
- The mode split in B12 would need to change 2.10's signing of any other RPC.
- Production code passes 3,000 lines. Cut in this order:
  1. `visibility set` (B12) moves to 2.15;
  2. then native keystore EIP-191 (B3) becomes import-only;
  3. then open the PR with 2.13 alone, and list 2.14 as not done.

## Tests (required)

**Unit:**
- A created statement round-trips through the `mkit-attest` owner verifier for ed25519 and software-keystore
  secp256k1.
- B3 produces low `s` and the right `v`, and a hardware backend reports unsupported.
- **Wallet import:** a high `s` with `v` ∈ {0, 1, 27, 28} normalizes, and the verifier accepts the result. Use the
  high-`s` twins in `rust/tests/golden/grants/eth-primitives.json`.
- **WebAuthn import:** a DER high-`s` normalizes, and an import with no pinned relying party is refused.
- Capability and audience canonicalization, including `write,read` → `read,write`.
- **Selection:**
  - a higher epoch wins per (namespace, audience);
  - epochs on different audiences don't interfere;
  - most-specific scope, then latest expiry;
  - the full tie is decided by header bytes.
- **Store load:**
  - a tampered file is skipped with a warning;
  - an oversize file is skipped;
  - the 1,024-file bound holds;
  - permissions are 0700/0600;
  - the write is atomic.
- The `Retry-After` parser: delay-seconds, the clamp, and garbage.
- The bump loop re-sends identical bytes and respects the total timeout.
- A loopback audience is refused unless the remote is a loopback remote.

**Config security:** a repository config can't set `grant.webauthn_rp` or relocate the store (the forbidden-keys
meta-test).

**Transport:**
- the epoch RPCs carry no `X-Repository` and no envelope;
- statement-mode `SetRepoVisibility` is unsigned and carries `X-Repository`;
- envelope-mode `SetRepoVisibility` is signed;
- the every-RPC classification test passes.

**CLI (trycmd/insta):**
- `grant create` output and statement bytes;
- `grant list` with and without `--check` (stubbed);
- the `grant add` rejection messages;
- `epoch show|bump` and `grant revoke` output;
- help, the man page and completions.

**E1, end-to-end against a real in-process server (always required):**
- the owner creates a write grant, the grantee's store holds it, and a grantee push succeeds through the installed
  `GrantSource`;
- `epoch bump` makes that grant fail with `permission_denied`, and a newly created grant at the new epoch works;
- a bump over the step bound is refused;
- a pending bump honors `Retry-After` (use the server's test-faults delay, or a stub returning `unavailable` +
  `Retry-After`) and then succeeds.

**E2, end-to-end with WP-2.9 (only if 2.9 has merged; see the E2 gate):**
- the owner makes a repository private with `visibility set` in both modes;
- a clone with the owner key succeeds;
- a clone with a read grant from the store succeeds;
- a write-only grant gets `not_found`;
- anonymous gets `not_found`.

## Gates

- the common gate set, plus `scripts/check-cli-baseline.sh` and `just ci-security` (the keystore changes);
- `cargo nextest run --locked -p mkit-cli -p mkit-keystore -p mkit-transport-connect -p mkit-attest --all-features`,
  plus the crate hosting your E1/E2 tests;
- `tests/help_snapshot.rs` and the trycmd transcripts;
- `cargo deny check`, if any dependency changes.
