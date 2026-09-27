## Purpose

Multi-repository addressing (WP-1.4) routes writes to any `ns/name`, but nothing yet decides whether the signer may
write there. This WP adds, in core:
- the deployment's **namespace policy** (`allowlist` | `any`);
- the **write policy** (`open` | `owner`, where `owner` means rule 1, the namespace's own Ed25519 key);
- the **role of the Authorizer hook** (an additional `check`, or the §7.5 rule-3 `authority`);
- the D27 startup refusals.

Grants (rule 2) are M2. Enabling multi mode in the adapters' configuration is a separate WP (B.8).

## A. Fixed by the plan and specs (do not change)

1. **Specs:**
   - STC §7.5 (read all): namespace policy, write policy, rules 1–3, "Order", "Creation signals";
   - §7.4 (Single vs Multi);
   - §2.1 (`namespace_policy` advertised values: `allowlist` | `any` | `single-repository`, where
     `single-repository` is advertised and never configured);
   - SPEC-SERVER §2 stage 2 and §6.2 (the Authorize roles `authority`/`check`; `owner`/`grant` facts set on
     Authorize and Admit requests; a namespace-policy denial can't be overridden);
   - SPEC-WRITE-GRANTS §6/§7 (rule 2 is M2) and its rule that writes are not an existence oracle.
2. **Plan:** `m1-m2-breakdown.md` "WP-1.5"; PRD D27; `00-plan.md` rows on D27.
3. **Order (STC §7.5):** authorize after authentication and after the replay-record check, and before any quota,
   reservation or replay record is allocated. WP-1.22's order stays:
   1. `read_ahead`
   2. `replay_lookup`
   3. `creation_facts`
   4. `authorize`
   5. `admit`
   6. `commit_creation`
   7. `pre_receive`
   8. `plan_and_apply`
4. **`Partition` is unchanged.** `nl` (namespace list) stays reserved: no M1 consumer, and no deployment-wide
   partition.
5. **Single-repository deployments behave exactly as today.**

## B. Decided by the orchestrator (do not change)

### B.1 Types (`mkit-server/src/policy/{mod.rs, namespace.rs, write.rs}`, exported as `mkit_server::policy`)

```rust
#[non_exhaustive] pub enum NamespacePolicy {
    Allowlist(BTreeSet<mkit_core::repo_identity::Namespace>),   // default: empty (denies every write)
    Any { unsafe_without_admission: bool },                    // D27 override flag
}
#[non_exhaustive] pub enum WritePolicy { Open, Owner }
#[non_exhaustive] pub enum AuthorizerRole { Check, Authority }  // default Check
```

- `MultiAddressing` (`repo.rs`) gains a `pub namespace_policy: NamespacePolicy`. `MultiAddressing::new()` and
  `Default` give `Allowlist(empty)`, which **fails closed**.
  - Add `MultiAddressing::with_namespace_policy(p)`.
- `PipelineConfig` gains:
  - `pub write_policy: WritePolicy`: `PipelineConfig::new` picks `Open` for `Single` and `Owner` for `Multi`;
  - `pub authorizer_role: AuthorizerRole`: default `Check`.
- `pub fn advertised_namespace_policy(&self) -> &'static str` on `PipelineConfig` returns `"single-repository"`,
  `"allowlist"` or `"any"`. WP-1.6 uses it.

### B.2 Evaluation (in `Pipeline::authorize`, `pipeline/mod.rs`; nothing else moves)

**For writes** (`Procedure::is_write()`):
1. **Single addressing:**
   - `write_policy = Open` → run the Authorizer hook exactly as today.
   - (`Owner` is refused at startup, B.3.)
2. **Multi addressing:**
   1. **Namespace policy:** `Allowlist(set)` → the repo's namespace must be in the set, otherwise **deny**. `Any` →
      pass. A namespace-policy denial is final: no hook is called.
   2. **Rule 1 (owner):**
      - `owner = true` when the repo's namespace is `Namespace::Ed25519(k)` and `Principal::ed25519() == Some(k)`,
        for `Signer`, `TransportPeer` and `SshForcedCommand { key: Some }` only.
      - `Anonymous` and `BearerHolder` are never the owner.
      - An `Address` (`0x`) namespace never satisfies rule 1.
      - Parse the namespace with `Namespace::parse(op.repo.namespace.as_str())`. A parse failure in Multi is
        `internal` (it can't happen after WP-1.4's resolution).
   3. **Rule 2 (grant):** not yet. Leave `// TODO(WP-2.6): rule 2 (grants)`.
   4. **Hook, by role:**
      - `Check`: the write needs `owner`, otherwise **deny**. If `owner`, call the hook, which may deny.
      - `Authority`: always call the hook (even when `owner`). The write is authorized iff (`owner` or the hook
        allows) and the hook did not deny while `owner`.
        - Precisely: when `owner` is true, a hook error denies. When `owner` is false, the hook's `Ok` authorizes
          and its error denies.
   5. Return `AuthzFacts { owner, grant: None }`, and set `op.authz` as today, so Admit sees `owner`.

**For reads:** unchanged. Private reads are M2 (WP-2.9). Leave `// TODO(WP-2.9)`.

**Existence must not influence the decision:** `op.creation` is available to the hook, but the built-in policy never
reads it. Add a test that a non-owner is denied identically for an existing and a nonexistent repo.

**Denials:** `permission_denied` with the single public message `"write not permitted"`, for both the
namespace-policy and the rule-1 case, so allowlist contents never leak. Hook errors pass through as today.

### B.3 Startup validation (in `Pipeline::new`, so every adapter and `with_auth` sibling gets it)

Return the existing constructor error (`invalid_argument` or the type `Pipeline::new` already uses) for:
- `Multi` + `WritePolicy::Open` ("write_policy open is single-repository only (SPEC-TRANSPORT-CONNECT §7.5)");
- `Single` + `WritePolicy::Owner` ("write_policy owner needs multi-repository addressing");
- `NamespacePolicy::Any { unsafe_without_admission: false }` with the default Admission ("namespace_policy any needs a
  non-default admission step, or the explicit unsafe override (D27)");
- `AuthorizerRole::Authority` with the open authorizer ("an authority authorizer must be a real authority source").

Detection, through provided trait methods that are wasm-safe with no `'static` bound:
- `Admission::is_default(&self) -> bool { false }`, overridden to `true` only by `DefaultAdmission`;
- `Authorizer::is_open(&self) -> bool { false }`, overridden to `true` only by `OpenAuthorizer`.

Every existing impl keeps compiling.

### B.4 Tests that change because of B.2 (do NOT weaken them; move them onto owned namespaces)

- `mkit-server-native/tests/repository_routing.rs`: sign with keys that own the namespaces. Use
  `ed25519-<hex(signer pubkey)>`, and replace the `0x` pair with two ed25519 namespaces. Keep the same-name /
  different-namespace isolation assertions.
- `mkit-server-native/tests/d34_creation.rs`: it uses its own `Policy` authorizer. Configure owned namespaces, or
  `Any { unsafe_without_admission: true }`, and keep every call-count assertion (2/3/4 and the 2-`get_many` denial)
  unchanged.
- Wire cases `conformance/src/wire/cases/repository.rs` (`identities()`): derive the namespace from
  `ctx.v2_signer(...)`'s key. The in-process `baseline_pipeline_memory` Multi baseline configures an allowlist that
  holds the derived namespaces (or `Any` + unsafe), your choice (C).

### B.5 New tests

1. **Core, a matrix** over {Single, Multi} × {Allowlist hit, Allowlist miss, Any} × {owner, non-owner, anonymous,
   bearer, `0x` namespace} × {Check, Authority with allow hook, Authority with deny hook}.
   - The expected results come from B.2.
   - A denial allocates nothing: use `d34_creation.rs`'s call-counting `TestStore` or `pipeline/tests.rs`'s `Spy`.
     It gets no replay record, no quota row and no `nr`/`rr`.
2. **Startup refusals:** each B.3 case, plus the accepted counterparts.
3. **`advertised_namespace_policy`** for each config.
4. **Existence-independence** (B.2).
5. **Wire:**
   - Add `Feature::NamespacePolicy` (`"namespace-policy"`, M1) to `profile.rs`. The feature-name list grows by one.
   - Cases:
     - `policy.owner_write_allowed`;
     - `policy.non_owner_write_denied` (`permission_denied`, then a read shows nothing changed);
     - `policy.non_allowlisted_namespace_denied`.
   - The in-process Multi baseline declares the feature. The native binary and the Worker don't (they are Single).

### B.6 Docs and cleanup

- Fix the wrong comment at `pipeline/hooks.rs:~272` ("WP-1.5 adds the per-namespace charge"): it's WP-1.26.
- Update the `keys.rs` `nl` comment: it stays reserved until a WP needs namespace enumeration under `any` (WP-1.29
  backup).
- Rustdoc on `NamespacePolicy`, `WritePolicy` and `AuthorizerRole`, citing STC §7.5 and SPEC-SERVER §6.2.
- `INVARIANTS.md`: a section on "Namespace and write policy decide before allocation and never read existence".
- CHANGELOG entry.

### B.7 What this WP does NOT do

- No native flags and no Worker vars. The adapters stay Single-only.
- No `nl` rows.
- No GetServerInfo wiring (that's WP-1.6).
- No grants (M2).

### B.8 Plan note

Add row `R-96` to `00-plan.md`:

> WP-1.5 is core-only. Enabling multi-repository mode in the adapters, with its policy configuration (native
> `--addressing multi`, `--namespace-policy`, `--namespace-allowlist <file>` and `--unsafe-open-namespaces`; Worker
> vars `ADDRESSING`, `NAMESPACE_POLICY`, `NAMESPACE_ALLOWLIST` and `UNSAFE_OPEN_NAMESPACES`), is a dedicated
> WP-1.30, scheduled after WP-1.10 (pack membership) and before WP-1.19 (staging).

## C. Your decisions

- Module layout inside `policy/` and helper names.
- Where `authorizer_role` sits if `PipelineConfig` has a sub-struct for auth. It stays one field.
- How the in-process Multi baseline configures its policy (B.4).
- Test organisation.

## D. Escalate (stop and report) if

- The B.2 `Authority` semantics contradict SPEC-SERVER §6.2 as merged. Quote the passage.
- Moving the tests in B.4 onto owned namespaces would require changing an assertion's meaning, not just its keys.
- `Pipeline::new`'s error type can't carry the B.3 refusals without a public signature change.

## Gates

- `just ci-server`
- `cargo nextest run --locked -p mkit-server -p mkit-server-native -p mkit-server-conformance -p mkit-server-worker --all-features`
- the wasm32 check of `mkit-server`; the build of `mkit-server-worker`
- goldens unchanged
