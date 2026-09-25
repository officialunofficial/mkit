# WP-S2: SPEC-WRITE-GRANTS v1 (write and read grants, epochs, verifier requirements)

- **Milestone/track:** spec PR for Track Identity / M2 (issues mkit#1085, mkit#1089)
- **Base:** head of WP-S1's branch (`mkit-server/wp-s1-addressing`). Retarget to `feat/mkit-server` once S1 merges.
- **Branch:** `mkit-server/wp-s2-grants`
- **Depends on:** WP-S1
- **Parallel with:** WP-S3
- **Size:** L (docs, ~700–900 lines; a new spec file ~500 lines). #1089 (signed reads, private repos, URL tokens) is
  folded in per the adopted Q19 default, so there is no WP-S2b and M2 has no separate spec WP (WP-2.1 is dropped).

## Goal

Rebuild pr1087's SPEC-WRITE-GRANTS draft to match PRD §6.4:

- exact-epoch validity checked inside the atomic apply
- explicit audience lists (D5)
- ref-pattern scopes with create/update/force/delete flags and packmap coverage (D6)
- `write`/`read` capabilities (D19)
- bounded, audience-bound, expiring epoch statements
- low-S rules and `GetGrantEpoch`
- server-side grants for ssh/enc principals

Documentation only; the verifier lands in M2.

## Credit (required)

Source text is PR mkit#1087 by Christopher Wallace (@christopherwxyz). Every commit carries:

```text
Co-authored-by: Christopher Wallace <362387+christopherwxyz@users.noreply.github.com>
Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
```

PR body: "Rebuilt from #1087 (SPEC-WRITE-GRANTS) by @christopherwxyz, revised per MKIT-29 §6.4 / D5 / D6 / D19."

## PRD refs

§6.4 (all of it), §5.3 (epoch lives in `NamespaceStore`; `apply` precondition), §5.4 stage 2, §6.9, §8 M2 and the
rollout note ("before M2 only `ed25519-` owners can write"). Decisions: D4, D5, D6, D19, D23, D28, D34 (supersedes D21).

## Inputs

- the PR #1087 diff (`gh pr diff 1087`) lines 280–541 (the SPEC-WRITE-GRANTS draft) and 1–46 (web/README registration)
- WP-S1's §7.4 (namespace grammar) and §7.5 (write policy), which this spec plugs into
- `rust/crates/mkit-attest` (it already has k256, p256 and WebAuthn verification; `verify_p256` rejects high-S)
- `docs/specs/SPEC-CONVENTIONS.md` §4 (domain separators are new, literal, permanent strings), §5 (vectors), §6 (no
  crate names in normative text)
- `docs/specs/SPEC-CONFIG-SECURITY.md` (grant files and keys a CLI may read later; informative only here)

## Files

1. **New** `docs/specs/SPEC-WRITE-GRANTS.md` (frontmatter `spec`, `version: 1`, `status: draft-normative`,
   `audience`)
2. `docs/specs/README.md`: add the alphabetical bullet (pr1087 line 46 wording, adjusted: "owner-signed grants that
   let Ed25519 keys write to, or read from, a namespace's repositories")
3. `apps/web/src/lib/spec-data.ts`: add the entry after `SPEC-KEYSTORE` (pr1087 lines 29–34), with an updated
   description
4. `apps/web/src/components/spec-index.tsx`: `KeyIcon` import and `'SPEC-WRITE-GRANTS': KeyIcon` (pr1087 lines
   1–19). The vitest in `spec-index.test.tsx` requires every listed spec to have an icon.
5. `docs/specs/SPEC-TRANSPORT-CONNECT.md`: §7.5 (from S1). Replace "forthcoming" with links to SPEC-WRITE-GRANTS.
   Add `GetGrantEpoch`/`SetGrantEpoch`/`SetRepoVisibility`/`IssueObjectUrl` rows to §2 (M2), and the signed-read
   rule to §7.1. Add the `X-Write-Grant` header to §7.1's header list as a
   non-signed header. Append "SPEC-WRITE-GRANTS (mkit#1085)" to the v2 history row.

## Spec outline (section → content → source)

| § | Content | Keep / change from pr1087 |
|---|---|---|
| Opening | Status: Draft. Golden vectors land with the M2 implementation; none are listed until then (keep pr1087's sentence, which complies with SPEC-CONVENTIONS §5). Scope: who may write **or read** a repository on a multi-repository deployment; grant format, owner schemes, epochs, server checks. | Scope widened to reads (D19) |
| 1 Model | Owner, grant, grantee. A grant authorizes a key, never an operation; auth v2 still binds each operation (keep). Add: a grant carries capabilities (`write`, `read`). | Keep + capabilities |
| 2 Self-certifying namespaces | Reference SPEC-TRANSPORT-CONNECT §7.4's grammar (don't redefine it). Table of the two forms (keep pr1087's table). **Drop** "A deployment MAY resolve other namespace forms through its own registry" (D4). | Drop registry sentence |
| 3 Grant statement | See "Statement format" below. | Redesigned: audiences, ref scopes, capabilities; equality epoch |
| 4 Owner signature schemes | Keep the table (`ed25519`, `secp256k1-eip191`, `webauthn-p256`), the §4.1 address derivation (`keccak256(x‖y)[12..]`), the WebAuthn rules (UP flag, exact `clientDataJSON`, RP pinning), and the §4.2 header `X-Write-Grant: <statement>.<scheme>.<blob>` (≤ 8,192 bytes, one per request). **Add** low-S: secp256k1 `s` MUST be ≤ n/2 (keep). P-256: clients MUST normalize to low-S before encoding and verifiers MUST reject high-S (PRD §6.4). `v` ∈ {27, 28} (keep). | Keep + P-256 low-S |
| 5 Epochs and revocation | See "Epochs" below. | Redesigned (equality, bounded, audience-bound, expiring) |
| 6 Server policy | Point to SPEC-TRANSPORT-CONNECT §7.5 for `namespace_policy`/`write_policy`. List the three authorization paths and add the **read** path: `read` capability grants for private repos (§9). | pr1087 §6 mostly moves to TRANSPORT-CONNECT §7.5 (S1) |
| 7 Verification order | See "Verification" below. | Revised order; add epoch-in-apply and ref-scope checks |
| 8 Ref scopes and packmap coverage | See "Ref scopes" below. | New (D6) |
| 9 Reads and private repositories (adopted Q19 default: always in S2) | `public`/`private` visibility, default `public`, changed only by an **owner-signed `SetRepoVisibility(repository, visibility)` RPC** (unary, auth v2 by the namespace owner key or a grant with `write`; replay-protected like any write); signed reads (auth v2 over reads with a `body:` commitment, idempotent, validity window only, no replay ledger) and which procedures they cover; a client with a signer signs every read to its own remote (D28); the `read` capability; an **unauthorized read of a private repo returns `not_found`**, indistinguishable from a missing repo (no existence oracle); `IssueObjectUrl(repository, object_id \| ref+path, ttl)` returns a signed URL token signed by a **dedicated deployment URL-token key** (Ed25519, with key id, rotation via the published key list; never the receipt, hook or admin key), binding audience, repository, target, expiry and key id; `url_token_ttl` default **15 min**, and a requested ttl above the deployment maximum is clamped. `GetServerInfo` stays unsigned. | New (#1089) |
| 10 ssh and enc principals | The frozen `mkit.rpc.v1.ssh` can't carry grants. Grants for ssh/enc principals are registered server-side by the deployment operator (informative: an operator command in M2; the M5 admin API later wraps it) and looked up by transport identity (the Ed25519 key of the ssh forced command's `--principal`, or the enc peer). The same scope, epoch and expiry rules apply, including the epoch check at apply. | New (§6.4, D23) |
| 11 Error codes | Grant missing, invalid, expired, out of scope or wrong epoch → `permission_denied`. Envelope failure → `unauthenticated`. An epoch mismatch detected at `apply` → `permission_denied`, with nothing committed and the reservation aborted. Any unauthorized read of a private repository → `not_found`. | New (PRD "aligned") |
| 12 Security considerations | Keep pr1087 §8 bullets. Add: an audience list prevents cross-deployment replay of grants (D5); ref scopes limit agent blast radius; packmap coverage rationale; epoch statement expiry prevents a stale epoch bump being replayed at another deployment. | Keep + additions |
| 13 Out of scope | Verifier implementation (informative: planned in the attestation crate with Keccak-256 and secp256k1 recovery, **not** the core crate; per §6 of SPEC-CONVENTIONS, keep crate names out of normative text); multisig/contract owners; the workspace grant `mkit-workspace-grant:v1` stays separate (keep). CLI `mkit grant create/list/revoke`, `mkit epoch` (M2). | Keep + edits |
| 14 Version history | `1` \| draft \| "Initial grant statement (audiences, ref scopes, capabilities), owner schemes, exact-epoch revocation with bounded epoch statements, server policy (mkit#1085, mkit#1089)". | |
| 15 Invariants | Keep pr1087's 4 rows, with "epoch is current" → "epoch equals the stored epoch at apply". Add: "A grant is valid only at the deployments in its audience list." "A packmap ref changes only together with its covered head in one `AdvanceRefs`." "A stored epoch changes only by a bounded increment from an unexpired, audience-matching epoch statement." | |

### Statement format (§3), suggested canonical encoding for the author to finalize

Requirements come from the PRD; the encoding is the author's to finalize, and the reviewer checks it for ambiguity.
Newline-separated UTF-8 fields, no final newline, every field canonical (lowercase hex, no leading zeros, sorted
lists, no duplicates):

```text
mkit-write-grant:v1
<namespace>                 ; self-certifying, SPEC-TRANSPORT-CONNECT §7.4
<repository scope>          ; "<namespace>/<name>" or "<namespace>/*"
<grantee>                   ; 64 lowercase hex Ed25519 public key
<capabilities>              ; "read" | "write" | "read,write"
<audiences>                 ; 1..=8 canonical origins (auth v2 origin rules), byte-sorted, comma-separated; no wildcard (D5)
<ref scopes>                ; "-" for read-only grants, else 1..=16 entries "<pattern>=<flags>" separated by ";" and byte-sorted
<epoch>                     ; decimal u64 — MUST EQUAL the stored epoch (§5)
<created epoch ms>
<expiry epoch ms>           ; expiry - created <= 2,592,000,000 (30 days)
<nonce>                     ; 64 lowercase hex, 32 random bytes
```

- `<pattern>` is an exact SPEC-REFS §3 ref name, or a prefix ending in `/*` (a single trailing wildcard; no other
  wildcard). `<flags>` is a non-empty subset of `c` (create), `u` (update), `f` (force), `d` (delete) in the
  canonical order `cufd`.
- Explain why commas and semicolons can't be ambiguous here: canonical origins and ref names can't contain them.
  Verify against SPEC-REFS §3 and state it.
- The grant id is the lowercase hex BLAKE3 of the canonical bytes (keep).
- The verifier rejects field-count mismatches, trailing newlines, noncanonical numbers, uppercase hex, unsorted or
  duplicate list items, and unknown flags or capabilities.
- `mkit-write-grant:v1` is a new domain separator (SPEC-CONVENTIONS §4). Add it to the spec's registry note.
- Decide in the PR, with rationale, whether the auth v2 signature binds the presented grant id. pr1087 doesn't
  bind it; the PRD is silent. Not binding is safe because a substituted grant must still name the same grantee.
  S3 lists grant headers as hard-reserved either way.

### Epochs (§5)

- The epoch is stored per namespace, authoritatively in the namespace coordinator (D34; D21's per-namespace
  partition is superseded), and starts at 0. A grant
  is valid only while `grant.epoch == stored_epoch` (**change** from pr1087's `>=`).
- `mkit-write-epoch:v1` statement fields: `<namespace>`, `<new epoch>`, `<audiences>` (same list rules; it MUST
  cover the deployment verifying it), `<created>`, `<expiry>` (bounded lifetime; the bound's value is an open
  default **30 days maximum lifetime**, adopted), `<nonce>`. It is signed with any scheme valid for the namespace (§4).
- Accept only if `stored < new ≤ stored + MAX_EPOCH_STEP` (bounded increment; planner default `MAX_EPOCH_STEP =
  1024`, reviewable), unexpired,
  audience-matching, and not in the future beyond clock lead. The epoch is persisted as durably as refs and never
  decreases.
- RPCs: `SetGrantEpoch(statement)` (unary; authorization is the owner signature) and `GetGrantEpoch(namespace)`
  (unary, unauthenticated read). Proto lands in M2.
- The epoch is re-checked **inside** the atomic `apply` as a precondition, together with the commit deadline below,
  so a revoke that races an in-flight write rejects the write at apply (M2 exit test), including a write that was
  paused past the lease expiry (review 01, R-63).
- **Epoch leases (D34; reconciliation R-30).** The epoch is authoritative in the namespace coordinator. A ref shard
  may use its cached epoch only while it holds an epoch lease from the coordinator (`epoch_lease` default 30 s,
  a named parameter); it renews on its next write after expiry, and the renewal returns the current epoch.
  `SetGrantEpoch` reports success only after every currently leased shard has acknowledged the new epoch or its
  lease has expired, so a reported revocation is exact, completes within one lease interval, and costs O(active
  shards). While completion is pending the RPC MAY return retryable `unavailable` with a retry-after; retrying the
  same statement is idempotent. An idle shard can never apply under a stale epoch.
- **Commit deadline (normative; review 01, R-61/R-62).** Acknowledgement or lease expiry alone isn't enough: a write
  planned under a valid lease can reach its shard late (queueing, CPU stall, restart), after the lease expired and
  after the coordinator reported the revocation, in particular when the push of the new epoch to that shard failed.
  Therefore every write that depends on a leased epoch MUST carry a **commit deadline**
  `deadline = min(lease_expires − margin, plan_time + MAX_APPLY_WINDOW)` that the **storage backend evaluates against
  its own clock at commit**, atomically with the other checks; a write arriving after its deadline commits nothing
  (the server re-plans, renews the lease, sees the new epoch and rejects the revoked grant with `permission_denied`).
  `margin` (default 5 s) MUST exceed the worst clock skew between the coordinator and any shard's storage backend;
  `MAX_APPLY_WINDOW` (default 10 s) bounds plan-to-commit time. Both are named parameters. State the resulting
  guarantee: once `SetGrantEpoch` reports success, no write authorized under the old epoch commits afterwards,
  whatever its delivery delay.
- The same lease carries the coordinator's other cached config (visibility), so `SetRepoVisibility` to `private`
  is reported complete under the same rule.

### Verification (§7)

In order, stopping at the first failure with `permission_denied`:

1. Decode the header and parse the statement.
2. Statement namespace = namespace of `X-Repository`.
3. Scheme valid for the namespace form; signature verifies.
4. Recovered or derived owner = namespace.
5. The deployment's own audience ∈ `audiences`.
6. The repository scope covers `X-Repository`.
7. The capability covers the operation (write procedures need `write`; signed reads of private repos need `read`).
8. For writes, the ref scopes cover every ref the RPC changes (§8).
9. Grantee = auth v2 signer.
10. Time checks (created ≤ now + 30 s; now < expiry).
11. The epoch equals the stored epoch as read now. It is also carried as an `apply` precondition.

All of this completes before quota, admission or replay-record allocation, and a rejection allocates nothing.

### Ref scopes (§8)

- `create` is required for a ref that is absent at apply. `update` without `force` allows fast-forward only, which
  needs indexed mode. A server without indexed mode MUST reject (at verification) any grant with `u` but not `f` for
  a ref it would have to check, rather than silently allowing non-fast-forward.
- `delete` (`d`) governs ref deletion requested through `UpdateRef`/`AdvanceRefs` (SPEC-TRANSPORT-CONNECT §7.8). It
  is kept for that purpose (adopted M2 default), not only for forward compatibility.
- A scope on `refs/heads/<x>` covers `refs/mkit/packmap/<x>`. Packmap writes are allowed only together with the
  covered head in one `AdvanceRefs`, and flags are evaluated on the head only. Explain why: re-baselining writes a
  packmap that isn't an append; cite the client behavior informatively. Direct `UpdateRef` on a packmap ref is
  denied (`permission_denied`).

## Validation

```bash
bash scripts/check-spec-status.sh
just ci-scripts
(cd apps/web && bun install --frozen-lockfile && bun run test)     # spec-index.test.tsx must pass (icon for new spec)
(cd apps/web && bun run lint && bun run build)                     # match web.yml's gate if feasible locally
git diff --stat origin/feat/mkit-server -- proto/ rust/            # must be empty
```

## Acceptance criteria

- [ ] New spec file with 4 frontmatter keys and Status/Scope lines, following the new-mkit-spec conventions.
- [ ] Registered in `docs/specs/README.md` (alphabetical), `spec-data.ts` and `spec-index.tsx`; the vitest passes.
- [ ] Statement includes an audience list (no wildcard), ref scopes with `cufd` flags, capabilities, and an
      equality epoch.
- [ ] Epoch statement is bounded, audience-bound and expiring. `SetGrantEpoch` and `GetGrantEpoch` are specified.
- [ ] §5 makes the commit deadline normative (`min(lease_expires − margin, plan_time + MAX_APPLY_WINDOW)`, evaluated
      by the storage backend's clock at commit), with the margin-vs-skew requirement and the resulting guarantee.
- [ ] Packmap coverage and "packmap only with covered head in one AdvanceRefs" are stated. Direct packmap writes
      are denied.
- [ ] Low-S for secp256k1 and P-256 (client normalizes, verifier rejects high-S).
- [ ] The error-code split is stated. The verification order ends with the epoch carried into `apply`.
- [ ] ssh/enc server-side grants are specified without touching `mkit.rpc.v1.ssh`.
- [ ] No crate or function names in normative text. The verifier location appears only in informative "Out of scope".
- [ ] Defaults are named parameters with their adopted values: epoch statement max lifetime 30 days, URL token TTL
      15 min, `MAX_EPOCH_STEP` 1024, lease 30 s, margin 5 s, `MAX_APPLY_WINDOW` 10 s (planner defaults, flagged
      reviewable in the PR).
- [ ] §9 specifies `SetRepoVisibility`, signed reads, the `read` capability, `not_found` for unauthorized private
      reads, and `IssueObjectUrl` tokens signed by the dedicated URL-token key.
- [ ] §13 "Out of scope" notes the client grant store lives under the user config dir (informative; SPEC-CONFIG-SECURITY:
      never repo-scoped).
- [ ] Credit trailers and PR-body credit are present.

## Risks / gotchas

- If S1's section numbers change during review, rebase and fix the cross-links.
- `spec-index.test.tsx` fails the web gate if the icon map and the list disagree.
- Don't let the capability or ref-scope encoding collide with characters allowed in ref names. Today's validator
  (`rust/crates/mkit-core/src/refs.rs:141-175`) allows only `[A-Za-z0-9._-]` components joined by `/`, so `, ; = *`
  are free as separators. Confirm against `SPEC-REFS.md` §3 and cite it in the spec.
