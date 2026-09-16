# Decisions, recommendations and evidence gates

Revised after owner approval of the mechanism/policy separation. These are planning defaults and remaining implementation evidence gates, not authorization to execute. The former requests to approve mandatory core grants, server-first development and makechain authority integration are withdrawn.

## Settled by the owner

- mkit is its own protocol. Reuse its existing objects, proofs, signatures, raw packs and refs; Git is only an analogy.
- Sufficient verified witnesses plus selected bytes allow local staging, ordinary Commit creation and export without any service permission.
- VCS services decide access, grants and branch protection; no mandatory core grant/owner model.
- Full clones stay default/unchanged, Tier2 shelved, existing-file replacement MVP, planning only.
- Implementation PRs target one feature branch. Consolidation must preserve review/test quality.

## 1. New-path creation is not implied by “add a change”

**Recommendation:** retain existing regular/executable file replacements for v1. The command `workspace add` stages changed bytes; it does not introduce a new filename.

**Evidence:** complete Tree witnesses could support some additions technically, but nonexistence checks, namespace collisions and scope semantics would broaden the accepted MVP. If new-path creation is required, name it explicitly and scope a subsequent profile before execution. No blocker to the current plan.

## 2. Generic publication versus durable hosted acceptance

**Recommendation:** core offline workflow and explicit-object transfer ship without a new local transactional server. Existing FileTransport provides ordered append-only packmap then head CAS; generic client reports PublicationUnknown when historical acceptance cannot be established. Managed host advertises DurableResults only after PR12.

**Evidence:** `protocol.rs:581,606,623` and `mkit-transport-file/src/lib.rs:400`: no atomic advance override or durable result journal. A wrapper cannot turn separate ref calls into one transaction, especially with ordinary concurrent writers. If exactly-once durable local/file receipt is required too, add a separately designed all-writer journal/lock protocol; do not claim it from head readback. This deliberately narrows the earlier blanket durable-retry promise to implementations that provide it.

## 3. Consolidated PR size and session expectations

**Recommendation:**15 PRs (3/4/5/3), ~1–2.5k handwritten lines per coherent contract, up to3k for publication. Fresh executor, potentially more than one bounded session for L. Do not preserve the old 1.5k/one-session ceiling by dropping negative tests.

**Evidence gate:** integrator reviews PR08 access enforcement and PR12 publication estimates before implementation; split with fail-closed guards if needed. “15” is a target, not a security constraint.

## 4. Optional host support package

**Recommendation:** separate `apps/mkit-hosting-policy/` codec/helper package with optional hosting-specific wasm exports; generic mkit-core/mkit-wasm have no grant dependency. Service-local binary HostGrant over shared exact bytes, rather than building DSSE transport.

**Evidence gate:** before Phase3, inspect current Cargo/npm packaging and crypto-version scripts to choose minimal package layout and name. Dependency graph must remain host->core. No chain types or host grant fields in portable wire/state. `SPEC-ATTESTATIONS.md:612` confirms DSSE cannot be assumed to travel with push/fetch.

## 5. Reference host authority and operational provisioning

**Recommendation:** standalone operator-provisioned owner/collaborators, dedicated managed build/storage, no chain integration. One deployment=one repository, no multi-tenancy or ownership transfer. Other hosts may enforce different models.

**Evidence gate:** deployment owner supplies origin/repository/bindings, owner and receipt key procedures before private rollout. Managed artifact must fail closed without policy/config; default artifact must not acquire a RefStore dependency for public reads. No claim of protection against an operator deliberately replacing all security state/binaries.

## 6. Resource limits and canonical file representations

**Recommendation:** explicit PartialLimits and bounded v1 interoperability profile in design; consumer keeps256 KiB/file,4 MiB total. Worker snapshot enrollment remains separately capped/measured.

**Resolved evidence:** `SPEC-FASTCDC.md:33` says production boundaries do not invalidate alternative valid existing representations. Validate types/length sums/fixed layout; do not introduce a CDC-boundary canonicalization project. `worktree/blob.rs:159` allocates from total_size, so bound before calling.

**Evidence gate:** PR03 separately measures early consumer JS/wasm/persistence memory with new12MiB bundle/6MiB witness caps before public activation; PR10 measures memory/CPU/I/O near host limits; lower advertised deployment caps if required before enabling, never fallback to full packs. A valid million-entry Tree may be unsupported.

## 7. Consumer privacy and key custody

**Recommendation:** PR03 is an explicit public-bundle consumer, proving core integration early. PR13 introduces a separately latched private mode only after full hosting enforcement. Retain legacy AgentGrant for execution consent; service credential does not become core validity.

**Evidence:** `workspace.ts:85,87,180` public defaults; `workspace-state.ts:155` service-held signer. No independent agent custody claim. No automatic public->private migration or retrospective secrecy.

## 8. Durable results, revocation and audit budget

**Recommendation:** accepted managed results or non-reusable tombstones survive for repository lifetime under admission quotas; fresh request authentication permits original subject to retrieve its own saved opaque outcome after grant expiry, but never resume effects. Authorization immediately before bounded read release; already sent bytes cannot be recalled.

**Evidence gate:** owner confirms retention budget/key backup procedure before PR12. Remote/HSM receipt signing requires a redesigned receipt lifecycle, not network I/O inside SQL. No pruning that reopens operation identity.

## 9. Explicit update payload simplification

**Recommendation:** v1 includes every changed file's complete representation/chunks, even if already present at the recipient; deduplicate within update only. No retained-ID optimization or invented proof of what the client was authorized to read. Unchanged opaque entries remain implicit. This is a deliberate bandwidth tradeoff within bounded files, reducing first-phase wire and anti-grafting complexity. A later optimization needs its own evidence/authorization contract.

## 10. Protocol extension and endpoint surface

**Recommendation:** portable bundle/update profile plus separate optional binary partial-exchange HTTP methods, outside seven-verb transport. Existing auth-v2 and AccessDenied reused. Host credential carried/bound by adapter metadata; not a required field of generic bundles.

**Evidence gate:** PR06 records exact native adapter capability discovery and error encoding with goldens; PR10 implements the reference network binding. Until then offline export and file transfer remain usable. Any proposal to change existing protobuf requires regenerated consumers and revised scope, not silent executor choice.

## Changes from the old plan

Mandatory core SPEC-GRANTS removed; service ACL prerequisite now applies to confidential deployment only. Generic selection no longer encodes write permission. Generic state has no grant_id. Local commit requires no live authority. Managed receipt optional to core. Existing FileTransport durability limitations explicit. Early consumer integration is public and partial, not an unfinished private service. Later briefs must reflect these changes; obsolete first-phase briefs must not be executed.

No unresolved item licenses a code/spec/deployment change during this planning task.
