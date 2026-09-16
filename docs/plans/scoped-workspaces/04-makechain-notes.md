# Consumer notes for makechain maintainers — not sent

Communication draft only; no makechain files, messages, issues or PRs changed. mkit's portable partial-workspace feature has **no makechain dependency or makechain-focused API**. It is built from mkit's existing object/proof/signing/pack/ref contracts. Any availability service may use it.

## What the consumer receives

A generic authenticated partial snapshot, ordinary client-signed Commit, explicit canonical object update, factual validation/diff/dependency helpers and conditional publication mechanisms. No mandatory project roles, chain keys, grants or consensus capability classes in mkit core.

Makechain's VCS/availability service chooses its own repository ownership, permission and branch policies. It can use the optional reference-host profile, implement a different one or adapt its existing authority checks. A service acceptance decision does not change mkit Commit validity.

## Existing code evidence: keep deployed and redesign lines distinct

Deployed checkout: `/Users/vitormarthendalnunes/Documents/21.Uno/07.Makechain/makechain`.

- `apps/vcs/src/services/authorization.ts:128–146`: project owner and WRITE/ADMIN/OWNER collaborators may write.
- `authorization.ts:149–155`: key scope and AGENT project allowlist; empty allowlist currently means all projects.
- `authorization.ts:24–75`: denied versus unavailable must remain distinct.
- `crates/makechain-state/src/handlers/commits.rs:105,139`: caller content_digest/url stored, content verification separate.

Redesign checkout: `/Users/vitormarthendalnunes/Documents/21.Uno/07.Makechain/makechain-v2`.

- `docs/design/makechain-protocol-redesign-rfc.md:77–85`: availability controls retention/access/retrieval; consumers recompute IDs.
- RFC `:929–964`: authorization generations/expiry/revocation and already-defined ACCOUNT/PROJECT/WRITE classes.
- RFC `:1095`: consensus checks identifier bounds/CommitmentId, not external bytes.
- RFC `:1149–1153`: generic refs, not branch/fast-forward/ancestry semantics; target is published same-project commitment.

Do not claim taxonomy is still open in this checkout or that v2 is deployed. These are consumer observations, not requirements imposed on mkit.

## Availability-layer enforcement contract

Before exposing a confidential subset or accepting restricted publication, the service must:

1. Authenticate caller and establish current authority using its own policy.
2. Authorize exact requested paths before returning a generic mkit bundle; protect legacy pack/ref/existence routes too.
3. Verify ordinary candidate and actual diff; enforce its ref/ancestry/path rules.
4. Enforce content origin: hidden object IDs cannot be made readable through an allowed output; bytes must be supplied or read-authorized.
5. Recheck live authority at publication and preserve immutable dependencies and durable outcome.
6. Keep broad publisher credentials and hidden repository data out of scoped agent execution.

An adapter may supply repository/project binding, issuer's explicit delegation right, scope ceiling, authority generation, finalized checkpoint/freshness and denied/unavailable distinction. This is a **service adapter**, not a new mkit protocol type. Whole-project write access does not automatically imply authority to delegate.

Path-limited agents should not simultaneously receive a broader direct chain write capability that bypasses service restrictions. How a chain deployment enforces that is its own integration work, outside this epic.

## Publisher receipt and anchoring

Optional host receipt binds exact request/context/base/result, enforcement-profile version and acceptance time. It records what the trusted publisher checked; it is not a consensus proof of private data, authority or availability. Agent Commit remains unchanged and client-signed. Current workspace-worker holds the ephemeral signing key in its service, not independently in the model.

mkit core neither requires nor interprets a host receipt as Commit validity. A consuming publisher may anchor accepted IDs using its existing authority. Local acceptance and chain anchoring are separate transitions; later integration needs outbox/idempotency and chain-ref CAS conflict policy. Never rewrite a candidate or equate local publication with completed anchoring.

Host grant/receipt storage is explicit, because mkit Remix sources are not closure edges and attestations are not currently transported. No chain outbox or anchor call in this epic.

## Separate item: verifiable content_digest

Keep outside this epic. Decide the claim first:

- Exact pack bytes: verifiable only against that encoding/order/compression, not stable across repacking.
- Canonical snapshot inventory: requires an independent specified framing/order/closure mode and verifier.
- Ongoing availability: cannot be established by a digest alone.

Recommendation: use native mkit commit ID for content binding and verify retrieved closure against it. Add another external commitment scheme only for a concrete missing claim. A publisher receipt can attest validation but does not magically make the consensus field verified. Any consensus-enforced proof needs its own privacy/resource/security design.

Commit optional annotation fields are not in the signing preimage (`mkit/docs/specs/SPEC-SIGNING.md:137–177`), even though the object ID binds serialized bytes. Do not repurpose an annotation as signed authorization evidence.

## Stale redesign README

At inspected baseline, v2 `README.md:10–15` describes active Phase1/specifications-only, while `redesign/program.toml:7–8,59–61` marks Phase2 active, phases0/1 complete, production crates still disabled. Recommend maintainers reconcile it without implying deployment. No edit or message made here.

## What to communicate

“mkit adds proof-verified partial editing and ordinary signed commits independently of hosting policy. Your availability service supplies permissions and private-publication enforcement. We can agree on a generic validation/receipt interface, but no chain-specific feature or capability class is required in mkit.”
