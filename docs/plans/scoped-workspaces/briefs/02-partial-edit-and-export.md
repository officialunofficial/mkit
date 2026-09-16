# Executor brief PR02: feat(core): build and export ordinary partial-edit commits

Status: **planning artifact, do not execute until explicitly authorized**. You are a fresh executor; this brief carries the required context. No prior conversation is assumed.

## Mission and branch contract

Implement only this PR after landed PR01. At execution time create your own worktree/branch from the current, landed `feat/scoped-workspaces`. Open the PR with **base feat/scoped-workspaces**, never main. **Do not merge.** Integrator, not executor, syncs main at phase boundaries and handles final integration. Planning branch is plan/scoped-workspaces; do not implement there. Confirm clean task worktree and preserve unrelated changes.

mkit is its own BLAKE3 content-addressed protocol, not a Git extension. Core proof verification, selected-data editing and ordinary Commit signing require no owner/grant/service. VCS services separately enforce permissions. Full-clone defaults and existing object/signature/pack/ref bytes stay unchanged. Tier2 hidden names is shelved. “Add changes” means replace existing regular/executable file bytes; no new/delete/rename paths, mode changes, symlink edits, chunk-only editing, auto-rebase or lazy fetch.

Read applicable AGENTS/CLAUDE instructions, CONTRIBUTING.md, docs/INVARIANTS.md, SPEC-CONVENTIONS and relevant specs before editing. Evidence below refers to baseline9f7511d0; verify line drift, report contradictions rather than silently changing contracts. New paths named below are deliverables, not claims of existing APIs.

## Facts you must not rediscover

PR01 delivers private VerifiedPartialSnapshot with base Commit/Remix, all ancestor Tree triples and complete selected file representations; no grant/clock/network. Its bundle limits and selected-only coverage are authoritative for this PR.

Existing ObjectSink is store.rs:732; store_file_object at worktree.rs:887 is the shared writer. content_eq_bytes at worktree/blob.rs:469 compares validated representations. EphemeralSink at store/source.rs:88,124 needs a backing full store and globally deduplicates: do not use unchanged. Ordinary builder reads all files at worktree.rs:482.

Commit signing uses sign.rs:386/560 and Commit::new_unannotated. Wasm objects.rs:155 signs arbitrary roots already. PackWriter::new_raw_only at pack.rs:317 reuses v1 raw entries; transfer.rs:664 full closure planning is unsuitable. Tree/ChunkedBlob IDs are domain-wrapped Merkle IDs, not hash(serialized bytes). Wasm chunking.rs:54 display hashes are not chunk Blob IDs.

## Exact deliverables

1. Add partial/{overlay,collector,update}.rs plus tests and thin mkit-wasm bindings. Types FileReplacement, PreparedPartialEdit, PartialUpdate. Functions replace_files, prepare_partial_commit, export_partial_update. Do not introduce host policy or new object type.
2. FileReplacement uses exact selected path and complete bytes, or explicit reference to a verified selected representation. No bare arbitrary child-ID setter. Preserve original mode; reject new/deleted/renamed/unselected paths, duplicate edits, symlink/mode/directory replacements.
3. Copy all untouched triples exactly, including hidden file IDs, empty Trees and symlinks. Apply all modifications bottom-up by ancestor PATH OCCURRENCE so sibling edits cannot overwrite each other. Old Tree IDs may repeat at different paths: object bytes can dedup by ID, rewrite contexts cannot. Editing a/x must not alter b/x when a and b originally share the same Tree. Counting source must observe zero hidden payload/subtree reads.
4. Bounded canonical collector implements ObjectSink without global store. Use current store_file_object for new bytes. Dedup within produced output only. Export includes all changed-file dependencies even when IDs exist in selected inputs or another store. For identical validated content retain previous ID/mode and omit no-op entry. If all edits no-op, return NoChanges; this is helper behavior, not a ban on ordinary empty commits.
5. Prepare ordinary unannotated Commit, tree=prepared root, parents=[base ID], caller author/signer/message/timestamp. Existing signer supplies signature; no new domain or private-key storage. Allow author!=signer at core level. No service-time or grant check. Pass the expected unsigned Commit returned by prepare_partial_commit explicitly to export_partial_update, alongside verified base, prepared edit and signed Commit. Verify signature and equality of all prepared unsigned fields/root/parent, with annotations absent, before exporting; do not invent expected author/message/time from tree-only PreparedPartialEdit.
6. PartialUpdate bytes below. Same commonware/endian convention as PR01. Exact Tree EntryMode byte values from existing object codec; no duplicate mode mapping. Paths ordered by joined bytes, objects raw-pack order by ID. Update bounds56MiB, pack48MiB, objects65536, message4KiB, at most256 changed paths. Include code/spec/goldens together.

```text
magic[4]="MKWU"; version:u8=1
base_id:[u8;32]; candidate_id:[u8;32]
changes:Vec<{path:components, old_mode:u8, old_id:[u8;32], new_id:[u8;32]}>
pack_hash:[u8;32]; pack_length:u64; pack_bytes:Vec<u8>
```

The manifest is unsigned metadata checked against candidate/base objects. Candidate Commit signs parent/root. Pack hash uses existing pack identity contract. Reject length/hash mismatch, duplicates/extras, trailing bytes, compressed/delta entries. Export MUST send all replacement representations/chunks, deduplicated within pack. No retained-ID optimization. Unchanged opaque entries remain implicit; source reuse in overlay still exports complete destination content.
7. Export includes ordinary signed Commit, rebuilt Trees, EVERY changed file's complete representation/chunks, regardless of previous selected-base membership. Do not include hidden closure/whole base/history. Explicit output inventory deterministic and canonical. It is not a closure-profile export even though carrier is raw-only.
8. Wasm exports call same verifier/overlay/export functions, accept public data and existing signer route, retain no zstd/blst. Return typed serialized errors and coverage; do not implement a second TypeScript encoder or new key custody.
9. Extend SPEC-PARTIAL-WORKSPACES for operations, signing adapter and exact export bytes. Add golden_partial_update.rs + partial_update MANIFEST/.bin/.json, native/wasm parity vectors and bounded overlay fuzz wiring.

## Acceptance tests

- One selected file next to hidden file/subtree/symlink/empty directory yields exactly the full-data rebuilt root.
- Two sibling edits and converging nested edits both survive shared ancestor rebuild. Identical old subtree ID under a/ and b/: editing only a/x preserves b, and different edits under both paths remain independent.
- Untouched triples/modes identical; missing hidden objects never read. Added/deleted/renamed/mode-changed/unselected paths fail atomically.
- No-op alternative valid chunk representation retains original ID; all-noop returns NoChanges.
- >1MiB whole-file replacement matches existing writer, including canonical chunk IDs; malformed metadata never excused by content equality.
- Fixed-key ordinary Commit verifies with existing sign::verify_commit; base may be Remix but result is Commit. No grant/context service needed; author!=signer is valid core input.
- Export deterministically inventories exact rebuilt objects and all changed-file representations/chunks; no hidden global dedup.
- Union exported objects into a complete base test store: independently reconstruct/check the full-data root and canonical IDs, then run existing closure verifier and require is_complete(). The reusable typed receiver API arrives PR06; do not depend on future code. Raw export alone correctly lacks hidden closure.
- Native/wasm roots/export bytes agree; no stale prepared-field or signature substitution accepted.

## Reviewer focus

Object-aware hashing, untouched-entry preservation, batch ordering, output completeness relative to selected base (not global store), ordinary signature bytes, key custody, no false closure/authorization claim.

## Quality, process and review

Target one coherent PR, normally <=2,500 handwritten lines including tests/specs. If larger or a dependency is missing, stop and ask the planner to re-slice; never omit negative tests or weaken acceptance. Fresh executor can use more than one bounded session. No deployment, release, chain call or unrelated cleanup.

Wire/durable formats ship spec+code+committed goldens together. New spec front matter: spec/version/status:draft-normative/audience; register docs/specs/README.md. Existing object/disclosure/sparse/signing/pack fixtures must remain unchanged. Golden area includes MANIFEST.txt/.bin/.json; generator runs only with MKIT_WRITE_GOLDEN=1, then unset it for a consumer which reads committed files only (pattern golden_disclosure.rs). Independently construct malformed bytes, not just encode/decode agreement.

Add actual enforced invariant(s), Always/Because/If-violated/Enforced-by, and CHANGELOG Unreleased **SemVer:** additive note. Conventional Commit title below. Crypto-adjacent work requires second reviewer and a PR threat-model note.

macOS: ensure ~/tmp exists, then export TMPDIR="$HOME/tmp". Run focused tests plus cargo fmt/clippy for affected crates; core/wasm changes require cargo check --manifest-path rust/Cargo.toml -p mkit-wasm --target wasm32-unknown-unknown. Run bash scripts/check-spec-status.sh, just ci-scripts, just ci-docs; phase integrator runs just ci plus standalone app gates. Do not present tests you did not run as passing. For bug fixes, include parent-failing regression; feature tests cover contract.

If adding fuzz: rust/fuzz/fuzz_targets/<name>.rs -> mkit_fuzz::<name>_one_iteration -> Cargo registration -> .github/workflows/fuzz.yml -> docs/FUZZ.md; bounded smoke, no unbounded campaign. No zstd/blst dependency added to generic wasm.

## PR title and body

Title: `feat(core): build and export ordinary partial-edit commits`

> Adds an authenticated replacement overlay, ordinary mkit signing integration, explicit raw-object export and shared wasm bindings. Clients can create/export valid commits without the hidden closure or a hosting grant.
>
> Base: feat/scoped-workspaces. Depends on landed PR01. Do not merge.
>
> Validation: [exact tests/goldens/wasm/docs checks and results].
> Threat model: [specific adversarial cases and remaining limits].
> Compatibility: [unchanged existing formats/defaults; new opt-in behavior].
> Review: [second reviewer required where crypto-adjacent].

## Required report

Report branch/worktree, base commit, commits, files changed, APIs/formats added, exact tests run/results/unrun gates, golden changes, line count, unresolved risks, evidence of unchanged defaults and PR URL/base. State “not merged.” Do not start the next PR.
