# WP-5.1a-2: Section D escalation

Execution stopped before push or PR under brief Section D: the prescribed
published-membership clearance rule permits uninspected bytes on a reader
surface. No normative resolution has been selected.

## Counterexample

1. An advance consumes a valid pack P containing commit C, tree T, reachable
   benign blob G, and an extra unreferenced file blob U.
2. SPEC-SERVER §9.3(c) requires closure inclusion, not that every consumed pack
   entry is reachable. P passes object identity and closure verification.
3. The fixed inspected set is every newly reachable file object, so G is
   inspected and U is not. All configured inspectors pass G.
4. Once P has published membership, a reader's DownloadPack(P) streams the
   whole pack, including U (STC §6.2). SPEC-SERVER §9.6 preserves pack entries
   when creating extracted copies.

This bypasses the Purpose requirement that pushed content must not reach
readers until every configured inspection has cleared it. A possible resolution
is inspecting every file entry in a pack before its membership is published;
another is withholding packs with uncleared surplus entries. Both require an
orchestrator decision beyond the fixed inspected set and clearance rule.

## Other requested clarifications

- B.1 requires packs already in published membership before clearing the advance
  that adds them. The initial publication needs an expressly atomic rule for
  an advance's own additions, while reused packs from other advances must already
  be published.
- B.1's no-async published-equals-live rule conflicts with B.2's synchronous
  quarantine committing an advance as held. The proposed exception preserves a
  synchronous hold even without asynchronous inspectors.

## Partial work committed

- The first commit copies the executor brief from Purpose through Gates.
- Additive hooks fields/enums and transport async_inspection at field 18.
  AuthorizeAllow.writer_view uses field 1; Inspect additions use the prescribed
  free numbers. Field 17 remains for WP-5.1a-1.
- Five new JSON fixtures, checker mappings/count, and manifest hashes.
- buf lint, buf breaking against origin/feat/mkit-server, and the 21-fixture
  schema/JSON round-trip check passed.

Remaining: resolve escalation and ambiguities; write SPEC-SERVER §§10–11 and
§6.4/§8 corrections; STC discovery/history rows; golden_server_hooks assertions;
regenerate transport bindings; run the complete requested gates; commit, push,
and open the PR. No registry changes or section renumbering were made.
