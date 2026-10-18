# Exporting acceptance evidence

The sealed verifier supplies `PackCounts::delta_entries`; export reads it rather
than deriving or accepting a caller count. A sealed-artifact integration test
drives `VerifyDriver` and `ClosureWalker` over a written pack, exports evidence,
and checks decode, binding, and head reverification.

Evidence format 1 remains unchanged. `AcceptanceEvidence::from_verified` borrows
a `VerifiedPack` and `ClosureProof`; it neither constructs them nor gives them a
wire representation. The verifier-side export performs work proportional to the
witness chain. The writer receives only bounded heads and distinct supplier IDs.

Supply canonical signed commit, remix, or tag bytes in the original closure
request order, preserving duplicate occurrences. Export decodes each object,
recomputes its canonical identity, derives kind and signer, and verifies its
individual signature through the same code as `recheck_heads`. It uses closure's
own sequence-root function and requires equality with `ClosureProof::heads_root`.
Only then does it sort and deduplicate records for the envelope. Every recorded
signature result is `Valid`.

Supply witness page bytes starting at `ClosureProof::relied_on_members`, following
each authenticated `previous` link. An iterator can yield owned page buffers and
release each after decoding. `closure::output::decode_witness` authenticates every
page. The exact page count must match `external_witnesses().count`, with neither
a remaining link nor an extra supplied page. Distinct supplier pack IDs are
collected under `max_external_dependencies` and sorted before encoding. A cap is
an execution limit: exhaustion returns `ResourceLimit`, never a truncated set.

Export checks equality of pack and closure object-set roots and ruleset/profile
bindings. The closure repository must equal the operation's repository. Pack ID,
exact length, entry count, delta-entry count, and object-set root originate in the
sealed verifier artifact. Host membership and denial versions and the configured
profile/limits digest remain observations; export does not derive authority from
them. Hosts still authenticate delivery, compare the frozen operation binding,
run local decisions, and atomically enforce live guards.

The build configuration bounds head occurrences (including duplicates), cumulative
head bytes, witness pages, cumulative witness bytes, each page, distinct suppliers,
and output. Head processing retains a borrowed table bounded by occurrence count;
nested canonical decoding uses per-head caps and core's existing parent/source
ceilings. Witness processing retains one page's decoded fixed-size fact and an
O(supplier-cap) fallibly allocated set. Sorting retains another bounded supplier
array. Encoding and strict decode temporarily hold two envelope-sized buffers.
The host budgets its input acquisitions and iterator-owned storage separately.

The exporter checks the original requested head sequence before canonicalizing the
envelope. A caller cannot replace that sequence with its sorted version unless
the closure was run with that exact sorted sequence. Missing, extra, reordered,
or tampered witness pages return `InvalidResponse`; artifact/head-root substitution
returns a binding refusal. Bad canonical objects or signatures retain their
existing object/signature refusal codes.
