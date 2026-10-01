# Uno launch operations handoff

Final preparation (WP-1.20 / R-195), pinned to feature checkpoint
`c3921b06effc0f38e2cdbe6f25b4e5a309018136`; not a launch candidate.

The maintained, self-contained [Workers operator guide](../../operations/workers.md)
ships to main and covers config/secrets/bindings, feature opt-ins, embedding,
empty first store, rotation, rollback, failure drills, takedown/legal holds,
WAF emergency read blocking and known limits. This planning file stays on feat
and is archived by the release rebuild.

Use [staging-uno.md](staging-uno.md) for isolated resource and measurement
geometry, [launch-readiness.md](launch-readiness.md) for pinned local evidence
and open items, and [the DRAFT REL-1 prompt](briefs/REL-1-draft.md) for the
user-owned main merge sequence. No version bump or tag at Workers launch.

| Operation / acceptance | Status / owner |
|---|---|
| Real staging resources, secrets, deployment and conformance | UNRUN / user |
| Hooks/scanner/purge outage drills and key rotation | UNRUN / user |
| CPU/calls/memory/concurrency/cost and multicolo acceptance | UNRUN / user |
| Final candidate/full-delta review and staging sign-off | UNRUN / user |
| Main merge / separate production deployment authorization | UNRUN / user |

Local Uno push/clone/takedown/Outcome evidence does not fill these slots.
FIX-preservation-memory (#1263) bounds scheduled Rust acquisition to 48 MiB;
whole-isolate staging measurement remains required before candidate/main.
many_refs remains unclassified. No operation here
has been executed; no scope or resource waiver is granted.
