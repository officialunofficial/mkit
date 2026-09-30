# WP-5.6a-3: restricted takedown administration (R-190)

Approved carry-forward from [PR2](WP-5.6a-2.md): implement signed, moderation-role
`GetTakedown`, `ListTakedowns`, `ReadPreserved` and `SetLegalHold` on the existing
admin framework and preservation core. All three parts are required for launch;
activation stays off until the complete catalog and launch gates are ready.

Status must disclose pending acquisition, verified preservation, discovery,
legal hold and actual completion separately, without preserved bytes. Any stays
incomplete; the exhaustive catalog remains post-launch. Admin SetLegalHold uses
PR2's hold/purge arbiter, not a second ownership or retention mechanism.

ReadPreserved keeps a bounded byte-free nonce descriptor. Each byte-reading
retry freshly checks key/role, retention/hold and ownership, audits acceptance,
and constructs a bounded verified stream. Verify each piece before release;
unchecked reads after whole-copy preflight are insufficient. Preserve ordered
exact offsets, one last only on success, empty last at size, and invalid offset
above size. Midstream failures terminate with an audited Connect error. No bytes
in caches, replay, logs or errors; no ReadPreserved exposure before this lands.

Use existing schema/signing/audit contracts and PR2 copy metadata. No new wire
version, storage primitive, cross-partition catalog or protocol. Keep §14.7
signing/publication/startup requirements and full-profile obligations. Run the
required common/full gates, default Worker conformance and independent review;
record measured evidence when run. This handoff claims no completed gates.
