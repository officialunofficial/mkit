# Isolated Workers staging

The [template](wrangler.staging.jsonc.template) is inert and incomplete: it
provides routes, classes, bindings, backup defaults and a provisional
`limits.cpu_ms=60000`, but does not select the launch profile or install secrets.
Use the self-contained [Workers operator guide](../../../docs/operations/workers.md)
for the complete configuration and user-run deployment procedure.

Staging runs before launch acceptance. It uses a Paid account, a distinct Worker
identity and DO namespaces, exact HTTPS audience and private staging buckets.
Copy the template to `apps/vcs-worker/wrangler.staging.jsonc`, replace all
placeholders and repeat every environment var/binding; they do not inherit.
Set its build command to the approved release feature selection. Add
`LAUNCH_PROFILE=paid-workers`, `INDEXED_MODE=true`, Multi/D34, permanent retention,
leases/GC off and ticket keys. The allowlist variant needs a nonempty canonical
namespace list; `any` additionally needs `UNSAFE_OPEN_NAMESPACES=true` and
acceptance of incomplete takedown discovery. For `any`, remove the template's
`NAMESPACE_ALLOWLIST` setting entirely; setting it even blank is refused.

Provision only user-approved isolated resources, start on an empty store, and
configure selected HTTP/token, hook/scanner or admin/preservation/purge roles
completely. The snapshot bucket binding alone does not activate snapshots;
programmatic fetch and all DO constructors must use the same configuration.
No deployment, secret installation or workflow is triggered by these files.

All actual staging conformance, failure drills, CPU/memory/call/cost/multicolo
measurements and operator sign-offs remain UNRUN and user-owned. Local workerd
is not real staging. A version bump or release tag is not part of the Workers
launch. Preserve retention and legal holds when resetting/recovering; unsupported
pre-launch persisted formats must be reset, not migrated.
