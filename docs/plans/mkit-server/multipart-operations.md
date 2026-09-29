# Multipart upload operations

The Worker and native S3 backends stage ticket parts under
`<prefix/>server-uploads/<ticket-id-hex>/`. A `meta` object records the pack
identity, length and part size; part objects use `<index>-<subtree-cv-hex>`.
A completed pack lives under `packs/`, outside this staging prefix. R2
assembles by streaming the parts through a whole-pack BLAKE3-verifying put;
native S3 copies the verified, immutable part objects through a private
multipart upload. Backend ETags are never used as integrity evidence.

Configure a bucket lifecycle rule on **both R2 and S3** to delete objects
under `server-uploads/` after **8 days**. Keep it even though the kind-2
ticket-expiry handler aborts an upload session when it can: abort is best
effort, and a process can stop between ticket creation and expiry. Set the
rule on every deployment prefix that contains `server-uploads/`. Do not
expire `packs/` or `upload-markers/v1/` with this rule. The filesystem
backend keeps its startup sweep for old `server-uploads/` directories.
On S3, also configure `AbortIncompleteMultipartUpload` after **8 days**.
Completion aborts its private upload on errors and attempts an abort on
request cancellation, but process termination can interrupt that cleanup.
Until the 3.2+3.3 outcome-outbox bundle lands, kind-2 expiry writes durable
`Expired` rows but does not deliver them. Do not deploy this bundle alone.

Worker uploads require **Workers Paid** and `limits.cpu_ms` raised enough for
the measured UploadPart and full-pack completion CPU. The Free plan's small
CPU budget is insufficient for BLAKE3 verification of production-size parts.
WP-1.19 sets this in the staging deployment config and validates the budget
under deployed R2.

Local `wrangler dev` with a release-built Worker and the 17 MiB, three-part
wire case measured approximately **2.5–2.6 s of profiler busy time per 8 MiB
UploadPart**, **0.12 s for the 1 MiB tail**, and **3.36 s for completion**.
The completion rate extrapolates to about **199 s of CPU per GiB**. These are
samples from a shared local machine, not deployed R2 measurements; the
`(program)` profiler frames are included in busy time. A 1 GiB completion
fits the 300 s Workers Paid ceiling by this estimate, so the default
`MAX_PACK_BYTES` is 1 GiB. WP-1.19 re-measures on staging and sets the
deployment's CPU limit and pack cap before allowing larger packs.

If a client receives `Invalid` after two writers upload the same index at
once, it should re-upload that part and retry completion. Each valid part is
stored at its own CV key, while competing sibling cleanup can race. A bad CV
never replaces an earlier verified part.
