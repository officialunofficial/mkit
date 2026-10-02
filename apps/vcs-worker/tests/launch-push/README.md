# Native push to the launch Worker

`scripts/vcs-worker-launch-push-runtime.sh` runs the native CLI's default zstd
pack writer against an optimized `worker-build --release --features launch`
Worker, then clones the published repository with the same native CLI. The
Worker uses Paid Workers, indexed D34 addressing, Any namespaces with explicit
`UNSAFE_OPEN_NAMESPACES`, permanent retention, and five Durable Object classes.
HTTP objects, inspection, hooks, admin, and takedown are left off.

Run from a clean committed Worker candidate and a clean independently pinned
CLI worktree containing the native CA-file support:

```sh
TMPDIR="$HOME/.cache/mkit-test-tmp/wp-4-18/launch-push" \
VCS_CONFORMANCE_PORT=8789 \
scripts/vcs-worker-launch-push-runtime.sh \
  --sha <exact-worker-SHA> \
  --cli-worktree /absolute/path/to/cli-ca-file \
  --cli-sha <exact-cli-SHA>
```

The runner builds both pins, records source/tree/config/artifact/log hashes,
and starts only Wrangler 4.134.0's local runtime. It generates a scratch-only
CA and localhost certificate with OpenSSL, enables Wrangler's HTTPS listener,
and supplies `MKIT_SSL_CA_FILE` to isolated native CLI child processes. TLS
certificate and hostname verification remain enabled. A standard-trust HTTPS
probe must reject the fixture CA. Nothing calls a cloud API or deploys.

The source repository uses a fixed raw 32-byte Ed25519 seed at the normal key
path with mode 0600. This matches `save_key`'s file format. Isolated user config
selects that existing key for source and clone because a fresh destination has
no signing key yet. The source key stays inside the isolated CLI home. Local remote config
is written directly, matching the native grant fixture's loopback setup;
request signatures and transport trust checks still run. Seventy distinct
512 KiB incompressible files keep the source pack above 33 MiB; six distinct
512 KiB compressible files exercise default zstd encoding. Native push must
report pending server verification and terminal completion. Native clone
must reproduce the exact signed commit, file set, sizes, and SHA-256 hashes.

After the owned Wrangler process group stops, the runner reads only local
Miniflare R2 metadata and backing blobs. It handles direct and multipart
source packs, parses canonical pack entry boundaries, and requires real zstd
frame magic in v2 compressed entries. Auxiliary packlist nodes share the same
keyspace and are recorded separately; native clone verifies their chain.
Inspection is bounded to eight source objects, 64 MiB per pack, nine parts per
pack, 4,096 entries, and 4 KiB per initial packlist node. Missing artifacts,
changed pins, skipped verification, malformed packs, or mismatched clone
contents fail the component. Failed runs retain evidence and logs in private
scratch; no private key or PEM contents are copied into evidence.

This is an initial push/clone component, not the complete integrated matrix.
It does not exercise deltas, overlapping writes, crash/restart recovery,
inspection, takedown, or HTTP read settlement. Command wall time is recorded;
Worker zstd CPU, resident memory, and physical-call bounds require separate
budget instrumentation. No deployed platform resource claim is made.
