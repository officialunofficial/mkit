# Running `mkit-server` in a container

Every release from 0.5.0 on publishes `mkit-server` as a container image. This
page covers pulling it, running it, storage and secrets, health checks, and
what to put in front of it. The server itself (flags, authentication,
storage backends, limits) is documented in the operator guide,
[`rust/crates/mkit-server-native/README.md`](../rust/crates/mkit-server-native/README.md).

## The image

| | |
| --- | --- |
| Name | `ghcr.io/officialunofficial/mkit-server` |
| Tags | `X.Y.Z`, and `X.Y`, which follows the newest final `X.Y.*` release. There is **no `latest` tag**. Tags are applied only after the digest is signed. |
| Visibility | Public: pull without logging in |
| Platforms | `linux/amd64`, `linux/arm64` |
| Base | `gcr.io/distroless/cc-debian13:nonroot`, pinned by digest: a few Debian 13 libraries (glibc 2.41, `libgcc_s`, …) and CA certificates, no shell, no package manager |
| Binary | `/usr/local/bin/mkit-server`, exactly the binary of the signed `mkit-server-X.Y.Z-<target>.tar.gz` release archive. It is not recompiled. |
| User | `65532:65532` (distroless `nonroot`) |
| Entrypoint | `["/usr/local/bin/mkit-server", "serve"]`, default arguments `["--help"]` |
| Ports | `8080` (HTTP/Connect), `9418` (`mkit+enc://`). Only documentation: a listener runs only when you pass its flag. |

Arguments after the image name are `mkit-server serve` flags. Run other
subcommands through the entrypoint:

```sh
docker run --rm --entrypoint /usr/local/bin/mkit-server "$IMAGE" version
```

## Verify, then pull by digest

The release notes give the image digest. Verify the digest (cosign
signature, SLSA provenance, SBOM attestation) as
[`docs/RELEASE.md`](RELEASE.md#verify-the-container-image) shows, pinning
the signer identity to the exact release tag, and then deploy that digest,
not a tag:

```sh
VERSION=X.Y.Z
IMAGE=ghcr.io/officialunofficial/mkit-server@sha256:...   # from the release notes
cosign verify "$IMAGE" \
  --certificate-identity "https://github.com/officialunofficial/mkit/.github/workflows/release.yml@refs/tags/v${VERSION}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

## Quick start

```sh
# Data: the served root (a directory holding `.mkit`) and the SQLite file,
# writable by uid 65532. `mkit init` creates `.mkit`; an empty `.mkit`
# directory is all the server checks for.
sudo mkdir -p /srv/mkit/data/root/.mkit
sudo chown -R 65532:65532 /srv/mkit/data

# The bearer token, outside the data volume: a regular file owned by
# 65532, mode 600, mounted read-only on its own.
sudo mkdir -p /etc/mkit-server
sudo install -o 65532 -g 65532 -m 600 /dev/null /etc/mkit-server/token
openssl rand -hex 32 | sudo tee /etc/mkit-server/token > /dev/null

docker run -d --name mkit-server \
  --read-only --tmpfs /tmp \
  --cap-drop ALL --security-opt no-new-privileges \
  --stop-timeout 40 \
  -p 127.0.0.1:8080:8080 \
  -v /srv/mkit/data:/data \
  -v /etc/mkit-server/token:/run/secrets/mkit-token:ro \
  "$IMAGE" \
  --listen 0.0.0.0:8080 \
  --repo-root /data/root \
  --meta sqlite:/data/meta.sqlite \
  --bearer-token-file /run/secrets/mkit-token \
  --log-format json
```

- **Listen on `0.0.0.0` inside the container.** A listener bound to
  `127.0.0.1` inside it cannot be reached through a published port. Limit
  exposure on the host side instead (`-p 127.0.0.1:…`), and put a reverse
  proxy in front (see [In front of the server](#in-front-of-the-server)).
- **`--read-only` needs `--tmpfs /tmp`** (in Kubernetes,
  `readOnlyRootFilesystem` needs an `emptyDir` at `/tmp`). The
  `mkit+enc://` listener's network runtime takes a directory under the
  temp directory at startup, and without a writable `/tmp` the server exits
  with a panic; `SQLite` may also put temporary files there.
- **Shutdown.** `docker stop` sends `SIGTERM`, and the server lets
  in-flight requests finish for up to `--shutdown-grace-secs` (default 30).
  Docker's default stop timeout is 10 s, so raise it (`--stop-timeout`, or
  `terminationGracePeriodSeconds` in Kubernetes) above the grace. The
  server is PID 1 and starts no child processes, so no init process is
  needed.
- **Logs** go to stderr. Use `--log-format json` in containers; the text
  format colors its output.
- **Exit codes** are `mkit`'s sysexits values (operator guide, "Shutdown
  and exit codes"). A refused configuration exits 78: a restart policy
  just restarts into the same error, so read the log.

## Storage and permissions

The container runs as uid and gid 65532. Everything it writes must be
writable by that user:

- `--repo-root`: the served root. It holds `.mkit` (with the server's locks
  and root marker), `packs/` (filesystem blobs), `refs/` (`--meta
  fs-layout`), and, with S3 blobs, the upload spool under
  `.mkit/server-spool`.
- `--meta sqlite:<PATH>`: the database and its `-wal` and `-shm` files. Keep
  it on local disk, not a network filesystem.
- `--enc-server-key <PATH>`: created on the first start (see below).

On Linux, `chown -R 65532:65532` the host directories (or the volume) before
the first start. A new named volume mounted where the image has no directory
is root-owned, so prepare it once with a throwaway container that runs as
root.

**One server process per root.** The server holds `.mkit/server.lock` for
its whole lifetime, and a second one on the same root refuses to start
(exit 78). Run one replica per volume. In Kubernetes use `replicas: 1` with
the `Recreate` strategy, so a rollout does not start the new pod while the
old one still holds the lock.

## Secrets

The server reads each secret file once, without following a symlink
(`O_NOFOLLOW`), and checks the open file:

| Secret | Flag | File rule | Environment alternative |
| --- | --- | --- | --- |
| Bearer token | `--bearer-token-file` | regular file, no group or other bits (`600`/`400`), readable by 65532 | `MKIT_API_TOKEN` |
| S3 credentials | `--s3-credentials-file` | same as the token | `MKIT_R2_ACCESS_KEY_ID` + `MKIT_R2_SECRET_ACCESS_KEY` (or `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY`) |
| Enc server key | `--enc-server-key` | regular file owned by 65532, `600`, in a directory with no group or other bits, and no symlink anywhere on its path; created (`0600`, directories `0700`) on first start | none |
| Enc peer allowlist | `--enc-authorized-peers` | regular file owned by 65532 or root, not writable by group or others | none |

Never pass a secret on the command line; the server has no flag for one.

- **Docker bind mounts and Compose file secrets** keep the host file's
  owner and mode, so `chown 65532` and `chmod 600` the file on the host, as
  in the quick start.
- **Kubernetes Secret and ConfigMap volumes are symlinks.** Each key is a
  symlink into a `..data/` directory, which the server refuses. Pass the
  token and the S3 credentials as environment variables instead
  (`env[].valueFrom.secretKeyRef`). The value is then in the container's
  environment, readable by anyone who can exec into the pod, so restrict
  `pods/exec`.
- **The enc server key** has no environment alternative. Keep it on the
  persistent volume and let the server create it on the first start
  (`--enc-server-key /data/keys/enc/server.key`): it must survive
  restarts, since clients pin its public half. With a Kubernetes `fsGroup`,
  set `fsGroupChangePolicy: OnRootMismatch`. The default policy re-applies
  group permissions to every file at each mount, which gives the key group
  bits, and the server then refuses to start.
- **The enc allowlist** can come from a ConfigMap mounted with `subPath`,
  which mounts the file itself rather than a symlink (root-owned, `0644`).
  Changes then need a pod restart, which the server needs anyway: it reads
  the allowlist once, at startup.

## Health checks

The image has no `HEALTHCHECK`: it has no shell or HTTP client, and the
binary has no probe subcommand. Probe from outside instead.
`grpc.health.v1.Health/Check` on the HTTP port answers without
authentication (each store's probe is cached for one second), over gRPC
(h2c), Connect and JSON:

- **Kubernetes:** a native gRPC probe for **readiness only**. Health
  reports the stores' state, so it turns `NOT_SERVING` when a store (the
  S3 bucket, the disk) is unavailable. That should take the pod out of
  service, not restart it: a liveness probe on it would restart-loop the
  pod through every storage outage. Use a TCP check for liveness (see
  [Kubernetes](#kubernetes)).

- **Docker, a load balancer, or a monitor:**

  ```sh
  curl -fsS -X POST -H 'Content-Type: application/json' -d '{}' \
    http://127.0.0.1:8080/grpc.health.v1.Health/Check
  # {"status":"SERVING"}
  ```

- An enc-only deployment has no health endpoint; use a TCP check on its
  port.

## Kubernetes

A fragment of a single-replica Deployment serving HTTP with SQLite
metadata. It is not a complete manifest: add the volume claim, a Service
and the reverse proxy in front.

```yaml
spec:
  replicas: 1                    # one server process per root
  strategy:
    type: Recreate               # the old pod releases the root's lock first
  template:
    spec:
      terminationGracePeriodSeconds: 45   # above --shutdown-grace-secs
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        runAsGroup: 65532
        fsGroup: 65532
        fsGroupChangePolicy: OnRootMismatch
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: mkit-server
          image: ghcr.io/officialunofficial/mkit-server@sha256:...   # verified digest
          args:
            - --listen=0.0.0.0:8080
            - --repo-root=/data/root
            - --meta=sqlite:/data/meta.sqlite
            - --log-format=json
          env:
            - name: MKIT_API_TOKEN           # Secret volumes are symlinks
              valueFrom:
                secretKeyRef:
                  name: mkit-server
                  key: api-token
          ports:
            - name: http
              containerPort: 8080
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
          readinessProbe:
            grpc:
              port: 8080
          livenessProbe:
            tcpSocket:
              port: 8080
          volumeMounts:
            - name: data
              mountPath: /data
            - name: tmp
              mountPath: /tmp
      volumes:
        - name: data
          persistentVolumeClaim:
            claimName: mkit-server-data
        - name: tmp
          emptyDir: {}
```

The served root needs its `.mkit` directory before the first start. The
image has no shell, so create it with `mkdir -p /data/root/.mkit` from an
init container using a small image with one (busybox, say), running as
65532.

## In front of the server

- **HTTP:** a buffering reverse proxy that terminates TLS and enforces
  connection limits, header and slow-body timeouts, and a request size
  limit (operator guide, "Deployment"). The server speaks plaintext
  HTTP/1.1 and h2c only. Pass the public origin through unchanged:
  auth v2 signatures name it (`--audience`).
- **`mkit+enc://`:** put the enc port behind a per-IP connection limit
  (a firewall rule, or an L4 proxy such as HAProxy or nginx `stream` with
  per-source limits), or expose it only on a private network. The server
  bounds concurrent handshakes (`--enc-max-handshakes`) and sessions, but
  not per source: a client that reconnects continuously still competes
  for the kernel's accept backlog and the handshake slots, and only a
  per-IP limit in front removes that.

> **Warning (M0): auth v2 authenticates, it does not authorize.** With the
> default hooks, `--auth auth-v2` lets ANY key holder write ANY ref: a
> signature proves who signed, not that the signer may write, and the
> per-signer quota can be bypassed by minting new keys. Real authorization
> arrives in M2 (write grants). Until then, run auth v2 only on a trusted
> network or behind an authorizer (operator guide, "Authentication"). An
> enc peer on the allowlist may likewise write any ref.

`--unsafe-allow-any-peer` and `--unsafe-allow-any-enc-peer` are for local
development only.
