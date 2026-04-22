# SSH transport security model

Status: **Informative** for mkit 0.1.0. Addresses red-team R-10 / R-11.

This document describes what mkit's SSH transport does and does NOT do,
what guarantees users can rely on, and how to harden a deployment.

---

## 1. What mkit delegates

The SSH transport shells out to the system `ssh(1)` CLI:

```
ssh [-p port] [-o StrictHostKeyChecking=…] [-o UserKnownHostsFile=…] \
    [-i identity] [user@]host mkit serve <path>
```

The stdin/stdout of that child process carry the mkit wire protocol
(SPEC-TRANSPORT §7). Nothing else. In particular, mkit does NOT:

- implement its own SSH client or server,
- perform host-key verification,
- read `~/.ssh/known_hosts` directly,
- negotiate kex, ciphers, MACs, or HostKeyAlgorithms,
- select credentials, talk to `ssh-agent`, or introspect agent state,
- pin a host-key fingerprint from `.mkit/config`,
- detect or rotate known-hosts entries without a process restart.

Everything listed above is the user's `ssh` CLI's job. **mkit's security
posture is exactly whatever that CLI is configured to enforce.**

The only protocol-level safety net mkit adds is **OP_HELLO** (SPEC-
TRANSPORT §7.4): a first-frame handshake that refuses peers with the
wrong binary name or a future `proto_version`. This prevents a silent
interop bug after the zmit → mkit rename, but it is NOT a replacement
for host-key verification.

---

## 2. Recommended defaults

For personal / development use:

```
Host *.your-forge.example
  StrictHostKeyChecking accept-new
  UpdateHostKeys yes
  HashKnownHosts yes
```

`accept-new` trusts a first-time host key and refuses thereafter if the
key rotates without a trust update. This is the same posture GitHub's
own CLI assumes for `git+ssh`.

For security-sensitive deployments (CI, automated mirroring, anything
with write credentials on a shared host):

- Pin `StrictHostKeyChecking=yes` and pre-seed the `UserKnownHostsFile`.
- Use a dedicated identity file, not `~/.ssh/id_*`.
- Disable agent forwarding (`ForwardAgent no`).

---

## 3. Per-repo pinning via `.mkit/config`

Three optional keys in `.mkit/config` override the user's SSH defaults
for mkit's SSH child process only (they do not affect other `ssh`
invocations). All default to empty, which means "inherit the user's
default":

```
ssh.strict_host_key_checking = yes
ssh.user_known_hosts_file    = /path/to/project.known_hosts
ssh.identity_file            = /path/to/id_ed25519
```

These are set via `mkit config <key> <value>`:

```
mkit config ssh.strict_host_key_checking yes
mkit config ssh.user_known_hosts_file /path/to/mkit_known_hosts
mkit config ssh.identity_file /path/to/id_ed25519
```

When set, they are passed to the child `ssh` process as:

```
ssh -o StrictHostKeyChecking=yes \
    -o UserKnownHostsFile=/path/to/mkit_known_hosts \
    -i /path/to/id_ed25519 \
    user@host mkit serve /path
```

A per-repo known-hosts file lets you scope trust to a specific remote —
if the upstream's host key rotates, only pushes from this repo are
affected, not every SSH session on your machine.

---

## 4. Known limitations (v0.1.0)

- **No native SSH.** We do not ship a libssh2-style in-process client,
  and we do not implement the SSH transport from scratch. This keeps
  the mkit binary small and compliance with the host's crypto policy
  transitive; it also means every SSH surface area (algorithm choice,
  agent behavior, quirks with specific OpenSSH versions) is out of
  mkit's control.
- **No fingerprint pinning in config.** You can point at a
  `UserKnownHostsFile`, but the file itself is the source of truth —
  mkit does not store a hash in `.mkit/config`.
- **No known-hosts auto-rotation.** If the upstream rotates its host
  key, the user's ssh will prompt or reject depending on
  `StrictHostKeyChecking`. mkit has no custom path here.
- **No timeout on initial hello (server side).** Zig 0.15.2 does not
  expose a portable per-handle read timeout; a misbehaving client that
  connects and sends nothing will block the server's `mkit serve`
  process until the SSH channel times out at the transport layer. This
  is flagged as `TODO(W5.5)` and deferred to 0.2.0.

---

## 5. Upgrade path (post-0.1.0)

Candidate 0.2.0 work (non-binding):

- A native SSH implementation (pure-Zig port or libssh binding), so
  mkit owns host-key verification and we can ship fingerprint pinning
  in `.mkit/config`.
- Server-side read deadline on the hello handshake, once Zig exposes a
  portable per-handle timeout or we drop to raw `poll(2)`.
- `mkit fingerprint` CLI for verifying and storing remote host keys.

Until then: rely on `ssh(1)` and the pinning keys above.

---

## 6. Threat model summary

| Threat                                    | mitigated by                       |
|-------------------------------------------|------------------------------------|
| MitM on first connection                  | user's `StrictHostKeyChecking`     |
| Upstream host-key rotation (silent swap)  | user's `StrictHostKeyChecking=yes` + known_hosts |
| Wrong binary on remote (legacy rename)    | OP_HELLO, §7.4 (fails loud)         |
| Future-proto mkit client ↔ 0.1 server     | OP_HELLO STATUS_UNSUPPORTED reply   |
| Slow-loris client against `mkit serve`    | **NOT mitigated in 0.1.0** (§4)    |
| Compromised identity file                 | user's key management              |
| Agent forwarding abuse                    | user's `ForwardAgent no`           |

For the `NOT mitigated` row: until the server-side read deadline lands,
run `mkit serve` under the SSH transport (which itself times out idle
channels via `ClientAliveInterval`). Do not expose it as a standalone
service on an unmanaged socket.
