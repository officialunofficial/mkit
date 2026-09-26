# SSH transport security model

Status: **Informative**. Addresses red-team R-10 / R-11.

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
interop bug after the mkit → mkit rename, but it is NOT a replacement
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

A per-repo known-hosts file lets you scope trust to a specific remote &mdash;
if the upstream's host key rotates, only pushes from this repo are
affected, not every SSH session on your machine.

---

## 4. Known limitations

- **No native SSH.** mkit does not ship a libssh2-style in-process client,
  and does not implement the SSH transport from scratch. This keeps
  the mkit binary small and compliance with the host's crypto policy
  transitive; it also means every SSH surface area (algorithm choice,
  agent behavior, quirks with specific OpenSSH versions) is out of
  mkit's control.
- **No fingerprint pinning in config.** You can point at a
  `UserKnownHostsFile`, but the file itself is the source of truth &mdash;
  mkit does not store a hash in `.mkit/config`.
- **No known-hosts auto-rotation.** If the upstream rotates its host
  key, the user's ssh will prompt or reject depending on
  `StrictHostKeyChecking`. mkit has no custom path here.
- **Idle timeout, reads only (server side).** `mkit serve` ends a
  session after `--idle-timeout-secs` seconds (default 60; `0` disables
  it) without a byte from the client: before `Hello`, between requests,
  or in the middle of an upload, whose partial pack is then discarded. It
  answers `Error{INVALID_REQUEST, "idle timeout"}` (best effort) and exits
  with status 76. Only silence counts: an upload that keeps sending never
  trips it, even when one chunk frame takes longer than the timeout to
  arrive, and time the server spends answering never counts. The write
  side has no deadline of its own: a client that stops *reading* a
  download blocks `mkit serve` until the SSH layer gives up
  (`ClientAliveInterval`/`ClientAliveCountMax`), so keep those set.

---

## 5. Push authorization (server side)

mkit core does not define a push-auth protocol. For `mkit+ssh://` the
idiomatic integration is the same one Git forges have used for a
decade:

1. User generates one Ed25519 key (`mkit keygen` &mdash; the seed doubles as
   an `id_ed25519` for OpenSSH 8.0+; see `docs/specs/SPEC-SIGNING.md` §8).
2. Server runs `sshd` with:

   ```
   AuthorizedKeysCommand /usr/local/bin/forge-resolve-pubkey
   AuthorizedKeysCommandUser nobody
   ```

   The resolver looks up the incoming pubkey in whatever account
   database the forge owns (a SQL table, a chain RPC, an LDAP
   directory) and emits a matching `authorized_keys` line, including
   a `command=` that execs `mkit serve /srv/mkit/<account>/<repo>`
   with the caller's account baked in.
3. mkit serve runs as that account and sees a repo path it can
   validate with a simple `startsWith(account_prefix)` check.

No custom handshake, no nonce opcode, no new domain separator. SSH's
KEX handshake already signs a per-session nonce with the client's
private key &mdash; that's the transport-level proof of possession. The
forge's only responsibility is the `pubkey → account` mapping plus a
shell that execs `mkit serve` with the resolved path.

`AuthorizedKeysCommand` gets the pubkey as `%k` (and the fingerprint
as `%f` / user as `%u`); see `sshd_config(5)` for the full token list.

---

## 6. Upgrade path

Candidate future work (non-binding):

- A native SSH implementation (for example, via `russh`), so mkit owns
  host-key verification and can ship fingerprint pinning in
  `.mkit/config`.
- `mkit fingerprint` CLI for verifying and storing remote host keys.

Until then: rely on `ssh(1)` and the pinning keys above.

---

## 7. Threat model summary

| Threat                                    | mitigated by                       |
|-------------------------------------------|------------------------------------|
| MitM on first connection                  | user's `StrictHostKeyChecking`     |
| Upstream host-key rotation (silent swap)  | user's `StrictHostKeyChecking=yes` plus known_hosts |
| Wrong binary on remote (legacy rename)    | OP_HELLO, §7.4 (fails loud)         |
| Future-proto mkit client ↔ older server   | OP_HELLO STATUS_UNSUPPORTED reply   |
| Slow-loris client against `mkit serve`    | `mkit serve --idle-timeout-secs` (default 60 s; §4) |
| Compromised identity file                 | user's key management              |
| Agent forwarding abuse                    | user's `ForwardAgent no`           |

For the slow-loris row: the idle timeout bounds a client that stops
sending, and the per-connection frame and byte budgets (SPEC-TRANSPORT
§4.4) bound one that keeps sending. A client that stops reading is left
to the SSH transport, which times out dead channels via
`ClientAliveInterval`. Keep `mkit serve` behind sshd as a forced command;
do not expose it as a standalone service on an unmanaged socket.
