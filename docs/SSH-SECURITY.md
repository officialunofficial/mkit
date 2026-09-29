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
- **Idle timeout: client silence only (server side).** `mkit serve`
  ends a session after `--idle-timeout-secs` seconds (default 60; `0`
  disables it) without a byte from the client: before `Hello`, between
  requests, or in the middle of an upload, whose partial pack is then
  discarded. It answers `Error{INVALID_REQUEST, "idle timeout"}` (best
  effort) and exits with status 76. Only silence counts: an upload that
  keeps sending never trips it, and time the server spends answering never
  counts.
- **What the idle timeout does not bound.** A client that trickles a few
  bytes at a time, or one that stops *reading* a download while its ssh
  still answers keepalives, is not idle. `ClientAliveInterval` does not
  help either, since the client's ssh is alive. Such a session is bounded
  only by the per-connection frame and byte budgets (SPEC-TRANSPORT §4.4),
  by sshd's `MaxSessions` and `MaxStartups`, and, if the operator sets
  one, by `mkit serve --max-session-secs <secs>` (default `0`, off): a
  hard cap on the process's lifetime, whatever the client does, exit 76.
  Set it above the longest legitimate clone or push.
- **No payments over ssh or enc.** A `mkit-server` deployment whose
  admission asks for a payment (or a reservation, which only a ticketed
  upload can settle) cannot take that write over an ssh or `mkit+enc://`
  session: these transports carry no payment credential. The write is
  refused with `Error{INVALID_REQUEST, "payment required: use
  mkit+https"}` and empty `details`, so a client reports a non-retryable
  remote error, never a ref conflict. Push over `mkit+https://` instead;
  reads are unaffected.

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

### 5.1 Root mode and `--principal`

A forge that serves many repositories under one filesystem root uses
`mkit serve --root <dir>`: the client still runs `mkit serve <path>`,
which sshd hands the process in `SSH_ORIGINAL_COMMAND`, and the path
names a `<NAMESPACE>/<NAME>` resolved under the root (SPEC-TRANSPORT
§4.1). The repository's owner is then whoever the namespace's
`ed25519-` key is — and the session's claim to that key is
`--principal`:

```
command="mkit serve --root /srv/mkit --principal <hex>",restrict ssh-ed25519 AAAA…
```

`--principal` is a **trust assertion made by the sshd
configuration**, the public-key half of the credential sshd has
already verified for this session (a raw 32-byte Ed25519 key as 64
lowercase hex). The rules:

- Only `authorized_keys` `command=`, a `ForceCommand`, or
  `AuthorizedKeysCommand` output may set it. The serving account MUST
  have no login shell — a shell (or any other way to run the binary)
  would let a caller invoke `mkit serve --principal <anyone's key>`
  and assert a principal it does not own.
- It MUST NOT come from the environment. Never reach for it via
  `AcceptEnv`, `PermitUserEnvironment`, or `SendEnv`: a variable the
  client supplies is an assertion the client makes about itself.
  `mkit serve` reads it from its argv alone.
- The client cannot name it through `SSH_ORIGINAL_COMMAND`: the
  server accepts only the exact `mkit serve <path>` form from that
  variable, so a forced command controls the flags entirely.
- Root-mode resolution checks the canonical path once at startup and
  later opens use the path; this is safe only because the root is not
  writable by ssh clients, and operators must keep it so.

For `AuthorizedKeysCommand`, the asserted key is the one sshd just
authenticated — `%k`, the base64 SSH wire blob whose tail is the raw
32-byte Ed25519 key (`len | "ssh-ed25519" | len | 32-byte key` after
decoding). The resolver hexes that tail into `--principal` and echoes
the key itself:

```sh
#!/bin/sh
# forge-resolve-pubkey — AuthorizedKeysCommand /usr/local/bin/forge-resolve-pubkey %t %k
# $1 = %t (key type), $2 = %k (base64 key blob)
[ "$1" = ssh-ed25519 ] || exit 1
hex=$(printf %s "$2" | base64 -d | tail -c 32 | od -An -tx1 | tr -d ' \n')
printf 'command="mkit serve --root /srv/mkit --principal %s",restrict %s %s\n' \
    "$hex" "$1" "$2"
```

The emitted line MUST assert the same key it carries: `--principal`
is the raw 32-byte key inside the `ssh-ed25519` blob that follows it.
Operators who need pubkey→account indirection resolve `%k` against
their account database first (as in step 3 above) and emit the
account's key, not the caller's.

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
| Silent client holding `mkit serve`        | `--idle-timeout-secs` (default 60 s; §4) |
| Trickling or non-reading client           | budgets (SPEC-TRANSPORT §4.4), sshd `MaxSessions`/`MaxStartups`, optional `--max-session-secs` (§4) |
| Compromised identity file                 | user's key management              |
| Agent forwarding abuse                    | user's `ForwardAgent no`           |

For the last two rows: the idle timeout bounds only a client that goes
silent. A client that keeps a session busy slowly, or stops reading, is
bounded by the budgets, by sshd's limits on sessions per connection and
on unauthenticated connections, and by `--max-session-secs` when the
operator sets it; it is off by default. Keep `mkit serve` behind sshd as
a forced command; do not expose it as a standalone service on an
unmanaged socket.
