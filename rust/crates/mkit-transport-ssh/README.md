# mkit-transport-ssh

SSH transport for mkit using a forced-command server pattern over a system
`ssh(1)` child process.

Implements the `Transport` trait (`docs/specs/SPEC-TRANSPORT.md`) over a long-lived
system `ssh(1)` child process, exchanging the seven mkit verbs as
length-prefixed protobuf `SshFrame` messages defined in
`mkit-rpc/proto/mkit/rpc/v1/ssh/ssh.proto`.

## Design choice: `std::process::Command`, not `russh`

mkit does not implement its own SSH client. It shells out to `ssh(1)` and
delegates host-key verification, agent handling, credential selection, and
key exchange to the user's installed `OpenSSH` — the same posture `git+ssh://`
takes:

- No crypto stack to ship (no `russh`, `rustls`, `openssl`, `native-tls`).
- `ssh-agent`, `~/.ssh/config`, `ProxyCommand`, and every other knob the user
  already configured just work, with zero mkit code.
- Host-key rotation / trust escalation stays on the `OpenSSH` side.

The `Transport` trait itself is synchronous (object-safe, `&self`), so
wrapping `Command::spawn` + blocking stdio is the shortest path to parity
with the other transports.
