# mkit-transport-enc

Encrypted-stream transport for mkit, layering `mkit-rpc`'s `SshFrame` on top
of `commonware-stream::encrypted` (`ChaCha20-Poly1305`, `X25519` and `Ed25519`
handshake). Full picture in `docs/specs/SPEC-TRANSPORT-ENC.md`.

Implements the `Transport` trait by carrying the existing mkit-rpc
`SshFrame` message set over an authenticated, encrypted byte stream. The
crate ships the full client and server stack: in-process round-trips, a real
TCP dial helper (`tcp::connect_tcp`), a TCP listener with peer-authorization
policy (`tcp::serve_tcp_with_policy_and_bounds`), and `mkit+enc://` URL
parsing (`url::parse_enc_url`). It's consumed in production by `mkit-cli`'s
remote dispatch and `mkit serve --listen-enc`.

## Layering

```text
┌──────────────────────────────────────────────┐
│ mkit-rpc::SshFrame  (verb-level protobuf)    │  app payload
├──────────────────────────────────────────────┤
│ length-prefixed framing (4-byte LE u32)      │  same as ssh transport
├──────────────────────────────────────────────┤
│ commonware-stream::encrypted                 │  ChaCha20-Poly1305
│   X25519 ephemeral DH + ed25519 static auth  │  + handshake transcript
├──────────────────────────────────────────────┤
│ commonware-runtime Sink / Stream             │  any byte transport
└──────────────────────────────────────────────┘
```

The encrypted layer guarantees mutual authentication (the client knows the
server's static `Ed25519` public key out-of-band; the server decides whether
to accept the client's key), forward secrecy via ephemeral `X25519`, and
per-direction nonce-derived `AEAD` keys. It reuses the same length-prefixed
`SshFrame` wire as `mkit-transport-ssh`, keeping one source of truth for verb
framing across the encrypted and SSH-tunneled paths. This is the
no-`OpenSSH` encrypted transport (`mkit+enc://`) &mdash; see the top-level README's
transport table for how it fits alongside `ssh`/`http`/`s3`.
