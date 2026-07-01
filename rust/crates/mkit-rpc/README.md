# mkit-rpc

Versioned wire protocols for mkit cross-system speech: external signers
(`signer.proto`), the SSH transport frames (`ssh.proto`), and shared types
(`common.proto`). Schemas are defined in protobuf via `buffa`, with
length-prefixed framing.

`mkit-rpc` owns the schemas mkit uses to talk to processes outside its own
address space:

- **External signers** (`signer.proto`) — `mkit-cli` ↔ a subprocess signer
  (file, `FIDO2`, TPM, future hardware backends). See
  `docs/SPEC-EXTERNAL-SIGNER.md` and `contrib/signers/README.md`.
- **SSH transport** (`ssh.proto`) — `mkit-cli` ↔ a remote `mkit-server` over
  an `ssh(1)` child process. See `docs/SPEC-TRANSPORT.md`.

Shared vocabulary (`common.proto`) — algorithms, key forms, error codes,
protocol-version negotiation — is re-exported at the crate root for
convenience.

## Wire framing

Both protocols use the same length-prefixed framing:

```text
[u32 LE length][N bytes protobuf-encoded Frame]
```

Generated code is vendored (not built fresh from `.proto` on every build);
regenerate it with `scripts/regen-rpc-proto.sh` after editing a schema.
