# mkit-rpc

Versioned wire protocols for mkit cross-system speech: external signers
(`signer.proto`), the SSH transport frames (`ssh.proto`), the object-
signature verification contract (`verify.proto`), and shared types
(`common.proto`). Schemas are defined in protobuf via `buffa`, with
length-prefixed framing.

`mkit-rpc` owns the schemas mkit uses to talk to processes outside its own
address space:

- **External signers** (`signer.proto`) — `mkit-cli` ↔ a subprocess signer
  (file, `FIDO2`, TPM, future hardware backends). See
  `docs/specs/SPEC-EXTERNAL-SIGNER.md` and `contrib/signers/README.md`.
- **SSH transport** (`ssh.proto`) — `mkit-cli` ↔ a remote `mkit-server` over
  an `ssh(1)` child process. See `docs/specs/SPEC-TRANSPORT.md`.
- **Signature verification** (`verify.proto`) — the `VerifyRequest`/
  `VerifyResponse` contract `mkit clone`/`pull`/`fetch` check every
  newly-fetched commit/remix/tag against (issue #692). Message-only today
  (no bound RPC method): `mkit-cli`'s local dispatch
  (`rust/crates/mkit-cli/src/remote_dispatch/packmap.rs`) calls the Rust
  implementation directly (`mkit_core::sign::{verify_commit,verify_remix,verify_tag}`);
  the schema is published so a future ConnectRPC-based transport
  (`apps/repo-worker`) can bind the identical check to a service method
  instead of reimplementing it.

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
