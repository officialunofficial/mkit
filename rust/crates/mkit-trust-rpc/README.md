# mkit-trust-rpc

Buf-lint/breaking-gated proto schema for the `mkit.trust.v1.TrustRegistryService`
contract: `Add` / `List` / `Remove` / `Verify` over `TrustRootEntry`
(`keyid`, `kind`, `pubkey`).

This is the same allowed-signers registry `mkit trust add/list/remove`
and `mkit verify --trusted` operate on today
(`rust/crates/mkit-cli/src/commands/trust_roots.rs`), expressed as a
schema-checked wire contract instead of an ad hoc TOML-only format &mdash;
see issue #693 and epic #676 (buf/ConnectRPC convergence).

## Status

**Schema only, in this PR.** `proto/mkit/trust/v1/trust.proto` is real,
`buf lint`/`buf breaking`-clean, and gated in CI
(`.github/workflows/proto.yml`) &mdash; but this crate does not yet run
generated ConnectRPC client/server code against it. The CLI reads and
writes the TOML file directly. Wiring actual `connectrpc-build`
codegen (mirroring `apps/repo-worker`'s `build.rs`/`generated/`
pattern) and a `TrustRegistryService` implementation backed by the same
TOML store is tracked as follow-up work under epic #676, at which point
the CLI's `trust.rs` and `verify.rs --trusted` become thin callers of
that implementation &mdash; and a future hosted trust-distribution endpoint
can serve the identical contract over HTTP.

## Why a schema now, without codegen

The value delivered now: the wire shape is buf-lint-clean, breaking
changes to it are caught in CI before merge, and `mkit trust`/`mkit
verify --trusted` are built against the SAME field semantics
(`keyid`/`kind`/`pubkey`) this proto defines, so wiring real codegen
later is a mechanical, non-breaking follow-up rather than a redesign.
