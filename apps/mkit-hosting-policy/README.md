# mkit hosting policy

This standalone Rust package defines MKHG v1 signed hosted workspace grants.
`encode_unsigned`, `encode_signed`, `decode`, `verify_signature`, and
`grant_id` establish intrinsic byte and signature facts. They do not query
the managed Worker registry or confer live authority. See
[SPEC-HOSTED-WORKSPACE-GRANTS](../../docs/specs/SPEC-HOSTED-WORKSPACE-GRANTS.md).

The `hosting-wasm` feature adds a separately named
`hosting_verify_grant(base64url)` export. Its JSON u64 fields are canonical
decimal strings, so large generations and times never pass through a
JavaScript Number. Build with `wasm-pack build --target nodejs --features
hosting-wasm` for local parity testing. The generated `pkg/` and `target/`
directories are ignored.

This package path-depends on portable `mkit-core` validation primitives.
Neither mkit-core nor default `mkit-wasm` depends on this package.
