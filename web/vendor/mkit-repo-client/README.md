# Local mkit-repo-client package shell

This package gives `web` a stable `mkit-repo-client` dependency target before
generated wasm-pack output exists. It is a Bun workspace member, so
`bun install` symlinks it into `node_modules/mkit-repo-client`;
`bun run wasm:build:repo-client` then writes the ignored `pkg/` build artifacts
here.

Do not commit `pkg/`. It is generated from `rust/crates/mkit-repo-client`.

See `rust/crates/mkit-repo-client/README.md` for the envelope-signing contract.
