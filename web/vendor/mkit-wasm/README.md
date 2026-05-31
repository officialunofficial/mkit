# Local mkit-wasm package shell

This package gives `web` a stable `mkit-wasm` dependency target before
generated wasm-pack output exists. `pnpm install` links this directory;
`pnpm wasm:build` then writes the ignored `pkg/` build artifacts here.

Do not commit `pkg/`. It is generated from `rust/crates/mkit-wasm`.
