# mkit-git-bridge

Deterministic mkit↔git bridge: export translation and importer-signed
import.

Every mkit v1 object maps to a git object whose bytes are a pure function of
the source bytes, with mkit-only fields carried in `mkit-*` commit/tag
headers so the original object &mdash; and its Ed25519 signature &mdash; can be
reconstructed and re-verified. Export is specified by
`docs/specs/SPEC-GIT-BRIDGE.md`; import is specified by `docs/specs/SPEC-GIT-IMPORT.md`;
see `docs/GUIDE-GIT-WORKFLOWS.md` for the end-user flow.

## Layout

- `translate` &mdash; export mapping (mkit → git), specified by SPEC-GIT-BRIDGE.
- `import` &mdash; importer-signed import (git → mkit), specified by
  SPEC-GIT-IMPORT.
- `reconstruct` &mdash; the export mapping's verification-grade inverse. It is
  **not** a general import path: it's defined only on objects `translate` can
  emit, and fails loudly on anything else.
- `map` &mdash; the blake3↔sha1 id mapping. Always a rebuildable cache: determinism
  means deleting it and re-deriving yields identical results, so it is never
  a source of truth.
- `gitobj` / `gitparse` / `gitsrc` &mdash; git object types and parsing.
- `headers` / `author` / `remoteid` / `refname` &mdash; the `mkit-*` header
  encoding and identity/ref-name mapping rules.
- `verify` &mdash; re-verification of a bridged object's signature after the round
  trip.
