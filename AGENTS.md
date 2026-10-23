# AGENTS.md

kit is a content-addressed, signed version-control system. Correctness and security come before features. Keep the tree small.

## Security

- Treat all input as hostile: object bytes, packs, refs, paths, remote responses, config, environment.
- Parse strictly and bound every allocation, depth and loop by a validated limit.
- No `unsafe` unless unavoidable. Every `unsafe` block carries a `SAFETY:` comment stating the invariant.
- Never log, print or commit secrets, key material or tokens. Zeroize key bytes after use.
- Verify before trusting: check signatures, hashes and attestations before acting on the data.
- Use constant-time comparison for secrets and MACs. Never implement your own crypto primitives.
- Every signed or hashed preimage has a unique domain-separation tag. Changing a tag, magic or encoded byte is a format change: update the spec and golden vectors in the same change.
- Add a dependency only when writing it ourselves is clearly worse. It must be actively maintained, permissively licensed, and pass `cargo deny`.

## Minimal and clean

- Do the smallest change that solves the problem. No speculative features, options or abstractions.
- Delete dead code instead of commenting it out or gating it.
- Do not vendor third-party code. Depend on published crates at pinned versions.
- Do not check in generated output unless a build requirement forces it. If you do, a script must verify it is fresh.
- Comments explain why, not what. No TODO without a linked failing test or spec section.
- Names, comments, docs, commit messages and issues describe the code, not the process. Do not mention phases, stages, parts, work packages, ticket or PR numbers, tracker names, tools, models or authors-of-the-change. State what changed and why.
- Docs live in `docs/`. Normative formats live in `docs/specs/` and are the source of truth over code.

## Workflow

- Before finishing, run and pass: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`, `cargo deny check`.
- New behavior needs a test. A bug fix needs a test that fails without the fix.
- Format and wire changes need an updated spec and regenerated golden vectors, with the diff reviewed.
- Do not edit lockfiles, toolchain pins or CI by hand beyond what the change requires.

## Commits

- One logical change per commit. Imperative subject, 72 characters or fewer, no trailing period.
- The body explains why, not how. Wrap at 72.
- No issue, PR or tracker references. No phase, stage or step labels. No tool or model attribution.
- Commits are signed.
