<!--
  Thanks for the PR. The checklist below mirrors CONTRIBUTING.md and
  is enforced (or about to be) in CI. Filling it in honestly speeds
  up review.
-->

## Summary

<!-- One or two sentences. What does this change do, and why? -->

## Test plan

<!-- How did you verify this? Commands, fixtures, manual repro. -->

- [ ]
- [ ]

## Checklist

- [ ] `cargo fmt --check` clean
- [ ] `cargo clippy --all-targets -- -D warnings` clean
- [ ] `cargo test --workspace` passes
- [ ] `scripts/verify-rename.sh` passes
- [ ] CHANGELOG entry under `## [Unreleased]` if user-visible
- [ ] Spec (`docs/SPEC-*.md`) and golden vectors updated if an
      on-disk or wire format changed
- [ ] Crypto / key-handling change reviewed by a second maintainer

For security-sensitive changes, also link the
[`docs/THREAT-MODEL.md`](../docs/THREAT-MODEL.md) sections affected
and note any new attacker-model entries or assumptions.
