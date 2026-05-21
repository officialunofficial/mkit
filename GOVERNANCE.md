# mkit governance

mkit is published by **Official Unofficial, Inc.** under MIT OR Apache-2.0.
This document describes how the project is maintained.

## Status

**Alpha / pre-1.0.** The v1 on-disk and wire formats are pinned by golden
vectors under `rust/tests/golden/`, but APIs and CLI surface may change in
any 0.x release. Production use is at your own risk.

## Maintainers

See [MAINTAINERS.md](MAINTAINERS.md) for the current list and contact information.

The active maintainer roster is also represented by GitHub teams under the
`officialunofficial` org and reflected in `.github/CODEOWNERS`.

## Decision model

Day-to-day changes use **lazy consensus**: a PR may be merged once it has
one maintainer approval, CI is green, and no other maintainer has registered
an objection within 48 business hours of review request.

Changes touching **security-sensitive code** (mkit-attest, mkit-keystore,
mkit-rpc, install.sh, .github/workflows for release & security) require
**two maintainer approvals**, with at least one from the `mkit-crypto` team
where applicable.

Changes to **on-disk or wire formats** (anything under `docs/SPEC-*.md` or
`rust/tests/golden/`) require a brief written rationale on the PR and two
maintainer approvals, plus a CHANGELOG entry describing the compatibility
impact.

Disagreements that lazy consensus cannot resolve are escalated to a
maintainer vote (simple majority; ties broken by the project lead at
Official Unofficial, Inc.).

## Releases

Release process is documented in [docs/RELEASE.md](docs/RELEASE.md) and the
per-release checklist under `docs/release/`. Release artifacts are signed
with cosign keyless OIDC; verification instructions live in
[docs/INSTALL.md](docs/INSTALL.md).

## Becoming a maintainer

New maintainers are nominated by existing maintainers after sustained
contribution (typically 3+ months of substantive review and merged work).
Nominations are decided by maintainer consensus.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for code/test/build expectations and
the inbound-license policy.

## Trademark and brand

See [TRADEMARKS.md](TRADEMARKS.md). The mkit name and marks are owned by
Official Unofficial, Inc.; the codebase is freely usable under the licenses
above, but the marks are not.
