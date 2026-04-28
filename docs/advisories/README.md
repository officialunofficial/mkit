# Security advisories

Markdown drafts of GitHub Security Advisories for `mkit`. Each file
mirrors what should appear at
<https://github.com/officialunofficial/mkit/security/advisories>;
the drafts live here so the wording is reviewable in the same PR
that ships the fix.

| ID | Severity | Title |
|---|---|---|
| [GHSA-001](GHSA-001-per-repo-config.md) | Critical | Per-repo `.mkit/config` allows attacker-controlled signing, signer selection, and SSH transport policy |
| [GHSA-002](GHSA-002-trust-roots-scope.md) | High | `mkit verify-attest` defaults to in-repo trust-roots, accepting attacker-shipped keys |
| [GHSA-003](GHSA-003-key-file-handling.md) | Medium | `mkit-core` key-file load follows symlinks; save is not crash-atomic |

All three are fixed in `0.3.0` (PR #91). Public disclosure is
coordinated with the release: file as drafts, publish on or shortly
after the `v0.3.0` tag.
