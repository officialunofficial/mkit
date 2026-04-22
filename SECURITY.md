# Security policy

## Reporting a vulnerability

**Please do not file public GitHub issues for security vulnerabilities.**

Preferred: open a private report through GitHub Security Advisories at
<https://github.com/officialunofficial/mkit/security/advisories/new>.
This routes the report to the maintainers privately, gives us a place to
collaborate on a fix, and produces a CVE on request.

If you cannot use GitHub Security Advisories for any reason, contact the
maintainers privately by opening a draft PR titled `SECURITY: contact me
out-of-band` (no details in the body) and we will reach out.

We aim to:

- Acknowledge your report within **72 hours**.
- Provide a triage update within **7 days**.
- Ship a fix (or publish a mitigation) within **90 days** of initial
  report, coordinated with you on disclosure timing.

If you do not hear back within the acknowledgement window, please nudge
us — notifications can drop.

## Supported versions

Only the latest minor line receives security fixes.

| Version | Supported |
| ------- | --------- |
| 0.1.x   | Yes       |
| < 0.1   | No        |

Pre-1.0 releases may ship breaking format changes alongside security
fixes. Read the CHANGELOG before upgrading.

## Coordinated disclosure

- **Day 0:** You file a report via GitHub Security Advisories.
- **Day 0–7:** We triage, confirm scope, and assign a CVE if warranted.
- **Day 7–60:** We fix, test, and prepare a coordinated release. We may
  request your review of the patch.
- **Day ≤90:** Public advisory published, CHANGELOG entry, and a patched
  release. Credit given to the reporter unless you ask to remain anonymous.

We will not pursue legal action against researchers who follow this
process in good faith, including accidental disclosure during testing.

## PGP / signed reports

We don't publish a long-lived PGP key for 0.1.x. GitHub Security
Advisories provides transport-layer privacy and a private collaboration
channel, which we believe is sufficient for the current scope. If you have
a strong need for end-to-end encryption beyond TLS, mention this in the
initial advisory and we'll arrange an out-of-band channel.

## Scope

In scope:

- The `mkit` binary and everything under `src/` that ships in a release
  archive.
- Release pipeline integrity (signing, SBOM, reproducibility claims).
- On-disk format parsers (v1 format documented in `docs/SPEC-*.md`).

Out of scope (please report to upstream instead):

- Vulnerabilities in the Zig compiler / standard library.
- Vulnerabilities in operating-system libraries linked at runtime.
