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

| Version | Supported                            |
| ------- | ------------------------------------ |
| 0.3.x   | Yes (current)                        |
| < 0.3   | No                                   |

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

## Local attack surface — initial posture

The initial release narrows the local attack surface around keys and
config. Briefly:

- **Per-repo config attack surface partitioned.** Security-sensitive
  keys (key paths, external-signer path/argv, SSH trust knobs) are
  now user-scoped only. A `<repo>/.mkit/config` that tries to set
  them is rejected with a warning and the value is ignored.
- **Key file handling.** Key files are opened with `O_NOFOLLOW`,
  written atomically (tmp + fsync + rename + parent fsync), and
  owner-checked against the running euid. Parent directory is
  enforced `0700`.
- **Trust roots scope-corrected.** `mkit verify-attest` defaults to
  `$XDG_CONFIG_HOME/mkit/trust-roots.toml`, not a repo-local path,
  so a hostile clone cannot choose its own verifier.

Full description, attacker models, and verification gates in
[`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md).

## PGP / signed reports

We don't publish a long-lived PGP key. GitHub Security
Advisories provides transport-layer privacy and a private collaboration
channel, which we believe is sufficient for the current scope. If you have
a strong need for end-to-end encryption beyond TLS, mention this in the
initial advisory and we'll arrange an out-of-band channel.

## Bug bounty

We do not currently offer a paid bug bounty. Researchers will be
credited in the published advisory and in `CHANGELOG.md`.

## Export control

This project contains cryptographic software (BLAKE3, Ed25519, secp256k1,
P-256, AES, rustls/TLS). Source code distribution is covered under the
publicly-available open-source exemption (US EAR §740.13(e); ECCN 5D002.c.1;
License Exception TSU). A §740.13(e) notification has been provided to BIS
(crypt@bis.doc.gov) and ENC (enc@bis.doc.gov) at the time of public launch.

## Scope

In scope:

- The `mkit` binary and the Rust workspace under `rust/crates/` —
  including the library crates published to crates.io (`mkit-core`,
  `mkit-rpc`, `mkit-attest`, `mkit-keystore`, `mkit-git-bridge`, the
  `mkit-transport-*` crates).
- The reference external signers under `contrib/signers/`.
- Release pipeline integrity (signing, SBOM, reproducibility claims).
- On-disk format parsers (v1 format documented in `docs/specs/SPEC-*.md`).

Out of scope (please report to upstream instead):

- Vulnerabilities in the Rust compiler / standard library.
- Vulnerabilities in operating-system libraries linked at runtime.
