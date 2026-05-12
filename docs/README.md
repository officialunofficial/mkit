# mkit documentation

The canonical mkit documentation is now hosted at
[mkit.makechain.net](https://mkit.makechain.net).

The source pages live under
[`apps/docs/src/pages/`](../apps/docs/src/pages/). Edit them directly
in this repository; Cloudflare Pages picks up changes on merge to
`main`.

The Markdown files in this directory are kept in place so existing
deep links (from external sites and from rustdoc `///` cross-references)
continue to resolve. They are no longer the source of truth — every
change must be made in the corresponding `.mdx` file under
`apps/docs/src/pages/docs/`. CI fails the build if the two diverge.

## Redirect map

| Old path | New URL |
| --- | --- |
| `docs/ARCHITECTURE.md` | https://mkit.makechain.net/docs/architecture |
| `docs/CLI.md` | https://mkit.makechain.net/docs/cli |
| `docs/FUZZ.md` | https://mkit.makechain.net/docs/fuzz |
| `docs/INSTALL.md` | https://mkit.makechain.net/docs/install |
| `docs/RELEASE.md` | https://mkit.makechain.net/docs/release |
| `docs/SPEC-ATTESTATIONS.md` | https://mkit.makechain.net/docs/spec/attestations |
| `docs/SPEC-DELTA.md` | https://mkit.makechain.net/docs/spec/delta |
| `docs/SPEC-EXTERNAL-SIGNER.md` | https://mkit.makechain.net/docs/spec/external-signer |
| `docs/SPEC-FASTCDC.md` | https://mkit.makechain.net/docs/spec/fastcdc |
| `docs/SPEC-INDEX.md` | https://mkit.makechain.net/docs/spec/staging-index |
| `docs/SPEC-OBJECTS.md` | https://mkit.makechain.net/docs/spec/objects |
| `docs/SPEC-PACKFILE.md` | https://mkit.makechain.net/docs/spec/packfile |
| `docs/SPEC-REFS.md` | https://mkit.makechain.net/docs/spec/refs |
| `docs/SPEC-RPC.md` | https://mkit.makechain.net/docs/spec/rpc |
| `docs/SPEC-SIGNING.md` | https://mkit.makechain.net/docs/spec/signing |
| `docs/SPEC-TRANSPORT.md` | https://mkit.makechain.net/docs/spec/transport |
| `docs/SSH-SECURITY.md` | https://mkit.makechain.net/docs/ssh-security |
| `docs/STYLE-GUIDE.md` | https://mkit.makechain.net/docs/style-guide |
| `docs/THREAT-MODEL.md` | https://mkit.makechain.net/docs/threat-model |
| `docs/advisories/README.md` | https://mkit.makechain.net/docs/advisories |
| `docs/advisories/GHSA-001-per-repo-config.md` | https://mkit.makechain.net/docs/advisories/ghsa-001-per-repo-config |
| `docs/advisories/GHSA-002-trust-roots-scope.md` | https://mkit.makechain.net/docs/advisories/ghsa-002-trust-roots-scope |
| `docs/advisories/GHSA-003-key-file-handling.md` | https://mkit.makechain.net/docs/advisories/ghsa-003-key-file-handling |
