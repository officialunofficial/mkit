# mkit

A content-addressed version control toolkit written in Zig.

`mkit` is a generic content-addressed VCS — Git-like commits, refs,
transports — with no built-in knowledge of any blockchain, notary, or
attestation backend. Downstream projects that need attestation can pull
`mkit` in as a Zig library and plug into the `Notary` trait exposed at
`src/notary.zig`.

## Quick start

```sh
# Build (Zig 0.16.0):
zig build

# Initialize a repo, generate a key, commit:
./zig-out/bin/mkit init
./zig-out/bin/mkit keygen
./zig-out/bin/mkit add some-file.txt
./zig-out/bin/mkit commit -m "first commit"
./zig-out/bin/mkit log
```

To push to a remote, declare a strict URL scheme (`mkit+file://`,
`mkit+https://`, `mkit+s3://`, `mkit+ssh://`):

```sh
mkit remote add origin mkit+file:///srv/mkit/my-repo
mkit push
```

See [`docs/CLI.md`](docs/CLI.md) for the full CLI reference.

## Build

Requires **Zig 0.16.0**.

```sh
zig build                       # mkit binary → zig-out/bin/mkit
zig build test                  # unit tests
zig build test-all              # unit + integration
zig build bench                 # benchmarks (ReleaseFast)
zig build -Djemalloc            # link jemalloc (if installed)
```

`scripts/verify-rename.sh` is the rename-gate enforced in CI; it greps
for forbidden legacy strings across the public build surface.

## Architecture

mkit is a thin, generic VCS. The `Notary` trait in `src/notary.zig` is a
library extension point for downstream consumers that need to witness or
attest to a push:

```
┌─────────────────────────────────────────────────────────┐
│  mkit core binary                                       │
│  - objects, packs, refs, transports, CLI                │
│  - depends only on: src/notary.zig (Notary vtable)      │
└────────────────────┬────────────────────────────────────┘
                     │
        ┌────────────┼────────────────┐
        │            │                │
┌───────┴────────┐   │   ┌────────────┴────────────────┐
│ NullNotary     │   │   │ your custom Notary impl     │
│ (core default) │   │   │ (supplied by library user)  │
│ no-op          │   │   │                             │
│ always present │   │   │                             │
└────────────────┘   │   └─────────────────────────────┘
                     │
           (library consumers plug in here)
```

The public `mkit` binary never surfaces notary behaviour in its CLI —
`NullNotary` is the only backend it knows about. Consumers that need
attestation bring their own `Notary` implementation in their own
codebase.

See [`docs/NOTARY.md`](docs/NOTARY.md) for the trait contract.

## Documentation

| Doc | Audience |
|---|---|
| [`docs/CLI.md`](docs/CLI.md) | End users — subcommands, env vars, exit codes |
| [`docs/NOTARY.md`](docs/NOTARY.md) | Library consumers — extension-point contract for downstream notary implementations |
| [`docs/SPEC-OBJECTS.md`](docs/SPEC-OBJECTS.md) | Implementers of compatible tools — on-disk format |
| [`docs/SPEC-SIGNING.md`](docs/SPEC-SIGNING.md) | Implementers — commit signing format |
| [`docs/SPEC-PACKFILE.md`](docs/SPEC-PACKFILE.md) | Implementers — packfile wire format |
| [`docs/SPEC-DELTA.md`](docs/SPEC-DELTA.md) | Implementers — delta encoding |
| [`docs/SPEC-REFS.md`](docs/SPEC-REFS.md) | Implementers — ref names and CAS |
| [`docs/SPEC-TRANSPORT.md`](docs/SPEC-TRANSPORT.md) | Implementers — 7-verb transport protocol incl. SSH OP_HELLO |
| [`docs/SPEC-FASTCDC.md`](docs/SPEC-FASTCDC.md) | Implementers — content chunking |
| [`docs/SSH-SECURITY.md`](docs/SSH-SECURITY.md) | Operators — SSH transport trust model |
| [`docs/FUZZ.md`](docs/FUZZ.md) | Contributors — fuzz harness conventions |
| [`docs/release/`](docs/release/) | Maintainers — release checklist, signing, reproducibility, supply chain |

## Installing

When `v0.1.0` is published, prebuilt binaries will be available via:

- **Homebrew** (macOS + Linux):
  ```sh
  brew tap officialunofficial/tap
  brew install mkit
  ```
  Tap publication flow: [`contrib/homebrew/README.md`](contrib/homebrew/README.md).

- **GitHub Releases** — cosign-keyless-signed archives for macOS
  (arm64 + x86_64) and Linux (x86_64 + arm64):
  <https://github.com/officialunofficial/mkit/releases>

  Verification steps: [`docs/release/SIGNING.md`](docs/release/SIGNING.md).

## Status

0.1.0 is the initial public release. See [`CHANGELOG.md`](CHANGELOG.md)
for the full change list.

## Contributing

This is a young project. Open issues and PRs welcome.

Security-sensitive disclosures: see [`SECURITY.md`](SECURITY.md).

## License

Dual-licensed under either of:

- MIT License ([LICENSE-MIT](LICENSE-MIT))
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))

at your option. Unless you explicitly state otherwise, any contribution
intentionally submitted for inclusion in this project shall be dual-licensed
as above, without any additional terms or conditions.
