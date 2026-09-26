# The mkit-server container image (WP-M0-19), published by release.yml's
# `container` job as ghcr.io/officialunofficial/mkit-server.
#
# Nothing is compiled here. The build context is a directory that
# scripts/release/stage-server-image.sh laid out from the cosign-verified
# release archives:
#
#   dist/amd64/{mkit-server,LICENSE-MIT,LICENSE-APACHE}   (x86_64-unknown-linux-gnu)
#   dist/arm64/{mkit-server,LICENSE-MIT,LICENSE-APACHE}   (aarch64-unknown-linux-gnu)
#
# so the image carries exactly the signed binary bytes. There is no RUN
# instruction, so a multi-platform build executes nothing for the foreign
# architecture and needs no QEMU. There is no `# syntax=` line on purpose:
# the builder's built-in Dockerfile frontend parses this file, so no
# unpinned frontend image is pulled.
#
# The binaries are glibc-linked (libc, libm, libgcc_s; SQLite is bundled),
# which distroless `cc` provides. The base is Debian 13 (glibc 2.41), not
# Debian 12: release.yml builds on ubuntu-24.04 runners, and aws-lc-sys's C
# code (rustls's crypto provider) links glibc 2.38 symbols
# (`__isoc23_strtol`, `__isoc23_sscanf`), which Debian 12's glibc 2.36
# lacks. The stage script refuses a binary that needs another library or a
# newer glibc than this base's.
#
# Dependabot (.github/dependabot.yml, "docker") bumps the digest below.
FROM gcr.io/distroless/cc-debian13:nonroot@sha256:54df941ed0d06a1bd95ef5e0ce391fd8d9f94b64782dc9a60062727849ee3f97

ARG TARGETARCH
ARG VERSION=unknown
ARG REVISION=unknown

LABEL org.opencontainers.image.title="mkit-server" \
      org.opencontainers.image.description="The long-running native mkit server (HTTP/Connect and mkit+enc:// listeners)" \
      org.opencontainers.image.source="https://github.com/officialunofficial/mkit" \
      org.opencontainers.image.documentation="https://github.com/officialunofficial/mkit/blob/main/docs/CONTAINER.md" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"

# Owned by root and not writable, so the server's user cannot replace it.
COPY --chmod=0555 dist/${TARGETARCH}/mkit-server /usr/local/bin/mkit-server
COPY --chmod=0444 dist/${TARGETARCH}/LICENSE-MIT dist/${TARGETARCH}/LICENSE-APACHE /usr/share/doc/mkit-server/

# distroless `nonroot`, numeric so Kubernetes `runAsNonRoot` can check it.
USER 65532:65532

# HTTP/Connect (`--listen 0.0.0.0:8080`) and mkit+enc:// (`--listen-enc
# 0.0.0.0:9418`, the scheme's default port). Neither listens unless its
# flag is passed.
EXPOSE 8080 9418

# No HEALTHCHECK: the image has no shell or HTTP client, and the binary has
# no probe subcommand. Probe `grpc.health.v1.Health` from outside (see
# docs/CONTAINER.md).
ENTRYPOINT ["/usr/local/bin/mkit-server", "serve"]
CMD ["--help"]
