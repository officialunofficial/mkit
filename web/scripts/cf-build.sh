#!/usr/bin/env bash
# Build command for Cloudflare Workers Builds (set in the dashboard as
# `bash scripts/cf-build.sh` with root directory `/web`).
#
# The Workers Builds image ships Node + Bun but no Rust toolchain, and
# vendor/mkit-wasm/pkg is built from source (gitignored), so this script
# bootstraps rustup + wasm-pack before running the normal `bun run build`
# chain (skill:stage -> wasm:build -> waku build -> config patchers).
# Pin the Bun version with the BUN_VERSION=1.3.14 build variable in the
# dashboard — the image default lags behind the version CI tests against.
# Idempotent, and safe to run locally if you already have the tools.
set -euo pipefail

cd "$(dirname "$0")/.."

# Rust toolchain. rust/rust-toolchain.toml pins 1.95.0 and rustup resolves
# it when cargo runs inside rust/, but the wasm32 target is not listed
# there and must be added explicitly.
if ! command -v rustup >/dev/null 2>&1; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain none
fi
# shellcheck disable=SC1091
. "$HOME/.cargo/env" 2>/dev/null || export PATH="$HOME/.cargo/bin:$PATH"
rustup toolchain install 1.95.0 --profile minimal
rustup target add wasm32-unknown-unknown --toolchain 1.95.0

# wasm-pack: prebuilt binary (cargo install would compile it from source,
# which blows most of the build budget). Version matches web.yml CI.
WASM_PACK_VERSION=0.13.1
if ! command -v wasm-pack >/dev/null 2>&1; then
  case "$(uname -s)-$(uname -m)" in
    Linux-x86_64) triple="x86_64-unknown-linux-musl" ;;
    Linux-aarch64) triple="aarch64-unknown-linux-musl" ;;
    Darwin-arm64) triple="aarch64-apple-darwin" ;;
    Darwin-x86_64) triple="x86_64-apple-darwin" ;;
    *)
      echo "cf-build: unsupported platform $(uname -s)-$(uname -m)" >&2
      exit 1
      ;;
  esac
  mkdir -p "$HOME/.cargo/bin"
  curl -sSfL "https://github.com/rustwasm/wasm-pack/releases/download/v${WASM_PACK_VERSION}/wasm-pack-v${WASM_PACK_VERSION}-${triple}.tar.gz" |
    tar -xz --strip-components=1 -C "$HOME/.cargo/bin" "wasm-pack-v${WASM_PACK_VERSION}-${triple}/wasm-pack"
fi
wasm-pack --version

bun install --frozen-lockfile
bun run build
