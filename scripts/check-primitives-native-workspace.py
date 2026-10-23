#!/usr/bin/env python3
"""Check the resolved native decoder's fixed bulk workspace, without decoding."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
# The fresh, dictionary-free ZSTD_decompressDCtx path allocates only its DCtx.
# Input/output stay caller-owned; literals use destination or inline scratch.
# Streaming/history buffers and prepared dictionaries are absent on this path.
# Source audit is pinned to the implementation below; dependency upgrades must
# repeat it rather than assume another decoder version has the same behavior.
# https://github.com/facebook/zstd/blob/v1.5.7/lib/decompress/zstd_decompress.c
# https://github.com/facebook/zstd/blob/v1.5.7/lib/decompress/zstd_decompress_block.c
EXPECTED_VERSION = "2.1.2+zstd.1.5.7"
ALLOWANCE = 28 << 20


def main():
    metadata = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--locked", "--all-features", "--format-version", "1"],
        cwd=ROOT / "rust", text=True, timeout=120,
    ))
    resolved = {node["id"] for node in metadata["resolve"]["nodes"]}
    packages = [package for package in metadata["packages"]
                if package["id"] in resolved and package["name"] == "zstd-sys"]
    if len(packages) != 1 or packages[0]["version"] != EXPECTED_VERSION:
        raise SystemExit("native workspace: resolved decoder requires a new source audit")
    features = next(node["features"] for node in metadata["resolve"]["nodes"]
                    if node["id"] == packages[0]["id"])
    legacy = "1" if "legacy" in features else "0"
    source = Path(packages[0]["manifest_path"]).parent / "zstd/lib/decompress"
    if not (source / "zstd_decompress_internal.h").is_file():
        raise SystemExit("native workspace: resolved decoder source is unavailable")
    with tempfile.TemporaryDirectory(prefix="primitives-native-workspace-") as temporary:
        directory = Path(temporary)
        program = directory / "workspace.c"
        binary = directory / "workspace"
        program.write_text(
            '#include <stdio.h>\n#include "zstd_decompress_internal.h"\n'
            'int main(void) { printf("%zu\\n", sizeof(ZSTD_DCtx)); return 0; }\n'
        )
        # GCC may emit unused static header helpers at -O0. Link their
        # resolved error-string implementation rather than rely on dead-code
        # elimination; this does not change the measured context layout.
        subprocess.run(
            shlex.split(os.environ.get("CC", "cc"))
            + [f"-DZSTD_LEGACY_SUPPORT={legacy}", "-I", str(source),
               str(program), str(source.parent / "common/error_private.c"),
               "-o", str(binary)],
            check=True, timeout=30,
        )
        size = int(subprocess.check_output([str(binary)], text=True, timeout=10))
    if not 0 < size <= ALLOWANCE:
        raise SystemExit("native workspace: fixed context exceeds decoder reservation")
    print(f"primitives native workspace: zstd 1.5.7 DCtx={size} bytes; "
          f"reserved={ALLOWANCE} bytes; fixed bulk context only")


if __name__ == "__main__":
    main()
