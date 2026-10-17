#!/usr/bin/env python3
"""Publish the fork once; reuse a version only when packaged files match."""
import io
import json
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tarfile
import tomllib
from urllib.error import HTTPError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "rust/vendor/ruzstd/Cargo.toml"


def archive_files(data):
    """Compare names and bytes, independent of gzip/tar metadata and ordering."""
    files = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        for member in archive.getmembers():
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or len(path.parts) < 2:
                raise ValueError("invalid crate archive path")
            if member.isdir():
                continue
            if not member.isfile():
                raise ValueError("crate archive contains a non-file entry")
            name = str(PurePosixPath(*path.parts[1:]))
            if name in files:
                raise ValueError("crate archive contains duplicate file names")
            files[name] = archive.extractfile(member).read()
    return files


def download(url):
    request = Request(url, headers={"User-Agent": "mkit-release (bounded decoder)"})
    with urlopen(request, timeout=60) as response:
        return response.read()


def publish():
    package = tomllib.loads(MANIFEST.read_text())["package"]
    name, version = package["name"], package["version"]
    cargo = ["cargo", "--manifest-path", str(MANIFEST)]
    # Package even an absent version, so all branches validate the same inputs.
    subprocess.run([cargo[0], "package", *cargo[1:], "--locked", "--no-verify"],
                   cwd=ROOT, check=True)
    metadata = json.loads(subprocess.check_output(
        [cargo[0], "metadata", *cargo[1:], "--format-version", "1", "--no-deps"],
        cwd=ROOT, text=True))
    local = (Path(metadata["target_directory"]) / "package" / f"{name}-{version}.crate").read_bytes()
    endpoint = f"https://crates.io/api/v1/crates/{name}/{version}"
    try:
        download(endpoint)
    except HTTPError as error:
        if error.code != 404:
            raise
        print(f"{name} {version} is absent; publishing", flush=True)
        subprocess.run([cargo[0], "publish", *cargo[1:], "--locked"], cwd=ROOT, check=True)
        return
    published = download(endpoint + "/download")
    if archive_files(local) != archive_files(published):
        raise ValueError(f"{name} {version}: the fork changed and needs a version bump; "
                         "published versions cannot be overwritten")
    print(f"{name} {version}: packaged file list and bytes match; skipping publish")


if __name__ == "__main__":
    try:
        publish()
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        sys.exit(f"bounded decoder release failed: {error}")
