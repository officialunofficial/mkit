#!/usr/bin/env python3
"""Independent release policy for mkit-primitives (never part of the release train).

  check              version, changelog and train-exclusion invariants (PR safe)
  guard TAG          `check`, plus the tag, a dated changelog section and the
                     published mkit-core the tree and requirement depend on
  baseline           print the semver baseline: newest non-yanked published
                     mkit-primitives version older than the current one, or `none`
  publish [--dry-run]
                     package, then publish only when the version is absent;
                     skip when the published files match, fail when they differ

Publishing reuses the content-compare policy of the bounded decoder script.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import tomllib
from urllib.error import HTTPError

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]
RUST = ROOT / "rust"
MANIFEST = RUST / "crates/mkit-primitives/Cargo.toml"
WORKSPACE = RUST / "Cargo.toml"
CORE_MANIFEST = RUST / "crates/mkit-core/Cargo.toml"
CHANGELOG = RUST / "crates/mkit-primitives/CHANGELOG.md"
TRAIN_WORKFLOW = ROOT / ".github/workflows/crates-publish.yml"
RELEASE_PLZ = RUST / "release-plz.toml"
NAME = "mkit-primitives"
TAG = re.compile(r"^mkit-primitives-v(\d+\.\d+\.\d+)$")
VERSION = re.compile(r"^\d+\.\d+\.\d+$")
API = "https://crates.io/api/v1/crates"

SPEC = importlib.util.spec_from_file_location(
    "publish_bounded_decoder", Path(__file__).with_name("publish-bounded-decoder.py"))
BOUNDED = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BOUNDED)


def parse(version):
    return tuple(int(part) for part in version.split("."))


def caret_allows(requirement, version):
    """Caret semantics for a bare `X`, `X.Y` or `X.Y.Z` requirement."""
    parts = [int(part) for part in requirement.lstrip("^").split(".")]
    if not 1 <= len(parts) <= 3:
        raise ValueError(f"unsupported mkit-core requirement {requirement!r}")
    padded = parts + [0] * (3 - len(parts))
    pivot = next((i for i, part in enumerate(parts) if part), len(parts) - 1)
    upper = padded[:pivot] + [padded[pivot] + 1] + [0] * (2 - pivot)
    return tuple(padded) <= parse(version) < tuple(upper)


def lower_bound(requirement):
    parts = [int(part) for part in requirement.lstrip("^").split(".")]
    return ".".join(str(part) for part in parts + [0] * (3 - len(parts)))


def manifests():
    package = tomllib.loads(MANIFEST.read_text())
    version = package["package"]["version"]
    if not isinstance(version, str) or not VERSION.match(version):
        raise ValueError("mkit-primitives needs its own literal X.Y.Z version")
    core = tomllib.loads(CORE_MANIFEST.read_text())["package"]["version"]
    if not isinstance(core, str):
        core = tomllib.loads(WORKSPACE.read_text())["workspace"]["package"]["version"]
    requirement = package["dependencies"]["mkit-core"]["version"]
    return version, core, requirement


def check(release_tag=None):
    version, core, requirement = manifests()
    if not caret_allows(requirement, core):
        raise ValueError(f"mkit-core {core} does not satisfy the declared requirement "
                         f"{requirement!r}; raise the requirement to the release that "
                         "contains the APIs mkit-primitives uses")
    train = re.sub(r"\\\n\s*", " ", TRAIN_WORKFLOW.read_text())
    if not re.search(r"cargo publish --workspace\b[^\n]*--exclude mkit-primitives\b", train):
        raise ValueError("the release-train publish must keep --exclude mkit-primitives")
    release_plz = tomllib.loads(RELEASE_PLZ.read_text())["package"]
    entry = [p for p in release_plz if p["name"] == NAME]
    if len(entry) != 1 or entry[0].get("release") is not False or "version_group" in entry[0]:
        raise ValueError("release-plz must keep mkit-primitives out of every release group")
    text = CHANGELOG.read_text()
    if not re.search(r"^## \[Unreleased\]$", text, re.MULTILINE):
        raise ValueError("crate CHANGELOG needs an `## [Unreleased]` section")
    heading = re.search(rf"^## \[{re.escape(version)}\](.*)$", text, re.MULTILINE)
    dated = bool(heading and re.fullmatch(r" - \d{4}-\d{2}-\d{2}", heading.group(1)))
    if heading and not dated:
        raise ValueError(f"CHANGELOG section for {version} needs a ` - YYYY-MM-DD` date")
    if release_tag is not None:
        if not dated:
            raise ValueError(f"CHANGELOG has no dated `## [{version}] - YYYY-MM-DD` section")
        if TAG.match(release_tag).group(1) != version:
            raise ValueError(f"tag {release_tag!r} != mkit-primitives version {version}")
    return version, core, requirement


def crate_info(path):
    """Return the parsed crates.io API document, or None when it answers 404."""
    try:
        return json.loads(BOUNDED.download(f"{API}/{path}"))
    except HTTPError as error:
        if error.code == 404:
            return None
        raise


def core_released(core):
    info = crate_info(f"mkit-core/{core}")
    if info is None or info["version"]["yanked"]:
        raise ValueError(f"mkit-core {core} is not published on crates.io; "
                         "release the train first, then tag mkit-primitives")


def baseline(current):
    """Newest live release strictly older than `current`, so reruns stay stable."""
    info = crate_info(NAME)
    if info is None:
        return "none"
    live = [v["num"] for v in info["versions"]
            if not v["yanked"] and VERSION.match(v["num"]) and parse(v["num"]) < parse(current)]
    return max(live, key=parse) if live else "none"


def publish(dry_run=False):
    version = check()[0]
    cargo = ["cargo"]
    subprocess.run([*cargo, "package", "-p", NAME, "--locked", "--no-verify"],
                   cwd=RUST, check=True)
    metadata = json.loads(subprocess.check_output(
        [*cargo, "metadata", "--format-version", "1", "--no-deps"], cwd=RUST, text=True))
    local = (Path(metadata["target_directory"]) / "package"
             / f"{NAME}-{version}.crate").read_bytes()
    endpoint = f"{API}/{NAME}/{version}"
    try:
        BOUNDED.download(endpoint)
    except HTTPError as error:
        if error.code != 404:
            raise
        print(f"{NAME} {version} is absent; publishing", flush=True)
        command = [*cargo, "publish", "-p", NAME, "--locked"]
        subprocess.run(command + (["--dry-run"] if dry_run else []), cwd=RUST, check=True)
        return
    published = BOUNDED.download(endpoint + "/download")
    if BOUNDED.archive_files(local) != BOUNDED.archive_files(published):
        raise ValueError(f"{NAME} {version}: the crate changed and needs a version bump; "
                         "published versions cannot be overwritten")
    print(f"{NAME} {version}: packaged files match (excluding .cargo_vcs_info.json); "
          "skipping publish")


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("check")
    guard = commands.add_parser("guard")
    guard.add_argument("tag")
    commands.add_parser("baseline")
    release = commands.add_parser("publish")
    release.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    if args.command == "check":
        version, core, _ = check()
        print(f"mkit-primitives {version}: independent of the release train; mkit-core {core}")
    elif args.command == "guard":
        if not TAG.match(args.tag):
            raise ValueError(f"tag {args.tag!r} is not mkit-primitives-vX.Y.Z")
        version, core, requirement = check(args.tag)
        # The tree's core version, and the oldest core the declared requirement
        # allows (what the published crate may resolve), must both be live.
        for needed in sorted({core, lower_bound(requirement)}):
            core_released(needed)
        print(f"mkit-primitives {version}: tag, changelog and published mkit-core {core} ok")
    elif args.command == "baseline":
        print(baseline(manifests()[0]))
    else:
        publish(args.dry_run)


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        sys.exit(f"mkit-primitives release failed: {error}")
