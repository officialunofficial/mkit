#!/usr/bin/env python3
"""Opt-in local Cargo cache and conservative worktree cleanup (Python 3.9+)."""

import argparse
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys

REPO = Path(__file__).resolve().parent.parent


def run(args, cwd=None, env=None):
    return subprocess.check_output(args, cwd=cwd, env=env, text=True).strip()


def build_env():
    env = os.environ.copy()
    root = Path(env.get("MKIT_BUILD_ROOT") or Path.home() / ".cache/mkit/build")
    if not root.is_absolute() or "{" in str(root) or "}" in str(root):
        raise ValueError("MKIT_BUILD_ROOT must be an absolute path without template braces")
    env["CARGO_BUILD_BUILD_DIR"] = str(root / "{workspace-path-hash}")
    return env, root


def worktrees(cwd):
    # -z preserves spaces, newlines, and non-ASCII worktree names without Git quoting.
    raw = subprocess.check_output(["git", "worktree", "list", "--porcelain", "-z"], cwd=cwd)
    records, record = [], {}
    for item in os.fsdecode(raw).split("\0"):
        if not item:
            if record:
                records.append(record)
                record = {}
        else:
            key, _, value = item.partition(" ")
            record[key] = value
    return records


def git(path, *args):
    return run(["git", "--no-optional-locks", "-C", str(path), *args])


def clean_status(path):
    return not git(path, "status", "--porcelain", "--untracked-files=all", "--ignore-submodules=none")


def eligible(record, current, main, base):
    path = Path(record["worktree"])
    if path.resolve() in (current, main) or record.get("branch") == "refs/heads/main":
        return "main or current checkout", None
    if "locked" in record or "prunable" in record or not path.is_dir():
        return "locked or missing worktree", None
    if "branch" not in record:
        return "detached HEAD", None
    if not clean_status(path):
        return "uncommitted changes", None
    merged = subprocess.run(["git", "-C", str(path), "merge-base", "--is-ancestor",
                             record["HEAD"], base], check=False).returncode
    if merged == 0:
        return None, f"merged into {base}"
    if merged != 1:
        raise ValueError("cannot determine merge status; fetch and retry")
    upstream = git(path, "for-each-ref", "--format=%(upstream:track)", record["branch"])
    if upstream == "[gone]":
        return None, "upstream branch gone"
    return "branch is not merged or gone", None


def output_dirs(path, env, root, records):
    workspace = path / "rust"
    if workspace.resolve() != path.resolve() / "rust":
        raise ValueError("workspace directory is symlinked")
    metadata = json.loads(run(["cargo", "metadata", "--offline", "--no-deps",
                               "--format-version", "1"], cwd=workspace, env=env))
    target = Path(metadata["target_directory"])
    build = Path(metadata["build_directory"])
    # Only the conventional target is eligible. Never follow a configured shared target.
    if target != workspace / "target" or target.resolve() != workspace.resolve() / "target":
        raise ValueError("target directory is external or symlinked")
    relative = build.relative_to(root)
    # Cargo expands workspace-path-hash as a two-level hexadecimal path.
    if len(relative.parts) != 2 or any(not part or any(c not in "0123456789abcdef" for c in part)
                                       for part in relative.parts):
        raise ValueError("build directory is not a workspace hash")
    if build.resolve() != root.resolve() / relative:
        raise ValueError("build directory is symlinked")
    for record in records:
        source = Path(record["worktree"]).resolve()
        if build.resolve() == source or source in build.resolve().parents:
            raise ValueError("build directory overlaps a source checkout")
    if git(path, "ls-files", "--", "rust/target"):
        raise ValueError("target directory contains tracked files")
    if Path(metadata["workspace_root"]).resolve() != workspace.resolve():
        raise ValueError("workspace root is outside this checkout")
    return workspace, target, build


def gc(apply):
    env, root = build_env()
    # Ignore inherited shared targets. Cargo config overrides are inspected below.
    env.pop("CARGO_TARGET_DIR", None)
    env.pop("CARGO_BUILD_TARGET_DIR", None)
    current = Path(git(Path.cwd(), "rev-parse", "--show-toplevel")).resolve()
    records = worktrees(current)
    main = Path(records[0]["worktree"]).resolve()
    base = "origin/main" if subprocess.run(
        ["git", "-C", str(current), "rev-parse", "--verify", "--quiet", "refs/remotes/origin/main"],
        stdout=subprocess.DEVNULL, check=False).returncode == 0 else "main"
    git(current, "rev-parse", "--verify", base + "^{commit}")
    failed = False
    for record in records:
        path = Path(record["worktree"])
        try:
            skip, reason = eligible(record, current, main, base)
            if skip:
                print(f"skip {path}: {skip}")
                continue
            workspace, target, build = output_dirs(path, env, root, records)
            if not target.exists() and not build.exists():
                print(f"skip {path}: no build output")
                continue
            if apply:
                # Recheck immediately before clean. Pin both output paths on the command line.
                if not clean_status(path) or git(path, "rev-parse", "HEAD") != record["HEAD"]:
                    print(f"skip {path}: checkout changed during scan")
                    continue
                output_dirs(path, env, root, records)
                subprocess.run(["cargo", "clean", "--target-dir", str(target), "--config",
                                "build.build-dir=" + json.dumps(str(build))],
                               cwd=workspace, env=env, check=True)
            print(f"{'cleaned' if apply else 'would clean'} {path}: {reason}\n"
                  f"  target: {target}\n  build: {build}")
        except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as error:
            print(f"skip {path}: {error}", file=sys.stderr)
            failed = True
    if not apply:
        print("Dry run. Run with --apply to delete eligible build output.")
    return int(failed)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("cargo", "env", "gc"))
    args = parser.parse_args(sys.argv[1:2])
    rest = sys.argv[2:]
    if args.command == "gc":
        gc_parser = argparse.ArgumentParser(description="Clean merged/gone worktrees; dry run by default.")
        gc_parser.add_argument("--apply", action="store_true")
        return gc(gc_parser.parse_args(rest).apply)
    env, _ = build_env()
    if args.command == "env":
        if rest:
            parser.error("env takes no arguments")
        print("export CARGO_BUILD_BUILD_DIR=" + shlex.quote(env["CARGO_BUILD_BUILD_DIR"]))
        return 0
    sccache = shutil.which("sccache")
    if not sccache:
        raise ValueError("sccache is not on PATH; install it with 'cargo install sccache' or 'brew install sccache'")
    if env.get("CARGO_TARGET_DIR") or env.get("CARGO_BUILD_TARGET_DIR"):
        raise ValueError("unset CARGO_TARGET_DIR and CARGO_BUILD_TARGET_DIR; never share targets between worktrees")
    env["RUSTC_WRAPPER"] = sccache
    env["CARGO_INCREMENTAL"] = "0"
    env.setdefault("SCCACHE_CACHE_SIZE", "30G")
    os.chdir(REPO / "rust")
    os.execvpe("cargo", ["cargo", *rest], env)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print(f"local-build: {error}", file=sys.stderr)
        sys.exit(1)
