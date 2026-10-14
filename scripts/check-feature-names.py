#!/usr/bin/env python3
"""Preserve Clippy's redundant feature-name gate with one public API exception."""
import json
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parent.parent
PREFIXES = ("use-", "use_", "with-", "with_")
SUFFIXES = ("-support", "_support")
EXCEPTION = ("mkit-server", "test-support")


def redundant(package, feature):
    return ((package, feature) != EXCEPTION
            and (feature.startswith(PREFIXES) or feature.endswith(SUFFIXES)))


class FeatureNames(unittest.TestCase):
    def test_exception_is_exact(self):
        self.assertFalse(redundant(*EXCEPTION))
        self.assertTrue(redundant("other", "test-support"))
        self.assertTrue(redundant("mkit-server", "other-support"))
        self.assertTrue(redundant("mkit-server", "test_support"))

    def test_clippy_redundant_patterns(self):
        for feature in ("use-x", "use_x", "with-x", "with_x", "x-support", "x_support"):
            self.assertTrue(redundant("other", feature))
        for feature in ("default", "connect", "memory", "support", "test"):
            self.assertFalse(redundant("other", feature))


def check():
    metadata = json.loads(subprocess.check_output([
        "cargo", "metadata", "--locked", "--no-deps", "--format-version", "1",
        "--manifest-path", str(ROOT / "rust/Cargo.toml"),
    ]))
    failures = [f"{package['name']}/{feature}" for package in metadata["packages"]
                for feature in package["features"] if redundant(package["name"], feature)]
    if failures:
        raise SystemExit("redundant feature names: " + ", ".join(sorted(failures)))
    print("PASS feature names: only mkit-server/test-support is exempt")


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(FeatureNames)
    if not unittest.TextTestRunner().run(suite).wasSuccessful():
        raise SystemExit(1)
    check()
