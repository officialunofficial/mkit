#!/usr/bin/env python3
"""Small stable tests for read-only fixture and wrapper infrastructure."""
import importlib.util
import os
import pathlib
import subprocess
import tempfile
import sys
sys.dont_write_bytecode = True
import unittest

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("fixtures", HERE / "check-primitives-fixtures.py")
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)


class InventoryTests(unittest.TestCase):
    def test_orphan_and_missing_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            manifest = root / "manifest.toml"
            manifest.write_text("schema_version = 1\nfixtures = []\n")
            self.assertEqual(fixtures.check(root), 0)
            (root / "orphan.bin").write_bytes(b"x")
            with self.assertRaisesRegex(ValueError, "orphan"):
                fixtures.check(root)
            (root / "orphan.bin").unlink()
            manifest.write_text('''schema_version = 1
[[fixtures]]
type = "test"
format_version = 1
ruleset = 1
profile = "indexed"
decode_config = "finite"
expected = "ok"
spec = "test"
path = "missing.bin"
semantic = "missing.toml"
''')
            with self.assertRaisesRegex(ValueError, "missing fixture"):
                fixtures.check(root)

    def test_nested_manifest_is_not_exempt_from_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "manifest.toml").write_text("schema_version = 1\nfixtures = []\n")
            nested = root / "semantic"
            nested.mkdir()
            (nested / "manifest.toml").write_text("orphan = true\n")
            with self.assertRaisesRegex(ValueError, "orphan"):
                fixtures.check(root)

    def test_wrapper_only_marks_primitives(self):
        wrapper = HERE / "primitives-stability-rustc.py"
        environment = dict(os.environ, MKIT_PRIMITIVES_MIN_STABILITY="GAMMA")
        # echo stands in for rustc; inspect exactly which arguments it receives.
        for crate in ("mkit_primitives", "mkit_core", "other"):
            args = subprocess.check_output([str(wrapper), "/bin/echo", "--crate-name", crate], env=environment, text=True)
            self.assertEqual("--cfg commonware_stability_GAMMA" in args, crate == "mkit_primitives")


if __name__ == "__main__":
    unittest.main()
