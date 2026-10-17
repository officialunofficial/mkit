#!/usr/bin/env python3
"""Small stable tests for read-only fixture and wrapper infrastructure."""
import hashlib
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

    def write_fixture_pair(self, root):
        (root / "sample.bin").write_bytes(b"fixture bytes")
        (root / "sample.json").write_bytes(b'{"expected":"ok"}\n')
        manifest = root / "manifest.toml"
        manifest.write_text('''schema_version = 1
[[formats]]
type = "test"
format_version = 1
decoder = "test::decode"
fuzz_target = "test"
spec = "test"
[[fixtures]]
type = "test"
format_version = 1
ruleset = 1
profile = "indexed"
decode_config = "finite"
expected = "ok"
spec = "test"
path = "sample.bin"
semantic = "sample.json"
''' + f'sha256 = "{hashlib.sha256((root / "sample.bin").read_bytes()).hexdigest()}"\n'
            + f'semantic_sha256 = "{hashlib.sha256((root / "sample.json").read_bytes()).hexdigest()}"\n')
        return manifest

    def test_binary_and_semantic_mutations_are_rejected(self):
        for name in ("sample.bin", "sample.json"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                self.write_fixture_pair(root)
                self.assertEqual(fixtures.check(root), 1)
                path = root / name
                contents = path.read_bytes()
                path.write_bytes(bytes([contents[0] ^ 1]) + contents[1:])
                with self.assertRaisesRegex(ValueError, f"changed fixture bytes: {name}"):
                    fixtures.check(root)

    def test_missing_and_invalid_digests_are_rejected(self):
        for key in ("sha256", "semantic_sha256"):
            for replacement in (None, '"short"', '"' + "z" * 64 + '"', "42"):
                with self.subTest(key=key, replacement=replacement), tempfile.TemporaryDirectory() as directory:
                    root = pathlib.Path(directory)
                    manifest = self.write_fixture_pair(root)
                    lines = manifest.read_text().splitlines()
                    lines = [line if not line.startswith(key + " = ") else
                             (f"{key} = {replacement}" if replacement else "") for line in lines]
                    manifest.write_text("\n".join(lines))
                    with self.assertRaisesRegex(ValueError, "missing or invalid SHA256 digest"):
                        fixtures.check(root)

    def test_digest_reads_are_bounded_and_read_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            self.write_fixture_pair(root)
            snapshot = {path.name: path.read_bytes() for path in root.iterdir()}
            self.assertEqual(fixtures.check(root), 1)
            self.assertEqual(snapshot, {path.name: path.read_bytes() for path in root.iterdir()})
            for name in ("sample.bin", "sample.json"):
                original = (root / name).read_bytes()
                (root / name).write_bytes(b"x" * (fixtures.MAX_FIXTURE_BYTES + 1))
                with self.assertRaisesRegex(ValueError, "exceeds.*byte cap"):
                    fixtures.check(root)
                (root / name).write_bytes(original)

    def test_encoded_format_needs_metadata_and_fixture_coverage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            manifest = root / "manifest.toml"
            manifest.write_text('''schema_version = 1
[[formats]]
type = "test"
format_version = 1
decoder = "test::decode"
fuzz_target = "test"
spec = "test"
''')
            with self.assertRaisesRegex(ValueError, "uncovered encoded formats"):
                fixtures.check(root)
            manifest.write_text(manifest.read_text().replace('decoder = "test::decode"\n', ''))
            with self.assertRaisesRegex(ValueError, "missing format metadata: decoder"):
                fixtures.check(root)

    def write_semantic_contract(self, root):
        path = root / "codes.txt"
        path.write_bytes(b"# module\nFailure\n")
        manifest = root / "manifest.toml"
        manifest.write_text('schema_version = 1\n[[contracts]]\n'
                            'type = "codes"\nruleset = 1\npath = "codes.txt"\n'
                            f'sha256 = "{hashlib.sha256(path.read_bytes()).hexdigest()}"\n'
                            'spec = "README.md stable failure codes"\n')
        return manifest, path

    def test_semantic_contract_inventory_and_bytes_are_read_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            manifest, path = self.write_semantic_contract(root)
            original = path.read_bytes()
            original_manifest = manifest.read_bytes()
            self.assertEqual(fixtures.check(root), 0)
            self.assertEqual(path.read_bytes(), original)
            self.assertEqual(manifest.read_bytes(), original_manifest)
            path.write_bytes(original.replace(b"Failure", b"Changed"))
            with self.assertRaisesRegex(ValueError, "changed fixture bytes: codes.txt"):
                fixtures.check(root)
            path.unlink()
            with self.assertRaisesRegex(ValueError, "missing fixture: codes.txt"):
                fixtures.check(root)
            path.write_bytes(original)
            manifest.write_text("schema_version = 1\n")
            with self.assertRaisesRegex(ValueError, "orphan"):
                fixtures.check(root)

    def test_semantic_contract_requires_metadata_and_valid_digest(self):
        for key in ("type", "ruleset", "path", "sha256", "spec"):
            with self.subTest(key=key), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                manifest, _ = self.write_semantic_contract(root)
                manifest.write_text("\n".join(line for line in manifest.read_text().splitlines()
                                              if not line.startswith(key + " = ")))
                with self.assertRaisesRegex(ValueError, f"missing semantic contract metadata: {key}"):
                    fixtures.check(root)
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            manifest, _ = self.write_semantic_contract(root)
            manifest.write_text(manifest.read_text().replace('sha256 = "', 'sha256 = "invalid'))
            with self.assertRaisesRegex(ValueError, "invalid SHA256 digest"):
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
