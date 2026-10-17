#!/usr/bin/env python3
"""Exercise the release policy with local crate fixtures and no network."""
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

SPEC = importlib.util.spec_from_file_location(
    "publish_bounded_decoder", Path(__file__).with_name("publish-bounded-decoder.py"))
RELEASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RELEASE)


def crate(files, mtime=0):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for name, data in files:
            member = tarfile.TarInfo("mkit-ruzstd-0.9.1/" + name)
            member.size, member.mtime = len(data), mtime
            archive.addfile(member, io.BytesIO(data))
    return output.getvalue()


FILES = [
    ("Cargo.toml", b"normalized manifest"),
    ("Cargo.toml.orig", b"original manifest"),
    ("Cargo.lock", b"locked dependencies"),
    ("src/lib.rs", b"bounded"),
    (".cargo_vcs_info.json", b'{"git":{"sha1":"first"}}'),
]


class PublishPolicy(unittest.TestCase):
    def run_policy(self, responses):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "Cargo.toml"
            manifest.write_text('[package]\nname = "mkit-ruzstd"\nversion = "0.9.1"\n')
            (root / "package").mkdir()
            (root / "package/mkit-ruzstd-0.9.1.crate").write_bytes(
                crate(FILES))
            with patch.object(RELEASE, "MANIFEST", manifest), \
                 patch.object(RELEASE.subprocess, "run") as run, \
                 patch.object(RELEASE.subprocess, "check_output", return_value=json.dumps(
                     {"target_directory": str(root)})), \
                 patch.object(RELEASE, "download", side_effect=responses) as fetch:
                try:
                    RELEASE.publish()
                finally:
                    self.commands = [call.args[0] for call in run.call_args_list]
                    self.requests = fetch.call_args_list

    def test_absent_publishes(self):
        self.run_policy([HTTPError("fixture", 404, "absent", {}, None)])
        self.assertEqual([command[1] for command in self.commands], ["package", "publish"])
        self.assertEqual(len(self.requests), 1)

    def test_identical_files_skip_despite_archive_metadata_and_order(self):
        self.run_policy([b"version exists", crate(
            list(reversed(FILES)), mtime=100)])
        self.assertEqual([command[1] for command in self.commands], ["package"])
        self.assertEqual(len(self.requests), 2)

    def test_only_cargo_vcs_info_differs_skips(self):
        changed = [(name, b'{"git":{"sha1":"later"}}'
                    if name == ".cargo_vcs_info.json" else data) for name, data in FILES]
        self.run_policy([b"exists", crate(changed)])
        self.assertEqual([command[1] for command in self.commands], ["package"])
        self.assertEqual(RELEASE.COMPARISON_EXCLUSIONS, {".cargo_vcs_info.json"})

    def test_source_file_differs_fails(self):
        changed = [(name, b"unbounded" if name == "src/lib.rs" else data)
                   for name, data in FILES]
        with self.assertRaisesRegex(ValueError, "fork changed and needs a version bump"):
            self.run_policy([b"exists", crate(changed)])
        self.assertEqual([command[1] for command in self.commands], ["package"])

    def test_cargo_manifests_and_lock_bytes_must_match(self):
        for filename in ("Cargo.toml", "Cargo.toml.orig", "Cargo.lock"):
            with self.subTest(filename=filename):
                changed = [(name, b"changed" if name == filename else data)
                           for name, data in FILES]
                with self.assertRaisesRegex(ValueError, "needs a version bump"):
                    self.run_policy([b"exists", crate(changed)])
                self.assertEqual(len(self.commands), 1)

    def test_different_file_list_fails(self):
        with self.assertRaisesRegex(ValueError, "needs a version bump"):
            self.run_policy([b"exists", crate([("Cargo.toml", b"manifest")])])
        self.assertEqual(len(self.commands), 1)

    def test_registry_error_does_not_publish(self):
        with self.assertRaises(HTTPError):
            self.run_policy([HTTPError("fixture", 503, "unavailable", {}, None)])
        self.assertEqual(len(self.commands), 1)

    def test_missing_download_does_not_publish(self):
        with self.assertRaises(HTTPError):
            self.run_policy([b"exists", HTTPError("fixture", 404, "missing", {}, None)])
        self.assertEqual(len(self.commands), 1)


if __name__ == "__main__":
    unittest.main()
