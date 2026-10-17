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


class PublishPolicy(unittest.TestCase):
    def run_policy(self, responses):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "Cargo.toml"
            manifest.write_text('[package]\nname = "mkit-ruzstd"\nversion = "0.9.1"\n')
            (root / "package").mkdir()
            (root / "package/mkit-ruzstd-0.9.1.crate").write_bytes(
                crate([("Cargo.toml", b"manifest"), ("src/lib.rs", b"bounded")]))
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
            [("src/lib.rs", b"bounded"), ("Cargo.toml", b"manifest")], mtime=100)])
        self.assertEqual([command[1] for command in self.commands], ["package"])
        self.assertEqual(len(self.requests), 2)

    def test_different_file_bytes_fail(self):
        with self.assertRaisesRegex(ValueError, "fork changed and needs a version bump"):
            self.run_policy([b"exists", crate(
                [("Cargo.toml", b"manifest"), ("src/lib.rs", b"unbounded")])])
        self.assertEqual([command[1] for command in self.commands], ["package"])

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
