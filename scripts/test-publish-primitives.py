#!/usr/bin/env python3
"""Exercise the mkit-primitives release policy with local fixtures and no network."""
import importlib.util
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

sys.dont_write_bytecode = True

SPEC = importlib.util.spec_from_file_location(
    "publish_primitives", Path(__file__).with_name("publish-primitives.py"))
RELEASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RELEASE)


def crate(files, mtime=0):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for name, data in files:
            member = tarfile.TarInfo("mkit-primitives-0.1.0/" + name)
            member.size, member.mtime = len(data), mtime
            archive.addfile(member, io.BytesIO(data))
    return output.getvalue()


FILES = [
    ("Cargo.toml", b"normalized"),
    ("CHANGELOG.md", b"changes"),
    ("src/lib.rs", b"api"),
    ("fixtures/manifest.toml", b"fixtures"),
    (".cargo_vcs_info.json", b'{"git":{"sha1":"first"}}'),
]
NOT_FOUND = HTTPError("fixture", 404, "absent", {}, None)


class Tree:
    """A minimal repository layout for the guards."""

    def __init__(self, root, *, version="0.1.0", core="0.5.0", requirement="0.5",
                 exclude=True, release=False, changelog=None):
        self.root = Path(root)
        write = lambda path, text: (self.root / path).parent.mkdir(parents=True, exist_ok=True) \
            or (self.root / path).write_text(text)
        write("rust/crates/mkit-primitives/Cargo.toml",
              f'[package]\nname = "mkit-primitives"\nversion = "{version}"\n'
              f'[dependencies]\nmkit-core = {{ version = "{requirement}" }}\n')
        write("rust/crates/mkit-core/Cargo.toml",
              '[package]\nname = "mkit-core"\nversion.workspace = true\n')
        write("rust/Cargo.toml", f'[workspace.package]\nversion = "{core}"\n')
        flag = "--exclude mkit-primitives" if exclude else ""
        write(".github/workflows/crates-publish.yml",
              f"run: cargo publish --workspace {flag} --locked\n")
        write("rust/release-plz.toml",
              f'[[package]]\nname = "mkit-primitives"\nrelease = {str(release).lower()}\n')
        write("rust/crates/mkit-primitives/CHANGELOG.md", changelog
              or "## [Unreleased]\n\n## [0.1.0] - 2026-01-02\n")

    def patched(self):
        r = self.root
        return patch.multiple(
            RELEASE, MANIFEST=r / "rust/crates/mkit-primitives/Cargo.toml",
            CORE_MANIFEST=r / "rust/crates/mkit-core/Cargo.toml",
            WORKSPACE=r / "rust/Cargo.toml",
            CHANGELOG=r / "rust/crates/mkit-primitives/CHANGELOG.md",
            TRAIN_WORKFLOW=r / ".github/workflows/crates-publish.yml",
            RELEASE_PLZ=r / "rust/release-plz.toml")


class Guards(unittest.TestCase):
    def check(self, tag=None, **kwargs):
        with tempfile.TemporaryDirectory() as directory:
            with Tree(directory, **kwargs).patched():
                return RELEASE.check(tag)

    def test_valid_tree_and_tag_pass(self):
        self.assertEqual(self.check("mkit-primitives-v0.1.0"), ("0.1.0", "0.5.0", "0.5"))

    def test_tag_must_match_primitives_version_not_the_train(self):
        with self.assertRaisesRegex(ValueError, "!= mkit-primitives version"):
            self.check("mkit-primitives-v0.5.0")

    def test_workspace_inherited_primitives_version_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            tree = Tree(directory)
            (tree.root / "rust/crates/mkit-primitives/Cargo.toml").write_text(
                '[package]\nname = "mkit-primitives"\nversion.workspace = true\n'
                '[dependencies]\nmkit-core = { version = "0.5" }\n')
            with tree.patched(), self.assertRaisesRegex(ValueError, "own literal"):
                RELEASE.check()

    def test_core_must_satisfy_the_declared_requirement(self):
        with self.assertRaisesRegex(ValueError, "does not satisfy"):
            self.check(core="0.6.0", requirement="0.5")

    def test_train_exclusion_is_required(self):
        with self.assertRaisesRegex(ValueError, "--exclude mkit-primitives"):
            self.check(exclude=False)

    def test_release_plz_must_not_release_the_crate(self):
        with self.assertRaisesRegex(ValueError, "release-plz"):
            self.check(release=True)

    def test_tag_needs_a_dated_section(self):
        with self.assertRaisesRegex(ValueError, "no dated"):
            self.check("mkit-primitives-v0.1.0", changelog="## [Unreleased]\n")
        with self.assertRaisesRegex(ValueError, "needs a"):
            self.check(changelog="## [Unreleased]\n## [0.1.0] - soon\n")

    def test_unreleased_section_is_required(self):
        with self.assertRaisesRegex(ValueError, "Unreleased"):
            self.check(changelog="## [0.1.0] - 2026-01-02\n")

    def test_multiline_train_publish_is_still_recognized(self):
        with tempfile.TemporaryDirectory() as directory:
            tree = Tree(directory)
            (tree.root / ".github/workflows/crates-publish.yml").write_text(
                "run: cargo publish --workspace \\\n  --exclude mkit-primitives \\\n  --locked\n")
            with tree.patched():
                RELEASE.check()

    def test_release_plz_entry_must_be_single_and_ungrouped(self):
        entry = '[[package]]\nname = "mkit-primitives"\nrelease = false\n'
        for text in ("", entry + entry, entry + 'version_group = "mkit"\n'):
            with self.subTest(text=text), tempfile.TemporaryDirectory() as directory:
                tree = Tree(directory)
                (tree.root / "rust/release-plz.toml").write_text(
                    text or '[[package]]\nname = "other"\n')
                with tree.patched(), self.assertRaisesRegex(ValueError, "release-plz"):
                    RELEASE.check()

    def test_guard_requires_tree_core_and_requirement_floor_live(self):
        asked = []

        def live(version):
            asked.append(version)

        with tempfile.TemporaryDirectory() as directory:
            with Tree(directory, core="0.5.3", requirement="0.5.1").patched(), \
                 patch.object(RELEASE, "core_released", side_effect=live):
                RELEASE.main(["guard", "mkit-primitives-v0.1.0"])
        self.assertEqual(asked, ["0.5.1", "0.5.3"])

    def test_guard_refuses_a_bad_tag_shape_and_an_unreleased_core(self):
        with tempfile.TemporaryDirectory() as directory:
            with Tree(directory).patched():
                with self.assertRaisesRegex(ValueError, "not mkit-primitives-vX.Y.Z"):
                    RELEASE.main(["guard", "v0.1.0"])
                with patch.object(RELEASE.BOUNDED, "download", side_effect=NOT_FOUND), \
                     self.assertRaisesRegex(ValueError, "not published"):
                    RELEASE.main(["guard", "mkit-primitives-v0.1.0"])

    def test_caret_requirements(self):
        allows = RELEASE.caret_allows
        self.assertTrue(allows("0", "0.9.0"))
        self.assertFalse(allows("0", "1.0.0"))
        self.assertTrue(allows("0.0", "0.0.9"))
        self.assertFalse(allows("0.0", "0.1.0"))
        self.assertTrue(allows("0.5", "0.5.9"))
        self.assertFalse(allows("0.5", "0.6.0"))
        self.assertFalse(allows("0.5.2", "0.5.1"))
        self.assertTrue(allows("1", "1.9.0"))
        self.assertFalse(allows("1.2", "2.0.0"))
        self.assertTrue(allows("0.0.3", "0.0.3"))
        self.assertFalse(allows("0.0.3", "0.0.4"))


class Registry(unittest.TestCase):
    def test_core_must_be_published_and_not_yanked(self):
        for answer, message in [(NOT_FOUND, "not published"),
                                (json.dumps({"version": {"yanked": True}}).encode(), "not published")]:
            with self.subTest(answer=message), \
                 patch.object(RELEASE.BOUNDED, "download", side_effect=[answer]):
                with self.assertRaisesRegex(ValueError, message):
                    RELEASE.core_released("0.5.0")
        with patch.object(RELEASE.BOUNDED, "download",
                          return_value=json.dumps({"version": {"yanked": False}}).encode()):
            RELEASE.core_released("0.5.0")

    def test_registry_errors_are_not_treated_as_absence(self):
        with patch.object(RELEASE.BOUNDED, "download",
                          side_effect=HTTPError("fixture", 503, "down", {}, None)):
            with self.assertRaises(HTTPError):
                RELEASE.core_released("0.5.0")
            with self.assertRaises(HTTPError):
                RELEASE.baseline("0.1.0")

    def test_baseline_is_none_before_first_publication(self):
        with patch.object(RELEASE.BOUNDED, "download", side_effect=NOT_FOUND):
            self.assertEqual(RELEASE.baseline("0.1.0"), "none")

    def baseline_for(self, current, versions):
        listing = [{"num": num, "yanked": yanked} for num, yanked in versions]
        with patch.object(RELEASE.BOUNDED, "download",
                          return_value=json.dumps({"versions": listing}).encode()):
            return RELEASE.baseline(current)

    def test_baseline_is_the_newest_live_version_older_than_current(self):
        versions = [("0.1.0", False), ("0.10.0", False), ("0.9.0", False),
                    ("0.11.0", True), ("0.12.0", False)]
        self.assertEqual(self.baseline_for("0.11.0", versions), "0.10.0")
        # A rerun of a published tag compares against its predecessor, not itself.
        self.assertEqual(self.baseline_for("0.12.0", versions), "0.10.0")
        self.assertEqual(self.baseline_for("0.1.0", versions), "none")

    def test_baseline_ignores_yanked_and_prerelease_versions(self):
        versions = [("0.1.0", True), ("0.2.0-rc.1", False)]
        self.assertEqual(self.baseline_for("0.3.0", versions), "none")


class PublishPolicy(unittest.TestCase):
    def run_policy(self, responses, dry_run=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "package").mkdir()
            (root / "package/mkit-primitives-0.1.0.crate").write_bytes(crate(FILES))
            with patch.object(RELEASE, "check", return_value=("0.1.0", "0.5.0", "0.5")), \
                 patch.object(RELEASE.subprocess, "run") as run, \
                 patch.object(RELEASE.subprocess, "check_output",
                              return_value=json.dumps({"target_directory": str(root)})), \
                 patch.object(RELEASE.BOUNDED, "download", side_effect=responses) as fetch:
                try:
                    RELEASE.publish(dry_run)
                finally:
                    self.commands = [call.args[0] for call in run.call_args_list]
                    self.requests = fetch.call_args_list

    def verbs(self):
        return [command[1] for command in self.commands]

    def test_absent_publishes_only_this_package(self):
        self.run_policy([NOT_FOUND])
        self.assertEqual(self.verbs(), ["package", "publish"])
        self.assertEqual(self.commands[1], ["cargo", "publish", "-p", "mkit-primitives", "--locked"])
        self.assertNotIn("--workspace", self.commands[1])

    def test_dry_run_never_uploads(self):
        self.run_policy([NOT_FOUND], dry_run=True)
        self.assertIn("--dry-run", self.commands[1])

    def test_identical_files_skip_despite_metadata_and_order(self):
        self.run_policy([b"exists", crate(list(reversed(FILES)), mtime=100)])
        self.assertEqual(self.verbs(), ["package"])

    def test_vcs_info_only_difference_skips(self):
        changed = [(n, b'{"git":{"sha1":"later"}}' if n == ".cargo_vcs_info.json" else d)
                   for n, d in FILES]
        self.run_policy([b"exists", crate(changed)])
        self.assertEqual(self.verbs(), ["package"])

    def test_any_other_difference_fails_without_publishing(self):
        for name in ("Cargo.toml", "CHANGELOG.md", "src/lib.rs", "fixtures/manifest.toml"):
            with self.subTest(name=name):
                changed = [(n, b"changed" if n == name else d) for n, d in FILES]
                with self.assertRaisesRegex(ValueError, "needs a version bump"):
                    self.run_policy([b"exists", crate(changed)])
                self.assertEqual(self.verbs(), ["package"])

    def test_missing_or_extra_files_fail(self):
        with self.assertRaisesRegex(ValueError, "needs a version bump"):
            self.run_policy([b"exists", crate(FILES[:2])])
        with self.assertRaisesRegex(ValueError, "needs a version bump"):
            self.run_policy([b"exists", crate(FILES + [("extra", b"x")])])

    def test_registry_and_download_errors_do_not_publish(self):
        with self.assertRaises(HTTPError):
            self.run_policy([HTTPError("fixture", 503, "down", {}, None)])
        self.assertEqual(self.verbs(), ["package"])
        with self.assertRaises(HTTPError):
            self.run_policy([b"exists", NOT_FOUND])
        self.assertEqual(self.verbs(), ["package"])


if __name__ == "__main__":
    unittest.main()
