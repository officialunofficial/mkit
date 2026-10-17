#!/usr/bin/env python3
"""Regression tests for resolved stability inventories and scoped compilation."""
import argparse
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("inventory", HERE / "check-primitives-stability-inventory.py")
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


def item(name, kind, body, visibility="public"):
    return {"name": name, "visibility": visibility, "inner": {kind: body}}


def document():
    return {"root": "0", "index": {"0": item("crate", "module", {"items": []})}}


class InventoryTests(unittest.TestCase):
    def surfaces(self, normal):
        return {level: copy.deepcopy(normal if level == "ALPHA" else document()) for level in checker.LEVELS}

    def test_inherited_macro_module_members_are_recorded(self):
        normal = document()
        normal["index"].update({
            "1": item("api", "module", {"items": ["2", "6", "9", "10"]}),
            "2": item("Record", "struct", {"kind": {"plain": {"fields": ["3"]}}, "impls": ["4"]}),
            "3": item("value", "struct_field", "u8"),
            "4": item(None, "impl", {"trait": None, "items": ["5"]}, "default"),
            "5": item("read", "function", {}),
            "6": item("State", "enum", {"variants": ["7"], "impls": []}),
            "7": item("Ready", "variant", {"kind": {"tuple": ["8"]}}, "default"),
            "8": item("0", "struct_field", "u8", "default"),
            "9": item("Export", "use", {"name": "Export", "id": None, "is_glob": False}),
            "10": item("Reader", "trait", {"items": ["11"], "implementations": []}),
            "11": item("read", "function", {}, "default"),
        })
        normal["index"]["0"]["inner"]["module"]["items"] = ["1"]
        recorded = checker.check(self.surfaces(normal))
        for path, kind in (("api::Record::value", "struct_field"),
                           ("api::Record::impl:inherent::read", "function"),
                           ("api::State::Ready::0", "struct_field"),
                           ("api::Reader::read", "function"), ("api::Export", "use")):
            self.assertEqual(recorded[(path, kind, None)], "ALPHA")

    def test_alias_and_glob_follow_private_module_targets(self):
        normal = document()
        normal["index"]["0"]["inner"]["module"]["items"] = ["1", "2"]
        normal["index"].update({
            "1": item("Alias", "use", {"name": "Alias", "id": "3", "is_glob": False}),
            "2": item("*", "use", {"name": "*", "id": "6", "is_glob": True}),
            "3": item("Hidden", "struct", {"kind": "unit", "impls": ["4"]}),
            "4": item(None, "impl", {"trait": None, "items": ["5"]}, "default"),
            "5": item("get", "function", {}),
            "6": item("private", "module", {"items": ["7"]}, "crate"),
            "7": item("imported", "function", {}),
        })
        surface = checker.inventory(normal)
        self.assertIn(("Alias::impl:inherent::get", "function", None), surface)
        self.assertIn(("imported", "function", None), surface)

    def test_unmarked_root_reexport_is_rejected(self):
        normal = document()
        normal["index"]["0"]["inner"]["module"]["items"] = ["1"]
        normal["index"]["1"] = item("Export", "use", {"name": "Export", "id": None})
        with self.assertRaisesRegex(ValueError, "unmarked public API"):
            checker.check({level: normal for level in checker.LEVELS})

    def test_unmarked_public_method_is_rejected(self):
        normal = document()
        normal["index"]["0"]["inner"]["module"]["items"] = ["1"]
        normal["index"].update({
            "1": item("Record", "struct", {"kind": "unit", "impls": ["2"]}),
            "2": item(None, "impl", {"trait": None, "items": ["3"]}, "default"),
            "3": item("unmarked", "function", {}),
        })
        with self.assertRaisesRegex(ValueError, "impl:inherent::unmarked"):
            checker.check({level: normal for level in checker.LEVELS})

    def test_higher_level_and_cfg_only_api_are_recorded_or_rejected(self):
        normal = document()
        normal["index"]["0"]["inner"]["module"]["items"] = ["1"]
        normal["index"]["1"] = item("beta", "function", {})
        surfaces = self.surfaces(normal)
        surfaces["BETA"] = normal
        self.assertEqual(checker.check(surfaces)[("beta", "function", None)], "BETA")
        surfaces["GAMMA"] = copy.deepcopy(normal)
        surfaces["GAMMA"]["index"]["1"]["name"] = "only_gamma"
        with self.assertRaisesRegex(ValueError, "appears only at GAMMA"):
            checker.check(surfaces)

    def test_same_named_constrained_methods_remain_distinct(self):
        normal = document()
        normal["index"]["0"]["inner"]["module"]["items"] = ["1"]
        normal["index"].update({
            "1": item("Record", "struct", {"kind": "unit", "impls": ["2", "4"]}),
            "2": item(None, "impl", {"trait": None, "items": ["3"]}, "default"),
            "3": item("new", "function", {}),
            "4": item(None, "impl", {"trait": None, "items": ["5"]}, "default"),
            "5": item("new", "function", {}),
        })
        for identifier, line in (("3", 2), ("5", 4)):
            normal["index"][identifier]["span"] = {"filename": "src/lib.rs", "begin": [line, 0], "end": [line, 20]}
        methods = [key for key in checker.inventory(normal) if key[0].endswith("::new")]
        self.assertEqual(len(methods), 2)

    def test_empty_canary_and_private_items(self):
        with self.assertRaisesRegex(ValueError, "canary"):
            checker.check({level: document() for level in checker.LEVELS})
        private = document()
        private["index"]["0"]["inner"]["module"]["items"] = ["1"]
        private["index"]["1"] = item("private", "function", {}, "crate")
        self.assertEqual(checker.inventory(private), set())

    def test_wrapper_scopes_rustc_and_rustdoc(self):
        for mode in ("rustc", "rustdoc"):
            for crate in ("mkit_primitives", "mkit_core"):
                env = dict(os.environ, MKIT_PRIMITIVES_MIN_STABILITY="GAMMA")
                command = [str(HERE / "primitives-stability-rustc.py")]
                if mode == "rustdoc":
                    env["MKIT_PRIMITIVES_REAL_RUSTDOC"] = "/bin/echo"
                else:
                    env.pop("MKIT_PRIMITIVES_REAL_RUSTDOC", None)
                    command.append("/bin/echo")
                output = subprocess.check_output(command + ["--crate-name", crate], env=env, text=True)
                self.assertEqual("--cfg commonware_stability_GAMMA" in output, crate == "mkit_primitives")


def compiler_tests():
    # Pin the cfg emitted by commonware's stability macros. The production
    # inventory exercises the real proc macros, including external modules.
    source = '''
#[cfg(not(any(commonware_stability_BETA, commonware_stability_GAMMA,
commonware_stability_DELTA, commonware_stability_EPSILON, commonware_stability_RESERVED)))]
pub struct Alpha;
#[cfg(not(any(commonware_stability_DELTA, commonware_stability_EPSILON,
commonware_stability_RESERVED)))]
pub fn gamma_uses_alpha(_: Alpha) {}
'''
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory)
        (path / "lib.rs").write_text(source)
        args = [str(HERE / "primitives-stability-rustc.py"), "rustc", "--crate-name", "mkit_primitives",
                "--crate-type", "lib", "--emit", "metadata", str(path / "lib.rs"), "--out-dir", directory]
        env = dict(os.environ, MKIT_PRIMITIVES_MIN_STABILITY="ALPHA")
        env.pop("MKIT_PRIMITIVES_REAL_RUSTDOC", None)
        subprocess.run(args, env=env, check=True)
        env["MKIT_PRIMITIVES_MIN_STABILITY"] = "GAMMA"
        result = subprocess.run(args, env=env, text=True, capture_output=True)
        if result.returncode == 0 or "cannot find type `Alpha`" not in result.stderr:
            raise AssertionError("GAMMA-to-ALPHA dependency was not rejected: " + result.stderr)
    print("scoped GAMMA-to-ALPHA compile-fail regression passed")


def rustdoc_tests(toolchain):
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory)
        source = path / "lib.rs"
        source.write_text("pub struct Unmarked; impl Unmarked { pub fn uncovered() {} } "
                          '#[doc(hidden)] pub use Unmarked as Export;')
        subprocess.run(["rustup", "run", toolchain, "rustdoc", "--crate-name", "inventory_probe",
                        "--edition", "2024", "-Z", "unstable-options", "--output-format", "json",
                        "--document-hidden-items", "--out-dir", directory, str(source)], check=True)
        actual = json.loads((path / "inventory_probe.json").read_text())
        try:
            checker.check({level: actual for level in checker.LEVELS})
        except ValueError as error:
            if "uncovered" not in str(error) or "Export" not in str(error):
                raise AssertionError("real rustdoc method/reexport missing from rejection") from error
        else:
            raise AssertionError("real rustdoc unmarked API accepted")
    print("real rustdoc unmarked method/reexport regression passed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--compiler-tests", action="store_true")
    parser.add_argument("--rustdoc-tests", metavar="PINNED_TOOLCHAIN")
    args = parser.parse_args()
    result = unittest.TextTestRunner().run(unittest.defaultTestLoader.loadTestsFromTestCase(InventoryTests))
    if not result.wasSuccessful():
        sys.exit(1)
    if args.compiler_tests:
        compiler_tests()
    if args.rustdoc_tests:
        rustdoc_tests(args.rustdoc_tests)
