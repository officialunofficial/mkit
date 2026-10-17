#!/usr/bin/env python3
"""The PR gate entry points must execute the isolated allocator regression."""
from pathlib import Path
import re
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]


def section(text, header):
    """Read an indentation-delimited executor block, excluding YAML comments."""
    lines = text.splitlines()
    start = next(i for i, line in enumerate(lines) if line.strip() == header)
    indent = len(lines[start]) - len(lines[start].lstrip())
    end = next((i for i in range(start + 1, len(lines))
                if lines[i].strip() and not lines[i].lstrip().startswith("#")
                and len(lines[i]) - len(lines[i].lstrip()) <= indent), len(lines))
    return "\n".join(line for line in lines[start:end] if not line.lstrip().startswith("#"))


class ServerGates(unittest.TestCase):
    def test_allocator_is_mandatory_in_pr_gates(self):
        for recipe in ("ci-linux", "ci-macos", "ci-server"):
            with self.subTest(recipe=recipe):
                body = subprocess.check_output(["just", "--show", recipe], text=True)
                self.assertIn("just ci-server-allocator", body)
        body = subprocess.check_output(["just", "--show", "ci-server-allocator"], text=True)
        for flag in ("--no-default-features", "memory,pack-ruzstd",
                     "--test zstd_slice_heap_bounds", "--ignored", "--test-threads=1"):
            self.assertIn(flag, body)

    def test_cloud_linux_allocator_executor(self):
        yaml = (ROOT / "cloudbuild/ci.yaml").read_text()
        # Locate by id, then the enclosing Cloud Build step (not a comment or recipe).
        steps = re.split(r"(?m)^  - name: ", yaml)[1:]
        allocator, = [step for step in steps if "\n    id: server-allocator\n" in step]
        self.assertIn("entrypoint: bash", allocator)
        self.assertIn("waitFor: [check]", allocator)
        self.assertIn("timeout: 600s", allocator)
        self.assertIn("        cd rust\n", allocator)
        self.assertIn("        cargo test --locked -p mkit-server --no-default-features --features memory,pack-ruzstd --test zstd_slice_heap_bounds -- --ignored --test-threads=1 --nocapture", allocator)
        self.assertNotIn("--all-features", allocator)
        self.assertNotIn("allowFailure", allocator)
        self.assertNotIn("allowExitCodes", allocator)
        guard, = [step for step in steps if "\n    id: server-gates\n" in step]
        self.assertIn("entrypoint: python3", guard)
        self.assertIn("args: [scripts/test-server-gates.py, --hosted-only]", guard)

    def test_cloud_workspace_test_compilation_is_serial(self):
        yaml = (ROOT / "cloudbuild/ci.yaml").read_text()
        steps = re.split(r"(?m)^  - name: ", yaml)[1:]
        for step_id in ("check", "ignored-lane"):
            step, = [s for s in steps if f"\n    id: {step_id}\n" in s]
            with self.subTest(step=step_id):
                self.assertRegex(
                    step,
                    r"(?m)^ +cargo nextest run --locked --workspace --all-features --build-jobs 1(?: |$)",
                )
                self.assertIn('"CARGO_PROFILE_TEST_CODEGEN_UNITS=256"', step)
                self.assertNotIn("allowFailure", step)
                self.assertNotIn("allowExitCodes", step)

    def test_native_wire_executor_and_gate(self):
        yaml = (ROOT / ".github/workflows/rust.yml").read_text()
        native = section(yaml, "native-wire-conformance:")
        self.assertIn("runs-on: ubuntu-latest", native)
        self.assertNotIn("if:", native)
        self.assertNotIn("continue-on-error", native)
        self.assertIn("--features test-host --lib --test test_host --test test_host_migrations --test test_host_regressions -j 3 --success-output immediate --failure-output immediate --no-fail-fast", native)
        self.assertIn("python3 scripts/check-launch-feature-graph.py", native)
        self.assertIn("bash scripts/wasm-ruzstd-check.sh", native)
        self.assertIn("python3 scripts/test-server-gates.py --hosted-only", native)
        gate = section(yaml, "ci-gate:")
        self.assertIn("native-wire-conformance]", gate)
        self.assertIn("needs.native-wire-conformance.result", gate)
        self.assertIn('"${NATIVE_WIRE}"', gate)


if __name__ == "__main__":
    if "--hosted-only" in sys.argv:
        suite = unittest.defaultTestLoader.loadTestsFromNames([
            "test_cloud_linux_allocator_executor", "test_cloud_workspace_test_compilation_is_serial",
            "test_native_wire_executor_and_gate"], ServerGates)
        result = unittest.TextTestRunner().run(suite)
        sys.exit(not result.wasSuccessful())
    unittest.main()
