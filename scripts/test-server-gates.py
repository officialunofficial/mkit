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

    def test_workers_paid_executor_and_gate(self):
        yaml = (ROOT / ".github/workflows/workers.yml").read_text()
        paid = section(yaml, "paid-acceptance:")
        self.assertIn("runs-on: ubuntu-latest", paid)
        self.assertIn("timeout-minutes: 30", paid)
        self.assertIn("github.event_name == 'push' || needs.changes.outputs.workers == 'true'", paid)
        for command in ("python3 scripts/test-server-gates.py --hosted-only", "time python3 scripts/check-launch-feature-graph.py",
                        "time bash scripts/wasm-ruzstd-check.sh", "python3 scripts/paid-worker-acceptance.py",
                        "cargo build --locked --release --target wasm32-unknown-unknown"):
            self.assertRegex(paid, rf"(?m)^(?:        run: |          ){re.escape(command)}$")
        self.assertIn("working-directory: apps/embedded-worker/tests/embedding-conformance", paid)
        self.assertNotIn("__test-faults", paid)
        self.assertNotIn("continue-on-error", paid)
        self.assertEqual(paid.count("if:"), 2, "only path selection and failure artifacts may be conditional")
        gate = section(yaml, "workers-gate:")
        self.assertIn("needs: [ci, workspace, vcs-worker-conformance, paid-acceptance]", gate)
        self.assertIn('"${PAID}"', gate)
        conformance = section(yaml, "vcs-worker-conformance:")
        self.assertEqual(conformance.count("if:"), 3, "only path selection, summary and artifacts may be conditional")
        summary = section(conformance, "- name: Summarize connection losses and retries")
        self.assertIn("if: always()", summary)
        self.assertIn('scripts/workers-wire-diagnostics.py', summary)
        self.assertIn('python3 scripts/test-workers-wire-diagnostics.py', summary)
        upload = section(conformance, "- name: Upload Wrangler and Miniflare diagnostics")
        self.assertIn("if: always() && (failure() || steps.wire-diagnostics.outputs.keep == 'true')", upload)
        self.assertNotIn("continue-on-error", conformance)
        signer_tool = "cargo install b3sum --locked --version 1.8.5"
        deadline_test = "python3 scripts/connect-deadline-runtime.py"
        self.assertIn(signer_tool, conformance)
        self.assertIn(deadline_test, conformance)
        self.assertLess(conformance.index(signer_tool), conformance.index(deadline_test))
        self.assertIn("timeout-minutes: 20", section(conformance, "- name: Paid indexed slice failure, resume and commit"))
        self.assertIn("run: scripts/vcs-worker-conformance.sh --indexed-only", conformance)
        self.assertIn("run: scripts/vcs-worker-conformance.sh --test-faults --sharding single", conformance)
        self.assertIn("path: ${{ runner.temp }}/wire-logs/**", conformance)
        runtime = (ROOT / "scripts/workers-wire-runtime.cjs").read_text()
        self.assertIn("unsafeDirectSockets:", runtime)
        self.assertIn("unsafeGetDirectURL", runtime)
        for script in ("vcs-worker-conformance.sh", "connect-deadline-runtime.py"):
            self.assertIn("scripts/workers-wire-runtime.cjs", (ROOT / "scripts" / script).read_text())
        for command in ("run: scripts/vcs-worker-conformance.sh", "run: scripts/vcs-worker-conformance.sh --test-faults --multi",
                        "run: python3 scripts/connect-deadline-runtime.py --portable"):
            self.assertIn(command + "\n", conformance)
        self.assertNotIn("--no-build", conformance)
        for path in ("apps/embedded-worker/**", "rust/vendor/ruzstd/**", "scripts/paid-worker-acceptance.py",
                     "scripts/embedded-worker-hooks.py", "scripts/vcs-worker-launch-runtime.py",
                     "scripts/check-launch-feature-graph.py", "scripts/wasm-ruzstd-check.sh",
                     "rust/crates/mkit-core-wasm-check/**", "rust/tests/golden/pack-v2/**",
                     "apps/workspace-worker/package-lock.json", "cloudbuild/ci.yaml", "scripts/workers-wire-runtime.cjs"):
            self.assertEqual(yaml.count(f"- '{path}'"), 2, path)


if __name__ == "__main__":
    if "--hosted-only" in sys.argv:
        suite = unittest.defaultTestLoader.loadTestsFromNames([
            "test_cloud_linux_allocator_executor", "test_workers_paid_executor_and_gate"], ServerGates)
        result = unittest.TextTestRunner().run(suite)
        sys.exit(not result.wasSuccessful())
    unittest.main()
