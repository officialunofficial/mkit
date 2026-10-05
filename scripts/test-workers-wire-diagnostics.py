#!/usr/bin/env python3
"""Exercise artifact selection using recovered, terminal and clean wire logs."""
# SPDX-License-Identifier: MIT OR Apache-2.0
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True

SCRIPT = Path(__file__).with_name("workers-wire-diagnostics.py")
SPEC = importlib.util.spec_from_file_location("diagnostics", SCRIPT)
diagnostics = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(diagnostics)


class WireDiagnostics(unittest.TestCase):
    def test_success_with_retries_keeps_all_phases_without_double_counting_tap(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            for phase in ("suite", "multi"):
                directory = root / phase
                directory.mkdir()
                (directory / "runner-1.log").write_text(
                    "refs.many_refs_one_repository: retry 1: Network connection lost\n"
                    "ok 1 - refs.many_refs_one_repository # retries=1\n")
                (directory / "http-1.jsonl").write_text(json.dumps({
                    "case": "refs.many_refs_one_repository", "connection_loss": True}) + "\n")
            (root / "last.tap").write_text("refs.many_refs_one_repository: retry 1: duplicate\n")
            output, summary, github, keep = [root / name for name in ("report.json", "summary.md", "output", "keep")]
            subprocess.run([sys.executable, str(SCRIPT), str(root), "--output", str(output),
                "--summary", str(summary), "--github-output", str(github), "--keep-file", str(keep)], check=True)
            report = json.loads(output.read_text())
            self.assertTrue(report["keep"])
            self.assertTrue(keep.exists())
            self.assertEqual(report["totals"]["retries"], 2)
            self.assertEqual(report["totals"]["traced_losses"], 2)
            self.assertEqual(github.read_text(), "keep=true\n")
            self.assertIn("**Total** | **2**", summary.read_text())
            self.assertIn("refs.many_refs_one_repository", summary.read_text())

    def test_terminal_loss_and_failed_case_retry_are_retained_without_pass_note(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            (root / "runner-1.log").write_text(
                "refs.many_refs_one_repository: retry 1: unknown (HTTP 500): Network connection lost\n"
                "not ok 1 - refs.many_refs_one_repository\n")
            (root / "wrangler.log").write_text("Error inside ProxyWorker: Network connection lost\n")
            report = diagnostics.collect(root)
            self.assertTrue(report["keep"])
            self.assertEqual(report["totals"]["retries"], 1)
            self.assertEqual(report["totals"]["runtime_loss_lines"], 1)
            (root / "runner-1.log").unlink()
            self.assertTrue(diagnostics.collect(root)["keep"])

    def test_non_loss_retry_and_debug_only_loss_are_retained(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            path = root / "runner-1.log"
            path.write_text("list.large_response_within_limit: retry 1: aborted\n")
            self.assertTrue(diagnostics.collect(root)["keep"])
            path.unlink()
            (root / "wrangler-debug.log").write_text("Network connection lost\n")
            self.assertTrue(diagnostics.collect(root)["keep"])

    def test_clean_and_absent_logs_show_zero_and_do_not_select_artifact(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            for logs in (False, True):
                if logs:
                    (root / "runner-1.log").write_text("ok 1 - refs.many_refs_one_repository\n")
                report = diagnostics.collect(root)
                self.assertFalse(report["keep"])
                self.assertEqual(report["totals"]["retries"], 0)
                self.assertIn("**Total** | **0**", diagnostics.markdown(report))

    def test_truncated_correlation_evidence_fails_collection(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            (root / "http-1.jsonl").write_text('{"connection_loss":')
            with self.assertRaises(json.JSONDecodeError):
                diagnostics.collect(root)


if __name__ == "__main__":
    unittest.main()
