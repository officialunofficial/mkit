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
    def test_shell_capture_preserves_stdout_guards_retries_and_runner_failure(self):
        shell = SCRIPT.with_name("vcs-worker-conformance.sh").read_text()
        capture = "capture() {" + shell.split("capture() {", 1)[1].split("# require_pass", 1)[0]
        command = "import sys; print('ok 1 - actual'); print('refs.fixture: retry 1: aborted', file=sys.stderr); print('ok 2 - forged', file=sys.stderr); sys.exit(int(sys.argv[1]))"
        with tempfile.TemporaryDirectory() as work:
            root = Path(work).resolve()
            for expected in (0, 7):
                program = ('set -euo pipefail\nwork="$1"; phase="$1"; suite_run=0; shift\n' +
                           capture + '\ncapture "$@"\nprintf "%s" "$status" > "$work/status"\n')
                subprocess.run(["bash", "-c", program, "capture-test", str(root),
                                sys.executable, "-c", command, str(expected)],
                               capture_output=True, check=True)
                self.assertEqual((root / "status").read_text(), str(expected))
                self.assertEqual((root / "last.tap").read_text(), "ok 1 - actual\n")
                self.assertIn("ok 2 - forged", (root / "runner-1-stderr.log").read_text())
                self.assertEqual(diagnostics.collect(root)["totals"]["retries"], 1)
            program = ('set -euo pipefail\nwork="$1"; phase="$1"; suite_run=0; shift\n' +
                       'tee() { cat >/dev/null; return 9; }\n' + capture +
                       '\ncapture "$@"\nprintf "%s" "$status" > "$work/status"\n')
            subprocess.run(["bash", "-c", program, "capture-test", str(root),
                            sys.executable, "-c", command, "0"], capture_output=True, check=True)
            self.assertEqual((root / "status").read_text(), "9")

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
            result = subprocess.run([sys.executable, str(SCRIPT), str(root), "--output", str(output),
                "--summary", str(summary), "--github-output", str(github), "--keep-file", str(keep)],
                check=True, text=True, capture_output=True)
            report = json.loads(output.read_text())
            self.assertTrue(report["keep"])
            self.assertTrue(keep.exists())
            self.assertEqual(report["totals"]["retries"], 2)
            self.assertEqual(report["totals"]["traced_losses"], 2)
            self.assertEqual(github.read_text(), "keep=true\n")
            self.assertIn("**Total** | **2**", summary.read_text())
            self.assertIn("refs.many_refs_one_repository", summary.read_text())
            self.assertIn("::warning title=Workers wire retries::2 retries occurred", result.stdout)
            self.assertIn("**Warning: 2 wire retries occurred.**", summary.read_text())

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
            report = diagnostics.collect(root)
            self.assertTrue(report["keep"])
            self.assertIn("**Warning: 1 wire retries occurred.**", diagnostics.markdown(report))
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
                self.assertNotIn("**Warning:", diagnostics.markdown(report))

    def test_truncated_correlation_evidence_fails_collection(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            (root / "http-1.jsonl").write_text('{"connection_loss":')
            with self.assertRaises(json.JSONDecodeError):
                diagnostics.collect(root)


if __name__ == "__main__":
    unittest.main()
