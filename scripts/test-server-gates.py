#!/usr/bin/env python3
"""The PR gate entry points must execute the isolated allocator regression."""
from pathlib import Path
import os
import re
import subprocess
import sys
import tempfile
import textwrap
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
        self.assertIn("waitFor: ['-']", allocator)
        self.assertIn("timeout: 1500s", allocator)
        self.assertIn("        cd rust\n", allocator)
        self.assertIn("        cargo test --locked -p mkit-server --no-default-features --features memory,pack-ruzstd --test zstd_slice_heap_bounds -- --ignored --test-threads=1 --nocapture", allocator)
        self.assertNotIn("--all-features", allocator)
        self.assertNotIn("allowFailure", allocator)
        self.assertNotIn("allowExitCodes", allocator)
        guard, = [step for step in steps if "\n    id: server-gates\n" in step]
        self.assertIn("entrypoint: python3", guard)
        self.assertIn("args: [scripts/test-server-gates.py, --hosted-only]", guard)

    def ci_steps(self):
        yaml = (ROOT / "cloudbuild/ci.yaml").read_text()
        steps = re.split(r"(?m)^  - name: ", yaml)[1:]
        return {re.search(r"(?m)^    id: (\S+)$", s).group(1): s for s in steps}

    def test_cloud_workspace_test_compilation_is_serial(self):
        steps = self.ci_steps()
        archive = steps["nextest-archive"]
        # One archive build compiles every workspace test binary. The serial
        # Cargo job bound reserves memory for the unified server lib-test.
        self.assertRegex(
            archive,
            r"(?m)^ +cargo nextest archive --locked --workspace --all-features --build-jobs 1 --archive-file /workspace/nextest-archive\.tar\.zst(?: |$)",
        )
        self.assertIn('"CARGO_PROFILE_TEST_CODEGEN_UNITS=256"', archive)
        self.assertIn('"RUSTC_WRAPPER=/workspace/scripts/ci-rustc-wrapper.sh"', archive)
        # The partitions and the ignored lane only run from the archive.
        for step_id in ("nextest-1", "nextest-2", "nextest-3", "ignored-lane"):
            with self.subTest(step=step_id):
                step = steps[step_id]
                self.assertIn("--archive-file /workspace/nextest-archive.tar.zst", step)
                self.assertNotRegex(step, r"cargo (build|test|check|clippy)\b")
        for step in steps.values():
            self.assertNotIn("allowFailure", step)
            self.assertNotIn("allowExitCodes", step)

    def test_cloud_parallel_step_graph(self):
        steps = self.ci_steps()
        ids = set(steps)
        for step_id, step in steps.items():
            match = re.search(r"(?m)^    waitFor: \[(.*)\]$", step)
            self.assertIsNotNone(match, f"{step_id} has no waitFor")
            for dep in [d.strip().strip("'\"") for d in match.group(1).split(",")]:
                self.assertTrue(dep == "-" or dep in ids, f"{step_id} waits for unknown {dep}")
        self.assertNotIn("check", ids)
        # Partitions cover count:1/N .. count:N/N exactly once.
        parts = sorted(i for i in ids if re.fullmatch(r"nextest-\d+", i))
        self.assertTrue(parts)
        for index, step_id in enumerate(parts, 1):
            step = steps[step_id]
            self.assertIn(f"--partition count:{index}/{len(parts)} ", step)
            # contrib/signers is built before any workspace test runs.
            self.assertIn("waitFor: [nextest-archive, signers-bin]", step)
            self.assertIn("source /workspace/scripts/ci-swtpm-setup.sh", step)
            self.assertIn('"MKIT_TEST_STRICT=1"', step)
        self.assertIn("waitFor: [nextest-archive]", steps["ignored-lane"])
        self.assertIn("source /workspace/scripts/ci-swtpm-setup.sh", steps["signers"])
        # The build-only prerequisite is separate from the signers gates, so a
        # gate failure cannot skip the partitions.
        self.assertIn("cargo build --locked --all-features", steps["signers-bin"])
        self.assertNotIn("cargo clippy", steps["signers-bin"])
        self.assertNotIn("nextest run", steps["signers-bin"])
        self.assertNotIn("CARGO_TARGET_DIR", steps["signers-bin"])
        for step_id, step in steps.items():
            self.assertNotRegex(step, r"(?m)^    waitFor: \[.*(?<![\w-])signers(?![\w-]).*\]$", step_id)
        # The signers step must keep the default target directory.
        self.assertNotIn("CARGO_TARGET_DIR", steps["signers"])
        for step_id in ("signers", "apps-workers", "indexed", "tests-misc", "release-cli"):
            self.assertIn('"MKIT_TEST_STRICT=1"', steps[step_id])
        self.assertIn('"MKIT_TEST_EXTRACT_CHAIN=1"', steps["indexed"])
        swtpm = (ROOT / "scripts/ci-swtpm-setup.sh").read_text()
        self.assertIn("export MKIT_TEST_STRICT=1", swtpm)
        self.assertIn("TPM2_Startup", swtpm)

    def cloud_rustc_wrapper(self):
        path = ROOT / "scripts/ci-rustc-wrapper.sh"
        self.assertTrue(os.access(path, os.X_OK), "wrapper must be executable")
        for step_id, step in self.ci_steps().items():
            if step_id != "primitives" and '"RUSTC_WRAPPER=' in step:
                with self.subTest(step=step_id):
                    self.assertIn('"RUSTC_WRAPPER=/workspace/scripts/ci-rustc-wrapper.sh"', step)
        return path.read_text()

    def test_cloud_step_scripts_fit_argument_limit(self):
        yaml = (ROOT / "cloudbuild/ci.yaml").read_text()
        steps = re.split(r"(?m)^  - name: ", yaml)[1:]
        for step in steps:
            if "entrypoint: bash" not in step:
                continue
            match = re.search(r"(?m)^      - \|\n((?:        [^\n]*\n|\n)*)", step)
            self.assertIsNotNone(match)
            script = textwrap.dedent(match.group(1))
            # Cloud Build rejects any step argument above 10,000 characters.
            # Count UTF-8 bytes conservatively so non-ASCII comments fit too.
            self.assertLessEqual(len(script.encode()), 10_000)

    def test_cloud_server_lib_test_preserves_cargo_jobserver(self):
        wrapper = self.cloud_rustc_wrapper()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = root / "wrapper"
            script.write_text(wrapper)
            compiler = root / "rustc"
            for path, label in ((compiler, "compiler"), (root / "sccache", "sccache")):
                path.write_text(f'#!/bin/sh\nprintf "{label}\\n"\nprintf "%s\\n" "$@"\n')
                path.chmod(0o755)
            env = dict(os.environ, PATH=directory + os.pathsep + os.environ["PATH"])
            target = ["--crate-name", "mkit_server", "crates/mkit-server/src/lib.rs",
                      "--test", "--emit=dep-info,link", "argument with spaces"]
            cases = [
                (target, True),
                (target[3:5] + target[:3] + target[5:], True),
                ([arg for arg in target if arg != "--test"], False),
                ([arg.replace("mkit_server", "another_crate") for arg in target], False),
                ([arg.replace("src/lib.rs", "tests/mkit_server.rs") for arg in target], False),
                ([arg.replace("dep-info,link", "dep-info,metadata") for arg in target], False),
                (["-vV"], False),
            ]
            for args, direct in cases:
                with self.subTest(args=args):
                    result = subprocess.run(["bash", str(script), str(compiler), *args],
                                            env=env, text=True, capture_output=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    expected = ["compiler", *args] if direct else ["sccache", str(compiler), *args]
                    self.assertEqual(result.stdout.splitlines(), expected)
                    self.assertEqual(result.stderr, "")

    def test_cloud_wrapper_failure_is_visible_and_fails(self):
        wrapper = self.cloud_rustc_wrapper()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = root / "wrapper"
            script.write_text(wrapper)
            cache = root / "sccache"
            cache.write_text('#!/bin/sh\necho "sccache: Compile terminated by signal 9"\n'
                             'echo "wrapper stderr diagnostic" >&2\nexit 2\n')
            cache.chmod(0o755)
            env = dict(os.environ, PATH=directory + os.pathsep + os.environ["PATH"])
            result = subprocess.run(["bash", str(script), "rustc", "--crate-name", "other"],
                                    env=env, text=True, capture_output=True)
            self.assertEqual(result.returncode, 2)
            # Cargo's JSON renderer discards this stdout message. Forwarding it
            # to stderr preserves the real signal without masking the failure.
            self.assertIn("sccache: Compile terminated by signal 9", result.stdout)
            self.assertIn("sccache: Compile terminated by signal 9", result.stderr)
            self.assertIn("wrapper stderr diagnostic", result.stderr)

    def test_cloud_nextest_reports_every_failure(self):
        steps = self.ci_steps()
        gated = ("lint", "signers", "apps-workers", "nextest-archive", "nextest-1",
                 "nextest-2", "nextest-3", "ignored-lane", "indexed", "tests-misc",
                 "release-cli", "wasm-gates")
        for step_id in gated:
            step = steps[step_id]
            with self.subTest(step=step_id):
                # Assemble each test command, following `\` continuations.
                commands = []
                lines = step.splitlines()
                index = 0
                while index < len(lines):
                    if lines[index].lstrip().startswith("#"):
                        index += 1
                        continue
                    if "nextest run" in lines[index] or "cargo test" in lines[index]:
                        command = lines[index]
                        while command.rstrip().endswith("\\"):
                            index += 1
                            command += lines[index]
                        commands.append(command)
                    index += 1
                if step_id not in ("lint", "wasm-gates", "nextest-archive"):
                    self.assertTrue(commands)
                for command in commands:
                    # No failure is suppressed or skipped: each test command
                    # records into the step's aggregate status instead of
                    # aborting (`set -e`) or being swallowed (`|| true`).
                    self.assertNotIn("|| true", command)
                    self.assertRegex(command, r"\|\| (failed|status)=1\s*$")
                    if "nextest run" in command:
                        self.assertIn("--no-fail-fast", command)
                # Inside an aggregated subshell (between `failed=0` and its
                # `exit "$failed"`), `set -e` is inert, so every command must
                # record into `failed` — a dropped recorder would silently
                # swallow that gate's failure. The subshell's `( cd` opener
                # must abort loudly (`|| exit 1`) instead of cascading, its
                # `)` closer must record (`|| status=1`) instead of
                # hard-aborting the step, and top-level `bash scripts/` gates
                # must record too.
                aggregated = False
                pending_closer = False
                last_cd = None
                for line in lines:
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    if pending_closer:
                        self.assertEqual(") || status=1", stripped)
                        pending_closer = False
                    if re.match(r"\(\s*cd\s", stripped):
                        last_cd = stripped
                    elif stripped.startswith(")"):
                        last_cd = None
                    if re.match(r"failed\s*=\s*0\b", stripped):
                        # A subshell containing a `failed=0` region is an
                        # aggregated one: its `cd` must abort loudly, not
                        # cascade "can't find Cargo.toml" noise.
                        self.assertTrue(last_cd and last_cd.endswith("|| exit 1"),
                                        f"aggregated subshell cd does not abort loudly: {last_cd}")
                        last_cd = None
                        aggregated = True
                    elif re.match(r'exit\s+"?\$\{?failed\}?"?\s*$', stripped):
                        aggregated = False
                        pending_closer = True
                    elif aggregated:
                        # Heuristic: shell keywords are allowlisted even
                        # though a command hidden in an `if`/`until`/`while`
                        # condition would swallow its status unrecorded.
                        self.assertTrue(
                            stripped.endswith("|| failed=1")
                            or stripped == "failed=1"
                            or re.match(r"(echo|if|elif|else|fi|for|do|done|while|then|until|case|esac)\b", stripped),
                            f"command in aggregated subshell does not record failure: {stripped}")
                    elif line.startswith("        bash scripts/"):
                        # Top-level gates only (8-space script indent): a
                        # `|| status=1` inside a subshell would set a
                        # subshell-local variable that is discarded. New
                        # top-level gate spellings need this check extended.
                        self.assertTrue(stripped.endswith("|| status=1"),
                                        f"top-level gate does not record failure: {stripped}")
                self.assertFalse(pending_closer, "aggregated subshell missing its `) || status=1` closer")
                self.assertFalse(aggregated, "aggregated subshell missing its `exit \"$failed\"` marker")
                self.assertNotIn("allowFailure", step)
                self.assertNotIn("allowExitCodes", step)

    def test_native_wire_executor_and_gate(self):
        yaml = (ROOT / "cloudbuild/server.yaml").read_text()
        lines = yaml.splitlines()
        start = next(i for i, line in enumerate(lines)
                     if line.strip() == "id: native-wire-conformance")
        end = next((i for i in range(start + 1, len(lines))
                    if lines[i].startswith("  - name:")), len(lines))
        native = "\n".join(line for line in lines[start:end]
                           if not line.lstrip().startswith("#"))
        self.assertNotIn("allowFailure", native)
        self.assertNotIn("allowExitCodes", native)
        self.assertIn("--features test-host --lib --test test_host --test test_host_migrations --test test_host_regressions -j 3 --success-output immediate --failure-output immediate --no-fail-fast", native)
        self.assertIn("python3 scripts/check-launch-feature-graph.py", native)
        self.assertIn("bash scripts/wasm-ruzstd-check.sh", native)
        self.assertIn("python3 scripts/test-server-gates.py --hosted-only", native)


if __name__ == "__main__":
    if "--hosted-only" in sys.argv:
        suite = unittest.defaultTestLoader.loadTestsFromNames([
            "test_cloud_linux_allocator_executor", "test_cloud_workspace_test_compilation_is_serial",
            "test_cloud_parallel_step_graph",
            "test_cloud_step_scripts_fit_argument_limit",
            "test_cloud_server_lib_test_preserves_cargo_jobserver",
            "test_cloud_wrapper_failure_is_visible_and_fails",
            "test_cloud_nextest_reports_every_failure", "test_native_wire_executor_and_gate"], ServerGates)
        result = unittest.TextTestRunner().run(suite)
        sys.exit(not result.wasSuccessful())
    unittest.main()
