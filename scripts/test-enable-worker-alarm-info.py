#!/usr/bin/env python3
"""Check the opt-in alarm wrapper without building or running a Worker."""
# SPDX-License-Identifier: MIT OR Apache-2.0
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
SCRIPT = Path(__file__).with_name("enable-worker-alarm-info.py")
SPEC = importlib.util.spec_from_file_location("alarm_wrapper", SCRIPT)
wrapper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(wrapper)


def fixture(missing=None):
    return (
        "export const other = Symbol('other');\n"
        "export default {fetch: () => 'default'};\n"
        "class Base {\n"
        "  constructor(...args) { this.args = args; }\n"
        "  static futureStatic() { return 'static'; }\n"
        "  fetch(...args) { return args; }\n"
        "  connect(...args) { return args; }\n"
        "  webSocketMessage(...args) { return args; }\n"
        "  webSocketClose(...args) { return args; }\n"
        "  webSocketError(...args) { return args; }\n"
        "  futureMethod(...args) { return args; }\n"
        "  alarm() { throw new Error('original alarm must not run'); }\n"
        "}\n"
        + "".join(
            f"export class {name} extends Base {{\n"
            + "  alarm() { return super.alarm(); }\n"
            + ("" if name == missing else "  alarmWithInfo(info) { return Promise.resolve(info); }\n")
            + "}\n"
            for name in wrapper.CLASSES
        )
        + "export const originals = new Map([\n"
        + "".join(f"  ['{name}', Object.getOwnPropertyDescriptors({name}.prototype)],\n"
                  for name in wrapper.CLASSES)
        + "]);\n"
    )


class AlarmWrapperTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.shim = self.root / "shim.mjs"
        self.shim.write_text(fixture())

    def node(self, source):
        return subprocess.run(
            ["node", "--input-type=module", "-e", source],
            cwd=self.root, text=True, capture_output=True, check=False,
        )

    def test_forwards_metadata_and_preserves_all_other_exports(self):
        original = self.shim.read_bytes()
        original_mode = self.shim.stat().st_mode
        wrapper.enable(self.shim)
        self.assertEqual(self.shim.stat().st_mode, original_mode)
        self.assertEqual((self.root / wrapper.BASE_NAME).read_bytes(), original)
        result = self.node(
            "import assert from 'node:assert/strict';\n"
            "import * as wrapped from './shim.mjs';\n"
            "import * as base from './alarm-base.mjs';\n"
            "assert.equal(wrapped.default, base.default);\n"
            "assert.equal(wrapped.other, base.other);\n"
            f"for (const name of {json.dumps(wrapper.CLASSES)}) {{\n"
            "  const object = new wrapped[name]('state', {env: true});\n"
            "  assert.equal(wrapped[name], base[name]);\n"
            "  const previous = base.originals.get(name);\n"
            "  const current = Object.getOwnPropertyDescriptors(wrapped[name].prototype);\n"
            "  assert.deepEqual(Reflect.ownKeys(current), Reflect.ownKeys(previous));\n"
            "  assert.notEqual(current.alarm.value, previous.alarm.value);\n"
            "  for (const key of Reflect.ownKeys(previous)) {\n"
            "    if (key === 'alarm') {\n"
            "      for (const flag of ['writable', 'enumerable', 'configurable'])\n"
            "        assert.equal(current.alarm[flag], previous.alarm[flag]);\n"
            "    } else assert.deepEqual(current[key], previous[key]);\n"
            "  }\n"
            "  assert.ok(object instanceof base[name]);\n"
            "  assert.deepEqual(object.args, ['state', {env: true}]);\n"
            "  assert.equal(wrapped[name].futureStatic(), 'static');\n"
            "  for (const method of ['fetch', 'connect', 'webSocketMessage', "
            "'webSocketClose', 'webSocketError', 'futureMethod']) {\n"
            "    assert.equal(object[method], base[name].prototype[method]);\n"
            "    assert.deepEqual(object[method](1, 2), [1, 2]);\n"
            "  }\n"
            "  for (const info of [undefined, null, {retryCount: 2, isRetry: true}, "
            "{retryCount: 'invalid', isRetry: 'invalid'}]) {\n"
            "    assert.equal(await object.alarm(info), info);\n"
            "  }\n"
            "}\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_fails_on_each_missing_additive_export(self):
        for missing in wrapper.CLASSES:
            with self.subTest(missing=missing):
                (self.root / wrapper.BASE_NAME).unlink(missing_ok=True)
                self.shim.write_text(fixture(missing))
                wrapper.enable(self.shim)
                result = self.node("await import('./shim.mjs');")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("requires a perf-metrics build", result.stderr)
                self.assertIn(missing, result.stderr)

    def test_idempotence_and_unexpected_base_are_non_destructive(self):
        wrapper.enable(self.shim)
        before = {path.name: path.read_bytes() for path in self.root.iterdir()}
        wrapper.enable(self.shim)
        self.assertEqual(before, {path.name: path.read_bytes() for path in self.root.iterdir()})
        self.shim.write_text("export default 'fresh build';\n")
        with self.assertRaisesRegex(ValueError, "already exists"):
            wrapper.enable(self.shim)
        self.assertEqual(self.shim.read_text(), "export default 'fresh build';\n")

    def test_replace_failure_preserves_original_and_removes_partial_base(self):
        original = self.shim.read_bytes()
        with mock.patch.object(wrapper.os, "replace", side_effect=OSError("injected")):
            with self.assertRaises(OSError):
                wrapper.enable(self.shim)
        self.assertEqual(self.shim.read_bytes(), original)
        self.assertFalse((self.root / wrapper.BASE_NAME).exists())
        self.assertEqual(list(self.root.iterdir()), [self.shim])

    def test_direct_runtime_registers_base_only_for_wrapped_shim(self):
        runtime = SCRIPT.with_name("workers-wire-runtime.cjs")
        artifacts = {}
        for mode in ("wrapped", "plain"):
            artifact = self.root / mode
            worker = artifact / "worker"
            worker.mkdir(parents=True)
            shim = worker / "shim.mjs"
            shim.write_text(fixture())
            if mode == "wrapped":
                wrapper.enable(shim)
            else:
                # A stale base from an earlier opt-in build must stay unregistered.
                (worker / wrapper.BASE_NAME).write_text(fixture())
            artifacts[mode] = str(artifact)
        binary_directory = self.root / "bin"
        binary_directory.mkdir()
        (binary_directory / "wrangler").write_text("fake executable")
        result = self.node(
            "import assert from 'node:assert/strict';\n"
            "import fs from 'node:fs';\n"
            "import path from 'node:path';\n"
            "import vm from 'node:vm';\n"
            "import {createRequire} from 'node:module';\n"
            f"const runtime = {json.dumps(str(runtime))};\n"
            f"const artifacts = {json.dumps(artifacts)};\n"
            f"const binaryDirectory = {json.dumps(str(binary_directory))};\n"
            "const realRequire = createRequire(runtime);\n"
            "for (const [mode, artifact] of Object.entries(artifacts)) {\n"
            "  let captured, disposed = false;\n"
            "  const errors = [];\n"
            "  const modules = {\n"
            "    wrangler: {unstable_getMiniflareWorkerOptions() {\n"
            "      return {workerOptions: {name: 'probe', bindings: {}},\n"
            "        main: path.join(artifact, 'worker/shim.mjs'), externalWorkers: []};\n"
            "    }},\n"
            "    miniflare: {\n"
            "      convertV4MiniflareOptions(options) {captured = options; return options;},\n"
            "      Log: class {}, LogLevel: {DEBUG: 0},\n"
            "      Miniflare: class {\n"
            "        async unsafeGetDirectURL() {return new URL('http://127.0.0.1:9000');}\n"
            "        async dispose() {disposed = true;}\n"
            "      },\n"
            "    },\n"
            "  };\n"
            "  const fakeProcess = {\n"
            "    env: {PATH: binaryDirectory},\n"
            "    argv: ['node', runtime, 'config', artifact, 'state', '9000'],\n"
            "    once(_signal, callback) {queueMicrotask(callback);},\n"
            "  };\n"
            "  vm.runInNewContext(fs.readFileSync(runtime, 'utf8'), {\n"
            "    process: fakeProcess,\n"
            "    console: {log() {}, error(error) {errors.push(error);}},\n"
            "    require(name) {\n"
            "      if (name === 'node:module') return {createRequire() {\n"
            "        return name => {assert.ok(name in modules); return modules[name];};\n"
            "      }};\n"
            "      return realRequire(name);\n"
            "    },\n"
            "  }, {filename: runtime});\n"
            "  await new Promise(resolve => setImmediate(resolve));\n"
            "  assert.deepEqual(errors, []);\n"
            "  assert.equal(disposed, true);\n"
            "  const registered = captured.workers[0].modules;\n"
            "  const base = path.join(artifact, 'worker/alarm-base.mjs');\n"
            "  const matching = registered.filter(module => module.path === base);\n"
            "  assert.equal(matching.length, mode === 'wrapped' ? 1 : 0, mode);\n"
            "  if (mode === 'wrapped') assert.equal(matching[0].type, 'ESModule');\n"
            "  assert.equal(new Set(registered.map(module => module.path)).size, registered.length);\n"
            "}\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_base_is_rejected(self):
        wrapper.enable(self.shim)
        (self.root / wrapper.BASE_NAME).unlink()
        with self.assertRaisesRegex(ValueError, "missing"):
            wrapper.enable(self.shim)


if __name__ == "__main__":
    unittest.main()
