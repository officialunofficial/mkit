#!/usr/bin/env python3
"""The PR gate entry points must execute the isolated allocator regression."""
import subprocess
import unittest


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


if __name__ == "__main__":
    unittest.main()
