"""Teeth for scripts/tracked_generated_check.py."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import tracked_generated_check as t  # noqa: E402


class Offenders(unittest.TestCase):
    def test_bytecode_build_output_and_fuzz_state_are_caught(self):
        bad = [
            "scripts/__pycache__/x.cpython-314.pyc",
            "a/b.pyc",
            "target/debug/x",
            "fuzz/target/x",
            ".DS_Store",
            "docs/.DS_Store",
            "default.profraw",
            "fuzz/artifacts/fuzz_x/crash-1",
            "fuzz/corpus/fuzz_x/abc",
        ]
        self.assertEqual(t.offenders(bad), bad)

    def test_sources_and_committed_regressions_pass(self):
        ok = [
            "src/lib.rs",
            "scripts/dp_rr_exact.py",
            "fuzz/regressions/fuzz_x/crash-1",
            "fuzz/fuzz_targets/fuzz_x.rs",
            "docs/target_audience.md",
        ]
        self.assertEqual(t.offenders(ok), [])


if __name__ == "__main__":
    unittest.main()
