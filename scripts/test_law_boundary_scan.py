"""Tests of scripts/law_boundary_scan.py on synthetic rustdoc JSON"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import law_boundary_scan as lb  # noqa: E402

U8 = {"primitive": "u8"}
F64 = {"primitive": "f64"}


def fn(file, name, inputs, output, line=1):
    return {
        "crate_id": 0,
        "visibility": "public",
        "name": name,
        "span": {"filename": file, "begin": [line, 0]},
        "inner": {"function": {"sig": {"inputs": [["x", t] for t in inputs], "output": output}}},
    }


def doc(*items):
    return {"index": {str(i): it for i, it in enumerate(items)}}


def table(*entries):
    return {"function": [{"file": f, "name": n, "class": "c", "reason": "r"} for f, n in entries]}


KEY32 = {"array": {"type": U8, "len": "32"}}
SLICE = {"borrowed_ref": {"type": {"slice": U8}}}


class LawBoundary(unittest.TestCase):
    """the rules for a Law-bearing module are tested on a synthetic one (this crate has none)"""

    def setUp(self):
        self.saved = lb.LAW_FILES
        lb.LAW_FILES = ("src/dp.rs",)

    def tearDown(self):
        lb.LAW_FILES = self.saved

    def test_a_listed_boundary_passes(self):
        d = doc(fn("src/stream.rs", "seal", [SLICE], SLICE))
        problems, found, listed = lb.check(d, table(("src/stream.rs", "seal")))
        self.assertEqual((problems, found, listed), ([], 1, 1))

    def test_an_unlisted_boundary_fails(self):
        d = doc(fn("src/stream.rs", "seal", [SLICE], SLICE))
        problems, _, _ = lb.check(d, table(("src/stream.rs", "open")))
        self.assertTrue(any("not in scripts/law_boundary_table.toml" in p for p in problems))
        self.assertTrue(any("listed in the table but not found" in p for p in problems))

    def test_a_dp_function_returning_bytes_fails_even_when_listed(self):
        d = doc(fn("src/dp.rs", "to_bytes", [], {"array": {"type": U8, "len": "16"}}))
        problems, _, _ = lb.check(d, table(("src/dp.rs", "to_bytes")))
        self.assertTrue(any("returns bytes" in p for p in problems))

    def test_a_dp_function_reading_bytes_other_than_a_key_fails(self):
        d = doc(fn("src/dp.rs", "from_bytes", [SLICE], F64))
        problems, _, _ = lb.check(d, table(("src/dp.rs", "from_bytes")))
        self.assertTrue(any("other than a 32-byte key" in p for p in problems))

    def test_a_dp_key_input_passes(self):
        d = doc(fn("src/dp.rs", "with_key", [F64, F64, KEY32], None))
        problems, _, _ = lb.check(d, table(("src/dp.rs", "with_key")))
        self.assertEqual(problems, [])

    def test_functions_without_bytes_are_not_boundaries(self):
        d = doc(fn("src/dp.rs", "privatize", [F64], F64))
        self.assertEqual(lb.boundary_functions(d), [])

    def test_an_entry_without_a_reason_fails(self):
        d = doc(fn("src/hash.rs", "hash", [SLICE], None))
        t = {"function": [{"file": "src/hash.rs", "name": "hash", "class": "digest", "reason": " "}]}
        problems, _, _ = lb.check(d, t)
        self.assertTrue(any("without a class and a reason" in p for p in problems))

    def test_this_crate_has_no_law_bearing_module(self):
        self.assertEqual(self.saved, ())

    def test_the_repository_table_parses_and_is_not_empty(self):
        import tomllib
        t = tomllib.loads(lb.TABLE.read_text(encoding="utf-8"))
        self.assertGreater(len(t.get("function", [])), 0)


if __name__ == "__main__":
    unittest.main()
