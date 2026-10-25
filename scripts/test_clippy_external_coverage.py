#!/usr/bin/env python3
"""Tests for scripts/clippy_external_coverage.py (synthetic rustdoc JSON, no cargo run)."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import clippy_external_coverage as c  # noqa: E402


def doc(items: dict, root: int = 0, version: int = 60) -> dict:
    """items: id -> (kind, name, visibility, payload)"""
    index = {}
    for i, (kind, name, vis, payload) in items.items():
        index[str(i)] = {"id": i, "name": name, "visibility": vis, "inner": {kind: payload}}
    return {"format_version": version, "root": root, "index": index}


# crate root: fn entropy, private fn hidden, `pub use self::math::*`, `pub use inner::renamed as alias`,
# pub mod nested { pub fn deep }
CRATE = doc({
    0: ("module", "krate", "public", {"items": [1, 2, 3, 4, 9]}),
    1: ("function", "entropy", "public", {}),
    2: ("function", "hidden", "crate", {}),
    3: ("use", None, "public", {"source": "self::math", "name": "math", "id": 5, "is_glob": True}),
    4: ("use", None, "public", {"source": "inner::renamed", "name": "alias", "id": 8, "is_glob": False}),
    5: ("module", "math", "crate", {"items": [6, 7]}),
    6: ("use", None, "public", {"source": "self::sin::sin", "name": "sin", "id": 10, "is_glob": False}),
    7: ("function", "sqrt", "public", {}),
    8: ("function", "renamed", "public", {}),
    9: ("module", "nested", "public", {"items": [11, 12]}),
    10: ("function", "sin", "public", {}),
    11: ("function", "deep", "public", {}),
    12: ("struct", "NotAFunction", "public", {}),
})


class PublicFunctions(unittest.TestCase):
    def test_root_follows_glob_named_and_renamed_reexports(self):
        self.assertEqual(c.public_functions(CRATE, ("krate",)), {"entropy", "sin", "sqrt", "alias"})

    def test_nested_module(self):
        self.assertEqual(c.public_functions(CRATE, ("krate", "nested")), {"deep"})

    def test_missing_module_is_empty(self):
        self.assertEqual(c.public_functions(CRATE, ("krate", "absent")), set())

    def test_unknown_format_version_stops(self):
        with self.assertRaises(SystemExit):
            c.public_functions(dict(CRATE, format_version=999), ("krate",))

    def test_glob_cycle_terminates(self):
        cyc = doc({0: ("module", "k", "public", {"items": [1, 2]}),
                   1: ("use", None, "public", {"name": "a", "id": 0, "is_glob": True}),
                   2: ("function", "f", "public", {})})
        self.assertEqual(c.public_functions(cyc, ("k",)), {"f"})


class BanList(unittest.TestCase):
    def test_only_external_paths_are_kept(self):
        clippy = {"disallowed-methods": [
            {"path": "f32::sin", "reason": "x"}, {"path": "std::time::Instant::now", "reason": "x"},
            {"path": "getrandom::getrandom", "reason": "x"}, "getrandom::getrandom_uninit",
            {"path": "libm::sin", "reason": "x"}]}
        self.assertEqual(c.banned_external(clippy), {
            ("getrandom",): {"getrandom", "getrandom_uninit"}, ("libm",): {"sin"}})

    def test_allow_file(self):
        text = '[[allow]]\npath = "libm::sqrt"\nreason = "exact"\n'
        self.assertEqual(c.read_allow(text), {("libm",): {"sqrt": "exact"}})


class Compare(unittest.TestCase):
    def test_complete_coverage_passes(self):
        self.assertEqual(c.compare(("libm",), {"sin", "sqrt"}, {"sin"}, {"sqrt": "exact"}), [])

    def test_unlisted_public_function_fails(self):
        errs = c.compare(("getrandom",), {"getrandom", "getrandom_uninit"}, {"getrandom"}, {})
        self.assertEqual(len(errs), 1)
        self.assertIn("getrandom_uninit", errs[0])

    def test_stale_allow_fails(self):
        self.assertTrue(c.compare(("libm",), {"sin"}, {"sin"}, {"gone": "r"}))

    def test_banned_and_allowed_fails(self):
        self.assertTrue(c.compare(("libm",), {"sin"}, {"sin"}, {"sin": "r"}))

    def test_empty_reason_fails(self):
        self.assertTrue(c.compare(("libm",), {"sin", "sqrt"}, {"sin"}, {"sqrt": " "}))

    def test_banned_path_gone_after_a_bump_fails(self):
        # getrandom 0.3 renamed getrandom -> fill: the old ban no longer covers anything
        errs = c.compare(("getrandom",), {"fill", "fill_uninit"}, {"getrandom", "fill", "fill_uninit"}, {})
        self.assertEqual(len(errs), 1)
        self.assertIn("getrandom::getrandom is banned", errs[0])

    def test_no_public_function_fails(self):
        self.assertTrue(c.compare(("libm",), set(), {"sin"}, {}))


class ResolvedFeatures(unittest.TestCase):
    META = {"packages": [{"id": "a", "name": "libm", "version": "0.2.16"},
                         {"id": "b", "name": "libm", "version": "0.2.9"},
                         {"id": "c", "name": "getrandom", "version": "0.2.17"},
                         {"id": "d", "name": "getrandom", "version": "0.2.17"}],
            "resolve": {"nodes": [{"id": "a", "features": ["arch", "default"]},
                                  {"id": "b", "features": ["unstable-float"]},
                                  {"id": "c", "features": ["std"]},
                                  {"id": "d", "features": ["custom"]}]}}

    def test_features_of_the_exact_version(self):
        self.assertEqual(c.resolved_features(self.META, "libm", "0.2.16"), ["arch", "default"])

    def test_union_over_nodes(self):
        self.assertEqual(c.resolved_features(self.META, "getrandom", "0.2.17"), ["custom", "std"])

    def test_absent_stops(self):
        with self.assertRaises(SystemExit):
            c.resolved_features(self.META, "libm", "9.9.9")


class LockedVersion(unittest.TestCase):
    def test_highest_of_several(self):
        lock = {"package": [{"name": "getrandom", "version": "0.2.17"},
                            {"name": "getrandom", "version": "0.3.4"},
                            {"name": "getrandom", "version": "0.2.9"}]}
        self.assertEqual(c.locked_version(lock, "getrandom"), "0.3.4")

    def test_absent(self):
        self.assertIsNone(c.locked_version({"package": []}, "libm"))


class RustdocTargetDir(unittest.TestCase):
    """rustdoc_json names its target directory, so CARGO_TARGET_DIR elsewhere does not move the output"""

    def run_with(self, write_json: bool):
        seen = {}

        def fake_run(cmd, cwd, env, **_):
            seen["cmd"], seen["cwd"] = cmd, Path(cwd)
            target = Path(cmd[cmd.index("--target-dir") + 1]) if "--target-dir" in cmd else Path(env["CARGO_TARGET_DIR"])
            if write_json:
                (target / "doc").mkdir(parents=True, exist_ok=True)
                (target / "doc" / "probe_crate.json").write_text(json.dumps({"format_version": 0}), encoding="utf-8")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        with tempfile.TemporaryDirectory() as work, tempfile.TemporaryDirectory() as elsewhere:
            with mock.patch.dict(os.environ, {"CARGO_TARGET_DIR": elsewhere}), mock.patch.object(c.subprocess, "run", fake_run):
                try:
                    got = c.rustdoc_json("probe-crate", "1.0.0", [], Path(work))
                except SystemExit as e:
                    got = e
            return got, seen, Path(work)

    def test_the_target_directory_is_named_so_the_output_is_where_it_is_read(self):
        got, seen, work = self.run_with(write_json=True)
        self.assertEqual(got, {"format_version": 0})
        self.assertEqual(Path(seen["cmd"][seen["cmd"].index("--target-dir") + 1]), work / "target")

    def test_no_output_is_a_stop_not_a_traceback(self):
        got, _, _ = self.run_with(write_json=False)
        self.assertIsInstance(got, SystemExit)
        self.assertIn("compared nothing", str(got))


if __name__ == "__main__":
    unittest.main()
