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



# a type with an inherent impl (pub generate, crate-private helper, pub const that is not a fn) and a trait
# impl (clone): the type's associated functions are the inherent impl's pub fns
TYPED = doc({
    0: ("module", "krate", "public", {"items": [1, 2, 3, 9]}),
    1: ("struct", "Key", "public", {"kind": {"plain": {"fields": []}}, "generics": {}, "impls": [4, 5]}),
    2: ("enum", "Mode", "public", {"generics": {}, "variants": [], "impls": [8]}),
    3: ("use", None, "public", {"name": "Alias", "id": 1, "is_glob": False}),
    4: ("impl", None, "default", {"trait": None, "items": [6, 7, 10]}),
    5: ("impl", None, "default", {"trait": {"path": "Clone", "id": 99}, "items": [11]}),
    6: ("function", "generate", "public", {}),
    7: ("function", "helper", "crate", {}),
    8: ("impl", None, "default", {"trait": None, "items": [12]}),
    9: ("module", "inner", "public", {"items": []}),
    10: ("assoc_const", "LEN", "public", {}),
    # public here so that only the trait-impl rule keeps it out (rustdoc marks trait impl items "default")
    11: ("function", "clone", "public", {}),
    12: ("function", "parse", "public", {}),
})


class AssociatedFunctions(unittest.TestCase):
    """an entry Crate::Type::fn names an associated function: its siblings are the type's inherent pub fns"""

    def test_a_struct_lists_its_inherent_pub_fns_only(self):
        self.assertEqual(c.public_functions(TYPED, ("krate", "Key")), {"generate"})

    def test_an_enum_lists_its_inherent_pub_fns(self):
        self.assertEqual(c.public_functions(TYPED, ("krate", "Mode")), {"parse"})

    def test_a_reexported_type_resolves_to_the_type(self):
        self.assertEqual(c.public_functions(TYPED, ("krate", "Alias")), {"generate"})

    def test_a_type_in_the_middle_of_the_path_is_not_a_module(self):
        self.assertEqual(c.public_functions(TYPED, ("krate", "Key", "generate")), set())

    def test_a_module_still_lists_its_free_functions(self):
        self.assertEqual(c.public_functions(CRATE, ("krate", "nested")), {"deep"})


class DependencySource(unittest.TestCase):
    """the probe depends on the crate from the source Cargo.lock resolved, not always from crates.io"""

    def meta(self, source, manifest="/r/vendor/alice-crypto/Cargo.toml"):
        return {"packages": [{"id": "x", "name": "alice-crypto", "version": "0.6.0", "source": source,
                              "manifest_path": manifest}]}

    def test_a_registry_source_pins_the_exact_version(self):
        spec = c.dependency_source(self.meta("registry+https://github.com/rust-lang/crates.io-index"),
                                   "alice-crypto", "0.6.0")
        self.assertEqual(spec, {"version": "=0.6.0"})

    def test_the_sparse_crates_io_index_is_the_registry_too(self):
        spec = c.dependency_source(self.meta("sparse+https://index.crates.io/"), "alice-crypto", "0.6.0")
        self.assertEqual(spec, {"version": "=0.6.0"})

    def test_a_git_source_takes_the_url_and_the_locked_commit(self):
        sha = "4ab0f0e" + "0" * 33
        spec = c.dependency_source(self.meta(f"git+https://github.com/ext-sakamoro/ALICE-Crypto?rev=4ab0f0e#{sha}"),
                                   "alice-crypto", "0.6.0")
        self.assertEqual(spec, {"git": "https://github.com/ext-sakamoro/ALICE-Crypto", "rev": sha})

    def test_a_git_source_on_a_branch_still_takes_the_locked_commit(self):
        sha = "a" * 40
        spec = c.dependency_source(self.meta(f"git+https://example.invalid/r.git?branch=main#{sha}"),
                                   "alice-crypto", "0.6.0")
        self.assertEqual(spec, {"git": "https://example.invalid/r.git", "rev": sha})

    def test_a_path_source_takes_the_manifest_directory(self):
        spec = c.dependency_source(self.meta(None), "alice-crypto", "0.6.0")
        self.assertEqual(spec, {"path": "/r/vendor/alice-crypto"})

    def test_another_registry_stops(self):
        with self.assertRaises(SystemExit):
            c.dependency_source(self.meta("registry+https://example.invalid/index"), "alice-crypto", "0.6.0")

    def test_one_version_from_two_sources_stops(self):
        meta = self.meta("registry+https://github.com/rust-lang/crates.io-index")
        meta["packages"].append(dict(meta["packages"][0], id="y", source=f"git+https://example.invalid/r.git#{'c' * 40}"))
        with self.assertRaises(SystemExit):
            c.dependency_source(meta, "alice-crypto", "0.6.0")

    def test_a_package_not_in_the_metadata_stops(self):
        with self.assertRaises(SystemExit):
            c.dependency_source(self.meta(None), "alice-crypto", "9.9.9")

    def test_the_probe_manifest_carries_the_source(self):
        sha = "b" * 40
        seen = {}

        def fake_run(cmd, cwd, env, **_):
            seen["toml"] = (Path(cwd) / "Cargo.toml").read_text(encoding="utf-8")
            target = Path(cmd[cmd.index("--target-dir") + 1])
            (target / "doc").mkdir(parents=True, exist_ok=True)
            (target / "doc" / "alice_crypto.json").write_text("{}", encoding="utf-8")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        with tempfile.TemporaryDirectory() as work, mock.patch.object(c.subprocess, "run", fake_run):
            c.rustdoc_json("alice-crypto", "0.6.0", ["std"], Path(work),
                           {"git": "https://github.com/ext-sakamoro/ALICE-Crypto", "rev": sha})
        dep = c.tomllib.loads(seen["toml"])["dependencies"]["alice-crypto"]
        self.assertEqual(dep, {"git": "https://github.com/ext-sakamoro/ALICE-Crypto", "rev": sha,
                               "default-features": False, "features": ["std"]})

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
