#!/usr/bin/env python3
"""Check that the clippy.toml ban list covers every entry point of each external
crate it names, at the version Cargo.lock resolves.

A disallowed-methods entry is a path, so it bans one function, not a capability.
The canary (scripts/clippy_canary.py) proves that each listed path is flagged;
it cannot see a sibling function of the same crate that does the same thing and
is not listed (getrandom 0.2 has both `getrandom` and `getrandom_uninit`). This
script lists the public functions of every external module the ban list names
and requires each one to be either banned or allowed with a reason.

For each disallowed-methods entry whose first path segment is not a built-in
root (std, core, alloc, the primitive types), the module is the path without
its last segment. The crate is documented at the version locked in Cargo.lock
(the highest one if several are locked), from the source Cargo.lock resolved it from (crates.io at that
exact version, the locked commit of a git source, or the directory of a path source), in a throwaway crate that copies
rust-toolchain.toml, with rustdoc's JSON output (unstable, enabled with
RUSTC_BOOTSTRAP=1 on the pinned toolchain) and --document-hidden-items (a
#[doc(hidden)] pub function is callable too); `pub use` re-exports, glob or
named, are followed. The crate is built with exactly the features cargo
resolves for it in this workspace with every workspace feature on (`cargo
metadata --all-features`), so a function behind a feature the real build
enables is listed, and one behind a feature nothing enables is not.

An entry whose parent is a public type (`alice_crypto::Key::generate`) names an associated function:
its siblings are the public functions of the type's inherent impls (a trait impl's methods are the
trait's, not the type's). The JSON format_version must be one this script was written
against (SUPPORTED_FORMATS) or it stops and says so: a new toolchain is a
reason to re-check the resolver, not to guess.

scripts/clippy_external_allow.toml lists the public functions that are allowed,
each with a reason:

    [[allow]]
    path = "libm::sqrt"
    reason = "IEEE 754 specifies sqrt exactly"

The script fails when
  (i)   a public function of a named module is neither banned nor allowed,
  (ii)  an allowed path is not a public function of its module (stale), is
        also banned, or has an empty reason,
  (iii) an allowed path names a module the ban list does not name,
  (iv)  a named crate is not in Cargo.lock, or the module has no public
        function (compared nothing for that module),
  (v)   the rustdoc JSON format_version is not supported,
  (vi)  a banned path is not a public function of the locked version (a
        version bump renamed or removed it, so the ban no longer covers what
        replaced it).
With no external entry in clippy.toml and an empty allow file it reports
"0 external modules" and passes; there is nothing to compare.

usage: scripts/clippy_external_coverage.py
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLIPPY_TOML = ROOT / "clippy.toml"
CARGO_LOCK = ROOT / "Cargo.lock"
TOOLCHAIN = ROOT / "rust-toolchain.toml"
ALLOW = ROOT / "scripts" / "clippy_external_allow.toml"
BUILTIN_ROOTS = frozenset(
    ["std", "core", "alloc", "f32", "f64", "bool", "char", "str", "isize", "usize"]
    + [f"{s}{n}" for s in "iu" for n in (8, 16, 32, 64, 128)])
# rustdoc JSON format versions the resolver below was checked against
SUPPORTED_FORMATS = frozenset({60})
# the item kinds whose inherent impls hold associated functions
TYPE_KINDS = frozenset({"struct", "enum", "union"})
# the crates.io index, as Cargo.lock names it (git and sparse protocols)
CRATES_IO = frozenset({"registry+https://github.com/rust-lang/crates.io-index", "sparse+https://index.crates.io/"})


def banned_external(clippy: dict) -> dict[tuple[str, ...], set[str]]:
    """module path (crate first) -> banned function names, external crates only."""
    out: dict[tuple[str, ...], set[str]] = defaultdict(set)
    for entry in clippy.get("disallowed-methods", []):
        path = entry["path"] if isinstance(entry, dict) else entry
        parts = tuple(path.split("::"))
        if len(parts) < 2 or parts[0] in BUILTIN_ROOTS:
            continue
        out[parts[:-1]].add(parts[-1])
    return dict(out)


def read_allow(text: str) -> dict[tuple[str, ...], dict[str, str]]:
    """module path -> {function name: reason}."""
    out: dict[tuple[str, ...], dict[str, str]] = defaultdict(dict)
    for entry in tomllib.loads(text).get("allow", []):
        parts = tuple(entry["path"].split("::"))
        out[parts[:-1]][parts[-1]] = entry.get("reason", "")
    return dict(out)


def locked_version(lock: dict, crate: str) -> str | None:
    def key(v: str):
        return tuple(int(x) if x.isdigit() else x for x in re.split(r"[.+-]", v))
    versions = [p["version"] for p in lock.get("package", []) if p["name"] == crate]
    return max(versions, key=key) if versions else None


def public_functions(doc: dict, module: tuple[str, ...]) -> set[str]:
    """Names of the public functions reachable as `<module>::<name>` in a rustdoc
    JSON document, following glob and named `pub use` re-exports."""
    if doc.get("format_version") not in SUPPORTED_FORMATS:
        raise SystemExit(f"clippy_external_coverage: rustdoc JSON format_version "
                         f"{doc.get('format_version')} is not in {sorted(SUPPORTED_FORMATS)}; "
                         "check the resolver against the new format, then add it")
    idx = doc["index"]

    def item(i):
        return idx.get(str(i))

    def kind(it):
        return next(iter(it["inner"]))

    def exports(mod_id, seen) -> dict[str, dict]:
        """name -> item for everything the module makes public."""
        if mod_id in seen:
            return {}
        seen = seen | {mod_id}
        names: dict[str, dict] = {}
        for i in item(mod_id)["inner"]["module"]["items"]:
            it = item(i)
            if it is None or it.get("visibility") != "public":
                continue
            k = kind(it)
            if k == "use":
                use = it["inner"]["use"]
                target = item(use.get("id")) if use.get("id") is not None else None
                if target is None:
                    continue
                if use.get("is_glob"):
                    if kind(target) == "module":
                        names.update(exports(target["id"], seen))
                    continue
                names[use["name"]] = resolve(target, seen)
            elif it.get("name"):
                names[it["name"]] = it
        return names

    def resolve(it, seen):
        while it is not None and kind(it) == "use":
            nxt = it["inner"]["use"].get("id")
            it = item(nxt) if nxt is not None else None
        return it

    def inherent_functions(ty) -> set[str]:
        """pub functions of the type's inherent impls"""
        names = set()
        for impl_id in ty["inner"][kind(ty)].get("impls", []):
            imp = item(impl_id)
            if imp is None or kind(imp) != "impl" or imp["inner"]["impl"].get("trait") is not None:
                continue
            for i in imp["inner"]["impl"].get("items", []):
                it = item(i)
                if it is not None and it.get("visibility") == "public" and kind(it) == "function":
                    names.add(it["name"])
        return names

    mod_id = doc["root"]
    for n, seg in enumerate(module[1:], start=2):
        sub = exports(mod_id, frozenset()).get(seg)
        if sub is not None and kind(sub) in TYPE_KINDS and n == len(module):
            return inherent_functions(sub)
        if sub is None or kind(sub) != "module":
            return set()
        mod_id = sub["id"]
    return {name for name, it in exports(mod_id, frozenset()).items()
            if it is not None and kind(it) == "function"}


def resolved_features(metadata: dict, crate: str, version: str) -> list[str]:
    """Features cargo enables for crate@version in this workspace with every
    feature of the workspace on (the union over its resolve nodes)."""
    names = {p["id"]: (p["name"], p["version"]) for p in metadata["packages"]}
    features: set[str] = set()
    found = False
    for node in metadata["resolve"]["nodes"]:
        if names.get(node["id"]) == (crate, version):
            found = True
            features.update(node.get("features", []))
    if not found:
        raise SystemExit(f"clippy_external_coverage: {crate} {version} is not in the workspace resolve")
    return sorted(features)


def dependency_source(metadata: dict, crate: str, version: str) -> dict[str, str]:
    """The dependency entry that takes crate@version from where this workspace takes it: crates.io at
    that exact version, the locked commit of a git source, or the directory of a path source."""
    sources = {p.get("source") for p in metadata["packages"] if (p["name"], p["version"]) == (crate, version)}
    paths = {str(Path(p["manifest_path"]).parent) for p in metadata["packages"]
             if (p["name"], p["version"]) == (crate, version) and p.get("source") is None}
    if not sources:
        raise SystemExit(f"clippy_external_coverage: {crate} {version} is not in the workspace metadata")
    if len(sources) > 1:
        raise SystemExit(f"clippy_external_coverage: {crate} {version} comes from more than one source: "
                         f"{sorted(str(x) for x in sources)}")
    source = sources.pop()
    if source is None:
        return {"path": paths.pop()}
    if source in CRATES_IO:
        return {"version": f"={version}"}
    if source.startswith("git+") and "#" in source:
        url, commit = source[len("git+"):].split("#", 1)
        return {"git": url.split("?", 1)[0], "rev": commit}
    raise SystemExit(f"clippy_external_coverage: {crate} {version} comes from {source}, which this script "
                     "cannot name as a dependency")


def workspace_metadata() -> dict:
    proc = subprocess.run(["cargo", "metadata", "--format-version", "1", "--all-features", "--locked"],
                          cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                          encoding="utf-8", check=False)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr[-3000:])
        raise SystemExit("clippy_external_coverage: cargo metadata failed")
    return json.loads(proc.stdout)


def rustdoc_json(crate: str, version: str, features: list[str], workdir: Path,
                 source: dict[str, str] | None = None) -> dict:
    (workdir / "src").mkdir(parents=True, exist_ok=True)
    (workdir / "src" / "lib.rs").write_text("", encoding="utf-8")
    feats = ", ".join(json.dumps(f) for f in features)
    where = ", ".join(f"{k} = {json.dumps(v)}" for k, v in (source or {"version": f"={version}"}).items())
    (workdir / "Cargo.toml").write_text(
        f'[package]\nname = "clippy_external_coverage_probe"\nversion = "0.0.0"\nedition = "2021"\n\n'
        f'[dependencies]\n{crate} = {{ {where}, default-features = false, features = [{feats}] }}\n\n'
        f'[workspace]\n', encoding="utf-8")
    if TOOLCHAIN.exists():
        shutil.copy2(TOOLCHAIN, workdir / TOOLCHAIN.name)
    env = dict(os.environ)
    env["RUSTC_BOOTSTRAP"] = "1"
    env["RUSTDOCFLAGS"] = ""
    # #[doc(hidden)] pub functions are callable entry points too
    # the output is read from workdir/target below, so the target directory is named here: a
    # CARGO_TARGET_DIR in the environment (a preflight with its target elsewhere) would send it
    # somewhere else
    target = workdir / "target"
    cmd = ["cargo", "rustdoc", "-q", "-p", crate, "--target-dir", str(target), "--", "-Z", "unstable-options",
           "--output-format", "json", "--document-hidden-items"]
    proc = subprocess.run(cmd, cwd=workdir, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True, encoding="utf-8", check=False)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr[-3000:])
        raise SystemExit(f"clippy_external_coverage: rustdoc of {crate} {version} failed")
    out = target / "doc" / f"{crate.replace('-', '_')}.json"
    if not out.is_file():
        raise SystemExit(f"clippy_external_coverage: rustdoc of {crate} {version} wrote no {out} (compared nothing)")
    return json.loads(out.read_text(encoding="utf-8"))


def compare(module: tuple[str, ...], public: set[str], banned: set[str], allowed: dict[str, str]) -> list[str]:
    where = "::".join(module)
    errors = []
    if not public:
        errors.append(f"{where}: no public function found (compared nothing)")
    for name in sorted(public - banned - set(allowed)):
        errors.append(f"{where}::{name} is public and neither banned in clippy.toml nor allowed in {ALLOW.name}")
    for name in sorted(banned - public) if public else []:
        errors.append(f"{where}::{name} is banned in clippy.toml but is not a public function of the locked "
                      "version (renamed or removed: ban what replaced it)")
    for name, reason in sorted(allowed.items()):
        if name not in public:
            errors.append(f"{where}::{name} is allowed but is not a public function of {where}")
        if name in banned:
            errors.append(f"{where}::{name} is both banned and allowed")
        if not reason.strip():
            errors.append(f"{where}::{name} is allowed without a reason")
    return errors


def main() -> int:
    banned = banned_external(tomllib.loads(CLIPPY_TOML.read_text(encoding="utf-8")))
    allowed = read_allow(ALLOW.read_text(encoding="utf-8")) if ALLOW.exists() else {}
    errors = [f"{'::'.join(m)}: allowed entries for a module the ban list does not name"
              for m in allowed if m not in banned]
    if not banned:
        for e in errors:
            print(f"clippy_external_coverage: {e}", file=sys.stderr)
        if errors:
            return 1
        print("clippy_external_coverage: 0 external modules in clippy.toml, nothing to compare")
        return 0
    lock = tomllib.loads(CARGO_LOCK.read_text(encoding="utf-8"))
    metadata = workspace_metadata()
    checked = 0
    with tempfile.TemporaryDirectory(prefix="clippy-ext-") as tmp:
        docs: dict[str, dict] = {}
        for module in sorted(banned):
            crate = module[0]
            package = crate.replace("_", "-") if locked_version(lock, crate.replace("_", "-")) else crate
            version = locked_version(lock, package)
            if version is None:
                errors.append(f"{crate}: banned in clippy.toml but not in Cargo.lock")
                continue
            if crate not in docs:
                features = resolved_features(metadata, package, version)
                docs[crate] = rustdoc_json(package, version, features, Path(tmp) / crate,
                                           dependency_source(metadata, package, version))
            public = public_functions(docs[crate], module)
            errors += compare(module, public, banned[module], allowed.get(module, {}))
            checked += len(public)
    for e in errors:
        print(f"clippy_external_coverage: {e}", file=sys.stderr)
    if errors:
        return 1
    print(f"clippy_external_coverage: {len(banned)} external module(s), {checked} public function(s), "
          "each banned or allowed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
