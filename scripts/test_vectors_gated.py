#!/usr/bin/env python3
"""The constructors that take a fixed ephemeral key (`Initiate::start_with_ephemeral`,
`Respond::with_ephemeral`) exist only with the cargo feature `test-vectors`: a reused ephemeral key voids
the anonymous handshake's guarantees, so no build that ships may reach them. This checks that:

- the manifest: `test-vectors` is a feature, it is not in `default`, and no other feature names it
  (`test-vectors`, `dep:...` or `alice-channel/test-vectors` in its list)
- the type system: a crate that depends on this one with its default features, or with every feature
  except `test-vectors` (`async`), and calls either constructor fails with E0599 naming it; the same
  calls compile when the dependent enables `alice-channel/test-vectors` (the control)

A small crate is written under the target directory with a path dependency on this one and this
repository's Cargo.lock. Running fewer checks than listed (0 included) is a failure.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FEATURE = "test-vectors"

# fixture feature -> (the alice-channel features it enables, the item E0599 must name; None = must compile)
CASES = {
    "default_initiate": ([], "start_with_ephemeral"),
    "default_respond": ([], "with_ephemeral"),
    "async_initiate": (["async"], "start_with_ephemeral"),
    "async_respond": (["async"], "with_ephemeral"),
    "control": ([FEATURE], None),
}

CARGO_TOML = """[package]
name = "alice-channel-test-vectors-fixture"
version = "0.0.0"
edition = "2021"
publish = false
license = "LicenseRef-Proprietary"

[lib]
path = "lib.rs"

[dependencies]
alice-channel = {{ path = "{root}" }}

[features]
{features}

[workspace]
"""

LIB_RS = """#![allow(dead_code, unused_variables, unused_imports)]
use alice_channel::noise::Keypair;
use alice_channel::{Initiate, Respond};

#[cfg(any(feature = "default_initiate", feature = "async_initiate"))]
fn case() {
    let _ = Initiate::start_with_ephemeral([9; 32], Keypair::from_secret([1; 32]));
}

#[cfg(any(feature = "default_respond", feature = "async_respond"))]
fn case() {
    let _ = Respond::with_ephemeral(Keypair::from_secret([2; 32]), Keypair::from_secret([1; 32]));
}

#[cfg(feature = "control")]
fn case() {
    let _ = Initiate::start_with_ephemeral([9; 32], Keypair::from_secret([1; 32]));
    let _ = Respond::with_ephemeral(Keypair::from_secret([2; 32]), Keypair::from_secret([1; 32]));
}
"""


def manifest_problems() -> tuple[int, list[str]]:
    features = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8")).get("features", {})
    problems = []
    checks = 0
    checks += 1
    if FEATURE not in features:
        problems.append(f"Cargo.toml has no feature `{FEATURE}`")
    checks += 1
    if FEATURE in features.get("default", []):
        problems.append(f"`{FEATURE}` is in `default`")
    for name, enables in features.items():
        if name == FEATURE:
            continue
        checks += 1
        for item in enables:
            if item in (FEATURE, f"dep:{FEATURE}") or item.endswith(f"/{FEATURE}"):
                problems.append(f"feature `{name}` enables `{FEATURE}` ({item})")
    return checks, problems


def write_fixture() -> Path:
    fixture = ROOT / "target" / "test-vectors-fixture"
    if fixture.exists():
        shutil.rmtree(fixture)
    fixture.mkdir(parents=True)
    lines = []
    for name, (enables, _) in CASES.items():
        deps = ", ".join(f'"alice-channel/{f}"' for f in enables)
        lines.append(f"{name} = [{deps}]")
    (fixture / "Cargo.toml").write_text(
        CARGO_TOML.format(root=ROOT.as_posix(), features="\n".join(lines)), encoding="utf-8"
    )
    (fixture / "lib.rs").write_text(LIB_RS, encoding="utf-8")
    shutil.copy(ROOT / "Cargo.lock", fixture / "Cargo.lock")
    return fixture


def check(fixture: Path, feature: str) -> subprocess.CompletedProcess[str]:
    target = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target"))
    return subprocess.run(
        ["cargo", "check", "--lib", "--message-format", "short", "--features", feature],
        cwd=fixture,
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, "CARGO_TARGET_DIR": str(target)},
    )


def main() -> int:
    ran, problems = manifest_problems()
    expected = ran + len(CASES)
    fixture = write_fixture()
    for feature, (_, item) in CASES.items():
        out = check(fixture, feature)
        ran += 1
        tail = "\n".join(out.stderr.strip().splitlines()[-6:])
        if item is None:
            if out.returncode != 0:
                problems.append(f"{feature}: does not compile with `{FEATURE}`:\n{tail}")
            else:
                print(f"ok   {feature}: compiles with `{FEATURE}`")
            continue
        errors = [l for l in out.stderr.splitlines() if "error[E0599]" in l]
        if out.returncode == 0:
            problems.append(f"{feature}: `{item}` resolved without `{FEATURE}`")
        elif not any(f"`{item}`" in l for l in errors):
            problems.append(f"{feature}: failed without E0599 naming `{item}`:\n{tail}")
        else:
            print(f"ok   {feature}: refused (E0599 `{item}`)")
    for p in problems:
        print(f"FAIL {p}")
    print(f"test-vectors-gated: {ran} checks, {len(problems)} problems")
    if ran != expected or ran == 0:
        print(f"::error::ran {ran} of {expected} checks")
        return 1
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
