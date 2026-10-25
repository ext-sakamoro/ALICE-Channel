#!/usr/bin/env python3
"""Compare the strict workflow reader of scripts/changed_paths.py with PyYAML.

usage: changed_paths_yaml_oracle.py [--fuzz N] ROOT [ROOT ...]

For every .github/workflows/*.yml / *.yaml under each ROOT (a repository checkout), the reader's
tree must equal yaml.safe_load's, or the reader must refuse the file (FormError: outside the subset,
fail-closed). A tree that differs is a failure: sync would read a workflow differently from GitHub.
The cases of test_changed_paths.py are checked against PyYAML too: every READ case equals
safe_load, every REFUSE case is valid YAML (so a refusal is a construct outside the subset, not an
error the reader invents), every INVALID case is rejected by PyYAML. --fuzz N also compares N
mutants of the workflow files (a character inserted, deleted or replaced, a line reindented,
duplicated or swapped, seed fixed): each must read as PyYAML reads it or be refused, and a mutant
PyYAML rejects must be refused. Fails when no workflow file was compared. Needs PyYAML (CI pins it); this file is not one of the shared copies.
"""
from __future__ import annotations

import random
import sys
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import changed_paths as cp  # noqa: E402
import test_changed_paths as t  # noqa: E402

def first_diff(a, b, path="$"):
    if type(a) is not type(b):
        return f"{path}: {type(a).__name__} {a!r:.60} != {type(b).__name__} {b!r:.60}"
    if isinstance(a, dict):
        for k in list(a) + [k for k in b if k not in a]:
            if k not in a or k not in b:
                return f"{path}.{k}: present on one side only"
            d = first_diff(a[k], b[k], f"{path}.{k}")
            if d:
                return d
    elif isinstance(a, list):
        if len(a) != len(b):
            return f"{path}: {len(a)} items != {len(b)}"
        for i, (x, y) in enumerate(zip(a, b)):
            d = first_diff(x, y, f"{path}[{i}]")
            if d:
                return d
    elif a != b:
        return f"{path}: {a!r:.80} != {b!r:.80}"
    return None


TOKENS = list(" \t#:-[]{},'\"\n|>&*!?%@`~\\") + [
    "\ufeff", "\x85", "\u2028", "\r", "\r\n", "  ", "- ", ": ", " #", "\"\"", "{}", "[]", "0", ".", "on", "yes"]


def mutate(rng: random.Random, t: str) -> str:
    lines = t.split("\n")
    op = rng.randrange(6)
    if op == 0 and t:
        i = rng.randrange(len(t) + 1)
        return t[:i] + rng.choice(TOKENS) + t[i:]
    if op == 1 and t:
        i = rng.randrange(len(t))
        return t[:i] + t[i + 1:]
    if op == 2:
        i = rng.randrange(len(lines))
        d = rng.choice([-2, -1, 1, 2, 4])
        l = lines[i]
        lines[i] = (" " * d + l) if d > 0 else l[min(-d, len(l) - len(l.lstrip(" "))):]
        return "\n".join(lines)
    if op == 3 and len(lines) > 1:
        i = rng.randrange(len(lines))
        lines.insert(i, lines[i])
        return "\n".join(lines)
    if op == 4 and len(lines) > 1:
        i = rng.randrange(len(lines) - 1)
        lines[i], lines[i + 1] = lines[i + 1], lines[i]
        return "\n".join(lines)
    i = rng.randrange(len(t) + 1) if t else 0
    return t[:i] + rng.choice(TOKENS) + t[min(len(t), i + rng.randrange(1, 4)):]


def fuzz(texts: list[str], n: int) -> tuple[list[str], dict]:
    rng = random.Random(20261024)
    bad, stats = [], {"equal": 0, "refused": 0, "rejected by both": 0}
    for _ in range(n):
        src = rng.choice(texts)
        for _ in range(rng.randrange(1, 4)):
            src = mutate(rng, src)
        try:
            want = ("ok", yaml.safe_load(src))
        except yaml.YAMLError:
            want = ("err", None)
        except Exception:  # an internal PyYAML error on a broken input: nothing to compare
            continue
        try:
            got = cp.load_yaml(src)
        except cp.FormError:
            stats["rejected by both" if want[0] == "err" else "refused"] += 1
            continue
        except Exception as e:  # the reader fails with something other than FormError: a bug
            bad.append(f"fuzz: the reader raised {type(e).__name__} ({e}): {src[:300]!r}")
            continue
        if want[0] == "err":
            bad.append(f"fuzz: PyYAML rejects a mutant the reader reads: {src[:300]!r}")
        elif want[1] != got:
            bad.append(f"fuzz: a mutant reads differently ({first_diff(got, want[1])}): {src[:300]!r}")
        else:
            stats["equal"] += 1
    return bad, stats


def main(roots: list[str], fuzz_n: int = 0) -> int:
    bad: list[str] = []
    equal = refused = not_yaml = 0
    files = sorted({f for r in roots for pat in ("*.yml", "*.yaml")
                    for f in (Path(r) / ".github" / "workflows").glob(pat)})
    for f in files:
        text = f.read_text(encoding="utf-8")
        try:
            want = yaml.safe_load(text)
        except yaml.YAMLError as e:
            not_yaml += 1
            try:
                cp.load_yaml(text)
                bad.append(f"{f}: PyYAML rejects it ({str(e).splitlines()[0]}) and the reader reads it")
            except cp.FormError:
                print(f"not YAML, refused by both: {f}")
            except Exception as e2:
                bad.append(f"{f}: the reader raised {type(e2).__name__} ({e2})")
            continue
        try:
            got = cp.load_yaml(text)
        except cp.FormError as e:
            refused += 1
            print(f"refused: {f}: {e}")
            continue
        except Exception as e:
            bad.append(f"{f}: the reader raised {type(e).__name__} ({e})")
            continue
        if got == want:
            equal += 1
        else:
            bad.append(f"{f}: the reader's tree differs from yaml.safe_load: {first_diff(got, want)}")

    cases = 0
    for name, src, expected in t.Reader.READ:
        cases += 1
        if yaml.safe_load(src) != expected:
            bad.append(f"READ case {name!r}: the expected tree is not what PyYAML builds")
    for name, src in t.Reader.REFUSE:
        cases += 1
        try:
            yaml.safe_load(src)
        except yaml.YAMLError as e:
            if name != "a tab in the indentation":
                bad.append(f"REFUSE case {name!r} is not valid YAML ({str(e).splitlines()[0]})")
    for name, src in t.Reader.INVALID:
        cases += 1
        try:
            yaml.safe_load(src)
            bad.append(f"INVALID case {name!r} is valid YAML")
        except yaml.YAMLError:
            pass

    fbad: list[str] = []
    if fuzz_n:
        fbad, fstats = fuzz([f.read_text(encoding="utf-8") for f in files], fuzz_n)
        print(f"fuzz: {fuzz_n} mutants, {fstats}, {len(fbad)} failure(s)")
        if fstats["equal"] == 0:
            bad.append("fuzz: no mutant compared equal (compared nothing)")
    for b in bad + fbad[:20]:
        print(f"FAIL: {b}")
    if len(fbad) > 20:
        print(f"(the first 20 of {len(fbad)} fuzz failures are listed)")
    total = len(bad) + len(fbad)
    print(f"compared: workflow files {len(files)}, equal {equal}, refused {refused}, not YAML {not_yaml}, "
          f"test cases {cases}, {total} failure(s)")
    if equal == 0:
        print("FAIL: no workflow file compared equal (compared nothing)")
        return 1
    return 1 if total else 0


if __name__ == "__main__":
    args = sys.argv[1:]
    n = 0
    if args[:1] == ["--fuzz"]:
        n, args = int(args[1]), args[2:]
    if not args:
        print(__doc__.split("\n\n", 1)[1].split("\n", 1)[0], file=sys.stderr)
        sys.exit(2)
    sys.exit(main(args, n))
