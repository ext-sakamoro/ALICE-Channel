#!/usr/bin/env python3
"""No generated file is tracked: bytecode caches, build output, fuzzer
artifacts and corpora, OS metadata.

A generated file committed by accident (a `__pycache__/*.pyc` written when a
script ran, picked up by `git add -A`) is reviewed by nobody and goes stale. The
check reads `git ls-files`; listing 0 files is a failure (it compared nothing).
"""
from __future__ import annotations

import re
import subprocess
import sys

GENERATED = re.compile(
    r"(^|/)__pycache__/|\.py[co]$|(^|/)target/|(^|/)\.DS_Store$|\.profraw$"
    r"|^fuzz/(artifacts|corpus|coverage)/"
)


def offenders(paths: list[str]) -> list[str]:
    return [p for p in paths if GENERATED.search(p)]


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass
    paths = subprocess.run(
        ["git", "ls-files"], capture_output=True, text=True, check=True
    ).stdout.splitlines()
    if not paths:
        print("error: git ls-files listed 0 files (compared nothing)", file=sys.stderr)
        return 1
    bad = offenders(paths)
    for p in bad:
        print(f"error: generated file is tracked: {p}", file=sys.stderr)
    print(f"tracked generated check: {len(paths)} files, {len(bad)} generated")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
