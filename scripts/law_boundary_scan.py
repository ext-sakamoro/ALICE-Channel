#!/usr/bin/env python3
"""ALICE-Law G7 / G8 / G9 scope check: no Law-bearing value of this crate
crosses a byte boundary.

The crate computes no Law-bearing value: what it puts on the wire is key
material, handshake messages and ciphertext (Noise IK over alice-crypto's
X25519, SHA-256 and ChaCha20-Poly1305). G7 (a value handed to another crate
carries an identifier), G8 (a durable form carries one) and G9 (its history)
apply only if a Law-bearing value is turned into bytes or read back from
bytes. This script measures that none is, from the rustdoc JSON of the library
(every feature named on the command line):

- every public function whose signature takes or returns bytes (`u8`
  anywhere in a parameter or the return type: arrays, slices, vectors) must be
  listed in scripts/law_boundary_table.toml with its class and a reason
  (key material, handshake message, ciphertext, a label ...);
- a function of a Law-bearing module (LAW_FILES; none in this crate) may take
  bytes only as a 32-byte key (`[u8; 32]`) and may never return bytes;
- a listed function that the scan no longer finds fails (remove it);
- scanning no function, or reading no table entry, fails.

    python3 scripts/law_boundary_scan.py --json target/doc/alice_channel.json
"""
from __future__ import annotations

import argparse
import json
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TABLE = ROOT / "scripts" / "law_boundary_table.toml"
LAW_FILES: tuple[str, ...] = ()


def has_u8(t) -> bool:
    if isinstance(t, dict):
        if t.get("primitive") == "u8":
            return True
        return any(has_u8(v) for v in t.values())
    if isinstance(t, list):
        return any(has_u8(v) for v in t)
    return False


def is_key32(t) -> bool:
    a = t.get("array") if isinstance(t, dict) else None
    return bool(a) and a.get("len") == "32" and a.get("type", {}).get("primitive") == "u8"


def boundary_functions(doc: dict) -> list[dict]:
    """public functions of the local crate whose signature carries bytes"""
    out = []
    for item in doc.get("index", {}).values():
        if item.get("crate_id") != 0 or item.get("visibility") != "public":
            continue
        fn = (item.get("inner") or {}).get("function")
        if not fn:
            continue
        sig = fn.get("sig", {})
        inputs = [t for _, t in sig.get("inputs", [])]
        output = sig.get("output")
        if not (any(has_u8(t) for t in inputs) or (output is not None and has_u8(output))):
            continue
        span = item.get("span") or {}
        out.append({
            "file": span.get("filename", ""),
            "line": (span.get("begin") or [0])[0],
            "name": item.get("name", ""),
            "inputs": inputs,
            "output": output,
        })
    return out


def check(doc: dict, table: dict) -> tuple[list[str], int, int]:
    found = boundary_functions(doc)
    entries = table.get("function", [])
    listed = {(e.get("file"), e.get("name")): e for e in entries}
    problems = []
    seen = set()
    for f in sorted(found, key=lambda f: (f["file"], f["line"])):
        key = (f["file"], f["name"])
        seen.add(key)
        if f["file"] in LAW_FILES:
            if f["output"] is not None and has_u8(f["output"]):
                problems.append(f"{f['file']}:{f['line']} {f['name']}: a Law-bearing module returns bytes")
            for t in f["inputs"]:
                if has_u8(t) and not is_key32(t):
                    problems.append(f"{f['file']}:{f['line']} {f['name']}: a Law-bearing module reads bytes other than a 32-byte key")
        e = listed.get(key)
        if e is None:
            problems.append(f"{f['file']}:{f['line']} {f['name']}: a byte boundary not in scripts/law_boundary_table.toml")
        elif not str(e.get("reason", "")).strip() or not str(e.get("class", "")).strip():
            problems.append(f"{f['file']} {f['name']}: table entry without a class and a reason")
    for key in sorted(set(listed) - seen):
        problems.append(f"{key[0]} {key[1]}: listed in the table but not found (remove it)")
    return problems, len(found), len(entries)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", required=True, help="rustdoc JSON of the library")
    args = ap.parse_args(argv)
    doc = json.loads(Path(args.json).read_text(encoding="utf-8"))
    table = tomllib.loads(TABLE.read_text(encoding="utf-8"))
    problems, n_found, n_listed = check(doc, table)
    if n_found == 0 or n_listed == 0:
        problems.append(f"compared nothing ({n_found} functions found, {n_listed} table entries)")
    for p in problems:
        print(f"error: {p}")
    print(f"law_boundary_scan: {n_found} byte-boundary functions, {n_listed} table entries, {len(problems)} problems")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
