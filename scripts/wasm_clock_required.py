#!/usr/bin/env python3
"""On WebAssembly with no OS (wasm32-unknown-unknown) the standard library has no clock (reading one
panics), so a channel or a datagram init that needs time must be given a `Clock` there. This checks that
the type system enforces it: a crate that uses a constructor without a clock, or the default clock type,
does not compile for that target, while the same code compiles for the host and the clock-taking
constructors compile for both.

A small crate is written under the target directory with a path dependency on this one and this
repository's Cargo.lock (so the dependencies are the pinned ones). Each case is one feature of it:

- a case that must not compile on wasm32-unknown-unknown fails there with E0599 naming its item, and
  builds on the host
- the control (every `*_with_clock` constructor, `Initiator::start_with_clock`, `InitTimestamp::from_clock`
  with a clock of the crate's own) builds on both

Running fewer checks than listed (0 included) is a failure.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WASM = "wasm32-unknown-unknown"

# feature name -> the item E0599 must name on wasm32-unknown-unknown
REFUSED = {
    "secure_connect": "connect",
    "secure_accept_with_timeout": "accept_with_timeout",
    "anonymous_connect": "connect",
    "initiator_start": "start",
    "timestamp_now": "now",
    "default_clock_recv_before": "recv_before",
}
CONTROL = "with_clock"

CARGO_TOML = """[package]
name = "alice-channel-wasm-clock-fixture"
version = "0.0.0"
edition = "2021"
publish = false
license = "LicenseRef-Proprietary"

[lib]
path = "lib.rs"

[dependencies]
alice-channel = {{ path = "{root}" }}
alice-identity = {{ version = "3.0", git = "https://github.com/ext-sakamoro/ALICE-Identity", branch = "main" }}

[features]
{features}

[workspace]
"""

LIB_RS = """#![allow(dead_code, unused_variables, unused_imports)]
use std::io::{Read, Write};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alice_channel::datagram::{InitTimestamp, Initiator};
use alice_channel::{AnonymousChannel, Clock, Credential, PeerPolicy, ReadTimeout, SecureChannel};
use alice_identity::device_cert::DeviceCert;

struct HostClock;

impl Clock for HostClock {
    fn now(&self) -> Duration {
        Duration::ZERO
    }
    fn system_now(&self) -> SystemTime {
        UNIX_EPOCH
    }
}

#[cfg(feature = "secure_connect")]
fn case<S: Read + Write + ReadTimeout>(s: S, c: &Credential, p: &impl PeerPolicy, d: &DeviceCert) {
    let _ = SecureChannel::connect(s, c, p, d);
}

#[cfg(feature = "secure_accept_with_timeout")]
fn case<S: Read + Write + ReadTimeout>(s: S, c: &Credential, p: &impl PeerPolicy, d: &DeviceCert) {
    let _ = SecureChannel::accept_with_timeout(s, c, p, Duration::from_secs(1));
}

#[cfg(feature = "anonymous_connect")]
fn case<S: Read + Write + ReadTimeout>(s: S, c: &Credential, p: &impl PeerPolicy, d: &DeviceCert) {
    let _ = AnonymousChannel::connect(s, p, d);
}

#[cfg(feature = "initiator_start")]
fn case<S: Read + Write + ReadTimeout>(s: S, c: &Credential, p: &impl PeerPolicy, d: &DeviceCert) {
    let _ = Initiator::start(c, p, d);
}

#[cfg(feature = "timestamp_now")]
fn case<S: Read + Write + ReadTimeout>(s: S, c: &Credential, p: &impl PeerPolicy, d: &DeviceCert) {
    let _ = InitTimestamp::now();
}

#[cfg(feature = "default_clock_recv_before")]
fn case<S: Read + Write + ReadTimeout>(ch: &mut SecureChannel<S>) {
    let _ = ch.recv_before(Duration::from_secs(1));
}

#[cfg(feature = "with_clock")]
fn case<S: Read + Write + ReadTimeout>(
    s: S,
    t: S,
    u: S,
    c: &Credential,
    p: &impl PeerPolicy,
    d: &DeviceCert,
) {
    let one = Duration::from_secs(1);
    if let Ok(mut ch) = SecureChannel::connect_with_clock(s, c, p, d, one, HostClock) {
        let _ = ch.recv_before(one);
    }
    let _ = SecureChannel::accept_with_clock(t, c, p, one, &HostClock);
    let _ = AnonymousChannel::connect_with_clock(u, p, d, one, HostClock);
    let _ = Initiator::start_with_clock(c, p, d, &HostClock);
    let _ = InitTimestamp::from_clock(&HostClock);
}
"""


def target_dir() -> Path:
    return Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target"))


def write_fixture() -> Path:
    # under the repository, so a cargo configuration of the repository applies to the fixture too
    fixture = ROOT / "target" / "wasm-clock-fixture"
    if fixture.exists():
        shutil.rmtree(fixture)
    fixture.mkdir(parents=True)
    features = "\n".join(f"{name} = []" for name in [*REFUSED, CONTROL])
    (fixture / "Cargo.toml").write_text(
        CARGO_TOML.format(root=ROOT.as_posix(), features=features), encoding="utf-8"
    )
    (fixture / "lib.rs").write_text(LIB_RS, encoding="utf-8")
    shutil.copy(ROOT / "Cargo.lock", fixture / "Cargo.lock")
    return fixture


def check(fixture: Path, target: str | None, feature: str) -> subprocess.CompletedProcess[str]:
    tgt = ["--target", target] if target else []
    return subprocess.run(
        ["cargo", "check", "--lib", "--message-format", "short", "--features", feature, *tgt],
        cwd=fixture,
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, "CARGO_TARGET_DIR": str(target_dir())},
    )


def tail(out: subprocess.CompletedProcess[str]) -> str:
    return "\n".join(out.stderr.strip().splitlines()[-6:])


def main() -> int:
    fixture = write_fixture()
    problems: list[str] = []
    ran = 0
    expected = 2 * len(REFUSED) + 2
    for feature, item in REFUSED.items():
        out = check(fixture, WASM, feature)
        ran += 1
        errors = [l for l in out.stderr.splitlines() if "error[E0599]" in l]
        if out.returncode == 0:
            problems.append(f"{WASM} {feature}: compiled, must be refused (no clock on this target)")
        elif not any(f"`{item}`" in l for l in errors):
            problems.append(f"{WASM} {feature}: failed without E0599 naming `{item}`:\n{tail(out)}")
        else:
            print(f"ok   {WASM} {feature}: refused (E0599 `{item}`)")
        out = check(fixture, None, feature)
        ran += 1
        if out.returncode != 0:
            problems.append(f"host {feature}: does not compile:\n{tail(out)}")
        else:
            print(f"ok   host {feature}: compiles")
    for target in (WASM, None):
        out = check(fixture, target, CONTROL)
        ran += 1
        if out.returncode != 0:
            problems.append(f"{target or 'host'} {CONTROL}: does not compile:\n{tail(out)}")
        else:
            print(f"ok   {target or 'host'} {CONTROL}: compiles")
    for p in problems:
        print(f"FAIL {p}")
    print(f"wasm-clock-required: {ran} checks, {len(problems)} problems")
    if ran != expected or ran == 0:
        print(f"::error::ran {ran} of {expected} checks")
        return 1
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
