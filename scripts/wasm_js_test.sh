#!/usr/bin/env bash
# Run one test file on WebAssembly (wasm32-unknown-unknown) in a JavaScript host: Node, through
# wasm-bindgen-test-runner at the version of the `wasm-bindgen` entry in Cargo.lock (a runner of another
# version refuses the test binary). The library is checked for that target first. Every test in the file must
# pass: the expected count is the number of `wasm_bindgen_test` attributes in it, and a file with none, or a
# run that passes fewer (0 included), fails.
#
# usage: scripts/wasm_js_test.sh <test file stem under tests/>
set -euo pipefail
cd "$(dirname "$0")/.."

name="${1:?usage: scripts/wasm_js_test.sh <test file stem>}"
file="tests/${name}.rs"
[ -f "$file" ] || { echo "::error::no test file $file"; exit 1; }
expected="$(grep -c 'wasm_bindgen_test)\]' "$file" || true)"
if [ "${expected:-0}" -lt 1 ]; then
  echo "::error::$file has no wasm_bindgen_test"
  exit 1
fi

want="$(awk '/^name = "wasm-bindgen"$/ { getline; gsub(/version = |"/, ""); print; exit }' Cargo.lock)"
[ -n "$want" ] || { echo "::error::Cargo.lock has no wasm-bindgen entry"; exit 1; }
command -v node >/dev/null 2>&1 || { echo "::error::node is not installed"; exit 1; }
have="$(wasm-bindgen-test-runner --version 2>/dev/null | awk '{ print $2 }' || true)"
if [ "$have" != "$want" ]; then
  echo "::error::wasm-bindgen-test-runner is ${have:-missing}, Cargo.lock has wasm-bindgen $want (cargo install wasm-bindgen-cli --version $want --locked)"
  exit 1
fi
echo "node $(node --version), wasm-bindgen-test-runner $have"

cargo check --locked --lib --target wasm32-unknown-unknown

log="$(mktemp)"
trap 'rm -f "$log"' EXIT
CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner \
  cargo test --locked --target wasm32-unknown-unknown --test "$name" 2>&1 | tee "$log"
passed="$(sed -n 's/^test result: ok\. \([0-9][0-9]*\) passed.*/\1/p' "$log" | awk '{ s += $1 } END { print s + 0 }')"
echo "wasm32-unknown-unknown under Node: $name: $passed of $expected passed"
if [ "$passed" -ne "$expected" ]; then
  echo "::error::$name: $passed of $expected tests passed on wasm32-unknown-unknown"
  exit 1
fi
