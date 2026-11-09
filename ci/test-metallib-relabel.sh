#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
base64 -D -i ci/fixtures/air-macos-triple.bc.b64 -o "$tmp/air.bc"
clang -std=c11 -Wall -Wextra -Werror -I. \
  ci/test-metallib-relabel.c devices/metallib.c -o "$tmp/test-metallib-relabel"
"$tmp/test-metallib-relabel" "$tmp/air.bc"
