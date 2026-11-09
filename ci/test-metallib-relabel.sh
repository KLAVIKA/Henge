#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
base64 -D -i ci/fixtures/air-macos-triple.bc.b64 -o "$tmp/air-versioned.bc"
base64 -D -i ci/fixtures/air-macosx15.6-triple.bc.b64 -o "$tmp/air-versionless.bc"
clang -std=c11 -Wall -Wextra -Werror -I. \
  ci/test-metallib-relabel.c devices/metallib.c -o "$tmp/test-metallib-relabel"
"$tmp/test-metallib-relabel" "$tmp/air-versioned.bc" \
  "air64_v27-apple-macosx15.0.0" "air64_v26-apple-ios17.000.00"
"$tmp/test-metallib-relabel" "$tmp/air-versionless.bc" \
  "air64-apple-macosx15.6.0" "air64-apple-ios17.000.00"
