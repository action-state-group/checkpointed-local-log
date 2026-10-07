#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$root"
interop_dir=$(mktemp -d)
trap 'rm -rf "$interop_dir"' EXIT
node ts/test/interop/checkpoint.mjs write "$interop_dir/ts.cose"
go -C go run ./test/interop/checkpoint verify "$interop_dir/ts.cose"
go -C go run ./test/interop/checkpoint write "$interop_dir/go.cose"
node ts/test/interop/checkpoint.mjs verify "$interop_dir/go.cose"
python ts/test/interop/verify_checkpoint.py "$interop_dir/ts.cose"
python ts/test/interop/verify_checkpoint.py "$interop_dir/go.cose"
cmp "$interop_dir/ts.cose" "$interop_dir/go.cose"
