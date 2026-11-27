#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Points node-gyp at the C++ headers inside the Node.js install on PATH, for
# every later step of the job (through $GITHUB_ENV), so `npm ci` builds the
# native addons (fs-ext, better-sqlite3, cpu-features) without downloading
# headers.
#
# Without it, each addon's install script downloads the headers into the shared
# ~/.cache/node-gyp/<version> on a fresh runner, and npm runs those scripts
# concurrently: a compile that read a half-extracted header failed with
# "invalid use of incomplete type 'class v8::Value'" and similar (runs
# 40587989001, 41241490297, 42567107819 and 45555855273; issue #152).
set -euo pipefail
dir=$(dirname "$(dirname "$(command -v node)")")
if [[ ! -f $dir/include/node/node.h ]]; then
  echo "::error::$dir has no include/node/node.h; node-gyp would download headers" >&2
  exit 1
fi
echo "npm_config_nodedir=$dir" >> "$GITHUB_ENV"
echo "node-gyp uses the headers in $dir/include/node ($(node -v))"
