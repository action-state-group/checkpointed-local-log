#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Run from ts/ after `npm ci` in a job that ran use-node-headers.sh: the native
# addons load under this Node.js, and node-gyp downloaded no headers for it (it
# would have created ~/.cache/node-gyp/<version>).
set -euo pipefail
cache=$HOME/.cache/node-gyp/$(node -p 'process.versions.node')
if [[ -e $cache ]]; then
  echo "::error::node-gyp downloaded headers into $cache despite npm_config_nodedir" >&2
  exit 1
fi
node -e 'require("fs-ext"); require("better-sqlite3"); console.log(`native addons load under Node.js ${process.version}`)'
