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
# better-sqlite3 loads its binding only when a database opens.
node -e '
require("fs-ext");
const Database = require("better-sqlite3");
const db = new Database(":memory:");
if (db.prepare("SELECT 1 AS one").get().one !== 1) throw new Error("better-sqlite3 returned a wrong row");
db.close();
console.log(`native addons load under Node.js ${process.version}`);
'
