#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Only an explicit crates.io 404 permits publishing a new immutable version.
# Exit 0: absent; 2: existing; 1: invalid input or registry failure.
set -euo pipefail
crate=${1:?crate name required}
version=${2:?version required}
if [[ ! "$crate" =~ ^[a-z0-9_-]+$ || ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "invalid crate name or version" >&2; exit 1
fi
status=$(curl --silent --show-error --connect-timeout 10 --max-time 30 \
  --output /dev/null --write-out '%{http_code}' \
  -A "publish-crates (github.com/${GITHUB_REPOSITORY:-action-state-group/checkpointed-local-log})" \
  "https://crates.io/api/v1/crates/$crate/$version") || {
  echo "could not establish registry availability for $crate $version" >&2; exit 1
}
case "$status" in
  404) echo "$crate $version is absent from crates.io" ;;
  200) echo "$crate $version is already on crates.io" >&2; exit 2 ;;
  *) echo "unexpected crates.io HTTP status $status for $crate $version" >&2; exit 1 ;;
esac
