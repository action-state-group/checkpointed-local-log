#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
root=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cat > "$work/curl" <<'SH'
#!/usr/bin/env bash
printf '%s' "$TEST_HTTP_STATUS"
exit "$TEST_CURL_EXIT"
SH
chmod +x "$work/curl"
export PATH="$work:$PATH"
export TEST_CURL_EXIT=0
for status in 404 200 401 403 429 500 000; do
  export TEST_HTTP_STATUS="$status"
  if bash "$root/check_crate_availability.sh" evidencebook 0.0.2 > "$work/result" 2>&1; then
    [ "$status" = 404 ] || { cat "$work/result"; exit 1; }
  else
    result=$?
    expected=1
    [ "$status" != 200 ] || expected=2
    [ "$status" != 404 ] && [ "$result" = "$expected" ] || { cat "$work/result"; exit 1; }
  fi
done
export TEST_HTTP_STATUS=404 TEST_CURL_EXIT=6
if bash "$root/check_crate_availability.sh" evidencebook 0.0.2 > "$work/result" 2>&1; then
  echo "network failure incorrectly accepted as absence" >&2; exit 1
fi
export TEST_CURL_EXIT=0
if bash "$root/check_crate_availability.sh" '../unexpected' 0.0.2 > "$work/result" 2>&1; then
  echo "invalid crate accepted" >&2; exit 1
fi
echo 'Crate availability: explicit absence, existing version and error tests passed.'
