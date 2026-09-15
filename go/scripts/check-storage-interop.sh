#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: check-storage-interop.sh <jsonl|sqlite|mysql>" >&2
  exit 2
fi

backend=$1
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
go_dir=$(cd -- "$script_dir/.." && pwd)
workspace_root=$(cd -- "$go_dir/.." && pwd)
export CLL_TS_DIST=${CLL_TS_DIST:-"$workspace_root/cll-ts/dist"}

if [[ ! -f "$CLL_TS_DIST/index.js" ]]; then
  echo "built cll-ts dist not found at $CLL_TS_DIST" >&2
  exit 1
fi

work_dir=$(mktemp -d)
holder_pid=""
stop_path=""
cleanup() {
  if [[ -n "$holder_pid" ]]; then
    if [[ -n "$stop_path" ]]; then
      : >"$stop_path"
    fi
    wait "$holder_pid" 2>/dev/null || true
  fi
  rm -rf -- "$work_dir"
}
trap cleanup EXIT

case "$backend" in
  jsonl)
    first_go_target="$work_dir/go-first.jsonl"
    first_ts_target=$first_go_target
    second_go_target="$work_dir/ts-first.jsonl"
    second_ts_target=$second_go_target
    ;;
  sqlite)
    first_go_target="$work_dir/go-first.sqlite"
    first_ts_target=$first_go_target
    second_go_target="$work_dir/ts-first.sqlite"
    second_ts_target=$second_go_target
    ;;
  mysql)
    if [[ -z "${CLL_MYSQL_DSN:-}" ]]; then
      echo "CLL_MYSQL_DSN is required for mysql" >&2
      exit 1
    fi
    if [[ -z "${CLL_MYSQL_URL:-}" ]]; then
      echo "CLL_MYSQL_URL is required for mysql" >&2
      exit 1
    fi
    first_go_target=$CLL_MYSQL_DSN
    first_ts_target=$CLL_MYSQL_URL
    second_go_target=$CLL_MYSQL_DSN
    second_ts_target=$CLL_MYSQL_URL
    ;;
  *)
    echo "unsupported backend: $backend" >&2
    exit 2
    ;;
esac

suffix="${GITHUB_RUN_ID:-local}-$$"
first_log="interop-go-first-$suffix"
second_log="interop-ts-first-$suffix"

go_driver() {
  go -C "$go_dir" run ./test/interop/storage "$@"
}

ts_driver() {
  node "$go_dir/test/interop/storage.mjs" "$@"
}

go_driver advance "$backend" "$first_go_target" "$first_log"
ts_driver advance "$backend" "$first_ts_target" "$first_log"
go_driver advance "$backend" "$first_go_target" "$first_log"
ts_driver verify "$backend" "$first_ts_target" "$first_log" 3

ts_driver advance "$backend" "$second_ts_target" "$second_log"
go_driver advance "$backend" "$second_go_target" "$second_log"
ts_driver advance "$backend" "$second_ts_target" "$second_log"
go_driver verify "$backend" "$second_go_target" "$second_log" 3

if [[ "$backend" == "jsonl" ]]; then
  wait_ready() {
    local ready=$1
    for _ in {1..200}; do
      if [[ -f "$ready" ]]; then
        return 0
      fi
      if ! kill -0 "$holder_pid" 2>/dev/null; then
        wait "$holder_pid"
        return 1
      fi
      sleep 0.05
    done
    echo "timed out waiting for JSONL lock holder" >&2
    return 1
  }

  lock_target="$work_dir/lock.jsonl"
  ready_path="$work_dir/go.ready"
  stop_path="$work_dir/go.stop"
  go_driver hold jsonl "$lock_target" lock-test "$ready_path" "$stop_path" &
  holder_pid=$!
  wait_ready "$ready_path"
  ts_driver expect-contention jsonl "$lock_target" lock-test
  : >"$stop_path"
  wait "$holder_pid"
  holder_pid=""

  ready_path="$work_dir/ts.ready"
  stop_path="$work_dir/ts.stop"
  ts_driver hold jsonl "$lock_target" lock-test "$ready_path" "$stop_path" &
  holder_pid=$!
  wait_ready "$ready_path"
  go_driver expect-contention jsonl "$lock_target" lock-test
  : >"$stop_path"
  wait "$holder_pid"
  holder_pid=""
fi

echo "$backend Go/TypeScript storage interoperability passed"
