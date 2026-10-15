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
export CLL_TS_DIST=${CLL_TS_DIST:-"$workspace_root/ts/dist"}

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

# Every language that ships a backend has a driver with the same modes:
#   <driver> advance|verify|summary|hold|expect-contention <backend> <target> <log-id> [argument...]
# CLL_INTEROP_LANGUAGES selects a subset (default: all). The py driver runs
# under CLL_PYTHON (default: python3), which must have ./python installed.
all_languages=(go ts py rs)
read -r -a languages <<<"${CLL_INTEROP_LANGUAGES:-${all_languages[*]}}"

# The Rust driver is built once; every call runs the binary.
rs_driver="${CARGO_TARGET_DIR:-$workspace_root/rust/target}/debug/examples/storage_interop"
if [[ " ${languages[*]} " == *" rs "* ]]; then
  cargo build --quiet --manifest-path "$workspace_root/rust/Cargo.toml" \
    -p checkpointed-local-log --features sqlite,mysql --example storage_interop
fi

driver() {
  local language=$1
  shift
  case "$language" in
    go) go -C "$go_dir" run ./test/interop/storage "$@" ;;
    ts) node "$go_dir/test/interop/storage.mjs" "$@" ;;
    py) "${CLL_PYTHON:-python3}" "$go_dir/test/interop/storage.py" "$@" ;;
    rs) "$rs_driver" "$@" ;;
    *)
      echo "unsupported language: $language" >&2
      return 2
      ;;
  esac
}

# target <language> <name>: the storage location a language opens for one log.
# Go takes a MySQL DSN; every other driver takes a mysql:// URL.
target() {
  case "$backend" in
    jsonl | sqlite) echo "$work_dir/$2.$backend" ;;
    mysql)
      if [[ "$1" == go ]]; then echo "$CLL_MYSQL_DSN"; else echo "$CLL_MYSQL_URL"; fi
      ;;
  esac
}

case "$backend" in
  jsonl | sqlite) ;;
  mysql)
    if [[ -z "${CLL_MYSQL_DSN:-}" || -z "${CLL_MYSQL_URL:-}" ]]; then
      echo "CLL_MYSQL_DSN and CLL_MYSQL_URL are required for mysql" >&2
      exit 1
    fi
    ;;
  *)
    echo "unsupported backend: $backend" >&2
    exit 2
    ;;
esac

suffix="${GITHUB_RUN_ID:-local}-$$"

canonical() {
  python3 -c 'import json, sys; print(json.dumps(json.load(sys.stdin), sort_keys=True, separators=(",", ":")))'
}

# For every ordered pair: the first language creates the log, the second
# continues it, the first continues again and the second verifies all three
# entries, checkpoints, nodes and witness rows.
for first in "${languages[@]}"; do
  for second in "${languages[@]}"; do
    [[ "$first" == "$second" ]] && continue
    name="interop-$first-$second-$suffix"
    driver "$first" advance "$backend" "$(target "$first" "$name")" "$name"
    driver "$second" advance "$backend" "$(target "$second" "$name")" "$name"
    driver "$first" advance "$backend" "$(target "$first" "$name")" "$name"
    driver "$second" verify "$backend" "$(target "$second" "$name")" "$name" 3
    # Every language must read the same entries, state, witness rows and
    # checkpoint root from this log, byte for byte after canonical encoding.
    for reader in "${languages[@]}"; do
      driver "$reader" summary "$backend" "$(target "$reader" "$name")" "$name" |
        canonical >"$work_dir/$name.$reader.summary"
    done
    for reader in "${languages[@]}"; do
      if ! cmp -s "$work_dir/$name.$first.summary" "$work_dir/$name.$reader.summary"; then
        echo "$backend: $reader reads $first -> $second differently from $first" >&2
        diff "$work_dir/$name.$first.summary" "$work_dir/$name.$reader.summary" >&2 || true
        exit 1
      fi
    done
    echo "$backend: $first -> $second passed; root $(sed -n 's/.*"root": *"\([0-9a-f]*\)".*/\1/p' "$work_dir/$name.$first.summary")"
  done
done

if [[ "$backend" == "jsonl" ]]; then
  wait_ready() {
    local ready=$1
    for _ in {1..600}; do
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

  # Each writer must lock the journal descriptor itself, so a holder in any
  # language excludes a writer in every other.
  for holder in "${languages[@]}"; do
    lock_target="$work_dir/lock-$holder.jsonl"
    ready_path="$work_dir/$holder.ready"
    stop_path="$work_dir/$holder.stop"
    driver "$holder" hold jsonl "$lock_target" lock-test "$ready_path" "$stop_path" &
    holder_pid=$!
    wait_ready "$ready_path"
    for contender in "${languages[@]}"; do
      [[ "$contender" == "$holder" ]] && continue
      driver "$contender" expect-contention jsonl "$lock_target" lock-test
    done
    : >"$stop_path"
    wait "$holder_pid"
    holder_pid=""
  done
fi

echo "$backend storage interoperability passed: ${languages[*]}"
