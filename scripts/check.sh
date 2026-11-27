#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Local check before a push: the commands CI runs, on this machine.
#
#   scripts/check.sh          what every pull request ran before the heavy
#                             suites left the PR path: Go, TypeScript (Node.js
#                             22 and 24), Python and Rust CI, the storage
#                             interlock (jsonl, sqlite and mysql),
#                             same-revision interoperability, the research
#                             vectors and crate packaging.
#   scripts/check.sh --full   also Python 3.9 (CI's oldest matrix version) and
#                             the spec build.
#
# Needs Go, npm (Node.js 22 and 24 are fetched with `npx -p node@<version>`;
# everything after the TypeScript steps runs on 24, as CI does), Rust (stable, rustfmt, clippy), Python 3.12 (and
# 3.9 for --full) found by `uv python find` or as python3.12/python3.9, and a
# running Docker daemon in any context (set DOCKER_HOST for a non-default one;
# with Colima, testcontainers also needs
# TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE=/var/run/docker.sock). The Python, Rust
# and interlock MySQL tests get a mysql:8.4 container from this script, as CI
# gives them a service; the Go and TypeScript MySQL tests start their own
# through testcontainers. --full also needs kramdown-rfc 1.7.43 and xml2rfc
# 3.34.1, the versions that built the committed spec/ files and that spec.yml
# pins (another xml2rfc changes the generator line). DCO, leak lint and the neutrality scan need CI's secrets or PR range and are
# not run (the neutrality scanner's self-test is).
#
# Independent groups run in parallel, each with its output in its own log:
# Go (and, with --full, the spec build); TypeScript on Node.js 22 then 24;
# Python then Rust and crate packaging (they share the Python 3.12
# virtualenv, python/build and rust/target). The cross-language steps that use
# their builds (interoperability, research vectors, storage interlock) then run
# in sequence. A group's log is printed when the group ends; a line per step
# reports progress meanwhile.
#
# Every step runs even after one fails, and a step whose MySQL container does
# not start still runs and counts as failed (with CI set, its MySQL tests fail
# without a server). The summary lists each step's result and the script exits
# 1 when any failed, or when a group ended without reporting its steps. Ctrl-C
# or a TERM stops every group. Containers it starts are named
# $CLL_CHECK_CONTAINER_PREFIX-<step>-<pid> (default prefix cll-check) and
# removed on exit.
set -uo pipefail
# Job control gives each background group its own process group, so stopping
# a group stops every command it started.
set -m

full=false
case "${1:-}" in
  "") ;;
  --full) full=true ;;
  *) echo "usage: scripts/check.sh [--full]" >&2; exit 2 ;;
esac

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root" || exit 2
# CI sets these; with CI set the MySQL tests fail instead of skipping when
# their server is missing.
export CI=true GITHUB_WORKSPACE="$root"
prefix=${CLL_CHECK_CONTAINER_PREFIX:-cll-check}
work=$(mktemp -d)
# Every container a step starts, from any group, is listed here so the parent
# removes it on exit.
container_list=$work/containers
: > "$container_list"
group_pids=()
# kill_group <pgid>: stops every process in a process group. A process the
# group forks while the first signal is sent can miss it, so the group is
# signalled again until it is empty, and killed after about 5 seconds.
kill_group() {
  local i
  for ((i = 0; i < 50; i++)); do
    kill -TERM -- "-$1" 2>/dev/null || return 0
    sleep 0.1
  done
  kill -KILL -- "-$1" 2>/dev/null
  return 0
}
stop_groups() {
  local pid
  for pid in "${group_pids[@]}"; do kill_group "$pid"; done
  for pid in "${group_pids[@]}"; do wait "$pid" 2>/dev/null; done
  group_pids=()
}
cleanup() {
  stop_groups
  local c
  while read -r c; do [[ -n $c ]] && docker rm -f "$c" >/dev/null 2>&1; done < "$container_list"
  rm -rf "$work"
}
trap cleanup EXIT
trap 'echo "interrupted" >&2; exit 130' INT TERM

# step <name> <command...>: runs the command and appends its result to
# $results_file. Progress goes to fd 3, the terminal, since a group's own
# output goes to its log.
exec 3>&1
results_file=$work/main.results
: > "$results_file"
failed=0
step() {
  local name=$1; shift
  local start=$SECONDS line
  echo
  echo "=== $name"
  if "$@"; then
    line="ok    $((SECONDS - start))s  $name"
  else
    line="FAIL  $((SECONDS - start))s  $name"
    failed=1
  fi
  echo "$line" >> "$results_file"
  echo "  $line" >&3
}

# group <name> <function>: runs the function in the background with its output
# in $work/<name>.log and its results in $work/<name>.results; the subshell
# exits 1 when any of its steps failed.
group() {
  local name=$1 fn=$2
  : > "$work/$name.results"
  (
    results_file=$work/$name.results failed=0
    trap - EXIT INT TERM
    "$fn" > "$work/$name.log" 2>&1 < /dev/null
    exit "$failed"
  ) &
  group_pids+=("$!")
  group_names+=("$name")
}
group_names=()
# wait_groups: waits for every running group, prints its log and results, and
# fails a group that exited non-zero without reporting a failed step.
wait_groups() {
  local i pid name status
  for i in "${!group_pids[@]}"; do
    pid=${group_pids[$i]} name=${group_names[$i]}
    wait "$pid"; status=$?
    # A group whose shell died can leave commands running in its process
    # group; stop them before later steps use the same build directories.
    kill_group "$pid"
    echo
    echo "##### group $name (exit $status)"
    cat "$work/$name.log"
    cat "$work/$name.results" >> "$work/main.results"
    if ((status != 0)); then
      failed=1
      grep -q '^FAIL' "$work/$name.results" ||
        echo "FAIL  -     group $name exited $status without a failed step" >> "$work/main.results"
    fi
  done
  group_pids=() group_names=()
}

find_python() {
  local version=$1 found
  if command -v uv >/dev/null && found=$(uv python find "$version" 2>/dev/null); then
    echo "$found"
  elif command -v "python$version" >/dev/null; then
    command -v "python$version"
  else
    echo "no Python $version found (uv python install $version)" >&2
    return 1
  fi
}

# A Python virtual environment under .venv-check-<version> (git-ignored).
venv() {
  local version=$1 dir="$root/.venv-check-$1" python
  if [[ ! -x "$dir/bin/python" ]]; then
    python=$(find_python "$version") || return 1
    "$python" -m venv "$dir" || return 1
  fi
  echo "$dir/bin"
}

# Starts a mysql:8.4 container like CI's service (database cll, the given root
# password) and exports CLL_MYSQL_URL and CLL_MYSQL_DSN for it.
start_mysql() {
  local name="$prefix-$1-$$" password=$2 port i
  echo "$name" >> "$container_list"
  docker run -d --name "$name" -e MYSQL_ROOT_PASSWORD="$password" -e MYSQL_DATABASE=cll \
    -p 127.0.0.1::3306 mysql:8.4 >/dev/null || return 1
  port=$(docker port "$name" 3306/tcp | head -n 1 | sed 's/.*://') || return 1
  for ((i = 0; i < 90; i++)); do
    if docker exec "$name" mysql -h 127.0.0.1 -uroot -p"$password" -e 'SELECT 1' cll >/dev/null 2>&1; then
      export CLL_MYSQL_URL="mysql://root:$password@127.0.0.1:$port/cll"
      export CLL_MYSQL_DSN="root:$password@tcp(127.0.0.1:$port)/cll"
      return 0
    fi
    sleep 2
  done
  echo "MySQL container $name did not become ready" >&2
  return 1
}
stop_mysql() {
  docker rm -f "$prefix-$1-$$" >/dev/null 2>&1
  unset CLL_MYSQL_URL CLL_MYSQL_DSN
}

# --- Go CI (ci-go.yml) -------------------------------------------------------
go_quality() (
  cd go &&
    test -z "$(gofmt -l .)" &&
    go mod tidy &&
    git diff --exit-code -- go.mod go.sum &&
    go vet ./... &&
    go run ./test/runnervectors -check
)
go_unit() (cd go && go test ./...)
go_race() (cd go && go test -race ./...)

# --- TypeScript CI (ci-ts.yml) -----------------------------------------------
# CI runs `npm ci` in every job; here once per Node.js version, before that
# version's other TypeScript steps, so native modules match the runtime.
node_dir() { npx -y -p "node@$1" -- sh -c 'dirname "$(command -v node)"'; }
node22_dir="" node24_dir=""
resolve_node() {
  node22_dir=$(node_dir 22) && node24_dir=$(node_dir 24) &&
    export PATH="$node24_dir:$PATH" &&
    PATH="$node22_dir:$PATH" node -v && node -v
}
# on_node <22|24> <function>: runs the function with that Node.js first on PATH.
on_node() {
  local dir
  if [[ $1 == 22 ]]; then dir=$node22_dir; else dir=$node24_dir; fi
  [[ -n $dir ]] || { echo "Node.js $1 was not resolved" >&2; return 1; }
  shift
  PATH="$dir:$PATH" "$@"
}
ts_install() (cd ts && npm ci)
ts_quality() (cd ts && CLL_ROOT=.. npm run format:check && npm run lint && npm run typecheck)
ts_unit_and_build() (
  cd ts && export CLL_ROOT=.. &&
    npm run build &&
    npx vitest run --coverage --exclude test/mysql.test.ts
)
# CI adds --with-deps, which installs Linux system packages.
ts_browser() (cd ts && export CLL_ROOT=.. && npx playwright install chromium && npm run test:browser)
ts_mysql() (cd ts && CLL_ROOT=.. npx vitest run test/mysql.test.ts)
ts_package_smoke() (
  cd ts || exit 1
  package_dir="$work/ts-package" consumer_dir="$work/ts-consumer"
  rm -rf "$package_dir" "$consumer_dir" && mkdir -p "$package_dir" "$consumer_dir" &&
    npm run build &&
    npm pack --pack-destination "$package_dir" &&
    cd "$consumer_dir" &&
    npm init -y >/dev/null &&
    npm install "$package_dir"/*.tgz &&
    node -e 'await import("@action-state-group/cll"); await import("@action-state-group/cll/jsonl"); await import("@action-state-group/cll/sqlite"); await import("@action-state-group/cll/mysql"); const { conformanceCases } = await import("@action-state-group/cll/conformance"); if (conformanceCases({ open: () => ({}) }).length === 0) throw new Error("no conformance cases")' &&
    node --conditions=browser -e 'const { checkpointMetadata } = await import("@action-state-group/cll"); const { readFileSync } = await import("node:fs"); const { cases } = JSON.parse(readFileSync(`${process.env.GITHUB_WORKSPACE}/checkpoint-conformance-vectors/cose-vectors.json`, "utf8")); for (const vector of cases) if ((await checkpointMetadata(Buffer.from(vector.cose_hex, "hex"))) === undefined) throw new Error(`browser entry refused ${vector.name}`)'
)

# --- Python CI (python.yml), one matrix version ------------------------------
python_test() {
  local version=$1 bin
  # A source install builds into python/build (git-ignored), and the tests
  # scan the python/ tree, so a copy left by an earlier run fails them. CI
  # always starts from a fresh checkout.
  rm -rf python/build
  bin=$(venv "$version") || return 1
  local mysql=0
  start_mysql "python$version" python || mysql=1
  (
    export PATH="$bin:$PATH"
    cd python &&
      python -m pip install -q --upgrade pip &&
      python -m pip install -q -e ".[dev,mysql]" &&
      python -m ruff check . &&
      python -m pytest -q &&
      python -c "import sys, cll, cll.log; loaded = [m for m in ('sqlite3', 'pymysql') if m in sys.modules]; assert not loaded, loaded" &&
      python -m pytest -q ../.github/test_leak_lint.py &&
      python -m pytest -q ../.github/test_release.py &&
      python -m pytest -q ../.github/test_check_script.py &&
      python -m pip install -q build &&
      bash ../.github/scripts/check_python_package.sh
  )
  local status=$?
  rm -rf python/build
  stop_mysql "python$version"
  return $((status | mysql))
}

# The 3.12 environment every later step uses for `python`.
py312() { venv 3.12; }

# --- Rust CI (rust.yml) ------------------------------------------------------
rust_test() {
  local bin
  bin=$(py312) || return 1
  local mysql=0
  start_mysql rust rust || mysql=1
  (
    export PATH="$bin:$PATH"
    python -m pip install -q -e "./python[dev]" &&
      cd rust &&
      cargo fmt --all -- --check &&
      cargo clippy --all-targets --all-features -- -D warnings &&
      cargo test --all-features &&
      (unset CLL_MYSQL_URL; cargo test) &&
      RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
  )
  local status=$?
  stop_mysql rust
  return $((status | mysql))
}
rust_cross_language_vectors() (
  bin=$(py312) || exit 1
  export PATH="$bin:$PATH"
  python -m pip install -q -e "./python[dev]" &&
    python3 mmr-conformance-vectors/reference_verifier.py &&
    python3 commitment-conformance-vectors/reference_verifier.py &&
    python3 checkpoint-conformance-vectors/reference_verifier.py &&
    cd rust &&
    cargo run --quiet -p checkpointed-local-log --example trait_signed_checkpoint |
    python3 ../checkpoint-conformance-vectors/verify_trait_signed_cose.py
)

# --- Crate packaging (crates-package.yml) ------------------------------------
crates_package() (
  bin=$(py312) || exit 1
  export PATH="$bin:$PATH"
  bash .github/scripts/test_crate_availability.sh &&
    python3 .github/scripts/check_crate_metadata.py rust/checkpointed-local-log/Cargo.toml &&
    cd rust || exit 1
  crate=checkpointed-local-log
  cargo package --list --allow-dirty -p "$crate" > "$work/$crate.list" || exit 1
  echo "== $crate"; cat "$work/$crate.list"
  # The one vector file a crate may ship: the pinned copy the conformance
  # runner embeds with include_str!.
  if grep -v '^src/log/conformance/vectors\.json$' "$work/$crate.list" |
    grep -E '^(tests|examples|scripts|target)/|vectors|\.(pem|key|env)$'; then
    echo "$crate packages a file it must not ship" >&2; exit 1
  fi
  cargo publish --dry-run --allow-dirty -p checkpointed-local-log
)

# --- Same-revision interoperability (interop.yml) ----------------------------
interop() (
  bin=$(py312) || exit 1
  export PATH="$bin:$PATH"
  (cd ts && npm run build) &&
    python -m pip install -q -e "./python[dev]" &&
    bash .github/scripts/check_checkpoint_interop.sh
)

# --- External MMR profile research vectors (research-vectors.yml) ------------
research_vectors() (
  bin=$(py312) || exit 1
  export PATH="$bin:$PATH"
  python -m pip install -q -e "./python[dev]" &&
    python mmr-profile-vectors/generate.py --check &&
    python cll-02-vectors/generate.py --check &&
    python backend-conformance-vectors/generate.py --check &&
    python checkpoint-conformance-vectors/generate_ed25519.py --check &&
    python checkpoint-conformance-vectors/generate_receipts.py --check &&
    (cd python && python -m pytest tests/checkpoint/test_mmr_profile_vectors.py)
)

# --- Storage interlock (storage-interlock.yml), one backend ------------------
storage_interlock() {
  local backend=$1 bin mysql=0
  bin=$(py312) || return 1
  if [[ $backend == mysql ]]; then
    start_mysql interlock interop || mysql=1
  fi
  (
    export PATH="$bin:$PATH"
    (cd ts && npm run build) &&
      (cd rust && cargo build -p checkpointed-local-log --features sqlite,mysql --example storage_interop) &&
      (cd go && case "$backend" in
        mysql) go test -count=1 -run 'TestContractAndCrossHandle' ./store/mysql ;;
        *) go test -count=1 -run 'TestConformanceVectors' "./store/$backend" ;;
      esac) &&
      (cd ts && case "$backend" in
        jsonl) npx vitest run test/conformance.test.ts -t "conformance vectors: JSONL" ;;
        sqlite) npx vitest run test/conformance.test.ts -t "conformance vectors: SQLite" ;;
        mysql) npx vitest run test/mysql.test.ts -t "conformance vectors" ;;
      esac) &&
      python -m pip install -q -e "./python[dev,mysql]" &&
      (cd python && python -m pytest -q tests/log/test_conformance.py -k "$backend") &&
      (cd rust && cargo test -p checkpointed-local-log --features sqlite,mysql --test log_conformance -- --exact "${backend}_with_reopen") &&
      bash go/scripts/check-storage-interop.sh "$backend"
  )
  local status=$?
  [[ $backend != mysql ]] || stop_mysql interlock
  return $((status | mysql))
}

neutrality_self_test() (bin=$(py312) && "$bin/python" .github/neutrality_scan.py --self-test)

# --- Spec (spec.yml), --full only --------------------------------------------
spec_build() (
  # A fresh CI checkout's spec/.refcache is under kramdown-rfc's one-hour
  # cache TTL, so CI builds from the committed references. Build from a copy
  # with the cache offline, so an older clone neither refetches them nor
  # rewrites the tracked cache files.
  cp -R spec "$work/spec-src" && cd "$work/spec-src" || exit 1
  draft=$(grep '^DRAFT[[:space:]]*=' Makefile | sed 's/^DRAFT[[:space:]]*=[[:space:]]*//')
  out="$work/spec"
  mkdir -p "$out" &&
    KRAMDOWN_OFFLINE=1 kramdown-rfc "$draft.md" > "$out/.draft.v2.xml" &&
    xml2rfc --v2v3 "$out/.draft.v2.xml" -o "$out/$draft.xml" &&
    xml2rfc --text --v3 "$out/$draft.xml" -o "$out/$draft.txt" || exit 1
  # The same normalization as spec.yml: build-date-derived text is stripped.
  strip_xml() {
    grep -v 'generated by.*kramdown-rfc' |
      sed 's/<date year="[^"]*" month="[^"]*" day="[^"]*"\/>/<date\/>/g'
  }
  strip_txt() {
    sed \
      -e 's/^Expires: [0-9][0-9]* [A-Za-z][A-Za-z]* [0-9][0-9][0-9][0-9]/Expires: DATE_NORM/' \
      -e 's/expire on [0-9][0-9]* [A-Za-z][A-Za-z]* [0-9][0-9][0-9][0-9]/expire on DATE_NORM/' \
      -e 's/Expires [0-9][0-9]* [A-Za-z][A-Za-z]* [0-9][0-9][0-9][0-9]  *\[Page/Expires DATE_NORM [Page/' \
      -e 's/^\(Intended status:.*[A-Za-z]\)  *[0-9][0-9]* [A-Za-z][A-Za-z]* [0-9][0-9][0-9][0-9] *$/\1 DATE_NORM/' \
      -e '/^ *[0-9][0-9]* [A-Za-z][A-Za-z]* [0-9][0-9][0-9][0-9] *$/s/.*/DATE_NORM/' \
      -e '/DATE_NORM/s/  */ /g'
  }
  diff <(strip_xml < "$draft.xml") <(strip_xml < "$out/$draft.xml") ||
    { echo "STALE: $draft.xml is out of date; run 'make' and commit" >&2; exit 1; }
  diff <(strip_txt < "$draft.txt") <(strip_txt < "$out/$draft.txt") ||
    { echo "STALE: $draft.txt is out of date; run 'make' and commit" >&2; exit 1; }
  grep -q 'version="3"' "$out/$draft.xml"
)

go_group() {
  step "go: quality" go_quality
  step "go: unit tests" go_unit
  step "go: race tests" go_race
  if $full; then step "spec build" spec_build; fi
}
# 22 first: the later steps use ts/node_modules and ts/dist from the 24 pass.
ts_group() {
  local v
  for v in 22 24; do
    step "ts node $v: npm ci" on_node "$v" ts_install
    step "ts node $v: quality" on_node "$v" ts_quality
    step "ts node $v: unit and build" on_node "$v" ts_unit_and_build
    [[ $v != 24 ]] || step "ts node $v: browser" on_node "$v" ts_browser
    step "ts node $v: mysql" on_node "$v" ts_mysql
    step "ts node $v: package smoke" on_node "$v" ts_package_smoke
  done
}
python_rust_group() {
  step "python 3.12: test" python_test 3.12
  if $full; then step "python 3.9: test" python_test 3.9; fi
  step "rust: test" rust_test
  step "rust: cross-language vectors" rust_cross_language_vectors
  step "crate packaging" crates_package
}

# Resolved here, before the groups start, so every later step (the groups and
# the cross-language steps) runs on Node.js 24 from PATH.
step "node.js 22 and 24" resolve_node
group go go_group
group ts ts_group
group python-rust python_rust_group
wait_groups
step "same-revision interoperability" interop
step "research vectors" research_vectors
step "storage interlock: jsonl" storage_interlock jsonl
step "storage interlock: sqlite" storage_interlock sqlite
step "storage interlock: mysql" storage_interlock mysql
step "neutrality scanner self-test" neutrality_self_test

echo
echo "=== summary ($([[ $full == true ]] && echo full || echo check), ${SECONDS}s)"
cat "$work/main.results"
exit "$failed"
