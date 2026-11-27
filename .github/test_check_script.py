# SPDX-License-Identifier: Apache-2.0
"""Tests for scripts/check.sh's orchestration: parallel groups, failure
propagation, the summary and the exit status, and cleanup on an interrupt.

Each test copies the script into a temporary tree and runs it against fake
tools on PATH (go, npm, cargo, python, docker and the rest), which log every
call and exit 0 unless a test asks one call to fail, sleep or kill its group.
The real suites are not run.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check.sh"
BASH = shutil.which("bash")

# One script behind every fake tool name. FAKE_FAIL, FAKE_SLEEP,
# FAKE_KILLGROUP and FAKE_KILLLEADER are extended regular expressions matched against
# "<tool> <args...>".
FAKE = r"""#!/usr/bin/env bash
name=$(basename "$0")
call="$name $*"
echo "$$ $call" >> "$FAKE_LOG"
if [[ -n ${FAKE_KILLGROUP:-} && $call =~ $FAKE_KILLGROUP ]]; then
  kill -KILL 0
fi
if [[ -n ${FAKE_KILLLEADER:-} && $call =~ $FAKE_KILLLEADER ]]; then
  # Kill only the process group's leader (the group's shell), then outlive it.
  # Logged first: once the leader dies, check.sh may stop this command.
  echo "$$ sleeping" >> "$FAKE_LOG"
  kill -KILL "$(ps -o pgid= -p $$ | tr -d ' ')"
  sleep 300
fi
if [[ -n ${FAKE_SLEEP:-} && $call =~ $FAKE_SLEEP ]]; then
  echo "$$ sleeping" >> "$FAKE_LOG"
  sleep 300
fi
if [[ -n ${FAKE_FAIL:-} && $call =~ $FAKE_FAIL ]]; then
  exit 1
fi
case "$name $1 $2" in
  "npx "*) echo "$FAKE_BIN" ;;
  "docker port "*) echo "127.0.0.1:55555" ;;
  "uv python "*) echo "$FAKE_BIN/python" ;;
  "python -m venv"|"python3 -m venv"|"python3.12 -m venv")
    mkdir -p "$3/bin" && ln -sf "$FAKE_BIN/fake" "$3/bin/python" ;;
  "node -v "*) echo "v24.0.0" ;;
esac
exit 0
"""

TOOLS = [
    "go", "gofmt", "git", "npx", "npm", "node", "uv", "python", "python3",
    "cargo", "docker", "kramdown-rfc", "xml2rfc",
]

STUB_SCRIPTS = [
    ".github/scripts/check_python_package.sh",
    ".github/scripts/test_crate_availability.sh",
    ".github/scripts/check_checkpoint_interop.sh",
    "go/scripts/check-storage-interop.sh",
]

ALL_STEPS = [
    "node.js 22 and 24",
    "go: quality", "go: unit tests", "go: race tests",
    "ts node 22: npm ci", "ts node 22: quality", "ts node 22: unit and build",
    "ts node 22: mysql", "ts node 22: package smoke",
    "ts node 24: npm ci", "ts node 24: quality", "ts node 24: unit and build",
    "ts node 24: browser", "ts node 24: mysql", "ts node 24: package smoke",
    "python 3.12: test", "rust: test", "rust: cross-language vectors",
    "crate packaging", "same-revision interoperability", "research vectors",
    "storage interlock: jsonl", "storage interlock: sqlite",
    "storage interlock: mysql", "neutrality scanner self-test",
]

pytestmark = pytest.mark.skipif(BASH is None, reason="needs bash")


@pytest.fixture
def tree(tmp_path: Path) -> dict:
    root = tmp_path / "repo"
    (root / "scripts").mkdir(parents=True)
    shutil.copy(SCRIPT, root / "scripts" / "check.sh")
    for d in ("go", "ts", "python", "rust", "spec"):
        (root / d).mkdir()
    for rel in STUB_SCRIPTS:
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("exit 0\n")
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake = fake_bin / "fake"
    fake.write_text(FAKE)
    fake.chmod(0o755)
    for tool in TOOLS:
        (fake_bin / tool).symlink_to(fake)
    log = tmp_path / "calls.log"
    log.touch()
    env = {
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "HOME": str(tmp_path),
        "FAKE_BIN": str(fake_bin),
        "FAKE_LOG": str(log),
        "TMPDIR": str(tmp_path),
    }
    return {"root": root, "env": env, "log": log}


def run(tree: dict, **fake: str) -> subprocess.CompletedProcess:
    env = {**tree["env"], **fake}
    return subprocess.run(
        [BASH, str(tree["root"] / "scripts" / "check.sh")],
        env=env, capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL,
    )


def summary(out: str) -> dict[str, str]:
    """Maps each step in the final summary to ok or FAIL."""
    lines = out.split("=== summary", 1)[1].splitlines()[1:]
    result = {}
    for line in lines:
        status, _, name = line.split(None, 2)
        result[name] = status
    return result


def assert_containers_removed(calls: list[str]) -> None:
    """Every container the run started was removed with its anonymous volumes
    (mysql:8.4 declares /var/lib/mysql a volume; `docker rm -f` alone leaves it
    behind and fills Docker's disk run after run)."""
    started = {
        line.split("--name ", 1)[1].split()[0]
        for line in calls if line.split(None, 1)[1].startswith("docker run ")
    }
    assert started, calls
    removals = [line.split(None, 1)[1] for line in calls if " docker rm " in f" {line} "]
    # A removal without -v orphans the volume for good: a later `rm -v` of
    # the same name finds no container.
    assert all(r.startswith("docker rm -f -v ") for r in removals), removals
    assert started <= {r.split()[-1] for r in removals}, calls


def test_every_step_runs_and_passes(tree):
    proc = run(tree)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert summary(proc.stdout) == {name: "ok" for name in ALL_STEPS}
    assert_containers_removed(tree["log"].read_text().splitlines())


@pytest.mark.parametrize(
    ("fail", "failed_steps"),
    [
        # One failure in each parallel group, and one after them.
        ("^go test -race", {"go: race tests"}),
        ("^npm run lint", {"ts node 22: quality", "ts node 24: quality"}),
        ("^cargo clippy", {"rust: test"}),
        ("neutrality_scan.py", {"neutrality scanner self-test"}),
    ],
)
def test_a_failed_step_fails_the_run_and_the_rest_still_run(tree, fail, failed_steps):
    proc = run(tree, FAKE_FAIL=fail)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert summary(proc.stdout) == {
        name: "FAIL" if name in failed_steps else "ok" for name in ALL_STEPS
    }


def test_a_group_killed_without_a_failed_step_fails_the_run(tree):
    # The fake kills its own process group: the whole Go group dies mid-step
    # and reports no failed step.
    proc = run(tree, FAKE_KILLGROUP="^go test -race")
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "group go exited 137 without a failed step" in proc.stdout
    steps = summary(proc.stdout)
    assert "go: race tests" not in steps
    assert steps["crate packaging"] == "ok"


def test_a_group_whose_shell_dies_has_its_commands_stopped(tree):
    # The Go group's shell is killed while its race test still runs; the run
    # must stop that test instead of waiting for it or leaving it behind.
    start = time.monotonic()
    proc = run(tree, FAKE_KILLLEADER="^go test -race")
    assert time.monotonic() - start < 60, "check.sh waited for an orphaned command"
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "group go exited 137 without a failed step" in proc.stdout
    sleepers = [
        int(line.split()[0]) for line in tree["log"].read_text().splitlines()
        if line.endswith(" sleeping")
    ]
    assert sleepers
    for pid in sleepers:
        with pytest.raises(ProcessLookupError):
            os.kill(pid, 0)


def test_interrupt_stops_every_group_and_removes_containers(tree):
    env = {**tree["env"], "FAKE_SLEEP": "^go test -race|^cargo test"}
    proc = subprocess.Popen(
        [BASH, str(tree["root"] / "scripts" / "check.sh")],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        stdin=subprocess.DEVNULL,
    )
    log = tree["log"]
    deadline = time.monotonic() + 60
    while log.read_text().count(" sleeping") < 2:
        assert time.monotonic() < deadline, log.read_text()
        assert proc.poll() is None, proc.stdout.read()
        time.sleep(0.1)
    proc.send_signal(signal.SIGINT)
    out, _ = proc.communicate(timeout=30)
    assert proc.returncode == 130, out

    calls = log.read_text().splitlines()
    sleepers = [int(line.split()[0]) for line in calls if line.endswith(" sleeping")]
    for pid in sleepers:
        with pytest.raises(ProcessLookupError):
            os.kill(pid, 0)
    assert_containers_removed(calls)
