# SPDX-License-Identifier: Apache-2.0
"""Backend checks outside the conformance vectors (docs/backend-contract.md,
"Checks outside the vectors"): concurrency, cross-handle visibility, copies,
reopen, corrupt durable data, JSONL writer exclusion and torn tails, and SQL
coexistence."""
from __future__ import annotations

import base64
import json
import threading
from datetime import datetime, timedelta, timezone

import pytest

from cll.log import (
    AppendInput,
    Backend,
    CheckpointState,
    CheckpointStore,
    ClosedError,
    CllState,
    ContentionError,
    CorruptError,
    EntryStore,
    InvalidError,
    WitnessReceipt,
    WitnessState,
    jsonl,
    sqlite,
)
from cll.log.memory import MemoryStore
from tests.log.conftest import mysql_url, unique_log_id

T0 = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)


def value(n: int) -> bytes:
    return bytes([n]) * 32


class Persistent:
    """Opens handles on one durable log of a backend."""

    def __init__(self, name: str, tmp_path) -> None:
        self.name = name
        if name == "jsonl":
            self.module, self.args = jsonl, (str(tmp_path / "log.jsonl"),)
        elif name == "sqlite":
            self.module, self.args = sqlite, (str(tmp_path / "cll.sqlite"), unique_log_id())
        else:
            from cll.log import mysql

            self.module, self.args = mysql, (mysql_url(), unique_log_id("backend"))
        self.module.init(*self.args)

    def open(self):
        return self.module.open(*self.args)


@pytest.fixture(params=["jsonl", "sqlite", "mysql"])
def persistent(request, tmp_path):
    return Persistent(request.param, tmp_path)


@pytest.fixture(params=["memory", "jsonl", "sqlite", "mysql"])
def backend(request, tmp_path):
    store = MemoryStore() if request.param == "memory" else Persistent(request.param, tmp_path).open()
    yield store
    store.close()


def test_backends_satisfy_the_protocols(backend):
    assert isinstance(backend, Backend)
    assert isinstance(backend, EntryStore)
    assert isinstance(backend, CheckpointStore)


def test_concurrent_appends_allocate_distinct_dense_sequences(backend):
    results = []
    errors = []

    def worker(start: int) -> None:
        try:
            for n in range(start, start + 10):
                results.append(backend.append(AppendInput(value(n), T0)).entry.seq)
        except Exception as exc:  # pragma: no cover - reported below
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i * 10,)) for i in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    assert sorted(results) == list(range(1, 41))
    assert [entry.seq for entry in backend.scan_entries(0, 1000)] == list(range(1, 41))


def test_append_normalizes_time_and_ignores_the_repeat_time(backend):
    local = timezone(timedelta(hours=5))
    at = datetime(2026, 9, 1, 17, 0, 0, 123999, tzinfo=local)
    first = backend.append(AppendInput(value(1), at))
    assert first.entry.appended_at == datetime(2026, 9, 1, 12, 0, 0, 123000, tzinfo=timezone.utc)
    again = backend.append(AppendInput(bytearray(value(1)), T0))
    assert again.outcome == "idempotent" and again.entry == first.entry
    with pytest.raises(InvalidError):
        backend.append(AppendInput(value(2), datetime(2026, 9, 1)))  # naive
    with pytest.raises(InvalidError):
        backend.append(AppendInput("not bytes", T0))  # type: ignore[arg-type]
    with pytest.raises(InvalidError):
        backend.scan_entries(True, 1)  # type: ignore[arg-type]


def test_returned_values_are_copies(backend):
    source = bytearray(value(1))
    backend.append(AppendInput(source, T0))
    source[0] = 0xFF
    assert backend.get_entry(value(1)).value == value(1)
    nodes = [value(0x30)]
    backend.commit_cll(0, None, CllState(size=1, nodes=nodes, indexed_seq=1))
    nodes[0] = value(0x31)
    assert backend.load_cll().nodes == (value(0x30),)


def test_two_handles_see_each_other(persistent):
    if persistent.name == "jsonl":
        pytest.skip("JSONL admits one writer handle")
    first, second = persistent.open(), persistent.open()
    try:
        first.append(AppendInput(value(1), T0))
        assert second.get_entry(value(1)).seq == 1
        second.append(AppendInput(value(2), T0))
        assert [entry.seq for entry in first.scan_entries(0, 10)] == [1, 2]
        first.commit_cll(0, None, CllState(size=1, nodes=(value(0x30),), indexed_seq=1))
        with pytest.raises(ContentionError):
            second.commit_cll(0, None, CllState(size=1, nodes=(value(0x30),), indexed_seq=1))
        assert second.load_cll().size == 1
    finally:
        first.close()
        second.close()


def full_state() -> CllState:
    witness = WitnessState(
        witness_id="primary",
        checkpoint_size=3,
        checkpoint=b"cp",
        attempts=0,
        next_attempt_at=T0,
        last_error="",
    )
    return CllState(
        size=3,
        nodes=(value(0x30), value(0x31), value(0x32)),
        indexed_seq=2,
        first_pending_at=T0,
        checkpoint=CheckpointState(bytes=b"cp", size=3, indexed_seq=2, peaks=(value(0x32),)),
        witnesses=(witness,),
    )


def test_reopen_recovers_entries_and_state(persistent):
    store = persistent.open()
    store.append(AppendInput(value(1), T0))
    store.append(AppendInput(value(2), T0))
    store.commit_cll(0, None, full_state())
    receipt = WitnessReceipt(b"r", entry_hash="ab" * 32, entry_hash_scheme="legacy", leaf_index=0, tree_size=3)
    done = WitnessState("primary", 3, b"cp", 1, T0, receipt=receipt, permanent=False, last_error="later")
    store.commit_witness(0, done)
    store.close()
    store.close()
    with pytest.raises(ClosedError):
        store.load_cll()
    persistent.module.init(*persistent.args)  # idempotent on existing data
    reopened = persistent.open()
    try:
        assert [entry.value for entry in reopened.scan_entries(0, 10)] == [value(1), value(2)]
        state = reopened.load_cll()
        assert state.nodes == full_state().nodes and state.checkpoint == full_state().checkpoint
        assert state.first_pending_at == T0
        assert reopened.get_witness("primary", 3) == done
        assert reopened.pending_witnesses(T0, 32) == []
        reopened.commit_witness(1, done)  # an unchanged row still satisfies the compare-and-set
    finally:
        reopened.close()


def test_open_never_creates(tmp_path):
    with pytest.raises(FileNotFoundError):
        jsonl.open(str(tmp_path / "missing.jsonl"))
    assert not (tmp_path / "missing.jsonl").exists()

    with pytest.raises(sqlite.sqlite3.Error):
        sqlite.open(str(tmp_path / "missing.sqlite"), "default")
    assert not (tmp_path / "missing.sqlite").exists()


def test_open_rejects_bad_arguments(tmp_path):
    with pytest.raises(InvalidError):
        jsonl.open("")
    with pytest.raises(InvalidError):
        sqlite.init(str(tmp_path / "x.sqlite"), "bad id")
    from cll.log.mysql import connect_args

    with pytest.raises(InvalidError):
        connect_args("postgres://u@h/db")
    with pytest.raises(InvalidError):
        connect_args("mysql://u@h/")
    assert connect_args("mysql://us%40r:p%3Ass@db.example:3307/cll") == {
        "host": "db.example",
        "port": 3307,
        "user": "us@r",
        "password": "p:ss",
        "database": "cll",
    }


# -- JSONL ------------------------------------------------------------------------


def lines(path) -> list:
    return [json.loads(line) for line in path.read_bytes().splitlines()]


def test_jsonl_writes_the_v4_journal(tmp_path):
    path = tmp_path / "log.jsonl"
    jsonl.init(str(path))
    store = jsonl.open(str(path))
    store.append(AppendInput(value(1), T0))
    store.append(AppendInput(value(1), T0))  # idempotent: no event
    store.commit_cll(0, None, CllState(size=1, nodes=(value(0x30),), indexed_seq=1))
    store.commit_cll(1, None, full_state())
    store.close()
    raw = path.read_bytes().splitlines()
    assert raw[0] == b'{"version":4,"type":"cll.init"}'
    assert raw[1] == (
        b'{"version":4,"type":"entry.append","entry":{"seq":"1","value":"'
        + base64.b64encode(value(1))
        + b'","appendedAt":"2026-09-01T12:00:00.000Z"}}'
    )
    events = lines(path)
    assert [event["type"] for event in events] == ["cll.init", "entry.append", "cll.commit", "cll.commit"]
    delta = events[3]
    assert delta["expected_size"] == "1" and "expected_checkpoint" not in delta
    assert len(delta["state"]["nodes"]) == 2  # only the added nodes
    assert delta["state"]["witnesses"][0]["witnessId"] == "primary"


def test_jsonl_writer_exclusion(tmp_path):
    path = str(tmp_path / "log.jsonl")
    jsonl.init(path)
    holder = jsonl.open(path)
    with pytest.raises(ContentionError):
        jsonl.open(path)
    with pytest.raises(ContentionError):
        jsonl.init(path)
    holder.close()
    jsonl.open(path).close()


def test_jsonl_torn_tail(tmp_path):
    path = tmp_path / "log.jsonl"
    jsonl.init(str(path))
    store = jsonl.open(str(path))
    store.append(AppendInput(value(1), T0))
    store.close()
    intact = path.read_bytes()
    path.write_bytes(intact + b'{"version":4,"type":"entry.ap')
    with pytest.raises(CorruptError, match="incomplete"):
        jsonl.open(str(path))
    assert path.read_bytes() == intact + b'{"version":4,"type":"entry.ap'
    jsonl.init(str(path))
    assert path.read_bytes() == intact
    store = jsonl.open(str(path))
    assert store.get_entry(value(1)).seq == 1
    store.close()


@pytest.mark.parametrize(
    "content,match",
    [
        (b'{"v":3,"type":"cll.init"}\n', "version 3"),
        (b'{"version":3,"type":"cll.init"}\n', "version 3"),
        (b'{"version":5,"type":"cll.init"}\n', "unsupported"),
        (b'{"version":"4","type":"cll.init"}\n', "unsupported"),
        (b"not json\n", "corrupt complete"),
        (b"[]\n", "not an object"),
        (b'\xff\n', "corrupt complete"),
        (b'{"version":4,"type":"entry.append"}\n', "begin with cll.init"),
        (b'{"version":4,"type":"cll.init"}\n{"version":4,"type":"mystery"}\n', "unknown event"),
        (
            b'{"version":4,"type":"cll.init"}\n{"version":4,"type":"entry.append","entry":'
            b'{"seq":"1","value":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","appendedAt":"2026-09-01T12:00:00.000Z"}}\n'
            b'{"version":4,"type":"cll.init"}\n',
            "duplicate CLL initialization",
        ),
        (
            b'{"version":4,"type":"cll.init"}\n{"version":4,"type":"entry.append","entry":'
            b'{"seq":"2","value":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","appendedAt":"2026-09-01T12:00:00.000Z"}}\n',
            "invalid stored entry",
        ),
        (
            b'{"version":4,"type":"cll.init"}\n{"version":4,"type":"entry.append","entry":'
            b'{"seq":"1","value":"AAAA","appendedAt":"2026-09-01T12:00:00.000Z"}}\n',
            "invalid stored entry",
        ),
        (
            b'{"version":4,"type":"cll.init"}\n{"version":4,"type":"entry.append","entry":'
            b'{"seq":"1","value":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","appendedAt":"+010000-01-01T00:00:00.000Z"}}\n',
            "portable time",
        ),
        (b'{"version":4,"type":"cll.init"}\n{"version":4,"type":"cll.commit","expected_size":"0"}\n', "missing"),
        (
            b'{"version":4,"type":"cll.init"}\n{"version":4,"type":"cll.commit","expected_size":"1",'
            b'"state":{"size":"0","indexedSeq":"0","nodes":[],"witnesses":[]}}\n',
            "changed",
        ),
        (
            b'{"version":4,"type":"cll.init"}\n{"version":4,"type":"witness.commit","expected_attempts":0,'
            b'"witness":{"witnessId":"w","checkpointSize":"1","checkpoint":"YQ==","attempts":1,'
            b'"nextAttemptAt":"2026-09-01T12:00:00.000Z","permanent":false}}\n',
            "witness state changed",
        ),
        (
            b'{"version":4,"type":"cll.init"}\n{"version":4,"type":"witness.commit",'
            b'"witness":{}}\n',
            "missing witness",
        ),
        (
            # state.size must equal the current size plus the nodes this commit adds.
            b'{"version":4,"type":"cll.init"}\n{"version":4,"type":"cll.commit","expected_size":"0",'
            b'"state":{"size":"3","indexedSeq":"2","nodes":["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="],'
            b'"witnesses":[]}}\n',
            "does not match size",
        ),
        (
            # An unpaired surrogate has no UTF-8 form: durable data, so corrupt.
            b'{"version":4,"type":"cll.init"}\n{"version":4,"type":"cll.commit","expected_size":"0",'
            b'"state":{"size":"1","indexedSeq":"1","nodes":["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="],'
            b'"witnesses":[{"witnessId":"w","checkpointSize":"1","checkpoint":"YQ==","attempts":0,'
            b'"nextAttemptAt":"2026-09-01T12:00:00.000Z","permanent":false,"lastError":"\\ud800"}]}}\n',
            "last_error",
        ),
        (
            b'{"version":4,"type":"cll.init"}\n{"version":4,"type":"cll.commit","expected_size":"0",'
            b'"state":{"size":"1","indexedSeq":"1","nodes":["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="],'
            b'"witnesses":[{"witnessId":"\\ud800","checkpointSize":"1","checkpoint":"YQ==","attempts":0,'
            b'"nextAttemptAt":"2026-09-01T12:00:00.000Z","permanent":false}]}}\n',
            "witness state is invalid",
        ),
        (
            b'{"version":4,"type":"cll.init"}\n{"version":4,"type":"cll.commit","expected_size":"'
            + b"1" * 5000
            + b'","state":{"size":"0","indexedSeq":"0","nodes":[],"witnesses":[]}}\n',
            "invalid decimal",
        ),
        (b"", "missing JSONL initialization"),
    ],
)
def test_jsonl_rejects_corrupt_journals_without_changing_them(tmp_path, content, match):
    path = tmp_path / "log.jsonl"
    path.write_bytes(content)
    with pytest.raises(CorruptError, match=match):
        jsonl.open(str(path))
    assert path.read_bytes() == content
    if content:
        with pytest.raises(CorruptError):
            jsonl.init(str(path))
        assert path.read_bytes() == content


def test_jsonl_failed_write_rolls_back_file_and_state(tmp_path, monkeypatch):
    path = tmp_path / "log.jsonl"
    jsonl.init(str(path))
    store = jsonl.open(str(path))
    store.append(AppendInput(value(1), T0))
    before = path.read_bytes()
    calls = {"n": 0}
    real_fsync = jsonl.os.fsync

    def fail_once(fd):
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError(5, "simulated fsync failure")
        real_fsync(fd)

    monkeypatch.setattr(jsonl.os, "fsync", fail_once)
    with pytest.raises(OSError, match="simulated"):
        store.append(AppendInput(value(2), T0))
    assert path.read_bytes() == before
    with pytest.raises(Exception) as missing:
        store.get_entry(value(2))
    assert getattr(missing.value, "code", None) == "not_found"
    assert store.append(AppendInput(value(2), T0)).entry.seq == 2
    store.close()


def test_jsonl_rejects_oversized_events(tmp_path):
    path = tmp_path / "log.jsonl"
    jsonl.init(str(path))
    store = jsonl.open(str(path))
    witnesses = tuple(
        WitnessState(f"w{index}", 1, b"x" * 65536, 0, T0) for index in range(64)
    )
    with pytest.raises(InvalidError, match="size limit"):
        store.commit_cll(0, None, CllState(size=1, nodes=(value(0x30),), indexed_seq=1, witnesses=witnesses))
    assert store.load_cll() == CllState()
    store.close()


# -- SQL ----------------------------------------------------------------------------


@pytest.fixture(params=["sqlite", "mysql"])
def relational(request, tmp_path):
    return Persistent(request.param, tmp_path)


def _raw(relational):
    """A raw DB-API connection and its placeholder."""
    if relational.name == "sqlite":
        return sqlite.sqlite3.connect(relational.args[0], isolation_level=None), "?"
    import pymysql

    from cll.log.mysql import connect_args

    return pymysql.connect(**connect_args(relational.args[0]), autocommit=True), "%s"


def _corrupt(relational, statement: str, params: tuple) -> None:
    connection, mark = _raw(relational)
    try:
        connection.cursor().execute(statement.replace("?", mark), params)
    finally:
        connection.close()


def test_sql_logs_coexist_with_each_other_and_application_tables(relational, tmp_path):
    connection, mark = _raw(relational)
    try:
        connection.cursor().execute("CREATE TABLE IF NOT EXISTS app_records (id INTEGER PRIMARY KEY)")
    finally:
        connection.close()
    other_store = Persistent(relational.name, tmp_path).open()  # same database, another log
    store = relational.open()
    try:
        store.append(AppendInput(value(1), T0))
        other_store.append(AppendInput(value(1), T0))
        other_store.append(AppendInput(value(2), T0))
        assert len(store.scan_entries(0, 10)) == 1
        assert len(other_store.scan_entries(0, 10)) == 2
    finally:
        store.close()
        other_store.close()


@pytest.mark.parametrize(
    "statement,params",
    [
        ("UPDATE cll_meta SET state=? WHERE log_id=?", (b"not json", None)),
        ("UPDATE cll_meta SET state=? WHERE log_id=?", (b'{"size":"1","indexedSeq":"1","nodes":[],"witnesses":[]}', None)),
        ("DELETE FROM cll_meta WHERE log_id=?", (None,)),
        ("UPDATE cll_entries SET seq=5 WHERE log_id=?", (None,)),
        ("UPDATE cll_entries SET appended_at='yesterday' WHERE log_id=?", (None,)),
        ("UPDATE cll_witnesses SET attempts=7 WHERE log_id=?", (None,)),
        ("UPDATE cll_nodes SET position=4 WHERE log_id=? AND position=2", (None,)),
    ],
)
def test_sql_open_rejects_corrupt_rows(relational, statement, params):
    store = relational.open()
    store.append(AppendInput(value(1), T0))
    store.commit_cll(0, None, full_state())
    store.close()
    log_id = relational.args[1]
    params = tuple(log_id if item is None else item for item in params)
    _corrupt(relational, statement, params)
    with pytest.raises(CorruptError):
        relational.open()


def test_sqlite_busy_writer_is_contention(tmp_path, monkeypatch):
    path = str(tmp_path / "cll.sqlite")
    sqlite.init(path, "default")
    monkeypatch.setattr(sqlite, "BUSY_TIMEOUT", 0.05)
    store = sqlite.open(path, "default")
    blocker = sqlite.sqlite3.connect(path, isolation_level=None)
    try:
        blocker.execute("BEGIN IMMEDIATE")
        with pytest.raises(ContentionError):
            store.append(AppendInput(value(1), T0))
        blocker.execute("ROLLBACK")
        assert store.append(AppendInput(value(1), T0)).entry.seq == 1
    finally:
        blocker.close()
        store.close()


def test_mysql_errors_are_classified():
    pymysql = pytest.importorskip("pymysql")
    from cll.log.mysql import MysqlStore

    store = MysqlStore.__new__(MysqlStore)
    for number in (1062, 1205, 1213):
        with pytest.raises(ContentionError):
            with store._classified():
                raise pymysql.err.OperationalError(number, "busy")
    with pytest.raises(pymysql.err.OperationalError):
        with store._classified():
            raise pymysql.err.OperationalError(1045, "denied")


def test_readme_example(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    jsonl.init("cll.jsonl")
    store = jsonl.open("cll.jsonl")
    result = store.append(AppendInput(bytes(32), datetime.now(timezone.utc)))
    store.close()
    assert result.outcome == "inserted"


# -- review fixes --------------------------------------------------------------------

# 128 bytes whose typed view has 32 items: lengths are bytes, never items.
TYPED = memoryview(bytes(128)).cast("I")


def one_node(**fields) -> CllState:
    return CllState(size=1, nodes=(value(0x30),), indexed_seq=1, **fields)


def test_typed_memoryviews_are_measured_in_bytes(backend):
    assert len(TYPED) == 32
    with pytest.raises(InvalidError):
        backend.append(AppendInput(TYPED, T0))
    with pytest.raises(InvalidError):
        backend.get_entry(TYPED)
    with pytest.raises(InvalidError):
        backend.commit_cll(0, None, CllState(size=1, nodes=(TYPED,), indexed_seq=1))
    with pytest.raises(InvalidError):
        backend.commit_cll(0, None, one_node(checkpoint=CheckpointState(b"cp", 1, 1, (TYPED,))))
    too_big = memoryview(bytes(4 * 65536)).cast("I")  # 65536 items, 262144 bytes
    with pytest.raises(InvalidError):
        backend.commit_cll(0, None, one_node(checkpoint=CheckpointState(too_big, 1, 1, ())))
    with pytest.raises(InvalidError):
        backend.commit_cll(0, None, one_node(witnesses=(WitnessState("w", 1, too_big, 0, T0),)))
    backend.commit_cll(0, None, one_node(witnesses=(WitnessState("w", 1, b"a", 0, T0),)))
    huge_receipt = memoryview(bytes(4 * 2097152)).cast("I")
    with pytest.raises(InvalidError):
        backend.commit_witness(0, WitnessState("w", 1, b"a", 1, T0, receipt=WitnessReceipt(huge_receipt)))
    # A plain byte-format memoryview of 32 bytes is a valid value.
    assert backend.append(AppendInput(memoryview(value(1)), T0)).entry.value == value(1)


def test_commit_witness_checks_expected_attempts_before_the_lookup(backend):
    missing = WitnessState("missing", 1, b"a", 1, T0)
    for expected in (-1, 1 << 32, True):
        with pytest.raises(InvalidError):
            backend.commit_witness(expected, missing)
    with pytest.raises(ContentionError):
        backend.commit_witness(0, missing)


def test_unpaired_surrogates_are_invalid_caller_input(backend):
    with pytest.raises(InvalidError):
        backend.get_witness("\ud800", 1)
    for row in (WitnessState("\ud800", 1, b"a", 0, T0), WitnessState("w", 1, b"a", 0, T0, last_error="\ud800")):
        with pytest.raises(InvalidError):
            backend.commit_cll(0, None, one_node(witnesses=(row,)))
        with pytest.raises(InvalidError):
            backend.commit_witness(0, row)
    assert backend.load_cll() == CllState()


def test_sql_rejects_corrupt_nodes(tmp_path):
    persistent = Persistent("sqlite", tmp_path)
    store = persistent.open()
    store.commit_cll(0, None, full_state())
    store.close()
    log_id = persistent.args[1]
    for node in (5, b"x" * 31, "A" * 32):
        _corrupt(persistent, "UPDATE cll_nodes SET node=? WHERE log_id=? AND position=1", (node, log_id))
        with pytest.raises(CorruptError, match="node"):
            persistent.open()


def test_sql_rejects_a_surrogate_in_a_witness_row(relational):
    store = relational.open()
    store.commit_cll(0, None, full_state())
    store.close()
    row = json.dumps({
        "witnessId": "primary", "checkpointSize": "3", "checkpoint": "Y3A=", "attempts": 0,
        "nextAttemptAt": "2026-09-01T12:00:00.000Z", "permanent": False, "lastError": "\ud800",
    }).encode("ascii")
    _corrupt(relational, "UPDATE cll_witnesses SET witness=? WHERE log_id=?", (row, relational.args[1]))
    with pytest.raises(CorruptError):
        relational.open()


def test_mysql_url_rejects_bad_ports():
    pytest.importorskip("pymysql")
    from cll.log.mysql import connect_args

    for url in ("mysql://u@h:abc/db", "mysql://u@h:99999/db"):
        with pytest.raises(InvalidError, match="port"):
            connect_args(url)


def test_mysql_reconnects_after_a_dropped_connection(tmp_path):
    relational = Persistent("mysql", tmp_path)
    store = relational.open()
    killer, _ = _raw(relational)
    try:
        killer.cursor().execute(f"KILL {store._connection.thread_id()}")
        assert store.append(AppendInput(value(1), T0)).entry.seq == 1
        assert store.get_entry(value(1)).seq == 1
    finally:
        killer.close()
        store.close()


def test_mysql_failed_rollback_does_not_mask_the_error(tmp_path):
    from cll.log import mysql

    store = Persistent("mysql", tmp_path).open()
    connection = store._connection

    class FailingRollback:
        def __getattr__(self, name):
            return getattr(connection, name)

        def rollback(self):
            raise mysql.pymysql.err.OperationalError(2013, "lost connection")

    store._connection = FailingRollback()
    try:
        with pytest.raises(InvalidError):
            store.append(AppendInput(b"short", T0))
    finally:
        store._connection = connection
        store.close()
