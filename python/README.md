# Python Checkpointed Local Log

Install from this directory with `pip install .` or `pip install -e ".[dev]"`.
The installed package is `cll`, including `checkpoint`, `ledger`, `log`,
`revocation` and `signing`; the command is `cll`. From the repository root, use
`pip install ./python`. Run tests here with `uv run --extra dev pytest`.

## CLL storage backends

`cll.log` implements the [CLL backend contract](https://github.com/action-state-group/checkpointed-local-log/blob/main/docs/backend-contract.md)
shared with Go and TypeScript: the `EntrySource`, `EntryStore`,
`CheckpointStateStore`, `WitnessStateStore`, `CheckpointStore` and `Backend`
protocols, their values and error classes, and four backends.

| Module | Backend | Lifecycle |
|---|---|---|
| `cll.log.memory` | `MemoryStore`, in process | constructor |
| `cll.log.jsonl` | JSONL v4 journal, single writer (POSIX `flock`) | `init(path)`, `open(path)` |
| `cll.log.sqlite` | shared SQLite schema, stdlib `sqlite3` | `init(path, log_id)`, `open(path, log_id)` |
| `cll.log.mysql` | shared MySQL 8 schema, PyMySQL | `init(url, log_id)`, `open(url, log_id)` |

```python
from datetime import datetime, timezone
from cll.log import AppendInput, jsonl

jsonl.init("cll.jsonl")
store = jsonl.open("cll.jsonl")
result = store.append(AppendInput(bytes(32), datetime.now(timezone.utc)))
store.close()
```

The JSONL, SQLite and MySQL formats interoperate with Go and TypeScript: a log
any of them writes opens, continues and verifies in the others. The MySQL
backend needs the `mysql` extra (`pip install ".[mysql]"`); its target is a
`mysql://user:password@host:port/database` URL. Importing `cll` or `cll.log`
loads no database driver.

`cll.log.conformance` runs the shared conformance vectors against any backend,
including your own; see its module docstring. `cll.log.ledger` puts the
Python-specific `LedgerStore` behind `EntryStore` (without bare-identity
append) and any `LogSource` behind `EntrySource`.

The MySQL tests read `CLL_MYSQL_URL` and skip when it is unset, except under
CI, where they fail.

The authoritative specification and shared vectors live at the repository root.
See the [repository README](https://github.com/action-state-group/checkpointed-local-log#readme) for API and trust boundaries.
