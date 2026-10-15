# CLL backend contract

Status: normative for every CLL storage backend in every language in this
repository, and for backends that users write against these interfaces.

This document is the single source of truth for the CLL entry log, checkpoint
state, witness state and full backend: their operations, semantics, error
codes, limits and storage formats. Each language's interface cites it. The
shared conformance suite in
[`backend-conformance-vectors/`](../backend-conformance-vectors/) turns the
rules below into cases that every backend runs.

The log stores opaque 32-byte identities. It does not know what an identity
names. Record bodies, signatures, admission and application indexes stay with
the application.

## Interfaces and names

Names differ only by language convention: camelCase in TypeScript,
exported PascalCase in Go, snake_case in Python and Rust. TypeScript prefixes
package-level type names with `Cll` (`CllEntry`, `CllState`, `CllError`,
`CllBackend`) because it imports into a flat namespace; Go, Python and Rust
qualify them with the module (`cll.Entry`, `cll.Backend`). `cll.Backend` and
`CllBackend` are therefore the same contract name, as are `cll.State` and
`CllState`.

| Contract | Operations | Go (`go/cll`) | TypeScript (`ts/src/types.ts`) | Python (`cll.log`) | Rust (`cll::log`) |
|---|---|---|---|---|---|
| Entry source | `scanEntries` | `EntrySource` | `EntrySource` | `EntrySource` | `EntrySource` |
| Entry log | entry source + `append`, `getEntry` | `EntryStore` | `EntryStore` | `EntryStore` | `EntryStore` |
| Checkpoint state | `loadCll`, `commitCll` | `CheckpointStateStore` | `CheckpointStateStore` | `CheckpointStateStore` | `CheckpointStateStore` |
| Witness state | `pendingWitnesses`, `getWitness`, `commitWitness` | `WitnessStateStore` | `WitnessStateStore` | `WitnessStateStore` | `WitnessStateStore` |
| Checkpoint store | entry source + checkpoint state + witness state | `CheckpointStore` | `CheckpointStore` | `CheckpointStore` | `CheckpointStore` |
| Full backend | entry log + checkpoint state + witness state + `close` | `Backend` | `CllBackend` | `Backend` | `Backend` |

A checkpoint runner needs only `CheckpointStore`. An application that appends
identities needs only `EntryStore`. A store may implement a subset; it then
runs the matching subset of the conformance suite.

Arguments keep this order in every language:

```text
scanEntries(afterSeq, limit)            -> Entry[]
append(input{value, appendedAt})        -> AppendResult{entry, outcome}
getEntry(value)                         -> Entry
loadCll()                               -> State
commitCll(expectedSize, expectedCheckpoint, next)
pendingWitnesses(now, limit)            -> WitnessState[]
getWitness(witnessId, checkpointSize)   -> WitnessState, or not found
commitWitness(expectedAttempts, next)
close()
```

Go adds a leading `context.Context` to every operation except `Close`. Go and
TypeScript are asynchronous or context-bound; the Python and Rust interfaces
are synchronous.

## Values

| Value | Fields | Rules |
|---|---|---|
| Entry | `seq`, `value`, `appendedAt` | `seq` is dense and 1-based. `value` is exactly 32 bytes. `appendedAt` is UTC with millisecond precision. |
| AppendInput | `value`, `appendedAt` | The application supplies the observation time. |
| AppendResult | `entry`, `outcome` | `outcome` is `inserted` or `idempotent`. |
| State | `size`, `nodes`, `indexedSeq`, `firstPendingAt?`, checkpoint?, `witnesses` | `size` equals the node count. The optional checkpoint is a complete tuple of `bytes`, `size`, `indexedSeq` and `peaks`, or absent. |
| WitnessState | `witnessId`, `checkpointSize`, `checkpoint`, `attempts`, `nextAttemptAt`, receipt?, `permanent`, `lastError?` | The key is (`witnessId`, `checkpointSize`). The optional receipt has `bytes` and optional `entryHash`, `entryHashScheme`, `leafIndex` and `treeSize`. |

TypeScript flattens the checkpoint tuple into `checkpoint`, `checkpointSize`,
`checkpointIndexedSeq` and `checkpointPeaks`, and the receipt into `receipt`,
`entryHash`, `entryHashScheme`, `leafIndex` and `treeSize`, which are also the
[portable field names](#portable-encodings). Go, Python and Rust group them in
a checkpoint struct and a receipt struct. Either way the tuple is all present or
all absent.

Every byte value a backend returns is a copy: mutating it never changes stored
state or another caller's result.

## Error codes

Every failure carries exactly one code.

| Code | Meaning | Go | TypeScript | Python | Rust |
|---|---|---|---|---|---|
| `not_found` | A direct lookup found nothing | `ErrNotFound` | `CllError` code `not_found` | `NotFoundError` | `ErrorCode::NotFound` |
| `invalid` | A caller-supplied value or transition breaks the contract | `ErrInvalid` | `invalid` | `InvalidError` | `ErrorCode::Invalid` |
| `corrupt` | Durable bytes, rows or events are malformed or inconsistent | `ErrCorrupt` | `corrupt` | `CorruptError` | `ErrorCode::Corrupt` |
| `closed` | The backend was closed | `ErrClosed` | `closed` | `ClosedError` | `ErrorCode::Closed` |
| `contention` | A compare-and-set failed, or another writer holds the log | `ErrContention` | `contention` | `ContentionError` | `ErrorCode::Contention` |
| `rejected` | A witness or offline verification permanently rejected a response | `ErrRejected` | `rejected` | `RejectedError` | `ErrorCode::Rejected` |
| `unsupported` | The store does not offer this operation (see [capabilities](#capabilities)) | `ErrUnsupported` | `unsupported` | `UnsupportedError` | `ErrorCode::Unsupported` |

Go errors wrap the sentinel, so callers test with `errors.Is`. TypeScript
throws `CllError` with a `code`. Python raises a subclass of `CllError`, whose
`code` attribute is the code string. Rust returns `cll::log::Error`, whose
`code()` is an `ErrorCode`.

`rejected` is not produced by storage operations. It is listed so that one code
set covers the whole library.

### Not found

`getEntry` reports `not_found` as an error in every language.

`getWitness` reports `not_found` with each language's idiom for an absent
value: TypeScript resolves `undefined`, Python returns `None`, Rust returns
`Ok(None)`. Go has no optional return, so `GetWitness` returns `ErrNotFound`.
Checkpoint and witness runners look up witness rows that may not exist yet,
so absence there is ordinary control flow rather than a caller error. A
malformed key is still `invalid`, never not found.

## Operations

Every operation checks `closed` first. `commitCll` then compares the expected
size and checkpoint (`contention`), validates `next` (`invalid`) and finally
applies the transition rules (`contention`). Every other operation validates
its arguments (`invalid`) before it consults stored state (`not_found`,
`contention`). The conformance cases pin this order, so backends report the
same code when one call breaks several rules.

### Entry log

| Operation or condition | Result |
|---|---|
| `append` of a new 32-byte value | Allocate the next dense 1-based `seq`, truncate `appendedAt` to whole UTC milliseconds, return `inserted`. Append is atomic. |
| `append` of a value already in the log | Return the original entry, with its original `seq` and `appendedAt`, and `idempotent`. The new time is ignored. |
| `append` with a value that is not 32 bytes, or a time outside the [portable range](#limits) | `invalid` |
| `getEntry` of a stored value | The entry |
| `getEntry` of an absent value | `not_found` |
| `getEntry` of a value that is not 32 bytes | `invalid` |
| `scanEntries(afterSeq, limit)` | Entries with `seq > afterSeq` in ascending order, at most `limit`. `afterSeq` beyond the last entry returns an empty list. |
| `scanEntries` with `afterSeq` above `MaxPortableInteger`, or `limit` outside 1..`MaxScanLimit` | `invalid` |

### Checkpoint state

`commitCll(expectedSize, expectedCheckpoint, next)` is a compare-and-set.
`expectedCheckpoint` is the exact current checkpoint bytes, or absent when the
state has no checkpoint.

| Condition | Result |
|---|---|
| `loadCll` on a new backend | `size` 0, `indexedSeq` 0, no nodes, no checkpoint, no witnesses |
| `expectedSize` or `expectedCheckpoint` differs from the current state | `contention` |
| `next.size` differs from the node count, a node is not 32 bytes, or `size` is not a complete MMR whose leaf count is `indexedSeq` | `invalid` |
| `next` changes an existing node, or `size` or `indexedSeq` moves backward | `invalid` |
| The checkpoint tuple is incomplete, its bytes are empty or exceed `MaxCheckpointBytes`, its size is 0 or above `next.size`, its `indexedSeq` is above `next.indexedSeq`, or a peak is not 32 bytes | `invalid` |
| A checkpoint is removed, its size or `indexedSeq` moves backward, or its bytes, `indexedSeq` or peaks change at the same size | `contention` |
| `next` contains a witness key twice, or a witness row breaks the witness rules | `invalid` |
| `next` adds a witness key | Insert the complete row |
| `next` repeats an existing witness key with the same checkpoint bytes | Keep the current row unchanged. Only `commitWitness` changes delivery state. |
| `next` repeats an existing witness key with different checkpoint bytes | `contention` |
| `next` omits a stored witness row | Keep the stored row. Witness rows are never deleted. |

The witness order that `loadCll` returns is not part of the contract; compare
witness lists by key.

### Witness state

| Condition | Result |
|---|---|
| `pendingWitnesses(now, limit)` | Rows with no receipt, not permanent and `nextAttemptAt <= now`, ordered by numeric `checkpointSize` and then by `witnessId` (byte order), at most `limit` |
| `pendingWitnesses` with `limit` outside 1..`MaxWitnesses` or `now` outside the portable range | `invalid` |
| `getWitness` with an identifier outside the [identifier rules](#limits), or `checkpointSize` 0 | `invalid` |
| `getWitness` of an absent key | not found, as described in [Not found](#not-found) |
| `commitWitness(expectedAttempts, next)` with `next` breaking the witness rules | `invalid` |
| `commitWitness` with no stored row for the key, a stored `attempts` different from `expectedAttempts`, or different checkpoint bytes | `contention` |
| `commitWitness` otherwise | Replace the row with `next` |

Witness rules: a valid identifier, `checkpointSize` above 0, checkpoint bytes of
1..`MaxCheckpointBytes`, `attempts` within 0..4294967295, a portable
`nextAttemptAt`, `lastError` at most
`MaxReasonBytes` UTF-8 bytes, and, when a receipt is present, receipt bytes of
1..`MaxWitnessResponseBytes`, an `entryHash` of 64 lowercase hex digits,
`entryHashScheme` equal to `legacy`, and `leafIndex` and `treeSize` within
0..`MaxPortableInteger`. Receipt metadata without receipt bytes is not
representable.

### Lifecycle

| Condition | Result |
|---|---|
| `close` | Succeeds, including when repeated |
| Any other operation after `close` | `closed`, before any argument validation |
| Opening durable state that is malformed or inconsistent | `corrupt`; the stored bytes are left untouched |
| A second writer opens a single-writer store (JSONL) | `contention` |

Persistent backends separate provisioning from opening. `init` creates the
file, tables or initial metadata and is idempotent. `open` requires existing
state and never creates it. In-memory backends have only a constructor.
TypeScript predates this split and has no separate `init`: `JsonlStore.open`
creates a missing file, truncates an incomplete final line and writes
`cll.init`, and `SqliteStore.open` and `MysqlStore.open` create tables and
metadata. Code that must open a log without changing it uses another
language's `open`.

## Capabilities

A store that implements `EntryStore` but cannot accept a bare identity, for
example because each entry must first be written as a full application record,
returns `unsupported` from `append` for an identity it does not already hold,
and returns the existing entry as `idempotent` for one it does. It still
validates the value first (`invalid`). Such a store declares the
`digest-append` capability as absent and runs only the conformance cases that
do not need it.

## Limits

| Name | Value |
|---|---|
| `EntryBytes` | 32 |
| `MaxWitnesses` | 32 |
| `MaxCheckpointBytes` | 65536 |
| `MaxJournalEventBytes` | 4194304 |
| `MaxWitnessResponseBytes` | 2097152 |
| `MaxIdentifierBytes` | 191 |
| `MaxReasonBytes` | 4096 |
| `DefaultScanLimit` | 100 |
| `MaxScanLimit` | 1000 |
| `MaxPortableInteger` | 9007199254740991 |
| `MinPortableUnixMillis` | -8640000000000000 |
| `MaxPortableUnixMillis` | 8640000000000000 |

Identifiers are 1..191 UTF-8 bytes matching `^[A-Za-z0-9._:/-]+$`. Entry
sequences and receipt positions never exceed `MaxPortableInteger`, because
TypeScript reads SQLite sequences and receipt positions as JavaScript numbers.
Times fall within the ECMAScript `Date` range: caller input outside it is
`invalid`, durable data outside it is `corrupt`.

## Portable encodings

Persistent JSON is compact UTF-8 without insignificant whitespace. Readers
accept unknown additive object fields and reject unknown event types, missing
required fields, invalid encodings and index columns that disagree with the
JSON they repeat.

| Logical value | Encoding |
|---|---|
| Counters and sequences (`seq`, `size`, `indexedSeq`, `checkpointSize`, ...) | Base-10 JSON string, no leading zero |
| Entry values, nodes, checkpoint, peaks and receipt bytes | RFC 4648 standard base64 with padding |
| Times | `Date.prototype.toISOString()` form with exactly three fraction digits, for example `2026-09-01T12:00:00.000Z`; years outside 0000..9999 use the signed six-digit form |
| `attempts`, `leafIndex`, `treeSize` | JSON numbers |
| Optional values | Field absent, never `null` |

Entry:

```json
{"seq":"1","value":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","appendedAt":"2026-09-01T12:00:00.000Z"}
```

State field names: `size`, `nodes`, `indexedSeq`, `firstPendingAt`,
`checkpoint`, `checkpointSize`, `checkpointIndexedSeq`, `checkpointPeaks`,
`witnesses`.

Witness field names: `witnessId`, `checkpointSize`, `checkpoint`, `attempts`,
`nextAttemptAt`, `receipt`, `entryHash`, `entryHashScheme`, `leafIndex`,
`treeSize`, `permanent`, `lastError`.

### JSONL v4

One file holds one log. The log identity used in signed checkpoints is runner
configuration and is not written to the journal.

Every durable event is one compact JSON object with `version: 4`, ending in a
newline:

```json
{"version":4,"type":"cll.init"}
{"version":4,"type":"entry.append","entry":{"seq":"1","value":"...","appendedAt":"..."}}
{"version":4,"type":"cll.commit","expected_size":"0","state":{"size":"1","indexedSeq":"1","nodes":["..."],"witnesses":[]}}
{"version":4,"type":"witness.commit","expected_attempts":0,"witness":{"witnessId":"primary","checkpointSize":"1","checkpoint":"...","attempts":1,"nextAttemptAt":"...","permanent":false}}
```

- `cll.commit` carries `expected_checkpoint` only when a checkpoint is
  expected. Its `state.nodes` holds only the nodes this commit adds and its
  `state.witnesses` only the witness rows it adds.
- Replay rebuilds full state and applies the same transition rules as a live
  mutation; a complete line that fails them is `corrupt`.
- `cll.init` is written once, as the first line of a new file. Replay accepts
  it while the log has no entries and no nodes, and treats it as `corrupt`
  afterwards.
- The writer takes a non-blocking exclusive lock on the journal file
  descriptor itself (`flock`), never a sidecar file, so writers in different
  languages exclude each other. A writer that cannot take it fails with
  `contention`.
- An event is durable once its complete line is written and fsynced. A failed
  write is truncated back to the previous durable offset.
- `init` truncates an incomplete final line. `open` rejects one without
  changing the file (TypeScript's `open` truncates it, see
  [Lifecycle](#lifecycle)). A malformed complete line is `corrupt`. A
  version 3 journal is legacy data and is also `corrupt`.
- No event may exceed `MaxJournalEventBytes`.

### Relational schema

SQLite and MySQL use the same four tables, keyed by a caller-chosen log ID, so
one database holds several logs. `default` is the conventional ID. The DDL is
byte-for-byte the same in every language.

SQLite:

```sql
CREATE TABLE IF NOT EXISTS cll_meta (
  log_id TEXT PRIMARY KEY,
  state BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS cll_entries (
  log_id TEXT NOT NULL,
  seq INTEGER NOT NULL,
  value BLOB NOT NULL,
  appended_at TEXT NOT NULL,
  PRIMARY KEY(log_id, seq),
  UNIQUE(log_id, value)
);
CREATE TABLE IF NOT EXISTS cll_nodes (
  log_id TEXT NOT NULL,
  position INTEGER NOT NULL,
  node BLOB NOT NULL,
  PRIMARY KEY(log_id, position)
);
CREATE TABLE IF NOT EXISTS cll_witnesses (
  log_id TEXT NOT NULL,
  witness_id TEXT NOT NULL,
  checkpoint_size TEXT NOT NULL,
  attempts INTEGER NOT NULL,
  witness BLOB NOT NULL,
  PRIMARY KEY(log_id, witness_id, checkpoint_size)
);
```

MySQL 8:

```sql
CREATE TABLE IF NOT EXISTS cll_meta (
  log_id VARCHAR(191) PRIMARY KEY,
  state LONGBLOB NOT NULL
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS cll_entries (
  log_id VARCHAR(191) NOT NULL,
  seq BIGINT UNSIGNED NOT NULL,
  value BINARY(32) NOT NULL,
  appended_at VARCHAR(32) NOT NULL,
  PRIMARY KEY(log_id, seq),
  UNIQUE KEY uq_cll_entry(log_id, value)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS cll_nodes (
  log_id VARCHAR(191) NOT NULL,
  position BIGINT UNSIGNED NOT NULL,
  node BINARY(32) NOT NULL,
  PRIMARY KEY(log_id, position)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS cll_witnesses (
  log_id VARCHAR(191) NOT NULL,
  witness_id VARCHAR(191) NOT NULL,
  checkpoint_size VARCHAR(32) NOT NULL,
  attempts INT UNSIGNED NOT NULL,
  witness LONGBLOB NOT NULL,
  PRIMARY KEY(log_id, witness_id, checkpoint_size)
) ENGINE=InnoDB;
```

- `cll_meta.state` holds the state JSON with empty `nodes` and `witnesses`;
  `init` writes `{"size":"0","indexedSeq":"0","nodes":[],"witnesses":[]}`.
- `cll_nodes` and `cll_witnesses` are authoritative for those collections.
  `position` is 0-based. `cll_entries.appended_at` holds the portable time
  string. Witness JSON repeats `checkpointSize` and `attempts`; opening a log
  rejects disagreement with the indexed columns as `corrupt`.
- Opening a log validates its complete state: dense entries from 1, distinct
  values, contiguous node positions and valid metadata.
- Append, `getEntry`, `scanEntries`, `getWitness` and `commitWitness` use
  targeted indexed queries. `loadCll` reads metadata, nodes and witnesses but
  never entries. Commits insert only new nodes and new witness rows.
- Writers serialize per log: SQLite uses `BEGIN IMMEDIATE` with a bounded busy
  wait, MySQL locks the log's `cll_meta` row with `SELECT ... FOR UPDATE`. A
  MySQL `commitWitness` may skip that lock and rely on its attempts
  compare-and-set. Contention left after the bounded wait is `contention`.
  Append derives the next `seq` from the entry rows, never from the MMR size.
- Other tables in the same database belong to the application and are never
  read, changed or used to classify the database. An existing `cll_*` table
  with an incompatible shape is an error.

## Checks outside the vectors

The conformance vectors cover single-handle behavior. Each language's own
backend tests also cover, against every backend that supports them:

- concurrent appends on one handle allocate distinct dense sequences;
- two handles on the same persistent log see each other's appends;
- returned bytes are copies (mutate a result, read it again);
- reopen recovers the same entries and state;
- corrupt files, rows and events fail to open with `corrupt`;
- JSONL writer exclusion, torn-tail handling and version 3 rejection;
- SQL coexistence with application tables and other logs.

## Cross-language storage interop

A JSONL journal, SQLite database or MySQL log written by one language opens,
continues and verifies in every other, with identical checkpoint roots. The
[storage interlock workflow](../.github/workflows/storage-interlock.yml) runs
on every pull request. For each storage format it runs every language's
conformance vectors, then
[`go/scripts/check-storage-interop.sh`](../go/scripts/check-storage-interop.sh),
which, for every ordered pair of languages, creates a log in one, continues it
in the other, and requires every language to read byte-identical entries,
state, witness rows and checkpoint root. A pull request that adds a language's
backend adds its driver and conformance step to both, so no language merges
without passing them.
