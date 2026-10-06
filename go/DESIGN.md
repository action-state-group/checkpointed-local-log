# cll-go design

Status: implementation contract for the generic-core refactor.

## Purpose

`cll-go` is an embeddable Go implementation of a Checkpointed Local Log. It
stores an ordered sequence of opaque identities whose width is `EntryBytes`,
maintains an MMR over those identities, signs periodic checkpoints, and
optionally delivers the checkpoints to external witnesses.

The library does not know what an identity names. Record bodies, signatures,
authorization decisions, application indexes, and retry outboxes remain in the
application that owns them.

## Required boundaries

- `cll-go` and `capsule-emit-go` do not depend on each other.
- `cll-go` contains no AAC, Capsule, Producer Envelope, admission,
  authenticity, chain-gap, or application-verification behavior.
- `capsule-emit-go` remains a deterministic, persistence-free AAC format-4
  construction and verification library.
- An application verifies and persists its complete record first. It then
  decodes the verified record identity to `EntryBytes` bytes and appends only
  those bytes to CLL.
- A failed CLL append is recovered by an application-owned durable outbox or
  equivalent retry mechanism. CLL never reads that outbox or application
  tables.
- Importing either library starts no goroutine and performs no network call.
  Hosts explicitly run checkpoint and witness loops with host-owned contexts.

## Compatibility baselines

These `main` revisions were refreshed on 2026-09-03 before this design was
written:

| Repository | Commit | Contract used here |
| --- | --- | --- |
| `action-state-group/cll-ts` | `91b88ca17e452eeb5994bd98bd514db7f02db814` | Generic API, state transitions, JSONL v4, SQLite and MySQL schemas |
| `action-state-group/checkpointed-local-log` | `f0f60baec7b19a2288de18283ffb715da0cdcd9c` | Generic log discipline and Python MMR/checkpoint verification |
| `action-state-group/capsule-anchor` | `8207b79ce2dd3eb1fce105d52162959e1d5aa680` | `/checkpoints` request and RFC 9162 receipt behavior |
| `action-state-group/capsule-emit-ts` | `984471ac310f249d5b3d0594a64db97f98adec17` | AAC application integration boundary |
| `action-state-group/capsule-emit-go` | `dda3a7451b3841237eba89c981c07bddd8f60b6f` | Go AAC application integration boundary |
| `action-state-group/cll-go` | `e13e718d83c21fc9159a5a87268eb90d407281fc` | Existing Go MMR, checkpoint, and witness implementation being refactored |

The Python package still includes application-shaped reference code and a
separate legacy checkpoint path. It is not the storage architecture for this
refactor. Python participates in MMR and checkpoint wire verification only.

## Package ownership

```text
cll-go/
├── cll/                 public entry, state, error, and backend contracts
├── checkpoint/          checkpoint wire format, signing, parsing, runner
├── mmr/                 MMR construction and proof verification
├── witness/             HTTP client, receipt verification, delivery runner
├── store/
│   ├── memory/          process-local backend
│   ├── jsonl/           single-writer JSONL v4 backend
│   ├── sqlite/          transactional SQLite backend
│   └── mysql/           transactional MySQL 8 backend
├── internal/backend/    shared validation and in-memory transition engine
├── internal/storetest/  one behavioral suite used by every backend
└── test/interop/        Go, TypeScript, and Python compatibility drivers
```

Allowed production dependencies are:

```text
stores ────────────────> cll + internal/backend
checkpoint runner ─────> cll + checkpoint wire + mmr
witness runner ────────> cll + checkpoint wire
witness receipt verify > checkpoint wire
```

The old application-specific package is removed. `capsuleanchor` is renamed to
the generic `witness` package because the protocol accepts CLL checkpoints and
contains no record-format behavior.

Backend constructors are:

```go
memory.New() *memory.Store
jsonl.Init(path string) error
sqlite.Init(path, logID string) error
mysql.Init(ctx context.Context, dsn, logID string) error
jsonl.Open(path string) (*jsonl.Store, error)
sqlite.Open(path, logID string) (*sqlite.Store, error)
mysql.Open(ctx context.Context, dsn, logID string) (*mysql.Store, error)
```

Relational constructors require an explicit log ID. Passing `"default"` opens
the row selected by the default `cll-ts` constructor. A different ID is a
different log, even in the same database. JSONL represents one log per file,
so it has no storage-level log ID argument.

## Public Go contract

The public contract is intentionally parallel to `cll-ts`, expressed in
idiomatic Go. Byte slices returned by public methods are defensive copies.

```go
package cll

type AppendOutcome string

const (
    AppendInserted   AppendOutcome = "inserted"
    AppendIdempotent AppendOutcome = "idempotent"
)

type Entry struct {
    Seq        uint64
    Value      []byte
    AppendedAt time.Time
}

type AppendInput struct {
    Value      []byte
    AppendedAt time.Time
}

type AppendResult struct {
    Entry   Entry
    Outcome AppendOutcome
}

type WitnessReceiptState struct {
    Bytes           []byte
    EntryHash       string
    EntryHashScheme string
    LeafIndex       *int64
    TreeSize        *int64
}

type WitnessState struct {
    WitnessID      string
    CheckpointSize uint64
    Checkpoint     []byte
    Attempts       uint32
    NextAttemptAt  time.Time
    Receipt        *WitnessReceiptState
    Permanent      bool
    LastError      string
}

type CheckpointState struct {
    Bytes      []byte
    Size       uint64
    IndexedSeq uint64
    Peaks      [][]byte
}

type State struct {
    Size           uint64
    Nodes          [][]byte
    IndexedSeq     uint64
    FirstPendingAt *time.Time
    Checkpoint     *CheckpointState
    Witnesses      []WitnessState
}

type EntrySource interface {
    ScanEntries(context.Context, uint64, int) ([]Entry, error)
}

type CheckpointStateStore interface {
    LoadCLL(context.Context) (State, error)
    CommitCLL(context.Context, uint64, []byte, State) error
}

type WitnessStateStore interface {
    PendingWitnesses(context.Context, time.Time, int) ([]WitnessState, error)
    GetWitness(context.Context, string, uint64) (WitnessState, error)
    CommitWitness(context.Context, uint32, WitnessState) error
}

type CheckpointStore interface {
    EntrySource
    CheckpointStateStore
    WitnessStateStore
}

type Backend interface {
    EntrySource
    Append(context.Context, AppendInput) (AppendResult, error)
    GetEntry(context.Context, []byte) (Entry, error)
    CheckpointStateStore
    WitnessStateStore
    Close() error
}
```

`CommitCLL` arguments are `expectedSize`, `expectedCheckpoint`, and `next` in
that order. A nil expected checkpoint means that no checkpoint currently
exists. Nil `State.Checkpoint`, `State.FirstPendingAt`, and
`WitnessState.Receipt` preserve the corresponding TypeScript `undefined`
values. Encoders flatten the two grouped structs back to the exact TypeScript
field names. Required timestamps do not use Go's zero value as absence because
`0001-01-01T00:00:00.000Z` is a valid JavaScript date. `GetWitness` returns
`ErrNotFound` rather than a zero value.

The stable error classes are:

```go
ErrNotFound
ErrInvalid
ErrCorrupt
ErrClosed
ErrContention
ErrRejected
```

Backends return `ErrContention` for failed compare-and-set operations. Witness
HTTP retry classification remains in `witness.IsRetryable`; it is not a
storage error class.

Shared limits and validation match `cll-ts`:

```go
EntryBytes              = 32
MaxWitnesses            = 32
MaxCheckpointBytes      = 64 << 10
MaxJournalEventBytes    = 4 << 20
MaxWitnessResponseBytes = 2 << 20
MaxIdentifierBytes      = 191
MaxReasonBytes          = 4096
DefaultScanLimit        = 100
MaxScanLimit            = 1000
MaxPortableInteger      = 9007199254740991
MinPortableUnixMillis   = -8640000000000000
MaxPortableUnixMillis   = 8640000000000000
```

Log and witness identifiers contain at most `MaxIdentifierBytes` UTF-8 bytes,
are non-empty, and match the ASCII subset `^[A-Za-z0-9._:/-]+$`.
Pending-witness and entry-scan query limits use `MaxWitnesses` and
`MaxScanLimit`. Dense entry sequences and receipt positions do not exceed
`MaxPortableInteger`. This is required even though most state counters use
decimal JSON strings, because `cll-ts` receives SQLite entry sequences and
receipt positions as JavaScript numbers.

## State transition contract

This table is the authoritative transition and error mapping shared by every
backend:

| Operation or condition | Required result |
| --- | --- |
| Append a valid, new `EntryBytes`-wide value | Allocate the next dense 1-based sequence, truncate its UTC time to milliseconds, and return `AppendInserted`. |
| Append an existing value | Return its original sequence and timestamp with `AppendIdempotent`; do not replace the timestamp. |
| Append with an invalid value or time | `ErrInvalid`. |
| `ScanEntries(afterSeq, limit)` with valid arguments | Return entries after `afterSeq` in ascending sequence order, bounded by `MaxScanLimit`. |
| Invalid identifier, query limit, sequence, receipt position, or other caller value | `ErrInvalid`. |
| Missing entry or witness in a direct lookup | `ErrNotFound`. |
| `CommitCLL` expected size or exact checkpoint bytes differ from current state | `ErrContention`. |
| CLL nodes or `IndexedSeq` are not append-only, a node width differs from `EntryBytes`, `Size` is not the node count, the checkpoint tuple is incomplete, checkpoint size is not positive or exceeds current `Size`, or checkpoint indexed sequence exceeds current `IndexedSeq` | `ErrInvalid`. |
| A checkpoint is removed, its size or indexed sequence moves backward, or its bytes, metadata, or peaks change at an already-used size | `ErrContention`. |
| `CommitCLL` introduces a witness key | Insert the complete row. |
| `CommitCLL` repeats a witness key with identical checkpoint bytes | Preserve the complete current row. Only `CommitWitness` may change delivery state. |
| `CommitCLL` rebinds an existing witness key to different checkpoint bytes | `ErrContention`. |
| `CommitWitness` finds no current row or its expected attempt count is stale | `ErrContention`. |
| `PendingWitnesses` | Return only receipt-free, non-permanent rows due at or before `now`, in numeric checkpoint-size order with witness-ID tie ordering, bounded by `MaxWitnesses`. |
| Malformed or internally inconsistent durable bytes, rows, or events are found while opening or reading | `ErrCorrupt`. |
| `Close` is repeated | Succeed. All other operations after close return `ErrClosed`. |
| Witness protocol or offline verification permanently rejects a response | `ErrRejected`. |

The storage transition layer enforces these structural rules. The checkpoint
runner additionally verifies the MMR leaf-count relationship, checkpoint
signature, checkpoint metadata, peak commitments, and consistency proof before
extending restored state.

Checkpoint and witness run loops retry `ErrContention`; they do not terminate a
long-running host loop for benign competing-writer races.

## Portable encodings

All persistent JSON uses compact UTF-8 JSON without insignificant whitespace.
Readers allow additive unknown object fields but reject unknown event types,
missing required fields, invalid encodings, and inconsistent duplicate index
columns.

| Logical value | Persistent encoding |
| --- | --- |
| `uint64` state and sequence values | Base-10 JSON strings with no leading zero |
| Entry value, node, checkpoint, receipt, and checkpoint peak bytes | RFC 4648 standard padded base64 |
| Append and state timestamps | ECMAScript `Date.toISOString()` form with exactly millisecond precision, such as `2026-09-01T12:00:00.000Z` |
| `Attempts`, `LeafIndex`, and `TreeSize` | JSON numbers within their declared Go and JavaScript-safe ranges |
| Optional values | Field absent, never JSON `null` |

The Go encoder and decoder reproduce the expanded signed six-digit year form
used by `Date.toISOString()` outside years 0000 through 9999. They do not use
`time.RFC3339Nano`, which would omit `.000` and diverge from TypeScript.
Every required entry, checkpoint, or state timestamp and every non-nil
optional timestamp must fall within `MinPortableUnixMillis` and
`MaxPortableUnixMillis`, inclusively. Caller input outside that range is
`ErrInvalid`; the same value in durable data is `ErrCorrupt`.

The wire entry object is:

```json
{"seq":"1","value":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","appendedAt":"2026-09-01T12:00:00.000Z"}
```

CLL state uses these exact JSON field names:

```text
size, nodes, indexedSeq, firstPendingAt,
checkpoint, checkpointSize, checkpointIndexedSeq, checkpointPeaks, witnesses
```

Witness state uses these exact JSON field names:

```text
witnessId, checkpointSize, checkpoint, attempts, nextAttemptAt,
receipt, entryHash, entryHashScheme, leafIndex, treeSize, permanent, lastError
```

`entryHashScheme`, when present, is currently the literal `legacy` required by
the existing checkpoint witness response.

## JSONL v4

`jsonl.Open(path)` opens one file representing one CLL. The log identity used
in signed checkpoints is runner configuration and is not duplicated into the
journal.

Every durable event ends with one newline and has `version: 4`:

```json
{"version":4,"type":"cll.init"}
{"version":4,"type":"entry.append","entry":{"seq":"1","value":"...","appendedAt":"..."}}
{"version":4,"type":"cll.commit","expected_size":"0","state":{"size":"1","indexedSeq":"1","nodes":["..."],"witnesses":[]}}
{"version":4,"type":"witness.commit","expected_attempts":0,"witness":{"witnessId":"primary","checkpointSize":"1","checkpoint":"...","attempts":1,"nextAttemptAt":"...","permanent":false}}
```

`cll.commit` includes `expected_checkpoint` only when a current checkpoint is
expected. Its `state.nodes` contains only newly added nodes, and
`state.witnesses` contains only newly added witnesses. Replay reconstructs the
full state before applying the same transition validation as a live mutation.

The writer acquires a non-blocking exclusive lock on the journal file
descriptor itself. A sidecar lock is not interoperable because the TypeScript
writer locks the journal descriptor. It records and fsyncs the complete event
before considering the mutation durable. A failed write is truncated back to
the previous durable offset and fsynced. Explicit `jsonl.Init` truncates an incomplete final tail; `Open` rejects it without modifying the journal; malformed complete lines are
corruption. A version 3 journal is rejected explicitly.

On a new empty file the writer emits `cll.init` exactly once. On an existing
file it never emits another init merely because the process reopened it.
Replay matches current TypeScript behavior: `cll.init` is valid while entries
and MMR state remain empty, but becomes corruption after either is non-empty.
The canonical writer therefore produces one leading init even though a replay
of manually constructed repeated init events in an otherwise empty state is
tolerated for compatibility.

## Relational schema

The table and column names, keys, value encodings, and initial metadata JSON
match `cll-ts`. The schema deliberately has no additional version table.
The initial state is
`{"size":"0","indexedSeq":"0","nodes":[],"witnesses":[]}`.

### SQLite

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

### MySQL 8

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

`cll_meta.state` contains the complete JSON state except that `nodes` and
`witnesses` are empty arrays. `cll_nodes` and `cll_witnesses` are authoritative
for those collections. Witness JSON repeats `checkpointSize` and `attempts`;
opening a store rejects disagreement between JSON and the indexed columns.

Relational loads use `ORDER BY position` for nodes and
`ORDER BY checkpoint_size, witness_id` for witnesses. Because
`checkpoint_size` is decimal text, the latter is lexicographic. Public pending
witness selection then applies a stable numeric checkpoint-size sort, matching
the TypeScript transition engine and preserving witness-ID order for ties.

SQLite enables WAL, foreign keys, a five-second busy timeout, and immediate write
transactions. A process-wide queue keyed by canonical database path and log ID
serializes handles in the same Go process; contention remaining after the
bounded database wait is `ErrContention`. MySQL locks the log's `cll_meta` row
with `SELECT ... FOR UPDATE`. Under that lock, append derives the next sequence
from the indexed entry rows, verifies dense ordering, and inserts the new entry.
MMR size is never used as an entry sequence because MMR size counts nodes, not
entries.

Reads stay incremental in both Go and TypeScript:

- `GetEntry` queries by `(log_id, value)`.
- `ScanEntries` queries the requested sequence range.
- `LoadCLL`/`loadCll` read metadata, nodes, and witnesses, not record entries.
- Commits insert only new nodes and witnesses.

Each runtime validates complete relational state when opening a backend. Normal
append, entry lookup, bounded scan, witness lookup, and witness CAS operations
use targeted indexed queries. Public capabilities align semantically while
retaining idiomatic Go and TypeScript names, numeric types, and error handling.
Both checkpoint APIs can emit and inspect the optional positive maximum
checkpoint interval in seconds. Go exposes the additive
`SignCheckpointWithCadence` method without widening the runner's existing
`Signer` interface.

## Legacy format policy

The removed pre-1.0 Go format stored complete application records and used a
different JSONL v3 event family and SQL schema. It cannot be opened as the
generic format.

- JSONL rejects version 3 and names it as unsupported legacy data.
- Explicit SQLite and MySQL `Init` calls initialize the shared `cll_*` tables and validate the
  requested log. Application-owned tables, including `ledger_metadata` and
  `schema_metadata`, may coexist and do not classify a database as a CLL
  format. Opening a log neither reads nor migrates those tables.
- An incompatible `cll_*` schema or corrupt requested-log state remains an
  error. Existing log entries, commitments and witness state are not reset
  when another log is initialized.
- Initializing a new log creates empty generic state, not imported application
  history. Hosts must verify migration completeness and checkpoint continuity;
  backend initialization does not establish either. Failed initialization may
  leave CLL tables already created before validation fails.
- No compatibility alias, automatic copy, or dual-write path remains in
  `cll-go`.

Migration is application-owned because the application must decide where full
record bodies and signer evidence live. A migration tool should read through
the old pinned module, verify and persist each complete record in application
storage, append its decoded 32-byte identity to a fresh generic backend in the
original order, and then establish the application's desired checkpoint
continuity. The old files or tables remain untouched for rollback and audit.

The private Alchemy `main` branch at
`3464a020f20022398e10ab8c19afd8b8c45bffa8` currently imports the removed
`cll-go/ledger` API and pins commit `e13e718d83c2`. It continues to build at
that pin. Alchemy must complete the application-owned migration before it
upgrades to this breaking release; Alchemy changes are outside this task.

The old operator-only `Rebaseline` operation is removed. Neither the generic
TypeScript contract nor the compatibility lane defines it. A future generic
continuity-reset design requires a separate cross-language contract before any
implementation is added.

## Checkpoint and witness behavior

The existing MMR leaf, interior-node, and peak-bagging rules remain unchanged:

```text
leaf   = SHA256(0x00 || entry_value_32)
parent = SHA256(be64(parent_position + 1) || left || right)
root   = bag peaks right-to-left with SHA256(right || left)
```

The canonical raw COSE_Sign1 checkpoint bytes, CWT issuer/subject claims,
consistency proof, checkpoint entry hash, `/checkpoints` content type, bounded
HTTP behavior, and offline RFC 9162 receipt verification remain byte-for-byte
compatible.

The checkpoint package removes its AAC canonicalization dependency. Its
checkpoint JSON projection uses a fixed lexicographic field order and integer
encoding. Frozen tests cover exact canonical JSON, payload digest, and
checkpoint entry hash for both first-checkpoint and non-zero predecessor
shapes. COSE byte equality alone is insufficient because the diagnostic JSON
is not the COSE payload but is authenticated indirectly by witness entry-hash
verification.

Only the latest checkpoint tuple is kept in CLL metadata. Each pending witness
row retains the exact signed checkpoint bytes needed for delivery, so
checkpoint history is not required by the backend. The checkpoint runner
restores and verifies the latest checkpoint against persisted nodes before
extending the MMR.

## Application integration

An AAC application composes the two independent libraries in this order:

```text
capsule-emit-go
  build + sign + verify Capsule and Producer Envelope
                 │
                 ▼
application store
  atomically persist exact Capsule/Envelope bytes and enqueue CLL delivery
                 │
                 ▼
cll-go
  append verified 32-byte Capsule ID only
  build checkpoint
  deliver checkpoint to witness
```

`capsule-emit-go` documentation will show this composition through a
caller-owned storage interface. It will not import `cll-go` in production code
or add SQLite/MySQL dependencies.

## Verification matrix

### Shared backend contract

The same Go test suite runs against Memory, JSONL, SQLite, and MySQL and covers:

- insert, duplicate append, dense sequence, timestamp preservation;
- defensive copies, missing values, invalid widths and scan ranges;
- checkpoint tuple validation and compare-and-set contention;
- witness addition, merge preservation, pending ordering, and attempt CAS;
- close idempotence and post-close errors;
- reopen recovery, concurrent handles, and concurrent append;
- corrupt metadata, rows, node positions, duplicate values, and sequence gaps;
- JSONL writer exclusion, delta events, torn-tail recovery, and complete-line
  corruption;
- transactional rollback when persistence fails.
- exact `cll.init` emission/replay behavior;
- SQLite two-handle success under concurrent append, including bounded busy
  waiting rather than treating immediate `SQLITE_BUSY` as the expected result;
- unsupported JSONL v3 rejection, application-table coexistence without
  changing existing log or application rows, and fail-closed validation of
  actual CLL metadata and table shapes.

### Cross-runtime storage

The `cll-go` CI owns bidirectional continuation tests without changing
`cll-ts`:

| Backend | Go creates, TS continues, Go verifies | TS creates, Go continues, TS verifies |
| --- | --- | --- |
| JSONL v4 | required | required |
| SQLite | required | required |
| MySQL 8 | required | required |

Each direction appends identities, advances CLL state, creates a pending
witness, updates its attempt state, closes, reopens in the other runtime, and
checks the original sequence, timestamp, nodes, checkpoint bytes, and witness
state before adding more data.

The matrix also checks `LoadCLL` witness ordering at checkpoint sizes such as 9
and 10, same-size witness-ID tie ordering, preservation of an already-updated
witness when a stale CLL state adds another witness, and exact error-class
agreement for every checkpoint and witness transition rule, including a
missing-key `CommitWitness` returning contention.

While one runtime holds a JSONL file open, the other runtime must fail to open
the same journal as a second writer. This proves both implementations lock the
journal descriptor rather than unrelated sidecar files.

### Wire compatibility

- Go-generated checkpoints are verified by TypeScript and Python.
- TypeScript-generated checkpoints are verified by Go and Python.
- Deterministic Go and TypeScript checkpoint bytes remain identical.
- Existing MMR vectors, consistency proofs, witness HTTP contract, and receipt
  verification tests remain green.
- First and linked checkpoint canonical JSON, payload digest, and witness entry
  hash have frozen byte-exact vectors independent of COSE equality.

### Static gates

- `go list -deps ./...` contains neither AAC nor `capsule-emit-go`.
- Production paths and identifiers contain none of the removed
  application-specific vocabulary.
- Stale import, table, event, and README references are absent.
- `go fmt ./...`, `go mod tidy`, `go vet ./...`, `go test ./...`, and
  `go test -race ./...` pass.
- MySQL tests run against MySQL 8 rather than being counted as passing when
  Docker is unavailable.

## CI structure

Independent GitHub checks should remain parallel:

1. `quality`: formatting, module tidiness, vet, and static vocabulary gates.
2. `unit`: non-MySQL unit and backend contract tests.
3. `race`: race-enabled Go tests.
4. `mysql`: MySQL backend contract against a real MySQL 8 service.
5. `storage-interop`: bidirectional JSONL, SQLite, and MySQL continuation with
   `cll-ts/main`.
6. `checkpoint-interop`: Go, TypeScript, and Python checkpoint compatibility.

`capsule-emit-go` keeps its existing independent quality, coverage, race, and
Python/TypeScript interoperability checks. Its documentation change must not
alter its dependency graph or wire vectors.

### Explicit persistent-store lifecycle

All persistent backends expose package-level `Init` and `Open` functions; these
are constructors, not methods on `cll.Backend`. `Open` requires existing state
and never creates tables, metadata, files, or JSONL headers. MySQL readers can
use SELECT-only credentials. SQLite connection-local settings and JSONL writer
locks remain in `Open`; they do not initialize log contents. `Init` is idempotent
and owns provisioning (including SQLite WAL configuration). JSONL `Init` is
not a no-op: it creates the `cll.init` header and explicitly repairs torn tails.
Complete corrupt records are rejected. The in-memory backend retains `New()`.
