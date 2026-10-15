# Go CLL design

Status: implementation contract for the generic core.

## Purpose

Go CLL is an embeddable Go implementation of a Checkpointed Local Log. It
stores an ordered sequence of opaque identities whose width is `EntryBytes`,
maintains an MMR over those identities, signs periodic checkpoints, and
optionally delivers the checkpoints to external witnesses.

The library does not know what an identity names. Record bodies, signatures,
authorization decisions, application indexes, and retry outboxes remain in the
application that owns them.

## Required boundaries

- Go CLL and `capsule-emit-go` do not depend on each other.
- Go CLL contains no AAC, Capsule, Producer Envelope, admission,
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
| `action-state-group/cll-go` | `e13e718d83c21fc9159a5a87268eb90d407281fc` | Earlier Go MMR, checkpoint, and witness implementation this module succeeds |

The Python package still includes application-shaped reference code and a
separate legacy checkpoint path. It is not the storage architecture for this
module. Python participates in MMR and checkpoint wire verification only.

## Package ownership

```text
go/
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
the row selected by the default TypeScript CLL constructor. A different ID is a
different log, even in the same database. JSONL represents one log per file,
so it has no storage-level log ID argument.

## Public Go contract

The backend interfaces, their semantics and error codes, the limits, the
portable encodings, JSONL v4 and the relational schema are defined once for
every language in [the CLL backend contract](../docs/backend-contract.md).
`cll/types.go` and `cll/errors.go` implement it; this section records only what
is specific to Go.

- Every operation except `Close` takes a leading `context.Context`.
- `CommitCLL` arguments are `expectedSize`, `expectedCheckpoint` and `next`. A
  nil expected checkpoint means that no checkpoint exists.
- Nil `State.Checkpoint`, `State.FirstPendingAt` and `WitnessState.Receipt`
  are the contract's absent values. Encoders flatten the grouped checkpoint and
  receipt structs to the portable field names.
- Required timestamps never use Go's zero value as absence, because
  `0001-01-01T00:00:00.000Z` is a valid JavaScript date.
- Errors wrap one sentinel per contract code (`ErrNotFound` ... `ErrUnsupported`),
  tested with `errors.Is`. `GetWitness` returns `ErrNotFound` for an absent
  key, Go's mapping of the contract's not-found result.
- Witness HTTP retry classification stays in `witness.IsRetryable`; it is not
  a storage error class.
- Checkpoint and witness run loops retry `ErrContention`; benign
  competing-writer races do not end a long-running host loop.
- The time encoder reproduces the signed six-digit year form of
  `Date.toISOString()` and never uses `time.RFC3339Nano`, which would omit
  `.000`.
- SQLite enables WAL, foreign keys, a five-second busy timeout and immediate
  write transactions. A process-wide queue keyed by canonical database path and
  log ID serializes handles in the same Go process.
- Relational loads use `ORDER BY position` for nodes and
  `ORDER BY checkpoint_size, witness_id` for witnesses; `PendingWitnesses`
  then sorts numerically as the contract requires.

The storage layer enforces the contract's structural rules. The checkpoint
runner additionally verifies the MMR leaf-count relationship, checkpoint
signature, checkpoint metadata, peak commitments and consistency proof before
extending restored state. Both checkpoint APIs can emit and inspect the
optional positive maximum checkpoint interval in seconds; Go exposes the
additive `SignCheckpointWithCadence` method without widening the runner's
existing `Signer` interface.

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
  Go CLL.

Migration is application-owned because the application must decide where full
record bodies and signer evidence live. A migration tool should read through
the old pinned module, verify and persist each complete record in application
storage, append its decoded 32-byte identity to a fresh generic backend in the
original order, and then establish the application's desired checkpoint
continuity. The old files or tables remain untouched for rollback and audit.

The old operator-only `Rebaseline` operation is removed. Neither the generic
TypeScript contract nor the compatibility layer defines it. A future generic
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
Go CLL (`go/`)
  append verified 32-byte Capsule ID only
  build checkpoint
  deliver checkpoint to witness
```

`capsule-emit-go` documentation will show this composition through a
caller-owned storage interface. It will not import Go CLL in production code
or add SQLite/MySQL dependencies.

## Verification matrix

### Shared backend contract

Every backend runs the language-neutral
[conformance vectors](../backend-conformance-vectors/) through
`cll/conformance`, which user-supplied backends can run too. The Go test suite
in `internal/storetest` runs against Memory, JSONL, SQLite and MySQL and also
covers what the vectors cannot express:

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

The root [interoperability workflow](../.github/workflows/interop.yml) runs
continuation tests between every ordered pair of languages at the same
checked-out repository revision:

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
   `ts/` at the same checked-out repository revision.
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
