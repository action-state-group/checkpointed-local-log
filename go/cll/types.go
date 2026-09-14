package cll

import (
	"context"
	"time"
)

const (
	// EntryBytes is the fixed width of every opaque identity in the log.
	EntryBytes = 32
	// MaxWitnesses bounds one pending-witness query and one checkpoint fanout.
	MaxWitnesses = 32
	// MaxCheckpointBytes bounds checkpoint state stored by a backend.
	MaxCheckpointBytes = 64 << 10
	// MaxJournalEventBytes bounds one encoded JSONL mutation.
	MaxJournalEventBytes = 4 << 20
	// MaxWitnessResponseBytes bounds witness receipts and HTTP responses.
	MaxWitnessResponseBytes = 2 << 20
	// MaxIdentifierBytes bounds portable log and witness identifiers.
	MaxIdentifierBytes = 191
	// MaxReasonBytes bounds persisted operational error text.
	MaxReasonBytes = 4096
	// DefaultScanLimit is the default checkpoint-runner entry batch size.
	DefaultScanLimit = 100
	// MaxScanLimit bounds a single entry scan.
	MaxScanLimit = 1000
	// MaxPortableInteger is JavaScript Number.MAX_SAFE_INTEGER.
	MaxPortableInteger = uint64(9007199254740991)
	// MinPortableUnixMillis and MaxPortableUnixMillis are ECMAScript Date bounds.
	MinPortableUnixMillis = int64(-8640000000000000)
	MaxPortableUnixMillis = int64(8640000000000000)
)

// AppendOutcome describes whether Append inserted or found an identity.
type AppendOutcome string

const (
	AppendInserted   AppendOutcome = "inserted"
	AppendIdempotent AppendOutcome = "idempotent"
)

// Entry is one dense, 1-based log entry containing an opaque identity.
type Entry struct {
	Seq        uint64
	Value      []byte
	AppendedAt time.Time
}

// Clone returns an entry whose value does not alias the original.
func (e Entry) Clone() Entry {
	e.Value = append([]byte(nil), e.Value...)
	return e
}

// AppendInput is the application-supplied identity and observation time.
type AppendInput struct {
	Value      []byte
	AppendedAt time.Time
}

// AppendResult returns the durable entry and idempotency outcome.
type AppendResult struct {
	Entry   Entry
	Outcome AppendOutcome
}

// WitnessReceiptState is the optional verified witness receipt projection.
type WitnessReceiptState struct {
	Bytes           []byte
	EntryHash       string
	EntryHashScheme string
	LeafIndex       *int64
	TreeSize        *int64
}

// WitnessState is the durable delivery state for one witness and checkpoint.
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

// CheckpointState is the latest durable checkpoint tuple.
type CheckpointState struct {
	Bytes      []byte
	Size       uint64
	IndexedSeq uint64
	Peaks      [][]byte
}

// State is the complete restartable MMR, checkpoint, and witness state.
type State struct {
	Size           uint64
	Nodes          [][]byte
	IndexedSeq     uint64
	FirstPendingAt *time.Time
	Checkpoint     *CheckpointState
	Witnesses      []WitnessState
}

// EntrySource exposes bounded entries after a dense sequence position.
type EntrySource interface {
	ScanEntries(context.Context, uint64, int) ([]Entry, error)
}

// CheckpointStateStore persists append-only CLL state with compare-and-set.
type CheckpointStateStore interface {
	LoadCLL(context.Context) (State, error)
	CommitCLL(context.Context, uint64, []byte, State) error
}

// WitnessStateStore persists independent witness-delivery state.
type WitnessStateStore interface {
	PendingWitnesses(context.Context, time.Time, int) ([]WitnessState, error)
	GetWitness(context.Context, string, uint64) (WitnessState, error)
	CommitWitness(context.Context, uint32, WitnessState) error
}

// CheckpointStore is the narrow backend surface used by checkpoint runners.
type CheckpointStore interface {
	EntrySource
	CheckpointStateStore
	WitnessStateStore
}

// Backend is the complete generic persistence contract.
type Backend interface {
	EntrySource
	Append(context.Context, AppendInput) (AppendResult, error)
	GetEntry(context.Context, []byte) (Entry, error)
	CheckpointStateStore
	WitnessStateStore
	Close() error
}
