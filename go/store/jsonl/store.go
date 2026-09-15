package jsonl

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/action-state-group/cll-go/cll"
	"github.com/action-state-group/cll-go/internal/backend"
)

const schemaVersion = 4

type event struct {
	Version            int                  `json:"version"`
	Type               string               `json:"type"`
	Entry              *backend.WireEntry   `json:"entry,omitempty"`
	ExpectedSize       string               `json:"expected_size,omitempty"`
	ExpectedCheckpoint *string              `json:"expected_checkpoint,omitempty"`
	State              *backend.WireState   `json:"state,omitempty"`
	ExpectedAttempts   *uint32              `json:"expected_attempts,omitempty"`
	Witness            *backend.WireWitness `json:"witness,omitempty"`
}

// Store persists one generic CLL in an append-only JSONL v4 journal.
type Store struct {
	mu     sync.RWMutex
	file   *os.File
	engine *backend.Engine
	closed bool
}

// Open validates an existing journal under a non-blocking exclusive writer
// lock. Missing initialization or a torn tail is rejected without file writes.
func Open(path string) (*Store, error) {
	return open(path, false)
}

// Init creates the format header for a new journal. For an existing journal it
// validates state and repairs only an incomplete final line, under writer lock.
// Complete corrupt records are never removed. Repeated Init is idempotent.
func Init(path string) error {
	store, err := open(path, true)
	if err != nil {
		return err
	}
	return store.Close()
}

func open(path string, initialize bool) (*Store, error) {
	if path == "" {
		return nil, fmt.Errorf("%w: journal path is required", cll.ErrInvalid)
	}
	file, err := os.OpenFile(path, journalFlags(initialize), 0o640)
	if err != nil {
		return nil, fmt.Errorf("open JSONL journal: %w", err)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return nil, errors.Join(
			fmt.Errorf("%w: JSONL backend already has a writer", cll.ErrContention),
			file.Close(),
		)
	}
	store := &Store{file: file, engine: backend.New()}
	if err := store.replay(initialize); err != nil {
		return nil, errors.Join(err, store.closeFile())
	}
	info, err := file.Stat()
	if err != nil {
		return nil, errors.Join(fmt.Errorf("stat JSONL journal: %w", err), store.closeFile())
	}
	if info.Size() == 0 {
		if !initialize {
			return nil, errors.Join(fmt.Errorf("%w: missing JSONL initialization; call Init", cll.ErrCorrupt), store.closeFile())
		}
		if err := store.appendEvent(event{Version: schemaVersion, Type: "cll.init"}); err != nil {
			return nil, errors.Join(err, store.closeFile())
		}
	}
	return store, nil
}

// journalFlags prevents Open from creating a missing file.
func journalFlags(initialize bool) int {
	if initialize {
		return os.O_CREATE | os.O_RDWR
	}
	return os.O_RDWR
}

func (s *Store) replay(repair bool) error {
	data, err := io.ReadAll(s.file)
	if err != nil {
		return fmt.Errorf("read JSONL journal: %w", err)
	}
	validEnd := 0
	initialized := false
	for start := 0; start < len(data); {
		relative := bytes.IndexByte(data[start:], '\n')
		if relative < 0 {
			break
		}
		end := start + relative
		if end-start > cll.MaxJournalEventBytes {
			return fmt.Errorf("%w: JSONL event exceeds size limit", cll.ErrCorrupt)
		}
		line := data[start:end]
		if !utf8.Valid(line) {
			return fmt.Errorf("%w: invalid UTF-8 at byte %d", cll.ErrCorrupt, start)
		}
		var header struct {
			Version int    `json:"version"`
			V       int    `json:"v"`
			Type    string `json:"type"`
		}
		if err := json.Unmarshal(line, &header); err != nil {
			return fmt.Errorf("%w: corrupt complete JSONL line at byte %d: %v", cll.ErrCorrupt, start, err)
		}
		if header.Version != schemaVersion {
			if header.Version == 3 || header.V == 3 {
				return fmt.Errorf("%w: legacy JSONL schema version 3 is unsupported", cll.ErrCorrupt)
			}
			return fmt.Errorf("%w: unsupported JSONL schema version", cll.ErrCorrupt)
		}
		if !initialized && header.Type != "cll.init" {
			return fmt.Errorf("%w: JSONL journal does not begin with cll.init", cll.ErrCorrupt)
		}
		var item event
		if err := json.Unmarshal(line, &item); err != nil {
			return fmt.Errorf("%w: decode JSONL event at byte %d: %v", cll.ErrCorrupt, start, err)
		}
		if err := s.applyEvent(item); err != nil {
			return fmt.Errorf("%w: event at byte %d: %v", cll.ErrCorrupt, start, err)
		}
		initialized = true
		validEnd = end + 1
		start = end + 1
	}
	if validEnd != len(data) {
		if !repair {
			return fmt.Errorf("%w: incomplete JSONL tail; call Init to recover", cll.ErrCorrupt)
		}
		if err := s.file.Truncate(int64(validEnd)); err != nil {
			return fmt.Errorf("truncate torn JSONL tail: %w", err)
		}
		if err := s.file.Sync(); err != nil {
			return fmt.Errorf("sync truncated JSONL journal: %w", err)
		}
	}
	_, err = s.file.Seek(0, io.SeekEnd)
	return err
}

func (s *Store) applyEvent(item event) error {
	switch item.Type {
	case "cll.init":
		if len(s.engine.Entries()) != 0 || s.engine.State().Size != 0 {
			return fmt.Errorf("duplicate CLL initialization after state")
		}
		if item.Entry != nil || item.State != nil || item.Witness != nil {
			return fmt.Errorf("invalid CLL initialization")
		}
		return nil
	case "entry.append":
		if item.Entry == nil {
			return fmt.Errorf("missing entry")
		}
		entry, err := backend.EntryFromWire(*item.Entry)
		if err != nil {
			return err
		}
		result, err := s.engine.Append(cll.AppendInput{Value: entry.Value, AppendedAt: entry.AppendedAt})
		if err != nil || result.Outcome != cll.AppendInserted || result.Entry.Seq != entry.Seq {
			return fmt.Errorf("invalid entry append event")
		}
		return nil
	case "cll.commit":
		if item.State == nil {
			return fmt.Errorf("missing CLL state")
		}
		expected, err := backend.ParseDecimal(item.ExpectedSize)
		if err != nil {
			return fmt.Errorf("invalid expected size")
		}
		var checkpoint []byte
		if item.ExpectedCheckpoint != nil {
			checkpoint, err = base64.StdEncoding.Strict().DecodeString(*item.ExpectedCheckpoint)
			if err != nil {
				return fmt.Errorf("invalid expected checkpoint")
			}
		}
		next, err := backend.StateDeltaFromWire(*item.State)
		if err != nil {
			return err
		}
		return s.engine.CommitCLLDelta(expected, checkpoint, next)
	case "witness.commit":
		if item.ExpectedAttempts == nil || item.Witness == nil {
			return fmt.Errorf("missing witness commit fields")
		}
		witness, err := backend.WitnessFromWire(*item.Witness)
		if err != nil {
			return err
		}
		return s.engine.CommitWitness(*item.ExpectedAttempts, witness)
	default:
		return fmt.Errorf("unknown event type %q", item.Type)
	}
}

func (s *Store) appendEvent(item event) error {
	encoded, err := json.Marshal(item)
	if err != nil {
		return fmt.Errorf("encode JSONL event: %w", err)
	}
	encoded = append(encoded, '\n')
	if len(encoded) > cll.MaxJournalEventBytes {
		return fmt.Errorf("%w: JSONL event exceeds size limit", cll.ErrInvalid)
	}
	start, err := s.file.Seek(0, io.SeekEnd)
	if err != nil {
		return fmt.Errorf("seek JSONL journal: %w", err)
	}
	for written := 0; written < len(encoded); {
		count, writeErr := s.file.Write(encoded[written:])
		written += count
		if writeErr != nil {
			return s.rollback(start, writeErr)
		}
		if count == 0 {
			return s.rollback(start, io.ErrShortWrite)
		}
	}
	if err := s.file.Sync(); err != nil {
		return s.rollback(start, err)
	}
	return nil
}

func (s *Store) rollback(offset int64, cause error) error {
	err := errors.Join(s.file.Truncate(offset), syncFileAt(s.file, offset))
	if err == nil {
		return cause
	}
	s.closed = true
	return errors.Join(cause, fmt.Errorf("%w: JSONL rollback failed", cll.ErrCorrupt), err, s.closeFile())
}

func syncFileAt(file *os.File, offset int64) error {
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return err
	}
	return file.Sync()
}

func (s *Store) Append(ctx context.Context, input cll.AppendInput) (cll.AppendResult, error) {
	if err := ctx.Err(); err != nil {
		return cll.AppendResult{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return cll.AppendResult{}, cll.ErrClosed
	}
	snapshot := s.engine.Snapshot()
	result, err := s.engine.Append(input)
	if err != nil || result.Outcome == cll.AppendIdempotent {
		return result, err
	}
	wire, err := backend.EntryToWire(result.Entry)
	if err == nil {
		err = s.appendEvent(event{Version: schemaVersion, Type: "entry.append", Entry: &wire})
	}
	if err != nil {
		return cll.AppendResult{}, s.restore(snapshot, err)
	}
	return result, nil
}

func (s *Store) GetEntry(ctx context.Context, value []byte) (cll.Entry, error) {
	if err := ctx.Err(); err != nil {
		return cll.Entry{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return cll.Entry{}, cll.ErrClosed
	}
	return s.engine.GetEntry(value)
}

func (s *Store) ScanEntries(ctx context.Context, afterSeq uint64, limit int) ([]cll.Entry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, cll.ErrClosed
	}
	return s.engine.ScanEntries(afterSeq, limit)
}

func (s *Store) LoadCLL(ctx context.Context) (cll.State, error) {
	if err := ctx.Err(); err != nil {
		return cll.State{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return cll.State{}, cll.ErrClosed
	}
	return s.engine.State(), nil
}

func (s *Store) CommitCLL(ctx context.Context, expectedSize uint64, expectedCheckpoint []byte, next cll.State) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return cll.ErrClosed
	}
	snapshot := s.engine.Snapshot()
	if err := s.engine.CommitCLL(expectedSize, expectedCheckpoint, next); err != nil {
		return err
	}
	delta, err := s.engine.DeltaSince(snapshot)
	if err != nil {
		return s.restore(snapshot, err)
	}
	wire, err := backend.StateToWire(delta)
	var checkpoint *string
	if expectedCheckpoint != nil {
		encoded := base64.StdEncoding.EncodeToString(expectedCheckpoint)
		checkpoint = &encoded
	}
	if err == nil {
		err = s.appendEvent(event{Version: schemaVersion, Type: "cll.commit", ExpectedSize: fmt.Sprintf("%d", expectedSize), ExpectedCheckpoint: checkpoint, State: &wire})
	}
	if err != nil {
		return s.restore(snapshot, err)
	}
	return nil
}

func (s *Store) PendingWitnesses(ctx context.Context, now time.Time, limit int) ([]cll.WitnessState, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, cll.ErrClosed
	}
	return s.engine.PendingWitnesses(now, limit)
}

func (s *Store) GetWitness(ctx context.Context, witnessID string, checkpointSize uint64) (cll.WitnessState, error) {
	if err := ctx.Err(); err != nil {
		return cll.WitnessState{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return cll.WitnessState{}, cll.ErrClosed
	}
	return s.engine.GetWitness(witnessID, checkpointSize)
}

func (s *Store) CommitWitness(ctx context.Context, expectedAttempts uint32, next cll.WitnessState) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return cll.ErrClosed
	}
	snapshot := s.engine.Snapshot()
	if err := s.engine.CommitWitness(expectedAttempts, next); err != nil {
		return err
	}
	wire, err := backend.WitnessToWire(next)
	if err == nil {
		expected := expectedAttempts
		err = s.appendEvent(event{Version: schemaVersion, Type: "witness.commit", ExpectedAttempts: &expected, Witness: &wire})
	}
	if err != nil {
		return s.restore(snapshot, err)
	}
	return nil
}

func (s *Store) restore(snapshot backend.Snapshot, cause error) error {
	if err := s.engine.Restore(snapshot); err != nil {
		s.closed = true
		return errors.Join(
			cause,
			fmt.Errorf("%w: restore JSONL state after persistence failure: %v", cll.ErrCorrupt, err),
			s.closeFile(),
		)
	}
	return cause
}

// Close flushes, unlocks, and closes the journal. It is idempotent.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.closeFile()
}

func (s *Store) closeFile() error {
	return errors.Join(syscall.Flock(int(s.file.Fd()), syscall.LOCK_UN), s.file.Close())
}

var _ cll.Backend = (*Store)(nil)
