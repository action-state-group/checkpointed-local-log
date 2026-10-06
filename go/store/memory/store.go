package memory

import (
	"context"
	"sync"
	"time"

	"github.com/action-state-group/cll-go/cll"
	"github.com/action-state-group/cll-go/internal/backend"
)

// Store is an in-memory implementation of cll.Backend.
type Store struct {
	mu     sync.RWMutex
	engine *backend.Engine
	closed bool
}

// New returns an empty in-memory backend.
func New() *Store { return &Store{engine: backend.New()} }

func (s *Store) Append(ctx context.Context, input cll.AppendInput) (cll.AppendResult, error) {
	if err := ctx.Err(); err != nil {
		return cll.AppendResult{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return cll.AppendResult{}, cll.ErrClosed
	}
	return s.engine.Append(input)
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
	return s.engine.CommitCLL(expectedSize, expectedCheckpoint, next)
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
	return s.engine.CommitWitness(expectedAttempts, next)
}

// Close is idempotent. Subsequent operations return cll.ErrClosed.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

var _ cll.Backend = (*Store)(nil)
