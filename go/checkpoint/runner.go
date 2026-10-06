package checkpoint

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/action-state-group/cll-go/cll"
	"github.com/action-state-group/cll-go/internal/portable"
	"github.com/action-state-group/cll-go/mmr"
)

// Signer signs canonical checkpoint payloads.
type Signer interface {
	KeyID() string
	SignCheckpoint(context.Context, []byte, [][]byte, [][]byte, *mmr.ConsistencyProof) ([]byte, error)
	VerifyCheckpoint([]byte, []byte) error
}

// RunnerConfig controls durable indexing and checkpoint cadence.
type RunnerConfig struct {
	LogID        string
	Cadence      Config
	ScanLimit    int
	PollInterval time.Duration
	WitnessIDs   []string
}

// DefaultRunnerConfig returns the interoperable initial cadence.
func DefaultRunnerConfig(logID string) RunnerConfig {
	return RunnerConfig{LogID: logID, Cadence: DefaultConfig(), ScanLimit: cll.DefaultScanLimit, PollInterval: time.Minute}
}

// Runner advances durable CLL state when explicitly run by its host.
type Runner struct {
	mu     sync.Mutex
	config RunnerConfig
	store  cll.CheckpointStore
	signer Signer
	notify chan struct{}
}

// NewRunner validates dependencies without starting background work.
func NewRunner(config RunnerConfig, store cll.CheckpointStore, signer Signer) (*Runner, error) {
	if cll.ValidateIdentifier(config.LogID) != nil || store == nil || signer == nil || config.ScanLimit < 1 || config.ScanLimit > cll.MaxScanLimit || config.PollInterval <= 0 {
		return nil, fmt.Errorf("%w: invalid runner configuration", cll.ErrInvalid)
	}
	if err := config.Cadence.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", cll.ErrInvalid, err)
	}
	if len(config.WitnessIDs) > cll.MaxWitnesses {
		return nil, fmt.Errorf("%w: too many witnesses", cll.ErrInvalid)
	}
	seen := make(map[string]struct{}, len(config.WitnessIDs))
	for _, id := range config.WitnessIDs {
		if err := cll.ValidateIdentifier(id); err != nil {
			return nil, fmt.Errorf("%w: invalid witness ID", cll.ErrInvalid)
		}
		if _, exists := seen[id]; exists {
			return nil, fmt.Errorf("%w: duplicate witness ID", cll.ErrInvalid)
		}
		seen[id] = struct{}{}
	}
	return &Runner{config: config, store: store, signer: signer, notify: make(chan struct{}, 1)}, nil
}

// Notify wakes a running host loop without blocking the caller.
func (r *Runner) Notify() {
	select {
	case r.notify <- struct{}{}:
	default:
	}
}

// Run catches up until canceled. Contention is retried on the next wakeup.
func (r *Runner) Run(ctx context.Context) error {
	ticker := time.NewTicker(r.config.PollInterval)
	defer ticker.Stop()
	for {
		if err := r.catchUp(ctx, time.Now().UTC()); err != nil && !errors.Is(err, cll.ErrContention) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-r.notify:
		case <-ticker.C:
		}
	}
}

type runnerState struct {
	state    cll.State
	tree     *mmr.Tree
	previous Record
}

// RunOnce advances durable state by at most one entry scan batch. It returns
// true when it commits nodes, a checkpoint, or both.
func (r *Runner) RunOnce(ctx context.Context, now time.Time) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var err error
	now, err = normalizeRunnerTime(now)
	if err != nil {
		return false, err
	}
	current, err := r.loadRunnerState(ctx)
	if err != nil {
		return false, err
	}
	return r.advanceOnce(ctx, now, current)
}

func normalizeRunnerTime(now time.Time) (time.Time, error) {
	now = portable.NormalizeTime(now)
	if portable.ValidateTime(now) != nil {
		return time.Time{}, fmt.Errorf("%w: invalid runner time", cll.ErrInvalid)
	}
	return now, nil
}

func (r *Runner) loadRunnerState(ctx context.Context) (*runnerState, error) {
	state, err := r.store.LoadCLL(ctx)
	if err != nil {
		return nil, err
	}
	tree, err := mmr.New(state.Nodes)
	if err != nil {
		return nil, fmt.Errorf("%w: restore MMR: %v", cll.ErrCorrupt, err)
	}
	leaves, ok := mmr.LeafCount(tree.Size())
	if !ok || leaves != state.IndexedSeq || state.Size != tree.Size() {
		return nil, fmt.Errorf("%w: MMR size does not match indexed sequence", cll.ErrCorrupt)
	}
	previous, err := r.verifyCheckpoint(state, tree)
	if err != nil {
		return nil, err
	}
	return &runnerState{state: state, tree: tree, previous: previous}, nil
}

func (r *Runner) advanceOnce(ctx context.Context, now time.Time, current *runnerState) (bool, error) {
	state := current.state
	tree := current.tree
	previous := current.previous
	entries, err := r.store.ScanEntries(ctx, state.IndexedSeq, r.config.ScanLimit)
	if err != nil {
		return false, err
	}
	var firstPending *time.Time
	if state.FirstPendingAt != nil {
		timestamp := *state.FirstPendingAt
		firstPending = &timestamp
	}
	indexed := state.IndexedSeq
	for _, entry := range entries {
		if entry.Seq != indexed+1 || portable.ValidateTime(entry.AppendedAt) != nil {
			return false, fmt.Errorf("%w: CLL entry sequence or time is invalid", cll.ErrCorrupt)
		}
		if _, err := tree.Append(entry.Value); err != nil {
			return false, fmt.Errorf("%w: append MMR entry: %v", cll.ErrCorrupt, err)
		}
		indexed = entry.Seq
		if firstPending == nil {
			timestamp := portable.NormalizeTime(entry.AppendedAt)
			firstPending = &timestamp
		}
	}
	lastCheckpointed := uint64(0)
	if state.Checkpoint != nil {
		lastCheckpointed = state.Checkpoint.IndexedSeq
	}
	uncheckpointed := indexed - lastCheckpointed
	due := firstPending != nil && r.config.Cadence.Due(uncheckpointed, *firstPending, now)
	next := cll.State{Size: tree.Size(), Nodes: tree.Nodes(), IndexedSeq: indexed, FirstPendingAt: firstPending, Checkpoint: state.Checkpoint, Witnesses: state.Witnesses}
	if due {
		root, err := tree.Root()
		if err != nil {
			return false, err
		}
		payload := Payload{LogID: r.config.LogID, KeyID: r.signer.KeyID(), MMRSize: tree.Size(), Root: hex.EncodeToString(root), Timestamp: now}
		var previousPeaks [][]byte
		var proof *mmr.ConsistencyProof
		if state.Checkpoint != nil {
			payload.PrevSize = state.Checkpoint.Size
			payload.PrevRoot = previous.Root
			previousPeaks = state.Checkpoint.Peaks
			consistency, err := tree.ConsistencyProof(state.Checkpoint.Size, tree.Size())
			if err != nil {
				return false, err
			}
			proof = &consistency
		}
		body, err := payload.CanonicalJSON()
		if err != nil {
			return false, err
		}
		peaks, err := tree.PeakHashesAt(tree.Size())
		if err != nil {
			return false, err
		}
		statement, err := r.signer.SignCheckpoint(ctx, body, peaks, previousPeaks, proof)
		if err != nil {
			return false, err
		}
		next.Checkpoint = &cll.CheckpointState{Bytes: statement, Size: tree.Size(), IndexedSeq: indexed, Peaks: peaks}
		next.FirstPendingAt = nil
		previous = Record{Root: payload.Root}
		for _, witnessID := range r.config.WitnessIDs {
			next.Witnesses = append(next.Witnesses, cll.WitnessState{WitnessID: witnessID, CheckpointSize: tree.Size(), Checkpoint: append([]byte(nil), statement...), NextAttemptAt: now})
		}
	}
	if len(entries) == 0 && !due {
		return false, nil
	}
	var expected []byte
	if state.Checkpoint != nil {
		expected = state.Checkpoint.Bytes
	}
	if err := r.store.CommitCLL(ctx, state.Size, expected, next); err != nil {
		return false, err
	}
	current.state = next
	current.previous = previous
	return true, nil
}

func (r *Runner) verifyCheckpoint(state cll.State, tree *mmr.Tree) (Record, error) {
	if state.Checkpoint == nil {
		return Record{}, nil
	}
	checkpoint := state.Checkpoint
	leaves, ok := mmr.LeafCount(checkpoint.Size)
	if !ok || checkpoint.Size > state.Size || leaves != checkpoint.IndexedSeq || checkpoint.IndexedSeq > state.IndexedSeq {
		return Record{}, fmt.Errorf("%w: invalid stored checkpoint position", cll.ErrCorrupt)
	}
	expectedPeaks, err := tree.PeakHashesAt(checkpoint.Size)
	if err != nil || !samePeaks(expectedPeaks, checkpoint.Peaks) {
		return Record{}, fmt.Errorf("%w: stored checkpoint peaks mismatch", cll.ErrCorrupt)
	}
	record, err := ParseRecord(checkpoint.Bytes)
	if err != nil || record.LogID != r.config.LogID || record.KeyID != r.signer.KeyID() || record.MMRSize != checkpoint.Size || !samePeaks(record.NewPeaks, checkpoint.Peaks) {
		return Record{}, fmt.Errorf("%w: stored checkpoint metadata mismatch", cll.ErrCorrupt)
	}
	root, err := treeRootAt(tree, checkpoint.Size)
	if err != nil || !bytes.Equal(root, mmr.RootFromPeaks(checkpoint.Peaks)) || record.Root != hex.EncodeToString(root) {
		return Record{}, fmt.Errorf("%w: stored checkpoint root mismatch", cll.ErrCorrupt)
	}
	payload, err := record.Payload().CanonicalJSON()
	if err != nil || r.signer.VerifyCheckpoint(payload, checkpoint.Bytes) != nil {
		return Record{}, fmt.Errorf("%w: stored checkpoint signature mismatch", cll.ErrCorrupt)
	}
	return record, nil
}

func treeRootAt(tree *mmr.Tree, size uint64) ([]byte, error) {
	peaks, err := tree.PeakHashesAt(size)
	if err != nil {
		return nil, err
	}
	return mmr.RootFromPeaks(peaks), nil
}

func samePeaks(left, right [][]byte) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if !bytes.Equal(left[index], right[index]) {
			return false
		}
	}
	return true
}

func (r *Runner) catchUp(ctx context.Context, now time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	var err error
	// now is pinned for the entire catch-up loop so every checkpoint emitted
	// in this pass shares one consistent evaluation time.
	now, err = normalizeRunnerTime(now)
	if err != nil {
		return err
	}
	current, err := r.loadRunnerState(ctx)
	if err != nil {
		return err
	}
	reloadedAfterContention := false
	for {
		changed, err := r.advanceOnce(ctx, now, current)
		if errors.Is(err, cll.ErrContention) && !reloadedAfterContention {
			current, err = r.loadRunnerState(ctx)
			if err != nil {
				return err
			}
			reloadedAfterContention = true
			continue
		}
		if err != nil {
			return err
		}
		if !changed {
			return nil
		}
		reloadedAfterContention = false
	}
}
