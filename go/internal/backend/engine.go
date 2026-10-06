package backend

import (
	"bytes"
	"fmt"
	"sort"
	"time"

	"github.com/action-state-group/cll-go/cll"
	"github.com/action-state-group/cll-go/internal/portable"
	"github.com/action-state-group/cll-go/mmr"
)

// Engine owns the generic in-memory representation and transition rules.
// Callers serialize access when using it from concurrent backends.
type Engine struct {
	entries []cll.Entry
	byValue map[string]int
	state   cll.State
}

// Snapshot is an opaque mutation checkpoint. Engine transitions replace state
// and only append entries, so capturing it does not copy log-sized slices.
type Snapshot struct {
	entryCount int
	state      cll.State
}

func New() *Engine { return &Engine{byValue: make(map[string]int)} }

// Snapshot captures the current engine position for O(1) rollback.
func (e *Engine) Snapshot() Snapshot {
	return Snapshot{entryCount: len(e.entries), state: e.state}
}

// Restore rolls back mutations performed after snapshot was captured.
func (e *Engine) Restore(snapshot Snapshot) error {
	if snapshot.entryCount > len(e.entries) {
		return fmt.Errorf("%w: invalid engine snapshot", cll.ErrCorrupt)
	}
	for index := snapshot.entryCount; index < len(e.entries); index++ {
		delete(e.byValue, string(e.entries[index].Value))
		e.entries[index] = cll.Entry{}
	}
	e.entries = e.entries[:snapshot.entryCount]
	e.state = snapshot.state
	return nil
}

// DeltaSince returns the portable CLL commit delta after snapshot without
// copying nodes and witness rows that predate the mutation.
func (e *Engine) DeltaSince(snapshot Snapshot) (cll.State, error) {
	before, current := snapshot.state, e.state
	if len(current.Nodes) < len(before.Nodes) {
		return cll.State{}, fmt.Errorf("%w: invalid engine snapshot lineage", cll.ErrCorrupt)
	}
	delta := CloneState(cll.State{
		Size:           current.Size,
		IndexedSeq:     current.IndexedSeq,
		FirstPendingAt: current.FirstPendingAt,
		Checkpoint:     current.Checkpoint,
	})
	delta.Nodes = cloneBytesList(current.Nodes[len(before.Nodes):])
	existing := make(map[string]struct{}, len(before.Witnesses))
	for _, witness := range before.Witnesses {
		existing[WitnessKey(witness.WitnessID, witness.CheckpointSize)] = struct{}{}
	}
	for _, witness := range current.Witnesses {
		if _, found := existing[WitnessKey(witness.WitnessID, witness.CheckpointSize)]; !found {
			delta.Witnesses = append(delta.Witnesses, CloneWitness(witness))
		}
	}
	return delta, nil
}

func (e *Engine) Entries() []cll.Entry { return cloneEntries(e.entries) }
func (e *Engine) State() cll.State     { return CloneState(e.state) }

func (e *Engine) Replace(entries []cll.Entry, state cll.State) error {
	seen := make(map[string]struct{}, len(entries))
	for index, entry := range entries {
		if entry.Seq != uint64(index+1) || entry.Seq > cll.MaxPortableInteger || len(entry.Value) != cll.EntryBytes || portable.ValidateTime(entry.AppendedAt) != nil {
			return fmt.Errorf("%w: stored CLL entries are not contiguous and valid", cll.ErrCorrupt)
		}
		key := string(entry.Value)
		if _, exists := seen[key]; exists {
			return fmt.Errorf("%w: stored CLL entries contain duplicates", cll.ErrCorrupt)
		}
		seen[key] = struct{}{}
	}
	if err := validateState(state, cll.ErrCorrupt); err != nil {
		return err
	}
	e.entries = cloneEntries(entries)
	e.byValue = make(map[string]int, len(entries))
	for index, entry := range e.entries {
		e.byValue[string(entry.Value)] = index
	}
	e.state = CloneState(state)
	return nil
}

func (e *Engine) Append(input cll.AppendInput) (cll.AppendResult, error) {
	if len(input.Value) != cll.EntryBytes || portable.ValidateTime(input.AppendedAt) != nil {
		return cll.AppendResult{}, fmt.Errorf("%w: entry value or append time is invalid", cll.ErrInvalid)
	}
	key := string(input.Value)
	if index, exists := e.byValue[key]; exists {
		return cll.AppendResult{Entry: CloneEntry(e.entries[index]), Outcome: cll.AppendIdempotent}, nil
	}
	seq := uint64(len(e.entries) + 1)
	if seq > cll.MaxPortableInteger {
		return cll.AppendResult{}, fmt.Errorf("%w: entry sequence exceeds portable range", cll.ErrInvalid)
	}
	entry := cll.Entry{Seq: seq, Value: append([]byte(nil), input.Value...), AppendedAt: portable.NormalizeTime(input.AppendedAt)}
	e.entries = append(e.entries, entry)
	e.byValue[key] = len(e.entries) - 1
	return cll.AppendResult{Entry: CloneEntry(entry), Outcome: cll.AppendInserted}, nil
}

func (e *Engine) GetEntry(value []byte) (cll.Entry, error) {
	if len(value) != cll.EntryBytes {
		return cll.Entry{}, fmt.Errorf("%w: entry value has wrong width", cll.ErrInvalid)
	}
	index, exists := e.byValue[string(value)]
	if !exists {
		return cll.Entry{}, cll.ErrNotFound
	}
	return CloneEntry(e.entries[index]), nil
}

func (e *Engine) ScanEntries(afterSeq uint64, limit int) ([]cll.Entry, error) {
	if afterSeq > cll.MaxPortableInteger || limit < 1 || limit > cll.MaxScanLimit {
		return nil, fmt.Errorf("%w: invalid entry scan", cll.ErrInvalid)
	}
	start := afterSeq
	if start > uint64(len(e.entries)) {
		start = uint64(len(e.entries))
	}
	end := start + uint64(limit)
	if end > uint64(len(e.entries)) {
		end = uint64(len(e.entries))
	}
	return cloneEntries(e.entries[start:end]), nil
}

func (e *Engine) CommitCLL(expectedSize uint64, expectedCheckpoint []byte, next cll.State) error {
	updated, err := ApplyCLL(e.state, expectedSize, expectedCheckpoint, next)
	if err != nil {
		return err
	}
	e.state = updated
	return nil
}

// CommitCLLDelta applies a journal commit whose Nodes and Witnesses contain
// only rows added by that event. Existing log-sized collections are preserved
// without reconstructing them during replay.
func (e *Engine) CommitCLLDelta(expectedSize uint64, expectedCheckpoint []byte, delta cll.State) error {
	current := e.state
	if current.Size != expectedSize || !sameOptional(current.Checkpoint, expectedCheckpoint) {
		return fmt.Errorf("%w: CLL state changed", cll.ErrContention)
	}
	addedCount := uint64(len(delta.Nodes))
	if delta.Size < current.Size || current.Size+addedCount < current.Size || delta.Size != current.Size+addedCount {
		return fmt.Errorf("%w: CLL node delta does not match size", cll.ErrInvalid)
	}
	if err := validateStateMetadata(delta, delta.Size, cll.ErrInvalid); err != nil {
		return err
	}
	for _, node := range delta.Nodes {
		if len(node) != cll.EntryBytes {
			return fmt.Errorf("%w: node has wrong width", cll.ErrInvalid)
		}
	}
	addedWitnesses, err := validateCLLTransition(current, delta)
	if err != nil {
		return err
	}

	result := cloneStateHeader(delta)
	result.Nodes = append(current.Nodes, cloneBytesList(delta.Nodes)...)
	result.Witnesses = append(current.Witnesses, addedWitnesses...)
	e.state = result
	return nil
}

func ApplyCLL(current cll.State, expectedSize uint64, expectedCheckpoint []byte, next cll.State) (cll.State, error) {
	if current.Size != expectedSize || !sameOptional(current.Checkpoint, expectedCheckpoint) {
		return cll.State{}, fmt.Errorf("%w: CLL state changed", cll.ErrContention)
	}
	if err := validateState(next, cll.ErrInvalid); err != nil {
		return cll.State{}, err
	}
	if next.Size < current.Size || next.IndexedSeq < current.IndexedSeq || !prefixEqual(current.Nodes, next.Nodes) {
		return cll.State{}, fmt.Errorf("%w: CLL state is not append-only", cll.ErrInvalid)
	}
	added, err := validateCLLTransition(current, next)
	if err != nil {
		return cll.State{}, err
	}
	result := cloneStateHeader(next)
	result.Nodes = cloneBytesList(next.Nodes)
	result.Witnesses = append([]cll.WitnessState(nil), current.Witnesses...)
	result.Witnesses = append(result.Witnesses, added...)
	for index := range result.Witnesses {
		result.Witnesses[index] = CloneWitness(result.Witnesses[index])
	}
	return result, nil
}

func validateCLLTransition(current, next cll.State) ([]cll.WitnessState, error) {
	if next.IndexedSeq < current.IndexedSeq {
		return nil, fmt.Errorf("%w: CLL state is not append-only", cll.ErrInvalid)
	}
	if current.Checkpoint != nil && next.Checkpoint == nil {
		return nil, fmt.Errorf("%w: checkpoint cannot be removed", cll.ErrContention)
	}
	if current.Checkpoint != nil && next.Checkpoint != nil {
		if next.Checkpoint.Size < current.Checkpoint.Size || next.Checkpoint.IndexedSeq < current.Checkpoint.IndexedSeq {
			return nil, fmt.Errorf("%w: checkpoint moved backward", cll.ErrContention)
		}
		if next.Checkpoint.Size == current.Checkpoint.Size && (!bytes.Equal(next.Checkpoint.Bytes, current.Checkpoint.Bytes) || next.Checkpoint.IndexedSeq != current.Checkpoint.IndexedSeq || !listEqual(next.Checkpoint.Peaks, current.Checkpoint.Peaks)) {
			return nil, fmt.Errorf("%w: checkpoint changed at an existing size", cll.ErrContention)
		}
	}
	existing := make(map[string]cll.WitnessState, len(current.Witnesses))
	for _, witness := range current.Witnesses {
		existing[WitnessKey(witness.WitnessID, witness.CheckpointSize)] = witness
	}
	added := make([]cll.WitnessState, 0)
	seen := make(map[string]struct{}, len(next.Witnesses))
	for _, witness := range next.Witnesses {
		key := WitnessKey(witness.WitnessID, witness.CheckpointSize)
		if _, duplicate := seen[key]; duplicate {
			return nil, fmt.Errorf("%w: duplicate witness key", cll.ErrInvalid)
		}
		seen[key] = struct{}{}
		if currentWitness, exists := existing[key]; exists {
			if !bytes.Equal(currentWitness.Checkpoint, witness.Checkpoint) {
				return nil, fmt.Errorf("%w: witness checkpoint changed", cll.ErrContention)
			}
			continue
		}
		added = append(added, CloneWitness(witness))
	}
	return added, nil
}

func (e *Engine) PendingWitnesses(now time.Time, limit int) ([]cll.WitnessState, error) {
	if portable.ValidateTime(now) != nil || limit < 1 || limit > cll.MaxWitnesses {
		return nil, fmt.Errorf("%w: invalid pending witness query", cll.ErrInvalid)
	}
	result := make([]cll.WitnessState, 0)
	for _, witness := range e.state.Witnesses {
		if witness.Receipt == nil && !witness.Permanent && !witness.NextAttemptAt.After(now) {
			result = append(result, CloneWitness(witness))
		}
	}
	sort.SliceStable(result, func(i, j int) bool {
		if result[i].CheckpointSize == result[j].CheckpointSize {
			return result[i].WitnessID < result[j].WitnessID
		}
		return result[i].CheckpointSize < result[j].CheckpointSize
	})
	if len(result) > limit {
		result = result[:limit]
	}
	return result, nil
}

func (e *Engine) GetWitness(id string, size uint64) (cll.WitnessState, error) {
	if cll.ValidateIdentifier(id) != nil || size == 0 {
		return cll.WitnessState{}, fmt.Errorf("%w: invalid witness key", cll.ErrInvalid)
	}
	key := WitnessKey(id, size)
	for _, witness := range e.state.Witnesses {
		if WitnessKey(witness.WitnessID, witness.CheckpointSize) == key {
			return CloneWitness(witness), nil
		}
	}
	return cll.WitnessState{}, cll.ErrNotFound
}

func (e *Engine) CommitWitness(expectedAttempts uint32, next cll.WitnessState) error {
	updated, err := ApplyWitness(e.state, expectedAttempts, next)
	if err != nil {
		return err
	}
	e.state = updated
	return nil
}

// ApplyWitness validates and applies a witness compare-and-set transition.
func ApplyWitness(current cll.State, expectedAttempts uint32, next cll.WitnessState) (cll.State, error) {
	if err := validateWitness(next, cll.ErrInvalid); err != nil {
		return cll.State{}, err
	}
	key := WitnessKey(next.WitnessID, next.CheckpointSize)
	for index, witness := range current.Witnesses {
		if WitnessKey(witness.WitnessID, witness.CheckpointSize) != key {
			continue
		}
		if witness.Attempts != expectedAttempts {
			return cll.State{}, fmt.Errorf("%w: witness state changed", cll.ErrContention)
		}
		if !bytes.Equal(witness.Checkpoint, next.Checkpoint) {
			return cll.State{}, fmt.Errorf("%w: witness checkpoint changed", cll.ErrContention)
		}
		result := current
		result.Witnesses = append([]cll.WitnessState(nil), current.Witnesses...)
		result.Witnesses[index] = CloneWitness(next)
		return result, nil
	}
	return cll.State{}, fmt.Errorf("%w: witness state changed", cll.ErrContention)
}

func WitnessKey(id string, size uint64) string { return fmt.Sprintf("%s\x00%d", id, size) }

func validateState(value cll.State, class error) error {
	if err := validateStateMetadata(value, uint64(len(value.Nodes)), class); err != nil {
		return err
	}
	for _, node := range value.Nodes {
		if len(node) != cll.EntryBytes {
			return fmt.Errorf("%w: node has wrong width", class)
		}
	}
	return nil
}

func validateStateMetadata(value cll.State, nodeCount uint64, class error) error {
	if value.Size != nodeCount {
		return fmt.Errorf("%w: CLL size does not match nodes", class)
	}
	if leaves, complete := mmr.LeafCount(value.Size); !complete || leaves != value.IndexedSeq {
		return fmt.Errorf("%w: CLL nodes do not form the indexed MMR", class)
	}
	if value.FirstPendingAt != nil && portable.ValidateTime(*value.FirstPendingAt) != nil {
		return fmt.Errorf("%w: pending time is invalid", class)
	}
	if value.Checkpoint != nil {
		checkpoint := value.Checkpoint
		if len(checkpoint.Bytes) < 1 || len(checkpoint.Bytes) > cll.MaxCheckpointBytes || checkpoint.Size == 0 || checkpoint.Size > value.Size || checkpoint.IndexedSeq > value.IndexedSeq {
			return fmt.Errorf("%w: checkpoint state is invalid", class)
		}
		for _, peak := range checkpoint.Peaks {
			if len(peak) != cll.EntryBytes {
				return fmt.Errorf("%w: checkpoint peak has wrong width", class)
			}
		}
	}
	seen := make(map[string]struct{}, len(value.Witnesses))
	for _, witness := range value.Witnesses {
		if err := validateWitness(witness, class); err != nil {
			return err
		}
		key := WitnessKey(witness.WitnessID, witness.CheckpointSize)
		if _, exists := seen[key]; exists {
			return fmt.Errorf("%w: duplicate witness key", class)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func validateWitness(value cll.WitnessState, class error) error {
	if cll.ValidateIdentifier(value.WitnessID) != nil || value.CheckpointSize == 0 || len(value.Checkpoint) < 1 || len(value.Checkpoint) > cll.MaxCheckpointBytes || portable.ValidateTime(value.NextAttemptAt) != nil || len(value.LastError) > cll.MaxReasonBytes {
		return fmt.Errorf("%w: witness state is invalid", class)
	}
	if value.Receipt != nil {
		if len(value.Receipt.Bytes) < 1 || len(value.Receipt.Bytes) > cll.MaxWitnessResponseBytes {
			return fmt.Errorf("%w: witness receipt is invalid", class)
		}
		if value.Receipt.EntryHash != "" && !validEntryHash(value.Receipt.EntryHash) {
			return fmt.Errorf("%w: witness entry hash is invalid", class)
		}
		if value.Receipt.EntryHashScheme != "" && value.Receipt.EntryHashScheme != "legacy" {
			return fmt.Errorf("%w: witness entry hash scheme is invalid", class)
		}
		for _, position := range []*int64{value.Receipt.LeafIndex, value.Receipt.TreeSize} {
			if position != nil && (*position < 0 || uint64(*position) > cll.MaxPortableInteger) {
				return fmt.Errorf("%w: witness receipt position is invalid", class)
			}
		}
	}
	return nil
}

func sameOptional(checkpoint *cll.CheckpointState, expected []byte) bool {
	if checkpoint == nil {
		return expected == nil
	}
	return expected != nil && bytes.Equal(checkpoint.Bytes, expected)
}

func prefixEqual(prefix, values [][]byte) bool {
	if len(values) < len(prefix) {
		return false
	}
	for index, value := range prefix {
		if !bytes.Equal(value, values[index]) {
			return false
		}
	}
	return true
}

func listEqual(left, right [][]byte) bool {
	return len(left) == len(right) && prefixEqual(left, right)
}
