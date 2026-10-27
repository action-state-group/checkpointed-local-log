// Package conformance runs the language-neutral CLL backend conformance
// vectors (backend-conformance-vectors/ in the repository, pinned here as
// vectors.json) against any backend, built-in or user-supplied.
//
// The vectors implement docs/backend-contract.md. Each case runs against a
// fresh backend that implements cll.EntryStore, cll.CheckpointStateStore,
// cll.WitnessStateStore and Close() error, or the subset the case needs.
package conformance

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/action-state-group/checkpointed-local-log/go/cll"
	"github.com/action-state-group/checkpointed-local-log/go/internal/backend"
	"github.com/stretchr/testify/require"
)

//go:embed vectors.json
var vectorsJSON []byte

// Config describes the backend under test.
type Config struct {
	// Open returns a fresh, empty backend for one case. The runner closes it
	// when the case ends if it implements Close() error.
	Open func(t *testing.T) any
	// Reopen closes current and opens the same durable state again. Leave it
	// nil for a backend without durable state; cases that reopen are skipped.
	Reopen func(t *testing.T, current any) any
	// NoDigestAppend declares that Append refuses identities the store does
	// not already hold, with cll.ErrUnsupported.
	NoDigestAppend bool
}

type document struct {
	Version int        `json:"version"`
	Cases   []testCase `json:"cases"`
}

type testCase struct {
	Name       string            `json:"name"`
	Interfaces []string          `json:"interfaces"`
	Requires   []string          `json:"requires"`
	Unless     []string          `json:"unless"`
	Steps      []json.RawMessage `json:"steps"`
}

type stepArgs struct {
	Op                 string          `json:"op"`
	Input              *wireInput      `json:"input"`
	Value              *string         `json:"value"`
	AfterSeq           string          `json:"afterSeq"`
	Limit              int             `json:"limit"`
	ExpectedSize       string          `json:"expectedSize"`
	ExpectedCheckpoint *string         `json:"expectedCheckpoint"`
	Next               json.RawMessage `json:"next"`
	Now                string          `json:"now"`
	WitnessID          string          `json:"witnessId"`
	CheckpointSize     string          `json:"checkpointSize"`
	ExpectedAttempts   uint32          `json:"expectedAttempts"`
	Expect             map[string]any  `json:"expect"`
}

type wireInput struct {
	Value      string `json:"value"`
	AppendedAt string `json:"appendedAt"`
}

// errUnrepresentable marks a vector argument that Go's types cannot hold. The
// contract counts it as an invalid caller value.
var errUnrepresentable = fmt.Errorf("%w: argument is not representable", cll.ErrInvalid)

// Run executes every applicable case as a subtest.
func Run(t *testing.T, config Config) {
	t.Helper()
	var doc document
	decoder := json.NewDecoder(bytes.NewReader(vectorsJSON))
	decoder.UseNumber()
	require.NoError(t, decoder.Decode(&doc))
	require.Equal(t, 1, doc.Version)
	capabilities := map[string]bool{
		"digest-append":  !config.NoDigestAppend,
		"reopen":         config.Reopen != nil,
		"extended-years": true,
	}
	for _, item := range doc.Cases {
		t.Run(item.Name, func(t *testing.T) {
			for _, name := range item.Requires {
				if !capabilities[name] {
					t.Skipf("backend lacks capability %s", name)
				}
			}
			for _, name := range item.Unless {
				if capabilities[name] {
					t.Skipf("case applies only without capability %s", name)
				}
			}
			subject := config.Open(t)
			for _, name := range item.Interfaces {
				if !implements(subject, name) {
					closeSubject(t, subject)
					t.Skipf("backend does not implement %s", name)
				}
			}
			defer func() { closeSubject(t, subject) }()
			for index, raw := range item.Steps {
				var step stepArgs
				stepDecoder := json.NewDecoder(bytes.NewReader(raw))
				stepDecoder.UseNumber()
				require.NoError(t, stepDecoder.Decode(&step))
				if step.Op == "reopen" {
					subject = config.Reopen(t, subject)
					continue
				}
				result, err := execute(t.Context(), subject, step)
				label := fmt.Sprintf("step %d (%s)", index, step.Op)
				if want, ok := step.Expect["error"]; ok {
					require.Error(t, err, label)
					require.Equal(t, want, code(err), "%s: %v", label, err)
					continue
				}
				require.NoError(t, err, label)
				require.Equal(t, normalize(t, step.Op, step.Expect["result"]), normalize(t, step.Op, result), label)
			}
		})
	}
}

func implements(subject any, name string) bool {
	switch name {
	case "entries":
		_, ok := subject.(cll.EntryStore)
		return ok
	case "checkpoint":
		_, ok := subject.(cll.CheckpointStateStore)
		return ok
	case "witness":
		_, ok := subject.(cll.WitnessStateStore)
		return ok
	case "count":
		_, ok := subject.(cll.EntryCounter)
		return ok
	case "close":
		_, ok := subject.(interface{ Close() error })
		return ok
	}
	return false
}

func closeSubject(t *testing.T, subject any) {
	if closer, ok := subject.(interface{ Close() error }); ok {
		require.NoError(t, closer.Close())
	}
}

func execute(ctx context.Context, subject any, step stepArgs) (any, error) {
	switch step.Op {
	case "append":
		value, err := decodeBytes(step.Input.Value)
		if err != nil {
			return nil, err
		}
		at, err := decodeTime(step.Input.AppendedAt)
		if err != nil {
			return nil, err
		}
		result, err := subject.(cll.EntryStore).Append(ctx, cll.AppendInput{Value: value, AppendedAt: at})
		if err != nil {
			return nil, err
		}
		entry, err := backend.EntryToWire(result.Entry)
		return map[string]any{"entry": entry, "outcome": string(result.Outcome)}, err
	case "getEntry":
		value, err := decodeBytes(*step.Value)
		if err != nil {
			return nil, err
		}
		entry, err := subject.(cll.EntryStore).GetEntry(ctx, value)
		if err != nil {
			return nil, err
		}
		return backend.EntryToWire(entry)
	case "scanEntries":
		afterSeq, err := decodeDecimal(step.AfterSeq)
		if err != nil {
			return nil, err
		}
		entries, err := subject.(cll.EntryStore).ScanEntries(ctx, afterSeq, step.Limit)
		if err != nil {
			return nil, err
		}
		wire := make([]backend.WireEntry, len(entries))
		for index, entry := range entries {
			if wire[index], err = backend.EntryToWire(entry); err != nil {
				return nil, err
			}
		}
		return wire, nil
	case "entryCount":
		count, err := subject.(cll.EntryCounter).EntryCount(ctx)
		if err != nil {
			return nil, err
		}
		return strconv.FormatUint(count, 10), nil
	case "loadCll":
		state, err := subject.(cll.CheckpointStateStore).LoadCLL(ctx)
		if err != nil {
			return nil, err
		}
		return backend.StateToWire(state)
	case "commitCll":
		expectedSize, err := decodeDecimal(step.ExpectedSize)
		if err != nil {
			return nil, err
		}
		var expectedCheckpoint []byte
		if step.ExpectedCheckpoint != nil {
			if expectedCheckpoint, err = decodeBytes(*step.ExpectedCheckpoint); err != nil {
				return nil, err
			}
		}
		next, err := decodeState(step.Next)
		if err != nil {
			return nil, err
		}
		return nil, subject.(cll.CheckpointStateStore).CommitCLL(ctx, expectedSize, expectedCheckpoint, next)
	case "pendingWitnesses":
		now, err := decodeTime(step.Now)
		if err != nil {
			return nil, err
		}
		rows, err := subject.(cll.WitnessStateStore).PendingWitnesses(ctx, now, step.Limit)
		if err != nil {
			return nil, err
		}
		wire := make([]backend.WireWitness, len(rows))
		for index, row := range rows {
			if wire[index], err = backend.WitnessToWire(row); err != nil {
				return nil, err
			}
		}
		return wire, nil
	case "getWitness":
		size, err := decodeDecimal(step.CheckpointSize)
		if err != nil {
			return nil, err
		}
		row, err := subject.(cll.WitnessStateStore).GetWitness(ctx, step.WitnessID, size)
		if err != nil {
			return nil, err
		}
		return backend.WitnessToWire(row)
	case "commitWitness":
		next, err := decodeWitness(step.Next)
		if err != nil {
			return nil, err
		}
		return nil, subject.(cll.WitnessStateStore).CommitWitness(ctx, step.ExpectedAttempts, next)
	case "close":
		return nil, subject.(interface{ Close() error }).Close()
	}
	return nil, fmt.Errorf("unknown conformance op %q", step.Op)
}

var codes = []struct {
	err  error
	code string
}{
	{cll.ErrNotFound, "not_found"},
	{cll.ErrInvalid, "invalid"},
	{cll.ErrCorrupt, "corrupt"},
	{cll.ErrClosed, "closed"},
	{cll.ErrContention, "contention"},
	{cll.ErrRejected, "rejected"},
	{cll.ErrUnsupported, "unsupported"},
}

func code(err error) string {
	for _, item := range codes {
		if errors.Is(err, item.err) {
			return item.code
		}
	}
	return "unclassified: " + err.Error()
}

// normalize turns an expected or actual result into comparable JSON values.
// loadCll witness order is not part of the contract, so it is sorted by key.
func normalize(t *testing.T, op string, value any) any {
	t.Helper()
	encoded, err := json.Marshal(value)
	require.NoError(t, err)
	var out any
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	require.NoError(t, decoder.Decode(&out))
	if op == "loadCll" {
		if state, ok := out.(map[string]any); ok {
			if rows, ok := state["witnesses"].([]any); ok {
				slices.SortFunc(rows, compareWitnessKeys)
			}
		}
	}
	return out
}

func compareWitnessKeys(left, right any) int {
	l, r := left.(map[string]any), right.(map[string]any)
	ls, _ := strconv.ParseUint(fmt.Sprint(l["checkpointSize"]), 10, 64)
	rs, _ := strconv.ParseUint(fmt.Sprint(r["checkpointSize"]), 10, 64)
	if ls != rs {
		if ls < rs {
			return -1
		}
		return 1
	}
	return bytes.Compare([]byte(fmt.Sprint(l["witnessId"])), []byte(fmt.Sprint(r["witnessId"])))
}

func decodeBytes(value string) ([]byte, error) {
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil {
		return nil, errUnrepresentable
	}
	return decoded, nil
}

var timeForm = regexp.MustCompile(`^([+-][0-9]{6}|[0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})\.([0-9]{3})Z$`)

// decodeTime reads the toISOString() form without enforcing the portable
// range, so a time outside it reaches the backend, which must reject it.
func decodeTime(value string) (time.Time, error) {
	parts := timeForm.FindStringSubmatch(value)
	if parts == nil {
		return time.Time{}, errUnrepresentable
	}
	fields := make([]int, len(parts)-1)
	for index, part := range parts[1:] {
		parsed, err := strconv.Atoi(part)
		if err != nil {
			return time.Time{}, errUnrepresentable
		}
		fields[index] = parsed
	}
	return time.Date(fields[0], time.Month(fields[1]), fields[2], fields[3], fields[4], fields[5], fields[6]*int(time.Millisecond), time.UTC), nil
}

func decodeDecimal(value string) (uint64, error) {
	parsed, err := backend.ParseDecimal(value)
	if err != nil {
		return 0, errUnrepresentable
	}
	return parsed, nil
}

type inputWitness struct {
	WitnessID       string       `json:"witnessId"`
	CheckpointSize  string       `json:"checkpointSize"`
	Checkpoint      string       `json:"checkpoint"`
	Attempts        uint32       `json:"attempts"`
	NextAttemptAt   string       `json:"nextAttemptAt"`
	Receipt         *string      `json:"receipt"`
	EntryHash       *string      `json:"entryHash"`
	EntryHashScheme *string      `json:"entryHashScheme"`
	LeafIndex       *json.Number `json:"leafIndex"`
	TreeSize        *json.Number `json:"treeSize"`
	Permanent       bool         `json:"permanent"`
	LastError       string       `json:"lastError"`
}

type inputState struct {
	Size                 string            `json:"size"`
	IndexedSeq           string            `json:"indexedSeq"`
	Nodes                []string          `json:"nodes"`
	FirstPendingAt       *string           `json:"firstPendingAt"`
	Checkpoint           *string           `json:"checkpoint"`
	CheckpointSize       *string           `json:"checkpointSize"`
	CheckpointIndexedSeq *string           `json:"checkpointIndexedSeq"`
	CheckpointPeaks      *[]string         `json:"checkpointPeaks"`
	Witnesses            []json.RawMessage `json:"witnesses"`
}

// decodeWitness decodes a caller value without validating it, so the backend
// under test applies the contract's rules itself.
func decodeWitness(raw json.RawMessage) (cll.WitnessState, error) {
	var wire inputWitness
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&wire); err != nil {
		return cll.WitnessState{}, errUnrepresentable
	}
	value := cll.WitnessState{WitnessID: wire.WitnessID, Attempts: wire.Attempts, Permanent: wire.Permanent, LastError: wire.LastError}
	var err error
	if value.CheckpointSize, err = decodeDecimal(wire.CheckpointSize); err != nil {
		return cll.WitnessState{}, err
	}
	if value.Checkpoint, err = decodeBytes(wire.Checkpoint); err != nil {
		return cll.WitnessState{}, err
	}
	if value.NextAttemptAt, err = decodeTime(wire.NextAttemptAt); err != nil {
		return cll.WitnessState{}, err
	}
	if wire.Receipt == nil {
		if wire.EntryHash != nil || wire.EntryHashScheme != nil || wire.LeafIndex != nil || wire.TreeSize != nil {
			return cll.WitnessState{}, errUnrepresentable
		}
		return value, nil
	}
	receipt := &cll.WitnessReceiptState{}
	if receipt.Bytes, err = decodeBytes(*wire.Receipt); err != nil {
		return cll.WitnessState{}, err
	}
	if wire.EntryHash != nil {
		receipt.EntryHash = *wire.EntryHash
	}
	if wire.EntryHashScheme != nil {
		receipt.EntryHashScheme = *wire.EntryHashScheme
	}
	for _, position := range []struct {
		from *json.Number
		to   **int64
	}{{wire.LeafIndex, &receipt.LeafIndex}, {wire.TreeSize, &receipt.TreeSize}} {
		if position.from == nil {
			continue
		}
		parsed, parseErr := position.from.Int64()
		if parseErr != nil {
			return cll.WitnessState{}, errUnrepresentable
		}
		*position.to = &parsed
	}
	value.Receipt = receipt
	return value, nil
}

func decodeState(raw json.RawMessage) (cll.State, error) {
	var wire inputState
	if err := json.Unmarshal(raw, &wire); err != nil {
		return cll.State{}, errUnrepresentable
	}
	var value cll.State
	var err error
	if value.Size, err = decodeDecimal(wire.Size); err != nil {
		return cll.State{}, err
	}
	if value.IndexedSeq, err = decodeDecimal(wire.IndexedSeq); err != nil {
		return cll.State{}, err
	}
	if value.Nodes, err = decodeList(wire.Nodes); err != nil {
		return cll.State{}, err
	}
	if wire.FirstPendingAt != nil {
		pending, timeErr := decodeTime(*wire.FirstPendingAt)
		if timeErr != nil {
			return cll.State{}, timeErr
		}
		value.FirstPendingAt = &pending
	}
	present := 0
	for _, exists := range []bool{wire.Checkpoint != nil, wire.CheckpointSize != nil, wire.CheckpointIndexedSeq != nil, wire.CheckpointPeaks != nil} {
		if exists {
			present++
		}
	}
	switch present {
	case 0:
	case 4:
		checkpoint := &cll.CheckpointState{}
		if checkpoint.Bytes, err = decodeBytes(*wire.Checkpoint); err != nil {
			return cll.State{}, err
		}
		if checkpoint.Size, err = decodeDecimal(*wire.CheckpointSize); err != nil {
			return cll.State{}, err
		}
		if checkpoint.IndexedSeq, err = decodeDecimal(*wire.CheckpointIndexedSeq); err != nil {
			return cll.State{}, err
		}
		if checkpoint.Peaks, err = decodeList(*wire.CheckpointPeaks); err != nil {
			return cll.State{}, err
		}
		value.Checkpoint = checkpoint
	default:
		return cll.State{}, errUnrepresentable
	}
	value.Witnesses = make([]cll.WitnessState, 0, len(wire.Witnesses))
	for _, item := range wire.Witnesses {
		witness, witnessErr := decodeWitness(item)
		if witnessErr != nil {
			return cll.State{}, witnessErr
		}
		value.Witnesses = append(value.Witnesses, witness)
	}
	return value, nil
}

func decodeList(values []string) ([][]byte, error) {
	out := make([][]byte, len(values))
	for index, item := range values {
		decoded, err := decodeBytes(item)
		if err != nil {
			return nil, err
		}
		out[index] = decoded
	}
	return out, nil
}
