package backend

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/action-state-group/cll-go/cll"
	"github.com/action-state-group/cll-go/internal/portable"
)

type WireEntry struct {
	Seq        string `json:"seq"`
	Value      string `json:"value"`
	AppendedAt string `json:"appendedAt"`
}

type WireWitness struct {
	WitnessID       string  `json:"witnessId"`
	CheckpointSize  string  `json:"checkpointSize"`
	Checkpoint      string  `json:"checkpoint"`
	Attempts        uint32  `json:"attempts"`
	NextAttemptAt   string  `json:"nextAttemptAt"`
	Receipt         *string `json:"receipt,omitempty"`
	EntryHash       string  `json:"entryHash,omitempty"`
	EntryHashScheme string  `json:"entryHashScheme,omitempty"`
	LeafIndex       *int64  `json:"leafIndex,omitempty"`
	TreeSize        *int64  `json:"treeSize,omitempty"`
	Permanent       bool    `json:"permanent"`
	LastError       string  `json:"lastError,omitempty"`
}

type WireState struct {
	Size                 string        `json:"size"`
	IndexedSeq           string        `json:"indexedSeq"`
	Nodes                []string      `json:"nodes"`
	FirstPendingAt       *string       `json:"firstPendingAt,omitempty"`
	Checkpoint           *string       `json:"checkpoint,omitempty"`
	CheckpointSize       *string       `json:"checkpointSize,omitempty"`
	CheckpointIndexedSeq *string       `json:"checkpointIndexedSeq,omitempty"`
	CheckpointPeaks      *[]string     `json:"checkpointPeaks,omitempty"`
	Witnesses            []WireWitness `json:"witnesses"`
}

func EntryToWire(entry cll.Entry) (WireEntry, error) {
	timestamp, err := portable.FormatTime(entry.AppendedAt)
	if err != nil {
		return WireEntry{}, err
	}
	return WireEntry{Seq: strconv.FormatUint(entry.Seq, 10), Value: base64.StdEncoding.EncodeToString(entry.Value), AppendedAt: timestamp}, nil
}

func EntryFromWire(wire WireEntry) (cll.Entry, error) {
	seq, err := parseDecimal(wire.Seq)
	if err != nil || seq == 0 || seq > cll.MaxPortableInteger {
		return cll.Entry{}, fmt.Errorf("%w: stored entry sequence is invalid", cll.ErrCorrupt)
	}
	value, err := base64.StdEncoding.Strict().DecodeString(wire.Value)
	if err != nil || len(value) != cll.EntryBytes {
		return cll.Entry{}, fmt.Errorf("%w: stored entry value is invalid", cll.ErrCorrupt)
	}
	appendedAt, err := portable.ParseTime(wire.AppendedAt)
	if err != nil {
		return cll.Entry{}, fmt.Errorf("%w: stored entry time is invalid", cll.ErrCorrupt)
	}
	return cll.Entry{Seq: seq, Value: value, AppendedAt: appendedAt}, nil
}

func WitnessToWire(value cll.WitnessState) (WireWitness, error) {
	timestamp, err := portable.FormatTime(value.NextAttemptAt)
	if err != nil {
		return WireWitness{}, err
	}
	wire := WireWitness{
		WitnessID: value.WitnessID, CheckpointSize: strconv.FormatUint(value.CheckpointSize, 10),
		Checkpoint: base64.StdEncoding.EncodeToString(value.Checkpoint), Attempts: value.Attempts,
		NextAttemptAt: timestamp, Permanent: value.Permanent, LastError: value.LastError,
	}
	if value.Receipt != nil {
		receipt := base64.StdEncoding.EncodeToString(value.Receipt.Bytes)
		wire.Receipt = &receipt
		wire.EntryHash = value.Receipt.EntryHash
		wire.EntryHashScheme = value.Receipt.EntryHashScheme
		wire.LeafIndex = value.Receipt.LeafIndex
		wire.TreeSize = value.Receipt.TreeSize
	}
	return wire, nil
}

func WitnessFromWire(wire WireWitness) (cll.WitnessState, error) {
	size, err := parseDecimal(wire.CheckpointSize)
	if err != nil {
		return cll.WitnessState{}, fmt.Errorf("%w: stored witness size is invalid", cll.ErrCorrupt)
	}
	checkpoint, err := base64.StdEncoding.Strict().DecodeString(wire.Checkpoint)
	if err != nil {
		return cll.WitnessState{}, fmt.Errorf("%w: stored witness checkpoint is invalid", cll.ErrCorrupt)
	}
	next, err := portable.ParseTime(wire.NextAttemptAt)
	if err != nil {
		return cll.WitnessState{}, fmt.Errorf("%w: stored witness time is invalid", cll.ErrCorrupt)
	}
	value := cll.WitnessState{WitnessID: wire.WitnessID, CheckpointSize: size, Checkpoint: checkpoint, Attempts: wire.Attempts, NextAttemptAt: next, Permanent: wire.Permanent, LastError: wire.LastError}
	if wire.Receipt != nil {
		receipt, decodeErr := base64.StdEncoding.Strict().DecodeString(*wire.Receipt)
		if decodeErr != nil {
			return cll.WitnessState{}, fmt.Errorf("%w: stored witness receipt is invalid", cll.ErrCorrupt)
		}
		value.Receipt = &cll.WitnessReceiptState{Bytes: receipt, EntryHash: wire.EntryHash, EntryHashScheme: wire.EntryHashScheme, LeafIndex: wire.LeafIndex, TreeSize: wire.TreeSize}
	} else if wire.EntryHash != "" || wire.EntryHashScheme != "" || wire.LeafIndex != nil || wire.TreeSize != nil {
		return cll.WitnessState{}, fmt.Errorf("%w: stored witness receipt metadata is incomplete", cll.ErrCorrupt)
	}
	if err := validateWitness(value, cll.ErrCorrupt); err != nil {
		return cll.WitnessState{}, err
	}
	return value, nil
}

func StateToWire(value cll.State) (WireState, error) {
	wire := WireState{Size: strconv.FormatUint(value.Size, 10), IndexedSeq: strconv.FormatUint(value.IndexedSeq, 10), Nodes: make([]string, len(value.Nodes)), Witnesses: make([]WireWitness, len(value.Witnesses))}
	for index, node := range value.Nodes {
		wire.Nodes[index] = base64.StdEncoding.EncodeToString(node)
	}
	if value.FirstPendingAt != nil {
		encoded, err := portable.FormatTime(*value.FirstPendingAt)
		if err != nil {
			return WireState{}, err
		}
		wire.FirstPendingAt = &encoded
	}
	if value.Checkpoint != nil {
		checkpoint := base64.StdEncoding.EncodeToString(value.Checkpoint.Bytes)
		size := strconv.FormatUint(value.Checkpoint.Size, 10)
		indexed := strconv.FormatUint(value.Checkpoint.IndexedSeq, 10)
		wire.Checkpoint, wire.CheckpointSize, wire.CheckpointIndexedSeq = &checkpoint, &size, &indexed
		peaks := make([]string, len(value.Checkpoint.Peaks))
		for index, peak := range value.Checkpoint.Peaks {
			peaks[index] = base64.StdEncoding.EncodeToString(peak)
		}
		wire.CheckpointPeaks = &peaks
	}
	for index, witness := range value.Witnesses {
		encoded, err := WitnessToWire(witness)
		if err != nil {
			return WireState{}, err
		}
		wire.Witnesses[index] = encoded
	}
	return wire, nil
}

func StateFromWire(wire WireState) (cll.State, error) {
	value, err := stateFromWire(wire)
	if err != nil {
		return cll.State{}, err
	}
	if err := validateState(value, cll.ErrCorrupt); err != nil {
		return cll.State{}, err
	}
	return value, nil
}

// StateDeltaFromWire decodes one cll.commit event. Engine validates the final
// counters against its current state before appending these delta rows.
func StateDeltaFromWire(wire WireState) (cll.State, error) {
	return stateFromWire(wire)
}

func stateFromWire(wire WireState) (cll.State, error) {
	size, err := parseDecimal(wire.Size)
	if err != nil {
		return cll.State{}, fmt.Errorf("%w: stored CLL size is invalid", cll.ErrCorrupt)
	}
	indexed, err := parseDecimal(wire.IndexedSeq)
	if err != nil {
		return cll.State{}, fmt.Errorf("%w: stored indexed sequence is invalid", cll.ErrCorrupt)
	}
	value := cll.State{Size: size, IndexedSeq: indexed, Nodes: make([][]byte, 0, len(wire.Nodes)), Witnesses: make([]cll.WitnessState, len(wire.Witnesses))}
	for _, encoded := range wire.Nodes {
		node, decodeErr := base64.StdEncoding.Strict().DecodeString(encoded)
		if decodeErr != nil {
			return cll.State{}, fmt.Errorf("%w: stored node is invalid", cll.ErrCorrupt)
		}
		value.Nodes = append(value.Nodes, node)
	}
	if wire.FirstPendingAt != nil {
		timestamp, parseErr := portable.ParseTime(*wire.FirstPendingAt)
		if parseErr != nil {
			return cll.State{}, fmt.Errorf("%w: stored pending time is invalid", cll.ErrCorrupt)
		}
		value.FirstPendingAt = &timestamp
	}
	present := 0
	for _, exists := range []bool{wire.Checkpoint != nil, wire.CheckpointSize != nil, wire.CheckpointIndexedSeq != nil, wire.CheckpointPeaks != nil} {
		if exists {
			present++
		}
	}
	if present != 0 && present != 4 {
		return cll.State{}, fmt.Errorf("%w: stored checkpoint tuple is incomplete", cll.ErrCorrupt)
	}
	if present == 4 {
		checkpoint, decodeErr := base64.StdEncoding.Strict().DecodeString(*wire.Checkpoint)
		if decodeErr != nil {
			return cll.State{}, fmt.Errorf("%w: stored checkpoint is invalid", cll.ErrCorrupt)
		}
		checkpointSize, sizeErr := parseDecimal(*wire.CheckpointSize)
		checkpointIndexed, indexedErr := parseDecimal(*wire.CheckpointIndexedSeq)
		if sizeErr != nil || indexedErr != nil {
			return cll.State{}, fmt.Errorf("%w: stored checkpoint position is invalid", cll.ErrCorrupt)
		}
		peaks := make([][]byte, len(*wire.CheckpointPeaks))
		for index, encoded := range *wire.CheckpointPeaks {
			peak, peakErr := base64.StdEncoding.Strict().DecodeString(encoded)
			if peakErr != nil {
				return cll.State{}, fmt.Errorf("%w: stored checkpoint peak is invalid", cll.ErrCorrupt)
			}
			peaks[index] = peak
		}
		value.Checkpoint = &cll.CheckpointState{Bytes: checkpoint, Size: checkpointSize, IndexedSeq: checkpointIndexed, Peaks: peaks}
	}
	for index, encoded := range wire.Witnesses {
		witness, witnessErr := WitnessFromWire(encoded)
		if witnessErr != nil {
			return cll.State{}, witnessErr
		}
		value.Witnesses[index] = witness
	}
	return value, nil
}

// MarshalMetadata encodes the relational metadata projection. Nodes and
// witnesses live in authoritative indexed tables and are omitted here.
func MarshalMetadata(value cll.State) ([]byte, error) {
	value.Nodes = [][]byte{}
	value.Witnesses = []cll.WitnessState{}
	wire, err := StateToWire(value)
	if err != nil {
		return nil, err
	}
	return json.Marshal(wire)
}

// MarshalWitness encodes one complete relational witness row.
func MarshalWitness(value cll.WitnessState) ([]byte, error) {
	wire, err := WitnessToWire(value)
	if err != nil {
		return nil, err
	}
	return json.Marshal(wire)
}

// UnmarshalWitness decodes and validates one complete relational witness row.
func UnmarshalWitness(data []byte) (cll.WitnessState, error) {
	var wire WireWitness
	if err := json.Unmarshal(data, &wire); err != nil {
		return cll.WitnessState{}, fmt.Errorf("%w: decode witness: %v", cll.ErrCorrupt, err)
	}
	return WitnessFromWire(wire)
}

func parseDecimal(value string) (uint64, error) {
	if value == "" || (len(value) > 1 && value[0] == '0') {
		return 0, fmt.Errorf("invalid decimal")
	}
	return strconv.ParseUint(value, 10, 64)
}

// ParseDecimal decodes the canonical portable uint64 representation.
func ParseDecimal(value string) (uint64, error) { return parseDecimal(value) }

func validEntryHash(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == cll.EntryBytes && hex.EncodeToString(decoded) == value
}
