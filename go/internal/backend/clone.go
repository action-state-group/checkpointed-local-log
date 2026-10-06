// Package backend implements the shared in-memory transition and wire engine.
package backend

import "github.com/action-state-group/cll-go/cll"

func CloneEntry(value cll.Entry) cll.Entry {
	value.Value = append([]byte(nil), value.Value...)
	return value
}

func CloneWitness(value cll.WitnessState) cll.WitnessState {
	value.Checkpoint = append([]byte(nil), value.Checkpoint...)
	if value.Receipt != nil {
		receipt := *value.Receipt
		receipt.Bytes = append([]byte(nil), receipt.Bytes...)
		if receipt.LeafIndex != nil {
			position := *receipt.LeafIndex
			receipt.LeafIndex = &position
		}
		if receipt.TreeSize != nil {
			size := *receipt.TreeSize
			receipt.TreeSize = &size
		}
		value.Receipt = &receipt
	}
	return value
}

func CloneState(value cll.State) cll.State {
	nodes := cloneBytesList(value.Nodes)
	witnesses := make([]cll.WitnessState, len(value.Witnesses))
	for index := range value.Witnesses {
		witnesses[index] = CloneWitness(value.Witnesses[index])
	}
	value = cloneStateHeader(value)
	value.Nodes = nodes
	value.Witnesses = witnesses
	return value
}

// cloneStateHeader copies bounded metadata without copying the potentially
// log-sized node and witness collections.
func cloneStateHeader(value cll.State) cll.State {
	value.Nodes = nil
	value.Witnesses = nil
	if value.FirstPendingAt != nil {
		timestamp := *value.FirstPendingAt
		value.FirstPendingAt = &timestamp
	}
	if value.Checkpoint != nil {
		checkpoint := *value.Checkpoint
		checkpoint.Bytes = append([]byte(nil), checkpoint.Bytes...)
		checkpoint.Peaks = cloneBytesList(checkpoint.Peaks)
		value.Checkpoint = &checkpoint
	}
	return value
}

func cloneBytesList(values [][]byte) [][]byte {
	result := make([][]byte, len(values))
	for index, value := range values {
		result[index] = append([]byte(nil), value...)
	}
	return result
}

func cloneEntries(values []cll.Entry) []cll.Entry {
	result := make([]cll.Entry, len(values))
	for index, value := range values {
		result[index] = CloneEntry(value)
	}
	return result
}
