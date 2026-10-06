// Package storetest contains the shared behavioral contract for every backend.
package storetest

import (
	"bytes"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/action-state-group/cll-go/cll"
	"github.com/stretchr/testify/require"
)

var contractTime = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

func Value(value byte) []byte { return bytes.Repeat([]byte{value}, cll.EntryBytes) }

// Run exercises the complete portable contract against one fresh backend.
func Run(t *testing.T, store cll.Backend) {
	t.Helper()
	ctx := t.Context()
	observedTime := contractTime.Add(123456789 * time.Nanosecond)
	normalizedTime := contractTime.Add(123 * time.Millisecond)

	var wait sync.WaitGroup
	results := make(chan cll.AppendResult, 2)
	errorsOut := make(chan error, 2)
	inputValues := [][]byte{Value(1), Value(2)}
	for _, value := range inputValues {
		wait.Add(1)
		go func(value []byte) {
			defer wait.Done()
			result, err := store.Append(ctx, cll.AppendInput{Value: value, AppendedAt: observedTime})
			results <- result
			errorsOut <- err
		}(value)
	}
	wait.Wait()
	close(results)
	close(errorsOut)
	for err := range errorsOut {
		require.NoError(t, err)
	}
	sequences := map[uint64]bool{}
	for result := range results {
		sequences[result.Entry.Seq] = true
	}
	require.Equal(t, map[uint64]bool{1: true, 2: true}, sequences)
	inputValues[0][0] = 97

	duplicate, err := store.Append(ctx, cll.AppendInput{Value: Value(1), AppendedAt: contractTime.Add(10 * time.Second)})
	require.NoError(t, err)
	require.Equal(t, cll.AppendIdempotent, duplicate.Outcome)
	require.Equal(t, normalizedTime, duplicate.Entry.AppendedAt)

	entries, err := store.ScanEntries(ctx, 0, 2)
	require.NoError(t, err)
	require.Len(t, entries, 2)
	entries[0].Value[0] = 99
	stored, err := store.GetEntry(ctx, Value(1))
	require.NoError(t, err)
	require.Equal(t, byte(1), stored.Value[0])
	stored.Value[0] = 98
	storedAgain, err := store.GetEntry(ctx, Value(1))
	require.NoError(t, err)
	require.Equal(t, byte(1), storedAgain.Value[0])

	callerValue := Value(1)
	appended, err := store.Append(ctx, cll.AppendInput{Value: callerValue, AppendedAt: contractTime})
	require.NoError(t, err)
	callerValue[0] = 97
	appended.Entry.Value[0] = 97
	storedCallerValue, err := store.GetEntry(ctx, Value(1))
	require.NoError(t, err)
	require.Equal(t, byte(1), storedCallerValue.Value[0])

	_, err = store.Append(ctx, cll.AppendInput{Value: []byte{1}, AppendedAt: contractTime})
	require.ErrorIs(t, err, cll.ErrInvalid)
	_, err = store.ScanEntries(ctx, 0, 0)
	require.ErrorIs(t, err, cll.ErrInvalid)
	_, err = store.ScanEntries(ctx, 0, cll.MaxScanLimit+1)
	require.ErrorIs(t, err, cll.ErrInvalid)
	_, err = store.GetEntry(ctx, Value(9))
	require.ErrorIs(t, err, cll.ErrNotFound)

	node := Value(3)
	checkpoint := []byte("checkpoint")
	pending := cll.WitnessState{WitnessID: "primary", CheckpointSize: 1, Checkpoint: checkpoint, NextAttemptAt: contractTime}
	invalidMMR := cll.State{Size: 2, Nodes: [][]byte{Value(3), Value(4)}, IndexedSeq: 1}
	err = store.CommitCLL(ctx, 0, nil, invalidMMR)
	require.ErrorIs(t, err, cll.ErrInvalid)
	next := cll.State{Size: 1, Nodes: [][]byte{node}, IndexedSeq: 1, Checkpoint: &cll.CheckpointState{Bytes: checkpoint, Size: 1, IndexedSeq: 1, Peaks: [][]byte{node}}, Witnesses: []cll.WitnessState{pending}}
	require.NoError(t, store.CommitCLL(ctx, 0, nil, next))

	next.Nodes[0][0] = 88
	next.Checkpoint.Bytes[0] = 'x'
	node = Value(3)
	checkpoint = []byte("checkpoint")

	state, err := store.LoadCLL(ctx)
	require.NoError(t, err)
	require.Equal(t, uint64(1), state.IndexedSeq)
	require.Equal(t, checkpoint, state.Checkpoint.Bytes)
	state.Nodes[0][0] = 88
	state.Witnesses[0].Checkpoint[0] = 88
	unchanged, err := store.LoadCLL(ctx)
	require.NoError(t, err)
	require.Equal(t, byte(3), unchanged.Nodes[0][0])
	require.Equal(t, byte('c'), unchanged.Witnesses[0].Checkpoint[0])

	pendingRows, err := store.PendingWitnesses(ctx, contractTime, 1)
	require.NoError(t, err)
	require.Len(t, pendingRows, 1)
	pendingRows[0].Checkpoint[0] = 'x'
	persistedPending, err := store.GetWitness(ctx, "primary", 1)
	require.NoError(t, err)
	require.Equal(t, byte('c'), persistedPending.Checkpoint[0])
	pendingRows, err = store.PendingWitnesses(ctx, contractTime, 1)
	require.NoError(t, err)
	_, err = store.PendingWitnesses(ctx, contractTime, cll.MaxWitnesses+1)
	require.ErrorIs(t, err, cll.ErrInvalid)
	witness := pendingRows[0]
	witness.Attempts = 1
	witness.NextAttemptAt = contractTime.Add(time.Minute)
	require.NoError(t, store.CommitWitness(ctx, 0, witness))
	storedWitness, err := store.GetWitness(ctx, "primary", 1)
	require.NoError(t, err)
	require.Equal(t, uint32(1), storedWitness.Attempts)
	storedWitness.Checkpoint[0] = 'x'
	storedWitness, err = store.GetWitness(ctx, "primary", 1)
	require.NoError(t, err)
	require.Equal(t, byte('c'), storedWitness.Checkpoint[0])
	oversizedReason := storedWitness
	oversizedReason.Attempts++
	oversizedReason.LastError = strings.Repeat("x", cll.MaxReasonBytes+1)
	err = store.CommitWitness(ctx, storedWitness.Attempts, oversizedReason)
	require.ErrorIs(t, err, cll.ErrInvalid)
	oversizedReceipt := storedWitness
	oversizedReceipt.Attempts++
	oversizedReceipt.Receipt = &cll.WitnessReceiptState{Bytes: make([]byte, cll.MaxWitnessResponseBytes+1)}
	err = store.CommitWitness(ctx, storedWitness.Attempts, oversizedReceipt)
	require.ErrorIs(t, err, cll.ErrInvalid)

	second := cll.WitnessState{WitnessID: "secondary", CheckpointSize: 1, Checkpoint: checkpoint, NextAttemptAt: contractTime}
	stale := unchanged
	stale.Witnesses = append(stale.Witnesses, second)
	require.NoError(t, store.CommitCLL(ctx, stale.Size, stale.Checkpoint.Bytes, stale))
	storedWitness, err = store.GetWitness(ctx, "primary", 1)
	require.NoError(t, err)
	require.Equal(t, uint32(1), storedWitness.Attempts, "CommitCLL must preserve the current witness row")
	leafIndex, treeSize := int64(0), int64(1)
	withReceipt := storedWitness
	withReceipt.Attempts++
	withReceipt.Receipt = &cll.WitnessReceiptState{Bytes: []byte("receipt"), LeafIndex: &leafIndex, TreeSize: &treeSize}
	require.NoError(t, store.CommitWitness(ctx, storedWitness.Attempts, withReceipt))
	withReceipt.Receipt.Bytes[0] = 'x'
	*withReceipt.Receipt.LeafIndex = 9
	storedReceipt, err := store.GetWitness(ctx, "primary", 1)
	require.NoError(t, err)
	require.NotNil(t, storedReceipt.Receipt)
	require.NotNil(t, storedReceipt.Receipt.LeafIndex)
	require.Equal(t, []byte("receipt"), storedReceipt.Receipt.Bytes)
	require.Equal(t, int64(0), *storedReceipt.Receipt.LeafIndex)
	storedReceipt.Receipt.Bytes[0] = 'x'
	storedReceipt, err = store.GetWitness(ctx, "primary", 1)
	require.NoError(t, err)
	require.NotNil(t, storedReceipt.Receipt)
	require.Equal(t, []byte("receipt"), storedReceipt.Receipt.Bytes)

	err = store.CommitWitness(ctx, 0, cll.WitnessState{WitnessID: "missing", CheckpointSize: 1, Checkpoint: checkpoint, NextAttemptAt: contractTime})
	require.ErrorIs(t, err, cll.ErrContention)
	err = store.CommitCLL(ctx, 0, nil, unchanged)
	require.ErrorIs(t, err, cll.ErrContention)
	invalid := unchanged
	invalid.Nodes = append(invalid.Nodes, []byte{1})
	invalid.Size++
	err = store.CommitCLL(ctx, unchanged.Size, unchanged.Checkpoint.Bytes, invalid)
	require.ErrorIs(t, err, cll.ErrInvalid)

	current, err := store.LoadCLL(ctx)
	require.NoError(t, err)
	forward := current
	forward.Nodes = append(append([][]byte(nil), current.Nodes...), Value(4), Value(5))
	forward.Size = 3
	forward.IndexedSeq = 2
	forward.Checkpoint = &cll.CheckpointState{Bytes: []byte("checkpoint-2"), Size: 3, IndexedSeq: 2, Peaks: [][]byte{Value(5)}}
	require.NoError(t, store.CommitCLL(ctx, current.Size, current.Checkpoint.Bytes, forward))

	badPrefix, err := store.LoadCLL(ctx)
	require.NoError(t, err)
	badPrefix.Nodes[0][0] = 99
	err = store.CommitCLL(ctx, badPrefix.Size, badPrefix.Checkpoint.Bytes, badPrefix)
	require.ErrorIs(t, err, cll.ErrInvalid)

	removedCheckpoint, err := store.LoadCLL(ctx)
	require.NoError(t, err)
	removedCheckpoint.Checkpoint = nil
	err = store.CommitCLL(ctx, removedCheckpoint.Size, []byte("checkpoint-2"), removedCheckpoint)
	require.ErrorIs(t, err, cll.ErrContention)

	backwardCheckpoint, err := store.LoadCLL(ctx)
	require.NoError(t, err)
	backwardCheckpoint.Checkpoint = &cll.CheckpointState{Bytes: []byte("checkpoint"), Size: 1, IndexedSeq: 1, Peaks: [][]byte{Value(3)}}
	err = store.CommitCLL(ctx, backwardCheckpoint.Size, []byte("checkpoint-2"), backwardCheckpoint)
	require.ErrorIs(t, err, cll.ErrContention)

	changedCheckpoint, err := store.LoadCLL(ctx)
	require.NoError(t, err)
	changedCheckpoint.Checkpoint.Bytes = []byte("changed")
	err = store.CommitCLL(ctx, changedCheckpoint.Size, []byte("checkpoint-2"), changedCheckpoint)
	require.ErrorIs(t, err, cll.ErrContention)

	oversizedCheckpoint, err := store.LoadCLL(ctx)
	require.NoError(t, err)
	oversizedCheckpoint.Checkpoint.Bytes = make([]byte, cll.MaxCheckpointBytes+1)
	err = store.CommitCLL(ctx, oversizedCheckpoint.Size, []byte("checkpoint-2"), oversizedCheckpoint)
	require.ErrorIs(t, err, cll.ErrInvalid)

	require.NoError(t, store.Close())
	require.NoError(t, store.Close())
	_, err = store.ScanEntries(ctx, 0, 1)
	require.ErrorIs(t, err, cll.ErrClosed)
	_, err = store.ScanEntries(ctx, cll.MaxPortableInteger+1, 0)
	require.ErrorIs(t, err, cll.ErrClosed)
	_, err = store.GetEntry(ctx, []byte{1})
	require.ErrorIs(t, err, cll.ErrClosed)
	_, err = store.GetWitness(ctx, "", 0)
	require.ErrorIs(t, err, cll.ErrClosed)
	_, err = store.LoadCLL(ctx)
	require.ErrorIs(t, err, cll.ErrClosed)
	err = store.CommitCLL(ctx, 0, nil, cll.State{Size: 2})
	require.ErrorIs(t, err, cll.ErrClosed)
	_, err = store.PendingWitnesses(ctx, time.Time{}, 0)
	require.ErrorIs(t, err, cll.ErrClosed)
	err = store.CommitWitness(ctx, 0, cll.WitnessState{})
	require.ErrorIs(t, err, cll.ErrClosed)
	_, err = store.Append(ctx, cll.AppendInput{Value: Value(8), AppendedAt: contractTime})
	require.ErrorIs(t, err, cll.ErrClosed)
}

// CrossHandle verifies dense allocation and shared visibility across handles.
func CrossHandle(t *testing.T, first, second cll.Backend) {
	t.Helper()
	ctx := t.Context()
	var wait sync.WaitGroup
	results := make(chan cll.AppendResult, 2)
	errs := make(chan error, 2)
	for index, store := range []cll.Backend{first, second} {
		wait.Add(1)
		go func(index int, store cll.Backend) {
			defer wait.Done()
			result, err := store.Append(ctx, cll.AppendInput{Value: Value(byte(index + 3)), AppendedAt: contractTime})
			results <- result
			errs <- err
		}(index, store)
	}
	wait.Wait()
	close(results)
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	sequences := map[uint64]bool{}
	for result := range results {
		sequences[result.Entry.Seq] = true
	}
	require.Equal(t, map[uint64]bool{1: true, 2: true}, sequences)
	for _, store := range []cll.Backend{first, second} {
		entries, err := store.ScanEntries(ctx, 0, 10)
		require.NoError(t, err)
		require.Len(t, entries, 2)
	}
}
