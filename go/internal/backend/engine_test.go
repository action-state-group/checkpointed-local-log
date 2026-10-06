package backend

import (
	"bytes"
	"testing"
	"time"

	"github.com/action-state-group/cll-go/cll"
	"github.com/stretchr/testify/require"
)

func TestSnapshotRestoresMutationAndBuildsDelta(t *testing.T) {
	engine := New()
	now := time.Date(2026, time.September, 3, 12, 0, 0, 0, time.UTC)
	firstNode := bytes.Repeat([]byte{1}, cll.EntryBytes)
	secondNode := bytes.Repeat([]byte{2}, cll.EntryBytes)

	_, err := engine.Append(cll.AppendInput{Value: firstNode, AppendedAt: now})
	require.NoError(t, err)
	first := cll.State{
		Size: 1, Nodes: [][]byte{firstNode}, IndexedSeq: 1,
		Witnesses: []cll.WitnessState{{
			WitnessID: "first", CheckpointSize: 1, Checkpoint: []byte{1}, NextAttemptAt: now,
		}},
	}
	require.NoError(t, engine.CommitCLL(0, nil, first))
	snapshot := engine.Snapshot()

	_, err = engine.Append(cll.AppendInput{Value: secondNode, AppendedAt: now.Add(time.Second)})
	require.NoError(t, err)
	second := engine.State()
	thirdNode := bytes.Repeat([]byte{3}, cll.EntryBytes)
	second.Size = 3
	second.Nodes = append(second.Nodes, secondNode, thirdNode)
	second.IndexedSeq = 2
	second.Witnesses = append(second.Witnesses, cll.WitnessState{
		WitnessID: "second", CheckpointSize: 3, Checkpoint: []byte{2}, NextAttemptAt: now,
	})
	require.NoError(t, engine.CommitCLL(1, nil, second))

	delta, err := engine.DeltaSince(snapshot)
	require.NoError(t, err)
	require.Equal(t, [][]byte{secondNode, thirdNode}, delta.Nodes)
	require.Len(t, delta.Witnesses, 1)
	require.Equal(t, "second", delta.Witnesses[0].WitnessID)

	require.NoError(t, engine.Restore(snapshot))
	require.Len(t, engine.Entries(), 1)
	require.Equal(t, first, engine.State())
}

func TestCommitCLLDeltaPreservesExistingCollections(t *testing.T) {
	engine := New()
	now := time.Date(2026, time.September, 3, 12, 0, 0, 0, time.UTC)
	firstNode := bytes.Repeat([]byte{1}, cll.EntryBytes)
	firstWitness := cll.WitnessState{WitnessID: "first", CheckpointSize: 1, Checkpoint: []byte{1}, NextAttemptAt: now}
	require.NoError(t, engine.CommitCLL(0, nil, cll.State{
		Size: 1, Nodes: [][]byte{firstNode}, IndexedSeq: 1, Witnesses: []cll.WitnessState{firstWitness},
	}))

	secondNode := bytes.Repeat([]byte{2}, cll.EntryBytes)
	thirdNode := bytes.Repeat([]byte{3}, cll.EntryBytes)
	secondWitness := cll.WitnessState{WitnessID: "second", CheckpointSize: 3, Checkpoint: []byte{2}, NextAttemptAt: now}
	delta := cll.State{Size: 3, Nodes: [][]byte{secondNode, thirdNode}, IndexedSeq: 2, Witnesses: []cll.WitnessState{secondWitness}}
	require.NoError(t, engine.CommitCLLDelta(1, nil, delta))

	delta.Nodes[0][0] = 99
	delta.Witnesses[0].Checkpoint[0] = 99
	state := engine.State()
	require.Equal(t, [][]byte{firstNode, bytes.Repeat([]byte{2}, cll.EntryBytes), thirdNode}, state.Nodes)
	require.Len(t, state.Witnesses, 2)
	require.Equal(t, []string{"first", "second"}, []string{state.Witnesses[0].WitnessID, state.Witnesses[1].WitnessID})
	require.Equal(t, byte(2), state.Witnesses[1].Checkpoint[0])

	require.ErrorIs(t, engine.CommitCLLDelta(3, nil, cll.State{Size: 4, IndexedSeq: 3}), cll.ErrInvalid)
	require.Equal(t, uint64(3), engine.State().Size)
	require.ErrorIs(t, engine.CommitCLLDelta(1, nil, cll.State{Size: 3, IndexedSeq: 2}), cll.ErrContention)
}

func TestCommitCLLDeltaAllocationsDoNotScaleWithExistingNodes(t *testing.T) {
	small := engineWithState(t, 1, 1)
	large := engineWithState(t, 8191, 4096)
	smallAllocs := testing.AllocsPerRun(20, func() {
		if err := small.CommitCLLDelta(1, nil, cll.State{Size: 1, IndexedSeq: 1}); err != nil {
			panic(err)
		}
	})
	largeAllocs := testing.AllocsPerRun(20, func() {
		if err := large.CommitCLLDelta(8191, nil, cll.State{Size: 8191, IndexedSeq: 4096}); err != nil {
			panic(err)
		}
	})
	require.LessOrEqual(t, largeAllocs, smallAllocs+1)
}

func engineWithState(t *testing.T, size, indexed uint64) *Engine {
	t.Helper()
	node := bytes.Repeat([]byte{1}, cll.EntryBytes)
	nodes := make([][]byte, size)
	for index := range nodes {
		nodes[index] = node
	}
	engine := New()
	require.NoError(t, engine.CommitCLL(0, nil, cll.State{Size: size, Nodes: nodes, IndexedSeq: indexed}))
	return engine
}
