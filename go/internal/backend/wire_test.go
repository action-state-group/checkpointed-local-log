package backend

import (
	"bytes"
	"testing"
	"time"

	"github.com/action-state-group/cll-go/cll"
	"github.com/stretchr/testify/require"
)

func TestRelationalEncodersOmitRowsAndRoundTripWitness(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	witness := cll.WitnessState{
		WitnessID:      "witness.example",
		CheckpointSize: 1,
		Checkpoint:     []byte("checkpoint"),
		NextAttemptAt:  now,
	}
	metadata, err := MarshalMetadata(cll.State{
		Nodes:     [][]byte{bytes.Repeat([]byte{1}, cll.EntryBytes)},
		Witnesses: []cll.WitnessState{witness},
	})
	require.NoError(t, err)
	require.Contains(t, string(metadata), `"nodes":[]`)
	require.Contains(t, string(metadata), `"witnesses":[]`)

	encoded, err := MarshalWitness(witness)
	require.NoError(t, err)
	decoded, err := UnmarshalWitness(encoded)
	require.NoError(t, err)
	require.Equal(t, witness, decoded)
}
