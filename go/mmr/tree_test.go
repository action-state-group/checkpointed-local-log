package mmr

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBaggedInclusionRoundTrip(t *testing.T) {
	tree, err := New(nil)
	require.NoError(t, err)
	ids := []string{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"1111111111111111111111111111111111111111111111111111111111111111",
		"2222222222222222222222222222222222222222222222222222222222222222",
		"3333333333333333333333333333333333333333333333333333333333333333",
		"4444444444444444444444444444444444444444444444444444444444444444",
	}
	for _, id := range ids {
		_, err := tree.AppendHexIdentity(id)
		require.NoError(t, err)
	}
	root, err := tree.Root()
	require.NoError(t, err)
	for index, id := range ids {
		proof, err := tree.InclusionProof(uint64(index), tree.Size())
		require.NoError(t, err)
		require.True(t, VerifyHexInclusion(root, tree.Size(), uint64(index), id, proof))
		proof.V = 2
		require.False(t, VerifyHexInclusion(root, tree.Size(), uint64(index), id, proof))
	}
}

func TestBaggedConsistencyProofAcrossMultiPeakTrees(t *testing.T) {
	tree, err := New(nil)
	require.NoError(t, err)
	for index := 1; index <= 3; index++ {
		_, err = tree.AppendHexIdentity(fmt.Sprintf("%064x", index))
		require.NoError(t, err)
	}
	oldSize := tree.Size()
	oldRoot, err := tree.Root()
	require.NoError(t, err)
	for index := 4; index <= 7; index++ {
		_, err = tree.AppendHexIdentity(fmt.Sprintf("%064x", index))
		require.NoError(t, err)
	}
	newRoot, err := tree.Root()
	require.NoError(t, err)
	proof, err := tree.ConsistencyProof(oldSize, tree.Size())
	require.NoError(t, err)
	require.True(t, VerifyConsistency(oldRoot, newRoot, proof))
	if len(proof.Witness) > 0 && len(proof.Witness[0]) > 0 {
		proof.Witness[0][0][0] ^= 1
		require.False(t, VerifyConsistency(oldRoot, newRoot, proof))
	}
}

func TestPeakHashesAtReturnsHistoricalCommitment(t *testing.T) {
	tree, err := New(nil)
	require.NoError(t, err)
	for index := 1; index <= 5; index++ {
		_, err = tree.AppendHexIdentity(fmt.Sprintf("%064x", index))
		require.NoError(t, err)
	}

	historicalSize := uint64(4)
	peaks, err := tree.PeakHashesAt(historicalSize)
	require.NoError(t, err)
	require.NotEmpty(t, peaks)

	historical, err := New(tree.Nodes()[:historicalSize])
	require.NoError(t, err)
	expected, err := historical.Root()
	require.NoError(t, err)
	require.Equal(t, expected, RootFromPeaks(peaks))

	_, err = tree.PeakHashesAt(2)
	require.Error(t, err)
	_, err = tree.PeakHashesAt(tree.Size() + 1)
	require.Error(t, err)
}

func TestAppendApplicationNeutralValue(t *testing.T) {
	tree, err := New(nil)
	require.NoError(t, err)

	value := []byte("0123456789abcdef0123456789abcdef")
	position, err := tree.Append(value)
	require.NoError(t, err)
	require.Equal(t, uint64(1), position)
	require.Equal(t, uint64(1), tree.Size())

	proof, err := tree.InclusionProof(0, tree.Size())
	require.NoError(t, err)
	root, err := tree.Root()
	require.NoError(t, err)
	require.True(t, VerifyInclusion(root, tree.Size(), 0, value, proof))
	require.False(t, VerifyInclusion(root, tree.Size(), 0, []byte("short"), proof))

	_, err = tree.Append(nil)
	require.EqualError(t, err, "CLL leaf value must be exactly 32 bytes")
}

func TestCommitmentObject(t *testing.T) {
	empty, err := CommitmentObject(nil)
	require.NoError(t, err)
	require.Equal(t, []byte{0x80}, empty)

	peaks := [][]byte{bytes.Repeat([]byte{0xab}, 32)}
	encoded, err := CommitmentObject(peaks)
	require.NoError(t, err)
	require.Equal(t, append([]byte{0x81, 0x58, 0x20}, peaks[0]...), encoded)

	_, err = CommitmentObject([][]byte{{1}})
	require.Error(t, err)
}

func TestEmptyRootAndAdversarialInputs(t *testing.T) {
	tree, err := New(nil)
	require.NoError(t, err)
	root, err := tree.Root()
	require.NoError(t, err)
	require.Equal(t, make([]byte, 32), root)
	require.False(t, VerifyHexInclusion(root, 0, 0, "bad", InclusionProof{}))
	_, err = New([][]byte{{1}})
	require.Error(t, err)
	_, err = New([][]byte{make([]byte, 32), make([]byte, 32)})
	require.Error(t, err)
	corrupt := [][]byte{make([]byte, 32), make([]byte, 32), make([]byte, 32)}
	_, err = New(corrupt)
	require.Error(t, err)
	require.False(t, VerifyHexInclusion(make([]byte, 32), 2, 0, fmt.Sprintf("%064x", 1), InclusionProof{}))
}
