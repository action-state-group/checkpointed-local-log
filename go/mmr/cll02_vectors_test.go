package mmr

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// testdata/cll02_vectors.json is a pinned copy of cll-02-vectors/vectors.json
// at the repository root; cll-02-vectors/generate.py --check keeps it identical.
type cll02Vectors struct {
	Entries []string `json:"entries"`
	Nodes   []string `json:"nodes"`
	Sizes   []struct {
		LeafCount  uint64   `json:"leaf_count"`
		LogSize    uint64   `json:"log_size"`
		Peaks      []string `json:"peaks"`
		Commitment string   `json:"commitment"`
	} `json:"sizes"`
	Checkpoints []struct {
		ID               string `json:"id"`
		ConsistencyProof *struct {
			TreeSize1        uint64     `json:"tree_size_1"`
			TreeSize2        uint64     `json:"tree_size_2"`
			ConsistencyPaths [][]string `json:"consistency_paths"`
			RightPeaks       []string   `json:"right_peaks"`
		} `json:"consistency_proof"`
	} `json:"checkpoints"`
}

func loadCLL02(t *testing.T) (cll02Vectors, *Tree, []uint64) {
	t.Helper()
	contents, err := os.ReadFile("testdata/cll02_vectors.json")
	require.NoError(t, err)
	var v cll02Vectors
	require.NoError(t, json.Unmarshal(contents, &v))
	tree, err := New(nil)
	require.NoError(t, err)
	sizes := []uint64{0}
	for _, entry := range v.Entries {
		size, err := tree.AppendHexIdentity(entry)
		require.NoError(t, err)
		sizes = append(sizes, size)
	}
	return v, tree, sizes
}

func hexList(values [][]byte) []string {
	out := make([]string, len(values))
	for i, value := range values {
		out[i] = hex.EncodeToString(value)
	}
	return out
}

// The -02 log layer: node values, log_size as the MMR node count, and the
// accumulator at every size, concatenated tallest first.
func TestCLL02LogMatchesVectors(t *testing.T) {
	v, tree, sizes := loadCLL02(t)
	require.Equal(t, v.Nodes, hexList(tree.Nodes()))
	for i, row := range v.Sizes {
		require.Equal(t, row.LogSize, sizes[i], "log_size after %d leaves", row.LeafCount)
		peaks, err := tree.PeakHashesAt(row.LogSize)
		require.NoError(t, err)
		require.Equal(t, row.Peaks, hexList(peaks))
		require.Equal(t, row.Commitment, hex.EncodeToString(bytes.Join(peaks, nil)))
		if row.LogSize > 0 {
			leaves, ok := LeafCount(row.LogSize)
			require.True(t, ok)
			require.Equal(t, row.LeafCount, leaves)
		}
	}
}

// The implementation's consistency proof carries the profile's proof
// losslessly: its per-old-peak witnesses are the consistency-paths, and the
// right-peaks are the new peaks no path reaches.
func TestCLL02ConsistencyProofMapsOntoProfile(t *testing.T) {
	v, tree, _ := loadCLL02(t)
	checked := 0
	for _, cp := range v.Checkpoints {
		want := cp.ConsistencyProof
		if want == nil {
			continue
		}
		proof, err := tree.ConsistencyProof(want.TreeSize1, want.TreeSize2)
		require.NoError(t, err)
		paths := make([][]string, len(proof.Witness))
		for i, w := range proof.Witness {
			paths[i] = hexList(w)
		}
		require.Equal(t, want.ConsistencyPaths, paths, cp.ID)
		right := proof.NewPeaks[len(proof.NewPeaks)-len(want.RightPeaks):]
		require.Equal(t, want.RightPeaks, hexList(right), cp.ID)
		require.True(t, VerifyConsistency(RootFromPeaks(proof.OldPeaks), RootFromPeaks(proof.NewPeaks), proof), cp.ID)
		checked++
	}
	require.Equal(t, 2, checked)
}
