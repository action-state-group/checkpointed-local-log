package mmr

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// vectors.json is a pinned copy of
// /Users/ezhang/GitHub/checkpointed-local-log/mmr-conformance-vectors/vectors.json.
// Do not read across repositories at test time.
type conformanceVectors struct {
	Cases []conformanceCase `json:"cases"`
}

type conformanceCase struct {
	Name          string          `json:"name"`
	Kind          string          `json:"kind"`
	Size          uint64          `json:"size"`
	LeafIndex     uint64          `json:"leaf_index"`
	BodyDigestHex string          `json:"body_digest_hex"`
	RootHex       string          `json:"root_hex"`
	SizeA         uint64          `json:"size_a"`
	SizeB         uint64          `json:"size_b"`
	RootAHex      string          `json:"root_a_hex"`
	RootBHex      string          `json:"root_b_hex"`
	Proof         json.RawMessage `json:"proof"`
}

type inclusionVectorProof struct {
	V          uint64   `json:"v"`
	Kind       string   `json:"kind"`
	Size       uint64   `json:"size"`
	LeafIndex  uint64   `json:"leaf_index"`
	Witness    []string `json:"witness"`
	PeaksLeft  []string `json:"peaks_left"`
	PeaksRight []string `json:"peaks_right"`
}

type consistencyVectorProof struct {
	V        uint64     `json:"v"`
	Kind     string     `json:"kind"`
	SizeA    uint64     `json:"size_a"`
	SizeB    uint64     `json:"size_b"`
	OldPeaks []string   `json:"old_peaks"`
	Witness  [][]string `json:"witness"`
	NewPeaks []string   `json:"new_peaks"`
}

func TestPythonMMRConformanceVectors(t *testing.T) {
	contents, err := os.ReadFile("testdata/vectors.json")
	require.NoError(t, err)
	var vectors conformanceVectors
	require.NoError(t, json.Unmarshal(contents, &vectors))
	require.Len(t, vectors.Cases, 19)

	tree, err := New(nil)
	require.NoError(t, err)
	for sequence := 1; sequence <= 7; sequence++ {
		body := sha256.Sum256([]byte(fmt.Sprintf("asg-ledger-mmr-vector-leaf-%d", sequence)))
		_, err := tree.Append(body[:])
		require.NoError(t, err)
	}

	firstLeafCovered := false
	for _, vector := range vectors.Cases {
		t.Run(vector.Name, func(t *testing.T) {
			switch vector.Kind {
			case "root":
				peaks, err := tree.PeakHashesAt(vector.Size)
				require.NoError(t, err)
				require.Equal(t, mustHex(t, vector.RootHex), RootFromPeaks(peaks))
			case "inclusion":
				var expected inclusionVectorProof
				require.NoError(t, json.Unmarshal(vector.Proof, &expected))
				proof, err := tree.InclusionProof(vector.LeafIndex, vector.Size)
				require.NoError(t, err)
				require.Equal(t, inclusionProofFromVector(t, expected), proof)
				require.True(t, VerifyInclusion(mustHex(t, vector.RootHex), vector.Size, vector.LeafIndex, mustHex(t, vector.BodyDigestHex), proof))
				if vector.LeafIndex == 0 {
					firstLeafCovered = true
				}
			case "consistency":
				var expected consistencyVectorProof
				require.NoError(t, json.Unmarshal(vector.Proof, &expected))
				proof, err := tree.ConsistencyProof(vector.SizeA, vector.SizeB)
				require.NoError(t, err)
				require.Equal(t, consistencyProofFromVector(t, expected), proof)
				require.True(t, VerifyConsistency(mustHex(t, vector.RootAHex), mustHex(t, vector.RootBHex), proof))
			default:
				t.Fatalf("unknown vector kind %q", vector.Kind)
			}
		})
	}
	require.True(t, firstLeafCovered, "the zero-based first-leaf vector must be exercised")
}

func inclusionProofFromVector(t *testing.T, proof inclusionVectorProof) InclusionProof {
	t.Helper()
	return InclusionProof{V: proof.V, Kind: proof.Kind, Size: proof.Size, LeafIndex: proof.LeafIndex, Witness: hexes(t, proof.Witness), PeaksLeft: hexes(t, proof.PeaksLeft), PeaksRight: hexes(t, proof.PeaksRight)}
}

func consistencyProofFromVector(t *testing.T, proof consistencyVectorProof) ConsistencyProof {
	t.Helper()
	witness := make([][][]byte, len(proof.Witness))
	for index := range proof.Witness {
		witness[index] = hexes(t, proof.Witness[index])
	}
	return ConsistencyProof{V: proof.V, Kind: proof.Kind, OldSize: proof.SizeA, NewSize: proof.SizeB, OldPeaks: hexes(t, proof.OldPeaks), Witness: witness, NewPeaks: hexes(t, proof.NewPeaks)}
}

func hexes(t *testing.T, values []string) [][]byte {
	t.Helper()
	result := make([][]byte, len(values))
	for index, value := range values {
		result[index] = mustHex(t, value)
	}
	return result
}

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	require.NoError(t, err)
	require.Len(t, decoded, hashSize)
	return decoded
}
