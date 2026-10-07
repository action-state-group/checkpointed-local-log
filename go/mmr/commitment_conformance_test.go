package mmr

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// testdata/commitment_vectors.json is a pinned copy of
// /Users/ezhang/GitHub/checkpointed-local-log/commitment-conformance-vectors/vectors.json.
// Do not read across repositories at test time.
type commitmentVectors struct {
	Count int                `json:"count"`
	Cases []commitmentVector `json:"cases"`
}

type commitmentVector struct {
	Name          string   `json:"name"`
	Kind          string   `json:"kind"`
	PeakHashesHex []string `json:"peak_hashes"`
	CommitmentHex string   `json:"commitment_hex"`
}

// TestCommitmentConformanceVectors exercises the real CommitmentObject
// encoder against every case in commitment-conformance-vectors/vectors.json:
// positive cases must reproduce commitment_hex byte-for-byte; must-fail
// cases list peak hashes whose canonical encoding is deliberately NOT what
// commitment_hex claims (wrong order, dropped/duplicated/flipped peaks, or
// non-canonical CBOR) -- CommitmentObject re-encoding them must NOT match.
func TestCommitmentConformanceVectors(t *testing.T) {
	contents, err := os.ReadFile("testdata/commitment_vectors.json")
	require.NoError(t, err)
	var vectors commitmentVectors
	require.NoError(t, json.Unmarshal(contents, &vectors))
	require.Len(t, vectors.Cases, vectors.Count)

	var positive, mustFail int
	for _, vector := range vectors.Cases {
		t.Run(vector.Name, func(t *testing.T) {
			peaks := make([][]byte, len(vector.PeakHashesHex))
			for index, value := range vector.PeakHashesHex {
				decoded, err := hex.DecodeString(value)
				require.NoError(t, err)
				peaks[index] = decoded
			}
			encoded, err := CommitmentObject(peaks)
			require.NoError(t, err)
			computed := hex.EncodeToString(encoded)
			switch vector.Kind {
			case "positive":
				require.Equal(t, vector.CommitmentHex, computed)
			case "must-fail":
				require.NotEqual(t, vector.CommitmentHex, computed)
			default:
				t.Fatalf("unknown vector kind %q", vector.Kind)
			}
		})
		if vector.Kind == "positive" {
			positive++
		} else {
			mustFail++
		}
	}
	require.Positive(t, positive, "must exercise at least one positive case")
	require.Positive(t, mustFail, "must exercise at least one must-fail case")
}
