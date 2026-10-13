package checkpoint

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/action-state-group/checkpointed-local-log/go/mmr"
	"github.com/stretchr/testify/require"
)

// The -02 wire form (cll-02-vectors/) is ahead of this package, which still
// emits the -01 form. These tests pin that gap: each one fails the day the
// package emits the -02 bytes, and must then become a plain equality test.
type cll02Wire struct {
	Entries     []string `json:"entries"`
	Conventions struct {
		LogIdentity struct {
			Sub string `json:"sub"`
		} `json:"log_identity"`
	} `json:"conventions"`
	Checkpoints []struct {
		ID     string `json:"id"`
		Claims struct {
			LogSize  uint64 `json:"log_size"`
			PrevSize uint64 `json:"prev_size"`
			IssuedAt string `json:"issued_at"`
			Cadence  uint64 `json:"cadence"`
		} `json:"claims"`
		ClaimsHex string `json:"claims_hex"`
	} `json:"checkpoints"`
}

func TestCLL02WireClaimsStillDiffer(t *testing.T) {
	contents, err := os.ReadFile("../mmr/testdata/cll02_vectors.json")
	require.NoError(t, err)
	var v cll02Wire
	require.NoError(t, json.Unmarshal(contents, &v))
	tree, err := mmr.New(nil)
	require.NoError(t, err)
	for _, entry := range v.Entries {
		_, err := tree.AppendHexIdentity(entry)
		require.NoError(t, err)
	}
	for _, cp := range v.Checkpoints {
		c := cp.Claims
		peaks, err := tree.PeakHashesAt(c.LogSize)
		require.NoError(t, err)
		prevPeaks, err := tree.PeakHashesAt(c.PrevSize)
		require.NoError(t, err)
		issued, err := time.Parse(time.RFC3339, c.IssuedAt)
		require.NoError(t, err)
		payload := Payload{
			LogID: v.Conventions.LogIdentity.Sub, MMRSize: c.LogSize,
			Root: hex.EncodeToString(mmr.RootFromPeaks(peaks)), PrevSize: c.PrevSize,
			Timestamp: issued,
		}
		if c.PrevSize > 0 {
			payload.PrevRoot = hex.EncodeToString(mmr.RootFromPeaks(prevPeaks))
		}
		var proof *mmr.ConsistencyProof
		if c.PrevSize > 0 {
			p, err := tree.ConsistencyProof(c.PrevSize, c.LogSize)
			require.NoError(t, err)
			proof = &p
		}
		cadence := c.Cadence
		got, err := encodeWireClaims(payload, peaks, prevPeaks, proof, &cadence)
		require.NoError(t, err, cp.ID)
		require.NotEqual(t, cp.ClaimsHex, hex.EncodeToString(got),
			"%s: the package now emits -02 claims; make this an equality test", cp.ID)
	}
}
