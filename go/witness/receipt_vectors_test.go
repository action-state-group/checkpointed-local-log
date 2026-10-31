package witness

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// testdata/receipt-vectors.json is a pinned copy of
// checkpoint-conformance-vectors/receipt-vectors.json at the repository root,
// the receipts agent-action-capsule's VerifyReceipts and scitt-cose's
// verify_receipt accept and refuse.
type receiptVectors struct {
	CheckpointCOSE string `json:"checkpoint_cose_b64"`
	EntryHash      string `json:"entry_hash_hex"`
	AuthorityKey   string `json:"authority_public_key_hex"`
	Cases          []struct {
		Name      string `json:"name"`
		Accept    bool   `json:"accept"`
		TreeSize  int64  `json:"tree_size"`
		LeafIndex int64  `json:"leaf_index"`
		Receipt   string `json:"receipt_b64"`
	} `json:"cases"`
}

func TestPinnedReceiptVectorsMatchRepository(t *testing.T) {
	root, err := os.ReadFile("../../checkpoint-conformance-vectors/receipt-vectors.json")
	if errors.Is(err, fs.ErrNotExist) {
		t.Skip("not in a repository checkout")
	}
	require.NoError(t, err)
	pinned, err := os.ReadFile("testdata/receipt-vectors.json")
	require.NoError(t, err)
	require.True(t, bytes.Equal(root, pinned), "copy checkpoint-conformance-vectors/receipt-vectors.json to testdata")
}

func TestReceiptVerifierDecidesEveryReceiptVector(t *testing.T) {
	data, err := os.ReadFile("testdata/receipt-vectors.json")
	require.NoError(t, err)
	var v receiptVectors
	require.NoError(t, json.Unmarshal(data, &v))
	require.NotEmpty(t, v.Cases)
	statement, err := base64.StdEncoding.DecodeString(v.CheckpointCOSE)
	require.NoError(t, err)
	key, err := hex.DecodeString(v.AuthorityKey)
	require.NoError(t, err)
	verifier, err := NewReceiptVerifier(key)
	require.NoError(t, err)
	for _, c := range v.Cases {
		raw, err := base64.StdEncoding.DecodeString(c.Receipt)
		require.NoError(t, err, c.Name)
		receipt := Receipt{Bytes: raw, EntryHash: v.EntryHash, EntryHashScheme: EntryHashSchemeCheckpointDigest, TreeSize: c.TreeSize, LeafIndex: c.LeafIndex}
		err = verifier.Verify(statement, receipt)
		require.Equal(t, c.Accept, err == nil, "%s: %v", c.Name, err)
		if c.Accept {
			// The stored position must be the one the verified proof carries.
			receipt.TreeSize++
			require.Error(t, verifier.Verify(statement, receipt), c.Name)
		}
	}
}

// scrapiReceiptPosition refuses every receipt vector ReceiptVerifier refuses
// for its shape and returns the position of every accepted one. It has no
// witness key, so the vectors refused only for their signature pass it.
func TestSCRAPIReceiptPositionDecidesEveryReceiptVector(t *testing.T) {
	data, err := os.ReadFile("testdata/receipt-vectors.json")
	require.NoError(t, err)
	var v receiptVectors
	require.NoError(t, json.Unmarshal(data, &v))
	signatureOnly := map[string]bool{"neg-wrong-key": true, "neg-other-entry": true}
	for _, c := range v.Cases {
		raw, err := base64.StdEncoding.DecodeString(c.Receipt)
		require.NoError(t, err, c.Name)
		index, size, err := scrapiReceiptPosition(raw)
		if !c.Accept && !signatureOnly[c.Name] {
			require.Error(t, err, c.Name)
			continue
		}
		require.NoError(t, err, c.Name)
		require.Equal(t, c.TreeSize, size, c.Name)
		require.Equal(t, c.LeafIndex, index, c.Name)
	}
}
