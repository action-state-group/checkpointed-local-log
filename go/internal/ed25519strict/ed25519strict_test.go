package ed25519strict_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"testing"

	"github.com/action-state-group/checkpointed-local-log/go/checkpoint"
	"github.com/action-state-group/checkpointed-local-log/go/internal/ed25519strict"
	"github.com/stretchr/testify/require"
)

// testdata/ed25519-vectors.json is a pinned copy of
// checkpoint-conformance-vectors/ed25519-vectors.json at the repository root.
type vectors struct {
	Ed25519Cases []struct {
		Name         string `json:"name"`
		PublicKeyHex string `json:"public_key_hex"`
		MessageHex   string `json:"message_hex"`
		SignatureHex string `json:"signature_hex"`
		Valid        bool   `json:"valid"`
	} `json:"ed25519_cases"`
	CoseCases []struct {
		Name    string `json:"name"`
		CoseHex string `json:"cose_hex"`
		Valid   bool   `json:"valid"`
	} `json:"cose_cases"`
}

func load(t *testing.T) vectors {
	t.Helper()
	data, err := os.ReadFile("testdata/ed25519-vectors.json")
	require.NoError(t, err)
	var v vectors
	require.NoError(t, json.Unmarshal(data, &v))
	require.NotEmpty(t, v.Ed25519Cases)
	require.NotEmpty(t, v.CoseCases)
	return v
}

func decode(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	require.NoError(t, err)
	return decoded
}

func TestPinnedCopyMatchesRepositoryVectors(t *testing.T) {
	root, err := os.ReadFile("../../../checkpoint-conformance-vectors/ed25519-vectors.json")
	if errors.Is(err, fs.ErrNotExist) {
		t.Skip("not in a repository checkout")
	}
	require.NoError(t, err)
	pinned, err := os.ReadFile("testdata/ed25519-vectors.json")
	require.NoError(t, err)
	require.True(t, bytes.Equal(root, pinned), "copy checkpoint-conformance-vectors/ed25519-vectors.json to testdata")
}

func TestVerifyDecidesEveryRawCase(t *testing.T) {
	for _, c := range load(t).Ed25519Cases {
		got := ed25519strict.Verify(decode(t, c.PublicKeyHex), decode(t, c.MessageHex), decode(t, c.SignatureHex))
		require.Equal(t, c.Valid, got, c.Name)
	}
}

func TestCheckpointVerifierDecidesEveryStatement(t *testing.T) {
	for _, c := range load(t).CoseCases {
		record, err := checkpoint.ParseRecord(decode(t, c.CoseHex))
		require.NoError(t, err, c.Name)
		require.Equal(t, c.Valid, record.VerifySignature() == nil, c.Name)
	}
}

func TestVerifyRefusesWrongLengths(t *testing.T) {
	c := load(t).Ed25519Cases[0]
	require.Equal(t, "honest", c.Name)
	public, message, signature := decode(t, c.PublicKeyHex), decode(t, c.MessageHex), decode(t, c.SignatureHex)
	require.True(t, ed25519strict.Verify(public, message, signature))
	require.False(t, ed25519strict.Verify(public[1:], message, signature))
	require.False(t, ed25519strict.Verify(public, message, signature[1:]))
	require.Error(t, ed25519strict.NewVerifier(public[1:]).Verify(message, signature))
	require.NoError(t, ed25519strict.NewVerifier(public).Verify(message, signature))
}
