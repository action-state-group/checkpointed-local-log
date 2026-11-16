package checkpoint

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/action-state-group/checkpointed-local-log/go/mmr"
	"github.com/stretchr/testify/require"
	"github.com/veraison/go-cose"
)

// subjectOf returns the CWT sub of a checkpoint statement.
func subjectOf(t *testing.T, statement []byte) string {
	t.Helper()
	var message cose.Sign1Message
	require.NoError(t, message.UnmarshalCBOR(statement))
	claims, err := protectedCWTClaims(message.Headers.Protected[cose.HeaderLabelCWTClaims])
	require.NoError(t, err)
	subject, ok := claims[cose.CWTClaimSubject].(string)
	require.True(t, ok)
	return subject
}

// resign re-signs statement with its CWT sub replaced.
func resign(t *testing.T, private ed25519.PrivateKey, statement []byte, subject string) []byte {
	t.Helper()
	var message cose.Sign1Message
	require.NoError(t, message.UnmarshalCBOR(statement))
	claims, err := protectedCWTClaims(message.Headers.Protected[cose.HeaderLabelCWTClaims])
	require.NoError(t, err)
	_, err = message.Headers.Protected.SetCWTClaims(cose.CWTClaims{
		cose.CWTClaimIssuer: claims[cose.CWTClaimIssuer], cose.CWTClaimSubject: subject,
	})
	require.NoError(t, err)
	signer, err := cose.NewSigner(cose.AlgorithmEdDSA, private)
	require.NoError(t, err)
	message.Signature = nil
	message.Headers.RawProtected = nil
	require.NoError(t, message.Sign(rand.Reader, nil, signer))
	out, err := message.MarshalCBOR()
	require.NoError(t, err)
	return out
}

// CLL -02 (Checkpoint Registration): sub is one value per log and MUST NOT vary per checkpoint.
func TestCheckpointSubjectIsConstantPerLog(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := NewEd25519Signer(private)
	require.NoError(t, err)
	peak := make([]byte, 32)
	peak[0] = 1
	statement := func(size uint64) []byte {
		payload, err := (Payload{
			LogID: "test-log", KeyID: signer.KeyID(), MMRSize: size,
			Root:      hex.EncodeToString(mmr.RootFromPeaks([][]byte{peak})),
			Timestamp: time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC),
		}).CanonicalJSON()
		require.NoError(t, err)
		out, err := signer.SignCheckpoint(t.Context(), payload, [][]byte{peak}, nil, nil)
		require.NoError(t, err)
		return out
	}
	first, second := statement(1), statement(3)
	require.Equal(t, "test-log", subjectOf(t, first))
	require.Equal(t, subjectOf(t, first), subjectOf(t, second))
	_, err = ParseRecord(first)
	require.NoError(t, err)

	// The pre-02 per-checkpoint form still parses, so stored checkpoints keep verifying.
	legacy := resign(t, private, second, fmt.Sprintf("test-log#%d", 3))
	_, err = ParseRecord(legacy)
	require.NoError(t, err)

	// Any other sub is refused, including another checkpoint's size.
	for _, bad := range []string{"other-log", "test-log#1", "test-log#", ""} {
		_, err = ParseRecord(resign(t, private, second, bad))
		require.Error(t, err, bad)
	}
}
