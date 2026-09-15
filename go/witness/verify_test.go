package witness

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/action-state-group/cll-go/checkpoint"
	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
	"github.com/veraison/go-cose"
)

func TestReceiptVerifierBindsStatementProofAndPinnedKey(t *testing.T) {
	_, statementPrivate, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	statementSigner, err := checkpoint.NewEd25519Signer(statementPrivate)
	require.NoError(t, err)
	checkpointRoot := bytes.Repeat([]byte{0x01}, 32)
	payload, err := (checkpoint.Payload{
		LogID: "verification-log", KeyID: statementSigner.KeyID(), MMRSize: 1,
		Root: fmt.Sprintf("%x", checkpointRoot), Timestamp: time.Date(2026, 8, 27, 0, 0, 0, 0, time.UTC),
	}).CanonicalJSON()
	require.NoError(t, err)
	statement, err := statementSigner.SignCheckpoint(t.Context(), payload, [][]byte{checkpointRoot}, nil, nil)
	require.NoError(t, err)
	record, err := checkpoint.ParseRecord(statement)
	require.NoError(t, err)
	entry, err := record.EntryHash()
	require.NoError(t, err)

	logPublic, logPrivate, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	receiptBytes := signedReceipt(t, entry, logPrivate)

	verifier, err := NewReceiptVerifier(logPublic)
	require.NoError(t, err)
	receipt := Receipt{Bytes: receiptBytes, EntryHash: hex.EncodeToString(entry), EntryHashScheme: EntryHashSchemeCheckpointDigest, LeafIndex: 0, TreeSize: 1}
	require.NoError(t, verifier.Verify(statement, receipt))
	receipt.EntryHash = hex.EncodeToString(make([]byte, 32))
	require.Error(t, verifier.Verify(statement, receipt))
	receipt.EntryHashScheme = "unknown"
	require.Error(t, verifier.Verify(statement, receipt))

	tampered := append([]byte(nil), statement...)
	tampered[len(tampered)-1] ^= 1
	receipt.EntryHashScheme = EntryHashSchemeCheckpointDigest
	require.Error(t, verifier.Verify(tampered, receipt))
}

func signedReceipt(t *testing.T, entry []byte, private ed25519.PrivateKey) []byte {
	t.Helper()
	proof, err := cbor.Marshal([]any{int64(1), int64(0), [][]byte{}})
	require.NoError(t, err)
	leaf := sha256.Sum256(append([]byte{0}, entry...))
	receiptMessage := cose.NewSign1Message()
	receiptMessage.Headers.Protected.SetAlgorithm(cose.AlgorithmEdDSA)
	receiptMessage.Headers.Protected[headerVDS] = vdsRFC9162
	receiptMessage.Headers.Unprotected[headerVDP] = map[any]any{vdpInclusion: []any{proof}}
	receiptMessage.Payload = leaf[:]
	logSigner, err := cose.NewSigner(cose.AlgorithmEdDSA, private)
	require.NoError(t, err)
	require.NoError(t, receiptMessage.Sign(rand.Reader, nil, logSigner))
	receiptMessage.Payload = nil
	receiptBytes, err := receiptMessage.MarshalCBOR()
	require.NoError(t, err)
	return receiptBytes
}
