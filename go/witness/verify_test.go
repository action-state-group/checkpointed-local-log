package witness

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/action-state-group/checkpointed-local-log/go/checkpoint"
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

// Under the identity as the pinned authority key, [k]A is the identity for
// every challenge k, so R = aB and S = a verify with no private key.
// crypto/ed25519 accepts such a signature; the receipt verifier must not.
func TestReceiptVerifierRefusesForgeryForSmallOrderPinnedKey(t *testing.T) {
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

	// R = aB is the public key for seed; S = a mod L.
	seed := bytes.Repeat([]byte{0x07}, ed25519.SeedSize)
	r := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	digest := sha512.Sum512(seed)
	digest[0] &= 248
	digest[31] &= 127
	digest[31] |= 64
	scalar := new(big.Int).SetBytes(reverse(digest[:32]))
	order, _ := new(big.Int).SetString("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed", 16)
	s := reverse(scalar.Mod(scalar, order).FillBytes(make([]byte, 32)))

	identity := make(ed25519.PublicKey, ed25519.PublicKeySize)
	identity[0] = 1
	_, anyPrivate, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	var message cose.Sign1Message
	require.NoError(t, message.UnmarshalCBOR(signedReceipt(t, entry, anyPrivate)))
	message.Signature = append(append([]byte(nil), r...), s...)
	forged, err := message.MarshalCBOR()
	require.NoError(t, err)

	verifier, err := NewReceiptVerifier(identity)
	require.NoError(t, err)
	receipt := Receipt{Bytes: forged, EntryHash: hex.EncodeToString(entry), EntryHashScheme: EntryHashSchemeCheckpointDigest, LeafIndex: 0, TreeSize: 1}
	require.Error(t, verifier.Verify(statement, receipt))

	// The forgery is real: crypto/ed25519 accepts it over the receipt's
	// signed bytes.
	leaf := sha256.Sum256(append([]byte{0}, entry...))
	message.Payload = leaf[:]
	toBeSigned, err := sigStructure(message)
	require.NoError(t, err)
	require.True(t, ed25519.Verify(identity, toBeSigned, message.Signature))
}

func reverse(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[len(b)-1-i] = b[i]
	}
	return out
}

func sigStructure(message cose.Sign1Message) ([]byte, error) {
	protected, err := message.Headers.MarshalProtected()
	if err != nil {
		return nil, err
	}
	return cbor.Marshal([]any{"Signature1", cbor.RawMessage(protected), []byte{}, message.Payload})
}
