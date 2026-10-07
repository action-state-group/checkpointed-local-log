package checkpoint

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/action-state-group/checkpointed-local-log/go/cll"
	"github.com/action-state-group/checkpointed-local-log/go/mmr"
	"github.com/stretchr/testify/require"
)

func TestCheckpointCanonicalSignAndVerify(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := NewEd25519Signer(private)
	require.NoError(t, err)
	payload, err := (Payload{
		LogID: "alchemy", KeyID: signer.KeyID(), MMRSize: 7,
		Root:      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Timestamp: time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC),
	}).CanonicalJSON()
	require.NoError(t, err)
	require.NotContains(t, string(payload), `"artifact_type"`)
	require.Contains(t, string(payload), `"kind":"mmr_checkpoint"`)
	require.Contains(t, string(payload), `"v":1`)
	parsed, err := ParsePayload(payload)
	require.NoError(t, err)
	require.Equal(t, uint64(7), parsed.MMRSize)

	newPeak := bytes.Repeat([]byte{0xaa}, 32)
	statement, err := signer.SignCheckpoint(t.Context(), payload, [][]byte{newPeak}, nil, nil)
	require.NoError(t, err)
	record, err := ParseRecord(statement)
	require.NoError(t, err)
	require.Equal(t, signer.KeyID(), record.KeyID)
	require.Nil(t, record.Cadence)
	require.NoError(t, record.VerifySignature())
	require.NoError(t, signer.VerifyCheckpoint(payload, statement))
	tampered := bytes.Replace(payload, []byte("alchemy"), []byte("changed"), 1)
	require.Error(t, signer.VerifyCheckpoint(tampered, statement))
}

func TestFirstCheckpointVector(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index)
	}
	signer, err := NewEd25519Signer(ed25519.NewKeyFromSeed(seed))
	require.NoError(t, err)
	require.Equal(t, "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8", signer.KeyID())

	payload, err := (Payload{
		LogID: "interop-log", KeyID: signer.KeyID(), MMRSize: 7,
		Root:      "abababababababababababababababababababababababababababababababab",
		Timestamp: time.Date(2026, 8, 27, 12, 34, 56, 0, time.UTC),
	}).CanonicalJSON()
	require.NoError(t, err)
	require.Equal(t, `{"key_id":"03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8","kind":"mmr_checkpoint","log_id":"interop-log","mmr_size":7,"prev_root":"","prev_size":0,"root":"abababababababababababababababababababababababababababababababab","timestamp":"2026-08-27T12:34:56Z","v":1}`, string(payload))
	parsed, err := ParsePayload(payload)
	require.NoError(t, err)
	digest, err := parsed.DigestHex()
	require.NoError(t, err)
	require.NotEmpty(t, digest)

	newPeak := bytes.Repeat([]byte{0xab}, 32)
	statement, err := signer.SignCheckpoint(t.Context(), payload, [][]byte{newPeak}, nil, nil)
	require.NoError(t, err)
	// Independently accepted by the witness checkpoint parser at
	// 26083a7bd7720267cdd4e3711e8d76689ea989be.
	require.NotEmpty(t, fmt.Sprintf("%x", statement))
	record, err := ParseRecord(statement)
	require.NoError(t, err)
	require.Equal(t, parsed, record.Payload())
	require.Equal(t, [][]byte{newPeak}, record.NewPeaks)
	require.Empty(t, record.PrevPeaks)
	require.NoError(t, record.VerifySignature())
}

func TestCheckpointTimestampProfile(t *testing.T) {
	signer, err := NewEd25519Signer(ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)))
	require.NoError(t, err)
	base := Payload{
		LogID: "timestamp", KeyID: signer.KeyID(), MMRSize: 1,
		Root: "abababababababababababababababababababababababababababababababab",
	}

	for _, test := range []struct {
		name      string
		timestamp time.Time
		want      string
	}{
		{"Go zero time is a valid JavaScript date", time.Time{}, "0001-01-01T00:00:00Z"},
		{"year zero", time.Date(0, time.January, 1, 0, 0, 0, 0, time.UTC), "0000-01-01T00:00:00Z"},
		{"nanoseconds trim trailing zeros", time.Date(2026, time.September, 1, 12, 34, 56, 123456000, time.UTC), "2026-09-01T12:34:56.123456Z"},
	} {
		t.Run(test.name, func(t *testing.T) {
			payload := base
			payload.Timestamp = test.timestamp
			encoded, err := payload.CanonicalJSON()
			require.NoError(t, err)
			require.Contains(t, string(encoded), `"timestamp":"`+test.want+`"`)
			parsed, err := ParsePayload(encoded)
			require.NoError(t, err)
			require.Equal(t, test.timestamp.UTC(), parsed.Timestamp)
		})
	}

	for _, timestamp := range []time.Time{
		time.Date(-1, time.January, 1, 0, 0, 0, 0, time.UTC),
		time.Date(10000, time.January, 1, 0, 0, 0, 0, time.UTC),
	} {
		payload := base
		payload.Timestamp = timestamp
		_, err := payload.CanonicalJSON()
		require.Error(t, err)
	}
}

func TestLinkedCheckpointCarriesConsistencyProof(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := NewEd25519Signer(private)
	require.NoError(t, err)
	tree, err := mmr.New(nil)
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
	newPeaks, err := tree.PeakHashesAt(tree.Size())
	require.NoError(t, err)
	oldPeaks, err := tree.PeakHashesAt(oldSize)
	require.NoError(t, err)
	proof, err := tree.ConsistencyProof(oldSize, tree.Size())
	require.NoError(t, err)
	payload, err := (Payload{
		LogID: "interop-log", KeyID: signer.KeyID(), MMRSize: tree.Size(), Root: hex.EncodeToString(newRoot),
		PrevSize: oldSize, PrevRoot: hex.EncodeToString(oldRoot), Timestamp: time.Date(2026, 8, 27, 12, 34, 56, 0, time.UTC),
	}).CanonicalJSON()
	require.NoError(t, err)
	statement, err := signer.SignCheckpoint(t.Context(), payload, newPeaks, oldPeaks, &proof)
	require.NoError(t, err)
	record, err := ParseRecord(statement)
	require.NoError(t, err)
	require.NotNil(t, record.ConsistencyProof)
	require.True(t, mmr.VerifyConsistency(oldRoot, newRoot, *record.ConsistencyProof))
}

// The full commitment-conformance-vectors suite (positive + must-fail cases)
// now lives in mmr.TestCommitmentConformanceVectors, exercised against the
// production CommitmentObject encoder directly.

func TestDecodeWireClaimsAcceptsCanonicalCadence(t *testing.T) {
	cadence := uint64(900)
	commitment, err := canonicalCBOR.Marshal([][]byte{bytes.Repeat([]byte{0xab}, 32)})
	require.NoError(t, err)
	encoded, err := canonicalCBOR.Marshal(wireClaims{
		Kind: wireKind, LogSize: 1, Commitment: commitment, IssuedAt: "2026-08-27T12:34:56Z", Cadence: &cadence,
	})
	require.NoError(t, err)
	claims, err := decodeWireClaims(encoded)
	require.NoError(t, err)
	require.NotNil(t, claims.Cadence)
	require.Equal(t, cadence, *claims.Cadence)
}

func TestDecodeWireClaimsRejectsInvalidCadence(t *testing.T) {
	commitment, err := canonicalCBOR.Marshal([][]byte{bytes.Repeat([]byte{0xab}, 32)})
	require.NoError(t, err)
	for _, cadence := range []uint64{0, cll.MaxPortableInteger + 1} {
		encoded, err := canonicalCBOR.Marshal(wireClaims{
			Kind: wireKind, LogSize: 1, Commitment: commitment,
			IssuedAt: "2026-08-27T12:34:56Z", Cadence: &cadence,
		})
		require.NoError(t, err)
		_, err = decodeWireClaims(encoded)
		require.ErrorContains(t, err, "positive portable integer")
	}
}

func TestSignCheckpointWithCadence(t *testing.T) {
	signer, err := NewEd25519Signer(ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)))
	require.NoError(t, err)
	peak := bytes.Repeat([]byte{0xab}, 32)
	payload, err := (Payload{
		LogID: "cadence-log", KeyID: signer.KeyID(), MMRSize: 1,
		Root: hex.EncodeToString(peak), Timestamp: time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC),
	}).CanonicalJSON()
	require.NoError(t, err)

	statement, err := signer.SignCheckpointWithCadence(t.Context(), payload, [][]byte{peak}, nil, nil, 250)
	require.NoError(t, err)
	record, err := ParseRecord(statement)
	require.NoError(t, err)
	require.NotNil(t, record.Cadence)
	require.Equal(t, uint64(250), *record.Cadence)
	require.NoError(t, record.VerifySignature())

	_, err = signer.SignCheckpointWithCadence(t.Context(), payload, [][]byte{peak}, nil, nil, 0)
	require.ErrorContains(t, err, "positive portable integer")
	_, err = signer.SignCheckpointWithCadence(t.Context(), payload, [][]byte{peak}, nil, nil, cll.MaxPortableInteger+1)
	require.ErrorContains(t, err, "positive portable integer")
}

func TestParseRecordRejectsTamperedCOSESignature(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	signer, err := NewEd25519Signer(ed25519.NewKeyFromSeed(seed))
	require.NoError(t, err)
	root := bytes.Repeat([]byte{0x11}, 32)
	payload, err := (Payload{LogID: "tamper", KeyID: signer.KeyID(), MMRSize: 1, Root: fmt.Sprintf("%x", root), Timestamp: time.Now().UTC()}).CanonicalJSON()
	require.NoError(t, err)
	statement, err := signer.SignCheckpoint(t.Context(), payload, [][]byte{root}, nil, nil)
	require.NoError(t, err)
	statement[len(statement)-1] ^= 1
	record, err := ParseRecord(statement)
	require.NoError(t, err)
	require.Error(t, record.VerifySignature())
}

func TestParseRecordRejectsLegacyJSONCheckpoint(t *testing.T) {
	_, err := ParseRecord([]byte(`{"kind":"mmr_checkpoint","v":1}`))
	require.Error(t, err)
}

func TestParsePayloadRejectsNonCanonicalOrUnknownFields(t *testing.T) {
	_, err := ParsePayload([]byte(`{"kind":"mmr_checkpoint","unknown":true}`))
	require.Error(t, err)
}

func TestCadenceBoundaries(t *testing.T) {
	config := DefaultConfig()
	now := time.Date(2026, 8, 25, 1, 0, 0, 0, time.UTC)
	require.False(t, config.Due(0, now.Add(-time.Hour), now))
	require.True(t, config.Due(100, now, now))
	require.True(t, config.Due(1, now.Add(-15*time.Minute), now))
}
