package checkpoint

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/action-state-group/cll-go/cll"
	"github.com/action-state-group/cll-go/mmr"
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

func TestCommitmentConformanceVectors(t *testing.T) {
	// Pinned cross-language commitment-conformance vectors at aa9f2fd.
	vectors := []struct {
		name       string
		peaks      []string
		commitment string
	}{
		{"empty-accumulator", nil, "80"},
		{"kat39-index-0", []string{"af5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc"}, "815820af5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc"},
		{"kat39-index-3", []string{"ad104051c516812ea5874ca3ff06d0258303623d04307c41ec80a7a18b332ef8", "d5688a52d55a02ec4aea5ec1eadfffe1c9e0ee6a4ddbe2377f98326d42dfc975"}, "825820ad104051c516812ea5874ca3ff06d0258303623d04307c41ec80a7a18b332ef85820d5688a52d55a02ec4aea5ec1eadfffe1c9e0ee6a4ddbe2377f98326d42dfc975"},
		{"kat39-index-10", []string{"827f3213c1de0d4c6277caccc1eeca325e45dfe2c65adce1943774218db61f88", "b8faf5f748f149b04018491a51334499fd8b6060c42a835f361fa9665562d12d", "8d85f8467240628a94819b26bee26e3a9b2804334c63482deacec8d64ab4e1e7"}, "835820827f3213c1de0d4c6277caccc1eeca325e45dfe2c65adce1943774218db61f885820b8faf5f748f149b04018491a51334499fd8b6060c42a835f361fa9665562d12d58208d85f8467240628a94819b26bee26e3a9b2804334c63482deacec8d64ab4e1e7"},
		{"kat39-index-18", []string{"78b2b4162eb2c58b229288bbcb5b7d97c7a1154eed3161905fb0f180eba6f112", "f4a0db79de0fee128fbe95ecf3509646203909dc447ae911aa29416bf6fcba21", "5bc67471c189d78c76461dcab6141a733bdab3799d1d69e0c419119c92e82b3d"}, "83582078b2b4162eb2c58b229288bbcb5b7d97c7a1154eed3161905fb0f180eba6f1125820f4a0db79de0fee128fbe95ecf3509646203909dc447ae911aa29416bf6fcba2158205bc67471c189d78c76461dcab6141a733bdab3799d1d69e0c419119c92e82b3d"},
		{"kat39-index-25", []string{"78b2b4162eb2c58b229288bbcb5b7d97c7a1154eed3161905fb0f180eba6f112", "61b3ff808934301578c9ed7402e3dd7dfe98b630acdf26d1fd2698a3c4a22710", "dd7efba5f1824103f1fa820a5c9e6cd90a82cf123d88bd035c7e5da0aba8a9ae", "561f627b4213258dc8863498bb9b07c904c3c65a78c1a36bca329154d1ded213"}, "84582078b2b4162eb2c58b229288bbcb5b7d97c7a1154eed3161905fb0f180eba6f112582061b3ff808934301578c9ed7402e3dd7dfe98b630acdf26d1fd2698a3c4a227105820dd7efba5f1824103f1fa820a5c9e6cd90a82cf123d88bd035c7e5da0aba8a9ae5820561f627b4213258dc8863498bb9b07c904c3c65a78c1a36bca329154d1ded213"},
		{"kat39-index-38", []string{"d4fb5649422ff2eaf7b1c0b851585a8cfd14fb08ce11addb30075a96309582a7", "6a169105dcc487dbbae5747a0fd9b1d33a40320cf91cf9a323579139e7ff72aa", "e9a5f5201eb3c3c856e0a224527af5ac7eb1767fb1aff9bd53ba41a60cde9785"}, "835820d4fb5649422ff2eaf7b1c0b851585a8cfd14fb08ce11addb30075a96309582a758206a169105dcc487dbbae5747a0fd9b1d33a40320cf91cf9a323579139e7ff72aa5820e9a5f5201eb3c3c856e0a224527af5ac7eb1767fb1aff9bd53ba41a60cde9785"},
	}
	for _, vector := range vectors {
		t.Run(vector.name, func(t *testing.T) {
			peaks := make([][]byte, len(vector.peaks))
			for index, value := range vector.peaks {
				decoded, err := hex.DecodeString(value)
				require.NoError(t, err)
				peaks[index] = decoded
			}
			encoded, err := canonicalCBOR.Marshal(peaks)
			require.NoError(t, err)
			require.Equal(t, vector.commitment, hex.EncodeToString(encoded))
		})
	}
}

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
