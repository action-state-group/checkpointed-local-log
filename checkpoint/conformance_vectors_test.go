package checkpoint

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/action-state-group/cll-go/mmr"
	"github.com/stretchr/testify/require"
)

// testdata/vectors.json is a pinned copy of
// /Users/ezhang/GitHub/checkpointed-local-log/checkpoint-conformance-vectors/vectors.json.
// Do not read across repositories at test time.
//
// This suite pins the Python reference's JSON `CheckpointRecord` model
// (digest_hex/entry_digest_hex/signature over a canonical-JSON signing
// body), which is a DIFFERENT wire representation from this package's own
// COSE_Sign1 checkpoint statement -- cll-go signs a CBOR claims map, not the
// raw digest_hex ASCII bytes the vectors' `signature` field pins. The two
// representations meet at Payload: its canonicalFields() field order and
// DigestHex() are deliberately built to reproduce the vectors' digest_hex
// byte-for-byte (see checkpoint.go), so that is what this test holds this
// package to. The raw Ed25519 signature and the full-record entry_digest_hex
// are cross-language/cross-implementation pins independent of any COSE
// wrapping; this test reproduces them with the standard library directly
// (mirroring the Rust crate's own conformance test) rather than inventing a
// second, unused signing mode in this package. The chained case additionally
// drives this package's real MMR and COSE checkpoint code end-to-end over
// the vectors' plaintext fields, self-verifying the result -- the same
// scope the Rust test's COSE round-trip check covers.
type conformanceDoc struct {
	SigningKeySeedHex string              `json:"signing_key_seed_hex"`
	KeyID             string              `json:"key_id"`
	Count             int                 `json:"count"`
	Cases             []conformanceRecord `json:"cases"`
}

type conformanceRecord struct {
	Version          uint64                  `json:"v"`
	Kind             string                  `json:"kind"`
	LogID            string                  `json:"log_id"`
	MMRSize          uint64                  `json:"mmr_size"`
	Root             string                  `json:"root"`
	PrevSize         uint64                  `json:"prev_size"`
	PrevRoot         string                  `json:"prev_root"`
	KeyID            string                  `json:"key_id"`
	Timestamp        string                  `json:"timestamp"`
	Signature        string                  `json:"signature"`
	DigestHex        string                  `json:"digest_hex"`
	EntryDigestHex   string                  `json:"entry_digest_hex"`
	Name             string                  `json:"name"`
	ConsistencyProof *conformanceConsistency `json:"consistency_proof"`
}

type conformanceConsistency struct {
	Version  uint64     `json:"v"`
	Kind     string     `json:"kind"`
	SizeA    uint64     `json:"size_a"`
	SizeB    uint64     `json:"size_b"`
	OldPeaks []string   `json:"old_peaks"`
	Witness  [][]string `json:"witness"`
	NewPeaks []string   `json:"new_peaks"`
}

// entryDigestFields mirrors the Python/Rust reference's sorted-key canonical
// JSON of the FULL persisted checkpoint entry (signing-body fields plus
// signature; the vectors carry no witnesses). Field order is alphabetical by
// JSON tag, matching `sort_keys=True` -- exactly the technique
// canonicalProjection already relies on for the signing body, extended by
// one field.
type entryDigestFields struct {
	KeyID     string `json:"key_id"`
	Kind      string `json:"kind"`
	LogID     string `json:"log_id"`
	MMRSize   uint64 `json:"mmr_size"`
	PrevRoot  string `json:"prev_root"`
	PrevSize  uint64 `json:"prev_size"`
	Root      string `json:"root"`
	Signature string `json:"signature"`
	Timestamp string `json:"timestamp"`
	Version   uint64 `json:"v"`
}

func loadConformanceDoc(t *testing.T) conformanceDoc {
	t.Helper()
	contents, err := os.ReadFile("testdata/vectors.json")
	require.NoError(t, err)
	var doc conformanceDoc
	require.NoError(t, json.Unmarshal(contents, &doc))
	require.Len(t, doc.Cases, doc.Count)
	return doc
}

func mustParseTimestamp(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339Nano, value)
	require.NoError(t, err)
	return parsed
}

func peaksFromHex(t *testing.T, values []string) [][]byte {
	t.Helper()
	peaks := make([][]byte, len(values))
	for index, value := range values {
		decoded, err := hex.DecodeString(value)
		require.NoError(t, err)
		peaks[index] = decoded
	}
	return peaks
}

func consistencyProofFromConformance(t *testing.T, proof *conformanceConsistency) mmr.ConsistencyProof {
	t.Helper()
	witness := make([][][]byte, len(proof.Witness))
	for index, level := range proof.Witness {
		witness[index] = peaksFromHex(t, level)
	}
	return mmr.ConsistencyProof{
		V: proof.Version, Kind: proof.Kind, OldSize: proof.SizeA, NewSize: proof.SizeB,
		OldPeaks: peaksFromHex(t, proof.OldPeaks), Witness: witness, NewPeaks: peaksFromHex(t, proof.NewPeaks),
	}
}

// TestCheckpointConformanceVectorsDigestAndSignature holds Payload.DigestHex
// (this package's real production code) to the vectors' digest_hex, and
// independently reproduces the raw Ed25519 signature and full-entry digest
// with the standard library -- the part of the Python/Rust model this
// package's COSE wire format does not itself compute.
func TestCheckpointConformanceVectorsDigestAndSignature(t *testing.T) {
	doc := loadConformanceDoc(t)
	seed, err := hex.DecodeString(doc.SigningKeySeedHex)
	require.NoError(t, err)
	private := ed25519.NewKeyFromSeed(seed)
	public, ok := private.Public().(ed25519.PublicKey)
	require.True(t, ok)
	require.Equal(t, doc.KeyID, hex.EncodeToString(public), "derived key_id does not match the vector's pinned key_id")

	for _, vector := range doc.Cases {
		t.Run(vector.Name, func(t *testing.T) {
			payload := Payload{
				LogID: vector.LogID, KeyID: vector.KeyID, MMRSize: vector.MMRSize, Root: vector.Root,
				PrevSize: vector.PrevSize, PrevRoot: vector.PrevRoot, Timestamp: mustParseTimestamp(t, vector.Timestamp),
			}
			digestHex, err := payload.DigestHex()
			require.NoError(t, err)
			require.Equal(t, vector.DigestHex, digestHex, "digest_hex mismatch")

			// Ed25519 is deterministic (RFC 8032): re-signing the SAME
			// digest_hex ASCII bytes with the SAME seed must reproduce the
			// pinned signature exactly -- the actual cross-language pin.
			resigned := ed25519.Sign(private, []byte(digestHex))
			require.Equal(t, vector.Signature, hex.EncodeToString(resigned), "re-signed signature does not match the pinned signature")
			require.True(t, ed25519.Verify(public, []byte(digestHex), resigned))

			entryJSON, err := json.Marshal(entryDigestFields{
				KeyID: vector.KeyID, Kind: vector.Kind, LogID: vector.LogID, MMRSize: vector.MMRSize,
				PrevRoot: vector.PrevRoot, PrevSize: vector.PrevSize, Root: vector.Root,
				Signature: vector.Signature, Timestamp: vector.Timestamp, Version: vector.Version,
			})
			require.NoError(t, err)
			entryDigest := sha256.Sum256(entryJSON)
			require.Equal(t, vector.EntryDigestHex, hex.EncodeToString(entryDigest[:]), "entry_digest_hex mismatch")
		})
	}
}

// TestCheckpointConformanceChainedCaseOverCLLGo drives this package's real
// MMR and COSE checkpoint code over the pinned vectors' plaintext fields: it
// rebuilds the 7-leaf MMR fixture the vectors were generated from, confirms
// the produced consistency proof matches the pinned one, then signs and
// self-verifies both checkpoints through this package's actual COSE
// pipeline -- the round-trip the Rust crate's
// checkpoint_conformance_chained_case_verifies_over_cose_wire test performs.
func TestCheckpointConformanceChainedCaseOverCLLGo(t *testing.T) {
	doc := loadConformanceDoc(t)
	var caseA, caseB *conformanceRecord
	for index := range doc.Cases {
		switch doc.Cases[index].Name {
		case "checkpoint-first-2-leaves":
			caseA = &doc.Cases[index]
		case "checkpoint-chained-2-to-7-leaves":
			caseB = &doc.Cases[index]
		}
	}
	require.NotNil(t, caseA, "checkpoint-first-2-leaves case is required")
	require.NotNil(t, caseB, "checkpoint-chained-2-to-7-leaves case is required")
	require.NotNil(t, caseB.ConsistencyProof)

	tree, err := mmr.New(nil)
	require.NoError(t, err)
	for sequence := 1; sequence <= 7; sequence++ {
		body := sha256.Sum256([]byte(fmt.Sprintf("asg-ledger-mmr-vector-leaf-%d", sequence)))
		_, err := tree.Append(body[:])
		require.NoError(t, err)
	}

	peaksA, err := tree.PeakHashesAt(caseA.MMRSize)
	require.NoError(t, err)
	peaksB, err := tree.PeakHashesAt(caseB.MMRSize)
	require.NoError(t, err)

	produced, err := tree.ConsistencyProofAt(caseA.MMRSize, caseB.MMRSize)
	require.NoError(t, err)
	pinned := consistencyProofFromConformance(t, caseB.ConsistencyProof)
	require.Equal(t, pinned, produced, "produced consistency proof does not match the pinned vector")

	seed, err := hex.DecodeString(doc.SigningKeySeedHex)
	require.NoError(t, err)
	signer, err := NewEd25519Signer(ed25519.NewKeyFromSeed(seed))
	require.NoError(t, err)
	require.Equal(t, doc.KeyID, signer.KeyID())

	ctx := context.Background()
	payloadA := Payload{
		LogID: caseA.LogID, KeyID: caseA.KeyID, MMRSize: caseA.MMRSize, Root: caseA.Root,
		PrevSize: caseA.PrevSize, PrevRoot: caseA.PrevRoot, Timestamp: mustParseTimestamp(t, caseA.Timestamp),
	}
	payloadAJSON, err := payloadA.CanonicalJSON()
	require.NoError(t, err)
	statementA, err := signer.SignCheckpoint(ctx, payloadAJSON, peaksA, nil, nil)
	require.NoError(t, err)
	recordA, err := ParseRecord(statementA)
	require.NoError(t, err)
	require.NoError(t, recordA.VerifySignature())
	require.Equal(t, caseA.Root, recordA.Root)

	payloadB := Payload{
		LogID: caseB.LogID, KeyID: caseB.KeyID, MMRSize: caseB.MMRSize, Root: caseB.Root,
		PrevSize: caseB.PrevSize, PrevRoot: caseB.PrevRoot, Timestamp: mustParseTimestamp(t, caseB.Timestamp),
	}
	payloadBJSON, err := payloadB.CanonicalJSON()
	require.NoError(t, err)
	statementB, err := signer.SignCheckpoint(ctx, payloadBJSON, peaksB, peaksA, &produced)
	require.NoError(t, err)
	recordB, err := ParseRecord(statementB)
	require.NoError(t, err)
	require.NoError(t, recordB.VerifySignature())
	require.Equal(t, caseB.Root, recordB.Root)
	require.Equal(t, caseA.Root, recordB.PrevRoot)
	require.NotNil(t, recordB.ConsistencyProof)
	require.True(t, mmr.VerifyConsistency(mmr.RootFromPeaks(peaksA), mmr.RootFromPeaks(peaksB), *recordB.ConsistencyProof))
}
