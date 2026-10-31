package witness

// Receipt verification is an attributed Go adaptation of
// action-state-group/scitt-cose/scitt-cose-go-verify at
// 36ec13992287a463481d1b00ac2098f032f229b5 (Apache-2.0), with the decoding
// rules of action-state-group/agent-action-capsule go/witness/cose.go at
// go/v0.18.0 (BSD-3-Clause, Copyright (c) 2026 Action State Group, Inc.).

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"

	"github.com/action-state-group/checkpointed-local-log/go/checkpoint"
	"github.com/action-state-group/checkpointed-local-log/go/internal/ed25519strict"
	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

const (
	headerAlg          = int64(1)
	headerCrit         = int64(2)
	headerCWTClaims    = int64(15)
	headerVDS          = int64(395)
	headerVDP          = int64(396)
	vdsRFC9162         = 1
	vdpInclusion       = int64(-1)
	maxTreeSize        = int64(1 << 62)
	maxInclusionProofs = 16
	maxAuditPath       = 64
)

// understoodLabels are the protected labels this verifier processes; a
// receipt marking any other label critical is refused.
var understoodLabels = map[uint64]bool{uint64(headerAlg): true, uint64(headerCrit): true, uint64(headerVDS): true, uint64(headerCWTClaims): true}

var (
	lenientDecoding = mustDecMode(cbor.DecOptions{IntDec: cbor.IntDecConvertNone})
	strictDecoding  = mustDecMode(cbor.DecOptions{
		DupMapKey:   cbor.DupMapKeyEnforcedAPF,
		IndefLength: cbor.IndefLengthForbidden,
		IntDec:      cbor.IntDecConvertNone,
	})
	deterministicEncoding = func() cbor.EncMode {
		mode, err := cbor.CoreDetEncOptions().EncMode()
		if err != nil {
			panic(err)
		}
		return mode
	}()
)

func mustDecMode(options cbor.DecOptions) cbor.DecMode {
	mode, err := options.DecMode()
	if err != nil {
		panic(err)
	}
	return mode
}

// ReceiptVerifier verifies RFC 9162 COSE receipts under a pinned authority key.
type ReceiptVerifier struct{ public ed25519.PublicKey }

// NewReceiptVerifier copies and pins the supplied Ed25519 authority key.
func NewReceiptVerifier(public ed25519.PublicKey) (*ReceiptVerifier, error) {
	if len(public) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("pinned Ed25519 authority key is required")
	}
	return &ReceiptVerifier{public: append(ed25519.PublicKey(nil), public...)}, nil
}

func (v *ReceiptVerifier) Verify(statement []byte, receipt Receipt) error {
	if len(receipt.Bytes) == 0 || len(receipt.Bytes) > DefaultMaxResponseBytes {
		return fmt.Errorf("receipt size is invalid")
	}
	if receipt.EntryHashScheme != EntryHashSchemeCheckpointDigest {
		return fmt.Errorf("unsupported receipt entry hash scheme %q", receipt.EntryHashScheme)
	}
	record, err := checkpoint.ParseRecord(statement)
	if err != nil {
		return err
	}
	if err := record.VerifySignature(); err != nil {
		return err
	}
	entry, err := record.EntryHash()
	if err != nil {
		return err
	}
	if hex.EncodeToString(entry) != receipt.EntryHash {
		return fmt.Errorf("entry hash does not bind signed checkpoint")
	}
	decoded, err := decodeReceipt(receipt.Bytes)
	if err != nil {
		return err
	}
	for _, proof := range decoded.proofs {
		root, ok := rootFromProof(entry, proof.index, proof.size, proof.path)
		if !ok || !ed25519strict.Verify(v.public, sigStructure(decoded.protected, root), decoded.signature) {
			continue
		}
		// The runner stores the response's position, so it must be the one
		// the verified proof carries.
		if proof.size != receipt.TreeSize || proof.index != receipt.LeafIndex {
			return fmt.Errorf("receipt position mismatch")
		}
		return nil
	}
	return fmt.Errorf("receipt signature did not verify over any reconstructed root")
}

type inclusionProof struct {
	size, index int64
	path        [][]byte
}

type decodedReceipt struct {
	protected, signature []byte
	proofs               []inclusionProof
}

// decodeReceipt applies the receipt profile agent-action-capsule's
// VerifyCOSEReceipt and scitt-cose's verify_receipt share, so all three
// accept the same receipts (checkpoint-conformance-vectors/receipt-vectors.json):
// a strictly encoded tag-18 COSE_Sign1 with a detached payload, protected vds
// 1 and alg EdDSA, crit naming only understood labels, and 1 to
// maxInclusionProofs inclusion proofs that all decode.
func decodeReceipt(raw []byte) (decodedReceipt, error) {
	value, err := strictItem(raw)
	if err != nil {
		return decodedReceipt{}, fmt.Errorf("decode COSE receipt: %w", err)
	}
	tag, isTag := value.(cbor.Tag)
	parts, isArray := tag.Content.([]any)
	if !isTag || tag.Number != 18 || !isArray || len(parts) != 4 {
		return decodedReceipt{}, fmt.Errorf("receipt is not a COSE_Sign1 message")
	}
	protectedBytes, isBytes := parts[0].([]byte)
	if !isBytes {
		return decodedReceipt{}, fmt.Errorf("receipt is not a COSE_Sign1 message")
	}
	// An attached payload binds nothing: the signature must cover the root
	// rebuilt from the proof. Detached is CBOR null; undefined also decodes
	// to nil, so the raw item is checked.
	if !detachedPayload(raw) {
		return decodedReceipt{}, fmt.Errorf("receipt payload is attached; a receipt's payload must be detached")
	}
	signature, isBytes := parts[3].([]byte)
	if !isBytes {
		return decodedReceipt{}, fmt.Errorf("receipt signature is not a byte string")
	}
	protected := map[any]any{}
	if len(protectedBytes) != 0 {
		value, err := strictItem(protectedBytes)
		if err != nil {
			return decodedReceipt{}, fmt.Errorf("decode receipt protected header: %w", err)
		}
		var isMap bool
		if protected, isMap = value.(map[any]any); !isMap {
			return decodedReceipt{}, fmt.Errorf("receipt protected header is not a map")
		}
	}
	if vds, _ := protected[uint64(headerVDS)].(uint64); vds != vdsRFC9162 {
		return decodedReceipt{}, fmt.Errorf("receipt protected header requires RFC9162 VDS")
	}
	if alg, _ := protected[uint64(headerAlg)].(int64); alg != int64(cose.AlgorithmEdDSA) {
		return decodedReceipt{}, fmt.Errorf("receipt must use EdDSA")
	}
	if err := checkCritical(protected); err != nil {
		return decodedReceipt{}, err
	}
	unprotected, isMap := parts[1].(map[any]any)
	if !isMap {
		return decodedReceipt{}, fmt.Errorf("receipt unprotected header is not a map")
	}
	vdp, isMap := unprotected[uint64(headerVDP)].(map[any]any)
	if !isMap {
		return decodedReceipt{}, fmt.Errorf("receipt missing VDP")
	}
	blobs, isArray := vdp[vdpInclusion].([]any)
	if !isArray || len(blobs) == 0 {
		return decodedReceipt{}, fmt.Errorf("receipt missing inclusion proof")
	}
	if len(blobs) > maxInclusionProofs {
		return decodedReceipt{}, fmt.Errorf("receipt has more than %d inclusion proofs", maxInclusionProofs)
	}
	// Decode every proof before verifying any: a valid proof must not hide a
	// malformed later entry in this unauthenticated array.
	proofs := make([]inclusionProof, 0, len(blobs))
	for _, entry := range blobs {
		blob, isBytes := entry.([]byte)
		if !isBytes {
			return decodedReceipt{}, fmt.Errorf("receipt proof is not bytes")
		}
		proof, err := decodeInclusionProof(blob)
		if err != nil {
			return decodedReceipt{}, err
		}
		proofs = append(proofs, proof)
	}
	return decodedReceipt{protected: protectedBytes, signature: signature, proofs: proofs}, nil
}

// detachedPayload reports whether the third item of a well-formed tag-18
// COSE_Sign1 is CBOR null.
func detachedPayload(raw []byte) bool {
	var tag cbor.RawTag
	var parts []cbor.RawMessage
	if cbor.Unmarshal(raw, &tag) != nil || cbor.Unmarshal(tag.Content, &parts) != nil || len(parts) != 4 {
		return false
	}
	return bytes.Equal(parts[2], []byte{0xf6})
}

// decodeInclusionProof decodes CBOR [tree_size, leaf_index, [audit_path...]]
// as AAC's decodeInclusionProof does: leniently (a non-shortest head or an
// indefinite length is accepted), with plain integers or bignums for the
// sizes and byte strings for the path, refusing a proof that cannot fit its
// tree so that it refuses the whole receipt.
func decodeInclusionProof(blob []byte) (inclusionProof, error) {
	var value any
	if err := lenientDecoding.Unmarshal(blob, &value); err != nil {
		return inclusionProof{}, fmt.Errorf("invalid inclusion proof: %w", err)
	}
	parts, isArray := value.([]any)
	if !isArray || len(parts) != 3 {
		return inclusionProof{}, fmt.Errorf("inclusion proof must be [tree_size, leaf_index, [path]]")
	}
	size, sizeOK := cborInteger(parts[0])
	index, indexOK := cborInteger(parts[1])
	if !sizeOK || !indexOK {
		return inclusionProof{}, fmt.Errorf("inclusion proof tree_size and leaf_index must be integers")
	}
	nodes, isArray := parts[2].([]any)
	if !isArray || len(nodes) > maxAuditPath {
		return inclusionProof{}, fmt.Errorf("inclusion proof path must be an array of at most %d nodes", maxAuditPath)
	}
	path := make([][]byte, len(nodes))
	for i, node := range nodes {
		raw, isBytes := node.([]byte)
		if !isBytes || len(raw) != sha256.Size {
			return inclusionProof{}, fmt.Errorf("inclusion proof path node must be a 32-byte string")
		}
		path[i] = raw
	}
	if index < 0 || index >= size || size > maxTreeSize || int64(len(path)) != expectedPath(size, index) {
		return inclusionProof{}, fmt.Errorf("invalid inclusion proof position or path length")
	}
	return inclusionProof{size, index, path}, nil
}

// cborInteger reads a decoded CBOR integer, a bignum included, that fits an
// int64.
func cborInteger(value any) (int64, bool) {
	switch value := value.(type) {
	case uint64:
		if value > math.MaxInt64 {
			return 0, false
		}
		return int64(value), true
	case int64:
		return value, true
	case big.Int:
		if value.IsInt64() {
			return value.Int64(), true
		}
	case *big.Int:
		if value.IsInt64() {
			return value.Int64(), true
		}
	}
	return 0, false
}

// strictItem decodes one CBOR item and refuses any encoding but its
// deterministic one up to map order: trailing bytes, indefinite lengths,
// duplicate keys, and non-shortest arguments or floats. Comparing lengths
// accepts a validly signed header whose keys are not in canonical order, as
// the scitt-cose verifiers do.
func strictItem(data []byte) (any, error) {
	var value any
	if err := strictDecoding.Unmarshal(data, &value); err != nil {
		return nil, err
	}
	canonical, err := deterministicEncoding.Marshal(value)
	if err != nil {
		return nil, err
	}
	if len(canonical) != len(data) {
		return nil, fmt.Errorf("non-deterministic CBOR encoding")
	}
	return value, nil
}

// checkCritical enforces RFC 9052 section 3.1: crit is a non-empty array of
// labels that are present in the protected header and understood here.
func checkCritical(protected map[any]any) error {
	raw, present := protected[uint64(headerCrit)]
	if !present {
		return nil
	}
	labels, isArray := raw.([]any)
	if !isArray || len(labels) == 0 {
		return fmt.Errorf("receipt crit must be a non-empty array")
	}
	for _, label := range labels {
		switch label.(type) {
		case uint64, int64, string:
		default:
			return fmt.Errorf("receipt crit lists a label that is not an integer or text")
		}
		if _, listed := protected[label]; !listed {
			return fmt.Errorf("receipt crit lists a header absent from the protected header")
		}
		if value, isUint := label.(uint64); !isUint || !understoodLabels[value] {
			return fmt.Errorf("receipt crit marks a header this verifier does not understand")
		}
	}
	return nil
}

func sigStructure(protected, root []byte) []byte {
	encoded, err := deterministicEncoding.Marshal([]any{"Signature1", protected, []byte{}, root})
	if err != nil {
		panic(err) // a fixed shape of text and byte strings always encodes
	}
	return encoded
}

func rootFromProof(entry []byte, index, size int64, path [][]byte) ([]byte, bool) {
	if index < 0 || index >= size || size > maxTreeSize || int64(len(path)) != expectedPath(size, index) {
		return nil, false
	}
	leaf := sha256.Sum256(append([]byte{0}, entry...))
	siblings := append([][]byte(nil), path...)
	var fold func(int64, int64) ([]byte, bool)
	fold = func(n, m int64) ([]byte, bool) {
		if n == 1 {
			return leaf[:], true
		}
		if len(siblings) == 0 {
			return nil, false
		}
		k := largestPowerBelow(n)
		sibling := siblings[len(siblings)-1]
		siblings = siblings[:len(siblings)-1]
		if m < k {
			child, ok := fold(k, m)
			if !ok {
				return nil, false
			}
			return nodeHash(child, sibling), true
		}
		child, ok := fold(n-k, m-k)
		if !ok {
			return nil, false
		}
		return nodeHash(sibling, child), true
	}
	root, ok := fold(size, index)
	return root, ok && len(siblings) == 0
}
func nodeHash(left, right []byte) []byte {
	input := make([]byte, 1, 1+len(left)+len(right))
	input[0] = 1
	input = append(input, left...)
	input = append(input, right...)
	sum := sha256.Sum256(input)
	return sum[:]
}
func largestPowerBelow(n int64) int64 {
	if n <= 1 {
		return 1
	}
	k := int64(1)
	for k <= (n-1)/2 {
		k *= 2
	}
	return k
}
func expectedPath(size, index int64) int64 {
	var count int64
	for size > 1 {
		k := largestPowerBelow(size)
		if index < k {
			size = k
		} else {
			size -= k
			index -= k
		}
		count++
	}
	return count
}
