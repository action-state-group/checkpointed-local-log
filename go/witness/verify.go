package witness

// Receipt verification is an attributed Go adaptation of
// action-state-group/scitt-cose/scitt-cose-go-verify at
// 36ec13992287a463481d1b00ac2098f032f229b5 (Apache-2.0).

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/action-state-group/cll-go/checkpoint"
	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

const (
	headerVDS    = int64(395)
	headerVDP    = int64(396)
	vdsRFC9162   = int64(1)
	vdpInclusion = int64(-1)
	maxTreeSize  = int64(1 << 62)
)

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
	var message cose.Sign1Message
	if err := message.UnmarshalCBOR(receipt.Bytes); err != nil {
		return fmt.Errorf("decode COSE receipt: %w", err)
	}
	vds, ok := integerHeader(message.Headers.Protected, headerVDS)
	if !ok || vds != vdsRFC9162 {
		return fmt.Errorf("receipt protected header requires RFC9162 VDS")
	}
	algorithm, err := message.Headers.Protected.Algorithm()
	if err != nil || algorithm != cose.AlgorithmEdDSA {
		return fmt.Errorf("receipt must use EdDSA")
	}
	vdpAny, ok := lookup(message.Headers.Unprotected, headerVDP)
	if !ok {
		return fmt.Errorf("receipt missing VDP")
	}
	vdp, ok := vdpAny.(map[any]any)
	if !ok {
		return fmt.Errorf("receipt VDP is not a map")
	}
	proofsAny, ok := lookup(vdp, vdpInclusion)
	if !ok {
		return fmt.Errorf("receipt missing inclusion proof")
	}
	proofs, ok := proofsAny.([]any)
	if !ok || len(proofs) != 1 {
		return fmt.Errorf("receipt requires one inclusion proof")
	}
	blob, ok := proofs[0].([]byte)
	if !ok {
		return fmt.Errorf("receipt proof is not bytes")
	}
	treeSize, leafIndex, path, err := decodeProof(blob)
	if err != nil {
		return err
	}
	if treeSize != receipt.TreeSize || leafIndex != receipt.LeafIndex {
		return fmt.Errorf("receipt position mismatch")
	}
	root, ok := rootFromProof(entry, leafIndex, treeSize, path)
	if !ok {
		return fmt.Errorf("receipt inclusion proof is invalid")
	}
	message.Payload = root
	verifier, err := cose.NewVerifier(cose.AlgorithmEdDSA, v.public)
	if err != nil {
		return err
	}
	if err := message.Verify(nil, verifier); err != nil {
		return fmt.Errorf("verify receipt authority signature: %w", err)
	}
	return nil
}

func decodeProof(blob []byte) (int64, int64, [][]byte, error) {
	var values []cbor.RawMessage
	if err := cbor.Unmarshal(blob, &values); err != nil || len(values) != 3 {
		return 0, 0, nil, fmt.Errorf("invalid inclusion proof")
	}
	var size, index int64
	var path [][]byte
	if err := cbor.Unmarshal(values[0], &size); err != nil {
		return 0, 0, nil, err
	}
	if err := cbor.Unmarshal(values[1], &index); err != nil {
		return 0, 0, nil, err
	}
	if err := cbor.Unmarshal(values[2], &path); err != nil {
		return 0, 0, nil, err
	}
	for _, node := range path {
		if len(node) != 32 {
			return 0, 0, nil, fmt.Errorf("invalid proof hash length")
		}
	}
	return size, index, path, nil
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
func lookup(values map[any]any, key int64) (any, bool) {
	for candidate, value := range values {
		switch typed := candidate.(type) {
		case int64:
			if typed == key {
				return value, true
			}
		case uint64:
			if key >= 0 && typed == uint64(key) {
				return value, true
			}
		case int:
			if int64(typed) == key {
				return value, true
			}
		}
	}
	return nil, false
}
func integerHeader(values map[any]any, key int64) (int64, bool) {
	value, ok := lookup(values, key)
	if !ok {
		return 0, false
	}
	switch typed := value.(type) {
	case int64:
		return typed, true
	case uint64:
		if typed <= uint64(^uint64(0)>>1) {
			return int64(typed), true
		}
	case int:
		return int64(typed), true
	}
	return 0, false
}
