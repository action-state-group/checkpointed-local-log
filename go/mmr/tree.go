package mmr

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sync"

	dtmmr "github.com/datatrails/go-datatrails-merklelog/mmr"
	"github.com/fxamacker/cbor/v2"
)

const hashSize = sha256.Size

// Tree is an in-memory DataTrails-compatible bagged MMR.
type Tree struct {
	mu    sync.RWMutex
	nodes [][]byte
}

// InclusionProof proves that an identity is committed at LeafIndex in Size.
// Witness is the sibling path to the leaf's peak; PeaksLeft and PeaksRight
// are the remaining peaks in their accumulator order.
type InclusionProof struct {
	V          uint64
	Kind       string
	Size       uint64
	LeafIndex  uint64
	Witness    [][]byte
	PeaksLeft  [][]byte
	PeaksRight [][]byte
}

// ConsistencyProof proves that NewSize append-only extends OldSize.
type ConsistencyProof struct {
	V        uint64
	Kind     string
	OldSize  uint64
	NewSize  uint64
	OldPeaks [][]byte
	Witness  [][][]byte
	NewPeaks [][]byte
}

// New restores a Tree from its complete ordered node sequence.
func New(nodes [][]byte) (*Tree, error) {
	tree := &Tree{nodes: cloneProof(nodes)}
	if !validMMRSize(uint64(len(tree.nodes))) {
		return nil, fmt.Errorf("invalid complete MMR size %d", len(tree.nodes))
	}
	for index, node := range tree.nodes {
		if len(node) != hashSize {
			return nil, fmt.Errorf("node %d has length %d", index, len(node))
		}
		height := dtmmr.IndexHeight(uint64(index))
		if height == 0 {
			continue
		}
		left := uint64(index) - (2 << (height - 1))
		right := uint64(index) - 1
		hasher := sha256.New()
		var position [8]byte
		binary.BigEndian.PutUint64(position[:], uint64(index)+1)
		hasher.Write(position[:])
		hasher.Write(tree.nodes[left])
		hasher.Write(tree.nodes[right])
		if !bytes.Equal(node, hasher.Sum(nil)) {
			return nil, fmt.Errorf("interior node %d does not match its children", index)
		}
	}
	return tree, nil
}

// AppendHexIdentity decodes and appends one lowercase hexadecimal identity.
func (t *Tree) AppendHexIdentity(identity string) (uint64, error) {
	id, err := hex.DecodeString(identity)
	if err != nil || len(id) != hashSize || hex.EncodeToString(id) != identity {
		return 0, fmt.Errorf("identity must be 64 lowercase hexadecimal characters")
	}
	return t.Append(id)
}

// Append commits an application-neutral 32-byte record identity as the next
// CLL leaf. Fixed-width identities preserve leaf/interior domain separation.
func (t *Tree) Append(value []byte) (uint64, error) {
	if len(value) != hashSize {
		return 0, fmt.Errorf("CLL leaf value must be exactly 32 bytes")
	}
	leafInput := append([]byte{0}, value...)
	leaf := sha256.Sum256(leafInput)

	t.mu.Lock()
	defer t.mu.Unlock()
	size, err := dtmmr.AddHashedLeaf((*nodeStore)(t), sha256.New(), leaf[:])
	if err != nil {
		return 0, fmt.Errorf("append MMR leaf: %w", err)
	}
	return size, nil
}

func (t *Tree) Size() uint64 {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return uint64(len(t.nodes))
}

func (t *Tree) Nodes() [][]byte {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return cloneProof(t.nodes)
}

func (t *Tree) Root() ([]byte, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if len(t.nodes) == 0 {
		return make([]byte, hashSize), nil
	}
	root, err := dtmmr.GetRoot(uint64(len(t.nodes)), (*nodeStore)(t), sha256.New())
	if err != nil {
		return nil, fmt.Errorf("compute bagged MMR root: %w", err)
	}
	return append([]byte(nil), root...), nil
}

// PeakHashesAt returns the ordered accumulator peaks at a complete historical
// MMR size. The order is tallest-to-smallest, matching the MMR commitment
// object carried by the CLL checkpoint COSE wire profile.
func (t *Tree) PeakHashesAt(size uint64) ([][]byte, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.peakHashesAtLocked(size)
}

func (t *Tree) peakHashesAtLocked(size uint64) ([][]byte, error) {
	if size == 0 {
		return [][]byte{}, nil
	}
	if size > uint64(len(t.nodes)) || !validMMRSize(size) {
		return nil, fmt.Errorf("invalid historical MMR size %d", size)
	}
	peaks, err := dtmmr.PeakHashes((*nodeStore)(t), size-1)
	if err != nil {
		return nil, fmt.Errorf("read MMR peaks at size %d: %w", size, err)
	}
	return cloneProof(peaks), nil
}

// InclusionProofAt generates the Python-reference-shaped inclusion proof for
// leafIndex at a complete historical MMR size.
func (t *Tree) InclusionProofAt(leafIndex, size uint64) (InclusionProof, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if size > uint64(len(t.nodes)) || !validMMRSize(size) || leafIndex >= dtmmr.LeafCount(size) {
		return InclusionProof{}, fmt.Errorf("invalid MMR inclusion position")
	}
	leafPosition := dtmmr.MMRIndex(leafIndex)
	peakPositions := dtmmr.Peaks(size - 1)
	peakIndex := containingPeak(uint64(leafPosition), peakPositions)
	if peakIndex < 0 {
		return InclusionProof{}, fmt.Errorf("leaf index %d is not contained in MMR", leafIndex)
	}
	peak := peakPositions[peakIndex]
	steps, ok := pathToPeak(peak, dtmmr.IndexHeight(peak), uint64(leafPosition))
	if !ok {
		return InclusionProof{}, fmt.Errorf("leaf index %d has no path to MMR peak", leafIndex)
	}
	witness := make([][]byte, len(steps))
	for index, step := range steps {
		witness[index] = append([]byte(nil), t.nodes[step.sibling]...)
	}
	allPeaks, err := t.peakHashesAtLocked(size)
	if err != nil {
		return InclusionProof{}, fmt.Errorf("read MMR peaks at size %d: %w", size, err)
	}
	return InclusionProof{
		V:          1,
		Kind:       "inclusion",
		Size:       size,
		LeafIndex:  leafIndex,
		Witness:    witness,
		PeaksLeft:  cloneProof(allPeaks[:peakIndex]),
		PeaksRight: cloneProof(allPeaks[peakIndex+1:]),
	}, nil
}

// InclusionProof generates the Python-reference-shaped inclusion proof for
// leafIndex at a complete historical MMR size.
func (t *Tree) InclusionProof(leafIndex, size uint64) (InclusionProof, error) {
	return t.InclusionProofAt(leafIndex, size)
}

// ConsistencyProofAt generates the Python-reference-shaped consistency proof
// between two complete historical MMR sizes.
func (t *Tree) ConsistencyProofAt(oldSize, newSize uint64) (ConsistencyProof, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if oldSize > newSize || newSize > uint64(len(t.nodes)) || !validMMRSize(oldSize) || !validMMRSize(newSize) {
		return ConsistencyProof{}, fmt.Errorf("invalid MMR consistency sizes")
	}
	oldPositions := peakPositions(oldSize)
	newPositions := peakPositions(newSize)
	oldPeaks, err := t.peakHashesAtLocked(oldSize)
	if err != nil {
		return ConsistencyProof{}, fmt.Errorf("read old MMR peaks: %w", err)
	}
	newPeaks, err := t.peakHashesAtLocked(newSize)
	if err != nil {
		return ConsistencyProof{}, fmt.Errorf("read new MMR peaks: %w", err)
	}
	witness := make([][][]byte, len(oldPositions))
	for index, oldPeak := range oldPositions {
		containing := containingPeak(oldPeak, newPositions)
		if containing < 0 {
			return ConsistencyProof{}, fmt.Errorf("old peak %d is not contained in new MMR", oldPeak)
		}
		steps, ok := pathToPeak(newPositions[containing], dtmmr.IndexHeight(newPositions[containing]), oldPeak)
		if !ok {
			return ConsistencyProof{}, fmt.Errorf("old peak %d has no path to new peak", oldPeak)
		}
		witness[index] = make([][]byte, len(steps))
		for stepIndex, step := range steps {
			witness[index][stepIndex] = append([]byte(nil), t.nodes[step.sibling]...)
		}
	}
	return ConsistencyProof{V: 1, Kind: "consistency", OldSize: oldSize, NewSize: newSize, OldPeaks: cloneProof(oldPeaks), Witness: cloneWitness(witness), NewPeaks: cloneProof(newPeaks)}, nil
}

// ConsistencyProof generates the Python-reference-shaped consistency proof
// between two complete historical MMR sizes.
func (t *Tree) ConsistencyProof(oldSize, newSize uint64) (ConsistencyProof, error) {
	return t.ConsistencyProofAt(oldSize, newSize)
}

// VerifyConsistency validates the accumulator consistency proof carried by the
// CLL checkpoint COSE profile.
func VerifyConsistency(oldRoot, newRoot []byte, proof ConsistencyProof) bool {
	if len(oldRoot) != hashSize || len(newRoot) != hashSize || proof.V != 1 || proof.Kind != "consistency" || proof.OldSize > proof.NewSize || !validMMRSize(proof.OldSize) || !validMMRSize(proof.NewSize) {
		return false
	}
	oldPositions := peakPositions(proof.OldSize)
	newPositions := peakPositions(proof.NewSize)
	if len(proof.OldPeaks) != len(oldPositions) || len(proof.NewPeaks) != len(newPositions) || len(proof.Witness) != len(oldPositions) {
		return false
	}
	for _, collection := range [][][]byte{proof.OldPeaks, proof.NewPeaks} {
		for _, node := range collection {
			if len(node) != hashSize {
				return false
			}
		}
	}
	if !bytes.Equal(RootFromPeaks(proof.OldPeaks), oldRoot) || !bytes.Equal(RootFromPeaks(proof.NewPeaks), newRoot) {
		return false
	}
	for index, oldPeak := range oldPositions {
		containing := containingPeak(oldPeak, newPositions)
		if containing < 0 {
			return false
		}
		steps, ok := pathToPeak(newPositions[containing], dtmmr.IndexHeight(newPositions[containing]), oldPeak)
		if !ok || len(steps) != len(proof.Witness[index]) {
			return false
		}
		accumulator := append([]byte(nil), proof.OldPeaks[index]...)
		for stepIndex, step := range steps {
			sibling := proof.Witness[index][stepIndex]
			if len(sibling) != hashSize {
				return false
			}
			if step.targetIsRight {
				accumulator = interiorHash(sibling, accumulator, step.parent)
			} else {
				accumulator = interiorHash(accumulator, sibling, step.parent)
			}
		}
		if !bytes.Equal(accumulator, proof.NewPeaks[containing]) {
			return false
		}
	}
	return true
}

// VerifyInclusion validates a 32-byte CLL identity against an inclusion proof.
func VerifyInclusion(root []byte, size, leafIndex uint64, value []byte, proof InclusionProof) bool {
	if len(root) != hashSize || len(value) != hashSize || proof.V != 1 || proof.Kind != "inclusion" || proof.Size != size || proof.LeafIndex != leafIndex || !validMMRSize(size) || leafIndex >= dtmmr.LeafCount(size) {
		return false
	}
	positions := peakPositions(size)
	leafPosition := uint64(dtmmr.MMRIndex(leafIndex))
	peakIndex := containingPeak(leafPosition, positions)
	if peakIndex < 0 || len(proof.PeaksLeft) != peakIndex || len(proof.PeaksRight) != len(positions)-peakIndex-1 {
		return false
	}
	steps, ok := pathToPeak(positions[peakIndex], dtmmr.IndexHeight(positions[peakIndex]), leafPosition)
	if !ok || len(steps) != len(proof.Witness) {
		return false
	}
	leaf := sha256.Sum256(append([]byte{0}, value...))
	accumulator := leaf[:]
	for index, step := range steps {
		sibling := proof.Witness[index]
		if len(sibling) != hashSize {
			return false
		}
		if step.targetIsRight {
			accumulator = interiorHash(sibling, accumulator, step.parent)
		} else {
			accumulator = interiorHash(accumulator, sibling, step.parent)
		}
	}
	peaks := make([][]byte, 0, len(positions))
	for _, collection := range [][][]byte{proof.PeaksLeft, [][]byte{accumulator}, proof.PeaksRight} {
		for _, peak := range collection {
			if len(peak) != hashSize {
				return false
			}
			peaks = append(peaks, peak)
		}
	}
	return bytes.Equal(RootFromPeaks(peaks), root)
}

// RootFromPeaks bags an ordered tallest-to-smallest accumulator into the
// scalar root used by the local CLL proof API.
func RootFromPeaks(peaks [][]byte) []byte {
	if len(peaks) == 0 {
		return make([]byte, hashSize)
	}
	return dtmmr.HashPeaksRHS(sha256.New(), cloneProof(peaks))
}

// CommitmentObject returns the canonical CBOR encoding of ordered MMR peaks
// carried by the CLL checkpoint wire profile.
func CommitmentObject(peaks [][]byte) ([]byte, error) {
	if peaks == nil {
		peaks = [][]byte{}
	}
	for _, peak := range peaks {
		if len(peak) != hashSize {
			return nil, fmt.Errorf("MMR peaks must be 32 bytes")
		}
	}
	mode, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		return nil, fmt.Errorf("create canonical CBOR encoder: %w", err)
	}
	encoded, err := mode.Marshal(peaks)
	if err != nil {
		return nil, fmt.Errorf("encode MMR commitment: %w", err)
	}
	return encoded, nil
}

type pathStep struct {
	sibling       uint64
	targetIsRight bool
	parent        uint64
}

func containingPeak(position uint64, peaks []uint64) int {
	for index, peak := range peaks {
		height := dtmmr.IndexHeight(peak)
		mountainSize := (uint64(1) << (height + 1)) - 1
		start := peak - mountainSize + 1
		if position >= start && position <= peak {
			return index
		}
	}
	return -1
}

func pathToPeak(root, height, target uint64) ([]pathStep, bool) {
	steps := make([]pathStep, 0, height)
	currentRoot := root
	currentHeight := height
	for currentHeight > 0 && currentRoot != target {
		leftSize := (uint64(1) << currentHeight) - 1
		leftRoot := currentRoot - leftSize - 1
		rightRoot := currentRoot - 1
		if target <= leftRoot {
			steps = append(steps, pathStep{sibling: rightRoot, parent: currentRoot})
			currentRoot = leftRoot
		} else {
			steps = append(steps, pathStep{sibling: leftRoot, targetIsRight: true, parent: currentRoot})
			currentRoot = rightRoot
		}
		currentHeight--
	}
	if currentRoot != target {
		return nil, false
	}
	for left, right := 0, len(steps)-1; left < right; left, right = left+1, right-1 {
		steps[left], steps[right] = steps[right], steps[left]
	}
	return steps, true
}

func interiorHash(left, right []byte, position uint64) []byte {
	hasher := sha256.New()
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], position+1)
	hasher.Write(encoded[:])
	hasher.Write(left)
	hasher.Write(right)
	return hasher.Sum(nil)
}

func cloneWitness(input [][][]byte) [][][]byte {
	output := make([][][]byte, len(input))
	for index := range input {
		output[index] = cloneProof(input[index])
	}
	return output
}

// VerifyHexInclusion decodes an identity and verifies its MMR inclusion proof.
func VerifyHexInclusion(root []byte, mmrSize, leafIndex uint64, identity string, proof InclusionProof) bool {
	id, err := hex.DecodeString(identity)
	if err != nil || len(id) != hashSize || hex.EncodeToString(id) != identity {
		return false
	}
	return VerifyInclusion(root, mmrSize, leafIndex, id, proof)
}

func peakPositions(size uint64) []uint64 {
	if size == 0 {
		return nil
	}
	return dtmmr.Peaks(size - 1)
}

func validMMRSize(size uint64) bool {
	if size == 0 {
		return true
	}
	// Leave enough arithmetic headroom for FirstMMRSize's peak completion.
	if size > (1<<63)-1 {
		return false
	}
	return dtmmr.FirstMMRSize(size-1) == size
}

// LeafCount returns the committed leaf count for a complete MMR size.
func LeafCount(size uint64) (uint64, bool) {
	if !validMMRSize(size) {
		return 0, false
	}
	return dtmmr.LeafCount(size), true
}

type nodeStore Tree

func (s *nodeStore) Get(index uint64) ([]byte, error) {
	if index >= uint64(len(s.nodes)) {
		return nil, dtmmr.ErrNotFound
	}
	return s.nodes[index], nil
}

func (s *nodeStore) Append(value []byte) (uint64, error) {
	s.nodes = append(s.nodes, append([]byte(nil), value...))
	return uint64(len(s.nodes)), nil
}

func cloneProof(input [][]byte) [][]byte {
	result := make([][]byte, len(input))
	for index, value := range input {
		result[index] = append([]byte(nil), value...)
	}
	return result
}
