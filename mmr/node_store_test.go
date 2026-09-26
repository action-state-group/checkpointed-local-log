package mmr

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	dtmmr "github.com/datatrails/go-datatrails-merklelog/mmr"
	"github.com/stretchr/testify/require"
)

func leafBody(sequence int) []byte {
	digest := sha256.Sum256([]byte(fmt.Sprintf("node-store-leaf-%d", sequence)))
	return digest[:]
}

// TestFileNodeStoreMatchesMemoryTree proves the durable store is not merely
// self-consistent: a Tree loaded back from a FileNodeStore produces the
// exact same root and consistency proof as a Tree built by direct in-memory
// Append calls over the same leaves -- the durable path and the in-memory
// path are two routes to the identical MMR.
func TestFileNodeStoreMatchesMemoryTree(t *testing.T) {
	memory, err := New(nil)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "nodes.bin")
	store, report, err := OpenFileNodeStore(path)
	require.NoError(t, err)
	defer store.Close()
	require.Equal(t, OpenReport{}, report)

	for sequence := 1; sequence <= 7; sequence++ {
		body := leafBody(sequence)
		_, err := memory.Append(body)
		require.NoError(t, err)
		leaf := sha256.Sum256(append([]byte{0}, body...))
		_, err = dtmmr.AddHashedLeaf(store, sha256.New(), leaf[:])
		require.NoError(t, err)
	}
	require.Equal(t, memory.Size(), store.Size())

	restored, err := NewFromNodeStore(store)
	require.NoError(t, err)
	memoryRoot, err := memory.Root()
	require.NoError(t, err)
	restoredRoot, err := restored.Root()
	require.NoError(t, err)
	require.Equal(t, memoryRoot, restoredRoot)

	memoryProof, err := memory.ConsistencyProof(3, memory.Size())
	require.NoError(t, err)
	restoredProof, err := restored.ConsistencyProof(3, restored.Size())
	require.NoError(t, err)
	require.Equal(t, memoryProof, restoredProof)
}

// TestOpenFileNodeStoreTruncatesTornTail proves the negative case a crash
// mid-append leaves behind: a partial 32-byte record at the file's tail.
// Without truncation, Get would silently hand back a short/garbage node
// past the true node count; the mutant here is "don't truncate," which
// would make this test's post-open Size() and re-append behavior wrong.
func TestOpenFileNodeStoreTruncatesTornTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nodes.bin")
	store, _, err := OpenFileNodeStore(path)
	require.NoError(t, err)
	for sequence := 1; sequence <= 3; sequence++ {
		leaf := sha256.Sum256(append([]byte{0}, leafBody(sequence)...))
		_, err := dtmmr.AddHashedLeaf(store, sha256.New(), leaf[:])
		require.NoError(t, err)
	}
	writtenNodes := store.Size()
	require.NoError(t, store.Close())

	// Simulate a crash mid-write: append 17 stray bytes (less than one
	// record) directly to the file, bypassing Append/fsync discipline.
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	require.NoError(t, err)
	_, err = file.Write(make([]byte, 17))
	require.NoError(t, err)
	require.NoError(t, file.Close())

	reopened, report, err := OpenFileNodeStore(path)
	require.NoError(t, err)
	defer reopened.Close()
	require.Equal(t, OpenReport{NodeCount: writtenNodes, TruncatedBytes: 17}, report)
	require.Equal(t, writtenNodes, reopened.Size())

	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, int64(writtenNodes*hashSize), info.Size())

	// A torn record must never be treated as valid: the discarded slot is
	// out of range now, not a zero/garbage node.
	_, err = reopened.Get(writtenNodes)
	require.Error(t, err)
}

// TestRebuildFileNodeStoreFromLeavesIsIdempotent proves the recovery path:
// rebuilding twice from the same leaves produces byte-identical files, and
// the rebuilt store's root matches a Tree built directly from those leaves.
func TestRebuildFileNodeStoreFromLeavesIsIdempotent(t *testing.T) {
	leaves := make([][]byte, 0, 7)
	for sequence := 1; sequence <= 7; sequence++ {
		leaves = append(leaves, leafBody(sequence))
	}
	memory, err := New(nil)
	require.NoError(t, err)
	for _, body := range leaves {
		_, err := memory.Append(body)
		require.NoError(t, err)
	}
	memoryRoot, err := memory.Root()
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), "rebuilt.bin")
	first, err := RebuildFileNodeStoreFromLeaves(path, leaves)
	require.NoError(t, err)
	firstNodes, err := first.Nodes()
	require.NoError(t, err)
	require.NoError(t, first.Close())

	second, err := RebuildFileNodeStoreFromLeaves(path, leaves)
	require.NoError(t, err)
	secondNodes, err := second.Nodes()
	require.NoError(t, err)
	require.NoError(t, second.Close())

	require.Equal(t, firstNodes, secondNodes, "rebuilding from the same leaves must be idempotent")

	rebuiltFile, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Len(t, rebuiltFile, len(firstNodes)*hashSize)

	restored, err := New(firstNodes)
	require.NoError(t, err)
	restoredRoot, err := restored.Root()
	require.NoError(t, err)
	require.Equal(t, memoryRoot, restoredRoot, "rebuilt store must match the in-memory tree built from the same leaves")
}

// TestFileNodeStoreAppendRejectsWrongSize is the negative half of Append:
// a value of any length other than hashSize must never be silently padded
// or truncated into a node.
func TestFileNodeStoreAppendRejectsWrongSize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nodes.bin")
	store, _, err := OpenFileNodeStore(path)
	require.NoError(t, err)
	defer store.Close()
	_, err = store.Append(make([]byte, hashSize-1))
	require.Error(t, err)
	require.Zero(t, store.Size())
}
