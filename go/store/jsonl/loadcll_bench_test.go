package jsonl

import (
	"encoding/binary"
	"path/filepath"
	"testing"

	"github.com/action-state-group/checkpointed-local-log/go/cll"
	"github.com/action-state-group/checkpointed-local-log/go/mmr"
	"github.com/stretchr/testify/require"
)

// BenchmarkLoadCLL measures the time LoadCLL holds the store read lock, which
// is dominated by cloning the state, for logs of increasing size.
func BenchmarkLoadCLL(b *testing.B) {
	for _, entries := range []uint64{1 << 10, 1 << 14, 1 << 17, 1 << 20} {
		b.Run(sizeName(entries), func(b *testing.B) {
			path := filepath.Join(b.TempDir(), "cll.jsonl")
			require.NoError(b, Init(path))
			store, err := Open(path)
			require.NoError(b, err)
			b.Cleanup(func() { require.NoError(b, store.Close()) })
			tree, err := mmr.New(nil)
			require.NoError(b, err)
			var committed uint64
			for sequence := uint64(1); sequence <= entries; sequence++ {
				value := make([]byte, cll.EntryBytes)
				binary.BigEndian.PutUint64(value[cll.EntryBytes-8:], sequence)
				_, err = tree.Append(value)
				require.NoError(b, err)
				if sequence%4096 == 0 || sequence == entries {
					next := cll.State{Size: tree.Size(), Nodes: tree.Nodes(), IndexedSeq: sequence}
					require.NoError(b, store.CommitCLL(b.Context(), committed, nil, next))
					committed = next.Size
				}
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := store.LoadCLL(b.Context())
				require.NoError(b, err)
			}
		})
	}
}

func sizeName(n uint64) string {
	switch n {
	case 1 << 10:
		return "1Ki"
	case 1 << 14:
		return "16Ki"
	case 1 << 17:
		return "128Ki"
	}
	return "1Mi"
}

func TestLoadCLLSnapshotIsolatedAndLockFree(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cll.jsonl")
	require.NoError(t, Init(path))
	store, err := Open(path)
	require.NoError(t, err)
	tree, err := mmr.New(nil)
	require.NoError(t, err)
	commit := func(sequence uint64, expected uint64) {
		value := make([]byte, cll.EntryBytes)
		binary.BigEndian.PutUint64(value[cll.EntryBytes-8:], sequence)
		_, err := tree.Append(value)
		require.NoError(t, err)
		require.NoError(t, store.CommitCLL(t.Context(), expected, nil, cll.State{Size: tree.Size(), Nodes: tree.Nodes(), IndexedSeq: sequence}))
	}
	commit(1, 0)
	first, err := store.LoadCLL(t.Context())
	require.NoError(t, err)
	want := append([]byte(nil), first.Nodes[0]...)
	first.Nodes[0][0] ^= 0xff // a caller owns its copy
	again, err := store.LoadCLL(t.Context())
	require.NoError(t, err)
	require.Equal(t, want, again.Nodes[0])

	// A writer holding the lock does not block LoadCLL.
	store.mu.Lock()
	loaded, err := store.LoadCLL(t.Context())
	store.mu.Unlock()
	require.NoError(t, err)
	require.Equal(t, uint64(1), loaded.Size)

	// A failed commit leaves the published state unchanged.
	require.ErrorIs(t, store.CommitCLL(t.Context(), 99, nil, cll.State{}), cll.ErrContention)
	after, err := store.LoadCLL(t.Context())
	require.NoError(t, err)
	require.Equal(t, loaded, after)

	require.NoError(t, store.Close())
	_, err = store.LoadCLL(t.Context())
	require.ErrorIs(t, err, cll.ErrClosed)
}

func TestLoadCLLConcurrentWithCommits(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cll.jsonl")
	require.NoError(t, Init(path))
	store, err := Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	done := make(chan struct{})
	errs := make(chan error, 4)
	for range 4 {
		go func() {
			for {
				select {
				case <-done:
					errs <- nil
					return
				default:
				}
				state, err := store.LoadCLL(t.Context())
				if err == nil && uint64(len(state.Nodes)) != state.Size {
					err = cll.ErrCorrupt
				}
				if err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	tree, err := mmr.New(nil)
	require.NoError(t, err)
	var size uint64
	for sequence := uint64(1); sequence <= 200; sequence++ {
		value := make([]byte, cll.EntryBytes)
		binary.BigEndian.PutUint64(value[cll.EntryBytes-8:], sequence)
		_, err = tree.Append(value)
		require.NoError(t, err)
		next := cll.State{Size: tree.Size(), Nodes: tree.Nodes(), IndexedSeq: sequence}
		require.NoError(t, store.CommitCLL(t.Context(), size, nil, next))
		size = next.Size
	}
	close(done)
	for range 4 {
		require.NoError(t, <-errs)
	}
}
