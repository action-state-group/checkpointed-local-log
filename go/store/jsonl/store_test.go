package jsonl

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/action-state-group/cll-go/cll"
	"github.com/action-state-group/cll-go/internal/storetest"
	"github.com/action-state-group/cll-go/mmr"
	"github.com/stretchr/testify/require"
)

func TestContractAndReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cll.jsonl")
	require.NoError(t, Init(path))
	store, err := Open(path)
	require.NoError(t, err)
	storetest.Run(t, store)

	reopened, err := Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, reopened.Close()) })
	entries, err := reopened.ScanEntries(t.Context(), 0, 10)
	require.NoError(t, err)
	require.Len(t, entries, 2)
	state, err := reopened.LoadCLL(t.Context())
	require.NoError(t, err)
	require.Equal(t, uint64(2), state.IndexedSeq)
}

func TestWriterLockAndTornTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cll.jsonl")
	require.NoError(t, Init(path))
	first, err := Open(path)
	require.NoError(t, err)
	_, err = Open(path)
	require.ErrorIs(t, err, cll.ErrContention)
	require.NoError(t, first.Close())

	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	require.NoError(t, err)
	_, err = file.WriteString("{torn")
	require.NoError(t, err)
	require.NoError(t, file.Close())
	_, err = Open(path)
	require.ErrorIs(t, err, cll.ErrCorrupt)
	require.NoError(t, Init(path))
	reopened, err := Open(path)
	require.NoError(t, err)
	require.NoError(t, reopened.Close())
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NotContains(t, string(data), "{torn")
}

func TestRejectsLegacyAndCompleteCorruption(t *testing.T) {
	for name, data := range map[string]string{
		"legacy":  "{\"version\":3,\"type\":\"log.init\"}\n",
		"corrupt": "{\"version\":4,\"type\":\"cll.init\"}\n{not-json}\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "cll.jsonl")
			require.NoError(t, os.WriteFile(path, []byte(data), 0o600))
			store, err := Open(path)
			require.Nil(t, store)
			require.ErrorIs(t, err, cll.ErrCorrupt)
		})
	}
}

func TestCLLCommitStoresOnlyNodeDelta(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cll.jsonl")
	require.NoError(t, Init(path))
	store, err := Open(path)
	require.NoError(t, err)
	nodes := make([][]byte, 127)
	for index := range nodes {
		nodes[index] = storetest.Value(byte(index))
	}
	require.NoError(t, store.CommitCLL(t.Context(), 0, nil, cll.State{Size: 127, Nodes: nodes, IndexedSeq: 64}))
	next := append(append([][]byte(nil), nodes...), storetest.Value(128))
	require.NoError(t, store.CommitCLL(t.Context(), 127, nil, cll.State{Size: 128, Nodes: next, IndexedSeq: 65}))
	require.NoError(t, store.Close())
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	require.Len(t, lines, 3)
	require.Less(t, len(lines[2]), len(lines[1])/2)
}

func TestReplayManyCLLCommitDeltas(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cll.jsonl")
	require.NoError(t, Init(path))
	store, err := Open(path)
	require.NoError(t, err)
	tree, err := mmr.New(nil)
	require.NoError(t, err)
	started := contractReplayTime()
	var size uint64
	for sequence := uint64(1); sequence <= 256; sequence++ {
		value := make([]byte, cll.EntryBytes)
		binary.BigEndian.PutUint64(value[cll.EntryBytes-8:], sequence)
		_, err = store.Append(t.Context(), cll.AppendInput{Value: value, AppendedAt: started})
		require.NoError(t, err)
		_, err = tree.Append(value)
		require.NoError(t, err)
		next := cll.State{Size: tree.Size(), Nodes: tree.Nodes(), IndexedSeq: sequence}
		require.NoError(t, store.CommitCLL(t.Context(), size, nil, next))
		size = next.Size
	}
	require.NoError(t, store.Close())

	reopened, err := Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, reopened.Close()) })
	state, err := reopened.LoadCLL(t.Context())
	require.NoError(t, err)
	require.Equal(t, uint64(256), state.IndexedSeq)
	require.Equal(t, size, state.Size)
}

func contractReplayTime() time.Time {
	return time.Date(2026, time.September, 3, 12, 0, 0, 0, time.UTC)
}

func TestCloseAfterOpenFailureReleasesLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cll.jsonl")
	require.NoError(t, os.WriteFile(path, []byte("{not-json}\n"), 0o600))
	_, err := Open(path)
	require.True(t, errors.Is(err, cll.ErrCorrupt))
}
