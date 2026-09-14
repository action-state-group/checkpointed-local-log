package jsonl

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOpenDoesNotInitialize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lifecycle.jsonl")
	_, err := Open(path)
	require.ErrorIs(t, err, os.ErrNotExist)
	_, err = os.Stat(path)
	require.ErrorIs(t, err, os.ErrNotExist)
	require.NoError(t, os.WriteFile(path, nil, 0600))
	_, err = Open(path)
	require.Error(t, err)
	before, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Empty(t, before)
	require.NoError(t, Init(path))
	before, err = os.ReadFile(path)
	require.NoError(t, err)
	require.Contains(t, string(before), "cll.init")
	require.NoError(t, Init(path))
	store, err := Open(path)
	require.NoError(t, err)
	require.NoError(t, store.Close())
	after, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, before, after)
}
