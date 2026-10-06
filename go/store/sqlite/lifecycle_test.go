package sqlite

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOpenDoesNotInitialize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lifecycle.sqlite")
	_, err := Open(path, "existing")
	require.Error(t, err)
	_, err = os.Stat(path)
	require.ErrorIs(t, err, os.ErrNotExist)
	partial, err := sql.Open("sqlite", path)
	require.NoError(t, err)
	_, err = partial.Exec("CREATE TABLE cll_meta (log_id TEXT PRIMARY KEY, state BLOB NOT NULL)")
	require.NoError(t, err)
	require.NoError(t, partial.Close())
	require.NoError(t, Init(path, "existing"))
	require.NoError(t, Init(path, "existing"))
	store, err := Open(path, "existing")
	require.NoError(t, err)
	require.NoError(t, store.Close())
	_, err = Open(path, "missing")
	require.Error(t, err)
	db, err := sql.Open("sqlite", path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	var count int
	require.NoError(t, db.QueryRow("SELECT COUNT(*) FROM cll_meta").Scan(&count))
	require.Equal(t, 1, count)
}
