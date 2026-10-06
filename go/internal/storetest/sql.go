package storetest

import (
	"database/sql"
	"testing"

	"github.com/action-state-group/cll-go/cll"
	"github.com/stretchr/testify/require"
)

// SQLApplicationTableCoexistence checks isolation from application tables and
// other logs. It requires a disposable database: the final checks deliberately
// corrupt CLL metadata and replace its table shape without deleting old rows.
func SQLApplicationTableCoexistence(t *testing.T, db *sql.DB, open func(string) (cll.Backend, error)) {
	t.Helper()
	ctx := t.Context()
	existing, err := open("existing")
	require.NoError(t, err)
	// Run populates entries, nodes, checkpoints and witness receipts, then closes.
	Run(t, existing)
	queries := []string{
		"SELECT * FROM cll_meta WHERE log_id='existing' ORDER BY log_id",
		"SELECT * FROM cll_entries WHERE log_id='existing' ORDER BY seq",
		"SELECT * FROM cll_nodes WHERE log_id='existing' ORDER BY position",
		"SELECT * FROM cll_witnesses WHERE log_id='existing' ORDER BY witness_id,checkpoint_size",
	}
	for _, statement := range []string{
		"CREATE TABLE ledger_metadata(id INTEGER PRIMARY KEY, marker VARCHAR(32))",
		"INSERT INTO ledger_metadata(id,marker) VALUES(1,'application-owned')",
		"CREATE TABLE schema_metadata(singleton INTEGER PRIMARY KEY, version INTEGER)",
		"INSERT INTO schema_metadata(singleton,version) VALUES(1,3)",
	} {
		_, err := db.ExecContext(ctx, statement)
		require.NoError(t, err)
	}
	queries = append(queries, "SELECT * FROM ledger_metadata ORDER BY id", "SELECT * FROM schema_metadata ORDER BY singleton")
	before := make([][][]string, len(queries))
	for i, query := range queries {
		before[i] = sqlRows(t, db, query)
		require.NotEmpty(t, before[i])
	}
	fresh, err := open("fresh")
	require.NoError(t, err)
	Run(t, fresh)
	reopened, err := open("existing")
	require.NoError(t, err)
	require.NoError(t, reopened.Close())
	for i, query := range queries {
		require.Equal(t, before[i], sqlRows(t, db, query), query)
	}

	// Coexistence must not silently replace a corrupt requested log with empty state.
	corrupt := []byte(`{"size":"unsupported","indexedSeq":"0","nodes":[],"witnesses":[]}`)
	_, err = db.ExecContext(ctx, "UPDATE cll_meta SET state=? WHERE log_id=?", corrupt, "existing")
	require.NoError(t, err)
	failed, err := open("existing")
	require.Nil(t, failed)
	require.ErrorIs(t, err, cll.ErrCorrupt)
	var retained []byte
	require.NoError(t, db.QueryRowContext(ctx, "SELECT state FROM cll_meta WHERE log_id=?", "existing").Scan(&retained))
	require.Equal(t, corrupt, retained)
	for i := 1; i < len(queries); i++ {
		require.Equal(t, before[i], sqlRows(t, db, queries[i]), queries[i])
	}

	// An incompatible shape in the actual CLL namespace must still fail. Retain
	// the original table rather than dropping existing commitments, even in tests.
	_, err = db.ExecContext(ctx, "ALTER TABLE cll_meta RENAME TO preserved_cll_meta")
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, "CREATE TABLE cll_meta(log_id VARCHAR(191) PRIMARY KEY, unsupported INTEGER)")
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, "INSERT INTO cll_meta(log_id,unsupported) VALUES('unsupported',99)")
	require.NoError(t, err)
	failed, err = open("unsupported")
	require.Nil(t, failed)
	require.Error(t, err)
	require.Equal(t, [][]string{{"unsupported", "99"}}, sqlRows(t, db, "SELECT * FROM cll_meta ORDER BY log_id"))
}

// sqlRows copies raw SQL values before advancing rows, comparing persisted
// encodings rather than only decoded logical CLL state.
func sqlRows(t *testing.T, db *sql.DB, query string) [][]string {
	t.Helper()
	rows, err := db.QueryContext(t.Context(), query)
	require.NoError(t, err)
	defer func() { require.NoError(t, rows.Close()) }()
	columns, err := rows.Columns()
	require.NoError(t, err)
	var result [][]string
	for rows.Next() {
		values := make([]sql.RawBytes, len(columns))
		targets := make([]any, len(columns))
		for i := range values {
			targets[i] = &values[i]
		}
		require.NoError(t, rows.Scan(targets...))
		copied := make([]string, len(values))
		for i, value := range values {
			copied[i] = string(value)
		}
		result = append(result, copied)
	}
	require.NoError(t, rows.Err())
	return result
}
