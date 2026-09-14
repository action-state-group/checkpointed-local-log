package mysql

import (
	"database/sql"
	"testing"
	"time"

	"github.com/action-state-group/cll-go/cll"
	mysqldriver "github.com/go-sql-driver/mysql"
	"github.com/stretchr/testify/require"
)

func TestExplicitInitializationAndSelectOnlyOpen(t *testing.T) {
	dsn, terminate := startMySQL(t)
	t.Cleanup(terminate)
	db, err := sql.Open("mysql", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	_, err = Open(t.Context(), dsn, "existing")
	require.Error(t, err)
	var count int
	require.NoError(t, db.QueryRow("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name LIKE 'cll_%'").Scan(&count))
	require.Zero(t, count, "Open must not create schema")
	// Simulate a setup process interrupted after the first DDL statement.
	_, err = db.Exec(schemaStatements[0])
	require.NoError(t, err)
	require.NoError(t, Init(t.Context(), dsn, "existing"))
	require.NoError(t, Init(t.Context(), dsn, "existing"))
	store, err := Open(t.Context(), dsn, "existing")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	_, err = store.Append(t.Context(), cll.AppendInput{Value: make([]byte, 32), AppendedAt: time.Now().UTC()})
	require.NoError(t, err)
	_, err = Open(t.Context(), dsn, "missing")
	require.Error(t, err)
	require.NoError(t, db.QueryRow("SELECT COUNT(*) FROM cll_meta").Scan(&count))
	require.Equal(t, 1, count, "Open must not insert log metadata")
	cfg, err := mysqldriver.ParseDSN(dsn)
	require.NoError(t, err)
	cfg.User = "root"
	admin, err := sql.Open("mysql", cfg.FormatDSN())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, admin.Close()) })
	_, err = admin.Exec("CREATE USER 'cll_reader'@'%' IDENTIFIED BY 'isolated-reader'")
	require.NoError(t, err)
	_, err = admin.Exec("GRANT SELECT ON cll.* TO 'cll_reader'@'%'")
	require.NoError(t, err)
	cfg.User, cfg.Passwd = "cll_reader", "isolated-reader"
	reader, err := Open(t.Context(), cfg.FormatDSN(), "existing")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, reader.Close()) })
	entries, err := reader.ScanEntries(t.Context(), 0, 10)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	require.Error(t, Init(t.Context(), cfg.FormatDSN(), "existing"))
}
