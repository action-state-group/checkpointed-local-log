package mysql

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/action-state-group/cll-go/cll"
	"github.com/action-state-group/cll-go/internal/storetest"
	mysqldriver "github.com/go-sql-driver/mysql"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	containermysql "github.com/testcontainers/testcontainers-go/modules/mysql"
)

func TestContractAndCrossHandle(t *testing.T) {
	dsn, terminate := startMySQL(t)
	t.Cleanup(terminate)
	require.NoError(t, Init(t.Context(), dsn, "contract"))
	store, err := Open(t.Context(), dsn, "contract")
	require.NoError(t, err)
	storetest.Run(t, store)

	require.NoError(t, Init(t.Context(), dsn, "shared"))
	first, err := Open(t.Context(), dsn, "shared")
	require.NoError(t, err)
	second, err := Open(t.Context(), dsn, "shared")
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, first.Close())
		require.NoError(t, second.Close())
	})
	storetest.CrossHandle(t, first, second)
}

func TestApplicationTableCoexistence(t *testing.T) {
	dsn, terminate := startMySQL(t)
	t.Cleanup(terminate)
	db, err := sql.Open("mysql", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	storetest.SQLApplicationTableCoexistence(t, db, func(logID string) (cll.Backend, error) {
		if err := Init(t.Context(), dsn, logID); err != nil {
			return nil, err
		}
		return Open(t.Context(), dsn, logID)
	})
}

func TestClassifyContention(t *testing.T) {
	for _, number := range []uint16{1062, 1205, 1213} {
		err := classify(&mysqldriver.MySQLError{Number: number, Message: "contention"})
		require.ErrorIs(t, err, cll.ErrContention)
	}
}

func startMySQL(t *testing.T) (string, func()) {
	t.Helper()
	if os.Getenv("CI") == "" {
		testcontainers.SkipIfProviderIsNotHealthy(t)
	}
	container, err := containermysql.Run(t.Context(), "mysql:8.0.36",
		containermysql.WithDatabase("cll"),
		containermysql.WithUsername("cll"),
		containermysql.WithPassword("password"),
	)
	require.NoError(t, err)
	terminate := func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		require.NoError(t, container.Terminate(ctx))
	}
	return container.MustConnectionString(t.Context()), terminate
}
