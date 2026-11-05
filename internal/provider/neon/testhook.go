package neon

import (
	"context"
	"errors"
	"testing"
)

// SQLSession is the Postgres surface rotation-role setup uses (see
// sqlSession), exported only for SetSQLConnectorForTest.
type SQLSession = sqlSession

// SetSQLConnectorForTest replaces how adapter opens Postgres sessions, so a
// synthetic end-to-end test in another package can run the rotation-role SQL
// against a fake (or a local Postgres) instead of a Neon compute endpoint.
// It refuses outside a test binary (testing.Testing), so no production code
// path, flag or agent input can redirect the owner's connection URI.
func SetSQLConnectorForTest(adapter *Adapter, connect func(ctx context.Context, uri []byte, readOnly bool) (SQLSession, error)) error {
	if !testing.Testing() {
		return errors.New("neon: the SQL connector can only be replaced in tests")
	}
	if adapter == nil || connect == nil {
		return errors.New("neon: adapter and connector are required")
	}
	adapter.sqlConnect = connect
	return nil
}
