package neon

import (
	"context"
	"crypto/tls"
	"errors"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const (
	sqlConnectTimeout   = 10 * time.Second
	sqlCloseTimeout     = 5 * time.Second
	sqlStatementTimeout = "15000" // milliseconds
	sqlLockTimeout      = "5000"  // ALTER ... OWNER must not queue behind app traffic
	sqlIdleTimeout      = "30000"
)

// neonDatabaseHost accepts Neon compute endpoint hosts such as
// "ep-cool-1234.us-east-2.aws.neon.tech". The owner's password is never sent
// anywhere else.
var neonDatabaseHost = regexp.MustCompile(`^ep-[a-z0-9-]{1,60}(?:\.[a-z0-9-]{1,63}){1,6}\.neon\.tech$`)

// uriAllowedKeys are the only connection-string keys accepted from a Neon
// URI. Anything else (options, sslrootcert, passfile, target_session_attrs,
// service, ...) is refused before pgx touches the filesystem or network.
var uriAllowedKeys = []string{"host", "port", "user", "password", "dbname", "sslmode", "channel_binding"}

var (
	errSQLConfig      = errors.New("SQL_CONNECT")
	errSQLTooManyRows = errors.New("SQL_TOO_MANY_ROWS")
)

// neonPostgresConfig builds a pgx config from a Neon URI with TLS
// verify-full against the system roots, SCRAM channel binding, no fallbacks,
// bounded timeouts and an allow-listed host. readOnly makes every
// transaction read-only.
//
// pgx only accepts the URI as a Go string and keeps the password in its
// Config as a string; Go strings are immutable and cannot be wiped, so wiping
// the caller's byte slice is best-effort: copies inside pgx live until
// collected.
func neonPostgresConfig(uri []byte, readOnly bool, allowHost func(string) bool) (*pgx.ConnConfig, error) {
	if !validPostgresURI(uri) || poolerHost(uri) {
		return nil, errSQLConfig
	}
	config, err := pgx.ParseConfigWithOptions(string(uri), pgx.ParseConfigOptions{
		ParseConfigOptions: pgconn.ParseConfigOptions{ConnStringAllowedKeys: uriAllowedKeys}})
	if err != nil {
		// ParseConfigError embeds the connection string; never surface it.
		return nil, errSQLConfig
	}
	if len(config.Fallbacks) != 0 || config.Password == "" || config.User == "" || config.Database == "" ||
		allowHost == nil || !allowHost(config.Host) {
		return nil, errSQLConfig
	}
	config.TLSConfig = &tls.Config{ServerName: config.Host, MinVersion: tls.VersionTLS12}
	config.Fallbacks = nil
	config.SSLNegotiation = "postgres"
	config.SSLCertMode = "disable"
	config.ChannelBinding = "require"
	config.ConnectTimeout = sqlConnectTimeout
	config.KerberosSrvName = ""
	config.KerberosSpn = ""
	config.AfterNetConnect = nil
	config.ValidateConnect = nil
	config.OnNotice = nil
	config.OnNotification = nil
	config.Tracer = nil
	config.StatementCacheCapacity = 0
	config.DescriptionCacheCapacity = 0
	config.DefaultQueryExecMode = pgx.QueryExecModeDescribeExec
	// Replace, do not merge: environment variables such as PGOPTIONS or
	// PGAPPNAME must not add server settings.
	config.RuntimeParams = map[string]string{
		"application_name":                    "envbank",
		"search_path":                         "pg_catalog, pg_temp",
		"statement_timeout":                   sqlStatementTimeout,
		"lock_timeout":                        sqlLockTimeout,
		"idle_in_transaction_session_timeout": sqlIdleTimeout,
	}
	if readOnly {
		config.RuntimeParams["default_transaction_read_only"] = "on"
	}
	return config, nil
}

func connectNeonPostgres(ctx context.Context, uri []byte, readOnly bool) (sqlSession, error) {
	config, err := neonPostgresConfig(uri, readOnly, neonDatabaseHost.MatchString)
	if err != nil {
		return nil, err
	}
	return connectPostgres(ctx, config)
}

func connectPostgres(ctx context.Context, config *pgx.ConnConfig) (sqlSession, error) {
	connectCtx, cancel := context.WithTimeout(ctx, sqlConnectTimeout)
	defer cancel()
	conn, err := pgx.ConnectConfig(connectCtx, config)
	if err != nil {
		return nil, err
	}
	return &pgxSession{conn: conn}, nil
}

type pgxSession struct{ conn *pgx.Conn }

func (session *pgxSession) Exec(ctx context.Context, statement string, args ...any) error {
	_, err := session.conn.Exec(ctx, statement, args...)
	return err
}

func (session *pgxSession) Query(ctx context.Context, statement string, args ...any) ([][]string, error) {
	rows, err := session.conn.Query(ctx, statement, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result [][]string
	for rows.Next() {
		if len(result) >= maxQueryRows {
			return nil, errSQLTooManyRows
		}
		count := len(rows.FieldDescriptions())
		values := make([]string, count)
		targets := make([]any, count)
		for index := range values {
			targets[index] = &values[index]
		}
		if err := rows.Scan(targets...); err != nil {
			return nil, err
		}
		result = append(result, values)
	}
	return result, rows.Err()
}

func (session *pgxSession) Close(ctx context.Context) error { return session.conn.Close(ctx) }
