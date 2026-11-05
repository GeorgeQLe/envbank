package neon

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// TestRotationRolesAgainstPostgres runs the rotation-role SQL against a real
// PostgreSQL 16+ server. It is skipped unless ENVBANK_TEST_POSTGRES_URL names
// a superuser connection to a disposable local cluster: it creates
// cluster-wide roles (including envbank_app_owner) and a scratch database,
// and drops them afterwards.
//
// It mimics Neon: a non-superuser CREATEROLE owner role owns the database and
// runs the setup; the login roles are created by that owner (so it holds
// ADMIN on them, which ALTER ROLE ... SET requires on PostgreSQL 16+).
func TestRotationRolesAgainstPostgres(t *testing.T) {
	adminURL := os.Getenv("ENVBANK_TEST_POSTGRES_URL")
	if adminURL == "" {
		t.Skip("ENVBANK_TEST_POSTGRES_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	const (
		owner = "envbank_it_owner"
		appA  = "envbank_it_app_a"
		appB  = "envbank_it_app_b"
	)
	roles := [2]string{appA, appB}
	suffix := make([]byte, 4)
	_, _ = rand.Read(suffix)
	database := "envbank_it_" + hex.EncodeToString(suffix)
	password := hex.EncodeToString(append(suffix, suffix...))

	admin := connectTestURL(t, ctx, adminURL, "", "", "")
	// Registered first so it runs last, after the cleanups that use admin.
	t.Cleanup(func() { _ = admin.Close(context.Background()) })
	var exists bool
	if err := admin.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = ANY ($1::text[]))",
		[]string{RotationGroupRole, owner, appA, appB}).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Skip("rotation test roles already exist on this server; use a disposable cluster")
	}
	mustExec(t, ctx, admin, "CREATE ROLE "+quoteIdent(owner)+" LOGIN CREATEROLE PASSWORD '"+password+"'")
	mustExec(t, ctx, admin, "CREATE DATABASE "+quoteIdent(database)+" OWNER "+quoteIdent(owner))
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, _ = admin.Exec(cleanup, "DROP DATABASE IF EXISTS "+quoteIdent(database)+" WITH (FORCE)")
		for _, role := range []string{appA, appB, RotationGroupRole, owner} {
			_, _ = admin.Exec(cleanup, "DROP ROLE IF EXISTS "+quoteIdent(role))
		}
	})

	ownerConn := connectTestURL(t, ctx, adminURL, owner, password, database)
	defer ownerConn.Close(context.Background())
	for _, role := range roles {
		mustExec(t, ctx, ownerConn, "CREATE ROLE "+quoteIdent(role)+" LOGIN PASSWORD '"+password+"'")
	}
	// Pre-existing objects from before the group existed: some owned by the
	// owner role, one created by app_a directly.
	mustExec(t, ctx, ownerConn, "GRANT CREATE ON SCHEMA public TO "+quoteIdent(appA))
	mustExec(t, ctx, ownerConn, `CREATE TABLE legacy_owner (id serial PRIMARY KEY, note text)`)
	mustExec(t, ctx, ownerConn, `CREATE TABLE "Mixed Case" (id int GENERATED ALWAYS AS IDENTITY, v text)`)
	mustExec(t, ctx, ownerConn, `CREATE SEQUENCE standalone_seq`)
	mustExec(t, ctx, ownerConn, `CREATE VIEW legacy_view AS SELECT id, note FROM legacy_owner`)
	mustExec(t, ctx, ownerConn, `CREATE MATERIALIZED VIEW legacy_mat AS SELECT count(*) AS n FROM legacy_owner`)
	mustExec(t, ctx, ownerConn, `CREATE FUNCTION add_note(integer, character varying) RETURNS text LANGUAGE sql AS $$ SELECT $2 || $1::text $$`)
	appAConn := connectTestURL(t, ctx, adminURL, appA, password, database)
	mustExec(t, ctx, appAConn, `CREATE TABLE legacy_a (id int)`)
	appAConn.Close(ctx)

	prepare := func() error {
		session := &pgxSession{conn: connectTestURL(t, ctx, adminURL, owner, password, database)}
		defer closeSession(session)
		return prepareRotationSQL(ctx, "rotation_roles_prepare", session, database, owner, roles, true)
	}
	if err := prepare(); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	// Idempotent: a second run succeeds and changes nothing material.
	if err := prepare(); err != nil {
		t.Fatalf("second prepare: %v", err)
	}
	check := &pgxSession{conn: connectTestURL(t, ctx, adminURL, owner, password, database)}
	mustExec(t, ctx, check.conn, "SET default_transaction_read_only = on")
	if err := checkSessionIdentity(ctx, "rotation_roles_check", check, database, owner); err != nil {
		t.Fatal(err)
	}
	ready, err := rotationReady(ctx, "rotation_roles_check", check, roles)
	closeSession(check)
	if err != nil || !ready {
		t.Fatalf("ready=%v err=%v", ready, err)
	}

	// app_a's sessions act as the group and create group-owned objects.
	appAConn = connectTestURL(t, ctx, adminURL, appA, password, database)
	if current := queryText(t, ctx, appAConn, "SELECT current_user::text"); current != RotationGroupRole {
		t.Fatalf("app_a session acts as %s", current)
	}
	mustExec(t, ctx, appAConn, `CREATE TABLE created_by_a (id bigserial PRIMARY KEY, v text)`)
	mustExec(t, ctx, appAConn, `INSERT INTO created_by_a (v) VALUES ('a')`)
	appAConn.Close(ctx)

	// After the switch, app_b can use and alter everything.
	appBConn := connectTestURL(t, ctx, adminURL, appB, password, database)
	defer appBConn.Close(context.Background())
	if current := queryText(t, ctx, appBConn, "SELECT current_user::text"); current != RotationGroupRole {
		t.Fatalf("app_b session acts as %s", current)
	}
	for _, statement := range []string{
		`INSERT INTO created_by_a (v) VALUES ('b')`,
		`ALTER TABLE created_by_a ADD COLUMN extra int`,
		`INSERT INTO legacy_a VALUES (1)`,
		`ALTER TABLE legacy_a ADD COLUMN extra int`,
		`INSERT INTO legacy_owner (note) VALUES ('b')`,
		`INSERT INTO "Mixed Case" (v) VALUES ('b')`,
		`SELECT nextval('standalone_seq')`,
		`SELECT * FROM legacy_view`,
		`REFRESH MATERIALIZED VIEW legacy_mat`,
		`SELECT add_note(1, 'n')`,
		`CREATE OR REPLACE FUNCTION add_note(integer, character varying) RETURNS text LANGUAGE sql AS $$ SELECT $2 $$`,
	} {
		mustExec(t, ctx, appBConn, statement)
	}
	if count := queryText(t, ctx, appBConn, "SELECT count(*)::text FROM created_by_a"); count != "2" {
		t.Fatalf("created_by_a rows = %s", count)
	}

	// Nothing in public is left owned by the old roles; the database owner is
	// unchanged.
	ownerConn2 := connectTestURL(t, ctx, adminURL, owner, password, database)
	defer ownerConn2.Close(context.Background())
	if leftovers := queryText(t, ctx, ownerConn2, `SELECT count(*)::text FROM (
		SELECT relowner AS o FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		  WHERE n.nspname = 'public' AND c.relkind IN ('r','p','S','v','m')
		UNION ALL SELECT proowner FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'public'
		UNION ALL SELECT nspowner FROM pg_namespace WHERE nspname = 'public') x
		WHERE pg_get_userbyid(o) <> 'envbank_app_owner'`); leftovers != "0" {
		t.Fatalf("%s public objects not owned by the group", leftovers)
	}
	if dbOwner := queryText(t, ctx, ownerConn2, "SELECT pg_get_userbyid(datdba)::text FROM pg_database WHERE datname = current_database()"); dbOwner != owner {
		t.Fatalf("database owner changed to %s", dbOwner)
	}

	// Without ADMIN on a login role (for example one created by another
	// role), ALTER ROLE ... SET is refused and the transaction rolls back.
	mustExec(t, ctx, admin, "CREATE ROLE envbank_it_foreign LOGIN")
	t.Cleanup(func() { _, _ = admin.Exec(context.Background(), "DROP ROLE IF EXISTS envbank_it_foreign") })
	session := &pgxSession{conn: connectTestURL(t, ctx, adminURL, owner, password, database)}
	err = prepareRotationSQL(ctx, "rotation_roles_prepare", session, database, owner, [2]string{appA, "envbank_it_foreign"}, false)
	closeSession(session)
	expectCode(t, err, "SQL_PERMISSION")
}

func connectTestURL(t *testing.T, ctx context.Context, base, user, password, database string) *pgx.Conn {
	t.Helper()
	parsed, err := url.Parse(base)
	if err != nil {
		t.Fatal("ENVBANK_TEST_POSTGRES_URL is not a URL")
	}
	if user != "" {
		parsed.User = url.UserPassword(user, password)
	}
	if database != "" {
		parsed.Path = "/" + database
	}
	config, err := pgx.ParseConfig(parsed.String())
	if err != nil {
		t.Fatal("test connection URL is invalid")
	}
	config.DefaultQueryExecMode = pgx.QueryExecModeDescribeExec
	session, err := connectPostgres(ctx, config)
	if err != nil {
		t.Fatalf("connect as %q: %v", user, sqlError("test", err, true))
	}
	return session.(*pgxSession).conn
}

func mustExec(t *testing.T, ctx context.Context, conn *pgx.Conn, statement string) {
	t.Helper()
	if _, err := conn.Exec(ctx, statement); err != nil {
		t.Fatalf("%s: %v", statement, err)
	}
}

func queryText(t *testing.T, ctx context.Context, conn *pgx.Conn, statement string) string {
	t.Helper()
	var value string
	if err := conn.QueryRow(ctx, statement).Scan(&value); err != nil {
		t.Fatalf("%s: %v", statement, err)
	}
	return value
}
