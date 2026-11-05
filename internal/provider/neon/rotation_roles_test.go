package neon

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/GeorgeQLe/envbank/internal/provider"
)

type sqlCall struct {
	Statement string
	Args      []any
}

// fakeSQL scripts query results by statement and records everything run.
type fakeSQL struct {
	mu        sync.Mutex
	calls     []sqlCall
	results   map[string][][]string
	failOn    string
	failWith  error
	closed    bool
	uris      [][]byte
	readOnly  []bool
	connected int
}

func newFakeSQL() *fakeSQL {
	return &fakeSQL{results: map[string][][]string{
		sqlIdentity:       {{testRole, testDB, "170005"}},
		sqlGroupState:     nil,
		sqlReadiness:      {{"true", "true", "2"}},
		sqlAdoptRelations: nil,
		sqlAdoptFunctions: nil,
		sqlHasPrivileges:  {{"false"}},
	}}
}

func (fake *fakeSQL) connector(t *testing.T) sqlConnector {
	return func(_ context.Context, uri []byte, readOnly bool) (sqlSession, error) {
		fake.mu.Lock()
		defer fake.mu.Unlock()
		if string(uri) != directURI {
			t.Errorf("connector did not receive the owner's direct URI")
		}
		// Keep the caller's slice (not a copy) to prove it is wiped later.
		fake.uris = append(fake.uris, uri)
		fake.readOnly = append(fake.readOnly, readOnly)
		fake.connected++
		return fake, nil
	}
}

func (fake *fakeSQL) record(statement string, args []any) error {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.calls = append(fake.calls, sqlCall{Statement: statement, Args: args})
	if fake.failOn != "" && strings.HasPrefix(statement, fake.failOn) {
		return fake.failWith
	}
	return nil
}

func (fake *fakeSQL) Exec(_ context.Context, statement string, args ...any) error {
	return fake.record(statement, args)
}

func (fake *fakeSQL) Query(_ context.Context, statement string, args ...any) ([][]string, error) {
	if err := fake.record(statement, args); err != nil {
		return nil, err
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	rows, ok := fake.results[statement]
	if !ok {
		return nil, errors.New("unscripted query")
	}
	return rows, nil
}

func (fake *fakeSQL) Close(context.Context) error {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.closed = true
	return nil
}

func (fake *fakeSQL) statements() []string {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	out := make([]string, 0, len(fake.calls))
	for _, call := range fake.calls {
		out = append(out, call.Statement)
	}
	return out
}

func (fake *fakeSQL) assertURIsWiped(t *testing.T) {
	t.Helper()
	fake.mu.Lock()
	defer fake.mu.Unlock()
	for _, uri := range fake.uris {
		for _, value := range uri {
			if value != 0 {
				t.Fatal("owner connection URI was not wiped")
			}
		}
	}
}

var testLoginRoles = [2]string{"app_a", "app_b"}

func rotationFake(t *testing.T) (*fakeNeon, *Adapter, *fakeSQL) {
	t.Helper()
	fake := newFake(t)
	adapter := fake.adapter(t, Options{})
	for _, role := range testLoginRoles {
		fake.json(http.MethodGet, rolePath(role), 200, `{"role":{"name":"`+role+`","branch_id":"`+testBranch+`"}}`)
	}
	fake.handle(http.MethodGet, connectionURIPath(), func(response http.ResponseWriter, request *http.Request) {
		query := request.URL.Query()
		if query.Get("role_name") != testRole || query.Get("pooled") != "false" ||
			query.Get("branch_id") != testBranch || query.Get("database_name") != testDB {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = fmt.Fprintf(response, `{"uri":%s}`, jsonURI(directURI))
	})
	db := newFakeSQL()
	adapter.sqlConnect = db.connector(t)
	return fake, adapter, db
}

func TestPrepareRotationRolesStatementSequence(t *testing.T) {
	fake, adapter, db := rotationFake(t)
	if err := adapter.PrepareRotationRoles(context.Background(), testProject, testBranch, testDB, testRole, testLoginRoles, false); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"BEGIN",
		"SET LOCAL search_path = pg_catalog, pg_temp",
		sqlIdentity,
		sqlGroupState,
		`CREATE ROLE "envbank_app_owner" NOLOGIN`,
		`GRANT "envbank_app_owner" TO "neondb_owner" WITH INHERIT TRUE, SET TRUE`,
		`GRANT "envbank_app_owner" TO "app_a" WITH INHERIT TRUE, SET TRUE`,
		`GRANT "envbank_app_owner" TO "app_b" WITH INHERIT TRUE, SET TRUE`,
		`ALTER ROLE "app_a" SET role = 'envbank_app_owner'`,
		`ALTER ROLE "app_b" SET role = 'envbank_app_owner'`,
		`ALTER SCHEMA public OWNER TO "envbank_app_owner"`,
		sqlReadiness,
		"COMMIT",
	}
	if got := db.statements(); !reflect.DeepEqual(got, want) {
		t.Fatalf("statements:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if !reflect.DeepEqual(db.calls[3].Args, []any{RotationGroupRole}) ||
		!reflect.DeepEqual(db.calls[11].Args, []any{RotationGroupRole, []string{"app_a", "app_b"}, "role=envbank_app_owner"}) {
		t.Fatalf("query parameters: %#v %#v", db.calls[3].Args, db.calls[11].Args)
	}
	if !db.closed || len(db.readOnly) != 1 || db.readOnly[0] {
		t.Fatal("session was not opened read-write and closed")
	}
	db.assertURIsWiped(t)
	if fake.count(http.MethodPost, "/projects/"+testProject+"/branches/"+testBranch+"/roles") != 0 {
		t.Fatal("existing roles were recreated")
	}
}

func TestPrepareRotationRolesIsIdempotentForExistingGroup(t *testing.T) {
	_, adapter, db := rotationFake(t)
	db.results[sqlGroupState] = [][]string{{"false", "false"}}
	if err := adapter.PrepareRotationRoles(context.Background(), testProject, testBranch, testDB, testRole, testLoginRoles, false); err != nil {
		t.Fatal(err)
	}
	for _, statement := range db.statements() {
		if strings.HasPrefix(statement, "CREATE ROLE") {
			t.Fatal("existing group was recreated")
		}
	}

	for _, conflict := range [][]string{{"true", "false"}, {"false", "true"}} {
		db = newFakeSQL()
		db.results[sqlGroupState] = [][]string{conflict}
		adapter.sqlConnect = db.connector(t)
		expectCode(t, adapter.PrepareRotationRoles(context.Background(), testProject, testBranch, testDB, testRole, testLoginRoles, false), "GROUP_ROLE_CONFLICT")
		if last := db.statements()[len(db.statements())-1]; last != "ROLLBACK" {
			t.Fatalf("conflict did not roll back: %s", last)
		}
	}
}

func TestPrepareRotationRolesCreatesMissingLoginRoles(t *testing.T) {
	fake, adapter, _ := rotationFake(t)
	fake.json(http.MethodGet, rolePath("app_b"), 404, canary)
	fake.json(http.MethodPost, "/projects/"+testProject+"/branches/"+testBranch+"/roles", 201,
		`{"role":{"name":"app_b","branch_id":"`+testBranch+`","password":"`+canary+`"},"operations":[]}`)
	if err := adapter.PrepareRotationRoles(context.Background(), testProject, testBranch, testDB, testRole, testLoginRoles, false); err != nil {
		t.Fatal(err)
	}
	calls := fake.callsTo(http.MethodPost, "/projects/"+testProject+"/branches/"+testBranch+"/roles")
	if len(calls) != 1 || string(calls[0].Body) != `{"role":{"name":"app_b"}}` {
		t.Fatalf("role creation calls: %+v", calls)
	}

	// An API failure stops before any SQL and keeps its fixed code.
	fake.json(http.MethodGet, rolePath("app_a"), 403, canary)
	db := newFakeSQL()
	adapter.sqlConnect = db.connector(t)
	safe := expectCode(t, adapter.PrepareRotationRoles(context.Background(), testProject, testBranch, testDB, testRole, testLoginRoles, false), "FORBIDDEN")
	if safe.Operation != "rotation_roles_prepare" || db.connected != 0 {
		t.Fatalf("operation=%s connected=%d", safe.Operation, db.connected)
	}
}

func TestPrepareRotationRolesAdoptsOwnedObjects(t *testing.T) {
	_, adapter, db := rotationFake(t)
	db.results[sqlAdoptRelations] = [][]string{
		{"S", "standalone_seq"}, {"m", "report"}, {"p", "events"}, {"r", `odd"name; DROP TABLE x`}, {"v", "active_users"},
	}
	db.results[sqlAdoptFunctions] = [][]string{
		{"touch", ""}, {"score", "integer,character varying,timestamp with time zone,text[],public.mood,\"char\""},
	}
	if err := adapter.PrepareRotationRoles(context.Background(), testProject, testBranch, testDB, testRole, testLoginRoles, true); err != nil {
		t.Fatal(err)
	}
	statements := db.statements()
	start := -1
	for index, statement := range statements {
		if statement == sqlAdoptRelations {
			start = index
		}
	}
	if start < 0 || statements[start+1] != sqlAdoptFunctions {
		t.Fatalf("adoption queries missing: %v", statements)
	}
	if !reflect.DeepEqual(db.calls[start].Args, []any{[]string{testRole, "app_a", "app_b"}}) {
		t.Fatalf("adoption owners: %#v", db.calls[start].Args)
	}
	if statements[start-2] != sqlHasPrivileges || statements[start-1] != sqlHasPrivileges ||
		!reflect.DeepEqual(db.calls[start-2].Args, []any{"app_a"}) || !reflect.DeepEqual(db.calls[start-1].Args, []any{"app_b"}) {
		t.Fatalf("privilege checks missing: %v", statements[:start])
	}
	want := []string{
		`GRANT "app_a" TO "neondb_owner" WITH INHERIT TRUE, SET FALSE`,
		`GRANT "app_b" TO "neondb_owner" WITH INHERIT TRUE, SET FALSE`,
		`ALTER SEQUENCE "public"."standalone_seq" OWNER TO "envbank_app_owner"`,
		`ALTER MATERIALIZED VIEW "public"."report" OWNER TO "envbank_app_owner"`,
		`ALTER TABLE "public"."events" OWNER TO "envbank_app_owner"`,
		`ALTER TABLE "public"."odd""name; DROP TABLE x" OWNER TO "envbank_app_owner"`,
		`ALTER VIEW "public"."active_users" OWNER TO "envbank_app_owner"`,
		`ALTER FUNCTION "public"."touch"() OWNER TO "envbank_app_owner"`,
		`ALTER FUNCTION "public"."score"(integer,character varying,timestamp with time zone,text[],public.mood,"char") OWNER TO "envbank_app_owner"`,
		`REVOKE "app_a" FROM "neondb_owner"`,
		`REVOKE "app_b" FROM "neondb_owner"`,
		sqlReadiness,
		"COMMIT",
	}
	if got := statements[start+2:]; !reflect.DeepEqual(got, want) {
		t.Fatalf("adoption statements:\n%s", strings.Join(got, "\n"))
	}
	for _, statement := range statements {
		if strings.Contains(statement, "REASSIGN") || strings.Contains(statement, "DATABASE") {
			t.Fatalf("database-wide ownership change issued: %s", statement)
		}
	}
}

func TestPrepareRotationRolesAdoptSkipsTemporaryGrantWhenPrivileged(t *testing.T) {
	_, adapter, db := rotationFake(t)
	db.results[sqlHasPrivileges] = [][]string{{"true"}}
	db.results[sqlAdoptRelations] = [][]string{{"r", "t"}}
	if err := adapter.PrepareRotationRoles(context.Background(), testProject, testBranch, testDB, testRole, testLoginRoles, true); err != nil {
		t.Fatal(err)
	}
	for _, statement := range db.statements() {
		if strings.HasPrefix(statement, `GRANT "app_`) || strings.HasPrefix(statement, "REVOKE") {
			t.Fatalf("unneeded temporary grant: %s", statement)
		}
	}
	db = newFakeSQL()
	db.results[sqlHasPrivileges] = [][]string{{"maybe"}}
	adapter.sqlConnect = db.connector(t)
	expectCode(t, adapter.PrepareRotationRoles(context.Background(), testProject, testBranch, testDB, testRole, testLoginRoles, true), "SQL_INVALID_RESULT")
}

func TestPrepareRotationRolesRefusesUnsafeAdoptionInput(t *testing.T) {
	for _, arguments := range []string{`"Weird"`, "integer); DROP ROLE x; --", "text,", "public.\"T\"", "int\n"} {
		_, adapter, db := rotationFake(t)
		db.results[sqlAdoptFunctions] = [][]string{{"fn", arguments}}
		expectCode(t, adapter.PrepareRotationRoles(context.Background(), testProject, testBranch, testDB, testRole, testLoginRoles, true), "SQL_UNSUPPORTED_OBJECT")
		for _, statement := range db.statements() {
			if strings.HasPrefix(statement, "ALTER FUNCTION") || statement == "COMMIT" {
				t.Fatalf("unsafe arguments %q reached SQL", arguments)
			}
		}
	}
	_, adapter, db := rotationFake(t)
	db.results[sqlAdoptRelations] = [][]string{{"i", "some_index"}}
	expectCode(t, adapter.PrepareRotationRoles(context.Background(), testProject, testBranch, testDB, testRole, testLoginRoles, true), "SQL_INVALID_RESULT")
}

func TestPrepareRotationRolesValidation(t *testing.T) {
	fake, adapter, db := rotationFake(t)
	cases := []struct {
		project, branch, database, owner string
		roles                            [2]string
	}{
		{"Bad", testBranch, testDB, testRole, testLoginRoles},
		{testProject, "main", testDB, testRole, testLoginRoles},
		{testProject, testBranch, "postgres", testRole, testLoginRoles},
		{testProject, testBranch, testDB, "app_a", testLoginRoles},
		{testProject, testBranch, testDB, testRole, [2]string{"app_a", "app_a"}},
		{testProject, testBranch, testDB, testRole, [2]string{"app_a", RotationGroupRole}},
		{testProject, testBranch, testDB, RotationGroupRole, testLoginRoles},
		{testProject, testBranch, testDB, testRole, [2]string{"app_a", `x"; DROP ROLE y`}},
		{testProject, testBranch, testDB, testRole, [2]string{"app_a", "pg_read_all_data"}},
		{testProject, testBranch, testDB, "Owner", testLoginRoles},
	}
	for _, test := range cases {
		expectCode(t, adapter.PrepareRotationRoles(context.Background(), test.project, test.branch, test.database, test.owner, test.roles, true), "INVALID_REQUEST")
		_, err := adapter.RotationRolesReady(context.Background(), test.project, test.branch, test.database, test.owner, test.roles)
		expectCode(t, err, "INVALID_REQUEST")
	}
	if fake.total() != 0 || db.connected != 0 {
		t.Fatal("invalid requests reached Neon or Postgres")
	}
}

func TestPrepareRotationRolesSQLErrorsAreFixedCodesAndRollBack(t *testing.T) {
	cases := []struct {
		failOn string
		err    error
		code   string
		retry  provider.RetryClass
	}{
		{`ALTER ROLE "app_a"`, &pgconn.PgError{Code: "42501", Message: "permission denied " + canary}, "SQL_PERMISSION", provider.RetryNever},
		{"GRANT", &pgconn.PgError{Code: "0LP01", Message: canary}, "SQL_PERMISSION", provider.RetryNever},
		{"ALTER SCHEMA", &pgconn.PgError{Code: "55P03", Message: canary}, "SQL_LOCK_TIMEOUT", provider.RetrySafe},
		{"CREATE ROLE", &pgconn.PgError{Code: "57014", Message: canary}, "SQL_TIMEOUT", provider.RetrySafe},
		{"CREATE ROLE", &pgconn.PgError{Code: "42710", Message: canary}, "SQL_FAILED", provider.RetryNever},
		{"BEGIN", errors.New("conn reset " + directURI), "SQL_TRANSPORT", provider.RetrySafe},
		{"COMMIT", &pgconn.PgError{Code: "08006", Message: canary}, "SQL_UNAVAILABLE", provider.RetrySafe},
		{"SELECT current_user", context.Canceled, "CANCELLED", provider.RetrySafe},
	}
	for _, test := range cases {
		_, adapter, db := rotationFake(t)
		db.failOn, db.failWith = test.failOn, test.err
		err := adapter.PrepareRotationRoles(context.Background(), testProject, testBranch, testDB, testRole, testLoginRoles, false)
		safe := expectCode(t, err, test.code)
		if safe.Retry != test.retry || strings.Contains(err.Error(), "ep-cool") {
			t.Fatalf("%s: retry=%s err=%v", test.failOn, safe.Retry, err)
		}
		statements := db.statements()
		if test.failOn != "BEGIN" && statements[len(statements)-1] != "ROLLBACK" {
			t.Fatalf("%s: no rollback: %v", test.failOn, statements)
		}
		if !db.closed {
			t.Fatal("session not closed")
		}
		db.assertURIsWiped(t)
	}
}

func TestPrepareRotationRolesRefusesWrongIdentityVersionOrIncompleteSetup(t *testing.T) {
	for _, test := range []struct {
		identity []string
		ready    []string
		code     string
	}{
		{[]string{"app_a", testDB, "170005"}, nil, "SQL_IDENTITY_MISMATCH"},
		{[]string{testRole, "otherdb", "170005"}, nil, "SQL_IDENTITY_MISMATCH"},
		{[]string{testRole, testDB, "150010"}, nil, "SQL_UNSUPPORTED_VERSION"},
		{[]string{testRole, testDB, "x"}, nil, "SQL_INVALID_RESULT"},
		{nil, []string{"true", "true", "1"}, "SETUP_INCOMPLETE"},
	} {
		_, adapter, db := rotationFake(t)
		if test.identity != nil {
			db.results[sqlIdentity] = [][]string{test.identity}
		}
		if test.ready != nil {
			db.results[sqlReadiness] = [][]string{test.ready}
		}
		expectCode(t, adapter.PrepareRotationRoles(context.Background(), testProject, testBranch, testDB, testRole, testLoginRoles, false), test.code)
		for _, statement := range db.statements() {
			if statement == "COMMIT" {
				t.Fatalf("%s committed", test.code)
			}
		}
	}
}

func TestPrepareRotationRolesConnectionFailures(t *testing.T) {
	fake, adapter, _ := rotationFake(t)
	var retained []byte
	adapter.sqlConnect = func(_ context.Context, uri []byte, _ bool) (sqlSession, error) {
		retained = uri
		return nil, errors.New("dial " + directURI)
	}
	err := adapter.PrepareRotationRoles(context.Background(), testProject, testBranch, testDB, testRole, testLoginRoles, false)
	expectCode(t, err, "SQL_CONNECT")
	if strings.Contains(err.Error(), "ep-cool") || strings.Trim(string(retained), "\x00") != "" {
		t.Fatal("connect failure leaked or kept the URI")
	}
	adapter.sqlConnect = func(context.Context, []byte, bool) (sqlSession, error) {
		return nil, &pgconn.PgError{Code: "28P01", Message: canary}
	}
	expectCode(t, adapter.PrepareRotationRoles(context.Background(), testProject, testBranch, testDB, testRole, testLoginRoles, false), "SQL_AUTH")

	// A pooled URI where a direct one was requested is refused before connecting.
	fake.handle(http.MethodGet, connectionURIPath(), func(response http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(response, `{"uri":%s}`, jsonURI(pooledURI))
	})
	db := newFakeSQL()
	adapter.sqlConnect = db.connector(t)
	expectCode(t, adapter.PrepareRotationRoles(context.Background(), testProject, testBranch, testDB, testRole, testLoginRoles, false), "INVALID_CONNECTION_URI")
	if db.connected != 0 {
		t.Fatal("connected with a pooled URI")
	}
}

func TestRotationRolesReady(t *testing.T) {
	fake, adapter, db := rotationFake(t)
	ready, err := adapter.RotationRolesReady(context.Background(), testProject, testBranch, testDB, testRole, testLoginRoles)
	if err != nil || !ready {
		t.Fatalf("ready=%v err=%v", ready, err)
	}
	if got := db.statements(); !reflect.DeepEqual(got, []string{sqlIdentity, sqlReadiness}) {
		t.Fatalf("readiness ran %v", got)
	}
	if len(db.readOnly) != 1 || !db.readOnly[0] || !db.closed {
		t.Fatal("readiness session was not read-only and closed")
	}
	db.assertURIsWiped(t)
	if fake.count(http.MethodGet, rolePath("app_a")) != 0 {
		t.Fatal("readiness touched the role API")
	}

	for _, row := range [][]string{{"false", "true", "2"}, {"true", "false", "2"}, {"true", "true", "1"}, {"true", "true", "0"}} {
		db = newFakeSQL()
		db.results[sqlReadiness] = [][]string{row}
		adapter.sqlConnect = db.connector(t)
		ready, err = adapter.RotationRolesReady(context.Background(), testProject, testBranch, testDB, testRole, testLoginRoles)
		if err != nil || ready {
			t.Fatalf("row %v: ready=%v err=%v", row, ready, err)
		}
	}
	db = newFakeSQL()
	db.results[sqlReadiness] = nil
	adapter.sqlConnect = db.connector(t)
	_, err = adapter.RotationRolesReady(context.Background(), testProject, testBranch, testDB, testRole, testLoginRoles)
	expectCode(t, err, "SQL_INVALID_RESULT")
}

func TestNeonPostgresConfigIsHardened(t *testing.T) {
	t.Setenv("PGOPTIONS", "-c role=postgres")
	t.Setenv("PGAPPNAME", "leak")
	config, err := neonPostgresConfig([]byte(directURI), true, neonDatabaseHost.MatchString)
	if err != nil {
		t.Fatal(err)
	}
	if config.Host != "ep-cool-1234.us-east-2.aws.neon.tech" || config.User != testRole || config.Database != testDB ||
		config.TLSConfig == nil || config.TLSConfig.InsecureSkipVerify || config.TLSConfig.ServerName != config.Host ||
		config.TLSConfig.RootCAs != nil || len(config.Fallbacks) != 0 || config.ChannelBinding != "require" ||
		config.ConnectTimeout != sqlConnectTimeout || config.SSLCertMode != "disable" {
		t.Fatalf("config not hardened: host=%s tls=%v fallbacks=%d", config.Host, config.TLSConfig != nil, len(config.Fallbacks))
	}
	want := map[string]string{"application_name": "envbank", "search_path": "pg_catalog, pg_temp",
		"statement_timeout": "15000", "lock_timeout": "5000", "idle_in_transaction_session_timeout": "30000",
		"default_transaction_read_only": "on"}
	if !reflect.DeepEqual(config.RuntimeParams, want) {
		t.Fatalf("runtime params: %v", config.RuntimeParams)
	}
	// sslmode=disable in the URI cannot downgrade TLS.
	config, err = neonPostgresConfig([]byte(strings.Replace(directURI, "sslmode=require", "sslmode=disable", 1)), false, neonDatabaseHost.MatchString)
	if err != nil || config.TLSConfig == nil || len(config.Fallbacks) != 0 || config.RuntimeParams["default_transaction_read_only"] != "" {
		t.Fatalf("sslmode downgrade accepted: %v", err)
	}

	for _, uri := range []string{
		strings.Replace(directURI, "ep-cool-1234.us-east-2.aws.neon.tech", "evil.example.com", 1),
		strings.Replace(directURI, "ep-cool-1234.us-east-2.aws.neon.tech", "ep-x.neon.tech.evil.com", 1),
		strings.Replace(directURI, "ep-cool-1234.us-east-2.aws.neon.tech", "127.0.0.1", 1),
		directURI + "&options=-c%20role%3Dpostgres",
		directURI + "&sslrootcert=/tmp/x",
		directURI + "&target_session_attrs=any",
		strings.Replace(directURI, "ep-cool-1234.us-east-2.aws.neon.tech", "ep-a.us-east-2.aws.neon.tech,ep-b.us-east-2.aws.neon.tech", 1),
		pooledURI,
		"postgresql://ep-cool-1234.us-east-2.aws.neon.tech/neondb",
		"mysql://u:p@ep-cool-1234.us-east-2.aws.neon.tech/db",
	} {
		if _, err := neonPostgresConfig([]byte(uri), false, neonDatabaseHost.MatchString); !errors.Is(err, errSQLConfig) ||
			strings.Contains(err.Error(), canary) {
			t.Fatalf("accepted or leaked for %q: %v", strings.ReplaceAll(uri, canary, "***"), err)
		}
	}
}

func TestSQLErrorNeverEchoesServerText(t *testing.T) {
	for _, input := range []error{
		&pgconn.PgError{Code: "XX000", Message: canary, Detail: directURI},
		fmt.Errorf("wrapped: %w", &pgconn.PgError{Code: "28000", Message: canary}),
		errors.New(directURI),
		context.DeadlineExceeded,
		errSQLTooManyRows,
	} {
		err := sqlError("rotation_roles_prepare", input, false)
		var safe provider.Error
		if !errors.As(err, &safe) || safe.Validate() != nil || strings.Contains(fmt.Sprintf("%v %+v %#v", err, err, err), canary) ||
			strings.Contains(err.Error(), "ep-cool") || errors.Unwrap(err) != nil {
			t.Fatalf("unsafe sql error: %v", err)
		}
	}
}
