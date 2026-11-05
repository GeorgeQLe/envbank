package neon

import (
	"context"
	"errors"
	"regexp"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/GeorgeQLe/envbank/internal/provider"
)

// Rotation roles.
//
// EnvBank rotates an app's credentials by alternating two login roles. Roles
// created through Neon's API do not share table ownership, so after a switch
// the new role could not use tables the previous one created. Both login roles
// are therefore members (INHERIT and SET) of one NOLOGIN group role that owns
// the public schema and every app object, and each has a role-level default
// "role = envbank_app_owner", so every session, direct or pooled, acts as the
// group.
//
// Setup runs as the branch's owner role (for example neondb_owner) through a
// direct connection URI fetched on demand from Neon. The URI is held only in a
// wiped buffer for the duration of the call and is never stored or returned.

// RotationGroupRole is the NOLOGIN group role that owns the app's objects.
const RotationGroupRole = "envbank_app_owner"

const (
	minServerVersion = 160000 // GRANT ... WITH INHERIT/SET needs PostgreSQL 16
	maxAdoptObjects  = 10000
	maxQueryRows     = maxAdoptObjects + 1
)

// sqlSession is the small Postgres surface the rotation-role setup needs, so
// the statement sequence can be tested without a database. Query returns every
// column as text (statements cast explicitly) and must bound its row count.
// Errors may carry server text; callers map them to fixed codes and discard
// them.
type sqlSession interface {
	Exec(ctx context.Context, statement string, args ...any) error
	Query(ctx context.Context, statement string, args ...any) ([][]string, error)
	Close(ctx context.Context) error
}

// sqlConnector opens one session from a connection URI. It must not retain
// uri, which the caller wipes once the connector returns.
type sqlConnector func(ctx context.Context, uri []byte, readOnly bool) (sqlSession, error)

// Fixed SQL. Identifiers that vary are added only through quoteIdent; values
// are bound parameters.
const (
	sqlBegin           = "BEGIN"
	sqlCommit          = "COMMIT"
	sqlRollback        = "ROLLBACK"
	sqlLocalSearchPath = "SET LOCAL search_path = pg_catalog, pg_temp"
	sqlIdentity        = "SELECT current_user::text, current_database()::text, current_setting('server_version_num')"
	sqlGroupState      = "SELECT rolcanlogin::text, rolsuper::text FROM pg_catalog.pg_roles WHERE rolname = $1::text"
	// sqlGroupMembers lists the roles that are members of the group (any
	// grant option).
	sqlGroupMembers = `SELECT r.rolname::text FROM pg_catalog.pg_auth_members m
  JOIN pg_catalog.pg_roles g ON g.oid = m.roleid
  JOIN pg_catalog.pg_roles r ON r.oid = m.member
  WHERE g.rolname = $1::text ORDER BY 1`
	roleSettingValue = "role=" + RotationGroupRole
	sqlHasPrivileges = "SELECT pg_catalog.pg_has_role(current_user, $1::text, 'USAGE')::text"

	// sqlReadiness reports (group is NOLOGIN and not superuser, public is
	// owned by the group, number of login roles that are INHERIT+SET members
	// with the role default and no conflicting per-database override).
	sqlReadiness = `SELECT
  coalesce((SELECT (NOT r.rolcanlogin AND NOT r.rolsuper)::text FROM pg_catalog.pg_roles r WHERE r.rolname = $1::text), 'false'),
  coalesce((SELECT (pg_catalog.pg_get_userbyid(n.nspowner) = $1::text)::text FROM pg_catalog.pg_namespace n WHERE n.nspname = 'public'), 'false'),
  (SELECT count(*)::text FROM pg_catalog.unnest($2::text[]) AS login(name)
    WHERE EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m
        JOIN pg_catalog.pg_roles g ON g.oid = m.roleid
        JOIN pg_catalog.pg_roles r ON r.oid = m.member
        WHERE g.rolname = $1::text AND r.rolname = login.name AND m.inherit_option AND m.set_option)
      AND EXISTS (SELECT 1 FROM pg_catalog.pg_db_role_setting s
        JOIN pg_catalog.pg_roles r ON r.oid = s.setrole
        WHERE r.rolname = login.name AND s.setdatabase = 0 AND $3::text = ANY (s.setconfig))
      AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_db_role_setting s
        JOIN pg_catalog.pg_roles r ON r.oid = s.setrole
        JOIN pg_catalog.pg_database d ON d.oid = s.setdatabase
        WHERE r.rolname = login.name AND d.datname = pg_catalog.current_database()
          AND EXISTS (SELECT 1 FROM pg_catalog.unnest(s.setconfig) AS c(item)
            WHERE c.item LIKE 'role=%' AND c.item <> $3::text)))`

	// sqlAdoptRelations lists public tables, sequences, views and
	// materialized views owned by the given roles. Extension members are
	// skipped, as are sequences owned by a table column (serial/identity),
	// which follow their table and cannot be altered directly.
	sqlAdoptRelations = `SELECT c.relkind::text, c.relname::text
FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'S', 'v', 'm')
  AND pg_catalog.pg_get_userbyid(c.relowner) = ANY ($1::text[])
  AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d
    WHERE d.classid = 'pg_catalog.pg_class'::pg_catalog.regclass AND d.objid = c.oid
      AND (d.deptype = 'e' OR (c.relkind = 'S' AND d.deptype IN ('a', 'i')
        AND d.refclassid = 'pg_catalog.pg_class'::pg_catalog.regclass)))
ORDER BY c.relkind, c.relname`

	// sqlAdoptFunctions lists public plain functions owned by the given
	// roles, with their input argument types. format_type output is checked
	// against a conservative pattern before use.
	sqlAdoptFunctions = `SELECT p.proname::text,
  coalesce((SELECT string_agg(pg_catalog.format_type(a.t, NULL), ',' ORDER BY a.ord)
    FROM pg_catalog.unnest(p.proargtypes::pg_catalog.oid[]) WITH ORDINALITY AS a(t, ord)), '')
FROM pg_catalog.pg_proc p
JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname = 'public' AND p.prokind = 'f'
  AND pg_catalog.pg_get_userbyid(p.proowner) = ANY ($1::text[])
  AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d
    WHERE d.classid = 'pg_catalog.pg_proc'::pg_catalog.regclass AND d.objid = p.oid AND d.deptype = 'e')
ORDER BY p.proname, p.oid`
)

// argumentTypePattern accepts format_type output made only of lowercase
// words, an optional schema qualifier and array suffixes ("integer",
// "character varying", "timestamp with time zone", "public.mood", "text[]"),
// plus the one built-in that format_type quotes, "char". Anything else
// (quoted or mixed-case names) makes adoption refuse rather than interpolate.
var argumentTypePattern = regexp.MustCompile(`^(?:(?:[a-z_][a-z0-9_]*\.)?[a-z_][a-z0-9_]*(?: [a-z_][a-z0-9_]*)*|"char")(?:\[\])*$`)

func quoteIdent(parts ...string) string { return pgx.Identifier(parts).Sanitize() }

func validRotationRoles(operation, ownerRole string, roles [2]string) error {
	if !ValidRoleName(ownerRole) || !ValidRoleName(roles[0]) || !ValidRoleName(roles[1]) ||
		roles[0] == roles[1] || ownerRole == roles[0] || ownerRole == roles[1] ||
		ownerRole == RotationGroupRole || roles[0] == RotationGroupRole || roles[1] == RotationGroupRole {
		return safeError(operation, "INVALID_REQUEST", provider.RetryNever)
	}
	return nil
}

// PrepareRotationRoles idempotently sets up the rotation group: it ensures
// both login roles exist (Neon API), then, as ownerRole over a direct
// connection and in one transaction, creates the NOLOGIN group if missing,
// grants it to ownerRole and both login roles (INHERIT, SET), sets each login
// role's default role to the group and hands it the public schema. With
// adopt, it also transfers public tables, sequences, views, materialized
// views and functions owned by ownerRole or either login role to the group.
// Database ownership is never changed (REASSIGN OWNED is deliberately not
// used). Requires PostgreSQL 16 or later.
//
// Every failure before COMMIT rolls back, so the call can be retried.
func (adapter *Adapter) PrepareRotationRoles(ctx context.Context, projectID, branchID, database, ownerRole string, roles [2]string, adopt bool) error {
	const operation = "rotation_roles_prepare"
	if !ValidProjectID(projectID) || !ValidBranchID(branchID) || !ValidDatabaseName(database) {
		return safeError(operation, "INVALID_REQUEST", provider.RetryNever)
	}
	if err := validRotationRoles(operation, ownerRole, roles); err != nil {
		return err
	}
	for _, role := range roles {
		if _, err := adapter.EnsureRole(ctx, projectID, branchID, role); err != nil {
			return provider.SanitizeError(operation, err)
		}
	}
	session, err := adapter.ownerSession(ctx, operation, projectID, branchID, database, ownerRole, false)
	if err != nil {
		return err
	}
	defer closeSession(session)
	return prepareRotationSQL(ctx, operation, session, database, ownerRole, roles, adopt)
}

// RotationRolesReady reports, read-only through ownerRole's direct connection,
// whether the group exists and is NOLOGIN, both login roles are INHERIT+SET
// members whose default role is the group, and the group owns public.
func (adapter *Adapter) RotationRolesReady(ctx context.Context, projectID, branchID, database, ownerRole string, roles [2]string) (bool, error) {
	const operation = "rotation_roles_check"
	if !ValidProjectID(projectID) || !ValidBranchID(branchID) || !ValidDatabaseName(database) {
		return false, safeError(operation, "INVALID_REQUEST", provider.RetryNever)
	}
	if err := validRotationRoles(operation, ownerRole, roles); err != nil {
		return false, err
	}
	session, err := adapter.ownerSession(ctx, operation, projectID, branchID, database, ownerRole, true)
	if err != nil {
		return false, err
	}
	defer closeSession(session)
	if err := checkSessionIdentity(ctx, operation, session, database, ownerRole); err != nil {
		return false, err
	}
	return rotationReady(ctx, operation, session, roles)
}

// ownerSession fetches ownerRole's direct URI, opens a session with it and
// wipes it before returning.
func (adapter *Adapter) ownerSession(ctx context.Context, operation, projectID, branchID, database, ownerRole string, readOnly bool) (sqlSession, error) {
	if adapter == nil {
		return nil, safeError(operation, "NOT_CONFIGURED", provider.RetryNever)
	}
	uri, err := adapter.connectionURI(ctx, operation,
		ProjectInfo{ProjectID: projectID, BranchID: branchID, Role: ownerRole, Database: database}, false)
	if err != nil {
		return nil, err
	}
	defer wipe(uri)
	connect := adapter.sqlConnect
	if connect == nil {
		connect = connectNeonPostgres
	}
	session, err := connect(ctx, uri, readOnly)
	wipe(uri)
	if err != nil {
		return nil, sqlError(operation, err, true)
	}
	if session == nil {
		return nil, safeError(operation, "SQL_CONNECT", provider.RetrySafe)
	}
	return session, nil
}

func closeSession(session sqlSession) {
	ctx, cancel := context.WithTimeout(context.Background(), sqlCloseTimeout)
	defer cancel()
	_ = session.Close(ctx)
}

func prepareRotationSQL(ctx context.Context, operation string, session sqlSession, database, ownerRole string, roles [2]string, adopt bool) error {
	if err := session.Exec(ctx, sqlBegin); err != nil {
		return sqlError(operation, err, false)
	}
	committed := false
	defer func() {
		if !committed {
			rollbackCtx, cancel := context.WithTimeout(context.Background(), sqlCloseTimeout)
			defer cancel()
			_ = session.Exec(rollbackCtx, sqlRollback)
		}
	}()
	if err := session.Exec(ctx, sqlLocalSearchPath); err != nil {
		return sqlError(operation, err, false)
	}
	if err := checkSessionIdentity(ctx, operation, session, database, ownerRole); err != nil {
		return err
	}

	rows, err := session.Query(ctx, sqlGroupState, RotationGroupRole)
	if err != nil {
		return sqlError(operation, err, false)
	}
	group := quoteIdent(RotationGroupRole)
	switch {
	case len(rows) == 0:
		if err := session.Exec(ctx, "CREATE ROLE "+group+" NOLOGIN"); err != nil {
			return sqlError(operation, err, false)
		}
	case len(rows) == 1 && len(rows[0]) == 2 && rows[0][0] == "false" && rows[0][1] == "false":
		// An existing group is ours only if nobody but the owner and the
		// rotation roles is a member: any other member would act as the
		// owner of the app's schema and objects.
		members, err := session.Query(ctx, sqlGroupMembers, RotationGroupRole)
		if err != nil {
			return sqlError(operation, err, false)
		}
		for _, row := range members {
			if len(row) != 1 || (row[0] != ownerRole && row[0] != roles[0] && row[0] != roles[1]) {
				return safeError(operation, "GROUP_ROLE_CONFLICT", provider.RetryNever)
			}
		}
	default:
		// A same-named role that can log in or is superuser is not ours.
		return safeError(operation, "GROUP_ROLE_CONFLICT", provider.RetryNever)
	}

	statements := []string{
		// ownerRole needs SET on the group to ALTER ... OWNER TO it; on
		// PostgreSQL 16+ CREATEROLE only grants the creator ADMIN.
		"GRANT " + group + " TO " + quoteIdent(ownerRole) + " WITH INHERIT TRUE, SET TRUE",
		"GRANT " + group + " TO " + quoteIdent(roles[0]) + " WITH INHERIT TRUE, SET TRUE",
		"GRANT " + group + " TO " + quoteIdent(roles[1]) + " WITH INHERIT TRUE, SET TRUE",
		"ALTER ROLE " + quoteIdent(roles[0]) + " SET role = '" + RotationGroupRole + "'",
		"ALTER ROLE " + quoteIdent(roles[1]) + " SET role = '" + RotationGroupRole + "'",
		"ALTER SCHEMA public OWNER TO " + group,
	}
	for _, statement := range statements {
		if err := session.Exec(ctx, statement); err != nil {
			return sqlError(operation, err, false)
		}
	}
	if adopt {
		if err := adoptObjects(ctx, operation, session, ownerRole, roles); err != nil {
			return err
		}
	}
	ready, err := rotationReady(ctx, operation, session, roles)
	if err != nil {
		return err
	}
	if !ready {
		return safeError(operation, "SETUP_INCOMPLETE", provider.RetryNever)
	}
	if err := session.Exec(ctx, sqlCommit); err != nil {
		// The work is idempotent, so a commit whose outcome is unknown can be
		// retried safely.
		return sqlError(operation, err, false)
	}
	committed = true
	return nil
}

func checkSessionIdentity(ctx context.Context, operation string, session sqlSession, database, ownerRole string) error {
	rows, err := session.Query(ctx, sqlIdentity)
	if err != nil {
		return sqlError(operation, err, false)
	}
	if len(rows) != 1 || len(rows[0]) != 3 {
		return safeError(operation, "SQL_INVALID_RESULT", provider.RetryNever)
	}
	if rows[0][0] != ownerRole || rows[0][1] != database {
		return safeError(operation, "SQL_IDENTITY_MISMATCH", provider.RetryNever)
	}
	version, err := strconv.Atoi(rows[0][2])
	if err != nil {
		return safeError(operation, "SQL_INVALID_RESULT", provider.RetryNever)
	}
	if version < minServerVersion {
		return safeError(operation, "SQL_UNSUPPORTED_VERSION", provider.RetryNever)
	}
	return nil
}

func rotationReady(ctx context.Context, operation string, session sqlSession, roles [2]string) (bool, error) {
	rows, err := session.Query(ctx, sqlReadiness, RotationGroupRole, []string{roles[0], roles[1]}, roleSettingValue)
	if err != nil {
		return false, sqlError(operation, err, false)
	}
	if len(rows) != 1 || len(rows[0]) != 3 {
		return false, safeError(operation, "SQL_INVALID_RESULT", provider.RetryNever)
	}
	return rows[0][0] == "true" && rows[0][1] == "true" && rows[0][2] == "2", nil
}

// adoptObjects transfers public objects owned by ownerRole or a login role
// to the group. ALTER ... OWNER requires the privileges of the current owner,
// which ownerRole lacks for login roles it only holds ADMIN on (PostgreSQL
// 16+ CREATEROLE semantics), so it is granted a login role (INHERIT, no SET)
// for the duration of the transfer and the grant is revoked afterwards, still
// inside the transaction. A role whose privileges ownerRole already has is
// left untouched.
func adoptObjects(ctx context.Context, operation string, session sqlSession, ownerRole string, roles [2]string) error {
	var temporary []string
	for _, role := range roles {
		rows, err := session.Query(ctx, sqlHasPrivileges, role)
		if err != nil {
			return sqlError(operation, err, false)
		}
		if len(rows) != 1 || len(rows[0]) != 1 || (rows[0][0] != "true" && rows[0][0] != "false") {
			return safeError(operation, "SQL_INVALID_RESULT", provider.RetryNever)
		}
		if rows[0][0] == "false" {
			temporary = append(temporary, role)
		}
	}
	statements := make([]string, 0, 2*len(temporary))
	for _, role := range temporary {
		statements = append(statements, "GRANT "+quoteIdent(role)+" TO "+quoteIdent(ownerRole)+" WITH INHERIT TRUE, SET FALSE")
	}
	adoptions, err := adoptionStatements(ctx, operation, session, []string{ownerRole, roles[0], roles[1]})
	if err != nil {
		return err
	}
	statements = append(statements, adoptions...)
	for _, role := range temporary {
		statements = append(statements, "REVOKE "+quoteIdent(role)+" FROM "+quoteIdent(ownerRole))
	}
	for _, statement := range statements {
		if err := session.Exec(ctx, statement); err != nil {
			return sqlError(operation, err, false)
		}
	}
	return nil
}

func adoptionStatements(ctx context.Context, operation string, session sqlSession, owners []string) ([]string, error) {
	group := quoteIdent(RotationGroupRole)
	relations, err := session.Query(ctx, sqlAdoptRelations, owners)
	if err != nil {
		return nil, sqlError(operation, err, false)
	}
	functions, err := session.Query(ctx, sqlAdoptFunctions, owners)
	if err != nil {
		return nil, sqlError(operation, err, false)
	}
	if len(relations)+len(functions) > maxAdoptObjects {
		return nil, safeError(operation, "SQL_TOO_MANY_OBJECTS", provider.RetryNever)
	}
	statements := make([]string, 0, len(relations)+len(functions))
	invalid := safeError(operation, "SQL_INVALID_RESULT", provider.RetryNever)
	for _, row := range relations {
		if len(row) != 2 || row[1] == "" {
			return nil, invalid
		}
		var keyword string
		switch row[0] {
		case "r", "p":
			keyword = "TABLE"
		case "S":
			keyword = "SEQUENCE"
		case "v":
			keyword = "VIEW"
		case "m":
			keyword = "MATERIALIZED VIEW"
		default:
			return nil, invalid
		}
		statements = append(statements, "ALTER "+keyword+" "+quoteIdent("public", row[1])+" OWNER TO "+group)
	}
	for _, row := range functions {
		if len(row) != 2 || row[0] == "" {
			return nil, invalid
		}
		arguments := row[1]
		if arguments != "" {
			for _, argument := range splitArguments(arguments) {
				if !argumentTypePattern.MatchString(argument) {
					return nil, safeError(operation, "SQL_UNSUPPORTED_OBJECT", provider.RetryNever)
				}
			}
		}
		statements = append(statements, "ALTER FUNCTION "+quoteIdent("public", row[0])+"("+arguments+") OWNER TO "+group)
	}
	return statements, nil
}

// splitArguments splits the comma-joined type list. Accepted type names
// contain no commas, so a type that did would fail the pattern check.
func splitArguments(arguments string) []string {
	var parts []string
	start := 0
	for index := 0; index < len(arguments); index++ {
		if arguments[index] == ',' {
			parts = append(parts, arguments[start:index])
			start = index + 1
		}
	}
	return append(parts, arguments[start:])
}

// sqlError maps a Postgres or transport error to a fixed code. Server
// messages, which might echo connection details, are discarded.
func sqlError(operation string, err error, connecting bool) error {
	var safe provider.Error
	if errors.As(err, &safe) {
		return provider.NewError(operation, 0, safe.Code, safe.Retry)
	}
	if errors.Is(err, errSQLTooManyRows) {
		return safeError(operation, "SQL_TOO_MANY_OBJECTS", provider.RetryNever)
	}
	if errors.Is(err, context.Canceled) {
		return safeError(operation, "CANCELLED", provider.RetrySafe)
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		code := pgErr.Code
		switch {
		case code == "42501" || code == "0LP01":
			return safeError(operation, "SQL_PERMISSION", provider.RetryNever)
		case len(code) == 5 && code[:2] == "28":
			return safeError(operation, "SQL_AUTH", provider.RetryNever)
		case code == "57014":
			return safeError(operation, "SQL_TIMEOUT", provider.RetrySafe)
		case code == "55P03":
			return safeError(operation, "SQL_LOCK_TIMEOUT", provider.RetrySafe)
		case code == "40001" || code == "40P01":
			return safeError(operation, "SQL_CONFLICT", provider.RetrySafe)
		case len(code) == 5 && (code[:2] == "08" || code[:2] == "53" || code[:2] == "57"):
			return safeError(operation, "SQL_UNAVAILABLE", provider.RetrySafe)
		default:
			return safeError(operation, "SQL_FAILED", provider.RetryNever)
		}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return safeError(operation, "SQL_TIMEOUT", provider.RetrySafe)
	}
	if connecting {
		return safeError(operation, "SQL_CONNECT", provider.RetrySafe)
	}
	return safeError(operation, "SQL_TRANSPORT", provider.RetrySafe)
}
