package live

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/GeorgeQLe/envbank/internal/provider/neon"
	"github.com/GeorgeQLe/envbank/internal/provideraction/provideractiontest"
)

// Stateful loopback fakes of Neon, Vercel and Stripe for the synthetic
// end-to-end test. They speak the API shapes the concrete adapters use,
// check the bearer credentials, and keep enough state to prove what the
// broker sent: Neon role passwords (the Postgres side is a fake SQL session
// that checks the owner URI's password), Vercel env vars and deployments
// that snapshot them, and Stripe endpoints with their signing secrets. A
// deployment is healthy only if every credential it was built with is still
// valid at the provider, so a rotation that invalidated the old role before
// the new deployment served would show up as a failed health check.
//
// Vercel production is modelled too: a production redeploy is created
// STAGED and serves nothing; the project's verified production domain is
// aliased to one deployment; promote and rollback move that alias (promote
// through an alias job that runs for aliasDelay project reads); and a
// production deployment snapshots the production env vars.

// events is the cross-provider order of state changes and health checks.
type events struct {
	mu  sync.Mutex
	all []string
}

func (e *events) add(format string, args ...any) {
	e.mu.Lock()
	e.all = append(e.all, fmt.Sprintf(format, args...))
	e.mu.Unlock()
}

func (e *events) list() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.all...)
}

func (e *events) index(s string) int {
	for i, x := range e.list() {
		if x == s {
			return i
		}
	}
	return -1
}

func (e *events) last(prefix string) int {
	all := e.list()
	for i := len(all) - 1; i >= 0; i-- {
		if strings.HasPrefix(all[i], prefix) {
			return i
		}
	}
	return -1
}

// secrets collects every secret value the fakes issue, for leak scans.
type secrets struct {
	mu  sync.Mutex
	all []string
}

func (s *secrets) issue(prefix string) string {
	v := provideractiontest.Sentinel(prefix)
	s.mu.Lock()
	s.all = append(s.all, v)
	s.mu.Unlock()
	return v
}

func (s *secrets) list() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.all...)
}

func bearer(r *http.Request, token string) bool {
	return r.Header.Get("Authorization") == "Bearer "+token
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// ---- Neon ----

type neonProject struct {
	id, branch, owner, database string
	host                        string // compute endpoint host label
	passwords                   map[string]string
	deleted                     bool
	// Postgres state the fake SQL session changes.
	group      bool
	publicByGr bool
	members    map[string]bool
	settings   map[string]bool
}

type fakeNeon struct {
	t      *testing.T
	key    string
	ev     *events
	sec    *secrets
	mu     sync.Mutex
	next   int
	byID   map[string]*neonProject
	server *httptest.Server
	opSeq  int
}

func newFakeNeon(t *testing.T, key string, ev *events, sec *secrets) *fakeNeon {
	f := &fakeNeon{t: t, key: key, ev: ev, sec: sec, byID: map[string]*neonProject{}}
	f.server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeNeon) opLocked(projectID string) map[string]string {
	f.opSeq++
	return map[string]string{"id": fmt.Sprintf("00000000-0000-4000-8000-%012d", f.opSeq), "project_id": projectID, "status": "finished"}
}

func (f *fakeNeon) uriLocked(p *neonProject, role string, pooled bool) string {
	host := p.host
	if pooled {
		host += "-pooler"
	}
	return "postgresql://" + role + ":" + p.passwords[role] + "@" + host + ".us-east-2.aws.neon.tech/" + p.database + "?sslmode=require&channel_binding=require"
}

// Password returns role's current password (test assertions only).
func (f *fakeNeon) password(projectID, role string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if p := f.byID[projectID]; p != nil {
		return p.passwords[role]
	}
	return ""
}

// validURI reports whether uri carries a role's current password.
func (f *fakeNeon) validURI(uri string) bool {
	u, err := url.Parse(uri)
	if err != nil || u.User == nil {
		return false
	}
	pw, _ := u.User.Password()
	label := strings.TrimSuffix(strings.SplitN(u.Hostname(), ".", 2)[0], "-pooler")
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, p := range f.byID {
		if p.host == label && !p.deleted {
			cur, ok := p.passwords[u.User.Username()]
			return ok && cur == pw && pw != ""
		}
	}
	return false
}

func (f *fakeNeon) serve(w http.ResponseWriter, r *http.Request) {
	if !bearer(r, f.key) {
		f.t.Errorf("neon: request without the control key")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/v2")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case r.Method == http.MethodPost && path == "/projects":
		var body struct {
			Project struct {
				Name  string `json:"name"`
				OrgID string `json:"org_id"`
			} `json:"project"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.next++
		p := &neonProject{id: fmt.Sprintf("e2e-proj-%d", f.next), branch: fmt.Sprintf("br-e2e-%d", f.next), owner: "neondb_owner", database: "neondb",
			host: fmt.Sprintf("ep-e2e-%d", f.next), passwords: map[string]string{}, members: map[string]bool{}, settings: map[string]bool{}}
		p.passwords[p.owner] = f.sec.issue("npg_owner_")
		f.byID[p.id] = p
		f.ev.add("neon.create_project %s org=%s", p.id, body.Project.OrgID)
		writeJSON(w, http.StatusCreated, map[string]any{
			"project": map[string]string{"id": p.id}, "branch": map[string]string{"id": p.branch},
			"connection_uris": []map[string]any{
				{"connection_uri": f.uriLocked(p, p.owner, false), "connection_parameters": map[string]string{"database": p.database, "role": p.owner}},
				{"connection_uri": f.uriLocked(p, p.owner, true), "connection_parameters": map[string]string{"database": p.database, "role": p.owner}},
			},
			"operations": []any{f.opLocked(p.id)},
		})
		return
	case len(parts) >= 2 && parts[0] == "projects":
		p := f.byID[parts[1]]
		if p == nil || p.deleted {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		switch {
		case len(parts) == 2 && r.Method == http.MethodDelete:
			p.deleted = true
			f.ev.add("neon.delete_project %s", p.id)
			writeJSON(w, http.StatusOK, map[string]any{"project": map[string]string{"id": p.id}})
			return
		case len(parts) == 3 && parts[2] == "connection_uri" && r.Method == http.MethodGet:
			q := r.URL.Query()
			role := q.Get("role_name")
			if q.Get("branch_id") != p.branch || q.Get("database_name") != p.database || p.passwords[role] == "" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			writeJSON(w, http.StatusOK, map[string]string{"uri": f.uriLocked(p, role, q.Get("pooled") == "true")})
			return
		case len(parts) >= 5 && parts[2] == "branches" && parts[3] == p.branch && parts[4] == "roles":
			switch {
			case len(parts) == 5 && r.Method == http.MethodPost:
				var body struct {
					Role struct {
						Name string `json:"name"`
					} `json:"role"`
				}
				_ = json.NewDecoder(r.Body).Decode(&body)
				if _, ok := p.passwords[body.Role.Name]; ok {
					w.WriteHeader(http.StatusConflict)
					return
				}
				p.passwords[body.Role.Name] = f.sec.issue("npg_created_")
				f.ev.add("neon.create_role %s", body.Role.Name)
				writeJSON(w, http.StatusCreated, map[string]any{"role": map[string]string{"name": body.Role.Name, "branch_id": p.branch}, "operations": []any{f.opLocked(p.id)}})
				return
			case len(parts) == 6 && r.Method == http.MethodGet:
				if _, ok := p.passwords[parts[5]]; !ok {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				writeJSON(w, http.StatusOK, map[string]any{"role": map[string]string{"name": parts[5], "branch_id": p.branch}})
				return
			case len(parts) == 7 && parts[6] == "reset_password" && r.Method == http.MethodPost:
				role := parts[5]
				if _, ok := p.passwords[role]; !ok {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				p.passwords[role] = f.sec.issue("npg_" + role + "_")
				f.ev.add("neon.reset %s", role)
				writeJSON(w, http.StatusOK, map[string]any{"role": map[string]string{"name": role}, "operations": []any{f.opLocked(p.id)}})
				return
			}
		}
	}
	w.WriteHeader(http.StatusNotFound)
}

// connect is the fake Postgres connector: it accepts only a direct owner
// URI with the role's current password, and the session it returns keeps
// the rotation-role state on the project.
func (f *fakeNeon) connect(_ context.Context, uri []byte, readOnly bool) (neon.SQLSession, error) {
	u, err := url.Parse(string(uri))
	if err != nil || u.User == nil || strings.Contains(u.Hostname(), "-pooler") {
		return nil, errors.New("fake postgres: bad uri")
	}
	if !f.validURI(string(uri)) {
		return nil, errors.New("fake postgres: password authentication failed")
	}
	label := strings.SplitN(u.Hostname(), ".", 2)[0]
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, p := range f.byID {
		if p.host == label {
			return &fakeSession{f: f, p: p, user: u.User.Username(), db: strings.TrimPrefix(u.Path, "/"), readOnly: readOnly}, nil
		}
	}
	return nil, errors.New("fake postgres: unknown host")
}

type fakeSession struct {
	f        *fakeNeon
	p        *neonProject
	user, db string
	readOnly bool
}

func (s *fakeSession) Exec(_ context.Context, statement string, _ ...any) error {
	s.f.mu.Lock()
	defer s.f.mu.Unlock()
	group := `"` + neon.RotationGroupRole + `"`
	switch {
	case statement == "BEGIN", statement == "COMMIT", statement == "ROLLBACK", strings.HasPrefix(statement, "SET LOCAL "):
		return nil
	case s.readOnly:
		return errors.New("fake postgres: read-only transaction")
	case statement == "CREATE ROLE "+group+" NOLOGIN":
		s.p.group = true
	case strings.HasPrefix(statement, "GRANT "+group+" TO ") && strings.HasSuffix(statement, " WITH INHERIT TRUE, SET TRUE"):
		role := strings.Trim(strings.TrimSuffix(strings.TrimPrefix(statement, "GRANT "+group+" TO "), " WITH INHERIT TRUE, SET TRUE"), `"`)
		s.p.members[role] = true
	case strings.HasPrefix(statement, "ALTER ROLE ") && strings.HasSuffix(statement, " SET role = '"+neon.RotationGroupRole+"'"):
		role := strings.Trim(strings.TrimSuffix(strings.TrimPrefix(statement, "ALTER ROLE "), " SET role = '"+neon.RotationGroupRole+"'"), `"`)
		s.p.settings[role] = true
	case statement == "ALTER SCHEMA public OWNER TO "+group:
		s.p.publicByGr = true
	default:
		return fmt.Errorf("fake postgres: unexpected statement %q", statement)
	}
	return nil
}

func (s *fakeSession) Query(_ context.Context, statement string, args ...any) ([][]string, error) {
	s.f.mu.Lock()
	defer s.f.mu.Unlock()
	switch {
	case strings.HasPrefix(statement, "SELECT current_user"):
		return [][]string{{s.user, s.db, "170002"}}, nil
	case strings.Contains(statement, "rolcanlogin::text, rolsuper::text"):
		if s.p.group {
			return [][]string{{"false", "false"}}, nil
		}
		return nil, nil
	case strings.Contains(statement, "pg_auth_members"):
		roles, _ := args[1].([]string)
		n := 0
		for _, r := range roles {
			if s.p.members[r] && s.p.settings[r] {
				n++
			}
		}
		return [][]string{{fmt.Sprint(s.p.group), fmt.Sprint(s.p.publicByGr), fmt.Sprint(n)}}, nil
	}
	return nil, fmt.Errorf("fake postgres: unexpected query")
}

func (s *fakeSession) Close(context.Context) error { return nil }

// ---- Vercel ----

type vercelEnv struct {
	id, key, target, branch, value string
}

type vercelDeployment struct {
	id, project, host, sha string
	target                 string // "" (preview) or "production"
	substate               string // production: STAGED or PROMOTED
	meta                   map[string]string
	snapshot               map[string]string // env values the build captured
	created                int64
}

type vercelProject struct {
	id, name, team string
	deleted        bool
	envs           []*vercelEnv
	// Production: one verified domain aliased to alias; jobStatus is the
	// last alias job's (lastAliasRequest), pending a promote's job.
	domain, alias string
	jobStatus     string
	pending       *aliasJob
}

type aliasJob struct {
	to    string
	reads int // project reads left while the job is in progress
}

type fakeVercel struct {
	t       *testing.T
	token   string
	team    string
	ev      *events
	neon    *fakeNeon
	stripe  *fakeStripe
	mu      sync.Mutex
	next    int
	clock   int64
	byID    map[string]*vercelProject
	deps    map[string]*vercelDeployment
	server  *httptest.Server
	protect bool // deployment protection: health answers 401
	// Production failure knobs.
	aliasDelay       int  // project reads a promote's alias job stays in progress
	promoteError     bool // promote moves the alias, then answers 500
	promoteJobFails  bool // promote is accepted, its alias job fails (alias unchanged)
	failWhileServing bool // a redeployed deployment answers 503 while it serves production
	// health requests the deployments received, for header checks.
	healthReqs []*http.Request
}

func newFakeVercel(t *testing.T, token, team string, ev *events, n *fakeNeon, s *fakeStripe) *fakeVercel {
	f := &fakeVercel{t: t, token: token, team: team, ev: ev, neon: n, stripe: s, byID: map[string]*vercelProject{}, deps: map[string]*vercelDeployment{}, clock: 1_700_000_000_000}
	f.server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeVercel) id(prefix string) string {
	f.next++
	return fmt.Sprintf("%se2e%d", prefix, f.next)
}

// envValue returns key's value in the project's preview scope.
func (f *fakeVercel) envValue(projectID, key string) string {
	return f.envValueIn(projectID, key, "preview")
}

// envValueIn returns key's value in the project's target scope.
func (f *fakeVercel) envValueIn(projectID, key, target string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := f.byID[projectID]
	if p == nil {
		return ""
	}
	for _, e := range p.envs {
		if e.key == key && e.target == target && e.branch == "" {
			return e.value
		}
	}
	return ""
}

// seedProduction gives the project a promoted production deployment, built
// with its production env vars, that its verified domain serves.
func (f *fakeVercel) seedProduction(projectID, domain string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := f.byID[projectID]
	d := f.deployLocked(p, map[string]string{}, "production")
	d.substate = "PROMOTED"
	p.domain, p.alias = domain, d.id
	return d.id
}

// production returns the deployment the project's domain serves.
func (f *fakeVercel) production(projectID string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.byID[projectID].alias
}

// snapshot returns the env value deployment id was built with.
func (f *fakeVercel) snapshot(id, key string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.deps[id].snapshot[key]
}

func (f *fakeVercel) aliasLocked(p *vercelProject, to string) {
	p.alias = to
	f.deps[to].substate = "PROMOTED"
	f.ev.add("vercel.alias %s", to)
}

func (f *fakeVercel) deployWire(d *vercelDeployment) map[string]any {
	meta := map[string]any{}
	for k, v := range d.meta {
		meta[k] = v
	}
	var target any
	if d.target != "" {
		target = d.target
	}
	return map[string]any{"id": d.id, "projectId": d.project, "ownerId": f.team, "target": target, "readyState": "READY", "readySubstate": d.substate,
		"url": d.host, "meta": meta, "gitSource": map[string]string{"ref": "main", "sha": d.sha}}
}

func (f *fakeVercel) deployLocked(p *vercelProject, meta map[string]string, target string) *vercelDeployment {
	f.clock += 1000
	id := f.id("dpl_")
	d := &vercelDeployment{id: id, project: p.id, host: strings.ToLower(p.name + "-" + strings.TrimPrefix(id, "dpl_") + ".vercel.app"), sha: "abc1234def5678",
		target: target, meta: meta, snapshot: map[string]string{}, created: f.clock}
	envTarget := "preview"
	if target == "production" {
		envTarget, d.substate = "production", "STAGED"
	}
	for _, e := range p.envs {
		if e.target == envTarget {
			d.snapshot[e.key] = e.value
		}
	}
	f.deps[id] = d
	return d
}

func (f *fakeVercel) serve(w http.ResponseWriter, r *http.Request) {
	if !bearer(r, f.token) {
		f.t.Errorf("vercel: request without the control token")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if r.URL.Query().Get("teamId") != f.team {
		f.t.Errorf("vercel: request without the exact teamId")
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if r.URL.Query().Get("decrypt") == "true" {
		f.t.Errorf("vercel: decrypted values requested")
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	f.mu.Lock()
	defer f.mu.Unlock()
	project := func(id string) *vercelProject {
		p := f.byID[id]
		if p == nil || p.deleted {
			return nil
		}
		return p
	}
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/v11/projects":
		var body struct {
			Name string `json:"name"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		p := &vercelProject{id: f.id("prj_"), name: body.Name, team: f.team}
		f.byID[p.id] = p
		// The first git deployment, as a linked repo would produce.
		f.deployLocked(p, map[string]string{}, "")
		f.ev.add("vercel.create_project %s", p.id)
		writeJSON(w, http.StatusOK, map[string]string{"id": p.id, "name": p.name, "accountId": f.team})
	case len(parts) == 3 && parts[0] == "v9" && parts[1] == "projects":
		p := project(parts[2])
		if p == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Method == http.MethodDelete {
			p.deleted = true
			f.ev.add("vercel.delete_project %s", p.id)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if p.pending != nil {
			if p.pending.reads > 0 {
				p.pending.reads--
				p.jobStatus = "in-progress"
			} else {
				f.aliasLocked(p, p.pending.to)
				p.pending, p.jobStatus = nil, "succeeded"
			}
		}
		info := map[string]any{"id": p.id, "name": p.name, "accountId": f.team}
		if p.jobStatus != "" {
			info["lastAliasRequest"] = map[string]string{"jobStatus": p.jobStatus}
		}
		writeJSON(w, http.StatusOK, info)
	case r.Method == http.MethodGet && len(parts) == 4 && parts[0] == "v9" && parts[1] == "projects" && parts[3] == "domains":
		p := project(parts[2])
		q := r.URL.Query()
		if p == nil || q.Get("production") != "true" || q.Get("redirects") != "false" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		// An unverified domain is listed too: it never counts as serving.
		domains := []map[string]any{{"name": "unverified-" + p.id[4:] + ".example.com", "projectId": p.id, "redirect": nil, "gitBranch": nil, "customEnvironmentId": nil, "verified": false}}
		if p.domain != "" {
			domains = append(domains, map[string]any{"name": p.domain, "projectId": p.id, "redirect": nil, "gitBranch": nil, "customEnvironmentId": nil, "verified": true})
		}
		writeJSON(w, http.StatusOK, map[string]any{"domains": domains, "pagination": map[string]any{"next": nil}})
	case r.Method == http.MethodGet && len(parts) == 3 && parts[0] == "v4" && parts[1] == "aliases":
		for _, p := range f.byID {
			if !p.deleted && p.domain == parts[2] && p.id == r.URL.Query().Get("projectId") {
				writeJSON(w, http.StatusOK, map[string]any{"alias": p.domain, "projectId": p.id, "deploymentId": p.alias, "redirect": nil})
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	case r.Method == http.MethodPost && len(parts) == 5 && parts[0] == "v10" && parts[1] == "projects" && parts[3] == "promote":
		p, d := project(parts[2]), f.deps[parts[4]]
		if p == nil || d == nil || d.project != p.id || d.target != "production" || d.substate != "STAGED" || p.pending != nil {
			f.t.Errorf("vercel: unexpected promote %s", parts[4])
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.ev.add("vercel.promote %s", d.id)
		switch {
		case f.promoteError:
			f.aliasLocked(p, d.id)
			p.jobStatus = "succeeded"
			w.WriteHeader(http.StatusInternalServerError)
			return
		case f.promoteJobFails:
			p.jobStatus = "failed"
		case f.aliasDelay == 0:
			f.aliasLocked(p, d.id)
			p.jobStatus = "succeeded"
		default:
			p.pending, p.jobStatus = &aliasJob{to: d.id, reads: f.aliasDelay}, "in-progress"
		}
		writeJSON(w, http.StatusCreated, map[string]any{})
	case r.Method == http.MethodPost && len(parts) == 5 && parts[0] == "v9" && parts[1] == "projects" && parts[3] == "rollback":
		p, d := project(parts[2]), f.deps[parts[4]]
		if p == nil || d == nil || d.project != p.id || d.target != "production" || d.substate != "PROMOTED" || p.alias == d.id {
			f.t.Errorf("vercel: unexpected rollback %s", parts[4])
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.ev.add("vercel.rollback %s", d.id)
		f.aliasLocked(p, d.id)
		p.jobStatus = "succeeded"
		writeJSON(w, http.StatusCreated, map[string]any{})
	case len(parts) == 4 && parts[0] == "v10" && parts[1] == "projects" && parts[3] == "env":
		p := project(parts[2])
		if p == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Method == http.MethodGet {
			list := []map[string]any{}
			for _, e := range p.envs {
				m := map[string]any{"id": e.id, "key": e.key, "type": "sensitive", "target": []string{e.target}, "updatedAt": 1}
				if e.branch != "" {
					m["gitBranch"] = e.branch
				}
				list = append(list, m)
			}
			writeJSON(w, http.StatusOK, map[string]any{"envs": list})
			return
		}
		var body struct {
			Key       string   `json:"key"`
			Type      string   `json:"type"`
			Target    []string `json:"target"`
			GitBranch string   `json:"gitBranch"`
			Value     string   `json:"value"`
		}
		if r.URL.Query().Get("upsert") != "true" || json.NewDecoder(r.Body).Decode(&body) != nil || body.Type != "sensitive" || len(body.Target) != 1 {
			f.t.Errorf("vercel: unexpected env write")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var entry *vercelEnv
		for _, e := range p.envs {
			if e.key == body.Key && e.target == body.Target[0] && e.branch == body.GitBranch {
				entry = e
			}
		}
		if entry == nil {
			entry = &vercelEnv{id: strings.TrimPrefix(f.id("env"), ""), key: body.Key, target: body.Target[0], branch: body.GitBranch}
			p.envs = append(p.envs, entry)
		}
		entry.value = body.Value
		f.ev.add("vercel.env %s", body.Key)
		created := map[string]any{"id": entry.id, "key": entry.key, "type": "sensitive", "target": []string{entry.target}}
		if entry.branch != "" {
			created["gitBranch"] = entry.branch
		}
		writeJSON(w, http.StatusCreated, map[string]any{"created": created, "failed": []any{}})
	case r.Method == http.MethodGet && (r.URL.Path == "/v6/deployments" || r.URL.Path == "/v7/deployments"):
		q := r.URL.Query()
		var list []*vercelDeployment
		for _, d := range f.deps {
			if d.project == q.Get("projectId") && (q.Get("target") != "preview" || d.target == "") {
				list = append(list, d)
			}
		}
		sort.Slice(list, func(i, j int) bool { return list[i].created > list[j].created })
		if q.Get("limit") == "1" && len(list) > 1 {
			list = list[:1]
		}
		items := []map[string]any{}
		for _, d := range list {
			meta := map[string]any{}
			for k, v := range d.meta {
				meta[k] = v
			}
			items = append(items, map[string]any{"uid": d.id, "projectId": d.project, "meta": meta})
		}
		writeJSON(w, http.StatusOK, map[string]any{"deployments": items, "pagination": map[string]any{"next": nil}})
	case r.Method == http.MethodGet && len(parts) == 3 && parts[0] == "v13" && parts[1] == "deployments":
		d := f.deps[parts[2]]
		if d == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, f.deployWire(d))
	case r.Method == http.MethodPost && r.URL.Path == "/v13/deployments":
		var body struct {
			Project                 string            `json:"project"`
			DeploymentID            string            `json:"deploymentId"`
			WithLatestCommit        bool              `json:"withLatestCommit"`
			AutoAssignCustomDomains bool              `json:"autoAssignCustomDomains"`
			Target                  string            `json:"target"`
			Meta                    map[string]string `json:"meta"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		p := project(body.Project)
		src := f.deps[body.DeploymentID]
		if p == nil || src == nil || body.WithLatestCommit || body.AutoAssignCustomDomains || body.Target != src.target || r.URL.Query().Get("forceNew") != "1" {
			f.t.Errorf("vercel: unexpected redeploy %+v", body)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		d := f.deployLocked(p, body.Meta, src.target)
		f.ev.add("vercel.deploy %s", d.id)
		writeJSON(w, http.StatusOK, f.deployWire(d))
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// healthy: every credential the deployment was built with is still valid.
func (f *fakeVercel) healthy(d *vercelDeployment) bool {
	for k, v := range d.snapshot {
		switch {
		case strings.HasPrefix(k, "DATABASE_URL"):
			if !f.neon.validURI(v) {
				return false
			}
		case k == "STRIPE_WEBHOOK_SECRET":
			if !f.stripe.liveSecret(v) {
				return false
			}
		}
	}
	return true
}

// RoundTrip is the deployments' side of the health check (the health
// transport): requests to <deployment host><path> are answered from the
// deployment's state, in memory.
func (f *fakeVercel) RoundTrip(r *http.Request) (*http.Response, error) {
	f.mu.Lock()
	f.healthReqs = append(f.healthReqs, r.Clone(context.Background()))
	var dep *vercelDeployment
	for _, d := range f.deps {
		if d.host == r.URL.Host {
			dep = d
		}
	}
	protect := f.protect
	serving := false
	if dep != nil && dep.meta["envbankOperationId"] != "" {
		p := f.byID[dep.project]
		serving = f.failWhileServing && p != nil && p.alias == dep.id
	}
	f.mu.Unlock()
	status := http.StatusOK
	switch {
	case r.URL.Scheme != "https" || dep == nil:
		status = http.StatusNotFound
	case protect:
		status = http.StatusUnauthorized
	case r.URL.Path != "/api/health" && r.URL.Path != "/":
		status = http.StatusNotFound
	case serving || !f.healthy(dep):
		status = http.StatusServiceUnavailable
	}
	if dep != nil {
		f.ev.add("health %s %d", dep.id, status)
	}
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(`{"ok":true}`)), Header: http.Header{}, Request: r}, nil
}

// ---- Stripe ----

type stripeEndpoint struct {
	id, url, secret string
	events          []string
	deleted         bool
}

type fakeStripe struct {
	t      *testing.T
	key    string
	ev     *events
	sec    *secrets
	mu     sync.Mutex
	next   int
	byID   map[string]*stripeEndpoint
	keys   map[string]bool // idempotency keys seen
	server *httptest.Server
}

func newFakeStripe(t *testing.T, key string, ev *events, sec *secrets) *fakeStripe {
	f := &fakeStripe{t: t, key: key, ev: ev, sec: sec, byID: map[string]*stripeEndpoint{}, keys: map[string]bool{}}
	f.server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeStripe) liveSecret(v string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, e := range f.byID {
		if !e.deleted && e.secret == v {
			return true
		}
	}
	return false
}

func (f *fakeStripe) endpoint(id string) *stripeEndpoint {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.byID[id]
}

func (f *fakeStripe) serve(w http.ResponseWriter, r *http.Request) {
	if !bearer(r, f.key) {
		f.t.Errorf("stripe: request without the control key")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	id := strings.TrimPrefix(r.URL.Path, "/v1/webhook_endpoints/")
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/v1/webhook_endpoints":
		key := r.Header.Get("Idempotency-Key")
		if key == "" || f.keys[key] {
			f.t.Errorf("stripe: missing or reused idempotency key")
		}
		f.keys[key] = true
		raw, _ := io.ReadAll(bufio.NewReader(r.Body))
		form, _ := url.ParseQuery(string(raw))
		f.next++
		e := &stripeEndpoint{id: fmt.Sprintf("we_e2e%d", f.next), url: form.Get("url"), events: form["enabled_events[]"], secret: f.sec.issue("whsec_")}
		f.byID[e.id] = e
		f.ev.add("stripe.create %s", e.id)
		writeJSON(w, http.StatusOK, map[string]any{"id": e.id, "url": e.url, "enabled_events": e.events, "secret": e.secret})
	case r.Method == http.MethodGet && id != r.URL.Path:
		e := f.byID[id]
		if e == nil || e.deleted {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"id": e.id, "url": e.url, "enabled_events": e.events})
	case r.Method == http.MethodDelete && id != r.URL.Path:
		e := f.byID[id]
		if e == nil || e.deleted {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		e.deleted = true
		f.ev.add("stripe.delete %s", e.id)
		writeJSON(w, http.StatusOK, map[string]any{"id": e.id, "deleted": true})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// ---- wiring ----

type fakes struct {
	ev     *events
	sec    *secrets
	neon   *fakeNeon
	vercel *fakeVercel
	stripe *fakeStripe
	team   string
	keys   map[string]string // control credentials by record
}

func newFakes(t *testing.T) *fakes {
	ev, sec := &events{}, &secrets{}
	k := map[string]string{
		"CONTROL_NEON_API_KEY": provideractiontest.Sentinel("napi_"),
		"CONTROL_VERCEL_TOKEN": provideractiontest.Sentinel("vcp_"),
		"CONTROL_STRIPE_KEY":   provideractiontest.Sentinel("rk_test_"),
	}
	fx := &fakes{ev: ev, sec: sec, team: "team_e2e123", keys: k}
	fx.neon = newFakeNeon(t, k["CONTROL_NEON_API_KEY"], ev, sec)
	fx.stripe = newFakeStripe(t, k["CONTROL_STRIPE_KEY"], ev, sec)
	fx.vercel = newFakeVercel(t, k["CONTROL_VERCEL_TOKEN"], fx.team, ev, fx.neon, fx.stripe)
	return fx
}

// factory returns a live factory pointed at the fakes (the only way to set
// test endpoints: this unexported field, from this package's tests).
func (fx *fakes) factory(cfg Config) *Factory {
	f, err := New(cfg)
	if err != nil {
		panic(err)
	}
	f.ep = testEndpoints{neon: fx.neon.server.URL, vercel: fx.vercel.server.URL, stripe: fx.stripe.server.URL,
		health: fx.vercel, neonSQL: fx.neon.connect}
	return f
}

func (fx *fakes) allSecrets() []string {
	out := fx.sec.list()
	for _, v := range fx.keys {
		out = append(out, v)
	}
	// URIs embed the passwords, which are scanned for on their own.
	return out
}
