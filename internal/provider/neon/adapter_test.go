package neon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GeorgeQLe/envbank/internal/lifecycle"
	"github.com/GeorgeQLe/envbank/internal/provider"
)

const (
	testKey     = "napi_test_control_key_fixture"
	canary      = "CANARYPASSWORD7f3a"
	testProject = "polished-pond-123456"
	testBranch  = "br-wispy-dew-a1b2c3"
	testRole    = "neondb_owner"
	testDB      = "neondb"
	opA         = "0b2a4f5e-1c2d-4e5f-8a9b-0c1d2e3f4a5b"
	opB         = "1c3b5a6f-2d3e-4f50-9bac-1d2e3f4a5b6c"
	directURI   = "postgresql://neondb_owner:" + canary + "@ep-cool-1234.us-east-2.aws.neon.tech/neondb?sslmode=require&channel_binding=require"
	pooledURI   = "postgresql://neondb_owner:" + canary + "@ep-cool-1234-pooler.us-east-2.aws.neon.tech/neondb?sslmode=require&channel_binding=require"
)

// jsonURI encodes like Neon's Go backend, escaping '&' as &.
func jsonURI(uri string) string {
	encoded, _ := json.Marshal(uri)
	return string(encoded)
}

type recordedCall struct {
	Method string
	Path   string
	Query  url.Values
	Body   []byte
}

type fakeNeon struct {
	t      *testing.T
	mu     sync.Mutex
	routes map[string]http.HandlerFunc
	calls  []recordedCall
	server *httptest.Server
}

func newFake(t *testing.T) *fakeNeon {
	t.Helper()
	fake := &fakeNeon{t: t, routes: map[string]http.HandlerFunc{}}
	fake.server = httptest.NewServer(http.HandlerFunc(fake.serve))
	t.Cleanup(fake.server.Close)
	return fake
}

func (fake *fakeNeon) serve(response http.ResponseWriter, request *http.Request) {
	body, _ := io.ReadAll(request.Body)
	key := request.Method + " " + request.URL.EscapedPath()
	fake.mu.Lock()
	fake.calls = append(fake.calls, recordedCall{Method: request.Method, Path: request.URL.EscapedPath(),
		Query: request.URL.Query(), Body: body})
	handler := fake.routes[key]
	fake.mu.Unlock()
	if request.Header.Get("Authorization") != "Bearer "+testKey {
		fake.t.Errorf("request did not carry the expected bearer key")
	}
	if handler == nil {
		response.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(response, `{"code":"","message":"`+canary+`"}`)
		return
	}
	request.Body = io.NopCloser(bytes.NewReader(body))
	handler(response, request)
}

func (fake *fakeNeon) handle(method, path string, handler http.HandlerFunc) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.routes[method+" /api/v2"+path] = handler
}

func (fake *fakeNeon) json(method, path string, status int, body string) {
	fake.handle(method, path, func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(status)
		_, _ = io.WriteString(response, body)
	})
}

func (fake *fakeNeon) count(method, path string) int {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	total := 0
	for _, call := range fake.calls {
		if call.Method == method && call.Path == "/api/v2"+path {
			total++
		}
	}
	return total
}

func (fake *fakeNeon) total() int {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	return len(fake.calls)
}

func (fake *fakeNeon) callsTo(method, path string) []recordedCall {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	var matched []recordedCall
	for _, call := range fake.calls {
		if call.Method == method && call.Path == "/api/v2"+path {
			matched = append(matched, call)
		}
	}
	return matched
}

func (fake *fakeNeon) adapter(t *testing.T, options Options) *Adapter {
	t.Helper()
	options.Endpoint = fake.server.URL
	options.Client = fake.server.Client()
	adapter, err := New([]byte(testKey), options)
	if err != nil {
		t.Fatal(err)
	}
	adapter.pollInterval = time.Millisecond
	adapter.operationTimeout = 2 * time.Second
	t.Cleanup(adapter.Close)
	return adapter
}

type vault struct {
	mu       sync.Mutex
	values   map[string][]byte
	failFor  string
	revision int64
}

func (store *vault) StoreSecret(_ context.Context, record string, provide func(func([]byte) error) error) (int64, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if record == store.failFor {
		return 0, errors.New("vault write failed: " + canary)
	}
	err := provide(func(value []byte) error {
		if store.values == nil {
			store.values = map[string][]byte{}
		}
		store.values[record] = append([]byte(nil), value...)
		return nil
	})
	store.revision++
	return store.revision, err
}

func (store *vault) get(record string) string {
	store.mu.Lock()
	defer store.mu.Unlock()
	return string(store.values[record])
}

func sinks(t *testing.T, store *vault) (*lifecycle.SecretSink, *lifecycle.SecretSink) {
	t.Helper()
	pooled, err := lifecycle.NewSecretSink(store, "DATABASE_URL")
	if err != nil {
		t.Fatal(err)
	}
	direct, err := lifecycle.NewSecretSink(store, "DATABASE_URL_UNPOOLED")
	if err != nil {
		t.Fatal(err)
	}
	return pooled, direct
}

func expectCode(t *testing.T, err error, code string) provider.Error {
	t.Helper()
	var safe provider.Error
	if !errors.As(err, &safe) {
		t.Fatalf("expected typed provider error %s, got %T %v", code, err, err)
	}
	if safe.Code != code {
		t.Fatalf("expected code %s, got %s (%v)", code, safe.Code, err)
	}
	if strings.Contains(fmt.Sprint(err), canary) || strings.Contains(fmt.Sprintf("%+v %#v", err, err), canary) || safe.Validate() != nil {
		t.Fatalf("unsafe provider error: %v", err)
	}
	return safe
}

func assertNoCanary(t *testing.T, values ...any) {
	t.Helper()
	for _, value := range values {
		encoded, _ := json.Marshal(value)
		if strings.Contains(string(encoded), canary) || strings.Contains(fmt.Sprintf("%+v %#v", value, value), canary) {
			t.Fatalf("secret canary leaked into %T", value)
		}
	}
}

func createBody(uris ...string) string {
	entries := make([]string, 0, len(uris))
	for _, uri := range uris {
		entries = append(entries, `{"connection_uri":`+jsonURI(uri)+`,"connection_parameters":{"database":"`+testDB+
			`","role":"`+testRole+`","password":"`+canary+`","host":"ep-cool-1234.us-east-2.aws.neon.tech"}}`)
	}
	return `{"project":{"id":"` + testProject + `","name":"envbank throwaway"},` +
		`"branch":{"id":"` + testBranch + `","project_id":"` + testProject + `"},` +
		`"roles":[{"branch_id":"` + testBranch + `","name":"` + testRole + `","password":"` + canary + `"}],` +
		`"databases":[{"branch_id":"` + testBranch + `","name":"` + testDB + `","owner_name":"` + testRole + `"}],` +
		`"connection_uris":[` + strings.Join(entries, ",") + `],` +
		`"operations":[{"id":"` + opA + `","project_id":"` + testProject + `","action":"create_timeline","status":"running"}]}`
}

func connectionURIPath() string { return "/projects/" + testProject + "/connection_uri" }
func operationPath(id string) string {
	return "/projects/" + testProject + "/operations/" + id
}
func rolePath(role string) string {
	return "/projects/" + testProject + "/branches/" + testBranch + "/roles/" + role
}

// connectionURIs serves pooled/direct URIs according to the query.
func (fake *fakeNeon) connectionURIs(t *testing.T, role string) {
	fake.handle(http.MethodGet, connectionURIPath(), func(response http.ResponseWriter, request *http.Request) {
		query := request.URL.Query()
		if query.Get("branch_id") != testBranch || query.Get("database_name") != testDB || query.Get("role_name") != role {
			t.Errorf("unexpected connection_uri query %v", query)
		}
		uri := strings.ReplaceAll(directURI, testRole, role)
		if query.Get("pooled") == "true" {
			uri = strings.ReplaceAll(pooledURI, testRole, role)
		} else if query.Get("pooled") != "false" {
			t.Errorf("pooled flag missing")
		}
		_, _ = io.WriteString(response, `{"uri":`+jsonURI(uri)+`}`)
	})
}

// operationAfter reports "running" for the first n polls, then "finished".
func (fake *fakeNeon) operationAfter(id string, n int32) *atomic.Int32 {
	var polls atomic.Int32
	fake.handle(http.MethodGet, operationPath(id), func(response http.ResponseWriter, _ *http.Request) {
		status := "running"
		if polls.Add(1) > n {
			status = "finished"
		}
		_, _ = io.WriteString(response, `{"operation":{"id":"`+id+`","project_id":"`+testProject+`","status":"`+status+`"}}`)
	})
	return &polls
}

func TestNewValidatesKeyEndpointAndOrg(t *testing.T) {
	for _, key := range []string{"", "has space", "tab\tkey", strings.Repeat("k", maxKeyBytes+1), "é"} {
		if _, err := New([]byte(key), Options{}); err == nil {
			t.Fatalf("accepted key %q", key)
		}
	}
	for _, endpoint := range []string{"http://console.neon.tech", "https://console.neon.tech.evil", "https://evil.test/api/v2",
		"https://console.neon.tech:8443", "https://user@console.neon.tech", "https://console.neon.tech/api/v1",
		"https://console.neon.tech/api/v2?x=1", "http://localhost:1", "http://10.0.0.1"} {
		if _, err := New([]byte(testKey), Options{Endpoint: endpoint}); err == nil {
			t.Fatalf("accepted endpoint %q", endpoint)
		}
	}
	for _, endpoint := range []string{"", "https://console.neon.tech", "https://console.neon.tech/api/v2", "http://127.0.0.1:9", "http://[::1]:9/api/v2"} {
		adapter, err := New([]byte(testKey), Options{Endpoint: endpoint})
		if err != nil {
			t.Fatalf("refused endpoint %q: %v", endpoint, err)
		}
		if !strings.HasSuffix(adapter.base, "/api/v2") {
			t.Fatalf("base=%s", adapter.base)
		}
		adapter.Close()
	}
	if _, err := New([]byte(testKey), Options{OrgID: "Org_bad"}); err == nil {
		t.Fatal("accepted invalid org ID")
	}
	adapter, err := New([]byte(testKey), Options{OrgID: "org-misty-sun-12345678"})
	if err != nil {
		t.Fatal(err)
	}
	if formatted := fmt.Sprintf("%v %+v %s %#v", adapter, adapter, adapter, adapter); strings.Contains(formatted, testKey) || adapter.String() != "Neon adapter [credential REDACTED]" {
		t.Fatalf("adapter formatting leaked the key: %s", formatted)
	}
}

func TestIDValidation(t *testing.T) {
	valid := map[string]func(string) bool{"project": ValidProjectID, "branch": ValidBranchID, "role": ValidRoleName, "database": ValidDatabaseName}
	accept := map[string][]string{
		"project":  {testProject, "a", "abc-123"},
		"branch":   {testBranch, "br-a"},
		"role":     {testRole, "app_a", "_x"},
		"database": {testDB, "app_db"},
	}
	refuse := map[string][]string{
		"project":  {"", "Polished-pond", "a--b", "-a", "a-", "a/b", "a b", "a.b", "br-../x", strings.Repeat("a", 65), "polished-pond-123456?x"},
		"branch":   {"", "br-", "main", "br-A", "br-a/../b", "br_a", testProject},
		"role":     {"", "App", "1app", "pg_signal", "neon_superuser", "postgres", "cloud_admin", "a-b", "a;drop", strings.Repeat("a", 64)},
		"database": {"", "postgres", "template1", "pg_x", "Db", "a b"},
	}
	for kind, values := range accept {
		for _, value := range values {
			if !valid[kind](value) {
				t.Fatalf("%s %q refused", kind, value)
			}
		}
	}
	for kind, values := range refuse {
		for _, value := range values {
			if valid[kind](value) {
				t.Fatalf("%s %q accepted", kind, value)
			}
		}
	}
}

func TestIdentifyUserAndOrg(t *testing.T) {
	fake := newFake(t)
	fake.json(http.MethodGet, "/users/me", 200, `{"id":"5f3b7c2a-1111-4222-8333-944455556666","email":"x@example.test","login":"`+canary+`"}`)
	identity, err := fake.adapter(t, Options{}).Identify(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if identity != (provider.Identity{Provider: "neon", ID: "user:5f3b7c2a-1111-4222-8333-944455556666"}) {
		t.Fatalf("identity=%+v", identity)
	}
	fake.json(http.MethodGet, "/organizations/org-misty-sun-12345678", 200, `{"id":"org-misty-sun-12345678","name":"`+canary+`"}`)
	identity, err = fake.adapter(t, Options{OrgID: "org-misty-sun-12345678"}).Identify(context.Background())
	if err != nil || identity.ID != "org:org-misty-sun-12345678" {
		t.Fatalf("identity=%+v err=%v", identity, err)
	}
	assertNoCanary(t, identity)

	fake.json(http.MethodGet, "/organizations/org-other-12345678", 200, `{"id":"org-misty-sun-12345678"}`)
	_, err = fake.adapter(t, Options{OrgID: "org-other-12345678"}).Identify(context.Background())
	expectCode(t, err, "INVALID_IDENTITY")
	fake.json(http.MethodGet, "/users/me", 200, `{"id":"`+canary+` x"}`)
	_, err = fake.adapter(t, Options{}).Identify(context.Background())
	expectCode(t, err, "INVALID_IDENTITY")
	fake.json(http.MethodGet, "/users/me", 401, `{"message":"`+canary+`"}`)
	_, err = fake.adapter(t, Options{}).Identify(context.Background())
	expectCode(t, err, "UNAUTHORIZED")
}

func TestCreateProjectStoresDirectAndDerivedPooledURIs(t *testing.T) {
	fake := newFake(t)
	fake.json(http.MethodPost, "/projects", 201, createBody(directURI))
	fake.connectionURIs(t, testRole)
	polls := fake.operationAfter(opA, 2)
	store := &vault{}
	pooled, direct := sinks(t, store)
	adapter := fake.adapter(t, Options{OrgID: "org-misty-sun-12345678"})
	info, err := adapter.CreateProject(context.Background(), ProjectSpec{Name: "envbank throwaway", RegionID: "aws-us-east-2", PGVersion: 17}, pooled, direct)
	if err != nil {
		t.Fatal(err)
	}
	if info != (ProjectInfo{ProjectID: testProject, BranchID: testBranch, Role: testRole, Database: testDB}) {
		t.Fatalf("info=%+v", info)
	}
	assertNoCanary(t, info)
	if store.get("DATABASE_URL") != pooledURI || store.get("DATABASE_URL_UNPOOLED") != directURI {
		t.Fatalf("stored URIs are wrong")
	}
	if polls.Load() != 3 {
		t.Fatalf("operation polled %d times", polls.Load())
	}
	var body map[string]map[string]any
	if err := json.Unmarshal(fake.callsTo(http.MethodPost, "/projects")[0].Body, &body); err != nil {
		t.Fatal(err)
	}
	project := body["project"]
	if project["name"] != "envbank throwaway" || project["region_id"] != "aws-us-east-2" || project["pg_version"] != float64(17) ||
		project["org_id"] != "org-misty-sun-12345678" || len(project) != 4 || len(body) != 1 {
		t.Fatalf("body=%v", body)
	}
	if calls := fake.callsTo(http.MethodGet, connectionURIPath()); len(calls) != 1 || calls[0].Query.Get("pooled") != "true" {
		t.Fatalf("pooled URI was not derived exactly once: %v", calls)
	}
}

func TestCreateProjectUsesPooledURIFromResponse(t *testing.T) {
	fake := newFake(t)
	fake.json(http.MethodPost, "/projects", 201, createBody(directURI, pooledURI))
	fake.operationAfter(opA, 0)
	store := &vault{}
	pooled, direct := sinks(t, store)
	if _, err := fake.adapter(t, Options{}).CreateProject(context.Background(), ProjectSpec{Name: "x"}, pooled, direct); err != nil {
		t.Fatal(err)
	}
	if fake.count(http.MethodGet, connectionURIPath()) != 0 {
		t.Fatal("pooled URI fetched although the response had one")
	}
	if store.get("DATABASE_URL") != pooledURI || store.get("DATABASE_URL_UNPOOLED") != directURI {
		t.Fatal("stored URIs are wrong")
	}
	if body := string(fake.callsTo(http.MethodPost, "/projects")[0].Body); body != `{"project":{"name":"x"}}` {
		t.Fatalf("body=%s", body)
	}
}

func TestCreateProjectRefusesInvalidRequestsBeforeSending(t *testing.T) {
	fake := newFake(t)
	adapter := fake.adapter(t, Options{})
	store := &vault{}
	pooled, direct := sinks(t, store)
	for _, spec := range []ProjectSpec{{}, {Name: " lead"}, {Name: "trail "}, {Name: "bad/name"}, {Name: strings.Repeat("a", 65)},
		{Name: "ok", RegionID: "us-east-2"}, {Name: "ok", RegionID: "aws-US"}, {Name: "ok", PGVersion: 13}, {Name: "ok", PGVersion: 19}} {
		_, err := adapter.CreateProject(context.Background(), spec, pooled, direct)
		expectCode(t, err, "INVALID_REQUEST")
	}
	for _, pair := range [][2]*lifecycle.SecretSink{{nil, direct}, {pooled, nil}, {pooled, pooled}} {
		_, err := adapter.CreateProject(context.Background(), ProjectSpec{Name: "ok"}, pair[0], pair[1])
		expectCode(t, err, "INVALID_REQUEST")
	}
	if fake.total() != 0 {
		t.Fatal("invalid request reached Neon")
	}
}

func TestCreateProjectMalformedResponses(t *testing.T) {
	foreignRole := strings.Replace(createBody(directURI), `"role":"`+testRole+`"`, `"role":"Bad-Role"`, 1)
	cases := map[string]struct {
		status        int
		body          string
		code          string
		wantProjectID bool
	}{
		"not json":          {201, `{"project":`, "INVALID_RESPONSE", false},
		"bad project id":    {201, strings.Replace(createBody(directURI), testProject, "Bad_ID", 1), "INVALID_RESPONSE", false},
		"bad branch":        {201, strings.Replace(createBody(directURI), `"id":"`+testBranch+`"`, `"id":"main"`, 1), "INVALID_RESPONSE", true},
		"no uris":           {201, createBody(), "INVALID_RESPONSE", true},
		"bad role":          {201, foreignRole, "INVALID_RESPONSE", true},
		"not postgres":      {201, createBody("https://" + canary + "@example.test/"), "INVALID_RESPONSE", true},
		"no credentials":    {201, createBody("postgresql://ep-cool-1234.us-east-2.aws.neon.tech/neondb"), "INVALID_RESPONSE", true},
		"control character": {201, createBody("postgresql://a:" + canary + "\n@ep-cool-1234.aws.neon.tech/neondb"), "INVALID_RESPONSE", true},
		"only pooled":       {201, createBody(pooledURI), "INVALID_RESPONSE", true},
		"uri not string":    {201, strings.Replace(createBody(directURI), jsonURI(directURI), `{"x":"`+canary+`"}`, 1), "INVALID_RESPONSE", true},
		"bad operation":     {201, strings.Replace(createBody(directURI, pooledURI), opA, "not-a-uuid", 1), "INVALID_OPERATION", true},
		"oversized":         {201, `{"project":{"id":"` + testProject + `"},"pad":"` + strings.Repeat(canary, maxResponseBytes/len(canary)+1) + `"}`, "RESPONSE_TOO_LARGE", false},
		"unauthorized":      {401, `{"message":"` + canary + `"}`, "UNAUTHORIZED", false},
		"limit":             {422, `{"message":"` + canary + `"}`, "UNPROCESSABLE", false},
		"server":            {500, canary, "SERVER_ERROR", false},
		"redirect":          {307, canary, "REDIRECT_REJECTED", false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			fake := newFake(t)
			fake.handle(http.MethodPost, "/projects", func(response http.ResponseWriter, _ *http.Request) {
				if c.status == 307 {
					response.Header().Set("Location", "https://evil.test/")
				}
				response.WriteHeader(c.status)
				_, _ = io.WriteString(response, c.body)
			})
			fake.connectionURIs(t, testRole)
			fake.operationAfter(opA, 0)
			store := &vault{}
			pooled, direct := sinks(t, store)
			info, err := fake.adapter(t, Options{}).CreateProject(context.Background(), ProjectSpec{Name: "x"}, pooled, direct)
			safe := expectCode(t, err, c.code)
			if (info.ProjectID != "") != c.wantProjectID {
				t.Fatalf("info=%+v", info)
			}
			assertNoCanary(t, info)
			if c.code == "SERVER_ERROR" && safe.Retry != provider.RetryAmbiguous {
				t.Fatalf("5xx create retry=%s", safe.Retry)
			}
			if store.get("DATABASE_URL") != "" && c.code != "INVALID_OPERATION" {
				t.Fatal("value stored despite failure")
			}
		})
	}
}

func TestCreateProjectStoreFailureIsReportedWithProjectID(t *testing.T) {
	fake := newFake(t)
	fake.json(http.MethodPost, "/projects", 201, createBody(directURI, pooledURI))
	store := &vault{failFor: "DATABASE_URL_UNPOOLED"}
	pooled, direct := sinks(t, store)
	info, err := fake.adapter(t, Options{}).CreateProject(context.Background(), ProjectSpec{Name: "x"}, pooled, direct)
	expectCode(t, err, "STORE_REQUIRED")
	if info.ProjectID != testProject {
		t.Fatalf("info=%+v", info)
	}
}

func TestCreateProjectOperationFailureAndTimeout(t *testing.T) {
	fake := newFake(t)
	fake.json(http.MethodPost, "/projects", 201, createBody(directURI, pooledURI))
	fake.json(http.MethodGet, operationPath(opA), 200, `{"operation":{"id":"`+opA+`","status":"failed","error":"`+canary+`"}}`)
	pooled, direct := sinks(t, &vault{})
	info, err := fake.adapter(t, Options{}).CreateProject(context.Background(), ProjectSpec{Name: "x"}, pooled, direct)
	expectCode(t, err, "OPERATION_FAILED")
	if info.ProjectID != testProject {
		t.Fatal("project ID missing after operation failure")
	}

	fake.json(http.MethodGet, operationPath(opA), 200, `{"operation":{"id":"`+opA+`","status":"running"}}`)
	adapter := fake.adapter(t, Options{})
	adapter.operationTimeout = 30 * time.Millisecond
	pooled, direct = sinks(t, &vault{})
	_, err = adapter.CreateProject(context.Background(), ProjectSpec{Name: "x"}, pooled, direct)
	expectCode(t, err, "OPERATION_TIMEOUT")
}

func resetBody(role string, ops ...string) string {
	entries := make([]string, 0, len(ops))
	for _, op := range ops {
		entries = append(entries, `{"id":"`+op+`","project_id":"`+testProject+`","action":"apply_config","status":"scheduling"}`)
	}
	return `{"role":{"branch_id":"` + testBranch + `","name":"` + role + `","password":"` + canary + `"},"operations":[` + strings.Join(entries, ",") + `]}`
}

func TestResetRolePasswordWaitsThenStoresBothURIs(t *testing.T) {
	fake := newFake(t)
	var locked atomic.Int32
	fake.handle(http.MethodPost, rolePath("app_b")+"/reset_password", func(response http.ResponseWriter, _ *http.Request) {
		if locked.Add(1) == 1 {
			response.WriteHeader(http.StatusLocked)
			_, _ = io.WriteString(response, `{"message":"`+canary+`"}`)
			return
		}
		_, _ = io.WriteString(response, resetBody("app_b", opA, opB))
	})
	pollsA := fake.operationAfter(opA, 1)
	pollsB := fake.operationAfter(opB, 0)
	fake.connectionURIs(t, "app_b")
	store := &vault{}
	pooled, direct := sinks(t, store)
	err := fake.adapter(t, Options{}).ResetRolePassword(context.Background(), testProject, testBranch, "app_b", testDB, pooled, direct)
	if err != nil {
		t.Fatal(err)
	}
	if locked.Load() != 2 || pollsA.Load() != 2 || pollsB.Load() != 1 {
		t.Fatalf("locked=%d pollsA=%d pollsB=%d", locked.Load(), pollsA.Load(), pollsB.Load())
	}
	if store.get("DATABASE_URL") != strings.ReplaceAll(pooledURI, testRole, "app_b") ||
		store.get("DATABASE_URL_UNPOOLED") != strings.ReplaceAll(directURI, testRole, "app_b") {
		t.Fatal("stored URIs are wrong")
	}
}

func TestResetRolePasswordFailures(t *testing.T) {
	store := &vault{}
	fake := newFake(t)
	adapter := fake.adapter(t, Options{})
	pooled, direct := sinks(t, store)
	for _, args := range [][4]string{{"Bad", testBranch, "app_b", testDB}, {testProject, "main", "app_b", testDB},
		{testProject, testBranch, "neon_superuser", testDB}, {testProject, testBranch, "app_b", "postgres"},
		{testProject, testBranch, "app_b/../x", testDB}} {
		expectCode(t, adapter.ResetRolePassword(context.Background(), args[0], args[1], args[2], args[3], pooled, direct), "INVALID_REQUEST")
	}
	expectCode(t, adapter.ResetRolePassword(context.Background(), testProject, testBranch, "app_b", testDB, pooled, pooled), "INVALID_REQUEST")
	if fake.total() != 0 {
		t.Fatal("invalid reset reached Neon")
	}

	expectCode(t, adapter.ResetRolePassword(context.Background(), testProject, testBranch, "app_b", testDB, pooled, direct), "NOT_FOUND")

	// A pooled URI served where a direct one was requested is refused.
	fake.json(http.MethodPost, rolePath("app_b")+"/reset_password", 200, resetBody("app_b"))
	fake.json(http.MethodGet, connectionURIPath(), 200, `{"uri":`+jsonURI(pooledURI)+`}`)
	pooled, direct = sinks(t, store)
	expectCode(t, adapter.ResetRolePassword(context.Background(), testProject, testBranch, "app_b", testDB, pooled, direct), "INVALID_CONNECTION_URI")
	fake.json(http.MethodGet, connectionURIPath(), 200, `{"uri":"postgresql://x:`+canary+`@h/db\u0000"}`)
	pooled, direct = sinks(t, store)
	expectCode(t, adapter.ResetRolePassword(context.Background(), testProject, testBranch, "app_b", testDB, pooled, direct), "INVALID_CONNECTION_URI")
	fake.json(http.MethodGet, connectionURIPath(), 200, `{"uri":`)
	pooled, direct = sinks(t, store)
	expectCode(t, adapter.ResetRolePassword(context.Background(), testProject, testBranch, "app_b", testDB, pooled, direct), "INVALID_RESPONSE")
	if store.get("DATABASE_URL") != "" || store.get("DATABASE_URL_UNPOOLED") != "" {
		t.Fatal("value stored despite failure")
	}

	// A mismatched role in the reset response is refused before polling.
	fake.json(http.MethodPost, rolePath("app_b")+"/reset_password", 200, resetBody("app_a"))
	pooled, direct = sinks(t, store)
	expectCode(t, adapter.ResetRolePassword(context.Background(), testProject, testBranch, "app_b", testDB, pooled, direct), "INVALID_RESPONSE")

	// Persistent 423 is bounded.
	lockedBefore := fake.count(http.MethodPost, rolePath("app_b")+"/reset_password")
	fake.json(http.MethodPost, rolePath("app_b")+"/reset_password", 423, canary)
	pooled, direct = sinks(t, store)
	safe := expectCode(t, adapter.ResetRolePassword(context.Background(), testProject, testBranch, "app_b", testDB, pooled, direct), "LOCKED")
	if safe.Retry != provider.RetrySafe || fake.count(http.MethodPost, rolePath("app_b")+"/reset_password") != lockedBefore+maxLockedAttempts {
		t.Fatalf("locked retry=%s", safe.Retry)
	}

	// A transient failure on a reset is ambiguous and never retried.
	before := fake.count(http.MethodPost, rolePath("app_b")+"/reset_password")
	fake.json(http.MethodPost, rolePath("app_b")+"/reset_password", 502, canary)
	pooled, direct = sinks(t, store)
	safe = expectCode(t, adapter.ResetRolePassword(context.Background(), testProject, testBranch, "app_b", testDB, pooled, direct), "SERVER_ERROR")
	if safe.Retry != provider.RetryAmbiguous || fake.count(http.MethodPost, rolePath("app_b")+"/reset_password") != before+1 {
		t.Fatal("ambiguous reset was retried")
	}
}

func TestEnsureRole(t *testing.T) {
	fake := newFake(t)
	adapter := fake.adapter(t, Options{})
	fake.json(http.MethodGet, rolePath("app_a"), 200, `{"role":{"name":"app_a","branch_id":"`+testBranch+`"}}`)
	created, err := adapter.EnsureRole(context.Background(), testProject, testBranch, "app_a")
	if err != nil || created {
		t.Fatalf("created=%v err=%v", created, err)
	}

	fake.json(http.MethodPost, "/projects/"+testProject+"/branches/"+testBranch+"/roles", 201,
		`{"role":{"name":"app_b","branch_id":"`+testBranch+`","password":"`+canary+`"},"operations":[{"id":"`+opA+`","status":"running"}]}`)
	polls := fake.operationAfter(opA, 0)
	created, err = adapter.EnsureRole(context.Background(), testProject, testBranch, "app_b")
	if err != nil || !created || polls.Load() != 1 {
		t.Fatalf("created=%v err=%v polls=%d", created, err, polls.Load())
	}
	body := fake.callsTo(http.MethodPost, "/projects/"+testProject+"/branches/"+testBranch+"/roles")[0].Body
	if string(body) != `{"role":{"name":"app_b"}}` {
		t.Fatalf("body=%s", body)
	}

	// A concurrent create (409) is resolved by a fresh read.
	var reads atomic.Int32
	fake.handle(http.MethodGet, rolePath("app_c"), func(response http.ResponseWriter, _ *http.Request) {
		if reads.Add(1) == 1 {
			response.WriteHeader(404)
			return
		}
		_, _ = io.WriteString(response, `{"role":{"name":"app_c"}}`)
	})
	fake.json(http.MethodPost, "/projects/"+testProject+"/branches/"+testBranch+"/roles", 409, canary)
	created, err = adapter.EnsureRole(context.Background(), testProject, testBranch, "app_c")
	if err != nil || created || reads.Load() != 2 {
		t.Fatalf("created=%v err=%v reads=%d", created, err, reads.Load())
	}

	fake.json(http.MethodPost, "/projects/"+testProject+"/branches/"+testBranch+"/roles", 201, `{"role":{"name":"other"}}`)
	_, err = adapter.EnsureRole(context.Background(), testProject, testBranch, "app_d")
	expectCode(t, err, "INVALID_RESPONSE")
	fake.json(http.MethodGet, rolePath("app_e"), 200, `{"role":{"name":"other"}}`)
	_, err = adapter.EnsureRole(context.Background(), testProject, testBranch, "app_e")
	expectCode(t, err, "INVALID_RESPONSE")
	fake.json(http.MethodGet, rolePath("app_f"), 403, canary)
	_, err = adapter.EnsureRole(context.Background(), testProject, testBranch, "app_f")
	expectCode(t, err, "FORBIDDEN")
	_, err = adapter.EnsureRole(context.Background(), testProject, testBranch, "pg_monitor")
	expectCode(t, err, "INVALID_REQUEST")
}

func TestDeleteProject(t *testing.T) {
	fake := newFake(t)
	adapter := fake.adapter(t, Options{})
	fake.json(http.MethodDelete, "/projects/"+testProject, 200, `{"project":{"id":"`+testProject+`"}}`)
	if err := adapter.DeleteProject(context.Background(), testProject); err != nil {
		t.Fatal(err)
	}
	expectCode(t, adapter.DeleteProject(context.Background(), "other-project-1"), "NOT_FOUND")
	fake.json(http.MethodDelete, "/projects/"+testProject, 200, `{"project":{"id":"other-project-1"}}`)
	expectCode(t, adapter.DeleteProject(context.Background(), testProject), "INVALID_RESPONSE")
	before := fake.total()
	expectCode(t, adapter.DeleteProject(context.Background(), "../users/me"), "INVALID_REQUEST")
	if fake.total() != before {
		t.Fatal("invalid delete reached Neon")
	}
}

func TestClosedAdapterSendsNothing(t *testing.T) {
	fake := newFake(t)
	adapter := fake.adapter(t, Options{})
	adapter.Close()
	if adapter.key != nil {
		t.Fatal("key not wiped")
	}
	_, err := adapter.Identify(context.Background())
	expectCode(t, err, "CLOSED")
	if fake.total() != 0 {
		t.Fatal("closed adapter sent a request")
	}
	var nilAdapter *Adapter
	_, err = nilAdapter.Identify(context.Background())
	expectCode(t, err, "NOT_CONFIGURED")
}

func TestCloseWipesRetainedKeyBytes(t *testing.T) {
	adapter, err := New([]byte(testKey), Options{})
	if err != nil {
		t.Fatal(err)
	}
	retained := adapter.key
	adapter.Close()
	for _, character := range retained {
		if character != 0 {
			t.Fatal("key bytes were not wiped")
		}
	}
}

// capturingBody records every buffer the adapter hands to Read so the test
// can prove those buffers were wiped after the call returned.
type capturingBody struct {
	reader  io.Reader
	mu      *sync.Mutex
	buffers *[][]byte
}

func (body capturingBody) Read(buffer []byte) (int, error) {
	read, err := body.reader.Read(buffer)
	body.mu.Lock()
	*body.buffers = append(*body.buffers, buffer[:read])
	body.mu.Unlock()
	return read, err
}
func (capturingBody) Close() error { return nil }

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestResponseBuffersHoldingSecretsAreWiped(t *testing.T) {
	var mu sync.Mutex
	var buffers [][]byte
	respond := func(body string) *http.Response {
		// Unknown length forces chunked reads and buffer growth.
		return &http.Response{StatusCode: 200, Header: http.Header{}, ContentLength: -1,
			Body: capturingBody{reader: io.MultiReader(strings.NewReader(body), strings.NewReader(strings.Repeat(" ", 40<<10))), mu: &mu, buffers: &buffers}}
	}
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch {
		case request.Method == http.MethodPost:
			return respond(resetBody("app_b")), nil
		case request.URL.Query().Get("pooled") == "true":
			return respond(`{"uri":` + jsonURI(strings.ReplaceAll(pooledURI, testRole, "app_b")) + `}`), nil
		default:
			return respond(`{"uri":` + jsonURI(strings.ReplaceAll(directURI, testRole, "app_b")) + `}`), nil
		}
	})}
	adapter, err := New([]byte(testKey), Options{Endpoint: "http://127.0.0.1:1", Client: client})
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()
	store := &vault{}
	pooled, direct := sinks(t, store)
	if err := adapter.ResetRolePassword(context.Background(), testProject, testBranch, "app_b", testDB, pooled, direct); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(store.get("DATABASE_URL"), canary) {
		t.Fatal("fixture did not store a secret")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(buffers) < 3 {
		t.Fatalf("captured %d buffers", len(buffers))
	}
	for _, buffer := range buffers {
		if bytes.Contains(buffer, []byte(canary)) || bytes.IndexFunc(buffer, func(r rune) bool { return r != 0 }) >= 0 {
			t.Fatal("a response buffer was not wiped")
		}
	}
}

func TestDecodeJSONString(t *testing.T) {
	cases := map[string]string{
		`"plain"`:          "plain",
		`"a&b"`:            "a&b",
		`"q\"\\\/\n"`:      "q\"\\/\n",
		`"😀"`:              "\U0001F600",
		`"café"`:           "café",
		jsonURI(directURI): directURI,
	}
	for raw, want := range cases {
		got, ok := decodeJSONString([]byte(raw))
		if !ok || string(got) != want {
			t.Fatalf("%s decoded to %q ok=%v", raw, got, ok)
		}
		if cap(got) > len(raw) {
			t.Fatalf("decoded buffer outgrew its bound")
		}
	}
	for _, raw := range []string{``, `"`, `x"`, `"a`, `"a"b"`, `"\x"`, `"\u12"`, `"\ud83d"`, `"\ude00\ud83d"`, "\"a\nb\"", `"\`} {
		if _, ok := decodeJSONString([]byte(raw)); ok {
			t.Fatalf("accepted %q", raw)
		}
	}
}

func TestPoolerHostDetection(t *testing.T) {
	if poolerHost([]byte(directURI)) || !poolerHost([]byte(pooledURI)) {
		t.Fatal("pooler classification is wrong")
	}
	if poolerHost([]byte("postgresql://u:p-pooler@ep-x.aws.neon.tech/db")) {
		t.Fatal("password content influenced pooler classification")
	}
	if !poolerHost([]byte("postgres://u:p@ep-x-pooler.aws.neon.tech:5432/db")) {
		t.Fatal("port broke pooler classification")
	}
}

func TestReadsRetryOnlyRetrySafeFailuresBounded(t *testing.T) {
	fake := newFake(t)
	var calls atomic.Int32
	fake.handle(http.MethodGet, "/users/me", func(response http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) < 3 {
			response.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(response, `{"id":"user-1"}`)
	})
	adapter := fake.adapter(t, Options{})
	if _, err := adapter.Identify(context.Background()); err != nil || calls.Load() != 3 {
		t.Fatalf("err=%v calls=%d", err, calls.Load())
	}
	fake.json(http.MethodGet, "/users/me", 429, canary)
	_, err := adapter.Identify(context.Background())
	if safe := expectCode(t, err, "RATE_LIMITED"); safe.Retry != provider.RetrySafe || fake.count(http.MethodGet, "/users/me") != 3+maxReadAttempts {
		t.Fatalf("retry=%s count=%d", safe.Retry, fake.count(http.MethodGet, "/users/me"))
	}

	// Transport failures map to fixed codes, not the transport's error text.
	failing := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("dial failed: " + canary)
	})}
	broken, err := New([]byte(testKey), Options{Endpoint: "http://127.0.0.1:1", Client: failing})
	if err != nil {
		t.Fatal(err)
	}
	broken.pollInterval = time.Millisecond
	defer broken.Close()
	_, err = broken.Identify(context.Background())
	expectCode(t, err, "TRANSPORT")
	err = broken.DeleteProject(context.Background(), testProject)
	if safe := expectCode(t, err, "TRANSPORT"); safe.Retry != provider.RetryAmbiguous {
		t.Fatalf("mutation transport retry=%s", safe.Retry)
	}
}

func TestRoleExistsAndDatabaseOwnerAreReadOnly(t *testing.T) {
	fake := newFake(t)
	adapter := fake.adapter(t, Options{})
	ctx := context.Background()
	fake.json(http.MethodGet, rolePath("app_a"), http.StatusOK, `{"role":{"name":"app_a","branch_id":"`+testBranch+`"}}`)
	fake.json(http.MethodGet, rolePath("app_b"), http.StatusNotFound, `{"message":"not found"}`)
	dbPath := "/projects/" + testProject + "/branches/" + testBranch + "/databases/"
	fake.json(http.MethodGet, dbPath+testDB, http.StatusOK, `{"database":{"name":"neondb","branch_id":"`+testBranch+`","owner_name":"neondb_owner"}}`)
	fake.json(http.MethodGet, dbPath+"other", http.StatusOK, `{"database":{"name":"wrong","owner_name":"neondb_owner"}}`)
	if ok, err := adapter.RoleExists(ctx, testProject, testBranch, "app_a"); err != nil || !ok {
		t.Fatalf("app_a: %v %v", ok, err)
	}
	if ok, err := adapter.RoleExists(ctx, testProject, testBranch, "app_b"); err != nil || ok {
		t.Fatalf("app_b: %v %v", ok, err)
	}
	if owner, err := adapter.DatabaseOwner(ctx, testProject, testBranch, testDB); err != nil || owner != "neondb_owner" {
		t.Fatalf("owner %q: %v", owner, err)
	}
	if _, err := adapter.DatabaseOwner(ctx, testProject, testBranch, "missing"); !IsNotFound(err) {
		t.Fatalf("missing database: %v", err)
	}
	expectCode(t, func() error { _, err := adapter.DatabaseOwner(ctx, testProject, testBranch, "other"); return err }(), "INVALID_RESPONSE")
	expectCode(t, func() error { _, err := adapter.RoleExists(ctx, testProject, testBranch, "bad role"); return err }(), "INVALID_REQUEST")
	for _, c := range fake.callsTo(http.MethodPost, rolePath("app_a")) {
		t.Fatalf("a read sent a mutation: %+v", c)
	}
}
