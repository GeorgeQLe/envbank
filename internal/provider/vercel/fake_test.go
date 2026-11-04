package vercel

import (
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
	"testing"
	"time"

	"github.com/GeorgeQLe/envbank/internal/provider"
)

const (
	testToken   = "vercel-token-fixture"
	testTeam    = "team_abc123"
	testProject = "prj_abc123"
	testCustom  = "env_custom123"
	canary      = "CANARY_SECRET_VALUE_7f3a"
	testBranch  = "feature/x"
	testSHA     = "abc1234def5678"
)

var fixedNow = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

type recordedCall struct {
	Method string
	Path   string
	Query  url.Values
	Body   []byte
}

type fakeVercel struct {
	t      *testing.T
	mu     sync.Mutex
	routes map[string]http.HandlerFunc
	calls  []recordedCall
	server *httptest.Server
}

func newFake(t *testing.T) *fakeVercel {
	t.Helper()
	fake := &fakeVercel{t: t, routes: map[string]http.HandlerFunc{}}
	fake.server = httptest.NewServer(http.HandlerFunc(fake.serve))
	t.Cleanup(fake.server.Close)
	return fake
}

func (fake *fakeVercel) serve(response http.ResponseWriter, request *http.Request) {
	body, _ := io.ReadAll(request.Body)
	fake.mu.Lock()
	fake.calls = append(fake.calls, recordedCall{Method: request.Method, Path: request.URL.EscapedPath(),
		Query: request.URL.Query(), Body: body})
	handler := fake.routes[request.Method+" "+request.URL.EscapedPath()]
	fake.mu.Unlock()
	if request.Header.Get("Authorization") != "Bearer "+testToken {
		fake.t.Errorf("request did not carry the expected bearer token")
	}
	if request.URL.Query().Get("teamId") != testTeam {
		fake.t.Errorf("request %s %s did not carry the exact teamId", request.Method, request.URL.Path)
	}
	if request.URL.Query().Get("decrypt") == "true" {
		fake.t.Errorf("adapter requested decrypted values")
	}
	if handler == nil {
		http.Error(response, `{"error":{"code":"not_found","message":"`+canary+`"}}`, http.StatusNotFound)
		return
	}
	request.Body = io.NopCloser(strings.NewReader(string(body)))
	handler(response, request)
}

func (fake *fakeVercel) handle(method, path string, handler http.HandlerFunc) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.routes[method+" "+path] = handler
}

func (fake *fakeVercel) json(method, path string, status int, body string) {
	fake.handle(method, path, func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(status)
		_, _ = io.WriteString(response, body)
	})
}

func (fake *fakeVercel) count(method, path string) int {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	total := 0
	for _, call := range fake.calls {
		if call.Method == method && call.Path == path {
			total++
		}
	}
	return total
}

func (fake *fakeVercel) total() int {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	return len(fake.calls)
}

func (fake *fakeVercel) mutations() int {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	total := 0
	for _, call := range fake.calls {
		if call.Method != http.MethodGet {
			total++
		}
	}
	return total
}

func (fake *fakeVercel) last(method, path string) recordedCall {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	for index := len(fake.calls) - 1; index >= 0; index-- {
		if fake.calls[index].Method == method && fake.calls[index].Path == path {
			return fake.calls[index]
		}
	}
	fake.t.Fatalf("no %s %s call recorded", method, path)
	return recordedCall{}
}

func previewScope() Scope {
	return Scope{TeamID: testTeam, ProjectID: testProject, Environment: EnvironmentPreview, GitBranch: testBranch}
}

func productionScope() Scope {
	return Scope{TeamID: testTeam, ProjectID: testProject, Environment: EnvironmentProduction}
}

func customScope() Scope {
	return Scope{TeamID: testTeam, ProjectID: testProject, Environment: EnvironmentCustom, CustomEnvironmentID: testCustom}
}

func (fake *fakeVercel) adapter(t *testing.T, scope Scope) *Adapter {
	t.Helper()
	adapter, err := New([]byte(testToken), scope, Options{Endpoint: fake.server.URL,
		Client: fake.server.Client(), Now: func() time.Time { return fixedNow }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(adapter.Close)
	return adapter
}

const projectPath = "/v9/projects/" + testProject
const envPath = "/v10/projects/" + testProject + "/env"

// projectBody includes value-bearing env data and a canary that must never
// surface.
func projectBody(accountID string, extra string) string {
	return `{"id":"` + testProject + `","name":"siftcut-web","accountId":"` + accountID + `",` +
		`"env":[{"key":"SECRET","value":"` + canary + `"}],` +
		`"customEnvironments":[{"id":"` + testCustom + `","slug":"staging","type":"preview"}]` + extra + `}`
}

func (fake *fakeVercel) project(extra string) {
	fake.json(http.MethodGet, projectPath, http.StatusOK, projectBody(testTeam, extra))
}

func (fake *fakeVercel) envs(entries ...string) {
	fake.json(http.MethodGet, envPath, http.StatusOK, `{"envs":[`+strings.Join(entries, ",")+`]}`)
}

func env(id, key, typ, target, branch, customs string) string {
	parts := []string{`"id":"` + id + `"`, `"key":"` + key + `"`, `"type":"` + typ + `"`,
		`"value":"` + canary + `"`, `"decrypted":false`, `"updatedAt":1700000000000`}
	if target != "" {
		parts = append(parts, `"target":`+target)
	}
	if branch != "" {
		parts = append(parts, `"gitBranch":"`+branch+`"`)
	}
	if customs != "" {
		parts = append(parts, `"customEnvironmentIds":`+customs)
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func deployment(id string, mutate func(map[string]any)) string {
	value := map[string]any{
		"id": id, "projectId": testProject, "ownerId": testTeam, "target": nil,
		"readyState": "READY", "readySubstate": "STAGED", "url": "siftcut-abc.vercel.app",
		"gitSource": map[string]any{"type": "github", "ref": testBranch, "sha": testSHA},
		"meta": map[string]any{"githubCommitRef": testBranch, "githubCommitSha": testSHA,
			"githubCommitMessage": canary},
		"env":   []string{"SECRET"},
		"build": map[string]any{"env": []string{canary}},
	}
	if mutate != nil {
		mutate(value)
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return string(encoded)
}

func production(value map[string]any) {
	value["target"] = "production"
	value["gitSource"] = map[string]any{"type": "github", "ref": "main", "sha": testSHA}
	value["meta"] = map[string]any{"githubCommitRef": "main", "githubCommitSha": testSHA}
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
	if strings.Contains(fmt.Sprint(err), canary) || safe.Validate() != nil {
		t.Fatalf("unsafe provider error: %v", err)
	}
	return safe
}

func assertNoCanary(t *testing.T, values ...any) {
	t.Helper()
	for _, value := range values {
		encoded, _ := json.Marshal(value)
		if strings.Contains(string(encoded), canary) || strings.Contains(fmt.Sprintf("%+v", value), canary) {
			t.Fatalf("response canary leaked into %T", value)
		}
	}
}

var background = context.Background()
