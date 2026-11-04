package vercel

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestScopeValidation(t *testing.T) {
	valid := []Scope{
		previewScope(),
		{TeamID: testTeam, ProjectID: testProject, Environment: EnvironmentPreview},
		productionScope(),
		customScope(),
	}
	for _, scope := range valid {
		if err := scope.Validate(); err != nil {
			t.Fatalf("valid scope %+v rejected: %v", scope, err)
		}
	}
	invalid := map[string]Scope{
		"development":          {TeamID: testTeam, ProjectID: testProject, Environment: "development"},
		"empty environment":    {TeamID: testTeam, ProjectID: testProject},
		"production branch":    {TeamID: testTeam, ProjectID: testProject, Environment: EnvironmentProduction, GitBranch: "main"},
		"production custom":    {TeamID: testTeam, ProjectID: testProject, Environment: EnvironmentProduction, CustomEnvironmentID: testCustom},
		"custom without id":    {TeamID: testTeam, ProjectID: testProject, Environment: EnvironmentCustom},
		"custom slug":          {TeamID: testTeam, ProjectID: testProject, Environment: EnvironmentCustom, CustomEnvironmentID: "staging"},
		"custom with branch":   {TeamID: testTeam, ProjectID: testProject, Environment: EnvironmentCustom, CustomEnvironmentID: testCustom, GitBranch: "main"},
		"preview with custom":  {TeamID: testTeam, ProjectID: testProject, Environment: EnvironmentPreview, CustomEnvironmentID: testCustom},
		"team slug":            {TeamID: "acme", ProjectID: testProject, Environment: EnvironmentProduction},
		"project name":         {TeamID: testTeam, ProjectID: "siftcut-web", Environment: EnvironmentProduction},
		"branch traversal":     {TeamID: testTeam, ProjectID: testProject, Environment: EnvironmentPreview, GitBranch: "a/../b"},
		"branch whitespace":    {TeamID: testTeam, ProjectID: testProject, Environment: EnvironmentPreview, GitBranch: "a b"},
		"branch control":       {TeamID: testTeam, ProjectID: testProject, Environment: EnvironmentPreview, GitBranch: "a\nb"},
		"branch leading dash":  {TeamID: testTeam, ProjectID: testProject, Environment: EnvironmentPreview, GitBranch: "-x"},
		"branch lock suffix":   {TeamID: testTeam, ProjectID: testProject, Environment: EnvironmentPreview, GitBranch: "x.lock"},
		"branch reflog syntax": {TeamID: testTeam, ProjectID: testProject, Environment: EnvironmentPreview, GitBranch: "x@{1}"},
		"branch too long":      {TeamID: testTeam, ProjectID: testProject, Environment: EnvironmentPreview, GitBranch: strings.Repeat("a", 251)},
	}
	for name, scope := range invalid {
		err := scope.Validate()
		if err == nil {
			t.Fatalf("%s: invalid scope accepted", name)
		}
		if scope.GitBranch != "" && strings.Contains(err.Error(), scope.GitBranch) {
			t.Fatalf("%s: validation error echoed input", name)
		}
		if _, err := New([]byte(testToken), scope, Options{}); err == nil {
			t.Fatalf("%s: New accepted invalid scope", name)
		}
	}
}

func TestFingerprintIsStableCanonicalAndScopeBound(t *testing.T) {
	canonical := `{"v":"envbank.vercel.scope.v1","provider":"vercel","team_id":"team_abc123",` +
		`"project_id":"prj_abc123","environment":"preview","git_branch":"feature/x","custom_environment_id":""}`
	sum := sha256.Sum256([]byte(canonical))
	if previewScope().Fingerprint() != hex.EncodeToString(sum[:]) {
		t.Fatal("fingerprint is not the documented canonical SHA-256")
	}
	if !fingerprintPattern.MatchString(previewScope().Fingerprint()) {
		t.Fatal("fingerprint is not lowercase hex")
	}
	otherBranch := previewScope()
	otherBranch.GitBranch = "feature/y"
	allPreview := previewScope()
	allPreview.GitBranch = ""
	otherTeam := previewScope()
	otherTeam.TeamID = "team_other1"
	seen := map[string]bool{}
	for _, scope := range []Scope{previewScope(), otherBranch, allPreview, otherTeam, productionScope(), customScope()} {
		fingerprint := scope.Fingerprint()
		if seen[fingerprint] {
			t.Fatalf("fingerprint collision for %+v", scope)
		}
		seen[fingerprint] = true
	}
	target := previewScope().Target()
	if target.ProjectID != testProject || target.EnvironmentID != EnvironmentPreview || len(target.ServiceIDs) != 1 ||
		target.ServiceIDs[ServiceName] != previewScope().Fingerprint() {
		t.Fatalf("unexpected preview target %+v", target)
	}
	custom := customScope().Target()
	if custom.EnvironmentID != testCustom {
		t.Fatalf("custom target must use the immutable custom environment ID: %+v", custom)
	}
	// Branch drift must not be accepted for an otherwise identical target.
	if previewScope().matchesTarget(otherBranch.Target()) || previewScope().matchesTarget(allPreview.Target()) {
		t.Fatal("target of a different branch matched")
	}
}

func TestSecretNamePolicyRejectsClientExposedAndReservedNames(t *testing.T) {
	for _, name := range []string{"NEXT_PUBLIC_API_KEY", "next_public_token", "PUBLIC_TOKEN", "VITE_SECRET",
		"REACT_APP_KEY", "NUXT_PUBLIC_X", "EXPO_PUBLIC_X", "GATSBY_X", "VERCEL_URL", "AWS_SECRET_ACCESS_KEY",
		"NODE_OPTIONS", "1BAD", "BAD-NAME", "", "BAD NAME"} {
		if validSecretName(name) {
			t.Fatalf("%q accepted as a vault secret name", name)
		}
	}
	for _, name := range []string{"DATABASE_URL", "STRIPE_SECRET_KEY", "_PRIVATE", "api_token"} {
		if !validSecretName(name) {
			t.Fatalf("%q rejected", name)
		}
	}
}

func TestNewRejectsUnsafeEndpointsAndTokens(t *testing.T) {
	for _, endpoint := range []string{
		"http://api.vercel.com", "https://api.vercel.com.evil.example", "https://evil.example",
		"https://user:pass@api.vercel.com", "https://api.vercel.com/v9", "https://api.vercel.com?x=1",
		"https://api.vercel.com:8443", "http://localhost:8080", "http://10.0.0.1", "http://127.0.0.1.nip.io",
		"ftp://127.0.0.1", "https://api.vercel.com#frag",
	} {
		if _, err := New([]byte(testToken), productionScope(), Options{Endpoint: endpoint}); err == nil {
			t.Fatalf("endpoint %q accepted", endpoint)
		}
	}
	for _, endpoint := range []string{"", "https://api.vercel.com", "https://api.vercel.com/",
		"http://127.0.0.1:9", "http://[::1]:9", "https://127.0.0.1:9"} {
		if _, err := New([]byte(testToken), productionScope(), Options{Endpoint: endpoint}); err != nil {
			t.Fatalf("endpoint %q rejected: %v", endpoint, err)
		}
	}
	for _, token := range [][]byte{nil, []byte(""), []byte("has space"), []byte("line\nbreak"),
		[]byte(strings.Repeat("a", maxTokenBytes+1))} {
		if _, err := New(token, productionScope(), Options{}); err == nil {
			t.Fatalf("token %q accepted", token)
		}
	}
	token := []byte(testToken)
	adapter, err := New(token, productionScope(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	token[0] = 'X'
	if string(adapter.token) != testToken {
		t.Fatal("adapter retained caller token storage")
	}
	adapter.Close()
	if adapter.token != nil {
		t.Fatal("Close did not drop the token")
	}
}

func TestRedirectsAreNeverFollowedEvenWithPermissiveClient(t *testing.T) {
	var leaked atomic.Int32
	attacker := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		leaked.Add(1)
	}))
	defer attacker.Close()
	fake := newFake(t)
	fake.handle(http.MethodGet, projectPath, func(response http.ResponseWriter, request *http.Request) {
		http.Redirect(response, request, attacker.URL+"/steal", http.StatusTemporaryRedirect)
	})
	permissive := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return nil }}
	adapter, err := New([]byte(testToken), productionScope(), Options{Endpoint: fake.server.URL, Client: permissive})
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()
	_, err = adapter.Identity(background)
	expectCode(t, err, "REDIRECT_REJECTED")
	if leaked.Load() != 0 {
		t.Fatal("redirect target received a request")
	}
	if permissive.CheckRedirect == nil {
		t.Fatal("caller client was mutated")
	}
}
