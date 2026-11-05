package vercel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const projectsPath = "/v11/projects"

func (fake *fakeVercel) teamAdapter(t *testing.T) *Adapter {
	t.Helper()
	adapter, err := NewTeam([]byte(testToken), testTeam, Options{Endpoint: fake.server.URL,
		Client: fake.server.Client(), Now: func() time.Time { return fixedNow }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(adapter.Close)
	return adapter
}

func TestNewTeamValidatesInputsAndRedacts(t *testing.T) {
	if _, err := NewTeam([]byte(testToken), "prj_abc", Options{}); err == nil {
		t.Fatal("non-team ID accepted")
	}
	if _, err := NewTeam([]byte("bad token"), testTeam, Options{}); err == nil {
		t.Fatal("invalid token accepted")
	}
	if _, err := NewTeam([]byte(testToken), testTeam, Options{Endpoint: "http://example.com"}); err == nil {
		t.Fatal("non-loopback http endpoint accepted")
	}
	adapter, err := NewTeam([]byte(testToken), testTeam, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()
	if formatted := fmt.Sprintf("%v %+v %s %#v", adapter, adapter, adapter, adapter); strings.Contains(formatted, testToken) {
		t.Fatal("team adapter formatting leaked the token")
	}
}

func TestCreateProjectSendsExactBodyAndValidatesResponse(t *testing.T) {
	fake := newFake(t)
	fake.json(http.MethodPost, projectsPath, http.StatusOK,
		`{"id":"prj_new123","name":"envbank-throwaway","accountId":"`+testTeam+`","env":[{"value":"`+canary+`"}]}`)
	adapter := fake.teamAdapter(t)
	id, err := adapter.CreateProject(background, testTeam, "envbank-throwaway", "GeorgeQLe/siftcut", "nextjs")
	if err != nil {
		t.Fatal(err)
	}
	if id != "prj_new123" {
		t.Fatalf("id=%q", id)
	}
	var body map[string]any
	if err := json.Unmarshal(fake.last(http.MethodPost, projectsPath).Body, &body); err != nil {
		t.Fatal(err)
	}
	repo, _ := body["gitRepository"].(map[string]any)
	if body["name"] != "envbank-throwaway" || body["framework"] != "nextjs" || repo["type"] != "github" ||
		repo["repo"] != "GeorgeQLe/siftcut" || len(body) != 3 {
		t.Fatalf("unexpected body %v", body)
	}

	// Without git repo and framework, neither field is sent.
	if _, err := adapter.CreateProject(background, testTeam, "envbank-throwaway", "", ""); err != nil {
		t.Fatal(err)
	}
	if got := string(fake.last(http.MethodPost, projectsPath).Body); got != `{"name":"envbank-throwaway"}` {
		t.Fatalf("body=%s", got)
	}
}

func TestCreateProjectRefusesInvalidInputBeforeSending(t *testing.T) {
	fake := newFake(t)
	adapter := fake.teamAdapter(t)
	cases := []struct{ team, name, repo, framework string }{
		{"team_other1", "ok-name", "", ""},
		{"prj_abc", "ok-name", "", ""},
		{testTeam, "Upper", "", ""},
		{testTeam, "a---b", "", ""},
		{testTeam, "", "", ""},
		{testTeam, strings.Repeat("a", 101), "", ""},
		{testTeam, "ok-name", "owner", ""},
		{testTeam, "ok-name", "owner/../x", ""},
		{testTeam, "ok-name", "-owner/repo", ""},
		{testTeam, "ok-name", "owner/repo?x", ""},
		{testTeam, "ok-name", "", "Next JS"},
	}
	for _, c := range cases {
		if _, err := adapter.CreateProject(background, c.team, c.name, c.repo, c.framework); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	if fake.total() != 0 {
		t.Fatal("invalid create reached Vercel")
	}
}

func TestCreateProjectRequiresMutationAuthority(t *testing.T) {
	fake := newFake(t)
	adapter := fake.teamAdapter(t)
	_, err := adapter.CreateProject(context.Background(), testTeam, "envbank-throwaway", "", "")
	expectCode(t, err, "AUTHORIZATION_DENIED")
	if fake.total() != 0 {
		t.Fatal("unauthorized create reached Vercel")
	}
}

func TestCreateProjectResponseValidationAndErrors(t *testing.T) {
	cases := map[string]struct {
		status int
		body   string
		code   string
	}{
		"foreign team":  {200, `{"id":"prj_new123","name":"envbank-throwaway","accountId":"team_other1"}`, "CREATED_PROJECT_MISMATCH"},
		"renamed":       {200, `{"id":"prj_new123","name":"other","accountId":"` + testTeam + `"}`, "CREATED_PROJECT_MISMATCH"},
		"bad id":        {200, `{"id":"` + canary + `","name":"envbank-throwaway","accountId":"` + testTeam + `"}`, "CREATED_PROJECT_MISMATCH"},
		"malformed":     {200, `{"id":`, "INVALID_RESPONSE"},
		"conflict":      {409, `{"error":{"message":"` + canary + `"}}`, "CONFLICT"},
		"forbidden":     {403, `{"error":{"message":"` + canary + `"}}`, "FORBIDDEN"},
		"server":        {500, canary, "SERVER_ERROR"},
		"oversized 2xx": {200, `{"id":"prj_new123","pad":"` + strings.Repeat("x", maxResponseBytes) + `"}`, "RESPONSE_TOO_LARGE"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			fake := newFake(t)
			fake.json(http.MethodPost, projectsPath, c.status, c.body)
			id, err := fake.teamAdapter(t).CreateProject(background, testTeam, "envbank-throwaway", "", "")
			expectCode(t, err, c.code)
			if id != "" {
				t.Fatal("id returned with error")
			}
		})
	}
}

func TestDeleteProjectProvesOwnershipThenDeletes(t *testing.T) {
	fake := newFake(t)
	fake.project("")
	var deleted atomic.Int32
	fake.handle(http.MethodDelete, projectPath, func(response http.ResponseWriter, _ *http.Request) {
		deleted.Add(1)
		response.WriteHeader(http.StatusNoContent)
	})
	if err := fake.teamAdapter(t).DeleteProject(background, testTeam, testProject); err != nil {
		t.Fatal(err)
	}
	if deleted.Load() != 1 {
		t.Fatal("project was not deleted exactly once")
	}
	// A project-scoped adapter may delete only its own project.
	scoped := fake.adapter(t, previewScope())
	if err := scoped.DeleteProject(background, testTeam, testProject); err != nil {
		t.Fatal(err)
	}
	expectCode(t, scoped.DeleteProject(background, testTeam, "prj_other1"), "INVALID_PROJECT_ID")
	if deleted.Load() != 2 {
		t.Fatal("unexpected delete count")
	}
}

func TestDeleteProjectRefusesForeignOrMissingProjects(t *testing.T) {
	fake := newFake(t)
	fake.json(http.MethodGet, projectPath, http.StatusOK, projectBody("team_other1", ""))
	adapter := fake.teamAdapter(t)
	expectCode(t, adapter.DeleteProject(background, testTeam, testProject), "PROJECT_OWNERSHIP_MISMATCH")
	expectCode(t, adapter.DeleteProject(background, "team_other1", testProject), "TEAM_SCOPE_MISMATCH")
	expectCode(t, adapter.DeleteProject(background, testTeam, "dpl_abc"), "INVALID_PROJECT_ID")
	expectCode(t, adapter.DeleteProject(background, testTeam, "prj_missing1"), "NOT_FOUND")
	expectCode(t, adapter.DeleteProject(context.Background(), testTeam, "prj_missing1"), "NOT_FOUND")
	if fake.mutations() != 0 {
		t.Fatal("refused delete reached Vercel")
	}
	fake.project("")
	expectCode(t, adapter.DeleteProject(context.Background(), testTeam, testProject), "AUTHORIZATION_DENIED")
	if fake.mutations() != 0 {
		t.Fatal("unauthorized delete reached Vercel")
	}
}

func TestTeamAdapterRefusesProjectScopedCalls(t *testing.T) {
	fake := newFake(t)
	adapter := fake.teamAdapter(t)
	_, err := adapter.Identity(background)
	expectCode(t, err, "PROJECT_SCOPE_REQUIRED")
	_, err = adapter.Deployment(background, "dpl_abc")
	expectCode(t, err, "PROJECT_SCOPE_REQUIRED")
	if _, err = adapter.CurrentDeployment(background); err == nil {
		t.Fatal("team adapter read a current deployment")
	}
	if fake.total() != 0 {
		t.Fatal("team adapter sent a project-scoped call")
	}
}

func TestWaitReadyPollsUntilReady(t *testing.T) {
	fake := newFake(t)
	var polls atomic.Int32
	fake.handle(http.MethodGet, deploymentPath("dpl_wait"), func(response http.ResponseWriter, _ *http.Request) {
		state := "BUILDING"
		switch n := polls.Add(1); {
		case n == 2:
			response.WriteHeader(http.StatusServiceUnavailable)
			return
		case n >= 4:
			state = "READY"
		}
		_, _ = io.WriteString(response, deployment("dpl_wait", set("readyState", state)))
	})
	adapter := fake.adapter(t, previewScope())
	adapter.pollInterval = time.Millisecond
	got, err := adapter.WaitReady(background, "dpl_wait", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "dpl_wait" || got.ReadyState != "READY" || polls.Load() != 4 {
		t.Fatalf("got=%+v polls=%d", got, polls.Load())
	}
	assertNoCanary(t, got)
}

func TestWaitReadyTerminalStatesAndBounds(t *testing.T) {
	for state, code := range map[string]string{"ERROR": "DEPLOYMENT_FAILED", "CANCELED": "DEPLOYMENT_CANCELED", "DELETED": "DEPLOYMENT_DELETED"} {
		fake := newFake(t)
		fake.json(http.MethodGet, deploymentPath("dpl_x"), 200, deployment("dpl_x", set("readyState", state)))
		adapter := fake.adapter(t, previewScope())
		adapter.pollInterval = time.Millisecond
		_, err := adapter.WaitReady(background, "dpl_x", time.Second)
		expectCode(t, err, code)
	}

	fake := newFake(t)
	fake.json(http.MethodGet, deploymentPath("dpl_x"), 200, deployment("dpl_x", set("readyState", "QUEUED")))
	adapter := fake.adapter(t, previewScope())
	adapter.pollInterval = time.Millisecond
	_, err := adapter.WaitReady(background, "dpl_x", 50*time.Millisecond)
	expectCode(t, err, "DEPLOYMENT_TIMEOUT")

	cancelled, cancel := context.WithCancel(background)
	cancel()
	_, err = adapter.WaitReady(cancelled, "dpl_x", time.Second)
	expectCode(t, err, "CANCELLED")

	_, err = adapter.WaitReady(background, "dpl_x", 0)
	expectCode(t, err, "INVALID_TIMEOUT")
	_, err = adapter.WaitReady(background, "dpl_x", MaxWaitReady+time.Second)
	expectCode(t, err, "INVALID_TIMEOUT")
	_, err = adapter.WaitReady(background, "prj_x", time.Second)
	expectCode(t, err, "INVALID_DEPLOYMENT_ID")

	// A scope mismatch is not retry-safe and ends the wait immediately.
	fake.json(http.MethodGet, deploymentPath("dpl_foreign"), 200, deployment("dpl_foreign", set("projectId", "prj_other1")))
	_, err = adapter.WaitReady(background, "dpl_foreign", time.Second)
	expectCode(t, err, codeScopeMismatch)
	if fake.count(http.MethodGet, deploymentPath("dpl_foreign")) != 1 {
		t.Fatal("non-retryable failure was polled again")
	}
}

func TestEnvUpsertBodyIsSensitive(t *testing.T) {
	for _, scope := range []Scope{previewScope(), productionScope(), customScope()} {
		body := scope.upsertBody("DATABASE_URL", []byte(canary))
		var decoded map[string]any
		if err := json.Unmarshal(body, &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded["type"] != "sensitive" {
			t.Fatalf("env write type=%v", decoded["type"])
		}
	}
}
