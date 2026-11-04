package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GeorgeQLe/envbank/internal/mcpserver"
	"github.com/GeorgeQLe/envbank/internal/provider/vercel"
	"github.com/GeorgeQLe/envbank/internal/vaultobject"
)

const vercelCLIManifest = `version: 1
bundle: acceptance/vercel
policies:
  password: {type: password, length: 24, lowercase: true}
records:
  API_SECRET: {source: generate, policy: password}
targets:
  vercel:
    team_id: team_fixture
    project: acceptance
    project_id: prj_fixture
    environment: preview
    git_branch: acceptance
    services:
      environment:
        order: 1
        variables:
          API_SECRET: {source: record, record: API_SECRET}
`

func TestVercelCLIBindPlanApprovalAndScopePin(t *testing.T) {
	fixture := newCLIDeviceFixture(t)
	path := filepath.Join(t.TempDir(), "vercel.yaml")
	if e := os.WriteFile(path, []byte(vercelCLIManifest), 0600); e != nil {
		t.Fatal(e)
	}
	auth := authArgs(fixture, fixture.firstConfigPath)
	if _, _, e := captureRunWithStdin(t, append([]string{"bundle", "prepare", "--manifest", path}, auth...), ""); e != nil {
		t.Fatal(e)
	}
	mutations := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fake-vercel-cli-credential" || r.URL.Query().Get("teamId") != "team_fixture" {
			t.Error("credential/scope mismatch")
			w.WriteHeader(403)
			return
		}
		if r.Method != "GET" {
			mutations++
			w.WriteHeader(400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v9/projects/prj_fixture":
			fmt.Fprint(w, `{"id":"prj_fixture","accountId":"team_fixture","name":"acceptance"}`)
		case "/v10/projects/prj_fixture/env":
			fmt.Fprint(w, `{"envs":[]}`)
		case "/v13/deployments/dpl_source":
			fmt.Fprint(w, `{"id":"dpl_source","projectId":"prj_fixture","ownerId":"team_fixture","target":null,"readyState":"READY","url":"acceptance.vercel.app","gitSource":{"ref":"acceptance","sha":"abc1234def5678"},"meta":{"githubCommitRef":"acceptance","githubCommitSha":"abc1234def5678"}}`)
		default:
			t.Error("unexpected API route")
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	previousStore, previousOptions, previousConfirmation := vercelCredentialStore, vercelAdapterOptions, vercelOwnerConfirmation
	vercelCredentialStore = &memoryKeychain{values: map[string][]byte{}}
	vercelAdapterOptions = func() vercel.Options { return vercel.Options{Endpoint: server.URL, Client: server.Client()} }
	prompted := false
	vercelOwnerConfirmation = func(prompt string) error {
		prompted = strings.Contains(prompt, "prj_fixture") && strings.Contains(prompt, "acceptance") && strings.Contains(prompt, "dpl_source")
		return nil
	}
	defer func() {
		vercelCredentialStore, vercelAdapterOptions, vercelOwnerConfirmation = previousStore, previousOptions, previousConfirmation
	}()
	run := func(sub string, extra []string, input string) string {
		t.Helper()
		args := append([]string{"vercel", sub, "--manifest", path}, extra...)
		args = append(args, auth...)
		out, errout, e := captureRunWithStdin(t, args, input)
		if e != nil || errout != "" {
			t.Fatalf("%s failed: %v", sub, e)
		}
		if strings.Contains(out+errout, "fake-vercel-cli-credential") {
			t.Fatal("CLI exposed provider credential")
		}
		return out
	}
	run("bind", nil, "fake-vercel-cli-credential\n")
	var result mcpserver.Result
	if e := json.Unmarshal([]byte(run("plan", nil, "")), &result); e != nil || result.PlanID == "" {
		t.Fatal("plan unavailable")
	}
	run("approve", []string{"--plan", result.PlanID, "--source-deployment", "dpl_source", "--health-path", "/health"}, "")
	if !prompted || mutations != 0 {
		t.Fatal("approval did not review exact scope or planning mutated provider")
	}
	api, key := unlockedFixtureAPI(t, fixture.firstConfigPath, fixture.passphrasePath)
	objects, e := api.ListObjects(key)
	if e != nil {
		t.Fatal(e)
	}
	plans, policies := 0, 0
	for _, object := range objects {
		if object.Kind == vaultobject.KindProviderPlan {
			plans++
		}
		if object.Kind == vaultobject.KindAutomationPolicy {
			policies++
		}
		if strings.Contains(string(object.Payload), "fake-vercel-cli-credential") {
			t.Fatal("provider credential entered object schema")
		}
	}
	if plans != 1 || policies != 1 {
		t.Fatal("missing encrypted plan/approval")
	}
	// A public manifest edit cannot repurpose an already imported credential.
	changed := strings.Replace(vercelCLIManifest, "git_branch: acceptance", "git_branch: other", 1)
	if e := os.WriteFile(path, []byte(changed), 0600); e != nil {
		t.Fatal(e)
	}
	_, _, e = captureRunWithStdin(t, append([]string{"vercel", "plan", "--manifest", path}, auth...), "")
	if e == nil {
		t.Fatal("credential silently followed manifest branch change")
	}
}
