package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/GeorgeQLe/envbank/internal/mcpserver"
	"github.com/GeorgeQLe/envbank/internal/ownerapproval"
	"github.com/GeorgeQLe/envbank/internal/ownerapproval/ownerapprovaltest"
	"github.com/GeorgeQLe/envbank/internal/provider/vercel"
	"github.com/GeorgeQLe/envbank/internal/vercelworkflow"
)

const vercelAcceptanceManifest = `version: 1
bundle: acceptance/vercel-fixture
policies:
  fixture: {type: password, length: 64, lowercase: true}
records:
  ENVBANK_ACCEPTANCE_FIXTURE_SECRET: {source: generate, policy: fixture}
targets:
  vercel:
    team_id: team_fixture
    project: envbank-acceptance-fixture
    project_id: prj_fixture
    environment: preview
    git_branch: envbank-acceptance-run1
    services:
      environment:
        order: 1
        variables:
          ENVBANK_ACCEPTANCE_FIXTURE_SECRET: {source: record, record: ENVBANK_ACCEPTANCE_FIXTURE_SECRET}
`

const vercelAcceptanceTarget = "disposable:team_fixture/prj_fixture/envbank-acceptance-fixture@envbank-acceptance-run1"

func TestVercelAcceptRefusesBeforeUnlockingWithoutAuthorization(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vercel.yaml")
	if e := os.WriteFile(path, []byte(vercelAcceptanceManifest), 0600); e != nil {
		t.Fatal(e)
	}
	base := []string{"vercel", "accept", "--manifest", path, "--plan", strings.Repeat("a", 64), "--config", "/nonexistent/must-not-read.json"}
	cases := []struct {
		name, want string
		env        map[string]string
	}{
		{"no-authorization", "EXPLICIT_AUTHORIZATION_REQUIRED", map[string]string{}},
		{"token-in-environment", "CREDENTIAL_ENVIRONMENT_FORBIDDEN", map[string]string{"ENVBANK_LIVE_ACCEPTANCE": "1", "VERCEL_TOKEN": "fake-token-must-not-be-used", "ENVBANK_VERCEL_ACCEPTANCE_TARGET": vercelAcceptanceTarget}},
		{"unmarked-target", "DISPOSABLE_TARGET_REQUIRED", map[string]string{"ENVBANK_LIVE_ACCEPTANCE": "1", "ENVBANK_VERCEL_ACCEPTANCE_TARGET": "disposable:team_fixture/prj_fixture/my-app@main"}},
		{"target-not-manifest", "ACCEPTANCE_MANIFEST_NOT_DISPOSABLE", map[string]string{"ENVBANK_LIVE_ACCEPTANCE": "1", "ENVBANK_VERCEL_ACCEPTANCE_TARGET": "disposable:team_fixture/prj_other/envbank-acceptance-fixture@envbank-acceptance-run1"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for _, name := range append([]string{"ENVBANK_LIVE_ACCEPTANCE", "ENVBANK_VERCEL_ACCEPTANCE_TARGET"}, vercelAcceptanceForbiddenEnvironment...) {
				t.Setenv(name, c.env[name])
			}
			out, errout, e := captureRunWithStdin(t, base, "")
			if e == nil || !strings.Contains(e.Error(), c.want) || strings.Contains(out+errout+e.Error(), "fake-token-must-not-be-used") {
				t.Fatalf("got %v", e)
			}
		})
	}
}

func TestVercelAcceptDrivesConfiguredBackendAndFailsClosedWithoutMutation(t *testing.T) {
	fixture := newCLIDeviceFixture(t)
	path := filepath.Join(t.TempDir(), "vercel.yaml")
	if e := os.WriteFile(path, []byte(vercelAcceptanceManifest), 0600); e != nil {
		t.Fatal(e)
	}
	auth := authArgs(fixture, fixture.firstConfigPath)
	if _, _, e := captureRunWithStdin(t, append([]string{"bundle", "prepare", "--manifest", path}, auth...), ""); e != nil {
		t.Fatal(e)
	}
	mutations := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fake-vercel-acceptance-credential" || r.URL.Query().Get("teamId") != "team_fixture" {
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
			fmt.Fprint(w, `{"id":"prj_fixture","accountId":"team_fixture","name":"envbank-acceptance-fixture"}`)
		case "/v10/projects/prj_fixture/env":
			fmt.Fprint(w, `{"envs":[]}`)
		case "/v13/deployments/dpl_source":
			fmt.Fprint(w, `{"id":"dpl_source","projectId":"prj_fixture","ownerId":"team_fixture","target":null,"readyState":"READY","url":"envbank-acceptance-fixture.vercel.app","gitSource":{"ref":"envbank-acceptance-run1","sha":"abc1234def5678"},"meta":{"githubCommitRef":"envbank-acceptance-run1","githubCommitSha":"abc1234def5678"}}`)
		default:
			t.Error("unexpected API route")
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	owner := ownerapprovaltest.New("cli-acceptance-owner")
	previousStore, previousOptions, previousConfirmation, previousSigner, previousProbe := vercelCredentialStore, vercelAdapterOptions, vercelOwnerConfirmation, vercelOwnerSigner, vercelAcceptanceProbe
	vercelCredentialStore = &memoryKeychain{values: map[string][]byte{}}
	vercelAdapterOptions = func() vercel.Options { return vercel.Options{Endpoint: server.URL, Client: server.Client()} }
	vercelOwnerConfirmation = func(string) error { return nil }
	vercelOwnerSigner = func([]byte) (ownerapproval.Signer, error) { return owner, nil }
	probes := 0
	// Loopback stand-in: the source deployment already holds the value, so a
	// fresh-consumption proof is impossible and acceptance must stop before
	// any provider write.
	vercelAcceptanceProbe = func(vercel.Scope, []byte) (vercelworkflow.AcceptanceProbe, func(), error) {
		return func(_ context.Context, d vercel.Deployment, headers map[string]string) (int, error) {
			probes++
			if d.ID != "dpl_source" || headers[vercelworkflow.AcceptanceProofHeader] == "" {
				t.Error("unexpected fixture probe")
			}
			return vercelworkflow.FixtureMatch, nil
		}, func() {}, nil
	}
	defer func() {
		vercelCredentialStore, vercelAdapterOptions, vercelOwnerConfirmation, vercelOwnerSigner, vercelAcceptanceProbe = previousStore, previousOptions, previousConfirmation, previousSigner, previousProbe
	}()
	t.Setenv("ENVBANK_LIVE_ACCEPTANCE", "1")
	t.Setenv("ENVBANK_VERCEL_ACCEPTANCE_TARGET", vercelAcceptanceTarget)
	for _, name := range vercelAcceptanceForbiddenEnvironment {
		t.Setenv(name, "")
	}
	run := func(args ...string) (string, error) {
		t.Helper()
		out, errout, e := captureRunWithStdin(t, append(append([]string{"vercel"}, args...), auth...), "")
		if strings.Contains(out+errout, "fake-vercel-acceptance-credential") {
			t.Fatal("CLI exposed provider credential")
		}
		return out, e
	}
	if _, _, e := captureRunWithStdin(t, append([]string{"vercel", "bind", "--manifest", path}, auth...), "fake-vercel-acceptance-credential\n"); e != nil {
		t.Fatal(e)
	}
	out, e := run("plan", "--manifest", path)
	var plan mcpserver.Result
	if e != nil || json.Unmarshal([]byte(out), &plan) != nil || plan.PlanID == "" {
		t.Fatal("plan unavailable")
	}
	// No owner pin: refuse with a precise blocker, never a fake PASS.
	out, e = run("accept", "--manifest", path, "--plan", plan.PlanID)
	var receipt vercelworkflow.AcceptanceReceipt
	if e == nil || json.Unmarshal([]byte(out), &receipt) != nil || receipt.Result != "BLOCKED" || receipt.Blocker != "OWNER_APPROVAL_KEY_NOT_PINNED" || probes != 0 || mutations != 0 {
		t.Fatalf("acceptance without owner setup: %v %+v", e, receipt)
	}
	pinOwnerKey(t, fixture.firstConfigPath, fixture.passphrasePath, owner.PublicKey())
	// Pinned but not yet approved: still refuses before reading the record.
	out, e = run("accept", "--manifest", path, "--plan", plan.PlanID)
	if e == nil || json.Unmarshal([]byte(out), &receipt) != nil || receipt.Blocker != "OWNER_APPROVAL_REQUIRED" || probes != 0 {
		t.Fatalf("acceptance without approval: %v %+v", e, receipt)
	}
	if _, e = run("approve", "--manifest", path, "--plan", plan.PlanID, "--source-deployment", "dpl_source", "--health-path", vercelworkflow.AcceptanceHealthPath); e != nil {
		t.Fatal(e)
	}
	out, e = run("accept", "--manifest", path, "--plan", plan.PlanID)
	if e == nil || json.Unmarshal([]byte(out), &receipt) != nil || receipt.Blocker != "ACCEPTANCE_FIXTURE_NOT_FRESH" || probes != 1 || mutations != 0 || receipt.FullWorkflow != "not-qualified" {
		t.Fatalf("non-fresh acceptance: %v %+v", e, receipt)
	}
	if bytes.Contains([]byte(out), []byte("proof")) {
		t.Fatal("receipt contains proof material")
	}
}

const vercelProductionAcceptanceManifest = `version: 1
bundle: acceptance/vercel-production-fixture
policies:
  fixture: {type: password, length: 64, lowercase: true}
records:
  ENVBANK_ACCEPTANCE_FIXTURE_SECRET: {source: generate, policy: fixture}
targets:
  vercel:
    team_id: team_fixture
    project: envbank-acceptance-fixture
    project_id: prj_fixture
    environment: production
    services:
      environment:
        order: 1
        variables:
          ENVBANK_ACCEPTANCE_FIXTURE_SECRET: {source: record, record: ENVBANK_ACCEPTANCE_FIXTURE_SECRET}
`

const vercelProductionAcceptanceTarget = "disposable-production:team_fixture/prj_fixture/envbank-acceptance-fixture"

func TestVercelAcceptProductionRefusesBeforeUnlocking(t *testing.T) {
	dir := t.TempDir()
	production := filepath.Join(dir, "production.yaml")
	preview := filepath.Join(dir, "preview.yaml")
	if os.WriteFile(production, []byte(vercelProductionAcceptanceManifest), 0600) != nil || os.WriteFile(preview, []byte(vercelAcceptanceManifest), 0600) != nil {
		t.Fatal("manifest setup failed")
	}
	noConfig := []string{"--config", "/nonexistent/must-not-read.json"}
	plan := strings.Repeat("a", 64)
	cases := []struct {
		name, want string
		args       []string
		env        map[string]string
	}{
		{"no-authorization", "EXPLICIT_AUTHORIZATION_REQUIRED", []string{"accept-production", "--manifest", production, "--plan", plan}, map[string]string{"ENVBANK_VERCEL_ACCEPTANCE_TARGET": vercelProductionAcceptanceTarget}},
		{"token-in-environment", "CREDENTIAL_ENVIRONMENT_FORBIDDEN", []string{"accept-production", "--manifest", production, "--plan", plan}, map[string]string{"ENVBANK_LIVE_ACCEPTANCE": "1", "VERCEL_TOKEN": "fake-token-must-not-be-used", "ENVBANK_VERCEL_ACCEPTANCE_TARGET": vercelProductionAcceptanceTarget}},
		{"preview-target-string", "DISPOSABLE_PRODUCTION_TARGET_REQUIRED", []string{"accept-production", "--manifest", production, "--plan", plan}, map[string]string{"ENVBANK_LIVE_ACCEPTANCE": "1", "ENVBANK_VERCEL_ACCEPTANCE_TARGET": vercelAcceptanceTarget}},
		{"branch-scoped-production", "DISPOSABLE_PRODUCTION_TARGET_REQUIRED", []string{"accept-production", "--manifest", production, "--plan", plan}, map[string]string{"ENVBANK_LIVE_ACCEPTANCE": "1", "ENVBANK_VERCEL_ACCEPTANCE_TARGET": vercelProductionAcceptanceTarget + "@main"}},
		{"unmarked-target", "DISPOSABLE_PRODUCTION_TARGET_REQUIRED", []string{"accept-production", "--manifest", production, "--plan", plan}, map[string]string{"ENVBANK_LIVE_ACCEPTANCE": "1", "ENVBANK_VERCEL_ACCEPTANCE_TARGET": "disposable-production:team_fixture/prj_fixture/my-app"}},
		{"missing-plan", "OWNER_APPROVED_PLAN_REQUIRED", []string{"accept-production", "--manifest", production}, map[string]string{"ENVBANK_LIVE_ACCEPTANCE": "1", "ENVBANK_VERCEL_ACCEPTANCE_TARGET": vercelProductionAcceptanceTarget}},
		{"target-not-manifest", "ACCEPTANCE_MANIFEST_NOT_DISPOSABLE", []string{"accept-production", "--manifest", production, "--plan", plan}, map[string]string{"ENVBANK_LIVE_ACCEPTANCE": "1", "ENVBANK_VERCEL_ACCEPTANCE_TARGET": "disposable-production:team_fixture/prj_other/envbank-acceptance-fixture"}},
		{"preview-manifest", "ACCEPTANCE_MANIFEST_NOT_DISPOSABLE", []string{"accept-production", "--manifest", preview, "--plan", plan}, map[string]string{"ENVBANK_LIVE_ACCEPTANCE": "1", "ENVBANK_VERCEL_ACCEPTANCE_TARGET": vercelProductionAcceptanceTarget}},
		// Mode separation: the Preview command never accepts the production form.
		{"preview-command-production-target", "DISPOSABLE_TARGET_REQUIRED", []string{"accept", "--manifest", production, "--plan", plan}, map[string]string{"ENVBANK_LIVE_ACCEPTANCE": "1", "ENVBANK_VERCEL_ACCEPTANCE_TARGET": vercelProductionAcceptanceTarget}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for _, name := range append([]string{"ENVBANK_LIVE_ACCEPTANCE", "ENVBANK_VERCEL_ACCEPTANCE_TARGET"}, vercelAcceptanceForbiddenEnvironment...) {
				t.Setenv(name, c.env[name])
			}
			out, errout, e := captureRunWithStdin(t, append(append([]string{"vercel"}, c.args...), noConfig...), "")
			if e == nil || !strings.Contains(e.Error(), c.want) || strings.Contains(out+errout+e.Error(), "fake-token-must-not-be-used") {
				t.Fatalf("got %v", e)
			}
		})
	}
}

func TestVercelAcceptProductionGuardsDomainsBeforeOwnerOrRecord(t *testing.T) {
	fixture := newCLIDeviceFixture(t)
	path := filepath.Join(t.TempDir(), "vercel.yaml")
	if e := os.WriteFile(path, []byte(vercelProductionAcceptanceManifest), 0600); e != nil {
		t.Fatal(e)
	}
	auth := authArgs(fixture, fixture.firstConfigPath)
	if _, _, e := captureRunWithStdin(t, append([]string{"bundle", "prepare", "--manifest", path}, auth...), ""); e != nil {
		t.Fatal(e)
	}
	var mu sync.Mutex
	mutations, customDomain := 0, true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer fake-vercel-production-acceptance-credential" || r.URL.Query().Get("teamId") != "team_fixture" {
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
			fmt.Fprint(w, `{"id":"prj_fixture","accountId":"team_fixture","name":"envbank-acceptance-fixture"}`)
		case "/v10/projects/prj_fixture/env":
			fmt.Fprint(w, `{"envs":[]}`)
		case "/v9/projects/prj_fixture/domains":
			extra := ""
			if customDomain {
				extra = `,{"name":"shop.example.com","projectId":"prj_fixture","verified":true}`
			}
			fmt.Fprint(w, `{"domains":[{"name":"envbank-acceptance-fixture.vercel.app","projectId":"prj_fixture","verified":true}`+extra+`],"pagination":{"next":null}}`)
		default:
			t.Error("unexpected API route")
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	owner := ownerapprovaltest.New("cli-production-acceptance-owner")
	previousStore, previousOptions, previousProbe := vercelCredentialStore, vercelAdapterOptions, vercelAcceptanceProbe
	vercelCredentialStore = &memoryKeychain{values: map[string][]byte{}}
	vercelAdapterOptions = func() vercel.Options { return vercel.Options{Endpoint: server.URL, Client: server.Client()} }
	probes := 0
	vercelAcceptanceProbe = func(vercel.Scope, []byte) (vercelworkflow.AcceptanceProbe, func(), error) {
		return func(context.Context, vercel.Deployment, map[string]string) (int, error) {
			probes++
			return 0, fmt.Errorf("fixture probe must not run before owner approval")
		}, func() {}, nil
	}
	defer func() {
		vercelCredentialStore, vercelAdapterOptions, vercelAcceptanceProbe = previousStore, previousOptions, previousProbe
	}()
	t.Setenv("ENVBANK_LIVE_ACCEPTANCE", "1")
	t.Setenv("ENVBANK_VERCEL_ACCEPTANCE_TARGET", vercelProductionAcceptanceTarget)
	for _, name := range vercelAcceptanceForbiddenEnvironment {
		t.Setenv(name, "")
	}
	run := func(args ...string) (string, error) {
		t.Helper()
		out, errout, e := captureRunWithStdin(t, append(append([]string{"vercel"}, args...), auth...), "")
		if strings.Contains(out+errout, "fake-vercel-production-acceptance-credential") {
			t.Fatal("CLI exposed provider credential")
		}
		return out, e
	}
	if _, _, e := captureRunWithStdin(t, append([]string{"vercel", "bind", "--manifest", path}, auth...), "fake-vercel-production-acceptance-credential\n"); e != nil {
		t.Fatal(e)
	}
	out, e := run("plan", "--manifest", path)
	var plan mcpserver.Result
	if e != nil || json.Unmarshal([]byte(out), &plan) != nil || plan.PlanID == "" {
		t.Fatal("plan unavailable")
	}
	// A custom domain is refused before owner, plan, record or source checks.
	out, e = run("accept-production", "--manifest", path, "--plan", plan.PlanID)
	var receipt vercelworkflow.ProductionAcceptanceReceipt
	if e == nil || json.Unmarshal([]byte(out), &receipt) != nil || receipt.Blocker != "ACCEPTANCE_PRODUCTION_PROJECT_NOT_DISPOSABLE" || receipt.GuardCode != "ACCEPTANCE_CUSTOM_DOMAIN_PRESENT" || receipt.PlanID != "" || probes != 0 {
		t.Fatalf("custom domain not refused first: %v %+v", e, receipt)
	}
	if receipt.Level != "provider-production" || receipt.APIPromotionRollback != "not-qualified" || receipt.FullWorkflow != "not-qualified" || receipt.VariablesReverted || receipt.VariableState != "not-started" {
		t.Fatalf("receipt overstated qualification: %+v", receipt)
	}
	mu.Lock()
	customDomain = false
	mu.Unlock()
	out, e = run("accept-production", "--manifest", path, "--plan", plan.PlanID)
	if e == nil || json.Unmarshal([]byte(out), &receipt) != nil || receipt.Blocker != "OWNER_APPROVAL_KEY_NOT_PINNED" || probes != 0 {
		t.Fatalf("acceptance without owner pin: %v %+v", e, receipt)
	}
	pinOwnerKey(t, fixture.firstConfigPath, fixture.passphrasePath, owner.PublicKey())
	out, e = run("accept-production", "--manifest", path, "--plan", plan.PlanID)
	if e == nil || json.Unmarshal([]byte(out), &receipt) != nil || receipt.Blocker != "OWNER_APPROVAL_REQUIRED" || probes != 0 {
		t.Fatalf("acceptance without approval: %v %+v", e, receipt)
	}
	mu.Lock()
	defer mu.Unlock()
	if mutations != 0 {
		t.Fatal("production acceptance mutated the provider without approval")
	}
	for _, forbidden := range []string{"proof", "challenge", "hash"} {
		if strings.Contains(out, forbidden) {
			t.Fatalf("receipt contains %q", forbidden)
		}
	}
}
