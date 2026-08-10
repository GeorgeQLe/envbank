package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GeorgeQLe/envbank/internal/keychain"
	"github.com/GeorgeQLe/envbank/internal/provider/railway"
	"github.com/GeorgeQLe/envbank/internal/rollout"
	"github.com/GeorgeQLe/envbank/internal/vaultobject"
)

const railwayCLIManifest = `version: 1
bundle: example/siftcut/railway-staging
policies:
  password:
    type: password
    length: 24
    lowercase: true
records:
  POSTGRES_PASSWORD:
    source: generate
    policy: password
targets:
  railway:
    project: siftcut-staging
    environment: staging
    services:
      postgres:
        order: 1
        variables:
          POSTGRES_PASSWORD: {source: record, record: POSTGRES_PASSWORD}
      migrator: {order: 2}
      api:
        order: 3
        variables:
          NODE_ENV: {source: constant, value: staging}
      web:
        order: 4
        absent: [VITE_API_URL]
`

type memoryKeychain struct{ values map[string][]byte }

func (store *memoryKeychain) Put(service, account string, secret []byte) error {
	store.values[service+"\x00"+account] = append([]byte(nil), secret...)
	return nil
}

func (store *memoryKeychain) Get(service, account, _ string) ([]byte, error) {
	value, exists := store.values[service+"\x00"+account]
	if !exists {
		return nil, keychain.ErrNotFound
	}
	return append([]byte(nil), value...), nil
}

func (store *memoryKeychain) Delete(service, account string) error {
	delete(store.values, service+"\x00"+account)
	return nil
}

func TestRailwayBindAndPlanCLIStayNamesOnly(t *testing.T) {
	fixture := newCLIDeviceFixture(t)
	manifestPath := filepath.Join(t.TempDir(), "railway.yaml")
	if err := os.WriteFile(manifestPath, []byte(railwayCLIManifest), 0600); err != nil {
		t.Fatal(err)
	}
	auth := authArgs(fixture, fixture.firstConfigPath)
	prepare := append([]string{"bundle", "prepare", "--manifest", manifestPath}, auth...)
	if _, _, err := captureRunWithStdin(t, prepare, ""); err != nil {
		t.Fatal(err)
	}

	queries := make([]string, 0)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Project-Access-Token") != "project-token-SENTINEL-915" {
			t.Error("Railway request did not use the bound project token")
		}
		var body struct {
			Query string `json:"query"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		queries = append(queries, body.Query)
		switch {
		case strings.Contains(body.Query, "EnvBankRailwayIdentity"):
			fmt.Fprint(response, `{"data":{"projectToken":{"projectId":"project-id","environmentId":"environment-id"}}}`)
		case strings.Contains(body.Query, "EnvBankRailwayTarget"):
			fmt.Fprint(response, `{"data":{"project":{"id":"project-id","name":"siftcut-staging","environments":{"edges":[{"node":{"id":"environment-id","name":"staging"}}]},"services":{"edges":[{"node":{"id":"postgres-id","name":"postgres"}},{"node":{"id":"migrator-id","name":"migrator"}},{"node":{"id":"api-id","name":"api"}},{"node":{"id":"web-id","name":"web"}}]}}}}`)
		default:
			t.Fatalf("unexpected Railway query: %s", body.Query)
		}
	}))
	defer server.Close()

	originalStore, originalOptions := railwayCredentialStore, railwayAdapterOptions
	railwayCredentialStore = &memoryKeychain{values: map[string][]byte{}}
	railwayAdapterOptions = func() railway.Options {
		return railway.Options{Endpoint: server.URL, Client: server.Client()}
	}
	t.Cleanup(func() {
		railwayCredentialStore, railwayAdapterOptions = originalStore, originalOptions
	})

	bind := append([]string{"railway", "bind", "--manifest", manifestPath}, auth...)
	stdout, stderr, err := captureRunWithStdin(t, bind, "project-token-SENTINEL-915\n")
	if err != nil || !strings.Contains(stdout, "status: bound") || stderr != "" {
		t.Fatalf("bind stdout=%q stderr=%q err=%v", stdout, stderr, err)
	}
	if strings.Contains(stdout+stderr, "project-token-SENTINEL") {
		t.Fatal("bind output exposed the Railway credential")
	}

	planArgs := append([]string{"railway", "plan", "--manifest", manifestPath}, auth...)
	stdout, stderr, err = captureRun(t, planArgs)
	if err != nil || stderr != "" || !strings.Contains(stdout, "status: names-only") ||
		!strings.Contains(stdout, "postgres/POSTGRES_PASSWORD: desired=present state=unverifiable") ||
		!strings.Contains(stdout, "web/VITE_API_URL: desired=absent state=unverifiable") {
		t.Fatalf("plan stdout=%q stderr=%q err=%v", stdout, stderr, err)
	}
	if strings.Contains(stdout+stderr, "project-token-SENTINEL") {
		t.Fatal("plan output exposed the Railway credential")
	}
	for _, query := range queries {
		lower := strings.ToLower(query)
		for _, forbidden := range []string{"mutation", "variables(", "deploy", "restart"} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("CLI used forbidden Railway operation %q in %s", forbidden, query)
			}
		}
	}

	api, key := unlockedFixtureAPI(t, fixture.firstConfigPath, fixture.passphrasePath)
	objects, err := api.ListObjects(key)
	if err != nil {
		t.Fatal(err)
	}
	foundPlan := false
	for _, object := range objects {
		if object.Kind != vaultobject.KindProviderPlan {
			continue
		}
		foundPlan = true
		if strings.Contains(string(object.Payload), "project-token-SENTINEL") {
			t.Fatal("encrypted plan payload schema contained the Railway credential")
		}
	}
	if !foundPlan {
		t.Fatal("railway plan did not persist an encrypted provider plan")
	}
}

func TestRailwayApplyResumesCommittedWritesAndVerifiesNamesOnly(t *testing.T) {
	fixture := newCLIDeviceFixture(t)
	manifestPath := filepath.Join(t.TempDir(), "railway.yaml")
	if err := os.WriteFile(manifestPath, []byte(railwayCLIManifest), 0600); err != nil {
		t.Fatal(err)
	}
	auth := authArgs(fixture, fixture.firstConfigPath)
	if _, _, err := captureRunWithStdin(t,
		append([]string{"bundle", "prepare", "--manifest", manifestPath}, auth...), ""); err != nil {
		t.Fatal(err)
	}

	mutations := make([]string, 0)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		var body struct {
			Query     string `json:"query"`
			Variables struct {
				Input struct {
					Name        string `json:"name"`
					Value       string `json:"value"`
					SkipDeploys bool   `json:"skipDeploys"`
				} `json:"input"`
			} `json:"variables"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		switch {
		case strings.Contains(body.Query, "EnvBankRailwayIdentity"):
			fmt.Fprint(response, `{"data":{"projectToken":{"projectId":"project-id","environmentId":"environment-id"}}}`)
		case strings.Contains(body.Query, "EnvBankRailwayTarget"):
			fmt.Fprint(response, `{"data":{"project":{"id":"project-id","name":"siftcut-staging","environments":{"edges":[{"node":{"id":"environment-id","name":"staging"}}]},"services":{"edges":[{"node":{"id":"postgres-id","name":"postgres"}},{"node":{"id":"migrator-id","name":"migrator"}},{"node":{"id":"api-id","name":"api"}},{"node":{"id":"web-id","name":"web"}}]}}}}`)
		case strings.Contains(body.Query, "EnvBankRailwayVariableUpsert"):
			if !body.Variables.Input.SkipDeploys {
				t.Fatal("Railway write did not set skipDeploys")
			}
			mutations = append(mutations, body.Variables.Input.Name)
			if len(mutations) == 2 {
				response.WriteHeader(http.StatusServiceUnavailable)
				fmt.Fprint(response, `provider-body-secret-SENTINEL-39`)
				return
			}
			fmt.Fprint(response, `{"data":{"variableUpsert":true}}`)
		default:
			t.Fatalf("forbidden Railway operation: %s", body.Query)
		}
	}))
	defer server.Close()

	originalStore, originalOptions, originalConfirmation := railwayCredentialStore, railwayAdapterOptions, railwayConfirmation
	railwayCredentialStore = &memoryKeychain{values: map[string][]byte{}}
	railwayAdapterOptions = func() railway.Options { return railway.Options{Endpoint: server.URL, Client: server.Client()} }
	railwayConfirmation = func(_ context.Context, confirmation rollout.Confirmation) error {
		if confirmation.Kind != "apply" || confirmation.ActionCount != 2 || confirmation.Destructive {
			t.Fatalf("unexpected confirmation: %+v", confirmation)
		}
		return nil
	}
	t.Cleanup(func() {
		railwayCredentialStore, railwayAdapterOptions, railwayConfirmation = originalStore, originalOptions, originalConfirmation
	})

	if _, _, err := captureRunWithStdin(t,
		append([]string{"railway", "bind", "--manifest", manifestPath}, auth...), "project-token\n"); err != nil {
		t.Fatal(err)
	}
	planOut, _, err := captureRun(t, append([]string{"railway", "plan", "--manifest", manifestPath}, auth...))
	if err != nil {
		t.Fatal(err)
	}
	planID := outputField(planOut, "plan")
	applyOut, applyErrOut, err := captureRun(t, append([]string{"railway", "apply", "--plan", planID}, auth...))
	if err == nil || !strings.Contains(err.Error(), "HTTP_ERROR") || strings.Contains(applyOut+applyErrOut+err.Error(), "provider-body-secret") {
		t.Fatalf("partial apply stdout=%q stderr=%q err=%v", applyOut, applyErrOut, err)
	}
	operationID := outputField(applyOut, "operation")
	resumeOut, resumeErrOut, err := captureRun(t,
		append([]string{"railway", "resume", "--operation", operationID}, auth...))
	if err != nil || resumeErrOut != "" || !strings.Contains(resumeOut, "status: limited") ||
		!strings.Contains(resumeOut, "ready for separately authorized deployment") {
		t.Fatalf("resume stdout=%q stderr=%q err=%v", resumeOut, resumeErrOut, err)
	}
	if fmt.Sprint(mutations) != fmt.Sprint([]string{"POSTGRES_PASSWORD", "NODE_ENV", "NODE_ENV"}) {
		t.Fatalf("resume repeated a proven write or used wrong order: %v", mutations)
	}
	verifyOut, verifyErrOut, err := captureRun(t,
		append([]string{"railway", "verify", "--bundle", "example/siftcut/railway-staging"}, auth...))
	if err != nil || verifyErrOut != "" || !strings.Contains(verifyOut, "presence=unknown local-write=committed") ||
		!strings.Contains(verifyOut, "VITE_API_URL: desired=absent presence=unknown local-write=not-written") ||
		!strings.Contains(verifyOut, "no deployment mutation issued") {
		t.Fatalf("verify stdout=%q stderr=%q err=%v", verifyOut, verifyErrOut, err)
	}
}

func outputField(output, name string) string {
	prefix := name + ": "
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(line, prefix))
		}
	}
	return ""
}

var _ keychain.Store = (*memoryKeychain)(nil)
