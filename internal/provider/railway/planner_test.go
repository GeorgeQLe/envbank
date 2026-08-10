package railway

import (
	"fmt"
	"testing"
	"time"

	"github.com/GeorgeQLe/envbank/internal/bundle"
	"github.com/GeorgeQLe/envbank/internal/contract"
	"github.com/GeorgeQLe/envbank/internal/provider"
	"github.com/GeorgeQLe/envbank/internal/rollout"
)

const plannerManifest = `version: 1
bundle: example/siftcut/staging
policies:
  password:
    type: password
    length: 24
    lowercase: true
records:
  POSTGRES_PASSWORD:
    source: generate
    policy: password
  DATABASE_URL:
    source: derive
    template: postgresql://user:${secret:POSTGRES_PASSWORD}@postgres.internal/db
targets:
  railway:
    project: siftcut-staging
    environment: staging
    services:
      postgres:
        order: 1
        variables:
          POSTGRES_DB: {source: constant, value: siftcut}
          POSTGRES_PASSWORD: {source: record, record: POSTGRES_PASSWORD}
      migrator:
        order: 2
        variables:
          DATABASE_URL: {source: record, record: DATABASE_URL}
      api:
        order: 3
        variables:
          NODE_ENV: {source: constant, value: staging}
      web:
        order: 4
        variables:
          API_UPSTREAM: {source: constant, value: "http://api.railway.internal:3000"}
        absent: [VITE_API_URL]
`

func TestBuildNamesOnlyInputBindsFourServicesAndLocalRevisions(t *testing.T) {
	document, err := contract.Parse([]byte(plannerManifest))
	if err != nil {
		t.Fatal(err)
	}
	snapshot := bundle.Snapshot{Version: bundle.SnapshotVersion, Bundle: document.Manifest.Bundle,
		ManifestDigest: document.Digest,
		PhysicalToLogical: map[string]string{
			bundle.PhysicalName(document.Manifest.Bundle, "POSTGRES_PASSWORD"): "POSTGRES_PASSWORD",
			bundle.PhysicalName(document.Manifest.Bundle, "DATABASE_URL"):      "DATABASE_URL",
		}, Sources: map[string]bundle.SourceStatus{
			"POSTGRES_PASSWORD": {Source: "generate", Status: "ready"},
			"DATABASE_URL":      {Source: "derive", Status: "ready"},
		}, RecordRevisions: map[string]int64{"POSTGRES_PASSWORD": 4, "DATABASE_URL": 7},
		CreatedAt: time.Date(2026, 8, 9, 20, 0, 0, 0, time.UTC).Format(time.RFC3339)}
	target := provider.Target{ProjectID: "project-id", EnvironmentID: "environment-id",
		ServiceIDs: map[string]string{"postgres": "postgres-id", "migrator": "migrator-id",
			"api": "api-id", "web": "web-id"}}
	input, err := BuildNamesOnlyInput(document, snapshot, 3, target)
	if err != nil {
		t.Fatal(err)
	}
	if input.Kind != rollout.PlanKindNamesOnly || len(input.Actions) != 5 || len(input.Target.ServiceIDs) != 4 {
		t.Fatalf("unexpected plan input: %+v", input)
	}
	want := []string{
		"postgres/POSTGRES_DB/present/unverifiable/0",
		"postgres/POSTGRES_PASSWORD/present/unverifiable/4",
		"migrator/DATABASE_URL/present/unverifiable/7",
		"api/NODE_ENV/present/unverifiable/0",
		"web/API_UPSTREAM/present/unverifiable/0",
		"web/VITE_API_URL/absent/unverifiable/0",
	}
	got := make([]string, len(input.Names))
	for index, item := range input.Names {
		got[index] = fmt.Sprintf("%s/%s/%s/%s/%d", item.Service, item.Name,
			item.Desired, item.State, item.ExpectedRecordRevision)
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("names = %v, want %v", got, want)
	}
	wantActions := []string{"postgres/POSTGRES_DB", "postgres/POSTGRES_PASSWORD", "migrator/DATABASE_URL", "api/NODE_ENV", "web/API_UPSTREAM"}
	gotActions := make([]string, len(input.Actions))
	for index, action := range input.Actions {
		gotActions[index] = action.ID
	}
	if fmt.Sprint(gotActions) != fmt.Sprint(wantActions) {
		t.Fatalf("actions = %v, want %v", gotActions, wantActions)
	}
}

func TestSiftCutBindingRejectsMissingOrUnexpectedServices(t *testing.T) {
	document, err := contract.Parse([]byte(plannerManifest))
	if err != nil {
		t.Fatal(err)
	}
	target := document.Manifest.Targets[ProviderName]
	delete(target.Services, "web")
	target.Services["worker"] = contract.Service{Order: 4}
	document.Manifest.Targets[ProviderName] = target
	if _, err := BindingRequestForManifest(document); err == nil {
		t.Fatal("unexpected four-service target was accepted")
	}
}
